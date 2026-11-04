//! Amazon SQS for MWS.
//!
//! Standard and FIFO queues hold real messages: send delays, visibility
//! timeouts with receipt handles, long polling (`WaitTimeSeconds` waits for
//! messages to arrive), retention, FIFO message groups, deduplication and
//! receive request attempt ids, dead-letter queues driven by
//! `maxReceiveCount` and message move tasks that redrive them. Queues
//! encrypted with SSE-KMS get their data keys from MWS KMS with the
//! caller's permissions. Every call is authorized through IAM together with
//! the queue policy, with `aws:ResourceTag` conditions.
//!
//! The model is `awsQueryCompatible`: errors carry the awsQuery code
//! (`AWS.SimpleQueueService.NonExistentQueue`) in `x-amzn-query-error`, as
//! SDKs expect.
//!
//! Other services (SNS, S3 event notifications) deliver messages through
//! [`Sqs::send_message_as_service`], judged by the queue policy alone, as
//! AWS service principals are.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/sqs_generated.rs"));
}

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod query_generated {
    include!(concat!(env!("OUT_DIR"), "/sqs_query_generated.rs"));
}

mod attributes;
mod handler;
mod md5;
mod messages;
mod metrics;
mod moves;
mod names;
mod public;
mod query;
mod queues;
mod state;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;

pub use md5::{md5_of_attributes, md5_of_body};
pub use metrics::{MetricPublisher, QueueMetric};
pub use public::{ServiceMessage, ServiceMessageAttribute, ServiceSendError};
use state::State;

/// The SQS service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Sqs {
    state: Arc<Mutex<State>>,
    /// Woken whenever messages may have become receivable, for long polls.
    arrivals: Arc<tokio::sync::Notify>,
    kms: Option<Kms>,
    /// `AWS/SQS` CloudWatch metrics.
    meter: Arc<metrics::Meter>,
}

impl Sqs {
    pub fn new() -> Self {
        Self::default()
    }

    /// SSE-KMS data keys come from here.
    pub fn with_kms(mut self, kms: Kms) -> Self {
        self.kms = Some(kms);
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("SQS state lock poisoned")
    }
}

/// The first `AttributeNames` entry of a `GetQueueAttributes` body that
/// SQS does not know.
fn unknown_attribute_name(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("AttributeNames")?
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find(|n| !attributes::known(n))
        .map(str::to_string)
}

#[async_trait::async_trait]
impl Service for Sqs {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "sqs"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe_clock(ctx.received_at);
        // SQS answers unknown attribute names with `InvalidAttributeName`
        // before the model's enum constraint would reject them.
        if generated::operation_for(&request) == Some("GetQueueAttributes") {
            if let Some(name) = unknown_attribute_name(request.body()) {
                return self.render_error(&ctx.request_id, &attributes::unknown_attribute(&name));
            }
        }
        if query::is_query(&request) {
            return query::handle(self, &ctx, &request).await;
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.observe_clock(ctx.received_at);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("SQS state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid SQS state: {e}"))?;
        *self.lock() = state;
        self.reset_metrics();
        self.arrivals.notify_waiters();
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
        self.reset_metrics();
        self.arrivals.notify_waiters();
    }
}
