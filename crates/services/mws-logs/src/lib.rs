//! Amazon CloudWatch Logs for MWS.
//!
//! Log groups and streams store the events written to them, in timestamp
//! order, and give them back through `GetLogEvents` and `FilterLogEvents`
//! (with the full filter pattern syntax: terms, JSON and space-delimited
//! patterns, see [`filter`]), CloudWatch Logs Insights queries ([`insights`])
//! and live tail sessions that stay open and stream new events as they
//! arrive. Retention applies against the emulated clock. Export tasks write
//! gzipped events into real S3 buckets as `logs.<region>.amazonaws.com`,
//! judged by the bucket policy; KMS keys associated with log groups must
//! exist and allow CloudWatch Logs in their key policy. Transformers and
//! metric filters really transform and match (`TestTransformer`,
//! `TestMetricFilter`). Every call is authorized through IAM, with log
//! group resource policies and `aws:ResourceTag` conditions.
//!
//! Other services write logs through [`Logs::put_log_events_as_service`],
//! checked against the account's resource policies the way AWS services
//! that deliver logs (Route 53 query logging, ...) are.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/logs_generated.rs"));
}

mod deliveries;
mod events;
pub mod filter;
mod forward;
mod groups;
mod handler;
pub mod insights;
mod livetail;
mod misc;
mod names;
mod policies;
mod public;
mod queries;
mod state;
mod subscriptions;
mod tasks;
pub mod transform;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;
use mws_s3::S3;

pub use forward::{control_message, lambda_event, SubscriptionSource, SubscriptionTarget};
pub use public::{ServiceLogError, ServiceLogEvent, ServiceLogWriter};
use state::State;

/// The CloudWatch Logs service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Logs {
    state: Arc<Mutex<State>>,
    tails: livetail::Sessions,
    s3: Option<S3>,
    kms: Option<Kms>,
    /// Where subscription filters deliver (Lambda, ...).
    targets: Arc<std::sync::RwLock<Vec<Arc<dyn SubscriptionTarget>>>>,
    /// The last request's context and clock offset, for deliveries of
    /// writes that come without one.
    template: Arc<Mutex<Option<(RequestContext, chrono::Duration)>>>,
}

impl Logs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Export tasks write into these S3 buckets.
    pub fn with_s3(mut self, s3: S3) -> Self {
        self.s3 = Some(s3);
        self
    }

    /// KMS keys for log group encryption come from here.
    pub fn with_kms(mut self, kms: Kms) -> Self {
        self.kms = Some(kms);
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("CloudWatch Logs state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for Logs {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "logs"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe(&ctx);
        // Live tail keeps its response open and streams events into it.
        if generated::operation_for(&request) == Some("StartLiveTail") {
            return match generated::decode_input_start_live_tail(&request) {
                Ok(input) => match self.start_live_tail_streaming(&ctx, input) {
                    Ok(r) => r,
                    Err(e) => self.render_error(&ctx.request_id, &e),
                },
                Err(e) => self.render_error(&ctx.request_id, &e),
            };
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
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("CloudWatch Logs state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid CloudWatch Logs state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
        self.tails.clear();
    }
}
