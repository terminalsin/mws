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
//!
//! Queries run in all three Logs Insights languages: the Logs Insights
//! language, OpenSearch SQL and OpenSearch PPL. Scheduled
//! queries run on the emulated clock as their execution role and deliver
//! their results to S3 or a lookup table.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/logs_generated.rs"));
}

mod background;
mod deliveries;
mod events;
pub mod filter;
mod forward;
mod groups;
mod handler;
pub mod insights;
mod lake;
mod livetail;
mod metrics;
mod misc;
mod names;
mod policies;
mod public;
mod queries;
mod scheduled;
mod sqlppl;
mod state;
mod subscriptions;
mod tasks;
pub mod transform;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;
use mws_s3::S3;

pub use forward::{control_message, lambda_event, DeliveryFailure, SubscriptionSource, SubscriptionTarget};
pub use lake::{LakeData, LakeEvent, LakeSource};
pub use metrics::{FilterMetric, MetricPublisher};
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
    metric_publisher: Arc<std::sync::RwLock<Option<Arc<dyn MetricPublisher>>>>,
    /// Scheduled queries assume their roles through STS.
    sts: Option<mws_sts::Sts>,
    /// Whether the scheduled query runner is started.
    scheduler: Arc<std::sync::atomic::AtomicBool>,
    /// Import tasks read CloudTrail Lake event data stores here.
    lake: Arc<std::sync::RwLock<Option<Arc<dyn LakeSource>>>>,
    /// The authorizer background work uses before Logs has seen a request
    /// (after restoring saved state).
    authorizer: Arc<std::sync::OnceLock<Arc<dyn mws_core::Authorizer>>>,
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

    /// Scheduled queries run as their execution role, assumed here.
    pub fn with_sts(mut self, sts: mws_sts::Sts) -> Self {
        self.sts = Some(sts);
        self
    }

    /// Import tasks read CloudTrail Lake event data stores from `source`.
    pub fn set_lake_source(&self, source: Arc<dyn LakeSource>) {
        *self.lake.write().expect("Logs lake lock poisoned") = Some(source);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("CloudWatch Logs state lock poisoned")
    }

    /// The authorizer scheduled queries and subscription deliveries use
    /// before Logs has seen a request, as after restoring saved state.
    pub fn set_authorizer(&self, authorizer: Arc<dyn mws_core::Authorizer>) {
        let _ = self.authorizer.set(authorizer);
    }

    /// The context background work starts from: the last request's (and
    /// how far its clock ran ahead), or one made from the authorizer set
    /// with [`Logs::set_authorizer`] when no request has been seen.
    pub(crate) fn background_template(&self) -> Option<(RequestContext, chrono::Duration)> {
        if let Some(t) = self.template.lock().expect("Logs template lock poisoned").clone() {
            return Some(t);
        }
        let authorizer = self.authorizer.get()?.clone();
        let ctx = RequestContext {
            request_id: String::new(),
            region: String::new(),
            partition: "aws".into(),
            received_at: chrono::Utc::now(),
            caller: mws_core::Caller::anonymous(),
            source_ip: None,
            secure_transport: true,
            authorizer,
            endpoint: None,
        };
        Some((ctx, chrono::Duration::zero()))
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
        // Calls from other services and scenario files start background
        // work (scheduled queries, subscription forwarding) too. Only HTTP
        // requests move the clock: a service's background call may carry
        // the wall clock.
        if self.template.lock().expect("Logs template lock poisoned").is_none() {
            self.observe(&ctx);
        } else {
            self.start_scheduler();
        }
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("CloudWatch Logs state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid CloudWatch Logs state: {e}"))?;
        *self.lock() = state;
        self.resume_background();
        self.start_scheduler();
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
        self.tails.clear();
    }
}
