//! Amazon Kinesis Data Streams for MWS.
//!
//! Streams hold real records in shards: partition keys hash with MD5 onto
//! the shards' hash key ranges (or `ExplicitHashKey`, or round-robin for the
//! `AUTO` distribution strategy), sequence numbers increase within a shard,
//! shard iterators (`TRIM_HORIZON`, `LATEST`, `AT_/AFTER_SEQUENCE_NUMBER`,
//! `AT_TIMESTAMP`) expire after five minutes, and retention trims records
//! against the emulated clock. Resharding (`SplitShard`, `MergeShards`,
//! `UpdateShardCount`) closes parent shards and opens children, which
//! `GetRecords` reports as `ChildShards` at the end of a closed shard.
//! Enhanced fan-out consumers receive records over `SubscribeToShard` event
//! streams that stay open and push records as they arrive. Streams
//! encrypted with KMS check the producer's `kms:GenerateDataKey` and the
//! reader's `kms:Decrypt` through MWS KMS. Every call is authorized through
//! IAM together with stream and consumer resource policies. Reads and
//! writes publish the `AWS/Kinesis` CloudWatch metrics, shard-level ones
//! for the metrics enhanced monitoring enabled.
//!
//! Other services (CloudWatch Logs subscriptions, EventBridge targets,
//! Firehose, Lambda event source mappings) act on streams as callers:
//! with the role they assumed, through this crate's operations.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/kinesis_generated.rs"));
}

mod channels;
mod consumers;
mod handler;
pub mod metrics;
mod names;
mod records;
pub mod shards;
mod state;
mod streams;
mod tags;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;

pub use metrics::{KinesisMetric, MetricPublisher};
pub use names::{split_arn, stream_arn};
use state::State;

/// The Kinesis service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Kinesis {
    state: Arc<Mutex<State>>,
    kms: Option<Kms>,
    /// Woken whenever records are put, for `SubscribeToShard` streams.
    arrivals: Arc<tokio::sync::Notify>,
    /// Open `SubscribeToShard` subscriptions: (consumer ARN, shard id).
    subscriptions: consumers::Subscriptions,
    /// Where `AWS/Kinesis` metrics go.
    metric_publisher: Arc<std::sync::RwLock<Option<Arc<dyn MetricPublisher>>>>,
}

impl Kinesis {
    pub fn new() -> Self {
        Self::default()
    }

    /// KMS keys for stream encryption come from here.
    pub fn with_kms(mut self, kms: Kms) -> Self {
        self.kms = Some(kms);
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Kinesis state lock poisoned")
    }

    /// The state with transitions due at `ctx`'s time applied.
    fn settled(&self, ctx: &RequestContext) -> MutexGuard<'_, State> {
        let mut st = self.lock();
        st.settle(names::now_ms(ctx));
        st
    }

    /// Whether the caller may perform `action` (`kinesis:GetRecords`, ...)
    /// on a stream, by its identity and the stream's resource policy, for
    /// services that read streams as a caller (Lambda's pollers). Fails
    /// with `ResourceNotFoundException` when the stream does not exist.
    pub fn authorize_caller(&self, ctx: &RequestContext, stream_arn: &str, action: &str) -> Result<(), ServiceError> {
        let r = names::StreamRef::from_arn(stream_arn)?;
        let st = self.settled(ctx);
        let s = r.get(&st)?;
        names::authorize(ctx, action, &r.arn, s.policy.as_deref(), &s.tags, mws_core::ConditionContext::new())
    }
}

#[async_trait::async_trait]
impl Service for Kinesis {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "kinesis"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        // Enhanced fan-out keeps its response open and pushes records.
        if generated::operation_for(&request) == Some("SubscribeToShard") {
            return match generated::decode_input_subscribe_to_shard(&request) {
                Ok(input) => match self.subscribe_to_shard_streaming(&ctx, input) {
                    Ok(r) => r,
                    Err(e) => self.render_error(&ctx.request_id, &e),
                },
                Err(e) => self.render_error(&ctx.request_id, &e),
            };
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, &names::kinesis_denial(error.clone()))
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
        Some(serde_json::to_value(state).expect("Kinesis state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Kinesis state: {e}"))?;
        *self.lock() = state;
        self.arrivals.notify_waiters();
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
        self.subscriptions.clear();
        self.arrivals.notify_waiters();
    }
}
