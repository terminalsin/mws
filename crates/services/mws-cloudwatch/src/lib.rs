//! Amazon CloudWatch (metrics, alarms, dashboards) for MWS.
//!
//! Metrics are stored as real datapoints (455 days, standard and high
//! resolution) and queried with `GetMetricStatistics` and `GetMetricData`,
//! whose metric math engine implements the expression language: arithmetic
//! and comparisons, the time series functions, `SEARCH`, `IF`, `FILL`,
//! `ANOMALY_DETECTION_BAND`, `INSIGHT_RULE_METRIC` and label templates.
//! Alarms (metric, metric math, anomaly band, composite and log alarms)
//! are evaluated every second against the emulated clock; state changes go
//! to the history, to EventBridge, and to their SNS and Lambda actions,
//! honouring mute rules and composite suppressors. Contributor Insights
//! rules analyse CloudWatch Logs events, metric streams deliver to
//! Firehose through [`MetricStreamDelivery`], and `GetMetricWidgetImage`
//! draws a real PNG.
//!
//! CloudWatch answers Smithy RPC v2 CBOR (current SDKs), awsJson 1.0 and
//! awsQuery (older SDKs). The model is `awsQueryCompatible`: errors carry
//! the awsQuery code in `x-amzn-query-error`. `PutMetricData` bodies may be
//! gzip-compressed, as SDKs send them.
//!
//! CloudWatch Logs metric filters publish into CloudWatch through
//! [`CloudWatch::put_metric_as_service`].

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/cloudwatch_generated.rs"));
}
#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod query_generated {
    include!(concat!(env!("OUT_DIR"), "/cloudwatch_query_generated.rs"));
}

mod alarms;
mod anomaly;
mod dashboards;
mod evaluate;
mod handler;
mod insights;
mod logalarm;
mod math;
mod metrics;
mod misc;
mod mute;
mod names;
mod query;
mod rule;
mod search;
mod state;
mod stats;
mod streams;
mod widget;

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use metrics::ServiceMetric;
use state::State;
pub use streams::MetricStreamDelivery;

pub(crate) struct Inner {
    pub(crate) clock_offset_ms: AtomicI64,
    pub(crate) template: Mutex<Option<RequestContext>>,
    pub(crate) scheduler: AtomicBool,
    pub(crate) sns: OnceLock<mws_sns::Sns>,
    pub(crate) lambda: OnceLock<mws_lambda::Lambda>,
    pub(crate) events: OnceLock<mws_events::Events>,
    pub(crate) logs: OnceLock<mws_logs::Logs>,
    pub(crate) kms: OnceLock<mws_kms::Kms>,
    pub(crate) streams: OnceLock<Arc<dyn MetricStreamDelivery>>,
}

#[derive(Clone)]
pub struct CloudWatch {
    state: Arc<Mutex<State>>,
    pub(crate) inner: Arc<Inner>,
}

impl Default for CloudWatch {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudWatch {
    pub fn new() -> Self {
        Self {
            state: Arc::default(),
            inner: Arc::new(Inner {
                clock_offset_ms: AtomicI64::new(0),
                template: Mutex::new(None),
                scheduler: AtomicBool::new(false),
                sns: OnceLock::new(),
                lambda: OnceLock::new(),
                events: OnceLock::new(),
                logs: OnceLock::new(),
                kms: OnceLock::new(),
                streams: OnceLock::new(),
            }),
        }
    }

    /// SNS topics as alarm actions.
    pub fn with_sns(self, sns: mws_sns::Sns) -> Self {
        let _ = self.inner.sns.set(sns);
        self
    }

    /// Lambda functions as alarm actions.
    pub fn with_lambda(self, lambda: mws_lambda::Lambda) -> Self {
        let _ = self.inner.lambda.set(lambda);
        self
    }

    /// EventBridge, for alarm state change events.
    pub fn with_events(self, events: mws_events::Events) -> Self {
        let _ = self.inner.events.set(events);
        self
    }

    /// CloudWatch Logs, for log alarms and Contributor Insights.
    pub fn with_logs(self, logs: mws_logs::Logs) -> Self {
        let _ = self.inner.logs.set(logs);
        self
    }

    /// KMS, for dataset encryption keys.
    pub fn with_kms(self, kms: mws_kms::Kms) -> Self {
        let _ = self.inner.kms.set(kms);
        self
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("CloudWatch state lock poisoned")
    }
}

/// Undo `Content-Encoding: gzip` (SDKs compress `PutMetricData`).
fn decompress(request: HttpRequest) -> Result<HttpRequest, ServiceError> {
    let gzip = request
        .headers()
        .get(http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|e| e.trim().eq_ignore_ascii_case("gzip")));
    if !gzip {
        return Ok(request);
    }
    let (mut parts, body) = request.into_parts();
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body.as_ref()).read_to_end(&mut out).map_err(|_| {
        ServiceError::client("InvalidParameterValue", 400, "The request body could not be decompressed.")
    })?;
    parts.headers.remove(http::header::CONTENT_ENCODING);
    Ok(HttpRequest::from_parts(parts, Bytes::from(out)))
}

#[async_trait::async_trait]
impl Service for CloudWatch {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
            || mws_proto_cbor::targets(generated::CBOR_SERVICE, request)
    }

    fn signing_name(&self) -> &'static str {
        "monitoring"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        let cbor = mws_proto_cbor::is_cbor(&request);
        let json = request.headers().contains_key("x-amz-target");
        let request = match decompress(request) {
            Ok(r) => r,
            Err(e) if cbor => return mws_proto_cbor::error_response(&generated::SERVICE_INFO, &ctx.request_id, &e),
            Err(e) if json => return mws_proto_json::error_response(&generated::SERVICE_INFO, &ctx.request_id, &e),
            Err(e) => {
                return mws_proto_query::error_response(
                    &query_generated::SERVICE_INFO,
                    &ctx.request_id,
                    &query::to_query_error(e),
                )
            }
        };
        if cbor {
            generated::dispatch_cbor(self, &ctx, &request).await
        } else if json {
            generated::dispatch(self, &ctx, &request).await
        } else {
            query::handle(self, &ctx, &request).await
        }
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_cbor::error_response(&generated::SERVICE_INFO, request_id, error)
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
        Some(serde_json::to_value(state).expect("CloudWatch state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid CloudWatch state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
