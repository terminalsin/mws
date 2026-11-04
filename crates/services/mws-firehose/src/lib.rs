//! Amazon Data Firehose for MWS.
//!
//! Delivery streams buffer the records put into them (`PutRecord`,
//! `PutRecordBatch`, or read from a Kinesis data stream with the source
//! role) and deliver them when the destination's buffering hints say so,
//! on the emulated clock:
//!
//! - Amazon S3 (and Extended S3): objects named as Firehose names them
//!   (`YYYY/MM/DD/HH/` or a custom prefix with `!{timestamp:..}`,
//!   `!{firehose:..}` and dynamic partitioning keys), compressed (GZIP,
//!   ZIP, Snappy, Hadoop Snappy), SSE-KMS encrypted, written with the
//!   delivery role's permissions; source record backup; processing
//!   failures under the error output prefix.
//! - HTTP endpoints and Splunk HEC: real HTTP requests in Firehose's
//!   format, retried for the retry duration, then backed up to S3.
//! - OpenSearch / Elasticsearch (and Serverless) with an endpoint: `_bulk`
//!   requests; Redshift: the intermediate S3 objects. Snowflake and
//!   Iceberg tables are not emulated: their records go to the S3 backup.
//!
//! Data format conversion needs the AWS Glue Data Catalog, which MWS does
//! not have: records go to the `format-conversion-failed` error output, as
//! they do in AWS when the schema's table cannot be found.
//!
//! Delivery errors go to the destination's CloudWatch Logs log stream when
//! error logging is enabled, `AWS/Firehose` metrics are published to
//! CloudWatch, and destination credentials can come from Secrets Manager.
//!
//! Data transformation runs the configured processors: Lambda (invoked
//! with the processor's role), decompression, CloudWatch Logs message
//! extraction, record de-aggregation, JQ-style metadata extraction for
//! dynamic partitioning, and delimiters. Every call is authorized through
//! IAM.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/firehose_generated.rs"));
}

mod config;
mod deliver;
mod handler;
mod http;
mod monitor;
mod names;
mod output;
mod processing;
mod records;
mod source;
mod state;
mod streams;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use names::stream_arn;
use state::State;

pub(crate) const SERVICE_PRINCIPAL: &str = "firehose.amazonaws.com";

#[derive(Default)]
pub(crate) struct Inner {
    state: Mutex<State>,
    s3: OnceLock<mws_s3::S3>,
    sts: OnceLock<mws_sts::Sts>,
    kms: OnceLock<mws_kms::Kms>,
    lambda: OnceLock<mws_lambda::Lambda>,
    kinesis: OnceLock<mws_kinesis::Kinesis>,
    logs: OnceLock<mws_logs::Logs>,
    cloudwatch: OnceLock<mws_cloudwatch::CloudWatch>,
    secrets_manager: OnceLock<mws_secretsmanager::SecretsManager>,
    /// The last request's context and clock offset, for background
    /// deliveries.
    template: Mutex<Option<(RequestContext, chrono::Duration)>>,
    started: OnceLock<()>,
    /// Serializes delivery rounds.
    delivering: tokio::sync::Mutex<()>,
}

/// The Firehose service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Firehose {
    inner: Arc<Inner>,
}

impl Firehose {
    pub fn new() -> Self {
        Self::default()
    }

    /// S3 destinations write here.
    pub fn with_s3(self, s3: mws_s3::S3) -> Self {
        let _ = self.inner.s3.set(s3);
        self
    }

    /// Delivery roles are assumed through STS.
    pub fn with_sts(self, sts: mws_sts::Sts) -> Self {
        let _ = self.inner.sts.set(sts);
        self
    }

    /// Server-side encryption keys come from here.
    pub fn with_kms(self, kms: mws_kms::Kms) -> Self {
        let _ = self.inner.kms.set(kms);
        self
    }

    /// Lambda processors run here.
    pub fn with_lambda(self, lambda: mws_lambda::Lambda) -> Self {
        let _ = self.inner.lambda.set(lambda);
        self
    }

    /// Kinesis data streams sources are read from here.
    pub fn with_kinesis(self, kinesis: mws_kinesis::Kinesis) -> Self {
        let _ = self.inner.kinesis.set(kinesis);
        self
    }

    /// Delivery errors are logged here, when a destination enables it.
    pub fn set_logs(&self, logs: mws_logs::Logs) {
        let _ = self.inner.logs.set(logs);
    }

    /// `AWS/Firehose` metrics are published here.
    pub fn set_cloudwatch(&self, cloudwatch: mws_cloudwatch::CloudWatch) {
        let _ = self.inner.cloudwatch.set(cloudwatch);
    }

    /// Destination credentials (`SecretsManagerConfiguration`) are read
    /// from here.
    pub fn set_secrets_manager(&self, secrets_manager: mws_secretsmanager::SecretsManager) {
        let _ = self.inner.secrets_manager.set(secrets_manager);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("Firehose state lock poisoned")
    }

    fn settled(&self, ctx: &RequestContext) -> MutexGuard<'_, State> {
        let mut st = self.lock();
        st.settle(names::now_ms(ctx));
        st
    }

    /// Deliver everything buffered now, whatever the buffering hints say
    /// (for tests and shutdown).
    pub async fn flush_all(&self) {
        self.deliver_round(true).await;
    }
}

#[async_trait::async_trait]
impl Service for Firehose {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "firehose"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe(&ctx);
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, &names::firehose_denial(error.clone()))
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.observe(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("Firehose state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Firehose state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
