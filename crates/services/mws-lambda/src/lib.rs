//! AWS Lambda for MWS.
//!
//! Functions are created, versioned, aliased, permissioned and configured
//! as in Lambda, and they really run: `Invoke` starts an execution
//! environment that is a local process speaking the Lambda Runtime API
//! (see [`runtime`]). Python and Node.js functions run on the machine's
//! `python3`/`node` with MWS's runtime client; `provided.*` functions run
//! their own `bootstrap`. Functions get credentials for their execution
//! role from STS, and `AWS_ENDPOINT_URL` pointing back at MWS, so AWS SDKs
//! inside them talk to the emulator.
//!
//! AWS couples Lambda to IAM (execution roles, `iam:PassRole`), STS (role
//! credentials) and S3 (deployment packages in buckets, S3 Object Lambda),
//! so this crate uses their public APIs.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/lambda_generated.rs"));
}

mod aliases;
mod code;
mod config_ops;
mod destinations;
mod esm;
mod esm_stream;
mod function_url;
mod functions;
mod handler;
mod invoke;
mod layers;
mod names;
mod object_lambda;
mod permissions;
mod runtime;
mod service_invoke;
mod state;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use destinations::{DestinationMessage, DestinationSink};
pub use esm::{QueueFacts, QueueMessage, QueueMessageAttribute, QueueSource};
pub use esm_stream::{StreamPosition, StreamRead, StreamRecord, StreamShard, StreamSource};
pub use names::FunctionRef;
pub use service_invoke::{ServiceInvocation, ServiceInvocationResult, ServiceInvokeError};
use state::State;

pub(crate) struct Inner {
    state: RwLock<State>,
    runtimes: runtime::Runtimes,
    sts: Option<mws_sts::Sts>,
    s3: Option<mws_s3::S3>,
    /// Where function logs go, when CloudWatch Logs is wired in.
    logs: std::sync::OnceLock<mws_logs::Logs>,
    /// The queues event source mappings poll, when SQS is wired in.
    queues: std::sync::OnceLock<Arc<dyn esm::QueueSource>>,
    /// The streams event source mappings poll, when Kinesis is wired in.
    streams: std::sync::OnceLock<Arc<dyn esm_stream::StreamSource>>,
    pollers: esm::Pollers,
    /// Where destination records for other services go.
    destinations: destinations::Sinks,
}

/// The Lambda service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Lambda {
    inner: Arc<Inner>,
}

impl Default for Lambda {
    fn default() -> Self {
        Self::new()
    }
}

impl Lambda {
    pub fn new() -> Self {
        Self::build(None, None)
    }

    /// Lambda wired to the services AWS couples it to: STS for execution
    /// role credentials (and their trust policies) and S3 for packages in
    /// buckets and Object Lambda.
    pub fn with_services(sts: mws_sts::Sts, s3: mws_s3::S3) -> Self {
        Self::build(Some(sts), Some(s3))
    }

    fn build(sts: Option<mws_sts::Sts>, s3: Option<mws_s3::S3>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(State::default()),
                runtimes: runtime::Runtimes::default(),
                sts,
                s3,
                logs: std::sync::OnceLock::new(),
                queues: std::sync::OnceLock::new(),
                streams: std::sync::OnceLock::new(),
                pollers: esm::Pollers::default(),
                destinations: destinations::Sinks::default(),
            }),
        }
    }

    /// Send function logs to CloudWatch Logs, written as the function's
    /// execution role like AWS does (so the role needs
    /// `logs:CreateLogGroup`, `logs:CreateLogStream` and `logs:PutLogEvents`).
    pub fn set_logs(&self, logs: mws_logs::Logs) {
        let _ = self.inner.logs.set(logs);
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner.state.read().expect("Lambda state lock poisoned")
    }

    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.state.write().expect("Lambda state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for Lambda {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        if function_url::target(request).is_some() {
            return true;
        }
        // `/2015-03-31/functions/...`, `/2018-10-31/layers/...` and the
        // other dated Lambda resources.
        let path = request.uri().path();
        let mut parts = path.trim_start_matches('/').splitn(3, '/');
        let (Some(date), Some(resource)) = (parts.next(), parts.next()) else { return false };
        date.len() == 10
            && date.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() })
            && matches!(
                resource,
                "functions" | "layers" | "tags" | "event-source-mappings" | "account-settings" | "code-signing-configs"
            )
    }

    fn signing_name(&self) -> &'static str {
        "lambda"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some((id, path)) = function_url::target(&request) {
            return self.serve_function_url(&ctx, &request, &id, &path).await;
        }
        self.observe(&ctx);
        if let Some(response) = self.serve_code_download(&ctx, &request) {
            return response;
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        code::is_download(request) || function_url::target(request).is_some()
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
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
        Some(serde_json::to_value(&*self.read()).expect("Lambda state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Lambda state: {e}"))?;
        *self.write() = state;
        self.inner.runtimes.retire_all();
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
        self.inner.runtimes.retire_all();
    }
}
