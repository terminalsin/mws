//! AWS Lambda for MWS.
//!
//! Functions are created, versioned, aliased, permissioned and configured
//! as in Lambda, and they really run: `Invoke` starts an execution
//! environment that is a local process speaking the Lambda Runtime API
//! (see [`runtime`]). Functions of managed runtimes run in AWS's own
//! Lambda base images when Docker is available ([`RuntimeExecutor`]);
//! otherwise Python and Node.js functions run on the machine's
//! `python3`/`node` with MWS's runtime client, and `provided.*` functions
//! run their own `bootstrap`. Functions get credentials for their execution
//! role from STS, and `AWS_ENDPOINT_URL` pointing back at MWS, so AWS SDKs
//! inside them talk to the emulator. Container image functions pull their
//! image from ECR (through [`ImageSource`]) and run it in Docker.
//!
//! AWS couples Lambda to IAM (execution roles, `iam:PassRole`), STS (role
//! credentials) and S3 (deployment packages in buckets, S3 Object Lambda),
//! so this crate uses their public APIs.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/lambda_generated.rs"));
}

mod aliases;
mod capacity;
mod code;
mod config_ops;
mod destinations;
mod durable;
mod esm;
mod esm_stream;
mod file_systems;
mod function_url;
mod functions;
mod handler;
mod image;
mod invoke;
mod layers;
mod lifecycle;
mod metrics;
mod names;
mod object_lambda;
mod permissions;
mod recursion;
mod runtime;
mod service_invoke;
mod state;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use destinations::{DestinationMessage, DestinationSink};
pub use esm::{QueueFacts, QueueMessage, QueueMessageAttribute, QueueSource};
pub use esm_stream::{StreamPosition, StreamRead, StreamRecord, StreamShard, StreamSource};
pub use file_systems::{FileSystemMountError, FileSystemMountRequest, FileSystems, MountedFileSystem};
pub use image::{ContainerImage, ImageBlob, ImageError, ImageSource};
pub use names::FunctionRef;
pub use runtime::RuntimeExecutor;
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
    /// Applied quota values (concurrent executions).
    quotas: std::sync::OnceLock<mws_servicequotas::ServiceQuotas>,
    pollers: esm::Pollers,
    /// Where destination records for other services go.
    destinations: destinations::Sinks,
    /// Where container images come from, when ECR is wired in.
    images: std::sync::OnceLock<Arc<dyn image::ImageSource>>,
    /// Where the `AWS/Lambda` metrics go.
    metrics: mws_core::metrics::MetricOutlet,
    /// Durable executions' background work.
    durable: durable::Runtime,
    /// Where `FileSystemConfigs` mount from, when EFS is wired in.
    file_systems: std::sync::OnceLock<Arc<dyn FileSystems>>,
    /// The authorizer for background work before any request was seen.
    authorizer: std::sync::OnceLock<Arc<dyn mws_core::Authorizer>>,
    /// The URL MWS serves on, for background work whose template has none.
    endpoint: std::sync::OnceLock<EndpointSource>,
}

/// Where the URL MWS serves on comes from.
pub type EndpointSource = Arc<dyn Fn() -> Option<String> + Send + Sync>;

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
                quotas: std::sync::OnceLock::new(),
                pollers: esm::Pollers::default(),
                destinations: destinations::Sinks::default(),
                images: std::sync::OnceLock::new(),
                metrics: Default::default(),
                durable: Default::default(),
                file_systems: std::sync::OnceLock::new(),
                authorizer: std::sync::OnceLock::new(),
                endpoint: std::sync::OnceLock::new(),
            }),
        }
    }

    /// Choose what runs functions of managed runtimes (`nodejs*`,
    /// `python*`, `java*`, ...): AWS's Lambda base images in Docker, local
    /// processes, or the former when Docker is available. Local processes
    /// unless set.
    pub fn set_runtime_executor(&self, executor: RuntimeExecutor) {
        self.inner.runtimes.set_executor(executor);
    }

    /// Send function logs to CloudWatch Logs, written as the function's
    /// execution role like AWS does (so the role needs
    /// `logs:CreateLogGroup`, `logs:CreateLogStream` and `logs:PutLogEvents`).
    /// Read the concurrent executions quota from Service Quotas.
    pub fn set_service_quotas(&self, quotas: mws_servicequotas::ServiceQuotas) {
        let _ = self.inner.quotas.set(quotas);
    }

    /// The account's concurrency limit in the request's Region. Never call
    /// with the state lock held.
    pub(crate) fn account_concurrency(&self, account: &str, ctx: &RequestContext) -> i32 {
        let value = match self.inner.quotas.get() {
            Some(q) => q.applied_value(account, &ctx.region, "lambda", "L-B99A9384", ctx.received_at),
            None => 1000.0,
        };
        value.clamp(0.0, i32::MAX as f64) as i32
    }

    /// Publish the `AWS/Lambda` metrics (`Invocations`, `Errors`,
    /// `Duration`, `Throttles`, `ConcurrentExecutions`, ...) through
    /// `publisher`.
    pub fn set_metric_publisher(&self, publisher: Arc<dyn mws_core::metrics::MetricPublisher>) {
        self.inner.metrics.connect(publisher);
    }

    /// Mount Amazon EFS access points for functions' `FileSystemConfigs`.
    pub fn set_file_systems(&self, file_systems: Arc<dyn FileSystems>) {
        let _ = self.inner.file_systems.set(file_systems);
    }

    /// The authorizer background work (event source mapping pollers) uses
    /// before Lambda has seen a request, as after restoring saved state.
    pub fn set_authorizer(&self, authorizer: Arc<dyn mws_core::Authorizer>) {
        let _ = self.inner.authorizer.set(authorizer);
    }

    /// Where background work learns the URL MWS serves on (which functions
    /// get as `AWS_ENDPOINT_URL`) when no request has told it.
    pub fn set_endpoint_source(&self, endpoint: EndpointSource) {
        let _ = self.inner.endpoint.set(endpoint);
    }

    pub(crate) fn background_endpoint(&self) -> Option<String> {
        self.inner.endpoint.get().and_then(|e| e())
    }

    /// A context for background work when no request has been seen.
    pub(crate) fn background_template(&self, region: &str) -> Option<RequestContext> {
        let authorizer = self.inner.authorizer.get()?.clone();
        // Not serving yet: functions would not know where MWS is.
        let endpoint = Some(self.background_endpoint()?);
        let partition = self
            .read()
            .functions
            .keys()
            .find_map(|arn| arn.split(':').nth(1).map(str::to_string))
            .unwrap_or_else(|| "aws".into());
        Some(RequestContext {
            request_id: String::new(),
            region: region.to_string(),
            partition,
            received_at: chrono::Utc::now(),
            caller: mws_core::Caller::anonymous(),
            source_ip: None,
            secure_transport: false,
            authorizer,
            endpoint,
        })
    }

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
                "functions"
                    | "layers"
                    | "tags"
                    | "event-source-mappings"
                    | "account-settings"
                    | "code-signing-configs"
                    | "resource-policy"
                    | "capacity-providers"
                    | "durable-executions"
                    | "durable-execution-callbacks"
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
        // CloudFormation and scenario files act through here: their event
        // source mappings poll as soon as they are enabled, too.
        self.observe(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        Some(serde_json::to_value(&*self.read()).expect("Lambda state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let mut state: State = serde_json::from_value(state).map_err(|e| format!("invalid Lambda state: {e}"))?;
        // Creates and updates in flight when the state was saved have
        // completed since.
        for func in state.functions.values_mut() {
            lifecycle::settle(func);
        }
        *self.write() = state;
        self.inner.runtimes.retire_all();
        // Restored mappings poll without waiting for a Lambda request.
        self.start_pollers();
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
        self.inner.runtimes.retire_all();
    }
}
