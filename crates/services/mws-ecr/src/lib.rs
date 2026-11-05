//! Amazon Elastic Container Registry (private registries) for MWS.
//!
//! Every account has one registry per Region. Repositories hold real OCI
//! content: layers uploaded through the API (`InitiateLayerUpload`,
//! `UploadLayerPart`, `CompleteLayerUpload`) or the registry endpoint, and
//! images put by manifest, so `docker push` / `docker pull` and the API see
//! the same images.
//!
//! The registry endpoint is the Docker registry HTTP API v2 under `/v2/` on
//! MWS's own address. `docker login` takes the password from
//! `GetAuthorizationToken` (`aws ecr get-login-password`); registry requests
//! then run as the caller who asked for it, with that caller's IAM and
//! repository-policy permissions (`ecr:BatchGetImage`,
//! `ecr:InitiateLayerUpload`, ...). The registry's account and Region come
//! from the password, or from a `Host` of the form
//! `<account>.dkr.ecr.<region>.<anything>`.
//!
//! Beyond storage: tag immutability (with exclusion filters), lifecycle
//! policies that expire or archive images on the emulated clock (and their
//! previews), replication to other Regions and accounts (with registry
//! policies, creation templates and backfills), scan-on-push and manual
//! scans (MWS has no vulnerability database, so scans complete with no
//! findings), archival storage, repository creation templates (including
//! create-on-push), pull-time update exclusions, KMS encryption settings
//! checked against KMS, and `aws.ecr` events on EventBridge.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ecr_generated.rs"));
}

mod handler;
mod images;
mod lifecycle;
mod names;
mod registry;
mod registry_config;
mod replication;
mod repos;
mod state;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{AlternateSignature, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use names::repository_arn;
use state::State;

/// Where `GetDownloadUrlForLayer` links point.
pub(crate) const LAYER_PATH: &str = "/_aws/ecr/layers/";
/// The audience of registry passwords this service issues.
pub(crate) const AUDIENCE: &str = "ecr";

tokio::task_local! {
    /// The session token the current API request was signed with, for
    /// `GetAuthorizationToken` to bind passwords to.
    pub(crate) static SESSION_TOKEN: Option<String>;
}

/// An `aws.ecr` event for the account's default event bus.
#[derive(Debug, Clone)]
pub struct EcrEvent {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub detail_type: String,
    pub resources: Vec<String>,
    pub detail: serde_json::Value,
    pub time: chrono::DateTime<chrono::Utc>,
}

/// Where ECR's events go (EventBridge).
pub trait EventSink: Send + Sync {
    fn event(&self, ctx: &RequestContext, event: EcrEvent);
}

#[derive(Default)]
pub(crate) struct Inner {
    state: Mutex<State>,
    kms: OnceLock<mws_kms::Kms>,
    events: OnceLock<Arc<dyn EventSink>>,
    /// The host repository URIs name (`MWS_ECR_REGISTRY_HOST`), with
    /// `{account}` and `{region}` placeholders.
    registry_host: OnceLock<String>,
    /// Registry paths (`/v2/<prefix>/...`) another service serves.
    excluded_prefix: OnceLock<String>,
}

/// The ECR service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Ecr {
    inner: Arc<Inner>,
}

impl Ecr {
    pub fn new() -> Self {
        Self::default()
    }

    /// Repository encryption keys are checked here.
    pub fn with_kms(self, kms: mws_kms::Kms) -> Self {
        let _ = self.inner.kms.set(kms);
        self
    }

    /// `aws.ecr` events go here.
    pub fn set_event_sink(&self, sink: Arc<dyn EventSink>) {
        let _ = self.inner.events.set(sink);
    }

    /// Name registries in repository URIs with this host instead of
    /// `<account>.dkr.ecr.<region>.amazonaws.com` (`{account}` and
    /// `{region}` are replaced), e.g. `localhost:4566` so that
    /// `docker push $(repositoryUri)` reaches MWS.
    pub fn set_registry_host(&self, host: impl Into<String>) {
        let _ = self.inner.registry_host.set(host.into());
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        let mut st = self.inner.state.lock().expect("ECR state lock poisoned");
        if st.token_key.is_empty() {
            st.token_key = hex_key();
        }
        st
    }

    /// The host part of repository URIs for a registry.
    pub fn registry_host(&self, account: &str, region: &str) -> String {
        match self.inner.registry_host.get() {
            Some(h) => h.replace("{account}", account).replace("{region}", region),
            None => format!("{account}.dkr.ecr.{region}.amazonaws.com"),
        }
    }

    fn emit(&self, ctx: &RequestContext, events: Vec<EcrEvent>) {
        if let Some(sink) = self.inner.events.get() {
            for e in events {
                sink.event(ctx, e);
            }
        }
    }

    /// The registry an API call addresses: `registryId` or the caller's
    /// account, in the request's Region.
    fn target(ctx: &RequestContext, registry_id: Option<&str>) -> String {
        registry_id.filter(|r| !r.is_empty()).map(str::to_string).unwrap_or_else(|| ctx.caller.account_id.clone())
    }
}

fn hex_key() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[async_trait::async_trait]
impl Service for Ecr {
    fn signing_name(&self) -> &'static str {
        "ecr"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request) || self.is_registry_request(request)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        self.is_registry_request(request)
    }

    fn anonymous_credentials(&self, request: &HttpRequest) -> bool {
        self.is_registry_request(request) && registry::is_anonymous_token(self, request)
    }

    fn alternate_signature(&self, request: &HttpRequest) -> Option<Result<AlternateSignature, ServiceError>> {
        registry::alternate_signature(self, request)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.settle(&ctx);
        if self.is_registry_request(&request) {
            return registry::serve(self, &ctx, &request);
        }
        let token = request.headers().get("x-amz-security-token").and_then(|v| v.to_str().ok()).map(str::to_string);
        let response = SESSION_TOKEN.scope(token, generated::dispatch(self, &ctx, &request)).await;
        rewrite_validation(response)
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, &names::ecr_denial(error.clone()))
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.settle(&ctx);
        generated::invoke(self, &ctx, operation, input).await.map_err(names::ecr_validation)
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("ECR state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid ECR state: {e}"))?;
        *self.inner.state.lock().expect("ECR state lock poisoned") = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.inner.state.lock().expect("ECR state lock poisoned") = State::default();
    }
}

/// Reword the generated layer's validation errors as ECR words them.
fn rewrite_validation(response: HttpResponse) -> HttpResponse {
    if response.status() != 400 {
        return response;
    }
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(response.body()) else { return response };
    let is_validation = body.get("__type").and_then(|t| t.as_str()) == Some(generated::errors::INVALID_PARAMETER)
        && body.get("message").and_then(|m| m.as_str()).is_some_and(|m| m.contains(" validation error"));
    if !is_validation {
        return response;
    }
    let message = body["message"].as_str().unwrap_or_default().to_string();
    let reworded = names::ecr_validation(generated::errors::invalid_parameter(message)).message;
    body["message"] = serde_json::Value::String(reworded);
    let (parts, _) = response.into_parts();
    let mut response = http::Response::from_parts(parts, bytes::Bytes::from(body.to_string()));
    response.headers_mut().remove(http::header::CONTENT_LENGTH);
    response
}
