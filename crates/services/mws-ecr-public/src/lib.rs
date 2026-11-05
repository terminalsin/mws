//! Amazon ECR Public for MWS.
//!
//! Each account has one public registry, named by an alias (assigned on
//! first use, as AWS assigns a default alias) and reachable as
//! `public.ecr.aws/<alias>`. Repositories carry catalog data (description,
//! architectures, operating systems, logo, about and usage text) and real
//! OCI content: layers and images put through the API or pushed with
//! Docker.
//!
//! The registry endpoint serves the Docker registry HTTP API v2 under
//! `/v2/public.ecr.aws/<alias>/<repository>/...` on MWS's own address, so
//! `docker pull localhost:4566/public.ecr.aws/<alias>/<repository>:<tag>`
//! works anonymously, as public registries do, and pushes run as the
//! caller whose `GetAuthorizationToken` password `docker login` sent, with
//! that caller's IAM and repository-policy permissions.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ecr_public_generated.rs"));
}

mod handler;
mod ops;
mod registry;
mod state;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{AlternateSignature, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

/// The first path segment, under `/v2/`, of public registry requests on
/// MWS's address: `/v2/public.ecr.aws/<alias>/<repository>/...`.
pub const REGISTRY_PATH_PREFIX: &str = "public.ecr.aws";
/// The audience of registry passwords this service issues.
pub(crate) const AUDIENCE: &str = "ecr-public";
/// Where catalog logos are served.
pub(crate) const LOGO_PATH: &str = "/_aws/ecr-public/logos/";

tokio::task_local! {
    /// The session token the current API request was signed with.
    pub(crate) static SESSION_TOKEN: Option<String>;
}

#[derive(Default)]
pub(crate) struct Inner {
    state: Mutex<State>,
    /// The host repository URIs name (`MWS_ECR_PUBLIC_REGISTRY_HOST`).
    registry_host: OnceLock<String>,
}

/// The ECR Public service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct EcrPublic {
    inner: Arc<Inner>,
}

impl EcrPublic {
    pub fn new() -> Self {
        Self::default()
    }

    /// Name the registry in repository URIs with this host (and path)
    /// instead of `public.ecr.aws`, e.g. `localhost:4566/public.ecr.aws` so
    /// that `docker push $(repositoryUri)` reaches MWS.
    pub fn set_registry_host(&self, host: impl Into<String>) {
        let _ = self.inner.registry_host.set(host.into());
    }

    pub(crate) fn registry_host(&self) -> String {
        self.inner.registry_host.get().cloned().unwrap_or_else(|| REGISTRY_PATH_PREFIX.to_string())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        let mut st = self.inner.state.lock().expect("ECR Public state lock poisoned");
        if st.token_key.is_empty() {
            let bytes: [u8; 32] = rand::random();
            st.token_key = bytes.iter().map(|b| format!("{b:02x}")).collect();
        }
        st
    }
}

#[async_trait::async_trait]
impl Service for EcrPublic {
    fn signing_name(&self) -> &'static str {
        "ecr-public"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request) || registry::is_registry_request(request)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        registry::is_registry_request(request)
    }

    fn anonymous_credentials(&self, request: &HttpRequest) -> bool {
        registry::is_registry_request(request) && registry::is_anonymous_token(self, request)
    }

    fn alternate_signature(&self, request: &HttpRequest) -> Option<Result<AlternateSignature, ServiceError>> {
        registry::alternate_signature(self, request)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if registry::is_registry_request(&request) {
            return registry::serve(self, &ctx, &request);
        }
        let token = request.headers().get("x-amz-security-token").and_then(|v| v.to_str().ok()).map(str::to_string);
        SESSION_TOKEN.scope(token, generated::dispatch(self, &ctx, &request)).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, &ops::denial(error.clone()))
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
        Some(serde_json::to_value(state).expect("ECR Public state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid ECR Public state: {e}"))?;
        *self.inner.state.lock().expect("ECR Public state lock poisoned") = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.inner.state.lock().expect("ECR Public state lock poisoned") = State::default();
    }
}
