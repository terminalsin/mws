//! AWS Private CA (ACM PCA) for MWS.
//!
//! Certificate authorities hold real private keys and issue real X.509
//! certificates: create a CA, fetch its CSR, issue its root certificate (or
//! have a parent CA sign it), import it, then issue and revoke end-entity
//! certificates. Every operation is authorized through IAM; CA resource
//! policies (`PutPolicy`) are evaluated as resource-based policies.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/acmpca_generated.rs"));
}

mod handler;
mod ops;
mod state;
mod x509;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

/// The Private CA service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct PrivateCa {
    state: Arc<Mutex<State>>,
}

impl PrivateCa {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Private CA state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for PrivateCa {
    fn signing_name(&self) -> &'static str {
        "acm-pca"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
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
        Some(serde_json::to_value(state).expect("Private CA state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Private CA state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
