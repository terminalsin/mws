//! AWS Identity Store for MWS: the users, groups and group memberships of
//! IAM Identity Center.
//!
//! Identity stores are not created through this API: IAM Identity Center
//! (`mws-ssoadmin`) creates one with each instance through
//! [`IdentityStore::create_store`], and the AWS access portal and the OIDC
//! service read users and their groups through the other public methods.
//! Every call is authorized through IAM. The account that owns a store can
//! do everything; read operations also work from the other accounts of its
//! organization, as AWS allows.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/identitystore_generated.rs"));
}

mod attrs;
mod ops;
mod public;
mod state;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_iam::Iam;

pub use public::{StoreInfo, UserInfo};
use state::State;

/// The Identity Store service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct IdentityStore {
    state: Arc<Mutex<State>>,
    iam: Iam,
}

impl IdentityStore {
    pub fn new(iam: Iam) -> Self {
        Self { state: Arc::default(), iam }
    }

    /// Never hold this while calling `ctx.authorize`.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Identity Store state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for IdentityStore {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "identitystore"
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
        Some(serde_json::to_value(state).expect("Identity Store state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Identity Store state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
