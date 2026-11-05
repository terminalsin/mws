//! AWS IAM Identity Center (the `sso-admin` API) for MWS.
//!
//! Instances come with an identity store in `mws-identitystore`. In an
//! organization's management account an instance is the organization
//! instance and assigns access to the organization's accounts; elsewhere it
//! is an account instance. Permission sets are provisioned into accounts as
//! real IAM roles (`AWSReservedSSO_<name>_<suffix>` under
//! `/aws-reserved/sso.amazonaws.com/`) trusted through an
//! `AWSSSO_<id>_DO_NOT_DELETE` SAML provider, exactly as AWS does, so the
//! credentials the AWS access portal hands out (`mws-ssoportal`) are judged
//! by the permission set's policies. Changes to a permission set reach the
//! roles only when it is provisioned again.
//!
//! Applications, their grants, scopes, authentication methods and
//! assignments, and trusted token issuers are kept for the OIDC service
//! (`mws-ssooidc`). Every call is authorized through IAM.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ssoadmin_generated.rs"));
}

mod applications;
mod assignments;
mod common;
mod handler;
mod instances;
mod permission_sets;
mod provision;
mod public;
mod state;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_iam::Iam;
use mws_identitystore::IdentityStore;
use mws_organizations::Organizations;

pub use public::{AccountRole, ApplicationInfo, InstanceInfo, TokenIssuerInfo};
use state::State;

/// The IAM Identity Center admin service. Cheap to clone; clones share
/// state.
#[derive(Clone)]
pub struct SsoAdmin {
    state: Arc<Mutex<State>>,
    iam: Iam,
    identity: IdentityStore,
    organizations: Organizations,
}

impl SsoAdmin {
    pub fn new(iam: Iam, identity: IdentityStore, organizations: Organizations) -> Self {
        Self { state: Arc::default(), iam, identity, organizations }
    }

    /// Never hold this while calling `ctx.authorize` or IAM.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("SSO admin state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for SsoAdmin {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "sso"
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
        Some(serde_json::to_value(state).expect("SSO admin state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid SSO admin state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
