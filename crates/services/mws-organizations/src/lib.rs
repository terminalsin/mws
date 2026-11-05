//! AWS Organizations for MWS.
//!
//! Organizations, organizational units, member accounts, policies of every
//! type, handshakes, delegated administrators, trusted service access and
//! billing responsibility transfers. Accounts created here are real MWS
//! accounts: each gets its own IAM namespace and an
//! `OrganizationAccountAccessRole` the management account can assume.
//!
//! Service control policies and resource control policies are enforced by
//! the IAM authorizer, which asks this crate (through
//! [`mws_iam::OrganizationView`]) which policies apply to an account.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/organizations_generated.rs"));
}

mod access;
mod accounts;
mod admin;
mod effective;
mod handler;
mod handshakes;
mod policies;
mod public;
mod service_api;
mod state;
mod structure;
mod view;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_iam::Iam;

pub use public::AccountSummary;
pub use service_api::{DelegationError, OrganizationAccount, OrganizationSnapshot};
use state::State;

/// The Organizations service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Organizations {
    state: Arc<Mutex<State>>,
    iam: Iam,
}

impl Organizations {
    pub fn new(iam: Iam) -> Self {
        Self { state: Arc::new(Mutex::new(State::default())), iam }
    }

    /// What the IAM authorizer needs to enforce SCPs and RCPs. Register it
    /// with [`Iam::set_organizations`].
    pub fn view(&self) -> Arc<dyn mws_iam::OrganizationView> {
        Arc::new(view::View { state: self.state.clone() })
    }

    /// Never hold this while calling `ctx.authorize`: the IAM authorizer
    /// reads Organizations state.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Organizations state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for Organizations {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "organizations"
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
        Some(serde_json::to_value(state).expect("Organizations state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Organizations state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
