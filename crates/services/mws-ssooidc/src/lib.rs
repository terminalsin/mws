//! AWS IAM Identity Center OIDC (`sso-oidc`) for MWS: the OAuth 2.0
//! authorization server the AWS CLI and SDKs sign users in through.
//!
//! Clients register, then get a token through the device authorization
//! grant or the authorization code grant with PKCE, and refresh it. A user
//! approves the request on MWS's sign-in page (see [`signin`]), naming an
//! Identity Store user; MWS has no passwords. The access token identifies
//! that user to the AWS access portal (`mws-ssoportal`), which exchanges it
//! for role credentials. `CreateTokenWithIAM` issues tokens to customer
//! managed applications for IAM principals, from an authorization code, a
//! refresh token, a trusted token issuer's JWT (`jwt-bearer`, signature
//! checked as STS checks web identity tokens) or another Identity Center
//! token (`token-exchange`).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ssooidc_generated.rs"));
}

mod iam_tokens;
mod ops;
mod public;
pub mod signin;
mod state;
mod tokens;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_identitystore::IdentityStore;
use mws_ssoadmin::SsoAdmin;
use mws_sts::Sts;

pub use public::TokenOwner;
use state::State;

/// The OIDC service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct SsoOidc {
    state: Arc<Mutex<State>>,
    identity: IdentityStore,
    admin: SsoAdmin,
    sts: Sts,
    /// Signs the ID tokens CreateTokenWithIAM issues.
    id_token_key: Arc<[u8; 32]>,
}

impl SsoOidc {
    pub fn new(identity: IdentityStore, admin: SsoAdmin, sts: Sts) -> Self {
        let mut key = [0u8; 32];
        aws_lc_rs::rand::fill(&mut key).expect("random bytes");
        Self { state: Arc::default(), identity, admin, sts, id_token_key: Arc::new(key) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("SSO OIDC state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for SsoOidc {
    fn signing_name(&self) -> &'static str {
        "sso-oauth"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        signin::is_signin_request(request) || generated::operation_for(request).is_some()
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        signin::is_signin_request(request)
            || matches!(
                generated::operation_for(request),
                Some("CreateToken" | "RegisterClient" | "StartDeviceAuthorization")
            )
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if signin::is_signin_request(&request) {
            return self.signin(&ctx, &request);
        }
        generated::dispatch(self, &ctx, &request).await
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
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("SSO OIDC state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid SSO OIDC state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
