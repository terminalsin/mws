//! AWS Identity and Access Management for MWS.
//!
//! The wire layer (types, validation, XML) is generated from AWS's Smithy
//! model at build time. This crate adds the state and behaviour. It owns the
//! account's identities, so it is also the gateway's
//! [`CredentialStore`](mws_core::CredentialStore) for long-term keys and its
//! [`Authorizer`](mws_core::Authorizer) for every service.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/iam_generated.rs"));
}

mod api;
mod authz;
mod common;
mod credentials;
mod handler;
mod ids;
mod managed;
mod ops;
mod state;
mod wire;

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError, SessionKind};

pub use api::{DelegationGrant, OidcProviderView, OutboundKey, RoleView, UserView};
pub use state::State;

/// Settings for the emulated account.
#[derive(Debug, Clone)]
pub struct IamConfig {
    pub account_id: String,
    pub partition: String,
    /// Access key pair for the account root user.
    pub root_access_key_id: String,
    pub root_secret_access_key: String,
}

impl Default for IamConfig {
    fn default() -> Self {
        Self {
            account_id: "123456789012".into(),
            partition: "aws".into(),
            root_access_key_id: "AKIAMWSROOTEXAMPLE00".into(),
            root_secret_access_key: "mwsRootSecretAccessKeyEXAMPLEKEY00000000".into(),
        }
    }
}

/// The IAM service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Iam {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub config: IamConfig,
    pub created_at: DateTime<Utc>,
    pub state: RwLock<State>,
}

impl Iam {
    pub fn new(config: IamConfig) -> Self {
        let iam =
            Self { inner: Arc::new(Inner { config, created_at: Utc::now(), state: RwLock::new(State::default()) }) };
        iam.reset_state();
        iam
    }

    pub fn config(&self) -> &IamConfig {
        &self.inner.config
    }

    /// A credential store backed by this account's root and user keys.
    pub fn credential_store(&self) -> Arc<dyn mws_core::CredentialStore> {
        Arc::new(credentials::IamCredentials { inner: self.inner.clone() })
    }

    /// The authorizer that evaluates IAM policies for every service.
    pub fn authorizer(&self) -> Arc<dyn mws_core::Authorizer> {
        Arc::new(authz::IamAuthorizer { inner: self.inner.clone() })
    }

    pub(crate) fn arn(&self, resource: &str) -> String {
        format!("arn:{}:iam::{}:{resource}", self.inner.config.partition, self.inner.config.account_id)
    }
}

#[async_trait::async_trait]
impl Service for Iam {
    fn signing_name(&self) -> &'static str {
        "iam"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        // Credentials from GetSessionToken cannot call IAM without MFA.
        if ctx.caller.session.as_ref().is_some_and(|s| s.kind == SessionKind::GetSessionToken && !s.mfa_authenticated) {
            return self.render_error(&ctx.request_id, &ServiceError::invalid_client_token_id());
        }
        let params = mws_proto_query::read_params(&request);
        generated::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, error)
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
        let state = self.read().clone();
        Some(serde_json::to_value(state).expect("IAM state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let mut state: State = serde_json::from_value(state).map_err(|e| format!("invalid IAM state: {e}"))?;
        self.seed_aws_managed_policies(&mut state);
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        let mut state = State::default();
        self.seed_aws_managed_policies(&mut state);
        *self.write() = state;
    }
}
