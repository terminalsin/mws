//! AWS Identity and Access Management for MWS.
//!
//! The wire layer (types, validation, XML) is generated from AWS's Smithy
//! model at build time. This crate adds the state and behaviour, and owns
//! the account's identities, so it also acts as the gateway's
//! [`CredentialStore`](mws_core::CredentialStore).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/iam_generated.rs"));
}

mod credentials;
mod handler;
mod ids;
mod state;

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

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
        Self { inner: Arc::new(Inner { config, created_at: Utc::now(), state: RwLock::new(State::default()) }) }
    }

    pub fn config(&self) -> &IamConfig {
        &self.inner.config
    }

    /// A credential store backed by this account's root and user keys.
    pub fn credential_store(&self) -> Arc<dyn mws_core::CredentialStore> {
        Arc::new(credentials::IamCredentials { inner: self.inner.clone() })
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
        let params = mws_proto_query::read_params(&request);
        generated::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, error)
    }
}
