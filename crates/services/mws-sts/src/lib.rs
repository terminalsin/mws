//! AWS Security Token Service for MWS.
//!
//! STS issues temporary credentials for identities that live in IAM, so this
//! crate depends on `mws-iam`'s public API (AWS couples the two the same
//! way). It is also a [`CredentialStore`](mws_core::CredentialStore) for the
//! credentials it issues.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/sts_generated.rs"));
}

mod credentials;
mod extra;
mod oidc_keys;
mod ops;
mod saml;
mod saml_sig;
mod web_identity;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use mws_core::{Caller, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_iam::Iam;

/// An issued set of temporary credentials.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Session {
    pub secret_access_key: String,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub caller: Caller,
}

pub(crate) struct Inner {
    pub iam: Iam,
    pub sessions: Mutex<HashMap<String, Session>>,
    /// Whether AssumeRoleWithWebIdentity and AssumeRoleWithSAML check
    /// signatures.
    pub verify_federation_signatures: bool,
}

/// The STS service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Sts {
    inner: Arc<Inner>,
}

impl Sts {
    pub fn new(iam: Iam) -> Self {
        Self {
            inner: Arc::new(Inner { iam, sessions: Mutex::new(HashMap::new()), verify_federation_signatures: true }),
        }
    }

    /// Accept web identity tokens and SAML responses without checking their
    /// signatures (for tests that hand-craft them). AWS always checks them.
    pub fn without_federation_signature_verification(iam: Iam) -> Self {
        Self {
            inner: Arc::new(Inner { iam, sessions: Mutex::new(HashMap::new()), verify_federation_signatures: false }),
        }
    }

    /// A credential store for the temporary credentials this service issues.
    pub fn credential_store(&self) -> Arc<dyn mws_core::CredentialStore> {
        Arc::new(credentials::StsCredentials { inner: self.inner.clone() })
    }

    pub(crate) fn iam(&self) -> &Iam {
        &self.inner.iam
    }

    /// The IAM namespace a request works in: the caller's account, or the
    /// configured one for unsigned requests.
    fn scope_account(&self, ctx: &RequestContext) -> String {
        match ctx.caller.account_id.as_str() {
            "" => self.iam().account_id_str().to_string(),
            a => a.to_string(),
        }
    }
}

const UNSIGNED_ACTIONS: &[&str] = &["AssumeRoleWithWebIdentity", "AssumeRoleWithSAML"];

#[async_trait::async_trait]
impl Service for Sts {
    fn signing_name(&self) -> &'static str {
        "sts"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        let params = mws_proto_query::read_params(&request);
        let account = self.scope_account(&ctx);
        self.iam().in_account(account, generated::dispatch(self, &ctx, &params)).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        let params = mws_proto_query::read_params(request);
        params.get("Action").is_some_and(|a| UNSIGNED_ACTIONS.contains(&a))
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        let account = self.scope_account(&ctx);
        self.iam().in_account(account, generated::invoke(self, &ctx, operation, input)).await
    }

    /// Issued temporary credentials, so sessions survive a restart.
    fn export_state(&self) -> Option<serde_json::Value> {
        let sessions = self.sessions().clone();
        let sessions: std::collections::BTreeMap<_, _> = sessions.into_iter().collect();
        Some(serde_json::json!({ "sessions": sessions }))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        #[derive(serde::Deserialize, Default)]
        #[serde(default)]
        struct Saved {
            sessions: HashMap<String, Session>,
        }
        let saved: Saved = serde_json::from_value(state).map_err(|e| format!("invalid STS state: {e}"))?;
        *self.sessions() = saved.sessions;
        Ok(())
    }

    fn reset_state(&self) {
        self.sessions().clear();
    }
}

impl Sts {
    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.inner.sessions.lock().expect("STS session lock poisoned")
    }
}
