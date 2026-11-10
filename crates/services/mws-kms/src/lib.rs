//! AWS Key Management Service for MWS.
//!
//! Keys hold real key material and do real cryptography (see [`crypto`]):
//! AES-256-GCM symmetric keys with encryption context bound into the
//! ciphertext, RSA, ECC, Ed25519 and ML-DSA signing keys, RSA encryption
//! keys, HMAC keys, ECDH key agreement and ML-KEM. Key policies are
//! evaluated as KMS evaluates them (the key policy must allow the caller,
//! directly or by delegating to the account's IAM policies), and grants
//! allow their grantees on top of that. Aliases, tags, automatic and
//! on-demand rotation, scheduled deletion, imported key material and
//! multi-Region keys follow the API reference.
//!
//! Other services use keys through [`Kms`]'s public methods, the way AWS
//! services call KMS on a caller's behalf.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/kms_generated.rs"));
}

pub mod crypto;
mod handler;
mod ops;
mod public;
mod state;
mod xks;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use chrono::{DateTime, Utc};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use public::ServiceKey;
use state::State;
pub use xks::XksTransport;

/// The KMS service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Kms {
    state: Arc<Mutex<State>>,
    /// How far the emulated clock (`/_mws/clock`) runs ahead of the wall
    /// clock, as last seen in a request. Scheduled deletions, automatic
    /// rotations and expiring imported material follow it.
    clock_offset_ms: Arc<AtomicI64>,
    principals: Arc<RwLock<Option<Arc<dyn PrincipalDirectory>>>>,
    xks: Arc<RwLock<XksTransport>>,
}

/// Which IAM principals exist (IAM's users and roles), so key policies
/// naming principals that don't exist are rejected as KMS rejects them.
pub trait PrincipalDirectory: Send + Sync {
    /// Whether `arn` names an existing principal. Principals the directory
    /// knows nothing about count as existing.
    fn principal_exists(&self, arn: &str) -> bool;
}

impl Kms {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check key policy principals against `directory`.
    pub fn set_principal_directory(&self, directory: Arc<dyn PrincipalDirectory>) {
        *self.principals.write().expect("KMS principals lock poisoned") = Some(directory);
    }

    /// How external key store proxies are reached.
    pub fn set_xks_transport(&self, transport: XksTransport) {
        *self.xks.write().expect("KMS XKS lock poisoned") = transport;
    }

    pub(crate) fn xks_transport(&self) -> XksTransport {
        self.xks.read().expect("KMS XKS lock poisoned").clone()
    }

    pub(crate) fn principals(&self) -> Option<Arc<dyn PrincipalDirectory>> {
        self.principals.read().expect("KMS principals lock poisoned").clone()
    }

    /// Note the emulated time of a request, so that time-driven changes
    /// happen when the emulated clock reaches them.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = (ctx.received_at - Utc::now()).num_milliseconds().max(0);
        self.clock_offset_ms.store(offset, Ordering::Relaxed);
    }

    /// The emulated time now.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::milliseconds(self.clock_offset_ms.load(Ordering::Relaxed))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        let now = self.now();
        let mut state = self.state.lock().expect("KMS state lock poisoned");
        state.sweep(now);
        state
    }
}

#[async_trait::async_trait]
impl Service for Kms {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "kms"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe(&ctx);
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
        self.observe(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("KMS state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid KMS state: {e}"))?;
        *self.state.lock().expect("KMS state lock poisoned") = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.state.lock().expect("KMS state lock poisoned") = State::default();
    }
}
