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

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use public::ServiceKey;
use state::State;

/// The KMS service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Kms {
    state: Arc<Mutex<State>>,
}

impl Kms {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().expect("KMS state lock poisoned");
        state.sweep(chrono::Utc::now());
        state
    }
}

#[async_trait::async_trait]
impl Service for Kms {
    fn signing_name(&self) -> &'static str {
        "kms"
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
