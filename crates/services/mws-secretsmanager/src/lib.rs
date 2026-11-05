//! AWS Secrets Manager for MWS.
//!
//! Secrets keep versions with staging labels (`AWSCURRENT`, `AWSPREVIOUS`,
//! `AWSPENDING`, and any of your own) exactly as Secrets Manager moves them.
//! Every version is sealed under a KMS data key generated through
//! [`mws_kms::Kms`] for the caller with `kms:ViaService`
//! `secretsmanager.<region>.amazonaws.com` and the secret ARN and version
//! id as encryption context, so key policies and IAM decide who can read a
//! value, as in AWS. Without a `KmsKeyId` the AWS managed key
//! `aws/secretsmanager` is created on first use.
//!
//! Every call is authorized through IAM with the secret's resource policy
//! and Secrets Manager's condition keys. Rotation really runs: `RotateSecret`
//! invokes the rotation Lambda function as `secretsmanager.amazonaws.com`
//! (the function policy must allow it) through the `createSecret`,
//! `setSecret`, `testSecret` and `finishSecret` steps, and the function
//! calls back into MWS with its execution role. Scheduled rotations
//! (`AutomaticallyAfterDays`, `rate()` and `cron()` expressions with a
//! `Duration` window) start when the emulated clock reaches their window.
//! Replicas live in their own Region with their own key and follow the
//! primary; deletions honour the recovery window.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/secretsmanager_generated.rs"));
}

mod handler;
mod managed;
mod names;
mod ops;
mod password;
mod policy;
mod public;
mod replication;
mod rotation;
pub mod schedule;
mod seal;
mod state;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;
use mws_lambda::Lambda;

pub use managed::{ManagedRotation, ManagedSecretSpec};
pub use public::SecretReference;
use state::State;

pub(crate) struct Inner {
    state: Mutex<State>,
    kms: Kms,
    lambda: std::sync::OnceLock<Lambda>,
    /// Rotation of secrets other services own, by owning service.
    managed: Mutex<std::collections::BTreeMap<String, Arc<dyn ManagedRotation>>>,
}

/// The Secrets Manager service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct SecretsManager {
    inner: Arc<Inner>,
}

impl SecretsManager {
    /// Secrets Manager encrypting with `kms`.
    pub fn new(kms: Kms) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                kms,
                lambda: Default::default(),
                managed: Default::default(),
            }),
        }
    }

    /// Rotation functions run on this Lambda.
    pub fn with_lambda(self, lambda: Lambda) -> Self {
        let _ = self.inner.lambda.set(lambda);
        self
    }

    pub(crate) fn kms(&self) -> &Kms {
        &self.inner.kms
    }

    pub(crate) fn lambda(&self) -> Option<&Lambda> {
        self.inner.lambda.get()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("Secrets Manager state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for SecretsManager {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "secretsmanager"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.tick(&ctx);
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
        self.tick(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("Secrets Manager state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Secrets Manager state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
