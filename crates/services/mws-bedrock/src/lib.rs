//! Amazon Bedrock (control plane) for MWS.
//!
//! The foundation model catalog, system-defined cross-Region inference
//! profiles and application inference profiles, guardrails (which
//! bedrock-runtime enforces), Provisioned Throughput, model customization
//! and import, custom model deployments, prompt routers, batch inference,
//! evaluation and prompt optimization jobs, Marketplace endpoints,
//! Automated Reasoning policies, invocation logging settings, resource
//! policies and tags.
//!
//! bedrock-runtime (`mws-bedrock-runtime`) resolves model identifiers and
//! guardrails through this crate's public API, as the real data plane
//! depends on the control plane.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/bedrock_generated.rs"));
}

pub mod api_key;
pub mod catalog;
mod datacheck;
pub mod guard;
mod handler;
mod jobs;
mod models;
mod ops;
mod profiles;
mod reasoning;
mod resolve;
mod state;
pub mod storage;
mod util;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use jobs::BatchJob;
pub use resolve::{InvocationTarget, TargetKind};
use state::{Scope, State};

/// The Bedrock control plane. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Bedrock {
    inner: Arc<RwLock<State>>,
    /// Runs batch inference jobs (bedrock-runtime installs it).
    runner: Arc<std::sync::OnceLock<JobRunner>>,
    /// S3 as job roles see it (bedrock-runtime installs it).
    storage: Arc<std::sync::OnceLock<Arc<dyn storage::JobStorage>>>,
}

/// Runs a batch inference job and reports with
/// [`Bedrock::finish_invocation_job`].
pub type JobRunner = Arc<dyn Fn(BatchJob) + Send + Sync>;

/// Paths bedrock-runtime serves; everything else signed for `bedrock` is
/// the control plane's.
pub fn is_runtime_path(path: &str) -> bool {
    path.starts_with("/model/")
        || path.starts_with("/guardrail/")
        || path.starts_with("/guardrail-checks/")
        || path == "/async-invoke"
        || path.starts_with("/async-invoke/")
}

fn scope_key(account: &str, region: &str) -> String {
    format!("{account}/{region}")
}

impl Bedrock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Have `runner` run batch inference jobs as they are created.
    pub fn set_job_runner(&self, runner: JobRunner) {
        let _ = self.runner.set(runner);
    }

    /// Have customization, import and evaluation jobs read and write S3
    /// as their roles through `storage`.
    pub fn set_job_storage(&self, storage: Arc<dyn storage::JobStorage>) {
        let _ = self.storage.set(storage);
    }

    pub(crate) fn job_storage(&self) -> Option<Arc<dyn storage::JobStorage>> {
        self.storage.get().cloned()
    }

    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner.read().expect("Bedrock state lock poisoned")
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.write().expect("Bedrock state lock poisoned")
    }

    /// The caller's account and Region, with timed transitions applied.
    pub(crate) fn scope<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut Scope) -> R) -> R {
        self.scope_in(&ctx.caller.account_id, &ctx.region, ctx.received_at, f)
    }

    pub(crate) fn scope_in<R>(
        &self,
        account: &str,
        region: &str,
        now: chrono::DateTime<chrono::Utc>,
        f: impl FnOnce(&mut Scope) -> R,
    ) -> R {
        let mut st = self.write();
        let scope = st.scopes.entry(scope_key(account, region)).or_default();
        scope.settle(now);
        f(scope)
    }

    /// The model invocation logging configuration of an account and
    /// Region, as `PutModelInvocationLoggingConfiguration` stored it.
    pub fn invocation_logging(&self, account: &str, region: &str) -> Option<generated::types::LoggingConfig> {
        let st = self.read();
        let doc = st.scopes.get(&scope_key(account, region))?.logging.clone()?;
        serde_json::from_value(doc).ok()
    }
}

#[async_trait::async_trait]
impl Service for Bedrock {
    fn signing_name(&self) -> &'static str {
        "bedrock"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        !is_runtime_path(request.uri().path())
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        let path = request.uri().path();
        [
            "/foundation-models",
            "/foundation-model-availability/",
            "/inference-profiles",
            "/guardrails",
            "/provisioned-model-throughput",
            "/custom-models",
            "/model-customization",
            "/model-invocation-job",
            "/model-import-jobs",
            "/model-copy-jobs",
            "/imported-models",
            "/evaluation-job",
            "/prompt-routers",
            "/logging/modelinvocations",
            "/marketplace-model/",
            "/automated-reasoning-policies",
            "/advanced-prompt-optimization-job",
        ]
        .iter()
        .any(|p| path.starts_with(p))
    }

    fn alternate_signature(&self, request: &HttpRequest) -> Option<Result<mws_core::AlternateSignature, ServiceError>> {
        // Bearer tokens with an API key's prefix are Bedrock's wherever they
        // go; other bearer tokens only on paths that are surely Bedrock's.
        let path = request.uri().path();
        if is_runtime_path(path) || !(self.recognizes(request) || api_key::token_type(request).is_some()) {
            return None;
        }
        api_key::alternate(request)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Err(e) = api_key::authorize(&ctx, &request) {
            return self.render_error(&ctx.request_id, &e);
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
        Some(serde_json::to_value(&*self.read()).expect("Bedrock state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Bedrock state: {e}"))?;
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
    }
}
