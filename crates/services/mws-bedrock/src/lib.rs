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

pub mod catalog;
pub mod guard;
mod handler;
mod jobs;
mod models;
mod ops;
mod profiles;
mod reasoning;
mod resolve;
mod state;
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

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
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
