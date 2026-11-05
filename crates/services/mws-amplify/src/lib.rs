//! AWS Amplify Hosting for MWS.
//!
//! Apps, branches, backend environments, domain associations, webhooks and
//! jobs are kept as Amplify keeps them, and deployments are really served:
//!
//! - Manual deployments (`CreateDeployment`, upload the zip or files to the
//!   returned URLs, `StartDeployment`) and deployments from a source URL
//!   (`s3://bucket/key.zip`, `s3://bucket/prefix/`, or an HTTP(S) zip) are
//!   unpacked and become the branch's site.
//! - Apps connected to a Git repository build for real: `StartJob` (or a
//!   webhook call) clones the repository, runs the build spec's commands
//!   with `sh` and deploys `artifacts.baseDirectory`.
//! - Sites are served at `https://<branch>.<appId>.amplifyapp.com` when a
//!   request's `Host` names that host (any `amplifyapp.*` suffix works, so
//!   `http://main.<appId>.amplifyapp.localhost:4566` opens in a browser),
//!   on associated custom domains, and at
//!   `<endpoint>/_aws/amplify/sites/<appId>/<branch>/<path>`. Rewrites and
//!   redirects (`customRules`), basic auth, custom headers and access logs
//!   behave as in Amplify.
//!
//! AWS couples Amplify to S3 (deploying from buckets, as the
//! `amplify.amazonaws.com` service principal judged by the bucket policy)
//! and Route 53 (custom domain records and verification), so this crate
//! uses their public APIs.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/amplify_generated.rs"));
}

mod apps;
mod builder;
mod deploy;
mod domains;
mod handler;
mod hosting;
mod http;
mod jobs;
mod names;
mod rules;
mod state;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

pub(crate) struct Inner {
    state: RwLock<State>,
    s3: Option<mws_s3::S3>,
    route53: Option<mws_route53::Route53>,
    /// Running jobs that can be stopped, by `appId/branch/jobId`.
    running: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    /// One job at a time per branch, by `appId/branch`.
    branch_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

/// The Amplify service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Amplify {
    inner: Arc<Inner>,
}

impl Default for Amplify {
    fn default() -> Self {
        Self::new()
    }
}

impl Amplify {
    pub fn new() -> Self {
        Self::build(None, None)
    }

    /// Amplify wired to the services AWS couples it to: S3 for deployments
    /// from buckets, Route 53 for custom domains.
    pub fn with_services(s3: mws_s3::S3, route53: mws_route53::Route53) -> Self {
        Self::build(Some(s3), Some(route53))
    }

    fn build(s3: Option<mws_s3::S3>, route53: Option<mws_route53::Route53>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(State::default()),
                s3,
                route53,
                running: Mutex::new(HashMap::new()),
                branch_locks: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner.state.read().expect("Amplify state lock poisoned")
    }

    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.state.write().expect("Amplify state lock poisoned")
    }

    fn stop_all_jobs(&self) {
        for (_, stop) in self.inner.running.lock().expect("running jobs lock").drain() {
            stop.notify_one();
        }
    }
}

#[async_trait::async_trait]
impl Service for Amplify {
    fn signing_name(&self) -> &'static str {
        "amplify"
    }

    fn serves_unauthenticated(&self, request: &HttpRequest) -> bool {
        hosting::is_site_request(self, request) || hosting::is_side_channel(request)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some(response) = self.serve_side_channel(&ctx, &request).await {
            return response;
        }
        if let Some(response) = self.serve_site(&ctx, &request).await {
            return response;
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
        Some(serde_json::to_value(&*self.read()).expect("Amplify state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Amplify state: {e}"))?;
        self.stop_all_jobs();
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        self.stop_all_jobs();
        *self.write() = State::default();
    }
}
