//! AWS CodeArtifact for MWS.
//!
//! Domains, repositories (with upstreams and external connections),
//! packages, package versions and package groups, as in CodeArtifact. The
//! repository endpoints `GetRepositoryEndpoint` hands out really serve the
//! npm, PyPI and Maven protocols, so `npm`, `pip`, `twine`, Maven and
//! Gradle publish to and install from them with a token from
//! `GetAuthorizationToken` (see [`endpoints`]).
//!
//! AWS couples CodeArtifact to KMS (domain assets are encrypted with a KMS
//! key, `aws/codeartifact` by default), so this crate uses its public API.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/codeartifact_generated.rs"));
}

mod domains;
pub mod endpoints;
mod external;
mod groups;
mod handler;
mod http;
mod names;
mod package_groups;
mod packages;
mod repositories;
mod state;
mod upstream;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

pub(crate) struct Inner {
    state: RwLock<State>,
    kms: Option<mws_kms::Kms>,
    /// External connection name to the registry it reads from, overriding
    /// the public registry (tests, mirrors). An empty URL turns the
    /// connection off.
    registries: RwLock<BTreeMap<String, String>>,
}

/// The CodeArtifact service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct CodeArtifact {
    inner: Arc<Inner>,
}

impl Default for CodeArtifact {
    fn default() -> Self {
        Self::new(None)
    }
}

impl CodeArtifact {
    /// CodeArtifact, with KMS for domain encryption keys when given.
    pub fn new(kms: Option<mws_kms::Kms>) -> Self {
        let mut registries = BTreeMap::new();
        for (name, _) in external::CONNECTIONS {
            let var = format!(
                "MWS_CODEARTIFACT_{}_URL",
                name.trim_start_matches("public:").replace('-', "_").to_ascii_uppercase()
            );
            if let Ok(url) = std::env::var(&var) {
                registries.insert(name.to_string(), url);
            }
        }
        Self {
            inner: Arc::new(Inner { state: RwLock::new(State::default()), kms, registries: RwLock::new(registries) }),
        }
    }

    /// Make external connection `connection` (`public:npmjs`, ...) read
    /// from `url` instead of the public registry; an empty URL turns it
    /// off. `MWS_CODEARTIFACT_<NAME>_URL` (e.g. `MWS_CODEARTIFACT_NPMJS_URL`)
    /// does the same.
    pub fn set_registry_url(&self, connection: &str, url: &str) {
        self.inner.registries.write().expect("registries lock").insert(connection.to_string(), url.to_string());
    }

    pub(crate) fn registry_url(&self, connection: &str) -> Option<String> {
        if let Some(url) = self.inner.registries.read().expect("registries lock").get(connection) {
            return (!url.is_empty()).then(|| url.trim_end_matches('/').to_string());
        }
        external::default_registry(connection).map(str::to_string)
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner.state.read().expect("CodeArtifact state lock poisoned")
    }

    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.state.write().expect("CodeArtifact state lock poisoned")
    }

    /// The domain owner a request names, defaulting to the caller's
    /// account.
    pub(crate) fn owner(ctx: &RequestContext, domain_owner: Option<&str>) -> String {
        domain_owner.filter(|o| !o.is_empty()).map(str::to_string).unwrap_or_else(|| ctx.caller.account_id.clone())
    }

    pub(crate) fn key(ctx: &RequestContext, owner: &str, domain: &str) -> String {
        state::domain_key(&ctx.region, owner, domain)
    }

    /// Authorize a domain-level action, with the domain's policy.
    pub(crate) fn authorize_domain(
        &self,
        ctx: &RequestContext,
        owner: &str,
        domain: &str,
        action: &str,
    ) -> Result<(), ServiceError> {
        let arn = names::domain_arn(&ctx.partition, &ctx.region, owner, domain);
        let (policy, tags) = {
            let st = self.read();
            match st.domains.get(&Self::key(ctx, owner, domain)) {
                Some(d) => (d.policy.as_ref().map(|p| p.document.clone()), d.tags.clone()),
                None => (None, BTreeMap::new()),
            }
        };
        ctx.authorize_with_resource_policy(action, &arn, policy.as_deref(), resource_tags(&tags))
    }

    /// Authorize a repository- or package-level action on `resource`
    /// (the repository's ARN, or a package's), with the repository's
    /// policy.
    pub(crate) fn authorize_repo(
        &self,
        ctx: &RequestContext,
        owner: &str,
        domain: &str,
        repo: &str,
        action: &str,
        resource: Option<&str>,
    ) -> Result<(), ServiceError> {
        let arn = names::repository_arn(&ctx.partition, &ctx.region, owner, domain, repo);
        let (policy, tags) = {
            let st = self.read();
            match st.domains.get(&Self::key(ctx, owner, domain)).and_then(|d| d.repositories.get(repo)) {
                Some(r) => (r.policy.as_ref().map(|p| p.document.clone()), r.tags.clone()),
                None => (None, BTreeMap::new()),
            }
        };
        let mut cond = ConditionContext::new();
        if resource.is_none() {
            cond = resource_tags(&tags);
        }
        ctx.authorize_with_resource_policy(action, resource.unwrap_or(&arn), policy.as_deref(), cond)
    }
}

pub(crate) fn resource_tags(tags: &BTreeMap<String, String>) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

pub(crate) fn request_tags(tags: &[generated::types::Tag]) -> ConditionContext {
    let mut c: ConditionContext =
        tags.iter().map(|t| (format!("aws:RequestTag/{}", t.key), vec![t.value.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

#[async_trait::async_trait]
impl Service for CodeArtifact {
    fn signing_name(&self) -> &'static str {
        "codeartifact"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        endpoints::target(request).is_some()
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        endpoints::target(request).is_some()
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some(target) = endpoints::target(&request) {
            return self.serve_endpoint(ctx, request, target).await;
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
        Some(serde_json::to_value(&*self.read()).expect("CodeArtifact state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid CodeArtifact state: {e}"))?;
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
    }
}
