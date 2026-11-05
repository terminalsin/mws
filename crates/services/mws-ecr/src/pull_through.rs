//! Pull-through caches: a registry pull (`docker pull`) of
//! `<ecrRepositoryPrefix>/<upstream repository>` that the registry doesn't
//! hold yet fetches the manifest or blob from the rule's upstream
//! registry, creating the repository on first pull (from a
//! `PULL_THROUGH_CACHE` creation template when one applies), as ECR does.
//! Manifests are fetched when asked for and their layers when Docker asks
//! for each, so a multi-platform pull fetches only the platform it needs.

use std::collections::BTreeMap;
use std::sync::Arc;

use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext};
use mws_oci::client::{FetchError, Upstream};
use mws_oci::server::{self, RegistryError, Route};
use mws_oci::store::PutManifest;

use crate::generated::types;
use crate::names::{authorize_repo, now_ms, repository_arn};
use crate::repos::{build_repo, template_for, NewRepo};
use crate::Ecr;

/// How long a cached tag is served before it is checked upstream again.
const TAG_REFRESH_MS: i64 = 24 * 3600 * 1000;

/// How ECR reads a rule's `credentialArn` (a Secrets Manager secret with
/// `username` and `accessToken`), as the registry's account.
#[async_trait::async_trait]
pub trait UpstreamCredentials: Send + Sync {
    async fn credentials(
        &self,
        ctx: &RequestContext,
        account: &str,
        secret_arn: &str,
    ) -> Result<(String, String), String>;
}

/// What a registry request asks for.
enum Want {
    Manifest(String),
    Blob(String),
}

impl Ecr {
    /// Read pull-through credentials through `credentials`.
    pub fn set_upstream_credentials(&self, credentials: Arc<dyn UpstreamCredentials>) {
        let _ = self.inner.upstream_credentials.set(credentials);
    }

    /// Reach upstream registries at other API bases (`host` -> URL ending
    /// in `/v2`), e.g. a local mirror, instead of `https://<host>/v2`.
    pub fn set_upstream_endpoints(&self, endpoints: BTreeMap<String, String>) {
        let _ = self.inner.upstream_endpoints.set(endpoints);
    }

    /// Fill the cache for a registry pull that a pull-through cache rule
    /// covers. `Some` is an error to answer with instead of serving.
    pub(crate) async fn pull_through(&self, ctx: &RequestContext, request: &HttpRequest) -> Option<HttpResponse> {
        if !matches!(*request.method(), http::Method::GET | http::Method::HEAD) || ctx.caller.access_key_id.is_empty() {
            return None;
        }
        let rel = request.uri().path().strip_prefix("/v2")?;
        let (name, want) = match server::route(rel)? {
            Route::Manifest { name, reference } => (name, Want::Manifest(reference)),
            Route::Blob { name, digest } => (name, Want::Blob(digest)),
            _ => return None,
        };
        let (account, region) = crate::registry::host_registry(request)
            .unwrap_or_else(|| (ctx.caller.account_id.clone(), ctx.region.clone()));
        let now = now_ms(ctx);
        let (rule, repo_exists) = {
            let st = self.lock();
            let reg = st.registry(&account, &region)?;
            let rule = rule_for(&reg.pull_through, &name)?.clone();
            let repo = reg.repositories.get(&name);
            let fresh = repo.is_some_and(|r| match &want {
                // Tags are checked upstream again once a day, as ECR does.
                Want::Manifest(tag) if !tag.contains(':') => {
                    r.content.tags.contains_key(tag)
                        && r.upstream_checked.get(tag).is_none_or(|t| now - t < TAG_REFRESH_MS)
                }
                Want::Manifest(digest) => r.content.images.contains_key(digest),
                Want::Blob(d) => r.content.blobs.contains_key(d),
            });
            if fresh {
                return None;
            }
            (rule, repo.is_some())
        };
        let arn = repository_arn(&ctx.partition, &region, &account, &name);
        let deny = |e: mws_core::ServiceError| Some(server::error_response(&RegistryError::denied(e.message)));
        {
            let st = self.lock();
            let repo = st.registry(&account, &region).and_then(|r| r.repositories.get(&name));
            if let Err(e) = authorize_repo(ctx, "ecr:BatchImportUpstreamImage", &arn, repo, ConditionContext::new()) {
                return deny(e);
            }
        }
        if !repo_exists {
            if let Err(e) = authorize_repo(ctx, "ecr:CreateRepository", &arn, None, ConditionContext::new()) {
                return deny(e);
            }
        }
        let upstream_name = upstream_repository(&rule, &name);
        let upstream_kind = rule.upstream_registry.clone().unwrap_or_default();
        let url = rule.upstream_registry_url.clone().unwrap_or_default();
        let cached = matches!(&want, Want::Manifest(tag) if !tag.contains(':')) && repo_exists;
        let result = if upstream_kind == "ecr" {
            self.copy_from_ecr(&url, &upstream_name, &want)
        } else {
            let upstream = match self.upstream(ctx, &account, &rule, &url).await {
                Ok(u) => u,
                Err(m) => return Some(server::error_response(&RegistryError::new(401, "UNAUTHORIZED", m))),
            };
            match &want {
                Want::Manifest(reference) => upstream.manifest(&upstream_name, reference).await.map(Fetch::Manifest),
                Want::Blob(d) => upstream.blob(&upstream_name, d).await.map(|b| Fetch::Blob(d.clone(), b)),
            }
        };
        let fetched = match result {
            Ok(f) => f,
            // A tag already cached is served as it is when the upstream
            // can't be reached.
            Err(e) if cached => {
                tracing::warn!(rule = ?rule.ecr_repository_prefix, "pull through cache: serving the cached tag: {e}");
                return None;
            }
            // The registry then answers that it has no such content.
            Err(FetchError::NotFound) => return None,
            Err(FetchError::Unauthorized(m)) => {
                tracing::warn!(rule = ?rule.ecr_repository_prefix, "pull through cache: {m}");
                return Some(server::error_response(&RegistryError::new(401, "UNAUTHORIZED", m)));
            }
            Err(FetchError::Throttled) => {
                return Some(server::error_response(&RegistryError::new(
                    429,
                    "TOOMANYREQUESTS",
                    "The upstream registry is rate limiting requests. Try again later.",
                )));
            }
            Err(FetchError::Failed(m)) => {
                tracing::warn!(rule = ?rule.ecr_repository_prefix, "pull through cache: {m}");
                return Some(server::error_response(&RegistryError::new(
                    502,
                    "UNKNOWN",
                    format!("The image could not be pulled from the upstream registry: {m}"),
                )));
            }
        };
        let mut st = self.lock();
        let reg = st.registry_mut(&account, &region);
        if !reg.repositories.contains_key(&name) {
            let settings =
                template_for(reg, &name, "PULL_THROUGH_CACHE").map(NewRepo::from_template).unwrap_or_default();
            let repo = build_repo(&ctx.partition, reg, &name, now, settings);
            reg.repositories.insert(name.clone(), repo);
        }
        let repo = reg.repositories.get_mut(&name).expect("created");
        match fetched {
            Fetch::Manifest(f) => {
                let tag = match &want {
                    Want::Manifest(r) if !r.contains(':') => Some(r.clone()),
                    _ => None,
                };
                if let Some(t) = &tag {
                    repo.upstream_checked.insert(t.clone(), now);
                }
                let put = PutManifest { manifest: f.manifest, media_type: Some(f.media_type), tag, digest: None };
                if let Err(e) = repo.content.put_cached_manifest(&put, now, |_| false) {
                    tracing::warn!("pull through cache: the upstream manifest can't be stored: {e:?}");
                }
            }
            Fetch::Blob(d, data) => {
                repo.content.put_blob(&d, data.into(), now);
            }
        }
        None
    }

    async fn upstream(
        &self,
        ctx: &RequestContext,
        account: &str,
        rule: &types::PullThroughCacheRule,
        url: &str,
    ) -> Result<Upstream, String> {
        let base = self
            .inner
            .upstream_endpoints
            .get()
            .and_then(|e| e.get(url))
            .cloned()
            .unwrap_or_else(|| format!("https://{}/v2", url.trim_end_matches('/')));
        let credentials = match &rule.credential_arn {
            None => None,
            Some(arn) => {
                let Some(source) = self.inner.upstream_credentials.get() else {
                    return Err("The pull through cache rule's credentials can't be read.".into());
                };
                Some(source.credentials(ctx, account, arn).await?)
            }
        };
        Ok(Upstream { base, credentials })
    }

    /// An upstream ECR registry (`<account>.dkr.ecr.<region>.amazonaws.com`)
    /// is this emulator's own: copy from it directly.
    fn copy_from_ecr(&self, url: &str, repository: &str, want: &Want) -> Result<Fetch, FetchError> {
        let mut parts = url.split('.');
        let (Some(account), Some(_), Some(_), Some(region)) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(FetchError::Failed(format!("{url} is not an ECR registry")));
        };
        let st = self.lock();
        let repo =
            st.registry(account, region).and_then(|r| r.repositories.get(repository)).ok_or(FetchError::NotFound)?;
        match want {
            Want::Manifest(reference) => {
                let digest = repo.content.resolve_digest(reference).ok_or(FetchError::NotFound)?;
                if repo.status(&digest) != "ACTIVE" {
                    return Err(FetchError::NotFound);
                }
                let image = &repo.content.images[&digest];
                Ok(Fetch::Manifest(mws_oci::client::Fetched {
                    digest,
                    media_type: image.media_type.clone(),
                    manifest: image.manifest.clone(),
                }))
            }
            Want::Blob(d) => {
                let blob = repo.content.blobs.get(d).ok_or(FetchError::NotFound)?;
                Ok(Fetch::Blob(d.clone(), blob.data.to_vec()))
            }
        }
    }
}

enum Fetch {
    Manifest(mws_oci::client::Fetched),
    Blob(String, Vec<u8>),
}

/// The rule whose prefix `name` is under (the longest one).
fn rule_for<'a>(
    rules: &'a BTreeMap<String, types::PullThroughCacheRule>,
    name: &str,
) -> Option<&'a types::PullThroughCacheRule> {
    rules
        .iter()
        .filter(|(p, _)| p.as_str() == "ROOT" || name.starts_with(&format!("{p}/")))
        .max_by_key(|(p, _)| if p.as_str() == "ROOT" { 0 } else { p.len() })
        .map(|(_, r)| r)
}

/// The upstream repository a cached repository mirrors: the name after the
/// rule's prefix, under the rule's upstream prefix.
fn upstream_repository(rule: &types::PullThroughCacheRule, name: &str) -> String {
    let prefix = rule.ecr_repository_prefix.as_deref().unwrap_or("ROOT");
    let rest = if prefix == "ROOT" { name } else { &name[prefix.len() + 1..] };
    match rule.upstream_repository_prefix.as_deref() {
        None | Some("ROOT") => rest.to_string(),
        Some(p) => format!("{p}/{rest}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_map_to_upstream_repositories() {
        let rule = |prefix: &str, up: Option<&str>| types::PullThroughCacheRule {
            ecr_repository_prefix: Some(prefix.into()),
            upstream_repository_prefix: up.map(str::to_string),
            ..Default::default()
        };
        assert_eq!(upstream_repository(&rule("quay", Some("ROOT")), "quay/coreos/etcd"), "coreos/etcd");
        assert_eq!(upstream_repository(&rule("hub", Some("library")), "hub/alpine"), "library/alpine");
        let mut rules = BTreeMap::new();
        rules.insert("a".to_string(), rule("a", None));
        rules.insert("a/b".to_string(), rule("a/b", None));
        assert_eq!(rule_for(&rules, "a/b/c").unwrap().ecr_repository_prefix.as_deref(), Some("a/b"));
        assert!(rule_for(&rules, "ab/c").is_none());
    }
}
