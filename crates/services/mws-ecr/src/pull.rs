//! Pulls on behalf of other services (Lambda container images): resolving
//! an image URI to a repository and digest, checking the caller may pull it,
//! and handing over the manifest, config and layers.

use bytes::Bytes;
use mws_core::{ConditionContext, RequestContext};
use mws_oci::manifest::{DOCKER_CONFIG, DOCKER_SCHEMA2, OCI_CONFIG, OCI_MANIFEST};
use mws_oci::Descriptor;

use crate::images::pull_time_excluded;
use crate::names::{authorize_repo, now_ms, repository_arn};
use crate::Ecr;

/// Where an image URI points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLocation {
    pub account: String,
    pub region: String,
    pub repository: String,
    /// A tag, or a digest (`sha256:...`).
    pub reference: String,
}

/// One single-platform image, with everything needed to run it.
#[derive(Debug, Clone)]
pub struct PulledImage {
    pub location: ImageLocation,
    /// The digest the reference resolved to (an index's, for multi-platform
    /// images).
    pub resolved_digest: String,
    /// The digest of the (platform) manifest below.
    pub digest: String,
    pub manifest: String,
    pub media_type: String,
    pub config: Descriptor,
    pub config_data: Bytes,
    /// Each layer with its content, base layer first.
    pub layers: Vec<(Descriptor, Bytes)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullError {
    /// No such repository or image.
    NotFound,
    /// The caller may not pull it (`ecr:BatchGetImage`,
    /// `ecr:GetDownloadUrlForLayer`).
    AccessDenied,
    /// Not a runnable image: an artifact, a schema 1 manifest, or an index
    /// with no manifest for the platform.
    Unsupported,
}

impl Ecr {
    /// Whether `ctx`'s caller may log in to the registry
    /// (`ecr:GetAuthorizationToken`), as a service pulling with the
    /// caller's credentials does first (ECS with a task's execution role).
    pub fn authorize_registry_login(&self, ctx: &RequestContext) -> Result<(), mws_core::ServiceError> {
        crate::names::authorize_registry(ctx, "ecr:GetAuthorizationToken", "*")
    }

    /// The repository and reference an image URI names. URIs use AWS's
    /// registry host (`<account>.dkr.ecr.<region>.amazonaws.com`) or the one
    /// repository URIs name (`MWS_ECR_REGISTRY_HOST`); when that host does
    /// not carry the account or Region, they are `account` and `region`.
    pub fn locate_image(&self, uri: &str, account: &str, region: &str) -> Option<ImageLocation> {
        let (host, path) = self.split_registry(uri, account, region)?;
        let (account, region) = host;
        let (repository, reference) = match path.rsplit_once('@') {
            Some((r, d)) => (r, d.to_string()),
            None => match path.rsplit_once(':').filter(|(r, t)| !t.contains('/') && !r.is_empty()) {
                Some((r, t)) => (r, t.to_string()),
                None => (path, "latest".to_string()),
            },
        };
        let valid_name = regex::Regex::new(r"^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*$")
            .expect("valid regex")
            .is_match(repository);
        let valid_ref = if reference.contains(':') {
            reference.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        } else {
            mws_oci::store::is_valid_tag(&reference)
        };
        (valid_name && valid_ref).then(|| ImageLocation {
            account,
            region,
            repository: repository.to_string(),
            reference,
        })
    }

    /// The `(account, region)` of a URI's registry host, and the rest.
    fn split_registry<'a>(&self, uri: &'a str, account: &str, region: &str) -> Option<((String, String), &'a str)> {
        let aws = regex::Regex::new(r"^(\d{12})\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?/(.+)$")
            .expect("valid regex");
        if let Some(c) = aws.captures(uri) {
            let rest = c.get(3).expect("group").as_str();
            return Some(((c[1].to_string(), c[2].to_string()), rest));
        }
        let template = self.inner.registry_host.get()?;
        let pattern = regex::escape(template)
            .replace(r"\{account\}", r"(?P<account>\d{12})")
            .replace(r"\{region\}", r"(?P<region>[a-z0-9-]+)");
        let re = regex::Regex::new(&format!("^{pattern}/(?P<rest>.+)$")).ok()?;
        let c = re.captures(uri)?;
        let a = c.name("account").map_or(account, |m| m.as_str()).to_string();
        let r = c.name("region").map_or(region, |m| m.as_str()).to_string();
        let rest = c.name("rest").expect("group").as_str();
        Some(((a, r), rest))
    }

    /// `<registry host>/<repository>@<digest>`, as repository URIs name
    /// the registry.
    pub fn image_uri(&self, location: &ImageLocation, digest: &str) -> String {
        format!("{}/{}@{digest}", self.registry_host(&location.account, &location.region), location.repository)
    }

    /// Pull an image for a service. With a request context, the caller
    /// must be allowed to pull it (identity or repository policy), and the
    /// pull is recorded as AWS records Lambda's; without one, the service
    /// pulls content it already resolved. `architecture` (`amd64`,
    /// `arm64`) picks the manifest of an index.
    pub fn pull_image(
        &self,
        ctx: Option<&RequestContext>,
        location: &ImageLocation,
        architecture: &str,
    ) -> Result<PulledImage, PullError> {
        if let Some(ctx) = ctx {
            self.settle(ctx);
        }
        let mut st = self.lock();
        let Some(reg) = st.registries.get_mut(&format!("{}/{}", location.account, location.region)) else {
            return Err(PullError::NotFound);
        };
        let excluded = ctx.is_some_and(|c| pull_time_excluded(reg, c));
        let repo = reg.repositories.get(&location.repository);
        if let Some(ctx) = ctx {
            let arn = repository_arn(&ctx.partition, &location.region, &location.account, &location.repository);
            for action in ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"] {
                if authorize_repo(ctx, action, &arn, repo, ConditionContext::new()).is_err() {
                    return Err(match repo {
                        None => PullError::NotFound,
                        Some(_) => PullError::AccessDenied,
                    });
                }
            }
        }
        let repo = reg.repositories.get_mut(&location.repository).ok_or(PullError::NotFound)?;
        let mut digest = repo.content.resolve_digest(&location.reference).ok_or(PullError::NotFound)?;
        let top = digest.clone();
        if repo.status(&digest) != "ACTIVE" {
            return Err(PullError::NotFound);
        }
        let mut image = repo.content.images.get(&digest).cloned().ok_or(PullError::NotFound)?;
        let mut parsed = image.parsed().ok_or(PullError::Unsupported)?;
        if parsed.is_index() {
            let child = parsed
                .manifests
                .iter()
                .find(|m| {
                    let p = m.platform.as_ref();
                    p.and_then(|p| p["os"].as_str()) == Some("linux")
                        && p.and_then(|p| p["architecture"].as_str()) == Some(architecture)
                })
                .ok_or(PullError::Unsupported)?;
            digest = child.digest.clone();
            image = repo.content.images.get(&digest).cloned().ok_or(PullError::NotFound)?;
            parsed = image.parsed().ok_or(PullError::Unsupported)?;
        }
        if !matches!(parsed.media_type.as_str(), DOCKER_SCHEMA2 | OCI_MANIFEST) {
            return Err(PullError::Unsupported);
        }
        let config = parsed.config.clone().ok_or(PullError::Unsupported)?;
        if !matches!(config.media_type.as_str(), DOCKER_CONFIG | OCI_CONFIG) {
            return Err(PullError::Unsupported);
        }
        let blob = |d: &Descriptor| repo.content.blobs.get(&d.digest).map(|b| b.data.clone());
        let config_data = blob(&config).ok_or(PullError::NotFound)?;
        let mut layers = Vec::new();
        for l in &parsed.layers {
            if !l.is_distributable() {
                return Err(PullError::Unsupported);
            }
            layers.push((l.clone(), blob(l).ok_or(PullError::NotFound)?));
        }
        if let (Some(ctx), false) = (ctx, excluded) {
            let now = now_ms(ctx);
            for d in [&top, &digest] {
                if let Some(i) = repo.content.images.get_mut(d) {
                    i.last_pulled_at = Some(now);
                }
            }
        }
        Ok(PulledImage {
            location: location.clone(),
            resolved_digest: top,
            digest,
            manifest: image.manifest.clone(),
            media_type: image.media_type.clone(),
            config,
            config_data,
            layers,
        })
    }
}
