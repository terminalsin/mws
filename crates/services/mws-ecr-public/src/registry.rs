//! The public registry endpoint: the Docker registry HTTP API v2 under
//! `/v2/public.ecr.aws/<alias>/<repository>/...`, and catalog logos.
//!
//! Pulls are anonymous, as on `public.ecr.aws`. Pushes carry the password
//! from `GetAuthorizationToken` (Basic, or as the bearer token the token
//! endpoint echoes back) and run as the caller who asked for it.

use bytes::Bytes;
use mws_core::{AlternateSignature, ConditionContext, HttpRequest, HttpResponse, RequestContext, ServiceError};
use mws_oci::server::{self, Op, RegistryError, TOKEN_PATH};
use mws_oci::store::{Image, PutManifest, PutOutcome, Repository};
use mws_oci::token;

use crate::ops::{authorize_repo, put_in, repository_arn};
use crate::{EcrPublic, AUDIENCE, LOGO_PATH, REGISTRY_PATH_PREFIX};

fn path(request: &HttpRequest) -> &str {
    request.uri().path()
}

fn base() -> String {
    format!("/v2/{REGISTRY_PATH_PREFIX}")
}

pub(crate) fn is_registry_request(request: &HttpRequest) -> bool {
    let p = path(request);
    p.starts_with(LOGO_PATH) || p.starts_with(&format!("{}/", base())) || is_own_ping(request)
}

/// `GET /v2/` with one of this service's passwords: `docker login` to the
/// public registry on MWS's address.
fn is_own_ping(request: &HttpRequest) -> bool {
    matches!(path(request), "/v2" | "/v2/")
        && password(request).and_then(|pw| token::claims(&pw)).is_some_and(|c| c.audience == AUDIENCE)
}

fn password(request: &HttpRequest) -> Option<String> {
    let h = request.headers().get(http::header::AUTHORIZATION)?.to_str().ok()?;
    token::password_from_header(h)
}

fn valid_claims(me: &EcrPublic, password: &str) -> Option<token::Claims> {
    let claims = token::claims(password)?;
    if claims.audience != AUDIENCE {
        return None;
    }
    let key = me.lock().token_key.clone();
    token::verify(password, &key, chrono::Utc::now().timestamp()).ok()
}

/// Credentials that are not one of this service's valid passwords run as
/// anonymous (public pulls need none).
pub(crate) fn is_anonymous_token(me: &EcrPublic, request: &HttpRequest) -> bool {
    match password(request) {
        None => false,
        Some(p) => valid_claims(me, &p).is_none(),
    }
}

pub(crate) fn alternate_signature(
    me: &EcrPublic,
    request: &HttpRequest,
) -> Option<Result<AlternateSignature, ServiceError>> {
    if !is_registry_request(request) {
        return None;
    }
    let claims = valid_claims(me, &password(request)?)?;
    Some(Ok(AlternateSignature {
        access_key_id: claims.access_key_id,
        session_token: claims.session_token,
        region: Some(claims.region),
        verify: Box::new(|_, _| Ok(())),
    }))
}

fn host(request: &HttpRequest) -> String {
    request.headers().get(http::header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("localhost:4566").to_string()
}

pub(crate) fn serve(me: &EcrPublic, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let p = path(request).to_string();
    if let Some(rest) = p.strip_prefix(LOGO_PATH) {
        return logo(me, rest);
    }
    let challenge = format!("Bearer realm=\"http://{}{TOKEN_PATH}\",service=\"public.ecr.aws\"", host(request));
    let backend = Backend { me, challenge };
    let b = base();
    if is_own_ping(request) {
        return server::serve(&backend, ctx, request, "/v2", "/");
    }
    let rel = p.strip_prefix(&b).unwrap_or("");
    server::serve(&backend, ctx, request, &b, rel)
}

fn not_found() -> HttpResponse {
    http::Response::builder().status(404).body(Bytes::from_static(b"Not Found")).expect("valid response")
}

fn logo(me: &EcrPublic, rest: &str) -> HttpResponse {
    use base64::Engine;
    let Some((account, name)) = rest.split_once('/') else { return not_found() };
    let st = me.lock();
    let data = st
        .registries
        .get(account)
        .and_then(|r| r.repositories.get(name))
        .and_then(|r| r.catalog.logo.as_ref())
        .and_then(|l| base64::engine::general_purpose::STANDARD.decode(l).ok());
    let Some(data) = data else { return not_found() };
    let ct = if data.starts_with(&[0x89, b'P']) { "image/png" } else { "image/jpeg" };
    http::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, ct)
        .body(Bytes::from(data))
        .expect("valid response")
}

struct Backend<'a> {
    me: &'a EcrPublic,
    challenge: String,
}

fn action(op: Op) -> Option<&'static str> {
    match op {
        Op::UploadStart => Some("ecr-public:InitiateLayerUpload"),
        Op::UploadPart => Some("ecr-public:UploadLayerPart"),
        Op::UploadComplete => Some("ecr-public:CompleteLayerUpload"),
        Op::ManifestWrite => Some("ecr-public:PutImage"),
        Op::ManifestDelete => Some("ecr-public:BatchDeleteImage"),
        // Pulls from a public registry need no credentials.
        Op::BlobCheck | Op::BlobRead | Op::ManifestRead | Op::ReferrersList | Op::TagList => None,
    }
}

fn registry_error(e: ServiceError) -> RegistryError {
    match e.code.as_ref() {
        "AccessDeniedException" | "AccessDenied" => RegistryError::denied(e.message),
        "RepositoryNotFoundException" | "RegistryNotFoundException" => RegistryError::name_unknown(e.message),
        "ImageTagAlreadyExistsException" => RegistryError::new(400, "TAG_INVALID", e.message),
        "LayersNotFoundException" | "ReferencedImagesNotFoundException" => {
            RegistryError::new(400, "MANIFEST_BLOB_UNKNOWN", e.message)
        }
        "ImageDigestDoesNotMatchException" => RegistryError::new(400, "DIGEST_INVALID", e.message),
        "InvalidParameterException" => RegistryError::new(400, "MANIFEST_INVALID", e.message),
        _ => RegistryError::new(e.status, "UNKNOWN", e.message),
    }
}

impl Backend<'_> {
    /// Authorize `op` on `<alias>/<repository>` and run `f` on the repo.
    fn open<R>(
        &self,
        ctx: &RequestContext,
        full: &str,
        op: Op,
        f: impl FnOnce(&mut crate::state::Repo, &str) -> Result<R, RegistryError>,
    ) -> Result<R, RegistryError> {
        let unknown = || RegistryError::name_unknown(format!("The repository '{full}' does not exist"));
        let (alias, name) = full.split_once('/').ok_or_else(unknown)?;
        let action = action(op);
        if action.is_some() && ctx.caller.access_key_id.is_empty() {
            return Err(RegistryError::unauthorized(&self.challenge, "Not Authorized"));
        }
        let mut st = self.me.lock();
        let account = st.account_of(alias).ok_or_else(unknown)?;
        let reg = st.registries.get_mut(&account).expect("found");
        if let Some(action) = action {
            let arn = repository_arn(&ctx.partition, &account, name);
            authorize_repo(ctx, action, &arn, reg.repositories.get(name), ConditionContext::new())
                .map_err(registry_error)?;
        }
        let repo = reg.repositories.get_mut(name).ok_or_else(unknown)?;
        f(repo, &account)
    }
}

impl server::Backend for Backend<'_> {
    fn ping(&self, ctx: &RequestContext) -> Result<(), RegistryError> {
        if ctx.caller.access_key_id.is_empty() {
            return Err(RegistryError::unauthorized(&self.challenge, "Not Authorized"));
        }
        Ok(())
    }

    fn with_repository<R>(
        &self,
        ctx: &RequestContext,
        name: &str,
        op: Op,
        f: impl FnOnce(&mut Repository) -> Result<R, RegistryError>,
    ) -> Result<R, RegistryError> {
        self.open(ctx, name, op, |repo, _| f(&mut repo.content))
    }

    fn put_manifest(&self, ctx: &RequestContext, name: &str, put: PutManifest) -> Result<PutOutcome, RegistryError> {
        let now = ctx.received_at.timestamp_millis();
        self.open(ctx, name, Op::ManifestWrite, |repo, account| {
            put_in(repo, account, &put, now, false).map_err(registry_error)
        })
    }

    fn get_manifest(&self, ctx: &RequestContext, name: &str, reference: &str) -> Result<Image, RegistryError> {
        self.open(ctx, name, Op::ManifestRead, |repo, _| {
            let image = repo.content.resolve(reference).cloned().ok_or_else(|| {
                RegistryError::manifest_unknown(format!(
                    "Requested image not found: the image with reference '{reference}' does not exist in the repository '{name}'"
                ))
            })?;
            Ok(image)
        })
    }

    fn delete_manifest(&self, ctx: &RequestContext, name: &str, reference: &str) -> Result<(), RegistryError> {
        self.open(ctx, name, Op::ManifestDelete, |repo, _| {
            let unknown =
                || RegistryError::manifest_unknown(format!("The image '{reference}' does not exist in '{name}'"));
            if !reference.contains(':') {
                repo.content.untag(reference).ok_or_else(unknown)?;
                repo.tag_times.remove(reference);
                return Ok(());
            }
            if repo.content.referenced_by_index(reference) {
                return Err(RegistryError::new(400, "DENIED", "Requested image referenced by manifest list"));
            }
            for t in repo.content.tags_of(reference) {
                repo.tag_times.remove(&t);
            }
            repo.content.delete_image(reference).ok_or_else(unknown)?;
            Ok(())
        })
    }
}
