//! The registry endpoint: the Docker registry HTTP API v2 under `/v2/`,
//! bearer tokens for clients that ask for them, and layer download links
//! (`GetDownloadUrlForLayer`).
//!
//! Requests carry the password from `GetAuthorizationToken` as HTTP Basic
//! credentials (`AWS:<password>`) or as a bearer token; the gateway then
//! runs them as the caller who asked for the password. Requests without
//! one are anonymous and get a `401` challenge.

use bytes::Bytes;
use mws_core::{AlternateSignature, ConditionContext, HttpRequest, HttpResponse, RequestContext, ServiceError};
use mws_oci::server::{self, Op, RegistryError, TOKEN_PATH};
use mws_oci::store::{Image, PutManifest, PutOutcome, Repository};
use mws_oci::token;

use crate::images::{pull_time_excluded, Via};
use crate::names::{authorize_repo, now_ms, repository_arn};
use crate::repos::{build_repo, template_for, NewRepo};
use crate::{Ecr, AUDIENCE, LAYER_PATH};

/// The bearer token anonymous clients get.
const ANONYMOUS: &str = "anonymous";
/// How long a layer download link lasts.
const LAYER_URL_MS: i64 = 3600 * 1000;

fn path(request: &HttpRequest) -> &str {
    request.uri().path()
}

impl Ecr {
    /// Leave registry paths under `/v2/<prefix>/` to another service (ECR
    /// Public serves its repositories there).
    pub fn exclude_registry_prefix(&self, prefix: impl Into<String>) {
        let _ = self.inner.excluded_prefix.set(prefix.into());
    }

    pub(crate) fn is_registry_request(&self, request: &HttpRequest) -> bool {
        let p = path(request);
        if p.starts_with(LAYER_PATH) || p == TOKEN_PATH {
            return true;
        }
        if p != "/v2" && !p.starts_with("/v2/") {
            return false;
        }
        if p == "/v2" || p == "/v2/" {
            // A ping with another registry's password (`docker login` to ECR
            // Public on the same address) is that registry's.
            return password(request).and_then(|pw| token::claims(&pw)).is_none_or(|c| c.audience == AUDIENCE);
        }
        match self.inner.excluded_prefix.get() {
            Some(prefix) => !p["/v2".len()..].trim_start_matches('/').starts_with(&format!("{prefix}/")),
            None => true,
        }
    }
}

fn password(request: &HttpRequest) -> Option<String> {
    let h = request.headers().get(http::header::AUTHORIZATION)?.to_str().ok()?;
    token::password_from_header(h)
}

/// Whether the request carries credentials that are not one of this
/// service's valid passwords (anonymous bearer tokens, expired or foreign
/// passwords): such requests run as anonymous.
pub(crate) fn is_anonymous_token(ecr: &Ecr, request: &HttpRequest) -> bool {
    if path(request) == TOKEN_PATH {
        return true;
    }
    match password(request) {
        None => false,
        Some(p) => valid_claims(ecr, &p).is_none(),
    }
}

fn valid_claims(ecr: &Ecr, password: &str) -> Option<token::Claims> {
    let claims = token::claims(password)?;
    if claims.audience != AUDIENCE {
        return None;
    }
    let key = ecr.lock().token_key.clone();
    token::verify(password, &key, chrono::Utc::now().timestamp()).ok()
}

pub(crate) fn alternate_signature(
    ecr: &Ecr,
    request: &HttpRequest,
) -> Option<Result<AlternateSignature, ServiceError>> {
    if !ecr.is_registry_request(request) || path(request) == TOKEN_PATH {
        return None;
    }
    let claims = valid_claims(ecr, &password(request)?)?;
    Some(Ok(AlternateSignature {
        access_key_id: claims.access_key_id,
        session_token: claims.session_token,
        region: Some(claims.region),
        verify: Box::new(|_, _| Ok(())),
    }))
}

/// A signed, expiring path segment for a layer download link.
pub(crate) fn layer_url_token(key: &str, account: &str, region: &str, repo: &str, digest: &str, now: i64) -> String {
    let payload = serde_json::json!({"a": account, "r": region, "n": repo, "d": digest, "e": now + LAYER_URL_MS});
    token::seal(&payload.to_string(), key)
}

/// `(account, region)` named by a `Host` of the form
/// `<account>.dkr.ecr.<region>.<anything>`.
fn host_registry(request: &HttpRequest) -> Option<(String, String)> {
    let host = request.headers().get(http::header::HOST)?.to_str().ok()?;
    let mut parts = host.split('.');
    let account = parts.next()?;
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if parts.next()? != "dkr" || parts.next()? != "ecr" {
        return None;
    }
    Some((account.to_string(), parts.next()?.to_string()))
}

fn host(request: &HttpRequest) -> String {
    request.headers().get(http::header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("localhost:4566").to_string()
}

pub(crate) fn serve(ecr: &Ecr, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let p = path(request).to_string();
    if let Some(t) = p.strip_prefix(LAYER_PATH) {
        return download_layer(ecr, ctx, t);
    }
    if p == TOKEN_PATH {
        return token_response(ctx, request);
    }
    let by_host = host_registry(request);
    let (account, region) = by_host.clone().unwrap_or_else(|| (ctx.caller.account_id.clone(), ctx.region.clone()));
    let host = host(request);
    let challenge = if by_host.is_some() {
        format!("Basic realm=\"https://{host}/\",service=\"ecr.amazonaws.com\"")
    } else {
        format!("Bearer realm=\"http://{host}{TOKEN_PATH}\",service=\"ecr.amazonaws.com\"")
    };
    let backend = Backend { ecr, account, region, challenge };
    let rel = p.strip_prefix("/v2").unwrap_or("");
    server::serve(&backend, ctx, request, "/v2", rel)
}

/// The bearer token endpoint: a client that presents a registry password
/// (HTTP Basic on `GET`, the OAuth2 password grant on `POST`) gets it back
/// as its bearer token, which registry requests then check; others get an
/// anonymous token.
fn token_response(ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let form = || form_urlencoded::parse(request.body()).find(|(k, _)| k == "password").map(|(_, v)| v.into_owned());
    let token =
        password(request).or_else(form).filter(|p| token::claims(p).is_some()).unwrap_or_else(|| ANONYMOUS.into());
    let body = serde_json::json!({
        "token": token,
        "access_token": token,
        "expires_in": crate::images::TOKEN_HOURS * 3600,
        "issued_at": ctx.received_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    http::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body.to_string()))
        .expect("valid response")
}

fn download_layer(ecr: &Ecr, ctx: &RequestContext, t: &str) -> HttpResponse {
    let denied = || {
        http::Response::builder()
            .status(403)
            .header(http::header::CONTENT_TYPE, "application/xml")
            .body(Bytes::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code><Message>Request has expired</Message></Error>",
            ))
            .expect("valid response")
    };
    let st = ecr.lock();
    let Some(payload) = token::open(t, &st.token_key) else { return denied() };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) else { return denied() };
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
    if v.get("e").and_then(|e| e.as_i64()).unwrap_or(0) < now_ms(ctx) {
        return denied();
    }
    let blob = st
        .registry(&field("a"), &field("r"))
        .and_then(|r| r.repositories.get(&field("n")))
        .and_then(|r| r.content.blobs.get(&field("d")))
        .map(|b| b.data.clone());
    match blob {
        Some(data) => http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .header(http::header::CONTENT_LENGTH, data.len().to_string())
            .body(data)
            .expect("valid response"),
        None => denied(),
    }
}

struct Backend<'a> {
    ecr: &'a Ecr,
    account: String,
    region: String,
    challenge: String,
}

fn action(op: Op) -> &'static str {
    match op {
        Op::BlobCheck => "ecr:BatchCheckLayerAvailability",
        Op::BlobRead => "ecr:GetDownloadUrlForLayer",
        Op::UploadStart => "ecr:InitiateLayerUpload",
        Op::UploadPart => "ecr:UploadLayerPart",
        Op::UploadComplete => "ecr:CompleteLayerUpload",
        Op::ManifestRead | Op::ReferrersList => "ecr:BatchGetImage",
        Op::ManifestWrite => "ecr:PutImage",
        Op::ManifestDelete => "ecr:BatchDeleteImage",
        Op::TagList => "ecr:ListImages",
    }
}

/// An API error as the registry protocol reports it.
fn registry_error(e: ServiceError) -> RegistryError {
    let code = e.code.to_string();
    match code.as_str() {
        "AccessDeniedException" | "AccessDenied" => RegistryError::denied(e.message),
        "RepositoryNotFoundException" => RegistryError::name_unknown(e.message),
        "ImageTagAlreadyExistsException" => RegistryError::new(400, "TAG_INVALID", e.message),
        "LayersNotFoundException" | "ReferencedImagesNotFoundException" => {
            RegistryError::new(400, "MANIFEST_BLOB_UNKNOWN", e.message)
        }
        "ImageDigestDoesNotMatchException" => RegistryError::new(400, "DIGEST_INVALID", e.message),
        "ImageNotFoundException" => RegistryError::manifest_unknown(e.message),
        "InvalidParameterException" => RegistryError::new(400, "MANIFEST_INVALID", e.message),
        "LimitExceededException" => RegistryError::new(429, "TOOMANYREQUESTS", e.message),
        _ => RegistryError::new(e.status, "UNKNOWN", e.message),
    }
}

impl Backend<'_> {
    fn require_caller(&self, ctx: &RequestContext) -> Result<(), RegistryError> {
        if ctx.caller.access_key_id.is_empty() {
            return Err(RegistryError::unauthorized(&self.challenge, "Not Authorized"));
        }
        Ok(())
    }

    /// Authorize `op` on repository `name`, creating it on push when a
    /// creation template says so.
    fn open<R>(
        &self,
        ctx: &RequestContext,
        name: &str,
        op: Op,
        f: impl FnOnce(&mut crate::state::State) -> Result<R, RegistryError>,
    ) -> Result<R, RegistryError> {
        self.require_caller(ctx)?;
        let arn = repository_arn(&ctx.partition, &self.region, &self.account, name);
        let mut st = self.ecr.lock();
        let reg = st.registry_mut(&self.account, &self.region);
        authorize_repo(ctx, action(op), &arn, reg.repositories.get(name), ConditionContext::new())
            .map_err(registry_error)?;
        if !reg.repositories.contains_key(name) {
            let push = matches!(op, Op::UploadStart | Op::ManifestWrite | Op::UploadComplete);
            let template = template_for(reg, name, "CREATE_ON_PUSH").filter(|_| push).cloned();
            let Some(template) = template else {
                return Err(RegistryError::name_unknown(format!(
                    "The repository with name '{name}' does not exist in the registry with id '{}'",
                    self.account
                )));
            };
            authorize_repo(ctx, "ecr:CreateRepository", &arn, None, ConditionContext::new()).map_err(registry_error)?;
            let repo = build_repo(&ctx.partition, reg, name, now_ms(ctx), NewRepo::from_template(&template));
            reg.repositories.insert(name.to_string(), repo);
        }
        f(&mut st)
    }
}

impl server::Backend for Backend<'_> {
    fn ping(&self, ctx: &RequestContext) -> Result<(), RegistryError> {
        self.require_caller(ctx)
    }

    fn with_repository<R>(
        &self,
        ctx: &RequestContext,
        name: &str,
        op: Op,
        f: impl FnOnce(&mut Repository) -> Result<R, RegistryError>,
    ) -> Result<R, RegistryError> {
        let (account, region) = (self.account.clone(), self.region.clone());
        self.open(ctx, name, op, |st| {
            let repo = st.registry_mut(&account, &region).repositories.get_mut(name).expect("opened");
            f(&mut repo.content)
        })
    }

    fn allows_mount(&self, _ctx: &RequestContext) -> bool {
        let st = self.ecr.lock();
        st.registry(&self.account, &self.region)
            .and_then(|r| r.settings.get("BLOB_MOUNTING"))
            .is_some_and(|v| v == "ENABLED")
    }

    fn put_manifest(&self, ctx: &RequestContext, name: &str, put: PutManifest) -> Result<PutOutcome, RegistryError> {
        let (account, region) = (self.account.clone(), self.region.clone());
        let now = now_ms(ctx);
        let (outcome, events) = self.open(ctx, name, Op::ManifestWrite, |st| {
            self.ecr
                .put_image_in(st, &ctx.partition, &account, &region, name, put, Via::Registry, now)
                .map_err(registry_error)
        })?;
        self.ecr.emit(ctx, events);
        Ok(outcome)
    }

    fn get_manifest(&self, ctx: &RequestContext, name: &str, reference: &str) -> Result<Image, RegistryError> {
        let (account, region) = (self.account.clone(), self.region.clone());
        self.open(ctx, name, Op::ManifestRead, |st| {
            let reg = st.registry_mut(&account, &region);
            let excluded = pull_time_excluded(reg, ctx);
            let repo = reg.repositories.get_mut(name).expect("opened");
            let unknown = || {
                RegistryError::manifest_unknown(format!(
                    "Requested image not found: the image with reference '{reference}' does not exist in the repository with name '{name}'"
                ))
            };
            let digest = repo.content.resolve_digest(reference).ok_or_else(unknown)?;
            if repo.status(&digest) != "ACTIVE" {
                return Err(RegistryError::new(
                    403,
                    "DENIED",
                    "The requested image is archived. Restore it to standard storage to pull it.",
                ));
            }
            let image = repo.content.images.get_mut(&digest).ok_or_else(unknown)?;
            if !excluded {
                image.last_pulled_at = Some(ctx.received_at.timestamp_millis());
            }
            Ok(image.clone())
        })
    }

    fn delete_manifest(&self, ctx: &RequestContext, name: &str, reference: &str) -> Result<(), RegistryError> {
        let (account, region) = (self.account.clone(), self.region.clone());
        let now = now_ms(ctx);
        let event = self.open(ctx, name, Op::ManifestDelete, |st| {
            let reg = st.registry_mut(&account, &region);
            let repo = reg.repositories.get_mut(name).expect("opened");
            let unknown =
                || RegistryError::manifest_unknown(format!("The image '{reference}' does not exist in '{name}'"));
            if !reference.contains(':') {
                let d = repo.content.untag(reference).ok_or_else(unknown)?;
                return Ok((d, Some(reference.to_string())));
            }
            if repo.content.referenced_by_index(reference) {
                return Err(RegistryError::new(400, "DENIED", "Requested image referenced by manifest list"));
            }
            let tags = repo.content.tags_of(reference);
            repo.content.delete_image(reference).ok_or_else(unknown)?;
            repo.meta.remove(reference);
            Ok((reference.to_string(), tags.into_iter().next()))
        })?;
        let st = self.ecr.lock();
        let ev = st.registry(&account, &region).map(|reg| {
            crate::images::image_event(&ctx.partition, reg, name, "DELETE", &event.0, event.1.as_deref(), now)
        });
        drop(st);
        self.ecr.emit(ctx, ev.into_iter().collect());
        Ok(())
    }
}
