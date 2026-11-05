//! The registry HTTP API (`/v2/...`), on top of a [`Backend`].
//!
//! Requests are routed by path: everything after the registry's base
//! (normally `/v2`) is `/<name>/manifests/<reference>`,
//! `/<name>/blobs/<digest>`, `/<name>/blobs/uploads/[<id>]`,
//! `/<name>/tags/list` or `/<name>/referrers/<digest>`; names may contain
//! slashes. The backend authorizes each step ([`Op`]) and owns the
//! repositories.

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use serde_json::json;

use crate::digest;
use crate::store::{Image, PutError, PutManifest, PutOutcome, Repository, UploadError};

/// What a registry request does to a repository, for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `HEAD` on a blob: does the repository have it (before a push).
    BlobCheck,
    /// `GET` on a blob.
    BlobRead,
    UploadStart,
    UploadPart,
    UploadComplete,
    ManifestRead,
    ManifestWrite,
    ManifestDelete,
    TagList,
    ReferrersList,
}

/// An error in the registry protocol's form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    pub status: u16,
    /// `NAME_UNKNOWN`, `MANIFEST_UNKNOWN`, `DENIED`, ...
    pub code: &'static str,
    pub message: String,
    /// For `401`: the challenge (`WWW-Authenticate`).
    pub challenge: Option<String>,
    /// Extra response headers (`Range` on an invalid upload range).
    pub headers: Vec<(String, String)>,
}

impl RegistryError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), challenge: None, headers: Vec::new() }
    }

    pub fn unauthorized(challenge: impl Into<String>, message: impl Into<String>) -> Self {
        Self { challenge: Some(challenge.into()), ..Self::new(401, "UNAUTHORIZED", message) }
    }

    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(403, "DENIED", message)
    }

    pub fn name_unknown(message: impl Into<String>) -> Self {
        Self::new(404, "NAME_UNKNOWN", message)
    }

    pub fn name_invalid(message: impl Into<String>) -> Self {
        Self::new(400, "NAME_INVALID", message)
    }

    pub fn manifest_unknown(message: impl Into<String>) -> Self {
        Self::new(404, "MANIFEST_UNKNOWN", message)
    }

    pub fn blob_unknown(message: impl Into<String>) -> Self {
        Self::new(404, "BLOB_UNKNOWN", message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(405, "UNSUPPORTED", message)
    }

    /// The protocol's usual answer to an upload error.
    pub fn from_upload(e: &UploadError, id: &str) -> Self {
        match e {
            UploadError::NotFound => {
                Self::new(404, "BLOB_UPLOAD_UNKNOWN", format!("Upload with id '{id}' was not found"))
            }
            UploadError::InvalidRange { expected_first } => {
                let mut err = Self::new(416, "BLOB_UPLOAD_INVALID", "The content range is not valid for this upload");
                err.headers.push(("Range".into(), format!("0-{}", expected_first.saturating_sub(1))));
                err
            }
            UploadError::InvalidDigest => Self::new(400, "DIGEST_INVALID", "The provided digest is not valid"),
            UploadError::DigestMismatch { actual } => Self::new(
                400,
                "DIGEST_INVALID",
                format!("The provided digest did not match uploaded content; calculated digest {actual}"),
            ),
        }
    }

    /// The protocol's usual answer to a refused manifest.
    pub fn from_put(e: &PutError) -> Self {
        match e {
            PutError::Manifest(m) => Self::new(400, "MANIFEST_INVALID", format!("manifest invalid: {m:?}")),
            PutError::DigestMismatch { computed } => {
                Self::new(400, "DIGEST_INVALID", format!("manifest digest does not match: computed {computed}"))
            }
            PutError::InvalidDigest(d) => Self::new(400, "DIGEST_INVALID", format!("invalid digest {d}")),
            PutError::MissingBlobs(d) => {
                Self::new(400, "MANIFEST_BLOB_UNKNOWN", format!("blob unknown to registry: {}", d.join(", ")))
            }
            PutError::MissingManifests(d) => {
                Self::new(400, "MANIFEST_BLOB_UNKNOWN", format!("manifest unknown to registry: {}", d.join(", ")))
            }
            PutError::TagImmutable { tag } => {
                Self::new(400, "TAG_INVALID", format!("The image tag '{tag}' already exists and cannot be overwritten"))
            }
        }
    }
}

/// Where repositories live and who may do what to them.
pub trait Backend {
    /// The answer to `GET /v2/`: `Ok` for a caller who may use
    /// the registry, else (normally) a `401` with a challenge.
    fn ping(&self, ctx: &RequestContext) -> Result<(), RegistryError>;

    /// Authorize `op` on the repository `name` and run `f` on its content.
    fn with_repository<R>(
        &self,
        ctx: &RequestContext,
        name: &str,
        op: Op,
        f: impl FnOnce(&mut Repository) -> Result<R, RegistryError>,
    ) -> Result<R, RegistryError>;

    /// Store a manifest, applying the registry's own rules (tag
    /// immutability, creating repositories on push, ...).
    fn put_manifest(&self, ctx: &RequestContext, name: &str, put: PutManifest) -> Result<PutOutcome, RegistryError>;

    /// Read a manifest by tag or digest (recording the pull).
    fn get_manifest(&self, ctx: &RequestContext, name: &str, reference: &str) -> Result<Image, RegistryError>;

    /// Delete an image (by digest) or a tag.
    fn delete_manifest(&self, ctx: &RequestContext, name: &str, reference: &str) -> Result<(), RegistryError>;

    /// Whether blobs may be mounted from another repository
    /// (`POST .../blobs/uploads/?mount=<digest>&from=<name>`); otherwise the
    /// client uploads them.
    fn allows_mount(&self, _ctx: &RequestContext) -> bool {
        true
    }
}

/// The path registry clients fetch bearer tokens from, when a registry's
/// challenge points them there.
pub const TOKEN_PATH: &str = "/_registry/token";

/// A routed registry request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Ping,
    Catalog,
    Tags { name: String },
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    Uploads { name: String },
    Upload { name: String, id: String },
    Referrers { name: String, digest: String },
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Route a path relative to the registry's base (`/`, `/<name>/...`).
pub fn route(rel: &str) -> Option<Route> {
    let rel = percent_decode(rel);
    let rel = rel.strip_prefix('/').unwrap_or(&rel);
    if rel.is_empty() {
        return Some(Route::Ping);
    }
    if rel == "_catalog" {
        return Some(Route::Catalog);
    }
    if let Some(name) = rel.strip_suffix("/tags/list") {
        return Some(Route::Tags { name: name.to_string() });
    }
    if let Some(name) = rel.strip_suffix("/blobs/uploads").or_else(|| rel.strip_suffix("/blobs/uploads/")) {
        return Some(Route::Uploads { name: name.to_string() });
    }
    if let Some((name, id)) = rel.rsplit_once("/blobs/uploads/") {
        return Some(Route::Upload { name: name.to_string(), id: id.to_string() });
    }
    if let Some((name, reference)) = rel.rsplit_once("/manifests/") {
        return Some(Route::Manifest { name: name.to_string(), reference: reference.to_string() });
    }
    if let Some((name, digest)) = rel.rsplit_once("/blobs/") {
        return Some(Route::Blob { name: name.to_string(), digest: digest.to_string() });
    }
    if let Some((name, digest)) = rel.rsplit_once("/referrers/") {
        return Some(Route::Referrers { name: name.to_string(), digest: digest.to_string() });
    }
    None
}

fn query(request: &HttpRequest) -> Vec<(String, String)> {
    form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes()).into_owned().collect()
}

fn param<'a>(q: &'a [(String, String)], name: &str) -> Option<&'a str> {
    q.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request.headers().get(name).and_then(|v| v.to_str().ok())
}

fn builder(status: u16) -> http::response::Builder {
    http::Response::builder().status(status).header("Docker-Distribution-API-Version", "registry/2.0")
}

/// Render a registry error.
pub fn error_response(e: &RegistryError) -> HttpResponse {
    let body = json!({"errors": [{"code": e.code, "message": e.message}]}).to_string();
    let mut b = builder(e.status).header(http::header::CONTENT_TYPE, "application/json; charset=utf-8");
    if let Some(c) = &e.challenge {
        b = b.header(http::header::WWW_AUTHENTICATE, c);
    }
    for (k, v) in &e.headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(Bytes::from(body)).expect("valid response")
}

fn empty(status: u16) -> http::response::Builder {
    builder(status).header(http::header::CONTENT_LENGTH, "0")
}

fn done(b: http::response::Builder) -> HttpResponse {
    b.body(Bytes::new()).expect("valid response")
}

/// Serve one registry request. `base` is the path prefix the registry is
/// served under (`/v2`), for `Location` headers; `rel` is the rest of the
/// path.
pub fn serve<B: Backend>(
    backend: &B,
    ctx: &RequestContext,
    request: &HttpRequest,
    base: &str,
    rel: &str,
) -> HttpResponse {
    let Some(route) = route(rel) else {
        return error_response(&RegistryError::new(404, "NOT_FOUND", "Not Found"));
    };
    match handle(backend, ctx, request, base, route) {
        Ok(r) => r,
        Err(e) => error_response(&e),
    }
}

fn now(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

fn handle<B: Backend>(
    backend: &B,
    ctx: &RequestContext,
    request: &HttpRequest,
    base: &str,
    route: Route,
) -> Result<HttpResponse, RegistryError> {
    let method = request.method().clone();
    let head = method == http::Method::HEAD;
    match route {
        Route::Ping => {
            backend.ping(ctx)?;
            Ok(builder(200).header(http::header::CONTENT_TYPE, "application/json").body(Bytes::from("{}")).unwrap())
        }
        Route::Catalog => {
            backend.ping(ctx)?;
            Err(RegistryError::unsupported("The operation is unsupported."))
        }
        Route::Manifest { name, reference } => match method {
            http::Method::GET | http::Method::HEAD => {
                let image = backend.get_manifest(ctx, &name, &reference)?;
                let b = builder(200)
                    .header(http::header::CONTENT_TYPE, &image.media_type)
                    .header(http::header::CONTENT_LENGTH, image.manifest.len().to_string())
                    .header("Docker-Content-Digest", &image.digest)
                    .header(http::header::ETAG, format!("\"{}\"", image.digest));
                let body = if head { Bytes::new() } else { Bytes::from(image.manifest) };
                Ok(b.body(body).unwrap())
            }
            http::Method::PUT => {
                let manifest = String::from_utf8(request.body().to_vec())
                    .map_err(|_| RegistryError::new(400, "MANIFEST_INVALID", "manifest invalid"))?;
                let is_digest = reference.contains(':');
                let subject = crate::manifest::parse(manifest.as_bytes(), header(request, "content-type"))
                    .ok()
                    .and_then(|m| m.subject)
                    .map(|s| s.digest);
                let put = PutManifest {
                    manifest,
                    media_type: header(request, "content-type").map(str::to_string),
                    tag: (!is_digest).then(|| reference.clone()),
                    digest: is_digest.then(|| reference.clone()),
                };
                let out = backend.put_manifest(ctx, &name, put)?;
                let mut b = empty(201)
                    .header(http::header::LOCATION, format!("{base}/{name}/manifests/{}", out.digest))
                    .header("Docker-Content-Digest", &out.digest);
                if let Some(s) = subject {
                    b = b.header("OCI-Subject", s);
                }
                Ok(done(b))
            }
            http::Method::DELETE => {
                backend.delete_manifest(ctx, &name, &reference)?;
                Ok(done(empty(202)))
            }
            _ => Err(RegistryError::unsupported("The operation is unsupported.")),
        },
        Route::Blob { name, digest: d } => match method {
            http::Method::GET | http::Method::HEAD => {
                let op = if head { Op::BlobCheck } else { Op::BlobRead };
                let data = backend.with_repository(ctx, &name, op, |repo| {
                    repo.blobs.get(&d).map(|b| b.data.clone()).ok_or_else(|| {
                        RegistryError::blob_unknown(format!(
                            "The specified blob does not exist in the repository with name '{name}'"
                        ))
                    })
                })?;
                let total = data.len() as u64;
                let range = header(request, "range").and_then(|r| parse_range(r, total));
                let mut b = builder(if range.is_some() { 206 } else { 200 })
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .header("Docker-Content-Digest", &d)
                    .header(http::header::ACCEPT_RANGES, "bytes")
                    .header(http::header::ETAG, format!("\"{d}\""));
                let body = match range {
                    Some((start, end)) => {
                        b = b.header(http::header::CONTENT_RANGE, format!("bytes {start}-{end}/{total}"));
                        data.slice(start as usize..=end as usize)
                    }
                    None => data,
                };
                b = b.header(http::header::CONTENT_LENGTH, body.len().to_string());
                Ok(b.body(if head { Bytes::new() } else { body }).unwrap())
            }
            http::Method::DELETE => {
                backend.with_repository(ctx, &name, Op::ManifestDelete, |_| Ok(()))?;
                Err(RegistryError::unsupported("The operation is unsupported."))
            }
            _ => Err(RegistryError::unsupported("The operation is unsupported.")),
        },
        Route::Uploads { name } => {
            if method != http::Method::POST {
                return Err(RegistryError::unsupported("The operation is unsupported."));
            }
            let q = query(request);
            let t = now(ctx);
            if let (Some(mount), Some(from), true) = (param(&q, "mount"), param(&q, "from"), backend.allows_mount(ctx))
            {
                let source = backend
                    .with_repository(ctx, from, Op::BlobRead, |repo| Ok(repo.blobs.get(mount).map(|b| b.data.clone())))
                    .ok()
                    .flatten();
                if let Some(data) = source {
                    backend.with_repository(ctx, &name, Op::UploadComplete, |repo| {
                        repo.put_blob(mount, data, t);
                        Ok(())
                    })?;
                    return Ok(done(
                        empty(201)
                            .header(http::header::LOCATION, format!("{base}/{name}/blobs/{mount}"))
                            .header("Docker-Content-Digest", mount),
                    ));
                }
            }
            let id = backend.with_repository(ctx, &name, Op::UploadStart, |repo| Ok(repo.start_upload(t)))?;
            if let Some(d) = param(&q, "digest") {
                let d = d.to_string();
                finish_upload(backend, ctx, &name, &id, Some(request.body()), &d, t)?;
                return Ok(done(
                    empty(201)
                        .header(http::header::LOCATION, format!("{base}/{name}/blobs/{d}"))
                        .header("Docker-Content-Digest", &d),
                ));
            }
            Ok(done(
                empty(202)
                    .header(http::header::LOCATION, format!("{base}/{name}/blobs/uploads/{id}"))
                    .header(http::header::RANGE, "0-0")
                    .header("Docker-Upload-UUID", &id),
            ))
        }
        Route::Upload { name, id } => {
            let t = now(ctx);
            let location = format!("{base}/{name}/blobs/uploads/{id}");
            match method {
                http::Method::PATCH => {
                    let first = header(request, "content-range")
                        .and_then(|r| {
                            r.trim().trim_start_matches("bytes").trim_start_matches(['=', ' ']).split('-').next()
                        })
                        .and_then(|s| s.trim().parse::<u64>().ok());
                    let body = request.body().clone();
                    let len = backend.with_repository(ctx, &name, Op::UploadPart, |repo| {
                        repo.append_upload(&id, first, &body).map_err(|e| RegistryError::from_upload(&e, &id))
                    })?;
                    Ok(done(
                        empty(202)
                            .header(http::header::LOCATION, &location)
                            .header(http::header::RANGE, format!("0-{}", len.saturating_sub(1)))
                            .header("Docker-Upload-UUID", &id),
                    ))
                }
                http::Method::PUT => {
                    let q = query(request);
                    let Some(d) = param(&q, "digest").map(str::to_string) else {
                        return Err(RegistryError::new(400, "DIGEST_INVALID", "A digest is required"));
                    };
                    finish_upload(backend, ctx, &name, &id, Some(request.body()), &d, t)?;
                    Ok(done(
                        empty(201)
                            .header(http::header::LOCATION, format!("{base}/{name}/blobs/{d}"))
                            .header("Docker-Content-Digest", &d),
                    ))
                }
                http::Method::GET => {
                    let len = backend.with_repository(ctx, &name, Op::UploadPart, |repo| {
                        repo.uploads
                            .get(&id)
                            .map(|u| u.data.len() as u64)
                            .ok_or_else(|| RegistryError::from_upload(&UploadError::NotFound, &id))
                    })?;
                    Ok(done(
                        empty(204)
                            .header(http::header::LOCATION, &location)
                            .header(http::header::RANGE, format!("0-{}", len.saturating_sub(1)))
                            .header("Docker-Upload-UUID", &id),
                    ))
                }
                http::Method::DELETE => {
                    backend.with_repository(ctx, &name, Op::UploadPart, |repo| {
                        repo.uploads
                            .remove(&id)
                            .map(|_| ())
                            .ok_or_else(|| RegistryError::from_upload(&UploadError::NotFound, &id))
                    })?;
                    Ok(done(empty(204)))
                }
                _ => Err(RegistryError::unsupported("The operation is unsupported.")),
            }
        }
        Route::Tags { name } => {
            let q = query(request);
            let n = param(&q, "n").and_then(|n| n.parse::<usize>().ok());
            let last = param(&q, "last").map(str::to_string);
            let tags = backend
                .with_repository(ctx, &name, Op::TagList, |repo| Ok(repo.tags.keys().cloned().collect::<Vec<_>>()))?;
            let mut tags: Vec<String> = tags.into_iter().filter(|t| last.as_ref().is_none_or(|l| t > l)).collect();
            let mut b = builder(200).header(http::header::CONTENT_TYPE, "application/json; charset=utf-8");
            if let Some(n) = n {
                if tags.len() > n {
                    tags.truncate(n);
                    let next = tags.last().cloned().unwrap_or_default();
                    b = b.header(
                        http::header::LINK,
                        format!("<{base}/{name}/tags/list?last={next}&n={n}>; rel=\"next\""),
                    );
                }
            }
            Ok(b.body(Bytes::from(json!({"name": name, "tags": tags}).to_string())).unwrap())
        }
        Route::Referrers { name, digest: d } => {
            if !digest::is_valid(&d) {
                return Err(RegistryError::new(400, "DIGEST_INVALID", "The provided digest is not valid"));
            }
            let q = query(request);
            let filter = param(&q, "artifactType").map(str::to_string);
            let manifests = backend.with_repository(ctx, &name, Op::ReferrersList, |repo| {
                Ok(repo
                    .referrers(&d, filter.as_deref())
                    .into_iter()
                    .map(|i| {
                        let parsed = i.parsed();
                        let mut desc = json!({
                            "mediaType": i.media_type,
                            "digest": i.digest,
                            "size": i.manifest.len(),
                        });
                        if let Some(t) = i.artifact_type.as_ref().or(i.config_media_type.as_ref()) {
                            desc["artifactType"] = json!(t);
                        }
                        if let Some(a) = parsed.and_then(|p| p.annotations) {
                            desc["annotations"] = serde_json::Value::Object(a);
                        }
                        desc
                    })
                    .collect::<Vec<_>>())
            })?;
            let body = json!({
                "schemaVersion": 2,
                "mediaType": crate::manifest::OCI_INDEX,
                "manifests": manifests,
            });
            let mut b = builder(200).header(http::header::CONTENT_TYPE, crate::manifest::OCI_INDEX);
            if filter.is_some() {
                b = b.header("OCI-Filters-Applied", "artifactType");
            }
            Ok(b.body(Bytes::from(body.to_string())).unwrap())
        }
    }
}

fn finish_upload<B: Backend>(
    backend: &B,
    ctx: &RequestContext,
    name: &str,
    id: &str,
    body: Option<&Bytes>,
    d: &str,
    t: i64,
) -> Result<(), RegistryError> {
    if let Some(body) = body.filter(|b| !b.is_empty()) {
        backend.with_repository(ctx, name, Op::UploadPart, |repo| {
            repo.append_upload(id, None, body).map(|_| ()).map_err(|e| RegistryError::from_upload(&e, id))
        })?;
    }
    backend.with_repository(ctx, name, Op::UploadComplete, |repo| {
        repo.complete_upload(id, d, t).map(|_| ()).map_err(|e| RegistryError::from_upload(&e, id))
    })
}

/// A single `bytes=start-end` range within `total` bytes.
fn parse_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') || total == 0 {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let (start, end) = match (start.trim(), end.trim()) {
        ("", suffix) => {
            let n: u64 = suffix.parse().ok()?;
            (total.saturating_sub(n), total - 1)
        }
        (s, "") => (s.parse().ok()?, total - 1),
        (s, e) => (s.parse().ok()?, e.parse::<u64>().ok()?.min(total - 1)),
    };
    (start <= end && start < total).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(route("/"), Some(Route::Ping));
        assert_eq!(route(""), Some(Route::Ping));
        assert_eq!(
            route("/team/app/manifests/latest"),
            Some(Route::Manifest { name: "team/app".into(), reference: "latest".into() })
        );
        assert_eq!(route("/a/blobs/uploads/"), Some(Route::Uploads { name: "a".into() }));
        assert_eq!(route("/a/b/blobs/uploads/xyz"), Some(Route::Upload { name: "a/b".into(), id: "xyz".into() }));
        assert_eq!(route("/a/blobs/sha256%3Aab"), Some(Route::Blob { name: "a".into(), digest: "sha256:ab".into() }));
        assert_eq!(route("/a/tags/list"), Some(Route::Tags { name: "a".into() }));
        assert_eq!(
            route("/a/referrers/sha256:x"),
            Some(Route::Referrers { name: "a".into(), digest: "sha256:x".into() })
        );
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-3", 10), Some((0, 3)));
        assert_eq!(parse_range("bytes=5-", 10), Some((5, 9)));
        assert_eq!(parse_range("bytes=-2", 10), Some((8, 9)));
        assert_eq!(parse_range("bytes=20-30", 10), None);
    }
}
