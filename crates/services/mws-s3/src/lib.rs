//! Amazon S3 for MWS.
//!
//! General purpose buckets with objects, versioning and delete markers,
//! multipart uploads, conditional and ranged reads, copies, checksums
//! (CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256), tagging, object lock, and the
//! bucket subresources (policy, ACLs, CORS, lifecycle, encryption, website,
//! logging, notifications, ownership controls, Block Public Access, ...).
//!
//! Every request is authorized through IAM, with the bucket policy evaluated
//! as a resource-based policy, Block Public Access applied, and ACL grants
//! honoured on buckets whose ownership controls allow ACLs. Unsigned
//! requests are evaluated as the anonymous principal.
//!
//! Buckets are addressed path-style (`http://localhost:4566/bucket/key`) or
//! virtual-hosted-style (`http://bucket.localhost:4566/key`, or any host of
//! the form `bucket.s3.<anything>`).
//!
//! Other MWS services that AWS couples to S3 (Private CA publishing CRLs and
//! audit reports) write objects through [`S3::put_object_as_service`].

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/s3_generated.rs"));
}

#[macro_use]
mod checksum;
mod acl;
mod annotations;
mod auth;
mod buckets;

mod config;
mod cors;
mod errors;
mod handler;
mod kms;
mod lifecycle;
mod listing;
mod metadata;
mod multipart;
mod objects;
mod public;
mod replication;
mod state;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use bytes::Bytes;
use http::Method;
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use public::{ServicePutError, ServicePutObject};
use state::State;

/// A Signature Version 2 presigned URL or `Authorization: AWS ...` header.
fn signature_v2(request: &HttpRequest) -> bool {
    let query = request.uri().query().unwrap_or_default();
    let has = |name: &str| query.split('&').any(|p| p.split('=').next() == Some(name));
    (has("AWSAccessKeyId") && has("Signature"))
        || request
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("AWS "))
}

/// The S3 service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct S3 {
    state: Arc<RwLock<State>>,
    kms: Option<mws_kms::Kms>,
}

/// How a request proved who sent it, for `s3:authType` and friends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthType {
    Header,
    /// A presigned URL, signed this many milliseconds ago.
    Query {
        age_ms: i64,
    },
    Anonymous,
}

/// One request: the service plus facts about the HTTP exchange that the
/// generated input types do not carry.
pub(crate) struct Call {
    pub s3: S3,
    pub auth: AuthType,
    pub content_sha256: Option<String>,
    /// Versions this request wrote (bucket, key, version id), for
    /// replication once the request is done.
    pub written: std::sync::Mutex<Vec<(String, String, String)>>,
}

impl Call {
    pub(crate) fn wrote(&self, bucket: &str, key: &str, version_id: &str) {
        if let Ok(mut w) = self.written.lock() {
            w.push((bucket.to_string(), key.to_string(), version_id.to_string()));
        }
    }

    fn take_written(&self) -> Vec<(String, String, String)> {
        self.written.lock().map(|mut w| std::mem::take(&mut *w)).unwrap_or_default()
    }
}

impl std::ops::Deref for Call {
    type Target = S3;
    fn deref(&self) -> &S3 {
        &self.s3
    }
}

impl S3 {
    pub fn new() -> Self {
        Self::default()
    }

    /// Use `kms` for SSE-KMS, as S3 does: data keys come from KMS with the
    /// caller's permissions.
    pub fn with_kms(mut self, kms: mws_kms::Kms) -> Self {
        self.kms = Some(kms);
        self
    }

    /// Act on lifecycle rules that have come due by `now`.
    fn run_lifecycle(&self, now: chrono::DateTime<chrono::Utc>) {
        if self.read().has_lifecycle() {
            self.write().run_lifecycle(now);
        }
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().expect("S3 state lock poisoned")
    }

    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().expect("S3 state lock poisoned")
    }

    fn call(&self, ctx: &RequestContext, request: Option<&HttpRequest>) -> Call {
        let auth = match request {
            None => AuthType::Header,
            Some(_) if ctx.caller.kind == mws_core::CallerKind::Anonymous => AuthType::Anonymous,
            Some(r) if r.headers().contains_key(http::header::AUTHORIZATION) => AuthType::Header,
            Some(r) => {
                let date = form_urlencoded_get(r.uri().query().unwrap_or(""), "X-Amz-Date");
                let age_ms = date
                    .and_then(|d| chrono::NaiveDateTime::parse_from_str(&d, "%Y%m%dT%H%M%SZ").ok())
                    .map(|d| (ctx.received_at - d.and_utc()).num_milliseconds())
                    .unwrap_or(0);
                AuthType::Query { age_ms }
            }
        };
        let content_sha256 = request
            .and_then(|r| r.headers().get("x-amz-content-sha256"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Call { s3: self.clone(), auth, content_sha256, written: Default::default() }
    }
}

fn form_urlencoded_get(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then(|| percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned())
    })
}

/// The bucket named by a virtual-hosted-style `Host`, if any:
/// `bucket.localhost`, `bucket.s3.amazonaws.com`,
/// `bucket.s3.us-west-2.amazonaws.com`, `bucket.s3-us-west-2.amazonaws.com`,
/// `bucket.s3.localhost.localstack.cloud`, ...
fn virtual_host_bucket(host: &str) -> Option<String> {
    let host = host.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(host, |h| h.0);
    let host = host.to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return None;
    }
    for marker in [".s3.", ".s3-"] {
        if let Some(i) = host.find(marker) {
            return (i > 0).then(|| host[..i].to_string());
        }
    }
    if let Some(bucket) = host.strip_suffix(".s3.amazonaws.com") {
        return Some(bucket.to_string());
    }
    host.strip_suffix(".localhost").filter(|b| !b.is_empty() && *b != "s3").map(str::to_string)
}

/// Rewrite a virtual-hosted-style request to path style.
fn to_path_style(request: HttpRequest) -> HttpRequest {
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| request.uri().authority().map(|a| a.to_string()));
    let Some(bucket) = host.as_deref().and_then(virtual_host_bucket) else { return request };
    let (mut parts, body) = request.into_parts();
    let path = parts.uri.path();
    let mut new = format!("/{bucket}{}", if path == "/" { "" } else { path });
    if let Some(q) = parts.uri.query() {
        new.push('?');
        new.push_str(q);
    }
    if let Ok(uri) = new.parse() {
        parts.uri = uri;
    }
    http::Request::from_parts(parts, body)
}

/// Whether an unsigned request looks like S3 rather than one of the other
/// services' unsigned operations (STS's form-encoded `POST /`, JSON
/// protocols' `X-Amz-Target`, Route 53's versioned paths).
fn looks_like_s3(request: &HttpRequest) -> bool {
    if request.headers().contains_key("x-amz-target") {
        return false;
    }
    let host = request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if virtual_host_bucket(host).is_some() {
        return true;
    }
    let path = request.uri().path();
    if path == "/" || path.is_empty() {
        // `GET /` is ListBuckets, which needs a signature anyway.
        return false;
    }
    if path.starts_with("/2013-04-01/") || path.starts_with("/_mws") {
        return false;
    }
    let form = request.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| {
        v.starts_with("application/x-www-form-urlencoded") || v.starts_with("application/ocsp-request")
    });
    !(request.method() == Method::POST && form)
}

#[async_trait::async_trait]
impl Service for S3 {
    fn signing_name(&self) -> &'static str {
        "s3"
    }

    fn signs_raw_path(&self) -> bool {
        true
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        let request = to_path_style(request);
        let head = request.method() == Method::HEAD;
        if request.method() == Method::OPTIONS {
            return self.preflight(&ctx, &request);
        }
        self.run_lifecycle(ctx.received_at);
        if signature_v2(&request) {
            // S3 turned Signature Version 2 off for buckets created since
            // June 2020; every MWS bucket is that new.
            let e = ServiceError::client(
                "InvalidRequest",
                400,
                "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.",
            );
            let mut response = self.render_error(&ctx.request_id, &e);
            self.finish_response(&ctx, &request, &mut response);
            return response;
        }
        let call = self.call(&ctx, Some(&request));
        let mut response = generated::dispatch(&call, &ctx, &request).await;
        self.replicate(&ctx, call.take_written());
        self.finish_response(&ctx, &request, &mut response);
        if head || response.status() == http::StatusCode::NOT_MODIFIED {
            *response.body_mut() = Bytes::new();
        }
        response
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        looks_like_s3(request)
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restxml::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.run_lifecycle(ctx.received_at);
        let call = self.call(&ctx, None);
        let out = generated::invoke(&call, &ctx, operation, input).await;
        self.replicate(&ctx, call.take_written());
        out
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.read();
        Some(serde_json::to_value(&*state).expect("S3 state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid S3 state: {e}"))?;
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
    }
}

impl S3 {
    /// Response details the model does not express: `206` for ranged reads,
    /// `x-amz-id-2`, and CORS headers.
    fn finish_response(&self, ctx: &RequestContext, request: &HttpRequest, response: &mut HttpResponse) {
        let headers = response.headers_mut();
        if let Ok(v) = http::HeaderValue::from_str(&host_id(&ctx.request_id)) {
            headers.insert("x-amz-id-2", v);
        }
        if response.status() == http::StatusCode::OK
            && request.headers().contains_key(http::header::RANGE)
            && response.headers().contains_key(http::header::CONTENT_RANGE)
        {
            *response.status_mut() = http::StatusCode::PARTIAL_CONTENT;
        }
        self.cors_headers(request, response);
    }
}

/// S3's extended request id, derived from the request id.
fn host_id(request_id: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(request_id.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_hosts() {
        assert_eq!(virtual_host_bucket("b.localhost:4566").as_deref(), Some("b"));
        assert_eq!(virtual_host_bucket("my.bucket.s3.us-west-2.amazonaws.com").as_deref(), Some("my.bucket"));
        assert_eq!(virtual_host_bucket("b.s3.amazonaws.com").as_deref(), Some("b"));
        assert_eq!(virtual_host_bucket("b.s3-us-west-2.amazonaws.com").as_deref(), Some("b"));
        assert_eq!(virtual_host_bucket("localhost:4566"), None);
        assert_eq!(virtual_host_bucket("127.0.0.1:4566"), None);
        assert_eq!(virtual_host_bucket("s3.amazonaws.com"), None);
        assert_eq!(virtual_host_bucket("s3.localhost"), None);
    }
}
