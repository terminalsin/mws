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
mod access_points;
mod acl;
mod annotations;
mod auth;
mod buckets;

mod access_log;
mod config;
mod cors;
mod directory;
mod errors;
mod handler;
mod inventory;
mod kms;
mod lifecycle;
mod listing;
mod metadata;
mod multipart;
mod notifications;
mod objects;
mod parquet;
mod post;
mod public;
mod replication;
mod select;
mod sigv2;
mod state;
mod website;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use bytes::Bytes;
use http::Method;
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use access_points::{
    AccessPoint, AccessPointDirectory, AccountPublicAccessBlock, LambdaInvocation, ObjectLambdaAccessPoint,
    ObjectLambdaInvoker, Transformation,
};
pub use auth::policy_is_public;
pub use checksum::compute as compute_checksum;
pub use notifications::{event_message, EventBridgeSink, NotificationDestination, NotificationSource, ObjectEvent};
pub use public::{ServicePutError, ServicePutObject, ServiceRead};
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

/// A form upload signed with Signature Version 2 (an `AWSAccessKeyId`
/// field rather than `x-amz-credential`).
fn form_signed_v2(request: &HttpRequest) -> bool {
    post::is_form_upload(request) && post::Form::parse(request).is_ok_and(|f| f.field("awsaccesskeyid").is_some())
}

/// The S3 service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct S3 {
    state: Arc<RwLock<State>>,
    kms: Option<mws_kms::Kms>,
    /// Directory bucket sessions from `CreateSession`.
    sessions: directory::Sessions,
    /// S3 Control and Lambda, for access points and Object Lambda.
    links: Arc<access_points::Links>,
    /// Where event notifications go.
    notifications: Arc<notifications::Sinks>,
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
    /// The access point the request came through.
    pub access_point: Option<AccessPoint>,
    /// The service that made the request for the caller
    /// (`aws:CalledVia`), e.g. S3 Object Lambda.
    pub called_via: Option<&'static str>,
    /// A success status other than the model's (`202 Accepted` for a
    /// restore that has started).
    pub status: std::sync::Mutex<Option<http::StatusCode>>,
    /// The request accepted Requester Pays charges
    /// (`x-amz-request-payer: requester`).
    pub request_payer: bool,
    /// The requester was charged, so the response says so.
    pub request_charged: std::sync::atomic::AtomicBool,
    /// Signed with Signature Version 2.
    pub sigv2: bool,
    /// A browser form upload (`POST` with a policy).
    pub form_post: bool,
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
        Call {
            s3: self.clone(),
            auth,
            content_sha256,
            written: Default::default(),
            access_point: None,
            called_via: None,
            status: Default::default(),
            request_payer: request
                .and_then(|r| r.headers().get("x-amz-request-payer"))
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"requester")),
            request_charged: Default::default(),
            sigv2: request.is_some_and(|r| signature_v2(r) || form_signed_v2(r)),
            form_post: false,
        }
    }
}

/// In a presigned URL, S3 reads `x-amz-*` query parameters (other than the
/// signature's own) as the request headers they stand for: SDKs move
/// headers such as `x-amz-checksum-crc32`, `x-amz-acl` or
/// `x-amz-server-side-encryption` into the query when presigning.
fn hoist_presigned_headers(mut request: HttpRequest) -> HttpRequest {
    const SIGNATURE_PARAMS: [&str; 8] = [
        "x-amz-algorithm",
        "x-amz-credential",
        "x-amz-date",
        "x-amz-expires",
        "x-amz-signedheaders",
        "x-amz-signature",
        "x-amz-security-token",
        "x-amz-content-sha256",
    ];
    let Some(query) = request.uri().query().map(str::to_string) else {
        return request;
    };
    if form_urlencoded_get(&query, "X-Amz-Signature").is_none() {
        return request;
    }
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        let name = k.to_ascii_lowercase();
        if !name.starts_with("x-amz-") || SIGNATURE_PARAMS.contains(&name.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (http::HeaderName::from_bytes(name.as_bytes()), http::HeaderValue::from_str(&v))
        {
            request.headers_mut().entry(name).or_insert(value);
        }
    }
    request
}

pub(crate) fn form_urlencoded_get(query: &str, name: &str) -> Option<String> {
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
pub(crate) fn to_path_style(request: HttpRequest) -> HttpRequest {
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

/// Whether the path could be S3's: not another service's versioned or
/// side-channel path, and not a query API's SigV2 (`SignatureVersion=2`).
fn s3_path(request: &HttpRequest) -> bool {
    let path = request.uri().path();
    let query = request.uri().query().unwrap_or_default();
    !(path.starts_with("/_")
        || path.starts_with("/2013-04-01/")
        || path.starts_with("/v20180820/")
        || query.split('&').any(|p| p.starts_with("SignatureVersion=")))
}

/// Whether an unsigned request looks like S3 rather than one of the other
/// services' unsigned operations (STS's form-encoded `POST /`, JSON
/// protocols' `X-Amz-Target`, Route 53's versioned paths).
fn looks_like_s3(request: &HttpRequest) -> bool {
    if request.headers().contains_key("x-amz-target") {
        return false;
    }
    if website::target(request).is_some() {
        return true;
    }
    let host = request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if virtual_host_bucket(host).is_some() {
        return true;
    }
    let path = request.uri().path();
    if path == "/" || path.is_empty() {
        // `GET /` is ListBuckets, which S3 refuses anonymously with
        // `AccessDenied`. Other methods on `/`, and query-protocol `GET`s
        // (`/?Action=...`, such as SNS's SubscribeURL), belong to other
        // services.
        let query_api =
            request.uri().query().unwrap_or("").split('&').any(|p| p.starts_with("Action=") || p == "Action");
        return request.method() == Method::GET && !query_api;
    }
    // Bucket names never start with `_`, so `/_mws/...` (the control API)
    // and `/_aws/...` (other services' side channels) are not S3's.
    if path.starts_with("/2013-04-01/") || path.starts_with("/_") {
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

    fn signing_aliases(&self) -> &'static [&'static str] {
        &["s3express", "s3-object-lambda"]
    }

    fn session_token(&self, request: &HttpRequest) -> Option<String> {
        directory::session_token(request)
    }

    fn signs_raw_path(&self) -> bool {
        true
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        // A function fetching its Object Lambda `inputS3Url` (signed with
        // credentials that act as the original caller).
        if let Some((bucket, path)) = website::target(&request) {
            return self.serve_website(&ctx, &request, &bucket, &path).await;
        }
        let called_via = self.called_via(&ctx);
        match self.resolve_target(request) {
            access_points::Target::Bucket(r) => self.serve(ctx, r, None, called_via).await,
            access_points::Target::AccessPoint(r, ap) => self.serve(ctx, r, Some(ap), called_via).await,
            access_points::Target::ObjectLambda(r, olap) => {
                let mut response = self.serve_object_lambda(&ctx, r, olap).await;
                if let Ok(v) = http::HeaderValue::from_str(&host_id(&ctx.request_id)) {
                    response.headers_mut().insert("x-amz-id-2", v);
                }
                response
            }
        }
    }

    fn alternate_signature(&self, request: &HttpRequest) -> Option<Result<mws_core::AlternateSignature, ServiceError>> {
        if request.headers().contains_key("x-amz-target") || !s3_path(request) {
            return None;
        }
        sigv2::alternate(request)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        looks_like_s3(request)
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restxml::error_response(&generated::SERVICE_INFO, request_id, &errors::s3_auth_error(error))
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.run_lifecycle(ctx.received_at);
        self.run_inventory(&ctx);
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
    /// Serve a path-style request, optionally through an access point.
    pub(crate) async fn serve(
        &self,
        ctx: RequestContext,
        request: HttpRequest,
        access_point: Option<AccessPoint>,
        called_via: Option<&'static str>,
    ) -> HttpResponse {
        let started = std::time::Instant::now();
        let request = directory::control_plane_listing(request);
        let request = hoist_presigned_headers(request);
        let head = request.method() == Method::HEAD;
        if request.method() == Method::OPTIONS {
            return self.preflight(&ctx, &request);
        }
        self.run_lifecycle(ctx.received_at);
        self.run_inventory(&ctx);
        if (signature_v2(&request) || form_signed_v2(&request)) && !self.takes_sigv2(&request) {
            let e = ServiceError::client(
                "InvalidRequest",
                400,
                "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256.",
            );
            let mut response = self.render_error(&ctx.request_id, &e);
            self.finish_response(&ctx, &request, &mut response);
            return response;
        }
        let mut call = self.call(&ctx, Some(&request));
        call.access_point = access_point;
        call.called_via = called_via;
        let routed = if post::is_form_upload(&request) {
            call.post_object(&ctx, &request).await
        } else {
            generated::route(&call, &ctx, &request).await
        };
        let mut response = match routed {
            Ok(r) => r,
            Err(e) => self.render_error(&ctx.request_id, &errors::s3_validation_error(e)),
        };
        if call.request_charged.load(std::sync::atomic::Ordering::Relaxed) && response.status().as_u16() < 300 {
            response.headers_mut().insert("x-amz-request-charged", http::HeaderValue::from_static("requester"));
        }
        if let Some(status) = call.status.lock().ok().and_then(|s| *s) {
            if response.status() == http::StatusCode::OK {
                *response.status_mut() = status;
            }
        }
        self.replicate(&ctx, call.take_written());
        self.finish_response(&ctx, &request, &mut response);
        self.log_request(&ctx, &request, &response, started);
        if head || response.status() == http::StatusCode::NOT_MODIFIED {
            *response.body_mut() = Bytes::new();
        }
        response
    }

    /// Whether Signature Version 2 is accepted: S3 refuses it for buckets
    /// created after 24 June 2020 (every MWS bucket), so only bucket-less
    /// requests (`ListBuckets`) take it.
    fn takes_sigv2(&self, request: &HttpRequest) -> bool {
        request.uri().path().trim_start_matches('/').is_empty()
    }

    /// Response details the model does not express: `206` for ranged reads,
    /// `x-amz-id-2`, and CORS headers.
    /// Server access logging for a path-style request.
    fn log_request(
        &self,
        ctx: &RequestContext,
        request: &HttpRequest,
        response: &HttpResponse,
        started: std::time::Instant,
    ) {
        let path = request.uri().path().trim_start_matches('/');
        let (bucket, key) = match path.split_once('/') {
            Some((b, k)) if !k.is_empty() => {
                (b, Some(percent_encoding::percent_decode_str(k).decode_utf8_lossy().into_owned()))
            }
            Some((b, _)) => (b, None),
            None => (path, None),
        };
        if bucket.is_empty() {
            return;
        }
        let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok());
        let error_code = (response.status().as_u16() >= 400)
            .then(|| {
                let body = String::from_utf8_lossy(response.body());
                body.split_once("<Code>").and_then(|(_, r)| r.split_once("</Code>")).map(|(c, _)| c.to_string())
            })
            .flatten();
        let is_object_read = key.is_some() && matches!(request.method(), &Method::GET | &Method::HEAD);
        self.log_access(
            ctx,
            request,
            access_log::Entry {
                bucket,
                key: key.as_deref(),
                operation: generated::operation_for(request),
                status: response.status().as_u16(),
                error_code,
                bytes_sent: response.body().len(),
                object_size: if is_object_read { header("content-length").and_then(|v| v.parse().ok()) } else { None },
                version_id: header("x-amz-version-id").map(str::to_string),
                started,
            },
        );
    }

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
pub(crate) fn host_id(request_id: &str) -> String {
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
