//! CORS: preflight (`OPTIONS`) answers and `Access-Control-*` headers on
//! responses, from the bucket's CORS configuration.

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext, ServiceError};

use crate::generated::{self, types};
use crate::S3;

fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request.headers().get(name).and_then(|v| v.to_str().ok())
}

fn bucket_of(request: &HttpRequest) -> Option<String> {
    let seg = request.uri().path().trim_start_matches('/').split('/').next()?;
    (!seg.is_empty()).then(|| percent_encoding::percent_decode_str(seg).decode_utf8_lossy().into_owned())
}

fn wildcard(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        Some((pre, post)) => value.len() >= pre.len() + post.len() && value.starts_with(pre) && value.ends_with(post),
        None => pattern == value,
    }
}

/// The first rule allowing `origin`, `method` and every requested header.
fn matching_rule<'a>(
    config: &'a types::CORSConfiguration,
    origin: &str,
    method: &str,
    headers: &[String],
) -> Option<&'a types::CORSRule> {
    config.cors_rules.iter().find(|r| {
        r.allowed_origins.iter().any(|o| wildcard(o, origin))
            && r.allowed_methods.iter().any(|m| m == method)
            && headers.iter().all(|h| {
                r.allowed_headers.iter().flatten().any(|a| wildcard(&a.to_ascii_lowercase(), &h.to_ascii_lowercase()))
            })
    })
}

fn cors_error(ctx: &RequestContext, status: u16, code: &'static str, message: &str) -> HttpResponse {
    let e = ServiceError::client(code, status, message);
    mws_proto_restxml::error_response(&generated::SERVICE_INFO, &ctx.request_id, &e)
}

fn allow_headers(
    b: &mut http::response::Builder,
    rule: &types::CORSRule,
    origin: &str,
    requested_headers: &[String],
    preflight: bool,
) {
    let any_origin = rule.allowed_origins.iter().any(|o| o == "*");
    let h = b.headers_mut().expect("builder is valid");
    let mut set = |k: &'static str, v: String| {
        if let Ok(v) = http::HeaderValue::from_str(&v) {
            h.insert(k, v);
        }
    };
    set("access-control-allow-origin", if any_origin { "*".into() } else { origin.to_string() });
    set("access-control-allow-methods", rule.allowed_methods.join(", "));
    if !any_origin {
        set("access-control-allow-credentials", "true".into());
    }
    if preflight && !requested_headers.is_empty() {
        set("access-control-allow-headers", requested_headers.join(", "));
    }
    if let Some(expose) = rule.expose_headers.as_ref().filter(|e| !e.is_empty()) {
        set("access-control-expose-headers", expose.join(", "));
    }
    if let Some(age) = rule.max_age_seconds {
        set("access-control-max-age", age.to_string());
    }
    set("vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method".into());
}

impl S3 {
    /// Answer a CORS preflight request.
    pub(crate) fn preflight(&self, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
        let Some(origin) = header(request, "origin") else {
            return cors_error(ctx, 400, "BadRequest", "Insufficient information. Origin request header needed.");
        };
        let Some(method) = header(request, "access-control-request-method") else {
            return cors_error(ctx, 400, "BadRequest", "Invalid Access-Control-Request-Method: null");
        };
        let requested: Vec<String> = header(request, "access-control-request-headers")
            .map(|h| h.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let Some(bucket) = bucket_of(request) else {
            return cors_error(ctx, 403, "AccessForbidden", "CORSResponse: Bucket not found");
        };
        let st = self.read();
        let Some(b) = st.buckets.get(&bucket) else {
            return cors_error(ctx, 403, "AccessForbidden", "CORSResponse: Bucket not found");
        };
        let Some(config) = &b.cors else {
            return cors_error(ctx, 403, "AccessForbidden", "CORSResponse: CORS is not enabled for this bucket.");
        };
        let Some(rule) = matching_rule(config, origin, method, &requested) else {
            return cors_error(
                ctx,
                403,
                "AccessForbidden",
                "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.",
            );
        };
        let mut b =
            http::Response::builder().status(200).header(generated::SERVICE_INFO.request_id_header, &ctx.request_id);
        allow_headers(&mut b, rule, origin, &requested, true);
        b.header(http::header::CONTENT_LENGTH, 0).body(Bytes::new()).expect("valid response")
    }

    /// Add `Access-Control-*` headers to a response when the request carries
    /// an `Origin` the bucket's CORS rules allow.
    pub(crate) fn cors_headers(&self, request: &HttpRequest, response: &mut HttpResponse) {
        let Some(origin) = header(request, "origin") else { return };
        let Some(bucket) = bucket_of(request) else { return };
        let st = self.read();
        let Some(config) = st.buckets.get(&bucket).and_then(|b| b.cors.as_ref()) else { return };
        let Some(rule) = matching_rule(config, origin, request.method().as_str(), &[]) else { return };
        let mut b = http::Response::builder();
        allow_headers(&mut b, rule, origin, &[], false);
        if let Some(h) = b.headers_ref() {
            for (k, v) in h {
                response.headers_mut().insert(k.clone(), v.clone());
            }
        }
    }
}
