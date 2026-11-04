//! Static website hosting: the website endpoint serves a bucket's objects
//! to anonymous `GET`/`HEAD` requests following its website configuration
//! (index and error documents, redirects, routing rules, and objects'
//! `x-amz-website-redirect-location`), with HTML error pages.
//!
//! Requests reach it by host, as on AWS
//! (`<bucket>.s3-website-<region>.amazonaws.com`,
//! `<bucket>.s3-website.<region>.amazonaws.com`, or
//! `<bucket>.s3-website.localhost`), or path-style at
//! `/_aws/s3-website/<bucket>/<key>`.

use bytes::Bytes;
use http::Method;
use mws_core::{HttpRequest, HttpResponse, RequestContext};

use crate::generated::types;
use crate::S3;

pub(crate) const PATH_PREFIX: &str = "/_aws/s3-website/";

/// The bucket and object path of a website request, if `request` is one.
pub(crate) fn target(request: &HttpRequest) -> Option<(String, String)> {
    let path = request.uri().path();
    if let Some(rest) = path.strip_prefix(PATH_PREFIX) {
        let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
        return (!bucket.is_empty()).then(|| (bucket.to_string(), format!("/{key}")));
    }
    let host = request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok())?;
    let host = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host, |h| h.0);
    let host = host.to_ascii_lowercase();
    let i = host.find(".s3-website")?;
    let after = &host[i + ".s3-website".len()..];
    let ok = after.starts_with('-') || after.starts_with('.');
    (ok && i > 0).then(|| (host[..i].to_string(), path.to_string()))
}

fn html_error(status: u16, code: &str, message: &str, extra: &[(&str, &str)], request_id: &str) -> HttpResponse {
    let reason = http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("Error");
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut items = format!("<li>Code: {}</li>\n<li>Message: {}</li>\n", esc(code), esc(message));
    for (k, v) in extra {
        items.push_str(&format!("<li>{k}: {}</li>\n", esc(v)));
    }
    let body = format!(
        "<html>\n<head><title>{status} {reason}</title></head>\n<body>\n<h1>{status} {reason}</h1>\n<ul>\n{items}<li>RequestId: {request_id}</li>\n<li>HostId: {}</li>\n</ul>\n<hr/>\n</body>\n</html>\n",
        crate::host_id(request_id)
    );
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("x-amz-request-id", request_id)
        .body(Bytes::from(body))
        .expect("valid response")
}

fn redirect(status: u16, location: &str, request_id: &str) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::LOCATION, location)
        .header("x-amz-request-id", request_id)
        .body(Bytes::new())
        .expect("valid response")
}

fn decode(path: &str) -> String {
    percent_encoding::percent_decode_str(path).decode_utf8_lossy().into_owned()
}

fn encode(key: &str) -> String {
    const SET: &percent_encoding::AsciiSet =
        &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~').remove(b'/');
    percent_encoding::utf8_percent_encode(key, SET).to_string()
}

/// Where a routing rule's redirect sends `key`.
fn rule_location(rule: &types::Redirect, key: &str, matched_prefix: &str, host: &str, protocol: &str) -> String {
    let new_key = match (&rule.replace_key_with, &rule.replace_key_prefix_with) {
        (Some(k), _) => k.clone(),
        (None, Some(p)) => format!("{p}{}", key.strip_prefix(matched_prefix).unwrap_or(key)),
        (None, None) => key.to_string(),
    };
    let host = rule.host_name.as_deref().unwrap_or(host);
    let protocol = rule.protocol.as_deref().unwrap_or(protocol);
    format!("{protocol}://{host}/{}", encode(&new_key))
}

impl S3 {
    pub(crate) async fn serve_website(
        &self,
        ctx: &RequestContext,
        request: &HttpRequest,
        bucket: &str,
        path: &str,
    ) -> HttpResponse {
        let rid = ctx.request_id.as_str();
        let head = request.method() == Method::HEAD;
        let mut response = self.website_response(ctx, request, bucket, path).await;
        if let Ok(v) = http::HeaderValue::from_str(&crate::host_id(rid)) {
            response.headers_mut().insert("x-amz-id-2", v);
        }
        if head {
            *response.body_mut() = Bytes::new();
        }
        let _ = rid;
        response
    }

    async fn website_response(
        &self,
        ctx: &RequestContext,
        request: &HttpRequest,
        bucket: &str,
        path: &str,
    ) -> HttpResponse {
        let rid = ctx.request_id.as_str();
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            let method = request.method().as_str();
            return html_error(
                405,
                "MethodNotAllowed",
                "The specified method is not allowed against this resource.",
                &[("Method", method), ("ResourceType", "OBJECT")],
                rid,
            );
        }
        let config = {
            let st = self.read();
            match st.buckets.get(bucket) {
                None => {
                    return html_error(
                        404,
                        "NoSuchBucket",
                        "The specified bucket does not exist",
                        &[("BucketName", bucket)],
                        rid,
                    )
                }
                Some(b) => match &b.website {
                    Some(w) => w.clone(),
                    None => {
                        return html_error(
                            404,
                            "NoSuchWebsiteConfiguration",
                            "The specified bucket does not have a website configuration",
                            &[("BucketName", bucket)],
                            rid,
                        )
                    }
                },
            }
        };
        let host =
            request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("localhost").to_string();
        let original = decode(path.trim_start_matches('/'));
        if let Some(all) = &config.redirect_all_requests_to {
            let protocol = all.protocol.as_deref().unwrap_or("http");
            return redirect(301, &format!("{protocol}://{}/{}", all.host_name, encode(&original)), rid);
        }
        let rules = config.routing_rules.clone().unwrap_or_default();
        // Rules without an error-code condition apply before the lookup.
        for rule in &rules {
            let c = rule.condition.clone().unwrap_or_default();
            if c.http_error_code_returned_equals.is_some() {
                continue;
            }
            let prefix = c.key_prefix_equals.clone().unwrap_or_default();
            if original.starts_with(&prefix) {
                let code = rule.redirect.http_redirect_code.as_deref().and_then(|c| c.parse().ok()).unwrap_or(301);
                return redirect(code, &rule_location(&rule.redirect, &original, &prefix, &host, "http"), rid);
            }
        }
        let suffix = config.index_document.as_ref().map(|i| i.suffix.clone()).unwrap_or_default();
        let key = if original.is_empty() || original.ends_with('/') {
            format!("{original}{suffix}")
        } else {
            original.clone()
        };

        let mut fetched = self.website_get(ctx, request, bucket, &key).await;
        if fetched.status() == 404 && !original.is_empty() && !original.ends_with('/') && !suffix.is_empty() {
            // `docs` with `docs/index.html` present redirects to `docs/`.
            let index = self.website_get(ctx, request, bucket, &format!("{original}/{suffix}")).await;
            if index.status().is_success() {
                return redirect(302, &format!("/{}/", encode(&original)), rid);
            }
        }
        let status = fetched.status().as_u16();
        if (200..300).contains(&status) || status == 304 {
            if let Some(location) =
                fetched.headers().get("x-amz-website-redirect-location").and_then(|v| v.to_str().ok())
            {
                return redirect(301, location, rid);
            }
            fetched.headers_mut().remove("x-amz-website-redirect-location");
            return fetched;
        }
        // Rules keyed on the error code apply to failed lookups.
        for rule in &rules {
            let c = rule.condition.clone().unwrap_or_default();
            let Some(code) = &c.http_error_code_returned_equals else { continue };
            let prefix = c.key_prefix_equals.clone().unwrap_or_default();
            if code == &status.to_string() && original.starts_with(&prefix) {
                let redirect_code =
                    rule.redirect.http_redirect_code.as_deref().and_then(|c| c.parse().ok()).unwrap_or(301);
                return redirect(redirect_code, &rule_location(&rule.redirect, &original, &prefix, &host, "http"), rid);
            }
        }
        let (code, message, extra): (&str, &str, Vec<(&str, &str)>) = match status {
            404 => ("NoSuchKey", "The specified key does not exist.", vec![("Key", key.as_str())]),
            403 => ("AccessDenied", "Access Denied", vec![]),
            _ => ("InternalError", "We encountered an internal error. Please try again.", vec![]),
        };
        if let Some(doc) = &config.error_document {
            let mut page = self.website_get(ctx, request, bucket, &doc.key).await;
            if page.status().is_success() {
                *page.status_mut() = fetched.status();
                page.headers_mut().remove("x-amz-website-redirect-location");
                return page;
            }
            let mut response = html_error(status, code, message, &extra, rid);
            let body = String::from_utf8_lossy(response.body()).replace(
                "<hr/>",
                &format!(
                    "<h3>An Error Occurred While Attempting to Retrieve a Custom Error Document</h3>\n<ul>\n<li>Code: {}</li>\n<li>Message: {}</li>\n</ul>\n<hr/>",
                    if page.status() == 404 { "NoSuchKey" } else { "AccessDenied" },
                    if page.status() == 404 { "The specified key does not exist." } else { "Access Denied" },
                ),
            );
            *response.body_mut() = Bytes::from(body);
            return response;
        }
        html_error(status, code, message, &extra, rid)
    }

    /// `GET` an object as the anonymous website visitor, passing the
    /// visitor's conditional headers along.
    async fn website_get(&self, ctx: &RequestContext, request: &HttpRequest, bucket: &str, key: &str) -> HttpResponse {
        let mut get = http::Request::builder().method(Method::GET).uri(format!("/{bucket}/{}", encode(key)));
        for name in ["if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "range"] {
            if let Some(v) = request.headers().get(name) {
                get = get.header(name, v.clone());
            }
        }
        let Ok(get) = get.body(Bytes::new()) else {
            return html_error(400, "InvalidRequest", "Invalid key", &[], &ctx.request_id);
        };
        let ctx = RequestContext { caller: mws_core::Caller::anonymous(), ..ctx.clone() };
        let call = self.call(&ctx, Some(&get));
        let mut response = match crate::generated::route(&call, &ctx, &get).await {
            Ok(r) => r,
            Err(e) => {
                let mut r = http::Response::new(Bytes::new());
                *r.status_mut() = http::StatusCode::from_u16(e.status).unwrap_or(http::StatusCode::FORBIDDEN);
                r
            }
        };
        if response.status() == http::StatusCode::OK
            && get.headers().contains_key(http::header::RANGE)
            && response.headers().contains_key(http::header::CONTENT_RANGE)
        {
            *response.status_mut() = http::StatusCode::PARTIAL_CONTENT;
        }
        response
    }
}
