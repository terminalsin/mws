//! Serving deployed sites, and the HTTP side channels Amplify hands out
//! (upload URLs, download links, webhooks).

use std::collections::BTreeMap;

use base64::Engine;
use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use serde::Deserialize;

use crate::deploy::glob_regex;
use crate::jobs::{DOWNLOAD_PREFIX, UPLOAD_PREFIX};
use crate::rules::Rule;
use crate::state::AccessEntry;
use crate::Amplify;

const SITE_PREFIX: &str = "/_aws/amplify/sites/";

/// Where a site request goes.
struct Target {
    app_id: String,
    branch: String,
    host: String,
    /// The path within the site, with its leading `/`.
    path: String,
}

fn host(request: &HttpRequest) -> String {
    let h = request
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| request.uri().host())
        .unwrap_or("");
    let h = if h.starts_with('[') { h } else { h.split(':').next().unwrap_or("") };
    h.trim_end_matches('.').to_ascii_lowercase()
}

fn is_app_id(s: &str) -> bool {
    s.len() > 1 && s.starts_with('d') && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The branch whose display name is `label`.
fn branch_by_label(amplify: &Amplify, app_id: &str, label: &str) -> Option<String> {
    let st = amplify.read();
    let rec = st.apps.get(app_id)?;
    rec.branches.values().find(|b| b.branch.display_name == label).map(|b| b.branch.branch_name.clone())
}

fn target(amplify: &Amplify, request: &HttpRequest) -> Option<Target> {
    let h = host(request);
    let path = request.uri().path().to_string();
    // `<branch>.<appId>.amplifyapp.<anything>`
    let labels: Vec<&str> = h.split('.').collect();
    // An unknown app or branch still belongs to Amplify: it answers 404.
    if labels.len() >= 3 && labels[2] == "amplifyapp" && is_app_id(labels[1]) {
        let branch = branch_by_label(amplify, labels[1], labels[0]).unwrap_or_default();
        return Some(Target { app_id: labels[1].to_string(), branch, host: h, path });
    }
    if let Some(rest) = path.strip_prefix(SITE_PREFIX) {
        let mut parts = rest.splitn(3, '/');
        let app_id = parts.next().unwrap_or("").to_string();
        let label = parts.next().unwrap_or("");
        let branch = branch_by_label(amplify, &app_id, label).unwrap_or_default();
        let path = format!("/{}", parts.next().unwrap_or(""));
        let host = format!("{label}.{app_id}.amplifyapp.com");
        return Some(Target { app_id, branch, host, path });
    }
    if h.contains('.') {
        let (app_id, branch) = amplify.custom_domain_target(&h)?;
        return Some(Target { app_id, branch, host: h, path });
    }
    None
}

pub(crate) fn is_site_request(amplify: &Amplify, request: &HttpRequest) -> bool {
    target(amplify, request).is_some()
}

fn is_webhook(request: &HttpRequest) -> bool {
    request.uri().path() == "/prod/webhooks"
        && request.uri().query().is_some_and(|q| q.contains("id=") && q.contains("token="))
}

pub(crate) fn is_side_channel(request: &HttpRequest) -> bool {
    let p = request.uri().path();
    p.starts_with(UPLOAD_PREFIX) || p.starts_with(DOWNLOAD_PREFIX) || is_webhook(request)
}

fn response(status: u16, headers: &[(&str, String)], body: Vec<u8>) -> HttpResponse {
    let mut b = http::Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    b.body(Bytes::from(body)).unwrap_or_else(|_| {
        http::Response::builder().status(500).body(Bytes::from_static(b"Internal Server Error")).expect("valid")
    })
}

fn s3_style_error(status: u16, code: &str, message: &str) -> HttpResponse {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code><Message>{message}</Message></Error>"
    );
    response(status, &[("content-type", "application/xml".into())], body.into_bytes())
}

pub(crate) fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" | "map" => "application/json",
        "txt" => "text/plain",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CustomHeaders {
    #[serde(default)]
    custom_headers: Vec<HeaderRule>,
}

#[derive(Debug, Deserialize)]
struct HeaderRule {
    pattern: String,
    #[serde(default)]
    headers: Vec<HeaderValue>,
}

#[derive(Debug, Deserialize)]
struct HeaderValue {
    key: String,
    value: serde_yaml::Value,
}

/// Parse a `customHeaders` YAML document (the app setting or
/// `customHttp.yml`).
pub(crate) fn parse_custom_headers(yaml: &str) -> Result<CustomHeaders, String> {
    if yaml.trim().is_empty() {
        return Ok(CustomHeaders { custom_headers: Vec::new() });
    }
    let parsed: CustomHeaders = serde_yaml::from_str(yaml).map_err(|e| format!("Invalid custom headers: {e}"))?;
    for rule in &parsed.custom_headers {
        if glob_regex(&rule.pattern).is_none() {
            return Err(format!("Invalid custom header pattern: {}", rule.pattern));
        }
        for h in &rule.headers {
            if http::HeaderName::from_bytes(h.key.as_bytes()).is_err() {
                return Err(format!("Invalid custom header key: {}", h.key));
            }
        }
    }
    Ok(parsed)
}

fn header_value(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

/// Everything serving needs, copied out of the state lock.
struct SiteView {
    files: BTreeMap<String, String>,
    rules: Vec<Rule>,
    basic_auth: Option<String>,
    custom_headers: Option<String>,
}

enum Resolved {
    File(String),
    /// A directory requested without its trailing slash.
    Directory,
    Missing,
}

fn resolve(files: &BTreeMap<String, String>, path: &str) -> Resolved {
    let p = path.trim_start_matches('/');
    let key = if p.is_empty() || p.ends_with('/') { format!("{p}index.html") } else { p.to_string() };
    if files.contains_key(&key) {
        return Resolved::File(key);
    }
    if !p.is_empty() && !p.ends_with('/') && files.contains_key(&format!("{p}/index.html")) {
        return Resolved::Directory;
    }
    Resolved::Missing
}

fn decode_path(path: &str) -> String {
    percent_encoding::percent_decode_str(path).decode_utf8_lossy().to_string()
}

impl Amplify {
    fn site_view(&self, t: &Target) -> Option<SiteView> {
        let st = self.read();
        let rec = st.apps.get(&t.app_id)?;
        let b = rec.branches.get(&t.branch)?;
        let basic_auth = if b.branch.enable_basic_auth {
            b.branch.basic_auth_credentials.clone()
        } else if rec.app.enable_basic_auth {
            rec.app.basic_auth_credentials.clone()
        } else {
            None
        };
        let rules = rec.app.custom_rules.iter().flatten().filter_map(|r| Rule::parse(r).ok()).collect();
        let site = b.site.as_ref();
        Some(SiteView {
            files: site.map(|s| s.files.clone()).unwrap_or_default(),
            rules,
            basic_auth,
            custom_headers: site.and_then(|s| s.custom_headers.clone()).or_else(|| rec.app.custom_headers.clone()),
        })
    }

    fn file_bytes(&self, hash: &str) -> Vec<u8> {
        self.read().blobs.get(hash).map(|b| b.0.clone()).unwrap_or_default()
    }

    /// Serve a request for a deployed site, if it is one.
    pub(crate) async fn serve_site(&self, ctx: &RequestContext, request: &HttpRequest) -> Option<HttpResponse> {
        let t = target(self, request)?;
        let Some(view) = self.site_view(&t) else {
            return Some(response(404, &[("content-type", "text/html".into())], not_found_page()));
        };
        let mut response = self.site_response(request, &t, &view).await;
        if response.status() != 401 {
            self.add_custom_headers(&mut response, &view, &t.path);
        }
        let header = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        self.record_access(
            &t.app_id,
            AccessEntry {
                time: ctx.received_at,
                client_ip: ctx.source_ip.clone().unwrap_or_default(),
                method: request.method().to_string(),
                host: t.host.clone(),
                path: t.path.clone(),
                query: request.uri().query().unwrap_or("").to_string(),
                status: response.status().as_u16(),
                bytes: response.body().len(),
                referer: header("referer"),
                user_agent: header("user-agent"),
                request_id: ctx.request_id.clone(),
                content_type: response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string(),
            },
        );
        if request.method() == http::Method::HEAD {
            let (parts, _) = response.into_parts();
            return Some(http::Response::from_parts(parts, Bytes::new()));
        }
        Some(response)
    }

    async fn site_response(&self, request: &HttpRequest, t: &Target, view: &SiteView) -> HttpResponse {
        if let Some(expected) = &view.basic_auth {
            let given = request
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")))
                .map(str::trim);
            let ok = given.is_some_and(|g| {
                let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).ok();
                decode(g).is_some_and(|g| Some(g) == decode(expected))
            });
            if !ok {
                return response(
                    401,
                    &[("www-authenticate", "Basic".into()), ("content-type", "text/plain".into())],
                    b"Unauthorized".to_vec(),
                );
            }
        }
        if !matches!(*request.method(), http::Method::GET | http::Method::HEAD | http::Method::OPTIONS) {
            return s3_style_error(
                405,
                "MethodNotAllowed",
                "The specified method is not allowed against this resource.",
            );
        }
        if view.files.is_empty() {
            return response(404, &[("content-type", "text/html".into())], not_found_page());
        }
        let path = decode_path(&t.path);
        let query = request.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        let exists = !matches!(resolve(&view.files, &path), Resolved::Missing);
        for rule in &view.rules {
            let Some(m) = rule.matches(&t.host, &path) else { continue };
            match rule.status.as_str() {
                "301" | "302" => {
                    let location = if m.target.contains('?') { m.target } else { format!("{}{query}", m.target) };
                    return response(rule.status.parse().unwrap_or(302), &[("location", location)], Vec::new());
                }
                // Not-found rules apply only when there is no such file.
                "404" | "404-200" if exists => continue,
                "200" | "404" | "404-200" => {
                    let status = if rule.status == "404" { 404 } else { 200 };
                    if m.target.starts_with("http://") || m.target.starts_with("https://") {
                        return self.proxy(&m.target, status).await;
                    }
                    let target = m.target.split('?').next().unwrap_or("/").to_string();
                    return self.serve_file(request, view, &target, status);
                }
                _ => continue,
            }
        }
        self.serve_file(request, view, &path, 200)
    }

    fn serve_file(&self, request: &HttpRequest, view: &SiteView, path: &str, status: u16) -> HttpResponse {
        match resolve(&view.files, path) {
            Resolved::File(key) => {
                let hash = &view.files[&key];
                let etag = format!("\"{}\"", &hash[..32.min(hash.len())]);
                if status == 200
                    && request.headers().get(http::header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(&etag)
                {
                    return response(304, &[("etag", etag)], Vec::new());
                }
                response(
                    status,
                    &[
                        ("content-type", content_type(&key).into()),
                        ("etag", etag),
                        ("cache-control", "public, max-age=0, must-revalidate".into()),
                    ],
                    self.file_bytes(hash),
                )
            }
            Resolved::Directory => {
                let query = request.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
                response(301, &[("location", format!("{path}/{query}"))], Vec::new())
            }
            Resolved::Missing => response(404, &[("content-type", "text/html".into())], not_found_page()),
        }
    }

    /// A rewrite to an external URL: Amplify proxies it.
    async fn proxy(&self, url: &str, status: u16) -> HttpResponse {
        match crate::http::send(crate::http::Request { method: "GET", url, headers: Vec::new(), body: None }).await {
            Ok(r) => {
                let ct = r.headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.clone());
                let code = if status == 404 { 404 } else { r.status };
                response(code, &[("content-type", ct.unwrap_or_else(|| "application/octet-stream".into()))], r.body)
            }
            Err(_) => response(502, &[("content-type", "text/plain".into())], b"Bad Gateway".to_vec()),
        }
    }

    fn add_custom_headers(&self, response: &mut HttpResponse, view: &SiteView, path: &str) {
        let Some(yaml) = &view.custom_headers else { return };
        let Ok(parsed) = parse_custom_headers(yaml) else { return };
        let rel = path.trim_start_matches('/');
        for rule in &parsed.custom_headers {
            let Some(glob) = glob_regex(&rule.pattern) else { continue };
            let pattern_all = rule.pattern.trim() == "**" || rule.pattern.trim() == "**/*";
            if !(pattern_all || glob.is_match(rel) || glob.is_match(&format!("{rel}index.html"))) {
                continue;
            }
            for h in &rule.headers {
                let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(h.key.as_bytes()),
                    http::HeaderValue::from_str(&header_value(&h.value)),
                ) else {
                    continue;
                };
                response.headers_mut().insert(name, value);
            }
        }
    }

    /// Upload URLs, download links and webhook calls.
    pub(crate) async fn serve_side_channel(&self, ctx: &RequestContext, request: &HttpRequest) -> Option<HttpResponse> {
        let path = request.uri().path();
        if let Some(rest) = path.strip_prefix(UPLOAD_PREFIX) {
            return Some(self.upload(request, rest));
        }
        if let Some(token) = path.strip_prefix(DOWNLOAD_PREFIX) {
            return Some(self.download(ctx, token));
        }
        if is_webhook(request) {
            return Some(self.webhook_call(ctx, request));
        }
        None
    }

    fn upload(&self, request: &HttpRequest, rest: &str) -> HttpResponse {
        if request.method() != http::Method::PUT {
            return s3_style_error(
                405,
                "MethodNotAllowed",
                "The specified method is not allowed against this resource.",
            );
        }
        let token = rest.split('/').next().unwrap_or("");
        let mut st = self.write();
        let Some(upload) = st.uploads.get(token).cloned() else {
            return s3_style_error(403, "AccessDenied", "Access Denied");
        };
        let hash = st.put_blob(request.body().to_vec());
        let job = st
            .apps
            .get_mut(&upload.app_id)
            .and_then(|a| a.branches.get_mut(&upload.branch_name))
            .and_then(|b| b.jobs.get_mut(&upload.job_id));
        let Some(job) = job.filter(|j| j.summary.status == "CREATED") else {
            return s3_style_error(403, "AccessDenied", "Request has expired");
        };
        job.uploaded.insert(upload.file.unwrap_or_default(), hash.clone());
        let md5 = hex::encode(crate::deploy::md5_digest(request.body()));
        response(200, &[("etag", format!("\"{md5}\""))], Vec::new())
    }

    fn download(&self, ctx: &RequestContext, token: &str) -> HttpResponse {
        let st = self.read();
        match st.downloads.get(token) {
            Some(d) if d.expires > ctx.received_at.timestamp() => {
                let data = st.blobs.get(&d.blob).map(|b| b.0.clone()).unwrap_or_default();
                response(200, &[("content-type", d.content_type.clone())], data)
            }
            Some(_) => s3_style_error(403, "AccessDenied", "Request has expired"),
            None => s3_style_error(403, "AccessDenied", "Access Denied"),
        }
    }

    fn webhook_call(&self, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
        let params: BTreeMap<String, String> =
            form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes()).into_owned().collect();
        let json = |status: u16, body: serde_json::Value| {
            response(status, &[("content-type", "application/json".into())], body.to_string().into_bytes())
        };
        if request.method() != http::Method::POST {
            return json(405, serde_json::json!({ "message": "Method Not Allowed" }));
        }
        let hook = {
            let st = self.read();
            st.webhooks
                .get(params.get("id").map(String::as_str).unwrap_or(""))
                .filter(|w| Some(&w.token) == params.get("token"))
                .cloned()
        };
        let Some(hook) = hook else {
            return json(403, serde_json::json!({ "message": "Forbidden" }));
        };
        let mut hook_ctx = ctx.clone();
        hook_ctx.region = hook.region.clone();
        let app_id = hook.webhook.app_id.clone().unwrap_or_default();
        let connected = self.read().apps.get(&app_id).is_some_and(|a| !a.app.repository.is_empty());
        if !connected {
            return json(400, serde_json::json!({ "message": "The app is not connected to a repository." }));
        }
        let commit = (String::from("HEAD"), String::new(), ctx.received_at);
        match self.start_build(&hook_ctx, &app_id, &hook.webhook.branch_name, "WEB_HOOK", commit) {
            Ok(summary) => json(200, serde_json::json!({ "jobId": summary.job_id, "jobArn": summary.job_arn })),
            Err(e) => json(e.status, serde_json::json!({ "message": e.message })),
        }
    }
}

fn not_found_page() -> Vec<u8> {
    b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>".to_vec()
}
