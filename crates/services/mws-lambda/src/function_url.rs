//! Function URLs that serve: an HTTP request to a function URL invokes the
//! function with Lambda's payload format 2.0 event and turns its result into
//! the HTTP response, as Lambda does.
//!
//! `CreateFunctionUrlConfig` hands out `https://<id>.lambda-url.<region>.on.aws/`
//! as AWS does. MWS serves that URL on its own endpoint when the request's
//! `Host` is the URL's host (e.g. `curl -H 'Host: <id>.lambda-url...'`, or a
//! resolver pointing `*.on.aws` at MWS), and also at
//! `<endpoint>/_aws/lambda-url/<id>/<path>`.
//!
//! Authorization is Lambda's: with `AWS_IAM` the request must be SigV4
//! signed for `lambda` and the caller needs `lambda:InvokeFunctionUrl` (with
//! `lambda:FunctionUrlAuthType`) and `lambda:InvokeFunction` (with
//! `lambda:InvokedViaFunctionUrl`); with `NONE` anyone may call, but the
//! function's resource policy must still grant both to `*`. Refusals are
//! `403 {"Message":"Forbidden"}`, function errors `502`.

use base64::Engine;
use bytes::Bytes;
use mws_core::{CallerKind, ConditionContext, HttpRequest, HttpResponse, RequestContext};
use serde_json::{json, Map, Value};

use crate::generated::types;
use crate::names::FunctionRef;
use crate::Lambda;

const PATH_PREFIX: &str = "/_aws/lambda-url/";
/// Function URL payloads, like synchronous invocations, are limited to 6 MB.
const MAX_PAYLOAD: usize = 6 * 1024 * 1024;

/// The URL id a request is for, and the path it asks for.
pub(crate) fn target(request: &HttpRequest) -> Option<(String, String)> {
    let host = request.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    let mut labels = host.split('.');
    if let (Some(id), Some("lambda-url")) = (labels.next(), labels.next()) {
        if is_id(id) {
            return Some((id.to_string(), request.uri().path().to_string()));
        }
    }
    let rest = request.uri().path().strip_prefix(PATH_PREFIX)?;
    let (id, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(i, p)| (i, format!("/{p}")));
    is_id(id).then(|| (id.to_string(), path))
}

fn is_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

fn response(status: u16, headers: &[(String, String)], body: Vec<u8>) -> HttpResponse {
    let mut b = http::Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(Bytes::from(body)).unwrap_or_else(|_| {
        http::Response::builder().status(502).body(Bytes::from_static(b"Internal Server Error")).expect("valid")
    })
}

fn message(status: u16, error_type: &str, text: &str, request_id: &str) -> HttpResponse {
    response(
        status,
        &[
            ("content-type".into(), "application/json".into()),
            ("x-amzn-errortype".into(), error_type.into()),
            ("x-amzn-requestid".into(), request_id.into()),
        ],
        json!({ "Message": text }).to_string().into_bytes(),
    )
}

fn forbidden(request_id: &str) -> HttpResponse {
    message(403, "AccessDeniedException", "Forbidden", request_id)
}

/// Content types Lambda passes as text rather than base64.
fn is_text(content_type: &str) -> bool {
    let t = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    t.starts_with("text/")
        || t.ends_with("+json")
        || t.ends_with("+xml")
        || matches!(
            t.as_str(),
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-www-form-urlencoded"
                | "application/graphql"
        )
}

fn header_map(request: &HttpRequest) -> (Map<String, Value>, Vec<Value>) {
    let mut headers: Map<String, Value> = Map::new();
    let mut cookies = Vec::new();
    for (name, value) in request.headers() {
        let Ok(v) = value.to_str() else { continue };
        let name = name.as_str().to_ascii_lowercase();
        if name == "cookie" {
            cookies.extend(v.split(';').map(|c| Value::String(c.trim().to_string())).filter(|c| c != ""));
            continue;
        }
        if name == "authorization" || name == "x-amz-security-token" {
            // Lambda keeps credentials out of the event.
            continue;
        }
        match headers.get_mut(&name) {
            Some(Value::String(existing)) => {
                existing.push(',');
                existing.push_str(v);
            }
            _ => {
                headers.insert(name, Value::String(v.to_string()));
            }
        }
    }
    (headers, cookies)
}

fn query_map(raw: &str) -> Option<Map<String, Value>> {
    if raw.is_empty() {
        return None;
    }
    let mut map: Map<String, Value> = Map::new();
    for (k, v) in form_urlencoded::parse(raw.as_bytes()) {
        match map.get_mut(k.as_ref()) {
            Some(Value::String(existing)) => {
                existing.push(',');
                existing.push_str(&v);
            }
            _ => {
                map.insert(k.into_owned(), Value::String(v.into_owned()));
            }
        }
    }
    Some(map)
}

/// CORS headers for a request whose `Origin` the configuration allows.
fn cors_headers(cors: Option<&types::Cors>, request: &HttpRequest, preflight: bool) -> Vec<(String, String)> {
    let Some(cors) = cors else { return Vec::new() };
    let Some(origin) = request.headers().get(http::header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return Vec::new();
    };
    let origins = cors.allow_origins.clone().unwrap_or_default();
    let allowed = origins.iter().any(|o| o == "*" || o.eq_ignore_ascii_case(origin) || wildcard(o, origin));
    if !allowed {
        return Vec::new();
    }
    let mut out = vec![(
        "access-control-allow-origin".to_string(),
        if origins.iter().any(|o| o == "*") && cors.allow_credentials != Some(true) {
            "*".to_string()
        } else {
            origin.to_string()
        },
    )];
    if cors.allow_credentials == Some(true) {
        out.push(("access-control-allow-credentials".into(), "true".into()));
    }
    if let Some(e) = cors.expose_headers.as_ref().filter(|e| !e.is_empty()) {
        out.push(("access-control-expose-headers".into(), e.join(",")));
    }
    if preflight {
        if let Some(m) = cors.allow_methods.as_ref().filter(|m| !m.is_empty()) {
            out.push(("access-control-allow-methods".into(), m.join(",")));
        }
        if let Some(h) = cors.allow_headers.as_ref().filter(|h| !h.is_empty()) {
            out.push(("access-control-allow-headers".into(), h.join(",")));
        }
        if let Some(age) = cors.max_age {
            out.push(("access-control-max-age".into(), age.to_string()));
        }
    }
    out
}

/// `https://*.example.com` style origins.
fn wildcard(pattern: &str, origin: &str) -> bool {
    match pattern.split_once('*') {
        Some((pre, post)) => {
            origin.len() >= pre.len() + post.len() && origin.starts_with(pre) && origin.ends_with(post)
        }
        None => false,
    }
}

/// The HTTP response for a function's result.
fn result_response(payload: &[u8], extra: &[(String, String)], request_id: &str) -> HttpResponse {
    let mut headers: Vec<(String, String)> = extra.to_vec();
    headers.push(("x-amzn-requestid".into(), request_id.into()));
    let parsed: Option<Value> = serde_json::from_slice(payload).ok();
    let Some(Value::Object(obj)) = parsed.as_ref().filter(|v| v.get("statusCode").is_some()) else {
        // Anything else is the body of a 200 JSON response.
        headers.push(("content-type".into(), "application/json".into()));
        return response(200, &headers, payload.to_vec());
    };
    let status = match obj.get("statusCode") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    let Some(status) = status.and_then(|s| u16::try_from(s).ok()).filter(|s| (100..600).contains(s)) else {
        return message(502, "InvalidResponse", "Internal Server Error", request_id);
    };
    let mut has_type = false;
    if let Some(Value::Object(h)) = obj.get("headers") {
        for (k, v) in h {
            let v = match v {
                Value::String(s) => s.clone(),
                Value::Null => continue,
                other => other.to_string(),
            };
            has_type |= k.eq_ignore_ascii_case("content-type");
            headers.push((k.to_ascii_lowercase(), v));
        }
    }
    if let Some(Value::Object(h)) = obj.get("multiValueHeaders") {
        for (k, vs) in h {
            for v in vs.as_array().into_iter().flatten().filter_map(Value::as_str) {
                has_type |= k.eq_ignore_ascii_case("content-type");
                headers.push((k.to_ascii_lowercase(), v.to_string()));
            }
        }
    }
    for c in obj.get("cookies").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        headers.push(("set-cookie".into(), c.to_string()));
    }
    if !has_type {
        headers.push(("content-type".into(), "application/json".into()));
    }
    let body = match obj.get("body") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) if obj.get("isBase64Encoded") == Some(&Value::Bool(true)) => {
            match base64::engine::general_purpose::STANDARD.decode(s) {
                Ok(b) => b,
                Err(_) => return message(502, "InvalidResponse", "Internal Server Error", request_id),
            }
        }
        Some(Value::String(s)) => s.clone().into_bytes(),
        Some(other) => other.to_string().into_bytes(),
    };
    response(status, &headers, body)
}

impl Lambda {
    /// The function (and alias) a URL id belongs to, with its configuration.
    fn url_function(&self, id: &str) -> Option<(FunctionRef, types::FunctionUrlConfig)> {
        let st = self.read();
        let prefix = format!("https://{id}.");
        for func in st.functions.values() {
            for (qualifier, config) in &func.url_configs {
                if !config.function_url.starts_with(&prefix) {
                    continue;
                }
                let arn = config.function_arn.strip_prefix("arn:")?;
                let parts: Vec<&str> = arn.splitn(7, ':').collect();
                if parts.len() < 6 {
                    return None;
                }
                let f = FunctionRef {
                    partition: parts[0].to_string(),
                    region: parts[2].to_string(),
                    account: parts[3].to_string(),
                    name: parts[5].to_string(),
                    qualifier: (!qualifier.is_empty()).then(|| qualifier.clone()),
                };
                return Some((f, config.clone()));
            }
        }
        None
    }

    /// Serve a request to a function URL.
    pub(crate) async fn serve_function_url(
        &self,
        ctx: &RequestContext,
        request: &HttpRequest,
        id: &str,
        path: &str,
    ) -> HttpResponse {
        let request_id = ctx.request_id.clone();
        let Some((f, config)) = self.url_function(id) else { return forbidden(&request_id) };
        let iam = config.auth_type == "AWS_IAM";
        let preflight = request.method() == http::Method::OPTIONS
            && request.headers().contains_key("access-control-request-method")
            && config.cors.is_some();
        if preflight {
            let mut headers = cors_headers(config.cors.as_ref(), request, true);
            headers.push(("x-amzn-requestid".into(), request_id.clone()));
            return response(200, &headers, Vec::new());
        }
        let signed = ctx.caller.kind != CallerKind::Anonymous;
        if iam && !signed {
            return forbidden(&request_id);
        }
        let mut ctx = ctx.clone();
        ctx.region = f.region.clone();
        if !iam {
            // With `NONE` Lambda does not look at a signature: the
            // function's resource policy alone decides.
            ctx.caller = mws_core::Caller::anonymous();
        }
        let mut c = ConditionContext::new();
        c.insert("lambda:FunctionUrlAuthType".into(), vec![config.auth_type.clone()]);
        if self.authorize_function(&ctx, "lambda:InvokeFunctionUrl", &f, c).is_err() {
            return forbidden(&request_id);
        }
        let mut c = ConditionContext::new();
        c.insert("lambda:InvokedViaFunctionUrl".into(), vec!["true".into()]);
        c.insert("lambda:FunctionUrlAuthType".into(), vec![config.auth_type.clone()]);
        if self.authorize_function(&ctx, "lambda:InvokeFunction", &f, c).is_err() {
            return forbidden(&request_id);
        }

        let body = request.body();
        if body.len() > MAX_PAYLOAD {
            return message(
                413,
                "RequestEntityTooLargeException",
                "Request must be smaller than 6291456 bytes",
                &request_id,
            );
        }
        let host = request
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .filter(|h| h.starts_with(id))
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_else(|| format!("{id}.lambda-url.{}.on.aws", f.region));
        let (headers, cookies) = header_map(request);
        let raw_query = request.uri().query().unwrap_or("").to_string();
        let content_type = request.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
        let text = std::str::from_utf8(body).ok().filter(|_| content_type.is_none_or(is_text));
        let now = ctx.received_at;
        let mut event = json!({
            "version": "2.0",
            "routeKey": "$default",
            "rawPath": path,
            "rawQueryString": raw_query,
            "headers": headers,
            "requestContext": {
                "accountId": if iam { ctx.caller.account_id.clone() } else { "anonymous".to_string() },
                "apiId": id,
                "domainName": host,
                "domainPrefix": id,
                "http": {
                    "method": request.method().as_str(),
                    "path": path,
                    "protocol": "HTTP/1.1",
                    "sourceIp": ctx.source_ip.clone().unwrap_or_else(|| "127.0.0.1".into()),
                    "userAgent": request.headers().get(http::header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or(""),
                },
                "requestId": request_id,
                "routeKey": "$default",
                "stage": "$default",
                "time": now.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
                "timeEpoch": now.timestamp_millis(),
            },
            "isBase64Encoded": false,
        });
        if !cookies.is_empty() {
            event["cookies"] = Value::Array(cookies);
        }
        if let Some(q) = query_map(&raw_query) {
            event["queryStringParameters"] = Value::Object(q);
        }
        if iam {
            event["requestContext"]["authorizer"] = json!({
                "iam": {
                    "accessKey": ctx.caller.access_key_id,
                    "accountId": ctx.caller.account_id,
                    "callerId": ctx.caller.user_id,
                    "cognitoIdentity": null,
                    "principalOrgId": null,
                    "userArn": ctx.caller.arn,
                    "userId": ctx.caller.user_id,
                }
            });
        }
        if !body.is_empty() {
            match text {
                Some(t) => event["body"] = Value::String(t.to_string()),
                None => {
                    event["body"] = Value::String(base64::engine::general_purpose::STANDARD.encode(body));
                    event["isBase64Encoded"] = Value::Bool(true);
                }
            }
        }

        let cors = cors_headers(config.cors.as_ref(), request, false);
        match self.run(&ctx, &f, event.to_string().into_bytes(), None).await {
            Ok(ran) if ran.outcome.function_error.is_none() => {
                result_response(&ran.outcome.payload, &cors, &request_id)
            }
            Ok(_) => message(502, "FunctionError", "Internal Server Error", &request_id),
            Err(e) if e.code == "TooManyRequestsException" => {
                message(429, "TooManyRequestsException", "Rate Exceeded.", &request_id)
            }
            Err(_) => message(502, "ServiceException", "Internal Server Error", &request_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: &str, path: &str) -> HttpRequest {
        http::Request::builder().uri(path).header("host", host).body(Bytes::new()).unwrap()
    }

    #[test]
    fn targets() {
        let id = "abcdefghijklmnopqrstuvwxyz012345";
        assert_eq!(
            target(&req(&format!("{id}.lambda-url.us-east-1.on.aws"), "/x?y=1")),
            Some((id.to_string(), "/x".to_string()))
        );
        assert_eq!(
            target(&req("localhost:4566", &format!("/_aws/lambda-url/{id}/a/b"))),
            Some((id.to_string(), "/a/b".to_string()))
        );
        assert_eq!(target(&req("localhost:4566", &format!("/_aws/lambda-url/{id}"))), Some((id.into(), "/".into())));
        assert_eq!(target(&req("localhost:4566", "/2015-03-31/functions")), None);
    }

    #[test]
    fn results() {
        let r = result_response(br#"{"hello":"world"}"#, &[], "r");
        assert_eq!(r.status(), 200);
        assert_eq!(r.body().as_ref(), br#"{"hello":"world"}"#);
        let r = result_response(
            br#"{"statusCode":201,"headers":{"Content-Type":"text/plain"},"body":"aGk=","isBase64Encoded":true,"cookies":["a=b"]}"#,
            &[],
            "r",
        );
        assert_eq!(r.status(), 201);
        assert_eq!(r.headers()["content-type"], "text/plain");
        assert_eq!(r.headers()["set-cookie"], "a=b");
        assert_eq!(r.body().as_ref(), b"hi");
    }
}
