//! Lambda targets: the request becomes ELB's Lambda event, the function's
//! result the HTTP response, as ELB invokes them (synchronously, as
//! `elasticloadbalancing.amazonaws.com`, which the function's resource
//! policy must allow).

use std::collections::BTreeMap;
use std::net::SocketAddr;

use base64::Engine;
use bytes::Bytes;
use http::{HeaderValue, Response};
use http_body_util::BodyExt;
use serde_json::{json, Map, Value};

use super::l7::{full, Body};
use super::FrontSpec;
use crate::Elb;

/// Requests to Lambda targets are limited to 1 MB.
const MAX_BODY: usize = 1024 * 1024;

fn is_text(content_type: &str) -> bool {
    let t = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    t.starts_with("text/")
        || t.ends_with("+json")
        || t.ends_with("+xml")
        || matches!(
            t.as_str(),
            "application/json" | "application/javascript" | "application/xml" | "application/x-www-form-urlencoded"
        )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn invoke(
    elb: &Elb,
    spec: &FrontSpec,
    tg_arn: &str,
    function: &str,
    multi_value: bool,
    parts: &http::request::Parts,
    host: &str,
    path_and_query: &str,
    body: Body,
    client: SocketAddr,
    secure: bool,
) -> Result<Response<Body>, u16> {
    let bytes = body.collect().await.map(|c| c.to_bytes()).map_err(|_| 502u16)?;
    if bytes.len() > MAX_BODY {
        return Err(413);
    }
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_and_query.to_string(), String::new()),
    };
    let content_type = parts.headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let (body_text, b64) = if bytes.is_empty() || is_text(content_type) {
        (String::from_utf8_lossy(&bytes).into_owned(), false)
    } else {
        (base64::engine::general_purpose::STANDARD.encode(&bytes), true)
    };
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in &parts.headers {
        headers.entry(k.as_str().to_string()).or_default().push(v.to_str().unwrap_or_default().to_string());
    }
    headers.insert("host".into(), vec![host.to_string()]);
    let xff = match headers.get("x-forwarded-for").and_then(|v| v.first()) {
        Some(prev) => format!("{prev}, {}", client.ip()),
        None => client.ip().to_string(),
    };
    headers.insert("x-forwarded-for".into(), vec![xff]);
    headers.insert("x-forwarded-proto".into(), vec![if secure { "https" } else { "http" }.into()]);
    headers.insert("x-forwarded-port".into(), vec![spec.port.to_string()]);
    headers
        .entry("x-amzn-trace-id".into())
        .or_insert_with(|| vec![format!("Root=1-{:08x}-{}", chrono::Utc::now().timestamp(), crate::names::hex_id(24))]);
    let mut queries: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        queries.entry(k.to_string()).or_default().push(v.to_string());
    }
    let mut event = Map::new();
    event.insert("requestContext".into(), json!({ "elb": { "targetGroupArn": tg_arn } }));
    event.insert("httpMethod".into(), json!(parts.method.as_str()));
    event.insert("path".into(), json!(path));
    if multi_value {
        event.insert("multiValueQueryStringParameters".into(), json!(queries));
        event.insert("multiValueHeaders".into(), json!(headers));
    } else {
        let single = |m: &BTreeMap<String, Vec<String>>| -> Map<String, Value> {
            m.iter().map(|(k, v)| (k.clone(), json!(v.last().cloned().unwrap_or_default()))).collect()
        };
        event.insert("queryStringParameters".into(), Value::Object(single(&queries)));
        event.insert("headers".into(), Value::Object(single(&headers)));
    }
    event.insert("body".into(), json!(body_text));
    event.insert("isBase64Encoded".into(), json!(b64));

    let ctx = elb.background_context(spec.account(), spec.region()).ok_or(502u16)?;
    let lambda = elb.lambda().ok_or(502u16)?;
    let inv = mws_lambda::ServiceInvocation {
        function,
        service_principal: "elasticloadbalancing.amazonaws.com",
        source_account: Some(spec.account()),
        source_arn: Some(tg_arn),
        payload: Value::Object(event).to_string().into_bytes(),
    };
    let result = lambda.invoke_as_service(&ctx, inv).await.map_err(|_| 502u16)?;
    if result.function_error.is_some() {
        return Err(502);
    }
    let v: Value = serde_json::from_slice(&result.payload).map_err(|_| 502u16)?;
    let status = v.get("statusCode").and_then(Value::as_u64).ok_or(502u16)?;
    let mut b = Response::builder().status(status as u16);
    if let Some(Value::Object(h)) = v.get("multiValueHeaders").filter(|_| multi_value) {
        for (k, vals) in h {
            for val in vals.as_array().into_iter().flatten() {
                if let Ok(hv) = HeaderValue::from_str(&value_string(val)) {
                    b = b.header(k.as_str(), hv);
                }
            }
        }
    } else if let Some(Value::Object(h)) = v.get("headers") {
        for (k, val) in h {
            if let Ok(hv) = HeaderValue::from_str(&value_string(val)) {
                b = b.header(k.as_str(), hv);
            }
        }
    }
    let raw = v.get("body").map(value_string).unwrap_or_default();
    let body = if v.get("isBase64Encoded").and_then(Value::as_bool) == Some(true) {
        base64::engine::general_purpose::STANDARD.decode(raw.as_bytes()).map_err(|_| 502u16)?
    } else {
        raw.into_bytes()
    };
    b.body(full(Bytes::from(body))).map_err(|_| 502u16)
}

fn value_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
