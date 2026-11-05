//! Runtime support for the `restJson1` protocol.
//!
//! Operations are routed by HTTP method and URI pattern, as for restXml
//! (the routing and HTTP-binding helpers are shared with
//! `mws-proto-restxml`). Input members are bound to URI labels, query
//! parameters, headers, or a JSON body; output members to headers, the
//! status code, or a JSON body. Errors are a JSON object with the code in
//! `X-Amzn-ErrorType`. Generated service code (see `mws-codegen`) calls into
//! this crate; it knows nothing about any particular service.
//!
//! Spec: <https://smithy.io/2.0/aws/protocols/aws-restjson1-protocol.html>

use bytes::Bytes;
use chrono::{DateTime, NaiveDateTime, Utc};
use mws_core::{ErrorFault, ErrorValue, HttpResponse, ServiceError};
pub use mws_proto_json::{Map, Value};
pub use mws_proto_restxml::{eventstream, format_timestamp, hint_matches, match_uri, prefix_headers, Labels, Query};

/// Re-exports used by generated code.
#[doc(hidden)]
pub mod __private {
    pub use async_trait::async_trait;
    pub use chrono;
    pub use regex;
}

/// Static facts about a restJson1 service, emitted by codegen.
#[derive(Debug, Clone, Copy)]
pub struct ServiceInfo {
    pub validation_error: &'static str,
    /// The key error bodies carry the message under.
    pub error_message_key: &'static str,
    /// A key naming the fault (`User` / `Service`), for services that send
    /// one.
    pub error_fault_key: Option<&'static str>,
    /// A key some services (EFS) repeat the error code under in the body.
    pub error_code_key: Option<&'static str>,
}

/// A response body.
#[derive(Debug, Clone)]
pub enum Body {
    None,
    Json(Value),
    /// A string payload (`text/plain` unless a header says otherwise).
    Text(String),
    /// A blob payload (`application/octet-stream` unless a header says
    /// otherwise).
    Raw(Bytes),
    /// `application/vnd.amazon.eventstream` messages.
    EventStream(Bytes),
}

/// Decodes values bound to labels, query parameters and headers, and (via
/// the awsJson decoder it derefs to) JSON body members, collecting every
/// validation error.
#[derive(Debug, Default)]
pub struct Decoder {
    json: mws_proto_json::Decoder,
}

impl std::ops::Deref for Decoder {
    type Target = mws_proto_json::Decoder;
    fn deref(&self) -> &mws_proto_json::Decoder {
        &self.json
    }
}

impl std::ops::DerefMut for Decoder {
    fn deref_mut(&mut self) -> &mut mws_proto_json::Decoder {
        &mut self.json
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// `None` for missing or JSON null (generated code calls this as an
    /// associated function, which `Deref` does not forward).
    pub fn present(v: Option<&Value>) -> Option<&Value> {
        mws_proto_json::Decoder::present(v)
    }

    pub fn finish(self, code: &'static str) -> Result<(), ServiceError> {
        self.json.finish(code)
    }

    pub fn raw_string(&mut self, raw: Option<&str>) -> Option<String> {
        raw.map(str::to_string)
    }

    /// A `@mediaType` string in a header travels base64-encoded.
    pub fn raw_base64_string(&mut self, raw: Option<&str>, path: &str) -> Option<String> {
        let bytes = self.raw_blob(raw, path)?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn raw_boolean(&mut self, raw: Option<&str>, path: &str) -> Option<bool> {
        let raw = raw?.trim();
        match raw {
            "true" => Some(true),
            "false" => Some(false),
            _ => {
                self.json.invalid(path, raw, "boolean");
                None
            }
        }
    }

    pub fn raw_number<T: std::str::FromStr>(&mut self, raw: Option<&str>, path: &str) -> Option<T> {
        let raw = raw?.trim();
        match raw.parse::<T>() {
            Ok(v) => Some(v),
            Err(_) => {
                self.json.invalid(path, raw, "number");
                None
            }
        }
    }

    /// ISO 8601 (query default), HTTP dates (header default) or epoch
    /// seconds.
    pub fn raw_timestamp(&mut self, raw: Option<&str>, path: &str) -> Option<DateTime<Utc>> {
        let raw = raw?.trim();
        if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
            return Some(t.with_timezone(&Utc));
        }
        if let Ok(t) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
            return Some(t.and_utc());
        }
        if let Ok(t) = DateTime::parse_from_rfc2822(raw) {
            return Some(t.with_timezone(&Utc));
        }
        if let Ok(secs) = raw.parse::<f64>() {
            if let Some(t) = DateTime::from_timestamp_millis((secs * 1000.0) as i64) {
                return Some(t);
            }
        }
        self.json.invalid(path, raw, "timestamp");
        None
    }

    pub fn raw_blob(&mut self, raw: Option<&str>, path: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        let raw = raw?.trim();
        match base64::engine::general_purpose::STANDARD.decode(raw) {
            Ok(v) => Some(v),
            Err(_) => {
                self.json.invalid(path, raw, "base64 blob");
                None
            }
        }
    }
}

/// Every query parameter (`httpQueryParams` of string values).
pub fn query_params(query: &Query) -> Option<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in query.pairs() {
        out.entry(k.to_string()).or_insert_with(|| v.to_string());
    }
    (!out.is_empty()).then_some(out)
}

/// Every query parameter with all its values (`httpQueryParams` of lists).
pub fn query_params_multi(query: &Query) -> Option<std::collections::BTreeMap<String, Vec<String>>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for (k, v) in query.pairs() {
        out.entry(k.to_string()).or_default().push(v.to_string());
    }
    (!out.is_empty()).then_some(out)
}

/// Parse the request body as JSON. An empty body is `Value::Null`; a body
/// that is not JSON is a `SerializationException`.
pub fn parse_body(body: &[u8]) -> Result<Value, ServiceError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(body)
        .map_err(|e| ServiceError::client("SerializationException", 400, format!("Unable to parse request body: {e}")))
}

/// No operation matches the method and path.
pub fn unknown_operation(method: &str, path: &str) -> ServiceError {
    ServiceError::client("UnknownOperationException", 404, format!("No operation matches {method} {path}"))
}

/// A response with a body and extra headers. A `Content-Type` among
/// `headers` wins over the body's default.
pub fn response(
    _info: &ServiceInfo,
    status: u16,
    request_id: &str,
    headers: Vec<(String, String)>,
    body: Body,
) -> HttpResponse {
    let mut b = http::Response::builder().status(status).header("x-amzn-RequestId", request_id);
    let has_type = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
    for (k, v) in headers {
        b = b.header(k, v);
    }
    let (default_type, body) = match body {
        Body::None => (None, Bytes::new()),
        Body::Json(v) => (Some("application/json"), Bytes::from(v.to_string())),
        Body::Text(s) => (Some("text/plain"), Bytes::from(s)),
        Body::Raw(b) => (Some("application/octet-stream"), b),
        Body::EventStream(b) => (Some("application/vnd.amazon.eventstream"), b),
    };
    if let (Some(t), false) = (default_type, has_type) {
        b = b.header(http::header::CONTENT_TYPE, t);
    }
    b.body(body).unwrap_or_else(|_| {
        http::Response::builder().status(500).body(Bytes::new()).expect("static response parts are valid")
    })
}

/// The JSON error body: the message, any extra fields, and the fault key
/// for services that send one.
pub fn error_body(info: &ServiceInfo, error: &ServiceError) -> Value {
    let mut body = Map::new();
    if let Some(k) = info.error_fault_key {
        let fault = match error.fault {
            ErrorFault::Client => "User",
            ErrorFault::Server => "Service",
        };
        body.insert(k.to_string(), Value::String(fault.into()));
    }
    if let Some(k) = info.error_code_key {
        let code = if error.code == "AccessDenied" { "AccessDeniedException" } else { &error.code };
        body.insert(k.to_string(), Value::String(code.to_string()));
    }
    body.insert(info.error_message_key.to_string(), Value::String(error.message.clone()));
    for f in &error.fields {
        let v = match &f.value {
            ErrorValue::String(s) => Value::String(s.clone()),
            ErrorValue::List { values, .. } => Value::Array(values.iter().cloned().map(Value::String).collect()),
        };
        body.insert(f.name.clone(), v);
    }
    Value::Object(body)
}

pub fn error_response(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> HttpResponse {
    // The gateway's authentication errors carry awsQuery names; restJson
    // services answer `UnrecognizedClientException`,
    // `InvalidSignatureException`, ... (status 403).
    if let Some(auth) = error.json_auth_equivalent() {
        return error_response(info, request_id, &ServiceError { status: 403, ..auth });
    }
    // The shared authorizer says `AccessDenied`; REST/JSON services call it
    // `AccessDeniedException`.
    let code = if error.code == "AccessDenied" { "AccessDeniedException" } else { &error.code };
    let mut resp = response(info, error.status, request_id, Vec::new(), Body::Json(error_body(info, error)));
    if let Ok(v) = http::HeaderValue::from_str(code) {
        resp.headers_mut().insert("x-amzn-ErrorType", v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_code_header_and_message() {
        let info = ServiceInfo {
            validation_error: "ValidationException",
            error_message_key: "Message",
            error_fault_key: Some("Type"),
            error_code_key: None,
        };
        let resp = error_response(&info, "rid", &ServiceError::client("ResourceNotFoundException", 404, "nope"));
        assert_eq!(resp.status(), 404);
        assert_eq!(resp.headers()["x-amzn-errortype"], "ResourceNotFoundException");
        let body: Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["Message"], "nope");
        assert_eq!(body["Type"], "User");
    }

    #[test]
    fn raw_values() {
        let mut d = Decoder::new();
        assert_eq!(d.raw_number::<i32>(Some("12"), "n"), Some(12));
        assert_eq!(d.raw_boolean(Some("true"), "b"), Some(true));
        assert!(d.raw_timestamp(Some("Tue, 03 Nov 2026 07:00:00 GMT"), "t").is_some());
        assert!(d.raw_number::<i32>(Some("x"), "n").is_none());
        assert!(d.finish("ValidationException").is_err());
    }
}
