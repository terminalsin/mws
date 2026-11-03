//! Runtime support for the `awsJson1_0` and `awsJson1_1` protocols.
//!
//! Every request is a `POST /` naming its operation in
//! `X-Amz-Target: {Service}.{Operation}`, with the input as a JSON object.
//! Responses are JSON; errors are `{"__type": code, "message": ...}` with the
//! code repeated in `x-amzn-ErrorType`. Generated service code (see
//! `mws-codegen`) calls into this crate; it knows nothing about any
//! particular service.
//!
//! Spec: <https://smithy.io/2.0/aws/protocols/aws-json-1_1-protocol.html>

use bytes::Bytes;
use chrono::{DateTime, Utc};
use mws_core::{ErrorValue, HttpRequest, HttpResponse, ServiceError, Validator};
pub use serde_json::{Map, Value};

/// Re-exports used by generated code.
#[doc(hidden)]
pub mod __private {
    pub use async_trait::async_trait;
    pub use chrono;
    pub use regex;
    pub use serde_json;
}

/// Static facts about a JSON service, emitted by codegen.
#[derive(Debug, Clone, Copy)]
pub struct ServiceInfo {
    /// Prefix of `X-Amz-Target`, e.g. `ACMPrivateCA`.
    pub target_prefix: &'static str,
    /// `application/x-amz-json-1.1` or `-1.0`.
    pub content_type: &'static str,
    pub validation_error: &'static str,
    /// Set for `awsQueryCompatible` services (SQS), which also report the
    /// error's awsQuery code in `x-amzn-query-error`.
    pub query_compatible: Option<QueryCompatible>,
}

/// awsQuery error codes of an `awsQueryCompatible` service.
#[derive(Debug, Clone, Copy)]
pub struct QueryCompatible {
    /// Smithy namespace `__type` qualifies modeled error names with.
    pub namespace: &'static str,
    /// `(shape name, awsQuery code)` per modeled error.
    pub codes: &'static [(&'static str, &'static str)],
}

/// The operation named by `X-Amz-Target`, if it belongs to this service.
pub fn operation<'a>(info: &ServiceInfo, request: &'a HttpRequest) -> Result<&'a str, ServiceError> {
    let target = request
        .headers()
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServiceError::client("UnknownOperationException", 400, "Missing X-Amz-Target header"))?;
    target.strip_prefix(info.target_prefix).and_then(|t| t.strip_prefix('.')).ok_or_else(|| unknown_operation(target))
}

pub fn unknown_operation(target: &str) -> ServiceError {
    ServiceError::client("UnknownOperationException", 400, format!("Unknown operation {target}"))
}

/// Parse the request body. An empty body is an empty object.
pub fn parse_body(body: &[u8]) -> Result<Value, ServiceError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(Map::new()));
    }
    let v: Value = serde_json::from_slice(body).map_err(|e| {
        ServiceError::client("SerializationException", 400, format!("Unable to parse request body: {e}"))
    })?;
    if !v.is_object() {
        return Err(ServiceError::client("SerializationException", 400, "Request body must be a JSON object"));
    }
    Ok(v)
}

/// Decodes typed values out of JSON while collecting validation errors.
/// Constraint checks come from the shared [`Validator`] it derefs to.
#[derive(Debug, Default)]
pub struct Decoder {
    validator: Validator,
    /// Wrong JSON types are SerializationExceptions in AWS, not
    /// validation errors.
    type_error: Option<String>,
}

impl std::ops::Deref for Decoder {
    type Target = Validator;
    fn deref(&self) -> &Validator {
        &self.validator
    }
}

impl std::ops::DerefMut for Decoder {
    fn deref_mut(&mut self) -> &mut Validator {
        &mut self.validator
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn finish(self, code: &'static str) -> Result<(), ServiceError> {
        if let Some(e) = self.type_error {
            return Err(ServiceError::client("SerializationException", 400, e));
        }
        self.validator.finish(code)
    }

    fn wrong_type(&mut self, path: &str, expected: &str) {
        self.type_error.get_or_insert_with(|| format!("Expected {expected} at '{path}'"));
    }

    /// `None` for missing or JSON null.
    pub fn present(v: Option<&Value>) -> Option<&Value> {
        v.filter(|v| !v.is_null())
    }

    pub fn string(&mut self, v: Option<&Value>, path: &str) -> Option<String> {
        match Self::present(v)? {
            Value::String(s) => Some(s.clone()),
            _ => {
                self.wrong_type(path, "a string");
                None
            }
        }
    }

    pub fn boolean(&mut self, v: Option<&Value>, path: &str) -> Option<bool> {
        match Self::present(v)? {
            Value::Bool(b) => Some(*b),
            _ => {
                self.wrong_type(path, "a boolean");
                None
            }
        }
    }

    pub fn integer<T: TryFrom<i64>>(&mut self, v: Option<&Value>, path: &str) -> Option<T> {
        let n = Self::present(v)?.as_i64().and_then(|n| T::try_from(n).ok());
        if n.is_none() {
            self.wrong_type(path, "an integer");
        }
        n
    }

    pub fn float(&mut self, v: Option<&Value>, path: &str) -> Option<f64> {
        let n = Self::present(v)?.as_f64();
        if n.is_none() {
            self.wrong_type(path, "a number");
        }
        n
    }

    /// Epoch seconds (the awsJson default), or an ISO 8601 string.
    pub fn timestamp(&mut self, v: Option<&Value>, path: &str) -> Option<DateTime<Utc>> {
        let v = Self::present(v)?;
        let t = match v {
            Value::Number(n) => n.as_f64().and_then(|s| DateTime::from_timestamp_millis((s * 1000.0).round() as i64)),
            Value::String(s) => DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc)),
            _ => None,
        };
        if t.is_none() {
            self.wrong_type(path, "a timestamp");
        }
        t
    }

    pub fn blob(&mut self, v: Option<&Value>, path: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        let s = match Self::present(v)? {
            Value::String(s) => s,
            _ => {
                self.wrong_type(path, "a base64 string");
                return None;
            }
        };
        match base64::engine::general_purpose::STANDARD.decode(s) {
            Ok(b) => Some(b),
            Err(_) => {
                self.wrong_type(path, "a base64 string");
                None
            }
        }
    }

    pub fn object<'v>(&mut self, v: Option<&'v Value>, path: &str) -> Option<&'v Map<String, Value>> {
        match Self::present(v)? {
            Value::Object(m) => Some(m),
            _ => {
                self.wrong_type(path, "an object");
                None
            }
        }
    }

    pub fn array<'v>(&mut self, v: Option<&'v Value>, path: &str) -> Option<&'v Vec<Value>> {
        match Self::present(v)? {
            Value::Array(a) => Some(a),
            _ => {
                self.wrong_type(path, "a list");
                None
            }
        }
    }
}

// ---- serialization helpers used by generated code ---------------------------

pub fn ser_timestamp(t: &DateTime<Utc>) -> Value {
    let secs = t.timestamp_millis() as f64 / 1000.0;
    serde_json::Number::from_f64(secs).map(Value::Number).unwrap_or(Value::Null)
}

pub fn ser_blob(b: &[u8]) -> Value {
    use base64::Engine;
    Value::String(base64::engine::general_purpose::STANDARD.encode(b))
}

pub fn ser_float(f: f64) -> Value {
    serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
}

pub fn json_response(info: &ServiceInfo, request_id: &str, status: u16, body: Option<Value>) -> HttpResponse {
    let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, info.content_type)
        .header("x-amzn-RequestId", request_id)
        .body(body)
        .expect("static response parts are valid")
}

/// What a generated operation produces: a JSON document, or the bytes of
/// an `application/vnd.amazon.eventstream` body.
#[derive(Debug)]
pub enum Reply {
    Json(Value),
    EventStream(Vec<u8>),
}

/// A streaming output: an `initial-response` event carrying the output's
/// other (here: no) members, as awsJson services send first, then `body`'s
/// events.
pub fn event_stream_response(info: &ServiceInfo, request_id: &str, body: Vec<u8>) -> HttpResponse {
    let _ = info;
    let mut stream = mws_core::eventstream::event("initial-response", Some("application/json"), b"{}");
    stream.extend(body);
    http::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/vnd.amazon.eventstream")
        .header("x-amzn-RequestId", request_id)
        .body(Bytes::from(stream))
        .expect("static response parts are valid")
}

pub fn error_response(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> HttpResponse {
    // JSON-protocol services name the authorization failure
    // `AccessDeniedException`; the shared authorizer says `AccessDenied`.
    let code = if error.code == "AccessDenied" { "AccessDeniedException" } else { &error.code };
    // awsQueryCompatible services qualify modeled errors with their
    // namespace and name the awsQuery code (`AWS.SimpleQueueService.
    // NonExistentQueue`, `AccessDenied`) in `x-amzn-query-error`, which SDKs
    // report as the error code.
    let (type_name, query_error) = match &info.query_compatible {
        Some(q) => match q.codes.iter().find(|(shape, _)| *shape == code) {
            Some((shape, query)) => (format!("{}#{shape}", q.namespace), Some(*query)),
            None => (code.to_string(), Some(error.code.as_ref())),
        },
        None => (code.to_string(), None),
    };
    let mut body = Map::new();
    body.insert("__type".into(), Value::String(type_name));
    body.insert("message".into(), Value::String(error.message.clone()));
    for f in &error.fields {
        let v = match &f.value {
            ErrorValue::String(s) => Value::String(s.clone()),
            ErrorValue::List { values, .. } => Value::Array(values.iter().cloned().map(Value::String).collect()),
        };
        body.insert(f.name.clone(), v);
    }
    let mut resp = json_response(info, request_id, error.status, Some(Value::Object(body)));
    if let Ok(v) = http::HeaderValue::from_str(code) {
        resp.headers_mut().insert("x-amzn-ErrorType", v);
    }
    if let Some(query) = query_error {
        let fault = match error.fault {
            mws_core::ErrorFault::Client => "Sender",
            mws_core::ErrorFault::Server => "Receiver",
        };
        if let Ok(v) = http::HeaderValue::from_str(&format!("{query};{fault}")) {
            resp.headers_mut().insert("x-amzn-query-error", v);
        }
    }
    resp
}
