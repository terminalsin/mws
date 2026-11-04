//! Runtime support for the Smithy `rpcv2Cbor` protocol.
//!
//! Every request is a `POST /service/{ServiceName}/operation/{Operation}`
//! with `smithy-protocol: rpc-v2-cbor` and the input as a CBOR map keyed by
//! member names. Responses are CBOR too; errors carry the same document as
//! awsJson (`__type`, `message`, modeled members), and
//! `awsQueryCompatible` services add `x-amzn-query-error`.
//!
//! Generated code (`mws-codegen`) runs rpcv2Cbor operations through the
//! awsJson document model: request bodies decode to a JSON [`Value`] (byte
//! strings become base64 strings, tag-1 timestamps epoch seconds), and
//! output documents encode back to CBOR guided by a [`Kind`] table the
//! generator emits, which says where timestamps, blobs and floats are.
//!
//! Spec: <https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html>

use base64::Engine;
use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, ServiceError};
use serde_json::{Map, Number, Value};

pub use mws_proto_json::ServiceInfo;

/// What a shape is, as far as its CBOR encoding differs from JSON's.
/// Indices refer to other entries of the same table.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Struct(&'static [(&'static str, usize)]),
    List(usize),
    Map(usize),
    Timestamp,
    Blob,
    Float,
    Double,
    /// Strings, booleans, integers, documents: encoded as their JSON
    /// value is.
    Plain,
}

/// The `{ServiceName}` path segment requests address.
fn route(request: &HttpRequest) -> Option<(&str, &str)> {
    let rest = request.uri().path().strip_prefix("/service/")?;
    let (service, rest) = rest.split_once('/')?;
    let op = rest.strip_prefix("operation/")?;
    (!op.is_empty() && !op.contains('/')).then_some((service, op))
}

/// Whether `request` is an rpcv2Cbor request for `service_name` (the
/// service shape's name).
pub fn targets(service_name: &str, request: &HttpRequest) -> bool {
    route(request).is_some_and(|(s, _)| s == service_name)
}

/// Whether `request` speaks rpcv2Cbor at all.
pub fn is_cbor(request: &HttpRequest) -> bool {
    request.headers().get("smithy-protocol").is_some_and(|v| v.as_bytes() == b"rpc-v2-cbor") || route(request).is_some()
}

/// The operation `request` addresses.
pub fn operation<'a>(service_name: &str, request: &'a HttpRequest) -> Result<&'a str, ServiceError> {
    match route(request) {
        Some((s, op)) if s == service_name => Ok(op),
        _ => Err(ServiceError::client(
            "UnknownOperationException",
            404,
            format!("Unknown operation path {}", request.uri().path()),
        )),
    }
}

/// Decode a request body; an empty body is an empty input.
pub fn decode_body(body: &[u8]) -> Result<Value, ServiceError> {
    if body.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let mut r = Reader { b: body, i: 0 };
    let v = r.value(0).map_err(serialization)?;
    if r.i != body.len() {
        return Err(serialization("trailing bytes after the CBOR document".into()));
    }
    if !v.is_object() {
        return Err(serialization("the request body must be a CBOR map".into()));
    }
    Ok(v)
}

fn serialization(e: String) -> ServiceError {
    ServiceError::client("SerializationException", 400, format!("Unable to parse request body: {e}"))
}

/// Decode any CBOR document into a JSON value (byte strings as base64).
pub fn decode(bytes: &[u8]) -> Result<Value, String> {
    let mut r = Reader { b: bytes, i: 0 };
    r.value(0)
}

const MAX_DEPTH: usize = 128;

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

enum Item {
    Value(Value),
    Break,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.i).ok_or("unexpected end of input")?;
        self.i += 1;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.i.checked_add(n).filter(|e| *e <= self.b.len()).ok_or("unexpected end of input")?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }

    /// The argument of an initial byte; `None` for indefinite length.
    fn arg(&mut self, info: u8) -> Result<Option<u64>, String> {
        Ok(Some(match info {
            0..=23 => info as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            31 => return Ok(None),
            _ => return Err(format!("invalid additional information {info}")),
        }))
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        match self.item(depth)? {
            Item::Value(v) => Ok(v),
            Item::Break => Err("unexpected break".into()),
        }
    }

    fn bytes_of(&mut self, major: u8, len: Option<u64>) -> Result<Vec<u8>, String> {
        match len {
            Some(n) => Ok(self.take(usize::try_from(n).map_err(|_| "length too large")?)?.to_vec()),
            None => {
                let mut out = Vec::new();
                loop {
                    let ib = self.byte()?;
                    if ib == 0xff {
                        return Ok(out);
                    }
                    if ib >> 5 != major {
                        return Err("bad chunk in indefinite-length string".into());
                    }
                    let n = self.arg(ib & 0x1f)?.ok_or("nested indefinite-length string")?;
                    out.extend_from_slice(self.take(usize::try_from(n).map_err(|_| "length too large")?)?);
                }
            }
        }
    }

    fn item(&mut self, depth: usize) -> Result<Item, String> {
        if depth > MAX_DEPTH {
            return Err("document nested too deeply".into());
        }
        let ib = self.byte()?;
        let (major, info) = (ib >> 5, ib & 0x1f);
        if ib == 0xff {
            return Ok(Item::Break);
        }
        let v = match major {
            0 => Value::from(self.arg(info)?.ok_or("indefinite integer")?),
            1 => {
                let n = self.arg(info)?.ok_or("indefinite integer")?;
                match i64::try_from(n) {
                    Ok(n) => Value::from(-1 - n),
                    Err(_) => Value::from(-1.0 - n as f64),
                }
            }
            2 => {
                let len = self.arg(info)?;
                Value::String(base64::engine::general_purpose::STANDARD.encode(self.bytes_of(2, len)?))
            }
            3 => {
                let len = self.arg(info)?;
                Value::String(String::from_utf8(self.bytes_of(3, len)?).map_err(|_| "invalid UTF-8 in text string")?)
            }
            4 => {
                let mut out = Vec::new();
                match self.arg(info)? {
                    Some(n) => {
                        for _ in 0..n {
                            out.push(self.value(depth + 1)?);
                        }
                    }
                    None => {
                        while let Item::Value(v) = self.item(depth + 1)? {
                            out.push(v);
                        }
                    }
                }
                Value::Array(out)
            }
            5 => {
                let mut out = Map::new();
                let mut entry = |r: &mut Self, k: Value| -> Result<(), String> {
                    let Value::String(k) = k else { return Err("map keys must be text strings".into()) };
                    let v = r.value(depth + 1)?;
                    out.insert(k, v);
                    Ok(())
                };
                match self.arg(info)? {
                    Some(n) => {
                        for _ in 0..n {
                            let k = self.value(depth + 1)?;
                            entry(self, k)?;
                        }
                    }
                    None => {
                        while let Item::Value(k) = self.item(depth + 1)? {
                            entry(self, k)?;
                        }
                    }
                }
                Value::Object(out)
            }
            6 => {
                let tag = self.arg(info)?.ok_or("indefinite tag")?;
                let inner = self.value(depth + 1)?;
                match tag {
                    // Bignums: the magnitude as a decimal string.
                    2 | 3 => {
                        let bytes = match &inner {
                            Value::String(s) => base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_default(),
                            _ => return Err("bignum tag must wrap a byte string".into()),
                        };
                        let mut n: u128 = 0;
                        for b in bytes {
                            n = n.checked_mul(256).and_then(|n| n.checked_add(b as u128)).ok_or("bignum too large")?;
                        }
                        let s = if tag == 2 { n.to_string() } else { format!("-{}", n + 1) };
                        Value::String(s)
                    }
                    _ => inner,
                }
            }
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 | 23 => Value::Null,
                25 => float(f16_to_f64(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))),
                26 => float(f32::from_be_bytes(self.take(4)?.try_into().unwrap()) as f64),
                27 => float(f64::from_be_bytes(self.take(8)?.try_into().unwrap())),
                _ => return Err(format!("unsupported simple value {info}")),
            },
        };
        Ok(Item::Value(v))
    }
}

/// JSON has no NaN or infinities; awsJson spells them as strings.
fn float(f: f64) -> Value {
    match Number::from_f64(f) {
        Some(n) => Value::Number(n),
        None if f.is_nan() => Value::String("NaN".into()),
        None if f > 0.0 => Value::String("Infinity".into()),
        None => Value::String("-Infinity".into()),
    }
}

fn f16_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = ((h >> 10) & 0x1f) as i32;
    let frac = (h & 0x3ff) as f64;
    sign * match exp {
        0 => frac * 2f64.powi(-24),
        31 if frac == 0.0 => f64::INFINITY,
        31 => f64::NAN,
        _ => (1.0 + frac / 1024.0) * 2f64.powi(exp - 15),
    }
}

// ---- encoding -----------------------------------------------------------------

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.extend([m | 24, n as u8]);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes());
    }
}

fn text(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn special_float(s: &str) -> Option<f64> {
    match s {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

fn number_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => special_float(s),
        _ => None,
    }
}

fn plain(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                head(out, 0, u);
            } else if let Some(i) = n.as_i64() {
                head(out, 1, (-1 - i) as u64);
            } else {
                out.push(0xfb);
                out.extend(n.as_f64().unwrap_or(0.0).to_be_bytes());
            }
        }
        Value::String(s) => text(out, s),
        Value::Array(a) => {
            head(out, 4, a.len() as u64);
            for x in a {
                plain(out, x);
            }
        }
        Value::Object(m) => {
            let entries: Vec<_> = m.iter().filter(|(_, v)| !v.is_null()).collect();
            head(out, 5, entries.len() as u64);
            for (k, x) in entries {
                text(out, k);
                plain(out, x);
            }
        }
    }
}

/// Encode `v` as the shape at `shapes[root]`.
pub fn encode(v: &Value, shapes: &[Kind], root: usize) -> Vec<u8> {
    let mut out = Vec::new();
    encode_as(&mut out, v, shapes, Some(root));
    out
}

fn encode_as(out: &mut Vec<u8>, v: &Value, shapes: &[Kind], kind: Option<usize>) {
    let Some(kind) = kind.and_then(|k| shapes.get(k)) else { return plain(out, v) };
    match (kind, v) {
        (Kind::Struct(members), Value::Object(m)) => {
            let entries: Vec<_> = m.iter().filter(|(_, v)| !v.is_null()).collect();
            head(out, 5, entries.len() as u64);
            for (k, x) in entries {
                text(out, k);
                let target = members.iter().find(|(n, _)| n == k).map(|(_, t)| *t);
                encode_as(out, x, shapes, target);
            }
        }
        (Kind::List(item), Value::Array(a)) => {
            head(out, 4, a.len() as u64);
            for x in a {
                encode_as(out, x, shapes, Some(*item));
            }
        }
        (Kind::Map(val), Value::Object(m)) => {
            head(out, 5, m.len() as u64);
            for (k, x) in m {
                text(out, k);
                encode_as(out, x, shapes, Some(*val));
            }
        }
        (Kind::Timestamp, v) if number_f64(v).is_some() => {
            out.push(0xc1);
            let secs = number_f64(v).unwrap_or(0.0);
            if secs.fract() == 0.0 && secs.abs() < 9.0e15 {
                let i = secs as i64;
                if i >= 0 {
                    head(out, 0, i as u64);
                } else {
                    head(out, 1, (-1 - i) as u64);
                }
            } else {
                out.push(0xfb);
                out.extend(secs.to_be_bytes());
            }
        }
        (Kind::Blob, Value::String(s)) => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
            head(out, 2, bytes.len() as u64);
            out.extend(bytes);
        }
        (Kind::Float, v) if number_f64(v).is_some() => {
            out.push(0xfa);
            out.extend((number_f64(v).unwrap_or(0.0) as f32).to_be_bytes());
        }
        (Kind::Double, v) if number_f64(v).is_some() => {
            out.push(0xfb);
            out.extend(number_f64(v).unwrap_or(0.0).to_be_bytes());
        }
        _ => plain(out, v),
    }
}

/// A successful response; `body` is `None` for operations without output.
pub fn response(request_id: &str, body: Option<Vec<u8>>) -> HttpResponse {
    let mut b = http::Response::builder().status(200).header("smithy-protocol", "rpc-v2-cbor");
    if body.is_some() {
        b = b.header(http::header::CONTENT_TYPE, "application/cbor");
    }
    b.header("x-amzn-RequestId", request_id)
        .body(body.map(Bytes::from).unwrap_or_default())
        .expect("static response parts are valid")
}

/// An error response: the awsJson error document, in CBOR.
pub fn error_response(info: &ServiceInfo, request_id: &str, error: &ServiceError) -> HttpResponse {
    let parts = mws_proto_json::error_parts(info, error);
    let mut body = Vec::new();
    plain(&mut body, &Value::Object(parts.body.clone()));
    let mut resp = http::Response::builder()
        .status(parts.status)
        .header("smithy-protocol", "rpc-v2-cbor")
        .header(http::header::CONTENT_TYPE, "application/cbor")
        .header("x-amzn-RequestId", request_id)
        .body(Bytes::from(body))
        .expect("static response parts are valid");
    parts.apply_headers(&mut resp);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_through_the_schema() {
        static SHAPES: &[Kind] = &[
            Kind::Struct(&[("When", 1), ("Data", 2), ("Value", 3), ("Items", 4)]),
            Kind::Timestamp,
            Kind::Blob,
            Kind::Double,
            Kind::List(5),
            Kind::Plain,
        ];
        let v = json!({"When": 1700000000.5, "Data": "aGk=", "Value": 2.0, "Items": ["a", 1, -3], "Gone": null});
        let bytes = encode(&v, SHAPES, 0);
        let back = decode(&bytes).unwrap();
        assert_eq!(back, json!({"When": 1700000000.5, "Data": "aGk=", "Value": 2.0, "Items": ["a", 1, -3]}));
        // Tag 1, then a float64.
        assert!(bytes.windows(2).any(|w| w == [0xc1, 0xfb]));
    }

    #[test]
    fn decodes_indefinite_lengths_and_half_floats() {
        // {_ "a": [_ 1, 2], "b": 1.5 (f16)}
        let bytes = [0xbf, 0x61, b'a', 0x9f, 0x01, 0x02, 0xff, 0x61, b'b', 0xf9, 0x3e, 0x00, 0xff];
        assert_eq!(decode(&bytes).unwrap(), json!({"a": [1, 2], "b": 1.5}));
    }
}
