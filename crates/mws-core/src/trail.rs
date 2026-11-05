//! A record of each API call, for whatever keeps an audit log of them.
//!
//! Generated dispatchers run every handler method through [`call`]. When
//! the front door is watching the request (see [`watch`]), `call` notes the
//! operation, its parameters and its outcome as an [`ApiCall`], which the
//! front door hands to its [`ApiCallObserver`]s once the response is ready.
//! Outside a watched request `call` just runs the handler.
//!
//! Parameters are rendered the way AWS audit logs show them: member names
//! in lowerCamelCase, absent members and empty collections left out,
//! binary payloads left out, and `@sensitive` members replaced with
//! [`HIDDEN`].

use std::future::Future;
use std::sync::{Arc, Mutex};

use serde::ser::{self, Serialize};
use serde_json::{Map, Value};

use crate::{RequestContext, ServiceError};

/// What sensitive values are replaced with.
pub const HIDDEN: &str = "HIDDEN_DUE_TO_SECURITY_REASONS";

/// What generated code knows about a service, from its model.
#[derive(Debug, Clone, Copy)]
pub struct ServiceTrail {
    /// `cloudTrailEventSource` from the model, e.g. `iam.amazonaws.com`.
    pub event_source: &'static str,
    /// Rust field names of members the model marks `@sensitive` (or that
    /// target sensitive shapes).
    pub sensitive: &'static [&'static str],
    /// `(wire code, error shape name)` for errors whose code is not their
    /// shape's name (`awsQueryError`): CloudTrail logs the shape's name.
    pub error_names: &'static [(&'static str, &'static str)],
}

/// One API call as an audit log sees it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApiCall {
    pub event_source: &'static str,
    /// The operation's name in the model, e.g. `CreateUser`.
    pub operation: &'static str,
    /// Whether the model marks the operation `@readonly`.
    pub read_only: bool,
    pub request_parameters: Option<Value>,
    /// The output, for operations that are not read-only.
    pub response_elements: Option<Value>,
    /// The error code and message, when the call failed.
    pub error: Option<(String, String)>,
}

/// Facts about the HTTP request that audit logs keep.
#[derive(Debug, Clone, Default)]
pub struct HttpFacts {
    pub user_agent: Option<String>,
    pub host: Option<String>,
    pub status: u16,
}

/// Receives every API call the front door watched, after it was handled.
/// Called on the request's task: do slow work elsewhere.
pub trait ApiCallObserver: Send + Sync {
    fn observe(&self, ctx: &RequestContext, call: &ApiCall, http: &HttpFacts);
}

type Slot = Arc<Mutex<Option<ApiCall>>>;

tokio::task_local! {
    static CURRENT: Slot;
}

/// Run `fut` (a request being handled), noting the API call it makes.
pub async fn watch<F: Future>(fut: F) -> (F::Output, Option<ApiCall>) {
    let slot: Slot = Arc::default();
    let out = CURRENT.scope(slot.clone(), fut).await;
    let call = slot.lock().ok().and_then(|mut s| s.take());
    (out, call)
}

fn current() -> Option<Slot> {
    CURRENT.try_with(Clone::clone).ok()
}

/// Run one handler method. Generated code calls this.
pub async fn call<I, O, F, Fut>(
    service: &ServiceTrail,
    operation: &'static str,
    read_only: bool,
    input: I,
    f: F,
) -> Result<O, ServiceError>
where
    I: Serialize,
    O: Serialize,
    F: FnOnce(I) -> Fut,
    Fut: Future<Output = Result<O, ServiceError>>,
{
    let slot = current();
    // A service calling another in-process (scenario steps, CBOR going
    // through `invoke`) is part of the same request: the first call wins.
    let slot = slot.filter(|s| s.lock().map(|g| g.is_none()).unwrap_or(false));
    if let Some(slot) = &slot {
        let call = ApiCall {
            event_source: service.event_source,
            operation,
            read_only,
            request_parameters: to_value(&input, service.sensitive),
            ..ApiCall::default()
        };
        if let Ok(mut s) = slot.lock() {
            *s = Some(call);
        }
    }
    let result = f(input).await;
    if let Some(slot) = &slot {
        if let Ok(mut s) = slot.lock() {
            if let Some(call) = s.as_mut() {
                match &result {
                    Ok(out) if !read_only => call.response_elements = to_value(out, service.sensitive),
                    Ok(_) => {}
                    Err(e) => {
                        let code = service
                            .error_names
                            .iter()
                            .find(|(wire, _)| *wire == e.code)
                            .map_or_else(|| e.code.to_string(), |(_, name)| name.to_string());
                        call.error = Some((code, e.message.to_string()));
                    }
                }
            }
        }
    }
    result
}

/// Render `value` the way audit logs show parameters. `None` when nothing
/// is left (no input, or every member absent).
pub fn to_value<T: Serialize + ?Sized>(value: &T, sensitive: &[&str]) -> Option<Value> {
    match value.serialize(Ser { sensitive }) {
        Ok(Some(Value::Object(m))) if m.is_empty() => None,
        Ok(v) => v,
        Err(_) => None,
    }
}

/// `user_name` -> `userName`, `MyVariant` -> `myVariant`.
pub fn lower_camel(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = false;
    for (i, c) in name.chars().enumerate() {
        if c == '_' {
            upper = !out.is_empty();
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else if i == 0 {
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Why a value was left out; not a failure.
#[derive(Debug)]
enum Skip {
    /// A byte payload.
    Binary,
    Other(String),
}

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Skip::Binary => f.write_str("binary"),
            Skip::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Skip {}

impl ser::Error for Skip {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Skip::Other(msg.to_string())
    }
}

/// Serializes into a [`Value`]; `Ok(None)` means "leave this out".
#[derive(Clone, Copy)]
struct Ser<'a> {
    sensitive: &'a [&'a str],
}

type R = Result<Option<Value>, Skip>;

impl<'a> ser::Serializer for Ser<'a> {
    type Ok = Option<Value>;
    type Error = Skip;
    type SerializeSeq = SeqSer<'a>;
    type SerializeTuple = SeqSer<'a>;
    type SerializeTupleStruct = SeqSer<'a>;
    type SerializeTupleVariant = ser::Impossible<Option<Value>, Skip>;
    type SerializeMap = MapSer<'a>;
    type SerializeStruct = StructSer<'a>;
    type SerializeStructVariant = ser::Impossible<Option<Value>, Skip>;

    fn serialize_bool(self, v: bool) -> R {
        Ok(Some(Value::Bool(v)))
    }
    fn serialize_i8(self, v: i8) -> R {
        Ok(Some(v.into()))
    }
    fn serialize_i16(self, v: i16) -> R {
        Ok(Some(v.into()))
    }
    fn serialize_i32(self, v: i32) -> R {
        Ok(Some(v.into()))
    }
    fn serialize_i64(self, v: i64) -> R {
        Ok(Some(v.into()))
    }
    // A sequence of `u8` is a byte payload: stop at its first element.
    fn serialize_u8(self, _v: u8) -> R {
        Err(Skip::Binary)
    }
    fn serialize_u16(self, v: u16) -> R {
        Ok(Some(v.into()))
    }
    fn serialize_u32(self, v: u32) -> R {
        Ok(Some(v.into()))
    }
    fn serialize_u64(self, v: u64) -> R {
        Ok(Some(v.into()))
    }
    fn serialize_f32(self, v: f32) -> R {
        Ok(serde_json::Number::from_f64(v as f64).map(Value::Number))
    }
    fn serialize_f64(self, v: f64) -> R {
        Ok(serde_json::Number::from_f64(v).map(Value::Number))
    }
    fn serialize_char(self, v: char) -> R {
        Ok(Some(Value::String(v.to_string())))
    }
    fn serialize_str(self, v: &str) -> R {
        Ok(Some(Value::String(v.to_string())))
    }
    fn serialize_bytes(self, _v: &[u8]) -> R {
        Ok(None)
    }
    fn serialize_none(self) -> R {
        Ok(None)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> R {
        value.serialize(self)
    }
    fn serialize_unit(self) -> R {
        Ok(None)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> R {
        Ok(None)
    }
    fn serialize_unit_variant(self, _name: &'static str, _index: u32, variant: &'static str) -> R {
        Ok(Some(Value::String(variant.to_string())))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _name: &'static str, value: &T) -> R {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> R {
        let inner = match value.serialize(self) {
            Ok(v) => v,
            Err(Skip::Binary) => None,
            Err(e) => return Err(e),
        };
        let mut m = Map::new();
        m.insert(lower_camel(variant), inner.unwrap_or(Value::Null));
        Ok(Some(Value::Object(m)))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSer<'a>, Skip> {
        Ok(SeqSer { ser: self, items: Vec::with_capacity(len.unwrap_or(0).min(64)) })
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqSer<'a>, Skip> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SeqSer<'a>, Skip> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Skip> {
        Err(Skip::Other("tuple variant".into()))
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<MapSer<'a>, Skip> {
        Ok(MapSer { ser: self, map: Map::new(), key: None })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<StructSer<'a>, Skip> {
        Ok(StructSer { ser: self, map: Map::new() })
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Skip> {
        Err(Skip::Other("struct variant".into()))
    }
}

struct SeqSer<'a> {
    ser: Ser<'a>,
    items: Vec<Value>,
}

impl SeqSer<'_> {
    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Skip> {
        if let Some(v) = value.serialize(self.ser)? {
            self.items.push(v);
        }
        Ok(())
    }
    fn done(self) -> R {
        Ok((!self.items.is_empty()).then_some(Value::Array(self.items)))
    }
}

impl ser::SerializeSeq for SeqSer<'_> {
    type Ok = Option<Value>;
    type Error = Skip;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Skip> {
        self.push(value)
    }
    fn end(self) -> R {
        self.done()
    }
}

impl ser::SerializeTuple for SeqSer<'_> {
    type Ok = Option<Value>;
    type Error = Skip;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Skip> {
        self.push(value)
    }
    fn end(self) -> R {
        self.done()
    }
}

impl ser::SerializeTupleStruct for SeqSer<'_> {
    type Ok = Option<Value>;
    type Error = Skip;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Skip> {
        self.push(value)
    }
    fn end(self) -> R {
        self.done()
    }
}

struct MapSer<'a> {
    ser: Ser<'a>,
    map: Map<String, Value>,
    key: Option<String>,
}

impl ser::SerializeMap for MapSer<'_> {
    type Ok = Option<Value>;
    type Error = Skip;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Skip> {
        // Map keys are data (tag keys, attribute names): kept as they are.
        self.key = match key.serialize(self.ser)? {
            Some(Value::String(s)) => Some(s),
            Some(other) => Some(other.to_string()),
            None => None,
        };
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Skip> {
        let Some(key) = self.key.take() else { return Ok(()) };
        let v = match value.serialize(self.ser) {
            Ok(v) => v,
            Err(Skip::Binary) => None,
            Err(e) => return Err(e),
        };
        self.map.insert(key, v.unwrap_or(Value::Null));
        Ok(())
    }
    fn end(self) -> R {
        Ok((!self.map.is_empty()).then_some(Value::Object(self.map)))
    }
}

struct StructSer<'a> {
    ser: Ser<'a>,
    map: Map<String, Value>,
}

impl ser::SerializeStruct for StructSer<'_> {
    type Ok = Option<Value>;
    type Error = Skip;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Skip> {
        // Byte payloads (bodies, plaintexts) and anything else that does
        // not render are left out.
        let v = value.serialize(self.ser).unwrap_or_default();
        if let Some(v) = v {
            let v = if self.ser.sensitive.contains(&key) { Value::String(HIDDEN.into()) } else { v };
            self.map.insert(lower_camel(key), v);
        }
        Ok(())
    }
    fn end(self) -> R {
        Ok(Some(Value::Object(self.map)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Tag {
        key: String,
        value: String,
    }

    #[derive(serde::Serialize)]
    enum Choice {
        FirstOne(String),
    }

    #[derive(serde::Serialize)]
    struct Input {
        user_name: String,
        path: Option<String>,
        password: Option<String>,
        body: Vec<u8>,
        tags: Vec<Tag>,
        empty: Vec<String>,
        attributes: std::collections::BTreeMap<String, String>,
        choice: Option<Choice>,
        max_items: i32,
    }

    #[test]
    fn renders_like_audit_logs() {
        let input = Input {
            user_name: "bob".into(),
            path: None,
            password: Some("hunter2".into()),
            body: vec![1, 2, 3],
            tags: vec![Tag { key: "k".into(), value: "v".into() }],
            empty: vec![],
            attributes: [("Some_Key".to_string(), "x".to_string())].into_iter().collect(),
            choice: Some(Choice::FirstOne("a".into())),
            max_items: 5,
        };
        let v = to_value(&input, &["password"]).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "userName": "bob",
                "password": HIDDEN,
                "tags": [{"key": "k", "value": "v"}],
                "attributes": {"Some_Key": "x"},
                "choice": {"firstOne": "a"},
                "maxItems": 5
            })
        );
        assert_eq!(to_value(&(), &[]), None);
    }

    #[tokio::test]
    async fn watch_records_the_first_call() {
        const SVC: ServiceTrail = ServiceTrail { event_source: "x.amazonaws.com", sensitive: &[], error_names: &[] };
        let (r, call) = watch(async {
            let r: Result<Tag, ServiceError> =
                call(&SVC, "CreateThing", false, Tag { key: "a".into(), value: "b".into() }, |t| async move {
                    let _: Result<(), ServiceError> = call(&SVC, "Inner", true, (), |()| async { Ok(()) }).await;
                    Ok(t)
                })
                .await;
            r.is_ok()
        })
        .await;
        assert!(r);
        let call = call.unwrap();
        assert_eq!(call.operation, "CreateThing");
        assert_eq!(call.response_elements, Some(serde_json::json!({"key": "a", "value": "b"})));
        let (_, none) = watch(async {}).await;
        assert_eq!(none, None);
    }
}
