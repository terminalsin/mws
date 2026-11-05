//! Helpers shared by the operations: ARNs, ids, errors, paging, tags and
//! conversions between generated types through documents.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, ErrorValue, RequestContext, ServiceError};
use rand::Rng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::generated::types;

pub fn arn(ctx: &RequestContext, resource: &str) -> String {
    format!("arn:{}:bedrock:{}:{}:{resource}", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// A random lowercase alphanumeric id, like Bedrock's 12-character ones.
pub fn random_id(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

pub fn not_found(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ResourceNotFoundException", 404, message)
}

pub fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationException", 400, message)
}

pub fn conflict(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ConflictException", 400, message)
}

pub fn in_use(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ResourceInUseException", 400, message)
}

/// The resource id at the end of an ARN or plain identifier.
pub fn last_segment(ident: &str) -> &str {
    ident.rsplit('/').next().unwrap_or(ident)
}

/// One page of `items` after the opaque `token`.
pub fn page<T>(items: Vec<T>, max: Option<i32>, token: Option<&str>) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        None | Some("") => 0,
        Some(t) => decode_token(t).ok_or_else(|| validation("The provided pagination token is invalid."))?,
    };
    let max = max.filter(|m| *m > 0).unwrap_or(1000) as usize;
    let total = items.len();
    let out: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + out.len() < total).then(|| encode_token(start + out.len()));
    Ok((out, next))
}

fn encode_token(offset: usize) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("mws-offset:{offset}"))
}

fn decode_token(token: &str) -> Option<usize> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(token).ok()?;
    String::from_utf8(raw).ok()?.strip_prefix("mws-offset:")?.parse().ok()
}

/// Sort `items` by creation time (or name), as `sortBy`/`sortOrder` ask;
/// the default is newest first.
pub fn sort_records(items: &mut [&crate::state::Record], sort_by: Option<&str>, sort_order: Option<&str>) {
    if sort_by == Some("Name") {
        items.sort_by(|a, b| a.name.cmp(&b.name));
    } else {
        items.sort_by(|a, b| a.created.cmp(&b.created).then(a.id.cmp(&b.id)));
    }
    let ascending = match sort_order {
        Some("Ascending") => true,
        Some("Descending") => false,
        _ => sort_by == Some("Name"),
    };
    if !ascending {
        items.reverse();
    }
}

/// A generated value as a document of its fields, without nulls.
pub fn to_doc<T: Serialize>(v: &T) -> Map<String, Value> {
    match strip_nulls(serde_json::to_value(v).expect("generated types serialize")) {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// A generated type from a document (missing fields take defaults).
pub fn from_doc<T: DeserializeOwned + Default>(doc: &Map<String, Value>) -> T {
    match serde_json::from_value(Value::Object(doc.clone())) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Bedrock document does not fit {}: {e}", std::any::type_name::<T>());
            T::default()
        }
    }
}

pub fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, strip_nulls(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        other => other,
    }
}

pub fn ts(t: chrono::DateTime<chrono::Utc>) -> Value {
    serde_json::to_value(t).expect("timestamps serialize")
}

pub fn tag_map(tags: &[types::Tag]) -> BTreeMap<String, String> {
    tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect()
}

pub fn tag_list(tags: &BTreeMap<String, String>) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()
}

pub const MAX_TAGS: usize = 200;

pub fn too_many_tags(resource: &str) -> ServiceError {
    ServiceError::client("TooManyTagsException", 400, "The number of tags exceeds the limit for this resource.")
        .with_field("resourceName", ErrorValue::String(resource.to_string()))
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &[types::Tag]) -> ConditionContext {
    let mut c: ConditionContext =
        tags.iter().map(|t| (format!("aws:RequestTag/{}", t.key), vec![t.value.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn resource_tag_context(tags: Option<&BTreeMap<String, String>>) -> ConditionContext {
    tags.into_iter().flatten().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

/// Insert `key: value` into a document.
pub fn set(doc: &mut Map<String, Value>, key: &str, value: impl Into<Value>) {
    doc.insert(key.to_string(), value.into());
}

/// Move `from` to `to` in a document.
pub fn rename(doc: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(v) = doc.remove(from) {
        doc.insert(to.to_string(), v);
    }
}
