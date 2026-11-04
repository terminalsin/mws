//! Decoding OIDC ID token claims for `AssumeRoleWithWebIdentity`.
//!
//! MWS checks the claims AWS checks (issuer registered as an IAM OIDC
//! provider, audience in its client ids, expiry); the signature is checked
//! in [`crate::oidc_keys`].

use base64::Engine;
use serde_json::Value;

pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: Option<i64>,
    pub raw: serde_json::Map<String, Value>,
}

pub fn decode(token: &str) -> Option<Claims> {
    let mut parts = token.split('.');
    let (_header, payload, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let raw: serde_json::Map<String, Value> = serde_json::from_slice(&bytes).ok()?;
    let iss = raw.get("iss")?.as_str()?.to_string();
    let sub = raw.get("sub").and_then(Value::as_str).unwrap_or_default().to_string();
    let aud = match raw.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![],
    };
    let exp = raw.get("exp").and_then(Value::as_i64);
    Some(Claims { iss, sub, aud, exp, raw })
}

/// Session tags, transitive tag keys and source identity carried by an
/// OIDC token, in either the nested (`https://aws.amazon.com/tags`) or the
/// flattened (`https://aws.amazon.com/tags/principal_tags/<key>`) form:
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html#id_session-tags_adding-assume-role-idp>
#[derive(Debug, Default)]
pub struct SessionTags {
    pub tags: std::collections::BTreeMap<String, String>,
    pub transitive: Vec<String>,
    pub source_identity: Option<String>,
}

const TAGS_CLAIM: &str = "https://aws.amazon.com/tags";
const SOURCE_IDENTITY_CLAIM: &str = "https://aws.amazon.com/source_identity";

/// A tag value: a string, or a list whose first entry is used (STS has no
/// multi-valued session tags).
fn single(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => a.first().and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec![],
    }
}

pub fn session_tags(raw: &serde_json::Map<String, Value>) -> SessionTags {
    let mut out = SessionTags::default();
    if let Some(nested) = raw.get(TAGS_CLAIM).and_then(Value::as_object) {
        if let Some(tags) = nested.get("principal_tags").and_then(Value::as_object) {
            out.tags.extend(tags.iter().filter_map(|(k, v)| single(v).map(|v| (k.clone(), v))));
        }
        if let Some(keys) = nested.get("transitive_tag_keys") {
            out.transitive = strings(keys);
        }
    }
    let flat_prefix = format!("{TAGS_CLAIM}/principal_tags/");
    for (k, v) in raw {
        if let (Some(key), Some(v)) = (k.strip_prefix(&flat_prefix), single(v)) {
            out.tags.insert(key.to_string(), v);
        }
    }
    if let Some(keys) = raw.get(&format!("{TAGS_CLAIM}/transitive_tag_keys")) {
        out.transitive = strings(keys);
    }
    out.source_identity = raw.get(SOURCE_IDENTITY_CLAIM).and_then(Value::as_str).map(str::to_string);
    out
}
