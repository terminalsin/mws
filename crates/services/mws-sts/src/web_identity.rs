//! Minimal OIDC ID token handling for `AssumeRoleWithWebIdentity`.
//!
//! MWS checks the claims AWS checks (issuer registered as an IAM OIDC
//! provider, audience in its client ids, expiry) but does not verify the
//! token signature: it has no network access to the provider's keys, and test
//! tokens are usually self-issued.

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
