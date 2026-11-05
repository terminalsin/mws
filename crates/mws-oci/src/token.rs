//! Registry passwords bound to an access key.
//!
//! A registry API hands out a password that `docker login` sends back as
//! HTTP Basic (or Bearer) credentials. The password names the access key
//! (and session token) it was issued to and carries an HMAC of its claims
//! keyed with the issuing registry's own key, so the gateway can
//! authenticate registry requests as the caller who asked for the password
//! (the access key must still be valid), with that caller's permissions,
//! until it expires.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// What a password says about who may use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Which registry the password is for (the issuing service's name).
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "key")]
    pub access_key_id: String,
    #[serde(rename = "tok", default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(rename = "reg")]
    pub region: String,
    /// Expiry, in Unix seconds on the wall clock.
    #[serde(rename = "exp")]
    pub expires: i64,
    #[serde(rename = "nonce", default)]
    pub nonce: String,
}

fn mac(secret: &str, payload: &str) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes keys of any length");
    m.update(payload.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// Issue a password for `claims`, signed with the registry's `key`.
pub fn issue(claims: &Claims, secret: &str) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
    let sig = URL_SAFE_NO_PAD.encode(mac(secret, &payload));
    format!("{payload}.{sig}")
}

/// The claims of a password, before its signature is checked.
pub fn claims(password: &str) -> Option<Claims> {
    let (payload, _) = password.split_once('.')?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// Why a password was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    BadSignature,
    Expired,
}

/// Check a password's signature with the registry's `key`, and its expiry
/// at `now` (Unix seconds).
pub fn verify(password: &str, secret: &str, now: i64) -> Result<Claims, TokenError> {
    let (payload, sig) = password.split_once('.').ok_or(TokenError::Malformed)?;
    let claims = claims(password).ok_or(TokenError::Malformed)?;
    let sig = URL_SAFE_NO_PAD.decode(sig).map_err(|_| TokenError::Malformed)?;
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes keys of any length");
    m.update(payload.as_bytes());
    m.verify_slice(&sig).map_err(|_| TokenError::BadSignature)?;
    if claims.expires <= now {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

/// The `authorizationToken` registries hand out: `base64(user:password)`.
pub fn basic_credentials(user: &str, password: &str) -> String {
    STANDARD.encode(format!("{user}:{password}"))
}

/// The password a request carries: HTTP Basic (`user:password`) or Bearer.
pub fn password_from_header(value: &str) -> Option<String> {
    let (scheme, rest) = value.trim().split_once(' ')?;
    let rest = rest.trim();
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = String::from_utf8(STANDARD.decode(rest).ok()?).ok()?;
        let (_, password) = decoded.split_once(':')?;
        Some(password.to_string())
    } else if scheme.eq_ignore_ascii_case("bearer") {
        Some(rest.to_string())
    } else {
        None
    }
}

/// Sign an arbitrary payload (a download link, ...) with `key`.
pub fn seal(payload: &str, key: &str) -> String {
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let sig = URL_SAFE_NO_PAD.encode(mac(key, &payload));
    format!("{payload}.{sig}")
}

/// The payload of a [`seal`]ed token, if `key` signed it.
pub fn open(token: &str, key: &str) -> Option<String> {
    let (payload, sig) = token.split_once('.')?;
    let sig = URL_SAFE_NO_PAD.decode(sig).ok()?;
    let mut m = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC takes keys of any length");
    m.update(payload.as_bytes());
    m.verify_slice(&sig).ok()?;
    String::from_utf8(URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// A random nonce for [`Claims::nonce`].
pub fn nonce() -> String {
    hex::encode(rand::random::<[u8; 8]>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let c = Claims {
            audience: "registry".into(),
            access_key_id: "AKIA".into(),
            session_token: None,
            region: "us-east-1".into(),
            expires: 100,
            nonce: nonce(),
        };
        let pw = issue(&c, "secret");
        assert_eq!(verify(&pw, "secret", 50).unwrap(), c);
        assert_eq!(verify(&pw, "other", 50), Err(TokenError::BadSignature));
        assert_eq!(verify(&pw, "secret", 100), Err(TokenError::Expired));
        let header = format!("Basic {}", basic_credentials("AWS", &pw));
        assert_eq!(password_from_header(&header).unwrap(), pw);
    }
}
