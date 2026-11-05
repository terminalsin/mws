//! Token formats, OAuth errors and the small pieces of OAuth 2.0 the
//! grants share.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{ErrorValue, ServiceError};

use crate::generated::errors;
use crate::state::{Session, Token};
use crate::SsoOidc;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";
pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The scope the AWS access portal needs.
pub const ACCOUNT_ACCESS_SCOPE: &str = "sso:account:access";

pub fn random(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    aws_lc_rs::rand::fill(&mut bytes).expect("random bytes");
    B64URL.encode(bytes)
}

/// `ABCD-EFGH`, without letters that are easy to confuse.
pub fn user_code() -> String {
    const LETTERS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let mut bytes = [0u8; 8];
    aws_lc_rs::rand::fill(&mut bytes).expect("random bytes");
    let s: String = bytes.iter().map(|b| LETTERS[*b as usize % LETTERS.len()] as char).collect();
    format!("{}-{}", &s[..4], &s[4..])
}

/// An OAuth error: the exception the model declares, with the RFC 6749
/// `error` code beside `error_description`.
pub fn oauth(make: fn(String) -> ServiceError, code: &str, description: impl Into<String>) -> ServiceError {
    make(description.into()).with_field("error", ErrorValue::String(code.into()))
}

pub fn invalid_client(d: impl Into<String>) -> ServiceError {
    oauth(errors::invalid_client, "invalid_client", d)
}
pub fn invalid_grant(d: impl Into<String>) -> ServiceError {
    oauth(errors::invalid_grant, "invalid_grant", d)
}
pub fn invalid_request(d: impl Into<String>) -> ServiceError {
    oauth(errors::invalid_request, "invalid_request", d)
}
pub fn invalid_scope(d: impl Into<String>) -> ServiceError {
    oauth(errors::invalid_scope, "invalid_scope", d)
}
pub fn unsupported_grant_type(d: impl Into<String>) -> ServiceError {
    oauth(errors::unsupported_grant_type, "unsupported_grant_type", d)
}
pub fn unauthorized_client(d: impl Into<String>) -> ServiceError {
    oauth(errors::unauthorized_client, "unauthorized_client", d)
}
pub fn invalid_client_metadata(d: impl Into<String>) -> ServiceError {
    oauth(errors::invalid_client_metadata, "invalid_client_metadata", d)
}
pub fn invalid_redirect_uri(d: impl Into<String>) -> ServiceError {
    oauth(errors::invalid_redirect_uri, "invalid_redirect_uri", d)
}
pub fn authorization_pending() -> ServiceError {
    oauth(errors::authorization_pending, "authorization_pending", "Authorization is still pending")
}
pub fn expired_token(d: impl Into<String>) -> ServiceError {
    oauth(errors::expired_token, "expired_token", d)
}
pub fn access_denied(d: impl Into<String>) -> ServiceError {
    oauth(errors::access_denied, "access_denied", d)
}

/// Whether a PKCE `code_verifier` matches the challenge the authorization
/// request sent.
pub fn pkce_matches(verifier: &str, challenge: &str, method: Option<&str>) -> bool {
    match method.unwrap_or("plain") {
        "S256" => {
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier.as_bytes());
            B64URL.encode(digest.as_ref()) == challenge
        }
        "plain" => verifier == challenge,
        _ => false,
    }
}

/// The claims of a compact JWT, without checking its signature.
pub fn jwt_claims(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&B64URL.decode(payload.trim_end_matches('=')).ok()?).ok()
}

/// Where an AWS access portal URL points: an identity store id
/// (`https://d-1234567890.awsapps.com/start`) or an instance id
/// (`https://ssoins-1234567890abcdef.portal.us-east-1.app.aws`).
pub enum StartUrl {
    IdentityStore(String),
    Instance(String),
}

pub fn parse_start_url(url: &str) -> Option<StartUrl> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    let first = host.split('.').next()?;
    if host.ends_with(".awsapps.com") && first.starts_with("d-") {
        return Some(StartUrl::IdentityStore(first.to_string()));
    }
    if host.contains(".portal.") && first.starts_with("ssoins-") {
        return Some(StartUrl::Instance(first.to_string()));
    }
    None
}

impl SsoOidc {
    /// The identity store an AWS access portal URL belongs to.
    pub(crate) fn store_for_start_url(&self, url: &str) -> Option<String> {
        match parse_start_url(url)? {
            StartUrl::IdentityStore(id) => self.identity.store(&id).map(|s| s.id),
            StartUrl::Instance(id) => ["aws", "aws-cn", "aws-us-gov"]
                .iter()
                .find_map(|p| self.admin.instance_info(&format!("arn:{p}:sso:::instance/{id}")))
                .map(|i| i.identity_store_id),
        }
    }

    /// Issue an access token (and a refresh token when `refresh`) for
    /// `session`, valid for `seconds`.
    pub(crate) fn issue(
        &self,
        session: Session,
        now: DateTime<Utc>,
        seconds: i64,
        refresh: bool,
    ) -> (String, Option<String>) {
        let access = format!("aoa{}", random(120));
        let refresh_token = refresh.then(|| format!("aor{}", random(120)));
        let mut st = self.lock();
        st.tokens.retain(|_, t| t.expires_at > now);
        st.tokens.insert(
            access.clone(),
            Token { session: session.clone(), expires_at: now + chrono::Duration::seconds(seconds) },
        );
        if let Some(r) = &refresh_token {
            st.refresh.insert(r.clone(), session);
        }
        (access, refresh_token)
    }

    /// An HS256-signed JWT with `claims`.
    pub(crate) fn sign_jwt(&self, claims: &serde_json::Value) -> String {
        let header = B64URL.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = B64URL.encode(claims.to_string().as_bytes());
        let input = format!("{header}.{payload}");
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, self.id_token_key.as_ref());
        let sig = aws_lc_rs::hmac::sign(&key, input.as_bytes());
        format!("{input}.{}", B64URL.encode(sig.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc7636_example() {
        assert!(pkce_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            Some("S256")
        ));
        assert!(!pkce_matches("nope", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Some("S256")));
    }

    #[test]
    fn start_urls() {
        assert!(matches!(
            parse_start_url("https://d-1234567890.awsapps.com/start"),
            Some(StartUrl::IdentityStore(id)) if id == "d-1234567890"
        ));
        assert!(matches!(
            parse_start_url("https://ssoins-1234567890abcdef.portal.us-east-1.app.aws"),
            Some(StartUrl::Instance(id)) if id == "ssoins-1234567890abcdef"
        ));
        assert!(parse_start_url("https://example.com/start").is_none());
    }

    #[test]
    fn user_codes_look_like_aws() {
        let c = user_code();
        assert_eq!(c.len(), 9);
        assert_eq!(&c[4..5], "-");
    }
}
