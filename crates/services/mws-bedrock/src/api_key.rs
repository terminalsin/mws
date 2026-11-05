//! Amazon Bedrock API keys: bearer tokens in place of a SigV4 signature.
//!
//! A long-term key (`ABSK...`) is an IAM service-specific credential for
//! `bedrock.amazonaws.com`: `ABSK` and the base64 of `alias:secret`. A
//! short-term key (`bedrock-api-key-...`) is the base64 of a SigV4 presigned
//! `GET bedrock.amazonaws.com/?Action=CallWithBearerToken` URL, followed by
//! `&Version=1`, so it carries the signer's own credentials.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use mws_core::{AlternateSignature, ConditionContext, HttpRequest, RequestContext, ServiceError};

const LONG_TERM: &str = "ABSK";
const SHORT_TERM: &str = "bedrock-api-key-";
const HOST: &str = "bedrock.amazonaws.com";

/// The bearer token on `request`, if it carries one.
fn bearer(request: &HttpRequest) -> Option<&str> {
    let auth = request.headers().get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = auth.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// `LONG_TERM` or `SHORT_TERM` (as `bedrock:BearerTokenType` names them)
/// when `request` authenticates with a Bedrock API key.
pub fn token_type(request: &HttpRequest) -> Option<&'static str> {
    let token = bearer(request)?;
    if token.starts_with(LONG_TERM) {
        Some("LONG_TERM")
    } else if token.starts_with(SHORT_TERM) {
        Some("SHORT_TERM")
    } else {
        None
    }
}

fn invalid_format() -> ServiceError {
    ServiceError::client("AccessDeniedException", 403, "Invalid API Key format: Must start with pre-defined prefix")
}

fn invalid_key() -> ServiceError {
    ServiceError::client("AccessDeniedException", 403, "Authentication failed: Please make sure your API Key is valid.")
}

/// The credentials a Bedrock API key on `request` stands for. `None` when
/// the request carries no bearer token.
pub fn alternate(request: &HttpRequest) -> Option<Result<AlternateSignature, ServiceError>> {
    let token = bearer(request)?.to_string();
    if let Some(encoded) = token.strip_prefix(LONG_TERM) {
        return Some(long_term(&token, encoded));
    }
    if let Some(encoded) = token.strip_prefix(SHORT_TERM) {
        return Some(short_term(encoded));
    }
    Some(Err(invalid_format()))
}

fn long_term(token: &str, encoded: &str) -> Result<AlternateSignature, ServiceError> {
    let decoded = B64.decode(encoded).ok().and_then(|d| String::from_utf8(d).ok()).ok_or_else(invalid_key)?;
    let (alias, _) = decoded.split_once(':').ok_or_else(invalid_key)?;
    let token = token.to_string();
    Ok(AlternateSignature {
        access_key_id: alias.to_string(),
        session_token: None,
        region: None,
        verify: Box::new(move |secret, _now| {
            // The credential store hands back the whole key as the secret.
            if secret.len() == token.len() && secret.bytes().zip(token.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
            {
                Ok(())
            } else {
                Err(invalid_key())
            }
        }),
    })
}

fn short_term(encoded: &str) -> Result<AlternateSignature, ServiceError> {
    let decoded = B64.decode(encoded).ok().and_then(|d| String::from_utf8(d).ok()).ok_or_else(invalid_key)?;
    let url = decoded.strip_suffix("&Version=1").ok_or_else(invalid_key)?;
    let query = url.strip_prefix(HOST).and_then(|r| r.strip_prefix("/?")).ok_or_else(invalid_key)?;
    if !query.split('&').any(|p| p == "Action=CallWithBearerToken") {
        return Err(invalid_key());
    }
    let presigned = http::Request::builder()
        .method("GET")
        .uri(format!("https://{HOST}/?{query}"))
        .header(http::header::HOST, HOST)
        .body(Vec::<u8>::new())
        .map_err(|_| invalid_key())?;
    let parsed = mws_sigv4::parse(&presigned).map_err(|_| invalid_key())?;
    if parsed.scope.service != "bedrock" || parsed.expires_in.is_none() {
        return Err(invalid_key());
    }
    Ok(AlternateSignature {
        access_key_id: parsed.scope.access_key_id.clone(),
        session_token: parsed.session_token.clone(),
        region: (!parsed.scope.region.is_empty()).then(|| parsed.scope.region.clone()),
        verify: Box::new(move |secret, now| {
            let options = mws_sigv4::VerifyOptions::default();
            // Token generators sign the empty payload's hash or, like S3
            // presigners, `UNSIGNED-PAYLOAD`.
            let mut unsigned = presigned.clone();
            unsigned.headers_mut().insert("x-amz-content-sha256", http::HeaderValue::from_static("UNSIGNED-PAYLOAD"));
            mws_sigv4::verify(&presigned, &parsed, secret, now, options)
                .or_else(|e| match e {
                    mws_sigv4::SigV4Error::Mismatch => mws_sigv4::verify(&unsigned, &parsed, secret, now, options),
                    e => Err(e),
                })
                .map_err(|e| match e {
                    mws_sigv4::SigV4Error::PresignExpired => ServiceError::client(
                        "AccessDeniedException",
                        403,
                        "Authentication failed: Bearer Token has expired",
                    ),
                    _ => invalid_key(),
                })
        }),
    })
}

/// Callers that sent an API key need `bedrock:CallWithBearerToken` too.
pub fn authorize(ctx: &RequestContext, request: &HttpRequest) -> Result<(), ServiceError> {
    let Some(kind) = token_type(request) else { return Ok(()) };
    let mut conditions = ConditionContext::new();
    conditions.insert("bedrock:BearerTokenType".into(), vec![kind.into()]);
    ctx.authorize("bedrock:CallWithBearerToken", "*", conditions)
}
