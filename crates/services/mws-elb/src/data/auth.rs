//! ALB authentication actions.
//!
//! `authenticate-oidc` runs the OpenID Connect authorization code flow as
//! ALB does: an unauthenticated request is redirected to the IdP's
//! authorization endpoint; the IdP sends the browser back to
//! `/oauth2/idpresponse` with a code, which the load balancer exchanges at
//! the token endpoint (client secret as HTTP Basic) before reading the user
//! info endpoint. It then sets the `AWSELBAuthSessionCookie-0` session
//! cookie and sends the user back to the original URL. Authenticated
//! requests reach targets with `x-amzn-oidc-accesstoken`,
//! `x-amzn-oidc-identity` and `x-amzn-oidc-data` (the user claims as an
//! ES256 JWT signed by the load balancer, whose public key is served at
//! `https://public-keys.auth.elb.<region>.amazonaws.com/<kid>`, or
//! `/_aws/elb/public-keys/<region>/<kid>` on the MWS endpoint). IdP errors
//! answer 561, as ALB does.
//!
//! `jwt-validation` checks a bearer token in `Authorization` against the
//! issuer's JWKS (RS256/384/512, ES256/384), its `iss`, `exp`, `nbf` and the
//! configured additional claims, answering 401 otherwise.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

use super::FrontSpec;
use crate::v2::types as t;
use crate::Elb;

/// ALB's callback path.
pub(crate) const CALLBACK: &str = "/oauth2/idpresponse";
const DEFAULT_COOKIE: &str = "AWSELBAuthSessionCookie";
/// How long the browser has to come back from the IdP.
const PENDING_TTL: Duration = Duration::from_secs(15 * 60);
const JWKS_TTL: Duration = Duration::from_secs(300);

struct Session {
    issuer: String,
    client_id: String,
    access_token: String,
    claims: Value,
    expires: DateTime<Utc>,
}

struct Pending {
    config: t::AuthenticateOidcActionConfig,
    original: String,
    created: Instant,
}

struct SigningKey {
    kid: String,
    pair: EcdsaKeyPair,
    pem: String,
}

#[derive(Default)]
pub(crate) struct AuthState {
    sessions: Mutex<HashMap<String, Session>>,
    pending: Mutex<HashMap<String, Pending>>,
    keys: Mutex<HashMap<String, SigningKey>>,
    jwks: Mutex<HashMap<String, (Instant, Value)>>,
}

impl AuthState {
    pub fn clear(&self) {
        self.sessions.lock().expect("auth lock").clear();
        self.pending.lock().expect("auth lock").clear();
    }

    /// Whether `query` carries the state of a login in progress.
    pub fn has_pending(&self, query: &str) -> bool {
        query_param(query, "state").is_some_and(|s| self.pending.lock().expect("auth lock").contains_key(&s))
    }

    /// The PEM public key with `kid`, if this load balancer region signed
    /// with it.
    pub fn public_key(&self, region: &str, kid: &str) -> Option<String> {
        let keys = self.keys.lock().expect("auth lock");
        keys.get(region).filter(|k| k.kid == kid).map(|k| k.pem.clone())
    }

    fn sign(&self, region: &str, header: Value, payload: &Value) -> String {
        let mut keys = self.keys.lock().expect("auth lock");
        let key = keys.entry(region.to_string()).or_insert_with(|| {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &aws_lc_rs::rand::SystemRandom::new(),
            )
            .expect("P-256 key");
            let pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
                .expect("P-256 key");
            let der = pair.public_key().as_der().expect("public key DER");
            let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
            let lines: Vec<&str> =
                b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect();
            let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", lines.join("\n"));
            SigningKey { kid: uuid::Uuid::new_v4().to_string(), pair, pem }
        });
        let mut header = header;
        header["kid"] = json!(key.kid);
        // ALB encodes with padding (`=`), unlike most JWT libraries.
        let enc = base64::engine::general_purpose::URL_SAFE;
        let input = format!("{}.{}", enc.encode(header.to_string()), enc.encode(payload.to_string()));
        let sig = key.pair.sign(&aws_lc_rs::rand::SystemRandom::new(), input.as_bytes()).expect("ES256 signature");
        format!("{input}.{}", enc.encode(sig.as_ref()))
    }
}

/// What an authentication action decided.
pub(crate) enum Outcome {
    /// Go on to the next action, adding these request headers.
    Continue(Vec<(String, String)>),
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
    },
}

fn respond(status: u16, headers: Vec<(String, String)>) -> Outcome {
    let body = if status == 302 { Bytes::new() } else { super::l7::error_page(status) };
    let mut headers = headers;
    if status != 302 {
        headers.push(("content-type".into(), "text/html".into()));
    }
    Outcome::Respond { status, headers, body }
}

fn cookie(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(&format!("{name}=")).map(str::to_string))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == name).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut b[..]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Run one authentication action for a request.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    elb: &Elb,
    spec: &FrontSpec,
    action: &t::Action,
    parts: &http::request::Parts,
    host: &str,
    path_and_query: &str,
) -> Outcome {
    match action.r#type.as_str() {
        "authenticate-oidc" => match &action.authenticate_oidc_config {
            Some(c) => oidc(elb, spec, c, parts, host, path_and_query).await,
            None => respond(500, Vec::new()),
        },
        "jwt-validation" => match &action.jwt_validation_config {
            Some(c) => jwt_validation(elb, c, parts).await,
            None => respond(500, Vec::new()),
        },
        // Cognito user pools are not emulated: ALB cannot reach one.
        _ => respond(500, Vec::new()),
    }
}

fn redirect_uri(host: &str) -> String {
    format!("https://{host}{CALLBACK}")
}

async fn oidc(
    elb: &Elb,
    spec: &FrontSpec,
    c: &t::AuthenticateOidcActionConfig,
    parts: &http::request::Parts,
    host: &str,
    path_and_query: &str,
) -> Outcome {
    let state_store = &elb.inner.data.auth;
    let cookie_name = c.session_cookie_name.clone().unwrap_or_else(|| DEFAULT_COOKIE.into());
    let now = elb.now();

    // The IdP sending the browser back.
    if parts.uri.path() == CALLBACK {
        let query = parts.uri.query().unwrap_or("");
        let pending = query_param(query, "state").and_then(|s| {
            let mut p = state_store.pending.lock().expect("auth lock");
            p.retain(|_, v| v.created.elapsed() < PENDING_TTL);
            p.remove(&s)
        });
        let Some(pending) = pending else { return respond(401, Vec::new()) };
        if query_param(query, "error").is_some() {
            return respond(561, Vec::new());
        }
        let Some(code) = query_param(query, "code") else { return respond(401, Vec::new()) };
        let cfg = &pending.config;
        let Ok(session) = exchange_code(cfg, &code, host, now).await else { return respond(561, Vec::new()) };
        let id = random_token();
        let timeout = cfg.session_timeout.unwrap_or(604_800);
        let expires = (now + chrono::Duration::seconds(timeout)).format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let cookie_name = cfg.session_cookie_name.clone().unwrap_or_else(|| DEFAULT_COOKIE.into());
        state_store.sessions.lock().expect("auth lock").insert(id.clone(), session);
        return respond(
            302,
            vec![
                ("location".into(), pending.original),
                (
                    "set-cookie".into(),
                    format!("{cookie_name}-0={id}; Expires={expires}; Path=/; Secure; HttpOnly; SameSite=None"),
                ),
            ],
        );
    }

    // An existing session.
    if let Some(id) = cookie(&parts.headers, &format!("{cookie_name}-0")) {
        let mut sessions = state_store.sessions.lock().expect("auth lock");
        sessions.retain(|_, s| s.expires > now);
        if let Some(s) = sessions.get(&id).filter(|s| s.issuer == c.issuer && s.client_id == c.client_id) {
            let header = json!({
                "typ": "JWT",
                "alg": "ES256",
                "iss": s.issuer,
                "client": s.client_id,
                "signer": spec.lb_arn,
                "exp": (now + chrono::Duration::seconds(120)).timestamp(),
            });
            let mut claims = s.claims.clone();
            if claims.get("exp").is_none() {
                claims["exp"] = json!((now + chrono::Duration::seconds(120)).timestamp());
            }
            if claims.get("iss").is_none() {
                claims["iss"] = json!(s.issuer);
            }
            let sub = claims.get("sub").and_then(Value::as_str).unwrap_or_default().to_string();
            let access = s.access_token.clone();
            drop(sessions);
            let data = state_store.sign(spec.region(), header, &claims);
            return Outcome::Continue(vec![
                ("x-amzn-oidc-accesstoken".into(), access),
                ("x-amzn-oidc-identity".into(), sub),
                ("x-amzn-oidc-data".into(), data),
            ]);
        }
    }

    match c.on_unauthenticated_request.as_deref().unwrap_or("authenticate") {
        "allow" => Outcome::Continue(Vec::new()),
        "deny" => respond(401, Vec::new()),
        _ => {
            let state = random_token();
            let scheme = "https";
            let original = format!("{scheme}://{host}{path_and_query}");
            state_store
                .pending
                .lock()
                .expect("auth lock")
                .insert(state.clone(), Pending { config: c.clone(), original, created: Instant::now() });
            let mut url = format!(
                "{}{}response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
                c.authorization_endpoint,
                if c.authorization_endpoint.contains('?') { "&" } else { "?" },
                encode(&c.client_id),
                encode(&redirect_uri(host)),
                encode(&state),
                encode(c.scope.as_deref().unwrap_or("openid")),
            );
            for (k, v) in c.authentication_request_extra_params.iter().flatten() {
                url.push_str(&format!("&{}={}", encode(k), encode(v)));
            }
            respond(302, vec![("location".into(), url), ("cache-control".into(), "no-cache".into())])
        }
    }
}

fn claims_of(jwt: &str) -> Option<Value> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn exchange_code(
    c: &t::AuthenticateOidcActionConfig,
    code: &str,
    host: &str,
    now: DateTime<Utc>,
) -> Result<Session, String> {
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}",
        encode(code),
        encode(&redirect_uri(host)),
        encode(&c.client_id)
    );
    let basic = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        c.client_id,
        c.client_secret.clone().unwrap_or_default()
    ));
    let (status, body) = fetch(
        "POST",
        &c.token_endpoint,
        &[("content-type", "application/x-www-form-urlencoded"), ("authorization", &format!("Basic {basic}"))],
        form.into_bytes(),
    )
    .await?;
    if status != 200 {
        return Err(format!("token endpoint answered {status}"));
    }
    let tokens: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let access = tokens.get("access_token").and_then(Value::as_str).ok_or("no access_token")?.to_string();
    // ALB checks the ID token's issuer and audience.
    if let Some(id) = tokens.get("id_token").and_then(Value::as_str) {
        let claims = claims_of(id).ok_or("unreadable id_token")?;
        if claims.get("iss").and_then(Value::as_str) != Some(c.issuer.as_str()) {
            return Err("id_token issuer mismatch".into());
        }
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => *a == c.client_id,
            Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(c.client_id.as_str())),
            _ => false,
        };
        if !aud_ok {
            return Err("id_token audience mismatch".into());
        }
    }
    let (status, body) =
        fetch("GET", &c.user_info_endpoint, &[("authorization", &format!("Bearer {access}"))], Vec::new()).await?;
    if status != 200 {
        return Err(format!("user info endpoint answered {status}"));
    }
    let claims: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let timeout = c.session_timeout.unwrap_or(604_800);
    Ok(Session {
        issuer: c.issuer.clone(),
        client_id: c.client_id.clone(),
        access_token: access,
        claims,
        expires: now + chrono::Duration::seconds(timeout),
    })
}

/// One HTTP(S) request to an IdP endpoint: `(status, body)`.
pub(crate) async fn fetch(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    let uri: http::Uri = url.parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let tls = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(format!("unsupported URL {url}")),
    };
    let host = uri.host().ok_or("no host")?.to_string();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let authority = uri.authority().map(|a| a.as_str().to_string()).unwrap_or(host.clone());
    let path = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let fut = async {
        let tcp = tokio::net::TcpStream::connect((host.trim_start_matches('[').trim_end_matches(']'), port))
            .await
            .map_err(|e| e.to_string())?;
        let mut req = http::Request::builder().method(method).uri(path).header(http::header::HOST, authority);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req.body(http_body_util::Full::new(Bytes::from(body))).map_err(|e| e.to_string())?;
        let resp = if tls {
            let s = super::tls::connect_insecure_named(tcp, host.trim_start_matches('[').trim_end_matches(']'))
                .await
                .map_err(|e| e.to_string())?;
            send_http1(TokioIo::new(s), req).await?
        } else {
            send_http1(TokioIo::new(tcp), req).await?
        };
        Ok::<_, String>(resp)
    };
    tokio::time::timeout(Duration::from_secs(5), fut).await.map_err(|_| "IdP timed out".to_string())?
}

async fn send_http1<I>(io: I, req: http::Request<http_body_util::Full<Bytes>>) -> Result<(u16, Vec<u8>), String>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes().to_vec();
    Ok((status, body))
}

async fn jwks(elb: &Elb, url: &str) -> Option<Value> {
    {
        let cache = elb.inner.data.auth.jwks.lock().expect("auth lock");
        if let Some((at, v)) = cache.get(url) {
            if at.elapsed() < JWKS_TTL {
                return Some(v.clone());
            }
        }
    }
    let (status, body) = fetch("GET", url, &[("accept", "application/json")], Vec::new()).await.ok()?;
    if status != 200 {
        return None;
    }
    let v: Value = serde_json::from_slice(&body).ok()?;
    elb.inner.data.auth.jwks.lock().expect("auth lock").insert(url.to_string(), (Instant::now(), v.clone()));
    Some(v)
}

fn b64url(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// Verify a compact JWS against a JWK.
fn verify(jwk: &Value, alg: &str, input: &[u8], sig: &[u8]) -> bool {
    let rsa = |a: &'static signature::RsaParameters| -> bool {
        let (Some(n), Some(e)) = (
            jwk.get("n").and_then(Value::as_str).and_then(b64url),
            jwk.get("e").and_then(Value::as_str).and_then(b64url),
        ) else {
            return false;
        };
        signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(a, input, sig).is_ok()
    };
    let ec = |a: &'static signature::EcdsaVerificationAlgorithm| -> bool {
        let (Some(x), Some(y)) = (
            jwk.get("x").and_then(Value::as_str).and_then(b64url),
            jwk.get("y").and_then(Value::as_str).and_then(b64url),
        ) else {
            return false;
        };
        let mut point = vec![4u8];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        signature::UnparsedPublicKey::new(a, &point).verify(input, sig).is_ok()
    };
    match alg {
        "RS256" => rsa(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => rsa(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => rsa(&signature::RSA_PKCS1_2048_8192_SHA512),
        "ES256" => ec(&signature::ECDSA_P256_SHA256_FIXED),
        "ES384" => ec(&signature::ECDSA_P384_SHA384_FIXED),
        _ => false,
    }
}

fn unauthorized(error: &str) -> Outcome {
    respond(401, vec![("www-authenticate".into(), format!("Bearer error=\"{error}\""))])
}

async fn jwt_validation(elb: &Elb, c: &t::JwtValidationActionConfig, parts: &http::request::Parts) -> Outcome {
    let Some(token) = parts
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(str::trim)
        .map(str::to_string)
    else {
        return unauthorized("invalid_request");
    };
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return unauthorized("invalid_token");
    }
    let (Some(header), Some(claims), Some(sig)) = (
        b64url(segments[0]).and_then(|b| serde_json::from_slice::<Value>(&b).ok()),
        b64url(segments[1]).and_then(|b| serde_json::from_slice::<Value>(&b).ok()),
        b64url(segments[2]),
    ) else {
        return unauthorized("invalid_token");
    };
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or_default().to_string();
    let kid = header.get("kid").and_then(Value::as_str).map(str::to_string);
    let Some(set) = jwks(elb, &c.jwks_endpoint).await else { return respond(500, Vec::new()) };
    let input = format!("{}.{}", segments[0], segments[1]);
    let keys = set.get("keys").and_then(Value::as_array).cloned().unwrap_or_default();
    let ok = keys
        .iter()
        .filter(|k| kid.is_none() || k.get("kid").and_then(Value::as_str) == kid.as_deref())
        .any(|k| verify(k, &alg, input.as_bytes(), &sig));
    if !ok {
        return unauthorized("invalid_token");
    }
    let now = elb.now().timestamp();
    if claims.get("iss").and_then(Value::as_str) != Some(c.issuer.as_str()) {
        return unauthorized("invalid_token");
    }
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp > now => {}
        _ => return unauthorized("invalid_token"),
    }
    if claims.get("nbf").and_then(Value::as_i64).is_some_and(|nbf| nbf > now) {
        return unauthorized("invalid_token");
    }
    for extra in c.additional_claims.iter().flatten() {
        let wanted = &extra.values;
        let have: Vec<String> = match (extra.format.as_str(), claims.get(&extra.name)) {
            ("string-array", Some(Value::Array(a))) => {
                a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
            }
            ("space-separated-values", Some(Value::String(s))) => {
                s.split(' ').filter(|x| !x.is_empty()).map(str::to_string).collect()
            }
            ("single-string", Some(Value::String(s))) => vec![s.clone()],
            _ => Vec::new(),
        };
        if !have.iter().any(|h| wanted.contains(h)) {
            return unauthorized("insufficient_scope");
        }
    }
    Outcome::Continue(Vec::new())
}
