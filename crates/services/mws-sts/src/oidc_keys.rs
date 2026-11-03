//! Verifying OIDC ID token signatures for `AssumeRoleWithWebIdentity`.
//!
//! As AWS does, MWS finds the issuer's keys through OpenID Connect
//! discovery: `https://<issuer>/.well-known/openid-configuration` names a
//! `jwks_uri`, and the token's `kid` picks a key from that set. The
//! provider's TLS certificate must chain to a public root, or one of the
//! certificates the server presents must match a thumbprint registered on
//! the IAM OIDC provider (how AWS trusts identity providers with private
//! CAs, and how tests run a local identity provider with a self-signed
//! certificate). Tokens issued by MWS itself (`GetWebIdentityToken`) are
//! checked against MWS's own signing keys.

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use base64::Engine;
use serde_json::Value;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DOCUMENT: usize = 1 << 20;

/// Why a token could not be verified.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The provider's keys could not be fetched.
    Communication(String),
    /// The token is malformed, uses an unsupported algorithm, names no
    /// known key, or its signature does not verify.
    Invalid(String),
}

/// A verification key: a JWK, or a raw public key MWS holds itself.
pub enum Key {
    Jwk(Value),
    /// (`kid`, `alg`, public key bytes as aws-lc-rs takes them).
    Raw {
        kid: String,
        alg: String,
        public: Vec<u8>,
    },
}

/// The JOSE header of a compact JWS.
pub fn header(token: &str) -> Option<serde_json::Map<String, Value>> {
    let h = token.split('.').next()?;
    serde_json::from_slice(&B64URL.decode(h.trim_end_matches('=')).ok()?).ok()
}

/// Check `token`'s signature against `keys`.
pub fn verify(token: &str, keys: &[Key]) -> Result<(), VerifyError> {
    let invalid = |m: &str| VerifyError::Invalid(m.to_string());
    let mut parts = token.splitn(3, '.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => return Err(invalid("not a JWS")),
    };
    let header = header(token).ok_or_else(|| invalid("unreadable header"))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or_default();
    let kid = header.get("kid").and_then(Value::as_str);
    let sig = B64URL.decode(s.trim_end_matches('=')).map_err(|_| invalid("unreadable signature"))?;
    let message = format!("{h}.{p}");
    let candidates: Vec<&Key> = keys
        .iter()
        .filter(|k| match (k, kid) {
            (Key::Jwk(j), Some(kid)) => j.get("kid").and_then(Value::as_str).is_none_or(|k| k == kid),
            (Key::Raw { kid: k, .. }, Some(kid)) => k == kid,
            _ => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err(invalid("no key matches the token's kid"));
    }
    for key in candidates {
        if verify_one(alg, key, message.as_bytes(), &sig)? {
            return Ok(());
        }
    }
    Err(invalid("signature does not verify"))
}

fn verify_one(alg: &str, key: &Key, message: &[u8], sig: &[u8]) -> Result<bool, VerifyError> {
    let rsa: Option<&'static signature::RsaParameters> = match alg {
        "RS256" => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
        "PS256" => Some(&signature::RSA_PSS_2048_8192_SHA256),
        "PS384" => Some(&signature::RSA_PSS_2048_8192_SHA384),
        "PS512" => Some(&signature::RSA_PSS_2048_8192_SHA512),
        _ => None,
    };
    let ec: Option<(&'static signature::EcdsaVerificationAlgorithm, &str)> = match alg {
        "ES256" => Some((&signature::ECDSA_P256_SHA256_FIXED, "P-256")),
        "ES384" => Some((&signature::ECDSA_P384_SHA384_FIXED, "P-384")),
        "ES512" => Some((&signature::ECDSA_P521_SHA512_FIXED, "P-521")),
        _ => None,
    };
    if rsa.is_none() && ec.is_none() {
        return Err(VerifyError::Invalid(format!("unsupported algorithm {alg:?}")));
    }
    let field = |j: &Value, name: &str| -> Option<Vec<u8>> {
        j.get(name).and_then(Value::as_str).and_then(|v| B64URL.decode(v.trim_end_matches('=')).ok())
    };
    match key {
        Key::Raw { alg: key_alg, public, .. } => {
            if key_alg != alg {
                return Ok(false);
            }
            if let Some(params) = rsa {
                return Ok(UnparsedPublicKey::new(params, public).verify(message, sig).is_ok());
            }
            let (params, _) = ec.expect("checked");
            Ok(UnparsedPublicKey::new(params, public).verify(message, sig).is_ok())
        }
        Key::Jwk(j) => {
            if j.get("alg").and_then(Value::as_str).is_some_and(|a| a != alg) {
                return Ok(false);
            }
            let kty = j.get("kty").and_then(Value::as_str).unwrap_or_default();
            if let Some(params) = rsa {
                if kty != "RSA" {
                    return Ok(false);
                }
                let (Some(n), Some(e)) = (field(j, "n"), field(j, "e")) else { return Ok(false) };
                return Ok(RsaPublicKeyComponents { n: &n, e: &e }.verify(params, message, sig).is_ok());
            }
            let (params, crv) = ec.expect("checked");
            if kty != "EC" || j.get("crv").and_then(Value::as_str) != Some(crv) {
                return Ok(false);
            }
            let (Some(x), Some(y)) = (field(j, "x"), field(j, "y")) else { return Ok(false) };
            let mut point = vec![4u8];
            point.extend(x);
            point.extend(y);
            Ok(UnparsedPublicKey::new(params, &point).verify(message, sig).is_ok())
        }
    }
}

/// Fetch the issuer's JSON Web Key Set through OpenID Connect discovery.
/// `thumbprints` are the IAM OIDC provider's (hex SHA-1) certificate
/// thumbprints.
pub async fn fetch_jwks(issuer: &str, thumbprints: &[String]) -> Result<Vec<Key>, VerifyError> {
    let comm = |m: String| VerifyError::Communication(m);
    let base = issuer.trim_end_matches('/');
    let discovery = get_json(&format!("{base}/.well-known/openid-configuration"), thumbprints).await.map_err(comm)?;
    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| comm("the discovery document has no jwks_uri".into()))?;
    let jwks = get_json(jwks_uri, thumbprints).await.map_err(comm)?;
    let keys = jwks.get("keys").and_then(Value::as_array).ok_or_else(|| comm("the JWKS has no keys".into()))?;
    Ok(keys.iter().cloned().map(Key::Jwk).collect())
}

async fn get_json(url: &str, thumbprints: &[String]) -> Result<Value, String> {
    let body = tokio::time::timeout(FETCH_TIMEOUT, https_get(url, thumbprints))
        .await
        .map_err(|_| format!("timed out fetching {url}"))??;
    serde_json::from_slice(&body).map_err(|e| format!("{url} is not JSON: {e}"))
}

/// A minimal HTTPS GET: HTTP/1.1, `Connection: close`.
async fn https_get(url: &str, thumbprints: &[String]) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("https://").ok_or_else(|| format!("{url} is not an https URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => {
            (h, p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?)
        }
        _ => (authority, 443),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let config = tls_config(thumbprints)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let tcp = tokio::net::TcpStream::connect((host, port)).await.map_err(|e| format!("connecting to {host}: {e}"))?;
    let mut tls = connector.connect(server_name, tcp).await.map_err(|e| format!("TLS with {host}: {e}"))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\nUser-Agent: mws-sts\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_DOCUMENT {
                    return Err(format!("{url} is too large"));
                }
            }
            // Servers often close without a TLS close_notify.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head.split(' ').nth(1).and_then(|s| s.parse().ok()).ok_or("malformed HTTP status line")?;
    if status != 200 {
        return Err(format!("{url} answered HTTP {status}"));
    }
    let body = &raw[split + 4..];
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    Ok(if chunked { dechunk(body) } else { body.to_vec() })
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(end) = data.windows(2).position(|w| w == b"\r\n") {
        let size = std::str::from_utf8(&data[..end])
            .ok()
            .and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok())
            .unwrap_or(0);
        if size == 0 || data.len() < end + 2 + size {
            break;
        }
        out.extend_from_slice(&data[end + 2..end + 2 + size]);
        data = &data[(end + 4 + size).min(data.len())..];
    }
    out
}

fn tls_config(thumbprints: &[String]) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let webpki = if roots.is_empty() {
        None
    } else {
        Some(
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|e| e.to_string())?,
        )
    };
    let verifier = ThumbprintVerifier {
        webpki,
        thumbprints: thumbprints.iter().map(|t| t.to_ascii_lowercase()).collect(),
        provider: provider.clone(),
    };
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// Trusts a server whose chain verifies against the public roots, or that
/// presents a certificate matching one of the provider's thumbprints.
#[derive(Debug)]
struct ThumbprintVerifier {
    webpki: Option<Arc<rustls::client::WebPkiServerVerifier>>,
    thumbprints: Vec<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

fn sha1_hex(der: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl rustls::client::danger::ServerCertVerifier for ThumbprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let pinned = std::iter::once(end_entity)
            .chain(intermediates.iter())
            .any(|c| self.thumbprints.contains(&sha1_hex(c.as_ref())));
        if pinned {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        match &self.webpki {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now),
            None => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_rs256_against_a_jwk_and_rejects_tampering() {
        use aws_lc_rs::rsa::KeyPair;
        use aws_lc_rs::signature::KeyPair as _;
        let key = KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let public = key.public_key();
        let components: RsaPublicKeyComponents<Vec<u8>> = public.into();
        let jwk = serde_json::json!({"kty":"RSA","kid":"k1","n":B64URL.encode(&components.n),"e":B64URL.encode(&components.e)});
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(r#"{"alg":"RS256","kid":"k1"}"#),
            B64URL.encode(r#"{"iss":"https://idp.example"}"#)
        );
        let mut sig = vec![0; key.public_modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            signing_input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        let token = format!("{signing_input}.{}", B64URL.encode(&sig));
        assert_eq!(verify(&token, &[Key::Jwk(jwk.clone())]), Ok(()));
        let forged = format!("{signing_input}.{}", B64URL.encode(b"sig"));
        assert!(matches!(verify(&forged, &[Key::Jwk(jwk.clone())]), Err(VerifyError::Invalid(_))));
        let none = format!("{}.{}.", B64URL.encode(r#"{"alg":"none"}"#), B64URL.encode("{}"));
        assert!(matches!(verify(&none, &[Key::Jwk(jwk)]), Err(VerifyError::Invalid(_))));
    }

    #[test]
    fn dechunks_bodies() {
        assert_eq!(dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"), b"Wikipedia");
    }
}
