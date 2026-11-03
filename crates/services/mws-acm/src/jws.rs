//! JSON Web Signatures as ACME (RFC 8555) uses them: flattened JSON
//! serialization, account keys as JWKs (ES256, ES384, RS256), and HS256
//! for external account binding.

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// A flattened JWS.
#[derive(Debug, Clone)]
pub struct Jws {
    pub protected: Value,
    pub protected_b64: String,
    pub payload_b64: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Jws {
    pub fn parse(value: &Value) -> Option<Jws> {
        let protected_b64 = value.get("protected")?.as_str()?.to_string();
        let payload_b64 = value.get("payload")?.as_str()?.to_string();
        let signature = unb64(value.get("signature")?.as_str()?)?;
        let protected: Value = serde_json::from_slice(&unb64(&protected_b64)?).ok()?;
        let payload = unb64(&payload_b64)?;
        Some(Jws { protected, protected_b64, payload_b64, payload, signature })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.protected.get(name)?.as_str()
    }

    fn signing_input(&self) -> Vec<u8> {
        format!("{}.{}", self.protected_b64, self.payload_b64).into_bytes()
    }

    /// The payload as JSON; `None` for POST-as-GET (empty payload).
    pub fn payload_json(&self) -> Option<Value> {
        if self.payload.is_empty() {
            return None;
        }
        serde_json::from_slice(&self.payload).ok()
    }

    /// Check the signature against the account key `jwk`.
    pub fn verify(&self, jwk: &Value) -> bool {
        let alg = self.header("alg").unwrap_or_default();
        let field = |n: &str| jwk.get(n).and_then(Value::as_str).and_then(unb64);
        let msg = self.signing_input();
        match (alg, jwk.get("kty").and_then(Value::as_str)) {
            ("ES256" | "ES384", Some("EC")) => {
                let (Some(x), Some(y)) = (field("x"), field("y")) else { return false };
                let (alg, crv, len): (&'static signature::EcdsaVerificationAlgorithm, &str, usize) = match alg {
                    "ES256" => (&signature::ECDSA_P256_SHA256_FIXED, "P-256", 32),
                    _ => (&signature::ECDSA_P384_SHA384_FIXED, "P-384", 48),
                };
                if jwk.get("crv").and_then(Value::as_str) != Some(crv) || x.len() != len || y.len() != len {
                    return false;
                }
                let mut point = vec![0x04];
                point.extend(x);
                point.extend(y);
                UnparsedPublicKey::new(alg, point).verify(&msg, &self.signature).is_ok()
            }
            ("RS256", Some("RSA")) => {
                let (Some(n), Some(e)) = (field("n"), field("e")) else { return false };
                signature::RsaPublicKeyComponents { n, e }
                    .verify(&signature::RSA_PKCS1_2048_8192_SHA256, &msg, &self.signature)
                    .is_ok()
            }
            _ => false,
        }
    }

    /// Check an HMAC signature (external account binding).
    pub fn verify_hmac(&self, key: &[u8]) -> bool {
        let alg = match self.header("alg") {
            Some("HS256") => aws_lc_rs::hmac::HMAC_SHA256,
            Some("HS384") => aws_lc_rs::hmac::HMAC_SHA384,
            Some("HS512") => aws_lc_rs::hmac::HMAC_SHA512,
            _ => return false,
        };
        let key = aws_lc_rs::hmac::Key::new(alg, key);
        aws_lc_rs::hmac::verify(&key, &self.signing_input(), &self.signature).is_ok()
    }
}

/// The RFC 7638 thumbprint of a JWK.
pub fn thumbprint(jwk: &Value) -> Option<String> {
    let s = |n: &str| jwk.get(n).and_then(Value::as_str);
    let canonical = match s("kty")? {
        "EC" => format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, s("crv")?, s("x")?, s("y")?),
        "RSA" => format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, s("e")?, s("n")?),
        _ => return None,
    };
    Some(b64(&Sha256::digest(canonical.as_bytes())))
}

/// Whether a JWK is one MWS accepts as an account key.
pub fn supported_key(jwk: &Value) -> bool {
    thumbprint(jwk).is_some()
}
