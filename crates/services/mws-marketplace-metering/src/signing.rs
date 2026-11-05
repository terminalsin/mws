//! The key RegisterUsage signs with, and the JWTs it signs.

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PSS_SHA256};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use mws_core::ServiceError;

use crate::state::State;

/// The only public key version AWS Marketplace has published.
pub const PUBLIC_KEY_VERSION: i32 = 1;

fn internal() -> ServiceError {
    crate::generated::errors::internal_service_error("An internal error has occurred. Retry your request.")
}

/// The signing key, made on first use and kept in state so saved state
/// keeps verifying.
fn key(state: &mut State) -> Result<RsaKeyPair, ServiceError> {
    if let Some(k) = &state.signing_key {
        let der = STANDARD.decode(k).map_err(|_| internal())?;
        return RsaKeyPair::from_pkcs8(&der).map_err(|_| internal());
    }
    let kp = RsaKeyPair::generate(KeySize::Rsa2048).map_err(|_| internal())?;
    let der = AsDer::<Pkcs8V1Der>::as_der(&kp).map_err(|_| internal())?;
    state.signing_key = Some(STANDARD.encode(der.as_ref()));
    Ok(kp)
}

/// A compact JWS (`PS256`) over `claims`.
pub fn sign_jwt(state: &mut State, claims: &serde_json::Value) -> Result<String, ServiceError> {
    let kp = key(state)?;
    let header = serde_json::json!({ "alg": "PS256", "typ": "JWT", "kid": PUBLIC_KEY_VERSION.to_string() });
    let input =
        format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
    let mut sig = vec![0u8; kp.public_modulus_len()];
    kp.sign(&RSA_PSS_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig).map_err(|_| internal())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

/// The public key as a PEM SubjectPublicKeyInfo.
pub fn public_key_pem(state: &mut State) -> Result<String, ServiceError> {
    let kp = key(state)?;
    let der = kp.public_key().as_der().map_err(|_| internal())?;
    let b64 = STANDARD.encode(der.as_ref());
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Ok(pem)
}
