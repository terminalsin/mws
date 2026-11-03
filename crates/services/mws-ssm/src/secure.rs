//! `SecureString` values, encrypted with KMS for the caller through
//! Parameter Store (`kms:ViaService` = `ssm.<region>.amazonaws.com`) and the
//! encryption context `PARAMETER_ARN` = the parameter's ARN, as AWS does.
//!
//! Standard parameters are encrypted with `kms:Encrypt` directly. Advanced
//! parameters use envelope encryption: a `kms:GenerateDataKey` data key
//! seals the value with AES-256-GCM, and reading it takes `kms:Decrypt` on
//! the data key. Either way the stored value is ciphertext.

use std::collections::BTreeMap;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use base64::Engine;
use mws_core::{RequestContext, ServiceError};
use mws_kms::Kms;

use crate::generated::errors;

/// The key SecureStrings use when the caller names none.
pub const DEFAULT_KEY: &str = "alias/aws/ssm";

const ENVELOPE_MAGIC: &[u8] = b"MWSSSM1";

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn context(arn: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("PARAMETER_ARN".to_string(), arn.to_string())])
}

/// KMS failures as Parameter Store reports them.
fn ssm_error(e: ServiceError) -> ServiceError {
    match &*e.code {
        "NotFoundException" | "DisabledException" | "KMSInvalidStateException" | "InvalidKeyUsageException" => {
            errors::invalid_key_id(format!("{} (Service: AWSKMS; Status Code: 400; Error Code: {})", e.message, e.code))
        }
        _ => e,
    }
}

/// The key to pass to KMS for `key_id` (creating `alias/aws/ssm` on first use).
fn kms_key(kms: &Kms, ctx: &RequestContext, key_id: &str) -> String {
    if key_id == DEFAULT_KEY {
        kms.aws_managed_key(ctx, "ssm")
    } else {
        key_id.to_string()
    }
}

/// Encrypt `plaintext` for the parameter `arn`; returns base64 ciphertext.
pub fn seal(
    kms: &Kms,
    ctx: &RequestContext,
    key_id: &str,
    advanced: bool,
    arn: &str,
    plaintext: &str,
) -> Result<String, ServiceError> {
    let key = kms_key(kms, ctx, key_id);
    let context = context(arn);
    if !advanced {
        let (_, ciphertext) = kms.encrypt_via(ctx, "ssm", &key, plaintext.as_bytes(), &context).map_err(ssm_error)?;
        return Ok(b64().encode(ciphertext));
    }
    let data_key = kms.generate_data_key_via(ctx, "ssm", &key, &context, 32).map_err(ssm_error)?;
    let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &data_key.plaintext).expect("32-byte AES key"));
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).expect("system randomness");
    let mut sealed = plaintext.as_bytes().to_vec();
    aead.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(arn.as_bytes()), &mut sealed)
        .map_err(|_| ServiceError::internal("encrypting the parameter failed"))?;
    let mut blob = ENVELOPE_MAGIC.to_vec();
    blob.extend_from_slice(&(data_key.ciphertext.len() as u16).to_be_bytes());
    blob.extend_from_slice(&data_key.ciphertext);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);
    Ok(b64().encode(blob))
}

/// Decrypt a stored value of the parameter `arn`.
pub fn open(kms: &Kms, ctx: &RequestContext, arn: &str, stored: &str) -> Result<String, ServiceError> {
    let corrupt = || ServiceError::internal("the stored parameter value can't be decrypted");
    let blob = b64().decode(stored).map_err(|_| corrupt())?;
    let context = context(arn);
    let plaintext = match blob.strip_prefix(ENVELOPE_MAGIC) {
        None => kms.decrypt_via(ctx, "ssm", &blob, &context).map_err(ssm_error)?.1,
        Some(rest) => {
            let (len, rest) = rest.split_at_checked(2).ok_or_else(corrupt)?;
            let len = u16::from_be_bytes([len[0], len[1]]) as usize;
            let (wrapped, rest) = rest.split_at_checked(len).ok_or_else(corrupt)?;
            let (nonce, sealed) = rest.split_at_checked(NONCE_LEN).ok_or_else(corrupt)?;
            let (_, data_key) = kms.decrypt_via(ctx, "ssm", wrapped, &context).map_err(ssm_error)?;
            let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &data_key).map_err(|_| corrupt())?);
            let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| corrupt())?;
            let mut buf = sealed.to_vec();
            let out = aead.open_in_place(nonce, Aad::from(arn.as_bytes()), &mut buf).map_err(|_| corrupt())?;
            out.to_vec()
        }
    };
    String::from_utf8(plaintext).map_err(|_| corrupt())
}
