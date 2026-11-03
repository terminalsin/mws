//! Envelope encryption of secret values, as Secrets Manager does it: a
//! 256-bit data key from KMS `GenerateDataKey` (for the caller, through
//! Secrets Manager) encrypts the value with AES-256-GCM; reading a value
//! asks KMS to `Decrypt` the data key. The encryption context is
//! `{"SecretARN": arn, "SecretVersionId": version}`.

use std::collections::BTreeMap;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use mws_core::{RequestContext, ServiceError};

use crate::generated::errors;
use crate::names::in_region;
use crate::state::Sealed;
use crate::SecretsManager;

/// A secret value in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plain {
    String(String),
    Binary(Vec<u8>),
}

impl Plain {
    pub fn from_input(string: Option<String>, binary: Option<Vec<u8>>) -> Result<Option<Self>, ServiceError> {
        match (string, binary) {
            (Some(_), Some(_)) => Err(errors::invalid_parameter(
                "You can't specify both a binary secret value and a string secret value in the same secret.",
            )),
            (Some(s), None) => Ok(Some(Plain::String(s))),
            (None, Some(b)) => Ok(Some(Plain::Binary(b))),
            (None, None) => Ok(None),
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Plain::String(s) => s.as_bytes(),
            Plain::Binary(b) => b,
        }
    }

    pub fn into_parts(self) -> (Option<String>, Option<Vec<u8>>) {
        match self {
            Plain::String(s) => (Some(s), None),
            Plain::Binary(b) => (None, Some(b)),
        }
    }
}

fn context(arn: &str, version: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("SecretARN".to_string(), arn.to_string()), ("SecretVersionId".to_string(), version.to_string())])
}

fn kms_access_denied() -> ServiceError {
    ServiceError::client("AccessDeniedException", 400, "Access to KMS is not allowed")
}

fn encrypt_error(e: ServiceError) -> ServiceError {
    match e.code.as_ref() {
        c if c.starts_with("AccessDenied") => kms_access_denied(),
        "NotFoundException" | "InvalidArnException" => {
            errors::encryption_failure("Secrets Manager can't find the specified KMS key.")
        }
        _ => errors::encryption_failure(
            "Secrets Manager can't encrypt the protected secret text using the provided KMS key. Check that the KMS key is available, enabled, and not in an invalid state. For more information, see Key state: Effect on your KMS key.",
        ),
    }
}

fn decrypt_error(e: ServiceError) -> ServiceError {
    if e.code.starts_with("AccessDenied") {
        kms_access_denied()
    } else {
        errors::decryption_failure(
            "Secrets Manager can't decrypt the protected secret text using the provided KMS key.",
        )
    }
}

impl SecretsManager {
    /// The KMS key to use for `kms_key_id` (`None` meaning
    /// `aws/secretsmanager`) in `region`.
    pub(crate) fn key_reference(&self, ctx: &RequestContext, region: &str, kms_key_id: Option<&str>) -> String {
        match kms_key_id {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => self.kms().aws_managed_key(&in_region(ctx, region), "secretsmanager"),
        }
    }

    /// Seal `value` for version `version` of the secret `arn` in `region`.
    pub(crate) fn seal(
        &self,
        ctx: &RequestContext,
        region: &str,
        kms_key_id: Option<&str>,
        arn: &str,
        version: &str,
        value: &Plain,
    ) -> Result<Sealed, ServiceError> {
        let rctx = in_region(ctx, region);
        let key = self.key_reference(ctx, region, kms_key_id);
        let dk = self
            .kms()
            .generate_data_key_via(&rctx, "secretsmanager", &key, &context(arn, version), 32)
            .map_err(encrypt_error)?;
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).map_err(|_| errors::internal_service_error("random failed"))?;
        let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &dk.plaintext).expect("32-byte key"));
        let mut data = value.bytes().to_vec();
        aead.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(arn.as_bytes()), &mut data)
            .map_err(|_| errors::internal_service_error("encryption failed"))?;
        Ok(Sealed {
            key_arn: dk.key_arn,
            encrypted_data_key: dk.ciphertext,
            nonce: nonce.to_vec(),
            ciphertext: data,
            binary: matches!(value, Plain::Binary(_)),
        })
    }

    /// Open a sealed value as the caller (who needs `kms:Decrypt` on the
    /// key, which `aws/secretsmanager` grants through Secrets Manager).
    pub(crate) fn unseal(
        &self,
        ctx: &RequestContext,
        region: &str,
        arn: &str,
        version: &str,
        sealed: &Sealed,
    ) -> Result<Plain, ServiceError> {
        let rctx = in_region(ctx, region);
        let (_, dk) = self
            .kms()
            .decrypt_via(&rctx, "secretsmanager", &sealed.encrypted_data_key, &context(arn, version))
            .map_err(decrypt_error)?;
        let fail = || {
            errors::decryption_failure(
                "Secrets Manager can't decrypt the protected secret text using the provided KMS key.",
            )
        };
        let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &dk).map_err(|_| fail())?);
        let nonce = Nonce::try_assume_unique_for_key(&sealed.nonce).map_err(|_| fail())?;
        let mut data = sealed.ciphertext.clone();
        let plain = aead.open_in_place(nonce, Aad::from(arn.as_bytes()), &mut data).map_err(|_| fail())?;
        Ok(if sealed.binary {
            Plain::Binary(plain.to_vec())
        } else {
            Plain::String(String::from_utf8(plain.to_vec()).map_err(|_| fail())?)
        })
    }
}
