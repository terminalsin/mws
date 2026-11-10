//! Cryptographic operations: encryption, data keys, signatures, MACs, key
//! agreement, key encapsulation and random bytes.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{key_arn, require_enabled, require_usage, spec, validation, Access, Target};
use crate::crypto::{self, CiphertextHeader, Message, Spec};
use crate::generated::{errors, types};
use crate::state::Key;
use crate::Kms;

fn invalid_ciphertext() -> ServiceError {
    errors::invalid_ciphertext("")
}

fn incorrect_key() -> ServiceError {
    errors::incorrect_key("The key ID in the request does not identify a KMS key that can perform this operation.")
}

fn no_recipient(recipient: &Option<types::RecipientInfo>) -> Result<(), ServiceError> {
    if recipient.is_some() {
        return Err(validation(
            "Recipient (Nitro Enclaves attestation) is not supported by MWS: there is no enclave to attest.",
        ));
    }
    Ok(())
}

fn check_dry_run(dry_run: Option<bool>) -> Result<(), ServiceError> {
    if dry_run == Some(true) {
        return Err(super::dry_run());
    }
    Ok(())
}

fn incompatible(what: &str, value: &str, key: &Key) -> ServiceError {
    errors::invalid_key_usage(format!(
        "{what} {value} is not compatible with KeySpec {} of key {}",
        key.key_spec, key.arn
    ))
}

/// The result of decrypting a ciphertext.
pub(crate) struct Decrypted {
    pub key_arn: String,
    pub plaintext: Vec<u8>,
    pub algorithm: String,
    pub material_id: Option<String>,
}

/// The result of encrypting a plaintext.
pub(crate) struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub algorithm: String,
    pub material_id: Option<String>,
}

/// Encrypt under `key` (already authorized and checked to be usable).
pub(crate) fn encrypt_with(
    key: &Key,
    plaintext: &[u8],
    context: &BTreeMap<String, String>,
    algorithm: Option<&str>,
) -> Result<Encrypted, ServiceError> {
    require_usage(key, "ENCRYPT_DECRYPT", "Encrypt")?;
    let s = spec(key);
    let algorithm = algorithm.unwrap_or("SYMMETRIC_DEFAULT").to_string();
    if !s.encryption_algorithms().contains(&algorithm) {
        return Err(incompatible("EncryptionAlgorithm", &algorithm, key));
    }
    match s {
        Spec::Symmetric => {
            let m = key.current().ok_or_else(|| super::invalid_state(key, "PendingImport"))?;
            let header = CiphertextHeader {
                account: key.account.clone(),
                key_id: key.key_id.clone(),
                material_id: m.id.clone(),
            };
            Ok(Encrypted {
                ciphertext: crypto::seal(&header, &m.secret, context, plaintext)?,
                algorithm,
                material_id: Some(m.id.clone()),
            })
        }
        Spec::Rsa(bits) => {
            if !context.is_empty() {
                return Err(validation("EncryptionContext is not supported with asymmetric KMS keys."));
            }
            let max = crypto::rsa_max_plaintext(bits, &algorithm);
            if plaintext.len() > max {
                return Err(validation(format!(
                    "Plaintext is too long for {algorithm} with key spec {}: the maximum is {max} bytes.",
                    key.key_spec
                )));
            }
            let m = key.current().ok_or_else(|| super::invalid_state(key, "PendingImport"))?;
            Ok(Encrypted {
                ciphertext: crypto::rsa_encrypt(&m.secret, &algorithm, plaintext)?,
                algorithm,
                material_id: None,
            })
        }
        _ => Err(incompatible("EncryptionAlgorithm", &algorithm, key)),
    }
}

/// A request to a key's external key store proxy.
pub(crate) struct XksCall {
    pub transport: crate::xks::XksTransport,
    pub proxy: crate::xks::Proxy,
    pub key: String,
    pub meta: crate::xks::Meta,
}

fn meta(ctx: Option<&RequestContext>, operation: &str, key: &Key) -> crate::xks::Meta {
    crate::xks::Meta {
        principal: ctx.map(|c| c.caller.arn.clone()).unwrap_or_else(|| format!("arn:aws:iam::{}:root", key.account)),
        operation: operation.into(),
        request_id: ctx.map(|c| c.request_id.clone()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        key_arn: Some(key.arn.clone()),
    }
}

/// A failed external key store request, as KMS reports it.
fn xks_error(key: &Key, e: crate::xks::XksError) -> ServiceError {
    use crate::xks::XksError;
    match &e {
        XksError::TimedOut => errors::dependency_timeout(format!("{}: {}", key.arn, e.describe())),
        XksError::Proxy { name, .. } if name == "InvalidCiphertextException" => invalid_ciphertext(),
        _ => errors::kms_invalid_state(format!("{} is unusable: {}.", key.arn, e.describe())),
    }
}

/// Decrypt with `key` (already authorized and checked to be usable).
pub(crate) fn decrypt_with(
    key: &Key,
    blob: &[u8],
    context: &BTreeMap<String, String>,
    algorithm: Option<&str>,
) -> Result<Decrypted, ServiceError> {
    require_usage(key, "ENCRYPT_DECRYPT", "Decrypt")?;
    let s = spec(key);
    let algorithm = algorithm.unwrap_or("SYMMETRIC_DEFAULT").to_string();
    if !s.encryption_algorithms().contains(&algorithm) {
        return Err(incompatible("EncryptionAlgorithm", &algorithm, key));
    }
    match s {
        Spec::Symmetric => {
            let (header, len) = crypto::parse_header(blob).ok_or_else(invalid_ciphertext)?;
            if header.key_id != key.key_id || header.account != key.account {
                return Err(incorrect_key());
            }
            let m = key.material(&header.material_id).ok_or_else(invalid_ciphertext)?;
            let plaintext = crypto::open(blob, len, &m.secret, context).ok_or_else(invalid_ciphertext)?;
            Ok(Decrypted { key_arn: key.arn.clone(), plaintext, algorithm, material_id: Some(m.id.clone()) })
        }
        Spec::Rsa(_) => {
            let m = key.current().ok_or_else(invalid_ciphertext)?;
            let plaintext = crypto::rsa_decrypt(&m.secret, &algorithm, blob).ok_or_else(invalid_ciphertext)?;
            Ok(Decrypted { key_arn: key.arn.clone(), plaintext, algorithm, material_id: None })
        }
        _ => Err(incompatible("EncryptionAlgorithm", &algorithm, key)),
    }
}

impl Kms {
    /// The external key store call for `key`, when it lives in one (the
    /// store must be connected).
    pub(crate) fn xks_for(&self, key: &Key, meta: crate::xks::Meta) -> Result<Option<XksCall>, ServiceError> {
        let Some(xks_key) = key.xks_key_id.clone() else { return Ok(None) };
        let st = self.lock();
        let store = key.custom_key_store_id.as_ref().and_then(|id| st.custom_key_stores.get(id));
        let Some(store) = store else {
            return Err(errors::kms_invalid_state(format!("The custom key store of {} does not exist.", key.arn)));
        };
        if store.connection_state != "CONNECTED" {
            return Err(errors::kms_invalid_state(format!(
                "{} is unusable because its custom key store {} is not connected.",
                key.arn, store.id
            )));
        }
        let proxy = crate::ops::stores::proxy_of(store)
            .ok_or_else(|| errors::kms_invalid_state(format!("The custom key store {} has no proxy.", store.id)))?;
        Ok(Some(XksCall { transport: self.xks_transport(), proxy, key: xks_key, meta }))
    }

    /// Encrypt with `key`, through its external key store if it has one.
    pub(crate) fn encrypt_key(
        &self,
        ctx: Option<&RequestContext>,
        operation: &str,
        key: &Key,
        plaintext: &[u8],
        context: &BTreeMap<String, String>,
        algorithm: Option<&str>,
    ) -> Result<Encrypted, ServiceError> {
        let mut out = encrypt_with(key, plaintext, context, algorithm)?;
        if let Some(x) = self.xks_for(key, meta(ctx, operation, key))? {
            let (_, len) = crypto::parse_header(&out.ciphertext).ok_or_else(invalid_ciphertext)?;
            let (head, inner) = out.ciphertext.split_at(len);
            let outer = crate::xks::encrypt(&x.transport, &x.proxy, &x.key, &x.meta, inner, head)
                .map_err(|e| xks_error(key, e))?;
            out.ciphertext = [head.to_vec(), outer.encode()].concat();
        }
        Ok(out)
    }

    /// Decrypt with `key`, through its external key store if it has one.
    pub(crate) fn decrypt_key(
        &self,
        ctx: Option<&RequestContext>,
        operation: &str,
        key: &Key,
        blob: &[u8],
        context: &BTreeMap<String, String>,
        algorithm: Option<&str>,
    ) -> Result<Decrypted, ServiceError> {
        if let Some(x) = self.xks_for(key, meta(ctx, operation, key))? {
            let (_, len) = crypto::parse_header(blob).ok_or_else(invalid_ciphertext)?;
            let (head, rest) = blob.split_at(len);
            let outer = crate::xks::Outer::decode(rest).ok_or_else(invalid_ciphertext)?;
            let inner = crate::xks::decrypt(&x.transport, &x.proxy, &x.key, &x.meta, &outer, head)
                .map_err(|e| xks_error(key, e))?;
            return decrypt_with(key, &[head, inner.as_slice()].concat(), context, algorithm);
        }
        decrypt_with(key, blob, context, algorithm)
    }

    /// Work out which key a `Decrypt`-style request uses: the `KeyId`
    /// parameter, or the key named in a symmetric ciphertext.
    fn decryption_key(
        &self,
        ctx: &RequestContext,
        key_id: Option<&str>,
        blob: &[u8],
        ignore_ciphertext: bool,
    ) -> Result<String, ServiceError> {
        match key_id {
            Some(id) => Ok(id.to_string()),
            None => {
                if ignore_ciphertext {
                    return Err(validation("KeyId is required when the IGNORE_CIPHERTEXT dry-run modifier is set."));
                }
                let (header, _) = crypto::parse_header(blob).ok_or_else(invalid_ciphertext)?;
                Ok(key_arn(&ctx.partition, &ctx.region, &header.account, &header.key_id))
            }
        }
    }

    /// Resolve, authorize and check the key for a cryptographic operation,
    /// returning a copy of it.
    pub(crate) fn usable_key(
        &self,
        ctx: &RequestContext,
        key_id: &str,
        access: Access<'_>,
    ) -> Result<Key, ServiceError> {
        let t: Target = self.authorize_key(ctx, key_id, access)?;
        let st = self.lock();
        let key = st.key(&t.arn)?;
        require_enabled(key)?;
        Ok(key.clone())
    }

    pub(crate) fn encrypt(
        &self,
        ctx: &RequestContext,
        input: types::EncryptRequest,
    ) -> Result<types::EncryptResponse, ServiceError> {
        let alg = input.encryption_algorithm.clone().unwrap_or_else(|| "SYMMETRIC_DEFAULT".into());
        let enc = input.encryption_context.unwrap_or_default();
        let key = self.usable_key(
            ctx,
            &input.key_id,
            Access::crypto("Encrypt").context(Some(&enc)).condition("kms:EncryptionAlgorithm", vec![alg.clone()]),
        )?;
        let out = self.encrypt_key(Some(ctx), "Encrypt", &key, &input.plaintext, &enc, Some(&alg))?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "Encrypt");
        Ok(types::EncryptResponse {
            ciphertext_blob: Some(out.ciphertext),
            key_id: Some(key.arn),
            encryption_algorithm: Some(out.algorithm),
        })
    }

    pub(crate) fn decrypt(
        &self,
        ctx: &RequestContext,
        input: types::DecryptRequest,
    ) -> Result<types::DecryptResponse, ServiceError> {
        no_recipient(&input.recipient)?;
        let blob = input.ciphertext_blob.unwrap_or_default();
        let ignore =
            input.dry_run == Some(true) && input.dry_run_modifiers.iter().flatten().any(|m| m == "IGNORE_CIPHERTEXT");
        if blob.is_empty() && !ignore {
            return Err(validation("CiphertextBlob is required."));
        }
        let alg = input.encryption_algorithm.clone().unwrap_or_else(|| "SYMMETRIC_DEFAULT".into());
        let enc = input.encryption_context.unwrap_or_default();
        let key_ref = self.decryption_key(ctx, input.key_id.as_deref(), &blob, ignore)?;
        let key = self.usable_key(
            ctx,
            &key_ref,
            Access::crypto("Decrypt").context(Some(&enc)).condition("kms:EncryptionAlgorithm", vec![alg.clone()]),
        )?;
        if ignore {
            require_usage(&key, "ENCRYPT_DECRYPT", "Decrypt")?;
            return Err(super::dry_run());
        }
        let out = self.decrypt_key(Some(ctx), "Decrypt", &key, &blob, &enc, Some(&alg))?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "Decrypt");
        Ok(types::DecryptResponse {
            key_id: Some(out.key_arn),
            plaintext: Some(out.plaintext),
            encryption_algorithm: Some(out.algorithm),
            ciphertext_for_recipient: None,
            key_material_id: out.material_id,
        })
    }

    pub(crate) fn re_encrypt(
        &self,
        ctx: &RequestContext,
        input: types::ReEncryptRequest,
    ) -> Result<types::ReEncryptResponse, ServiceError> {
        let blob = input.ciphertext_blob.unwrap_or_default();
        let ignore =
            input.dry_run == Some(true) && input.dry_run_modifiers.iter().flatten().any(|m| m == "IGNORE_CIPHERTEXT");
        let src_alg = input.source_encryption_algorithm.clone().unwrap_or_else(|| "SYMMETRIC_DEFAULT".into());
        let dst_alg = input.destination_encryption_algorithm.clone().unwrap_or_else(|| "SYMMETRIC_DEFAULT".into());
        let src_enc = input.source_encryption_context.unwrap_or_default();
        let dst_enc = input.destination_encryption_context.unwrap_or_default();
        let src_ref = self.decryption_key(ctx, input.source_key_id.as_deref(), &blob, ignore)?;
        let (src_arn, dst_arn) = {
            let st = self.lock();
            (st.resolve(ctx, &src_ref, true)?.arn, st.resolve(ctx, &input.destination_key_id, true)?.arn)
        };
        let same = (src_arn == dst_arn).to_string();
        let src = self.usable_key(
            ctx,
            &src_ref,
            Access::crypto("ReEncryptFrom")
                .context(Some(&src_enc))
                .condition("kms:EncryptionAlgorithm", vec![src_alg.clone()])
                .condition("kms:ReEncryptOnSameKey", vec![same.clone()]),
        )?;
        let dst = self.usable_key(
            ctx,
            &input.destination_key_id,
            Access::crypto("ReEncryptTo")
                .context(Some(&dst_enc))
                .condition("kms:EncryptionAlgorithm", vec![dst_alg.clone()])
                .condition("kms:ReEncryptOnSameKey", vec![same]),
        )?;
        if ignore {
            return Err(super::dry_run());
        }
        let plain = self.decrypt_key(Some(ctx), "ReEncrypt", &src, &blob, &src_enc, Some(&src_alg))?;
        let out = self.encrypt_key(Some(ctx), "ReEncrypt", &dst, &plain.plaintext, &dst_enc, Some(&dst_alg))?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &src.arn, "ReEncrypt");
        self.record_use(ctx, &dst.arn, "ReEncrypt");
        Ok(types::ReEncryptResponse {
            ciphertext_blob: Some(out.ciphertext),
            source_key_id: Some(src.arn),
            key_id: Some(dst.arn),
            source_encryption_algorithm: Some(plain.algorithm),
            destination_encryption_algorithm: Some(out.algorithm),
            source_key_material_id: plain.material_id,
            destination_key_material_id: out.material_id,
        })
    }

    /// Plaintext and ciphertext of a new data key.
    pub(crate) fn new_data_key(
        &self,
        ctx: &RequestContext,
        action: &str,
        key_id: &str,
        enc: &BTreeMap<String, String>,
        key_spec: Option<&str>,
        number_of_bytes: Option<i32>,
    ) -> Result<(Key, Vec<u8>, Encrypted), ServiceError> {
        let len = match (key_spec, number_of_bytes) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(validation("Please specify either number of bytes or key spec."));
            }
            (Some("AES_128"), None) => 16,
            (Some(_), None) => 32,
            (None, Some(n)) => n as usize,
        };
        let key = self.usable_key(ctx, key_id, Access::crypto(action).context(Some(enc)))?;
        if !key.is_symmetric() || key.key_usage != "ENCRYPT_DECRYPT" {
            return Err(errors::invalid_key_usage(format!(
                "{} is not a symmetric encryption KMS key. {action} requires a symmetric encryption KMS key.",
                key.arn
            )));
        }
        let plaintext = crypto::random_bytes(len);
        let out = self.encrypt_key(Some(ctx), action, &key, &plaintext, enc, None)?;
        Ok((key, plaintext, out))
    }

    pub(crate) fn generate_data_key(
        &self,
        ctx: &RequestContext,
        input: types::GenerateDataKeyRequest,
    ) -> Result<types::GenerateDataKeyResponse, ServiceError> {
        no_recipient(&input.recipient)?;
        let enc = input.encryption_context.unwrap_or_default();
        let (key, plaintext, out) = self.new_data_key(
            ctx,
            "GenerateDataKey",
            &input.key_id,
            &enc,
            input.key_spec.as_deref(),
            input.number_of_bytes,
        )?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "GenerateDataKey");
        Ok(types::GenerateDataKeyResponse {
            ciphertext_blob: Some(out.ciphertext),
            plaintext: Some(plaintext),
            key_id: Some(key.arn),
            ciphertext_for_recipient: None,
            key_material_id: out.material_id,
        })
    }

    pub(crate) fn generate_data_key_without_plaintext(
        &self,
        ctx: &RequestContext,
        input: types::GenerateDataKeyWithoutPlaintextRequest,
    ) -> Result<types::GenerateDataKeyWithoutPlaintextResponse, ServiceError> {
        let enc = input.encryption_context.unwrap_or_default();
        let (key, _, out) = self.new_data_key(
            ctx,
            "GenerateDataKeyWithoutPlaintext",
            &input.key_id,
            &enc,
            input.key_spec.as_deref(),
            input.number_of_bytes,
        )?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "GenerateDataKeyWithoutPlaintext");
        Ok(types::GenerateDataKeyWithoutPlaintextResponse {
            ciphertext_blob: Some(out.ciphertext),
            key_id: Some(key.arn),
            key_material_id: out.material_id,
        })
    }

    fn new_data_key_pair(
        &self,
        ctx: &RequestContext,
        action: &str,
        key_id: &str,
        enc: &BTreeMap<String, String>,
        pair_spec: &str,
    ) -> Result<(Key, Vec<u8>, Vec<u8>, Encrypted), ServiceError> {
        let key = self.usable_key(
            ctx,
            key_id,
            Access::crypto(action).context(Some(enc)).condition("kms:DataKeyPairSpec", vec![pair_spec.to_string()]),
        )?;
        if !key.is_symmetric() || key.key_usage != "ENCRYPT_DECRYPT" {
            return Err(errors::invalid_key_usage(format!(
                "{} is not a symmetric encryption KMS key. {action} requires a symmetric encryption KMS key.",
                key.arn
            )));
        }
        let s = Spec::parse(pair_spec).ok_or_else(|| validation(format!("Invalid KeyPairSpec {pair_spec}")))?;
        let (private, public) = crypto::data_key_pair(s)?;
        let out = self.encrypt_key(Some(ctx), action, &key, &private, enc, None)?;
        Ok((key, private, public, out))
    }

    pub(crate) fn generate_data_key_pair(
        &self,
        ctx: &RequestContext,
        input: types::GenerateDataKeyPairRequest,
    ) -> Result<types::GenerateDataKeyPairResponse, ServiceError> {
        no_recipient(&input.recipient)?;
        let enc = input.encryption_context.unwrap_or_default();
        let (key, private, public, out) =
            self.new_data_key_pair(ctx, "GenerateDataKeyPair", &input.key_id, &enc, &input.key_pair_spec)?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "GenerateDataKeyPair");
        Ok(types::GenerateDataKeyPairResponse {
            private_key_ciphertext_blob: Some(out.ciphertext),
            private_key_plaintext: Some(private),
            public_key: Some(public),
            key_id: Some(key.arn),
            key_pair_spec: Some(input.key_pair_spec),
            ciphertext_for_recipient: None,
            key_material_id: out.material_id,
        })
    }

    pub(crate) fn generate_data_key_pair_without_plaintext(
        &self,
        ctx: &RequestContext,
        input: types::GenerateDataKeyPairWithoutPlaintextRequest,
    ) -> Result<types::GenerateDataKeyPairWithoutPlaintextResponse, ServiceError> {
        let enc = input.encryption_context.unwrap_or_default();
        let (key, _, public, out) = self.new_data_key_pair(
            ctx,
            "GenerateDataKeyPairWithoutPlaintext",
            &input.key_id,
            &enc,
            &input.key_pair_spec,
        )?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "GenerateDataKeyPairWithoutPlaintext");
        Ok(types::GenerateDataKeyPairWithoutPlaintextResponse {
            private_key_ciphertext_blob: Some(out.ciphertext),
            public_key: Some(public),
            key_id: Some(key.arn),
            key_pair_spec: Some(input.key_pair_spec),
            key_material_id: out.material_id,
        })
    }

    // ---- signatures ---------------------------------------------------------

    fn signing_key(
        &self,
        ctx: &RequestContext,
        action: &str,
        key_id: &str,
        alg: &str,
        message_type: &str,
    ) -> Result<Key, ServiceError> {
        let key = self.usable_key(
            ctx,
            key_id,
            Access::crypto(action)
                .condition("kms:SigningAlgorithm", vec![alg.to_string()])
                .condition("kms:MessageType", vec![message_type.to_string()]),
        )?;
        require_usage(&key, "SIGN_VERIFY", action)?;
        if !spec(&key).signing_algorithms().iter().any(|a| a == alg) {
            return Err(incompatible("SigningAlgorithm", alg, &key));
        }
        Ok(key)
    }

    fn message<'a>(message_type: &str, m: &'a [u8]) -> Result<Message<'a>, ServiceError> {
        match message_type {
            "RAW" => Ok(Message::Raw(m)),
            "DIGEST" => Ok(Message::Digest(m)),
            other => Err(validation(format!("MessageType {other} is not supported by MWS."))),
        }
    }

    pub(crate) fn sign(
        &self,
        ctx: &RequestContext,
        input: types::SignRequest,
    ) -> Result<types::SignResponse, ServiceError> {
        let mt = input.message_type.clone().unwrap_or_else(|| "RAW".into());
        let key = self.signing_key(ctx, "Sign", &input.key_id, &input.signing_algorithm, &mt)?;
        let msg = Self::message(&mt, &input.message)?;
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let signature = crypto::sign(spec(&key), &m.secret, &input.signing_algorithm, msg)?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "Sign");
        Ok(types::SignResponse {
            key_id: Some(key.arn),
            signature: Some(signature),
            signing_algorithm: Some(input.signing_algorithm),
        })
    }

    pub(crate) fn verify(
        &self,
        ctx: &RequestContext,
        input: types::VerifyRequest,
    ) -> Result<types::VerifyResponse, ServiceError> {
        let mt = input.message_type.clone().unwrap_or_else(|| "RAW".into());
        let key = self.signing_key(ctx, "Verify", &input.key_id, &input.signing_algorithm, &mt)?;
        let msg = Self::message(&mt, &input.message)?;
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let valid = crypto::verify(spec(&key), &m.secret, &input.signing_algorithm, msg, &input.signature)?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "Verify");
        if !valid {
            return Err(errors::kms_invalid_signature(""));
        }
        Ok(types::VerifyResponse {
            key_id: Some(key.arn),
            signature_valid: true,
            signing_algorithm: Some(input.signing_algorithm),
        })
    }

    pub(crate) fn get_public_key(
        &self,
        ctx: &RequestContext,
        input: types::GetPublicKeyRequest,
    ) -> Result<types::GetPublicKeyResponse, ServiceError> {
        let key = self.usable_key(ctx, &input.key_id, Access::crypto("GetPublicKey"))?;
        let s = spec(&key);
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let public = crypto::public_key_der(s, &m.secret)?;
        let usage = key.key_usage.as_str();
        Ok(types::GetPublicKeyResponse {
            key_id: Some(key.arn.clone()),
            public_key: Some(public),
            customer_master_key_spec: Some(key.key_spec.clone()),
            key_spec: Some(key.key_spec.clone()),
            key_usage: Some(key.key_usage.clone()),
            encryption_algorithms: (usage == "ENCRYPT_DECRYPT").then(|| s.encryption_algorithms()),
            signing_algorithms: (usage == "SIGN_VERIFY").then(|| s.signing_algorithms()),
            key_agreement_algorithms: (usage == "KEY_AGREEMENT").then(|| vec!["ECDH".into()]),
            encapsulation_algorithms: (usage == "ENCAPSULATE_DECAPSULATE").then(|| vec!["ML_KEM".into()]),
        })
    }

    // ---- MACs ---------------------------------------------------------------

    fn mac_key(&self, ctx: &RequestContext, action: &str, key_id: &str, alg: &str) -> Result<Key, ServiceError> {
        let key =
            self.usable_key(ctx, key_id, Access::crypto(action).condition("kms:MacAlgorithm", vec![alg.to_string()]))?;
        require_usage(&key, "GENERATE_VERIFY_MAC", action)?;
        if !spec(&key).mac_algorithms().iter().any(|a| a == alg) {
            return Err(incompatible("MacAlgorithm", alg, &key));
        }
        Ok(key)
    }

    pub(crate) fn generate_mac(
        &self,
        ctx: &RequestContext,
        input: types::GenerateMacRequest,
    ) -> Result<types::GenerateMacResponse, ServiceError> {
        let key = self.mac_key(ctx, "GenerateMac", &input.key_id, &input.mac_algorithm)?;
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let mac = crypto::mac(&m.secret, &input.mac_algorithm, &input.message);
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "GenerateMac");
        Ok(types::GenerateMacResponse {
            mac: Some(mac),
            mac_algorithm: Some(input.mac_algorithm),
            key_id: Some(key.arn),
        })
    }

    pub(crate) fn verify_mac(
        &self,
        ctx: &RequestContext,
        input: types::VerifyMacRequest,
    ) -> Result<types::VerifyMacResponse, ServiceError> {
        let key = self.mac_key(ctx, "VerifyMac", &input.key_id, &input.mac_algorithm)?;
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let expected = crypto::mac(&m.secret, &input.mac_algorithm, &input.message);
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "VerifyMac");
        if !aws_lc_rs::constant_time::verify_slices_are_equal(&expected, &input.mac).is_ok() {
            return Err(errors::kms_invalid_mac(""));
        }
        Ok(types::VerifyMacResponse {
            key_id: Some(key.arn),
            mac_valid: true,
            mac_algorithm: Some(input.mac_algorithm),
        })
    }

    // ---- key agreement and encapsulation ------------------------------------

    pub(crate) fn derive_shared_secret(
        &self,
        ctx: &RequestContext,
        input: types::DeriveSharedSecretRequest,
    ) -> Result<types::DeriveSharedSecretResponse, ServiceError> {
        no_recipient(&input.recipient)?;
        let key = self.usable_key(
            ctx,
            &input.key_id,
            Access::crypto("DeriveSharedSecret")
                .condition("kms:KeyAgreementAlgorithm", vec![input.key_agreement_algorithm.clone()]),
        )?;
        require_usage(&key, "KEY_AGREEMENT", "DeriveSharedSecret")?;
        let Spec::Ecc(curve) = spec(&key) else {
            return Err(incompatible("KeyAgreementAlgorithm", &input.key_agreement_algorithm, &key));
        };
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let secret = crypto::derive_shared_secret(curve, &m.secret, &input.public_key)?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "DeriveSharedSecret");
        Ok(types::DeriveSharedSecretResponse {
            key_id: Some(key.arn.clone()),
            shared_secret: Some(secret),
            ciphertext_for_recipient: None,
            key_agreement_algorithm: Some(input.key_agreement_algorithm),
            key_origin: Some(key.origin),
        })
    }

    fn kem_key(&self, ctx: &RequestContext, action: &str, key_id: &str, alg: &str) -> Result<(Key, u16), ServiceError> {
        let key = self.usable_key(
            ctx,
            key_id,
            Access::crypto(action).condition("kms:EncapsulationAlgorithm", vec![alg.to_string()]),
        )?;
        require_usage(&key, "ENCAPSULATE_DECAPSULATE", action)?;
        let Spec::MlKem(level) = spec(&key) else { return Err(incompatible("EncapsulationAlgorithm", alg, &key)) };
        Ok((key, level))
    }

    pub(crate) fn encapsulate(
        &self,
        ctx: &RequestContext,
        input: types::EncapsulateRequest,
    ) -> Result<types::EncapsulateResponse, ServiceError> {
        let (key, level) = self.kem_key(ctx, "Encapsulate", &input.key_id, &input.encapsulation_algorithm)?;
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let (secret, ct) = crypto::encapsulate(level, &m.secret)?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "Encapsulate");
        Ok(types::EncapsulateResponse {
            key_id: Some(key.arn),
            shared_secret: Some(secret),
            shared_secret_ciphertext_blob: Some(ct),
            encapsulation_algorithm: Some(input.encapsulation_algorithm),
        })
    }

    pub(crate) fn decapsulate(
        &self,
        ctx: &RequestContext,
        input: types::DecapsulateRequest,
    ) -> Result<types::DecapsulateResponse, ServiceError> {
        let (key, level) = self.kem_key(ctx, "Decapsulate", &input.key_id, &input.encapsulation_algorithm)?;
        let m = key.current().ok_or_else(|| super::invalid_state(&key, "PendingImport"))?;
        let secret = crypto::decapsulate(level, &m.secret, &input.shared_secret_ciphertext_blob)
            .ok_or_else(invalid_ciphertext)?;
        check_dry_run(input.dry_run)?;
        self.record_use(ctx, &key.arn, "Decapsulate");
        Ok(types::DecapsulateResponse {
            key_id: Some(key.arn),
            shared_secret: Some(secret),
            encapsulation_algorithm: Some(input.encapsulation_algorithm),
        })
    }

    pub(crate) fn generate_random(
        &self,
        ctx: &RequestContext,
        input: types::GenerateRandomRequest,
    ) -> Result<types::GenerateRandomResponse, ServiceError> {
        no_recipient(&input.recipient)?;
        self.authorize_account(ctx, "GenerateRandom", ConditionContext::new())?;
        if let Some(id) = &input.custom_key_store_id {
            let st = self.lock();
            let store = st
                .custom_key_stores
                .get(id)
                .filter(|s| s.account == ctx.caller.account_id)
                .ok_or_else(|| errors::custom_key_store_not_found(format!("Custom key store {id} not found.")))?;
            if store.store_type != "AWS_CLOUDHSM" {
                return Err(errors::unsupported_operation("GenerateRandom is not supported for external key stores."));
            }
            if store.connection_state != "CONNECTED" {
                return Err(errors::custom_key_store_invalid_state(format!(
                    "The custom key store {id} is not connected."
                )));
            }
        }
        let n = input.number_of_bytes.ok_or_else(|| validation("NumberOfBytes is required."))?;
        Ok(types::GenerateRandomResponse {
            plaintext: Some(crypto::random_bytes(n as usize)),
            ciphertext_for_recipient: None,
        })
    }
}
