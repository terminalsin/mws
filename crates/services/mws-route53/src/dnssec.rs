//! DNSSEC: key-signing keys and zone signing status.
//!
//! Route 53 keeps KSKs in KMS: the KMS key must be a customer managed,
//! enabled `ECC_NIST_P256` signing key in us-east-1 whose key policy lets
//! `dnssec-route53.amazonaws.com` describe it, read its public key and
//! sign. The DNSKEY and DS records (key tag, digest) come from that key's
//! public key. A `Route53` built without KMS generates the key pair itself.

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::Engine;
use chrono::Utc;
use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::{KeySigningKey, Zone};
use crate::{arn, strip_id, Route53};

const MAX_KSKS: usize = 2;
const KSK_FLAGS: u16 = 257;
const ALGORITHM: u8 = 13; // ECDSAP256SHA256

fn no_such_ksk(name: &str) -> ServiceError {
    errors::no_such_key_signing_key(format!("The specified key-signing key ({name}) doesn't exist."))
}

fn check_name(name: &str) -> Result<(), ServiceError> {
    let ok = (3..=128).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        return Err(errors::invalid_key_signing_key_name(format!(
            "The key-signing key (KSK) name {name} is not valid. It must be 3-128 characters: letters, digits and underscores."
        )));
    }
    Ok(())
}

fn check_kms_arn(kms: &str) -> Result<(), ServiceError> {
    let parts: Vec<&str> = kms.split(':').collect();
    let ok = parts.len() == 6
        && parts[0] == "arn"
        && parts[2] == "kms"
        && parts[3] == "us-east-1"
        && parts[4].len() == 12
        && (parts[5].starts_with("key/") || parts[5].starts_with("alias/"));
    if !ok {
        return Err(invalid_kms_arn());
    }
    Ok(())
}

/// The owner name in canonical DNS wire format (lowercase labels).
fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend(label.to_ascii_lowercase().as_bytes());
    }
    out.push(0);
    out
}

/// RFC 4034 Appendix B key tag.
fn key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, b) in rdata.iter().enumerate() {
        ac += if i % 2 == 0 { (*b as u32) << 8 } else { *b as u32 };
    }
    ac += (ac >> 16) & 0xffff;
    (ac & 0xffff) as u16
}

fn invalid_kms_arn() -> ServiceError {
    errors::invalid_kms_arn("The KeyManagementServiceArn that you specified isn't valid to use with DNSSEC signing.")
}

/// A standalone P-256 public point, when no KMS is attached.
fn generated_point() -> Result<Vec<u8>, ServiceError> {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .map_err(|_| ServiceError::internal("key generation failed"))?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
        .map_err(|_| ServiceError::internal("key generation failed"))?;
    Ok(pair.public_key().as_ref().to_vec())
}

fn new_ksk(
    zone: &Zone,
    name: &str,
    kms: &str,
    status: &str,
    point: &[u8],
) -> Result<types::KeySigningKey, ServiceError> {
    // Uncompressed point without its 0x04 prefix: RFC 6605.
    let public = point[1..].to_vec();
    let mut rdata = KSK_FLAGS.to_be_bytes().to_vec();
    rdata.extend([3, ALGORITHM]);
    rdata.extend(&public);
    let tag = key_tag(&rdata);
    let digest_value = hex::encode_upper(digest::digest(&digest::SHA256, &[wire_name(&zone.name), rdata].concat()));
    let b64 = base64::engine::general_purpose::STANDARD.encode(&public);
    let now = Utc::now();
    Ok(types::KeySigningKey {
        name: Some(name.to_string()),
        kms_arn: Some(kms.to_string()),
        flag: KSK_FLAGS as i32,
        signing_algorithm_mnemonic: Some("ECDSAP256SHA256".into()),
        signing_algorithm_type: ALGORITHM as i32,
        digest_algorithm_mnemonic: Some("SHA-256".into()),
        digest_algorithm_type: 2,
        key_tag: tag as i32,
        ds_record: Some(format!("{tag} {ALGORITHM} 2 {digest_value}")),
        digest_value: Some(digest_value),
        dnskey_record: Some(format!("{KSK_FLAGS} 3 {ALGORITHM} {b64}")),
        public_key: Some(b64),
        status: Some(status.to_string()),
        status_message: None,
        created_date: Some(now),
        last_modified_date: Some(now),
    })
}

fn set_status(ksk: &mut KeySigningKey, status: &str) {
    ksk.key.status = Some(status.into());
    ksk.key.last_modified_date = Some(Utc::now());
}

fn is_active(k: &KeySigningKey) -> bool {
    k.key.status.as_deref() == Some("ACTIVE")
}

impl Route53 {
    /// The public point of the KMS key behind a new KSK, after checking the
    /// key is one Route 53 can use.
    fn ksk_public_point(&self, ctx: &RequestContext, zone_arn: &str, kms_arn: &str) -> Result<Vec<u8>, ServiceError> {
        let Some(kms) = &self.kms else { return generated_point() };
        let mut cond = mws_core::ConditionContext::new();
        cond.insert("aws:SourceAccount".into(), vec![ctx.caller.account_id.clone()]);
        cond.insert("aws:SourceArn".into(), vec![zone_arn.to_string()]);
        let key = kms
            .key_for_service(
                kms_arn,
                "dnssec-route53.amazonaws.com",
                &["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
                &cond,
            )
            .map_err(|_| invalid_kms_arn())?;
        let usable = key.key_spec == "ECC_NIST_P256"
            && key.key_usage == "SIGN_VERIFY"
            && key.key_state == "Enabled"
            && key.key_manager == "CUSTOMER";
        key.ec_point.filter(|_| usable).ok_or_else(invalid_kms_arn)
    }

    pub(crate) fn create_key_signing_key(
        &self,
        ctx: &RequestContext,
        input: types::CreateKeySigningKeyRequest,
    ) -> Result<types::CreateKeySigningKeyResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "CreateKeySigningKey", &arn(ctx, "hostedzone", &zone_id))?;
        check_name(&input.name)?;
        check_kms_arn(&input.key_management_service_arn)?;
        if !matches!(input.status.as_str(), "ACTIVE" | "INACTIVE") {
            return Err(errors::invalid_key_signing_key_status(
                "The key-signing key (KSK) status isn't valid or another KSK has the status INTERNAL_FAILURE.",
            ));
        }
        let point = self.ksk_public_point(ctx, &arn(ctx, "hostedzone", &zone_id), &input.key_management_service_arn)?;
        let mut st = self.lock();
        let zone = st.zone(&zone_id)?;
        if zone.private {
            return Err(errors::invalid_input(
                "Invalid input: DNSSEC signing is not supported for private hosted zones.",
            ));
        }
        if zone.ksks.contains_key(&input.name)
            || zone.ksks.values().any(|k| k.caller_reference == input.caller_reference)
        {
            return Err(errors::key_signing_key_already_exists(
                "You've already created a key-signing key (KSK) with this name or with the CallerReference.",
            ));
        }
        if zone.ksks.len() >= MAX_KSKS {
            return Err(errors::too_many_key_signing_keys(
                "You've reached the limit for the number of key-signing keys (KSKs). Remove at least one KSK, and then try again.",
            ));
        }
        let key = new_ksk(zone, &input.name, &input.key_management_service_arn, &input.status, &point)?;
        st.zone_mut(&zone_id)?
            .ksks
            .insert(input.name.clone(), KeySigningKey { key: key.clone(), caller_reference: input.caller_reference });
        Ok(types::CreateKeySigningKeyResponse {
            change_info: st.new_change(None),
            key_signing_key: key,
            location: format!("https://route53.amazonaws.com/2013-04-01/keysigningkey/{zone_id}/{}", input.name),
        })
    }

    fn ksk_change(
        &self,
        ctx: &RequestContext,
        action: &str,
        zone_id: &str,
        name: &str,
        apply: impl FnOnce(&mut Zone) -> Result<(), ServiceError>,
    ) -> Result<types::ChangeInfo, ServiceError> {
        let zone_id = strip_id(zone_id).to_string();
        self.authorize(ctx, action, &arn(ctx, "hostedzone", &zone_id))?;
        let mut st = self.lock();
        let zone = st.zone_mut(&zone_id)?;
        if !zone.ksks.contains_key(name) {
            return Err(no_such_ksk(name));
        }
        apply(zone)?;
        Ok(st.new_change(None))
    }

    pub(crate) fn activate_key_signing_key(
        &self,
        ctx: &RequestContext,
        input: types::ActivateKeySigningKeyRequest,
    ) -> Result<types::ActivateKeySigningKeyResponse, ServiceError> {
        let name = input.name.clone();
        let change_info = self.ksk_change(ctx, "ActivateKeySigningKey", &input.hosted_zone_id, &input.name, |z| {
            let k = z.ksks.get_mut(&name).expect("checked");
            if k.key.status.as_deref() == Some("DELETING") {
                return Err(errors::invalid_key_signing_key_status("The key-signing key (KSK) is being deleted."));
            }
            set_status(k, "ACTIVE");
            Ok(())
        })?;
        Ok(types::ActivateKeySigningKeyResponse { change_info })
    }

    pub(crate) fn deactivate_key_signing_key(
        &self,
        ctx: &RequestContext,
        input: types::DeactivateKeySigningKeyRequest,
    ) -> Result<types::DeactivateKeySigningKeyResponse, ServiceError> {
        let name = input.name.clone();
        let change_info = self.ksk_change(ctx, "DeactivateKeySigningKey", &input.hosted_zone_id, &input.name, |z| {
            let others_active = z.ksks.iter().any(|(n, k)| *n != name && is_active(k));
            if z.dnssec_signing && !others_active && is_active(&z.ksks[&name]) {
                return Err(errors::key_signing_key_in_use(
                    "The key-signing key (KSK) that you specified can't be deactivated because it's the only KSK for a currently-enabled DNSSEC. Disable DNSSEC signing, or add or enable another KSK.",
                ));
            }
            set_status(z.ksks.get_mut(&name).expect("checked"), "INACTIVE");
            Ok(())
        })?;
        Ok(types::DeactivateKeySigningKeyResponse { change_info })
    }

    pub(crate) fn delete_key_signing_key(
        &self,
        ctx: &RequestContext,
        input: types::DeleteKeySigningKeyRequest,
    ) -> Result<types::DeleteKeySigningKeyResponse, ServiceError> {
        let name = input.name.clone();
        let change_info = self.ksk_change(ctx, "DeleteKeySigningKey", &input.hosted_zone_id, &input.name, |z| {
            if is_active(&z.ksks[&name]) {
                return Err(errors::invalid_key_signing_key_status(
                    "The key-signing key (KSK) status isn't valid or another KSK has the status INTERNAL_FAILURE.",
                ));
            }
            z.ksks.remove(&name);
            Ok(())
        })?;
        Ok(types::DeleteKeySigningKeyResponse { change_info })
    }

    pub(crate) fn enable_hosted_zone_dnssec(
        &self,
        ctx: &RequestContext,
        input: types::EnableHostedZoneDNSSECRequest,
    ) -> Result<types::EnableHostedZoneDNSSECResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "EnableHostedZoneDNSSEC", &arn(ctx, "hostedzone", &zone_id))?;
        let mut st = self.lock();
        let zone = st.zone_mut(&zone_id)?;
        if zone.private {
            return Err(errors::invalid_input(
                "Invalid input: DNSSEC signing is not supported for private hosted zones.",
            ));
        }
        if !zone.ksks.values().any(is_active) {
            return Err(errors::key_signing_key_with_active_status_not_found(
                "A key-signing key (KSK) with ACTIVE status wasn't found.",
            ));
        }
        zone.dnssec_signing = true;
        Ok(types::EnableHostedZoneDNSSECResponse { change_info: st.new_change(None) })
    }

    pub(crate) fn disable_hosted_zone_dnssec(
        &self,
        ctx: &RequestContext,
        input: types::DisableHostedZoneDNSSECRequest,
    ) -> Result<types::DisableHostedZoneDNSSECResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "DisableHostedZoneDNSSEC", &arn(ctx, "hostedzone", &zone_id))?;
        let mut st = self.lock();
        let zone = st.zone_mut(&zone_id)?;
        if zone.ksks.is_empty() && !zone.dnssec_signing {
            return Err(errors::dnssec_not_found(format!(
                "The hosted zone {zone_id} doesn't have any DNSSEC resources."
            )));
        }
        zone.dnssec_signing = false;
        Ok(types::DisableHostedZoneDNSSECResponse { change_info: st.new_change(None) })
    }

    pub(crate) fn get_dnssec(
        &self,
        ctx: &RequestContext,
        input: types::GetDNSSECRequest,
    ) -> Result<types::GetDNSSECResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "GetDNSSEC", &arn(ctx, "hostedzone", &zone_id))?;
        let st = self.lock();
        let zone = st.zone(&zone_id)?;
        Ok(types::GetDNSSECResponse {
            status: types::DNSSECStatus {
                serve_signature: Some(if zone.dnssec_signing { "SIGNING" } else { "NOT_SIGNING" }.into()),
                status_message: None,
            },
            key_signing_keys: zone.ksks.values().map(|k| k.key.clone()).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_tag_and_wire_name() {
        assert_eq!(key_tag(&[0x01, 0x01, 0x03, 0x0d]), 0x0101 + 0x030d);
        assert_eq!(wire_name("Example.COM."), b"\x07example\x03com\x00".to_vec());
    }
}
