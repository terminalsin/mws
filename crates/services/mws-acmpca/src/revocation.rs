//! Certificate revocation: CRLs written where ACM PCA would publish them,
//! and an OCSP responder (RFC 6960) for CAs with OCSP enabled.
//!
//! ACM PCA writes CRLs to the S3 bucket named in the CA's CRL
//! configuration, at `crl/{ca-id}.crl` (or `{CustomPath}/{ca-id}.crl`), and
//! answers OCSP at `ocsp.acm-pca.{region}.amazonaws.com`. MWS keeps the
//! latest CRL with the CA and serves it, unsigned, at any URL whose path
//! ends in `/{ca-id}.crl`, so the distribution point in issued certificates
//! works once its host resolves to MWS (or with the path on the MWS
//! endpoint). OCSP requests are answered at any path when POSTed as
//! `application/ocsp-request`, or as a GET whose last path segment is the
//! base64 request.

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, RsaKeyPair};
use chrono::{DateTime, Duration, Utc};
use mws_core::ServiceError;
use rcgen::{
    CertificateParams, CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams, SerialNumber,
};
use x509_parser::prelude::*;

use crate::der;
use crate::generated::types;
use crate::state::Ca;
use crate::x509;

const DEFAULT_CRL_DAYS: i64 = 7;
/// OCSP responses are valid this long; ACM PCA uses a day.
const OCSP_VALIDITY_HOURS: i64 = 24;

pub fn ca_id(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

fn region(arn: &str) -> &str {
    arn.split(':').nth(3).unwrap_or("us-east-1")
}

pub fn crl_config(ca: &Ca) -> Option<&types::CrlConfiguration> {
    ca.revocation.as_ref()?.crl_configuration.as_ref().filter(|c| c.enabled)
}

pub fn ocsp_config(ca: &Ca) -> Option<&types::OcspConfiguration> {
    ca.revocation.as_ref()?.ocsp_configuration.as_ref().filter(|c| c.enabled)
}

/// The S3 key ACM PCA writes the CRL to.
pub fn crl_key(ca: &Ca) -> Option<String> {
    let c = crl_config(ca)?;
    let path = c.custom_path.as_deref().map(|p| p.trim_matches('/')).filter(|p| !p.is_empty()).unwrap_or("crl");
    Some(format!("{path}/{}.crl", ca_id(&ca.arn)))
}

/// The URL put in the CRL Distribution Points extension, if any.
pub fn crl_url(ca: &Ca) -> Option<String> {
    let c = crl_config(ca)?;
    if c.crl_distribution_point_extension_configuration.as_ref().is_some_and(|d| d.omit_extension) {
        return None;
    }
    let host = match (&c.custom_cname, &c.s3_bucket_name) {
        (Some(cname), _) => cname.clone(),
        (None, Some(bucket)) => format!("{bucket}.s3.{}.amazonaws.com", region(&ca.arn)),
        (None, None) => return None,
    };
    Some(format!("http://{host}/{}", crl_key(ca)?))
}

/// The OCSP responder URL put in the Authority Information Access extension.
pub fn ocsp_url(ca: &Ca) -> Option<String> {
    let c = ocsp_config(ca)?;
    Some(match &c.ocsp_custom_cname {
        Some(cname) => format!("http://{cname}"),
        None => format!("http://ocsp.acm-pca.{}.amazonaws.com", region(&ca.arn)),
    })
}

/// Check a revocation configuration the way ACM PCA does on Create/Update.
pub fn validate(config: &types::RevocationConfiguration) -> Result<(), ServiceError> {
    use crate::generated::errors;
    if let Some(c) = config.crl_configuration.as_ref().filter(|c| c.enabled) {
        if c.s3_bucket_name.is_none() {
            return Err(errors::invalid_args("S3 bucket name must be specified when the CRL is enabled."));
        }
        let omit = c.crl_distribution_point_extension_configuration.as_ref().is_some_and(|d| d.omit_extension);
        if omit && c.custom_cname.is_some() {
            return Err(errors::invalid_args(
                "CrlDistributionPointExtensionConfiguration.OmitExtension cannot be true when a custom CNAME is set.",
            ));
        }
        for cname in c.custom_cname.iter() {
            if cname.contains("://") {
                return Err(errors::invalid_args("CustomCname must not include a protocol prefix."));
            }
        }
    }
    if let Some(c) = config.ocsp_configuration.as_ref().filter(|c| c.enabled) {
        for cname in c.ocsp_custom_cname.iter() {
            if cname.contains("://") {
                return Err(errors::invalid_args("OcspCustomCname must not include a protocol prefix."));
            }
        }
    }
    Ok(())
}

fn reason(r: &str) -> RevocationReason {
    match r {
        "KEY_COMPROMISE" => RevocationReason::KeyCompromise,
        "CERTIFICATE_AUTHORITY_COMPROMISE" => RevocationReason::CaCompromise,
        "AFFILIATION_CHANGED" => RevocationReason::AffiliationChanged,
        "SUPERSEDED" => RevocationReason::Superseded,
        "CESSATION_OF_OPERATION" => RevocationReason::CessationOfOperation,
        "PRIVILEGE_WITHDRAWN" => RevocationReason::PrivilegeWithdrawn,
        "A_A_COMPROMISE" => RevocationReason::AaCompromise,
        _ => RevocationReason::Unspecified,
    }
}

fn to_offset(t: DateTime<Utc>) -> ::time::OffsetDateTime {
    ::time::OffsetDateTime::from_unix_timestamp(t.timestamp()).unwrap_or(::time::OffsetDateTime::UNIX_EPOCH)
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

/// Regenerate the CA's CRL if CRLs are enabled and it has a certificate.
/// Revoked certificates stay listed until they expire, and in one more CRL.
pub fn refresh_crl(ca: &mut Ca) -> Result<(), ServiceError> {
    let (Some(config), Some(cert_pem)) = (crl_config(ca), ca.cert_pem.clone()) else {
        ca.crl = None;
        return Ok(());
    };
    let days = config.expiration_in_days.map(i64::from).unwrap_or(DEFAULT_CRL_DAYS);
    let alg = x509::signature_algorithm(&ca.config.key_algorithm, &ca.config.signing_algorithm)?;
    let key = x509::key_for(&ca.key_der, alg)?;
    let issuer = CertificateParams::from_ca_cert_pem(&cert_pem)
        .and_then(|p| p.self_signed(&key))
        .map_err(|e| ServiceError::internal(format!("loading CA certificate: {e}")))?;
    let now = Utc::now();
    let previous_crl_end = ca.crl.as_ref().map(|c| c.this_update).unwrap_or(now);
    let revoked_certs = ca
        .certs
        .iter()
        .filter_map(|(serial, cert)| {
            let (r, at) = cert.revoked.as_ref()?;
            // Drop an expired certificate once one CRL issued after its expiry has listed it.
            if cert.not_after < previous_crl_end && cert.not_after < now {
                return None;
            }
            Some(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&hex_bytes(serial)),
                revocation_time: to_offset(*at),
                reason_code: Some(reason(r)),
                invalidity_date: None,
            })
        })
        .collect();
    ca.crl_number += 1;
    let params = CertificateRevocationListParams {
        this_update: to_offset(now),
        next_update: to_offset(now + Duration::days(days)),
        crl_number: SerialNumber::from_slice(der::unsigned_integer(&ca.crl_number.to_be_bytes())),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = params.signed_by(&issuer, &key).map_err(|e| ServiceError::internal(format!("signing CRL: {e}")))?;
    ca.crl =
        Some(crate::state::Crl { der: crl.der().to_vec(), this_update: now, next_update: now + Duration::days(days) });
    Ok(())
}

// ---------------------------------------------------------------------------
// OCSP

/// OCSPResponseStatus values.
pub mod status {
    pub const MALFORMED_REQUEST: u8 = 1;
    pub const INTERNAL_ERROR: u8 = 2;
    pub const UNAUTHORIZED: u8 = 6;
}

/// A parsed OCSP request: each CertID (raw DER and its parts) and the nonce.
pub struct OcspRequest<'a> {
    pub cert_ids: Vec<CertId<'a>>,
    /// The whole nonce Extension, echoed back.
    pub nonce: Option<&'a [u8]>,
}

pub struct CertId<'a> {
    pub raw: &'a [u8],
    pub hash_oid: &'a [u8],
    pub name_hash: &'a [u8],
    pub key_hash: &'a [u8],
    pub serial: String,
}

const NONCE_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2];

pub fn parse_request(bytes: &[u8]) -> Option<OcspRequest<'_>> {
    let (req, rest) = der::read(bytes)?;
    if req.tag != der::SEQUENCE || !rest.is_empty() {
        return None;
    }
    let (tbs, _) = der::read(req.content)?;
    let parts = der::children(tbs.content)?;
    let list = parts.iter().find(|e| e.tag == der::SEQUENCE)?;
    let nonce_oid = der::oid(NONCE_OID);
    let nonce = parts.iter().find(|e| e.tag == der::ctx(2)).and_then(|exts| {
        let (seq, _) = der::read(exts.content)?;
        der::children(seq.content)?
            .into_iter()
            .find(|ext| der::read(ext.content).is_some_and(|(o, _)| o.raw == nonce_oid.as_slice()))
            .map(|ext| ext.raw)
    });
    let mut cert_ids = Vec::new();
    for single in der::children(list.content)? {
        let (cert_id, _) = der::read(single.content)?;
        let fields = der::children(cert_id.content)?;
        let [alg, name_hash, key_hash, serial] = fields.as_slice() else { return None };
        let (hash_oid, _) = der::read(alg.content)?;
        if serial.tag != der::INTEGER {
            return None;
        }
        cert_ids.push(CertId {
            raw: cert_id.raw,
            hash_oid: hash_oid.raw,
            name_hash: name_hash.content,
            key_hash: key_hash.content,
            serial: der::unsigned_integer(serial.content).iter().map(|b| format!("{b:02x}")).collect(),
        });
    }
    if cert_ids.is_empty() {
        return None;
    }
    Some(OcspRequest { cert_ids, nonce })
}

fn hash_for(oid_der: &[u8]) -> Option<&'static digest::Algorithm> {
    let algs: [(&[u64], &'static digest::Algorithm); 4] = [
        (&[1, 3, 14, 3, 2, 26], &digest::SHA1_FOR_LEGACY_USE_ONLY),
        (&[2, 16, 840, 1, 101, 3, 4, 2, 1], &digest::SHA256),
        (&[2, 16, 840, 1, 101, 3, 4, 2, 2], &digest::SHA384),
        (&[2, 16, 840, 1, 101, 3, 4, 2, 3], &digest::SHA512),
    ];
    algs.into_iter().find(|(arcs, _)| der::oid(arcs) == oid_der).map(|(_, a)| a)
}

/// The issuer name and key bytes a CertID hashes, from the CA certificate.
pub struct IssuerIds {
    pub name_der: Vec<u8>,
    pub key_bits: Vec<u8>,
}

pub fn issuer_ids(cert_pem: &str) -> Option<IssuerIds> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;
    Some(IssuerIds {
        name_der: cert.subject().as_raw().to_vec(),
        key_bits: cert.public_key().subject_public_key.data.to_vec(),
    })
}

/// Whether `id` names a certificate issued by the CA with these ids.
pub fn matches(id: &CertId<'_>, issuer: &IssuerIds) -> bool {
    let Some(alg) = hash_for(id.hash_oid) else { return false };
    digest::digest(alg, &issuer.name_der).as_ref() == id.name_hash
        && digest::digest(alg, &issuer.key_bits).as_ref() == id.key_hash
}

pub fn error_response(status: u8) -> Vec<u8> {
    der::seq(&[&der::tlv(der::ENUMERATED, &[status])])
}

fn reason_code(r: &str) -> u8 {
    reason(r) as u8
}

/// A signed, successful OCSP response from `ca` for `request`.
pub fn respond(ca: &Ca, request: &OcspRequest<'_>, issuer: &IssuerIds) -> Result<Vec<u8>, ServiceError> {
    let now = Utc::now();
    let next = now + Duration::hours(OCSP_VALIDITY_HOURS);
    let mut singles = Vec::new();
    for id in &request.cert_ids {
        let status = if !matches(id, issuer) {
            der::tlv(der::ctx_prim(2), &[])
        } else {
            match ca.certs.get(&id.serial) {
                None => der::tlv(der::ctx_prim(2), &[]),
                Some(cert) => match &cert.revoked {
                    None => der::tlv(der::ctx_prim(0), &[]),
                    Some((r, at)) => {
                        let reason = der::tlv(der::ctx(0), &der::tlv(der::ENUMERATED, &[reason_code(r)]));
                        der::tlv(der::ctx(1), &[der::generalized_time(*at), reason].concat())
                    }
                },
            }
        };
        let next_update = der::tlv(der::ctx(0), &der::generalized_time(next));
        singles.push(der::seq(&[id.raw, &status, &der::generalized_time(now), &next_update]));
    }
    let key_hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &issuer.key_bits);
    let responder_id = der::tlv(der::ctx(2), &der::tlv(der::OCTET_STRING, key_hash.as_ref()));
    let mut tbs_parts = vec![responder_id, der::generalized_time(now), der::tlv(der::SEQUENCE, &singles.concat())];
    if let Some(nonce) = request.nonce {
        tbs_parts.push(der::tlv(der::ctx(1), &der::tlv(der::SEQUENCE, nonce)));
    }
    let tbs = der::tlv(der::SEQUENCE, &tbs_parts.concat());
    let (alg_id, sig) = sign(ca, &tbs)?;
    let mut bits = vec![0u8];
    bits.extend(sig);
    let basic = der::seq(&[&tbs, &alg_id, &der::tlv(der::BIT_STRING, &bits)]);
    let response_bytes = der::seq(&[&der::oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]), &der::tlv(der::OCTET_STRING, &basic)]);
    Ok(der::seq(&[&der::tlv(der::ENUMERATED, &[0]), &der::tlv(der::ctx(0), &response_bytes)]))
}

/// Sign with the CA key, returning the AlgorithmIdentifier and signature.
fn sign(ca: &Ca, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ServiceError> {
    let fail = |e: &dyn std::fmt::Display| ServiceError::internal(format!("OCSP signing failed: {e}"));
    let rng = SystemRandom::new();
    let rsa = |oid: u64, enc: &'static dyn signature::RsaEncoding| -> Result<(Vec<u8>, Vec<u8>), ServiceError> {
        let key = RsaKeyPair::from_pkcs8(&ca.key_der).map_err(|e| fail(&e))?;
        let mut sig = vec![0; key.public_modulus_len()];
        key.sign(enc, &rng, message, &mut sig).map_err(|e| fail(&e))?;
        let alg = der::seq(&[&der::oid(&[1, 2, 840, 113549, 1, 1, oid]), &der::tlv(der::NULL, &[])]);
        Ok((alg, sig))
    };
    let ec = |oid: u64, alg: &'static signature::EcdsaSigningAlgorithm| -> Result<(Vec<u8>, Vec<u8>), ServiceError> {
        let key = EcdsaKeyPair::from_pkcs8(alg, &ca.key_der).map_err(|e| fail(&e))?;
        let sig = key.sign(&rng, message).map_err(|e| fail(&e))?;
        Ok((der::seq(&[&der::oid(&[1, 2, 840, 10045, 4, 3, oid])]), sig.as_ref().to_vec()))
    };
    match ca.config.signing_algorithm.as_str() {
        "SHA256WITHRSA" => rsa(11, &signature::RSA_PKCS1_SHA256),
        "SHA384WITHRSA" => rsa(12, &signature::RSA_PKCS1_SHA384),
        "SHA512WITHRSA" => rsa(13, &signature::RSA_PKCS1_SHA512),
        "SHA256WITHECDSA" => ec(2, &signature::ECDSA_P256_SHA256_ASN1_SIGNING),
        "SHA384WITHECDSA" => ec(3, &signature::ECDSA_P384_SHA384_ASN1_SIGNING),
        "SHA512WITHECDSA" => ec(4, &signature::ECDSA_P521_SHA512_ASN1_SIGNING),
        other => Err(ServiceError::internal(format!("OCSP signing is not supported for {other}"))),
    }
}
