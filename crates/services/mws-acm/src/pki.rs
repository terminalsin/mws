//! Real X.509 for ACM: key pairs, CSRs, the public CA that signs
//! Amazon-issued certificates, certificate inspection, private key
//! matching for imports, and passphrase-encrypted PKCS#8 for exports.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::ServiceError;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, RsaKeySize, SanType, SerialNumber, SignatureAlgorithm, SubjectPublicKeyInfo,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

fn internal(what: &str, e: impl std::fmt::Display) -> ServiceError {
    ServiceError::internal(format!("{what}: {e}"))
}

/// The rcgen signing algorithm for an ACM key algorithm.
pub fn signing_alg(key_algorithm: &str) -> &'static SignatureAlgorithm {
    match key_algorithm {
        "EC_prime256v1" => &rcgen::PKCS_ECDSA_P256_SHA256,
        "EC_secp384r1" => &rcgen::PKCS_ECDSA_P384_SHA384,
        "EC_secp521r1" => &rcgen::PKCS_ECDSA_P521_SHA512,
        _ => &rcgen::PKCS_RSA_SHA256,
    }
}

/// A new key pair for `key_algorithm`, as PKCS#8 DER.
pub fn generate_key(key_algorithm: &str) -> Result<Vec<u8>, ServiceError> {
    let alg = signing_alg(key_algorithm);
    let key = match key_algorithm {
        "RSA_3072" => KeyPair::generate_rsa_for(alg, RsaKeySize::_3072),
        "RSA_4096" => KeyPair::generate_rsa_for(alg, RsaKeySize::_4096),
        k if k.starts_with("RSA") => KeyPair::generate_rsa_for(alg, RsaKeySize::_2048),
        _ => KeyPair::generate_for(alg),
    }
    .map_err(|e| internal("key generation failed", e))?;
    Ok(key.serialize_der())
}

/// Load a PKCS#8 key this service generated.
pub fn load_key(pkcs8: &[u8], key_algorithm: &str) -> Result<KeyPair, ServiceError> {
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec()));
    KeyPair::from_der_and_sign_algo(&der, signing_alg(key_algorithm)).map_err(|e| internal("loading key", e))
}

fn dns_san(name: &str) -> Option<SanType> {
    name.to_string().try_into().ok().map(SanType::DnsName)
}

/// A CSR for `domain` (the subject common name) and `names` (the SANs).
pub fn csr_pem(key: &KeyPair, domain: &str, names: &[String]) -> Result<String, ServiceError> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;
    params.subject_alt_names = names.iter().filter_map(|n| dns_san(n)).collect();
    params.serialize_request(key).and_then(|c| c.pem()).map_err(|e| internal("building CSR", e))
}

fn to_offset(t: DateTime<Utc>) -> ::time::OffsetDateTime {
    ::time::OffsetDateTime::from_unix_timestamp(t.timestamp()).unwrap_or(::time::OffsetDateTime::UNIX_EPOCH)
}

/// A random positive 16-byte serial number.
pub fn serial() -> [u8; 16] {
    let mut s: [u8; 16] = rand::random();
    s[0] &= 0x7f;
    if s[0] == 0 {
        s[0] = 1;
    }
    s
}

/// One of the issuing CAs behind Amazon-issued (public) certificates. MWS
/// makes its own on first use: a root, `MWS Root CA 1`, and intermediates
/// named like Amazon's, so `Issuer` reads `Amazon` as it does in AWS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuingCa {
    pub key_algorithm: String,
    pub key_der: Vec<u8>,
    pub cert_pem: String,
    /// The root above it.
    pub root_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCa {
    pub key_der: Vec<u8>,
    pub cert_pem: String,
}

/// The intermediate that signs certificates with keys of `key_algorithm`.
pub fn intermediate_kind(key_algorithm: &str) -> &'static str {
    match key_algorithm {
        "EC_prime256v1" => "EC_prime256v1",
        "EC_secp384r1" | "EC_secp521r1" => "EC_secp384r1",
        _ => "RSA_2048",
    }
}

fn ca_params(dn: &[(DnType, &str)], not_before: DateTime<Utc>, years: i64) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut name = DistinguishedName::new();
    for (ty, v) in dn {
        name.push(ty.clone(), *v);
    }
    p.distinguished_name = name;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = to_offset(not_before);
    p.not_after = to_offset(not_before + chrono::Duration::days(365 * years));
    p.serial_number = Some(SerialNumber::from_slice(&serial()));
    p.key_identifier_method = KeyIdMethod::Sha256;
    p
}

pub fn new_root(now: DateTime<Utc>) -> Result<RootCa, ServiceError> {
    let key_der = generate_key("RSA_2048")?;
    let key = load_key(&key_der, "RSA_2048")?;
    let params = ca_params(
        &[(DnType::CountryName, "US"), (DnType::OrganizationName, "MWS"), (DnType::CommonName, "MWS Root CA 1")],
        now - chrono::Duration::days(1),
        25,
    );
    let cert = params.self_signed(&key).map_err(|e| internal("signing root", e))?;
    Ok(RootCa { key_der, cert_pem: cert.pem() })
}

fn issuer_cert(pem: &str, key: &KeyPair) -> Result<rcgen::Certificate, ServiceError> {
    CertificateParams::from_ca_cert_pem(pem)
        .and_then(|p| p.self_signed(key))
        .map_err(|e| internal("loading CA certificate", e))
}

pub fn new_intermediate(root: &RootCa, kind: &str, now: DateTime<Utc>) -> Result<IssuingCa, ServiceError> {
    let cn = match kind {
        "EC_prime256v1" => "Amazon ECDSA 256 M01",
        "EC_secp384r1" => "Amazon ECDSA 384 M01",
        _ => "Amazon RSA 2048 M01",
    };
    let key_der = generate_key(kind)?;
    let key = load_key(&key_der, kind)?;
    let root_key = load_key(&root.key_der, "RSA_2048")?;
    let root_cert = issuer_cert(&root.cert_pem, &root_key)?;
    let mut params = ca_params(
        &[(DnType::CountryName, "US"), (DnType::OrganizationName, "Amazon"), (DnType::CommonName, cn)],
        now - chrono::Duration::days(1),
        10,
    );
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, &root_cert, &root_key).map_err(|e| internal("signing intermediate", e))?;
    Ok(IssuingCa { key_algorithm: kind.into(), key_der, cert_pem: cert.pem(), root_pem: root.cert_pem.clone() })
}

/// What goes into an Amazon-issued end-entity certificate.
pub struct LeafRequest<'a> {
    /// The subject common name.
    pub common_name: &'a str,
    pub names: &'a [String],
    /// The subject public key, as SubjectPublicKeyInfo DER.
    pub spki_der: &'a [u8],
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

/// Sign a TLS server certificate with `ca`.
pub fn issue_leaf(ca: &IssuingCa, req: &LeafRequest<'_>) -> Result<String, ServiceError> {
    let key = load_key(&ca.key_der, &ca.key_algorithm)?;
    let issuer = issuer_cert(&ca.cert_pem, &key)?;
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, req.common_name);
    p.distinguished_name = dn;
    p.subject_alt_names = req.names.iter().filter_map(|n| dns_san(n)).collect();
    p.not_before = to_offset(req.not_before);
    p.not_after = to_offset(req.not_after);
    p.serial_number = Some(SerialNumber::from_slice(&serial()));
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = true;
    p.key_identifier_method = KeyIdMethod::Sha256;
    let spki = SubjectPublicKeyInfo::from_der(req.spki_der).map_err(|e| internal("reading public key", e))?;
    p.signed_by(&spki, &issuer, &key).map(|c| c.pem()).map_err(|e| internal("signing certificate", e))
}

/// The SubjectPublicKeyInfo of a key pair.
pub fn spki_of(key: &KeyPair) -> Vec<u8> {
    key.public_key_der()
}

/// Every PEM block in `input` with label `label`, as DER.
pub fn pem_blocks(input: &[u8], label: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for pem in Pem::iter_from_buffer(input) {
        match pem {
            Ok(p) if p.label == label => out.push(p.contents),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    out
}

/// DER as PEM with 64-character lines.
pub fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The first certificate in `pem`, as DER.
pub fn first_cert_der(pem: &str) -> Option<Vec<u8>> {
    pem_blocks(pem.as_bytes(), "CERTIFICATE").into_iter().next()
}

/// What ACM shows about a certificate.
#[derive(Debug, Clone, Default)]
pub struct CertInfo {
    /// Colon-separated lowercase hex.
    pub serial: String,
    /// RFC 2253 style, most significant first as ACM shows it (`CN=...`).
    pub subject: String,
    pub subject_cn: Option<String>,
    /// The issuer's organization, else its common name.
    pub issuer: String,
    pub issuer_dn: Dn,
    pub subject_dn: Dn,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature_algorithm: String,
    /// `RSA_2048`, `EC_prime256v1`, ...
    pub key_algorithm: String,
    pub key_usages: Vec<String>,
    /// `(name, oid)`.
    pub extended_key_usages: Vec<(String, String)>,
    pub dns_names: Vec<String>,
    pub sans: Vec<GeneralNameInfo>,
    pub spki_der: Vec<u8>,
}

/// One subject alternative name.
#[derive(Debug, Clone)]
pub enum GeneralNameInfo {
    Dns(String),
    Ip(String),
    Email(String),
    Uri(String),
    RegisteredId(String),
    Directory(Box<Dn>),
    Other(String, String),
}

/// A distinguished name's attributes, as `X509Attributes` shows them.
#[derive(Debug, Clone, Default)]
pub struct Dn {
    pub common_name: Option<String>,
    pub country: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub locality: Option<String>,
    pub state: Option<String>,
    pub serial_number: Option<String>,
    pub title: Option<String>,
    pub surname: Option<String>,
    pub given_name: Option<String>,
    pub initials: Option<String>,
    pub pseudonym: Option<String>,
    pub generation_qualifier: Option<String>,
    pub distinguished_name_qualifier: Option<String>,
    pub domain_components: Vec<String>,
    pub custom: Vec<(String, String)>,
}

fn dn_info(name: &X509Name<'_>) -> Dn {
    let mut dn = Dn::default();
    for attr in name.iter_attributes() {
        let Ok(value) = attr.as_str().map(str::to_string) else { continue };
        let oid = attr.attr_type().to_id_string();
        let slot = match oid.as_str() {
            "2.5.4.3" => &mut dn.common_name,
            "2.5.4.6" => &mut dn.country,
            "2.5.4.10" => &mut dn.organization,
            "2.5.4.11" => &mut dn.organizational_unit,
            "2.5.4.7" => &mut dn.locality,
            "2.5.4.8" => &mut dn.state,
            "2.5.4.5" => &mut dn.serial_number,
            "2.5.4.12" => &mut dn.title,
            "2.5.4.4" => &mut dn.surname,
            "2.5.4.42" => &mut dn.given_name,
            "2.5.4.43" => &mut dn.initials,
            "2.5.4.65" => &mut dn.pseudonym,
            "2.5.4.44" => &mut dn.generation_qualifier,
            "2.5.4.46" => &mut dn.distinguished_name_qualifier,
            "0.9.2342.19200300.100.1.25" => {
                dn.domain_components.push(value);
                continue;
            }
            _ => {
                dn.custom.push((oid, value));
                continue;
            }
        };
        *slot = Some(value);
    }
    dn
}

/// `CN=a,O=b` in the order the attributes appear, most specific first.
fn dn_string(name: &X509Name<'_>) -> String {
    let mut parts = Vec::new();
    for rdn in name.iter().collect::<Vec<_>>().into_iter().rev() {
        for attr in rdn.iter() {
            let key = match attr.attr_type().to_id_string().as_str() {
                "2.5.4.3" => "CN".to_string(),
                "2.5.4.6" => "C".to_string(),
                "2.5.4.10" => "O".to_string(),
                "2.5.4.11" => "OU".to_string(),
                "2.5.4.7" => "L".to_string(),
                "2.5.4.8" => "ST".to_string(),
                "0.9.2342.19200300.100.1.25" => "DC".to_string(),
                other => other.to_string(),
            };
            parts.push(format!("{key}={}", attr.as_str().unwrap_or_default()));
        }
    }
    parts.join(",")
}

fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA256WITHRSA",
        "1.2.840.113549.1.1.12" => "SHA384WITHRSA",
        "1.2.840.113549.1.1.13" => "SHA512WITHRSA",
        "1.2.840.113549.1.1.5" => "SHA1WITHRSA",
        "1.2.840.113549.1.1.4" => "MD5WITHRSA",
        "1.2.840.10045.4.3.2" => "SHA256WITHECDSA",
        "1.2.840.10045.4.3.3" => "SHA384WITHECDSA",
        "1.2.840.10045.4.3.4" => "SHA512WITHECDSA",
        "1.2.840.113549.1.1.10" => "SSASSA-PSS",
        other => other,
    }
    .to_string()
}

fn eku_name(oid: &str) -> &'static str {
    match oid {
        "1.3.6.1.5.5.7.3.1" => "TLS_WEB_SERVER_AUTHENTICATION",
        "1.3.6.1.5.5.7.3.2" => "TLS_WEB_CLIENT_AUTHENTICATION",
        "1.3.6.1.5.5.7.3.3" => "CODE_SIGNING",
        "1.3.6.1.5.5.7.3.4" => "EMAIL_PROTECTION",
        "1.3.6.1.5.5.7.3.8" => "TIME_STAMPING",
        "1.3.6.1.5.5.7.3.9" => "OCSP_SIGNING",
        "1.3.6.1.5.5.7.3.5" => "IPSEC_END_SYSTEM",
        "1.3.6.1.5.5.7.3.6" => "IPSEC_TUNNEL",
        "1.3.6.1.5.5.7.3.7" => "IPSEC_USER",
        "2.5.29.37.0" => "ANY",
        _ => "CUSTOM",
    }
}

fn key_algorithm_of(spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> String {
    match spki.parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => format!("RSA_{}", rsa.key_size()),
        Ok(x509_parser::public_key::PublicKey::EC(_)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string())
                .unwrap_or_default();
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => "EC_prime256v1",
                "1.3.132.0.34" => "EC_secp384r1",
                "1.3.132.0.35" => "EC_secp521r1",
                _ => "EC_unknown",
            }
            .to_string()
        }
        _ => "UNKNOWN".to_string(),
    }
}

fn general_name(name: &GeneralName<'_>) -> Option<GeneralNameInfo> {
    Some(match name {
        GeneralName::DNSName(d) => GeneralNameInfo::Dns(d.to_string()),
        GeneralName::RFC822Name(e) => GeneralNameInfo::Email(e.to_string()),
        GeneralName::URI(u) => GeneralNameInfo::Uri(u.to_string()),
        GeneralName::IPAddress(ip) => GeneralNameInfo::Ip(match ip.len() {
            4 => std::net::IpAddr::from(<[u8; 4]>::try_from(*ip).ok()?).to_string(),
            16 => std::net::IpAddr::from(<[u8; 16]>::try_from(*ip).ok()?).to_string(),
            _ => return None,
        }),
        GeneralName::RegisteredID(oid) => GeneralNameInfo::RegisteredId(oid.to_id_string()),
        GeneralName::DirectoryName(n) => GeneralNameInfo::Directory(Box::new(dn_info(n))),
        GeneralName::OtherName(oid, value) => GeneralNameInfo::Other(oid.to_id_string(), hex::encode(value)),
        _ => return None,
    })
}

/// Inspect a DER certificate.
pub fn inspect_der(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let subject_dn = dn_info(cert.subject());
    let issuer_dn = dn_info(cert.issuer());
    let issuer = issuer_dn.organization.clone().or_else(|| issuer_dn.common_name.clone()).unwrap_or_default();
    let mut info = CertInfo {
        serial: cert.raw_serial().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"),
        subject: dn_string(cert.subject()),
        subject_cn: subject_dn.common_name.clone(),
        issuer,
        issuer_dn,
        subject_dn,
        not_before: DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)?,
        not_after: DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)?,
        signature_algorithm: signature_name(&cert.signature_algorithm.algorithm.to_id_string()),
        key_algorithm: key_algorithm_of(cert.public_key()),
        spki_der: cert.public_key().raw.to_vec(),
        ..Default::default()
    };
    if let Ok(Some(ku)) = cert.key_usage() {
        let ku = ku.value;
        let flags = [
            (ku.digital_signature(), "DIGITAL_SIGNATURE"),
            (ku.non_repudiation(), "NON_REPUDIATION"),
            (ku.key_encipherment(), "KEY_ENCIPHERMENT"),
            (ku.data_encipherment(), "DATA_ENCIPHERMENT"),
            (ku.key_agreement(), "KEY_AGREEMENT"),
            (ku.key_cert_sign(), "CERTIFICATE_SIGNING"),
            (ku.crl_sign(), "CRL_SIGNING"),
            (ku.encipher_only(), "ENCIPHER_ONLY"),
            (ku.decipher_only(), "DECIPHER_ONLY"),
        ];
        info.key_usages = flags.iter().filter(|(on, _)| *on).map(|(_, n)| n.to_string()).collect();
    }
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        let eku = eku.value;
        let mut oids: Vec<String> = Vec::new();
        let known = [
            (eku.server_auth, "1.3.6.1.5.5.7.3.1"),
            (eku.client_auth, "1.3.6.1.5.5.7.3.2"),
            (eku.code_signing, "1.3.6.1.5.5.7.3.3"),
            (eku.email_protection, "1.3.6.1.5.5.7.3.4"),
            (eku.time_stamping, "1.3.6.1.5.5.7.3.8"),
            (eku.ocsp_signing, "1.3.6.1.5.5.7.3.9"),
            (eku.any, "2.5.29.37.0"),
        ];
        oids.extend(known.iter().filter(|(on, _)| *on).map(|(_, o)| o.to_string()));
        oids.extend(eku.other.iter().map(|o| o.to_id_string()));
        info.extended_key_usages = oids.into_iter().map(|o| (eku_name(&o).to_string(), o)).collect();
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let Some(n) = general_name(name) {
                if let GeneralNameInfo::Dns(d) = &n {
                    info.dns_names.push(d.clone());
                }
                info.sans.push(n);
            }
        }
    }
    Some(info)
}

pub fn inspect_pem(pem: &str) -> Option<CertInfo> {
    inspect_der(&first_cert_der(pem)?)
}

/// Why an imported private key was refused.
pub enum KeyError {
    Unreadable,
    Encrypted,
    Mismatch,
}

/// Check that the PEM private key `key_pem` belongs to the certificate
/// whose SubjectPublicKeyInfo is `spki_der`.
pub fn check_key_matches(key_pem: &[u8], spki_der: &[u8]) -> Result<(), KeyError> {
    let mut found = None;
    for pem in Pem::iter_from_buffer(key_pem) {
        let Ok(pem) = pem else { break };
        let der = match pem.label.as_str() {
            "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem.contents)),
            "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(pem.contents)),
            "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(pem.contents)),
            "ENCRYPTED PRIVATE KEY" => return Err(KeyError::Encrypted),
            _ => continue,
        };
        found = Some(der);
        break;
    }
    let der = found.ok_or(KeyError::Unreadable)?;
    let algs: [&'static SignatureAlgorithm; 4] = [
        &rcgen::PKCS_RSA_SHA256,
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ECDSA_P521_SHA512,
    ];
    let mut loaded = false;
    for alg in algs {
        if let Ok(key) = KeyPair::from_der_and_sign_algo(&der, alg) {
            loaded = true;
            if key.public_key_der() == spki_der {
                return Ok(());
            }
        }
    }
    Err(if loaded { KeyError::Mismatch } else { KeyError::Unreadable })
}

// --- DER, for the encrypted PKCS#8 that ExportCertificate returns ---

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut stack = vec![(arc & 0x7f) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            stack.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        body.extend(stack.iter().rev());
    }
    tlv(0x06, &body)
}

fn integer(v: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

const PBKDF2_ITERATIONS: u32 = 2048;

/// `-----BEGIN ENCRYPTED PRIVATE KEY-----`: PKCS#8 encrypted with PBES2
/// (PBKDF2-HMAC-SHA256, AES-256-CBC) under `passphrase`, which OpenSSL and
/// the usual crypto libraries read.
pub fn encrypt_pkcs8(pkcs8: &[u8], passphrase: &[u8]) -> Result<String, ServiceError> {
    use aws_lc_rs::cipher::{EncryptionContext, PaddedBlockEncryptingKey, UnboundCipherKey, AES_256};
    let salt: [u8; 16] = rand::random();
    let iv: [u8; 16] = rand::random();
    let mut key = [0u8; 32];
    let iterations = std::num::NonZeroU32::new(PBKDF2_ITERATIONS).expect("non-zero");
    aws_lc_rs::pbkdf2::derive(aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, passphrase, &mut key);
    let cipher = UnboundCipherKey::new(&AES_256, &key)
        .and_then(PaddedBlockEncryptingKey::cbc_pkcs7)
        .map_err(|e| internal("encrypting key", e))?;
    let mut data = pkcs8.to_vec();
    cipher
        .less_safe_encrypt(&mut data, EncryptionContext::Iv128(iv.into()))
        .map_err(|e| internal("encrypting key", e))?;
    let prf = seq(&[&oid(&[1, 2, 840, 113549, 2, 9]), &[0x05, 0x00]]);
    let pbkdf2_params = seq(&[&tlv(0x04, &salt), &integer(PBKDF2_ITERATIONS), &prf]);
    let kdf = seq(&[&oid(&[1, 2, 840, 113549, 1, 5, 12]), &pbkdf2_params]);
    let scheme = seq(&[&oid(&[2, 16, 840, 1, 101, 3, 4, 1, 42]), &tlv(0x04, &iv)]);
    let alg = seq(&[&oid(&[1, 2, 840, 113549, 1, 5, 13]), &seq(&[&kdf, &scheme])]);
    let info = seq(&[&alg, &tlv(0x04, &data)]);
    Ok(to_pem("ENCRYPTED PRIVATE KEY", &info))
}

/// A CSR's subject common name, DNS SANs and SubjectPublicKeyInfo, after
/// checking its signature.
pub struct ParsedCsr {
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub spki_der: Vec<u8>,
    pub key_algorithm: String,
}

pub fn parse_csr_der(der: &[u8]) -> Option<ParsedCsr> {
    let (_, csr) = X509CertificationRequest::from_der(der).ok()?;
    csr.verify_signature().ok()?;
    let info = &csr.certification_request_info;
    let common_name = dn_info(&info.subject).common_name;
    let mut dns_names = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    if let GeneralName::DNSName(d) = name {
                        dns_names.push(d.to_lowercase());
                    }
                }
            }
        }
    }
    Some(ParsedCsr {
        common_name,
        dns_names,
        spki_der: info.subject_pki.raw.to_vec(),
        key_algorithm: key_algorithm_of(&info.subject_pki),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_and_inspects_a_leaf() {
        let now = Utc::now();
        let root = new_root(now).unwrap();
        let ca = new_intermediate(&root, "RSA_2048", now).unwrap();
        let key_der = generate_key("EC_prime256v1").unwrap();
        let key = load_key(&key_der, "EC_prime256v1").unwrap();
        let names = vec!["example.com".to_string(), "www.example.com".to_string()];
        let pem = issue_leaf(
            &ca,
            &LeafRequest {
                common_name: "example.com",
                names: &names,
                spki_der: &spki_of(&key),
                not_before: now,
                not_after: now + chrono::Duration::days(198),
            },
        )
        .unwrap();
        let info = inspect_pem(&pem).unwrap();
        assert_eq!(info.issuer, "Amazon");
        assert_eq!(info.subject, "CN=example.com");
        assert_eq!(info.key_algorithm, "EC_prime256v1");
        assert_eq!(info.signature_algorithm, "SHA256WITHRSA");
        assert_eq!(info.dns_names, names);
        assert_eq!(info.extended_key_usages[0].0, "TLS_WEB_SERVER_AUTHENTICATION");
        let pkcs8_pem = to_pem("PRIVATE KEY", &key_der);
        assert!(check_key_matches(pkcs8_pem.as_bytes(), &info.spki_der).is_ok());
        assert!(encrypt_pkcs8(&key_der, b"passphrase").unwrap().starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    }
}
