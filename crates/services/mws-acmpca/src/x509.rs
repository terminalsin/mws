//! Real X.509: CA keys, CSRs, certificate issuance and parsing.

use chrono::{DateTime, Utc};
use mws_core::ServiceError;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, IsCa, KeyIdMethod, KeyPair, RsaKeySize, SerialNumber,
    SignatureAlgorithm, SubjectPublicKeyInfo,
};
use x509_parser::cri_attributes::ParsedCriAttribute;
use x509_parser::prelude::*;

use crate::der;
use crate::extensions::{self as ext, Ext, ExtSet};
use crate::generated::{errors, types};

/// The rcgen algorithm for a CA key and signing algorithm. MWS supports
/// the combinations whose hash matches the curve for EC keys.
pub fn signature_algorithm(key_alg: &str, signing_alg: &str) -> Result<&'static SignatureAlgorithm, ServiceError> {
    let alg = match (key_alg, signing_alg) {
        ("RSA_2048" | "RSA_3072" | "RSA_4096", "SHA256WITHRSA") => &rcgen::PKCS_RSA_SHA256,
        ("RSA_2048" | "RSA_3072" | "RSA_4096", "SHA384WITHRSA") => &rcgen::PKCS_RSA_SHA384,
        ("RSA_2048" | "RSA_3072" | "RSA_4096", "SHA512WITHRSA") => &rcgen::PKCS_RSA_SHA512,
        ("EC_prime256v1", "SHA256WITHECDSA") => &rcgen::PKCS_ECDSA_P256_SHA256,
        ("EC_secp384r1", "SHA384WITHECDSA") => &rcgen::PKCS_ECDSA_P384_SHA384,
        ("EC_secp521r1", "SHA512WITHECDSA") => &rcgen::PKCS_ECDSA_P521_SHA512,
        _ => {
            return Err(errors::invalid_args(format!(
                "The signing algorithm {signing_alg} is not supported for key algorithm {key_alg}."
            )))
        }
    };
    Ok(alg)
}

/// A new CA private key, as PKCS#8 DER.
pub fn generate_key(key_alg: &str, signing_alg: &str) -> Result<Vec<u8>, ServiceError> {
    let alg = signature_algorithm(key_alg, signing_alg)?;
    let key = match key_alg {
        "RSA_2048" => KeyPair::generate_rsa_for(alg, RsaKeySize::_2048),
        "RSA_3072" => KeyPair::generate_rsa_for(alg, RsaKeySize::_3072),
        "RSA_4096" => KeyPair::generate_rsa_for(alg, RsaKeySize::_4096),
        _ => KeyPair::generate_for(alg),
    }
    .map_err(|e| ServiceError::internal(format!("key generation failed: {e}")))?;
    Ok(key.serialize_der())
}

/// Load a stored key for signing with `alg`.
pub fn key_for(der: &[u8], alg: &'static SignatureAlgorithm) -> Result<KeyPair, ServiceError> {
    let der = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(der.to_vec()));
    KeyPair::from_der_and_sign_algo(&der, alg).map_err(|e| ServiceError::internal(format!("loading CA key: {e}")))
}

/// The X.500 name for an `ASN1Subject`, in the order ACM PCA encodes it.
pub fn subject_dn(s: &types::ASN1Subject) -> Result<DistinguishedName, ServiceError> {
    let mut dn = DistinguishedName::new();
    for (oid, v) in ext::subject_attributes(s)? {
        let ty = DnType::from_oid(&oid);
        let value = match (&ty, rcgen::PrintableString::try_from(v.as_str())) {
            (DnType::CountryName, Ok(p)) => DnValue::PrintableString(p),
            _ => DnValue::Utf8String(v),
        };
        dn.push(ty, value);
    }
    Ok(dn)
}

/// The CA's certificate signing request, PEM, carrying `extensions`
/// (from the CA's `CsrExtensions`).
pub fn csr_pem(key: &KeyPair, dn: &DistinguishedName, extensions: &[Ext]) -> Result<String, ServiceError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = dn.clone();
    params.custom_extensions = extensions.iter().map(Ext::to_rcgen).collect();
    params
        .serialize_request(key)
        .and_then(|csr| csr.pem())
        .map_err(|e| ServiceError::internal(format!("building CSR: {e}")))
}

/// What MWS needs from a CSR.
pub struct Csr {
    pub subject: DistinguishedName,
    pub spki_der: Vec<u8>,
    /// The extensions the CSR requests, raw.
    pub extensions: Vec<Ext>,
}

fn malformed_csr() -> ServiceError {
    errors::malformed_csr("The certificate signing request is malformed or its signature is invalid.")
}

pub fn parse_csr(pem_bytes: &[u8]) -> Result<Csr, ServiceError> {
    let (_, pem) = parse_x509_pem(pem_bytes).map_err(|_| malformed_csr())?;
    if pem.label != "CERTIFICATE REQUEST" && pem.label != "NEW CERTIFICATE REQUEST" {
        return Err(malformed_csr());
    }
    let (_, csr) = X509CertificationRequest::from_der(&pem.contents).map_err(|_| malformed_csr())?;
    csr.verify_signature().map_err(|_| malformed_csr())?;
    let info = &csr.certification_request_info;
    let subject = dn_from_name(&info.subject).ok_or_else(malformed_csr)?;
    let mut extensions = Vec::new();
    for attr in info.iter_attributes() {
        if let ParsedCriAttribute::ExtensionRequest(req) = attr.parsed_attribute() {
            for e in &req.extensions {
                let oid: Vec<u64> = e.oid.iter().ok_or_else(malformed_csr)?.collect();
                extensions.push(Ext { oid, critical: e.critical, value: e.value.to_vec() });
            }
        }
    }
    Ok(Csr { subject, spki_der: info.subject_pki.raw.to_vec(), extensions })
}

/// Convert a parsed name, keeping each attribute's string type so chains
/// built from it match byte for byte.
fn dn_from_name(name: &X509Name<'_>) -> Option<DistinguishedName> {
    use x509_parser::der_parser::asn1_rs::Tag;
    let mut dn = DistinguishedName::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid: Vec<u64> = attr.attr_type().iter()?.collect();
            let data = attr.attr_value().data;
            let s = std::str::from_utf8(data).ok()?;
            let value = match attr.attr_value().header.tag() {
                Tag::PrintableString => DnValue::PrintableString(s.try_into().ok()?),
                Tag::Ia5String => DnValue::Ia5String(s.try_into().ok()?),
                Tag::Utf8String => DnValue::Utf8String(s.to_string()),
                Tag::T61String => DnValue::TeletexString(s.try_into().ok()?),
                _ => return None,
            };
            dn.push(DnType::from_oid(&oid), value);
        }
    }
    Some(dn)
}

/// A certificate template: what ACM PCA puts in a certificate itself, and
/// whether the API request's (`ApiPassthrough`) or the CSR's extensions
/// pass through. Template values win over API values, which win over the
/// CSR's.
pub struct Template {
    pub ca: bool,
    /// Self-signed by the issuing (root) CA, for its own CSR.
    pub root: bool,
    pub path_len: Option<u8>,
    pub basic_constraints_critical: bool,
    /// Key usage bits in RFC 5280 order, when the template sets them.
    pub key_usage: Option<[bool; 9]>,
    pub extended_key_usages: Vec<Vec<u64>>,
    pub api_passthrough: bool,
    pub csr_passthrough: bool,
}

const DS: usize = 0;
const KE: usize = 2;
const KCS: usize = 5;
const CRL: usize = 6;

fn bits(set: &[usize]) -> Option<[bool; 9]> {
    let mut b = [false; 9];
    for i in set {
        b[*i] = true;
    }
    Some(b)
}

const SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
const CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
const CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];
const OCSP_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 9];

/// Look up `arn:aws:acm-pca:::template/{name}/V1`.
pub fn template(arn: &str) -> Result<Template, ServiceError> {
    let unsupported = || errors::invalid_args(format!("The template ARN {arn} is not supported."));
    let name = arn
        .split_once(":template/")
        .map(|(_, n)| n)
        .ok_or_else(|| errors::invalid_args(format!("The template ARN {arn} is not valid.")))?;
    let name = name.strip_suffix("/V1").ok_or_else(unsupported)?;
    let (base, api, csr) = if let Some(b) = name.strip_suffix("_APICSRPassthrough") {
        (b, true, true)
    } else if let Some(b) = name.strip_suffix("_APIPassthrough") {
        (b, true, false)
    } else if let Some(b) = name.strip_suffix("_CSRPassthrough") {
        (b, false, true)
    } else {
        (name, false, false)
    };
    let end_entity = |key_usage, ekus: &[&[u64]]| Template {
        ca: false,
        root: false,
        path_len: None,
        basic_constraints_critical: true,
        key_usage,
        extended_key_usages: ekus.iter().map(|o| o.to_vec()).collect(),
        api_passthrough: api,
        csr_passthrough: csr,
    };
    let ca = |root: bool, path_len: Option<u8>, key_usage| Template {
        ca: true,
        root,
        path_len,
        basic_constraints_critical: true,
        key_usage,
        extended_key_usages: vec![],
        api_passthrough: api,
        csr_passthrough: csr,
    };
    let path_len = |prefix: &str| -> Option<u8> {
        base.strip_prefix(prefix)?.strip_prefix("_PathLen")?.parse::<u8>().ok().filter(|n| *n <= 3)
    };
    let t = match base {
        "EndEntityCertificate" => end_entity(bits(&[DS, KE]), &[SERVER_AUTH, CLIENT_AUTH]),
        "EndEntityServerAuthCertificate" => end_entity(bits(&[DS, KE]), &[SERVER_AUTH]),
        "EndEntityClientAuthCertificate" => end_entity(bits(&[DS, KE]), &[CLIENT_AUTH]),
        "CodeSigningCertificate" => end_entity(bits(&[DS]), &[CODE_SIGNING]),
        "OCSPSigningCertificate" => end_entity(bits(&[DS]), &[OCSP_SIGNING]),
        "RootCACertificate" => ca(true, None, bits(&[DS, KCS, CRL])),
        "BlankEndEntityCertificate" if api => Template { basic_constraints_critical: false, ..end_entity(None, &[]) },
        "BlankEndEntityCertificate_CriticalBasicConstraints" if api => end_entity(None, &[]),
        "BlankRootCACertificate" if api => ca(true, None, None),
        _ => {
            if let Some(n) = path_len("SubordinateCACertificate") {
                ca(false, Some(n), bits(&[DS, KCS, CRL]))
            } else if let Some(n) = path_len("BlankSubordinateCACertificate").filter(|_| api) {
                ca(false, Some(n), None)
            } else if let Some(n) = path_len("BlankRootCACertificate").filter(|_| api) {
                ca(true, Some(n), None)
            } else {
                return Err(unsupported());
            }
        }
    };
    Ok(t)
}

fn to_offset(t: DateTime<Utc>) -> ::time::OffsetDateTime {
    ::time::OffsetDateTime::from_unix_timestamp(t.timestamp()).unwrap_or(::time::OffsetDateTime::UNIX_EPOCH)
}

/// Extensions a CSR may not dictate: the CA sets these itself.
const CA_CONTROLLED: [&[u64]; 5] = [
    ext::BASIC_CONSTRAINTS,
    ext::SUBJECT_KEY_IDENTIFIER,
    ext::AUTHORITY_KEY_IDENTIFIER,
    ext::CRL_DISTRIBUTION_POINTS,
    ext::AUTHORITY_INFO_ACCESS,
];

pub struct Issue<'a> {
    pub csr: &'a Csr,
    pub template: Template,
    /// `ApiPassthrough`, used only by templates that pass it through.
    pub api: Option<&'a types::ApiPassthrough>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// 16 random bytes, high bit cleared.
    pub serial: [u8; 16],
    /// CRL Distribution Points URL, when the CA publishes CRLs.
    pub crl_url: Option<String>,
    /// Authority Information Access OCSP URL, when the CA answers OCSP.
    pub ocsp_url: Option<String>,
}

impl Issue<'_> {
    /// The certificate's extensions: CSR passthrough, then API passthrough,
    /// then the template's own, each overriding the one before.
    fn extensions(&self) -> Result<ExtSet, ServiceError> {
        let mut set = ExtSet::default();
        let t = &self.template;
        for e in &self.csr.extensions {
            if CA_CONTROLLED.contains(&e.oid.as_slice()) {
                continue;
            }
            // Every template takes the subject alternative names from the CSR.
            if t.csr_passthrough || e.oid == ext::SUBJECT_ALT_NAME {
                set.set(e.clone());
            }
        }
        if t.api_passthrough {
            if let Some(extensions) = self.api.and_then(|a| a.extensions.as_ref()) {
                for e in ext::api_extensions(extensions)? {
                    set.set(e);
                }
            }
        }
        set.set(Ext::new(
            ext::BASIC_CONSTRAINTS,
            t.basic_constraints_critical,
            ext::basic_constraints(t.ca, t.path_len),
        ));
        if let Some(bits) = &t.key_usage {
            set.set(Ext::new(ext::KEY_USAGE, true, ext::key_usage_bits(bits)));
        }
        if !t.extended_key_usages.is_empty() {
            set.set(Ext::new(ext::EXTENDED_KEY_USAGE, false, ext::extended_key_usage(&t.extended_key_usages)));
        }
        set.set(Ext::new(ext::SUBJECT_KEY_IDENTIFIER, false, ext::subject_key_identifier(&self.csr.spki_der)));
        if let Some(url) = self.ocsp_url.as_ref().filter(|_| !t.root) {
            // AuthorityInfoAccess ::= SEQUENCE OF AccessDescription { id-ad-ocsp, [6] uri }
            let desc =
                der::seq(&[&der::oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1]), &der::tlv(der::ctx_prim(6), url.as_bytes())]);
            set.set(Ext::new(ext::AUTHORITY_INFO_ACCESS, false, der::seq(&[&desc])));
        }
        Ok(set)
    }

    fn params(&self) -> Result<CertificateParams, ServiceError> {
        let mut p = CertificateParams::default();
        p.distinguished_name = match self.api.and_then(|a| a.subject.as_ref()).filter(|_| self.template.api_passthrough)
        {
            Some(subject) => subject_dn(subject)?,
            None => self.csr.subject.clone(),
        };
        p.not_before = to_offset(self.not_before);
        p.not_after = to_offset(self.not_after);
        p.serial_number = Some(SerialNumber::from_slice(&self.serial));
        // Every extension but the authority key identifier and the CRL
        // distribution point is written here, so rcgen adds no others.
        p.is_ca = IsCa::NoCa;
        p.custom_extensions = self.extensions()?.0.iter().map(Ext::to_rcgen).collect();
        p.use_authority_key_identifier_extension = !self.template.root;
        p.key_identifier_method = KeyIdMethod::Sha256;
        if let Some(url) = self.crl_url.as_ref().filter(|_| !self.template.root) {
            p.crl_distribution_points = vec![rcgen::CrlDistributionPoint { uris: vec![url.clone()] }];
        }
        Ok(p)
    }

    /// Self-signed (the root CA certificate): the CSR must carry `key`.
    pub fn self_signed(&self, key: &KeyPair) -> Result<String, ServiceError> {
        if key.public_key_der() != self.csr.spki_der {
            return Err(errors::invalid_args(
                "A root CA certificate can only be issued for the certificate authority's own CSR.",
            ));
        }
        self.params()?.self_signed(key).map(|c| c.pem()).map_err(|e| ServiceError::internal(format!("signing: {e}")))
    }

    /// Signed by the CA whose certificate is `issuer_pem` and key `key`.
    pub fn signed_by(&self, issuer_pem: &str, key: &KeyPair) -> Result<String, ServiceError> {
        let issuer = CertificateParams::from_ca_cert_pem(issuer_pem)
            .and_then(|p| p.self_signed(key))
            .map_err(|e| ServiceError::internal(format!("loading CA certificate: {e}")))?;
        let spki = SubjectPublicKeyInfo::from_der(&self.csr.spki_der).map_err(|_| malformed_csr())?;
        self.params()?
            .signed_by(&spki, &issuer, key)
            .map(|c| c.pem())
            .map_err(|e| ServiceError::internal(format!("signing: {e}")))
    }
}

/// The certificate's subject in RFC 2253 form (`CN=...,O=...`).
pub fn subject_string(pem_str: &str) -> String {
    parse_x509_pem(pem_str.as_bytes())
        .ok()
        .and_then(|(_, pem)| {
            let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;
            let mut parts = Vec::new();
            for rdn in cert.subject().iter() {
                for attr in rdn.iter() {
                    let name = x509_parser::objects::oid2abbrev(attr.attr_type(), x509_parser::objects::oid_registry())
                        .map(str::to_string)
                        .unwrap_or_else(|_| attr.attr_type().to_id_string());
                    let value = attr.as_str().map(str::to_string).unwrap_or_default();
                    parts.push(format!("{name}={value}"));
                }
            }
            parts.reverse();
            Some(parts.join(","))
        })
        .unwrap_or_default()
}

/// Facts about a certificate MWS needs to track.
pub struct CertInfo {
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub spki_der: Vec<u8>,
    pub is_ca: bool,
    pub self_signed: bool,
    /// The certificate re-encoded as PEM.
    pub pem: String,
}

fn malformed_cert() -> ServiceError {
    errors::malformed_certificate("The certificate is malformed.")
}

/// Parse the first certificate in `pem_bytes`.
pub fn cert_info(pem_bytes: &[u8]) -> Result<CertInfo, ServiceError> {
    let (_, pem) = parse_x509_pem(pem_bytes).map_err(|_| malformed_cert())?;
    if pem.label != "CERTIFICATE" {
        return Err(malformed_cert());
    }
    let (_, cert) = X509Certificate::from_der(&pem.contents).map_err(|_| malformed_cert())?;
    let ts = |t: ASN1Time| DateTime::from_timestamp(t.timestamp(), 0).unwrap_or_default();
    Ok(CertInfo {
        serial: colon_hex(cert.raw_serial()),
        not_before: ts(cert.validity().not_before),
        not_after: ts(cert.validity().not_after),
        spki_der: cert.public_key().raw.to_vec(),
        is_ca: cert.basic_constraints().ok().flatten().is_some_and(|b| b.value.ca),
        self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
        pem: pem_encode("CERTIFICATE", &pem.contents),
    })
}

/// Every certificate in a PEM bundle, in order, re-encoded.
pub fn split_chain(pem_bytes: &[u8]) -> Result<Vec<String>, ServiceError> {
    let mut out = Vec::new();
    for pem in Pem::iter_from_buffer(pem_bytes) {
        let pem = pem.map_err(|_| malformed_cert())?;
        X509Certificate::from_der(&pem.contents).map_err(|_| malformed_cert())?;
        out.push(pem_encode("CERTIFICATE", &pem.contents));
    }
    if out.is_empty() {
        return Err(malformed_cert());
    }
    Ok(out)
}

/// Whether `child_pem` is signed by the key in `issuer_pem`.
pub fn verify_signed_by(child_pem: &str, issuer_pem: &str) -> bool {
    let parse = |p: &str| parse_x509_pem(p.as_bytes()).ok().map(|(_, pem)| pem.contents);
    let (Some(child), Some(issuer)) = (parse(child_pem), parse(issuer_pem)) else { return false };
    let (Ok((_, child)), Ok((_, issuer))) = (X509Certificate::from_der(&child), X509Certificate::from_der(&issuer))
    else {
        return false;
    };
    child.verify_signature(Some(issuer.public_key())).is_ok()
}

pub fn public_key_der(key: &KeyPair) -> Vec<u8> {
    key.public_key_der()
}

pub fn colon_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    out
}
