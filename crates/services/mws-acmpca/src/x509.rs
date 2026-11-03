//! Real X.509: CA keys, CSRs, certificate issuance and parsing.

use chrono::{DateTime, Utc};
use mws_core::ServiceError;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RsaKeySize, SanType, SerialNumber, SignatureAlgorithm, SubjectPublicKeyInfo,
};
use x509_parser::prelude::*;

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
pub fn subject_dn(s: &types::ASN1Subject) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    let oid = |o: &[u64]| DnType::CustomDnType(o.to_vec());
    let attrs: [(DnType, &Option<String>); 14] = [
        (DnType::CountryName, &s.country),
        (DnType::OrganizationName, &s.organization),
        (DnType::OrganizationalUnitName, &s.organizational_unit),
        (oid(&[2, 5, 4, 46]), &s.distinguished_name_qualifier),
        (DnType::StateOrProvinceName, &s.state),
        (DnType::CommonName, &s.common_name),
        (oid(&[2, 5, 4, 5]), &s.serial_number),
        (DnType::LocalityName, &s.locality),
        (oid(&[2, 5, 4, 12]), &s.title),
        (oid(&[2, 5, 4, 4]), &s.surname),
        (oid(&[2, 5, 4, 42]), &s.given_name),
        (oid(&[2, 5, 4, 43]), &s.initials),
        (oid(&[2, 5, 4, 65]), &s.pseudonym),
        (oid(&[2, 5, 4, 44]), &s.generation_qualifier),
    ];
    for (ty, v) in attrs {
        if let Some(v) = v {
            let value = match (&ty, rcgen::PrintableString::try_from(v.as_str())) {
                (DnType::CountryName, Ok(p)) => DnValue::PrintableString(p),
                _ => DnValue::Utf8String(v.clone()),
            };
            dn.push(ty, value);
        }
    }
    for a in s.custom_attributes.iter().flatten() {
        if let Some(parts) = a.object_identifier.split('.').map(|p| p.parse::<u64>().ok()).collect::<Option<Vec<_>>>() {
            dn.push(DnType::CustomDnType(parts), DnValue::Utf8String(a.value.clone()));
        }
    }
    dn
}

/// The CA's certificate signing request, PEM.
pub fn csr_pem(key: &KeyPair, dn: &DistinguishedName) -> Result<String, ServiceError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = dn.clone();
    params
        .serialize_request(key)
        .and_then(|csr| csr.pem())
        .map_err(|e| ServiceError::internal(format!("building CSR: {e}")))
}

/// What MWS needs from a CSR.
pub struct Csr {
    pub subject: DistinguishedName,
    pub sans: Vec<SanType>,
    pub spki_der: Vec<u8>,
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
    let mut sans = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    let converted = match name {
                        GeneralName::DNSName(d) => d.to_string().try_into().ok().map(SanType::DnsName),
                        GeneralName::RFC822Name(e) => e.to_string().try_into().ok().map(SanType::Rfc822Name),
                        GeneralName::URI(u) => u.to_string().try_into().ok().map(SanType::URI),
                        GeneralName::IPAddress(ip) => ip_from_bytes(ip).map(SanType::IpAddress),
                        _ => None,
                    };
                    sans.extend(converted);
                }
            }
        }
    }
    Ok(Csr { subject, sans, spki_der: info.subject_pki.raw.to_vec() })
}

fn ip_from_bytes(b: &[u8]) -> Option<std::net::IpAddr> {
    match b.len() {
        4 => Some(std::net::IpAddr::from(<[u8; 4]>::try_from(b).ok()?)),
        16 => Some(std::net::IpAddr::from(<[u8; 16]>::try_from(b).ok()?)),
        _ => None,
    }
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

/// Certificate shapes from ACM PCA's templates.
pub struct Template {
    pub is_ca: IsCa,
    pub key_usages: Vec<KeyUsagePurpose>,
    pub extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
}

pub const ROOT_TEMPLATE: &str = "RootCACertificate/V1";

/// Look up `arn:aws:acm-pca:::template/{name}`.
pub fn template(arn: &str) -> Result<(String, Template), ServiceError> {
    let name = arn
        .split_once(":template/")
        .map(|(_, n)| n.to_string())
        .ok_or_else(|| errors::invalid_args(format!("The template ARN {arn} is not valid.")))?;
    use ExtendedKeyUsagePurpose as E;
    use KeyUsagePurpose as K;
    let ca = |constraint| Template {
        is_ca: IsCa::Ca(constraint),
        key_usages: vec![K::DigitalSignature, K::KeyCertSign, K::CrlSign],
        extended_key_usages: vec![],
    };
    let end_entity = |ekus| Template {
        is_ca: IsCa::ExplicitNoCa,
        key_usages: vec![K::DigitalSignature, K::KeyEncipherment],
        extended_key_usages: ekus,
    };
    let t = match name.as_str() {
        "EndEntityCertificate/V1" => end_entity(vec![E::ServerAuth, E::ClientAuth]),
        "EndEntityServerAuthCertificate/V1" => end_entity(vec![E::ServerAuth]),
        "EndEntityClientAuthCertificate/V1" => end_entity(vec![E::ClientAuth]),
        "CodeSigningCertificate/V1" => Template {
            is_ca: IsCa::ExplicitNoCa,
            key_usages: vec![K::DigitalSignature],
            extended_key_usages: vec![E::CodeSigning],
        },
        "OCSPSigningCertificate/V1" => Template {
            is_ca: IsCa::ExplicitNoCa,
            key_usages: vec![K::DigitalSignature],
            extended_key_usages: vec![E::OcspSigning],
        },
        ROOT_TEMPLATE => ca(BasicConstraints::Unconstrained),
        "SubordinateCACertificate_PathLen0/V1" => ca(BasicConstraints::Constrained(0)),
        "SubordinateCACertificate_PathLen1/V1" => ca(BasicConstraints::Constrained(1)),
        "SubordinateCACertificate_PathLen2/V1" => ca(BasicConstraints::Constrained(2)),
        "SubordinateCACertificate_PathLen3/V1" => ca(BasicConstraints::Constrained(3)),
        _ => return Err(errors::invalid_args(format!("The template ARN {arn} is not supported."))),
    };
    Ok((name, t))
}

fn to_offset(t: DateTime<Utc>) -> ::time::OffsetDateTime {
    ::time::OffsetDateTime::from_unix_timestamp(t.timestamp()).unwrap_or(::time::OffsetDateTime::UNIX_EPOCH)
}

pub struct Issue<'a> {
    pub csr: &'a Csr,
    pub template: Template,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// 16 random bytes, high bit cleared.
    pub serial: [u8; 16],
}

impl Issue<'_> {
    fn params(&self) -> CertificateParams {
        let mut p = CertificateParams::default();
        p.distinguished_name = self.csr.subject.clone();
        p.subject_alt_names = self.csr.sans.clone();
        p.not_before = to_offset(self.not_before);
        p.not_after = to_offset(self.not_after);
        p.serial_number = Some(SerialNumber::from_slice(&self.serial));
        p.is_ca = self.template.is_ca.clone();
        if matches!(p.is_ca, IsCa::ExplicitNoCa) {
            // rcgen writes `cA FALSE` explicitly, which DER forbids (it is the
            // default); strict parsers reject that. Emit the canonical empty
            // BasicConstraints instead, critical as ACM PCA does.
            p.is_ca = IsCa::NoCa;
            let mut ext = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 0x00]);
            ext.set_criticality(true);
            p.custom_extensions.push(ext);
        }
        p.key_usages = self.template.key_usages.clone();
        p.extended_key_usages = self.template.extended_key_usages.clone();
        p.use_authority_key_identifier_extension = true;
        p.key_identifier_method = KeyIdMethod::Sha256;
        p
    }

    /// Self-signed (the root CA certificate): the CSR must carry `key`.
    pub fn self_signed(&self, key: &KeyPair) -> Result<String, ServiceError> {
        if key.public_key_der() != self.csr.spki_der {
            return Err(errors::invalid_args(
                "A root CA certificate can only be issued for the certificate authority's own CSR.",
            ));
        }
        let mut params = self.params();
        params.use_authority_key_identifier_extension = false;
        params.self_signed(key).map(|c| c.pem()).map_err(|e| ServiceError::internal(format!("signing: {e}")))
    }

    /// Signed by the CA whose certificate is `issuer_pem` and key `key`.
    pub fn signed_by(&self, issuer_pem: &str, key: &KeyPair) -> Result<String, ServiceError> {
        let issuer = CertificateParams::from_ca_cert_pem(issuer_pem)
            .and_then(|p| p.self_signed(key))
            .map_err(|e| ServiceError::internal(format!("loading CA certificate: {e}")))?;
        let spki = SubjectPublicKeyInfo::from_der(&self.csr.spki_der).map_err(|_| malformed_csr())?;
        self.params()
            .signed_by(&spki, &issuer, key)
            .map(|c| c.pem())
            .map_err(|e| ServiceError::internal(format!("signing: {e}")))
    }
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
