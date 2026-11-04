//! X.509 extensions as DER, built from the API's shapes: `ApiPassthrough`
//! extensions and subjects, `CsrExtensions` on a CA's own CSR, and the
//! extensions certificate templates define.

use std::net::IpAddr;

use base64::Engine;
use mws_core::ServiceError;

use crate::der;
use crate::generated::{errors, types};

pub const BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
pub const SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];
pub const AUTHORITY_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 35];
pub const KEY_USAGE: &[u64] = &[2, 5, 29, 15];
pub const EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
pub const SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
pub const CERTIFICATE_POLICIES: &[u64] = &[2, 5, 29, 32];
pub const CRL_DISTRIBUTION_POINTS: &[u64] = &[2, 5, 29, 31];
pub const AUTHORITY_INFO_ACCESS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
pub const SUBJECT_INFO_ACCESS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 11];

/// One extension: its OID, criticality, and the DER inside `extnValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext {
    pub oid: Vec<u64>,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl Ext {
    pub fn new(oid: &[u64], critical: bool, value: Vec<u8>) -> Self {
        Self { oid: oid.to_vec(), critical, value }
    }

    pub fn to_rcgen(&self) -> rcgen::CustomExtension {
        let mut ext = rcgen::CustomExtension::from_oid_content(&self.oid, self.value.clone());
        ext.set_criticality(self.critical);
        ext
    }
}

/// Extensions in the order they were set; setting an OID again replaces it.
#[derive(Debug, Default)]
pub struct ExtSet(pub Vec<Ext>);

impl ExtSet {
    pub fn set(&mut self, ext: Ext) {
        match self.0.iter_mut().find(|e| e.oid == ext.oid) {
            Some(existing) => *existing = ext,
            None => self.0.push(ext),
        }
    }
}

fn bad(message: impl Into<String>) -> ServiceError {
    errors::invalid_args(message)
}

/// A dotted OID string as arcs.
pub fn parse_oid(s: &str) -> Result<Vec<u64>, ServiceError> {
    let arcs: Option<Vec<u64>> = s.split('.').map(|p| p.parse::<u64>().ok()).collect();
    match arcs {
        Some(a) if a.len() >= 2 && a[0] <= 2 && (a[0] == 2 || a[1] < 40) => Ok(a),
        _ => Err(bad(format!("The object identifier {s} is not valid."))),
    }
}

/// `KeyUsage ::= BIT STRING`, named bits in RFC 5280 order.
pub fn key_usage(ku: &types::KeyUsage) -> Vec<u8> {
    let bits = [
        ku.digital_signature,
        ku.non_repudiation,
        ku.key_encipherment,
        ku.data_encipherment,
        ku.key_agreement,
        ku.key_cert_sign,
        ku.crl_sign,
        ku.encipher_only,
        ku.decipher_only,
    ];
    key_usage_bits(&bits)
}

pub fn key_usage_bits(bits: &[bool]) -> Vec<u8> {
    let Some(highest) = bits.iter().rposition(|b| *b) else { return der::tlv(der::BIT_STRING, &[0]) };
    let mut bytes = vec![0u8; highest / 8 + 1];
    for (i, set) in bits.iter().enumerate() {
        if *set {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
    }
    // DER drops trailing zero bits of a named-bit list.
    let unused = 7 - (highest % 8) as u8;
    der::tlv(der::BIT_STRING, &[&[unused][..], &bytes].concat())
}

pub fn extended_key_usage_oid(e: &types::ExtendedKeyUsage) -> Result<Vec<u64>, ServiceError> {
    if let Some(oid) = &e.extended_key_usage_object_identifier {
        return parse_oid(oid);
    }
    let oid: &[u64] = match e.extended_key_usage_type.as_deref().unwrap_or_default() {
        "SERVER_AUTH" => &[1, 3, 6, 1, 5, 5, 7, 3, 1],
        "CLIENT_AUTH" => &[1, 3, 6, 1, 5, 5, 7, 3, 2],
        "CODE_SIGNING" => &[1, 3, 6, 1, 5, 5, 7, 3, 3],
        "EMAIL_PROTECTION" => &[1, 3, 6, 1, 5, 5, 7, 3, 4],
        "TIME_STAMPING" => &[1, 3, 6, 1, 5, 5, 7, 3, 8],
        "OCSP_SIGNING" => &[1, 3, 6, 1, 5, 5, 7, 3, 9],
        "SMART_CARD_LOGIN" => &[1, 3, 6, 1, 4, 1, 311, 20, 2, 2],
        "DOCUMENT_SIGNING" => &[1, 3, 6, 1, 5, 5, 7, 3, 36],
        "CERTIFICATE_TRANSPARENCY" => &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 4],
        other => return Err(bad(format!("The extended key usage type {other} is not valid."))),
    };
    Ok(oid.to_vec())
}

pub fn extended_key_usage(oids: &[Vec<u64>]) -> Vec<u8> {
    let parts: Vec<Vec<u8>> = oids.iter().map(|o| der::oid(o)).collect();
    der::tlv(der::SEQUENCE, &parts.concat())
}

const UTF8_STRING: u8 = 0x0c;
const PRINTABLE_STRING: u8 = 0x13;
const IA5_STRING: u8 = 0x16;
const SET: u8 = 0x31;

/// The attributes of an `ASN1Subject`, in the order ACM PCA encodes them.
pub fn subject_attributes(s: &types::ASN1Subject) -> Result<Vec<(Vec<u64>, String)>, ServiceError> {
    let standard: [(&[u64], &Option<String>); 14] = [
        (&[2, 5, 4, 6], &s.country),
        (&[2, 5, 4, 10], &s.organization),
        (&[2, 5, 4, 11], &s.organizational_unit),
        (&[2, 5, 4, 46], &s.distinguished_name_qualifier),
        (&[2, 5, 4, 8], &s.state),
        (&[2, 5, 4, 3], &s.common_name),
        (&[2, 5, 4, 5], &s.serial_number),
        (&[2, 5, 4, 7], &s.locality),
        (&[2, 5, 4, 12], &s.title),
        (&[2, 5, 4, 4], &s.surname),
        (&[2, 5, 4, 42], &s.given_name),
        (&[2, 5, 4, 43], &s.initials),
        (&[2, 5, 4, 65], &s.pseudonym),
        (&[2, 5, 4, 44], &s.generation_qualifier),
    ];
    let mut out: Vec<(Vec<u64>, String)> =
        standard.into_iter().filter_map(|(oid, v)| Some((oid.to_vec(), v.clone()?))).collect();
    if let Some(custom) = s.custom_attributes.as_ref().filter(|c| !c.is_empty()) {
        if !out.is_empty() {
            return Err(bad("CustomAttributes cannot be combined with standard subject attributes."));
        }
        for a in custom {
            out.push((parse_oid(&a.object_identifier)?, a.value.clone()));
        }
    }
    Ok(out)
}

fn is_printable(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || " '()+,-./:=?".contains(c))
}

/// `Name` DER for an `ASN1Subject` (for directoryName general names).
pub fn name_der(s: &types::ASN1Subject) -> Result<Vec<u8>, ServiceError> {
    let mut rdns = Vec::new();
    for (oid, value) in subject_attributes(s)? {
        let tag = if oid == [2, 5, 4, 6] && is_printable(&value) { PRINTABLE_STRING } else { UTF8_STRING };
        let atv = der::seq(&[&der::oid(&oid), &der::tlv(tag, value.as_bytes())]);
        rdns.push(der::tlv(SET, &atv));
    }
    Ok(der::tlv(der::SEQUENCE, &rdns.concat()))
}

/// One `GeneralName`.
pub fn general_name(n: &types::GeneralName) -> Result<Vec<u8>, ServiceError> {
    if let Some(dns) = &n.dns_name {
        return Ok(der::tlv(der::ctx_prim(2), dns.as_bytes()));
    }
    if let Some(email) = &n.rfc822_name {
        return Ok(der::tlv(der::ctx_prim(1), email.as_bytes()));
    }
    if let Some(uri) = &n.uniform_resource_identifier {
        return Ok(der::tlv(der::ctx_prim(6), uri.as_bytes()));
    }
    if let Some(ip) = &n.ip_address {
        let addr: IpAddr = ip.parse().map_err(|_| bad(format!("The IP address {ip} is not valid.")))?;
        let octets = match addr {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        return Ok(der::tlv(der::ctx_prim(7), &octets));
    }
    if let Some(id) = &n.registered_id {
        let oid = der::oid(&parse_oid(id)?);
        return Ok(der::tlv(der::ctx_prim(8), &oid[2..]));
    }
    if let Some(dn) = &n.directory_name {
        return Ok(der::tlv(der::ctx(4), &name_der(dn)?));
    }
    if let Some(other) = &n.other_name {
        let value = der::tlv(der::ctx(0), &der::tlv(UTF8_STRING, other.value.as_bytes()));
        return Ok(der::tlv(der::ctx(0), &[der::oid(&parse_oid(&other.type_id)?), value].concat()));
    }
    if let Some(edi) = &n.edi_party_name {
        let mut parts = Vec::new();
        if let Some(assigner) = &edi.name_assigner {
            parts.push(der::tlv(der::ctx(0), &der::tlv(UTF8_STRING, assigner.as_bytes())));
        }
        parts.push(der::tlv(der::ctx(1), &der::tlv(UTF8_STRING, edi.party_name.as_bytes())));
        return Ok(der::tlv(der::ctx(5), &parts.concat()));
    }
    Err(bad("A GeneralName must specify exactly one name."))
}

pub fn general_names(names: &[types::GeneralName]) -> Result<Vec<u8>, ServiceError> {
    let parts: Vec<Vec<u8>> = names.iter().map(general_name).collect::<Result<_, _>>()?;
    Ok(der::tlv(der::SEQUENCE, &parts.concat()))
}

pub fn certificate_policies(policies: &[types::PolicyInformation]) -> Result<Vec<u8>, ServiceError> {
    let mut out = Vec::new();
    for p in policies {
        let mut parts = vec![der::oid(&parse_oid(&p.cert_policy_id)?)];
        if let Some(qualifiers) = p.policy_qualifiers.as_ref().filter(|q| !q.is_empty()) {
            let qs: Vec<Vec<u8>> = qualifiers
                .iter()
                .map(|q| {
                    // CPS pointer: id-qt-cps with an IA5String URI.
                    der::seq(&[
                        &der::oid(&[1, 3, 6, 1, 5, 5, 7, 2, 1]),
                        &der::tlv(IA5_STRING, q.qualifier.cps_uri.as_bytes()),
                    ])
                })
                .collect();
            parts.push(der::tlv(der::SEQUENCE, &qs.concat()));
        }
        out.push(der::tlv(der::SEQUENCE, &parts.concat()));
    }
    Ok(der::tlv(der::SEQUENCE, &out.concat()))
}

fn access_method_oid(m: &types::AccessMethod) -> Result<Vec<u64>, ServiceError> {
    if let Some(oid) = &m.custom_object_identifier {
        return parse_oid(oid);
    }
    let oid: &[u64] = match m.access_method_type.as_deref().unwrap_or_default() {
        "CA_REPOSITORY" => &[1, 3, 6, 1, 5, 5, 7, 48, 5],
        "RESOURCE_PKI_MANIFEST" => &[1, 3, 6, 1, 5, 5, 7, 48, 10],
        "RESOURCE_PKI_NOTIFY" => &[1, 3, 6, 1, 5, 5, 7, 48, 13],
        other => return Err(bad(format!("The access method type {other} is not valid."))),
    };
    Ok(oid.to_vec())
}

/// The extensions `CsrExtensions` asks to put in a CA's CSR.
pub fn csr_extensions(c: &types::CsrExtensions) -> Result<Vec<Ext>, ServiceError> {
    let mut out = Vec::new();
    if let Some(ku) = &c.key_usage {
        out.push(Ext::new(KEY_USAGE, true, key_usage(ku)));
    }
    if let Some(sia) = c.subject_information_access.as_ref().filter(|s| !s.is_empty()) {
        let mut descs = Vec::new();
        for d in sia {
            descs.push(der::seq(&[
                &der::oid(&access_method_oid(&d.access_method)?),
                &general_name(&d.access_location)?,
            ]));
        }
        out.push(Ext::new(SUBJECT_INFO_ACCESS, false, der::tlv(der::SEQUENCE, &descs.concat())));
    }
    Ok(out)
}

/// The extensions an `ApiPassthrough` asks for.
pub fn api_extensions(e: &types::Extensions) -> Result<Vec<Ext>, ServiceError> {
    let mut out = Vec::new();
    if let Some(ku) = &e.key_usage {
        out.push(Ext::new(KEY_USAGE, true, key_usage(ku)));
    }
    if let Some(ekus) = e.extended_key_usage.as_ref().filter(|x| !x.is_empty()) {
        let oids: Vec<Vec<u64>> = ekus.iter().map(extended_key_usage_oid).collect::<Result<_, _>>()?;
        out.push(Ext::new(EXTENDED_KEY_USAGE, false, extended_key_usage(&oids)));
    }
    if let Some(sans) = e.subject_alternative_names.as_ref().filter(|x| !x.is_empty()) {
        out.push(Ext::new(SUBJECT_ALT_NAME, false, general_names(sans)?));
    }
    if let Some(policies) = e.certificate_policies.as_ref().filter(|x| !x.is_empty()) {
        out.push(Ext::new(CERTIFICATE_POLICIES, false, certificate_policies(policies)?));
    }
    for c in e.custom_extensions.iter().flatten() {
        let value = base64::engine::general_purpose::STANDARD
            .decode(&c.value)
            .map_err(|_| bad(format!("The value of custom extension {} is not valid base64.", c.object_identifier)))?;
        out.push(Ext::new(&parse_oid(&c.object_identifier)?, c.critical.unwrap_or(false), value));
    }
    Ok(out)
}

/// `BasicConstraints` for a CA (optionally with a path length) or an end entity.
pub fn basic_constraints(ca: bool, path_len: Option<u8>) -> Vec<u8> {
    if !ca {
        return der::seq(&[]);
    }
    let mut parts = vec![der::tlv(0x01, &[0xff])];
    if let Some(n) = path_len {
        parts.push(der::tlv(der::INTEGER, &[n]));
    }
    der::tlv(der::SEQUENCE, &parts.concat())
}

/// The subject key identifier rcgen also uses (SHA-256 of the SPKI, 20 bytes),
/// so CRLs and children's authority key identifiers match it.
pub fn subject_key_identifier(spki_der: &[u8]) -> Vec<u8> {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, spki_der);
    der::tlv(der::OCTET_STRING, &digest.as_ref()[..20])
}
