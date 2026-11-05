//! The CMS (RFC 5652) side of SCEP (RFC 8894): reading a signed and
//! enveloped `pkiMessage`, and writing `CertRep` replies and certs-only
//! messages.

use aws_lc_rs::cipher::{
    DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, UnboundCipherKey,
    AES_128, AES_192, AES_256,
};
use aws_lc_rs::digest;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::{
    OaepPrivateDecryptingKey, Pkcs1PrivateDecryptingKey, Pkcs1PublicEncryptingKey, PrivateDecryptingKey,
    PublicEncryptingKey, OAEP_SHA1_MGF1SHA1,
};
use aws_lc_rs::signature::{self, RsaKeyPair, UnparsedPublicKey};
use chrono::{DateTime, Utc};
use x509_parser::prelude::*;

use crate::der::{self, Node};

pub mod oids {
    pub const DATA: &str = "1.2.840.113549.1.7.1";
    pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
    pub const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
    pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
    pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
    pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
    pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    pub const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
    pub const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
    pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
    pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
    pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
    pub const SHA1: &str = "1.3.14.3.2.26";
    pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
    pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
    pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";
    pub const AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
    pub const AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
    pub const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
    pub const MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
    pub const PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
    pub const FAIL_INFO: &str = "2.16.840.1.113733.1.9.4";
    pub const SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
    pub const RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";
    pub const TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";
}

/// Why a message could not be read; the text is what AWS answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmsError {
    Invalid,
    Undecodable,
    NoCertificate,
    Expired,
    Unencodable,
    UnsupportedAlgorithm(String),
}

impl CmsError {
    pub fn message(&self) -> String {
        match self {
            Self::Invalid => "The request contains invalid Cryptographic Message Syntax.".into(),
            Self::Undecodable => "The request could not be decoded. Please send a valid SCEP request.".into(),
            Self::NoCertificate => "There must be a valid certificate included in the request.".into(),
            Self::Expired => "The certificate included in the request is expired.".into(),
            Self::Unencodable => {
                "The response could not be encoded with values derived from the request. Please send a valid SCEP request."
                    .into()
            }
            Self::UnsupportedAlgorithm(oid) => format!("Unsupported algorithm: {oid}"),
        }
    }
}

/// A verified SCEP `pkiMessage`.
#[derive(Debug, Clone)]
pub struct PkiMessage {
    pub message_type: String,
    pub transaction_id: String,
    pub sender_nonce: Vec<u8>,
    /// The certificate the request was signed with (self-signed for an
    /// initial enrollment).
    pub signer_cert: Vec<u8>,
    /// The `pkcsPKIEnvelope`: a ContentInfo holding EnvelopedData.
    pub envelope: Vec<u8>,
}

fn attr_value<'a>(attrs: &'a Node, oid: &str) -> Option<&'a Node> {
    attrs.children.iter().find(|a| a.child(0).and_then(Node::oid).as_deref() == Some(oid))?.child(1)?.child(0)
}

fn digest_alg(oid: &str) -> Option<&'static digest::Algorithm> {
    match oid {
        oids::SHA1 => Some(&digest::SHA1_FOR_LEGACY_USE_ONLY),
        oids::SHA256 => Some(&digest::SHA256),
        oids::SHA384 => Some(&digest::SHA384),
        oids::SHA512 => Some(&digest::SHA512),
        _ => None,
    }
}

fn rsa_verification(digest_oid: &str) -> Option<&'static signature::RsaParameters> {
    match digest_oid {
        oids::SHA1 => Some(&signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
        oids::SHA256 => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
        oids::SHA384 => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
        oids::SHA512 => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
        _ => None,
    }
}

/// The ContentInfo's content, if it has the expected type.
fn content_of<'a>(info: &'a Node, ty: &str) -> Option<&'a Node> {
    if info.tag != der::SEQUENCE || info.child(0)?.oid()? != ty {
        return None;
    }
    let explicit = info.child(1)?;
    (explicit.context() == Some(0)).then(|| explicit.child(0))?
}

/// Read and verify a `pkiMessage` (DER or BER) at time `now`.
pub fn read_pki_message(raw: &[u8], now: DateTime<Utc>) -> Result<PkiMessage, CmsError> {
    let info = der::parse(raw).map(|(n, _)| n).ok_or(CmsError::Invalid)?;
    let sd = content_of(&info, oids::SIGNED_DATA).ok_or(CmsError::Invalid)?;
    // SignedData: version, digestAlgorithms, encapContentInfo, [0] certs?,
    // [1] crls?, signerInfos.
    let encap = sd.child(2).ok_or(CmsError::Invalid)?;
    let econtent = encap.child(1).and_then(|e| e.child(0)).map(Node::bytes).ok_or(CmsError::Undecodable)?;
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut signer_infos = None;
    for n in &sd.children[3..] {
        match n.tag {
            0xa0 => certs.extend(n.children.iter().map(Node::to_der)),
            der::SET => signer_infos = Some(n),
            _ => {}
        }
    }
    let si = signer_infos.and_then(|s| s.child(0)).ok_or(CmsError::Invalid)?;
    let sid = si.child(1).ok_or(CmsError::Invalid)?;
    let digest_oid = si.child(2).and_then(|a| a.child(0)).and_then(Node::oid).ok_or(CmsError::Invalid)?;
    let attrs = si.child(3).filter(|a| a.tag == 0xa0).ok_or(CmsError::Undecodable)?;
    let sig_alg = si.child(4).and_then(|a| a.child(0)).and_then(Node::oid).ok_or(CmsError::Invalid)?;
    let sig = si.child(5).map(Node::bytes).ok_or(CmsError::Invalid)?;

    // The signer's certificate: matched by issuer and serial number, or
    // the only one there.
    let signer_cert = certs
        .iter()
        .find(|c| {
            let Ok((_, cert)) = X509Certificate::from_der(c) else { return false };
            match (sid.child(0), sid.child(1)) {
                (Some(issuer), Some(serial)) if sid.tag == der::SEQUENCE => {
                    issuer.to_der() == cert.issuer().as_raw() && serial.content == cert.raw_serial()
                }
                _ => false,
            }
        })
        .or_else(|| (certs.len() == 1).then(|| &certs[0]))
        .cloned()
        .ok_or(CmsError::NoCertificate)?;
    let (_, cert) = X509Certificate::from_der(&signer_cert).map_err(|_| CmsError::NoCertificate)?;
    let validity = cert.validity();
    if now.timestamp() > validity.not_after.timestamp() {
        return Err(CmsError::Expired);
    }

    let dalg = digest_alg(&digest_oid).ok_or_else(|| CmsError::UnsupportedAlgorithm(digest_oid.clone()))?;
    let md = attr_value(attrs, oids::MESSAGE_DIGEST).map(Node::bytes).ok_or(CmsError::Undecodable)?;
    if digest::digest(dalg, &econtent).as_ref() != md.as_slice() {
        return Err(CmsError::Invalid);
    }
    let params = match sig_alg.as_str() {
        oids::RSA_ENCRYPTION => rsa_verification(&digest_oid),
        oids::SHA1_WITH_RSA => rsa_verification(oids::SHA1),
        oids::SHA256_WITH_RSA => rsa_verification(oids::SHA256),
        oids::SHA384_WITH_RSA => rsa_verification(oids::SHA384),
        oids::SHA512_WITH_RSA => rsa_verification(oids::SHA512),
        // An ECDSA requester can't receive an RSA-enveloped reply.
        _ => return Err(CmsError::Unencodable),
    }
    .ok_or_else(|| CmsError::UnsupportedAlgorithm(sig_alg.clone()))?;
    let public_key = cert.public_key();
    if public_key.algorithm.algorithm.to_id_string() != oids::RSA_ENCRYPTION {
        return Err(CmsError::Unencodable);
    }
    UnparsedPublicKey::new(params, public_key.subject_public_key.data.as_ref())
        .verify(&attrs.to_der_tagged(der::SET), &sig)
        .map_err(|_| CmsError::Invalid)?;

    let printable = |oid: &str| attr_value(attrs, oid).map(|n| String::from_utf8_lossy(&n.bytes()).into_owned());
    Ok(PkiMessage {
        message_type: printable(oids::MESSAGE_TYPE).ok_or(CmsError::Undecodable)?,
        transaction_id: printable(oids::TRANSACTION_ID).ok_or(CmsError::Undecodable)?,
        sender_nonce: attr_value(attrs, oids::SENDER_NONCE).map(Node::bytes).ok_or(CmsError::Undecodable)?,
        signer_cert,
        envelope: econtent,
    })
}

/// The cipher and its key length.
fn aes_for(oid: &str) -> Option<(&'static aws_lc_rs::cipher::Algorithm, usize)> {
    match oid {
        oids::AES128_CBC => Some((&AES_128, 16)),
        oids::AES192_CBC => Some((&AES_192, 24)),
        oids::AES256_CBC => Some((&AES_256, 32)),
        _ => None,
    }
}

/// Open the envelope with the RA key (PKCS#8). Returns the content and the
/// content-encryption algorithm, for the reply.
pub fn open_envelope(envelope: &[u8], ra_key: &[u8]) -> Result<(Vec<u8>, String), CmsError> {
    let info = der::parse(envelope).map(|(n, _)| n).ok_or(CmsError::Undecodable)?;
    let ed = content_of(&info, oids::ENVELOPED_DATA).ok_or(CmsError::Undecodable)?;
    let mut rest = ed.children.iter().skip(1);
    let mut recipients = rest.next().ok_or(CmsError::Undecodable)?;
    if recipients.context() == Some(0) {
        recipients = rest.next().ok_or(CmsError::Undecodable)?; // originatorInfo
    }
    let eci = rest.next().ok_or(CmsError::Undecodable)?;
    let alg = eci.child(1).ok_or(CmsError::Undecodable)?;
    let alg_oid = alg.child(0).and_then(Node::oid).ok_or(CmsError::Undecodable)?;
    let (cipher, _) = aes_for(&alg_oid).ok_or_else(|| CmsError::UnsupportedAlgorithm(alg_oid.clone()))?;
    let iv: [u8; 16] = alg.child(1).map(Node::bytes).and_then(|b| b.try_into().ok()).ok_or(CmsError::Undecodable)?;
    let mut ciphertext =
        eci.child(2).filter(|n| n.context() == Some(0)).map(Node::bytes).ok_or(CmsError::Undecodable)?;

    let private = PrivateDecryptingKey::from_pkcs8(ra_key).map_err(|_| CmsError::Undecodable)?;
    let mut cek = None;
    for ri in &recipients.children {
        // KeyTransRecipientInfo: version, rid, keyEncryptionAlgorithm, encryptedKey.
        let (Some(kalg), Some(ek)) = (ri.child(2).and_then(|a| a.child(0)).and_then(Node::oid), ri.child(3)) else {
            continue;
        };
        let ek = ek.bytes();
        let mut out = vec![0u8; private.key_size_bytes()];
        let opened = match kalg.as_str() {
            oids::RSA_ENCRYPTION => Pkcs1PrivateDecryptingKey::new(private.clone())
                .ok()
                .and_then(|k| k.decrypt(&ek, &mut out).ok().map(|p| p.to_vec())),
            oids::RSAES_OAEP => OaepPrivateDecryptingKey::new(private.clone())
                .ok()
                .and_then(|k| k.decrypt(&OAEP_SHA1_MGF1SHA1, &ek, &mut out, None).ok().map(|p| p.to_vec())),
            other => return Err(CmsError::UnsupportedAlgorithm(other.to_string())),
        };
        if let Some(k) = opened {
            cek = Some(k);
            break;
        }
    }
    let cek = cek.ok_or(CmsError::Undecodable)?;
    let key = UnboundCipherKey::new(cipher, &cek).map_err(|_| CmsError::Undecodable)?;
    let key = PaddedBlockDecryptingKey::cbc_pkcs7(key).map_err(|_| CmsError::Undecodable)?;
    let plain = key
        .decrypt(&mut ciphertext, DecryptionContext::Iv128(FixedLength::from(iv)))
        .map_err(|_| CmsError::Undecodable)?
        .to_vec();
    Ok((plain, alg_oid))
}

/// Issuer and serial number of a certificate, as an IssuerAndSerialNumber.
fn issuer_and_serial(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    Some(der::seq(&[cert.issuer().as_raw().to_vec(), der::tlv(der::INTEGER, cert.raw_serial())]))
}

/// A certs-only (degenerate) SignedData ContentInfo, as `GetCACert` and
/// successful replies carry.
pub fn certs_only(certs: &[Vec<u8>]) -> Vec<u8> {
    let sd = der::seq(&[
        der::int(1),
        der::set(&[]),
        der::seq(&[der::oid(oids::DATA)]),
        der::implicit_constructed(0, &certs.concat()),
        der::set(&[]),
    ]);
    der::seq(&[der::oid(oids::SIGNED_DATA), der::explicit(0, &sd)])
}

/// Encrypt `content` for the holder of `recipient_cert` with `alg_oid`.
pub fn envelope_for(content: &[u8], recipient_cert: &[u8], alg_oid: &str) -> Result<Vec<u8>, CmsError> {
    let (_, cert) = X509Certificate::from_der(recipient_cert).map_err(|_| CmsError::NoCertificate)?;
    let public = PublicEncryptingKey::from_der(cert.public_key().raw).map_err(|_| CmsError::Unencodable)?;
    let public = Pkcs1PublicEncryptingKey::new(public).map_err(|_| CmsError::Unencodable)?;
    let alg_oid = if aes_for(alg_oid).is_some() { alg_oid } else { oids::AES256_CBC };
    let (cipher, key_len) = aes_for(alg_oid).expect("known cipher");
    let rng = SystemRandom::new();
    let mut cek = vec![0u8; key_len];
    let mut iv = [0u8; 16];
    rng.fill(&mut cek).map_err(|_| CmsError::Unencodable)?;
    rng.fill(&mut iv).map_err(|_| CmsError::Unencodable)?;
    let key = UnboundCipherKey::new(cipher, &cek).map_err(|_| CmsError::Unencodable)?;
    let key = PaddedBlockEncryptingKey::cbc_pkcs7(key).map_err(|_| CmsError::Unencodable)?;
    let mut data = content.to_vec();
    key.less_safe_encrypt(&mut data, EncryptionContext::Iv128(FixedLength::from(iv)))
        .map_err(|_| CmsError::Unencodable)?;
    let mut encrypted_key = vec![0u8; public.ciphertext_size()];
    let ek = public.encrypt(&cek, &mut encrypted_key).map_err(|_| CmsError::Unencodable)?.to_vec();
    let ktri = der::seq(&[
        der::int(0),
        issuer_and_serial(recipient_cert).ok_or(CmsError::Unencodable)?,
        der::algorithm(oids::RSA_ENCRYPTION, Some(der::null())),
        der::octets(&ek),
    ]);
    let eci = der::seq(&[
        der::oid(oids::DATA),
        der::algorithm(alg_oid, Some(der::octets(&iv))),
        der::implicit_primitive(0, &data),
    ]);
    let ed = der::seq(&[der::int(0), der::set(&[ktri]), eci]);
    Ok(der::seq(&[der::oid(oids::ENVELOPED_DATA), der::explicit(0, &ed)]))
}

/// SCEP `pkiStatus` of a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Success, with the enveloped certs-only message.
    Success(Vec<u8>),
    /// Failure with a `failInfo` (0 badAlg, 1 badMessageCheck, 2
    /// badRequest, 3 badTime, 4 badCertId).
    Failure(u8),
}

/// A `CertRep` signed by the RA (`ra_key` PKCS#8, `ra_cert` DER).
pub fn cert_rep(
    req: &PkiMessage,
    reply: &Reply,
    ra_key: &[u8],
    ra_cert: &[u8],
    now: DateTime<Utc>,
) -> Result<Vec<u8>, CmsError> {
    let key = RsaKeyPair::from_pkcs8(ra_key).map_err(|_| CmsError::Unencodable)?;
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce).map_err(|_| CmsError::Unencodable)?;
    let econtent: Option<&[u8]> = match reply {
        Reply::Success(env) => Some(env),
        Reply::Failure(_) => None,
    };
    let attr = |oid: &str, value: Vec<u8>| der::seq(&[der::oid(oid), der::set(&[value])]);
    let mut attrs = vec![
        attr(oids::CONTENT_TYPE, der::oid(oids::DATA)),
        attr(oids::SIGNING_TIME, der::tlv(der::UTC_TIME, now.format("%y%m%d%H%M%SZ").to_string().as_bytes())),
        attr(oids::MESSAGE_DIGEST, der::octets(digest::digest(&digest::SHA256, econtent.unwrap_or_default()).as_ref())),
        attr(oids::MESSAGE_TYPE, der::printable("3")),
        attr(oids::TRANSACTION_ID, der::printable(&req.transaction_id)),
        attr(oids::SENDER_NONCE, der::octets(&nonce)),
        attr(oids::RECIPIENT_NONCE, der::octets(&req.sender_nonce)),
    ];
    match reply {
        Reply::Success(_) => attrs.push(attr(oids::PKI_STATUS, der::printable("0"))),
        Reply::Failure(info) => {
            attrs.push(attr(oids::PKI_STATUS, der::printable("2")));
            attrs.push(attr(oids::FAIL_INFO, der::printable(&info.to_string())));
        }
    }
    let attrs_set = der::set(&attrs);
    let mut sig = vec![0u8; key.public_modulus_len()];
    key.sign(&signature::RSA_PKCS1_SHA256, &rng, &attrs_set, &mut sig).map_err(|_| CmsError::Unencodable)?;
    let mut signed_attrs = attrs_set.clone();
    signed_attrs[0] = 0xa0;
    let signer_info = der::seq(&[
        der::int(1),
        issuer_and_serial(ra_cert).ok_or(CmsError::Unencodable)?,
        der::algorithm(oids::SHA256, None),
        signed_attrs,
        der::algorithm(oids::RSA_ENCRYPTION, Some(der::null())),
        der::octets(&sig),
    ]);
    let encap = match econtent {
        Some(c) => der::seq(&[der::oid(oids::DATA), der::explicit(0, &der::octets(c))]),
        None => der::seq(&[der::oid(oids::DATA)]),
    };
    let sd = der::seq(&[
        der::int(1),
        der::set(&[der::algorithm(oids::SHA256, None)]),
        encap,
        der::implicit_constructed(0, ra_cert),
        der::set(&[signer_info]),
    ]);
    Ok(der::seq(&[der::oid(oids::SIGNED_DATA), der::explicit(0, &sd)]))
}
