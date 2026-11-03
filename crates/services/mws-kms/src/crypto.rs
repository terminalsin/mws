//! The cryptography behind KMS keys, all done with aws-lc-rs: AES-256-GCM
//! for symmetric keys, RSA (OAEP, PKCS#1 v1.5, PSS), ECDSA, Ed25519,
//! ML-DSA, HMAC, ECDH and ML-KEM.

use std::collections::BTreeMap;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::agreement;
use aws_lc_rs::digest::{self, Digest};
use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use aws_lc_rs::hmac;
use aws_lc_rs::kem;
use aws_lc_rs::key_wrap::{AesKek, KeyWrapPadded, AES_256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::{
    KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, Pkcs1PrivateDecryptingKey, Pkcs1PublicEncryptingKey,
    PrivateDecryptingKey, OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256,
};
use aws_lc_rs::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, PqdsaKeyPair, RsaKeyPair, UnparsedPublicKey};
use mws_core::ServiceError;

use crate::generated::errors;

/// Bytes every MWS symmetric ciphertext starts with. Real KMS ciphertexts
/// start the same way (`AQICAHg` in base64).
const HEADER: [u8; 5] = [0x01, 0x02, 0x02, 0x00, 0x78];
const TAG_LEN: usize = 16;

fn internal() -> ServiceError {
    errors::kms_internal("An internal error occurred while performing the cryptographic operation.")
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    SystemRandom::new().fill(&mut out).expect("system random is available");
    out
}

pub fn random_hex(n: usize) -> String {
    hex(&random_bytes(n))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

// ---- key specs --------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spec {
    Symmetric,
    Rsa(usize),
    Ecc(Curve),
    Ed25519,
    Hmac(usize),
    MlDsa(u8),
    MlKem(u16),
    Sm2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
    Secp256k1,
}

impl Spec {
    pub fn parse(spec: &str) -> Option<Spec> {
        Some(match spec {
            "SYMMETRIC_DEFAULT" => Spec::Symmetric,
            "RSA_2048" => Spec::Rsa(2048),
            "RSA_3072" => Spec::Rsa(3072),
            "RSA_4096" => Spec::Rsa(4096),
            "ECC_NIST_P256" => Spec::Ecc(Curve::P256),
            "ECC_NIST_P384" => Spec::Ecc(Curve::P384),
            "ECC_NIST_P521" => Spec::Ecc(Curve::P521),
            "ECC_SECG_P256K1" => Spec::Ecc(Curve::Secp256k1),
            "ECC_NIST_EDWARDS25519" => Spec::Ed25519,
            "HMAC_224" => Spec::Hmac(224),
            "HMAC_256" => Spec::Hmac(256),
            "HMAC_384" => Spec::Hmac(384),
            "HMAC_512" => Spec::Hmac(512),
            "ML_DSA_44" => Spec::MlDsa(44),
            "ML_DSA_65" => Spec::MlDsa(65),
            "ML_DSA_87" => Spec::MlDsa(87),
            "ML_KEM_512" => Spec::MlKem(512),
            "ML_KEM_768" => Spec::MlKem(768),
            "ML_KEM_1024" => Spec::MlKem(1024),
            "SM2" => Spec::Sm2,
            _ => return None,
        })
    }

    /// Key usages KMS allows for this spec.
    pub fn usages(self) -> &'static [&'static str] {
        match self {
            Spec::Symmetric => &["ENCRYPT_DECRYPT"],
            Spec::Rsa(_) => &["ENCRYPT_DECRYPT", "SIGN_VERIFY"],
            Spec::Ecc(Curve::Secp256k1) | Spec::Ed25519 | Spec::MlDsa(_) => &["SIGN_VERIFY"],
            Spec::Ecc(_) => &["SIGN_VERIFY", "KEY_AGREEMENT"],
            Spec::Hmac(_) => &["GENERATE_VERIFY_MAC"],
            Spec::MlKem(_) => &["ENCAPSULATE_DECAPSULATE"],
            Spec::Sm2 => &["ENCRYPT_DECRYPT", "SIGN_VERIFY", "KEY_AGREEMENT"],
        }
    }

    pub fn encryption_algorithms(self) -> Vec<String> {
        let v: &[&str] = match self {
            Spec::Symmetric => &["SYMMETRIC_DEFAULT"],
            Spec::Rsa(_) => &["RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"],
            Spec::Sm2 => &["SM2PKE"],
            _ => &[],
        };
        v.iter().map(|s| s.to_string()).collect()
    }

    pub fn signing_algorithms(self) -> Vec<String> {
        let v: &[&str] = match self {
            Spec::Rsa(_) => &[
                "RSASSA_PKCS1_V1_5_SHA_256",
                "RSASSA_PKCS1_V1_5_SHA_384",
                "RSASSA_PKCS1_V1_5_SHA_512",
                "RSASSA_PSS_SHA_256",
                "RSASSA_PSS_SHA_384",
                "RSASSA_PSS_SHA_512",
            ],
            Spec::Ecc(Curve::P256) | Spec::Ecc(Curve::Secp256k1) => &["ECDSA_SHA_256"],
            Spec::Ecc(Curve::P384) => &["ECDSA_SHA_384"],
            Spec::Ecc(Curve::P521) => &["ECDSA_SHA_512"],
            Spec::Ed25519 => &["ED25519_SHA_512", "ED25519_PH_SHA_512"],
            Spec::MlDsa(_) => &["ML_DSA_SHAKE_256"],
            Spec::Sm2 => &["SM2DSA"],
            _ => &[],
        };
        v.iter().map(|s| s.to_string()).collect()
    }

    pub fn mac_algorithms(self) -> Vec<String> {
        match self {
            Spec::Hmac(bits) => vec![format!("HMAC_SHA_{bits}")],
            _ => vec![],
        }
    }

    pub fn is_asymmetric(self) -> bool {
        !matches!(self, Spec::Symmetric | Spec::Hmac(_))
    }
}

fn ecdsa_alg(curve: Curve) -> &'static signature::EcdsaSigningAlgorithm {
    match curve {
        Curve::P256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        Curve::P384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        Curve::P521 => &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        Curve::Secp256k1 => &signature::ECDSA_P256K1_SHA256_ASN1_SIGNING,
    }
}

fn mldsa_alg(level: u8) -> &'static signature::PqdsaSigningAlgorithm {
    match level {
        44 => &signature::ML_DSA_44_SIGNING,
        65 => &signature::ML_DSA_65_SIGNING,
        _ => &signature::ML_DSA_87_SIGNING,
    }
}

fn mlkem_alg(level: u16) -> &'static kem::Algorithm {
    match level {
        512 => &kem::ML_KEM_512,
        768 => &kem::ML_KEM_768,
        _ => &kem::ML_KEM_1024,
    }
}

fn rsa_size(bits: usize) -> KeySize {
    match bits {
        2048 => KeySize::Rsa2048,
        3072 => KeySize::Rsa3072,
        _ => KeySize::Rsa4096,
    }
}

fn unsupported_sm2() -> ServiceError {
    errors::unsupported_operation("SM2 key specs are only supported in the AWS China Regions.")
}

/// New key material for `spec`.
pub fn generate(spec: Spec) -> Result<Vec<u8>, ServiceError> {
    Ok(match spec {
        Spec::Symmetric => random_bytes(32),
        Spec::Hmac(bits) => random_bytes(bits / 8),
        Spec::Rsa(bits) => {
            let kp = RsaKeyPair::generate(rsa_size(bits)).map_err(|_| internal())?;
            AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&kp).map_err(|_| internal())?.as_ref().to_vec()
        }
        Spec::Ecc(curve) => {
            let kp = EcdsaKeyPair::generate(ecdsa_alg(curve)).map_err(|_| internal())?;
            kp.to_pkcs8v1().map_err(|_| internal())?.as_ref().to_vec()
        }
        Spec::Ed25519 => {
            let kp = Ed25519KeyPair::generate().map_err(|_| internal())?;
            kp.to_pkcs8v1().map_err(|_| internal())?.as_ref().to_vec()
        }
        Spec::MlDsa(level) => {
            let kp = PqdsaKeyPair::generate(mldsa_alg(level)).map_err(|_| internal())?;
            kp.to_pkcs8v1().map_err(|_| internal())?.as_ref().to_vec()
        }
        Spec::MlKem(level) => {
            let dk = kem::DecapsulationKey::generate(mlkem_alg(level)).map_err(|_| internal())?;
            dk.key_bytes().map_err(|_| internal())?.as_ref().to_vec()
        }
        Spec::Sm2 => return Err(unsupported_sm2()),
    })
}

/// Check that imported material fits `spec`.
pub fn validate_material(spec: Spec, material: &[u8]) -> bool {
    match spec {
        Spec::Symmetric => material.len() == 32,
        Spec::Hmac(bits) => material.len() == bits / 8,
        _ => public_key_der(spec, material).is_ok(),
    }
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

/// SubjectPublicKeyInfo for a raw ML-KEM encapsulation key (FIPS 203 OIDs
/// 2.16.840.1.101.3.4.4.{1,2,3}).
fn mlkem_spki(level: u16, raw: &[u8]) -> Vec<u8> {
    let last = match level {
        512 => 1,
        768 => 2,
        _ => 3,
    };
    let oid = der(0x06, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, last]);
    let alg = der(0x30, &oid);
    let mut bits = vec![0u8];
    bits.extend_from_slice(raw);
    der(0x30, &[alg, der(0x03, &bits)].concat())
}

fn x509(der: Result<PublicKeyX509Der<'static>, aws_lc_rs::error::Unspecified>) -> Result<Vec<u8>, ServiceError> {
    Ok(der.map_err(|_| internal())?.as_ref().to_vec())
}

/// The DER SubjectPublicKeyInfo for an asymmetric key, as `GetPublicKey`
/// returns it.
pub fn public_key_der(spec: Spec, material: &[u8]) -> Result<Vec<u8>, ServiceError> {
    let bad = || errors::kms_internal("The key material is not valid for its key spec.");
    match spec {
        Spec::Rsa(_) => {
            let kp = RsaKeyPair::from_pkcs8(material).map_err(|_| bad())?;
            x509(kp.public_key().as_der())
        }
        Spec::Ecc(curve) => {
            let kp = EcdsaKeyPair::from_pkcs8(ecdsa_alg(curve), material).map_err(|_| bad())?;
            x509(kp.public_key().as_der())
        }
        Spec::Ed25519 => {
            let kp = Ed25519KeyPair::from_pkcs8(material).map_err(|_| bad())?;
            x509(kp.public_key().as_der())
        }
        Spec::MlDsa(level) => {
            let kp = PqdsaKeyPair::from_pkcs8(mldsa_alg(level), material).map_err(|_| bad())?;
            x509(kp.public_key().as_der())
        }
        Spec::MlKem(level) => {
            let ek = mlkem_encapsulation_key(level, material).ok_or_else(bad)?;
            Ok(mlkem_spki(level, ek.key_bytes().map_err(|_| internal())?.as_ref()))
        }
        Spec::Sm2 => Err(unsupported_sm2()),
        Spec::Symmetric | Spec::Hmac(_) => {
            Err(errors::unsupported_operation("You cannot perform this operation on a symmetric or HMAC KMS key."))
        }
    }
}

/// The raw uncompressed EC point of a P-256 key (for DNSSEC).
pub fn ec_public_point(spec: Spec, material: &[u8]) -> Option<Vec<u8>> {
    let Spec::Ecc(curve) = spec else { return None };
    let kp = EcdsaKeyPair::from_pkcs8(ecdsa_alg(curve), material).ok()?;
    Some(kp.public_key().as_ref().to_vec())
}

// ---- symmetric ciphertexts --------------------------------------------------

/// Everything a symmetric ciphertext carries in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextHeader {
    pub account: String,
    pub key_id: String,
    pub material_id: String,
}

/// Encryption context in a canonical byte form, bound into the AAD.
pub fn canonical_context(ctx: &BTreeMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend((ctx.len() as u16).to_be_bytes());
    for (k, v) in ctx {
        out.extend((k.len() as u16).to_be_bytes());
        out.extend(k.as_bytes());
        out.extend((v.len() as u16).to_be_bytes());
        out.extend(v.as_bytes());
    }
    out
}

fn header_bytes(h: &CiphertextHeader) -> Vec<u8> {
    let mut out = HEADER.to_vec();
    out.push(h.account.len() as u8);
    out.extend(h.account.as_bytes());
    out.push(h.key_id.len() as u8);
    out.extend(h.key_id.as_bytes());
    out.extend(unhex(&h.material_id).unwrap_or_else(|| vec![0; 32]));
    out
}

/// Encrypt under a symmetric key: header, nonce, AES-256-GCM output.
pub fn seal(
    header: &CiphertextHeader,
    key: &[u8],
    context: &BTreeMap<String, String>,
    plaintext: &[u8],
) -> Result<Vec<u8>, ServiceError> {
    let head = header_bytes(header);
    let aad = [head.as_slice(), &canonical_context(context)].concat();
    let nonce_bytes = random_bytes(NONCE_LEN);
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| internal())?);
    let mut buf = plaintext.to_vec();
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| internal())?;
    key.seal_in_place_append_tag(nonce, Aad::from(aad.as_slice()), &mut buf).map_err(|_| internal())?;
    Ok([head, nonce_bytes, buf].concat())
}

/// Read the clear header of a symmetric ciphertext.
pub fn parse_header(blob: &[u8]) -> Option<(CiphertextHeader, usize)> {
    let rest = blob.strip_prefix(&HEADER)?;
    let (alen, rest) = rest.split_first()?;
    let account = std::str::from_utf8(rest.get(..*alen as usize)?).ok()?.to_string();
    let rest = &rest[*alen as usize..];
    let (klen, rest) = rest.split_first()?;
    let key_id = std::str::from_utf8(rest.get(..*klen as usize)?).ok()?.to_string();
    let rest = &rest[*klen as usize..];
    let material_id = hex(rest.get(..32)?);
    let used = HEADER.len() + 1 + *alen as usize + 1 + *klen as usize + 32;
    if blob.len() < used + NONCE_LEN + TAG_LEN {
        return None;
    }
    Some((CiphertextHeader { account, key_id, material_id }, used))
}

/// Decrypt a symmetric ciphertext whose header was already parsed.
pub fn open(blob: &[u8], header_len: usize, key: &[u8], context: &BTreeMap<String, String>) -> Option<Vec<u8>> {
    let head = &blob[..header_len];
    let nonce = Nonce::try_assume_unique_for_key(&blob[header_len..header_len + NONCE_LEN]).ok()?;
    let aad = [head, &canonical_context(context)].concat();
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let mut buf = blob[header_len + NONCE_LEN..].to_vec();
    let plain = key.open_in_place(nonce, Aad::from(aad.as_slice()), &mut buf).ok()?;
    Some(plain.to_vec())
}

// ---- RSA encryption ---------------------------------------------------------

/// Largest plaintext `algorithm` accepts for an RSA key of `bits`.
pub fn rsa_max_plaintext(bits: usize, algorithm: &str) -> usize {
    let k = bits / 8;
    match algorithm {
        "RSAES_OAEP_SHA_1" => k - 2 * 20 - 2,
        _ => k - 2 * 32 - 2,
    }
}

pub fn rsa_encrypt(material: &[u8], algorithm: &str, plaintext: &[u8]) -> Result<Vec<u8>, ServiceError> {
    let private = PrivateDecryptingKey::from_pkcs8(material).map_err(|_| internal())?;
    let public = OaepPublicEncryptingKey::new(private.public_key()).map_err(|_| internal())?;
    let alg = if algorithm == "RSAES_OAEP_SHA_1" { &OAEP_SHA1_MGF1SHA1 } else { &OAEP_SHA256_MGF1SHA256 };
    let mut out = vec![0u8; public.ciphertext_size()];
    let n = public.encrypt(alg, plaintext, &mut out, None).map_err(|_| internal())?.len();
    out.truncate(n);
    Ok(out)
}

pub fn rsa_decrypt(material: &[u8], algorithm: &str, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let private = PrivateDecryptingKey::from_pkcs8(material).ok()?;
    let mut out = vec![0u8; ciphertext.len().max(1024)];
    match algorithm {
        "RSAES_OAEP_SHA_1" | "RSAES_OAEP_SHA_256" => {
            let alg = if algorithm == "RSAES_OAEP_SHA_1" { &OAEP_SHA1_MGF1SHA1 } else { &OAEP_SHA256_MGF1SHA256 };
            let key = OaepPrivateDecryptingKey::new(private).ok()?;
            let n = key.decrypt(alg, ciphertext, &mut out, None).ok()?.len();
            out.truncate(n);
        }
        "RSAES_PKCS1_V1_5" => {
            let key = Pkcs1PrivateDecryptingKey::new(private).ok()?;
            let n = key.decrypt(ciphertext, &mut out).ok()?.len();
            out.truncate(n);
        }
        _ => return None,
    }
    Some(out)
}

/// Encrypt with an RSA public key, as a client wrapping key material for
/// import does. Used by tests.
pub fn rsa_public_encrypt(public_der: &[u8], algorithm: &str, plaintext: &[u8]) -> Option<Vec<u8>> {
    let public = aws_lc_rs::rsa::PublicEncryptingKey::from_der(public_der).ok()?;
    if algorithm == "RSAES_PKCS1_V1_5" {
        let key = Pkcs1PublicEncryptingKey::new(public).ok()?;
        let mut out = vec![0u8; key.ciphertext_size()];
        let n = key.encrypt(plaintext, &mut out).ok()?.len();
        out.truncate(n);
        return Some(out);
    }
    let key = OaepPublicEncryptingKey::new(public).ok()?;
    let alg = if algorithm.ends_with("SHA_1") { &OAEP_SHA1_MGF1SHA1 } else { &OAEP_SHA256_MGF1SHA256 };
    let mut out = vec![0u8; key.ciphertext_size()];
    let n = key.encrypt(alg, plaintext, &mut out, None).ok()?.len();
    out.truncate(n);
    Some(out)
}

/// Unwrap key material sent to `ImportKeyMaterial`.
pub fn unwrap_import(wrapping_key: &[u8], algorithm: &str, blob: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        "RSA_AES_KEY_WRAP_SHA_1" | "RSA_AES_KEY_WRAP_SHA_256" => {
            let private = PrivateDecryptingKey::from_pkcs8(wrapping_key).ok()?;
            let k = private.key_size_bytes();
            if blob.len() <= k {
                return None;
            }
            let oaep = if algorithm.ends_with("SHA_1") { "RSAES_OAEP_SHA_1" } else { "RSAES_OAEP_SHA_256" };
            let aes = rsa_decrypt(wrapping_key, oaep, &blob[..k])?;
            let kek = AesKek::new(&AES_256, &aes).ok()?;
            let mut out = vec![0u8; blob.len()];
            let n = kek.unwrap_with_padding(&blob[k..], &mut out).ok()?.len();
            out.truncate(n);
            Some(out)
        }
        other => rsa_decrypt(wrapping_key, other, blob),
    }
}

/// Wrap material the way the AWS docs tell clients to for
/// `RSA_AES_KEY_WRAP_SHA_*`. Used by tests.
pub fn wrap_import(public_der: &[u8], algorithm: &str, material: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        "RSA_AES_KEY_WRAP_SHA_1" | "RSA_AES_KEY_WRAP_SHA_256" => {
            let aes = random_bytes(32);
            let oaep = if algorithm.ends_with("SHA_1") { "RSAES_OAEP_SHA_1" } else { "RSAES_OAEP_SHA_256" };
            let wrapped_key = rsa_public_encrypt(public_der, oaep, &aes)?;
            let kek = AesKek::new(&AES_256, &aes).ok()?;
            let mut out = vec![0u8; material.len() + 16];
            let n = kek.wrap_with_padding(material, &mut out).ok()?.len();
            out.truncate(n);
            Some([wrapped_key, out].concat())
        }
        other => rsa_public_encrypt(public_der, other, material),
    }
}

// ---- signatures -------------------------------------------------------------

fn digest_alg(signing_algorithm: &str) -> &'static digest::Algorithm {
    if signing_algorithm.ends_with("384") {
        &digest::SHA384
    } else if signing_algorithm.ends_with("512") {
        &digest::SHA512
    } else {
        &digest::SHA256
    }
}

fn rsa_encoding(alg: &str) -> &'static dyn signature::RsaEncoding {
    match alg {
        "RSASSA_PSS_SHA_256" => &signature::RSA_PSS_SHA256,
        "RSASSA_PSS_SHA_384" => &signature::RSA_PSS_SHA384,
        "RSASSA_PSS_SHA_512" => &signature::RSA_PSS_SHA512,
        "RSASSA_PKCS1_V1_5_SHA_384" => &signature::RSA_PKCS1_SHA384,
        "RSASSA_PKCS1_V1_5_SHA_512" => &signature::RSA_PKCS1_SHA512,
        _ => &signature::RSA_PKCS1_SHA256,
    }
}

fn rsa_verification(alg: &str) -> &'static signature::RsaParameters {
    match alg {
        "RSASSA_PSS_SHA_256" => &signature::RSA_PSS_2048_8192_SHA256,
        "RSASSA_PSS_SHA_384" => &signature::RSA_PSS_2048_8192_SHA384,
        "RSASSA_PSS_SHA_512" => &signature::RSA_PSS_2048_8192_SHA512,
        "RSASSA_PKCS1_V1_5_SHA_384" => &signature::RSA_PKCS1_2048_8192_SHA384,
        "RSASSA_PKCS1_V1_5_SHA_512" => &signature::RSA_PKCS1_2048_8192_SHA512,
        _ => &signature::RSA_PKCS1_2048_8192_SHA256,
    }
}

fn ecdsa_verification(curve: Curve) -> &'static signature::EcdsaVerificationAlgorithm {
    match curve {
        Curve::P256 => &signature::ECDSA_P256_SHA256_ASN1,
        Curve::P384 => &signature::ECDSA_P384_SHA384_ASN1,
        Curve::P521 => &signature::ECDSA_P521_SHA512_ASN1,
        Curve::Secp256k1 => &signature::ECDSA_P256K1_SHA256_ASN1,
    }
}

/// A message to sign or verify: the message itself, or its digest.
pub enum Message<'a> {
    Raw(&'a [u8]),
    Digest(&'a [u8]),
}

fn imported_digest(alg: &str, d: &[u8]) -> Result<Digest, ServiceError> {
    let a = digest_alg(alg);
    Digest::import_less_safe(d, a).map_err(|_| {
        ServiceError::client(
            "ValidationException",
            400,
            format!(
                "Digest is invalid length for algorithm {alg}. Expected {} bytes, got {} bytes.",
                a.output_len(),
                d.len()
            ),
        )
    })
}

pub fn sign(spec: Spec, material: &[u8], alg: &str, message: Message<'_>) -> Result<Vec<u8>, ServiceError> {
    match spec {
        Spec::Rsa(_) => {
            let kp = RsaKeyPair::from_pkcs8(material).map_err(|_| internal())?;
            let mut sig = vec![0u8; kp.public_modulus_len()];
            match message {
                Message::Raw(m) => {
                    kp.sign(rsa_encoding(alg), &SystemRandom::new(), m, &mut sig).map_err(|_| internal())?
                }
                Message::Digest(d) => {
                    kp.sign_digest(rsa_encoding(alg), &imported_digest(alg, d)?, &mut sig).map_err(|_| internal())?
                }
            }
            Ok(sig)
        }
        Spec::Ecc(curve) => {
            let kp = EcdsaKeyPair::from_pkcs8(ecdsa_alg(curve), material).map_err(|_| internal())?;
            let sig = match message {
                Message::Raw(m) => kp.sign(&SystemRandom::new(), m).map_err(|_| internal())?,
                Message::Digest(d) => kp.sign_digest(&imported_digest(alg, d)?).map_err(|_| internal())?,
            };
            Ok(sig.as_ref().to_vec())
        }
        Spec::Ed25519 => {
            let kp = Ed25519KeyPair::from_pkcs8(material).map_err(|_| internal())?;
            match (alg, message) {
                ("ED25519_SHA_512", Message::Raw(m)) => Ok(kp.sign(m).as_ref().to_vec()),
                _ => Err(ServiceError::client(
                    "ValidationException",
                    400,
                    format!("MWS supports {alg} only with MessageType RAW and ED25519_SHA_512."),
                )),
            }
        }
        Spec::MlDsa(level) => {
            let Message::Raw(m) = message else {
                return Err(ServiceError::client(
                    "ValidationException",
                    400,
                    "ML_DSA_SHAKE_256 supports MessageType RAW and EXTERNAL_MU; MWS supports RAW.",
                ));
            };
            let kp = PqdsaKeyPair::from_pkcs8(mldsa_alg(level), material).map_err(|_| internal())?;
            let mut sig = vec![0u8; mldsa_alg(level).signature_len()];
            let n = kp.sign(m, &mut sig).map_err(|_| internal())?;
            sig.truncate(n);
            Ok(sig)
        }
        _ => Err(internal()),
    }
}

/// Whether `sig` is a valid signature. Errors only for bad inputs.
pub fn verify(spec: Spec, material: &[u8], alg: &str, message: Message<'_>, sig: &[u8]) -> Result<bool, ServiceError> {
    let public_raw: Vec<u8>;
    let verifier: &'static dyn signature::VerificationAlgorithm = match spec {
        Spec::Rsa(_) => {
            let kp = RsaKeyPair::from_pkcs8(material).map_err(|_| internal())?;
            public_raw = kp.public_key().as_ref().to_vec();
            rsa_verification(alg)
        }
        Spec::Ecc(curve) => {
            let kp = EcdsaKeyPair::from_pkcs8(ecdsa_alg(curve), material).map_err(|_| internal())?;
            public_raw = kp.public_key().as_ref().to_vec();
            ecdsa_verification(curve)
        }
        Spec::Ed25519 => {
            let kp = Ed25519KeyPair::from_pkcs8(material).map_err(|_| internal())?;
            public_raw = kp.public_key().as_ref().to_vec();
            if alg != "ED25519_SHA_512" || matches!(message, Message::Digest(_)) {
                return Err(ServiceError::client(
                    "ValidationException",
                    400,
                    format!("MWS supports {alg} only with MessageType RAW and ED25519_SHA_512."),
                ));
            }
            &signature::ED25519
        }
        Spec::MlDsa(level) => {
            let kp = PqdsaKeyPair::from_pkcs8(mldsa_alg(level), material).map_err(|_| internal())?;
            public_raw = kp.public_key().as_ref().to_vec();
            match level {
                44 => &signature::ML_DSA_44,
                65 => &signature::ML_DSA_65,
                _ => &signature::ML_DSA_87,
            }
        }
        _ => return Err(internal()),
    };
    let key = UnparsedPublicKey::new(verifier, public_raw);
    Ok(match message {
        Message::Raw(m) => key.verify(m, sig).is_ok(),
        Message::Digest(d) => {
            let d = imported_digest(alg, d)?;
            verifier.verify_digest_sig(key.as_ref(), &d, sig).is_ok()
        }
    })
}

// ---- HMAC -------------------------------------------------------------------

pub fn mac(key: &[u8], alg: &str, message: &[u8]) -> Vec<u8> {
    let a = match alg {
        "HMAC_SHA_224" => hmac::HMAC_SHA224,
        "HMAC_SHA_384" => hmac::HMAC_SHA384,
        "HMAC_SHA_512" => hmac::HMAC_SHA512,
        _ => hmac::HMAC_SHA256,
    };
    hmac::sign(&hmac::Key::new(a, key), message).as_ref().to_vec()
}

// ---- key agreement and KEM --------------------------------------------------

pub fn derive_shared_secret(curve: Curve, material: &[u8], peer_der: &[u8]) -> Result<Vec<u8>, ServiceError> {
    let alg = match curve {
        Curve::P256 => &agreement::ECDH_P256,
        Curve::P384 => &agreement::ECDH_P384,
        Curve::P521 => &agreement::ECDH_P521,
        Curve::Secp256k1 => return Err(internal()),
    };
    let private = agreement::PrivateKey::from_private_key_der(alg, material).map_err(|_| internal())?;
    let peer = agreement::UnparsedPublicKey::new(alg, peer_der);
    agreement::agree(&private, peer, (), |s| Ok(s.to_vec())).map_err(|_| {
        ServiceError::client(
            "ValidationException",
            400,
            "The PublicKey is not a valid DER-encoded X.509 public key for the KMS key's curve.",
        )
    })
}

pub fn encapsulate(level: u16, material: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ServiceError> {
    let ek = mlkem_encapsulation_key(level, material).ok_or_else(internal)?;
    let (ct, ss) = ek.encapsulate().map_err(|_| internal())?;
    Ok((ss.as_ref().to_vec(), ct.as_ref().to_vec()))
}

/// The encapsulation key inside an expanded FIPS 203 decapsulation key
/// (`dk = dk_PKE || ek || H(ek) || z`, with `ek` at offset 384k).
fn mlkem_encapsulation_key(level: u16, material: &[u8]) -> Option<kem::EncapsulationKey> {
    let k = match level {
        512 => 2,
        768 => 3,
        _ => 4,
    };
    let ek = material.get(384 * k..384 * k + 384 * k + 32)?;
    kem::EncapsulationKey::new(mlkem_alg(level), ek).ok()
}

pub fn decapsulate(level: u16, material: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let dk = kem::DecapsulationKey::new(mlkem_alg(level), material).ok()?;
    let ss = dk.decapsulate(kem::Ciphertext::from(ciphertext)).ok()?;
    Some(ss.as_ref().to_vec())
}

// ---- data key pairs ---------------------------------------------------------

/// A fresh key pair for `GenerateDataKeyPair`: PKCS#8 private key and DER
/// SubjectPublicKeyInfo.
pub fn data_key_pair(spec: Spec) -> Result<(Vec<u8>, Vec<u8>), ServiceError> {
    match spec {
        Spec::Rsa(_) | Spec::Ecc(_) | Spec::Ed25519 | Spec::MlDsa(_) => {
            let private = generate(spec)?;
            let public = public_key_der(spec, &private)?;
            Ok((private, public))
        }
        Spec::Sm2 => Err(unsupported_sm2()),
        _ => Err(internal()),
    }
}

/// Key material ids are 64 hex characters; KMS derives them from the
/// material, so the same imported material always gets the same id.
pub fn material_id(material: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, &[b"mws-kms-material".as_slice(), material].concat()).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_round_trip_binds_context() {
        let key = generate(Spec::Symmetric).unwrap();
        let h = CiphertextHeader {
            account: "123456789012".into(),
            key_id: "1234abcd-12ab-34cd-56ef-1234567890ab".into(),
            material_id: material_id(&key),
        };
        let mut ctx = BTreeMap::new();
        ctx.insert("purpose".to_string(), "test".to_string());
        let blob = seal(&h, &key, &ctx, b"hello").unwrap();
        let (parsed, len) = parse_header(&blob).unwrap();
        assert_eq!(parsed, h);
        assert_eq!(open(&blob, len, &key, &ctx).unwrap(), b"hello");
        assert!(open(&blob, len, &key, &BTreeMap::new()).is_none());
    }

    #[test]
    fn every_signing_spec_signs_and_verifies() {
        for (spec, alg) in [
            ("RSA_2048", "RSASSA_PSS_SHA_256"),
            ("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_512"),
            ("ECC_NIST_P256", "ECDSA_SHA_256"),
            ("ECC_NIST_P384", "ECDSA_SHA_384"),
            ("ECC_NIST_P521", "ECDSA_SHA_512"),
            ("ECC_SECG_P256K1", "ECDSA_SHA_256"),
            ("ECC_NIST_EDWARDS25519", "ED25519_SHA_512"),
            ("ML_DSA_44", "ML_DSA_SHAKE_256"),
        ] {
            let s = Spec::parse(spec).unwrap();
            let m = generate(s).unwrap();
            let sig = sign(s, &m, alg, Message::Raw(b"msg")).unwrap();
            assert!(verify(s, &m, alg, Message::Raw(b"msg"), &sig).unwrap(), "{spec}");
            assert!(!verify(s, &m, alg, Message::Raw(b"other"), &sig).unwrap(), "{spec}");
            public_key_der(s, &m).unwrap();
        }
    }

    #[test]
    fn digest_signatures_match_raw_ones() {
        let s = Spec::Ecc(Curve::P256);
        let m = generate(s).unwrap();
        let d = digest::digest(&digest::SHA256, b"msg");
        let sig = sign(s, &m, "ECDSA_SHA_256", Message::Digest(d.as_ref())).unwrap();
        assert!(verify(s, &m, "ECDSA_SHA_256", Message::Raw(b"msg"), &sig).unwrap());
    }

    #[test]
    fn import_wrapping_round_trips() {
        let wrapping = generate(Spec::Rsa(2048)).unwrap();
        let public = public_key_der(Spec::Rsa(2048), &wrapping).unwrap();
        let material = random_bytes(32);
        for alg in ["RSAES_OAEP_SHA_256", "RSAES_OAEP_SHA_1", "RSA_AES_KEY_WRAP_SHA_256", "RSAES_PKCS1_V1_5"] {
            let blob = wrap_import(&public, alg, &material).unwrap();
            assert_eq!(unwrap_import(&wrapping, alg, &blob).unwrap(), material, "{alg}");
        }
    }

    #[test]
    fn ml_kem_and_ecdh() {
        let m = generate(Spec::MlKem(768)).unwrap();
        let (ss, ct) = encapsulate(768, &m).unwrap();
        assert_eq!(decapsulate(768, &m, &ct).unwrap(), ss);
        public_key_der(Spec::MlKem(768), &m).unwrap();

        let a = generate(Spec::Ecc(Curve::P256)).unwrap();
        let b = generate(Spec::Ecc(Curve::P256)).unwrap();
        let pa = public_key_der(Spec::Ecc(Curve::P256), &a).unwrap();
        let pb = public_key_der(Spec::Ecc(Curve::P256), &b).unwrap();
        assert_eq!(
            derive_shared_secret(Curve::P256, &a, &pb).unwrap(),
            derive_shared_secret(Curve::P256, &b, &pa).unwrap()
        );
    }
}
