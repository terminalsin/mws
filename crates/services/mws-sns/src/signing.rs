//! Message signatures. SNS signs every message it delivers with an RSA key
//! whose certificate is published at `SigningCertURL`; `SignatureVersion`
//! 1 is SHA1withRSA and 2 is SHA256withRSA. The key is made on first use
//! and the certificate is served at `/_aws/sns/...pem`.

use std::sync::OnceLock;

use base64::Engine;
use num_bigint::BigUint;
use sha2::Digest;

struct Key {
    n: BigUint,
    d: BigUint,
    size: usize,
    cert_pem: String,
    id: String,
}

#[derive(Default)]
pub struct Signer {
    key: OnceLock<Key>,
}

const SHA1_PREFIX: &[u8] = &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
const SHA256_PREFIX: &[u8] =
    &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

impl Signer {
    fn key(&self) -> &Key {
        self.key.get_or_init(generate)
    }

    /// The base64 signature of `text` for `SignatureVersion` `version`.
    pub fn sign(&self, text: &str, version: &str) -> String {
        let key = self.key();
        let mut t = if version == "2" { SHA256_PREFIX.to_vec() } else { SHA1_PREFIX.to_vec() };
        if version == "2" {
            t.extend_from_slice(&sha2::Sha256::digest(text.as_bytes()));
        } else {
            t.extend_from_slice(&sha1::Sha1::digest(text.as_bytes()));
        }
        // EMSA-PKCS1-v1_5: 00 01 FF..FF 00 T
        let mut em = vec![0x00, 0x01];
        em.resize(key.size - t.len() - 1, 0xff);
        em.push(0x00);
        em.extend_from_slice(&t);
        let s = BigUint::from_bytes_be(&em).modpow(&key.d, &key.n).to_bytes_be();
        let mut out = vec![0u8; key.size - s.len()];
        out.extend_from_slice(&s);
        base64::engine::general_purpose::STANDARD.encode(out)
    }

    /// The path the certificate is served at.
    pub fn cert_path(&self) -> String {
        format!("{}SimpleNotificationService-{}.pem", crate::outbox::PREFIX, self.key().id)
    }

    pub fn cert_pem(&self, path: &str) -> Option<String> {
        let key = self.key();
        (path == self.cert_path()).then(|| key.cert_pem.clone())
    }
}

fn generate() -> Key {
    let pair = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        .expect("RSA key generation works");
    let mut params = rcgen::CertificateParams::new(vec!["sns.amazonaws.com".to_string()]).expect("valid SAN");
    params.distinguished_name.push(rcgen::DnType::CommonName, "sns.amazonaws.com");
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "MWS");
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2049, 12, 31);
    let cert = params.self_signed(&pair).expect("self-signed certificate");
    let (n, d) = rsa_private(&pair.serialize_der()).expect("rcgen writes PKCS#8 RSA keys");
    let size = n.bits().div_ceil(8) as usize;
    let digest = sha2::Sha256::digest(cert.der());
    Key { n, d, size, cert_pem: cert.pem(), id: digest[..16].iter().map(|b| format!("{b:02x}")).collect() }
}

/// `(n, d)` from a PKCS#8 `PrivateKeyInfo` holding an `RSAPrivateKey`.
fn rsa_private(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let (_, info, _) = tlv(der)?;
    let (_, _version, rest) = tlv(info)?;
    let (_, _alg, rest) = tlv(rest)?;
    let (tag, octets, _) = tlv(rest)?;
    if tag != 0x04 {
        return None;
    }
    let (_, key, _) = tlv(octets)?;
    let (_, _v, rest) = tlv(key)?;
    let (_, n, rest) = tlv(rest)?;
    let (_, _e, rest) = tlv(rest)?;
    let (_, d, _) = tlv(rest)?;
    Some((BigUint::from_bytes_be(n), BigUint::from_bytes_be(d)))
}

/// One DER element: `(tag, contents, rest)`.
fn tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *buf.get(2 + i)? as usize;
        }
        (len, 2 + count)
    };
    let contents = buf.get(header..header + len)?;
    Some((tag, contents, &buf[header + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_with_the_certificate() {
        use x509_parser::prelude::*;
        let signer = Signer::default();
        let text =
            "Message\nhello\nMessageId\n1\nTimestamp\n2026-01-01T00:00:00.000Z\nTopicArn\narn\nType\nNotification\n";
        let pem = signer.cert_pem(&signer.cert_path()).unwrap();
        let (_, pem) = parse_x509_pem(pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        let spki = cert.public_key().raw.to_vec();
        for (version, alg) in [
            ("1", &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
            ("2", &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256),
        ] {
            let sig = base64::engine::general_purpose::STANDARD.decode(signer.sign(text, version)).unwrap();
            let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki).unwrap();
            let key = aws_lc_rs::signature::UnparsedPublicKey::new(alg, spki.subject_public_key.data.to_vec());
            key.verify(text.as_bytes(), &sig).unwrap();
        }
    }
}
