//! Key pairs: real RSA and ED25519 keys in the formats EC2 returns, OpenSSH
//! public keys, and EC2's fingerprints.

use aws_lc_rs::encoding::{AsBigEndian, AsDer};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine;
use md5::{Digest, Md5};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A key pair EC2 generated.
pub struct Generated {
    /// The private key as returned to the caller.
    pub material: String,
    /// OpenSSH `authorized_keys` line.
    pub public_key: String,
    pub fingerprint: String,
}

/// A key the caller imported.
pub struct Imported {
    pub key_type: &'static str,
    pub public_key: String,
    pub fingerprint: String,
}

// ---- generation -------------------------------------------------------------------

pub fn generate_rsa() -> Result<Generated, String> {
    let kp = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).map_err(|e| e.to_string())?;
    let pkcs8 = kp.as_der().map_err(|e| e.to_string())?;
    let pkcs8 = pkcs8.as_ref();
    let pkcs1 = pkcs8_inner(pkcs8).ok_or("unexpected PKCS#8 encoding")?;
    let (n, e) = rsa_public_numbers(kp.public_key().as_ref()).ok_or("unexpected public key encoding")?;
    let sha1 = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, pkcs8);
    Ok(Generated {
        material: pem("RSA PRIVATE KEY", pkcs1, 64),
        public_key: format!("ssh-rsa {}", B64.encode(ssh_rsa_blob(&e, &n))),
        fingerprint: colon_hex(sha1.as_ref()),
    })
}

pub fn generate_ed25519() -> Result<Generated, String> {
    let kp = aws_lc_rs::signature::Ed25519KeyPair::generate().map_err(|e| e.to_string())?;
    let public: Vec<u8> = kp.public_key().as_ref().to_vec();
    let seed = kp.seed().map_err(|e| e.to_string())?;
    let seed = seed.as_be_bytes().map_err(|e| e.to_string())?;
    let blob = ssh_ed25519_blob(&public);
    Ok(Generated {
        material: openssh_private_key(&blob, &public, seed.as_ref()),
        public_key: format!("ssh-ed25519 {}", B64.encode(&blob)),
        fingerprint: sha256_fingerprint(&blob),
    })
}

/// The OpenSSH private key format EC2 returns for ED25519 keys.
fn openssh_private_key(pub_blob: &[u8], public: &[u8], seed: &[u8]) -> String {
    let check: u32 = rand::random();
    let mut private = Vec::new();
    private.extend(check.to_be_bytes());
    private.extend(check.to_be_bytes());
    put_string(&mut private, b"ssh-ed25519");
    put_string(&mut private, public);
    let mut secret = seed.to_vec();
    secret.extend(public);
    put_string(&mut private, &secret);
    put_string(&mut private, b"");
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }
    let mut out = b"openssh-key-v1\0".to_vec();
    put_string(&mut out, b"none");
    put_string(&mut out, b"none");
    put_string(&mut out, b"");
    out.extend(1u32.to_be_bytes());
    put_string(&mut out, pub_blob);
    put_string(&mut out, &private);
    pem("OPENSSH PRIVATE KEY", &out, 70)
}

// ---- import -------------------------------------------------------------------------

/// Parse imported public key material: an OpenSSH public key line
/// (`ssh-rsa AAAA... comment`, `ssh-ed25519 ...`).
pub fn import(material: &[u8]) -> Result<Imported, String> {
    let text = std::str::from_utf8(material).map_err(|_| "not text")?.trim();
    // The SDKs base64-encode the blob on the wire; some callers encode the
    // key line themselves as well.
    let text = match B64.decode(text) {
        Ok(inner) if inner.starts_with(b"ssh-") => String::from_utf8(inner).map_err(|_| "not text")?,
        _ => text.to_string(),
    };
    let mut parts = text.split_whitespace();
    let kind = parts.next().ok_or("empty")?;
    let blob = B64.decode(parts.next().ok_or("no key")?).map_err(|_| "bad base64")?;
    let mut r = Reader(&blob);
    let inner_kind = r.string().ok_or("truncated")?;
    if inner_kind != kind.as_bytes() {
        return Err("key type mismatch".into());
    }
    match kind {
        "ssh-rsa" => {
            let e = r.string().ok_or("truncated")?;
            let n = r.string().ok_or("truncated")?;
            let bits = (strip_zeros(n).len() * 8) as u32;
            if !(1024..=16384).contains(&bits) {
                return Err("unsupported RSA key size".into());
            }
            let spki = rsa_spki(n, e);
            Ok(Imported {
                key_type: "rsa",
                public_key: format!("ssh-rsa {}", B64.encode(&blob)),
                fingerprint: colon_hex(&Md5::digest(&spki)),
            })
        }
        "ssh-ed25519" => {
            let public = r.string().ok_or("truncated")?;
            if public.len() != 32 {
                return Err("bad ed25519 key".into());
            }
            Ok(Imported {
                key_type: "ed25519",
                public_key: format!("ssh-ed25519 {}", B64.encode(&blob)),
                fingerprint: sha256_fingerprint(&blob),
            })
        }
        _ => Err("unsupported key type".into()),
    }
}

// ---- encodings ------------------------------------------------------------------------

fn sha256_fingerprint(blob: &[u8]) -> String {
    B64.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, blob).as_ref())
}

fn colon_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn pem(label: &str, der: &[u8], width: usize) -> String {
    let b64 = B64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(width) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    out
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend(s);
}

fn put_mpint(out: &mut Vec<u8>, n: &[u8]) {
    let n = strip_zeros(n);
    if n.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v = vec![0];
        v.extend(n);
        put_string(out, &v);
    } else {
        put_string(out, n);
    }
}

fn strip_zeros(n: &[u8]) -> &[u8] {
    let i = n.iter().position(|b| *b != 0).unwrap_or(n.len());
    &n[i..]
}

fn ssh_rsa_blob(e: &[u8], n: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, b"ssh-rsa");
    put_mpint(&mut out, e);
    put_mpint(&mut out, n);
    out
}

fn ssh_ed25519_blob(public: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, b"ssh-ed25519");
    put_string(&mut out, public);
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.0.get(..4)?.try_into().ok()?) as usize;
        let s = self.0.get(4..4 + len)?;
        self.0 = &self.0[4 + len..];
        Some(s)
    }
}

/// One DER element: `(tag, contents, rest)`.
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for b in input.get(2..2 + n)? {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    let body = input.get(hdr..hdr + len)?;
    Some((tag, body, &input[hdr + len..]))
}

fn der_encode(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend(body);
    out
}

fn der_integer(n: &[u8]) -> Vec<u8> {
    let n = strip_zeros(n);
    let mut v = Vec::new();
    if n.is_empty() || n[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend(n);
    der_encode(0x02, &v)
}

/// The `privateKey` octets of a PKCS#8 `PrivateKeyInfo`.
fn pkcs8_inner(pkcs8: &[u8]) -> Option<&[u8]> {
    let (_, seq, _) = der(pkcs8)?;
    let (_, _, rest) = der(seq)?; // version
    let (_, _, rest) = der(rest)?; // algorithm
    let (tag, key, _) = der(rest)?;
    (tag == 0x04).then_some(key)
}

/// `(n, e)` of a DER `RSAPublicKey`.
fn rsa_public_numbers(der_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (_, seq, _) = der(der_key)?;
    let (_, n, rest) = der(seq)?;
    let (_, e, _) = der(rest)?;
    Some((n.to_vec(), e.to_vec()))
}

/// DER `SubjectPublicKeyInfo` for an RSA key.
fn rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    let rsa_key = der_encode(0x30, &[der_integer(n), der_integer(e)].concat());
    let oid = der_encode(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
    let alg = der_encode(0x30, &[oid, vec![0x05, 0x00]].concat());
    let mut bits = vec![0u8];
    bits.extend(rsa_key);
    der_encode(0x30, &[alg, der_encode(0x03, &bits)].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_round_trip() {
        let g = generate_rsa().unwrap();
        assert!(g.material.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert_eq!(g.fingerprint.len(), 59);
        let imported = import(g.public_key.as_bytes()).unwrap();
        assert_eq!(imported.key_type, "rsa");
        assert_eq!(imported.public_key, g.public_key);
        assert_eq!(imported.fingerprint.len(), 47);
    }

    #[test]
    fn ed25519_round_trip() {
        let g = generate_ed25519().unwrap();
        assert!(g.material.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        let imported = import(format!("{} me@host", g.public_key).as_bytes()).unwrap();
        assert_eq!(imported.fingerprint, g.fingerprint);
    }

    #[test]
    fn rejects_garbage() {
        assert!(import(b"not a key").is_err());
    }
}
