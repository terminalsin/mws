//! SigV4a: ECDSA P-256 signatures with a key pair derived from the secret
//! access key, so one signature is valid in several Regions.
//!
//! The private key comes from NIST SP 800-108 counter-mode HMAC-SHA256 over
//! `"AWS4A" + secret`, with the label `AWS4-ECDSA-P256-SHA256` and the
//! access key id plus an external counter as context; the counter goes up
//! until the candidate is below `n - 1`, and the key is the candidate plus
//! one.

use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair, UnparsedPublicKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::SigV4Error;

/// The order of P-256 minus two, big-endian.
const N_MINUS_2: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa,
    0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
];

/// The private scalar SigV4a derives from a credential, big-endian.
pub(crate) fn private_key(access_key_id: &str, secret_access_key: &str) -> [u8; 32] {
    let input_key = format!("AWS4A{secret_access_key}");
    for counter in 1u8..=254 {
        let mut mac = Hmac::<Sha256>::new_from_slice(input_key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(&1u32.to_be_bytes());
        mac.update(b"AWS4-ECDSA-P256-SHA256");
        mac.update(&[0]);
        mac.update(access_key_id.as_bytes());
        mac.update(&[counter]);
        mac.update(&256u32.to_be_bytes());
        let mut candidate: [u8; 32] = mac.finalize().into_bytes().into();
        if candidate > N_MINUS_2 {
            continue;
        }
        // d = candidate + 1
        for b in candidate.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
        return candidate;
    }
    unreachable!("a SigV4a key is found long before the counter runs out")
}

/// The uncompressed public key for a credential.
pub(crate) fn public_key(access_key_id: &str, secret_access_key: &str) -> Option<Vec<u8>> {
    let d = private_key(access_key_id, secret_access_key);
    // RFC 5915 ECPrivateKey with the prime256v1 parameters.
    let mut der = vec![0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20];
    der.extend_from_slice(&d);
    der.extend_from_slice(&[0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let pair = EcdsaKeyPair::from_private_key_der(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &der).ok()?;
    Some(pair.public_key().as_ref().to_vec())
}

/// Check a hex, DER-encoded ECDSA signature over `string_to_sign`.
pub(crate) fn verify(
    access_key_id: &str,
    secret_access_key: &str,
    string_to_sign: &[u8],
    signature_hex: &str,
) -> Result<(), SigV4Error> {
    let sig = hex::decode(signature_hex).map_err(|_| SigV4Error::Mismatch)?;
    let public = public_key(access_key_id, secret_access_key).ok_or(SigV4Error::Mismatch)?;
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public)
        .verify(string_to_sign, &sig)
        .map_err(|_| SigV4Error::Mismatch)
}
