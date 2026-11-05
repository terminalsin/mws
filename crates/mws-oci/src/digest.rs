//! Content digests as registries write them: `<algorithm>:<hex>`.

use sha2::{Digest as _, Sha256, Sha512};

/// The `sha256:` digest of `data`.
pub fn sha256(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

/// Whether `digest` is well formed: a known algorithm and a lowercase hex
/// value of the right length.
pub fn is_valid(digest: &str) -> bool {
    let Some((alg, hex)) = digest.split_once(':') else { return false };
    let len = match alg {
        "sha256" => 64,
        "sha512" => 128,
        _ => return false,
    };
    hex.len() == len && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The digest of `data` with the algorithm `digest` names, or `None` for an
/// unknown algorithm.
pub fn compute_like(digest: &str, data: &[u8]) -> Option<String> {
    match digest.split_once(':')?.0 {
        "sha256" => Some(sha256(data)),
        "sha512" => Some(format!("sha512:{}", hex::encode(Sha512::digest(data)))),
        _ => None,
    }
}

/// Whether `data` has the digest `digest`.
pub fn matches(digest: &str, data: &[u8]) -> bool {
    compute_like(digest, data).is_some_and(|d| d == digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests() {
        let d = sha256(b"");
        assert_eq!(d, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(is_valid(&d));
        assert!(matches(&d, b""));
        assert!(!is_valid("sha256:E3B0"));
        assert!(!is_valid("md5:abc"));
    }
}
