//! Identifier formats IAM uses.

use rand::Rng;

const ID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SECRET_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn random_from(alphabet: &[u8], len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char).collect()
}

/// Unique ids are a 4-letter prefix (`AIDA` user, `AROA` role, `AGPA` group,
/// `ANPA` policy, ...) plus 17 characters.
pub fn unique_id(prefix: &str) -> String {
    format!("{prefix}{}", random_from(ID_ALPHABET, 17))
}

/// Long-term access key ids are `AKIA` plus 16 characters.
pub fn access_key_id() -> String {
    format!("AKIA{}", random_from(ID_ALPHABET, 16))
}

pub fn secret_access_key() -> String {
    random_from(SECRET_ALPHABET, 40)
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats() {
        assert_eq!(super::unique_id("AIDA").len(), 21);
        assert_eq!(super::access_key_id().len(), 20);
        assert_eq!(super::secret_access_key().len(), 40);
    }
}
