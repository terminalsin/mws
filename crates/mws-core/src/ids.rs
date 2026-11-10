//! Access key ids in AWS's format: a four-letter prefix (`AKIA` long-term,
//! `ASIA` temporary) and 16 base32 characters whose leading bits carry the
//! owning account, so `sts:GetAccessKeyInfo` can name the account of any
//! well-formed key, even one that no longer exists.

use rand::RngCore;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ACCOUNT_MASK: u64 = 0x7fff_ffff_ff80;

/// A new access key id with `prefix` that encodes `account` (a 12-digit
/// account id; anything else gets random bits).
pub fn access_key_id(prefix: &str, account: &str) -> String {
    let mut bytes = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut bytes);
    if let Ok(n) = account.parse::<u64>() {
        if account.len() == 12 {
            let head = u64::from_be_bytes([0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]);
            let head = (head & !ACCOUNT_MASK & 0xffff_ffff_ffff) | ((n << 7) & ACCOUNT_MASK);
            bytes[..6].copy_from_slice(&head.to_be_bytes()[2..]);
        }
    }
    let mut out = String::with_capacity(prefix.len() + 16);
    out.push_str(prefix);
    let mut bits: u128 = 0;
    for b in bytes {
        bits = (bits << 8) | u128::from(b);
    }
    for i in (0..16).rev() {
        out.push(BASE32[((bits >> (i * 5)) & 31) as usize] as char);
    }
    out
}

/// The account an access key id encodes, if it is in AWS's format.
pub fn account_of_access_key_id(akid: &str) -> Option<String> {
    let body = akid.get(4..)?;
    if body.len() < 16 {
        return None;
    }
    let mut bits: u128 = 0;
    for c in body[..16].bytes() {
        let v = BASE32.iter().position(|&a| a == c)? as u128;
        bits = (bits << 5) | v;
    }
    let head = (bits >> 32) as u64;
    Some(format!("{:012}", (head & ACCOUNT_MASK) >> 7))
}

/// A new request id, a random (version 4) UUID like AWS's.
pub fn request_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_aws_published_examples() {
        // The worked example from public research into the key id format.
        assert_eq!(account_of_access_key_id("ASIAY34FZKBOKMUTVV7A").as_deref(), Some("609629065308"));
    }

    #[test]
    fn round_trips() {
        for account in ["123456789012", "000000000001", "999999999999"] {
            let id = access_key_id("AKIA", account);
            assert_eq!(id.len(), 20);
            assert!(id.starts_with("AKIA"));
            assert_eq!(account_of_access_key_id(&id).as_deref(), Some(account));
        }
        assert_eq!(access_key_id("ASIA", "not-an-account").len(), 20);
    }
}
