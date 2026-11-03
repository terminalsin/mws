//! Object checksums: CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, SHA-512 and
//! MD5 (base64 of the big-endian digest, as S3 sends them), and MD5 ETags.

use base64::Engine;
use md5::Digest as _;

pub const ALGORITHMS: &[&str] =
    &["CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256", "SHA512", "MD5", "XXHASH64", "XXHASH3", "XXHASH128"];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

const fn crc32_table(poly: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const fn crc64_table(poly: u64) -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { poly ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC32: [u32; 256] = crc32_table(0xEDB8_8320);
static CRC32C: [u32; 256] = crc32_table(0x82F6_3B78);
static CRC64NVME: [u64; 256] = crc64_table(0x9A6C_9329_AC4B_C9B5);

fn crc32_with(table: &[u32; 256], data: &[u8]) -> u32 {
    let mut c = !0u32;
    for b in data {
        c = table[((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

fn crc64nvme(data: &[u8]) -> u64 {
    let mut c = !0u64;
    for b in data {
        c = CRC64NVME[((c ^ *b as u64) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// The raw digest of `data` under `algorithm`, or `None` when MWS cannot
/// compute it (the xxHash family, whose values are stored as sent).
pub fn raw(algorithm: &str, data: &[u8]) -> Option<Vec<u8>> {
    Some(match algorithm {
        "CRC32" => crc32_with(&CRC32, data).to_be_bytes().to_vec(),
        "CRC32C" => crc32_with(&CRC32C, data).to_be_bytes().to_vec(),
        "CRC64NVME" => crc64nvme(data).to_be_bytes().to_vec(),
        "SHA1" => aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref().to_vec(),
        "SHA256" => sha2::Sha256::digest(data).to_vec(),
        "SHA512" => sha2::Sha512::digest(data).to_vec(),
        "MD5" => md5::Md5::digest(data).to_vec(),
        _ => return None,
    })
}

/// Base64 checksum of `data`.
pub fn compute(algorithm: &str, data: &[u8]) -> Option<String> {
    raw(algorithm, data).map(|d| b64(&d))
}

/// A composite multipart checksum: the checksum of the concatenated part
/// checksums, suffixed with the part count.
pub fn composite(algorithm: &str, part_checksums: &[String]) -> Option<String> {
    let mut concat = Vec::new();
    for c in part_checksums {
        concat.extend(base64::engine::general_purpose::STANDARD.decode(c).ok()?);
    }
    Some(format!("{}-{}", compute(algorithm, &concat)?, part_checksums.len()))
}

/// Whether multipart uploads with this algorithm produce a full-object
/// checksum by default (the CRCs can be combined; the SHAs cannot).
pub fn full_object_by_default(algorithm: &str) -> bool {
    algorithm == "CRC64NVME"
}

pub fn supports_full_object(algorithm: &str) -> bool {
    matches!(algorithm, "CRC32" | "CRC32C" | "CRC64NVME")
}

/// The quoted MD5 ETag of `data`.
pub fn etag(data: &[u8]) -> String {
    format!("\"{}\"", hex::encode(md5::Md5::digest(data)))
}

/// Base64 MD5, as `Content-MD5` carries it.
pub fn md5_b64(data: &[u8]) -> String {
    b64(&md5::Md5::digest(data))
}

/// The multipart ETag: MD5 of the concatenated part MD5s, with the part
/// count.
pub fn multipart_etag(part_etags: &[String]) -> String {
    let mut concat = Vec::new();
    for e in part_etags {
        concat.extend(hex::decode(e.trim_matches('"')).unwrap_or_default());
    }
    format!("\"{}-{}\"", hex::encode(md5::Md5::digest(&concat)), part_etags.len())
}

/// The `(algorithm, value)` checksum members of an input or output shape.
macro_rules! provided_checksums {
    ($x:expr) => {
        [
            ("CRC32", $x.checksum_crc32.clone()),
            ("CRC32C", $x.checksum_crc32_c.clone()),
            ("CRC64NVME", $x.checksum_crc64_nvme.clone()),
            ("SHA1", $x.checksum_sha1.clone()),
            ("SHA256", $x.checksum_sha256.clone()),
            ("SHA512", $x.checksum_sha512.clone()),
            ("MD5", $x.checksum_md5.clone()),
            ("XXHASH64", $x.checksum_xxhash64.clone()),
            ("XXHASH3", $x.checksum_xxhash3.clone()),
            ("XXHASH128", $x.checksum_xxhash128.clone()),
        ]
    };
}

/// Set the checksum member for `alg` on an output shape.
macro_rules! set_checksum {
    ($out:expr, $alg:expr, $val:expr) => {
        match $alg {
            "CRC32" => $out.checksum_crc32 = $val,
            "CRC32C" => $out.checksum_crc32_c = $val,
            "CRC64NVME" => $out.checksum_crc64_nvme = $val,
            "SHA1" => $out.checksum_sha1 = $val,
            "SHA256" => $out.checksum_sha256 = $val,
            "SHA512" => $out.checksum_sha512 = $val,
            "MD5" => $out.checksum_md5 = $val,
            "XXHASH64" => $out.checksum_xxhash64 = $val,
            "XXHASH3" => $out.checksum_xxhash3 = $val,
            "XXHASH128" => $out.checksum_xxhash128 = $val,
            _ => {}
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // "123456789" check values.
        assert_eq!(crc32_with(&CRC32, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_with(&CRC32C, b"123456789"), 0xE306_9283);
        assert_eq!(crc64nvme(b"123456789"), 0xAE8B_1486_0A79_9888);
        assert_eq!(compute("CRC32", b"hello").unwrap(), "NhCmhg==");
        assert_eq!(etag(b""), "\"d41d8cd98f00b204e9800998ecf8427e\"");
    }
}
