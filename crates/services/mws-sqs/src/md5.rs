//! The MD5 digests SQS returns and SDKs verify: of the body, and of
//! message attributes in SQS's binary encoding (sorted by name; each name,
//! data type and value length-prefixed, with a transport byte of 1 for
//! String and Number, 2 for Binary).

use std::collections::BTreeMap;

use md5::{Digest, Md5};

use crate::state::Attr;

pub fn md5_of_body(body: &str) -> String {
    hex::encode(Md5::digest(body.as_bytes()))
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// MD5 of message attributes as SQS computes it. `None` when empty.
pub fn md5_of_attributes(attrs: &BTreeMap<String, Attr>) -> Option<String> {
    if attrs.is_empty() {
        return None;
    }
    let mut buf = Vec::new();
    for (name, v) in attrs {
        put(&mut buf, name.as_bytes());
        put(&mut buf, v.data_type.as_bytes());
        if v.data_type.starts_with("Binary") {
            buf.push(2);
            put(&mut buf, v.binary_value.as_deref().unwrap_or_default());
        } else {
            buf.push(1);
            put(&mut buf, v.string_value.as_deref().unwrap_or_default().as_bytes());
        }
    }
    Some(hex::encode(Md5::digest(&buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_match_aws_examples() {
        assert_eq!(md5_of_body("hello"), "5d41402abc4b2a76b9719d911017c592");
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "attr".to_string(),
            Attr { data_type: "String".into(), string_value: Some("value".into()), binary_value: None },
        );
        // Encoding: 0004 'attr' 0006 'String' 01 0005 'value'.
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0, 0, 0, 4]);
        expected.extend_from_slice(b"attr");
        expected.extend_from_slice(&[0, 0, 0, 6]);
        expected.extend_from_slice(b"String");
        expected.push(1);
        expected.extend_from_slice(&[0, 0, 0, 5]);
        expected.extend_from_slice(b"value");
        assert_eq!(md5_of_attributes(&attrs), Some(hex::encode(Md5::digest(&expected))));
        assert_eq!(md5_of_attributes(&BTreeMap::new()), None);
    }
}
