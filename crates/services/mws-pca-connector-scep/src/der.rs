//! Just enough ASN.1 for SCEP's CMS messages: a BER reader (SCEP clients
//! built on OpenSSL send indefinite lengths and constructed OCTET STRINGs)
//! and a DER writer.

/// One parsed TLV. Single-byte tags only, which is all CMS needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub tag: u8,
    /// Contents of a primitive node.
    pub content: Vec<u8>,
    /// Children of a constructed node.
    pub children: Vec<Node>,
}

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const NULL: u8 = 0x05;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const UTC_TIME: u8 = 0x17;

impl Node {
    pub fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    /// Context-specific tag number, if this node has one.
    pub fn context(&self) -> Option<u8> {
        (self.tag & 0xc0 == 0x80).then_some(self.tag & 0x1f)
    }

    pub fn child(&self, i: usize) -> Option<&Node> {
        self.children.get(i)
    }

    /// The bytes of a string type, including constructed (BER) strings.
    pub fn bytes(&self) -> Vec<u8> {
        if self.constructed() {
            self.children.iter().flat_map(Node::bytes).collect()
        } else {
            self.content.clone()
        }
    }

    pub fn oid(&self) -> Option<String> {
        (self.tag == OID).then(|| decode_oid(&self.content))
    }

    /// The DER encoding of this node (re-encoding definite lengths).
    pub fn to_der(&self) -> Vec<u8> {
        self.to_der_tagged(self.tag)
    }

    /// The DER encoding with another tag (for IMPLICIT re-tagging, such
    /// as signed attributes, which are signed as a SET).
    pub fn to_der_tagged(&self, tag: u8) -> Vec<u8> {
        if self.constructed() {
            tlv(tag, &self.children.iter().flat_map(Node::to_der).collect::<Vec<_>>())
        } else {
            tlv(tag, &self.content)
        }
    }
}

/// Parse one node from the start of `input`; returns it and what follows.
pub fn parse(input: &[u8]) -> Option<(Node, &[u8])> {
    parse_at(input, 0)
}

/// Parse `input`, which must hold exactly one node.
#[cfg(test)]
pub fn parse_all(input: &[u8]) -> Option<Node> {
    let (node, rest) = parse(input)?;
    rest.is_empty().then_some(node)
}

fn parse_at(input: &[u8], depth: usize) -> Option<(Node, &[u8])> {
    if depth > 64 {
        return None;
    }
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags: not used by CMS
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = if first == 0x80 {
        None
    } else if first & 0x80 == 0 {
        Some(first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for b in &rest[..n] {
            len = (len << 8) | *b as usize;
        }
        rest = &rest[n..];
        Some(len)
    };
    let constructed = tag & 0x20 != 0;
    match len {
        Some(len) => {
            if rest.len() < len {
                return None;
            }
            let (body, after) = rest.split_at(len);
            if constructed {
                let mut children = Vec::new();
                let mut b = body;
                while !b.is_empty() {
                    let (c, r) = parse_at(b, depth + 1)?;
                    children.push(c);
                    b = r;
                }
                Some((Node { tag, content: Vec::new(), children }, after))
            } else {
                Some((Node { tag, content: body.to_vec(), children: Vec::new() }, after))
            }
        }
        None => {
            if !constructed {
                return None;
            }
            let mut children = Vec::new();
            let mut b = rest;
            loop {
                if b.len() >= 2 && b[0] == 0 && b[1] == 0 {
                    return Some((Node { tag, content: Vec::new(), children }, &b[2..]));
                }
                let (c, r) = parse_at(b, depth + 1)?;
                children.push(c);
                b = r;
            }
        }
    }
}

pub fn decode_oid(bytes: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = if v < 40 {
                    0
                } else if v < 80 {
                    1
                } else {
                    2
                };
                parts.push(first);
                parts.push(v - first * 40);
            } else {
                parts.push(v);
            }
            v = 0;
        } else if i == bytes.len() - 1 {
            break;
        }
    }
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

// --- writing -----------------------------------------------------------

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A DER SET OF: elements sorted by their encodings.
pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    tlv(SET, &sorted.concat())
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let nums: Vec<u64> = dotted.split('.').map(|p| p.parse().expect("valid OID")).collect();
    let mut body = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        body.extend(tmp);
    };
    push(nums[0] * 40 + nums[1]);
    for n in &nums[2..] {
        push(*n);
    }
    tlv(OID, &body)
}

pub fn int(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(7);
    let mut body = bytes[skip..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(INTEGER, &body)
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn printable(s: &str) -> Vec<u8> {
    tlv(PRINTABLE_STRING, s.as_bytes())
}

pub fn null() -> Vec<u8> {
    vec![NULL, 0]
}

/// `[n] EXPLICIT` around `inner`.
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

/// `[n] IMPLICIT` constructed, with `content` as its body.
pub fn implicit_constructed(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// `[n] IMPLICIT` primitive.
pub fn implicit_primitive(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

/// An AlgorithmIdentifier.
pub fn algorithm(dotted: &str, params: Option<Vec<u8>>) -> Vec<u8> {
    match params {
        Some(p) => seq(&[oid(dotted), p]),
        None => seq(&[oid(dotted)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_round_trip() {
        for o in ["1.2.840.113549.1.7.2", "2.16.840.1.113733.1.9.2", "2.16.840.1.101.3.4.1.42", "2.5.29.37"] {
            let enc = oid(o);
            assert_eq!(parse_all(&enc).unwrap().oid().unwrap(), o);
        }
    }

    #[test]
    fn indefinite_lengths_and_constructed_strings() {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "c" } }
        let ber = [0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0];
        let n = parse_all(&ber).unwrap();
        assert_eq!(n.child(0).unwrap().bytes(), b"abc");
        assert_eq!(seq(&[tlv(0x24, &[octets(b"ab"), octets(b"c")].concat())]), n.to_der());
    }

    #[test]
    fn long_lengths() {
        let body = vec![7u8; 300];
        let enc = octets(&body);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(parse_all(&enc).unwrap().content, body);
        assert_eq!(int(0x80), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(int(0), vec![0x02, 0x01, 0x00]);
    }
}
