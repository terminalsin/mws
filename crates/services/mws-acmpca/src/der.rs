//! Just enough DER to read OCSP requests and write OCSP responses.

pub const SEQUENCE: u8 = 0x30;
pub const OCTET_STRING: u8 = 0x04;
pub const BIT_STRING: u8 = 0x03;
pub const INTEGER: u8 = 0x02;
pub const ENUMERATED: u8 = 0x0a;
pub const OID: u8 = 0x06;
pub const NULL: u8 = 0x05;
pub const GENERALIZED_TIME: u8 = 0x18;

/// Context-specific constructed tag `[n]`.
pub const fn ctx(n: u8) -> u8 {
    0xa0 | n
}

/// Context-specific primitive tag `[n]` (an IMPLICIT primitive).
pub const fn ctx_prim(n: u8) -> u8 {
    0x80 | n
}

/// One element: its tag, its content, the whole encoding, and what follows.
#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Read one element from the front of `input`, returning it and the rest.
pub fn read(input: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags never occur here
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return None;
    }
    let header = input.len() - rest.len();
    Some((Element { tag, content: &rest[..len], raw: &input[..header + len] }, &rest[len..]))
}

/// Every element inside `content`, in order.
pub fn children(mut content: &[u8]) -> Option<Vec<Element<'_>>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (e, rest) = read(content)?;
        out.push(e);
        content = rest;
    }
    Some(out)
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

pub fn generalized_time(t: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
    tlv(GENERALIZED_TIME, t.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
}

/// Encode a dotted OID.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut push = |mut v: u64| {
        let mut stack = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            stack.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        body.extend(stack.into_iter().rev());
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    tlv(OID, &body)
}

/// The content of an unsigned INTEGER with leading zero bytes removed.
pub fn unsigned_integer(content: &[u8]) -> &[u8] {
    let mut c = content;
    while c.len() > 1 && c[0] == 0 {
        c = &c[1..];
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_long_lengths() {
        let body = vec![7u8; 300];
        let enc = tlv(OCTET_STRING, &body);
        let (e, rest) = read(&enc).unwrap();
        assert!(rest.is_empty());
        assert_eq!(e.content, &body[..]);
        assert_eq!(e.raw, &enc[..]);
    }

    #[test]
    fn encodes_oids() {
        assert_eq!(oid(&[1, 3, 14, 3, 2, 26]), vec![0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]);
        assert_eq!(oid(&[1, 2, 840, 113549, 1, 1, 11]), vec![6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11]);
    }
}
