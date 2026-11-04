//! A small authoritative DNS responder that answers from the hosted zones,
//! so code under test can resolve the records it created. Enabled by the
//! composition root (`MWS_DNS_LISTEN`, UDP and TCP); it is not part of the
//! AWS API.
//!
//! Answers come from [`crate::resolve`], so routing policies, health
//! checks, wildcards, delegations and CNAMEs inside a zone behave as on
//! Route 53's name servers. Negative answers carry the zone's SOA, UDP
//! answers too large for the client are truncated (TC) so it retries over
//! TCP, and EDNS(0) is answered with an OPT record. Record types: A, AAAA,
//! CAA, CNAME, DS, HTTPS, MX, NAPTR, NS, PTR, SOA, SPF, SRV, SSHFP, SVCB,
//! TLSA and TXT. Responses are not DNSSEC-signed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::resolve::{Rcode, Record};
use crate::{names, Route53};

const TYPES: &[(&str, u16)] = &[
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("NAPTR", 35),
    ("DS", 43),
    ("SSHFP", 44),
    ("TLSA", 52),
    ("SVCB", 64),
    ("HTTPS", 65),
    ("SPF", 99),
    ("ANY", 255),
    ("CAA", 257),
];

fn type_code(name: &str) -> Option<u16> {
    TYPES.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

fn type_name(code: u16) -> Option<&'static str> {
    TYPES.iter().find(|(_, c)| *c == code).map(|(n, _)| *n)
}

/// Serve DNS over UDP on `socket` until the task is dropped.
pub async fn serve(route53: Route53, socket: tokio::net::UdpSocket) {
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else { continue };
        if let Some(reply) = respond(&route53, &buf[..n], Some(peer.ip()), Transport::Udp) {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}

/// Serve DNS over TCP on `listener` until the task is dropped.
pub async fn serve_tcp(route53: Route53, listener: tokio::net::TcpListener) {
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else { continue };
        let route53 = route53.clone();
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
                if stream.read_exact(&mut query).await.is_err() {
                    return;
                }
                let Some(reply) = respond(&route53, &query, Some(peer.ip()), Transport::Tcp) else { return };
                let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                if stream.write_all(&framed).await.is_err() {
                    return;
                }
            }
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// Build the response to one DNS query message, as over UDP.
pub fn answer(route53: &Route53, query: &[u8]) -> Option<Vec<u8>> {
    respond(route53, query, None, Transport::Udp)
}

/// Like [`answer`], for a query from `resolver`, which IP-based routing
/// uses and which goes in the zone's query log.
pub fn answer_from(route53: &Route53, query: &[u8], resolver: Option<IpAddr>) -> Option<Vec<u8>> {
    respond(route53, query, resolver, Transport::Udp)
}

fn respond(route53: &Route53, query: &[u8], resolver: Option<IpAddr>, transport: Transport) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let id = &query[0..2];
    let flags_in = u16::from_be_bytes([query[2], query[3]]);
    if flags_in & 0x8000 != 0 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (raw_qname, mut pos) = read_name(query, 12)?;
    let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
    pos += 4;
    let question = &query[12..pos];
    let edns = read_edns(query, pos);
    let client = edns.and_then(|e| e.client_subnet).or(resolver);

    let qname = names::normalize(&raw_qname).unwrap_or(raw_qname);
    let opcode = (flags_in >> 11) & 0xF;
    let qtype_name = type_name(qtype).map(str::to_string).unwrap_or_else(|| format!("TYPE{qtype}"));
    let found = if opcode == 0 { route53.lookup(None, &qname, &qtype_name, client) } else { None };

    let (rcode, aa, answers, authority) = match &found {
        // NOTIMP for anything but a standard query; REFUSED outside zones.
        None if opcode != 0 => (4u16, false, Vec::new(), Vec::new()),
        None => (5, false, Vec::new(), Vec::new()),
        Some((_, a)) => {
            let rcode = if a.rcode == Rcode::NxDomain { 3 } else { 0 };
            (rcode, a.authoritative, a.answers.clone(), a.authority.clone())
        }
    };

    if let Some((zone_id, _)) = &found {
        let rcode_name = match rcode {
            0 => "NOERROR",
            3 => "NXDOMAIN",
            _ => "REFUSED",
        };
        let proto = if transport == Transport::Tcp { "TCP" } else { "UDP" };
        let resolver = resolver.map(|ip| ip.to_string()).unwrap_or_else(|| "-".into());
        let subnet = edns.and_then(|e| e.client_subnet).map(|ip| ip.to_string()).unwrap_or_else(|| "-".into());
        route53.log_query(zone_id, |zone_id| {
            format!(
                "1.0 {} {zone_id} {} {qtype_name} {rcode_name} {proto} {} {resolver} {subnet}",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                names::bare(&qname),
                crate::query_logging::EDGE_LOCATION,
            )
        });
    }

    let encode = |records: &[Record]| -> Vec<Vec<u8>> { records.iter().filter_map(record).collect() };
    let answers = encode(&answers);
    let authority = encode(&authority);
    let limit = match transport {
        Transport::Tcp => u16::MAX as usize,
        Transport::Udp => edns.map(|e| e.udp_size.max(512) as usize).unwrap_or(512),
    };
    let build = |answers: &[Vec<u8>], authority: &[Vec<u8>], tc: bool| {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(id);
        let rd = flags_in & 0x0100;
        let mut flags = 0x8000 | (flags_in & 0x7800) | rd | rcode; // QR, opcode, RD
        if aa {
            flags |= 0x0400;
        }
        if tc {
            flags |= 0x0200;
        }
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(authority.len() as u16).to_be_bytes());
        out.extend_from_slice(&(edns.is_some() as u16).to_be_bytes());
        out.extend_from_slice(question);
        for a in answers.iter().chain(authority) {
            out.extend_from_slice(a);
        }
        if edns.is_some() {
            // OPT: root name, type 41, our UDP payload size, no flags.
            out.extend_from_slice(&[0, 0, 41]);
            out.extend_from_slice(&4096u16.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        out
    };
    let full = build(&answers, &authority, false);
    if full.len() <= limit {
        return Some(full);
    }
    Some(build(&[], &[], true))
}

#[derive(Clone, Copy)]
struct Edns {
    udp_size: u16,
    client_subnet: Option<IpAddr>,
}

/// The OPT record in the additional section, if any.
fn read_edns(msg: &[u8], mut pos: usize) -> Option<Edns> {
    let count = |at: usize| u16::from_be_bytes([msg[at], msg[at + 1]]);
    let (an, ns, ar) = (count(6), count(8), count(10));
    if ar == 0 {
        return None;
    }
    for i in 0..(an as usize + ns as usize + ar as usize) {
        let (_, after) = skip_name(msg, pos)?;
        let ty = u16::from_be_bytes([*msg.get(after)?, *msg.get(after + 1)?]);
        let class = u16::from_be_bytes([*msg.get(after + 2)?, *msg.get(after + 3)?]);
        let rdlen = u16::from_be_bytes([*msg.get(after + 8)?, *msg.get(after + 9)?]) as usize;
        let rdata = msg.get(after + 10..after + 10 + rdlen)?;
        if ty == 41 && i >= an as usize + ns as usize {
            return Some(Edns { udp_size: class, client_subnet: client_subnet(rdata) });
        }
        pos = after + 10 + rdlen;
    }
    None
}

/// The address in an EDNS Client Subnet option (RFC 7871).
fn client_subnet(mut opts: &[u8]) -> Option<IpAddr> {
    while opts.len() >= 4 {
        let code = u16::from_be_bytes([opts[0], opts[1]]);
        let len = u16::from_be_bytes([opts[2], opts[3]]) as usize;
        let data = opts.get(4..4 + len)?;
        if code == 8 && data.len() >= 4 {
            let family = u16::from_be_bytes([data[0], data[1]]);
            let addr = &data[4..];
            return match family {
                1 => {
                    let mut b = [0u8; 4];
                    b[..addr.len().min(4)].copy_from_slice(&addr[..addr.len().min(4)]);
                    Some(IpAddr::V4(Ipv4Addr::from(b)))
                }
                2 => {
                    let mut b = [0u8; 16];
                    b[..addr.len().min(16)].copy_from_slice(&addr[..addr.len().min(16)]);
                    Some(IpAddr::V6(Ipv6Addr::from(b)))
                }
                _ => None,
            };
        }
        opts = &opts[4 + len..];
    }
    None
}

fn skip_name(msg: &[u8], mut pos: usize) -> Option<((), usize)> {
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            return Some(((), pos + 2));
        }
        pos += 1;
        if len == 0 {
            return Some(((), pos));
        }
        pos += len;
    }
}

fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = *msg.get(pos)? as usize;
        if len & 0xC0 != 0 {
            return None; // queries do not compress the question name
        }
        pos += 1;
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos..pos + len)?).to_ascii_lowercase());
        pos += len;
    }
    Some((format!("{}.", labels.join(".")), pos))
}

fn write_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    for label in names::bare(name).split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(())
}

fn character_string(d: &mut Vec<u8>, s: &str) -> Option<()> {
    let bytes = s.as_bytes();
    if bytes.len() > 255 {
        return None;
    }
    d.push(bytes.len() as u8);
    d.extend_from_slice(bytes);
    Some(())
}

/// SVCB/HTTPS parameters MWS can encode (RFC 9460).
fn svc_params(d: &mut Vec<u8>, params: &[&str]) -> Option<()> {
    let mut encoded: Vec<(u16, Vec<u8>)> = Vec::new();
    for p in params {
        let (key, value) = p.split_once('=').unwrap_or((p, ""));
        let value = value.trim_matches('"');
        let (code, data) = match key {
            "alpn" => {
                let mut v = Vec::new();
                for id in value.split(',') {
                    character_string(&mut v, id)?;
                }
                (1, v)
            }
            "no-default-alpn" => (2, Vec::new()),
            "port" => (3, value.parse::<u16>().ok()?.to_be_bytes().to_vec()),
            "ipv4hint" => (
                4,
                value
                    .split(',')
                    .map(|a| a.parse::<Ipv4Addr>().ok().map(|a| a.octets()))
                    .collect::<Option<Vec<_>>>()?
                    .concat(),
            ),
            "ipv6hint" => (
                6,
                value
                    .split(',')
                    .map(|a| a.parse::<Ipv6Addr>().ok().map(|a| a.octets()))
                    .collect::<Option<Vec<_>>>()?
                    .concat(),
            ),
            _ => return None,
        };
        encoded.push((code, data));
    }
    encoded.sort_by_key(|(k, _)| *k);
    for (k, v) in encoded {
        d.extend_from_slice(&k.to_be_bytes());
        d.extend_from_slice(&(v.len() as u16).to_be_bytes());
        d.extend_from_slice(&v);
    }
    Some(())
}

fn rdata(rtype: u16, value: &str) -> Option<Vec<u8>> {
    let mut d = Vec::new();
    let fields: Vec<&str> = value.split_whitespace().collect();
    let num = |i: usize| fields.get(i).and_then(|f| f.parse::<u16>().ok());
    match rtype {
        1 => d.extend_from_slice(&value.trim().parse::<Ipv4Addr>().ok()?.octets()),
        28 => d.extend_from_slice(&value.trim().parse::<Ipv6Addr>().ok()?.octets()),
        2 | 5 | 12 => write_name(&mut d, value.trim())?,
        15 => {
            d.extend_from_slice(&num(0)?.to_be_bytes());
            write_name(&mut d, fields.get(1)?)?;
        }
        33 => {
            for i in 0..3 {
                d.extend_from_slice(&num(i)?.to_be_bytes());
            }
            write_name(&mut d, fields.get(3)?)?;
        }
        6 => {
            write_name(&mut d, fields.first()?)?;
            write_name(&mut d, fields.get(1)?)?;
            for i in 2..7 {
                d.extend_from_slice(&fields.get(i)?.parse::<u32>().ok()?.to_be_bytes());
            }
        }
        16 | 99 => {
            for s in txt_strings(value) {
                for chunk in s.as_bytes().chunks(255) {
                    d.push(chunk.len() as u8);
                    d.extend_from_slice(chunk);
                }
            }
        }
        // NAPTR: order preference "flags" "service" "regexp" replacement
        35 => {
            d.extend_from_slice(&num(0)?.to_be_bytes());
            d.extend_from_slice(&num(1)?.to_be_bytes());
            let rest = value.splitn(3, char::is_whitespace).nth(2)?;
            let strings = txt_strings(rest);
            for s in strings.iter().take(3) {
                character_string(&mut d, s)?;
            }
            write_name(&mut d, rest.rsplit(char::is_whitespace).next()?)?;
        }
        // DS: key tag, algorithm, digest type, digest (hex)
        43 => {
            d.extend_from_slice(&num(0)?.to_be_bytes());
            d.push(fields.get(1)?.parse().ok()?);
            d.push(fields.get(2)?.parse().ok()?);
            d.extend_from_slice(&hex::decode(fields[3..].concat()).ok()?);
        }
        // SSHFP: algorithm, fingerprint type, fingerprint (hex)
        44 => {
            d.push(fields.first()?.parse().ok()?);
            d.push(fields.get(1)?.parse().ok()?);
            d.extend_from_slice(&hex::decode(fields[2..].concat()).ok()?);
        }
        // TLSA: usage, selector, matching type, data (hex)
        52 => {
            for i in 0..3 {
                d.push(fields.get(i)?.parse().ok()?);
            }
            d.extend_from_slice(&hex::decode(fields[3..].concat()).ok()?);
        }
        // SVCB / HTTPS: priority, target, parameters
        64 | 65 => {
            d.extend_from_slice(&num(0)?.to_be_bytes());
            write_name(&mut d, fields.get(1)?)?;
            svc_params(&mut d, &fields[2..])?;
        }
        // CAA: flags tag "value"
        257 => {
            d.push(fields.first()?.parse().ok()?);
            let tag = fields.get(1)?;
            character_string(&mut d, tag)?;
            let rest = value.splitn(3, char::is_whitespace).nth(2)?.trim();
            d.extend_from_slice(rest.trim_matches('"').as_bytes());
        }
        _ => return None,
    }
    Some(d)
}

/// Split a Route 53 TXT value (`"a" "b c"`) into its character strings.
pub(crate) fn txt_strings(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quote => {
                out.push(std::mem::take(&mut cur));
                in_quote = false;
            }
            '"' => in_quote = true,
            '\\' if in_quote => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if in_quote => cur.push(c),
            _ => {}
        }
    }
    if out.is_empty() && !value.trim().is_empty() {
        out.push(value.trim().to_string());
    }
    out
}

fn record(r: &Record) -> Option<Vec<u8>> {
    let rtype = type_code(&r.ty)?;
    let data = rdata(rtype, &r.value)?;
    let mut out = Vec::new();
    write_name(&mut out, &r.name)?;
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&r.ttl.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&data);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_values_split_like_route53() {
        assert_eq!(txt_strings(r#""v=spf1 -all" "x\"y""#), vec!["v=spf1 -all", "x\"y"]);
    }

    #[test]
    fn encodes_more_record_types() {
        assert_eq!(rdata(257, r#"0 issue "amazon.com""#).unwrap(), b"\x00\x05issueamazon.com".to_vec());
        assert_eq!(rdata(43, "12345 13 2 ABCD").unwrap(), vec![0x30, 0x39, 13, 2, 0xab, 0xcd]);
        assert!(rdata(65, "1 . alpn=h2,h3 port=8443").is_some());
        assert!(rdata(35, r#"100 10 "S" "SIP+D2U" "" _sip._udp.example.com."#).is_some());
    }

    #[test]
    fn refuses_names_outside_zones() {
        let r = Route53::new();
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        write_name(&mut q, "example.com.").unwrap();
        q.extend_from_slice(&[0, 1, 0, 1]);
        let a = answer(&r, &q).unwrap();
        assert_eq!(&a[0..2], &[0x12, 0x34]);
        assert_eq!(a[3] & 0x0f, 5);
    }
}
