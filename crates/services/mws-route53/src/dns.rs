//! A small authoritative DNS responder over UDP that answers from the hosted
//! zones, so code under test can resolve the records it created. Enabled by
//! the composition root (`MWS_DNS_LISTEN`); it is not part of the AWS API.
//!
//! Supports A, AAAA, CNAME, NS, PTR, MX, TXT, SRV and SOA, wildcards, and
//! alias records that point at other records in MWS zones.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::generated::types::ResourceRecordSet;
use crate::{names, Route53};

const TYPES: &[(&str, u16)] =
    &[("A", 1), ("NS", 2), ("CNAME", 5), ("SOA", 6), ("PTR", 12), ("MX", 15), ("TXT", 16), ("AAAA", 28), ("SRV", 33)];

fn type_code(name: &str) -> Option<u16> {
    TYPES.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

fn type_name(code: u16) -> Option<&'static str> {
    TYPES.iter().find(|(_, c)| *c == code).map(|(n, _)| *n)
}

/// Serve DNS on `socket` until the task is dropped.
pub async fn serve(route53: Route53, socket: tokio::net::UdpSocket) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else { continue };
        if let Some(reply) = answer_from(&route53, &buf[..n], Some(peer.ip())) {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}

/// Build the response to one DNS query message.
pub fn answer(route53: &Route53, query: &[u8]) -> Option<Vec<u8>> {
    answer_from(route53, query, None)
}

/// Like [`answer`], for a query from `resolver`, which goes in the zone's
/// query log when it has a query logging configuration.
pub fn answer_from(route53: &Route53, query: &[u8], resolver: Option<std::net::IpAddr>) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let id = &query[0..2];
    let flags_in = u16::from_be_bytes([query[2], query[3]]);
    if flags_in & 0x8000 != 0 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let (qname, mut pos) = read_name(query, 12)?;
    let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
    pos += 4;
    let question = &query[12..pos];

    let qname = names::normalize(&qname).unwrap_or(qname);
    let zones = route53.snapshot();
    let zone = zones.iter().filter(|(z, _)| names::in_zone(&qname, z)).max_by_key(|(z, _)| z.len());

    let mut answers: Vec<Vec<u8>> = Vec::new();
    let mut rcode = 0u16;
    match zone {
        None => rcode = 5, // REFUSED: not authoritative
        Some((_, records)) => {
            let mut at_name: Vec<&ResourceRecordSet> = records.iter().filter(|r| r.name == qname).collect();
            if at_name.is_empty() {
                // Wildcard: replace the first label with `*`.
                if let Some((_, rest)) = qname.split_once('.') {
                    let wild = format!("*.{rest}");
                    at_name = records.iter().filter(|r| r.name == wild).collect();
                }
            }
            if at_name.is_empty() {
                rcode = 3; // NXDOMAIN
            }
            let wanted = type_name(qtype);
            for r in &at_name {
                let matches = Some(r.r#type.as_str()) == wanted || r.r#type == "CNAME" || qtype == 255;
                if !matches {
                    continue;
                }
                let rtype = type_code(&r.r#type).unwrap_or(0);
                if let Some(alias) = &r.alias_target {
                    let target = names::normalize(&alias.dns_name).unwrap_or_default();
                    for (_, zrecs) in &zones {
                        for t in zrecs.iter().filter(|t| t.name == target && t.r#type == r.r#type) {
                            for v in t.resource_records.iter().flatten() {
                                if let Some(rr) = record(&qname, rtype, 60, &v.value) {
                                    answers.push(rr);
                                }
                            }
                        }
                    }
                    continue;
                }
                let ttl = r.ttl.unwrap_or(300).clamp(0, u32::MAX as i64) as u32;
                for v in r.resource_records.iter().flatten() {
                    if let Some(rr) = record(&qname, rtype, ttl, &v.value) {
                        answers.push(rr);
                    }
                }
            }
        }
    }

    if let Some((zone_name, _)) = zone {
        let rcode_name = match rcode {
            0 => "NOERROR",
            3 => "NXDOMAIN",
            _ => "REFUSED",
        };
        let qtype_name = type_name(qtype).map(str::to_string).unwrap_or_else(|| format!("TYPE{qtype}"));
        let resolver = resolver.map(|ip| ip.to_string()).unwrap_or_else(|| "-".into());
        route53.log_query(zone_name, |zone_id| {
            format!(
                "1.0 {} {zone_id} {} {qtype_name} {rcode_name} UDP {} {resolver} -",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                names::bare(&qname),
                crate::query_logging::EDGE_LOCATION,
            )
        });
    }

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(id);
    let rd = flags_in & 0x0100;
    let flags = 0x8000 | 0x0400 | rd | rcode; // QR, AA
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    for a in answers {
        out.extend_from_slice(&a);
    }
    Some(out)
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

fn rdata(rtype: u16, value: &str) -> Option<Vec<u8>> {
    let mut d = Vec::new();
    let mut fields = value.split_whitespace();
    match rtype {
        1 => d.extend_from_slice(&value.trim().parse::<Ipv4Addr>().ok()?.octets()),
        28 => d.extend_from_slice(&value.trim().parse::<Ipv6Addr>().ok()?.octets()),
        2 | 5 | 12 => write_name(&mut d, value.trim())?,
        15 => {
            d.extend_from_slice(&fields.next()?.parse::<u16>().ok()?.to_be_bytes());
            write_name(&mut d, fields.next()?)?;
        }
        33 => {
            for _ in 0..3 {
                d.extend_from_slice(&fields.next()?.parse::<u16>().ok()?.to_be_bytes());
            }
            write_name(&mut d, fields.next()?)?;
        }
        6 => {
            write_name(&mut d, fields.next()?)?;
            write_name(&mut d, fields.next()?)?;
            for _ in 0..5 {
                d.extend_from_slice(&fields.next()?.parse::<u32>().ok()?.to_be_bytes());
            }
        }
        16 => {
            for s in txt_strings(value) {
                for chunk in s.as_bytes().chunks(255) {
                    d.push(chunk.len() as u8);
                    d.extend_from_slice(chunk);
                }
            }
        }
        _ => return None,
    }
    Some(d)
}

/// Split a Route 53 TXT value (`"a" "b c"`) into its character strings.
fn txt_strings(value: &str) -> Vec<String> {
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

fn record(name: &str, rtype: u16, ttl: u32, value: &str) -> Option<Vec<u8>> {
    let data = rdata(rtype, value)?;
    let mut out = Vec::new();
    write_name(&mut out, name)?;
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
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
