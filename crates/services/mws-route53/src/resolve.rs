//! How a Route 53 name server answers a query from a hosted zone: shared by
//! the DNS responder and `TestDNSAnswer`.
//!
//! Follows RFC 1034's algorithm for one zone: delegations below the apex
//! give referrals, names that only have names below them answer NODATA,
//! wildcards match any depth below their closest encloser, CNAMEs inside
//! the zone are followed, and negative answers carry the SOA. Among record
//! sets with the same name and type, routing policies choose what to
//! return, skipping record sets whose health check is unhealthy (and alias
//! records that evaluate an unhealthy target), as Route 53 does.
//!
//! MWS answers from a single location and knows nothing about where a
//! resolver is, so latency records answer from the healthy record set in
//! `us-east-1` (else the first healthy one), geolocation records from the
//! default (`*`) location, and geoproximity records from the first healthy
//! record set. IP-based records match the resolver's address (or the EDNS
//! client subnet) against the CIDR collection.

use std::collections::HashMap;
use std::net::IpAddr;

use rand::Rng;

use crate::generated::types::{self, ResourceRecordSet};
use crate::names;
use crate::records::routing_policy;
use crate::state::{CidrCollection, Zone};

/// One resource record in an answer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Record {
    pub name: String,
    pub ty: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rcode {
    NoError,
    NxDomain,
}

#[derive(Debug, Clone)]
pub(crate) struct Answer {
    pub rcode: Rcode,
    /// False for referrals to a delegated subdomain.
    pub authoritative: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
}

/// What resolution needs besides the zone.
pub(crate) struct Context<'a> {
    /// The zone owner's CIDR collections, by id.
    pub cidr_collections: &'a std::collections::BTreeMap<String, CidrCollection>,
    /// Whether a health check is healthy.
    pub healthy: &'a dyn Fn(&str) -> bool,
    /// The resolver's address or EDNS client subnet, for IP-based routing.
    pub client: Option<IpAddr>,
}

fn ttl_of(r: &ResourceRecordSet) -> u32 {
    r.ttl.unwrap_or(300).clamp(0, u32::MAX as i64) as u32
}

fn values(r: &ResourceRecordSet) -> impl Iterator<Item = &str> {
    r.resource_records.iter().flatten().map(|v| v.value.as_str())
}

/// The record sets at `name` exactly.
fn at<'z>(zone: &'z Zone, name: &str) -> Vec<&'z ResourceRecordSet> {
    zone.records.values().filter(|r| r.name == name).collect()
}

/// Whether some record lives below `name` (an empty non-terminal).
fn has_descendants(zone: &Zone, name: &str) -> bool {
    let suffix = format!(".{name}");
    zone.records.values().any(|r| r.name.ends_with(&suffix))
}

fn parent(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, rest)| rest).filter(|r| !r.is_empty())
}

/// The SOA for negative answers, with the TTL Route 53 gives it: the lower
/// of the record's TTL and the SOA minimum.
fn soa(zone: &Zone) -> Vec<Record> {
    zone.records
        .values()
        .filter(|r| r.name == zone.name && r.r#type == "SOA")
        .flat_map(|r| {
            let minimum = values(r)
                .next()
                .and_then(|v| v.split_whitespace().nth(6))
                .and_then(|m| m.parse::<u32>().ok())
                .unwrap_or(u32::MAX);
            values(r).map(move |v| Record {
                name: zone.name.clone(),
                ty: "SOA".into(),
                ttl: ttl_of(r).min(minimum),
                value: v.to_string(),
            })
        })
        .collect()
}

/// Answer `qtype` (a type name, or `ANY`) for `qname` from `zone`.
pub(crate) fn resolve(zone: &Zone, qname: &str, qtype: &str, cx: &Context<'_>) -> Answer {
    let mut answers = Vec::new();
    let mut name = qname.to_string();
    // Follow CNAMEs within the zone, as Route 53 does, a few hops deep.
    for _ in 0..8 {
        // A delegation at or above the name (below the apex) refers.
        let mut cut = Some(name.as_str());
        while let Some(n) = cut {
            if n == zone.name || !names::in_zone(n, &zone.name) {
                break;
            }
            let ns: Vec<&ResourceRecordSet> = at(zone, n).into_iter().filter(|r| r.r#type == "NS").collect();
            if !ns.is_empty() && !(n == name && qtype == "DS") {
                let authority = ns
                    .iter()
                    .flat_map(|r| {
                        values(r).map(|v| Record {
                            name: n.to_string(),
                            ty: "NS".into(),
                            ttl: ttl_of(r),
                            value: v.into(),
                        })
                    })
                    .collect();
                return Answer { rcode: Rcode::NoError, authoritative: false, answers, authority };
            }
            cut = parent(n);
        }

        let mut sets = at(zone, &name);
        if sets.is_empty() && !has_descendants(zone, &name) {
            // Wildcard at the closest encloser.
            let mut encloser = parent(&name);
            while let Some(e) = encloser {
                if !names::in_zone(e, &zone.name) {
                    break;
                }
                let wild = at(zone, &format!("*.{e}"));
                if !wild.is_empty() {
                    sets = wild;
                    break;
                }
                if !at(zone, e).is_empty() || has_descendants(zone, e) {
                    // `e` exists (or has other names below it), so the
                    // name does not match a wildcard further up.
                    break;
                }
                encloser = parent(e);
            }
            if sets.is_empty() {
                return Answer {
                    rcode: if answers.is_empty() { Rcode::NxDomain } else { Rcode::NoError },
                    authoritative: true,
                    answers,
                    authority: soa(zone),
                };
            }
        }

        let cname: Vec<&ResourceRecordSet> = sets.iter().copied().filter(|r| r.r#type == "CNAME").collect();
        if !cname.is_empty() && qtype != "CNAME" && qtype != "ANY" {
            let chosen = select(zone, &cname, cx, 0);
            let target = chosen.first().map(|r| r.value.clone());
            answers.extend(chosen.into_iter().map(|mut r| {
                r.name = name.clone();
                r
            }));
            match target.and_then(|t| names::normalize(&t)) {
                Some(t) if names::in_zone(&t, &zone.name) => {
                    name = t;
                    continue;
                }
                _ => return Answer { rcode: Rcode::NoError, authoritative: true, answers, authority: Vec::new() },
            }
        }

        let mut by_type: Vec<&str> = sets.iter().map(|r| r.r#type.as_str()).collect();
        by_type.dedup();
        for ty in by_type.into_iter().filter(|t| qtype == "ANY" || t == &qtype) {
            let group: Vec<&ResourceRecordSet> = sets.iter().copied().filter(|r| r.r#type == ty).collect();
            answers.extend(select(zone, &group, cx, 0).into_iter().map(|mut r| {
                r.name = name.clone();
                r
            }));
        }
        let authority = if answers.is_empty() { soa(zone) } else { Vec::new() };
        return Answer { rcode: Rcode::NoError, authoritative: true, answers, authority };
    }
    Answer { rcode: Rcode::NoError, authoritative: true, answers, authority: Vec::new() }
}

/// Whether a record set may be returned: its health check is healthy, and
/// an alias that evaluates target health has a healthy target.
fn usable(zone: &Zone, r: &ResourceRecordSet, cx: &Context<'_>, depth: usize) -> bool {
    if r.health_check_id.as_deref().is_some_and(|id| !(cx.healthy)(id)) {
        return false;
    }
    match &r.alias_target {
        Some(a) if a.evaluate_target_health => !alias_records(zone, r, cx, depth).is_empty(),
        _ => true,
    }
}

/// The records an alias resolves to: the target record sets of the same
/// type in the zone, routed in turn. Targets outside MWS (load balancers,
/// CloudFront, S3 websites) resolve to nothing.
fn alias_records(zone: &Zone, r: &ResourceRecordSet, cx: &Context<'_>, depth: usize) -> Vec<Record> {
    let Some(alias) = &r.alias_target else { return Vec::new() };
    if depth > 8 || crate::strip_id(&alias.hosted_zone_id) != zone.id {
        return Vec::new();
    }
    let Some(target) = names::normalize(&alias.dns_name) else { return Vec::new() };
    let group: Vec<&ResourceRecordSet> =
        zone.records.values().filter(|t| t.name == target && t.r#type == r.r#type).collect();
    select(zone, &group, cx, depth + 1)
}

fn expand(zone: &Zone, r: &ResourceRecordSet, cx: &Context<'_>, depth: usize) -> Vec<Record> {
    if r.alias_target.is_some() {
        return alias_records(zone, r, cx, depth);
    }
    values(r).map(|v| Record { name: r.name.clone(), ty: r.r#type.clone(), ttl: ttl_of(r), value: v.into() }).collect()
}

/// Choose among the record sets with one name and type.
fn select(zone: &Zone, group: &[&ResourceRecordSet], cx: &Context<'_>, depth: usize) -> Vec<Record> {
    let Some(first) = group.first() else { return Vec::new() };
    let healthy: Vec<&ResourceRecordSet> = group.iter().copied().filter(|r| usable(zone, r, cx, depth)).collect();
    // When every record set is unhealthy, Route 53 treats them all as
    // healthy.
    let pool = if healthy.is_empty() { group.to_vec() } else { healthy };
    let chosen: Vec<&ResourceRecordSet> = match routing_policy(first) {
        None => vec![first],
        Some("weighted") => {
            let positive: Vec<&ResourceRecordSet> =
                pool.iter().copied().filter(|r| r.weight.unwrap_or(0) > 0).collect();
            if positive.is_empty() {
                // All weights zero: equal chances.
                let i = rand::thread_rng().gen_range(0..pool.len());
                vec![pool[i]]
            } else {
                let total: i64 = positive.iter().map(|r| r.weight.unwrap_or(0)).sum();
                let mut pick = rand::thread_rng().gen_range(0..total);
                let mut out = positive[0];
                for r in &positive {
                    let w = r.weight.unwrap_or(0);
                    if pick < w {
                        out = r;
                        break;
                    }
                    pick -= w;
                }
                vec![out]
            }
        }
        Some("failover") => {
            let role = |want: &str| group.iter().copied().find(|r| r.failover.as_deref() == Some(want));
            match (role("PRIMARY"), role("SECONDARY")) {
                (Some(p), _) if usable(zone, p, cx, depth) => vec![p],
                (_, Some(s)) if usable(zone, s, cx, depth) => vec![s],
                (Some(p), _) => vec![p],
                (None, Some(s)) => vec![s],
                (None, None) => Vec::new(),
            }
        }
        Some("multivalue answer") => {
            // Up to eight healthy record sets.
            pool.iter().copied().take(8).collect()
        }
        Some("latency") => {
            let home = pool.iter().copied().find(|r| r.region.as_deref() == Some("us-east-1"));
            home.or_else(|| pool.first().copied()).into_iter().collect()
        }
        Some("geolocation") => {
            let default = |r: &&ResourceRecordSet| {
                r.geo_location.as_ref().is_some_and(|g| g.country_code.as_deref() == Some("*"))
            };
            pool.iter().copied().find(default).into_iter().collect()
        }
        Some("IP-based") => cidr_choice(&pool, cx).into_iter().collect(),
        Some(_) => pool.first().copied().into_iter().collect(),
    };
    chosen.into_iter().flat_map(|r| expand(zone, r, cx, depth)).collect()
}

/// The record set whose CIDR location contains the client, by longest
/// prefix, else the one for the default location `*`.
fn cidr_choice<'r>(pool: &[&'r ResourceRecordSet], cx: &Context<'_>) -> Option<&'r ResourceRecordSet> {
    let mut best: Option<(u8, &ResourceRecordSet)> = None;
    if let Some(ip) = cx.client {
        for r in pool {
            let Some(cfg) = &r.cidr_routing_config else { continue };
            let Some(c) = cx.cidr_collections.get(&cfg.collection_id) else { continue };
            let Some(blocks) = c.locations.get(&cfg.location_name) else { continue };
            for b in blocks {
                if let Some(len) = contains(b, ip) {
                    if best.is_none_or(|(l, _)| len > l) {
                        best = Some((len, r));
                    }
                }
            }
        }
    }
    best.map(|(_, r)| r).or_else(|| {
        pool.iter().copied().find(|r| r.cidr_routing_config.as_ref().is_some_and(|c| c.location_name == "*"))
    })
}

/// The prefix length of `block` if it contains `ip`.
fn contains(block: &str, ip: IpAddr) -> Option<u8> {
    let (net, len) = block.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    let net: IpAddr = net.parse().ok()?;
    let (a, b, max) = match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => (u32::from(n) as u128, u32::from(i) as u128, 32u8),
        (IpAddr::V6(n), IpAddr::V6(i)) => (u128::from(n), u128::from(i), 128u8),
        _ => return None,
    };
    let shift = (max - len.min(max)) as u32;
    let mask = if shift >= 128 { 0 } else { u128::MAX << shift };
    (a & mask == b & mask).then_some(len)
}

/// Health check configurations by id, for [`Context::healthy`].
pub(crate) fn health_configs<'a>(
    checks: impl Iterator<Item = (&'a String, &'a crate::state::HealthCheck)>,
) -> HashMap<String, types::HealthCheckConfig> {
    checks.map(|(id, h)| (id.clone(), h.check.health_check_config.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_containment() {
        assert_eq!(contains("192.0.2.0/24", "192.0.2.9".parse().unwrap()), Some(24));
        assert_eq!(contains("192.0.2.0/24", "192.0.3.9".parse().unwrap()), None);
        assert_eq!(contains("0.0.0.0/0", "10.0.0.1".parse().unwrap()), Some(0));
        assert_eq!(contains("2001:db8::/32", "2001:db8::1".parse().unwrap()), Some(32));
    }
}
