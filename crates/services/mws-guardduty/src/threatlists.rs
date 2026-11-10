//! Threat list and trusted list files: where they are, how GuardDuty
//! reads them (`ACTIVATING`, then `ACTIVE`, or `ERROR` when the file
//! cannot be read or holds nothing usable) and matching IP addresses
//! against them.

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;

use crate::common::detector_arn;
use crate::lists::Kind;
use crate::state::ThreatList;
use crate::GuardDuty;

/// How long a list stays `ACTIVATING` before GuardDuty has read it.
pub const ACTIVATION_SECONDS: i64 = 5;

/// `(bucket, key)` of a list location: `s3://bucket/key`, or an S3 HTTPS
/// URL in path style (`https://s3[.region].amazonaws.com/bucket/key`) or
/// virtual-hosted style (`https://bucket.s3[.region].amazonaws.com/key`).
pub fn parse_location(location: &str) -> Option<(String, String)> {
    if let Some(rest) = location.strip_prefix("s3://") {
        let (b, k) = rest.split_once('/')?;
        return (!b.is_empty() && !k.is_empty()).then(|| (b.to_string(), k.to_string()));
    }
    let rest = location.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/')?;
    if host.starts_with("s3.") || host.starts_with("s3-") {
        let (b, k) = path.split_once('/')?;
        return (!b.is_empty() && !k.is_empty()).then(|| (b.to_string(), k.to_string()));
    }
    let i = host.find(".s3.").or_else(|| host.find(".s3-"))?;
    let bucket = &host[..i];
    (!bucket.is_empty() && !path.is_empty()).then(|| (bucket.to_string(), path.to_string()))
}

/// An IP address or CIDR range: `(network address, prefix length)`.
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
        None => max,
    };
    Some((ip, prefix))
}

/// Whether `ip` is the address, or in the range, `entry` names.
pub fn contains(entry: &str, ip: IpAddr) -> bool {
    let Some((net, prefix)) = parse_cidr(entry) else { return false };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

fn is_domain(s: &str) -> bool {
    s.contains('.')
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '*')
        })
        && s.rsplit('.').next().is_some_and(|tld| tld.chars().any(|c| c.is_ascii_alphabetic()))
}

/// The entries of a list file in `format`: one IP address, CIDR range (or,
/// for entity sets, domain) per line for `TXT`; for the structured formats
/// (`STIX`, `OTX_CSV`, `ALIEN_VAULT`, `FIRE_EYE`, `PROOF_POINT`) every IP
/// address and CIDR range the file mentions. `Err` when nothing usable is
/// there.
pub fn parse_list(format: &str, body: &[u8], domains: bool) -> Result<Vec<String>, String> {
    let text = String::from_utf8_lossy(body);
    let mut out: Vec<String> = Vec::new();
    if format == "TXT" {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if parse_cidr(line).is_some() || (domains && is_domain(line)) {
                out.push(line.to_string());
            } else {
                return Err(format!("The list file has an invalid entry: {line}"));
            }
        }
    } else {
        let token = |c: char| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/');
        for t in text.split(|c: char| !token(c)) {
            let t = t.trim_matches(|c| c == '.' || c == ':' || c == '/');
            if !t.is_empty()
                && parse_cidr(t).is_some()
                && (t.contains('.') || t.contains("::") || t.matches(':').count() >= 2)
            {
                out.push(t.to_string());
            }
        }
    }
    out.dedup();
    if out.is_empty() {
        return Err("The list file has no valid entries.".into());
    }
    Ok(out)
}

/// Start activating `l` at `now`.
pub fn start_activation(l: &mut ThreatList, now: DateTime<Utc>) {
    l.status = "ACTIVATING".into();
    l.ready_at = Some(now + Duration::seconds(ACTIVATION_SECONDS));
    l.entries.clear();
    l.error = None;
}

struct Pending {
    account: String,
    region: String,
    detector: String,
    kind: Kind,
    id: String,
    format: String,
    location: String,
    expected_bucket_owner: Option<String>,
}

impl GuardDuty {
    /// Finish activating every list whose activation time has come:
    /// GuardDuty reads its file and the list becomes `ACTIVE`, or `ERROR`.
    pub(crate) fn settle_lists(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let pending: Vec<Pending> = {
            let state = self.lock();
            let mut out = Vec::new();
            for (key, acct) in &state.accounts {
                let Some(d) = &acct.detector else { continue };
                let (account, region) = key.split_once('/').unwrap_or((key, ""));
                for kind in Kind::ALL {
                    for (id, l) in kind.map(d) {
                        if l.status == "ACTIVATING" && l.ready_at.is_some_and(|t| t <= now) {
                            out.push(Pending {
                                account: account.to_string(),
                                region: region.to_string(),
                                detector: d.id.clone(),
                                kind,
                                id: id.clone(),
                                format: l.format.clone(),
                                location: l.location.clone(),
                                expected_bucket_owner: l.expected_bucket_owner.clone(),
                            });
                        }
                    }
                }
            }
            out
        };
        if pending.is_empty() {
            return;
        }
        let source = self.list_source();
        for p in pending {
            let result = match parse_location(&p.location) {
                None => Err("The location is not a valid S3 URL.".to_string()),
                Some((bucket, key)) => match &source {
                    None => Ok(Vec::new()),
                    Some(src) => {
                        let rctx = RequestContext { region: p.region.clone(), ..ctx.clone() };
                        let arn = detector_arn(&rctx, &p.account, &p.detector);
                        src.read(&ctx.partition, &p.account, &arn, &bucket, &key, p.expected_bucket_owner.as_deref())
                            .map_err(|code| format!("GuardDuty could not read the list file: {code}"))
                            .and_then(|body| {
                                parse_list(
                                    &p.format,
                                    &body,
                                    matches!(p.kind, Kind::ThreatEntitySet | Kind::TrustedEntitySet),
                                )
                            })
                    }
                },
            };
            let mut state = self.lock();
            let Some(d) = state.detector_mut(&p.account, &p.region).filter(|d| d.id == p.detector) else { continue };
            let Some(l) = p.kind.map_mut(d).get_mut(&p.id) else { continue };
            if l.status != "ACTIVATING" || l.location != p.location {
                continue;
            }
            l.ready_at = None;
            match result {
                Ok(entries) => {
                    l.status = "ACTIVE".into();
                    l.entries = entries;
                    l.error = None;
                }
                Err(e) => {
                    tracing::debug!(list = %p.id, "GuardDuty list activation failed: {e}");
                    l.status = "ERROR".into();
                    l.entries.clear();
                    l.error = Some(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations() {
        let bk = |b: &str, k: &str| Some((b.to_string(), k.to_string()));
        assert_eq!(parse_location("s3://lists/a/b.txt"), bk("lists", "a/b.txt"));
        assert_eq!(parse_location("https://s3.amazonaws.com/lists/office.txt"), bk("lists", "office.txt"));
        assert_eq!(parse_location("https://s3.eu-west-1.amazonaws.com/lists/o.txt"), bk("lists", "o.txt"));
        assert_eq!(parse_location("https://lists.s3.amazonaws.com/o.txt"), bk("lists", "o.txt"));
        assert_eq!(parse_location("https://lists.s3.us-east-1.amazonaws.com/o.txt"), bk("lists", "o.txt"));
        assert_eq!(parse_location("s3://lists"), None);
    }

    #[test]
    fn cidrs_match() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(contains("127.0.0.0/8", ip("127.0.0.1")));
        assert!(contains("198.51.100.7", ip("198.51.100.7")));
        assert!(!contains("198.51.100.0/25", ip("198.51.100.200")));
        assert!(contains("0.0.0.0/0", ip("10.1.2.3")));
        assert!(contains("2001:db8::/32", ip("2001:db8::1")));
        assert!(!contains("2001:db8::/32", ip("127.0.0.1")));
    }

    #[test]
    fn formats() {
        assert_eq!(parse_list("TXT", b"# office\n198.51.100.0/24\n\n203.0.113.9\n", false).unwrap().len(), 2);
        assert!(parse_list("TXT", b"not-an-ip\n", false).is_err());
        assert_eq!(parse_list("TXT", b"evil.example.com\n", true).unwrap(), ["evil.example.com"]);
        assert!(parse_list("TXT", b"", false).is_err());
        let stix = br#"<cybox:Object><AddressObj:Address_Value condition="Equals">203.0.113.5</AddressObj:Address_Value></cybox:Object>"#;
        assert_eq!(parse_list("STIX", stix, false).unwrap(), ["203.0.113.5"]);
        let csv = b"Indicator type,Indicator,Description\nIPv4,198.51.100.3,bad\nCIDR,203.0.113.0/24,worse\n";
        assert_eq!(parse_list("OTX_CSV", csv, false).unwrap(), ["198.51.100.3", "203.0.113.0/24"]);
    }
}
