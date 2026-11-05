//! The identity store's API network controls (`UpdateIdentityStore`).
//!
//! Requests to MWS never arrive through a VPC endpoint or from a VPC, so a
//! store that requires either accepts only callers whose source IP is in
//! `ApiAllowSourceIps`, which bypasses the other controls.

use std::net::IpAddr;

use crate::generated::types::NetworkConfigurationDetails;

fn in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n, b.parse::<u32>().ok()),
        None => (cidr, None),
    };
    let Ok(net) = net.parse::<IpAddr>() else { return false };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = bits.unwrap_or(32).min(32);
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = bits.unwrap_or(128).min(128);
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Whether a request from `source_ip` may use the identity store's API.
pub fn allows(n: &NetworkConfigurationDetails, source_ip: Option<&str>) -> bool {
    let allow_ips = n.api_allow_source_ips.as_deref().unwrap_or_default();
    let ip = source_ip.and_then(|s| s.parse::<IpAddr>().ok());
    if let Some(ip) = ip {
        if allow_ips.iter().any(|c| in_cidr(ip, c)) {
            return true;
        }
    }
    let restricted = n.vpce_access_required || !n.api_restrict_source_vpcs.as_deref().unwrap_or_default().is_empty();
    !restricted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs_and_restrictions() {
        assert!(in_cidr("10.1.2.3".parse().unwrap(), "10.0.0.0/8"));
        assert!(!in_cidr("11.1.2.3".parse().unwrap(), "10.0.0.0/8"));
        assert!(in_cidr("::1".parse().unwrap(), "::1/128"));
        let open = NetworkConfigurationDetails::default();
        assert!(allows(&open, Some("1.2.3.4")));
        let vpce = NetworkConfigurationDetails { vpce_access_required: true, ..Default::default() };
        assert!(!allows(&vpce, Some("127.0.0.1")));
        let bypass = NetworkConfigurationDetails {
            vpce_access_required: true,
            api_allow_source_ips: Some(vec!["127.0.0.0/8".into()]),
            ..Default::default()
        };
        assert!(allows(&bypass, Some("127.0.0.1")));
        assert!(!allows(&bypass, Some("10.0.0.1")));
    }
}
