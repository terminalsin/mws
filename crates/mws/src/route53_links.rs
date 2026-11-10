//! Route 53's links to the services its records point at: alias targets
//! that are load balancers or S3 website endpoints, and the VPCs of
//! private hosted zones.

use std::net::IpAddr;
use std::sync::Arc;

use mws_core::RequestContext;
use mws_route53::{AliasTargetCheck, AliasTargetResolver, Route53, VpcDirectory};

/// Connect Route 53 to ELB, S3 website endpoints and EC2 VPCs.
pub(crate) fn wire(route53: &Route53, elb: &mws_elb::Elb, ec2: &mws_ec2::Ec2) {
    route53.add_alias_resolver(Arc::new(Route53ToElb(elb.clone())));
    route53.add_alias_resolver(Arc::new(Route53ToS3Website));
    route53.set_vpc_directory(Arc::new(Route53Vpcs(ec2.clone())));
}

/// The Regions whose ELB and S3 website hosted zones Route 53 knows.
const REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "sa-east-1",
];

/// Aliases to Application, Network and Classic Load Balancers: the target
/// must be a load balancer published in that hosted zone. Answers are the
/// addresses its listeners are served on, and its health is whether it is
/// active with a healthy target.
struct Route53ToElb(mws_elb::Elb);

/// The suffixes of names in an ELB hosted zone: `<region>.elb.amazonaws.com`
/// for Application and Classic Load Balancers, `elb.<region>.amazonaws.com`
/// for Network and Gateway Load Balancers. Empty if the zone isn't ELB's.
fn elb_zone_suffixes(zone: &str) -> Vec<String> {
    let mut out = Vec::new();
    for region in REGIONS {
        if mws_elb::canonical_hosted_zone(region, "application") == zone {
            out.push(format!(".{region}.elb.amazonaws.com"));
        }
        if mws_elb::canonical_hosted_zone(region, "network") == zone {
            out.push(format!(".elb.{region}.amazonaws.com"));
        }
    }
    out
}

impl Route53ToElb {
    /// The load balancer an alias in ELB's hosted zone `zone` names.
    fn target(&self, zone: &str, dns_name: &str) -> Option<mws_elb::LoadBalancerInfo> {
        if elb_zone_suffixes(zone).is_empty() {
            return None;
        }
        let (_, _, lb) = self.0.load_balancer_by_dns_name(dns_name)?;
        (lb.canonical_hosted_zone_id.as_deref() == Some(zone)).then_some(lb)
    }
}

impl AliasTargetResolver for Route53ToElb {
    fn resolve(&self, hosted_zone_id: &str, dns_name: &str, record_type: &str) -> Option<Vec<String>> {
        let lb = self.target(hosted_zone_id, dns_name)?;
        let mut ips: Vec<IpAddr> = Vec::new();
        for a in self.0.listener_addresses().into_iter().filter(|a| a.load_balancer == lb.arn) {
            let ip = match a.address.ip() {
                IpAddr::V4(v) if v.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(v) if v.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                ip => ip,
            };
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        let values = match record_type {
            "A" => {
                let v4: Vec<String> = ips.iter().filter(|i| i.is_ipv4()).map(IpAddr::to_string).collect();
                // A load balancer without listeners still has addresses:
                // where MWS would serve them.
                if v4.is_empty() {
                    vec!["127.0.0.1".to_string()]
                } else {
                    v4
                }
            }
            "AAAA" => ips.iter().filter(|i| i.is_ipv6()).map(IpAddr::to_string).collect(),
            _ => Vec::new(),
        };
        Some(values)
    }

    fn check(&self, hosted_zone_id: &str, dns_name: &str, _record_type: &str) -> Option<AliasTargetCheck> {
        let suffixes = elb_zone_suffixes(hosted_zone_id);
        if suffixes.is_empty() {
            return None;
        }
        if let Some((_, _, lb)) = self.0.load_balancer_by_dns_name(dns_name) {
            return Some(if lb.canonical_hosted_zone_id.as_deref() == Some(hosted_zone_id) {
                AliasTargetCheck::Found
            } else {
                AliasTargetCheck::OutsideZone
            });
        }
        let name = dns_name.trim_end_matches('.').to_ascii_lowercase();
        Some(if suffixes.iter().any(|s| name.ends_with(s.as_str())) {
            AliasTargetCheck::NotFound
        } else {
            AliasTargetCheck::OutsideZone
        })
    }

    fn healthy(&self, hosted_zone_id: &str, dns_name: &str) -> Option<bool> {
        let lb = self.target(hosted_zone_id, dns_name)?;
        Some(lb.state.starts_with("active") && lb.healthy_targets > 0)
    }
}

/// The hosted zone of S3 website endpoints, per Region.
fn s3_website_zone(region: &str) -> Option<&'static str> {
    Some(match region {
        "us-east-1" => "Z3AQBSTGFYJSTF",
        "us-east-2" => "Z2O1EMRO9K5GLX",
        "us-west-1" => "Z2F56UZL2M1ACD",
        "us-west-2" => "Z3BJ6K6RIION7M",
        "ca-central-1" => "Z1QDHH18159H29",
        "eu-west-1" => "Z1BKCTXD74EZPE",
        "eu-west-2" => "Z3GKZC51ZF0DB4",
        "eu-west-3" => "Z3R1K369G5AVDG",
        "eu-central-1" => "Z21DNDUVLTQW6Q",
        "eu-north-1" => "Z3BAZG2TWCNX0D",
        "ap-southeast-1" => "Z3O0J2DXBE1FTB",
        "ap-southeast-2" => "Z1WCIGYICN2BYD",
        "ap-northeast-1" => "Z2M4EHUR26P7ZW",
        "ap-northeast-2" => "Z3W03O7B5YMIYP",
        "ap-south-1" => "Z11RGJOFQNVJUP",
        "sa-east-1" => "Z7KQH4QJS55SO",
        _ => return None,
    })
}

/// Aliases to S3 website endpoints (`s3-website-<region>.amazonaws.com` or
/// `s3-website.<region>.amazonaws.com` in that Region's hosted zone). As
/// on AWS, the endpoint is checked but the bucket is not (it is the
/// record's name, and may come later). MWS serves website endpoints
/// itself, so answers are the loopback address.
struct Route53ToS3Website;

impl Route53ToS3Website {
    /// `Some(true)` for the zone's endpoint, `Some(false)` for another name
    /// in an S3 website zone, `None` for other zones.
    fn endpoint(zone: &str, dns_name: &str) -> Option<bool> {
        let region = REGIONS.iter().find(|r| s3_website_zone(r) == Some(zone))?;
        let name = dns_name.trim_end_matches('.').to_ascii_lowercase();
        Some(
            name == format!("s3-website-{region}.amazonaws.com")
                || name == format!("s3-website.{region}.amazonaws.com"),
        )
    }
}

impl AliasTargetResolver for Route53ToS3Website {
    fn resolve(&self, hosted_zone_id: &str, dns_name: &str, record_type: &str) -> Option<Vec<String>> {
        if !Self::endpoint(hosted_zone_id, dns_name)? {
            return Some(Vec::new());
        }
        Some(if record_type == "A" { vec!["127.0.0.1".to_string()] } else { Vec::new() })
    }

    fn check(&self, hosted_zone_id: &str, dns_name: &str, _record_type: &str) -> Option<AliasTargetCheck> {
        Some(if Self::endpoint(hosted_zone_id, dns_name)? {
            AliasTargetCheck::Found
        } else {
            AliasTargetCheck::OutsideZone
        })
    }

    fn healthy(&self, hosted_zone_id: &str, dns_name: &str) -> Option<bool> {
        Self::endpoint(hosted_zone_id, dns_name)
    }
}

/// Private hosted zone VPCs are EC2's.
struct Route53Vpcs(mws_ec2::Ec2);

impl VpcDirectory for Route53Vpcs {
    fn vpc_exists(&self, ctx: &RequestContext, account: &str, region: &str, vpc_id: &str) -> bool {
        let mut in_region = ctx.clone();
        in_region.region = region.to_string();
        self.0.vpc_info(&in_region, account, Some(vpc_id)).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elb_zones_know_their_names() {
        assert_eq!(elb_zone_suffixes("Z35SXDOTRQ7X7K"), vec![".us-east-1.elb.amazonaws.com".to_string()]);
        assert_eq!(elb_zone_suffixes("Z26RNL4JYFTOTI"), vec![".elb.us-east-1.amazonaws.com".to_string()]);
        assert!(elb_zone_suffixes("Z2FDTNDATAQYW2").is_empty());
    }

    #[test]
    fn s3_website_endpoints() {
        assert_eq!(Route53ToS3Website::endpoint("Z3AQBSTGFYJSTF", "s3-website-us-east-1.amazonaws.com."), Some(true));
        assert_eq!(Route53ToS3Website::endpoint("Z3AQBSTGFYJSTF", "s3-website.us-west-2.amazonaws.com"), Some(false));
        assert_eq!(Route53ToS3Website::endpoint("Z2FDTNDATAQYW2", "d111.cloudfront.net"), None);
    }
}
