//! Identifiers, ARNs, DNS names and small helpers shared by both APIs.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::v2::{errors, types as t};

pub const SERVICE: &str = "elasticloadbalancing";

/// `n` random lower-case hex digits.
pub fn hex_id(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| char::from_digit(rng.gen_range(0..16), 16).expect("hex digit")).collect()
}

/// `n` random decimal digits, not starting with 0.
pub fn decimal_id(n: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(n);
    s.push(char::from_digit(rng.gen_range(1..10), 10).expect("digit"));
    for _ in 1..n {
        s.push(char::from_digit(rng.gen_range(0..10), 10).expect("digit"));
    }
    s
}

pub fn arn(ctx: &RequestContext, account: &str, resource: &str) -> String {
    format!("arn:{}:{SERVICE}:{}:{account}:{resource}", ctx.partition, ctx.region)
}

/// `app`, `net` or `gwy` for a load balancer type.
pub fn type_prefix(ty: &str) -> &'static str {
    match ty {
        "network" => "net",
        "gateway" => "gwy",
        _ => "app",
    }
}

/// The `app/name/id` part of a load balancer ARN, as CloudWatch's
/// `LoadBalancer` dimension names it.
pub fn lb_dimension(lb_arn: &str) -> String {
    lb_arn.split_once(":loadbalancer/").map(|(_, r)| r.to_string()).unwrap_or_default()
}

/// The `targetgroup/name/id` part of a target group ARN.
pub fn tg_dimension(tg_arn: &str) -> String {
    tg_arn.rsplit_once(':').map(|(_, r)| r.to_string()).unwrap_or_default()
}

/// The `app/name/lbid` part shared by a load balancer and its listeners.
pub fn lb_path_of_listener(listener_arn: &str) -> Option<String> {
    let rest = listener_arn.split_once(":listener/")?.1;
    let parts: Vec<&str> = rest.split('/').collect();
    (parts.len() >= 3).then(|| parts[..3].join("/"))
}

/// The DNS name AWS gives a load balancer.
pub fn dns_name(ctx: &RequestContext, ty: &str, name: &str, scheme: &str) -> String {
    let internal = if scheme == "internal" { "internal-" } else { "" };
    let suffix = dns_suffix(&ctx.partition);
    match ty {
        "network" | "gateway" => format!("{internal}{name}-{}.elb.{}.{suffix}", hex_id(16), ctx.region),
        _ => format!("{internal}{name}-{}.{}.elb.{suffix}", decimal_id(10), ctx.region),
    }
}

pub fn dns_suffix(partition: &str) -> &'static str {
    match partition {
        "aws-cn" => "amazonaws.com.cn",
        _ => "amazonaws.com",
    }
}

/// The Route 53 hosted zone ELB publishes load balancer names in, per
/// Region: Application and Classic Load Balancers share one, Network and
/// Gateway Load Balancers another.
pub fn canonical_hosted_zone(region: &str, ty: &str) -> &'static str {
    let network = matches!(ty, "network" | "gateway");
    let (app, net) = match region {
        "us-east-1" => ("Z35SXDOTRQ7X7K", "Z26RNL4JYFTOTI"),
        "us-east-2" => ("Z3AADJGX6KTTL2", "ZLMOA37VPKANP"),
        "us-west-1" => ("Z368ELLRRE2KJ0", "Z24FKFUX50B4VW"),
        "us-west-2" => ("Z1H1FL5HABSF5", "Z18D5FSROUN65G"),
        "ca-central-1" => ("ZQSVJUPU6J1EY", "Z2EPGBW3API2WT"),
        "eu-west-1" => ("Z32O12XQLNTSW2", "Z2IFOLAFXWLO4F"),
        "eu-west-2" => ("ZHURV8PSTC4K8", "ZD4D7Y8KGAS4G"),
        "eu-west-3" => ("Z3Q77PNBQS71R4", "Z1CMS0P5QUZ6D5"),
        "eu-central-1" => ("Z215JYRZR1TBD5", "Z3F0SRJ5LGBH90"),
        "eu-north-1" => ("Z23TAZ7KHOXRUD", "Z1UDT6IFJ4EJM"),
        "ap-southeast-1" => ("Z1LMS91P8CMLE5", "ZKVM4W9LS7TM"),
        "ap-southeast-2" => ("Z1GM3OXH4ZPM65", "ZCT6FZBF4S36A"),
        "ap-northeast-1" => ("Z14GRHDCWA56QT", "Z31USIVHYNEOWT"),
        "ap-northeast-2" => ("ZWKZPGTI48KDX", "ZIBE1TIR4HY56"),
        "ap-south-1" => ("ZP97RAFLXTNZK", "ZVDDRBQ08TROA"),
        "sa-east-1" => ("Z2P70J7HTTTPLU", "ZTK26PT1VY4CU"),
        _ => ("Z35SXDOTRQ7X7K", "Z26RNL4JYFTOTI"),
    };
    if network {
        net
    } else {
        app
    }
}

/// Load balancer and target group names: 1-32 alphanumerics and hyphens,
/// not starting or ending with a hyphen.
pub fn check_name(kind: &str, name: &str) -> Result<(), ServiceError> {
    if name.is_empty() || name.len() > 32 {
        return Err(validation(format!("{kind} name '{name}' cannot be longer than '32' characters")));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(validation(format!(
            "{kind} name '{name}' can only contain characters that are alphanumeric characters or hyphens(-)"
        )));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(validation(format!("{kind} name '{name}' cannot begin or end with '-' character")));
    }
    Ok(())
}

pub fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationError", 400, message)
}

/// `elasticloadbalancing:<action>` on `resource`.
pub fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    extra: ConditionContext,
) -> Result<(), ServiceError> {
    ctx.authorize(&format!("{SERVICE}:{action}"), resource, extra)
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &[t::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags {
        c.insert(format!("aws:RequestTag/{}", tag.key), vec![tag.value.clone().unwrap_or_default()]);
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

/// `aws:ResourceTag/*` (and the service's own `elasticloadbalancing:
/// ResourceTag/*`) for a resource's tags.
pub fn resource_tag_context(tags: &[t::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags {
        let v = vec![tag.value.clone().unwrap_or_default()];
        c.insert(format!("aws:ResourceTag/{}", tag.key), v.clone());
        c.insert(format!("{SERVICE}:ResourceTag/{}", tag.key), v);
    }
    c
}

pub fn merge(mut a: ConditionContext, b: ConditionContext) -> ConditionContext {
    a.extend(b);
    a
}

/// One page of `items` after `marker` (an index, opaque to callers).
pub fn page<T: Clone>(
    items: &[T],
    marker: Option<&str>,
    page_size: Option<i32>,
    max: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match marker {
        None => 0,
        Some(m) => m.parse::<usize>().map_err(|_| validation("The marker is not valid"))?,
    };
    let size = page_size.map(|s| s.max(1) as usize).unwrap_or(max).min(max);
    let end = (start + size).min(items.len());
    let slice = items.get(start..end).map(<[T]>::to_vec).unwrap_or_default();
    let next = (end < items.len()).then(|| end.to_string());
    Ok((slice, next))
}

/// Check tags: unique keys, no `aws:` prefix.
pub fn check_tags(tags: &[t::Tag]) -> Result<(), ServiceError> {
    let mut seen = std::collections::BTreeSet::new();
    for tag in tags {
        if !seen.insert(tag.key.as_str()) {
            return Err(errors::duplicate_tag_keys(format!("Tag key '{}' is duplicated", tag.key)));
        }
        if tag.key.to_ascii_lowercase().starts_with("aws:") {
            return Err(validation(format!("Tag key '{}' cannot start with 'aws:'", tag.key)));
        }
    }
    Ok(())
}

/// Whether `ip` (IPv4) falls in `cidr`.
pub fn ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
    let Some((net, bits)) = cidr.split_once('/') else { return false };
    let (Ok(ip), Ok(net), Ok(bits)) =
        (ip.parse::<std::net::Ipv4Addr>(), net.parse::<std::net::Ipv4Addr>(), bits.parse::<u32>())
    else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// Whether `ip` (IPv6) falls in `cidr`.
pub fn ipv6_in_cidr(ip: &str, cidr: &str) -> bool {
    let Some((net, bits)) = cidr.split_once('/') else { return false };
    let (Ok(ip), Ok(net), Ok(bits)) =
        (ip.parse::<std::net::Ipv6Addr>(), net.parse::<std::net::Ipv6Addr>(), bits.parse::<u32>())
    else {
        return false;
    };
    if bits > 128 {
        return false;
    }
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

/// Whether a source address matches a CIDR (either family).
pub fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    ipv4_in_cidr(ip, cidr) || ipv6_in_cidr(ip, cidr)
}
