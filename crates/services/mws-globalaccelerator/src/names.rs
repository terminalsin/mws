//! ARNs, ids, errors, authorization, tags and pagination.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::{errors, types};

pub const TAG_LIMIT: usize = 50;

/// The Regions an endpoint group can be in.
pub const REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-south-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-south-1",
    "eu-south-2",
    "eu-north-1",
    "il-central-1",
    "me-south-1",
    "me-central-1",
    "mx-central-1",
    "sa-east-1",
];

pub fn now_ms(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

pub fn time(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

pub fn account(ctx: &RequestContext) -> String {
    ctx.caller.account_id.clone()
}

fn hex(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| char::from_digit(rng.gen_range(0..16), 16).unwrap()).collect()
}

pub fn accelerator_arn(ctx: &RequestContext) -> String {
    format!("arn:{}:globalaccelerator::{}:accelerator/{}", ctx.partition, account(ctx), uuid::Uuid::new_v4())
}

pub fn listener_arn(accelerator: &str) -> String {
    format!("{accelerator}/listener/{}", hex(8))
}

pub fn group_arn(listener: &str) -> String {
    format!("{listener}/endpoint-group/{}", hex(12))
}

pub fn attachment_arn(ctx: &RequestContext) -> String {
    format!("arn:{}:globalaccelerator::{}:attachment/{}", ctx.partition, account(ctx), uuid::Uuid::new_v4())
}

pub fn dns_name() -> String {
    format!("a{}.awsglobalaccelerator.com", hex(16))
}

pub fn dual_stack_dns_name() -> String {
    format!("a{}.dualstack.awsglobalaccelerator.com", hex(16))
}

/// `accelerator/<id>[/listener/<id>[/endpoint-group/<id>]]` split into the
/// accelerator, listener and endpoint group ARNs it names.
pub struct Path {
    pub accelerator: String,
    pub listener: Option<String>,
    pub group: Option<String>,
}

pub fn parse(arn: &str) -> Option<Path> {
    if !arn.starts_with("arn:") || !arn.contains(":globalaccelerator::") {
        return None;
    }
    let (accelerator, rest) = match arn.find("/listener/") {
        Some(i) => (&arn[..i], Some(&arn[i..])),
        None => (arn, None),
    };
    if !accelerator.split(':').nth(5).is_some_and(|r| r.starts_with("accelerator/")) {
        return None;
    }
    let mut path = Path { accelerator: accelerator.to_string(), listener: None, group: None };
    if let Some(rest) = rest {
        match rest.find("/endpoint-group/") {
            Some(i) => {
                path.listener = Some(format!("{accelerator}{}", &rest[..i]));
                path.group = Some(arn.to_string());
            }
            None => path.listener = Some(arn.to_string()),
        }
    }
    Some(path)
}

pub fn invalid(message: impl Into<String>) -> ServiceError {
    errors::invalid_argument(message)
}

pub fn accelerator_not_found(arn: &str) -> ServiceError {
    errors::accelerator_not_found(format!("Accelerator {arn} not found."))
}

pub fn listener_not_found(arn: &str) -> ServiceError {
    errors::listener_not_found(format!("Listener {arn} not found."))
}

pub fn group_not_found(arn: &str) -> ServiceError {
    errors::endpoint_group_not_found(format!("Endpoint group {arn} not found."))
}

pub fn attachment_not_found(arn: &str) -> ServiceError {
    errors::attachment_not_found(format!("Cross-account attachment {arn} not found."))
}

/// Global Accelerator answers denials with `AccessDeniedException`.
pub fn denial(e: ServiceError) -> ServiceError {
    if e.code == "AccessDenied" {
        errors::access_denied(e.message)
    } else {
        e
    }
}

pub fn tag_map(tags: &[types::Tag]) -> BTreeMap<String, String> {
    tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect()
}

pub fn tag_list(tags: &BTreeMap<String, String>) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()
}

pub fn check_tags(tags: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    if tags.len() > TAG_LIMIT {
        return Err(invalid(format!("A resource can have at most {TAG_LIMIT} tags.")));
    }
    if let Some(k) = tags.keys().find(|k| k.starts_with("aws:")) {
        return Err(invalid(format!("Tag key {k} uses the reserved prefix aws:.")));
    }
    Ok(())
}

pub fn resource_tags(tags: &BTreeMap<String, String>) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

pub fn request_tags(tags: &BTreeMap<String, String>) -> ConditionContext {
    let mut c: ConditionContext = tags.iter().map(|(k, v)| (format!("aws:RequestTag/{k}"), vec![v.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    c
}

/// Authorize `globalaccelerator:<action>` on `resource`.
pub fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    extra: ConditionContext,
) -> Result<(), ServiceError> {
    ctx.authorize(&format!("globalaccelerator:{action}"), resource, extra).map_err(denial)
}

/// One page of `items`: tokens are opaque offsets.
pub fn page<T>(
    items: Vec<T>,
    max_results: Option<i32>,
    next_token: Option<&str>,
    default_max: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token {
        None => 0,
        Some(t) => decode_token(t)?,
    };
    if start > items.len() {
        return Err(errors::invalid_next_token("The next token is not valid."));
    }
    let max = max_results.map(|m| m.max(1) as usize).unwrap_or(default_max);
    let end = (start + max).min(items.len());
    let token = (end < items.len()).then(|| encode_token(end));
    Ok((items.into_iter().skip(start).take(max).collect(), token))
}

pub fn encode_token(offset: usize) -> String {
    format!("{:016x}{}", offset, hex(16))
}

pub fn decode_token(token: &str) -> Result<usize, ServiceError> {
    token
        .get(..16)
        .filter(|_| token.len() == 32)
        .and_then(|h| usize::from_str_radix(h, 16).ok())
        .ok_or_else(|| errors::invalid_next_token("The next token is not valid."))
}

/// What an endpoint id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    ApplicationLoadBalancer,
    NetworkLoadBalancer,
    Instance,
    ElasticIp,
}

impl EndpointKind {
    pub fn of(id: &str) -> Option<Self> {
        if id.starts_with("arn:") {
            let parts: Vec<&str> = id.splitn(6, ':').collect();
            if parts.len() == 6 && parts[2] == "elasticloadbalancing" {
                if parts[5].starts_with("loadbalancer/app/") {
                    return Some(Self::ApplicationLoadBalancer);
                }
                if parts[5].starts_with("loadbalancer/net/") {
                    return Some(Self::NetworkLoadBalancer);
                }
            }
            return None;
        }
        let suffix_ok =
            |p: &str| id.strip_prefix(p).is_some_and(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()));
        if suffix_ok("i-") {
            Some(Self::Instance)
        } else if suffix_ok("eipalloc-") {
            Some(Self::ElasticIp)
        } else {
            None
        }
    }

    /// Client IP address preservation when the request does not say.
    pub fn preserves_client_ip_by_default(self) -> bool {
        matches!(self, Self::ApplicationLoadBalancer | Self::Instance)
    }
}

/// The load balancer ARN's Region and account.
pub fn elb_region_account(id: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = id.splitn(6, ':').collect();
    (parts.len() == 6).then(|| (parts[3], parts[4]))
}
