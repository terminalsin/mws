//! ARNs, ids, how requests name resources, pagination and authorization.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::{errors, types as t};

/// The account a request works in.
pub fn account_of(ctx: &RequestContext) -> String {
    match ctx.caller.account_id.as_str() {
        "" => "000000000000".to_string(),
        a => a.to_string(),
    }
}

/// Where a request's resources live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub partition: String,
    pub region: String,
    pub account: String,
}

impl Scope {
    pub fn of(ctx: &RequestContext) -> Self {
        Self { partition: ctx.partition.clone(), region: ctx.region.clone(), account: account_of(ctx) }
    }

    pub fn key(&self) -> String {
        format!("{}/{}", self.account, self.region)
    }

    pub fn arn(&self, resource: &str) -> String {
        format!("arn:{}:ecs:{}:{}:{resource}", self.partition, self.region, self.account)
    }

    pub fn cluster_arn(&self, name: &str) -> String {
        self.arn(&format!("cluster/{name}"))
    }

    pub fn iam_root(&self) -> String {
        format!("arn:{}:iam::{}:root", self.partition, self.account)
    }
}

/// `(region, account, resource)` of an ECS ARN.
pub fn split_arn(arn: &str) -> Option<(&str, &str, &str)> {
    let mut p = arn.splitn(6, ':');
    let (Some("arn"), Some(_), Some("ecs"), Some(region), Some(account), Some(resource)) =
        (p.next(), p.next(), p.next(), p.next(), p.next(), p.next())
    else {
        return None;
    };
    Some((region, account, resource))
}

/// The name a cluster reference (name or ARN) points at. `None` defaults
/// to the `default` cluster, as in AWS.
pub fn cluster_name(reference: Option<&str>) -> String {
    match reference.filter(|r| !r.is_empty()) {
        None => "default".to_string(),
        Some(r) => match split_arn(r) {
            Some((_, _, res)) => res.strip_prefix("cluster/").unwrap_or(res).to_string(),
            None => r.to_string(),
        },
    }
}

/// The last path segment of a resource reference (a task id from a task
/// ARN, a service name from a service ARN, ...).
pub fn last_segment(reference: &str) -> &str {
    match split_arn(reference) {
        Some((_, _, res)) => res.rsplit('/').next().unwrap_or(res),
        None => reference,
    }
}

pub fn now(ctx: &RequestContext) -> DateTime<Utc> {
    ctx.received_at
}

pub fn hex_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A 19-digit numeric id (deployment and revision ids).
pub fn numeric_id() -> String {
    let mut rng = rand::thread_rng();
    let first: u8 = rng.gen_range(1..10);
    let rest: String = (0..18).map(|_| char::from(b'0' + rng.gen_range(0..10u8))).collect();
    format!("{first}{rest}")
}

/// A 22-character id (service deployment ids).
pub fn short_id() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = rand::thread_rng();
    (0..22).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

pub fn invalid(message: impl Into<String>) -> ServiceError {
    errors::invalid_parameter(message)
}

pub fn client(message: impl Into<String>) -> ServiceError {
    errors::client(message)
}

pub fn cluster_not_found() -> ServiceError {
    errors::cluster_not_found("Cluster not found.")
}

pub fn service_not_found() -> ServiceError {
    errors::service_not_found("Service not found.")
}

pub fn failure(arn: impl Into<String>, reason: &str) -> t::Failure {
    t::Failure { arn: Some(arn.into()), reason: Some(reason.into()), detail: None }
}

/// Pagination over an ordered list: tokens carry the offset.
pub fn paginate<T: Clone>(
    items: &[T],
    next_token: Option<&str>,
    max_results: Option<i32>,
    max_allowed: i32,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token.filter(|t| !t.is_empty()) {
        None => 0,
        Some(tok) => decode_token(tok).ok_or_else(|| invalid("Invalid token"))?,
    };
    let limit = match max_results {
        None => max_allowed as usize,
        Some(n) if n < 1 || n > max_allowed => {
            return Err(invalid(format!("maxResults must be between 1 and {max_allowed}.")));
        }
        Some(n) => n as usize,
    };
    let page: Vec<T> = items.iter().skip(start).take(limit).cloned().collect();
    let next = (start + page.len() < items.len()).then(|| encode_token(start + page.len()));
    Ok((page, next))
}

fn encode_token(offset: usize) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{{\"mws\":{offset}}}"))
}

fn decode_token(token: &str) -> Option<usize> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(token).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get("mws")?.as_u64().map(|n| n as usize)
}

pub type Tags = Vec<t::Tag>;

pub fn tag_map(tags: &[t::Tag]) -> BTreeMap<String, String> {
    tags.iter().map(|t| (t.key.clone().unwrap_or_default(), t.value.clone().unwrap_or_default())).collect()
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn resource_tags(tags: Option<&Tags>) -> ConditionContext {
    tags.into_iter()
        .flatten()
        .map(|t| (format!("aws:ResourceTag/{}", t.key.clone().unwrap_or_default()), vec![t.value.clone().unwrap_or_default()]))
        .collect()
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tags(tags: Option<&Tags>) -> ConditionContext {
    let mut c = ConditionContext::new();
    let Some(tags) = tags.filter(|t| !t.is_empty()) else { return c };
    for t in tags {
        c.insert(format!("aws:RequestTag/{}", t.key.clone().unwrap_or_default()), vec![t.value.clone().unwrap_or_default()]);
    }
    c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone().unwrap_or_default()).collect());
    c
}

/// Builds the condition context of one authorization.
#[derive(Default)]
pub struct Cond(pub ConditionContext);

impl Cond {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        self.0.insert(key.to_string(), vec![value.into()]);
        self
    }

    pub fn with_opt(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.with(key, v),
            None => self,
        }
    }

    pub fn with_list(mut self, key: &str, values: Vec<String>) -> Self {
        if !values.is_empty() {
            self.0.insert(key.to_string(), values);
        }
        self
    }

    pub fn cluster(self, scope: &Scope, cluster: &str) -> Self {
        self.with("ecs:cluster", scope.cluster_arn(cluster))
    }

    pub fn extend(mut self, other: ConditionContext) -> Self {
        self.0.extend(other);
        self
    }
}

pub fn authorize(ctx: &RequestContext, action: &str, resource: &str, cond: Cond) -> Result<(), ServiceError> {
    ctx.authorize(&format!("ecs:{action}"), resource, cond.0).map_err(ecs_denial)
}

/// ECS answers authorization failures with `AccessDeniedException`.
pub fn ecs_denial(mut e: ServiceError) -> ServiceError {
    if e.code == "AccessDenied" {
        e.code = "AccessDeniedException".into();
        e.status = 400;
    }
    e
}

/// Validate tags the way ECS does.
pub fn check_tags(tags: &[t::Tag]) -> Result<(), ServiceError> {
    if tags.len() > 50 {
        return Err(invalid("The number of tags in the request exceeds the maximum of 50."));
    }
    for tag in tags {
        let key = tag.key.as_deref().unwrap_or_default();
        if key.is_empty() {
            return Err(invalid("Tag keys must be between 1 and 128 characters."));
        }
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err(invalid("Tag keys and values may not start with 'aws:'."));
        }
    }
    Ok(())
}

/// ECS accepts task CPU as units (`1024`) or vCPU (`1 vCPU`), and memory as
/// MiB (`2048`) or GB (`2 GB`); it stores the numbers.
pub fn normalize_cpu(v: &str) -> Option<String> {
    let s = v.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n.to_string());
    }
    let lower = s.to_ascii_lowercase();
    let num = lower.strip_suffix("vcpu").map(str::trim)?;
    let f: f64 = num.parse().ok()?;
    Some(((f * 1024.0).round() as u64).to_string())
}

pub fn normalize_memory(v: &str) -> Option<String> {
    let s = v.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n.to_string());
    }
    let lower = s.to_ascii_lowercase();
    let num = lower.strip_suffix("gb").map(str::trim)?;
    let f: f64 = num.parse().ok()?;
    Some(((f * 1024.0).round() as u64).to_string())
}
