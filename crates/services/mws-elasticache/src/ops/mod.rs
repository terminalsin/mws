//! The ElastiCache operations, grouped by resource.

pub mod clusters;
pub mod global;
pub mod misc;
pub mod params;
pub mod replication;
pub mod serverless;
pub mod snapshots;
pub mod subnets;
pub mod users;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::{errors, types as t};
use crate::state::RegionState;
use crate::{account_of, ElastiCache};

pub(crate) fn invalid(message: impl Into<String>) -> ServiceError {
    errors::invalid_parameter_value(message)
}

pub(crate) fn combination(message: impl Into<String>) -> ServiceError {
    errors::invalid_parameter_combination(message)
}

pub(crate) fn arn(ctx: &RequestContext, kind: &str, id: &str) -> String {
    format!("arn:{}:elasticache:{}:{}:{kind}:{id}", ctx.partition, ctx.region, account_of(ctx))
}

/// Check an identifier the way ElastiCache does, returning it lowercased
/// (ElastiCache stores identifiers in lowercase).
pub(crate) fn identifier(param: &str, id: &str, max: usize) -> Result<String, ServiceError> {
    if id.is_empty() {
        return Err(invalid(format!("The parameter {param} must be provided and must not be blank.")));
    }
    if id.len() > max {
        return Err(invalid(format!(
            "The parameter {param} is not a valid identifier because it is longer than {max} characters."
        )));
    }
    let ok = id.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !id.ends_with('-')
        && !id.contains("--");
    if !ok {
        return Err(invalid(format!(
            "The parameter {param} is not a valid identifier. Identifiers must begin with a letter; must contain only ASCII letters, digits, and hyphens; and must not end with a hyphen or contain two consecutive hyphens."
        )));
    }
    Ok(id.to_ascii_lowercase())
}

/// One page of `items` after `marker`, at most `max` (20..=100, default
/// 100) long, and the marker of the next page.
pub(crate) fn page<T: Clone>(
    items: Vec<T>,
    marker: Option<&str>,
    max: Option<i32>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let max = match max {
        None => 100,
        Some(m) if (20..=100).contains(&m) => m as usize,
        Some(_) => return Err(invalid("Invalid value for parameter MaxRecords: must be between 20 and 100.")),
    };
    page_with(items, marker, max, "Marker")
}

pub(crate) fn page_with<T: Clone>(
    items: Vec<T>,
    marker: Option<&str>,
    max: usize,
    marker_name: &str,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match marker.filter(|m| !m.is_empty()) {
        None => 0,
        Some(m) => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(m)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.strip_prefix("mws:").and_then(|n| n.parse::<usize>().ok()))
            .ok_or_else(|| invalid(format!("Invalid {marker_name}: {m}")))?,
    };
    let end = (start + max).min(items.len());
    let next =
        (end < items.len()).then(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("mws:{end}")));
    Ok((items.get(start..end).map(<[T]>::to_vec).unwrap_or_default(), next))
}

pub(crate) fn random_hex(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| format!("{:x}", rng.gen_range(0..16u8))).collect()
}

pub(crate) fn random_password() -> String {
    let mut rng = rand::thread_rng();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..32).map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char).collect()
}

// ---- tags and authorization ---------------------------------------------

pub(crate) fn check_tags(tags: &[t::Tag]) -> Result<(), ServiceError> {
    for tag in tags {
        let key = tag.key.as_deref().unwrap_or_default();
        if key.is_empty() || key.len() > 128 {
            return Err(invalid("Tag keys must be between 1 and 128 characters long."));
        }
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err(invalid("Invalid tag key: aws: prefix is reserved and cannot be used in tag keys."));
        }
        if tag.value.as_deref().unwrap_or_default().len() > 256 {
            return Err(invalid("Tag values must be at most 256 characters long."));
        }
    }
    if tags.len() > 50 {
        return Err(errors::tag_quota_per_resource_exceeded("TagQuotaPerResource has been exceeded"));
    }
    Ok(())
}

pub(crate) fn request_tag_context(tags: &[t::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags {
        let k = tag.key.clone().unwrap_or_default();
        c.insert(format!("aws:RequestTag/{k}"), vec![tag.value.clone().unwrap_or_default()]);
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone().unwrap_or_default()).collect());
    }
    c
}

/// Authorize `elasticache:<action>` on `resource`, with the resource's
/// tags as `aws:ResourceTag/*`.
pub(crate) fn authorize(
    ctx: &RequestContext,
    r: &RegionState,
    action: &str,
    resource: &str,
    mut extra: ConditionContext,
) -> Result<(), ServiceError> {
    for tag in r.tags.get(resource).into_iter().flatten() {
        extra
            .entry(format!("aws:ResourceTag/{}", tag.key.clone().unwrap_or_default()))
            .or_insert_with(|| vec![tag.value.clone().unwrap_or_default()]);
    }
    ctx.authorize(&format!("elasticache:{action}"), resource, extra)
}

/// Authorize creating `resource` with `tags` (tagging on create also needs
/// `elasticache:AddTagsToResource`).
pub(crate) fn authorize_create(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    tags: &[t::Tag],
    mut extra: ConditionContext,
) -> Result<(), ServiceError> {
    extra.extend(request_tag_context(tags));
    ctx.authorize(&format!("elasticache:{action}"), resource, extra.clone())?;
    if !tags.is_empty() {
        ctx.authorize("elasticache:AddTagsToResource", resource, extra)?;
    }
    Ok(())
}

pub(crate) fn cond(pairs: &[(&str, Option<String>)]) -> ConditionContext {
    pairs.iter().filter_map(|(k, v)| v.as_ref().map(|v| (format!("elasticache:{k}"), vec![v.clone()]))).collect()
}

pub(crate) fn set_tags(r: &mut RegionState, arn: &str, tags: Option<Vec<t::Tag>>) {
    if let Some(tags) = tags.filter(|t| !t.is_empty()) {
        r.tags.insert(arn.to_string(), tags);
    }
}

/// Deliver an event to a notification topic, when one is configured.
pub(crate) fn notify(svc: &ElastiCache, ctx: &RequestContext, topic: Option<&str>, source_arn: &str, message: &str) {
    if let (Some(topic), Some(n)) = (topic, svc.notifier()) {
        n.notify(ctx, topic, source_arn, message);
    }
}

/// `elasticache:` condition values for booleans.
pub(crate) fn b(v: Option<bool>) -> Option<String> {
    v.map(|v| v.to_string())
}

pub(crate) fn now(ctx: &RequestContext) -> chrono::DateTime<chrono::Utc> {
    ctx.received_at
}

/// Parse an AWS window `ddd:hh24:mi-ddd:hh24:mi` (maintenance) or
/// `hh24:mi-hh24:mi` (snapshot).
pub(crate) fn check_window(param: &str, w: &str, with_day: bool) -> Result<(), ServiceError> {
    let parts: Vec<&str> = w.split('-').collect();
    let ok = parts.len() == 2
        && parts.iter().all(|p| {
            let f: Vec<&str> = p.split(':').collect();
            let (day, hh, mm) = match (with_day, f.as_slice()) {
                (true, [d, h, m]) => (Some(*d), *h, *m),
                (false, [h, m]) => (None, *h, *m),
                _ => return false,
            };
            day.is_none_or(|d| {
                ["sun", "mon", "tue", "wed", "thu", "fri", "sat"].contains(&d.to_ascii_lowercase().as_str())
            }) && hh.parse::<u32>().is_ok_and(|h| h < 24)
                && mm.parse::<u32>().is_ok_and(|m| m < 60)
        });
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("Invalid {param} format: {w}")))
    }
}

/// A port for a new node or endpoint: a free host port when engines run
/// (each node is published on the host), else the engine's default.
pub(crate) fn alloc_port(svc: &ElastiCache, default: u16) -> u16 {
    if svc.runs_engines() {
        match crate::proxy::free_port(&svc.options().bind_address) {
            0 => default,
            p => p,
        }
    } else {
        default
    }
}

pub(crate) fn endpoint(svc: &ElastiCache, port: u16) -> t::Endpoint {
    t::Endpoint { address: Some(svc.options().advertise_host.clone()), port: Some(port as i32) }
}

pub(crate) fn region_key(ctx: &RequestContext) -> String {
    crate::state::State::key(&account_of(ctx), &ctx.region)
}
