//! Shared helpers: ARNs, ids, pagination, authorization, errors.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::errors;
use crate::infra::{InfrastructureError, Scope};
use crate::state::{ClusterRec, Region, State};

pub(crate) type Tags = BTreeMap<String, String>;

pub(crate) fn account(ctx: &RequestContext) -> &str {
    &ctx.caller.account_id
}

pub(crate) fn scope(ctx: &RequestContext) -> Scope<'_> {
    Scope { account: &ctx.caller.account_id, region: &ctx.region, partition: &ctx.partition, now: ctx.received_at }
}

/// `arn:aws:eks:<region>:<account>:<resource>`.
pub(crate) fn arn(ctx: &RequestContext, resource: &str) -> String {
    format!("arn:{}:eks:{}:{}:{resource}", ctx.partition, ctx.region, account(ctx))
}

pub(crate) fn cluster_arn(ctx: &RequestContext, name: &str) -> String {
    arn(ctx, &format!("cluster/{name}"))
}

pub(crate) fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Random characters from `alphabet`.
pub(crate) fn random(alphabet: &[u8], len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char).collect()
}

pub(crate) const HEX_UPPER: &[u8] = b"0123456789ABCDEF";
pub(crate) const LOWER_ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

pub(crate) fn not_found_cluster(name: &str) -> ServiceError {
    errors::resource_not_found(format!("No cluster found for name: {name}.")).with_field("clusterName", text(name))
}

pub(crate) fn text(s: &str) -> mws_core::ErrorValue {
    mws_core::ErrorValue::String(s.to_string())
}

/// Authorize `action` on `resource`, with the resource's tags and any tags
/// the request adds as condition keys.
pub(crate) fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    resource_tags: Option<&Tags>,
    request_tags: Option<&Tags>,
    mut extra: ConditionContext,
) -> Result<(), ServiceError> {
    if let Some(tags) = resource_tags {
        for (k, v) in tags {
            extra.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
        }
    }
    if let Some(tags) = request_tags.filter(|t| !t.is_empty()) {
        for (k, v) in tags {
            extra.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        }
        extra.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    ctx.authorize(&format!("eks:{action}"), resource, extra)
}

/// `iam:PassRole` for a role EKS will hand to `service`.
pub(crate) fn pass_role(ctx: &RequestContext, role_arn: &str, service: &str) -> Result<(), ServiceError> {
    let mut c = ConditionContext::new();
    c.insert("iam:PassedToService".into(), vec![service.into()]);
    ctx.authorize("iam:PassRole", role_arn, c)
}

/// Tags must not use the reserved `aws:` prefix, and a resource holds at
/// most 50.
pub(crate) fn check_tags(tags: Option<&Tags>) -> Result<(), ServiceError> {
    let Some(tags) = tags else { return Ok(()) };
    if tags.len() > 50 {
        return Err(errors::bad_request("Tags exceed the maximum of 50 per resource."));
    }
    if tags.keys().any(|k| k.to_ascii_lowercase().starts_with("aws:")) {
        return Err(errors::bad_request("Tag keys with the prefix 'aws:' are reserved for AWS use."));
    }
    Ok(())
}

pub(crate) fn check_create_tags(tags: Option<&Tags>) -> Result<(), ServiceError> {
    check_tags(tags).map_err(|e| errors::invalid_parameter(e.message))
}

pub(crate) fn infra_error(e: &InfrastructureError) -> ServiceError {
    errors::invalid_parameter(e.to_string())
}

/// An opaque pagination token over a sorted list.
pub(crate) fn page<T: Clone>(
    items: &[T],
    max_results: Option<i32>,
    next_token: Option<&str>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token.filter(|t| !t.is_empty()) {
        Some(t) => decode_token(t).ok_or_else(|| errors::invalid_parameter("The nextToken provided is invalid."))?,
        None => 0,
    };
    let max = max_results.unwrap_or(100).clamp(1, 100) as usize;
    let end = (start + max).min(items.len());
    let slice = items.get(start.min(items.len())..end).unwrap_or_default().to_vec();
    let next = (end < items.len()).then(|| encode_token(end));
    Ok((slice, next))
}

fn encode_token(offset: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{{\"offset\":{offset},\"v\":1}}"))
}

fn decode_token(token: &str) -> Option<usize> {
    let raw = base64::engine::general_purpose::STANDARD.decode(token).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get("offset")?.as_u64().map(|n| n as usize)
}

/// The caller's region, created if need be.
pub(crate) fn region<'a>(st: &'a mut State, ctx: &RequestContext) -> &'a mut Region {
    st.region(account(ctx), &ctx.region)
}

pub(crate) fn cluster<'a>(
    st: &'a mut State,
    ctx: &RequestContext,
    name: &str,
) -> Result<&'a mut ClusterRec, ServiceError> {
    region(st, ctx).clusters.get_mut(name).ok_or_else(|| not_found_cluster(name))
}

/// The last path segment of an ARN (`role/path/name` → `name`).
pub(crate) fn arn_name(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

/// `(account, kind, name)` of an IAM role or user ARN.
pub(crate) fn iam_principal(arn: &str) -> Option<(&str, &str, &str)> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "iam" {
        return None;
    }
    let (kind, _) = parts[5].split_once('/')?;
    if !matches!(kind, "role" | "user") {
        return None;
    }
    Some((parts[4], kind, arn_name(parts[5])))
}

/// A JSON array of strings, as update params carry lists.
pub(crate) fn json_list(items: &[String]) -> String {
    serde_json::to_string(items).unwrap_or_default()
}

pub(crate) fn param(kind: &str, value: impl Into<String>) -> crate::generated::types::UpdateParam {
    crate::generated::types::UpdateParam { r#type: Some(kind.into()), value: Some(value.into()) }
}
