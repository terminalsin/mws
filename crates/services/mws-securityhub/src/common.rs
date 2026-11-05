//! Helpers shared by the operations: errors, ARNs, authorization,
//! pagination, tags.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::errors;
use crate::state::{Hub, State, Tags};

pub fn partition(ctx: &RequestContext) -> &str {
    &ctx.partition
}

pub fn account(ctx: &RequestContext) -> &str {
    &ctx.caller.account_id
}

pub fn hub_arn(ctx: &RequestContext, account: &str) -> String {
    format!("arn:{}:securityhub:{}:{account}:hub/default", ctx.partition, ctx.region)
}

/// `arn:aws:securityhub:<region>:<account>:<resource>` in the caller's
/// account and Region.
pub fn arn(ctx: &RequestContext, resource: &str) -> String {
    format!("arn:{}:securityhub:{}:{}:{resource}", ctx.partition, ctx.region, ctx.caller.account_id)
}

pub fn not_subscribed(account: &str) -> ServiceError {
    errors::invalid_access(format!("Account {account} is not subscribed to AWS Security Hub"))
}

pub fn invalid_input(message: impl Into<String>) -> ServiceError {
    errors::invalid_input(message)
}

pub fn not_found(message: impl Into<String>) -> ServiceError {
    errors::resource_not_found(message)
}

/// `securityhub:<action>` on `resource`.
pub fn authorize(ctx: &RequestContext, action: &str, resource: &str) -> Result<(), ServiceError> {
    ctx.authorize(&format!("securityhub:{action}"), resource, ConditionContext::new())
}

pub fn authorize_with(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    cond: ConditionContext,
) -> Result<(), ServiceError> {
    ctx.authorize(&format!("securityhub:{action}"), resource, cond)
}

/// Authorize `action` on the caller's hub.
pub fn authorize_hub(ctx: &RequestContext, action: &str) -> Result<(), ServiceError> {
    authorize(ctx, action, &hub_arn(ctx, account(ctx)))
}

/// The caller's hub, or the "not subscribed" error.
pub fn hub<'s>(state: &'s State, ctx: &RequestContext) -> Result<&'s Hub, ServiceError> {
    state.hub(account(ctx), &ctx.region).ok_or_else(|| not_subscribed(account(ctx)))
}

pub fn hub_mut<'s>(state: &'s mut State, ctx: &RequestContext) -> Result<&'s mut Hub, ServiceError> {
    let account = account(ctx).to_string();
    state.hub_mut(&account, &ctx.region).ok_or_else(|| not_subscribed(&account))
}

/// ASFF timestamps: ISO 8601 with milliseconds.
pub fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse an ASFF timestamp (RFC 3339, with or without fractional seconds).
pub fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

/// Index-based pagination with an opaque token. `max` is the caller's
/// MaxResults (validated by the model), `default` the page size without it.
pub fn paginate<T>(
    items: Vec<T>,
    max: Option<i32>,
    default: usize,
    token: Option<&str>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token.filter(|t| !t.is_empty()) {
        Some(t) => decode_token(t).ok_or_else(|| invalid_input("The NextToken value is invalid."))?,
        None => 0,
    };
    if start > items.len() {
        return Err(invalid_input("The NextToken value is invalid."));
    }
    let size = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(default);
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then(|| encode_token(end));
    Ok((items.into_iter().skip(start).take(size).collect(), next))
}

fn encode_token(i: usize) -> String {
    format!("{:x}", (i as u64) ^ 0x5348_5348)
}

fn decode_token(t: &str) -> Option<usize> {
    u64::from_str_radix(t, 16).ok().map(|v| (v ^ 0x5348_5348) as usize)
}

pub fn tag_conditions(tags: &BTreeMap<String, String>) -> ConditionContext {
    let mut cond = ConditionContext::new();
    for (k, v) in tags {
        cond.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
    }
    if !tags.is_empty() {
        cond.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    cond
}

pub fn resource_tag_conditions(tags: &Tags) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

/// Reject `aws:` keys and more than 50 tags.
pub fn check_tags(existing: &Tags, added: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    if added.keys().any(|k| k.to_ascii_lowercase().starts_with("aws:")) {
        return Err(invalid_input("Tag keys starting with 'aws:' are reserved for AWS use."));
    }
    let total = existing.keys().chain(added.keys().filter(|k| !existing.contains_key(*k))).count();
    if total > 50 {
        return Err(invalid_input("A resource can have up to 50 tags."));
    }
    Ok(())
}

/// The account id from an ARN.
pub fn arn_account(arn: &str) -> Option<&str> {
    arn.split(':').nth(4)
}

/// The Region from an ARN.
pub fn arn_region(arn: &str) -> Option<&str> {
    arn.split(':').nth(3)
}

pub fn is_account_id(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}
