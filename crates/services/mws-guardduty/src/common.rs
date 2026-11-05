//! Helpers shared by the operations: errors, ids, ARNs, tags, pagination
//! and authorization.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use mws_core::{ConditionContext, ErrorValue, RequestContext, ServiceError};

use crate::generated::errors;

pub type Tags = BTreeMap<String, String>;

/// GuardDuty's service principal.
pub const SERVICE_PRINCIPAL: &str = "guardduty.amazonaws.com";

/// GuardDuty's `BadRequestException`, with the finer `type` AWS sends.
pub fn bad_request(ty: &str, message: impl Into<String>) -> ServiceError {
    errors::bad_request(message).with_field("type", ErrorValue::String(ty.into()))
}

pub fn invalid_input(message: impl Into<String>) -> ServiceError {
    bad_request("InvalidInputException", message)
}

pub fn not_found(message: impl Into<String>) -> ServiceError {
    errors::resource_not_found(message).with_field("type", ErrorValue::String("ResourceNotFoundException".into()))
}

pub fn conflict(message: impl Into<String>) -> ServiceError {
    errors::conflict(message).with_field("type", ErrorValue::String("ConflictException".into()))
}

/// A detector id the caller does not own (or that does not exist).
pub fn detector_not_owned() -> ServiceError {
    invalid_input("The request is rejected because the input detectorId is not owned by the current account.")
}

pub fn no_such_resource() -> ServiceError {
    invalid_input("The request is rejected since no such resource found.")
}

pub fn invalid_token() -> ServiceError {
    invalid_input(
        "The request is rejected because an invalid or out-of-range value is specified as an input parameter.",
    )
}

/// A random lowercase hex id of `len` characters, the form GuardDuty uses
/// for detector, finding, list and destination ids.
pub fn hex_id(len: usize) -> String {
    let mut s = String::with_capacity(len);
    while s.len() < len {
        s.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    s.truncate(len);
    s
}

/// A deterministic 32 hex character id derived from `parts`.
pub fn stable_id(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    hex::encode(h.finalize())[..32].to_string()
}

/// ISO 8601 with milliseconds, as GuardDuty writes its string timestamps.
pub fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn detector_arn(ctx: &RequestContext, account: &str, detector: &str) -> String {
    format!("arn:{}:guardduty:{}:{account}:detector/{detector}", ctx.partition, ctx.region)
}

pub fn child_arn(ctx: &RequestContext, account: &str, detector: &str, kind: &str, id: &str) -> String {
    format!("{}/{kind}/{id}", detector_arn(ctx, account, detector))
}

pub fn plan_arn(ctx: &RequestContext, account: &str, id: &str) -> String {
    format!("arn:{}:guardduty:{}:{account}:malware-protection-plan/{id}", ctx.partition, ctx.region)
}

pub fn service_role_arn(ctx: &RequestContext, account: &str) -> String {
    format!(
        "arn:{}:iam::{account}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
        ctx.partition
    )
}

/// Reject reserved tag keys.
pub fn validate_tags(tags: &Tags) -> Result<(), ServiceError> {
    for k in tags.keys() {
        if k.to_ascii_lowercase().starts_with("aws:") {
            return Err(invalid_input(format!(
                "The request is rejected because the tag key {k} is invalid. Tag keys may not begin with aws:."
            )));
        }
    }
    Ok(())
}

/// `aws:RequestTag/*` and `aws:TagKeys` for a request carrying tags.
pub fn request_tag_context(tags: Option<&Tags>) -> ConditionContext {
    let mut cond = ConditionContext::new();
    let Some(tags) = tags.filter(|t| !t.is_empty()) else { return cond };
    for (k, v) in tags {
        cond.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
    }
    cond.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    cond
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn resource_tag_context(tags: &Tags) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

/// Index-based pagination with an opaque token.
pub fn paginate<T>(
    items: Vec<T>,
    max: Option<i32>,
    default_max: usize,
    token: Option<&str>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token.filter(|t| !t.is_empty()) {
        Some(t) => t.strip_prefix("mws-").and_then(|n| n.parse::<usize>().ok()).ok_or_else(invalid_token)?,
        None => 0,
    };
    let max = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(default_max);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total).then(|| format!("mws-{}", start + max));
    Ok((page, next))
}

/// `UnprocessedAccount` for an account the operation skipped.
pub fn unprocessed(account: &str, result: impl Into<String>) -> crate::generated::types::UnprocessedAccount {
    crate::generated::types::UnprocessedAccount { account_id: account.to_string(), result: result.into() }
}

/// Whether `id` is a 12-digit account id.
pub fn is_account_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit())
}
