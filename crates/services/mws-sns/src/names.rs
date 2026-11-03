//! ARNs and names.

use mws_core::{RequestContext, ServiceError};

use crate::errors;

/// The account a request works in: the caller's, or the default one for
/// unsigned requests.
pub fn account_of(ctx: &RequestContext) -> String {
    if ctx.caller.account_id.is_empty() {
        "000000000000".into()
    } else {
        ctx.caller.account_id.clone()
    }
}

/// The parts of an SNS ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnsArn {
    pub partition: String,
    pub region: String,
    pub account: String,
    pub resource: String,
}

pub fn parse_sns_arn(arn: &str) -> Option<SnsArn> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "sns" || parts[5].is_empty() {
        return None;
    }
    if parts[4].len() != 12 || !parts[4].bytes().all(|b| b.is_ascii_digit()) || parts[3].is_empty() {
        return None;
    }
    Some(SnsArn {
        partition: parts[1].to_string(),
        region: parts[3].to_string(),
        account: parts[4].to_string(),
        resource: parts[5].to_string(),
    })
}

/// Check a `TopicArn` parameter: well formed and in the request's region.
pub fn check_topic_arn(ctx: &RequestContext, arn: &str, param: &str) -> Result<SnsArn, ServiceError> {
    let parsed = parse_sns_arn(arn).ok_or_else(|| errors::invalid(param))?;
    if parsed.resource.contains(':') || parsed.resource.contains('/') || parsed.region != ctx.region {
        return Err(errors::invalid(param));
    }
    Ok(parsed)
}

pub fn topic_arn(ctx: &RequestContext, account: &str, name: &str) -> String {
    format!("arn:{}:sns:{}:{account}:{name}", ctx.partition, ctx.region)
}

/// Topic names: 1-256 letters, digits, hyphens and underscores, plus a
/// `.fifo` suffix for FIFO topics.
pub fn valid_topic_name(name: &str, fifo: bool) -> bool {
    let base = if fifo {
        match name.strip_suffix(".fifo") {
            Some(b) => b,
            None => return false,
        }
    } else {
        name
    };
    !name.is_empty()
        && name.len() <= 256
        && !base.is_empty()
        && base.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Platform application names: 1-256 letters, digits, `-`, `_` and `.`.
pub fn valid_application_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// E.164: `+` and up to 15 digits.
pub fn valid_phone_number(n: &str) -> bool {
    n.strip_prefix('+').is_some_and(|d| (2..=15).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()))
}

/// A generic AWS ARN's `(service, region, account, resource)`.
pub fn arn_parts(arn: &str) -> Option<(&str, &str, &str, &str)> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" {
        return None;
    }
    Some((parts[2], parts[3], parts[4], parts[5]))
}
