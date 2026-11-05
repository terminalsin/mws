//! Ids, ARNs, errors and other small helpers.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::generated::errors;

/// The service principal Amplify acts as on customer resources.
pub const SERVICE_PRINCIPAL: &str = "amplify.amazonaws.com";

/// `d` and 13 lowercase letters and digits, like `d1a2b3c4d5e6f7`.
pub fn new_app_id() -> String {
    format!("d{}", random_alnum(13))
}

pub fn random_alnum(n: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

pub fn random_hex(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| char::from_digit(rng.gen_range(0..16), 16).unwrap_or('0')).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn app_arn(ctx_partition: &str, region: &str, account: &str, app_id: &str) -> String {
    format!("arn:{ctx_partition}:amplify:{region}:{account}:apps/{app_id}")
}

/// The app ARN in the caller's account and Region.
pub fn caller_app_arn(ctx: &RequestContext, app_id: &str) -> String {
    app_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, app_id)
}

/// Branch ARNs encode the branch name as a URL path segment.
pub fn branch_arn(app_arn: &str, branch: &str) -> String {
    format!("{app_arn}/branches/{}", encode_segment(branch))
}

pub fn job_arn(branch_arn: &str, job_id: u64) -> String {
    format!("{branch_arn}/jobs/{job_id:010}")
}

pub fn encode_segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// The subdomain label a branch is served under: its display name.
pub fn display_name(branch: &str) -> String {
    branch.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' }).collect()
}

pub fn not_found(kind: &str, id: &str) -> ServiceError {
    errors::not_found(format!("{kind} {id} not found."))
}

pub fn bad_request(message: impl Into<String>) -> ServiceError {
    errors::bad_request(message)
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn tag_context(tags: Option<&BTreeMap<String, String>>) -> ConditionContext {
    tags.into_iter().flatten().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: Option<&BTreeMap<String, String>>) -> ConditionContext {
    let Some(tags) = tags else { return ConditionContext::new() };
    let mut c: ConditionContext = tags.iter().map(|(k, v)| (format!("aws:RequestTag/{k}"), vec![v.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    c
}

pub fn merge(mut a: ConditionContext, b: ConditionContext) -> ConditionContext {
    a.extend(b);
    a
}

/// Amplify allows 50 tags per resource.
pub fn check_tags(tags: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    if tags.len() > 50 {
        return Err(bad_request("The number of tags must not exceed 50."));
    }
    for (k, v) in tags {
        if k.starts_with("aws:") {
            return Err(bad_request(format!("Tag key {k} must not start with aws:.")));
        }
        if v.len() > 256 {
            return Err(bad_request(format!("Tag value for key {k} must be at most 256 characters.")));
        }
    }
    Ok(())
}

/// One page of `items`: `next_token` is the index to resume from.
pub fn paginate<T: Clone>(
    items: &[T],
    next_token: Option<&str>,
    max_results: i32,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token.filter(|t| !t.is_empty()) {
        Some(t) => t.parse::<usize>().map_err(|_| bad_request("Invalid nextToken."))?,
        None => 0,
    };
    let max = if max_results <= 0 { 100 } else { max_results as usize };
    let page: Vec<T> = items.iter().skip(start).take(max).cloned().collect();
    let next = (start + page.len() < items.len()).then(|| (start + page.len()).to_string());
    Ok((page, next))
}

/// Validate `basicAuthCredentials`: base64 of `user:password`.
pub fn check_basic_auth(credentials: Option<&str>, enabled: Option<bool>) -> Result<(), ServiceError> {
    use base64::Engine;
    if let Some(c) = credentials.filter(|c| !c.is_empty()) {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(c)
            .ok()
            .and_then(|d| String::from_utf8(d).ok())
            .filter(|d| d.contains(':'));
        if decoded.is_none() {
            return Err(bad_request("Basic auth credentials must be base64 encoded username:password."));
        }
    } else if enabled == Some(true) {
        return Err(bad_request("Basic auth credentials are required when basic auth is enabled."));
    }
    Ok(())
}
