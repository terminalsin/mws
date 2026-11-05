//! Ids, ARNs, errors, tags and pagination shared by the operations.

use mws_core::{ConditionContext, ErrorValue, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::types as t;

/// The account a request works in.
pub fn account_of(ctx: &RequestContext) -> String {
    match ctx.caller.account_id.as_str() {
        "" => "000000000000".to_string(),
        a => a.to_string(),
    }
}

/// A new resource id: `prefix-` and 17 hex digits (long ids) or 8 (short
/// ids, `PutAccountPreferences`).
pub fn new_id(prefix: &str, long: bool) -> String {
    let mut rng = rand::thread_rng();
    let n = if long { 17 } else { 8 };
    let hex: String = (0..n).map(|_| char::from_digit(rng.gen_range(0..16), 16).expect("hex digit")).collect();
    format!("{prefix}-{hex}")
}

pub fn fs_arn(partition: &str, region: &str, account: &str, id: &str) -> String {
    format!("arn:{partition}:elasticfilesystem:{region}:{account}:file-system/{id}")
}

pub fn ap_arn(partition: &str, region: &str, account: &str, id: &str) -> String {
    format!("arn:{partition}:elasticfilesystem:{region}:{account}:access-point/{id}")
}

/// An EFS error: the code doubles as the `ErrorCode` member every EFS error
/// shape carries.
pub fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

pub fn bad_request(message: impl Into<String>) -> ServiceError {
    err("BadRequest", 400, message)
}

pub fn fs_not_found(id: &str) -> ServiceError {
    err("FileSystemNotFound", 404, format!("File system '{id}' does not exist."))
}

pub fn mt_not_found(id: &str) -> ServiceError {
    err("MountTargetNotFound", 404, format!("Mount target '{id}' does not exist."))
}

pub fn ap_not_found(id: &str) -> ServiceError {
    err("AccessPointNotFound", 404, format!("Access point '{id}' does not exist."))
}

pub fn wrong_state(id: &str, state: &str) -> ServiceError {
    err("IncorrectFileSystemLifeCycleState", 409, format!("File system '{id}' is in the '{state}' state."))
}

/// Add `ErrorCode` (and any extra member) to an error body.
pub fn with_member(e: ServiceError, name: &str, value: &str) -> ServiceError {
    e.with_field(name, ErrorValue::String(value.into()))
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &[t::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags {
        c.insert(format!("aws:RequestTag/{}", tag.key), vec![tag.value.clone()]);
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn resource_tag_context(tags: &[t::Tag]) -> ConditionContext {
    tags.iter().map(|t| (format!("aws:ResourceTag/{}", t.key), vec![t.value.clone()])).collect()
}

/// Check tags the way EFS does: no `aws:` prefix, unique keys, at most 50.
pub fn validate_tags(tags: &[t::Tag]) -> Result<(), ServiceError> {
    if tags.len() > 50 {
        return Err(bad_request("Too many tags. A resource can have at most 50 tags."));
    }
    let mut seen = std::collections::HashSet::new();
    for tag in tags {
        if tag.key.to_ascii_lowercase().starts_with("aws:") {
            return Err(bad_request("Tag keys starting with 'aws:' are reserved for system use."));
        }
        if !seen.insert(tag.key.as_str()) {
            return Err(bad_request(format!("Duplicate tag key '{}'.", tag.key)));
        }
    }
    Ok(())
}

/// Merge `new` into `tags`, replacing values of keys already there.
pub fn merge_tags(tags: &mut Vec<t::Tag>, new: &[t::Tag]) {
    for tag in new {
        match tags.iter_mut().find(|t| t.key == tag.key) {
            Some(existing) => existing.value = tag.value.clone(),
            None => tags.push(tag.clone()),
        }
    }
}

/// The value of the `Name` tag.
pub fn name_tag(tags: &[t::Tag]) -> Option<String> {
    tags.iter().find(|t| t.key == "Name").map(|t| t.value.clone())
}

/// One page of `items` (already in order) starting after `marker`, which
/// is the key of the first item of the page, as EFS markers name a
/// position. Returns the page and the next marker.
pub fn page<T>(
    items: Vec<T>,
    key: impl Fn(&T) -> String,
    marker: Option<&str>,
    limit: Option<i32>,
    default_limit: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let limit = match limit {
        Some(n) if n <= 0 => return Err(bad_request("MaxItems must be greater than 0.")),
        Some(n) => n as usize,
        None => default_limit,
    };
    let start = match marker.filter(|m| !m.is_empty()) {
        Some(m) => items.iter().position(|i| key(i) == m).ok_or_else(|| bad_request("Invalid pagination token."))?,
        None => 0,
    };
    let rest: Vec<T> = items.into_iter().skip(start).collect();
    let next = rest.get(limit).map(&key);
    Ok((rest.into_iter().take(limit).collect(), next))
}
