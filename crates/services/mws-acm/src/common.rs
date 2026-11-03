//! Helpers shared by the operations: tags, pagination, ARNs.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};

pub const MAX_TAGS: usize = 50;

pub type Tags = Vec<(String, Option<String>)>;

pub fn tags_from_wire(tags: &[types::Tag]) -> Tags {
    tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect()
}

pub fn tags_to_wire(tags: &Tags) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()
}

/// Reject reserved keys and duplicate keys in one request.
pub fn validate_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    for t in tags {
        if t.key.to_ascii_lowercase().starts_with("aws:") {
            return Err(errors::invalid_tag(format!(
                "Tag key '{}' is invalid. Tag keys may not begin with the prefix aws:.",
                t.key
            )));
        }
    }
    Ok(())
}

/// Add or overwrite tags, enforcing ACM's limit of 50 per resource.
pub fn merge_tags(existing: &mut Tags, added: &[types::Tag]) -> Result<(), ServiceError> {
    validate_tags(added)?;
    let mut merged = existing.clone();
    for t in added {
        match merged.iter_mut().find(|(k, _)| *k == t.key) {
            Some(slot) => slot.1 = t.value.clone(),
            None => merged.push((t.key.clone(), t.value.clone())),
        }
    }
    if merged.len() > MAX_TAGS {
        return Err(errors::too_many_tags(format!("A resource can have at most {MAX_TAGS} tags.")));
    }
    *existing = merged;
    Ok(())
}

/// `RemoveTagsFromCertificate`: a tag given with a value only goes when
/// the value matches.
pub fn remove_tags(existing: &mut Tags, removed: &[types::Tag]) -> Result<(), ServiceError> {
    validate_tags(removed)?;
    existing
        .retain(|(k, v)| !removed.iter().any(|r| r.key == *k && (r.value.is_none() || r.value.as_ref() == v.as_ref())));
    Ok(())
}

/// `aws:RequestTag/*` and `aws:TagKeys` for a request carrying tags.
pub fn request_tag_context(tags: &[types::Tag]) -> ConditionContext {
    let mut cond = ConditionContext::new();
    for t in tags {
        cond.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone().unwrap_or_default()]);
    }
    if !tags.is_empty() {
        cond.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    cond
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn resource_tag_context(tags: &Tags) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone().unwrap_or_default()])).collect()
}

/// Index-based pagination with an opaque token.
pub fn paginate<T>(
    items: Vec<T>,
    max: Option<i32>,
    default_max: usize,
    token: Option<&str>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| errors::invalid_args("The NextToken is not valid."))?,
        None => 0,
    };
    let max = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(default_max);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total).then(|| format!("mws-{}", start + max));
    Ok((page, next))
}

/// The parts of an ACM ARN: `(region, account, resource)`.
pub fn split_arn<'a>(ctx: &RequestContext, arn: &'a str) -> Option<(&'a str, &'a str, &'a str)> {
    let mut parts = arn.splitn(6, ':');
    let (Some("arn"), Some(partition), Some("acm"), Some(region), Some(account), Some(resource)) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    (partition == ctx.partition && account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()))
        .then_some((region, account, resource))
}

/// Whether `arn` names something in the caller's account and region.
pub fn is_local(ctx: &RequestContext, arn: &str) -> bool {
    split_arn(ctx, arn).is_some_and(|(r, a, _)| r == ctx.region && a == ctx.caller.account_id)
}

pub fn invalid_arn(arn: &str) -> ServiceError {
    errors::invalid_arn(format!("String '{arn}' is not a valid ARN."))
}

/// Check a certificate ARN's form.
pub fn check_certificate_arn(ctx: &RequestContext, arn: &str) -> Result<(), ServiceError> {
    match split_arn(ctx, arn) {
        Some((_, _, resource)) if resource.starts_with("certificate/") => Ok(()),
        _ => Err(invalid_arn(arn)),
    }
}
