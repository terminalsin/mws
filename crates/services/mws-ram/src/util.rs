use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};

/// Index-based pagination with an opaque token.
pub fn paginate<T>(
    items: Vec<T>,
    max: Option<i32>,
    token: Option<&str>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    if let Some(m) = max {
        if !(1..=500).contains(&m) {
            return Err(errors::invalid_max_results(format!(
                "The value {m} for maxResults is not valid. It must be between 1 and 500."
            )));
        }
    }
    let start = match token {
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| errors::invalid_next_token("The specified value for NextToken is not valid."))?,
        None => 0,
    };
    let max = max.map(|m| m as usize).unwrap_or(500);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total).then(|| format!("mws-{}", start + max));
    Ok((page, next))
}

pub const MAX_TAGS: usize = 50;

/// Validate `tags` and merge them into `into`.
pub fn merge_tags(into: &mut BTreeMap<String, String>, tags: &[types::Tag]) -> Result<(), ServiceError> {
    for t in tags {
        let key = t.key.clone().unwrap_or_default();
        if key.is_empty() || key.len() > 128 {
            return Err(errors::invalid_parameter("A tag key must be between 1 and 128 characters long."));
        }
        if key.to_ascii_lowercase().starts_with("aws:") {
            return Err(errors::invalid_parameter(format!("The tag key {key} uses the reserved prefix aws:.")));
        }
        let value = t.value.clone().unwrap_or_default();
        if value.len() > 256 {
            return Err(errors::invalid_parameter("A tag value can be at most 256 characters long."));
        }
        into.insert(key, value);
    }
    if into.len() > MAX_TAGS {
        return Err(errors::tag_limit_exceeded(format!("A resource can have at most {MAX_TAGS} tags.")));
    }
    Ok(())
}

pub fn wire_tags(tags: &BTreeMap<String, String>) -> Option<Vec<types::Tag>> {
    if tags.is_empty() {
        return None;
    }
    Some(tags.iter().map(|(k, v)| types::Tag { key: Some(k.clone()), value: Some(v.clone()) }).collect())
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &[types::Tag]) -> ConditionContext {
    let mut cond = ConditionContext::new();
    for t in tags {
        cond.insert(
            format!("aws:RequestTag/{}", t.key.clone().unwrap_or_default()),
            vec![t.value.clone().unwrap_or_default()],
        );
    }
    if !tags.is_empty() {
        cond.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone().unwrap_or_default()).collect());
    }
    cond
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn resource_tag_context(tags: &BTreeMap<String, String>) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

/// The region and account fields of an ARN.
pub fn arn_region_account(arn: &str) -> Option<(&str, &str)> {
    let mut parts = arn.splitn(6, ':');
    let (_, _, _, region, account) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    parts.next()?;
    Some((region, account))
}

/// Whether `arn` looks like an ARN at all.
pub fn check_arn(arn: &str) -> Result<(), ServiceError> {
    if arn.starts_with("arn:") && arn.split(':').count() >= 6 {
        Ok(())
    } else {
        Err(errors::malformed_arn(format!("The format of ARN {arn} is not valid.")))
    }
}

pub fn ram_arn(ctx: &RequestContext, kind: &str, id: &str) -> String {
    format!("arn:{}:ram:{}:{}:{kind}/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// Remember the ARN a create call with `token` made, or return the one an
/// earlier call with it made.
pub fn idempotent(st: &crate::state::State, ctx: &RequestContext, token: Option<&str>) -> Option<String> {
    let token = token?;
    st.client_tokens.get(&format!("{}/{token}", ctx.caller.account_id)).cloned()
}

pub fn remember_token(st: &mut crate::state::State, ctx: &RequestContext, token: Option<&str>, arn: &str) {
    if let Some(token) = token {
        st.client_tokens.insert(format!("{}/{token}", ctx.caller.account_id), arn.to_string());
    }
}
