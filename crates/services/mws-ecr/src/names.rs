//! ARNs, URIs, AWS's error wording, authorization and small helpers.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::Repo;

pub fn now_ms(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

pub fn dt(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

pub fn repository_arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:ecr:{region}:{account}:repository/{name}")
}

pub fn registry_arn(partition: &str, region: &str, account: &str) -> String {
    format!("arn:{partition}:ecr:{region}:{account}:registry/{account}")
}

/// AWS's access denials carry `AccessDeniedException` with HTTP 400 in
/// ECR's protocol.
pub fn ecr_denial(e: ServiceError) -> ServiceError {
    if e.code == "AccessDenied" {
        ServiceError::client("AccessDeniedException", 400, e.message)
    } else {
        e
    }
}

/// ECR words model constraint violations its own way: `Invalid parameter
/// at 'repositoryName' failed to satisfy constraint: 'must satisfy regular
/// expression '...''`.
pub fn ecr_validation(e: ServiceError) -> ServiceError {
    if e.code != errors::INVALID_PARAMETER || !e.message.contains(" validation error") {
        return e;
    }
    let first = e.message.split_once("detected: ").map(|(_, r)| r).unwrap_or(&e.message);
    let first = first.split("; ").next().unwrap_or(first);
    let Some((_, rest)) = first.split_once(" at '") else { return e };
    let Some((path, constraint)) = rest.split_once("' failed to satisfy constraint: ") else { return e };
    let constraint = constraint.strip_prefix("Member ").unwrap_or(constraint);
    let constraint =
        constraint.replace("must satisfy regular expression pattern: ", "must satisfy regular expression '");
    let constraint = if constraint.contains("regular expression '") { format!("{constraint}'") } else { constraint };
    let message = format!("Invalid parameter at '{path}' failed to satisfy constraint: '{constraint}'");
    ServiceError { message, ..e }
}

pub fn invalid_parameter(message: impl Into<String>) -> ServiceError {
    errors::invalid_parameter(message)
}

pub fn repository_not_found(name: &str, registry: &str) -> ServiceError {
    errors::repository_not_found(format!(
        "The repository with name '{name}' does not exist in the registry with id '{registry}'"
    ))
}

pub fn repository_already_exists(name: &str, registry: &str) -> ServiceError {
    errors::repository_already_exists(format!(
        "The repository with name '{name}' already exists in the registry with id '{registry}'"
    ))
}

/// `{imageDigest:'sha256:...', imageTag:'null'}`, as ECR quotes image ids.
pub fn image_id_text(id: &types::ImageIdentifier) -> String {
    format!(
        "{{imageDigest:'{}', imageTag:'{}'}}",
        id.image_digest.as_deref().unwrap_or("null"),
        id.image_tag.as_deref().unwrap_or("null")
    )
}

pub fn image_not_found(id: &types::ImageIdentifier, repo: &str, registry: &str) -> ServiceError {
    errors::image_not_found(format!(
        "The image with imageId {} does not exist within the repository with name '{repo}' in the registry with id '{registry}'",
        image_id_text(id)
    ))
}

/// Shell-style wildcard matching (`*` only), as tag and repository filters
/// use it.
pub fn wildcard(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    let (mut pi, mut vi, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while vi < v.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == v[vi] {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = vi;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            vi = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn tag_map(tags: &[types::Tag]) -> BTreeMap<String, String> {
    tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect()
}

pub fn tag_list(tags: &BTreeMap<String, String>) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()
}

pub fn resource_tag_context(tags: &BTreeMap<String, String>) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

pub fn request_tag_context(tags: &[types::Tag]) -> ConditionContext {
    let mut c: ConditionContext =
        tags.iter().map(|t| (format!("aws:RequestTag/{}", t.key), vec![t.value.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

/// Authorize an action on a repository (which may not exist yet): the
/// repository policy or identity policies may grant it.
pub fn authorize_repo(
    ctx: &RequestContext,
    action: &str,
    arn: &str,
    repo: Option<&Repo>,
    extra: ConditionContext,
) -> Result<(), ServiceError> {
    let mut context = repo.map(|r| resource_tag_context(&r.tags)).unwrap_or_default();
    context.extend(extra);
    let account = arn.split(':').nth(4).unwrap_or_default().to_string();
    context.insert("aws:ResourceAccount".into(), vec![account]);
    ctx.authorize_with_resource_policy(action, arn, repo.and_then(|r| r.policy.as_deref()), context).map_err(ecr_denial)
}

/// Authorize an action on the registry itself (`Resource: *` actions are
/// authorized against the registry ARN, as `iam:simulate` shows them).
pub fn authorize_registry(ctx: &RequestContext, action: &str, resource: &str) -> Result<(), ServiceError> {
    ctx.authorize(action, resource, ConditionContext::new()).map_err(ecr_denial)
}

/// Page through `items` with an opaque numeric token.
pub fn page<T: Clone>(
    items: &[T],
    next_token: Option<&str>,
    max_results: Option<i32>,
    default_max: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token {
        None | Some("") => 0,
        Some(t) => t.parse::<usize>().map_err(|_| {
            invalid_parameter(
                "Invalid parameter at 'nextToken' failed to satisfy constraint: 'must be a valid pagination token'",
            )
        })?,
    };
    let max = max_results.map(|m| m.max(1) as usize).unwrap_or(default_max);
    let end = (start + max).min(items.len());
    let slice = items.get(start..end).map(<[T]>::to_vec).unwrap_or_default();
    let next = (end < items.len()).then(|| end.to_string());
    Ok((slice, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard("release-*", "release-1.0"));
        assert!(wildcard("*", ""));
        assert!(wildcard("a*b*c", "aXXbYYc"));
        assert!(!wildcard("prod", "production"));
        assert!(wildcard("prod*", "production"));
    }

    #[test]
    fn validation_wording() {
        let e = errors::invalid_parameter("1 validation error detected: Value 'Bad' at 'repositoryName' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-z]+");
        assert_eq!(
            ecr_validation(e).message,
            "Invalid parameter at 'repositoryName' failed to satisfy constraint: 'must satisfy regular expression '[a-z]+''"
        );
    }
}
