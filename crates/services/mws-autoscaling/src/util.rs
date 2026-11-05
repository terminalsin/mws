//! Errors in Auto Scaling's wording, ARNs, pagination and authorization.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;

pub fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationError", 400, message)
}

pub fn already_exists(message: impl Into<String>) -> ServiceError {
    ServiceError::client("AlreadyExists", 400, message)
}

pub fn limit_exceeded(message: impl Into<String>) -> ServiceError {
    ServiceError::client("LimitExceeded", 400, message)
}

pub fn resource_in_use(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ResourceInUse", 400, message)
}

pub fn scaling_in_progress(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ScalingActivityInProgress", 400, message)
}

pub fn group_not_found(name: &str) -> ServiceError {
    validation(format!("AutoScalingGroup name not found - AutoScalingGroup {name} not found"))
}

pub fn group_arn(ctx: &RequestContext, account: &str, name: &str) -> String {
    format!(
        "arn:{}:autoscaling:{}:{account}:autoScalingGroup:{}:autoScalingGroupName/{name}",
        ctx.partition,
        ctx.region,
        uuid::Uuid::new_v4()
    )
}

/// The ARN IAM policies name a group by (any id).
pub fn group_resource(ctx: &RequestContext, account: &str, name: &str) -> String {
    format!("arn:{}:autoscaling:{}:{account}:autoScalingGroup:*:autoScalingGroupName/{name}", ctx.partition, ctx.region)
}

pub fn launch_configuration_arn(ctx: &RequestContext, account: &str, name: &str) -> String {
    format!(
        "arn:{}:autoscaling:{}:{account}:launchConfiguration:{}:launchConfigurationName/{name}",
        ctx.partition,
        ctx.region,
        uuid::Uuid::new_v4()
    )
}

pub fn policy_arn(ctx: &RequestContext, account: &str, group: &str, name: &str) -> String {
    format!(
        "arn:{}:autoscaling:{}:{account}:scalingPolicy:{}:autoScalingGroupName/{group}:policyName/{name}",
        ctx.partition,
        ctx.region,
        uuid::Uuid::new_v4()
    )
}

pub fn scheduled_action_arn(ctx: &RequestContext, account: &str, group: &str, name: &str) -> String {
    format!(
        "arn:{}:autoscaling:{}:{account}:scheduledUpdateGroupAction:{}:autoScalingGroupName/{group}:scheduledActionName/{name}",
        ctx.partition,
        ctx.region,
        uuid::Uuid::new_v4()
    )
}

/// `autoscaling:{action}` on `resource`, with the group's tags as
/// `aws:ResourceTag/*`.
pub fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    tags: Option<&Vec<t::TagDescription>>,
    mut extra: ConditionContext,
) -> Result<(), ServiceError> {
    for tag in tags.into_iter().flatten() {
        if let Some(k) = &tag.key {
            extra.insert(format!("aws:ResourceTag/{k}"), vec![tag.value.clone().unwrap_or_default()]);
            extra.insert(format!("autoscaling:ResourceTag/{k}"), vec![tag.value.clone().unwrap_or_default()]);
        }
    }
    ctx.authorize(&format!("autoscaling:{action}"), resource, extra)
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tags(tags: &[t::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags {
        c.insert(format!("aws:RequestTag/{}", tag.key), vec![tag.value.clone().unwrap_or_default()]);
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

/// One page: `MaxRecords` (default 50, at most 100) and `NextToken`.
pub fn paginate<T>(
    items: Vec<T>,
    max_records: Option<i32>,
    next_token: &Option<String>,
    max: i32,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token.as_deref().filter(|t| !t.is_empty()) {
        None => 0,
        Some(tok) => base64::engine::general_purpose::STANDARD
            .decode(tok)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.strip_prefix("mws:").and_then(|n| n.parse::<usize>().ok()))
            .ok_or_else(|| ServiceError::client("InvalidNextToken", 400, "The token passed is invalid."))?,
    };
    let limit = max_records.unwrap_or(50);
    if limit < 1 || limit > max {
        return Err(validation(format!(
            "1 validation error detected: Value '{limit}' at 'maxRecords' failed to satisfy constraint: Member must have value less than or equal to {max}"
        )));
    }
    let limit = limit as usize;
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(limit).collect();
    let next = (start + limit < total)
        .then(|| base64::engine::general_purpose::STANDARD.encode(format!("mws:{}", start + limit)));
    Ok((page, next))
}

/// `2026-11-05T04:03:51Z`-style timestamps for messages.
pub fn iso(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// The `At <time>` prefix of activity causes.
pub fn at(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("At %Y-%m-%dT%H:%M:%SZ").to_string()
}

pub const PROCESSES: &[&str] = &[
    "Launch",
    "Terminate",
    "AddToLoadBalancer",
    "AlarmNotification",
    "AZRebalance",
    "HealthCheck",
    "InstanceRefresh",
    "RemoveFromLoadBalancerLowPriority",
    "ReplaceUnhealthy",
    "ScheduledActions",
];

pub const METRICS: &[&str] = &[
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
    "GroupInServiceCapacity",
    "GroupPendingCapacity",
    "GroupStandbyCapacity",
    "GroupTerminatingCapacity",
    "GroupTotalCapacity",
    "WarmPoolDesiredCapacity",
    "WarmPoolWarmedCapacity",
    "WarmPoolPendingCapacity",
    "WarmPoolTerminatingCapacity",
    "WarmPoolTotalCapacity",
    "GroupAndWarmPoolDesiredCapacity",
    "GroupAndWarmPoolTotalCapacity",
];

pub const NOTIFICATION_TYPES: &[&str] = &[
    "autoscaling:EC2_INSTANCE_LAUNCH",
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
    "autoscaling:EC2_INSTANCE_TERMINATE",
    "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
    "autoscaling:TEST_NOTIFICATION",
];

pub const TERMINATION_POLICIES: &[&str] = &[
    "ClosestToNextInstanceHour",
    "Default",
    "NewestInstance",
    "OldestInstance",
    "OldestLaunchConfiguration",
    "OldestLaunchTemplate",
    "AllocationStrategy",
];

pub const LAUNCHING: &str = "autoscaling:EC2_INSTANCE_LAUNCHING";
pub const TERMINATING: &str = "autoscaling:EC2_INSTANCE_TERMINATING";
