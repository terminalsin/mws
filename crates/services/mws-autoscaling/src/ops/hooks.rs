//! Lifecycle hooks, lifecycle actions and notification configurations.

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::json;

use super::authorized_group;
use crate::engine::Op;
use crate::generated::types as t;
use crate::util::{authorize, iso, limit_exceeded, paginate, validation, LAUNCHING, NOTIFICATION_TYPES, TERMINATING};
use crate::{account_of, AutoScaling};

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_hook(
    group: &str,
    name: &str,
    existing: Option<&t::LifecycleHook>,
    transition: Option<String>,
    target: Option<String>,
    role: Option<String>,
    metadata: Option<String>,
    heartbeat: Option<i32>,
    default_result: Option<String>,
) -> Result<t::LifecycleHook, ServiceError> {
    let transition = transition
        .or_else(|| existing.and_then(|h| h.lifecycle_transition.clone()))
        .ok_or_else(|| validation("LifecycleTransition must be specified for a new lifecycle hook."))?;
    if transition != LAUNCHING && transition != TERMINATING {
        return Err(validation(format!(
            "The value '{transition}' for parameter LifecycleTransition is invalid. Valid values are {LAUNCHING} and {TERMINATING}."
        )));
    }
    let heartbeat = heartbeat.or_else(|| existing.and_then(|h| h.heartbeat_timeout)).unwrap_or(3600);
    if !(30..=7200).contains(&heartbeat) {
        return Err(validation(format!(
            "The value '{heartbeat}' for parameter HeartbeatTimeout is invalid. It must be between 30 and 7200."
        )));
    }
    let default_result =
        default_result.or_else(|| existing.and_then(|h| h.default_result.clone())).unwrap_or_else(|| "ABANDON".into());
    if default_result != "CONTINUE" && default_result != "ABANDON" {
        return Err(validation(format!(
            "The value '{default_result}' for parameter DefaultResult is invalid. Valid values are CONTINUE and ABANDON."
        )));
    }
    let target = target.or_else(|| existing.and_then(|h| h.notification_target_arn.clone())).filter(|t| !t.is_empty());
    let role = role.or_else(|| existing.and_then(|h| h.role_arn.clone())).filter(|r| !r.is_empty());
    if target.is_some() && role.is_none() {
        return Err(validation("RoleARN must be specified when NotificationTargetARN is specified."));
    }
    if let Some(m) = &metadata {
        if m.len() > 1023 {
            return Err(validation("NotificationMetadata must be at most 1023 characters."));
        }
    }
    Ok(t::LifecycleHook {
        lifecycle_hook_name: Some(name.to_string()),
        auto_scaling_group_name: Some(group.to_string()),
        lifecycle_transition: Some(transition),
        notification_target_arn: target,
        role_arn: role,
        notification_metadata: metadata.or_else(|| existing.and_then(|h| h.notification_metadata.clone())),
        heartbeat_timeout: Some(heartbeat),
        global_timeout: Some((heartbeat * 100).min(172800)),
        default_result: Some(default_result),
    })
}

fn test_message(account: &str, group: &str, group_arn: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    json!({
        "AccountId": account,
        "RequestId": uuid::Uuid::new_v4().to_string(),
        "AutoScalingGroupARN": group_arn,
        "AutoScalingGroupName": group,
        "Service": "AWS Auto Scaling",
        "Event": "autoscaling:TEST_NOTIFICATION",
        "Time": iso(now),
    })
    .to_string()
}

impl AutoScaling {
    pub(crate) fn put_lifecycle_hook_op(
        &self,
        ctx: &RequestContext,
        input: t::PutLifecycleHookType,
    ) -> Result<t::PutLifecycleHookAnswer, ServiceError> {
        let account = account_of(ctx);
        let now = self.now();
        let (test, arn) = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "PutLifecycleHook", &input.auto_scaling_group_name)?;
            let existing = g.hooks.get(&input.lifecycle_hook_name);
            if existing.is_none() && g.hooks.len() >= 50 {
                return Err(limit_exceeded(format!(
                    "Cannot add lifecycle hook {} to AutoScalingGroup {}: the limit of 50 lifecycle hooks per group was reached.",
                    input.lifecycle_hook_name, input.auto_scaling_group_name
                )));
            }
            let hook = make_hook(
                &input.auto_scaling_group_name,
                &input.lifecycle_hook_name,
                existing,
                input.lifecycle_transition.clone(),
                input.notification_target_arn.clone(),
                input.role_arn.clone(),
                input.notification_metadata.clone(),
                input.heartbeat_timeout,
                input.default_result.clone(),
            )?;
            let new_target = hook.notification_target_arn.clone().filter(|t| {
                existing.and_then(|h| h.notification_target_arn.as_ref()) != Some(t)
            });
            let test = new_target.map(|target| Op::Notify {
                target,
                role: hook.role_arn.clone(),
                subject: None,
                message: test_message(&account, g.name(), &g.arn(), now),
            });
            g.hooks.insert(input.lifecycle_hook_name.clone(), hook);
            Ok((test, g.arn()))
        })?;
        if let Some(op) = test {
            let sctx = self.service_ctx(ctx, &account, &ctx.region);
            self.deliver(&sctx, &account, &ctx.region, &arn, op, now);
        }
        Ok(Default::default())
    }

    pub(crate) fn delete_lifecycle_hook_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteLifecycleHookType,
    ) -> Result<t::DeleteLifecycleHookAnswer, ServiceError> {
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DeleteLifecycleHook", &input.auto_scaling_group_name)?;
            if g.hooks.remove(&input.lifecycle_hook_name).is_none() {
                return Err(validation(format!(
                    "No Lifecycle Hook found with name {} for group {}",
                    input.lifecycle_hook_name, input.auto_scaling_group_name
                )));
            }
            // Instances waiting on it continue with its default result.
            for m in g.members.values_mut() {
                if let Some(a) = m.action.as_mut().filter(|a| a.hook == input.lifecycle_hook_name) {
                    a.result.get_or_insert_with(|| "ABANDON".into());
                }
            }
            Ok(Default::default())
        })
    }

    pub(crate) fn describe_lifecycle_hooks_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeLifecycleHooksType,
    ) -> Result<t::DescribeLifecycleHooksAnswer, ServiceError> {
        let names = input.lifecycle_hook_names.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DescribeLifecycleHooks", &input.auto_scaling_group_name)?;
            Ok(t::DescribeLifecycleHooksAnswer {
                lifecycle_hooks: Some(
                    g.hooks
                        .values()
                        .filter(|h| {
                            names.is_empty() || h.lifecycle_hook_name.as_ref().is_some_and(|n| names.contains(n))
                        })
                        .cloned()
                        .collect(),
                ),
            })
        })
    }

    pub(crate) fn describe_lifecycle_hook_types_op(
        &self,
        ctx: &RequestContext,
    ) -> Result<t::DescribeLifecycleHookTypesAnswer, ServiceError> {
        authorize(ctx, "DescribeLifecycleHookTypes", "*", None, ConditionContext::new())?;
        Ok(t::DescribeLifecycleHookTypesAnswer {
            lifecycle_hook_types: Some(vec![LAUNCHING.into(), TERMINATING.into()]),
        })
    }

    /// The member waiting on `hook`, by instance id or token.
    fn find_action<'a>(
        g: &'a mut crate::state::Group,
        hook: &str,
        instance_id: &Option<String>,
        token: &Option<String>,
    ) -> Result<&'a mut crate::state::LifecycleAction, ServiceError> {
        if instance_id.is_none() && token.is_none() {
            return Err(validation("Either InstanceId or LifecycleActionToken must be specified."));
        }
        let found = g.members.values_mut().find(|m| {
            instance_id.as_ref().is_none_or(|i| *i == m.instance_id)
                && m.action.as_ref().is_some_and(|a| {
                    a.hook == hook && a.result.is_none() && token.as_ref().is_none_or(|t| *t == a.token)
                })
        });
        match found.and_then(|m| m.action.as_mut()) {
            Some(a) => Ok(a),
            None => Err(validation(match (instance_id, token) {
                (Some(i), _) => format!("No active Lifecycle Action found with instance ID {i}"),
                (None, Some(t)) => format!("No active Lifecycle Action found with token {t}"),
                _ => unreachable!(),
            })),
        }
    }

    pub(crate) fn complete_lifecycle_action_op(
        &self,
        ctx: &RequestContext,
        input: t::CompleteLifecycleActionType,
    ) -> Result<t::CompleteLifecycleActionAnswer, ServiceError> {
        let result = input.lifecycle_action_result.to_ascii_uppercase();
        if result != "CONTINUE" && result != "ABANDON" {
            return Err(validation(format!(
                "The value '{}' for parameter LifecycleActionResult is invalid. Valid values are CONTINUE and ABANDON.",
                input.lifecycle_action_result
            )));
        }
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "CompleteLifecycleAction", &input.auto_scaling_group_name)?;
            if !g.hooks.contains_key(&input.lifecycle_hook_name) {
                return Err(validation(format!(
                    "No Lifecycle Hook found with name {} for group {}",
                    input.lifecycle_hook_name, input.auto_scaling_group_name
                )));
            }
            let action =
                Self::find_action(g, &input.lifecycle_hook_name, &input.instance_id, &input.lifecycle_action_token)?;
            action.result = Some(result);
            Ok(Default::default())
        })
    }

    pub(crate) fn record_lifecycle_action_heartbeat_op(
        &self,
        ctx: &RequestContext,
        input: t::RecordLifecycleActionHeartbeatType,
    ) -> Result<t::RecordLifecycleActionHeartbeatAnswer, ServiceError> {
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "RecordLifecycleActionHeartbeat", &input.auto_scaling_group_name)?;
            let heartbeat =
                g.hooks.get(&input.lifecycle_hook_name).and_then(|h| h.heartbeat_timeout).ok_or_else(|| {
                    validation(format!(
                        "No Lifecycle Hook found with name {} for group {}",
                        input.lifecycle_hook_name, input.auto_scaling_group_name
                    ))
                })?;
            let action =
                Self::find_action(g, &input.lifecycle_hook_name, &input.instance_id, &input.lifecycle_action_token)?;
            action.deadline = (now + Duration::seconds(heartbeat as i64)).min(action.global_deadline);
            Ok(Default::default())
        })
    }

    pub(crate) fn put_notification_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::PutNotificationConfigurationType,
    ) -> Result<(), ServiceError> {
        for n in &input.notification_types {
            if !NOTIFICATION_TYPES.contains(&n.as_str()) {
                return Err(validation(format!("Notification type {n} is not valid.")));
            }
        }
        let account = account_of(ctx);
        let now = self.now();
        let arn = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "PutNotificationConfiguration", &input.auto_scaling_group_name)?;
            let mut types = input.notification_types.clone();
            types.sort();
            types.dedup();
            g.notifications.insert(input.topic_arn.clone(), types);
            Ok::<_, ServiceError>(g.arn())
        })?;
        // Auto Scaling confirms the topic with a test notification.
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        let op = Op::Notify {
            target: input.topic_arn.clone(),
            role: None,
            subject: Some(format!("Auto Scaling: test notification for group \"{}\"", input.auto_scaling_group_name)),
            message: test_message(&account, &input.auto_scaling_group_name, &arn, now),
        };
        self.deliver(&sctx, &account, &ctx.region, &arn, op, now);
        Ok(())
    }

    pub(crate) fn delete_notification_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteNotificationConfigurationType,
    ) -> Result<(), ServiceError> {
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DeleteNotificationConfiguration", &input.auto_scaling_group_name)?;
            if g.notifications.remove(&input.topic_arn).is_none() {
                return Err(validation(format!(
                    "Notification configuration for topic {} not found for group {}",
                    input.topic_arn, input.auto_scaling_group_name
                )));
            }
            Ok(())
        })
    }

    pub(crate) fn describe_notification_configurations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeNotificationConfigurationsType,
    ) -> Result<t::DescribeNotificationConfigurationsAnswer, ServiceError> {
        authorize(ctx, "DescribeNotificationConfigurations", "*", None, ConditionContext::new())?;
        let names = input.auto_scaling_group_names.clone().unwrap_or_default();
        let list: Vec<t::NotificationConfiguration> = self.with_region(ctx, |r| {
            r.groups
                .values()
                .filter(|g| names.is_empty() || names.iter().any(|n| n == g.name()))
                .flat_map(|g| {
                    g.notifications.iter().flat_map(move |(topic, types)| {
                        types.iter().map(move |ty| t::NotificationConfiguration {
                            auto_scaling_group_name: Some(g.name().to_string()),
                            topic_arn: Some(topic.clone()),
                            notification_type: Some(ty.clone()),
                        })
                    })
                })
                .collect()
        });
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 100)?;
        Ok(t::DescribeNotificationConfigurationsAnswer { notification_configurations: page, next_token })
    }

    pub(crate) fn describe_auto_scaling_notification_types_op(
        &self,
        ctx: &RequestContext,
    ) -> Result<t::DescribeAutoScalingNotificationTypesAnswer, ServiceError> {
        authorize(ctx, "DescribeAutoScalingNotificationTypes", "*", None, ConditionContext::new())?;
        Ok(t::DescribeAutoScalingNotificationTypesAnswer {
            auto_scaling_notification_types: Some(NOTIFICATION_TYPES.iter().map(|s| s.to_string()).collect()),
        })
    }
}
