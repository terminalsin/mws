//! Scheduled actions (run by the reconciliation loop on the emulated
//! clock).

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::authorized_group;
use crate::engine::cron_schedule;
use crate::generated::types as t;
use crate::state::Group;
use crate::util::{authorize, limit_exceeded, paginate, scheduled_action_arn, validation};
use crate::{account_of, AutoScaling};

struct Request {
    name: String,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    recurrence: Option<String>,
    min_size: Option<i32>,
    max_size: Option<i32>,
    desired_capacity: Option<i32>,
    time_zone: Option<String>,
}

fn put(ctx: &RequestContext, g: &mut Group, req: Request, now: DateTime<Utc>) -> Result<(), ServiceError> {
    if req.min_size.is_none() && req.max_size.is_none() && req.desired_capacity.is_none() {
        return Err(validation("At least one of MinSize, MaxSize, or DesiredCapacity must be specified."));
    }
    if let (Some(min), Some(max)) = (req.min_size, req.max_size) {
        if max < min {
            return Err(validation(format!("Max bound, {max}, must be greater than or equal to min bound, {min}")));
        }
    }
    if let Some(r) = &req.recurrence {
        if cron_schedule(r).is_none() {
            return Err(validation(format!("Given recurrence string '{r}' is not a valid cron expression.")));
        }
    }
    if let Some(tz) = &req.time_zone {
        if !matches!(tz.as_str(), "UTC" | "Etc/UTC" | "GMT" | "Etc/GMT" | "Z") && !tz.contains('/') {
            return Err(validation(format!("Invalid time zone: {tz}")));
        }
    }
    if req.recurrence.is_none() {
        match req.start_time {
            None => return Err(validation("Either StartTime or Recurrence must be specified.")),
            Some(s) if s < now => return Err(validation("Given start time is in the past")),
            _ => {}
        }
    }
    if let (Some(s), Some(e)) = (req.start_time, req.end_time) {
        if e <= s {
            return Err(validation("End time must be after start time."));
        }
    }
    let existing = g.scheduled.get(&req.name);
    if existing.is_none() && g.scheduled.len() >= 125 {
        return Err(limit_exceeded("You have reached the limit of 125 scheduled actions for the Auto Scaling group."));
    }
    let arn = existing
        .and_then(|e| e.scheduled_action_arn.clone())
        .unwrap_or_else(|| scheduled_action_arn(ctx, &account_of(ctx), g.name(), &req.name));
    let action = t::ScheduledUpdateGroupAction {
        auto_scaling_group_name: Some(g.name().to_string()),
        scheduled_action_name: Some(req.name.clone()),
        scheduled_action_arn: Some(arn),
        time: req.start_time,
        start_time: req.start_time,
        end_time: req.end_time,
        recurrence: req.recurrence,
        min_size: req.min_size,
        max_size: req.max_size,
        desired_capacity: req.desired_capacity,
        time_zone: req.time_zone,
    };
    g.scheduled_ran.remove(&req.name);
    g.scheduled.insert(req.name, action);
    Ok(())
}

impl AutoScaling {
    pub(crate) fn put_scheduled_update_group_action_op(
        &self,
        ctx: &RequestContext,
        input: t::PutScheduledUpdateGroupActionType,
    ) -> Result<(), ServiceError> {
        if input.time.is_some() && input.start_time.is_some() && input.time != input.start_time {
            return Err(validation("Time and StartTime can't both be specified with different values."));
        }
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "PutScheduledUpdateGroupAction", &input.auto_scaling_group_name)?;
            put(
                ctx,
                g,
                Request {
                    name: input.scheduled_action_name.clone(),
                    start_time: input.start_time.or(input.time),
                    end_time: input.end_time,
                    recurrence: input.recurrence.clone(),
                    min_size: input.min_size,
                    max_size: input.max_size,
                    desired_capacity: input.desired_capacity,
                    time_zone: input.time_zone.clone(),
                },
                now,
            )
        })
    }

    pub(crate) fn batch_put_scheduled_update_group_action_op(
        &self,
        ctx: &RequestContext,
        input: t::BatchPutScheduledUpdateGroupActionType,
    ) -> Result<t::BatchPutScheduledUpdateGroupActionAnswer, ServiceError> {
        if input.scheduled_update_group_actions.len() > 50 {
            return Err(validation("You can specify up to 50 scheduled actions."));
        }
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "BatchPutScheduledUpdateGroupAction", &input.auto_scaling_group_name)?;
            let mut failed = Vec::new();
            for a in &input.scheduled_update_group_actions {
                let req = Request {
                    name: a.scheduled_action_name.clone(),
                    start_time: a.start_time,
                    end_time: a.end_time,
                    recurrence: a.recurrence.clone(),
                    min_size: a.min_size,
                    max_size: a.max_size,
                    desired_capacity: a.desired_capacity,
                    time_zone: a.time_zone.clone(),
                };
                if let Err(e) = put(ctx, g, req, now) {
                    failed.push(t::FailedScheduledUpdateGroupActionRequest {
                        scheduled_action_name: a.scheduled_action_name.clone(),
                        error_code: Some(e.code.to_string()),
                        error_message: Some(e.message.clone()),
                    });
                }
            }
            Ok(t::BatchPutScheduledUpdateGroupActionAnswer { failed_scheduled_update_group_actions: Some(failed) })
        })
    }

    pub(crate) fn delete_scheduled_action_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteScheduledActionType,
    ) -> Result<(), ServiceError> {
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DeleteScheduledAction", &input.auto_scaling_group_name)?;
            if g.scheduled.remove(&input.scheduled_action_name).is_none() {
                return Err(validation(format!(
                    "Scheduled Update Group Action name not found - Could not find scheduled update group action: {}",
                    input.scheduled_action_name
                )));
            }
            g.scheduled_ran.remove(&input.scheduled_action_name);
            Ok(())
        })
    }

    pub(crate) fn batch_delete_scheduled_action_op(
        &self,
        ctx: &RequestContext,
        input: t::BatchDeleteScheduledActionType,
    ) -> Result<t::BatchDeleteScheduledActionAnswer, ServiceError> {
        if input.scheduled_action_names.len() > 50 {
            return Err(validation("You can specify up to 50 scheduled actions."));
        }
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "BatchDeleteScheduledAction", &input.auto_scaling_group_name)?;
            let mut failed = Vec::new();
            for n in &input.scheduled_action_names {
                if g.scheduled.remove(n).is_none() {
                    failed.push(t::FailedScheduledUpdateGroupActionRequest {
                        scheduled_action_name: n.clone(),
                        error_code: Some("ValidationError".into()),
                        error_message: Some(format!(
                            "Scheduled Update Group Action name not found - Could not find scheduled update group action: {n}"
                        )),
                    });
                }
                g.scheduled_ran.remove(n);
            }
            Ok(t::BatchDeleteScheduledActionAnswer { failed_scheduled_actions: Some(failed) })
        })
    }

    pub(crate) fn describe_scheduled_actions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeScheduledActionsType,
    ) -> Result<t::ScheduledActionsType, ServiceError> {
        authorize(ctx, "DescribeScheduledActions", "*", None, ConditionContext::new())?;
        let names = input.scheduled_action_names.clone().unwrap_or_default();
        let list: Vec<t::ScheduledUpdateGroupAction> = self.with_region(ctx, |r| {
            if let Some(g) = &input.auto_scaling_group_name {
                if !r.groups.contains_key(g) {
                    return Err(crate::util::group_not_found(g));
                }
            }
            Ok(r.groups
                .values()
                .filter(|g| input.auto_scaling_group_name.as_ref().is_none_or(|n| n == g.name()))
                .flat_map(|g| g.scheduled.values().cloned())
                .filter(|a| names.is_empty() || a.scheduled_action_name.as_ref().is_some_and(|n| names.contains(n)))
                .filter(|a| {
                    input.start_time.is_none_or(|s| a.start_time.is_none_or(|t| t >= s) || a.recurrence.is_some())
                })
                .filter(|a| input.end_time.is_none_or(|e| a.start_time.is_none_or(|t| t <= e)))
                .collect())
        })?;
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 100)?;
        Ok(t::ScheduledActionsType { scheduled_update_group_actions: Some(page), next_token })
    }
}
