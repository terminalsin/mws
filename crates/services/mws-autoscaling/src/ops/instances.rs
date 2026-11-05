//! Instances in groups: describe, attach and detach, standby, health,
//! scale-in protection, termination and `LaunchInstances`.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::json;

use super::{authorized_group, group_of_instance, render_instance};
use crate::engine::{new_activity, Op, Planner, Source};
use crate::generated::types as t;
use crate::state::Member;
use crate::util::{at, authorize, paginate, validation};
use crate::{account_of, AutoScaling};

fn not_managed(id: &str) -> ServiceError {
    validation(format!("Instance Id not found - No managed instance found for instance ID: {id}"))
}

fn not_in_group(id: &str, group: &str) -> ServiceError {
    validation(format!("The instance {id} is not part of Auto Scaling group {group}."))
}

impl AutoScaling {
    pub(crate) fn describe_auto_scaling_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAutoScalingInstancesType,
    ) -> Result<t::AutoScalingInstancesType, ServiceError> {
        authorize(ctx, "DescribeAutoScalingInstances", "*", None, ConditionContext::new())?;
        let ids = input.instance_ids.clone().unwrap_or_default();
        let list: Vec<t::AutoScalingInstanceDetails> = self.with_region(ctx, |r| {
            let mut out: Vec<t::AutoScalingInstanceDetails> = r
                .groups
                .values()
                .flat_map(|g| {
                    g.members.values().filter(|m| ids.is_empty() || ids.contains(&m.instance_id)).map(|m| {
                        let i = render_instance(m);
                        t::AutoScalingInstanceDetails {
                            instance_id: i.instance_id,
                            instance_type: i.instance_type,
                            auto_scaling_group_name: g.name().to_string(),
                            availability_zone: i.availability_zone,
                            availability_zone_id: i.availability_zone_id,
                            lifecycle_state: i.lifecycle_state,
                            health_status: i.health_status.to_ascii_uppercase(),
                            launch_configuration_name: i.launch_configuration_name,
                            launch_template: i.launch_template,
                            image_id: i.image_id,
                            protected_from_scale_in: i.protected_from_scale_in,
                            weighted_capacity: i.weighted_capacity,
                        }
                    })
                })
                .collect();
            out.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
            out
        });
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 50)?;
        Ok(t::AutoScalingInstancesType { auto_scaling_instances: Some(page), next_token })
    }

    pub(crate) async fn attach_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::AttachInstancesQuery,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let name = input.auto_scaling_group_name.clone();
        let ids = input.instance_ids.clone().unwrap_or_default();
        let (zones, tags) = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "AttachInstances", &name)?;
            Ok::<_, ServiceError>((g.cfg.availability_zones.clone(), g.cfg.tags.clone().unwrap_or_default()))
        })?;
        if ids.is_empty() {
            return Ok(());
        }
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        let info = self.ec2_instances(&sctx, &ids).await?;
        for id in &ids {
            let i = info
                .get(id)
                .ok_or_else(|| validation(format!("Instance {id} is not in a valid state to be attached.")))?;
            if i.state != "running" {
                return Err(validation(format!("Instance {id} is not in correct state")));
            }
            if !zones.contains(&i.availability_zone) {
                return Err(validation(format!(
                    "Instance {id} is in availability zone {} which is not part of the AutoScalingGroup {name}",
                    i.availability_zone
                )));
            }
        }
        let now = self.now();
        self.with_region(ctx, |r| {
            if let Some(other) = ids.iter().find_map(|id| group_of_instance(r, id).map(|g| (id.clone(), g.name().to_string()))) {
                return Err(validation(format!(
                    "The instance {} is already part of the Auto Scaling group {}",
                    other.0, other.1
                )));
            }
            let crate::state::RegionState { groups, activities, .. } = r;
            let g = groups.get_mut(&name).ok_or_else(|| crate::util::group_not_found(&name))?;
            let before = g.cfg.desired_capacity;
            let after = before + ids.len() as i32;
            if after > g.cfg.max_size {
                return Err(validation(format!(
                    "AutoScalingGroup: {name} has min-size={}, max-size={}, and desired-size={before}. To place another instance would violate the group's max size constraint.",
                    g.cfg.min_size, g.cfg.max_size
                )));
            }
            g.cfg.desired_capacity = after;
            for id in &ids {
                let i = &info[id];
                let cause = format!(
                    "{} an instance was added in response to user request. Keeping the capacity at the new {after}.",
                    at(now)
                );
                let details = json!({"Subnet ID": i.subnet_id.clone().unwrap_or_default(), "Availability Zone": i.availability_zone});
                let activity = new_activity(
                    activities,
                    g,
                    format!("Attaching an existing EC2 instance: {id}"),
                    cause,
                    "PreInService",
                    now,
                    details,
                );
                g.members.insert(
                    id.clone(),
                    Member {
                        instance_id: id.clone(),
                        instance_type: i.instance_type.clone(),
                        availability_zone: i.availability_zone.clone(),
                        availability_zone_id: i.availability_zone_id.clone(),
                        subnet_id: i.subnet_id.clone(),
                        lifecycle_state: "Pending".into(),
                        health_status: "Healthy".into(),
                        image_id: i.image_id.clone(),
                        launched_at: i.launch_time.unwrap_or(now),
                        activity_id: Some(activity),
                        ..Default::default()
                    },
                );
            }
            Ok(())
        })?;
        let mut instance_tags: Vec<(String, Option<String>)> =
            vec![("aws:autoscaling:groupName".to_string(), Some(name.clone()))];
        instance_tags.extend(
            tags.iter()
                .filter(|t| t.propagate_at_launch == Some(true))
                .filter_map(|t| Some((t.key.clone()?, Some(t.value.clone().unwrap_or_default())))),
        );
        for id in &ids {
            self.ec2().set_tags_as_service(&sctx, id, &instance_tags);
        }
        Ok(())
    }

    pub(crate) fn detach_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DetachInstancesQuery,
    ) -> Result<t::DetachInstancesAnswer, ServiceError> {
        let account = account_of(ctx);
        let name = input.auto_scaling_group_name.clone();
        let ids = input.instance_ids.clone().unwrap_or_default();
        let now = self.now();
        let (activities, ops) = self.with_region(ctx, |r| {
            authorized_group(ctx, r, "DetachInstances", &name)?;
            let crate::state::RegionState { groups, activities, .. } = r;
            let g = groups.get_mut(&name).expect("checked");
            for id in &ids {
                let m = g.members.get(id).ok_or_else(|| not_in_group(id, &name))?;
                if m.warm || !matches!(m.lifecycle_state.as_str(), "InService" | "Standby") {
                    return Err(validation(format!("The instance {id} is not in InService or Standby.")));
                }
            }
            let before = g.cfg.desired_capacity;
            let counted = ids.iter().filter(|id| g.members[*id].lifecycle_state == "InService").count() as i32;
            let after = if input.should_decrement_desired_capacity { before - counted } else { before };
            if after < g.cfg.min_size {
                return Err(validation(format!(
                    "AutoScalingGroup: {name} has min-size={}, max-size={}, and desired-size={before}. Detaching {} instance(s) with ShouldDecrementDesiredCapacity would violate the group's min size constraint.",
                    g.cfg.min_size, g.cfg.max_size, ids.len()
                )));
            }
            g.cfg.desired_capacity = after;
            let ops = super::traffic::member_ops(
                g,
                &ids.iter().filter(|id| g.members[*id].lifecycle_state == "InService").cloned().collect::<Vec<_>>(),
                false,
            );
            let mut out = Vec::new();
            for id in &ids {
                let m = g.members.remove(id).expect("checked");
                let cause = if input.should_decrement_desired_capacity {
                    format!(
                        "{} instance {id} was detached in response to a user request, shrinking the capacity from {before} to {after}.",
                        at(now)
                    )
                } else {
                    format!("{} instance {id} was detached in response to a user request.", at(now))
                };
                let details = json!({"Subnet ID": m.subnet_id.clone().unwrap_or_default(), "Availability Zone": m.availability_zone});
                let aid = new_activity(activities, g, format!("Detaching EC2 instance: {id}"), cause, "Successful", now, details);
                if let Some(a) = activities.iter_mut().rev().find(|a| a.activity_id == aid) {
                    a.end_time = Some(now);
                    let mut shown = a.clone();
                    shown.status_code = "InProgress".into();
                    shown.end_time = None;
                    shown.progress = Some(50);
                    out.push(shown);
                }
            }
            Ok((out, ops))
        })?;
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        for id in &ids {
            self.ec2().set_tags_as_service(&sctx, id, &[("aws:autoscaling:groupName".into(), None)]);
        }
        for op in ops {
            self.deliver_traffic(&sctx, op);
        }
        Ok(t::DetachInstancesAnswer { activities: Some(activities) })
    }

    pub(crate) fn enter_standby_op(
        &self,
        ctx: &RequestContext,
        input: t::EnterStandbyQuery,
    ) -> Result<t::EnterStandbyAnswer, ServiceError> {
        let account = account_of(ctx);
        let name = input.auto_scaling_group_name.clone();
        let ids = input.instance_ids.clone().unwrap_or_default();
        let now = self.now();
        let (out, ops) = self.with_region(ctx, |r| {
            authorized_group(ctx, r, "EnterStandby", &name)?;
            let crate::state::RegionState { groups, activities, .. } = r;
            let g = groups.get_mut(&name).expect("checked");
            for id in &ids {
                let m = g.members.get(id).ok_or_else(|| not_in_group(id, &name))?;
                if m.warm || m.lifecycle_state != "InService" {
                    return Err(validation(format!("The instance {id} is not in InService.")));
                }
            }
            let before = g.cfg.desired_capacity;
            let after = if input.should_decrement_desired_capacity { before - ids.len() as i32 } else { before };
            if after < g.cfg.min_size {
                return Err(validation(format!(
                    "AutoScalingGroup: {name} has min-size={}, max-size={}, and desired-size={before}. Moving {} instance(s) to Standby with ShouldDecrementDesiredCapacity would violate the group's min size constraint.",
                    g.cfg.min_size, g.cfg.max_size, ids.len()
                )));
            }
            g.cfg.desired_capacity = after;
            let ops = super::traffic::member_ops(g, &ids, false);
            let mut out = Vec::new();
            for id in &ids {
                let cause = if input.should_decrement_desired_capacity {
                    format!(
                        "{} instance {id} was moved to standby in response to a user request, shrinking the capacity from {before} to {after}.",
                        at(now)
                    )
                } else {
                    format!("{} instance {id} was moved to standby in response to a user request.", at(now))
                };
                let m = g.members.get(id).expect("checked");
                let details = json!({"Subnet ID": m.subnet_id.clone().unwrap_or_default(), "Availability Zone": m.availability_zone});
                let aid = new_activity(activities, g, format!("Moving EC2 instance to Standby: {id}"), cause, "Successful", now, details);
                if let Some(a) = activities.iter_mut().rev().find(|a| a.activity_id == aid) {
                    a.end_time = Some(now);
                    let mut shown = a.clone();
                    shown.status_code = "InProgress".into();
                    shown.end_time = None;
                    shown.progress = Some(50);
                    out.push(shown);
                }
                g.members.get_mut(id).expect("checked").lifecycle_state = "Standby".into();
            }
            Ok((out, ops))
        })?;
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        for op in ops {
            self.deliver_traffic(&sctx, op);
        }
        Ok(t::EnterStandbyAnswer { activities: Some(out) })
    }

    pub(crate) fn exit_standby_op(
        &self,
        ctx: &RequestContext,
        input: t::ExitStandbyQuery,
    ) -> Result<t::ExitStandbyAnswer, ServiceError> {
        let name = input.auto_scaling_group_name.clone();
        let ids = input.instance_ids.clone().unwrap_or_default();
        let now = self.now();
        self.with_region(ctx, |r| {
            authorized_group(ctx, r, "ExitStandby", &name)?;
            let crate::state::RegionState { groups, activities, .. } = r;
            let g = groups.get_mut(&name).expect("checked");
            for id in &ids {
                let m = g.members.get(id).ok_or_else(|| not_in_group(id, &name))?;
                if m.lifecycle_state != "Standby" {
                    return Err(validation(format!("The instance {id} is not in Standby.")));
                }
            }
            let before = g.cfg.desired_capacity;
            let after = before + ids.len() as i32;
            if after > g.cfg.max_size {
                return Err(validation(format!(
                    "AutoScalingGroup: {name} has min-size={}, max-size={}, and desired-size={before}. Moving {} instance(s) out of Standby would violate the group's max size constraint.",
                    g.cfg.min_size, g.cfg.max_size, ids.len()
                )));
            }
            g.cfg.desired_capacity = after;
            let mut out = Vec::new();
            for id in &ids {
                let cause = format!(
                    "{} instance {id} was moved out of standby in response to a user request, increasing the capacity from {before} to {after}.",
                    at(now)
                );
                let m = g.members.get(id).expect("checked");
                let details = json!({"Subnet ID": m.subnet_id.clone().unwrap_or_default(), "Availability Zone": m.availability_zone});
                let aid = new_activity(activities, g, format!("Moving EC2 instance out of Standby: {id}"), cause, "PreInService", now, details);
                if let Some(a) = activities.iter().rev().find(|a| a.activity_id == aid) {
                    out.push(a.clone());
                }
                let m = g.members.get_mut(id).expect("checked");
                m.lifecycle_state = "Pending".into();
                m.activity_id = Some(aid);
                m.hooks_done.clear();
            }
            Ok(t::ExitStandbyAnswer { activities: Some(out) })
        })
    }

    pub(crate) fn set_instance_health_op(
        &self,
        ctx: &RequestContext,
        input: t::SetInstanceHealthQuery,
    ) -> Result<(), ServiceError> {
        let status = match input.health_status.as_str() {
            "Healthy" | "HEALTHY" => "Healthy",
            "Unhealthy" | "UNHEALTHY" => "Unhealthy",
            other => {
                return Err(validation(format!(
                    "Invalid health status: {other}. Valid values are Healthy and Unhealthy."
                )))
            }
        };
        let now = self.now();
        self.with_region(ctx, |r| {
            let name = group_of_instance(r, &input.instance_id).map(|g| g.name().to_string());
            let Some(name) = name else {
                authorize(ctx, "SetInstanceHealth", "*", None, ConditionContext::new())?;
                return Err(not_managed(&input.instance_id));
            };
            let g = authorized_group(ctx, r, "SetInstanceHealth", &name)?;
            let grace = g.cfg.health_check_grace_period.unwrap_or(0) as i64;
            let m = g.members.get_mut(&input.instance_id).expect("member");
            let in_grace = m.in_service_at.unwrap_or(m.launched_at) + chrono::Duration::seconds(grace) > now;
            if status == "Unhealthy" && input.should_respect_grace_period.unwrap_or(true) && in_grace {
                return Ok(());
            }
            m.health_status = status.into();
            Ok(())
        })
    }

    pub(crate) fn set_instance_protection_op(
        &self,
        ctx: &RequestContext,
        input: t::SetInstanceProtectionQuery,
    ) -> Result<t::SetInstanceProtectionAnswer, ServiceError> {
        if input.instance_ids.len() > 50 {
            return Err(validation("You can specify up to 50 instances."));
        }
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "SetInstanceProtection", &input.auto_scaling_group_name)?;
            for id in &input.instance_ids {
                if !g.members.contains_key(id) {
                    return Err(not_in_group(id, &input.auto_scaling_group_name));
                }
            }
            for id in &input.instance_ids {
                g.members.get_mut(id).expect("checked").protected_from_scale_in = input.protected_from_scale_in;
            }
            Ok(Default::default())
        })
    }

    pub(crate) fn terminate_instance_in_auto_scaling_group_op(
        &self,
        ctx: &RequestContext,
        input: t::TerminateInstanceInAutoScalingGroupType,
    ) -> Result<t::ActivityType, ServiceError> {
        let mut ids: Vec<String> = input.instance_ids.clone().unwrap_or_default();
        if let Some(id) = &input.instance_id {
            ids.insert(0, id.clone());
        }
        ids.dedup();
        if ids.is_empty() {
            return Err(validation("InstanceId must be specified."));
        }
        let now = self.now();
        let account = account_of(ctx);
        let (out, ops) = self.with_region(ctx, |r| {
            let mut out = Vec::new();
            let mut all_ops = Vec::new();
            for id in &ids {
                let name = match (&input.auto_scaling_group_name, group_of_instance(r, id)) {
                    (_, Some(g)) => g.name().to_string(),
                    (Some(n), None) => {
                        authorized_group(ctx, r, "TerminateInstanceInAutoScalingGroup", n)?;
                        return Err(not_in_group(id, n));
                    }
                    (None, None) => {
                        authorize(ctx, "TerminateInstanceInAutoScalingGroup", "*", None, ConditionContext::new())?;
                        return Err(not_managed(id));
                    }
                };
                if input.auto_scaling_group_name.as_ref().is_some_and(|n| *n != name) {
                    return Err(not_in_group(id, input.auto_scaling_group_name.as_deref().unwrap_or_default()));
                }
                authorized_group(ctx, r, "TerminateInstanceInAutoScalingGroup", &name)?;
                let crate::state::RegionState { groups, activities, .. } = r;
                let g = groups.get_mut(&name).expect("checked");
                let before = g.cfg.desired_capacity;
                let m = g.members.get(id).expect("member");
                if m.lifecycle_state.starts_with("Terminating") {
                    if let Some(a) = activities.iter().rev().find(|a| Some(&a.activity_id) == m.activity_id.as_ref()) {
                        out.push(a.clone());
                    }
                    continue;
                }
                let counted = !m.warm && (m.lifecycle_state.starts_with("Pending") || m.lifecycle_state == "InService");
                let cause = if input.should_decrement_desired_capacity && counted {
                    if before <= g.cfg.min_size {
                        return Err(validation(format!(
                            "Currently, desiredSize equals minSize ({}). Terminating instance without replacement will violate group's min size constraint. Either set shouldDecrementDesiredCapacity flag to false or lower group's min size.",
                            g.cfg.min_size
                        )));
                    }
                    g.cfg.desired_capacity = before - 1;
                    format!(
                        "{} instance {id} was taken out of service in response to a user request, shrinking the capacity from {before} to {}.",
                        at(now),
                        before - 1
                    )
                } else {
                    format!("{} instance {id} was taken out of service in response to a user request.", at(now))
                };
                let empty = Default::default();
                let source = Source::default();
                let mut p = Planner {
                    g,
                    activities,
                    info: &empty,
                    source: &source,
                    now,
                    account: &account,
                    region: &ctx.region,
                    partition: &ctx.partition,
                    ops: Vec::new(),
                    changed: false,
                };
                p.mark_terminating(id, cause, false);
                all_ops.append(&mut p.ops);
                let aid = g.members.get(id).and_then(|m| m.activity_id.clone());
                if let Some(a) = activities.iter().rev().find(|a| Some(&a.activity_id) == aid.as_ref()) {
                    out.push(a.clone());
                }
            }
            Ok((out, all_ops))
        })?;
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        for op in ops {
            if matches!(op, Op::Traffic { .. }) {
                self.deliver_traffic(&sctx, op);
            }
        }
        Ok(t::ActivityType { activity: out.first().cloned(), activities: (ids.len() > 1).then_some(out) })
    }

    pub(crate) async fn launch_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::LaunchInstancesRequest,
    ) -> Result<t::LaunchInstancesResult, ServiceError> {
        let account = account_of(ctx);
        let name = input.auto_scaling_group_name.clone();
        if input.requested_capacity < 1 {
            return Err(validation("RequestedCapacity must be at least 1."));
        }
        if let Some(s) = &input.retry_strategy {
            if !matches!(s.as_str(), "retry-with-group-configuration" | "none") {
                return Err(validation(format!("Invalid RetryStrategy: {s}")));
            }
        }
        // No reconciliation pass may run while the launch adds capacity.
        let _guard = self.inner.reconciling.lock().await;
        let now = self.now();
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        let (snapshot, lcs, reused) = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "LaunchInstances", &name)?;
            if let Some(prev) = g.launch_tokens.get(&input.client_token) {
                return Ok((None, Default::default(), Some(prev.clone())));
            }
            Ok::<_, ServiceError>((Some(g.clone()), r.launch_configurations.clone(), None))
        })?;
        if let Some(prev) = reused {
            return Ok(prev);
        }
        let snapshot = snapshot.expect("group");
        let n = input.requested_capacity;
        if snapshot.cfg.desired_capacity + n > snapshot.cfg.max_size {
            return Err(validation(format!(
                "The requested capacity {n} would exceed the group's maximum size of {}.",
                snapshot.cfg.max_size
            )));
        }
        let source = self.resolve_source(&sctx, &snapshot, &lcs);
        // Where to launch: the request's subnets or zones, else the group's.
        let wanted_subnets = input.subnet_ids.clone().unwrap_or_default();
        let wanted_zones: Vec<String> = input
            .availability_zones
            .clone()
            .unwrap_or_default()
            .into_iter()
            .chain(input.availability_zone_ids.clone().unwrap_or_default())
            .collect();
        for s in &wanted_subnets {
            if !snapshot.subnet_zones.contains_key(s) {
                return Err(validation(format!("The subnet {s} is not part of the Auto Scaling group {name}.")));
            }
        }
        let launches = self.with_region(ctx, |r| {
            let crate::state::RegionState { groups, activities, .. } = r;
            let g = groups.get_mut(&name).ok_or_else(|| crate::util::group_not_found(&name))?;
            let before = g.cfg.desired_capacity;
            g.cfg.desired_capacity = before + n;
            let all = g.subnet_zones.clone();
            if !wanted_subnets.is_empty() || !wanted_zones.is_empty() {
                g.subnet_zones.retain(|s, (z, id)| {
                    wanted_subnets.contains(s) || wanted_zones.contains(z) || wanted_zones.contains(id)
                });
            }
            let cause = format!(
                "{} a user request to launch instances increased the capacity from {before} to {}.",
                at(now),
                before + n
            );
            let empty = Default::default();
            let mut p = Planner {
                g,
                activities,
                info: &empty,
                source: &source,
                now,
                account: &account,
                region: &ctx.region,
                partition: &ctx.partition,
                ops: Vec::new(),
                changed: false,
            };
            let mut planned = Vec::new();
            for _ in 0..n {
                match p.plan_launch(&planned, false, cause.clone(), None) {
                    Some(l) => planned.push(l),
                    None => break,
                }
            }
            p.g.subnet_zones = all;
            Ok::<_, ServiceError>(planned)
        })?;
        if launches.is_empty() {
            self.with_region(ctx, |r| {
                if let Some(g) = r.groups.get_mut(&name) {
                    g.cfg.desired_capacity -= n;
                }
            });
            return Err(validation(
                "None of the requested Availability Zones or subnets belong to the Auto Scaling group.",
            ));
        }
        let activity_ids: Vec<String> = launches.iter().map(|l| l.activity_id.clone()).collect();
        let tags = snapshot.cfg.tags.clone().unwrap_or_default();
        let arn = snapshot.arn();
        let ops: Vec<Op> = launches.into_iter().map(|l| Op::Launch(Box::new(l))).collect();
        self.execute(&sctx, &account, &ctx.region, &name, &arn, &tags, ops, now).await;
        let result = self.with_region(ctx, |r| {
            let crate::state::RegionState { groups, activities, .. } = r;
            let Some(g) = groups.get_mut(&name) else { return t::LaunchInstancesResult::default() };
            let mut collections: Vec<t::InstanceCollection> = Vec::new();
            let mut errors = Vec::new();
            let mut launched = 0;
            for aid in &activity_ids {
                if let Some(m) = g.members.values().find(|m| m.activity_id.as_ref() == Some(aid)) {
                    launched += 1;
                    match collections.iter_mut().find(|c| {
                        c.subnet_id == m.subnet_id && c.instance_type.as_deref() == Some(m.instance_type.as_str())
                    }) {
                        Some(c) => c.instance_ids.get_or_insert_with(Vec::new).push(m.instance_id.clone()),
                        None => collections.push(t::InstanceCollection {
                            instance_type: Some(m.instance_type.clone()),
                            market_type: Some("on-demand".into()),
                            subnet_id: m.subnet_id.clone(),
                            availability_zone: Some(m.availability_zone.clone()),
                            availability_zone_id: m.availability_zone_id.clone(),
                            instance_ids: Some(vec![m.instance_id.clone()]),
                        }),
                    }
                } else if let Some(a) = activities.iter().rev().find(|a| a.activity_id == *aid) {
                    let details: serde_json::Value =
                        a.details.as_deref().and_then(|d| serde_json::from_str(d).ok()).unwrap_or_default();
                    errors.push(t::LaunchInstancesError {
                        market_type: Some("on-demand".into()),
                        subnet_id: details["Subnet ID"].as_str().map(String::from),
                        availability_zone: details["Availability Zone"].as_str().map(String::from),
                        error_code: Some("InsufficientInstanceCapacity".into()),
                        error_message: a.status_message.clone(),
                        ..Default::default()
                    });
                }
            }
            if input.retry_strategy.as_deref() == Some("none") {
                g.cfg.desired_capacity -= n - launched;
            }
            let out = t::LaunchInstancesResult {
                auto_scaling_group_name: Some(name.clone()),
                client_token: Some(input.client_token.clone()),
                instances: Some(collections),
                errors: Some(errors),
            };
            g.launch_tokens.insert(input.client_token.clone(), out.clone());
            out
        });
        Ok(result)
    }
}
