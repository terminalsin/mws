//! Instance refreshes: replace a group's instances in batches that keep
//! `MinHealthyPercentage` of the desired capacity healthy, pausing at
//! checkpoints; on success the group takes the desired configuration.
//! Rollbacks replace what was refreshed with the group's own
//! configuration again.

use chrono::Duration;
use mws_core::{RequestContext, ServiceError};

use super::authorized_group;
use crate::engine::Planner;
use crate::generated::types as t;
use crate::state::{Member, Refresh};
use crate::util::{at, paginate, validation};
use crate::AutoScaling;

fn not_found(group: &str) -> ServiceError {
    ServiceError::client(
        "ActiveInstanceRefreshNotFound",
        400,
        format!("No in progress or pending Instance Refresh found for Auto Scaling group {group}"),
    )
}

/// Whether a member already runs `template` (or the launch configuration).
fn matches(m: &Member, template: &Option<(String, i64)>, configuration: Option<&str>) -> bool {
    match template {
        Some((id, v)) => m.launch_template.as_ref().is_some_and(|lt| {
            lt.launch_template_id.as_deref() == Some(id.as_str())
                && lt.version.as_deref() == Some(v.to_string().as_str())
        }),
        None => configuration.is_some_and(|c| m.launch_configuration_name.as_deref() == Some(c)),
    }
}

fn percent(done: i32, total: i32) -> i32 {
    if total <= 0 {
        100
    } else {
        (done * 100 / total).clamp(0, 100)
    }
}

/// Advance the group's active refresh, if any (called from each
/// reconciliation pass, under the state lock).
pub(crate) fn advance(p: &mut Planner<'_>) {
    let now = p.now;
    let Some(status) = p.g.active_refresh().and_then(|r| r.info.status.clone()) else { return };
    if p.g.suspended("InstanceRefresh") && status != "Cancelling" {
        return;
    }
    // New instances count as warming up (the refresh waits) until the
    // instance warmup has passed since they went InService.
    let warmup =
        p.g.active_refresh()
            .and_then(|r| r.info.preferences.as_ref().and_then(|x| x.instance_warmup))
            .or(p.g.cfg.default_instance_warmup)
            .unwrap_or(0)
            .max(0);
    let started = p.g.active_refresh().and_then(|r| r.info.start_time).unwrap_or(now);
    let busy = p.g.members.values().any(|m| {
        !m.warm
            && (m.lifecycle_state.starts_with("Pending")
                || m.lifecycle_state.starts_with("Terminating")
                || (status != "Cancelling"
                    && m.lifecycle_state == "InService"
                    && m.launched_at >= started
                    && m.in_service_at.is_some_and(|t| t + chrono::Duration::seconds(warmup as i64) > now)))
    });
    let configuration = p.g.cfg.launch_configuration_name.clone();
    let target = match status.as_str() {
        "RollbackInProgress" => p.source.current_template.clone(),
        _ => p.source.template.clone(),
    };
    let desired = p.g.cfg.desired_capacity;
    let healthy = p.g.members.values().filter(|m| !m.warm && m.lifecycle_state == "InService").count() as i32;
    let ids: Vec<String> = p.g.members.keys().cloned().collect();
    let candidates: Vec<(String, bool, bool, bool)> =
        p.g.members
            .values()
            .filter(|m| !m.warm)
            .map(|m| {
                (
                    m.instance_id.clone(),
                    matches(m, &target, configuration.as_deref()),
                    m.protected_from_scale_in,
                    m.lifecycle_state == "Standby",
                )
            })
            .collect();
    let group_min = p_min_healthy(p);
    let r = p.g.active_refresh_mut().expect("active refresh");
    match status.as_str() {
        "Pending" => {
            let prefs = r.info.preferences.clone().unwrap_or_default();
            let skip = prefs.skip_matching.unwrap_or(false);
            let protected = prefs.scale_in_protected_instances.clone().unwrap_or_else(|| "Ignore".into());
            let standby = prefs.standby_instances.clone().unwrap_or_else(|| "Ignore".into());
            r.to_replace = candidates
                .iter()
                .filter(|(_, matching, prot, sb)| {
                    !(skip && *matching) && !(*prot && protected != "Refresh") && !(*sb && standby != "Terminate")
                })
                .map(|(id, ..)| id.clone())
                .collect();
            r.total = r.to_replace.len() as i32;
            r.info.status = Some("InProgress".into());
            r.info.instances_to_update = Some(r.total);
            r.info.percentage_complete = Some(percent(0, r.total));
            p.changed = true;
        }
        "InProgress" | "RollbackInProgress" | "Cancelling" => {
            r.to_replace.retain(|id| ids.contains(id));
            if status == "RollbackInProgress" {
                r.to_replace.retain(|id| candidates.iter().any(|(c, matching, ..)| c == id && !matching));
                if r.total < 0 {
                    r.total = r.to_replace.len() as i32;
                }
            }
            let remaining = r.to_replace.len() as i32;
            let done = r.total - remaining;
            let pct = percent(done, r.total);
            if status == "RollbackInProgress" {
                if let Some(rb) = r.info.rollback_details.as_mut() {
                    rb.percentage_complete_on_rollback = Some(pct);
                    rb.instances_to_update_on_rollback = Some(remaining);
                }
            } else {
                r.info.percentage_complete = Some(pct);
                r.info.instances_to_update = Some(remaining);
                r.info.progress_details = Some(t::InstanceRefreshProgressDetails {
                    live_pool_progress: Some(t::InstanceRefreshLivePoolProgress {
                        percentage_complete: Some(pct),
                        instances_to_update: Some(remaining),
                    }),
                    warm_pool_progress: Some(t::InstanceRefreshWarmPoolProgress {
                        percentage_complete: Some(100),
                        instances_to_update: Some(0),
                    }),
                });
            }
            if busy {
                return;
            }
            if status == "Cancelling" {
                r.info.status = Some("Cancelled".into());
                r.info.status_reason = Some("Instance Refresh was cancelled by the user.".into());
                r.info.end_time = Some(now);
                p.changed = true;
                return;
            }
            if remaining == 0 {
                let bake = r.info.preferences.as_ref().and_then(|p| p.bake_time).unwrap_or(0);
                if status == "InProgress" && bake > 0 && r.paused_until.is_none() {
                    r.info.status = Some("Baking".into());
                    r.paused_until = Some(now + Duration::seconds(bake as i64));
                    p.changed = true;
                    return;
                }
                finish(p, &status);
                return;
            }
            if r.paused_until.is_some_and(|u| now < u) {
                return;
            }
            if r.paused_until.take().is_some() {
                r.info.status_reason = None;
            }
            // Checkpoints pause the refresh once their share is replaced.
            if status == "InProgress" {
                let prefs = r.info.preferences.clone().unwrap_or_default();
                if let Some(cp) = prefs
                    .checkpoint_percentages
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .find(|cp| pct >= *cp && *cp < 100 && !r.checkpoints_done.contains(cp))
                {
                    r.checkpoints_done.push(cp);
                    r.paused_until = Some(now + Duration::seconds(prefs.checkpoint_delay.unwrap_or(3600) as i64));
                    r.info.status_reason = Some(format!("Waiting for a checkpoint at {cp}% to complete."));
                    p.changed = true;
                    return;
                }
            }
            let min_pct =
                r.info.preferences.as_ref().and_then(|p| p.min_healthy_percentage).or(group_min).unwrap_or(90);
            let keep = (desired as i64 * min_pct as i64 + 99) / 100;
            let batch = ((healthy as i64 - keep).max(1)) as usize;
            let batch: Vec<String> = {
                let r = p.g.active_refresh().expect("active refresh");
                r.to_replace.iter().take(batch).cloned().collect()
            };
            let cause = if status == "RollbackInProgress" {
                format!("{} an instance was taken out of service in response to an instance refresh rollback.", at(now))
            } else {
                format!("{} an instance was taken out of service in response to an instance refresh.", at(now))
            };
            for id in batch {
                p.mark_terminating(&id, cause.clone(), false);
            }
        }
        "Baking" if r.paused_until.is_some_and(|u| now >= u) => finish(p, "InProgress"),
        _ => {}
    }
}

fn p_min_healthy(p: &Planner<'_>) -> Option<i32> {
    p.g.cfg.instance_maintenance_policy.as_ref().and_then(|m| m.min_healthy_percentage).filter(|v| *v >= 0)
}

fn finish(p: &mut Planner<'_>, status: &str) {
    let now = p.now;
    let rollback = status == "RollbackInProgress";
    let g = &mut *p.g;
    let r = g.active_refresh_mut().expect("active refresh");
    r.info.end_time = Some(now);
    r.paused_until = None;
    if rollback {
        r.info.status = Some("RollbackSuccessful".into());
        r.info.status_reason = Some("Instance refresh was rolled back.".into());
    } else {
        r.info.status = Some("Successful".into());
        r.info.percentage_complete = Some(100);
        r.info.instances_to_update = Some(0);
        r.info.status_reason = None;
        if let Some(dc) = r.info.desired_configuration.clone() {
            if let Some(lt) = dc.launch_template {
                g.cfg.launch_template = Some(lt);
                g.cfg.mixed_instances_policy = None;
                g.cfg.launch_configuration_name = None;
            }
            if let Some(m) = dc.mixed_instances_policy {
                g.cfg.mixed_instances_policy = Some(m);
                g.cfg.launch_template = None;
                g.cfg.launch_configuration_name = None;
            }
        }
    }
    p.changed = true;
}

impl AutoScaling {
    pub(crate) fn start_instance_refresh_op(
        &self,
        ctx: &RequestContext,
        input: t::StartInstanceRefreshType,
    ) -> Result<t::StartInstanceRefreshAnswer, ServiceError> {
        if let Some(s) = &input.strategy {
            if !matches!(s.as_str(), "Rolling" | "ReplaceRootVolume") {
                return Err(validation(format!("Invalid strategy: {s}")));
            }
        }
        if let Some(prefs) = &input.preferences {
            if let Some(m) = prefs.min_healthy_percentage {
                if !(0..=100).contains(&m) {
                    return Err(validation("MinHealthyPercentage must be between 0 and 100."));
                }
            }
            let mut last = 0;
            for cp in prefs.checkpoint_percentages.iter().flatten() {
                if *cp < 1 || *cp > 100 || *cp <= last {
                    return Err(validation("Checkpoint percentages must be in ascending order, between 1 and 100."));
                }
                last = *cp;
            }
        }
        if let Some(dc) = &input.desired_configuration {
            if let Some(spec) = &dc.launch_template {
                self.check_launch_template(ctx, spec)?;
            }
            if let Some(spec) = dc
                .mixed_instances_policy
                .as_ref()
                .and_then(|m| m.launch_template.as_ref())
                .and_then(|l| l.launch_template_specification.as_ref())
            {
                self.check_launch_template(ctx, spec)?;
            }
        }
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "StartInstanceRefresh", &input.auto_scaling_group_name)?;
            if g.active_refresh().is_some() {
                return Err(ServiceError::client(
                    "InstanceRefreshInProgress",
                    400,
                    "An Instance Refresh is already in progress and blocks the execution of this Instance Refresh.",
                ));
            }
            if input.desired_configuration.is_some() && g.cfg.launch_configuration_name.is_some() {
                return Err(validation(
                    "You can't specify a desired configuration for an Auto Scaling group that uses a launch configuration.",
                ));
            }
            let mut prefs = input.preferences.clone().unwrap_or_default();
            prefs.min_healthy_percentage = prefs
                .min_healthy_percentage
                .or_else(|| g.cfg.instance_maintenance_policy.as_ref().and_then(|m| m.min_healthy_percentage).filter(|v| *v >= 0))
                .or(Some(90));
            prefs.max_healthy_percentage = prefs.max_healthy_percentage.or(Some(100));
            prefs.instance_warmup = prefs.instance_warmup.or(g.cfg.default_instance_warmup);
            prefs.skip_matching = prefs.skip_matching.or(Some(false));
            prefs.auto_rollback = prefs.auto_rollback.or(Some(false));
            prefs.scale_in_protected_instances = prefs.scale_in_protected_instances.or(Some("Ignore".into()));
            prefs.standby_instances = prefs.standby_instances.or(Some("Ignore".into()));
            prefs.bake_time = prefs.bake_time.or(Some(0));
            if prefs.checkpoint_percentages.is_some() {
                prefs.checkpoint_delay = prefs.checkpoint_delay.or(Some(3600));
            }
            let id = uuid::Uuid::new_v4().to_string();
            g.refreshes.push(Refresh {
                info: t::InstanceRefresh {
                    instance_refresh_id: Some(id.clone()),
                    auto_scaling_group_name: Some(input.auto_scaling_group_name.clone()),
                    status: Some("Pending".into()),
                    start_time: Some(now),
                    percentage_complete: Some(0),
                    instances_to_update: Some(0),
                    preferences: Some(prefs),
                    desired_configuration: input.desired_configuration.clone(),
                    strategy: Some(input.strategy.clone().unwrap_or_else(|| "Rolling".into())),
                    ..Default::default()
                },
                previous_launch_template: g.cfg.launch_template.clone(),
                previous_mixed_instances_policy: g.cfg.mixed_instances_policy.clone(),
                previous_launch_configuration: g.cfg.launch_configuration_name.clone(),
                ..Default::default()
            });
            if g.refreshes.len() > 50 {
                g.refreshes.remove(0);
            }
            Ok(t::StartInstanceRefreshAnswer { instance_refresh_id: Some(id) })
        })
    }

    pub(crate) fn cancel_instance_refresh_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelInstanceRefreshType,
    ) -> Result<t::CancelInstanceRefreshAnswer, ServiceError> {
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "CancelInstanceRefresh", &input.auto_scaling_group_name)?;
            let refresh = g
                .active_refresh_mut()
                .filter(|r| matches!(r.info.status.as_deref(), Some("Pending" | "InProgress" | "Baking")))
                .ok_or_else(|| not_found(&input.auto_scaling_group_name))?;
            refresh.info.status = Some("Cancelling".into());
            refresh.paused_until = None;
            Ok(t::CancelInstanceRefreshAnswer { instance_refresh_id: refresh.info.instance_refresh_id.clone() })
        })
    }

    pub(crate) fn rollback_instance_refresh_op(
        &self,
        ctx: &RequestContext,
        input: t::RollbackInstanceRefreshType,
    ) -> Result<t::RollbackInstanceRefreshAnswer, ServiceError> {
        let now = self.now();
        self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "RollbackInstanceRefresh", &input.auto_scaling_group_name)?;
            let members: Vec<String> = g.members.values().filter(|m| !m.warm).map(|m| m.instance_id.clone()).collect();
            let refresh = g
                .active_refresh_mut()
                .filter(|r| matches!(r.info.status.as_deref(), Some("Pending" | "InProgress" | "Baking")))
                .ok_or_else(|| not_found(&input.auto_scaling_group_name))?;
            if refresh.info.desired_configuration.is_none() {
                return Err(ServiceError::client(
                    "IrreversibleInstanceRefresh",
                    400,
                    "The instance refresh can't be rolled back because it doesn't specify a desired configuration.",
                ));
            }
            let pct = refresh.info.percentage_complete;
            let left = refresh.info.instances_to_update;
            refresh.info.status = Some("RollbackInProgress".into());
            refresh.info.status_reason = Some("Rollback was started by the user.".into());
            refresh.paused_until = None;
            refresh.info.rollback_details = Some(t::RollbackDetails {
                rollback_reason: Some("Rollback was started by the user.".into()),
                rollback_start_time: Some(now),
                percentage_complete_on_rollback: pct,
                instances_to_update_on_rollback: left,
                progress_details_on_rollback: refresh.info.progress_details.clone(),
            });
            // Everything the refresh launched goes back to the group's own
            // configuration; the engine checks which members differ.
            refresh.to_replace = members;
            // Counted on the next pass, once the matching ones are dropped.
            refresh.total = -1;
            refresh.checkpoints_done.clear();
            let id = refresh.info.instance_refresh_id.clone();
            Ok(t::RollbackInstanceRefreshAnswer { instance_refresh_id: id })
        })
    }

    pub(crate) fn describe_instance_refreshes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstanceRefreshesType,
    ) -> Result<t::DescribeInstanceRefreshesAnswer, ServiceError> {
        let ids = input.instance_refresh_ids.clone().unwrap_or_default();
        let list: Vec<t::InstanceRefresh> = self.with_region(ctx, |r| {
            let g = authorized_group(ctx, r, "DescribeInstanceRefreshes", &input.auto_scaling_group_name)?;
            Ok::<_, ServiceError>(
                g.refreshes
                    .iter()
                    .rev()
                    .filter(|r| ids.is_empty() || r.info.instance_refresh_id.as_ref().is_some_and(|i| ids.contains(i)))
                    .map(|r| r.info.clone())
                    .collect(),
            )
        })?;
        let (page, next_token) = paginate(list, input.max_records, &input.next_token, 100)?;
        Ok(t::DescribeInstanceRefreshesAnswer { instance_refreshes: Some(page), next_token })
    }
}
