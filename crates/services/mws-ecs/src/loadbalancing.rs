//! Service tasks in Elastic Load Balancing target groups: ECS registers a
//! service's tasks with the target groups in its `loadBalancers` once they
//! run (an `awsvpc` task by its private IP, others by their container
//! instance's EC2 instance and host port), deregisters them when they are
//! asked to stop, and replaces tasks that fail the target group's health
//! checks after the service's health check grace period.

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;

use crate::generated::types as t;
use crate::services::push_event;
use crate::state::{LbTarget, Region, TaskRecord};
use crate::Ecs;

/// Load balancer work for one account and Region, planned under the state
/// lock and carried out without it.
#[derive(Debug, Default)]
pub(crate) struct LbPlan {
    /// (targets, register?)
    pub changes: Vec<(Vec<LbTarget>, bool)>,
    /// Running service tasks past their grace period: (task, service, targets).
    pub probes: Vec<(String, String, Vec<LbTarget>)>,
}

/// The load balancers a service task belongs to: its task set's, or the
/// service's.
fn load_balancers(r: &Region, rec: &TaskRecord) -> Vec<t::LoadBalancer> {
    let Some(svc) = rec.service_arn.as_ref().and_then(|a| r.services.get(a)) else { return Vec::new() };
    if let Some(ts) = svc.service.task_sets.iter().flatten().find(|ts| ts.id.is_some() && ts.id == rec.deployment_id) {
        return ts.load_balancers.clone().unwrap_or_default();
    }
    svc.service.load_balancers.clone().unwrap_or_default()
}

fn targets_of(r: &Region, rec: &TaskRecord) -> Vec<LbTarget> {
    let ip = rec
        .task
        .attachments
        .iter()
        .flatten()
        .flat_map(|a| a.details.iter().flatten())
        .find(|d| d.name.as_deref() == Some("privateIPv4Address"))
        .and_then(|d| d.value.clone())
        .or_else(|| rec.vpc.as_ref().map(|v| v.2.clone()));
    let instance = rec
        .task
        .container_instance_arn
        .as_ref()
        .and_then(|a| r.container_instances.get(a))
        .and_then(|i| i.instance.ec2_instance_id.clone());
    let mut out = Vec::new();
    for lb in load_balancers(r, rec) {
        let (Some(tg), Some(port)) = (lb.target_group_arn.clone(), lb.container_port) else { continue };
        if rec.eni_id.is_some() {
            if let Some(ip) = &ip {
                out.push(LbTarget { target_group_arn: tg, id: ip.clone(), port });
            }
            continue;
        }
        let host_port = rec
            .task
            .containers
            .iter()
            .flatten()
            .filter(|c| lb.container_name.is_none() || c.name == lb.container_name)
            .flat_map(|c| c.network_bindings.iter().flatten())
            .find(|b| b.container_port == Some(port))
            .and_then(|b| b.host_port)
            .unwrap_or(port);
        if let Some(id) = &instance {
            out.push(LbTarget { target_group_arn: tg, id: id.clone(), port: host_port });
        }
    }
    out
}

impl Ecs {
    /// Work out registrations, deregistrations and health probes.
    pub(crate) fn plan_load_balancing(r: &mut Region, now: DateTime<Utc>) -> LbPlan {
        let mut plan = LbPlan::default();
        let arns: Vec<String> =
            r.tasks.iter().filter(|(_, t)| t.service_arn.is_some()).map(|(a, _)| a.clone()).collect();
        for arn in arns {
            let rec = &r.tasks[&arn];
            let stopping = rec.task.desired_status.as_deref() == Some("STOPPED");
            if stopping {
                if !rec.lb_targets.is_empty() && !rec.lb_deregistered {
                    plan.changes.push((rec.lb_targets.clone(), false));
                    if let Some(rec) = r.tasks.get_mut(&arn) {
                        rec.lb_deregistered = true;
                    }
                }
                continue;
            }
            if rec.task.last_status.as_deref() != Some("RUNNING") {
                continue;
            }
            if rec.lb_targets.is_empty() {
                let targets = targets_of(r, rec);
                if targets.is_empty() {
                    continue;
                }
                plan.changes.push((targets.clone(), true));
                if let Some(rec) = r.tasks.get_mut(&arn) {
                    rec.lb_targets = targets;
                }
                continue;
            }
            let service = rec.service_arn.clone().unwrap_or_default();
            let grace = r.services.get(&service).and_then(|s| s.service.health_check_grace_period_seconds).unwrap_or(0);
            let started = rec.task.started_at.unwrap_or(now);
            if started + Duration::seconds(grace as i64) <= now {
                plan.probes.push((arn.clone(), service, rec.lb_targets.clone()));
            }
        }
        plan
    }

    /// Carry out `plan` for the account and Region of `ctx`, then replace
    /// tasks their target groups report unhealthy.
    pub(crate) async fn apply_load_balancing(&self, ctx: &RequestContext, key: &str, plan: LbPlan) {
        let Some(platform) = self.platform() else { return };
        for (targets, register) in plan.changes {
            let mut by_group: std::collections::BTreeMap<String, Vec<(String, i32)>> = Default::default();
            for t in targets {
                by_group.entry(t.target_group_arn).or_default().push((t.id, t.port));
            }
            for (tg, list) in by_group {
                if let Err(e) = platform.update_targets(ctx, &tg, &list, register).await {
                    tracing::warn!(target_group = %tg, "ECS target registration failed: {} {}", e.code, e.message);
                }
            }
        }
        // With nothing running the tasks, health checks could only fail.
        if self.backend_name() == "metadata" {
            return;
        }
        let mut unhealthy = Vec::new();
        for (task, service, targets) in plan.probes {
            for t in targets {
                if platform.target_health(ctx, &t.target_group_arn, &t.id, t.port).await.as_deref() == Some("unhealthy")
                {
                    unhealthy.push((task.clone(), service.clone(), t));
                    break;
                }
            }
        }
        if unhealthy.is_empty() {
            return;
        }
        let now = self.now();
        let mut st = self.lock();
        let Some(r) = st.regions.get_mut(key) else { return };
        for (task, service, t) in unhealthy {
            let reason = format!("Task failed ELB health checks in (target-group {})", t.target_group_arn);
            if !self.request_stop(r, &task, "ServiceSchedulerInitiated", &reason, now) {
                continue;
            }
            if let Some(rec) = r.services.get_mut(&service) {
                let name = rec.service.service_name.clone().unwrap_or_default();
                push_event(
                    &mut rec.service,
                    format!(
                        "(service {name}) (port {}) is unhealthy in (target-group {}) due to (reason Health checks failed).",
                        t.port, t.target_group_arn
                    ),
                    now,
                );
            }
        }
        drop(st);
        self.kick();
    }
}
