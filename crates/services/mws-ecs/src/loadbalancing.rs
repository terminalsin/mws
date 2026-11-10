//! Service tasks in Elastic Load Balancing target groups: ECS registers a
//! service's tasks with the target groups in its `loadBalancers` once they
//! run (an `awsvpc` task by its private IP, others by their container
//! instance's EC2 instance and host port), deregisters them when they are
//! asked to stop, and replaces tasks that fail the target group's health
//! checks after the service's health check grace period.
//!
//! While a task is registered ECS follows its target health: a service
//! task behind a load balancer only counts as healthy (for
//! `minimumHealthyPercent`, steady state and the deployment's completion)
//! once its targets are `healthy`, and a task replaced for failing ELB
//! health checks counts as a failed launch for the circuit breaker.

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
    /// Registered running service tasks: (task, service, targets, past
    /// the service's health check grace period?).
    pub probes: Vec<(String, String, Vec<LbTarget>, bool)>,
}

/// Whether a service task counts as healthy as far as its load balancers
/// are concerned: it has none, or all its targets are `healthy`.
pub(crate) fn lb_healthy(r: &Region, rec: &TaskRecord) -> bool {
    if load_balancers(r, rec).iter().all(|lb| lb.target_group_arn.is_none()) {
        return true;
    }
    !rec.lb_targets.is_empty() && rec.lb_health.as_deref() == Some("healthy")
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
            let past_grace = started + Duration::seconds(grace as i64) <= now;
            plan.probes.push((arn.clone(), service, rec.lb_targets.clone(), past_grace));
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
        // With nothing running the tasks, health checks could only fail:
        // the targets count as healthy.
        let metadata_only = self.backend_name() == "metadata";
        let mut states: Vec<(String, String)> = Vec::new();
        let mut unhealthy = Vec::new();
        for (task, service, targets, past_grace) in plan.probes {
            let mut state = "healthy".to_string();
            for t in targets {
                if metadata_only {
                    break;
                }
                let s = platform.target_health(ctx, &t.target_group_arn, &t.id, t.port).await.unwrap_or_default();
                if s == "unhealthy" && past_grace {
                    unhealthy.push((task.clone(), service.clone(), t));
                    state = s;
                    break;
                }
                if s != "healthy" {
                    state = s;
                }
            }
            states.push((task, state));
        }
        {
            let mut st = self.lock();
            if let Some(r) = st.regions.get_mut(key) {
                for (task, state) in states {
                    if let Some(rec) = r.tasks.get_mut(&task) {
                        rec.lb_ever_healthy |= state == "healthy";
                        rec.lb_health = Some(state);
                    }
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
            // A task that never passed its ELB health checks failed to
            // launch, for the deployment circuit breaker.
            if let Some(rec) = r.tasks.get_mut(&task) {
                rec.failed_elb_checks = !rec.lb_ever_healthy;
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

/// Why a service's `loadBalancers` cannot be used, as ECS words it.
fn load_balancer_problem(
    lb: &t::LoadBalancer,
    group: Option<&crate::platform::TargetGroupInfo>,
    def: Option<&t::TaskDefinition>,
) -> Option<String> {
    let arn = lb.target_group_arn.as_deref()?;
    let Some(group) = group else {
        return Some(
            "Unable to assume role and validate the specified targetGroupArn. Please verify that the ECS service role being passed has the proper permissions."
                .into(),
        );
    };
    if group.load_balancer_arns.is_empty() {
        return Some(format!("The target group with targetGroupArn {arn} does not have an associated load balancer."));
    }
    let def = def?;
    let mode = def.network_mode.clone().unwrap_or_else(|| "bridge".into());
    let compatible = match mode.as_str() {
        "awsvpc" => group.target_type == "ip",
        _ => group.target_type == "instance",
    };
    if !compatible {
        return Some(format!(
            "The provided target group {arn} has target type {}, which is incompatible with the {mode} network mode specified in the task definition.",
            group.target_type
        ));
    }
    let name = lb.container_name.as_deref().unwrap_or_default();
    let Some(container) = def.container_definitions.iter().flatten().find(|c| c.name.as_deref() == Some(name)) else {
        return Some(format!("The container {name} does not exist in the task definition."));
    };
    let port = lb.container_port.unwrap_or_default();
    if !container.port_mappings.iter().flatten().any(|m| m.container_port == Some(port)) {
        return Some(format!("The container {name} did not have a container port {port} defined."));
    }
    None
}

impl Ecs {
    /// Check a service's `loadBalancers` against Elastic Load Balancing
    /// and the task definition, as `CreateService` and `UpdateService` do.
    pub(crate) async fn check_load_balancers(
        &self,
        ctx: &RequestContext,
        def: Option<&t::TaskDefinition>,
        lbs: &[t::LoadBalancer],
    ) -> Result<(), mws_core::ServiceError> {
        let Some(platform) = self.platform() else { return Ok(()) };
        for lb in lbs {
            let Some(arn) = lb.target_group_arn.as_deref() else { continue };
            let group = platform.target_group(ctx, arn).await;
            if let Some(problem) = load_balancer_problem(lb, group.as_ref(), def) {
                return Err(crate::names::invalid(problem));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TargetGroupInfo;

    fn def(mode: &str, port: i32) -> t::TaskDefinition {
        t::TaskDefinition {
            network_mode: Some(mode.into()),
            container_definitions: Some(vec![t::ContainerDefinition {
                name: Some("web".into()),
                port_mappings: Some(vec![t::PortMapping { container_port: Some(port), ..Default::default() }]),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    fn lb(name: &str, port: i32) -> t::LoadBalancer {
        t::LoadBalancer {
            target_group_arn: Some("arn:tg".into()),
            container_name: Some(name.into()),
            container_port: Some(port),
            ..Default::default()
        }
    }

    fn group(target_type: &str, with_lb: bool) -> TargetGroupInfo {
        TargetGroupInfo {
            target_group_arn: "arn:tg".into(),
            target_type: target_type.into(),
            load_balancer_arns: if with_lb { vec!["arn:lb".into()] } else { Vec::new() },
        }
    }

    #[test]
    fn load_balancers_are_checked_as_ecs_does() {
        let d = def("awsvpc", 80);
        assert_eq!(load_balancer_problem(&lb("web", 80), Some(&group("ip", true)), Some(&d)), None);
        assert!(load_balancer_problem(&lb("web", 80), None, Some(&d)).unwrap().starts_with("Unable to assume role"));
        assert_eq!(
            load_balancer_problem(&lb("web", 80), Some(&group("ip", false)), Some(&d)).unwrap(),
            "The target group with targetGroupArn arn:tg does not have an associated load balancer."
        );
        assert_eq!(
            load_balancer_problem(&lb("web", 80), Some(&group("instance", true)), Some(&d)).unwrap(),
            "The provided target group arn:tg has target type instance, which is incompatible with the awsvpc network mode specified in the task definition."
        );
        assert_eq!(
            load_balancer_problem(&lb("api", 80), Some(&group("ip", true)), Some(&d)).unwrap(),
            "The container api does not exist in the task definition."
        );
        assert_eq!(
            load_balancer_problem(&lb("web", 8080), Some(&group("ip", true)), Some(&d)).unwrap(),
            "The container web did not have a container port 8080 defined."
        );
        let bridge = def("bridge", 80);
        assert_eq!(load_balancer_problem(&lb("web", 80), Some(&group("instance", true)), Some(&bridge)), None);
        assert!(load_balancer_problem(&lb("web", 80), Some(&group("ip", true)), Some(&bridge)).is_some());
    }

    #[test]
    fn tasks_behind_a_load_balancer_count_once_their_targets_are_healthy() {
        let mut r = Region::default();
        let svc = crate::state::ServiceRecord {
            service: t::Service { load_balancers: Some(vec![lb("web", 80)]), ..Default::default() },
            ..Default::default()
        };
        r.services.insert("svc".into(), svc);
        let mut task = TaskRecord { service_arn: Some("svc".into()), ..Default::default() };
        assert!(!lb_healthy(&r, &task), "not registered yet");
        task.lb_targets = vec![LbTarget { target_group_arn: "arn:tg".into(), id: "10.0.0.1".into(), port: 80 }];
        task.lb_health = Some("initial".into());
        assert!(!lb_healthy(&r, &task));
        task.lb_health = Some("healthy".into());
        assert!(lb_healthy(&r, &task));
        let plain = TaskRecord::default();
        assert!(lb_healthy(&r, &plain), "tasks without load balancers");
    }
}
