//! The service scheduler: keeps every service at its desired count,
//! rolls deployments forward within `minimumHealthyPercent` and
//! `maximumPercent`, trips the deployment circuit breaker, places one task
//! per container instance for DAEMON services, and reconciles task sets.

use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use mws_core::RequestContext;

use crate::generated::types as t;
use crate::names::Scope;
use crate::services::{breaker_threshold, push_event, revision_config};
use crate::state::Region;
use crate::tasks::{self, Launch, Placement};
use crate::{capacity, taskdefs, Ecs};

/// What a deployment or task set launches.
#[derive(Debug, Clone, Default)]
struct LaunchConfig {
    id: String,
    task_definition: String,
    launch_type: Option<String>,
    strategy: Vec<t::CapacityProviderStrategyItem>,
    network: Option<t::NetworkConfiguration>,
    platform_version: Option<String>,
}

#[derive(Debug, Clone)]
struct Live {
    arn: String,
    deployment: Option<String>,
    running: bool,
    unhealthy: bool,
    protected: bool,
    instance: Option<String>,
}

fn task_id(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

impl Ecs {
    /// Wake the scheduler now.
    pub(crate) fn kick(&self) {
        self.inner.kick.notify_one();
    }

    pub(crate) async fn scheduler_loop(&self) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(StdDuration::from_secs(1)) => {}
                _ = self.inner.kick.notified() => {}
            }
            self.reconcile_all();
        }
    }

    fn reconcile_all(&self) {
        let partition = match self.inner.template.lock().expect("ECS template lock poisoned").as_ref() {
            Some((ctx, _)) => ctx.partition.clone(),
            None => return,
        };
        let keys: Vec<String> = self.lock().regions.keys().cloned().collect();
        for key in keys {
            let Some((account, region)) = key.split_once('/') else { continue };
            let Some(ctx) = self.background_context(account, region) else { continue };
            let scope = Scope { partition: partition.clone(), region: region.to_string(), account: account.to_string() };
            let now = ctx.received_at;
            let mut st = self.lock();
            let Some(r) = st.regions.get_mut(&key) else { continue };
            tasks::expire(r, now);
            crate::services::settle(r, now);
            let arns: Vec<String> = r
                .services
                .iter()
                .filter(|(_, s)| matches!(s.service.status.as_deref(), Some("ACTIVE" | "DRAINING")))
                .map(|(a, _)| a.clone())
                .collect();
            for arn in arns {
                self.reconcile_service(&ctx, r, &scope, &arn, now);
            }
            crate::services::settle(r, now);
        }
    }

    fn live_tasks(r: &Region, service: &str) -> Vec<Live> {
        r.tasks
            .values()
            .filter(|t| t.service_arn.as_deref() == Some(service))
            .filter(|t| t.task.desired_status.as_deref() != Some("STOPPED"))
            .map(|t| Live {
                arn: t.task.task_arn.clone().unwrap_or_default(),
                deployment: t.deployment_id.clone(),
                running: t.task.last_status.as_deref() == Some("RUNNING"),
                unhealthy: t.task.health_status.as_deref() == Some("UNHEALTHY"),
                protected: t.protection.as_ref().is_some_and(|p| p.enabled),
                instance: t.task.container_instance_arn.clone(),
            })
            .collect()
    }

    fn stop_service_tasks(&self, r: &mut Region, service: &str, arns: &[String], reason: &str, now: DateTime<Utc>) {
        if arns.is_empty() {
            return;
        }
        for a in arns {
            self.request_stop(r, a, "ServiceSchedulerInitiated", reason, now);
        }
        if let Some(rec) = r.services.get_mut(service) {
            let name = rec.service.service_name.clone().unwrap_or_default();
            let list: Vec<String> = arns.iter().map(|a| format!("(task {})", task_id(a))).collect();
            push_event(
                &mut rec.service,
                format!("(service {name}) has stopped {} running tasks: {}.", arns.len(), list.join(" ")),
                now,
            );
        }
    }

    /// Start up to `n` tasks of a deployment; returns how many started.
    fn start_service_tasks(
        &self,
        ctx: &RequestContext,
        r: &mut Region,
        scope: &Scope,
        service: &str,
        config: &LaunchConfig,
        n: usize,
        on_instances: Option<Vec<String>>,
        now: DateTime<Utc>,
    ) -> usize {
        if n == 0 {
            return 0;
        }
        let Some(rec) = r.services.get(service).cloned() else { return 0 };
        let s = &rec.service;
        let name = s.service_name.clone().unwrap_or_default();
        let Some(def) = taskdefs::resolve(r, &config.task_definition).cloned() else {
            if let Some(rec) = r.services.get_mut(service) {
                push_event(&mut rec.service, format!("(service {name}) failed to launch a task: TaskDefinition not found."), now);
            }
            return 0;
        };
        let mut counts: Vec<usize> = config
            .strategy
            .iter()
            .map(|i| {
                r.tasks
                    .values()
                    .filter(|t| t.service_arn.as_deref() == Some(service))
                    .filter(|t| t.task.desired_status.as_deref() != Some("STOPPED"))
                    .filter(|t| t.task.capacity_provider_name.as_deref() == Some(i.capacity_provider.as_str()))
                    .count()
            })
            .collect();
        let mut started = Vec::new();
        let mut taken: Vec<String> = Vec::new();
        let mut problem: Option<String> = None;
        let mut instances = on_instances.into_iter().flatten();
        for _ in 0..n {
            let (lt, cp) = match &config.launch_type {
                Some(lt) => (lt.clone(), None),
                None if !config.strategy.is_empty() => {
                    let i = capacity::pick(&config.strategy, &counts);
                    counts[i] += 1;
                    let cp = capacity::provider_name(&config.strategy[i].capacity_provider);
                    (tasks::launch_type_of_provider(r, scope, &cp), Some(cp))
                }
                None => ("EC2".to_string(), None),
            };
            let mut placement = Placement { launch_type: lt.clone(), capacity_provider: cp.clone(), container_instance_arn: None };
            if lt != "FARGATE" {
                if let Some(ci) = instances.next() {
                    placement.container_instance_arn = Some(ci);
                } else {
                    let any = r.container_instances.values().any(|i| i.cluster == rec.cluster && i.instance.status.as_deref() == Some("ACTIVE"));
                    if !any {
                        problem = Some(format!(
                            "(service {name}) was unable to place a task because no container instance met all of its requirements. Reason: No Container Instances were found in your cluster. For more information, see the Troubleshooting section of the Amazon ECS Developer Guide."
                        ));
                        break;
                    }
                    match tasks::place_on_instance(
                        r,
                        &rec.cluster,
                        &def,
                        cp.as_deref(),
                        s.placement_constraints.as_deref().unwrap_or_default(),
                        s.placement_strategy.as_deref().unwrap_or_default(),
                        &taken,
                    ) {
                        Ok(ci) => {
                            taken.push(ci.clone());
                            placement.container_instance_arn = Some(ci);
                        }
                        Err(failures) => {
                            let detail = failures
                                .first()
                                .map(|f| {
                                    let what = match f.reason.as_deref() {
                                        Some("RESOURCE:CPU") => "has insufficient CPU units available",
                                        Some("RESOURCE:MEMORY") => "has insufficient memory available",
                                        Some("RESOURCE:PORTS") => "is already using a port required by your task",
                                        _ => "did not match a placement constraint",
                                    };
                                    format!(
                                        " The closest matching (container-instance {}) {what}.",
                                        f.arn.as_deref().map(task_id).unwrap_or_default()
                                    )
                                })
                                .unwrap_or_default();
                            problem = Some(format!(
                                "(service {name}) was unable to place a task because no container instance met all of its requirements.{detail} For more information, see the Troubleshooting section of the Amazon ECS Developer Guide."
                            ));
                            break;
                        }
                    }
                }
            }
            let mut tags = tasks::propagated_tags(r, &def, s.propagate_tags.as_deref(), None, Some(service));
            if s.enable_ecs_managed_tags {
                tags.push(t::Tag { key: Some("aws:ecs:serviceName".into()), value: Some(name.clone()) });
                tags.push(t::Tag { key: Some("aws:ecs:clusterName".into()), value: Some(rec.cluster.clone()) });
            }
            let launch = Launch {
                cluster: rec.cluster.clone(),
                definition: def.clone(),
                placement,
                network: config.network.clone(),
                overrides: None,
                group: Some(format!("service:{name}")),
                started_by: Some(config.id.clone()),
                tags,
                enable_execute_command: s.enable_execute_command,
                platform_version: config.platform_version.clone(),
                service_arn: Some(service.to_string()),
                deployment_id: Some(config.id.clone()),
            };
            match self.launch(ctx, r, scope, launch) {
                Ok(task) => started.push(task.task_arn.unwrap_or_default()),
                Err(e) => {
                    problem = Some(format!("(service {name}) failed to launch a task with ({}: {}).", e.code, e.message));
                    if let Some(rec) = r.services.get_mut(service) {
                        rec.failed_launches += 1;
                    }
                    break;
                }
            }
        }
        if let Some(rec) = r.services.get_mut(service) {
            if !started.is_empty() {
                let list: Vec<String> = started.iter().map(|a| format!("(task {})", task_id(a))).collect();
                push_event(
                    &mut rec.service,
                    format!("(service {name}) has started {} tasks: {}.", started.len(), list.join(" ")),
                    now,
                );
            }
            if let Some(p) = problem {
                push_event(&mut rec.service, p, now);
            }
        }
        started.len()
    }

    fn reconcile_service(&self, ctx: &RequestContext, r: &mut Region, scope: &Scope, arn: &str, now: DateTime<Utc>) {
        let Some(rec) = r.services.get(arn).cloned() else { return };
        let s = &rec.service;
        let name = s.service_name.clone().unwrap_or_default();
        let live = Self::live_tasks(r, arn);
        if s.status.as_deref() == Some("DRAINING") {
            let all: Vec<String> = live.iter().map(|l| l.arn.clone()).collect();
            self.stop_service_tasks(r, arn, &all, "Service is being deleted", now);
            return;
        }
        let controller = s.deployment_controller.as_ref().map(|c| c.r#type.clone()).unwrap_or_else(|| "ECS".into());
        if controller != "ECS" {
            self.reconcile_task_sets(ctx, r, scope, arn, now);
            return;
        }
        let Some(primary) = s.deployments.iter().flatten().find(|d| d.status.as_deref() == Some("PRIMARY")).cloned() else {
            return;
        };
        let primary_id = primary.id.clone().unwrap_or_default();
        // Count tasks of the primary deployment that failed to start.
        let mut new_failures = 0;
        for t in r.tasks.values_mut() {
            if t.service_arn.as_deref() == Some(arn)
                && t.deployment_id.as_deref() == Some(primary_id.as_str())
                && t.task.last_status.as_deref() == Some("STOPPED")
                && !t.reached_running
                && !t.failure_counted
            {
                t.failure_counted = true;
                new_failures += 1;
            }
        }
        if new_failures > 0 {
            if let Some(rec) = r.services.get_mut(arn) {
                rec.failed_launches += new_failures;
                for d in rec.service.deployments.iter_mut().flatten() {
                    if d.id.as_deref() == Some(primary_id.as_str()) {
                        d.failed_tasks += new_failures;
                    }
                }
            }
        }
        let rec = r.services.get(arn).cloned().expect("exists");
        let conf = rec.service.deployment_configuration.clone().unwrap_or_default();
        let breaker = conf.deployment_circuit_breaker.clone().unwrap_or_default();
        let daemon = rec.service.scheduling_strategy.as_deref() == Some("DAEMON");
        let rollout = primary.rollout_state.clone().unwrap_or_default();
        let sd_arn = rec.current_deployment_arn.clone();
        if let Some(sd) = sd_arn.as_ref().and_then(|a| r.service_deployments.get_mut(a)) {
            if let Some(cb) = sd.deployment_circuit_breaker.as_mut() {
                cb.failure_count = rec.failed_launches;
            }
        }

        // The circuit breaker.
        let threshold = breaker_threshold(rec.service.desired_count);
        if breaker.enable && rollout == "IN_PROGRESS" && rec.failed_launches >= threshold {
            let reason = "ECS deployment circuit breaker: tasks failed to start.".to_string();
            let previous = sd_arn
                .as_ref()
                .and_then(|a| r.service_deployments.get(a))
                .and_then(|sd| sd.source_service_revisions.as_ref())
                .and_then(|s| s.first())
                .and_then(|s| s.arn.clone())
                .and_then(|a| r.service_revisions.get(&a).cloned());
            if let Some(rec) = r.services.get_mut(arn) {
                for d in rec.service.deployments.iter_mut().flatten() {
                    if d.id.as_deref() == Some(primary_id.as_str()) {
                        d.rollout_state = Some("FAILED".into());
                        d.rollout_state_reason = Some(reason.clone());
                        d.updated_at = Some(now);
                    }
                }
                push_event(&mut rec.service, format!("(service {name}) (deployment {primary_id}) deployment failed: tasks failed to start."), now);
            }
            if let Some(sd) = sd_arn.as_ref().and_then(|a| r.service_deployments.get_mut(a)) {
                if let Some(cb) = sd.deployment_circuit_breaker.as_mut() {
                    cb.status = Some("TRIGGERED".into());
                }
            }
            match previous.filter(|_| breaker.rollback) {
                Some(rev) => {
                    if let Some(rec) = r.services.get_mut(arn) {
                        push_event(&mut rec.service, format!("(service {name}) rolling back to {}.", rev.task_definition.clone().unwrap_or_default()), now);
                    }
                    self.new_deployment(r, scope, arn, revision_config(&rev), now, Some(reason));
                }
                None => {
                    if let Some(sd) = sd_arn.as_ref().and_then(|a| r.service_deployments.get_mut(a)) {
                        sd.status = Some("STOPPED".into());
                        sd.status_reason = Some(reason);
                        sd.stopped_at = Some(now);
                        sd.updated_at = Some(now);
                    }
                }
            }
            return;
        }

        let config = LaunchConfig {
            id: primary_id.clone(),
            task_definition: primary.task_definition.clone().unwrap_or_default(),
            launch_type: primary.launch_type.clone(),
            strategy: primary.capacity_provider_strategy.clone().unwrap_or_default(),
            network: primary.network_configuration.clone(),
            platform_version: primary.platform_version.clone(),
        };
        let launching = rollout != "FAILED";

        // Replace unhealthy tasks.
        let unhealthy: Vec<String> = live.iter().filter(|l| l.unhealthy && !l.protected).map(|l| l.arn.clone()).collect();
        self.stop_service_tasks(r, arn, &unhealthy, "Task failed container health checks", now);
        let live: Vec<Live> = live.into_iter().filter(|l| !unhealthy.contains(&l.arn)).collect();
        let (prim, old): (Vec<&Live>, Vec<&Live>) = live.iter().partition(|l| l.deployment.as_deref() == Some(primary_id.as_str()));

        if daemon {
            let instances: Vec<String> = r
                .container_instances
                .iter()
                .filter(|(_, i)| i.cluster == rec.cluster && i.instance.status.as_deref() == Some("ACTIVE"))
                .map(|(a, _)| a.clone())
                .collect();
            let desired = instances.len() as i32;
            if let Some(rec) = r.services.get_mut(arn) {
                rec.service.desired_count = desired;
                for d in rec.service.deployments.iter_mut().flatten() {
                    if d.id.as_deref() == Some(primary_id.as_str()) {
                        d.desired_count = desired;
                    }
                }
            }
            let missing: Vec<String> = instances
                .iter()
                .filter(|i| !prim.iter().any(|l| l.instance.as_deref() == Some(i.as_str())))
                .cloned()
                .collect();
            if launching {
                self.start_service_tasks(ctx, r, scope, arn, &config, missing.len(), Some(missing), now);
            }
            // Old tasks go once the instance runs the new one; tasks on
            // instances that left go too.
            let stale: Vec<String> = old
                .iter()
                .filter(|l| prim.iter().any(|p| p.running && p.instance == l.instance) || !l.instance.as_ref().is_some_and(|i| instances.contains(i)))
                .map(|l| l.arn.clone())
                .collect();
            self.stop_service_tasks(r, arn, &stale, &format!("Scaling activity initiated by (deployment {primary_id})"), now);
        } else {
            let desired = rec.service.desired_count.max(0) as usize;
            let max_total = (desired as i64 * conf.maximum_percent.unwrap_or(200) as i64 / 100).max(desired as i64) as usize;
            let min_running = (desired as i64 * conf.minimum_healthy_percent.unwrap_or(100) as i64 + 99) / 100;
            let min_running = min_running as usize;
            // Scale in: pending tasks first, protected tasks never.
            if prim.len() > desired {
                let mut candidates: Vec<&&Live> = prim.iter().filter(|l| !l.protected).collect();
                candidates.sort_by_key(|l| l.running);
                let excess: Vec<String> = candidates.iter().take(prim.len() - desired).map(|l| l.arn.clone()).collect();
                self.stop_service_tasks(r, arn, &excess, &format!("Scaling activity initiated by (deployment {primary_id})"), now);
            }
            let total_live = prim.len().min(desired) + old.len();
            let need = desired.saturating_sub(prim.len());
            let room = max_total.saturating_sub(total_live);
            if launching {
                self.start_service_tasks(ctx, r, scope, arn, &config, need.min(room), None, now);
            }
            // Retire old deployments' tasks while enough keep running.
            let prim_running = prim.iter().filter(|l| l.running).count();
            let old_running = old.iter().filter(|l| l.running).count();
            let mut stoppable = (prim_running + old_running).saturating_sub(min_running);
            let mut retire: Vec<String> = old.iter().filter(|l| !l.running).map(|l| l.arn.clone()).collect();
            for l in old.iter().filter(|l| l.running && !l.protected) {
                if stoppable == 0 {
                    break;
                }
                retire.push(l.arn.clone());
                stoppable -= 1;
            }
            self.stop_service_tasks(r, arn, &retire, &format!("Scaling activity initiated by (deployment {primary_id})"), now);
        }

        // Old deployments without tasks are done.
        let live_after = Self::live_tasks(r, arn);
        let Some(rec) = r.services.get_mut(arn) else { return };
        if let Some(deps) = rec.service.deployments.as_mut() {
            deps.retain(|d| {
                d.status.as_deref() == Some("PRIMARY") || live_after.iter().any(|l| l.deployment.as_deref() == d.id.as_deref())
            });
        }
        let prim_running = live_after.iter().filter(|l| l.deployment.as_deref() == Some(primary_id.as_str()) && l.running).count();
        let prim_live = live_after.iter().filter(|l| l.deployment.as_deref() == Some(primary_id.as_str())).count();
        let only_primary = rec.service.deployments.iter().flatten().count() == 1;
        let desired = rec.service.desired_count.max(0) as usize;
        let steady = only_primary && prim_running == desired && prim_live == desired;
        if steady && rollout == "IN_PROGRESS" {
            for d in rec.service.deployments.iter_mut().flatten() {
                d.rollout_state = Some("COMPLETED".into());
                d.rollout_state_reason = Some(format!("ECS deployment {primary_id} completed."));
                d.updated_at = Some(now);
            }
            push_event(&mut rec.service, format!("(service {name}) (deployment {primary_id}) deployment completed."), now);
            push_event(&mut rec.service, format!("(service {name}) has reached a steady state."), now);
            if let Some(sd) = sd_arn.as_ref().and_then(|a| r.service_deployments.get_mut(a)) {
                sd.status = Some(match sd.status.as_deref() {
                    Some("ROLLBACK_IN_PROGRESS") => "ROLLBACK_SUCCESSFUL",
                    _ => "SUCCESSFUL",
                }
                .into());
                sd.finished_at = Some(now);
                sd.updated_at = Some(now);
                sd.lifecycle_stage = Some("CLEAN_UP".into());
                if let Some(cb) = sd.deployment_circuit_breaker.as_mut() {
                    if cb.status.as_deref() == Some("MONITORING") {
                        cb.status = Some("MONITORING_COMPLETE".into());
                    }
                }
                if let Some(target) = sd.target_service_revision.as_mut() {
                    target.running_task_count = prim_running as i32;
                    target.requested_task_count = desired as i32;
                }
            }
        } else if steady && rollout == "COMPLETED" {
            push_event(&mut rec.service, format!("(service {name}) has reached a steady state."), now);
        } else if let Some(sd) = sd_arn.as_ref().and_then(|a| r.service_deployments.get_mut(a)) {
            if let Some(target) = sd.target_service_revision.as_mut() {
                target.running_task_count = prim_running as i32;
                target.pending_task_count = (prim_live - prim_running) as i32;
                target.requested_task_count = desired as i32;
            }
            if matches!(sd.status.as_deref(), Some("IN_PROGRESS")) {
                sd.lifecycle_stage = Some(if prim_running < desired { "SCALE_UP" } else { "CLEAN_UP" }.into());
            }
        }
    }

    fn reconcile_task_sets(&self, ctx: &RequestContext, r: &mut Region, scope: &Scope, arn: &str, now: DateTime<Utc>) {
        let Some(rec) = r.services.get(arn).cloned() else { return };
        let desired = rec.service.desired_count;
        let live = Self::live_tasks(r, arn);
        for ts in rec.service.task_sets.iter().flatten() {
            let id = ts.id.clone().unwrap_or_default();
            let target = if ts.status.as_deref() == Some("DRAINING") {
                0
            } else {
                (desired as f64 * ts.scale.as_ref().map(|s| s.value).unwrap_or(100.0) / 100.0).ceil() as usize
            };
            let mine: Vec<&Live> = live.iter().filter(|l| l.deployment.as_deref() == Some(id.as_str())).collect();
            if mine.len() < target {
                let config = LaunchConfig {
                    id: id.clone(),
                    task_definition: ts.task_definition.clone().unwrap_or_default(),
                    launch_type: ts.launch_type.clone(),
                    strategy: ts.capacity_provider_strategy.clone().unwrap_or_default(),
                    network: ts.network_configuration.clone(),
                    platform_version: ts.platform_version.clone(),
                };
                self.start_service_tasks(ctx, r, scope, arn, &config, target - mine.len(), None, now);
            } else if mine.len() > target {
                let mut c: Vec<&&Live> = mine.iter().filter(|l| !l.protected).collect();
                c.sort_by_key(|l| l.running);
                let excess: Vec<String> = c.iter().take(mine.len() - target).map(|l| l.arn.clone()).collect();
                self.stop_service_tasks(r, arn, &excess, &format!("Scaling activity initiated by (deployment {id})"), now);
            }
        }
        let live = Self::live_tasks(r, arn);
        let Some(rec) = r.services.get_mut(arn) else { return };
        if let Some(sets) = rec.service.task_sets.as_mut() {
            sets.retain(|ts| {
                ts.status.as_deref() != Some("DRAINING") || live.iter().any(|l| l.deployment.as_deref() == ts.id.as_deref())
            });
            for ts in sets.iter_mut() {
                let id = ts.id.clone().unwrap_or_default();
                ts.computed_desired_count = if ts.status.as_deref() == Some("DRAINING") {
                    0
                } else {
                    (desired as f64 * ts.scale.as_ref().map(|s| s.value).unwrap_or(100.0) / 100.0).ceil() as i32
                };
                let running = live.iter().filter(|l| l.deployment.as_deref() == Some(id.as_str()) && l.running).count() as i32;
                let total = live.iter().filter(|l| l.deployment.as_deref() == Some(id.as_str())).count() as i32;
                let stable = running == ts.computed_desired_count && total == running;
                let status = if stable { "STEADY_STATE" } else { "STABILIZING" };
                if ts.stability_status.as_deref() != Some(status) {
                    ts.stability_status = Some(status.into());
                    ts.stability_status_at = Some(now);
                }
            }
        }
    }
}
