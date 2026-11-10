//! Deferred modifications and maintenance: changes made without
//! `ApplyImmediately` wait in `PendingModifiedValues` for the resource's
//! next `PreferredMaintenanceWindow` on the emulated clock (or for
//! `ApplyImmediately`, which applies them with the new change). Pending
//! engine upgrades are also listed as `db-upgrade` maintenance actions,
//! which `ApplyPendingMaintenanceAction` applies. Storage changes are
//! followed by `storage-optimization`, and Enhanced Monitoring roles are
//! checked here.

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, cluster_arn, db_arn};
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::util::{account_of, invalid_combination, invalid_parameter, next_window_start, paginate, Filters};
use crate::Rds;

/// How long storage optimization lasts after a storage change. AWS takes
/// "six hours or until optimization completes, whichever is longer"; MWS
/// takes the six hours.
pub(crate) const STORAGE_OPTIMIZATION: i64 = 6;

/// AWS's error for a storage change while the last one is optimized.
pub(crate) fn storage_being_optimized() -> ServiceError {
    invalid_combination(
        "You can't currently modify the storage of this DB instance because the previous storage change is being optimized.",
    )
}

/// Which pending changes to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Everything in `PendingModifiedValues` (a maintenance window or
    /// `ApplyImmediately`).
    All,
    /// Only the engine upgrade (`ApplyPendingMaintenanceAction db-upgrade`).
    EngineOnly,
}

/// Whether an instance has changes waiting for the maintenance window
/// (a pending password is applied at once and does not count).
pub(crate) fn instance_has_deferred(p: &t::PendingModifiedValues) -> bool {
    p.db_instance_class.is_some()
        || p.allocated_storage.is_some()
        || p.storage_type.is_some()
        || p.iops.is_some()
        || p.storage_throughput.is_some()
        || p.multi_az.is_some()
        || p.engine_version.is_some()
        || p.db_instance_identifier.is_some()
}

pub(crate) fn cluster_has_deferred(p: &t::ClusterPendingModifiedValues) -> bool {
    p.engine_version.is_some() || p.allocated_storage.is_some() || p.storage_type.is_some() || p.iops.is_some()
}

/// Statuses in which an instance is up and serving (RDS keeps it usable
/// during storage optimization).
pub(crate) fn operational(status: &str) -> bool {
    matches!(status, "available" | "storage-optimization")
}

fn upgrade_description(engine: &str, version: &str) -> String {
    let name = catalog::engine(engine)
        .and_then(|e| e.version(version))
        .map(|v| v.description.to_string())
        .unwrap_or_else(|| format!("{engine} {version}"));
    format!("Upgrade to {name}")
}

impl Rds {
    /// Check `MonitoringInterval` and `MonitoringRoleArn` the way RDS does:
    /// an interval other than 0 needs a role, the caller must be allowed to
    /// pass it, and `monitoring.rds.amazonaws.com` must be able to assume it.
    pub(crate) fn check_monitoring(
        &self,
        ctx: &RequestContext,
        interval: Option<i32>,
        role: Option<&str>,
        source_arn: &str,
    ) -> Result<(), ServiceError> {
        let interval = interval.unwrap_or(0);
        if ![0, 1, 5, 10, 15, 30, 60].contains(&interval) {
            return Err(invalid_parameter(format!(
                "Invalid MonitoringInterval {interval}. Valid values are 0, 1, 5, 10, 15, 30, 60."
            )));
        }
        if interval == 0 {
            return Ok(());
        }
        let Some(role) = role.filter(|r| !r.is_empty()) else {
            return Err(invalid_combination(
                "A MonitoringRoleARN value is required if you specify a MonitoringInterval value other than 0.",
            ));
        };
        ctx.authorize("iam:PassRole", role, ConditionContext::new())?;
        let usable = role.starts_with("arn:")
            && self
                .service_roles()
                .is_none_or(|roles| roles.can_assume(ctx, role, "monitoring.rds.amazonaws.com", source_arn));
        if usable {
            Ok(())
        } else {
            Err(invalid_parameter(
                "IAM role ARN value is invalid or does not include the required permissions for: ENHANCED_MONITORING",
            ))
        }
    }

    /// Apply an instance's pending changes now. Returns its identifier
    /// (which a pending rename changes).
    pub(crate) async fn apply_instance_changes(&self, ctx: &RequestContext, id: &str, scope: Scope) -> String {
        let now = ctx.received_at;
        let zones = crate::util::zones(&ctx.region);
        let applied = self.with_region(ctx, |r| {
            let rec = r.instances.get_mut(id)?;
            let mut p = rec.db.pending_modified_values.clone().unwrap_or_default();
            let (mut class, mut storage, mut version) = (false, false, false);
            let mut rename = None;
            if let Some(v) = p.engine_version.take() {
                if rec.db.engine_version.as_ref() != Some(&v) {
                    let target =
                        catalog::engine(rec.db.engine.as_deref().unwrap_or_default()).and_then(|e| e.version(&v));
                    if let Some(target) = target {
                        rec.image = target.image.to_string();
                    }
                    rec.db.engine_version = Some(v);
                    version = true;
                }
                rec.maintenance_opt_in = None;
            }
            if scope == Scope::All {
                if let Some(c) = p.db_instance_class.take() {
                    if rec.db.db_instance_class.as_ref() != Some(&c) {
                        rec.db.db_instance_class = Some(c);
                        class = true;
                    }
                }
                // A storage change is pending as a whole (type, size, IOPS
                // and throughput).
                if p.storage_type.is_some() || p.allocated_storage.is_some() {
                    if let Some(st) = p.storage_type.take() {
                        rec.db.storage_type = Some(st);
                    }
                    if let Some(a) = p.allocated_storage.take() {
                        rec.db.allocated_storage = Some(a);
                    }
                    rec.db.iops = p.iops.take();
                    rec.db.storage_throughput = p.storage_throughput.take();
                    storage = true;
                }
                if let Some(m) = p.multi_az.take() {
                    rec.db.multi_az = Some(m);
                    let az = rec.db.availability_zone.clone().unwrap_or_default();
                    rec.db.secondary_availability_zone = m.then(|| zones.iter().find(|z| **z != az).cloned()).flatten();
                }
                rename = p.db_instance_identifier.take();
            }
            if !instance_has_deferred(&p) {
                rec.pending_since = None;
                rec.maintenance_opt_in = None;
            }
            rec.db.pending_modified_values = Some(p);
            if storage {
                rec.storage_optimized_until = Some(now + Duration::hours(STORAGE_OPTIMIZATION));
            }
            let restart = class || version;
            if restart || storage {
                rec.generation += 1;
                rec.db.db_instance_status = Some(
                    if version {
                        "upgrading"
                    } else if class {
                        "modifying"
                    } else {
                        "storage-optimization"
                    }
                    .into(),
                );
            }
            Some((rec.generation, class, storage, restart, rename))
        });
        let Some((generation, class, storage, restart, rename)) = applied else { return id.to_string() };
        let mut id = id.to_string();
        if let Some(n) = rename.filter(|n| *n != id) {
            self.rename_instance(ctx, &id, &n);
            id = n;
        }
        let arn = db_arn(ctx, &id);
        if restart {
            self.restart_instance(ctx, &id, generation, ("DB instance restarted", "RDS-EVENT-0006")).await;
        }
        if class {
            self.emit(
                ctx,
                "db-instance",
                &id,
                &arn,
                &["configuration change"],
                "Finished applying modification to DB instance class",
                "RDS-EVENT-0014",
            );
        }
        if storage {
            self.emit(
                ctx,
                "db-instance",
                &id,
                &arn,
                &["configuration change"],
                "Finished applying modification to allocated storage",
                "RDS-EVENT-0017",
            );
        }
        id
    }

    /// Apply a cluster's pending changes now: its engine upgrade and, for
    /// Multi-AZ DB clusters, storage.
    pub(crate) async fn apply_cluster_changes(&self, ctx: &RequestContext, id: &str, scope: Scope) {
        let runs = self.backend().runs_databases();
        let applied = self.with_region(ctx, |r| {
            let rec = r.clusters.get_mut(id)?;
            let mut p = rec.cluster.pending_modified_values.clone().unwrap_or_default();
            let mut version = false;
            if let Some(v) = p.engine_version.take() {
                if rec.cluster.engine_version.as_ref() != Some(&v) {
                    let engine = catalog::engine(rec.cluster.engine.as_deref().unwrap_or_default());
                    let old = engine.and_then(|e| e.version(rec.cluster.engine_version.as_deref().unwrap_or_default()));
                    let new = engine.and_then(|e| e.version(&v));
                    // A minor upgrade swaps the image; a major one keeps
                    // the data's server.
                    if let (Some(old), Some(new)) = (old, new) {
                        if runs && old.major == new.major {
                            rec.image = new.image.to_string();
                        }
                    }
                    rec.cluster.engine_version = Some(v);
                    version = true;
                }
                rec.maintenance_opt_in = None;
            }
            if scope == Scope::All {
                if let Some(st) = p.storage_type.take() {
                    rec.cluster.storage_type = Some(st);
                }
                if let Some(a) = p.allocated_storage.take() {
                    rec.cluster.allocated_storage = Some(a);
                }
                if let Some(i) = p.iops.take() {
                    rec.cluster.iops = Some(i);
                }
            }
            if !cluster_has_deferred(&p) {
                rec.pending_since = None;
                rec.maintenance_opt_in = None;
            }
            rec.cluster.pending_modified_values = Some(p);
            if version {
                rec.generation += 1;
                rec.cluster.status = Some("upgrading".into());
                let version = rec.cluster.engine_version.clone();
                for m in rec.cluster.db_cluster_members.iter().flatten() {
                    if let Some(i) = r.instances.get_mut(m.db_instance_identifier.as_deref().unwrap_or_default()) {
                        i.db.engine_version = version.clone();
                    }
                }
            }
            Some((rec.generation, version))
        });
        if let Some((generation, true)) = applied {
            self.restart_cluster(ctx, id, generation, ("Database cluster engine version upgraded", "RDS-EVENT-0172"))
                .await;
        }
    }

    /// Run what is due on the emulated clock: pending changes whose
    /// maintenance window has come, and storage optimizations that ended.
    pub(crate) async fn run_maintenance(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let due = |since: Option<DateTime<Utc>>, window: &Option<String>| {
            since.zip(window.as_deref()).and_then(|(s, w)| next_window_start(w, s)).is_some_and(|at| at <= now)
        };
        let (instances, clusters, optimized) = self.with_region(ctx, |r| {
            let instances: Vec<String> = r
                .instances
                .values()
                .filter(|i| operational(i.db.db_instance_status.as_deref().unwrap_or_default()))
                .filter(|i| i.db.pending_modified_values.as_ref().is_some_and(instance_has_deferred))
                .filter(|i| due(i.pending_since, &i.db.preferred_maintenance_window))
                .filter_map(|i| i.db.db_instance_identifier.clone())
                .collect();
            let clusters: Vec<String> = r
                .clusters
                .values()
                .filter(|c| c.cluster.status.as_deref() == Some("available"))
                .filter(|c| c.cluster.pending_modified_values.as_ref().is_some_and(cluster_has_deferred))
                .filter(|c| due(c.pending_since, &c.cluster.preferred_maintenance_window))
                .filter_map(|c| c.cluster.db_cluster_identifier.clone())
                .collect();
            let optimized: Vec<(String, u64)> = r
                .instances
                .values()
                .filter(|i| i.db.db_instance_status.as_deref() == Some("storage-optimization"))
                .filter(|i| i.storage_optimized_until.is_none_or(|u| u <= now))
                .filter_map(|i| i.db.db_instance_identifier.clone().map(|id| (id, i.generation)))
                .collect();
            (instances, clusters, optimized)
        });
        for (id, generation) in optimized {
            self.set_instance_status(ctx, &id, generation, "available", None);
        }
        for id in instances {
            self.apply_instance_changes(ctx, &id, Scope::All).await;
        }
        for id in clusters {
            self.apply_cluster_changes(ctx, &id, Scope::All).await;
        }
    }

    /// The maintenance actions pending on each instance and cluster: the
    /// engine upgrades waiting for the maintenance window (`db-upgrade`).
    fn pending_actions(&self, ctx: &RequestContext) -> Vec<(String, String, t::PendingMaintenanceAction)> {
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for i in r.instances.values() {
                let Some(v) = i.db.pending_modified_values.as_ref().and_then(|p| p.engine_version.clone()) else {
                    continue;
                };
                let id = i.db.db_instance_identifier.clone().unwrap_or_default();
                let window = i.db.preferred_maintenance_window.clone().unwrap_or_default();
                out.push((
                    "db".to_string(),
                    id,
                    t::PendingMaintenanceAction {
                        action: Some("db-upgrade".into()),
                        description: Some(upgrade_description(i.db.engine.as_deref().unwrap_or_default(), &v)),
                        current_apply_date: next_window_start(&window, i.pending_since.unwrap_or(now).max(now)),
                        opt_in_status: i.maintenance_opt_in.clone(),
                        ..Default::default()
                    },
                ));
            }
            for c in r.clusters.values() {
                let Some(v) = c.cluster.pending_modified_values.as_ref().and_then(|p| p.engine_version.clone()) else {
                    continue;
                };
                let id = c.cluster.db_cluster_identifier.clone().unwrap_or_default();
                let window = c.cluster.preferred_maintenance_window.clone().unwrap_or_default();
                out.push((
                    "cluster".to_string(),
                    id,
                    t::PendingMaintenanceAction {
                        action: Some("db-upgrade".into()),
                        description: Some(upgrade_description(c.cluster.engine.as_deref().unwrap_or_default(), &v)),
                        current_apply_date: next_window_start(&window, c.pending_since.unwrap_or(now).max(now)),
                        opt_in_status: c.maintenance_opt_in.clone(),
                        ..Default::default()
                    },
                ));
            }
            out
        })
    }

    pub(crate) fn describe_pending_maintenance_actions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribePendingMaintenanceActionsMessage,
    ) -> Result<t::PendingMaintenanceActionsMessage, ServiceError> {
        authorize(ctx, "DescribePendingMaintenanceActions", "*", ConditionContext::new())?;
        let f = Filters::new(&input.filters, &["db-cluster-id", "db-instance-id"])?;
        if let Some(r) = &input.resource_identifier {
            self.resource_exists(ctx, r)?;
        }
        let mut by_resource: Vec<t::ResourcePendingMaintenanceActions> = Vec::new();
        for (kind, id, action) in self.pending_actions(ctx) {
            let arn = if kind == "db" { db_arn(ctx, &id) } else { cluster_arn(ctx, &id) };
            if input.resource_identifier.as_ref().is_some_and(|w| *w != arn) {
                continue;
            }
            let matches = f.matches(|name| match (name, kind.as_str()) {
                ("db-instance-id", "db") | ("db-cluster-id", "cluster") => vec![id.clone(), arn.clone()],
                _ => Vec::new(),
            });
            if !matches {
                continue;
            }
            match by_resource.iter_mut().find(|r| r.resource_identifier.as_deref() == Some(&arn)) {
                Some(r) => r.pending_maintenance_action_details.get_or_insert_with(Vec::new).push(action),
                None => by_resource.push(t::ResourcePendingMaintenanceActions {
                    resource_identifier: Some(arn),
                    pending_maintenance_action_details: Some(vec![action]),
                }),
            }
        }
        let (page, marker) = paginate(by_resource, &input.marker, input.max_records)?;
        Ok(t::PendingMaintenanceActionsMessage { pending_maintenance_actions: Some(page), marker })
    }

    pub(crate) async fn apply_pending_maintenance_action_op(
        &self,
        ctx: &RequestContext,
        input: t::ApplyPendingMaintenanceActionMessage,
    ) -> Result<t::ApplyPendingMaintenanceActionResult, ServiceError> {
        authorize(ctx, "ApplyPendingMaintenanceAction", &input.resource_identifier, ConditionContext::new())?;
        self.resource_exists(ctx, &input.resource_identifier)?;
        let opt_in = input.opt_in_type.as_str();
        if !["immediate", "next-maintenance", "undo-opt-in"].contains(&opt_in) {
            return Err(invalid_parameter(format!("Invalid opt-in type: {}", input.opt_in_type)));
        }
        let arn = input.resource_identifier.clone();
        let (_, _, kind, name) = crate::util::parse_arn(&arn).unwrap_or_default();
        let pending = self
            .pending_actions(ctx)
            .into_iter()
            .find(|(k, id, a)| *k == kind && *id == name && a.action.as_deref() == Some(input.apply_action.as_str()));
        let Some((_, id, mut action)) = pending else {
            return Err(invalid_parameter(format!(
                "No pending maintenance action {} for resource {}.",
                input.apply_action, input.resource_identifier
            )));
        };
        if opt_in == "immediate" {
            if kind == "db" {
                let st = self.instance(ctx, &id)?.db.db_instance_status.unwrap_or_default();
                if !operational(&st) {
                    return Err(super::invalid_instance_state(&id, &st));
                }
            } else {
                let st = self.cluster(ctx, &id)?.cluster.status.unwrap_or_default();
                if st != "available" {
                    return Err(super::invalid_cluster_state(&id, &st));
                }
            }
        }
        let status = match opt_in {
            "undo-opt-in" => None,
            other => Some(other.to_string()),
        };
        if opt_in == "immediate" {
            action.current_apply_date = Some(ctx.received_at);
        }
        action.opt_in_status = status.clone();
        self.with_region(ctx, |r| {
            if kind == "db" {
                if let Some(i) = r.instances.get_mut(&id) {
                    i.maintenance_opt_in = status.clone();
                }
            } else if let Some(c) = r.clusters.get_mut(&id) {
                c.maintenance_opt_in = status.clone();
            }
        });
        if opt_in == "immediate" {
            if kind == "db" {
                self.apply_instance_changes(ctx, &id, Scope::EngineOnly).await;
            } else {
                self.apply_cluster_changes(ctx, &id, Scope::EngineOnly).await;
            }
        }
        Ok(t::ApplyPendingMaintenanceActionResult {
            resource_pending_maintenance_actions: Some(t::ResourcePendingMaintenanceActions {
                resource_identifier: Some(arn),
                pending_maintenance_action_details: Some(vec![action]),
            }),
        })
    }

    pub(crate) fn resource_exists(&self, ctx: &RequestContext, arn: &str) -> Result<(), ServiceError> {
        let Some((_, account, kind, name)) = crate::util::parse_arn(arn) else {
            return Err(errors::resource_not_found_fault(format!("The resource {arn} could not be found.")));
        };
        let found = account == account_of(ctx)
            && self.with_region(ctx, |r| match kind.as_str() {
                "db" => r.instances.contains_key(&name),
                "cluster" => r.clusters.contains_key(&name),
                _ => false,
            });
        if found {
            Ok(())
        } else {
            Err(errors::resource_not_found_fault(format!("The resource {arn} could not be found.")))
        }
    }
}
