//! Point-in-time recovery and the backup schedule.
//!
//! With a backend that runs databases, a point-in-time restore is real: the
//! newest backup taken before the restore time is copied and rolled
//! forward with the source's transaction log (PostgreSQL's archived WAL,
//! MySQL's binary log) up to that time. Automated backups follow the
//! emulated clock: one a day per database while its retention period is
//! above zero, kept for the retention period.
//!
//! Restore times are on the emulated clock and the databases' log is
//! stamped by the wall clock, so RDS remembers how far apart the two were
//! over time.

use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;

use crate::backend::{DatabaseSpec, LogSource};
use crate::Rds;

/// How to build a restore's data: roll one of `bases` (backend snapshots,
/// newest first) forward with `log` up to `until` (wall clock).
#[derive(Debug, Clone)]
pub(crate) struct Recovery {
    pub spec: DatabaseSpec,
    pub bases: Vec<String>,
    pub log: LogSource,
    pub until: DateTime<Utc>,
}

/// Backups in progress (by resource id), so a burst of requests starts
/// each day's backup once.
#[derive(Default)]
pub(crate) struct Schedule {
    running: HashSet<String>,
}

impl Rds {
    /// The wall-clock time at which the emulated clock read `emulated`.
    pub(crate) fn wall_time(&self, emulated: DateTime<Utc>) -> DateTime<Utc> {
        let history = self.inner.clock_history.lock().expect("clock lock");
        let offset = history
            .iter()
            .rev()
            .find(|(at, _)| *at <= emulated)
            .or(history.first())
            .map(|(_, o)| *o)
            .unwrap_or_else(Duration::zero);
        emulated - offset
    }

    /// The backend snapshots a recovery of database `resource` to `until`
    /// (wall clock) may start from: its snapshots with data taken before
    /// then, newest first.
    pub(crate) fn recovery_bases(
        &self,
        ctx: &RequestContext,
        resource: &str,
        cluster: bool,
        until: DateTime<Utc>,
    ) -> Vec<String> {
        let mut bases: Vec<(DateTime<Utc>, String)> = self.with_region(ctx, |r| {
            if cluster {
                r.cluster_snapshots
                    .values()
                    .filter(|s| s.has_data && s.snapshot.db_cluster_resource_id.as_deref() == Some(resource))
                    .filter_map(|s| s.data_time.filter(|t| *t <= until).map(|t| (t, s.backend_name.clone())))
                    .collect()
            } else {
                r.snapshots
                    .values()
                    .filter(|s| s.has_data && s.snapshot.dbi_resource_id.as_deref() == Some(resource))
                    .filter_map(|s| s.data_time.filter(|t| *t <= until).map(|t| (t, s.backend_name.clone())))
                    .collect()
            }
        });
        bases.sort();
        bases.dedup_by(|a, b| a.1 == b.1);
        bases.into_iter().rev().map(|(_, b)| b).collect()
    }

    /// The earliest time a database can be restored to: its oldest
    /// automated backup (or its creation, before the first one).
    pub(crate) fn earliest_restorable(
        &self,
        ctx: &RequestContext,
        resource: &str,
        cluster: bool,
        created: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        let oldest = self.with_region(ctx, |r| {
            if cluster {
                r.cluster_snapshots
                    .values()
                    .filter(|s| {
                        s.snapshot.snapshot_type.as_deref() == Some("automated")
                            && s.snapshot.db_cluster_resource_id.as_deref() == Some(resource)
                    })
                    .filter_map(|s| s.snapshot.snapshot_create_time)
                    .min()
            } else {
                r.snapshots
                    .values()
                    .filter(|s| {
                        s.snapshot.snapshot_type.as_deref() == Some("automated")
                            && s.snapshot.dbi_resource_id.as_deref() == Some(resource)
                    })
                    .filter_map(|s| s.snapshot.snapshot_create_time)
                    .min()
            }
        });
        oldest.or(created)
    }

    /// Build backend snapshot `target` for a recovery, trying older bases
    /// when a newer one cannot be rolled forward.
    pub(crate) async fn recover_into(&self, recovery: &Recovery, target: &str) -> Result<(), String> {
        let mut last = "no backup holds data from before the restore time".to_string();
        for base in &recovery.bases {
            match self.backend().recover(&recovery.spec, base, &recovery.log, target, recovery.until).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(base = %base, "point-in-time recovery failed: {e}");
                    last = e.0;
                }
            }
        }
        Err(last)
    }

    /// Housekeeping on the emulated clock, run with each request for the
    /// caller's account and Region: take the day's automated backups and
    /// drop the ones past their retention period.
    pub(crate) async fn tick(&self, ctx: &RequestContext) {
        self.ensure_proxy_listeners(ctx).await;
        self.run_maintenance(ctx).await;
        let now = ctx.received_at;
        let day = Duration::hours(24);
        let (due_instances, due_clusters, expired) = self.with_region(ctx, |r| {
            let last_instance = |resource: &str| {
                r.snapshots
                    .values()
                    .filter(|s| {
                        s.snapshot.snapshot_type.as_deref() == Some("automated")
                            && s.snapshot.dbi_resource_id.as_deref() == Some(resource)
                    })
                    .filter_map(|s| s.snapshot.snapshot_create_time)
                    .max()
            };
            let due_instances: Vec<(String, String)> = r
                .instances
                .values()
                .filter(|i| {
                    i.db.db_cluster_identifier.is_none()
                        && i.db.backup_retention_period.unwrap_or(0) > 0
                        && super::maintenance::operational(i.db.db_instance_status.as_deref().unwrap_or_default())
                        && i.db.read_replica_source_db_instance_identifier.is_none()
                })
                .filter_map(|i| {
                    let resource = i.db.dbi_resource_id.clone()?;
                    let last = last_instance(&resource).or(i.db.instance_create_time)?;
                    (now - last >= day).then(|| (i.db.db_instance_identifier.clone().unwrap_or_default(), resource))
                })
                .collect();
            let last_cluster = |resource: &str| {
                r.cluster_snapshots
                    .values()
                    .filter(|s| {
                        s.snapshot.snapshot_type.as_deref() == Some("automated")
                            && s.snapshot.db_cluster_resource_id.as_deref() == Some(resource)
                    })
                    .filter_map(|s| s.snapshot.snapshot_create_time)
                    .max()
            };
            let due_clusters: Vec<(String, String)> = r
                .clusters
                .values()
                .filter(|c| c.cluster.status.as_deref() == Some("available"))
                .filter_map(|c| {
                    let resource = c.cluster.db_cluster_resource_id.clone()?;
                    let last = last_cluster(&resource).or(c.cluster.cluster_create_time)?;
                    (now - last >= day).then(|| (c.cluster.db_cluster_identifier.clone().unwrap_or_default(), resource))
                })
                .collect();
            // Automated backups past their database's retention period.
            let retention = |resource: &str, cluster: bool| -> Option<i64> {
                if cluster {
                    r.clusters
                        .values()
                        .find(|c| c.cluster.db_cluster_resource_id.as_deref() == Some(resource))
                        .map(|c| c.cluster.backup_retention_period.unwrap_or(1) as i64)
                        .or_else(|| {
                            r.retained_cluster_backups
                                .get(resource)
                                .map(|b| b.backup_retention_period.unwrap_or(1) as i64)
                        })
                } else {
                    r.instances
                        .values()
                        .find(|i| i.db.dbi_resource_id.as_deref() == Some(resource))
                        .map(|i| i.db.backup_retention_period.unwrap_or(0) as i64)
                        .or_else(|| {
                            r.retained_backups.get(resource).map(|b| b.backup_retention_period.unwrap_or(0) as i64)
                        })
                }
            };
            let mut expired = Vec::new();
            let old: Vec<String> = r
                .snapshots
                .iter()
                .filter(|(_, s)| s.snapshot.snapshot_type.as_deref() == Some("automated"))
                .filter(|(_, s)| {
                    let resource = s.snapshot.dbi_resource_id.clone().unwrap_or_default();
                    match (retention(&resource, false), s.snapshot.snapshot_create_time) {
                        (Some(days), Some(at)) if days > 0 => now - at > Duration::days(days),
                        _ => false,
                    }
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in old {
                if let Some(s) = r.snapshots.remove(&k) {
                    if s.has_data {
                        expired.push(s.backend_name);
                    }
                }
            }
            let old: Vec<String> = r
                .cluster_snapshots
                .iter()
                .filter(|(_, s)| s.snapshot.snapshot_type.as_deref() == Some("automated"))
                .filter(|(_, s)| {
                    let resource = s.snapshot.db_cluster_resource_id.clone().unwrap_or_default();
                    match (retention(&resource, true), s.snapshot.snapshot_create_time) {
                        (Some(days), Some(at)) => now - at > Duration::days(days.max(1)),
                        _ => false,
                    }
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in old {
                if let Some(s) = r.cluster_snapshots.remove(&k) {
                    if s.has_data {
                        expired.push(s.backend_name);
                    }
                }
            }
            (due_instances, due_clusters, expired)
        });
        let mut jobs = Vec::new();
        {
            let mut schedule = self.inner.schedule.lock().expect("schedule lock");
            for (id, resource) in due_instances {
                if schedule.running.insert(resource.clone()) {
                    jobs.push((id, resource, false));
                }
            }
            for (id, resource) in due_clusters {
                if schedule.running.insert(resource.clone()) {
                    jobs.push((id, resource, true));
                }
            }
        }
        for (id, resource, cluster) in jobs {
            let this = self.clone();
            let ctx = ctx.clone();
            self.run_task(async move {
                if cluster {
                    this.automated_cluster_snapshot(&ctx, &id).await;
                } else {
                    this.automated_snapshot(&ctx, &id).await;
                }
                this.inner.schedule.lock().expect("schedule lock").running.remove(&resource);
            })
            .await;
        }
        if !expired.is_empty() {
            let backend = self.backend();
            tokio::spawn(async move {
                for s in expired {
                    let _ = backend.delete_snapshot(&s).await;
                }
            });
        }
    }
}
