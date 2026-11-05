//! Aurora MySQL backtracking: rewinding a cluster in place to an earlier
//! time within its backtrack window.
//!
//! With a backend that runs databases the rewind is real: the cluster's
//! data is rebuilt from its newest backup before the target time and its
//! binary log replayed up to that time (the same recovery a point-in-time
//! restore uses), then swapped in under the same endpoint.

use chrono::Duration;
use mws_core::{RequestContext, ServiceError};

use super::{authorize, cluster_arn, invalid_cluster_state};
use crate::backend::LogSource;
use crate::generated::{errors, types as t};
use crate::ops::pitr::Recovery;
use crate::util::{invalid_combination, invalid_parameter, name_of, paginate, resource_tag_context, Filters};
use crate::Rds;

/// The longest backtrack window: 72 hours.
const MAX_WINDOW: i64 = 259_200;

/// Check a `BacktrackWindow` for an engine; `Some(0)` turns it off.
pub(crate) fn window(engine: &str, window: Option<i64>) -> Result<Option<i64>, ServiceError> {
    match window {
        None => Ok(None),
        Some(w) if !(0..=MAX_WINDOW).contains(&w) => {
            Err(invalid_parameter(format!("The backtrack window must be between 0 and {MAX_WINDOW} seconds.")))
        }
        Some(0) => Ok(Some(0)),
        Some(w) if engine == "aurora-mysql" => Ok(Some(w)),
        Some(_) => Err(invalid_combination(format!("Backtrack is not supported for engine {engine}."))),
    }
}

impl Rds {
    pub(crate) async fn backtrack_db_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::BacktrackDBClusterMessage,
    ) -> Result<t::DBClusterBacktrack, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "BacktrackDBCluster",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let window = rec.cluster.backtrack_window.unwrap_or(0);
        if window == 0 {
            return Err(errors::invalid_db_cluster_state_fault(format!(
                "Backtrack is not enabled for the DB cluster {id}."
            )));
        }
        let status = rec.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(invalid_cluster_state(&id, &status));
        }
        let now = ctx.received_at;
        let earliest = rec.cluster.cluster_create_time.unwrap_or(now).max(now - Duration::seconds(window));
        let mut to = input.backtrack_to;
        if to > now {
            return Err(invalid_parameter("The BacktrackTo time can't be in the future."));
        }
        if to < earliest {
            if input.use_earliest_time_on_point_in_time_unavailable == Some(true) {
                to = earliest;
            } else {
                return Err(invalid_parameter(format!(
                    "The BacktrackTo time must be later than the earliest backtrack time {}.",
                    earliest.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                )));
            }
        }
        let backtrack = t::DBClusterBacktrack {
            db_cluster_identifier: Some(id.clone()),
            backtrack_identifier: Some(uuid::Uuid::new_v4().to_string()),
            backtrack_to: Some(to),
            backtracked_from: Some(now),
            backtrack_request_creation_time: Some(now),
            status: Some("applying".into()),
        };
        let generation = self.with_region(ctx, |r| {
            r.backtracks.entry(id.clone()).or_default().push(backtrack.clone());
            let c = r.clusters.get_mut(&id)?;
            c.cluster.status = Some("backtracking".into());
            c.generation += 1;
            Some(c.generation)
        });
        let this = self.clone();
        let tctx = ctx.clone();
        let bid = backtrack.backtrack_identifier.clone().unwrap_or_default();
        self.run_task(async move {
            let ok = this.rewind_cluster(&tctx, &id, to).await;
            this.with_region(&tctx, |r| {
                if let Some(b) = r
                    .backtracks
                    .get_mut(&id)
                    .and_then(|l| l.iter_mut().find(|b| b.backtrack_identifier.as_deref() == Some(bid.as_str())))
                {
                    b.status = Some(if ok { "completed" } else { "failed" }.into());
                }
                if let Some(c) = r.clusters.get_mut(&id) {
                    if Some(c.generation) == generation {
                        c.cluster.status = Some("available".into());
                        c.generation += 1;
                    }
                }
            });
        })
        .await;
        Ok(backtrack)
    }

    /// Rebuild cluster `id`'s data as of `to` (emulated clock).
    async fn rewind_cluster(&self, ctx: &RequestContext, id: &str, to: chrono::DateTime<chrono::Utc>) -> bool {
        if !self.backend().runs_databases() {
            return true;
        }
        let Some((spec, backend, resource)) = self.with_region(ctx, |r| {
            r.clusters.get(id).map(|c| {
                (self.cluster_spec(r, c, ctx), c.backend_name.clone(), c.cluster.db_cluster_resource_id.clone())
            })
        }) else {
            return false;
        };
        if let Err(e) = self.backend().seal_log(&spec).await {
            tracing::warn!(cluster = %id, "archiving the binary log failed: {e}");
        }
        let until = self.wall_time(to);
        let bases = self.recovery_bases(ctx, resource.as_deref().unwrap_or_default(), true, until);
        let tmp = format!("backtrack-{}", uuid::Uuid::new_v4().simple());
        let recovery = Recovery { spec: spec.clone(), bases, log: LogSource::Database(backend.clone()), until };
        if let Err(e) = self.recover_into(&recovery, &tmp).await {
            tracing::warn!(cluster = %id, "backtrack failed: {e}");
            return false;
        }
        let _ = self.backend().delete(&spec.name).await;
        let created = self.backend().create(&spec, Some(&tmp)).await;
        let _ = self.backend().delete_snapshot(&tmp).await;
        match created {
            Ok(l) => {
                self.with_region(ctx, |r| {
                    if let Some(c) = r.clusters.get_mut(id) {
                        c.listen = Some(crate::state::Listen { host: l.host, port: l.port });
                    }
                });
                true
            }
            Err(e) => {
                tracing::warn!(cluster = %id, "restarting the cluster after backtrack failed: {e}");
                false
            }
        }
    }

    pub(crate) fn describe_db_cluster_backtracks_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClusterBacktracksMessage,
    ) -> Result<t::DBClusterBacktrackMessage, ServiceError> {
        let id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let rec = self.cluster(ctx, &id)?;
        authorize(
            ctx,
            "DescribeDBClusterBacktracks",
            &cluster_arn(ctx, &id),
            resource_tag_context("cluster", &rec.cluster.tag_list),
        )?;
        let f = Filters::new(&input.filters, &["db-cluster-backtrack-id", "db-cluster-backtrack-status"])?;
        let all: Vec<t::DBClusterBacktrack> = self
            .with_region(ctx, |r| r.backtracks.get(&id).cloned().unwrap_or_default())
            .into_iter()
            .rev()
            .filter(|b| input.backtrack_identifier.as_ref().is_none_or(|i| b.backtrack_identifier.as_ref() == Some(i)))
            .filter(|b| {
                f.matches(|name| match name {
                    "db-cluster-backtrack-id" => b.backtrack_identifier.iter().cloned().collect(),
                    "db-cluster-backtrack-status" => b.status.iter().cloned().collect(),
                    _ => Vec::new(),
                })
            })
            .collect();
        if let Some(b) = &input.backtrack_identifier {
            if all.is_empty() {
                return Err(errors::db_cluster_backtrack_not_found_fault(format!(
                    "Backtrack {b} not found for DB cluster {id}."
                )));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBClusterBacktrackMessage { marker, db_cluster_backtracks: Some(page) })
    }
}
