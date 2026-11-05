//! Aurora PostgreSQL Limitless Database: DB shard groups on clusters
//! created with `ClusterScalabilityType=limitless`. A shard group's
//! endpoint reaches the cluster's database.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, cluster_arn, invalid_cluster_state};
use crate::generated::{errors, types as t};
use crate::util::{
    arn, endpoint_suffix, identifier, invalid_parameter, name_of, opt, paginate, request_tag_context,
    resource_tag_context, stable_token, tags_from, Filters,
};
use crate::Rds;

fn not_found(id: &str) -> ServiceError {
    errors::db_shard_group_not_found_fault(format!("DBShardGroup {id} not found."))
}

fn check_acus(min: Option<f64>, max: Option<f64>) -> Result<(), ServiceError> {
    if let Some(m) = max {
        if !(16.0..=6144.0).contains(&m) {
            return Err(invalid_parameter("MaxACU must be between 16 and 6144."));
        }
    }
    if let (Some(lo), Some(hi)) = (min, max) {
        if lo > hi {
            return Err(invalid_parameter("MinACU can't be greater than MaxACU."));
        }
    }
    if let Some(lo) = min {
        if lo < 16.0 {
            return Err(invalid_parameter("MinACU must be at least 16."));
        }
    }
    Ok(())
}

fn check_redundancy(r: Option<i32>) -> Result<(), ServiceError> {
    match r {
        Some(r) if !(0..=2).contains(&r) => Err(invalid_parameter("ComputeRedundancy must be 0, 1 or 2.")),
        _ => Ok(()),
    }
}

impl Rds {
    /// A shard group as DescribeDBShardGroups shows it.
    fn shard_group_view(&self, ctx: &RequestContext, g: &t::DBShardGroup) -> t::DBShardGroup {
        let mut g = g.clone();
        let cluster = g.db_cluster_identifier.clone().unwrap_or_default();
        let listen = self.with_region(ctx, |r| r.clusters.get(&cluster).and_then(|c| c.listen.clone()));
        let id = g.db_shard_group_identifier.clone().unwrap_or_default();
        let host = format!("{id}.limitless-{}", endpoint_suffix(ctx));
        g.endpoint = self.endpoint_for(ctx, &host, 5432, &listen).address;
        g
    }

    pub(crate) async fn create_db_shard_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBShardGroupMessage,
    ) -> Result<t::DBShardGroup, ServiceError> {
        let id = identifier("DBShardGroupIdentifier", &input.db_shard_group_identifier, 63)?;
        let cluster_id = name_of(&input.db_cluster_identifier).to_ascii_lowercase();
        let tags = tags_from(&input.tags)?;
        let garn = arn(ctx, "shard-group", &id);
        authorize(ctx, "CreateDBShardGroup", &garn, request_tag_context(&tags))?;
        check_acus(input.min_acu, Some(input.max_acu))?;
        check_redundancy(input.compute_redundancy)?;
        let cluster = self.cluster(ctx, &cluster_id)?;
        if cluster.cluster.cluster_scalability_type.as_deref() != Some("limitless") {
            return Err(errors::invalid_db_cluster_state_fault(format!(
                "The DB cluster {cluster_id} isn't a Limitless Database cluster. Create it with ClusterScalabilityType limitless."
            )));
        }
        let status = cluster.cluster.status.clone().unwrap_or_default();
        if status != "available" {
            return Err(invalid_cluster_state(&cluster_id, &status));
        }
        let group = t::DBShardGroup {
            db_shard_group_resource_id: Some(format!("shardgrp-{}", stable_token(&garn, 32))),
            db_shard_group_identifier: Some(id.clone()),
            db_cluster_identifier: Some(cluster_id.clone()),
            max_acu: Some(input.max_acu),
            min_acu: input.min_acu.or(Some(16.0)),
            compute_redundancy: Some(input.compute_redundancy.unwrap_or(0)),
            status: Some("creating".into()),
            publicly_accessible: Some(input.publicly_accessible.unwrap_or(false)),
            endpoint: None,
            db_shard_group_arn: Some(garn),
            tag_list: Some(tags),
        };
        self.with_region(ctx, |r| {
            if r.shard_groups.contains_key(&id) {
                return Err(errors::db_shard_group_already_exists_fault(format!("DBShardGroup {id} already exists.")));
            }
            if r.shard_groups.values().any(|g| g.db_cluster_identifier.as_deref() == Some(cluster_id.as_str())) {
                return Err(errors::max_db_shard_group_limit_reached(format!(
                    "The DB cluster {cluster_id} already has a DB shard group."
                )));
            }
            r.shard_groups.insert(id.clone(), group.clone());
            if let Some(c) = r.clusters.get_mut(&cluster_id) {
                if let Some(l) = c.cluster.limitless_database.as_mut() {
                    l.status = Some("active".into());
                }
            }
            Ok(())
        })?;
        let view = self.shard_group_view(ctx, &group);
        self.settle_shard_group(ctx, &id, "available").await;
        Ok(view)
    }

    /// Move a shard group to `status` once its change is done.
    async fn settle_shard_group(&self, ctx: &RequestContext, id: &str, status: &'static str) {
        let this = self.clone();
        let ctx = ctx.clone();
        let id = id.to_string();
        self.run_task(async move {
            if this.backend().runs_databases() {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            this.with_region(&ctx, |r| {
                if let Some(g) = r.shard_groups.get_mut(&id) {
                    g.status = Some(status.into());
                }
            });
        })
        .await;
    }

    pub(crate) async fn modify_db_shard_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBShardGroupMessage,
    ) -> Result<t::DBShardGroup, ServiceError> {
        let id = input.db_shard_group_identifier.to_ascii_lowercase();
        let g = self.with_region(ctx, |r| r.shard_groups.get(&id).cloned()).ok_or_else(|| not_found(&id))?;
        authorize(
            ctx,
            "ModifyDBShardGroup",
            g.db_shard_group_arn.as_deref().unwrap_or_default(),
            resource_tag_context("shard-group", &g.tag_list),
        )?;
        if g.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_cluster_state_fault(format!(
                "DBShardGroup {id} is not in the available state."
            )));
        }
        check_acus(input.min_acu.or(g.min_acu), input.max_acu.or(g.max_acu))?;
        check_redundancy(input.compute_redundancy)?;
        let g = self
            .with_region(ctx, |r| {
                let g = r.shard_groups.get_mut(&id)?;
                if let Some(v) = input.max_acu {
                    g.max_acu = Some(v);
                }
                if let Some(v) = input.min_acu {
                    g.min_acu = Some(v);
                }
                if let Some(v) = input.compute_redundancy {
                    g.compute_redundancy = Some(v);
                }
                g.status = Some("modifying".into());
                Some(g.clone())
            })
            .ok_or_else(|| not_found(&id))?;
        let view = self.shard_group_view(ctx, &g);
        self.settle_shard_group(ctx, &id, "available").await;
        Ok(view)
    }

    pub(crate) async fn reboot_db_shard_group_op(
        &self,
        ctx: &RequestContext,
        input: t::RebootDBShardGroupMessage,
    ) -> Result<t::DBShardGroup, ServiceError> {
        let id = input.db_shard_group_identifier.to_ascii_lowercase();
        let g = self.with_region(ctx, |r| r.shard_groups.get(&id).cloned()).ok_or_else(|| not_found(&id))?;
        authorize(
            ctx,
            "RebootDBShardGroup",
            g.db_shard_group_arn.as_deref().unwrap_or_default(),
            resource_tag_context("shard-group", &g.tag_list),
        )?;
        if g.status.as_deref() != Some("available") {
            return Err(errors::invalid_db_shard_group_state_fault(format!(
                "DBShardGroup {id} is not in the available state."
            )));
        }
        let g = self
            .with_region(ctx, |r| {
                let g = r.shard_groups.get_mut(&id)?;
                g.status = Some("rebooting".into());
                Some(g.clone())
            })
            .ok_or_else(|| not_found(&id))?;
        let view = self.shard_group_view(ctx, &g);
        self.settle_shard_group(ctx, &id, "available").await;
        Ok(view)
    }

    pub(crate) async fn delete_db_shard_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBShardGroupMessage,
    ) -> Result<t::DBShardGroup, ServiceError> {
        let id = input.db_shard_group_identifier.to_ascii_lowercase();
        let g = self.with_region(ctx, |r| r.shard_groups.get(&id).cloned()).ok_or_else(|| not_found(&id))?;
        authorize(
            ctx,
            "DeleteDBShardGroup",
            g.db_shard_group_arn.as_deref().unwrap_or_default(),
            resource_tag_context("shard-group", &g.tag_list),
        )?;
        if g.status.as_deref() == Some("deleting") {
            return Err(errors::invalid_db_shard_group_state_fault(format!(
                "DBShardGroup {id} is already being deleted."
            )));
        }
        let mut shown = g.clone();
        shown.status = Some("deleting".into());
        let view = self.shard_group_view(ctx, &shown);
        self.with_region(ctx, |r| {
            if let Some(g) = r.shard_groups.get_mut(&id) {
                g.status = Some("deleting".into());
            }
        });
        let this = self.clone();
        let tctx = ctx.clone();
        self.run_task(async move {
            this.with_region(&tctx, |r| {
                if let Some(g) = r.shard_groups.remove(&id) {
                    let cluster = g.db_cluster_identifier.unwrap_or_default();
                    if let Some(l) = r.clusters.get_mut(&cluster).and_then(|c| c.cluster.limitless_database.as_mut()) {
                        l.status = Some("not-in-use".into());
                    }
                }
            });
        })
        .await;
        Ok(view)
    }

    pub(crate) fn describe_db_shard_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBShardGroupsMessage,
    ) -> Result<t::DescribeDBShardGroupsResponse, ServiceError> {
        authorize(ctx, "DescribeDBShardGroups", &arn(ctx, "shard-group", "*"), ConditionContext::new())?;
        let f = Filters::new(&input.filters, &["db-cluster-id"])?;
        let wanted = input.db_shard_group_identifier.as_deref().map(|i| name_of(i).to_ascii_lowercase());
        let all: Vec<t::DBShardGroup> = self.with_region(ctx, |r| r.shard_groups.values().cloned().collect());
        let all: Vec<t::DBShardGroup> = all
            .into_iter()
            .filter(|g| wanted.as_ref().is_none_or(|w| g.db_shard_group_identifier.as_ref() == Some(w)))
            .filter(|g| {
                f.matches(|n| match n {
                    "db-cluster-id" => {
                        let mut v = opt(&g.db_cluster_identifier);
                        if let Some(c) = &g.db_cluster_identifier {
                            v.push(cluster_arn(ctx, c));
                        }
                        v
                    }
                    _ => Vec::new(),
                })
            })
            .map(|g| self.shard_group_view(ctx, &g))
            .collect();
        if let Some(w) = &wanted {
            if all.is_empty() {
                return Err(not_found(w));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DescribeDBShardGroupsResponse { db_shard_groups: Some(page), marker })
    }
}
