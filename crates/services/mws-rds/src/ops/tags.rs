//! Tags on any RDS resource, by ARN.

use mws_core::{RequestContext, ServiceError};

use super::authorize;
use crate::generated::{errors, types as t};
use crate::state::{RegionState, State};
use crate::util::{
    check_tags, invalid_parameter, merge_tags, parse_arn, request_tag_context, resource_tag_context, Filters,
};
use crate::Rds;

/// The tags of the resource `kind`/`name` in `r`, if it exists.
fn tags_of<'a>(r: &'a mut RegionState, kind: &str, name: &str) -> Option<&'a mut Vec<t::Tag>> {
    match kind {
        "db" => r.instances.get_mut(name).map(|i| i.db.tag_list.get_or_insert_with(Vec::new)),
        "cluster" => r.clusters.get_mut(name).map(|c| c.cluster.tag_list.get_or_insert_with(Vec::new)),
        "snapshot" => r.snapshots.get_mut(name).map(|s| s.snapshot.tag_list.get_or_insert_with(Vec::new)),
        "cluster-snapshot" => {
            r.cluster_snapshots.get_mut(name).map(|s| s.snapshot.tag_list.get_or_insert_with(Vec::new))
        }
        "pg" => r.parameter_groups.get_mut(name).map(|g| &mut g.tags),
        "cluster-pg" => r.cluster_parameter_groups.get_mut(name).map(|g| &mut g.tags),
        "og" => r.option_groups.get_mut(name).map(|g| &mut g.tags),
        "subgrp" => r.subnet_groups.get_mut(name).map(|g| &mut g.tags),
        "es" => r.event_subscriptions.get_mut(name).map(|g| &mut g.tags),
        "cluster-endpoint" => r.cluster_endpoints.get_mut(name).map(|g| &mut g.tags),
        _ => None,
    }
}

fn not_found(kind: &str, name: &str, arn: &str) -> ServiceError {
    match kind {
        "db" => super::instance_not_found(name),
        "cluster" => super::cluster_not_found(name),
        "snapshot" => errors::db_snapshot_not_found_fault(format!("DBSnapshot {name} not found.")),
        "cluster-snapshot" => {
            errors::db_cluster_snapshot_not_found_fault(format!("DBClusterSnapshot {name} not found."))
        }
        "pg" => errors::db_parameter_group_not_found_fault(format!("DBParameterGroup {name} not found.")),
        "cluster-pg" => {
            errors::db_cluster_parameter_group_not_found_fault(format!("DBClusterParameterGroup {name} not found."))
        }
        "og" => errors::option_group_not_found_fault(format!("OptionGroup {name} not found.")),
        "subgrp" => errors::db_subnet_group_not_found_fault(format!("DBSubnetGroup {name} not found.")),
        "es" => errors::subscription_not_found_fault(format!("Subscription {name} not found.")),
        "cluster-endpoint" => {
            errors::db_cluster_endpoint_not_found_fault(format!("DBClusterEndpoint {name} not found."))
        }
        "global-cluster" => errors::global_cluster_not_found_fault(format!("Global cluster {name} not found.")),
        _ => invalid_parameter(format!("Invalid resource name: {arn}")),
    }
}

impl Rds {
    /// Run `f` on a resource's tags.
    fn with_tags<R>(
        &self,
        ctx: &RequestContext,
        arn: &str,
        f: impl FnOnce(&mut Vec<t::Tag>) -> R,
    ) -> Result<R, ServiceError> {
        let Some((region, account, kind, name)) = parse_arn(arn) else {
            return Err(invalid_parameter(
                "The specified resource name does not match an RDS resource in this region.",
            ));
        };
        if kind == "global-cluster" {
            let mut st = self.lock();
            let g =
                st.global_clusters.get_mut(&State::key(&account, &name)).ok_or_else(|| not_found(&kind, &name, arn))?;
            return Ok(f(g.global.tag_list.get_or_insert_with(Vec::new)));
        }
        if region != ctx.region || account != crate::util::account_of(ctx) {
            return Err(invalid_parameter(
                "The specified resource name does not match an RDS resource in this region.",
            ));
        }
        self.with_region(ctx, |r| tags_of(r, &kind, &name).map(f)).ok_or_else(|| not_found(&kind, &name, arn))
    }

    pub(crate) fn add_tags_to_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::AddTagsToResourceMessage,
    ) -> Result<(), ServiceError> {
        check_tags(&input.tags)?;
        let current = self.with_tags(ctx, &input.resource_name, |t| t.clone())?;
        let kind = parse_arn(&input.resource_name).map(|p| p.2).unwrap_or_default();
        let mut c = resource_tag_context(&kind, &Some(current.clone()));
        c.extend(request_tag_context(&input.tags));
        authorize(ctx, "AddTagsToResource", &input.resource_name, c)?;
        let mut merged = current;
        merge_tags(&mut merged, &input.tags);
        check_tags(&merged)?;
        self.with_tags(ctx, &input.resource_name, |t| *t = merged)
    }

    pub(crate) fn remove_tags_from_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::RemoveTagsFromResourceMessage,
    ) -> Result<(), ServiceError> {
        let current = self.with_tags(ctx, &input.resource_name, |t| t.clone())?;
        let kind = parse_arn(&input.resource_name).map(|p| p.2).unwrap_or_default();
        let mut c = resource_tag_context(&kind, &Some(current));
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize(ctx, "RemoveTagsFromResource", &input.resource_name, c)?;
        self.with_tags(ctx, &input.resource_name, |t| {
            t.retain(|t| !input.tag_keys.contains(&t.key.clone().unwrap_or_default()))
        })
    }

    pub(crate) fn list_tags_for_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::ListTagsForResourceMessage,
    ) -> Result<t::TagListMessage, ServiceError> {
        Filters::new(&input.filters, &[])?;
        let tags = self.with_tags(ctx, &input.resource_name, |t| t.clone())?;
        let kind = parse_arn(&input.resource_name).map(|p| p.2).unwrap_or_default();
        authorize(ctx, "ListTagsForResource", &input.resource_name, resource_tag_context(&kind, &Some(tags.clone())))?;
        Ok(t::TagListMessage { tag_list: Some(tags) })
    }
}
