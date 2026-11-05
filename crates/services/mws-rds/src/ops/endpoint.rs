//! Aurora custom cluster endpoints.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, cluster_not_found};
use crate::generated::{errors, types as t};
use crate::state::Tagged;
use crate::util::{
    arn, endpoint_suffix, identifier, invalid_parameter, name_of, opt, paginate, request_tag_context,
    resource_tag_context, stable_token, tags_from, Filters,
};
use crate::Rds;

fn not_found(id: &str) -> ServiceError {
    errors::db_cluster_endpoint_not_found_fault(format!("DBClusterEndpoint {id} not found."))
}

fn check_type(t: &str) -> Result<String, ServiceError> {
    let up = t.to_ascii_uppercase();
    if up == "READER" || up == "ANY" {
        Ok(up)
    } else {
        Err(invalid_parameter(format!("Invalid endpoint type: {t}. Valid values are READER and ANY.")))
    }
}

impl Rds {
    fn check_members(
        &self,
        ctx: &RequestContext,
        cluster: &str,
        ids: &Option<Vec<String>>,
    ) -> Result<Option<Vec<String>>, ServiceError> {
        let Some(ids) = ids else { return Ok(None) };
        let rec = self.cluster(ctx, cluster)?;
        let members: Vec<String> =
            rec.cluster.db_cluster_members.iter().flatten().filter_map(|m| m.db_instance_identifier.clone()).collect();
        let mut out = Vec::new();
        for i in ids {
            let i = i.to_ascii_lowercase();
            if !members.contains(&i) {
                return Err(invalid_parameter(format!("DB instance {i} is not a member of DB cluster {cluster}.")));
            }
            out.push(i);
        }
        Ok(Some(out))
    }

    pub(crate) fn create_db_cluster_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBClusterEndpointMessage,
    ) -> Result<t::DBClusterEndpoint, ServiceError> {
        let id = identifier("DBClusterEndpointIdentifier", &input.db_cluster_endpoint_identifier, 63)?;
        let cluster = input.db_cluster_identifier.to_ascii_lowercase();
        let earn = arn(ctx, "cluster-endpoint", &id);
        let tags = tags_from(&input.tags)?;
        authorize(ctx, "CreateDBClusterEndpoint", &earn, request_tag_context(&tags))?;
        let rec = self.cluster(ctx, &cluster)?;
        if rec.cluster.status.as_deref() != Some("available") {
            return Err(super::invalid_cluster_state(&cluster, rec.cluster.status.as_deref().unwrap_or_default()));
        }
        let kind = check_type(&input.endpoint_type)?;
        if input.static_members.is_some() && input.excluded_members.is_some() {
            return Err(invalid_parameter("You can't specify both StaticMembers and ExcludedMembers."));
        }
        let static_members = self.check_members(ctx, &cluster, &input.static_members)?;
        let excluded = self.check_members(ctx, &cluster, &input.excluded_members)?;
        let endpoint = t::DBClusterEndpoint {
            db_cluster_endpoint_identifier: Some(id.clone()),
            db_cluster_identifier: Some(cluster.clone()),
            db_cluster_endpoint_resource_identifier: Some(format!(
                "cluster-endpoint-{}",
                &stable_token(&earn, 26)[..26]
            )),
            endpoint: Some(format!("{id}.cluster-custom-{}", endpoint_suffix(ctx))),
            status: Some("available".into()),
            endpoint_type: Some("CUSTOM".into()),
            custom_endpoint_type: Some(kind),
            static_members: Some(static_members.unwrap_or_default()),
            excluded_members: Some(excluded.unwrap_or_default()),
            db_cluster_endpoint_arn: Some(earn),
        };
        self.with_region(ctx, |r| {
            if r.cluster_endpoints.contains_key(&id) {
                return Err(errors::db_cluster_endpoint_already_exists_fault(format!(
                    "DBClusterEndpoint with identifier {id} already exists."
                )));
            }
            if r.cluster_endpoints
                .values()
                .filter(|e| e.item.db_cluster_identifier.as_deref() == Some(cluster.as_str()))
                .count()
                >= 5
            {
                return Err(errors::db_cluster_endpoint_quota_exceeded_fault(
                    "Cannot create more than 5 custom endpoints per DB cluster.",
                ));
            }
            r.cluster_endpoints.insert(id.clone(), Tagged { item: endpoint.clone(), tags });
            Ok(())
        })?;
        Ok(endpoint)
    }

    pub(crate) fn modify_db_cluster_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBClusterEndpointMessage,
    ) -> Result<t::DBClusterEndpoint, ServiceError> {
        let id = input.db_cluster_endpoint_identifier.to_ascii_lowercase();
        let current = self.with_region(ctx, |r| r.cluster_endpoints.get(&id).cloned()).ok_or_else(|| not_found(&id))?;
        authorize(
            ctx,
            "ModifyDBClusterEndpoint",
            &arn(ctx, "cluster-endpoint", &id),
            resource_tag_context("cluster-endpoint", &Some(current.tags.clone())),
        )?;
        let cluster = current.item.db_cluster_identifier.clone().unwrap_or_default();
        let kind = match &input.endpoint_type {
            Some(k) => Some(check_type(k)?),
            None => None,
        };
        let static_members = self.check_members(ctx, &cluster, &input.static_members)?;
        let excluded = self.check_members(ctx, &cluster, &input.excluded_members)?;
        Ok(self.with_region(ctx, |r| {
            let e = r.cluster_endpoints.get_mut(&id).expect("looked up above");
            if let Some(k) = kind {
                e.item.custom_endpoint_type = Some(k);
            }
            if let Some(s) = static_members {
                e.item.static_members = Some(s);
                e.item.excluded_members = Some(Vec::new());
            }
            if let Some(x) = excluded {
                e.item.excluded_members = Some(x);
                e.item.static_members = Some(Vec::new());
            }
            e.item.clone()
        }))
    }

    pub(crate) fn delete_db_cluster_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBClusterEndpointMessage,
    ) -> Result<t::DBClusterEndpoint, ServiceError> {
        let id = input.db_cluster_endpoint_identifier.to_ascii_lowercase();
        let current = self.with_region(ctx, |r| r.cluster_endpoints.get(&id).cloned()).ok_or_else(|| not_found(&id))?;
        authorize(
            ctx,
            "DeleteDBClusterEndpoint",
            &arn(ctx, "cluster-endpoint", &id),
            resource_tag_context("cluster-endpoint", &Some(current.tags.clone())),
        )?;
        self.with_region(ctx, |r| r.cluster_endpoints.remove(&id));
        let mut e = current.item;
        e.status = Some("deleting".into());
        Ok(e)
    }

    pub(crate) fn describe_db_cluster_endpoints_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClusterEndpointsMessage,
    ) -> Result<t::DBClusterEndpointMessage, ServiceError> {
        authorize(
            ctx,
            "DescribeDBClusterEndpoints",
            &arn(ctx, "cluster", input.db_cluster_identifier.as_deref().map(name_of).as_deref().unwrap_or("*")),
            ConditionContext::new(),
        )?;
        let f = Filters::new(
            &input.filters,
            &[
                "db-cluster-endpoint-type",
                "db-cluster-endpoint-custom-type",
                "db-cluster-endpoint-id",
                "db-cluster-endpoint-status",
            ],
        )?;
        let cluster = input.db_cluster_identifier.as_deref().map(|c| name_of(c).to_ascii_lowercase());
        let wanted = input.db_cluster_endpoint_identifier.as_deref().map(|e| e.to_ascii_lowercase());
        let mut all: Vec<t::DBClusterEndpoint> = Vec::new();
        let clusters: Vec<_> = self.with_region(ctx, |r| r.clusters.values().cloned().collect());
        if let Some(c) = &cluster {
            if !clusters.iter().any(|x| x.cluster.db_cluster_identifier.as_ref() == Some(c)) {
                return Err(cluster_not_found(c));
            }
        }
        // Each cluster's own writer and reader endpoints come first.
        if wanted.is_none() {
            for c in clusters
                .iter()
                .filter(|c| cluster.as_ref().is_none_or(|w| c.cluster.db_cluster_identifier.as_ref() == Some(w)))
            {
                let view = self.cluster_view(ctx, c);
                let cid = view.db_cluster_identifier.clone().unwrap_or_default();
                for (kind, host) in [("WRITER", &view.endpoint), ("READER", &view.reader_endpoint)] {
                    all.push(t::DBClusterEndpoint {
                        db_cluster_identifier: Some(cid.clone()),
                        endpoint: host.clone(),
                        status: Some("available".into()),
                        endpoint_type: Some(kind.into()),
                        ..Default::default()
                    });
                }
            }
        }
        let custom: Vec<t::DBClusterEndpoint> =
            self.with_region(ctx, |r| r.cluster_endpoints.values().map(|e| e.item.clone()).collect());
        all.extend(custom.into_iter().filter(|e| {
            cluster.as_ref().is_none_or(|c| e.db_cluster_identifier.as_ref() == Some(c))
                && wanted.as_ref().is_none_or(|w| e.db_cluster_endpoint_identifier.as_ref() == Some(w))
        }));
        if let Some(w) = &wanted {
            if all.is_empty() {
                return Err(not_found(w));
            }
        }
        let all: Vec<_> = all
            .into_iter()
            .filter(|e| {
                f.matches(|n| match n {
                    "db-cluster-endpoint-type" => opt(&e.endpoint_type),
                    "db-cluster-endpoint-custom-type" => opt(&e.custom_endpoint_type),
                    "db-cluster-endpoint-id" => opt(&e.db_cluster_endpoint_identifier),
                    "db-cluster-endpoint-status" => opt(&e.status),
                    _ => Vec::new(),
                })
            })
            .collect();
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::DBClusterEndpointMessage { marker, db_cluster_endpoints: Some(page) })
    }
}
