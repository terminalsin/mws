//! Update records: every asynchronous change to a cluster, node group,
//! add-on or capability is an `Update` the caller can follow.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::{ClusterRec, UpdateRec};
use crate::util;
use crate::Eks;

/// What an update applies to besides the cluster.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum Target<'a> {
    #[default]
    Cluster,
    Nodegroup(&'a str),
    Addon(&'a str),
    Capability(&'a str),
}

/// Record an update that is `InProgress` and return it.
pub(crate) fn push(
    rec: &mut ClusterRec,
    now: DateTime<Utc>,
    kind: &str,
    params: Vec<types::UpdateParam>,
    target: Option<Target<'_>>,
) -> types::Update {
    let update = types::Update {
        id: Some(util::uuid()),
        status: Some("InProgress".into()),
        r#type: Some(kind.into()),
        params: Some(params),
        created_at: Some(now),
        errors: Some(Vec::new()),
        cancellation: None,
    };
    let mut r = UpdateRec { update: update.clone(), ..Default::default() };
    match target.unwrap_or_default() {
        Target::Cluster => {}
        Target::Nodegroup(n) => r.nodegroup = Some(n.into()),
        Target::Addon(n) => r.addon = Some(n.into()),
        Target::Capability(n) => r.capability = Some(n.into()),
    }
    rec.updates.push(r);
    update
}

/// Finish every update in progress.
pub(crate) fn settle(rec: &mut ClusterRec) {
    for u in &mut rec.updates {
        if u.update.status.as_deref() == Some("InProgress") {
            u.update.status = Some("Successful".into());
        }
    }
}

/// Mark the update `id` as `Failed` with one error.
pub(crate) fn fail(rec: &mut ClusterRec, id: &str, code: &str, message: String, resources: Vec<String>) {
    if let Some(u) = rec.updates.iter_mut().find(|u| u.update.id.as_deref() == Some(id)) {
        u.update.status = Some("Failed".into());
        u.update.errors = Some(vec![types::ErrorDetail {
            error_code: Some(code.into()),
            error_message: Some(message),
            resource_ids: Some(resources),
        }]);
    }
}

fn matches(u: &UpdateRec, nodegroup: Option<&str>, addon: Option<&str>, capability: Option<&str>) -> bool {
    u.nodegroup.as_deref() == nodegroup && u.addon.as_deref() == addon && u.capability.as_deref() == capability
}

fn check_target(
    rec: &ClusterRec,
    cluster: &str,
    nodegroup: Option<&str>,
    addon: Option<&str>,
    capability: Option<&str>,
) -> Result<(), ServiceError> {
    if let Some(n) = nodegroup {
        if !rec.nodegroups.contains_key(n) && !rec.updates.iter().any(|u| u.nodegroup.as_deref() == Some(n)) {
            return Err(crate::nodegroups::not_found(cluster, n));
        }
    }
    if let Some(a) = addon {
        if !rec.addons.contains_key(a) && !rec.updates.iter().any(|u| u.addon.as_deref() == Some(a)) {
            return Err(crate::addons::not_found(cluster, a));
        }
    }
    if let Some(c) = capability {
        if !rec.capabilities.contains_key(c) && !rec.updates.iter().any(|u| u.capability.as_deref() == Some(c)) {
            return Err(crate::capabilities::not_found(c));
        }
    }
    Ok(())
}

impl Eks {
    pub(crate) async fn describe_update(
        &self,
        ctx: &RequestContext,
        input: types::DescribeUpdateRequest,
    ) -> Result<types::DescribeUpdateResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.name)?;
        util::authorize(ctx, "DescribeUpdate", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let (n, a, c) =
            (input.nodegroup_name.as_deref(), input.addon_name.as_deref(), input.capability_name.as_deref());
        check_target(rec, &input.name, n, a, c)?;
        let u = rec
            .updates
            .iter()
            .find(|u| u.update.id.as_deref() == Some(input.update_id.as_str()) && matches(u, n, a, c))
            .ok_or_else(|| errors::resource_not_found(format!("No update found for ID: {}", input.update_id)))?;
        Ok(types::DescribeUpdateResponse { update: Some(u.update.clone()) })
    }

    pub(crate) async fn list_updates(
        &self,
        ctx: &RequestContext,
        input: types::ListUpdatesRequest,
    ) -> Result<types::ListUpdatesResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.name)?;
        util::authorize(ctx, "ListUpdates", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let (n, a, c) =
            (input.nodegroup_name.as_deref(), input.addon_name.as_deref(), input.capability_name.as_deref());
        check_target(rec, &input.name, n, a, c)?;
        let ids: Vec<String> =
            rec.updates.iter().filter(|u| matches(u, n, a, c)).filter_map(|u| u.update.id.clone()).collect();
        let (items, next) = util::page(&ids, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListUpdatesResponse { update_ids: Some(items), next_token: next })
    }

    pub(crate) async fn cancel_update(
        &self,
        ctx: &RequestContext,
        input: types::CancelUpdateRequest,
    ) -> Result<types::CancelUpdateResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.name)?;
        util::authorize(ctx, "CancelUpdate", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let u = rec
            .updates
            .iter_mut()
            .find(|u| u.update.id.as_deref() == Some(input.update_id.as_str()))
            .ok_or_else(|| errors::resource_not_found(format!("No update found for ID: {}", input.update_id)))?;
        let status = u.update.status.clone().unwrap_or_default();
        if status != "InProgress" {
            return Err(errors::invalid_state(format!(
                "Update {} cannot be cancelled because it is {status}.",
                input.update_id
            ))
            .with_field("clusterName", util::text(&input.name)));
        }
        u.update.status = Some("Cancelled".into());
        u.update.cancellation = Some(types::Cancellation { status: Some("Successful".into()), reason: None });
        Ok(types::CancelUpdateResponse { update: Some(u.update.clone()) })
    }
}
