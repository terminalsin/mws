//! Tags on every taggable EKS resource, addressed by ARN.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::State;
use crate::util::{self, Tags};
use crate::Eks;

/// The tag map of the resource `arn` names, if it exists in the caller's
/// account and Region.
fn tags_of<'a>(st: &'a mut State, ctx: &RequestContext, arn: &str) -> Result<&'a mut Option<Tags>, ServiceError> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "eks" || !parts[5].contains('/') {
        return Err(errors::bad_request(format!("{arn} is not a valid resource ARN.")));
    }
    let not_found = || errors::not_found(format!("Resource {arn} not found."));
    if parts[3] != ctx.region || parts[4] != util::account(ctx) {
        return Err(not_found());
    }
    let (kind, rest) = parts[5].split_once('/').expect("checked");
    let region = util::region(st, ctx);
    if kind == "eks-anywhere-subscription" {
        return region.subscriptions.get_mut(rest).map(|s| &mut s.tags).ok_or_else(not_found);
    }
    let cluster_name = rest.split('/').next().unwrap_or_default();
    let rec = region.clusters.get_mut(cluster_name).ok_or_else(not_found)?;
    let same = |a: &Option<String>| a.as_deref() == Some(arn);
    let tags = match kind {
        "cluster" if rest == cluster_name => Some(&mut rec.cluster.tags),
        "nodegroup" => {
            rec.nodegroups.values_mut().find(|n| same(&n.nodegroup.nodegroup_arn)).map(|n| &mut n.nodegroup.tags)
        }
        "addon" => rec.addons.values_mut().find(|a| same(&a.addon_arn)).map(|a| &mut a.tags),
        "fargateprofile" => {
            rec.fargate_profiles.values_mut().find(|f| same(&f.fargate_profile_arn)).map(|f| &mut f.tags)
        }
        "identityproviderconfig" => {
            rec.identity_providers.values_mut().find(|p| same(&p.identity_provider_config_arn)).map(|p| &mut p.tags)
        }
        "access-entry" => {
            rec.access_entries.values_mut().find(|e| same(&e.entry.access_entry_arn)).map(|e| &mut e.entry.tags)
        }
        "podidentityassociation" => {
            rec.pod_identities.values_mut().find(|p| same(&p.association_arn)).map(|p| &mut p.tags)
        }
        "capability" => rec.capabilities.values_mut().find(|c| same(&c.arn)).map(|c| &mut c.tags),
        _ => None,
    };
    tags.ok_or_else(not_found)
}

impl Eks {
    pub(crate) async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        let mut st = self.write();
        let tags = tags_of(&mut st, ctx, &input.resource_arn)?;
        util::authorize(
            ctx,
            "TagResource",
            &input.resource_arn,
            tags.as_ref(),
            Some(&input.tags),
            ConditionContext::new(),
        )?;
        util::check_tags(Some(&input.tags))?;
        let mut merged = tags.clone().unwrap_or_default();
        merged.extend(input.tags.clone());
        util::check_tags(Some(&merged))?;
        *tags = Some(merged);
        Ok(types::TagResourceResponse {})
    }

    pub(crate) async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut st = self.write();
        let tags = tags_of(&mut st, ctx, &input.resource_arn)?;
        let mut c = ConditionContext::new();
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        util::authorize(ctx, "UntagResource", &input.resource_arn, tags.as_ref(), None, c)?;
        if let Some(map) = tags.as_mut() {
            for k in &input.tag_keys {
                map.remove(k);
            }
        }
        Ok(types::UntagResourceResponse {})
    }

    pub(crate) async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let mut st = self.write();
        let tags = tags_of(&mut st, ctx, &input.resource_arn)?;
        util::authorize(ctx, "ListTagsForResource", &input.resource_arn, tags.as_ref(), None, ConditionContext::new())?;
        Ok(types::ListTagsForResourceResponse { tags: Some(tags.clone().unwrap_or_default()) })
    }
}
