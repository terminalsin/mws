//! `AddTagsToResource`, `RemoveTagsFromResource` and `ListTagsForResource`
//! for parameters, documents, maintenance windows, patch baselines and
//! activations.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use std::collections::BTreeMap;

use crate::names::{request_tag_conditions, resource_tag_conditions, ParamRef};
use crate::state::Parameter;
use crate::Ssm;

const MAX_TAGS: usize = 50;

fn invalid_id() -> ServiceError {
    errors::invalid_resource_id("The resource ID isn't valid. Verify that you entered the correct ID and try again.")
}

impl Ssm {
    /// The parameter a tagging call names, authorized for `action`.
    fn tagged(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource_type: &str,
        id: &str,
        extra: ConditionContext,
    ) -> Result<(ParamRef, Parameter), ServiceError> {
        if resource_type != "Parameter" {
            return Err(invalid_id());
        }
        let r = ParamRef::parse(ctx, id).filter(|r| r.selector.is_none()).ok_or_else(invalid_id)?;
        let p = self.snapshot(ctx, &r);
        self.authorize_param(ctx, action, &r, p.as_ref(), extra)?;
        Ok((r, p.ok_or_else(invalid_id)?))
    }

    /// The tag map of a non-parameter resource, authorized for `action`.
    fn other_tags(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource_type: &str,
        id: &str,
        extra: ConditionContext,
        change: impl FnOnce(&mut BTreeMap<String, String>) -> Result<(), ServiceError>,
    ) -> Result<BTreeMap<String, String>, ServiceError> {
        let kind = match resource_type {
            "Document" => "document",
            "MaintenanceWindow" => "maintenancewindow",
            "PatchBaseline" => "patchbaseline",
            "Activation" => "activation",
            "Association" => "association",
            "OpsItem" => "opsitem",
            "OpsMetadata" => "opsmetadata",
            _ => return Err(errors::invalid_resource_type("The resource type isn't valid.")),
        };
        let arn = format!("arn:{}:ssm:{}:{}:{kind}/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
        let current = {
            let mut st = self.lock();
            let r = st.region(&ctx.caller.account_id, &ctx.region);
            Self::tag_map(r, resource_type, id).map(|m| m.clone())
        };
        let mut cond = extra;
        if let Some(t) = &current {
            cond.extend(resource_tag_conditions(t));
        }
        ctx.authorize(&format!("ssm:{action}"), &arn, cond)?;
        let mut tags = current.ok_or_else(invalid_id)?;
        change(&mut tags)?;
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let m = Self::tag_map(r, resource_type, id).ok_or_else(invalid_id)?;
        *m = tags.clone();
        if resource_type == "Activation" {
            if let Some(a) = r.activations.get_mut(id) {
                a.activation.tags =
                    Some(tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect());
            }
        }
        Ok(tags)
    }

    fn tag_map<'a>(
        r: &'a mut crate::state::Region,
        resource_type: &str,
        id: &str,
    ) -> Option<&'a mut BTreeMap<String, String>> {
        match resource_type {
            "Document" => r.documents.get_mut(id).map(|d| &mut d.tags),
            "MaintenanceWindow" => Self::window_tags_mut(r, id),
            "PatchBaseline" => Self::baseline_tags_mut(r, id),
            "Activation" => r.activations.get_mut(id).map(|a| &mut a.tags),
            "Association" => Self::association_tags_mut(r, id),
            "OpsItem" => Self::ops_item_tags_mut(r, id),
            "OpsMetadata" => Self::ops_metadata_tags_mut(r, id),
            _ => None,
        }
    }

    pub(crate) fn add_tags_to_resource(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsToResourceRequest,
    ) -> Result<types::AddTagsToResourceResult, ServiceError> {
        let tags: Vec<(String, String)> = input.tags.into_iter().map(|t| (t.key, t.value)).collect();
        let cond = request_tag_conditions(tags.iter().map(|(k, v)| (k, v)));
        if let Some((k, _)) = tags.iter().find(|(k, _)| k.to_ascii_lowercase().starts_with("aws:")) {
            return Err(errors::invalid_parameters(format!(
                "Tag keys can't start with the reserved prefix aws: ({k})."
            )));
        }
        if input.resource_type != "Parameter" {
            self.other_tags(ctx, "AddTagsToResource", &input.resource_type, &input.resource_id, cond, |m| {
                let mut merged = m.clone();
                merged.extend(tags);
                if merged.len() > MAX_TAGS {
                    return Err(errors::too_many_tags_error(
                        "The Targets parameter includes too many tags. Remove one or more tags and try the command again.",
                    ));
                }
                *m = merged;
                Ok(())
            })?;
            return Ok(types::AddTagsToResourceResult::default());
        }
        let (r, _) = self.tagged(ctx, "AddTagsToResource", &input.resource_type, &input.resource_id, cond)?;
        let mut st = self.lock();
        let p = st.region(&r.account, &r.region).parameters.get_mut(&r.key()).ok_or_else(invalid_id)?;
        let mut merged = p.tags.clone();
        merged.extend(tags);
        if merged.len() > MAX_TAGS {
            return Err(errors::too_many_tags_error(
                "The Targets parameter includes too many tags. Remove one or more tags and try the command again.",
            ));
        }
        p.tags = merged;
        Ok(types::AddTagsToResourceResult::default())
    }

    pub(crate) fn remove_tags_from_resource(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTagsFromResourceRequest,
    ) -> Result<types::RemoveTagsFromResourceResult, ServiceError> {
        let mut cond = ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        if input.resource_type != "Parameter" {
            let keys = input.tag_keys.clone();
            self.other_tags(ctx, "RemoveTagsFromResource", &input.resource_type, &input.resource_id, cond, |m| {
                for k in &keys {
                    m.remove(k);
                }
                Ok(())
            })?;
            return Ok(types::RemoveTagsFromResourceResult::default());
        }
        let (r, _) = self.tagged(ctx, "RemoveTagsFromResource", &input.resource_type, &input.resource_id, cond)?;
        let mut st = self.lock();
        let p = st.region(&r.account, &r.region).parameters.get_mut(&r.key()).ok_or_else(invalid_id)?;
        for k in &input.tag_keys {
            p.tags.remove(k);
        }
        Ok(types::RemoveTagsFromResourceResult::default())
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResult, ServiceError> {
        if input.resource_type != "Parameter" {
            let tags = self.other_tags(
                ctx,
                "ListTagsForResource",
                &input.resource_type,
                &input.resource_id,
                ConditionContext::new(),
                |_| Ok(()),
            )?;
            let tags = tags.into_iter().map(|(key, value)| types::Tag { key, value }).collect();
            return Ok(types::ListTagsForResourceResult { tag_list: Some(tags) });
        }
        let (_, p) =
            self.tagged(ctx, "ListTagsForResource", &input.resource_type, &input.resource_id, ConditionContext::new())?;
        let tags = p.tags.into_iter().map(|(key, value)| types::Tag { key, value }).collect();
        Ok(types::ListTagsForResourceResult { tag_list: Some(tags) })
    }
}
