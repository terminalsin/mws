//! `AddTagsToResource`, `RemoveTagsFromResource` and `ListTagsForResource`
//! for parameters. Other SSM resource types don't exist in MWS.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{request_tag_conditions, ParamRef};
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

    pub(crate) fn add_tags_to_resource(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsToResourceRequest,
    ) -> Result<types::AddTagsToResourceResult, ServiceError> {
        let tags: Vec<(String, String)> = input.tags.into_iter().map(|t| (t.key, t.value)).collect();
        let cond = request_tag_conditions(tags.iter().map(|(k, v)| (k, v)));
        let (r, _) = self.tagged(ctx, "AddTagsToResource", &input.resource_type, &input.resource_id, cond)?;
        if let Some((k, _)) = tags.iter().find(|(k, _)| k.to_ascii_lowercase().starts_with("aws:")) {
            return Err(errors::invalid_parameters(format!(
                "Tag keys can't start with the reserved prefix aws: ({k})."
            )));
        }
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
        let (_, p) =
            self.tagged(ctx, "ListTagsForResource", &input.resource_type, &input.resource_id, ConditionContext::new())?;
        let tags = p.tags.into_iter().map(|(key, value)| types::Tag { key, value }).collect();
        Ok(types::ListTagsForResourceResult { tag_list: Some(tags) })
    }
}
