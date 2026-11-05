//! Tags on any Image Builder resource.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::Region;
use crate::util::{account_of, authorize, invalid_parameter, merge, not_found, request_tags, resource_tags, Arn};
use crate::ImageBuilder;

/// The tags of the resource `arn` names in `r`.
fn tags_of<'a>(r: &'a mut Region, arn: &str, kind: &str) -> Option<&'a mut Option<BTreeMap<String, String>>> {
    Some(match kind {
        "component" => &mut r.components.get_mut(arn)?.resource.tags,
        "image-recipe" => &mut r.image_recipes.get_mut(arn)?.resource.tags,
        "container-recipe" => &mut r.container_recipes.get_mut(arn)?.resource.tags,
        "infrastructure-configuration" => &mut r.infrastructure.get_mut(arn)?.tags,
        "distribution-configuration" => &mut r.distributions.get_mut(arn)?.tags,
        "image-pipeline" => &mut r.pipelines.get_mut(arn)?.pipeline.tags,
        "image" => &mut r.images.get_mut(arn)?.image.tags,
        "lifecycle-policy" => &mut r.lifecycle_policies.get_mut(arn)?.tags,
        k if k.starts_with("workflow/") => &mut r.workflows.get_mut(arn)?.tags,
        _ => return None,
    })
}

impl ImageBuilder {
    fn with_tags<R>(
        &self,
        ctx: &RequestContext,
        arn: &str,
        f: impl FnOnce(&mut Option<BTreeMap<String, String>>) -> R,
    ) -> Result<R, ServiceError> {
        let a = Arn::parse(arn).ok_or_else(|| invalid_parameter(format!("The resource ARN '{arn}' is not valid.")))?;
        if a.account != account_of(ctx) || a.region != ctx.region {
            return Err(not_found(format!("The resource '{arn}' does not exist.")));
        }
        let kind = a.kind.clone();
        self.with_region(ctx, |r| tags_of(r, arn, &kind).map(f))
            .ok_or_else(|| not_found(format!("The resource '{arn}' does not exist.")))
    }

    pub(crate) fn tag_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::TagResourceRequest,
    ) -> Result<t::TagResourceResponse, ServiceError> {
        let existing = self.with_tags(ctx, &input.resource_arn, |t| t.clone()).ok().flatten();
        authorize(
            ctx,
            "TagResource",
            &input.resource_arn,
            merge(resource_tags(&existing), request_tags(&Some(input.tags.clone()))),
        )?;
        self.with_tags(ctx, &input.resource_arn, |t| t.get_or_insert_with(BTreeMap::new).extend(input.tags.clone()))?;
        Ok(t::TagResourceResponse {})
    }

    pub(crate) fn untag_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::UntagResourceRequest,
    ) -> Result<t::UntagResourceResponse, ServiceError> {
        let existing = self.with_tags(ctx, &input.resource_arn, |t| t.clone()).ok().flatten();
        let mut c = resource_tags(&existing);
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize(ctx, "UntagResource", &input.resource_arn, c)?;
        self.with_tags(ctx, &input.resource_arn, |t| {
            if let Some(map) = t {
                for k in &input.tag_keys {
                    map.remove(k);
                }
            }
        })?;
        Ok(t::UntagResourceResponse {})
    }

    pub(crate) fn list_tags_for_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::ListTagsForResourceRequest,
    ) -> Result<t::ListTagsForResourceResponse, ServiceError> {
        let existing = self.with_tags(ctx, &input.resource_arn, |t| t.clone());
        authorize(ctx, "ListTagsForResource", &input.resource_arn, resource_tags(&existing.clone().ok().flatten()))?;
        Ok(t::ListTagsForResourceResponse { tags: Some(existing?.unwrap_or_default()) })
    }
}
