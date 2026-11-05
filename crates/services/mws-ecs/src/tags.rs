//! TagResource, UntagResource and ListTagsForResource over every ECS
//! resource that takes tags.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types as t};
use crate::names::{authorize, check_tags, invalid, request_tags, resource_tags, split_arn, Cond, Scope};
use crate::state::Region;
use crate::Ecs;

/// Whether `arn` names a resource that exists in `r`.
fn exists(r: &Region, arn: &str) -> bool {
    let Some((_, _, resource)) = split_arn(arn) else { return false };
    let kind = resource.split('/').next().unwrap_or_default();
    match kind {
        "cluster" => {
            let name = &resource["cluster/".len()..];
            r.clusters.get(name).is_some_and(|c| c.status.as_deref() != Some("INACTIVE"))
        }
        "service" => r.services.contains_key(arn),
        "task" => r.tasks.contains_key(arn),
        "container-instance" => r.container_instances.contains_key(arn),
        "task-definition" => r
            .task_definitions
            .values()
            .flatten()
            .any(|d| d.task_definition_arn.as_deref() == Some(arn) && d.status.as_deref() != Some("DELETE_IN_PROGRESS")),
        "capacity-provider" => r.capacity_providers.values().any(|c| c.capacity_provider_arn.as_deref() == Some(arn)),
        "task-set" => r.services.values().any(|s| {
            s.service.task_sets.iter().flatten().any(|ts| ts.task_set_arn.as_deref() == Some(arn))
        }),
        "daemon" => r.daemons.contains_key(arn),
        "daemon-task-definition" => r
            .daemon_task_definitions
            .values()
            .flatten()
            .any(|d| d.daemon_task_definition_arn.as_deref() == Some(arn)),
        "gateway" => r.gateways.contains_key(arn),
        _ => r.express_services.contains_key(arn),
    }
}

impl Ecs {
    fn check_tag_target(&self, ctx: &RequestContext, arn: &str) -> Result<(), ServiceError> {
        let Some((region, account, _)) = split_arn(arn) else {
            return Err(invalid("The ARN provided is invalid."));
        };
        let scope = Scope::of(ctx);
        if region != scope.region || account != scope.account {
            return Err(invalid("The ARN provided is invalid."));
        }
        Ok(())
    }

    pub(crate) fn tag_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::TagResourceRequest,
    ) -> Result<t::TagResourceResponse, ServiceError> {
        self.check_tag_target(ctx, &input.resource_arn)?;
        check_tags(&input.tags)?;
        let current = self.with_region(ctx, |r, _| r.tags.get(&input.resource_arn).cloned());
        authorize(
            ctx,
            "TagResource",
            &input.resource_arn,
            Cond::new().extend(resource_tags(current.as_ref())).extend(request_tags(Some(&input.tags))),
        )?;
        self.with_region(ctx, |r, _| {
            if !exists(r, &input.resource_arn) {
                return Err(errors::resource_not_found("The specified resource could not be found."));
            }
            let tags = r.tags.entry(input.resource_arn.clone()).or_default();
            for tag in input.tags {
                tags.retain(|t| t.key != tag.key);
                tags.push(tag);
            }
            if tags.len() > 50 {
                return Err(invalid("The number of tags on the resource exceeds the maximum of 50."));
            }
            Ok(t::TagResourceResponse {})
        })
    }

    pub(crate) fn untag_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::UntagResourceRequest,
    ) -> Result<t::UntagResourceResponse, ServiceError> {
        self.check_tag_target(ctx, &input.resource_arn)?;
        let current = self.with_region(ctx, |r, _| r.tags.get(&input.resource_arn).cloned());
        authorize(
            ctx,
            "UntagResource",
            &input.resource_arn,
            Cond::new().extend(resource_tags(current.as_ref())).with_list("aws:TagKeys", input.tag_keys.clone()),
        )?;
        self.with_region(ctx, |r, _| {
            if !exists(r, &input.resource_arn) {
                return Err(errors::resource_not_found("The specified resource could not be found."));
            }
            if let Some(tags) = r.tags.get_mut(&input.resource_arn) {
                tags.retain(|t| !input.tag_keys.contains(t.key.as_ref().unwrap_or(&String::new())));
            }
            Ok(t::UntagResourceResponse {})
        })
    }

    pub(crate) fn list_tags_for_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::ListTagsForResourceRequest,
    ) -> Result<t::ListTagsForResourceResponse, ServiceError> {
        self.check_tag_target(ctx, &input.resource_arn)?;
        let current = self.with_region(ctx, |r, _| r.tags.get(&input.resource_arn).cloned());
        authorize(ctx, "ListTagsForResource", &input.resource_arn, Cond::new().extend(resource_tags(current.as_ref())))?;
        self.with_region(ctx, |r, _| {
            if !exists(r, &input.resource_arn) {
                return Err(errors::resource_not_found("The specified resource could not be found."));
            }
            Ok(t::ListTagsForResourceResponse { tags: Some(r.tags.get(&input.resource_arn).cloned().unwrap_or_default()) })
        })
    }
}

/// Tags to store for a new resource (and its `aws:RequestTag` context).
pub fn store(r: &mut Region, arn: &str, tags: Option<&Vec<t::Tag>>) {
    if let Some(tags) = tags.filter(|t| !t.is_empty()) {
        r.tags.insert(arn.to_string(), tags.clone());
    }
}
