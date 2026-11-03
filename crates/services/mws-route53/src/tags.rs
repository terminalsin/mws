//! Tags on hosted zones and health checks.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::health::no_such_health_check;
use crate::state::State;
use crate::zones::no_such_zone;
use crate::{arn, strip_id, Route53};

const MAX_TAGS: usize = 50;

fn tag_map<'a>(st: &'a mut State, kind: &str, id: &str) -> Result<&'a mut BTreeMap<String, String>, ServiceError> {
    match kind {
        "hostedzone" => st.zones.get_mut(id).map(|z| &mut z.tags).ok_or_else(|| no_such_zone(id)),
        "healthcheck" => st.health_checks.get_mut(id).map(|h| &mut h.tags).ok_or_else(|| no_such_health_check(id)),
        other => Err(errors::invalid_input(format!("Invalid resource type: {other}"))),
    }
}

fn tag_set(kind: &str, id: &str, tags: &BTreeMap<String, String>) -> types::ResourceTagSet {
    types::ResourceTagSet {
        resource_type: Some(kind.to_string()),
        resource_id: Some(id.to_string()),
        tags: Some(tags.iter().map(|(k, v)| types::Tag { key: Some(k.clone()), value: Some(v.clone()) }).collect()),
    }
}

impl Route53 {
    pub(crate) fn change_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ChangeTagsForResourceRequest,
    ) -> Result<types::ChangeTagsForResourceResponse, ServiceError> {
        let id = strip_id(&input.resource_id);
        self.authorize(ctx, "ChangeTagsForResource", &arn(ctx, &input.resource_type, id))?;
        let mut st = self.lock();
        let tags = tag_map(&mut st, &input.resource_type, id)?;
        let mut next = tags.clone();
        for k in input.remove_tag_keys.iter().flatten() {
            next.remove(k);
        }
        for t in input.add_tags.iter().flatten() {
            let Some(k) = &t.key else {
                return Err(errors::invalid_input("Invalid request: Tag key must be specified"));
            };
            next.insert(k.clone(), t.value.clone().unwrap_or_default());
        }
        if next.len() > MAX_TAGS {
            return Err(errors::invalid_input(format!(
                "Invalid request: The number of tags exceeds the limit of {MAX_TAGS} for the resource"
            )));
        }
        *tags = next;
        Ok(types::ChangeTagsForResourceResponse {})
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let id = strip_id(&input.resource_id);
        self.authorize(ctx, "ListTagsForResource", &arn(ctx, &input.resource_type, id))?;
        let mut st = self.lock();
        let tags = tag_map(&mut st, &input.resource_type, id)?;
        Ok(types::ListTagsForResourceResponse { resource_tag_set: tag_set(&input.resource_type, id, tags) })
    }

    pub(crate) fn list_tags_for_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourcesRequest,
    ) -> Result<types::ListTagsForResourcesResponse, ServiceError> {
        let ids: Vec<String> = input.resource_ids.iter().map(|i| strip_id(i).to_string()).collect();
        for id in &ids {
            self.authorize(ctx, "ListTagsForResources", &arn(ctx, &input.resource_type, id))?;
        }
        let mut st = self.lock();
        let mut sets = Vec::new();
        for id in &ids {
            let tags = tag_map(&mut st, &input.resource_type, id)?;
            sets.push(tag_set(&input.resource_type, id, tags));
        }
        Ok(types::ListTagsForResourcesResponse { resource_tag_sets: sets })
    }
}
