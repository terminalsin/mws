//! TagResource, UntagResource and ListTagsForResource.

use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::types;
use crate::state::State;
use crate::GuardDuty;

const MAX_TAGS: usize = 50;

/// The tags of the resource `arn` names in `state`.
fn tags_mut<'s>(state: &'s mut State, ctx: &RequestContext, arn: &str) -> Option<&'s mut Tags> {
    let mut parts = arn.splitn(6, ':');
    let (Some("arn"), Some(partition), Some("guardduty"), Some(region), Some(account), Some(resource)) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if partition != ctx.partition || region != ctx.region || account != ctx.caller.account_id {
        return None;
    }
    let segs: Vec<&str> = resource.split('/').collect();
    if segs.first() == Some(&"malware-protection-plan") && segs.len() == 2 {
        return state
            .accounts
            .get_mut(&State::key(account, region))?
            .malware_plans
            .get_mut(segs[1])
            .map(|p| &mut p.tags);
    }
    if segs.first() != Some(&"detector") || segs.len() < 2 {
        return None;
    }
    let det = state.detector_mut(account, region).filter(|d| d.id == segs[1])?;
    match segs.as_slice() {
        [_, _] => Some(&mut det.tags),
        [_, _, "filter", name] => det.filters.get_mut(*name).map(|f| &mut f.tags),
        [_, _, "ipset", id] => det.ip_sets.get_mut(*id).map(|l| &mut l.tags),
        [_, _, "threatintelset", id] => det.threat_intel_sets.get_mut(*id).map(|l| &mut l.tags),
        [_, _, "threatentityset", id] => det.threat_entity_sets.get_mut(*id).map(|l| &mut l.tags),
        [_, _, "trustedentityset", id] => det.trusted_entity_sets.get_mut(*id).map(|l| &mut l.tags),
        [_, _, "publishingDestination", id] => det.destinations.get_mut(*id).map(|d| &mut d.tags),
        _ => None,
    }
}

fn bad_arn() -> ServiceError {
    invalid_input("The request is rejected because the resource ARN is invalid.")
}

impl GuardDuty {
    fn current_tags(&self, ctx: &RequestContext, arn: &str) -> Result<Tags, ServiceError> {
        let mut state = self.lock();
        tags_mut(&mut state, ctx, arn).cloned().ok_or_else(bad_arn)
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        validate_tags(&input.tags)?;
        let existing = self.current_tags(ctx, &input.resource_arn)?;
        let mut cond = resource_tag_context(&existing);
        cond.extend(request_tag_context(Some(&input.tags)));
        self.authorize(ctx, "TagResource", &input.resource_arn, cond)?;
        let mut state = self.lock();
        let tags = tags_mut(&mut state, ctx, &input.resource_arn).ok_or_else(bad_arn)?;
        let mut merged = tags.clone();
        merged.extend(input.tags);
        if merged.len() > MAX_TAGS {
            return Err(invalid_input(format!(
                "The request is rejected because a resource can have at most {MAX_TAGS} tags."
            )));
        }
        *tags = merged;
        Ok(Default::default())
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let existing = self.current_tags(ctx, &input.resource_arn)?;
        let mut cond = resource_tag_context(&existing);
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize(ctx, "UntagResource", &input.resource_arn, cond)?;
        let mut state = self.lock();
        let tags = tags_mut(&mut state, ctx, &input.resource_arn).ok_or_else(bad_arn)?;
        for k in &input.tag_keys {
            tags.remove(k);
        }
        Ok(Default::default())
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let existing = self.current_tags(ctx, &input.resource_arn)?;
        self.authorize(ctx, "ListTagsForResource", &input.resource_arn, resource_tag_context(&existing))?;
        Ok(types::ListTagsForResourceResponse { tags: Some(existing) })
    }
}
