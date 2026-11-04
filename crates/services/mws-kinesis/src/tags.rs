//! Tags (the stream-named operations and the ARN-named ones, which also
//! cover consumers) and resource policies.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{
    authorize, authorize_stream, invalid_argument, request_tag_context, split_arn, validate_tags, StreamRef,
};
use crate::state::State;
use crate::Kinesis;

const TAG_LIMIT: usize = 50;

/// A taggable resource an ARN names.
enum Target {
    Stream(StreamRef),
    Consumer(String),
}

fn target(arn: &str) -> Result<Target, ServiceError> {
    let Some((_, _, _, resource)) = split_arn(arn) else {
        return Err(invalid_argument(format!("Invalid ResourceARN {arn}.")));
    };
    if resource.contains("/consumer/") {
        Ok(Target::Consumer(arn.to_string()))
    } else if resource.starts_with("stream/") {
        Ok(Target::Stream(StreamRef::from_arn(arn)?))
    } else {
        Err(invalid_argument(format!("Invalid ResourceARN {arn}.")))
    }
}

fn tags_mut<'a>(st: &'a mut State, t: &Target) -> Result<&'a mut BTreeMap<String, String>, ServiceError> {
    match t {
        Target::Stream(r) => Ok(&mut r.get_mut(st)?.tags),
        Target::Consumer(arn) => st
            .consumers
            .get_mut(arn)
            .map(|c| &mut c.tags)
            .ok_or_else(|| errors::resource_not_found(format!("Consumer {arn} not found."))),
    }
}

fn policy_mut<'a>(st: &'a mut State, t: &Target) -> Result<&'a mut Option<String>, ServiceError> {
    match t {
        Target::Stream(r) => Ok(&mut r.get_mut(st)?.policy),
        Target::Consumer(arn) => st
            .consumers
            .get_mut(arn)
            .map(|c| &mut c.policy)
            .ok_or_else(|| errors::resource_not_found(format!("Consumer {arn} not found."))),
    }
}

/// Authorize an action on a stream or consumer by ARN.
fn authorize_target(
    ctx: &RequestContext,
    st: &State,
    action: &str,
    arn: &str,
    t: &Target,
    extra: ConditionContext,
) -> Result<(), ServiceError> {
    match t {
        Target::Stream(r) => authorize_stream(ctx, st, action, r, extra),
        Target::Consumer(c) => {
            let (policy, tags) = st.consumers.get(c).map(|c| (c.policy.clone(), c.tags.clone())).unwrap_or_default();
            authorize(ctx, &format!("kinesis:{action}"), arn, policy.as_deref(), &tags, extra)
        }
    }
}

fn add(tags: &mut BTreeMap<String, String>, new: BTreeMap<String, String>, name: &str) -> Result<(), ServiceError> {
    let mut merged = tags.clone();
    merged.extend(new);
    if merged.len() > TAG_LIMIT {
        return Err(invalid_argument(format!(
            "Failed to add tags to {name} because a given resource cannot have more than {TAG_LIMIT} tags associated with it."
        )));
    }
    *tags = merged;
    Ok(())
}

fn sorted_tags(tags: &BTreeMap<String, String>) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: Some(v.clone()) }).collect()
}

impl Kinesis {
    pub fn add_tags_to_stream(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsToStreamInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "AddTagsToStream", &r, request_tag_context(&input.tags))?;
        validate_tags(&input.tags)?;
        let s = r.get_mut(&mut st)?;
        let name = format!("stream {} under account {}", s.name, s.account);
        add(&mut s.tags, input.tags, &name)
    }

    pub fn remove_tags_from_stream(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTagsFromStreamInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        let mut extra = ConditionContext::new();
        extra.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize_stream(ctx, &st, "RemoveTagsFromStream", &r, extra)?;
        let s = r.get_mut(&mut st)?;
        for k in &input.tag_keys {
            s.tags.remove(k);
        }
        Ok(())
    }

    pub fn list_tags_for_stream(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForStreamInput,
    ) -> Result<types::ListTagsForStreamOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let st = self.settled(ctx);
        authorize_stream(ctx, &st, "ListTagsForStream", &r, ConditionContext::new())?;
        let s = r.get(&st)?;
        let after = input.exclusive_start_tag_key.as_deref();
        let all: Vec<types::Tag> =
            sorted_tags(&s.tags).into_iter().filter(|t| after.is_none_or(|a| t.key.as_str() > a)).collect();
        let limit = input.limit.unwrap_or(50).clamp(1, 50) as usize;
        let more = all.len() > limit;
        Ok(types::ListTagsForStreamOutput { tags: all.into_iter().take(limit).collect(), has_more_tags: more })
    }

    pub fn tag_resource(&self, ctx: &RequestContext, input: types::TagResourceInput) -> Result<(), ServiceError> {
        let t = target(&input.resource_arn)?;
        let mut st = self.settled(ctx);
        authorize_target(ctx, &st, "TagResource", &input.resource_arn, &t, request_tag_context(&input.tags))?;
        validate_tags(&input.tags)?;
        let name = input.resource_arn.clone();
        add(tags_mut(&mut st, &t)?, input.tags, &name)
    }

    pub fn untag_resource(&self, ctx: &RequestContext, input: types::UntagResourceInput) -> Result<(), ServiceError> {
        let t = target(&input.resource_arn)?;
        let mut st = self.settled(ctx);
        let mut extra = ConditionContext::new();
        extra.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize_target(ctx, &st, "UntagResource", &input.resource_arn, &t, extra)?;
        let tags = tags_mut(&mut st, &t)?;
        for k in &input.tag_keys {
            tags.remove(k);
        }
        Ok(())
    }

    pub fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceInput,
    ) -> Result<types::ListTagsForResourceOutput, ServiceError> {
        let t = target(&input.resource_arn)?;
        let mut st = self.settled(ctx);
        authorize_target(ctx, &st, "ListTagsForResource", &input.resource_arn, &t, ConditionContext::new())?;
        let tags = tags_mut(&mut st, &t)?;
        Ok(types::ListTagsForResourceOutput { tags: Some(sorted_tags(tags)) })
    }

    pub fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyInput,
    ) -> Result<(), ServiceError> {
        let t = target(&input.resource_arn)?;
        let mut st = self.settled(ctx);
        authorize_target(ctx, &st, "PutResourcePolicy", &input.resource_arn, &t, ConditionContext::new())?;
        let parsed = mws_iam_policy::Policy::parse(&input.policy, mws_iam_policy::PolicyKind::Resource)
            .map_err(|e| invalid_argument(format!("Invalid policy: {}", e.0)))?;
        let _ = parsed;
        *policy_mut(&mut st, &t)? = Some(input.policy);
        Ok(())
    }

    pub fn get_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePolicyInput,
    ) -> Result<types::GetResourcePolicyOutput, ServiceError> {
        let t = target(&input.resource_arn)?;
        let mut st = self.settled(ctx);
        authorize_target(ctx, &st, "GetResourcePolicy", &input.resource_arn, &t, ConditionContext::new())?;
        let policy = policy_mut(&mut st, &t)?.clone().unwrap_or_else(|| "{}".into());
        Ok(types::GetResourcePolicyOutput { policy })
    }

    pub fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyInput,
    ) -> Result<(), ServiceError> {
        let t = target(&input.resource_arn)?;
        let mut st = self.settled(ctx);
        authorize_target(ctx, &st, "DeleteResourcePolicy", &input.resource_arn, &t, ConditionContext::new())?;
        let policy = policy_mut(&mut st, &t)?;
        if policy.is_none() {
            return Err(errors::resource_not_found(format!(
                "No resource policy found for resource ARN {}.",
                input.resource_arn
            )));
        }
        *policy = None;
        Ok(())
    }
}
