//! Tags and resource policies, which apply to trails, event data stores,
//! channels and dashboards alike.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::parse_arn;
use crate::state::State;
use crate::CloudTrail;

const MAX_TAGS: usize = 50;

pub fn check_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    if tags.len() > MAX_TAGS {
        return Err(too_many_tags());
    }
    for t in tags {
        if t.key.is_empty() || t.key.chars().count() > 128 {
            return Err(errors::invalid_tag_parameter("Tag key must be between 1 and 128 characters."));
        }
        if t.key.starts_with("aws:") {
            return Err(errors::invalid_tag_parameter("Tag keys cannot start with the aws: prefix."));
        }
        if t.value.as_deref().is_some_and(|v| v.chars().count() > 256) {
            return Err(errors::invalid_tag_parameter("Tag value cannot be longer than 256 characters."));
        }
    }
    Ok(())
}

fn too_many_tags() -> ServiceError {
    errors::tags_limit_exceeded(
        "The number of tags per trail, event data store, dashboard, or channel has exceeded the permitted amount. Currently, the limit is 50.",
    )
}

/// `existing` with `new` added (a key already present takes the new value).
pub fn merge_tags(existing: &[types::Tag], new: &[types::Tag]) -> Result<Vec<types::Tag>, ServiceError> {
    check_tags(new)?;
    let mut out = existing.to_vec();
    for t in new {
        match out.iter_mut().find(|o| o.key == t.key) {
            Some(o) => o.value = t.value.clone(),
            None => out.push(t.clone()),
        }
    }
    if out.len() > MAX_TAGS {
        return Err(too_many_tags());
    }
    Ok(out)
}

/// Which kind of resource an ARN names, refusing ARNs that are not
/// CloudTrail's.
fn kind_of(id: &str) -> Result<String, ServiceError> {
    if !id.starts_with("arn:") {
        // A bare trail name.
        return Ok("trail".into());
    }
    let arn = parse_arn(id).ok_or_else(|| errors::cloud_trail_arn_invalid(format!("Invalid ARN: {id}")))?;
    match arn.kind.as_str() {
        "trail" | "eventdatastore" | "channel" | "dashboard" => Ok(arn.kind),
        _ => Err(errors::resource_type_not_supported(format!("Resource type {} is not supported.", arn.kind))),
    }
}

impl CloudTrail {
    fn tags_mut<'a>(
        &self,
        st: &'a mut State,
        ctx: &RequestContext,
        id: &str,
    ) -> Result<&'a mut Vec<types::Tag>, ServiceError> {
        let account = &ctx.caller.account_id;
        match kind_of(id)?.as_str() {
            "trail" => self.trail_tags_mut(st, ctx, id),
            "eventdatastore" => {
                let eds =
                    st.accounts.get_mut(account).and_then(|a| a.event_data_stores.get_mut(id)).ok_or_else(|| {
                        errors::event_data_store_not_found(format!("The event data store {id} was not found."))
                    })?;
                if eds.status == "PENDING_DELETION" {
                    return Err(errors::inactive_event_data_store(format!(
                        "Event data store {id} is in PENDING_DELETION status."
                    )));
                }
                Ok(&mut eds.tags)
            }
            "channel" => st
                .accounts
                .get_mut(account)
                .and_then(|a| a.channels.get_mut(id))
                .map(|c| &mut c.tags)
                .ok_or_else(|| errors::channel_not_found(format!("Channel {id} was not found."))),
            _ => st
                .accounts
                .get_mut(account)
                .and_then(|a| a.dashboards.get_mut(id))
                .map(|d| &mut d.tags)
                .ok_or_else(|| errors::resource_not_found(format!("Dashboard {id} was not found."))),
        }
    }

    fn resource_arn(&self, st: &State, ctx: &RequestContext, id: &str) -> Result<String, ServiceError> {
        if id.starts_with("arn:") {
            Ok(id.to_string())
        } else {
            Ok(self.find_trail(st, ctx, id)?.1)
        }
    }

    pub(crate) fn add_tags(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsRequest,
    ) -> Result<types::AddTagsResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.resource_arn(&st, ctx, &input.resource_id)?;
        ctx.authorize("cloudtrail:AddTags", &arn, ConditionContext::new())?;
        let tags = self.tags_mut(&mut st, ctx, &input.resource_id)?;
        *tags = merge_tags(tags, &input.tags_list)?;
        Ok(types::AddTagsResponse {})
    }

    pub(crate) fn remove_tags(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTagsRequest,
    ) -> Result<types::RemoveTagsResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.resource_arn(&st, ctx, &input.resource_id)?;
        ctx.authorize("cloudtrail:RemoveTags", &arn, ConditionContext::new())?;
        let tags = self.tags_mut(&mut st, ctx, &input.resource_id)?;
        // A tag with a value is removed only when the value matches.
        tags.retain(|t| !input.tags_list.iter().any(|r| r.key == t.key && (r.value.is_none() || r.value == t.value)));
        Ok(types::RemoveTagsResponse {})
    }

    pub(crate) fn list_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsRequest,
    ) -> Result<types::ListTagsResponse, ServiceError> {
        if input.resource_id_list.len() > 20 {
            return Err(errors::invalid_parameter("You can specify at most 20 resources."));
        }
        let mut st = self.lock();
        let mut out = Vec::new();
        for id in &input.resource_id_list {
            let arn = self.resource_arn(&st, ctx, id)?;
            ctx.authorize("cloudtrail:ListTags", &arn, ConditionContext::new())?;
            let tags = if kind_of(id)? == "trail" {
                self.trail_tags(&st, ctx, id)?
            } else {
                self.tags_mut(&mut st, ctx, id)?.clone()
            };
            out.push(types::ResourceTag { resource_id: Some(arn), tags_list: Some(tags) });
        }
        Ok(types::ListTagsResponse { resource_tag_list: Some(out), next_token: None })
    }

    /// Check that a resource policy may be attached to `arn`, and that the
    /// resource exists.
    fn policy_target(&self, st: &State, ctx: &RequestContext, arn: &str) -> Result<(), ServiceError> {
        let parsed = parse_arn(arn)
            .ok_or_else(|| errors::resource_arn_not_valid(format!("Resource ARN {arn} is not valid.")))?;
        let account = &ctx.caller.account_id;
        let a = st.accounts.get(account);
        let exists = match parsed.kind.as_str() {
            "eventdatastore" => a.is_some_and(|a| a.event_data_stores.contains_key(arn)),
            "channel" => a.is_some_and(|a| a.channels.contains_key(arn)),
            "dashboard" => a.is_some_and(|a| a.dashboards.contains_key(arn)),
            other => {
                return Err(errors::resource_type_not_supported(format!(
                    "Resource type {other} is not supported for resource-based policies."
                )))
            }
        };
        if exists {
            Ok(())
        } else {
            Err(errors::resource_not_found(format!("The resource {arn} was not found.")))
        }
    }

    pub(crate) fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        let mut st = self.lock();
        self.policy_target(&st, ctx, &input.resource_arn)?;
        ctx.authorize("cloudtrail:PutResourcePolicy", &input.resource_arn, ConditionContext::new())?;
        mws_iam_policy::Policy::parse(&input.resource_policy, mws_iam_policy::PolicyKind::Resource)
            .map_err(|e| errors::resource_policy_not_valid(format!("Resource policy is not valid: {}", e.0)))?;
        st.account(&ctx.caller.account_id)
            .resource_policies
            .insert(input.resource_arn.clone(), input.resource_policy.clone());
        Ok(types::PutResourcePolicyResponse {
            resource_arn: Some(input.resource_arn),
            resource_policy: Some(input.resource_policy),
            delegated_admin_resource_policy: None,
        })
    }

    pub(crate) fn get_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePolicyRequest,
    ) -> Result<types::GetResourcePolicyResponse, ServiceError> {
        let st = self.lock();
        self.policy_target(&st, ctx, &input.resource_arn)?;
        ctx.authorize("cloudtrail:GetResourcePolicy", &input.resource_arn, ConditionContext::new())?;
        let policy = st
            .accounts
            .get(&ctx.caller.account_id)
            .and_then(|a| a.resource_policies.get(&input.resource_arn))
            .cloned()
            .ok_or_else(|| {
                errors::resource_policy_not_found(format!(
                    "The resource policy for resource {} was not found.",
                    input.resource_arn
                ))
            })?;
        Ok(types::GetResourcePolicyResponse {
            resource_arn: Some(input.resource_arn),
            resource_policy: Some(policy),
            delegated_admin_resource_policy: None,
        })
    }

    pub(crate) fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyRequest,
    ) -> Result<types::DeleteResourcePolicyResponse, ServiceError> {
        let mut st = self.lock();
        self.policy_target(&st, ctx, &input.resource_arn)?;
        ctx.authorize("cloudtrail:DeleteResourcePolicy", &input.resource_arn, ConditionContext::new())?;
        st.account(&ctx.caller.account_id).resource_policies.remove(&input.resource_arn).ok_or_else(|| {
            errors::resource_policy_not_found(format!(
                "The resource policy for resource {} was not found.",
                input.resource_arn
            ))
        })?;
        Ok(types::DeleteResourcePolicyResponse {})
    }
}
