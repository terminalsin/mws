//! Resource policies on advanced parameters (`PutResourcePolicy`,
//! `GetResourcePolicies`, `DeleteResourcePolicy`). A policy lets the
//! accounts it names read the parameter by ARN; IAM evaluates it together
//! with the caller's own identity policies for cross-account access.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::ParamRef;
use crate::state::{Parameter, ResourcePolicy};
use crate::Ssm;

fn hash(policy: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, policy.as_bytes());
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

impl Ssm {
    /// The parameter a resource policy call names, authorized for `action`.
    fn policy_target(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
    ) -> Result<(ParamRef, Parameter), ServiceError> {
        let r = ParamRef::parse(ctx, arn).filter(|r| r.by_arn && r.selector.is_none()).ok_or_else(|| {
            errors::resource_policy_invalid_parameter_with_parameter_names(
                format!("{arn} is not a valid resource ARN for a resource policy."),
                vec!["ResourceArn".into()],
            )
        })?;
        let p = self.snapshot(ctx, &r);
        self.authorize_param(ctx, action, &r, p.as_ref(), ConditionContext::new())?;
        if r.account != ctx.caller.account_id || r.region != ctx.region {
            return Err(errors::resource_not_found(format!("The resource {arn} doesn't exist.")));
        }
        let p = p.ok_or_else(|| errors::resource_not_found(format!("The resource {arn} doesn't exist.")))?;
        Ok((r, p))
    }

    pub(crate) fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        let (r, p) = self.policy_target(ctx, "PutResourcePolicy", &input.resource_arn)?;
        if p.latest().tier != "Advanced" {
            return Err(errors::resource_policy_invalid_parameter_with_parameter_names(
                "Only advanced-tier parameters can be shared. Change the parameter to the advanced tier, and try again.",
                vec!["ResourceArn".into()],
            ));
        }
        let doc: serde_json::Value = serde_json::from_str(&input.policy)
            .map_err(|_| errors::malformed_resource_policy_document("The policy document isn't valid JSON."))?;
        if !doc.get("Statement").is_some_and(|s| s.is_array() || s.is_object()) {
            return Err(errors::malformed_resource_policy_document("The policy document must contain a Statement."));
        }
        let new_hash = hash(&input.policy);
        let mut st = self.lock();
        let p =
            st.region(&r.account, &r.region).parameters.get_mut(&r.key()).ok_or_else(|| {
                errors::resource_not_found(format!("The resource {} doesn't exist.", input.resource_arn))
            })?;
        let id = match &input.policy_id {
            Some(id) => {
                let existing = p
                    .resource_policies
                    .iter_mut()
                    .find(|x| &x.id == id)
                    .ok_or_else(|| errors::resource_policy_not_found(format!("The policy {id} wasn't found.")))?;
                if input.policy_hash.as_deref() != Some(existing.hash.as_str()) {
                    return Err(errors::resource_policy_conflict(
                        "The PolicyHash doesn't match the current policy. Get the latest policy, and try again.",
                    ));
                }
                existing.policy = input.policy;
                existing.hash = new_hash.clone();
                id.clone()
            }
            None => {
                let id = uuid::Uuid::new_v4().to_string();
                p.resource_policies.push(ResourcePolicy {
                    id: id.clone(),
                    hash: new_hash.clone(),
                    policy: input.policy,
                });
                id
            }
        };
        Ok(types::PutResourcePolicyResponse { policy_id: Some(id), policy_hash: Some(new_hash) })
    }

    pub(crate) fn get_resource_policies(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePoliciesRequest,
    ) -> Result<types::GetResourcePoliciesResponse, ServiceError> {
        let (_, p) = self.policy_target(ctx, "GetResourcePolicies", &input.resource_arn)?;
        let entries: Vec<_> = p
            .resource_policies
            .into_iter()
            .map(|x| types::GetResourcePoliciesResponseEntry {
                policy_id: Some(x.id),
                policy_hash: Some(x.hash),
                policy: Some(x.policy),
            })
            .collect();
        let (page, next) =
            crate::names::page(entries, input.next_token.as_deref(), input.max_results.unwrap_or(50) as usize)?;
        Ok(types::GetResourcePoliciesResponse { next_token: next, policies: Some(page) })
    }

    pub(crate) fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyRequest,
    ) -> Result<types::DeleteResourcePolicyResponse, ServiceError> {
        let (r, _) = self.policy_target(ctx, "DeleteResourcePolicy", &input.resource_arn)?;
        let mut st = self.lock();
        let p =
            st.region(&r.account, &r.region).parameters.get_mut(&r.key()).ok_or_else(|| {
                errors::resource_not_found(format!("The resource {} doesn't exist.", input.resource_arn))
            })?;
        let i = p.resource_policies.iter().position(|x| x.id == input.policy_id).ok_or_else(|| {
            errors::resource_policy_not_found(format!("The policy {} wasn't found.", input.policy_id))
        })?;
        if p.resource_policies[i].hash != input.policy_hash {
            return Err(errors::resource_policy_conflict(
                "The PolicyHash doesn't match the current policy. Get the latest policy, and try again.",
            ));
        }
        p.resource_policies.remove(i);
        Ok(types::DeleteResourcePolicyResponse::default())
    }
}
