//! Organization policies: creating them, attaching them to the root, OUs and
//! accounts, and enabling policy types.

use mws_core::{RequestContext, ServiceError};
use mws_iam_policy::{policy_size, Policy, PolicyKind};

use crate::access::*;
use crate::generated::{errors, types};
use crate::state::{aws_managed, default_policy_for, is_aws_managed, Org, PolicyRec, RCP, SCP};
use crate::structure::root_wire;
use crate::Organizations;

const MAX_POLICIES_PER_TYPE: usize = 1000;

fn max_size(ty: &str) -> usize {
    match ty {
        SCP | RCP => 5120,
        "AISERVICES_OPT_OUT_POLICY" => 2500,
        _ => 10_000,
    }
}

fn max_attachments(ty: &str) -> usize {
    match ty {
        SCP | RCP => 5,
        _ => 10,
    }
}

fn malformed() -> ServiceError {
    errors::malformed_policy_document(
        "The provided policy document doesn't meet the requirements of the specified policy type.",
    )
}

fn type_not_available() -> ServiceError {
    errors::policy_type_not_available_for_organization(
        "You can't use the specified policy type with the feature set currently enabled for this organization. For example, you can enable SCPs only after you enable all features in the organization.",
    )
}

fn type_not_enabled() -> ServiceError {
    errors::policy_type_not_enabled(
        "The specified policy type isn't currently enabled in this root. You can't attach policies of the specified type to entities in a root until you enable that type in the root.",
    )
}

fn immutable() -> ServiceError {
    invalid("IMMUTABLE_POLICY", "You specified a policy that is managed by AWS and can't be modified.")
}

/// Check a policy document against its type's grammar and size limit.
pub(crate) fn validate_content(ty: &str, content: &str) -> Result<(), ServiceError> {
    if policy_size(content) > max_size(ty) {
        return Err(constraint(
            "POLICY_CONTENT_LIMIT_EXCEEDED",
            "You attempted to create a policy that is larger than the maximum size.",
        ));
    }
    match ty {
        SCP => {
            Policy::parse(content, PolicyKind::ServiceControl).map_err(|_| malformed())?;
        }
        RCP => {
            let policy = Policy::parse(content, PolicyKind::ResourceControl).map_err(|_| malformed())?;
            // Customer managed RCPs can only deny.
            if policy.statements.iter().any(|s| s.effect == mws_iam_policy::Effect::Allow) {
                return Err(malformed());
            }
        }
        _ => {
            let value: serde_json::Value = serde_json::from_str(content).map_err(|_| malformed())?;
            if !value.is_object() {
                return Err(malformed());
            }
        }
    }
    Ok(())
}

pub(crate) fn summary(org: &Org, p: &PolicyRec, partition: &str) -> types::PolicySummary {
    types::PolicySummary {
        id: Some(p.id.clone()),
        arn: Some(org.policy_arn(partition, &p.id, &p.ty)),
        name: Some(p.name.clone()),
        description: Some(p.description.clone()),
        r#type: Some(p.ty.clone()),
        aws_managed: is_aws_managed(&p.id),
    }
}

fn policy_wire(org: &Org, p: &PolicyRec, partition: &str) -> types::Policy {
    types::Policy { policy_summary: Some(summary(org, p, partition)), content: Some(p.content.clone()) }
}

impl Organizations {
    /// ARN and type of a policy in the caller's organization.
    fn policy_ref(&self, ctx: &RequestContext, id: &str) -> Result<(String, String, crate::state::Tags), ServiceError> {
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        let p = org.policy(id).ok_or_else(policy_not_found)?;
        Ok((org.policy_arn(&ctx.partition, id, &p.ty), p.ty, p.tags))
    }

    pub(crate) fn create_policy(
        &self,
        ctx: &RequestContext,
        input: types::CreatePolicyRequest,
    ) -> Result<types::CreatePolicyResponse, ServiceError> {
        let tags = tags_from(input.tags)?;
        let mut cond = request_tag_context(&tags);
        cond.insert("organizations:PolicyType".into(), vec![input.r#type.clone()]);
        self.authorize(ctx, "CreatePolicy", "*", cond)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "CreatePolicy", "*", Need::Delegable)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if org.feature_set != "ALL" {
            return Err(type_not_available());
        }
        validate_content(&input.r#type, &input.content)?;
        if org.policies.values().any(|p| p.ty == input.r#type && p.name == input.name) {
            return Err(errors::duplicate_policy("A policy with the same name already exists."));
        }
        if org.policies.values().filter(|p| p.ty == input.r#type).count() >= MAX_POLICIES_PER_TYPE {
            return Err(constraint(
                "POLICY_NUMBER_LIMIT_EXCEEDED",
                "You attempted to exceed the number of policies that you can have in an organization.",
            ));
        }
        let p = PolicyRec {
            id: new_id("p-", 8),
            name: input.name,
            description: input.description,
            ty: input.r#type,
            content: input.content,
            tags,
        };
        org.policies.insert(p.id.clone(), p.clone());
        Ok(types::CreatePolicyResponse { policy: Some(policy_wire(org, &p, &ctx.partition)) })
    }

    pub(crate) fn describe_policy(
        &self,
        ctx: &RequestContext,
        input: types::DescribePolicyRequest,
    ) -> Result<types::DescribePolicyResponse, ServiceError> {
        let (arn, ty, tags) = self.policy_ref(ctx, &input.policy_id)?;
        let mut cond = resource_tag_context(&tags);
        cond.insert("organizations:PolicyType".into(), vec![ty]);
        self.authorize(ctx, "DescribePolicy", &arn, cond)?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "DescribePolicy", &arn, Need::Read)?;
        let p = org.policy(&input.policy_id).ok_or_else(policy_not_found)?;
        Ok(types::DescribePolicyResponse { policy: Some(policy_wire(org, &p, &ctx.partition)) })
    }

    pub(crate) fn update_policy(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePolicyRequest,
    ) -> Result<types::UpdatePolicyResponse, ServiceError> {
        let (arn, ty, tags) = self.policy_ref(ctx, &input.policy_id)?;
        let mut cond = resource_tag_context(&tags);
        cond.insert("organizations:PolicyType".into(), vec![ty.clone()]);
        self.authorize(ctx, "UpdatePolicy", &arn, cond)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "UpdatePolicy", &arn, Need::Delegable)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if is_aws_managed(&input.policy_id) {
            return Err(immutable());
        }
        if let Some(content) = &input.content {
            validate_content(&ty, content)?;
        }
        if let Some(name) = &input.name {
            if org.policies.values().any(|p| p.ty == ty && p.name == *name && p.id != input.policy_id) {
                return Err(errors::duplicate_policy("A policy with the same name already exists."));
            }
        }
        let p = org.policies.get_mut(&input.policy_id).ok_or_else(policy_not_found)?;
        if let Some(name) = input.name {
            p.name = name;
        }
        if let Some(d) = input.description {
            p.description = d;
        }
        if let Some(c) = input.content {
            p.content = c;
        }
        let p = p.clone();
        Ok(types::UpdatePolicyResponse { policy: Some(policy_wire(org, &p, &ctx.partition)) })
    }

    pub(crate) fn delete_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeletePolicyRequest,
    ) -> Result<(), ServiceError> {
        let (arn, ty, tags) = self.policy_ref(ctx, &input.policy_id)?;
        let mut cond = resource_tag_context(&tags);
        cond.insert("organizations:PolicyType".into(), vec![ty]);
        self.authorize(ctx, "DeletePolicy", &arn, cond)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "DeletePolicy", &arn, Need::Delegable)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if is_aws_managed(&input.policy_id) {
            return Err(immutable());
        }
        if !org.policies.contains_key(&input.policy_id) {
            return Err(policy_not_found());
        }
        if !org.targets_of(&input.policy_id).is_empty() {
            return Err(errors::policy_in_use(
                "The policy is attached to one or more entities. You must detach it from all roots, OUs, and accounts before performing this operation.",
            ));
        }
        org.policies.remove(&input.policy_id);
        Ok(())
    }

    /// Authorize an attach/detach on both the policy and the target.
    fn authorize_attachment(
        &self,
        ctx: &RequestContext,
        action: &str,
        policy_id: &str,
        target_id: &str,
    ) -> Result<(String, String), ServiceError> {
        let (policy_arn, ty, tags) = self.policy_ref(ctx, policy_id)?;
        let target_arn = self.target_arn_for(ctx, target_id, target_not_found)?;
        let mut cond = resource_tag_context(&tags);
        cond.insert("organizations:PolicyType".into(), vec![ty.clone()]);
        self.authorize(ctx, action, &policy_arn, cond.clone())?;
        self.authorize(ctx, action, &target_arn, single("organizations:PolicyType", ty.clone()))?;
        Ok((policy_arn, ty))
    }

    pub(crate) fn attach_policy(
        &self,
        ctx: &RequestContext,
        input: types::AttachPolicyRequest,
    ) -> Result<(), ServiceError> {
        let (arn, ty) = self.authorize_attachment(ctx, "AttachPolicy", &input.policy_id, &input.target_id)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "AttachPolicy", &arn, Need::Delegable)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if !org.has_target(&input.target_id) {
            return Err(target_not_found());
        }
        if !org.type_enabled(&ty) {
            return Err(type_not_enabled());
        }
        let attached: Vec<String> = org.attached(&input.target_id).to_vec();
        if attached.contains(&input.policy_id) {
            return Err(errors::duplicate_policy_attachment(
                "The selected policy is already attached to the specified target.",
            ));
        }
        let same_type = attached.iter().filter(|id| org.policy(id).is_some_and(|p| p.ty == ty)).count();
        if same_type >= max_attachments(&ty) {
            return Err(constraint(
                "MAX_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED",
                "You attempted to exceed the number of policies of a certain type that can be attached to an entity at one time.",
            ));
        }
        org.attachments.entry(input.target_id).or_default().push(input.policy_id);
        Ok(())
    }

    pub(crate) fn detach_policy(
        &self,
        ctx: &RequestContext,
        input: types::DetachPolicyRequest,
    ) -> Result<(), ServiceError> {
        let (arn, ty) = self.authorize_attachment(ctx, "DetachPolicy", &input.policy_id, &input.target_id)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "DetachPolicy", &arn, Need::Delegable)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        let attached: Vec<String> = org.attached(&input.target_id).to_vec();
        if !attached.contains(&input.policy_id) {
            return Err(errors::policy_not_attached(
                "The policy isn't attached to the specified target in the specified root.",
            ));
        }
        let same_type = attached.iter().filter(|id| org.policy(id).is_some_and(|p| p.ty == ty)).count();
        if (ty == SCP || ty == RCP) && same_type <= 1 {
            return Err(constraint(
                "MIN_POLICY_TYPE_ATTACHMENT_LIMIT_EXCEEDED",
                "You attempted to detach a policy from an entity that would cause the entity to have fewer than the minimum number of policies of a certain type required.",
            ));
        }
        if let Some(list) = org.attachments.get_mut(&input.target_id) {
            list.retain(|p| *p != input.policy_id);
        }
        Ok(())
    }

    pub(crate) fn list_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListPoliciesRequest,
    ) -> Result<types::ListPoliciesResponse, ServiceError> {
        self.authorize(ctx, "ListPolicies", "*", single("organizations:PolicyType", input.filter.clone()))?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListPolicies", "*", Need::Read)?;
        let mut all: Vec<PolicyRec> = default_policy_for(&input.filter).and_then(aws_managed).into_iter().collect();
        all.extend(org.policies.values().filter(|p| p.ty == input.filter).cloned());
        let all: Vec<_> = all.iter().map(|p| summary(org, p, &ctx.partition)).collect();
        let (policies, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListPoliciesResponse { policies: Some(policies), next_token })
    }

    pub(crate) fn list_policies_for_target(
        &self,
        ctx: &RequestContext,
        input: types::ListPoliciesForTargetRequest,
    ) -> Result<types::ListPoliciesForTargetResponse, ServiceError> {
        let arn = self.target_arn_for(ctx, &input.target_id, target_not_found)?;
        self.authorize(ctx, "ListPoliciesForTarget", &arn, single("organizations:PolicyType", input.filter.clone()))?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListPoliciesForTarget", &arn, Need::Read)?;
        if !org.has_target(&input.target_id) {
            return Err(target_not_found());
        }
        let all: Vec<_> = org
            .attached(&input.target_id)
            .iter()
            .filter_map(|id| org.policy(id))
            .filter(|p| p.ty == input.filter)
            .map(|p| summary(org, &p, &ctx.partition))
            .collect();
        let (policies, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListPoliciesForTargetResponse { policies: Some(policies), next_token })
    }

    pub(crate) fn list_targets_for_policy(
        &self,
        ctx: &RequestContext,
        input: types::ListTargetsForPolicyRequest,
    ) -> Result<types::ListTargetsForPolicyResponse, ServiceError> {
        let (arn, ty, _) = self.policy_ref(ctx, &input.policy_id)?;
        self.authorize(ctx, "ListTargetsForPolicy", &arn, single("organizations:PolicyType", ty))?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListTargetsForPolicy", &arn, Need::Read)?;
        let all: Vec<_> = org
            .targets_of(&input.policy_id)
            .into_iter()
            .map(|t| {
                let (name, ty) = if t == org.root_id {
                    ("Root".to_string(), "ROOT")
                } else if let Some(ou) = org.ous.get(&t) {
                    (ou.name.clone(), "ORGANIZATIONAL_UNIT")
                } else {
                    (state.accounts.get(&t).map(|a| a.name.clone()).unwrap_or_default(), "ACCOUNT")
                };
                types::PolicyTargetSummary {
                    arn: Some(org.target_arn(&ctx.partition, &t)),
                    target_id: Some(t),
                    name: Some(name),
                    r#type: Some(ty.into()),
                }
            })
            .collect();
        let (targets, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListTargetsForPolicyResponse { targets: Some(targets), next_token })
    }

    fn root_arn_for(&self, ctx: &RequestContext, root: &str) -> Result<String, ServiceError> {
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        if org.root_id != root {
            return Err(root_not_found());
        }
        Ok(org.root_arn(&ctx.partition))
    }

    pub(crate) fn enable_policy_type(
        &self,
        ctx: &RequestContext,
        input: types::EnablePolicyTypeRequest,
    ) -> Result<types::EnablePolicyTypeResponse, ServiceError> {
        let arn = self.root_arn_for(ctx, &input.root_id)?;
        self.authorize(ctx, "EnablePolicyType", &arn, single("organizations:PolicyType", input.policy_type.clone()))?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "EnablePolicyType", &arn, Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if org.feature_set != "ALL" {
            return Err(type_not_available());
        }
        if org.type_enabled(&input.policy_type) {
            return Err(errors::policy_type_already_enabled("The specified policy type is already enabled."));
        }
        org.policy_types.insert(input.policy_type.clone(), "ENABLED".into());
        if let Some(default) = default_policy_for(&input.policy_type) {
            for target in org.all_targets() {
                let list = org.attachments.entry(target).or_default();
                if !list.iter().any(|p| p == default) {
                    list.push(default.to_string());
                }
            }
        }
        Ok(types::EnablePolicyTypeResponse { root: Some(root_wire(org, &ctx.partition)) })
    }

    pub(crate) fn disable_policy_type(
        &self,
        ctx: &RequestContext,
        input: types::DisablePolicyTypeRequest,
    ) -> Result<types::DisablePolicyTypeResponse, ServiceError> {
        let arn = self.root_arn_for(ctx, &input.root_id)?;
        self.authorize(ctx, "DisablePolicyType", &arn, single("organizations:PolicyType", input.policy_type.clone()))?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "DisablePolicyType", &arn, Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if !org.type_enabled(&input.policy_type) {
            return Err(type_not_enabled());
        }
        org.policy_types.remove(&input.policy_type);
        let of_type: Vec<String> = org
            .policies
            .values()
            .filter(|p| p.ty == input.policy_type)
            .map(|p| p.id.clone())
            .chain(default_policy_for(&input.policy_type).map(str::to_string))
            .collect();
        for list in org.attachments.values_mut() {
            list.retain(|p| !of_type.contains(p));
        }
        Ok(types::DisablePolicyTypeResponse { root: Some(root_wire(org, &ctx.partition)) })
    }
}
