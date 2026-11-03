//! Trusted service access, delegated administrators, the organization's
//! resource policy, and tags.

use chrono::Utc;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::access::*;
use crate::generated::{errors, types};
use crate::state::{is_aws_managed, Org, ResourcePolicyRec, State, Tags};
use crate::Organizations;

fn unrecognized_principal() -> ServiceError {
    invalid("UNRECOGNIZED_SERVICE_PRINCIPAL", "You specified a service principal that isn't recognized.")
}

fn check_principal(p: &str) -> Result<(), ServiceError> {
    let ok = p.ends_with(".amazonaws.com") && p.split('.').count() >= 3;
    if ok {
        Ok(())
    } else {
        Err(unrecognized_principal())
    }
}

fn not_registered() -> ServiceError {
    errors::account_not_registered(
        "The specified account is not a delegated administrator for this Amazon Web Services service.",
    )
}

fn resource_policy_not_found() -> ServiceError {
    errors::resource_policy_not_found("We can't find a resource policy request with the parameter that you specified.")
}

fn resource_policy_wire(org: &Org, rp: &ResourcePolicyRec, partition: &str) -> types::ResourcePolicy {
    types::ResourcePolicy {
        resource_policy_summary: Some(types::ResourcePolicySummary {
            id: Some(rp.id.clone()),
            arn: Some(org.resource_policy_arn(partition, &rp.id)),
        }),
        content: Some(rp.content.clone()),
    }
}

/// Where a taggable resource's tags live.
enum Taggable {
    Root,
    Ou(String),
    Account(String),
    Policy(String),
    ResourcePolicy,
    Transfer(String),
}

fn find_taggable(state: &State, org: &Org, id: &str) -> Option<Taggable> {
    if id == org.root_id {
        Some(Taggable::Root)
    } else if org.is_ou(id) {
        Some(Taggable::Ou(id.into()))
    } else if org.members.contains_key(id) {
        Some(Taggable::Account(id.into()))
    } else if org.policies.contains_key(id) {
        Some(Taggable::Policy(id.into()))
    } else if org.resource_policy.as_ref().is_some_and(|rp| rp.id == id) {
        Some(Taggable::ResourcePolicy)
    } else if state.transfers.get(id).is_some_and(|t| t.source_org == org.id || t.target_org == org.id) {
        Some(Taggable::Transfer(id.into()))
    } else {
        None
    }
}

fn tags_of(state: &State, org: &Org, t: &Taggable) -> Tags {
    match t {
        Taggable::Root => org.root_tags.clone(),
        Taggable::Ou(id) => org.ous[id].tags.clone(),
        Taggable::Account(id) => org.members[id].tags.clone(),
        Taggable::Policy(id) => org.policies[id].tags.clone(),
        Taggable::ResourcePolicy => org.resource_policy.as_ref().map(|r| r.tags.clone()).unwrap_or_default(),
        Taggable::Transfer(id) => state.transfers[id].tags.clone(),
    }
}

fn tags_mut<'a>(state: &'a mut State, org_id: &str, t: &Taggable) -> &'a mut Tags {
    if let Taggable::Transfer(id) = t {
        return &mut state.transfers.get_mut(id).expect("transfer exists").tags;
    }
    let org = state.organizations.get_mut(org_id).expect("organization exists");
    match t {
        Taggable::Root => &mut org.root_tags,
        Taggable::Ou(id) => &mut org.ous.get_mut(id).expect("OU exists").tags,
        Taggable::Account(id) => &mut org.members.get_mut(id).expect("account exists").tags,
        Taggable::Policy(id) => &mut org.policies.get_mut(id).expect("policy exists").tags,
        Taggable::ResourcePolicy => &mut org.resource_policy.as_mut().expect("resource policy exists").tags,
        Taggable::Transfer(_) => unreachable!(),
    }
}

impl Organizations {
    // ---- trusted access ----------------------------------------------------------

    pub(crate) fn enable_aws_service_access(
        &self,
        ctx: &RequestContext,
        input: types::EnableAWSServiceAccessRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "EnableAWSServiceAccess",
            "*",
            single("organizations:ServicePrincipal", input.service_principal.clone()),
        )?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "EnableAWSServiceAccess", "*", Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if org.feature_set != "ALL" {
            return Err(constraint(
                "ORGANIZATION_NOT_IN_ALL_FEATURES_MODE",
                "You can't perform this operation unless the organization has all features enabled.",
            ));
        }
        check_principal(&input.service_principal)?;
        org.services.entry(input.service_principal).or_insert_with(Utc::now);
        Ok(())
    }

    pub(crate) fn disable_aws_service_access(
        &self,
        ctx: &RequestContext,
        input: types::DisableAWSServiceAccessRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "DisableAWSServiceAccess",
            "*",
            single("organizations:ServicePrincipal", input.service_principal.clone()),
        )?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "DisableAWSServiceAccess", "*", Need::Management)?.id.clone();
        check_principal(&input.service_principal)?;
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        org.services.remove(&input.service_principal);
        Ok(())
    }

    pub(crate) fn list_aws_service_access_for_organization(
        &self,
        ctx: &RequestContext,
        input: types::ListAWSServiceAccessForOrganizationRequest,
    ) -> Result<types::ListAWSServiceAccessForOrganizationResponse, ServiceError> {
        self.authorize(ctx, "ListAWSServiceAccessForOrganization", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListAWSServiceAccessForOrganization", "*", Need::Read)?;
        let all: Vec<_> = org
            .services
            .iter()
            .map(|(p, d)| types::EnabledServicePrincipal { service_principal: Some(p.clone()), date_enabled: Some(*d) })
            .collect();
        let (principals, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAWSServiceAccessForOrganizationResponse {
            enabled_service_principals: Some(principals),
            next_token,
        })
    }

    // ---- delegated administrators ------------------------------------------------

    pub(crate) fn register_delegated_administrator(
        &self,
        ctx: &RequestContext,
        input: types::RegisterDelegatedAdministratorRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "RegisterDelegatedAdministrator",
            "*",
            single("organizations:ServicePrincipal", input.service_principal.clone()),
        )?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "RegisterDelegatedAdministrator", "*", Need::Management)?.id.clone();
        check_principal(&input.service_principal)?;
        let suspended = state.accounts.get(&input.account_id).is_some_and(|a| a.status != "ACTIVE");
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if !org.members.contains_key(&input.account_id) {
            return Err(account_not_found());
        }
        if org.management_account == input.account_id {
            return Err(constraint(
                "CANNOT_REGISTER_MASTER_AS_DELEGATED_ADMINISTRATOR",
                "You can't register the management account of an organization as a delegated administrator.",
            ));
        }
        if suspended {
            return Err(constraint(
                "CANNOT_REGISTER_SUSPENDED_ACCOUNT_AS_DELEGATED_ADMINISTRATOR",
                "You can't register a suspended account as a delegated administrator.",
            ));
        }
        if !org.services.contains_key(&input.service_principal) {
            return Err(constraint(
                "SERVICE_ACCESS_NOT_ENABLED",
                "You attempted to register a delegated administrator for a service that doesn't have trusted access enabled for the organization.",
            ));
        }
        let entry = org.delegated.entry(input.account_id).or_default();
        if entry.contains_key(&input.service_principal) {
            return Err(errors::account_already_registered(
                "The specified account is already a delegated administrator for this Amazon Web Services service.",
            ));
        }
        entry.insert(input.service_principal, Utc::now());
        Ok(())
    }

    pub(crate) fn deregister_delegated_administrator(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterDelegatedAdministratorRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "DeregisterDelegatedAdministrator",
            "*",
            single("organizations:ServicePrincipal", input.service_principal.clone()),
        )?;
        let mut state = self.lock();
        let org_id =
            self.caller_org(&state, ctx, "DeregisterDelegatedAdministrator", "*", Need::Management)?.id.clone();
        check_principal(&input.service_principal)?;
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if !org.members.contains_key(&input.account_id) {
            return Err(account_not_found());
        }
        let services = org.delegated.get_mut(&input.account_id).ok_or_else(not_registered)?;
        services.remove(&input.service_principal).ok_or_else(not_registered)?;
        if services.is_empty() {
            org.delegated.remove(&input.account_id);
        }
        Ok(())
    }

    pub(crate) fn list_delegated_administrators(
        &self,
        ctx: &RequestContext,
        input: types::ListDelegatedAdministratorsRequest,
    ) -> Result<types::ListDelegatedAdministratorsResponse, ServiceError> {
        self.authorize(ctx, "ListDelegatedAdministrators", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListDelegatedAdministrators", "*", Need::Read)?;
        if let Some(p) = &input.service_principal {
            check_principal(p)?;
        }
        let all: Vec<_> = org
            .delegated
            .iter()
            .filter_map(|(account, services)| {
                let since = match &input.service_principal {
                    Some(p) => *services.get(p)?,
                    None => *services.values().min()?,
                };
                let info = state.accounts.get(account);
                let member = org.members.get(account);
                Some(types::DelegatedAdministrator {
                    id: Some(account.clone()),
                    arn: Some(org.account_arn(&ctx.partition, account)),
                    email: info.map(|a| a.email.clone()),
                    name: info.map(|a| a.name.clone()),
                    status: info.map(|a| a.status.clone()),
                    state: info.map(|a| a.state.clone()),
                    joined_method: member.map(|m| m.joined_method.clone()),
                    joined_timestamp: member.map(|m| m.joined),
                    delegation_enabled_date: Some(since),
                })
            })
            .collect();
        let (admins, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListDelegatedAdministratorsResponse { delegated_administrators: Some(admins), next_token })
    }

    pub(crate) fn list_delegated_services_for_account(
        &self,
        ctx: &RequestContext,
        input: types::ListDelegatedServicesForAccountRequest,
    ) -> Result<types::ListDelegatedServicesForAccountResponse, ServiceError> {
        self.authorize(ctx, "ListDelegatedServicesForAccount", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListDelegatedServicesForAccount", "*", Need::Read)?;
        if !org.members.contains_key(&input.account_id) {
            return Err(account_not_found());
        }
        let services = org.delegated.get(&input.account_id).ok_or_else(not_registered)?;
        let all: Vec<_> = services
            .iter()
            .map(|(p, d)| types::DelegatedService {
                service_principal: Some(p.clone()),
                delegation_enabled_date: Some(*d),
            })
            .collect();
        let (services, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListDelegatedServicesForAccountResponse { delegated_services: Some(services), next_token })
    }

    // ---- resource policy ---------------------------------------------------------

    pub(crate) fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        let tags = tags_from(input.tags)?;
        self.authorize(ctx, "PutResourcePolicy", "*", request_tag_context(&tags))?;
        validate_resource_policy(&input.content)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "PutResourcePolicy", "*", Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        let rp = match org.resource_policy.take() {
            Some(mut existing) => {
                if !tags.is_empty() {
                    org.resource_policy = Some(existing);
                    return Err(constraint(
                        "UPDATE_EXISTING_RESOURCE_POLICY_WITH_TAGS_NOT_SUPPORTED",
                        "You can't add tags when you update an existing resource policy. Use TagResource instead.",
                    ));
                }
                existing.content = input.content;
                existing
            }
            None => ResourcePolicyRec { id: new_id("rp-", 8), content: input.content, tags },
        };
        let out = resource_policy_wire(org, &rp, &ctx.partition);
        org.resource_policy = Some(rp);
        Ok(types::PutResourcePolicyResponse { resource_policy: Some(out) })
    }

    pub(crate) fn describe_resource_policy(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeResourcePolicyResponse, ServiceError> {
        self.authorize(ctx, "DescribeResourcePolicy", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        let rp = org.resource_policy.as_ref().ok_or_else(resource_policy_not_found)?;
        Ok(types::DescribeResourcePolicyResponse {
            resource_policy: Some(resource_policy_wire(org, rp, &ctx.partition)),
        })
    }

    pub(crate) fn delete_resource_policy(&self, ctx: &RequestContext, _input: ()) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteResourcePolicy", "*", ConditionContext::new())?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "DeleteResourcePolicy", "*", Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        org.resource_policy.take().ok_or_else(resource_policy_not_found)?;
        Ok(())
    }

    // ---- tags --------------------------------------------------------------------

    /// The ARN and current tags of a taggable resource.
    fn taggable_ref(&self, ctx: &RequestContext, id: &str) -> Result<(String, Tags), ServiceError> {
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        if is_aws_managed(id) {
            return Err(target_not_found());
        }
        let t = find_taggable(&state, org, id).ok_or_else(target_not_found)?;
        let arn = match &t {
            Taggable::Policy(p) => org.policy_arn(&ctx.partition, p, &org.policies[p].ty),
            Taggable::ResourcePolicy => org.resource_policy_arn(&ctx.partition, id),
            Taggable::Transfer(t) => state.transfers[t].transfer.arn.clone().unwrap_or_default(),
            _ => org.target_arn(&ctx.partition, id),
        };
        Ok((arn, tags_of(&state, org, &t)))
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        let (arn, existing) = self.taggable_ref(ctx, &input.resource_id)?;
        let tags = tags_from(Some(input.tags))?;
        let mut cond = request_tag_context(&tags);
        cond.extend(resource_tag_context(&existing));
        self.authorize(ctx, "TagResource", &arn, cond)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "TagResource", &arn, Need::Delegable)?.id.clone();
        let org = state.organizations.get(&org_id).expect("caller's organization exists");
        let t = find_taggable(&state, org, &input.resource_id).ok_or_else(target_not_found)?;
        let target = tags_mut(&mut state, &org_id, &t);
        let mut merged = target.clone();
        merged.extend(tags);
        if merged.len() > MAX_TAGS {
            return Err(constraint(
                "MAX_TAG_LIMIT_EXCEEDED",
                "You have exceeded the number of tags allowed on this resource.",
            ));
        }
        *target = merged;
        Ok(())
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        let (arn, existing) = self.taggable_ref(ctx, &input.resource_id)?;
        let mut cond = resource_tag_context(&existing);
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize(ctx, "UntagResource", &arn, cond)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "UntagResource", &arn, Need::Delegable)?.id.clone();
        let org = state.organizations.get(&org_id).expect("caller's organization exists");
        let t = find_taggable(&state, org, &input.resource_id).ok_or_else(target_not_found)?;
        let target = tags_mut(&mut state, &org_id, &t);
        for k in &input.tag_keys {
            target.remove(k);
        }
        Ok(())
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let (arn, tags) = self.taggable_ref(ctx, &input.resource_id)?;
        self.authorize(ctx, "ListTagsForResource", &arn, resource_tag_context(&tags))?;
        let state = self.lock();
        self.caller_org(&state, ctx, "ListTagsForResource", &arn, Need::Read)?;
        let (tags, next_token) = page(tags_to_wire(&tags), input.next_token.as_deref(), None)?;
        Ok(types::ListTagsForResourceResponse { tags: Some(tags), next_token })
    }
}
