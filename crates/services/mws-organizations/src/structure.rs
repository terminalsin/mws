//! The organization itself, its root and organizational units.

use std::collections::BTreeMap;

use chrono::Utc;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::access::*;
use crate::generated::{errors, types};
use crate::state::{default_policy_for, AccountInfo, Member, Org, Ou, State};
use crate::Organizations;

/// OUs can nest five levels below the root.
const MAX_OU_DEPTH: usize = 5;
const MAX_OUS: usize = 1000;

pub(crate) const ORGANIZATIONS_PRINCIPAL: &str = "organizations.amazonaws.com";

pub(crate) fn policy_type_summaries(org: &Org) -> Vec<types::PolicyTypeSummary> {
    org.policy_types
        .iter()
        .map(|(t, s)| types::PolicyTypeSummary { r#type: Some(t.clone()), status: Some(s.clone()) })
        .collect()
}

pub(crate) fn org_wire(state: &State, org: &Org, partition: &str) -> types::Organization {
    let mgmt = state.accounts.get(&org.management_account);
    types::Organization {
        id: Some(org.id.clone()),
        arn: Some(org.arn(partition)),
        feature_set: Some(org.feature_set.clone()),
        master_account_arn: Some(org.account_arn(partition, &org.management_account)),
        master_account_id: Some(org.management_account.clone()),
        master_account_email: mgmt.map(|a| a.email.clone()),
        available_policy_types: Some(policy_type_summaries(org)),
    }
}

pub(crate) fn root_wire(org: &Org, partition: &str) -> types::Root {
    types::Root {
        id: Some(org.root_id.clone()),
        arn: Some(org.root_arn(partition)),
        name: Some("Root".into()),
        policy_types: Some(policy_type_summaries(org)),
    }
}

pub(crate) fn ou_wire(org: &Org, ou: &Ou, partition: &str) -> types::OrganizationalUnit {
    types::OrganizationalUnit {
        id: Some(ou.id.clone()),
        arn: Some(org.ou_arn(partition, &ou.id)),
        name: Some(ou.name.clone()),
        path: Some(org.path_of_container(&ou.id)),
    }
}

pub(crate) fn account_wire(state: &State, org: &Org, id: &str, partition: &str) -> types::Account {
    let info = state.accounts.get(id);
    let member = org.members.get(id);
    types::Account {
        id: Some(id.to_string()),
        arn: Some(org.account_arn(partition, id)),
        email: info.map(|a| a.email.clone()),
        name: info.map(|a| a.name.clone()),
        status: info.map(|a| a.status.clone()),
        state: info.map(|a| a.state.clone()),
        paths: Some(vec![org.account_path(id)]),
        joined_method: member.map(|m| m.joined_method.clone()),
        joined_timestamp: member.map(|m| m.joined),
    }
}

/// Make sure Organizations has a record of `account` (accounts that never
/// went through CreateAccount, such as the configured MWS account).
pub(crate) fn ensure_account_info(state: &mut State, account: &str) {
    state.accounts.entry(account.to_string()).or_insert_with(|| AccountInfo {
        id: account.to_string(),
        name: format!("mws-{account}"),
        email: format!("mws+{account}@example.com"),
        status: "ACTIVE".into(),
        state: "ACTIVE".into(),
    });
}

impl Organizations {
    /// The ARN of a root, OU or account in the caller's organization.
    pub(crate) fn target_arn_for(
        &self,
        ctx: &RequestContext,
        target: &str,
        missing: fn() -> ServiceError,
    ) -> Result<String, ServiceError> {
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        if !org.has_target(target) {
            return Err(missing());
        }
        Ok(org.target_arn(&ctx.partition, target))
    }

    pub(crate) fn create_organization(
        &self,
        ctx: &RequestContext,
        input: types::CreateOrganizationRequest,
    ) -> Result<types::CreateOrganizationResponse, ServiceError> {
        self.authorize(ctx, "CreateOrganization", "*", ConditionContext::new())?;
        let account = ctx.caller.account_id.clone();
        let feature_set = input.feature_set.unwrap_or_else(|| "ALL".into());
        let mut state = self.lock();
        if state.org_of(&account).is_some() {
            return Err(errors::already_in_organization("The AWS account is already a member of an organization."));
        }
        ensure_account_info(&mut state, &account);
        let id = new_id("o-", 10);
        let root_id = new_id("r-", 4);
        let now = Utc::now();
        let mut members = BTreeMap::new();
        members.insert(
            account.clone(),
            Member { parent: root_id.clone(), joined_method: "INVITED".into(), joined: now, tags: Default::default() },
        );
        let org = Org {
            id: id.clone(),
            management_account: account.clone(),
            feature_set: feature_set.clone(),
            created: now,
            root_id,
            root_tags: Default::default(),
            policy_types: Default::default(),
            ous: Default::default(),
            members,
            policies: Default::default(),
            attachments: Default::default(),
            services: Default::default(),
            delegated: Default::default(),
            create_statuses: Default::default(),
            resource_policy: None,
        };
        let out = org_wire(&state, &org, &ctx.partition);
        state.organizations.insert(id, org);
        drop(state);
        if feature_set == "ALL" {
            self.iam.ensure_service_linked_role(
                &account,
                ORGANIZATIONS_PRINCIPAL,
                "AWSOrganizationsServiceTrustPolicy",
            );
        }
        Ok(types::CreateOrganizationResponse { organization: Some(out) })
    }

    pub(crate) fn describe_organization(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeOrganizationResponse, ServiceError> {
        self.authorize(ctx, "DescribeOrganization", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        Ok(types::DescribeOrganizationResponse { organization: Some(org_wire(&state, org, &ctx.partition)) })
    }

    pub(crate) fn delete_organization(&self, ctx: &RequestContext, _input: ()) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteOrganization", "*", ConditionContext::new())?;
        let mut state = self.lock();
        let org = self.caller_org(&state, ctx, "DeleteOrganization", "*", Need::Management)?;
        if org.members.len() > 1 {
            return Err(errors::organization_not_empty(
                "The organization isn't empty. To delete an organization, you must first remove all accounts except the management account.",
            ));
        }
        let id = org.id.clone();
        for h in state.handshakes.values_mut().filter(|h| h.org_id == id) {
            if matches!(h.handshake.state.as_deref(), Some("OPEN") | Some("REQUESTED")) {
                h.handshake.state = Some("CANCELED".into());
            }
        }
        state.organizations.remove(&id);
        Ok(())
    }

    pub(crate) fn list_roots(
        &self,
        ctx: &RequestContext,
        input: types::ListRootsRequest,
    ) -> Result<types::ListRootsResponse, ServiceError> {
        self.authorize(ctx, "ListRoots", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListRoots", "*", Need::Read)?;
        let (roots, next_token) =
            page(vec![root_wire(org, &ctx.partition)], input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListRootsResponse { roots: Some(roots), next_token })
    }

    // ---- organizational units --------------------------------------------------

    pub(crate) fn create_organizational_unit(
        &self,
        ctx: &RequestContext,
        input: types::CreateOrganizationalUnitRequest,
    ) -> Result<types::CreateOrganizationalUnitResponse, ServiceError> {
        let parent_arn = self.target_arn_for(ctx, &input.parent_id, parent_not_found)?;
        let tags = tags_from(input.tags)?;
        self.authorize(ctx, "CreateOrganizationalUnit", &parent_arn, request_tag_context(&tags))?;
        let mut state = self.lock();
        let org_id =
            self.caller_org(&state, ctx, "CreateOrganizationalUnit", &parent_arn, Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        if !org.has_parent(&input.parent_id) {
            return Err(parent_not_found());
        }
        if org.ous.values().any(|o| o.parent == input.parent_id && o.name == input.name) {
            return Err(errors::duplicate_organizational_unit("An OU with the same name already exists."));
        }
        if org.ou_depth(&input.parent_id) + 1 > MAX_OU_DEPTH {
            return Err(constraint(
                "OU_DEPTH_LIMIT_EXCEEDED",
                "You attempted to create an OU tree that is too many levels deep.",
            ));
        }
        if org.ous.len() >= MAX_OUS {
            return Err(constraint(
                "OU_NUMBER_LIMIT_EXCEEDED",
                "You have reached the maximum number of OUs in your organization.",
            ));
        }
        let suffix = org.root_id.trim_start_matches("r-").to_string();
        let id = new_id(&format!("ou-{suffix}-"), 8);
        let ou = Ou { id: id.clone(), name: input.name, parent: input.parent_id, tags };
        org.ous.insert(id.clone(), ou.clone());
        attach_defaults(org, &id);
        Ok(types::CreateOrganizationalUnitResponse { organizational_unit: Some(ou_wire(org, &ou, &ctx.partition)) })
    }

    pub(crate) fn describe_organizational_unit(
        &self,
        ctx: &RequestContext,
        input: types::DescribeOrganizationalUnitRequest,
    ) -> Result<types::DescribeOrganizationalUnitResponse, ServiceError> {
        let arn = self.ou_arn_for(ctx, &input.organizational_unit_id)?;
        self.authorize(ctx, "DescribeOrganizationalUnit", &arn, ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "DescribeOrganizationalUnit", &arn, Need::Read)?;
        let ou = org.ous.get(&input.organizational_unit_id).ok_or_else(ou_not_found)?;
        Ok(types::DescribeOrganizationalUnitResponse { organizational_unit: Some(ou_wire(org, ou, &ctx.partition)) })
    }

    pub(crate) fn update_organizational_unit(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOrganizationalUnitRequest,
    ) -> Result<types::UpdateOrganizationalUnitResponse, ServiceError> {
        let arn = self.ou_arn_for(ctx, &input.organizational_unit_id)?;
        self.authorize(ctx, "UpdateOrganizationalUnit", &arn, ConditionContext::new())?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "UpdateOrganizationalUnit", &arn, Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        let parent = org.ous.get(&input.organizational_unit_id).ok_or_else(ou_not_found)?.parent.clone();
        if let Some(name) = &input.name {
            if org.ous.values().any(|o| o.parent == parent && o.name == *name && o.id != input.organizational_unit_id) {
                return Err(errors::duplicate_organizational_unit("An OU with the same name already exists."));
            }
        }
        let ou = org.ous.get_mut(&input.organizational_unit_id).expect("checked above");
        if let Some(name) = input.name {
            ou.name = name;
        }
        let ou = ou.clone();
        Ok(types::UpdateOrganizationalUnitResponse { organizational_unit: Some(ou_wire(org, &ou, &ctx.partition)) })
    }

    pub(crate) fn delete_organizational_unit(
        &self,
        ctx: &RequestContext,
        input: types::DeleteOrganizationalUnitRequest,
    ) -> Result<(), ServiceError> {
        let arn = self.ou_arn_for(ctx, &input.organizational_unit_id)?;
        self.authorize(ctx, "DeleteOrganizationalUnit", &arn, ConditionContext::new())?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "DeleteOrganizationalUnit", &arn, Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        let id = &input.organizational_unit_id;
        if !org.ous.contains_key(id) {
            return Err(ou_not_found());
        }
        if org.ous.values().any(|o| o.parent == *id) || org.members.values().any(|m| m.parent == *id) {
            return Err(errors::organizational_unit_not_empty(
                "The specified OU is not empty. Move all accounts to another root or to other OUs, remove all child OUs, and try the operation again.",
            ));
        }
        org.ous.remove(id);
        org.attachments.remove(id);
        Ok(())
    }

    fn ou_arn_for(&self, ctx: &RequestContext, ou: &str) -> Result<String, ServiceError> {
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        if !org.is_ou(ou) {
            return Err(ou_not_found());
        }
        Ok(org.ou_arn(&ctx.partition, ou))
    }

    pub(crate) fn list_organizational_units_for_parent(
        &self,
        ctx: &RequestContext,
        input: types::ListOrganizationalUnitsForParentRequest,
    ) -> Result<types::ListOrganizationalUnitsForParentResponse, ServiceError> {
        let arn = self.target_arn_for(ctx, &input.parent_id, parent_not_found)?;
        self.authorize(ctx, "ListOrganizationalUnitsForParent", &arn, ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListOrganizationalUnitsForParent", &arn, Need::Read)?;
        if !org.has_parent(&input.parent_id) {
            return Err(parent_not_found());
        }
        let ous: Vec<_> =
            org.ous.values().filter(|o| o.parent == input.parent_id).map(|o| ou_wire(org, o, &ctx.partition)).collect();
        let (ous, next_token) = page(ous, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListOrganizationalUnitsForParentResponse { organizational_units: Some(ous), next_token })
    }

    pub(crate) fn list_children(
        &self,
        ctx: &RequestContext,
        input: types::ListChildrenRequest,
    ) -> Result<types::ListChildrenResponse, ServiceError> {
        let arn = self.target_arn_for(ctx, &input.parent_id, parent_not_found)?;
        self.authorize(ctx, "ListChildren", &arn, ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListChildren", &arn, Need::Read)?;
        if !org.has_parent(&input.parent_id) {
            return Err(parent_not_found());
        }
        let ids: Vec<String> = match input.child_type.as_str() {
            "ACCOUNT" => {
                org.members.iter().filter(|(_, m)| m.parent == input.parent_id).map(|(id, _)| id.clone()).collect()
            }
            _ => org.ous.values().filter(|o| o.parent == input.parent_id).map(|o| o.id.clone()).collect(),
        };
        let children: Vec<_> =
            ids.into_iter().map(|id| types::Child { id: Some(id), r#type: Some(input.child_type.clone()) }).collect();
        let (children, next_token) = page(children, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListChildrenResponse { children: Some(children), next_token })
    }

    pub(crate) fn list_parents(
        &self,
        ctx: &RequestContext,
        input: types::ListParentsRequest,
    ) -> Result<types::ListParentsResponse, ServiceError> {
        let missing = || errors::child_not_found("You specified a child that doesn't exist.");
        let arn = {
            let state = self.lock();
            let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
            if !org.is_ou(&input.child_id) && !org.members.contains_key(&input.child_id) {
                return Err(missing());
            }
            org.target_arn(&ctx.partition, &input.child_id)
        };
        self.authorize(ctx, "ListParents", &arn, ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListParents", &arn, Need::Read)?;
        let parent = org.parent_of(&input.child_id).ok_or_else(missing)?;
        let ty = if parent == org.root_id { "ROOT" } else { "ORGANIZATIONAL_UNIT" };
        let parents = vec![types::Parent { id: Some(parent.to_string()), r#type: Some(ty.into()) }];
        let (parents, next_token) = page(parents, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListParentsResponse { parents: Some(parents), next_token })
    }
}

/// When a policy type is enabled, every new OU and account gets its default
/// AWS managed policy (FullAWSAccess, RCPFullAWSAccess).
pub(crate) fn attach_defaults(org: &mut Org, target: &str) {
    let defaults: Vec<&str> = org.policy_types.keys().filter_map(|t| default_policy_for(t)).collect();
    let entry = org.attachments.entry(target.to_string()).or_default();
    for p in defaults {
        if !entry.iter().any(|x| x == p) {
            entry.push(p.to_string());
        }
    }
}
