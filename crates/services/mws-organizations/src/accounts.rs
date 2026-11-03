//! Member accounts: creating, describing, moving, removing and closing them.

use chrono::Utc;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::access::*;
use crate::generated::{errors, types};
use crate::state::{AccountInfo, Member, Org, State};
use crate::structure::{account_wire, attach_defaults, ORGANIZATIONS_PRINCIPAL};
use crate::Organizations;

impl Organizations {
    /// The ARN of an account in the caller's organization.
    fn account_arn_for(&self, ctx: &RequestContext, account: &str) -> Result<String, ServiceError> {
        let state = self.lock();
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        if !org.members.contains_key(account) {
            return Err(account_not_found());
        }
        Ok(org.account_arn(&ctx.partition, account))
    }

    fn new_account_id(&self, state: &State) -> String {
        loop {
            let id = new_account_id();
            if !state.accounts.contains_key(&id) && !self.iam.account_exists(&id) {
                return id;
            }
        }
    }

    pub(crate) fn create_account(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccountRequest,
    ) -> Result<types::CreateAccountResponse, ServiceError> {
        let tags = tags_from(input.tags)?;
        self.authorize(ctx, "CreateAccount", "*", request_tag_context(&tags))?;
        let role = input.role_name.unwrap_or_else(|| mws_iam::org::DEFAULT_ACCESS_ROLE.to_string());
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "CreateAccount", "*", Need::Management)?.id.clone();
        let now = Utc::now();
        let request_id = new_id("car-", 32);
        let email_taken = state.accounts.values().any(|a| a.email.eq_ignore_ascii_case(&input.email));
        let mut status = types::CreateAccountStatus {
            id: Some(request_id.clone()),
            account_name: Some(input.account_name.clone()),
            state: Some("IN_PROGRESS".into()),
            requested_timestamp: Some(now),
            ..Default::default()
        };
        let response = types::CreateAccountResponse { create_account_status: Some(status.clone()) };
        status.completed_timestamp = Some(now);
        if email_taken {
            // AWS accepts the request and fails it asynchronously.
            status.state = Some("FAILED".into());
            status.failure_reason = Some("EMAIL_ALREADY_EXISTS".into());
            let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
            org.create_statuses.insert(request_id, status);
            return Ok(response);
        }
        let account = self.new_account_id(&state);
        state.accounts.insert(
            account.clone(),
            AccountInfo {
                id: account.clone(),
                name: input.account_name,
                email: input.email,
                status: "ACTIVE".into(),
                state: "ACTIVE".into(),
            },
        );
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        org.members.insert(
            account.clone(),
            Member { parent: org.root_id.clone(), joined_method: "CREATED".into(), joined: now, tags },
        );
        attach_defaults(org, &account);
        status.state = Some("SUCCEEDED".into());
        status.account_id = Some(account.clone());
        org.create_statuses.insert(request_id, status);
        let management = org.management_account.clone();
        let all_features = org.feature_set == "ALL";
        drop(state);
        self.iam.create_member_account(&account, &role, &management);
        if all_features {
            self.iam.ensure_service_linked_role(
                &account,
                ORGANIZATIONS_PRINCIPAL,
                "AWSOrganizationsServiceTrustPolicy",
            );
        }
        Ok(response)
    }

    pub(crate) fn create_gov_cloud_account(
        &self,
        ctx: &RequestContext,
        input: types::CreateGovCloudAccountRequest,
    ) -> Result<types::CreateGovCloudAccountResponse, ServiceError> {
        let tags = tags_from(input.tags)?;
        self.authorize(ctx, "CreateGovCloudAccount", "*", request_tag_context(&tags))?;
        let state = self.lock();
        self.caller_org(&state, ctx, "CreateGovCloudAccount", "*", Need::Management)?;
        // MWS accounts are never associated with an AWS GovCloud (US)
        // account, which AWS requires of the management account.
        Err(constraint(
            "MASTER_ACCOUNT_NOT_GOVCLOUD_ENABLED",
            "The management account must have an associated account in the AWS GovCloud (US-West) Region.",
        ))
    }

    pub(crate) fn describe_create_account_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCreateAccountStatusRequest,
    ) -> Result<types::DescribeCreateAccountStatusResponse, ServiceError> {
        self.authorize(ctx, "DescribeCreateAccountStatus", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "DescribeCreateAccountStatus", "*", Need::Read)?;
        let status = org.create_statuses.get(&input.create_account_request_id).cloned().ok_or_else(|| {
            errors::create_account_status_not_found(
                "We can't find an create account request with the CreateAccountRequestId that you specified.",
            )
        })?;
        Ok(types::DescribeCreateAccountStatusResponse { create_account_status: Some(status) })
    }

    pub(crate) fn list_create_account_status(
        &self,
        ctx: &RequestContext,
        input: types::ListCreateAccountStatusRequest,
    ) -> Result<types::ListCreateAccountStatusResponse, ServiceError> {
        self.authorize(ctx, "ListCreateAccountStatus", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListCreateAccountStatus", "*", Need::Read)?;
        let mut all: Vec<_> = org
            .create_statuses
            .values()
            .filter(|s| input.states.as_ref().is_none_or(|w| s.state.as_ref().is_some_and(|st| w.contains(st))))
            .cloned()
            .collect();
        all.sort_by_key(|s| s.requested_timestamp);
        let (statuses, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListCreateAccountStatusResponse { create_account_statuses: Some(statuses), next_token })
    }

    pub(crate) fn describe_account(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountRequest,
    ) -> Result<types::DescribeAccountResponse, ServiceError> {
        let arn = self.account_arn_for(ctx, &input.account_id)?;
        self.authorize(ctx, "DescribeAccount", &arn, ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "DescribeAccount", &arn, Need::Read)?;
        if !org.members.contains_key(&input.account_id) {
            return Err(account_not_found());
        }
        Ok(types::DescribeAccountResponse {
            account: Some(account_wire(&state, org, &input.account_id, &ctx.partition)),
        })
    }

    pub(crate) fn list_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountsRequest,
    ) -> Result<types::ListAccountsResponse, ServiceError> {
        self.authorize(ctx, "ListAccounts", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListAccounts", "*", Need::Read)?;
        let all: Vec<_> = org.members.keys().map(|id| account_wire(&state, org, id, &ctx.partition)).collect();
        let (accounts, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAccountsResponse { accounts: Some(accounts), next_token })
    }

    pub(crate) fn list_accounts_for_parent(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountsForParentRequest,
    ) -> Result<types::ListAccountsForParentResponse, ServiceError> {
        let arn = self.target_arn_for(ctx, &input.parent_id, parent_not_found)?;
        self.authorize(ctx, "ListAccountsForParent", &arn, ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListAccountsForParent", &arn, Need::Read)?;
        if !org.has_parent(&input.parent_id) {
            return Err(parent_not_found());
        }
        let all: Vec<_> = org
            .members
            .iter()
            .filter(|(_, m)| m.parent == input.parent_id)
            .map(|(id, _)| account_wire(&state, org, id, &ctx.partition))
            .collect();
        let (accounts, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAccountsForParentResponse { accounts: Some(accounts), next_token })
    }

    pub(crate) fn move_account(
        &self,
        ctx: &RequestContext,
        input: types::MoveAccountRequest,
    ) -> Result<(), ServiceError> {
        let arn = self.account_arn_for(ctx, &input.account_id)?;
        let mut cond = ConditionContext::new();
        cond.insert("organizations:SourceParentId".into(), vec![input.source_parent_id.clone()]);
        cond.insert("organizations:DestinationParentId".into(), vec![input.destination_parent_id.clone()]);
        self.authorize(ctx, "MoveAccount", &arn, cond)?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "MoveAccount", &arn, Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        let current = org.members.get(&input.account_id).ok_or_else(account_not_found)?.parent.clone();
        if !org.has_parent(&input.source_parent_id) || current != input.source_parent_id {
            return Err(errors::source_parent_not_found(
                "We can't find a source root or OU with the ParentId that you specified.",
            ));
        }
        if !org.has_parent(&input.destination_parent_id) {
            return Err(errors::destination_parent_not_found(
                "We can't find the destination container (a root or OU) with the ParentId that you specified.",
            ));
        }
        if current == input.destination_parent_id {
            return Err(errors::duplicate_account("That account is already present in the specified destination."));
        }
        org.members.get_mut(&input.account_id).expect("checked above").parent = input.destination_parent_id;
        Ok(())
    }

    pub(crate) fn remove_account_from_organization(
        &self,
        ctx: &RequestContext,
        input: types::RemoveAccountFromOrganizationRequest,
    ) -> Result<(), ServiceError> {
        let arn = self.account_arn_for(ctx, &input.account_id)?;
        self.authorize(ctx, "RemoveAccountFromOrganization", &arn, ConditionContext::new())?;
        let mut state = self.lock();
        let org_id = self.caller_org(&state, ctx, "RemoveAccountFromOrganization", &arn, Need::Management)?.id.clone();
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        remove_member(org, &input.account_id)
    }

    pub(crate) fn leave_organization(&self, ctx: &RequestContext, _input: ()) -> Result<(), ServiceError> {
        self.authorize(ctx, "LeaveOrganization", "*", ConditionContext::new())?;
        let account = ctx.caller.account_id.clone();
        let mut state = self.lock();
        let org_id = state.org_id_of(&account).ok_or_else(not_in_use)?;
        let org = state.organizations.get_mut(&org_id).expect("caller's organization exists");
        remove_member(org, &account)
    }

    pub(crate) fn close_account(
        &self,
        ctx: &RequestContext,
        input: types::CloseAccountRequest,
    ) -> Result<(), ServiceError> {
        let arn = self.account_arn_for(ctx, &input.account_id)?;
        self.authorize(ctx, "CloseAccount", &arn, ConditionContext::new())?;
        let mut state = self.lock();
        let org = self.caller_org(&state, ctx, "CloseAccount", &arn, Need::Management)?;
        if !org.members.contains_key(&input.account_id) {
            return Err(account_not_found());
        }
        if org.management_account == input.account_id {
            return Err(constraint(
                "CANNOT_CLOSE_MANAGEMENT_ACCOUNT",
                "You attempted to close the management account. To close the management account for the organization, you must first either remove or close all member accounts in the organization.",
            ));
        }
        let info = state.accounts.get_mut(&input.account_id).ok_or_else(account_not_found)?;
        if info.status != "ACTIVE" {
            return Err(errors::account_already_closed("You attempted to close an account that is already closed."));
        }
        // AWS moves the account through PENDING_CLOSURE to SUSPENDED within
        // minutes; MWS completes it at once.
        info.status = "SUSPENDED".into();
        info.state = "SUSPENDED".into();
        Ok(())
    }
}

/// Take `account` out of `org` (RemoveAccountFromOrganization,
/// LeaveOrganization).
fn remove_member(org: &mut Org, account: &str) -> Result<(), ServiceError> {
    if !org.members.contains_key(account) {
        return Err(account_not_found());
    }
    if org.management_account == account {
        return Err(errors::master_cannot_leave_organization(
            "You can't remove a management account from an organization. If you want the management account to become a member account in another organization, you must first delete the current organization of the management account.",
        ));
    }
    if org.delegated.contains_key(account) {
        return Err(constraint(
            "CANNOT_REMOVE_DELEGATED_ADMINISTRATOR_FROM_ORG",
            "You can't remove an account that is a delegated administrator. Deregister it first.",
        ));
    }
    org.members.remove(account);
    org.attachments.remove(account);
    Ok(())
}
