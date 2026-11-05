//! Administrators and members: invitations, organization accounts added
//! by the delegated administrator, the organization configuration, and
//! the delegated administrator itself (registered through Organizations).

use mws_core::{RequestContext, ServiceError};

use crate::common::{self, account, authorize_hub, hub, invalid_input, not_found, paginate};
use crate::generated::{errors, types};
use crate::hub::ensure_hub;
use crate::state::{key, MemberRec, State};
use crate::{OrgInfo, SecurityHub};

fn result(account: &str, message: &str) -> types::Result {
    types::Result { account_id: Some(account.to_string()), processing_result: Some(message.to_string()) }
}

fn member_wire(admin: &str, account: &str, m: &MemberRec) -> types::Member {
    types::Member {
        account_id: Some(account.to_string()),
        email: m.email.clone(),
        master_id: Some(admin.to_string()),
        administrator_id: Some(admin.to_string()),
        member_status: Some(m.status.clone()),
        invited_at: m.invited_at,
        updated_at: Some(m.updated_at),
    }
}

/// The delegated administrator of the organization `info` describes, in `region`.
fn delegated_admin(state: &State, info: &OrgInfo, region: &str) -> Option<String> {
    state.org_admins.get(&key(&info.management_account, region)).cloned()
}

impl SecurityHub {
    fn org_of(&self, account: &str) -> Option<OrgInfo> {
        self.organizations().and_then(|o| o.organization(account))
    }

    /// If the caller is its organization's delegated administrator and
    /// auto-enable is on, enable Security Hub in organization accounts that
    /// are not members yet and add them, as Security Hub does when accounts
    /// join the organization.
    pub(crate) fn sync_organization(&self, ctx: &RequestContext) {
        let Some(info) = self.org_of(account(ctx)) else { return };
        let mut state = self.write();
        if delegated_admin(&state, &info, &ctx.region).as_deref() != Some(account(ctx)) {
            return;
        }
        let admin_key = key(account(ctx), &ctx.region);
        let Some(config) = state.org_configs.get(&admin_key).cloned() else { return };
        if !config.auto_enable || config.configuration_type == "CENTRAL" {
            return;
        }
        for a in info.accounts.iter().filter(|a| a.active && a.id != account(ctx)) {
            let known = state.members.get(&admin_key).is_some_and(|m| m.contains_key(&a.id));
            if known {
                continue;
            }
            ensure_hub(
                &mut state,
                &ctx.partition,
                &a.id,
                &ctx.region,
                ctx.received_at,
                config.auto_enable_standards == "DEFAULT",
            );
            state.members.entry(admin_key.clone()).or_default().insert(
                a.id.clone(),
                MemberRec {
                    email: Some(a.email.clone()),
                    status: "Enabled".into(),
                    invitation_id: None,
                    invited_at: None,
                    updated_at: ctx.received_at,
                    organization: true,
                },
            );
        }
    }

    pub(crate) fn create_members_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateMembersRequest,
    ) -> Result<types::CreateMembersResponse, ServiceError> {
        authorize_hub(ctx, "CreateMembers")?;
        let org = self.org_of(account(ctx));
        let mut state = self.write();
        hub(&state, ctx)?;
        if state.administrator_of(account(ctx), &ctx.region).is_some() {
            return Err(errors::invalid_access("A member account can't add member accounts."));
        }
        let admin_key = key(account(ctx), &ctx.region);
        let is_delegated =
            org.as_ref().is_some_and(|o| delegated_admin(&state, o, &ctx.region).as_deref() == Some(account(ctx)));
        let standards =
            state.org_configs.get(&admin_key).cloned().unwrap_or_default().auto_enable_standards == "DEFAULT";
        let mut unprocessed = Vec::new();
        for d in input.account_details {
            if !common::is_account_id(&d.account_id) {
                unprocessed.push(result(&d.account_id, "Invalid account ID"));
                continue;
            }
            if d.account_id == account(ctx) {
                unprocessed.push(result(&d.account_id, "The administrator account can't be added as a member"));
                continue;
            }
            if let Some(other) = state.administrator_of(&d.account_id, &ctx.region) {
                if other != account(ctx) {
                    unprocessed
                        .push(result(&d.account_id, "Account is already a member of another administrator account"));
                    continue;
                }
            }
            let org_account = is_delegated
                .then(|| org.as_ref().and_then(|o| o.accounts.iter().find(|a| a.id == d.account_id && a.active)))
                .flatten()
                .cloned();
            if let Some(a) = org_account {
                ensure_hub(&mut state, &ctx.partition, &a.id, &ctx.region, ctx.received_at, standards);
                state.members.entry(admin_key.clone()).or_default().insert(
                    a.id.clone(),
                    MemberRec {
                        email: d.email.clone().or(Some(a.email)),
                        status: "Enabled".into(),
                        invitation_id: None,
                        invited_at: None,
                        updated_at: ctx.received_at,
                        organization: true,
                    },
                );
                continue;
            }
            let members = state.members.entry(admin_key.clone()).or_default();
            match members.get_mut(&d.account_id) {
                Some(m) if matches!(m.status.as_str(), "Removed" | "Resigned" | "Deleted") => {
                    m.status = "Created".into();
                    m.email = d.email.clone().or(m.email.take());
                    m.updated_at = ctx.received_at;
                }
                Some(_) => {}
                None => {
                    members.insert(
                        d.account_id.clone(),
                        MemberRec {
                            email: d.email.clone(),
                            status: "Created".into(),
                            invitation_id: None,
                            invited_at: None,
                            updated_at: ctx.received_at,
                            organization: false,
                        },
                    );
                }
            }
        }
        Ok(types::CreateMembersResponse { unprocessed_accounts: Some(unprocessed) })
    }

    pub(crate) fn invite_members_op(
        &self,
        ctx: &RequestContext,
        input: types::InviteMembersRequest,
    ) -> Result<types::InviteMembersResponse, ServiceError> {
        authorize_hub(ctx, "InviteMembers")?;
        let mut state = self.write();
        hub(&state, ctx)?;
        let admin_key = key(account(ctx), &ctx.region);
        let mut unprocessed = Vec::new();
        for a in input.account_ids {
            let Some(m) = state.members.get_mut(&admin_key).and_then(|m| m.get_mut(&a)) else {
                unprocessed.push(result(&a, "The request is rejected because the specified account is not a member"));
                continue;
            };
            if m.organization || m.status == "Enabled" {
                continue;
            }
            m.status = "Invited".into();
            m.invitation_id = Some(uuid::Uuid::new_v4().simple().to_string());
            m.invited_at = Some(ctx.received_at);
            m.updated_at = ctx.received_at;
        }
        Ok(types::InviteMembersResponse { unprocessed_accounts: Some(unprocessed) })
    }

    pub(crate) fn list_invitations_op(
        &self,
        ctx: &RequestContext,
        input: types::ListInvitationsRequest,
    ) -> Result<types::ListInvitationsResponse, ServiceError> {
        authorize_hub(ctx, "ListInvitations")?;
        let state = self.read();
        hub(&state, ctx)?;
        let all: Vec<types::Invitation> = state
            .invitations_for(account(ctx), &ctx.region)
            .into_iter()
            .map(|(admin, m)| types::Invitation {
                account_id: Some(admin),
                invitation_id: m.invitation_id,
                invited_at: m.invited_at,
                member_status: Some("Pending".into()),
            })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListInvitationsResponse { invitations: Some(page), next_token })
    }

    pub(crate) fn get_invitations_count_op(
        &self,
        ctx: &RequestContext,
        _input: types::GetInvitationsCountRequest,
    ) -> Result<types::GetInvitationsCountResponse, ServiceError> {
        authorize_hub(ctx, "GetInvitationsCount")?;
        let state = self.read();
        hub(&state, ctx)?;
        Ok(types::GetInvitationsCountResponse {
            invitations_count: Some(state.invitations_for(account(ctx), &ctx.region).len() as i32),
        })
    }

    fn accept(&self, ctx: &RequestContext, admin: &str, invitation_id: &str) -> Result<(), ServiceError> {
        let mut state = self.write();
        hub(&state, ctx)?;
        if let Some(current) = state.administrator_of(account(ctx), &ctx.region) {
            if current != admin {
                return Err(invalid_input("The account is already associated with an administrator account."));
            }
        }
        let m = state
            .members
            .get_mut(&key(admin, &ctx.region))
            .and_then(|m| m.get_mut(account(ctx)))
            .filter(|m| m.status == "Invited" && m.invitation_id.as_deref() == Some(invitation_id))
            .ok_or_else(|| not_found(format!("Invitation {invitation_id} from account {admin} not found")))?;
        m.status = "Enabled".into();
        m.updated_at = ctx.received_at;
        Ok(())
    }

    pub(crate) fn accept_administrator_invitation_op(
        &self,
        ctx: &RequestContext,
        input: types::AcceptAdministratorInvitationRequest,
    ) -> Result<types::AcceptAdministratorInvitationResponse, ServiceError> {
        authorize_hub(ctx, "AcceptAdministratorInvitation")?;
        self.accept(ctx, &input.administrator_id, &input.invitation_id)?;
        Ok(types::AcceptAdministratorInvitationResponse {})
    }

    pub(crate) fn accept_invitation_op(
        &self,
        ctx: &RequestContext,
        input: types::AcceptInvitationRequest,
    ) -> Result<types::AcceptInvitationResponse, ServiceError> {
        authorize_hub(ctx, "AcceptInvitation")?;
        self.accept(ctx, &input.master_id, &input.invitation_id)?;
        Ok(types::AcceptInvitationResponse {})
    }

    /// Decline or delete invitations from the listed administrators.
    fn drop_invitations(&self, ctx: &RequestContext, admins: Vec<String>) -> Vec<types::Result> {
        let mut state = self.write();
        let mut unprocessed = Vec::new();
        for admin in admins {
            let m = state
                .members
                .get_mut(&key(&admin, &ctx.region))
                .and_then(|m| m.get_mut(account(ctx)))
                .filter(|m| m.status == "Invited");
            match m {
                Some(m) => {
                    m.status = "Removed".into();
                    m.invitation_id = None;
                    m.updated_at = ctx.received_at;
                }
                None => unprocessed.push(result(&admin, "Invitation not found")),
            }
        }
        unprocessed
    }

    pub(crate) fn decline_invitations_op(
        &self,
        ctx: &RequestContext,
        input: types::DeclineInvitationsRequest,
    ) -> Result<types::DeclineInvitationsResponse, ServiceError> {
        authorize_hub(ctx, "DeclineInvitations")?;
        Ok(types::DeclineInvitationsResponse {
            unprocessed_accounts: Some(self.drop_invitations(ctx, input.account_ids)),
        })
    }

    pub(crate) fn delete_invitations_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInvitationsRequest,
    ) -> Result<types::DeleteInvitationsResponse, ServiceError> {
        authorize_hub(ctx, "DeleteInvitations")?;
        Ok(types::DeleteInvitationsResponse {
            unprocessed_accounts: Some(self.drop_invitations(ctx, input.account_ids)),
        })
    }

    fn administrator(&self, ctx: &RequestContext) -> Result<Option<types::Invitation>, ServiceError> {
        let state = self.read();
        hub(&state, ctx)?;
        let Some(admin) = state.administrator_of(account(ctx), &ctx.region) else { return Ok(None) };
        let m = &state.members[&key(&admin, &ctx.region)][account(ctx)];
        Ok(Some(types::Invitation {
            account_id: Some(admin),
            invitation_id: m.invitation_id.clone(),
            invited_at: m.invited_at.or(Some(m.updated_at)),
            member_status: Some(m.status.clone()),
        }))
    }

    pub(crate) fn get_administrator_account_op(
        &self,
        ctx: &RequestContext,
        _input: types::GetAdministratorAccountRequest,
    ) -> Result<types::GetAdministratorAccountResponse, ServiceError> {
        authorize_hub(ctx, "GetAdministratorAccount")?;
        Ok(types::GetAdministratorAccountResponse { administrator: self.administrator(ctx)? })
    }

    pub(crate) fn get_master_account_op(
        &self,
        ctx: &RequestContext,
        _input: types::GetMasterAccountRequest,
    ) -> Result<types::GetMasterAccountResponse, ServiceError> {
        authorize_hub(ctx, "GetMasterAccount")?;
        Ok(types::GetMasterAccountResponse { master: self.administrator(ctx)? })
    }

    fn resign(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        let mut state = self.write();
        hub(&state, ctx)?;
        let admin = state
            .administrator_of(account(ctx), &ctx.region)
            .ok_or_else(|| not_found("The account is not associated with an administrator account."))?;
        let m = state.members.get_mut(&key(&admin, &ctx.region)).and_then(|m| m.get_mut(account(ctx))).expect("member");
        if m.organization {
            return Err(invalid_input(
                "An organization member account can't disassociate from its administrator account. The administrator account must disassociate it.",
            ));
        }
        m.status = "Resigned".into();
        m.updated_at = ctx.received_at;
        Ok(())
    }

    pub(crate) fn disassociate_from_administrator_account_op(
        &self,
        ctx: &RequestContext,
        _input: types::DisassociateFromAdministratorAccountRequest,
    ) -> Result<types::DisassociateFromAdministratorAccountResponse, ServiceError> {
        authorize_hub(ctx, "DisassociateFromAdministratorAccount")?;
        self.resign(ctx)?;
        Ok(types::DisassociateFromAdministratorAccountResponse {})
    }

    pub(crate) fn disassociate_from_master_account_op(
        &self,
        ctx: &RequestContext,
        _input: types::DisassociateFromMasterAccountRequest,
    ) -> Result<types::DisassociateFromMasterAccountResponse, ServiceError> {
        authorize_hub(ctx, "DisassociateFromMasterAccount")?;
        self.resign(ctx)?;
        Ok(types::DisassociateFromMasterAccountResponse {})
    }

    pub(crate) fn disassociate_members_op(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateMembersRequest,
    ) -> Result<types::DisassociateMembersResponse, ServiceError> {
        authorize_hub(ctx, "DisassociateMembers")?;
        let mut state = self.write();
        hub(&state, ctx)?;
        let admin_key = key(account(ctx), &ctx.region);
        for a in &input.account_ids {
            let m =
                state.members.get_mut(&admin_key).and_then(|m| m.get_mut(a)).ok_or_else(|| {
                    invalid_input(format!("Account {a} is not a member of this administrator account."))
                })?;
            m.status = "Removed".into();
            m.updated_at = ctx.received_at;
        }
        Ok(types::DisassociateMembersResponse {})
    }

    pub(crate) fn delete_members_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMembersRequest,
    ) -> Result<types::DeleteMembersResponse, ServiceError> {
        authorize_hub(ctx, "DeleteMembers")?;
        let mut state = self.write();
        hub(&state, ctx)?;
        let admin_key = key(account(ctx), &ctx.region);
        let mut unprocessed = Vec::new();
        for a in input.account_ids {
            let members = state.members.entry(admin_key.clone()).or_default();
            match members.get(&a) {
                None => unprocessed.push(result(&a, "Account not found")),
                Some(m) if m.organization && m.status == "Enabled" => unprocessed
                    .push(result(&a, "An organization member account must be disassociated before it can be deleted")),
                Some(_) => {
                    members.remove(&a);
                }
            }
        }
        Ok(types::DeleteMembersResponse { unprocessed_accounts: Some(unprocessed) })
    }

    pub(crate) fn get_members_op(
        &self,
        ctx: &RequestContext,
        input: types::GetMembersRequest,
    ) -> Result<types::GetMembersResponse, ServiceError> {
        authorize_hub(ctx, "GetMembers")?;
        self.sync_organization(ctx);
        let state = self.read();
        hub(&state, ctx)?;
        let members = state.members.get(&key(account(ctx), &ctx.region));
        let mut found = Vec::new();
        let mut unprocessed = Vec::new();
        for a in input.account_ids {
            match members.and_then(|m| m.get(&a)) {
                Some(m) => found.push(member_wire(account(ctx), &a, m)),
                None => unprocessed.push(result(&a, "Account not found")),
            }
        }
        Ok(types::GetMembersResponse { members: Some(found), unprocessed_accounts: Some(unprocessed) })
    }

    pub(crate) fn list_members_op(
        &self,
        ctx: &RequestContext,
        input: types::ListMembersRequest,
    ) -> Result<types::ListMembersResponse, ServiceError> {
        authorize_hub(ctx, "ListMembers")?;
        self.sync_organization(ctx);
        let state = self.read();
        hub(&state, ctx)?;
        let only_associated = input.only_associated.unwrap_or(true);
        let all: Vec<types::Member> = state
            .members
            .get(&key(account(ctx), &ctx.region))
            .into_iter()
            .flatten()
            .filter(|(_, m)| !only_associated || m.status == "Enabled")
            .map(|(a, m)| member_wire(account(ctx), a, m))
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListMembersResponse { members: Some(page), next_token })
    }

    // ---- organization ------------------------------------------------------------

    /// The caller's organization, which the caller must manage.
    fn managed_org(&self, ctx: &RequestContext) -> Result<OrgInfo, ServiceError> {
        match self.org_of(account(ctx)) {
            Some(o) if o.management_account == account(ctx) => Ok(o),
            Some(_) => Err(errors::invalid_access(format!(
                "Account {} is not the management account of the organization.",
                account(ctx)
            ))),
            None => {
                Err(errors::invalid_access(format!("Account {} is not part of an AWS organization.", account(ctx))))
            }
        }
    }

    pub(crate) fn enable_organization_admin_account_op(
        &self,
        ctx: &RequestContext,
        input: types::EnableOrganizationAdminAccountRequest,
    ) -> Result<types::EnableOrganizationAdminAccountResponse, ServiceError> {
        authorize_hub(ctx, "EnableOrganizationAdminAccount")?;
        let org = self.managed_org(ctx)?;
        if !org.accounts.iter().any(|a| a.id == input.admin_account_id) {
            return Err(invalid_input(format!(
                "Account {} is not a member of the organization.",
                input.admin_account_id
            )));
        }
        let mgmt_key = key(account(ctx), &ctx.region);
        if let Some(existing) = self.read().org_admins.get(&mgmt_key) {
            if *existing != input.admin_account_id {
                return Err(invalid_input(format!(
                    "Account {existing} is already the delegated administrator for Security Hub in this Region. Remove it first."
                )));
            }
        }
        if input.admin_account_id != account(ctx) {
            if let Some(link) = self.organizations() {
                link.register_delegated_administrator(account(ctx), &input.admin_account_id).map_err(invalid_input)?;
            }
        }
        let mut state = self.write();
        state.org_admins.insert(mgmt_key, input.admin_account_id.clone());
        ensure_hub(&mut state, &ctx.partition, &input.admin_account_id, &ctx.region, ctx.received_at, true);
        state.org_configs.entry(key(&input.admin_account_id, &ctx.region)).or_default();
        Ok(types::EnableOrganizationAdminAccountResponse {
            admin_account_id: Some(input.admin_account_id),
            feature: Some(input.feature.unwrap_or_else(|| "SecurityHub".into())),
        })
    }

    pub(crate) fn disable_organization_admin_account_op(
        &self,
        ctx: &RequestContext,
        input: types::DisableOrganizationAdminAccountRequest,
    ) -> Result<types::DisableOrganizationAdminAccountResponse, ServiceError> {
        authorize_hub(ctx, "DisableOrganizationAdminAccount")?;
        let _org = self.managed_org(ctx)?;
        let mgmt_key = key(account(ctx), &ctx.region);
        {
            let mut state = self.write();
            if state.org_admins.get(&mgmt_key) != Some(&input.admin_account_id) {
                return Err(invalid_input(format!(
                    "Account {} is not the delegated administrator for Security Hub.",
                    input.admin_account_id
                )));
            }
            state.org_admins.remove(&mgmt_key);
            let admin_key = key(&input.admin_account_id, &ctx.region);
            if let Some(members) = state.members.get_mut(&admin_key) {
                members.retain(|_, m| !m.organization);
            }
            state.org_configs.remove(&admin_key);
        }
        if let Some(link) = self.organizations() {
            let still_admin = self
                .read()
                .org_admins
                .iter()
                .any(|(k, a)| k.starts_with(&format!("{}/", account(ctx))) && *a == input.admin_account_id);
            if !still_admin {
                link.deregister_delegated_administrator(account(ctx), &input.admin_account_id);
            }
        }
        Ok(types::DisableOrganizationAdminAccountResponse {})
    }

    pub(crate) fn list_organization_admin_accounts_op(
        &self,
        ctx: &RequestContext,
        input: types::ListOrganizationAdminAccountsRequest,
    ) -> Result<types::ListOrganizationAdminAccountsResponse, ServiceError> {
        authorize_hub(ctx, "ListOrganizationAdminAccounts")?;
        let org = self.org_of(account(ctx)).ok_or_else(|| {
            errors::invalid_access(format!("Account {} is not part of an AWS organization.", account(ctx)))
        })?;
        let state = self.read();
        if org.management_account != account(ctx)
            && delegated_admin(&state, &org, &ctx.region).as_deref() != Some(account(ctx))
        {
            return Err(errors::invalid_access(format!(
                "Account {} is not the management account of the organization.",
                account(ctx)
            )));
        }
        let all: Vec<types::AdminAccount> = delegated_admin(&state, &org, &ctx.region)
            .into_iter()
            .map(|a| types::AdminAccount { account_id: Some(a), status: Some("ENABLED".into()) })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 10, input.next_token.as_deref())?;
        Ok(types::ListOrganizationAdminAccountsResponse {
            admin_accounts: Some(page),
            next_token,
            feature: Some(input.feature.unwrap_or_else(|| "SecurityHub".into())),
        })
    }

    /// The caller must be its organization's delegated administrator.
    pub(crate) fn require_delegated_admin(&self, ctx: &RequestContext) -> Result<OrgInfo, ServiceError> {
        let not_admin = || {
            errors::invalid_access(format!("Account {} is not an administrator for this organization", account(ctx)))
        };
        let org = self.org_of(account(ctx)).ok_or_else(not_admin)?;
        if delegated_admin(&self.read(), &org, &ctx.region).as_deref() != Some(account(ctx)) {
            return Err(not_admin());
        }
        Ok(org)
    }

    pub(crate) fn describe_organization_configuration_op(
        &self,
        ctx: &RequestContext,
        _input: types::DescribeOrganizationConfigurationRequest,
    ) -> Result<types::DescribeOrganizationConfigurationResponse, ServiceError> {
        authorize_hub(ctx, "DescribeOrganizationConfiguration")?;
        self.require_delegated_admin(ctx)?;
        let state = self.read();
        hub(&state, ctx)?;
        let c = state.org_configs.get(&key(account(ctx), &ctx.region)).cloned().unwrap_or_default();
        Ok(types::DescribeOrganizationConfigurationResponse {
            auto_enable: Some(c.auto_enable),
            member_account_limit_reached: Some(false),
            auto_enable_standards: Some(c.auto_enable_standards),
            organization_configuration: Some(types::OrganizationConfiguration {
                configuration_type: Some(c.configuration_type),
                status: Some("ENABLED".into()),
                status_message: None,
            }),
        })
    }

    pub(crate) fn update_organization_configuration_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOrganizationConfigurationRequest,
    ) -> Result<types::UpdateOrganizationConfigurationResponse, ServiceError> {
        authorize_hub(ctx, "UpdateOrganizationConfiguration")?;
        self.require_delegated_admin(ctx)?;
        let mut state = self.write();
        let h = hub(&state, ctx)?;
        let mut c = state.org_configs.get(&key(account(ctx), &ctx.region)).cloned().unwrap_or_default();
        let ty = input
            .organization_configuration
            .as_ref()
            .and_then(|o| o.configuration_type.clone())
            .unwrap_or_else(|| c.configuration_type.clone());
        if ty == "CENTRAL" {
            if h.finding_aggregator.is_none() {
                return Err(invalid_input(
                    "Central configuration requires a home Region. Create a finding aggregator in this Region first.",
                ));
            }
            if input.auto_enable || input.auto_enable_standards.as_deref().is_some_and(|s| s != "NONE") {
                return Err(invalid_input(
                    "When ConfigurationType is CENTRAL, AutoEnable must be false and AutoEnableStandards must be NONE.",
                ));
            }
            c.auto_enable_standards = "NONE".into();
        } else if let Some(s) = input.auto_enable_standards {
            c.auto_enable_standards = s;
        }
        c.auto_enable = input.auto_enable;
        c.configuration_type = ty;
        state.org_configs.insert(key(account(ctx), &ctx.region), c);
        Ok(types::UpdateOrganizationConfigurationResponse {})
    }
}
