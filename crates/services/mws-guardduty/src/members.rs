//! Multi-account management: members and invitations from both sides.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::common::*;
use crate::detectors::{apply_features, data_source_features, data_sources_result, member_features_result};
use crate::generated::types;
use crate::state::{AdminLink, Invite, MemberRec, State};
use crate::GuardDuty;

fn not_associated() -> String {
    "The request is rejected because the given account ID is not an associated member of account the current account."
        .into()
}

impl GuardDuty {
    fn member_wire(state: &State, ctx: &RequestContext, admin: &str, m: &MemberRec) -> types::Member {
        let detector_id = if m.status == "Enabled" || m.status == "Disabled" {
            state.detector(&m.account, &ctx.region).map(|d| d.id.clone())
        } else {
            None
        };
        types::Member {
            account_id: m.account.clone(),
            detector_id,
            master_id: admin.to_string(),
            email: m.email.clone(),
            relationship_status: m.status.clone(),
            invited_at: m.invited_at.map(iso),
            updated_at: iso(m.updated_at),
            administrator_id: Some(admin.to_string()),
        }
    }

    /// Make `member` an enabled member of `admin` (both sides).
    pub(crate) fn associate(state: &mut State, ctx: &RequestContext, admin: &str, member: &str, via_org: bool) {
        let now = ctx.received_at;
        if state.detector(member, &ctx.region).is_none() {
            state.account_mut(member, &ctx.region).detector = Some(crate::detectors::new_detector(now));
        }
        let invitation = state
            .detector(admin, &ctx.region)
            .and_then(|d| d.members.get(member))
            .and_then(|m| m.invitation_id.clone().map(|id| (id, m.invited_at)));
        state.account_mut(member, &ctx.region).administrator = Some(AdminLink {
            account: admin.to_string(),
            invitation_id: invitation.as_ref().map(|(id, _)| id.clone()),
            invited_at: invitation.and_then(|(_, at)| at),
        });
        state.account_mut(member, &ctx.region).invitations.remove(admin);
        if let Some(d) = state.detector_mut(admin, &ctx.region) {
            if let Some(m) = d.members.get_mut(member) {
                m.status = "Enabled".into();
                m.updated_at = now;
                m.via_organization |= via_org;
            }
        }
    }

    /// End `member`'s association with `admin` from the administrator's
    /// side, leaving the member record with `status`.
    fn dissociate(state: &mut State, ctx: &RequestContext, admin: &str, member: &str, status: &str) {
        let acct = state.account_mut(member, &ctx.region);
        if acct.administrator.as_ref().is_some_and(|l| l.account == admin) {
            acct.administrator = None;
        }
        if let Some(d) = state.detector_mut(admin, &ctx.region) {
            if let Some(m) = d.members.get_mut(member) {
                m.status = status.into();
                m.updated_at = ctx.received_at;
            }
        }
    }

    pub(crate) fn create_members(
        &self,
        ctx: &RequestContext,
        input: types::CreateMembersRequest,
    ) -> Result<types::CreateMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "CreateMembers", &input.detector_id)?;
        let admin = ctx.caller.account_id.clone();
        let org = self.organizations().and_then(|o| o.organization(&admin));
        let mut state = self.lock();
        Self::owned(&state, ctx, &input.detector_id)?;
        if state.account(&admin, &ctx.region).is_some_and(|a| a.administrator.is_some()) {
            return Err(invalid_input(
                "The request is rejected because the current account is a member account and cannot create members.",
            ));
        }
        let org_admin = org.as_ref().filter(|o| Self::org_admin_of(&state, &o.id, &ctx.region) == Some(admin.as_str()));
        let mut unprocessed_accounts = Vec::new();
        for detail in input.account_details {
            let id = detail.account_id.clone();
            if !is_account_id(&id) {
                unprocessed_accounts
                    .push(unprocessed(&id, "The request is rejected because the account ID is invalid."));
                continue;
            }
            if id == admin {
                unprocessed_accounts.push(unprocessed(
                    &id,
                    "The request is rejected because the current account cannot create itself as a member.",
                ));
                continue;
            }
            let in_org = org_admin.is_some_and(|o| o.accounts.iter().any(|a| a.id == id));
            if let Some(other) = state.account(&id, &ctx.region).and_then(|a| a.administrator.as_ref()) {
                if other.account != admin {
                    unprocessed_accounts.push(unprocessed(
                        &id,
                        "The request is rejected because the given account ID is already associated with another administrator account.",
                    ));
                    continue;
                }
            }
            let det = state.detector_mut(&admin, &ctx.region).expect("checked above");
            let existing = det.members.get(&id).map(|m| m.status.clone());
            match existing.as_deref() {
                Some("Enabled") | Some("Disabled") | Some("Invited") => {
                    unprocessed_accounts.push(unprocessed(
                        &id,
                        "The request is rejected because the input account ID is already a member of the current account.",
                    ));
                    continue;
                }
                _ => {}
            }
            det.members.insert(
                id.clone(),
                MemberRec {
                    account: id.clone(),
                    email: detail.email,
                    status: "Created".into(),
                    invited_at: None,
                    updated_at: ctx.received_at,
                    invitation_id: None,
                    via_organization: in_org,
                },
            );
            if in_org {
                Self::associate(&mut state, ctx, &admin, &id, true);
            }
        }
        Ok(types::CreateMembersResponse { unprocessed_accounts })
    }

    pub(crate) fn invite_members(
        &self,
        ctx: &RequestContext,
        input: types::InviteMembersRequest,
    ) -> Result<types::InviteMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "InviteMembers", &input.detector_id)?;
        let admin = ctx.caller.account_id.clone();
        let mut state = self.lock();
        Self::owned(&state, ctx, &input.detector_id)?;
        let mut unprocessed_accounts = Vec::new();
        for id in input.account_ids {
            let det = state.detector(&admin, &ctx.region).expect("checked above");
            let Some(m) = det.members.get(&id) else {
                unprocessed_accounts.push(unprocessed(&id, not_associated()));
                continue;
            };
            if m.status == "Enabled" || m.status == "Disabled" {
                unprocessed_accounts.push(unprocessed(
                    &id,
                    "The request is rejected because the given account ID is already an associated member.",
                ));
                continue;
            }
            if m.via_organization {
                unprocessed_accounts.push(unprocessed(
                    &id,
                    "The request is rejected because the account is managed by your organization. Organization accounts don't need invitations.",
                ));
                continue;
            }
            let invitation_id = hex_id(32);
            let now = ctx.received_at;
            let det = state.detector_mut(&admin, &ctx.region).expect("checked above");
            let m = det.members.get_mut(&id).expect("checked above");
            m.status = "Invited".into();
            m.invited_at = Some(now);
            m.updated_at = now;
            m.invitation_id = Some(invitation_id.clone());
            state
                .account_mut(&id, &ctx.region)
                .invitations
                .insert(admin.clone(), Invite { invitation_id, invited_at: now, message: input.message.clone() });
        }
        Ok(types::InviteMembersResponse { unprocessed_accounts })
    }

    pub(crate) fn get_members(
        &self,
        ctx: &RequestContext,
        input: types::GetMembersRequest,
    ) -> Result<types::GetMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "GetMembers", &input.detector_id)?;
        let admin = ctx.caller.account_id.clone();
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let mut members = Vec::new();
        let mut unprocessed_accounts = Vec::new();
        for id in &input.account_ids {
            match det.members.get(id) {
                Some(m) => members.push(Self::member_wire(&state, ctx, &admin, m)),
                None => unprocessed_accounts.push(unprocessed(id, not_associated())),
            }
        }
        Ok(types::GetMembersResponse { members, unprocessed_accounts })
    }

    pub(crate) fn list_members(
        &self,
        ctx: &RequestContext,
        input: types::ListMembersRequest,
    ) -> Result<types::ListMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "ListMembers", &input.detector_id)?;
        let admin = ctx.caller.account_id.clone();
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let only = input.only_associated.as_deref() != Some("false");
        let all: Vec<types::Member> = det
            .members
            .values()
            .filter(|m| !only || m.status == "Enabled" || m.status == "Disabled")
            .map(|m| Self::member_wire(&state, ctx, &admin, m))
            .collect();
        let (members, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListMembersResponse { members: Some(members), next_token })
    }

    /// Run `f` for each account of `ids` that is a member of the caller's
    /// detector; others are unprocessed.
    fn each_member(
        &self,
        ctx: &RequestContext,
        detector_id: &str,
        ids: &[String],
        mut f: impl FnMut(&mut State, &str, &MemberRec) -> Option<String>,
    ) -> Result<Vec<types::UnprocessedAccount>, ServiceError> {
        let admin = ctx.caller.account_id.clone();
        let mut state = self.lock();
        Self::owned(&state, ctx, detector_id)?;
        let mut out = Vec::new();
        for id in ids {
            let m = state.detector(&admin, &ctx.region).and_then(|d| d.members.get(id)).cloned();
            match m {
                None => out.push(unprocessed(id, not_associated())),
                Some(m) => {
                    if let Some(err) = f(&mut state, &admin, &m) {
                        out.push(unprocessed(id, err));
                    }
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn disassociate_members(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateMembersRequest,
    ) -> Result<types::DisassociateMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "DisassociateMembers", &input.detector_id)?;
        let unprocessed_accounts =
            self.each_member(ctx, &input.detector_id, &input.account_ids, |state, admin, m| {
                Self::dissociate(state, ctx, admin, &m.account, "Removed");
                None
            })?;
        Ok(types::DisassociateMembersResponse { unprocessed_accounts })
    }

    pub(crate) fn delete_members(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMembersRequest,
    ) -> Result<types::DeleteMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "DeleteMembers", &input.detector_id)?;
        let unprocessed_accounts = self.each_member(ctx, &input.detector_id, &input.account_ids, |state, admin, m| {
            if m.status == "Enabled" && m.via_organization {
                return Some(
                    "The request is rejected because the account is an associated organization member. Disassociate it first."
                        .into(),
                );
            }
            Self::dissociate(state, ctx, admin, &m.account, "Removed");
            state.account_mut(&m.account, &ctx.region).invitations.remove(admin);
            if let Some(d) = state.detector_mut(admin, &ctx.region) {
                d.members.remove(&m.account);
            }
            None
        })?;
        Ok(types::DeleteMembersResponse { unprocessed_accounts })
    }

    pub(crate) fn stop_monitoring_members(
        &self,
        ctx: &RequestContext,
        input: types::StopMonitoringMembersRequest,
    ) -> Result<types::StopMonitoringMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "StopMonitoringMembers", &input.detector_id)?;
        let unprocessed_accounts =
            self.each_member(ctx, &input.detector_id, &input.account_ids, |state, admin, m| {
                if m.status != "Enabled" && m.status != "Disabled" {
                    return Some(not_associated());
                }
                if let Some(r) = state.detector_mut(admin, &ctx.region).and_then(|d| d.members.get_mut(&m.account)) {
                    r.status = "Disabled".into();
                    r.updated_at = ctx.received_at;
                }
                None
            })?;
        Ok(types::StopMonitoringMembersResponse { unprocessed_accounts })
    }

    pub(crate) fn start_monitoring_members(
        &self,
        ctx: &RequestContext,
        input: types::StartMonitoringMembersRequest,
    ) -> Result<types::StartMonitoringMembersResponse, ServiceError> {
        self.authorize_detector(ctx, "StartMonitoringMembers", &input.detector_id)?;
        let unprocessed_accounts =
            self.each_member(ctx, &input.detector_id, &input.account_ids, |state, admin, m| {
                if m.status != "Enabled" && m.status != "Disabled" {
                    return Some(not_associated());
                }
                if let Some(r) = state.detector_mut(admin, &ctx.region).and_then(|d| d.members.get_mut(&m.account)) {
                    r.status = "Enabled".into();
                    r.updated_at = ctx.received_at;
                }
                None
            })?;
        Ok(types::StartMonitoringMembersResponse { unprocessed_accounts })
    }

    pub(crate) fn get_member_detectors(
        &self,
        ctx: &RequestContext,
        input: types::GetMemberDetectorsRequest,
    ) -> Result<types::GetMemberDetectorsResponse, ServiceError> {
        self.authorize_detector(ctx, "GetMemberDetectors", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let mut configs = Vec::new();
        let mut unprocessed_accounts = Vec::new();
        for id in &input.account_ids {
            let associated = det.members.get(id).is_some_and(|m| m.status == "Enabled" || m.status == "Disabled");
            match state.detector(id, &ctx.region).filter(|_| associated) {
                Some(md) => configs.push(types::MemberDataSourceConfiguration {
                    account_id: id.clone(),
                    data_sources: data_sources_result(ctx, id, md),
                    features: Some(member_features_result(md)),
                }),
                None => unprocessed_accounts.push(unprocessed(id, not_associated())),
            }
        }
        Ok(types::GetMemberDetectorsResponse { member_data_source_configurations: configs, unprocessed_accounts })
    }

    pub(crate) fn update_member_detectors(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMemberDetectorsRequest,
    ) -> Result<types::UpdateMemberDetectorsResponse, ServiceError> {
        self.authorize_detector(ctx, "UpdateMemberDetectors", &input.detector_id)?;
        if input.data_sources.is_some() && input.features.is_some() {
            return Err(invalid_input(
                "The request is rejected because both data source and feature configurations are specified. Use only features.",
            ));
        }
        let mut requested = input.data_sources.as_ref().map(data_source_features).unwrap_or_default();
        for f in input.features.iter().flatten() {
            let add = f.additional_configuration.iter().flatten().map(|a| (a.name.clone(), a.status.clone())).collect();
            requested.push((f.name.clone(), f.status.clone(), add));
        }
        let mut err = None;
        let unprocessed_accounts = self.each_member(ctx, &input.detector_id, &input.account_ids, |state, _, m| {
            if m.status != "Enabled" && m.status != "Disabled" {
                return Some(not_associated());
            }
            let det = state.detector_mut(&m.account, &ctx.region)?;
            if let Err(e) = apply_features(&mut det.features, &requested, ctx.received_at) {
                err = Some(e);
            }
            det.updated_at = ctx.received_at;
            None
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        Ok(types::UpdateMemberDetectorsResponse { unprocessed_accounts })
    }

    // ---- the member's side ----------------------------------------------

    pub(crate) fn list_invitations(
        &self,
        ctx: &RequestContext,
        input: types::ListInvitationsRequest,
    ) -> Result<types::ListInvitationsResponse, ServiceError> {
        self.authorize(ctx, "ListInvitations", "*", ConditionContext::new())?;
        let state = self.lock();
        let all: Vec<types::Invitation> = state
            .account(&ctx.caller.account_id, &ctx.region)
            .map(|a| {
                a.invitations
                    .iter()
                    .map(|(admin, i)| types::Invitation {
                        account_id: Some(admin.clone()),
                        invitation_id: Some(i.invitation_id.clone()),
                        relationship_status: Some("Invited".into()),
                        invited_at: Some(iso(i.invited_at)),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (invitations, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListInvitationsResponse { invitations: Some(invitations), next_token })
    }

    pub(crate) fn get_invitations_count(
        &self,
        ctx: &RequestContext,
        _input: types::GetInvitationsCountRequest,
    ) -> Result<types::GetInvitationsCountResponse, ServiceError> {
        self.authorize(ctx, "GetInvitationsCount", "*", ConditionContext::new())?;
        let state = self.lock();
        let n = state.account(&ctx.caller.account_id, &ctx.region).map(|a| a.invitations.len()).unwrap_or(0);
        Ok(types::GetInvitationsCountResponse { invitations_count: Some(n as i32) })
    }

    fn drop_invitations(&self, ctx: &RequestContext, ids: &[String], declined: bool) -> Vec<types::UnprocessedAccount> {
        let me = ctx.caller.account_id.clone();
        let mut state = self.lock();
        let mut out = Vec::new();
        for admin in ids {
            let removed = state.account_mut(&me, &ctx.region).invitations.remove(admin);
            if removed.is_none() {
                out.push(unprocessed(
                    admin,
                    "The request is rejected because the input account ID has not sent an invitation to the current account.",
                ));
                continue;
            }
            if declined {
                if let Some(m) = state.detector_mut(admin, &ctx.region).and_then(|d| d.members.get_mut(&me)) {
                    if m.status == "Invited" {
                        m.status = "Removed".into();
                        m.updated_at = ctx.received_at;
                    }
                }
            }
        }
        out
    }

    pub(crate) fn decline_invitations(
        &self,
        ctx: &RequestContext,
        input: types::DeclineInvitationsRequest,
    ) -> Result<types::DeclineInvitationsResponse, ServiceError> {
        self.authorize(ctx, "DeclineInvitations", "*", ConditionContext::new())?;
        Ok(types::DeclineInvitationsResponse {
            unprocessed_accounts: self.drop_invitations(ctx, &input.account_ids, true),
        })
    }

    pub(crate) fn delete_invitations(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInvitationsRequest,
    ) -> Result<types::DeleteInvitationsResponse, ServiceError> {
        self.authorize(ctx, "DeleteInvitations", "*", ConditionContext::new())?;
        Ok(types::DeleteInvitationsResponse {
            unprocessed_accounts: self.drop_invitations(ctx, &input.account_ids, false),
        })
    }

    pub(crate) fn accept_administrator(
        &self,
        ctx: &RequestContext,
        action: &str,
        detector_id: &str,
        admin: &str,
        invitation_id: &str,
    ) -> Result<(), ServiceError> {
        self.authorize_detector(ctx, action, detector_id)?;
        let me = ctx.caller.account_id.clone();
        let mut state = self.lock();
        Self::owned(&state, ctx, detector_id)?;
        if let Some(link) = state.account(&me, &ctx.region).and_then(|a| a.administrator.as_ref()) {
            if link.account != admin {
                return Err(invalid_input(
                    "The request is rejected because the current account has already accepted an invitation from another administrator account.",
                ));
            }
        }
        let valid = state
            .account(&me, &ctx.region)
            .and_then(|a| a.invitations.get(admin))
            .is_some_and(|i| i.invitation_id == invitation_id);
        if !valid {
            return Err(invalid_input("The request is rejected because the input invitationId is invalid."));
        }
        let invited =
            state.detector(admin, &ctx.region).and_then(|d| d.members.get(&me)).is_some_and(|m| m.status == "Invited");
        if !invited {
            return Err(invalid_input("The request is rejected because the input invitationId is invalid."));
        }
        if state.detector(&me, &ctx.region).is_some_and(|d| d.members.values().any(|m| m.status == "Enabled")) {
            return Err(invalid_input(
                "The request is rejected because the current account is an administrator account and cannot become a member.",
            ));
        }
        Self::associate(&mut state, ctx, admin, &me, false);
        Ok(())
    }

    pub(crate) fn administrator_of(
        &self,
        ctx: &RequestContext,
        action: &str,
        detector_id: &str,
    ) -> Result<types::Administrator, ServiceError> {
        self.authorize_detector(ctx, action, detector_id)?;
        let me = ctx.caller.account_id.clone();
        let state = self.lock();
        Self::owned(&state, ctx, detector_id)?;
        let Some(link) = state.account(&me, &ctx.region).and_then(|a| a.administrator.clone()) else {
            return Ok(types::Administrator::default());
        };
        let status = state
            .detector(&link.account, &ctx.region)
            .and_then(|d| d.members.get(&me))
            .map(|m| m.status.clone())
            .unwrap_or_else(|| "Removed".into());
        Ok(types::Administrator {
            account_id: Some(link.account),
            invitation_id: link.invitation_id,
            relationship_status: Some(status),
            invited_at: link.invited_at.map(iso),
        })
    }

    pub(crate) fn leave_administrator(
        &self,
        ctx: &RequestContext,
        action: &str,
        detector_id: &str,
    ) -> Result<(), ServiceError> {
        self.authorize_detector(ctx, action, detector_id)?;
        let me = ctx.caller.account_id.clone();
        let mut state = self.lock();
        Self::owned(&state, ctx, detector_id)?;
        let Some(link) = state.account(&me, &ctx.region).and_then(|a| a.administrator.clone()) else {
            return Err(invalid_input(
                "The request is rejected because the current account is not associated with an administrator account.",
            ));
        };
        let via_org = state
            .detector(&link.account, &ctx.region)
            .and_then(|d| d.members.get(&me))
            .is_some_and(|m| m.via_organization);
        if via_org {
            return Err(invalid_input(
                "The request is rejected because the current account is managed by your organization's GuardDuty delegated administrator and cannot disassociate itself.",
            ));
        }
        Self::dissociate(&mut state, ctx, &link.account, &me, "Resigned");
        Ok(())
    }
}
