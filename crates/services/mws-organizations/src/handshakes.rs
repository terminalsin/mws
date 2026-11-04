//! Handshakes (invitations, enabling all features) and billing
//! responsibility transfers between organizations.

use chrono::{DateTime, Datelike, TimeDelta, Timelike, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::access::*;
use crate::generated::{errors, types};
use crate::state::{HandshakeRec, Member, Org, State, Tags, TransferRec};
use crate::structure::{attach_defaults, ensure_account_info, ORGANIZATIONS_PRINCIPAL};
use crate::Organizations;

const INVITE: &str = "INVITE";
const ENABLE_ALL: &str = "ENABLE_ALL_FEATURES";
const APPROVE_ALL: &str = "APPROVE_ALL_FEATURES";
const TRANSFER: &str = "TRANSFER_RESPONSIBILITY";
/// Invitations (and billing transfer invitations) expire after 15 days.
const HANDSHAKE_LIFETIME_DAYS: i64 = 15;
/// A request to enable all features stays open for 90 days.
const ENABLE_ALL_LIFETIME_DAYS: i64 = 90;

fn party(ty: &str, id: &str) -> types::HandshakeParty {
    types::HandshakeParty { id: id.to_string(), r#type: ty.to_string() }
}

fn resource(ty: &str, value: impl Into<String>) -> types::HandshakeResource {
    types::HandshakeResource { r#type: Some(ty.into()), value: Some(value.into()), resources: None }
}

fn transfer_not_found() -> ServiceError {
    errors::responsibility_transfer_not_found("We can't find a transfer that you specified.")
}

fn already_in_state() -> ServiceError {
    errors::handshake_already_in_state("The specified handshake is already in the requested state.")
}

fn bad_transition() -> ServiceError {
    errors::invalid_handshake_transition("You can't perform the operation on the handshake in its current state.")
}

/// The organization resource every handshake an organization sends carries.
fn org_resource(state: &State, org: &Org) -> types::HandshakeResource {
    let mgmt = state.accounts.get(&org.management_account);
    types::HandshakeResource {
        r#type: Some("ORGANIZATION".into()),
        value: Some(org.id.clone()),
        resources: Some(vec![
            resource("MASTER_EMAIL", mgmt.map(|a| a.email.clone()).unwrap_or_default()),
            resource("MASTER_NAME", mgmt.map(|a| a.name.clone()).unwrap_or_default()),
            resource("ORGANIZATION_FEATURE_SET", org.feature_set.clone()),
        ]),
    }
}

fn new_handshake(
    org: &Org,
    ctx: &RequestContext,
    action: &str,
    parties: Vec<types::HandshakeParty>,
    resources: Vec<types::HandshakeResource>,
) -> types::Handshake {
    new_handshake_with_id(new_id("h-", 10), org, ctx, action, parties, resources)
}

fn new_handshake_with_id(
    id: String,
    org: &Org,
    ctx: &RequestContext,
    action: &str,
    parties: Vec<types::HandshakeParty>,
    resources: Vec<types::HandshakeResource>,
) -> types::Handshake {
    let partition = &ctx.partition;
    let now = ctx.received_at;
    let lifetime =
        if matches!(action, ENABLE_ALL | APPROVE_ALL) { ENABLE_ALL_LIFETIME_DAYS } else { HANDSHAKE_LIFETIME_DAYS };
    types::Handshake {
        arn: Some(org.handshake_arn(partition, action, &id)),
        id: Some(id),
        parties: Some(parties),
        state: Some("OPEN".into()),
        requested_timestamp: Some(now),
        expiration_timestamp: Some(now + TimeDelta::days(lifetime)),
        action: Some(action.into()),
        resources: Some(resources),
    }
}

fn action_of(h: &HandshakeRec) -> &str {
    h.handshake.action.as_deref().unwrap_or_default()
}

fn resource_value<'a>(h: &'a HandshakeRec, ty: &str) -> Option<&'a str> {
    h.handshake.resources.iter().flatten().find(|r| r.r#type.as_deref() == Some(ty)).and_then(|r| r.value.as_deref())
}

fn is_open(h: &HandshakeRec) -> bool {
    matches!(h.handshake.state.as_deref(), Some("OPEN") | Some("REQUESTED"))
}

/// Whether `account` is the party a handshake asks to respond.
fn is_recipient(state: &State, h: &HandshakeRec, account: &str) -> bool {
    if action_of(h) == ENABLE_ALL {
        return state.organizations.get(&h.org_id).is_some_and(|o| o.management_account == account);
    }
    let email = state.accounts.get(account).map(|a| a.email.to_lowercase());
    h.handshake.parties.iter().flatten().any(|p| match p.r#type.as_str() {
        "ACCOUNT" => p.id == account,
        "EMAIL" => email.as_deref() == Some(p.id.to_lowercase().as_str()),
        _ => false,
    })
}

/// Whether `account` sent the handshake (manages its organization).
fn is_originator(state: &State, h: &HandshakeRec, account: &str) -> bool {
    state.organizations.get(&h.org_id).is_some_and(|o| o.management_account == account)
}

fn start_of_month(t: DateTime<Utc>) -> DateTime<Utc> {
    t.with_day(1)
        .and_then(|t| t.with_hour(0))
        .and_then(|t| t.with_minute(0))
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(t)
}

fn participant(state: &State, account: &str) -> types::TransferParticipant {
    types::TransferParticipant {
        management_account_id: Some(account.to_string()),
        management_account_email: state.accounts.get(account).map(|a| a.email.clone()),
    }
}

impl Organizations {
    fn handshake_arn_for(&self, ctx: &RequestContext, id: &str) -> Result<String, ServiceError> {
        let state = self.lock();
        let h = state.handshakes.get(id).ok_or_else(handshake_not_found)?;
        let account = &ctx.caller.account_id;
        if !is_recipient(&state, h, account) && !is_originator(&state, h, account) {
            return Err(handshake_not_found());
        }
        Ok(h.handshake.arn.clone().unwrap_or_default())
    }

    /// Mark handshakes whose time has run out as expired.
    fn expire(state: &mut State, now: DateTime<Utc>) {
        for h in state.handshakes.values_mut() {
            if is_open(h) && h.handshake.expiration_timestamp.is_some_and(|t| t <= now) {
                h.handshake.state = Some("EXPIRED".into());
            }
        }
        for t in state.transfers.values_mut() {
            if t.transfer.status.as_deref() == Some("REQUESTED") {
                let expired = t.transfer.active_handshake_id.as_ref().is_some_and(|id| {
                    state.handshakes.get(id).is_some_and(|h| h.handshake.state.as_deref() == Some("EXPIRED"))
                });
                if expired {
                    t.transfer.status = Some("EXPIRED".into());
                }
            }
        }
    }

    pub(crate) fn invite_account_to_organization(
        &self,
        ctx: &RequestContext,
        input: types::InviteAccountToOrganizationRequest,
    ) -> Result<types::InviteAccountToOrganizationResponse, ServiceError> {
        let tags = tags_from(input.tags)?;
        self.authorize(ctx, "InviteAccountToOrganization", "*", request_tag_context(&tags))?;
        let handshake_id = new_id("h-", 10);
        if !tags.is_empty() {
            let arn = {
                let state = self.lock();
                let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
                org.handshake_arn(&ctx.partition, INVITE, &handshake_id)
            };
            self.authorize_tagging(ctx, &arn, &tags)?;
        }
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let org = self.caller_org(&state, ctx, "InviteAccountToOrganization", "*", Need::Management)?.clone();
        let target = input.target;
        match target.r#type.as_str() {
            "ACCOUNT" if target.id.len() == 12 && target.id.bytes().all(|b| b.is_ascii_digit()) => {}
            "ACCOUNT" => {
                return Err(invalid("INVALID_PARTY_TYPE_TARGET", "You provided a value that does not match the required pattern."))
            }
            "EMAIL" if target.id.contains('@') => {}
            "EMAIL" => {
                return Err(invalid(
                    "INVALID_EMAIL_ADDRESS_TARGET",
                    "You specified an invalid email address for the invited account owner.",
                ))
            }
            _ => {
                return Err(invalid(
                    "INVALID_PARTY_TYPE_TARGET",
                    "You specified the wrong type for the invitation target. You can invite only an account or an email address.",
                ))
            }
        }
        let target_account = match target.r#type.as_str() {
            "ACCOUNT" => Some(target.id.clone()),
            _ => state.accounts.values().find(|a| a.email.eq_ignore_ascii_case(&target.id)).map(|a| a.id.clone()),
        };
        if target_account.as_ref().is_some_and(|a| org.members.contains_key(a)) {
            return Err(handshake_constraint(
                "ALREADY_IN_AN_ORGANIZATION",
                "The account is already a member of an organization.",
            ));
        }
        let enabling =
            state.handshakes.values().any(|h| h.org_id == org.id && action_of(h) == ENABLE_ALL && is_open(h));
        if enabling {
            return Err(handshake_constraint(
                "INVITE_DISABLED_DURING_ENABLE_ALL_FEATURES",
                "You can't invite an account while the organization is migrating to all features.",
            ));
        }
        let duplicate = state.handshakes.values().any(|h| {
            h.org_id == org.id
                && action_of(h) == INVITE
                && is_open(h)
                && h.handshake.parties.iter().flatten().any(|p| p.id.eq_ignore_ascii_case(&target.id))
        });
        if duplicate {
            return Err(errors::duplicate_handshake("A handshake with the same action and target already exists."));
        }
        let mut resources = vec![org_resource(&state, &org), resource(&target.r#type, target.id.clone())];
        if let Some(notes) = input.notes {
            resources.push(resource("NOTES", notes));
        }
        let handshake = new_handshake_with_id(
            handshake_id,
            &org,
            ctx,
            INVITE,
            vec![party("ORGANIZATION", &org.id), party(&target.r#type, &target.id)],
            resources,
        );
        state.handshakes.insert(
            handshake.id.clone().unwrap_or_default(),
            HandshakeRec { org_id: org.id.clone(), handshake: handshake.clone(), tags },
        );
        Ok(types::InviteAccountToOrganizationResponse { handshake: Some(handshake) })
    }

    pub(crate) fn enable_all_features(
        &self,
        ctx: &RequestContext,
        _input: types::EnableAllFeaturesRequest,
    ) -> Result<types::EnableAllFeaturesResponse, ServiceError> {
        self.authorize(ctx, "EnableAllFeatures", "*", ConditionContext::new())?;
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let org = self.caller_org(&state, ctx, "EnableAllFeatures", "*", Need::Management)?.clone();
        if org.feature_set == "ALL" {
            return Err(handshake_constraint(
                "ORGANIZATION_ALREADY_HAS_ALL_FEATURES",
                "This organization already has all features enabled.",
            ));
        }
        if state.handshakes.values().any(|h| h.org_id == org.id && action_of(h) == ENABLE_ALL && is_open(h)) {
            return Err(handshake_constraint(
                "ORGANIZATION_IS_ALREADY_PENDING_ALL_FEATURES_MIGRATION",
                "This organization is already in the process of enabling all features.",
            ));
        }
        let parent = new_handshake(
            &org,
            ctx,
            ENABLE_ALL,
            vec![party("ORGANIZATION", &org.id)],
            vec![resource("ORGANIZATION", org.id.clone())],
        );
        let parent_id = parent.id.clone().unwrap_or_default();
        for (account, m) in &org.members {
            if *account == org.management_account {
                continue;
            }
            let mut child = new_handshake(
                &org,
                ctx,
                APPROVE_ALL,
                vec![party("ORGANIZATION", &org.id), party("ACCOUNT", account)],
                vec![resource("ORGANIZATION", org.id.clone()), resource("PARENT_HANDSHAKE", parent_id.clone())],
            );
            // Accounts the organization created approve automatically.
            if m.joined_method == "CREATED" {
                child.state = Some("ACCEPTED".into());
            }
            state.handshakes.insert(
                child.id.clone().unwrap_or_default(),
                HandshakeRec { org_id: org.id.clone(), handshake: child, tags: Tags::new() },
            );
        }
        state
            .handshakes
            .insert(parent_id, HandshakeRec { org_id: org.id.clone(), handshake: parent.clone(), tags: Tags::new() });
        Ok(types::EnableAllFeaturesResponse { handshake: Some(parent) })
    }

    pub(crate) fn accept_handshake(
        &self,
        ctx: &RequestContext,
        input: types::AcceptHandshakeRequest,
    ) -> Result<types::AcceptHandshakeResponse, ServiceError> {
        let arn = self.handshake_arn_for(ctx, &input.handshake_id)?;
        self.authorize(ctx, "AcceptHandshake", &arn, ConditionContext::new())?;
        let account = ctx.caller.account_id.clone();
        // Joining an organization with all features creates
        // AWSServiceRoleForOrganizations in the account, which the caller
        // must be allowed to do.
        let joins_all_features = {
            let state = self.lock();
            state.handshakes.get(&input.handshake_id).is_some_and(|h| {
                action_of(h) == INVITE
                    && is_open(h)
                    && state.organizations.get(&h.org_id).is_some_and(|o| o.feature_set == "ALL")
            })
        };
        if joins_all_features {
            self.authorize_service_linked_role(ctx, &account)?;
        }
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let h = state.handshakes.get(&input.handshake_id).cloned().ok_or_else(handshake_not_found)?;
        if !is_recipient(&state, &h, &account) {
            return Err(access_denied());
        }
        match h.handshake.state.as_deref() {
            Some("ACCEPTED") => return Err(already_in_state()),
            Some("OPEN") | Some("REQUESTED") => {}
            _ => return Err(bad_transition()),
        }
        let mut new_roles: Vec<String> = vec![];
        match action_of(&h) {
            INVITE => {
                if state.org_of(&account).is_some() {
                    return Err(handshake_constraint(
                        "ALREADY_IN_AN_ORGANIZATION",
                        "The account is already a member of an organization.",
                    ));
                }
                ensure_account_info(&mut state, &account);
                let org = state.organizations.get_mut(&h.org_id).ok_or_else(bad_transition)?;
                org.members.insert(
                    account.clone(),
                    Member {
                        parent: org.root_id.clone(),
                        joined_method: "INVITED".into(),
                        joined: ctx.received_at,
                        tags: h.tags.clone(),
                    },
                );
                attach_defaults(org, &account);
                if org.feature_set == "ALL" {
                    new_roles.push(account.clone());
                }
            }
            ENABLE_ALL => {
                let pending = state.handshakes.values().any(|c| {
                    action_of(c) == APPROVE_ALL
                        && resource_value(c, "PARENT_HANDSHAKE") == Some(input.handshake_id.as_str())
                        && c.handshake.state.as_deref() != Some("ACCEPTED")
                });
                if pending {
                    return Err(errors::invalid_handshake_transition(
                        "Every invited member account must approve enabling all features before you can finalize it.",
                    ));
                }
                let org = state.organizations.get_mut(&h.org_id).ok_or_else(bad_transition)?;
                org.feature_set = "ALL".into();
                new_roles.extend(org.members.keys().cloned());
            }
            TRANSFER => {
                if let Some(t) =
                    resource_value(&h, "RESPONSIBILITY_TRANSFER").and_then(|id| state.transfers.get_mut(id))
                {
                    t.transfer.status = Some("ACCEPTED".into());
                }
            }
            _ => {}
        }
        let rec = state.handshakes.get_mut(&input.handshake_id).expect("handshake exists");
        rec.handshake.state = Some("ACCEPTED".into());
        let out = rec.handshake.clone();
        drop(state);
        for a in new_roles {
            self.iam.ensure_service_linked_role(&a, ORGANIZATIONS_PRINCIPAL, "AWSOrganizationsServiceTrustPolicy");
        }
        Ok(types::AcceptHandshakeResponse { handshake: Some(out) })
    }

    pub(crate) fn decline_handshake(
        &self,
        ctx: &RequestContext,
        input: types::DeclineHandshakeRequest,
    ) -> Result<types::DeclineHandshakeResponse, ServiceError> {
        let arn = self.handshake_arn_for(ctx, &input.handshake_id)?;
        self.authorize(ctx, "DeclineHandshake", &arn, ConditionContext::new())?;
        let out = self.close_handshake(ctx, &input.handshake_id, "DECLINED", true)?;
        Ok(types::DeclineHandshakeResponse { handshake: Some(out) })
    }

    pub(crate) fn cancel_handshake(
        &self,
        ctx: &RequestContext,
        input: types::CancelHandshakeRequest,
    ) -> Result<types::CancelHandshakeResponse, ServiceError> {
        let arn = self.handshake_arn_for(ctx, &input.handshake_id)?;
        self.authorize(ctx, "CancelHandshake", &arn, ConditionContext::new())?;
        let out = self.close_handshake(ctx, &input.handshake_id, "CANCELED", false)?;
        Ok(types::CancelHandshakeResponse { handshake: Some(out) })
    }

    /// Decline (by the recipient) or cancel (by the sender) a handshake.
    fn close_handshake(
        &self,
        ctx: &RequestContext,
        id: &str,
        to: &str,
        by_recipient: bool,
    ) -> Result<types::Handshake, ServiceError> {
        let account = ctx.caller.account_id.clone();
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let h = state.handshakes.get(id).cloned().ok_or_else(handshake_not_found)?;
        let allowed =
            if by_recipient { is_recipient(&state, &h, &account) } else { is_originator(&state, &h, &account) };
        if !allowed {
            return Err(access_denied());
        }
        if h.handshake.state.as_deref() == Some(to) {
            return Err(already_in_state());
        }
        if !is_open(&h) {
            return Err(bad_transition());
        }
        if let Some(t) = resource_value(&h, "RESPONSIBILITY_TRANSFER").and_then(|t| state.transfers.get_mut(t)) {
            t.transfer.status = Some(to.to_string());
        }
        if action_of(&h) == ENABLE_ALL {
            for c in state.handshakes.values_mut() {
                if resource_value(c, "PARENT_HANDSHAKE") == Some(id) && is_open(c) {
                    c.handshake.state = Some(to.to_string());
                }
            }
        }
        let rec = state.handshakes.get_mut(id).expect("handshake exists");
        rec.handshake.state = Some(to.to_string());
        Ok(rec.handshake.clone())
    }

    pub(crate) fn describe_handshake(
        &self,
        ctx: &RequestContext,
        input: types::DescribeHandshakeRequest,
    ) -> Result<types::DescribeHandshakeResponse, ServiceError> {
        let arn = self.handshake_arn_for(ctx, &input.handshake_id)?;
        self.authorize(ctx, "DescribeHandshake", &arn, ConditionContext::new())?;
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let h = state.handshakes.get(&input.handshake_id).ok_or_else(handshake_not_found)?;
        Ok(types::DescribeHandshakeResponse { handshake: Some(h.handshake.clone()) })
    }

    fn filtered(
        state: &State,
        filter: &Option<types::HandshakeFilter>,
        keep: impl Fn(&HandshakeRec) -> bool,
    ) -> Result<Vec<types::Handshake>, ServiceError> {
        if filter.as_ref().is_some_and(|f| f.action_type.is_some() && f.parent_handshake_id.is_some()) {
            return Err(invalid(
                "MAX_FILTER_LIMIT_EXCEEDED",
                "You can specify only one filter parameter for the operation.",
            ));
        }
        let mut out: Vec<&HandshakeRec> = state
            .handshakes
            .values()
            .filter(|h| keep(h))
            .filter(|h| {
                filter.as_ref().is_none_or(|f| {
                    f.action_type.as_ref().is_none_or(|a| action_of(h) == a)
                        && f.parent_handshake_id
                            .as_ref()
                            .is_none_or(|p| resource_value(h, "PARENT_HANDSHAKE") == Some(p))
                })
            })
            .collect();
        out.sort_by_key(|h| h.handshake.requested_timestamp);
        Ok(out.into_iter().map(|h| h.handshake.clone()).collect())
    }

    pub(crate) fn list_handshakes_for_account(
        &self,
        ctx: &RequestContext,
        input: types::ListHandshakesForAccountRequest,
    ) -> Result<types::ListHandshakesForAccountResponse, ServiceError> {
        self.authorize(ctx, "ListHandshakesForAccount", "*", ConditionContext::new())?;
        let account = ctx.caller.account_id.clone();
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let all = Self::filtered(&state, &input.filter, |h| is_recipient(&state, h, &account))?;
        let (handshakes, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListHandshakesForAccountResponse { handshakes: Some(handshakes), next_token })
    }

    pub(crate) fn list_handshakes_for_organization(
        &self,
        ctx: &RequestContext,
        input: types::ListHandshakesForOrganizationRequest,
    ) -> Result<types::ListHandshakesForOrganizationResponse, ServiceError> {
        self.authorize(ctx, "ListHandshakesForOrganization", "*", ConditionContext::new())?;
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let org_id = self.caller_org(&state, ctx, "ListHandshakesForOrganization", "*", Need::Read)?.id.clone();
        let all = Self::filtered(&state, &input.filter, |h| h.org_id == org_id)?;
        let (handshakes, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListHandshakesForOrganizationResponse { handshakes: Some(handshakes), next_token })
    }

    // ---- responsibility transfers ----------------------------------------------

    pub(crate) fn invite_organization_to_transfer_responsibility(
        &self,
        ctx: &RequestContext,
        input: types::InviteOrganizationToTransferResponsibilityRequest,
    ) -> Result<types::InviteOrganizationToTransferResponsibilityResponse, ServiceError> {
        let tags = tags_from(input.tags)?;
        self.authorize(ctx, "InviteOrganizationToTransferResponsibility", "*", request_tag_context(&tags))?;
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let org =
            self.caller_org(&state, ctx, "InviteOrganizationToTransferResponsibility", "*", Need::Management)?.clone();
        if input.target.r#type != "ACCOUNT" {
            return Err(invalid(
                "INVALID_PARTY_TYPE_TARGET",
                "You specified the wrong type for the invitation target. Specify the management account of the other organization.",
            ));
        }
        let target = input.target.id.clone();
        if target == org.management_account {
            return Err(handshake_constraint(
                "SOURCE_AND_TARGET_CANNOT_MATCH",
                "The source and target of a responsibility transfer can't be the same organization.",
            ));
        }
        let target_org =
            state.organizations.values().find(|o| o.management_account == target).map(|o| o.id.clone()).ok_or_else(
                || {
                    handshake_constraint(
                        "TARGET_ACCOUNT_VALIDATION_FAILURE",
                        "The target account must be the management account of an organization.",
                    )
                },
            )?;
        let start = input.start_timestamp;
        if start_of_month(start) != start {
            return Err(invalid(
                "START_DATE_NOT_BEGINNING_OF_MONTH",
                "The start date must be the first day of a month at 00:00 UTC.",
            ));
        }
        if start < start_of_month(ctx.received_at) {
            return Err(invalid("START_DATE_TOO_EARLY", "The start date can't be in the past."));
        }
        let active = state.transfers.values().any(|t| {
            t.source_org == target_org
                && t.target_org == org.id
                && matches!(t.transfer.status.as_deref(), Some("REQUESTED") | Some("ACCEPTED"))
                && t.transfer.end_timestamp.is_none()
        });
        if active {
            return Err(handshake_constraint(
                "RESPONSIBILITY_TRANSFER_ALREADY_EXISTS",
                "A responsibility transfer between these organizations already exists.",
            ));
        }
        let transfer_id = new_id("rt-", 10);
        let mgmt = state.accounts.get(&org.management_account).cloned();
        let mut resources = vec![
            resource("RESPONSIBILITY_TRANSFER", transfer_id.clone()),
            resource("TRANSFER_TYPE", input.r#type.clone()),
            resource("TRANSFER_START_TIMESTAMP", start.to_rfc3339()),
            resource("MANAGEMENT_ACCOUNT", org.management_account.clone()),
            resource("MANAGEMENT_EMAIL", mgmt.as_ref().map(|a| a.email.clone()).unwrap_or_default()),
            resource("MANAGEMENT_NAME", mgmt.as_ref().map(|a| a.name.clone()).unwrap_or_default()),
        ];
        if let Some(notes) = input.notes {
            resources.push(resource("NOTES", notes));
        }
        let handshake = new_handshake(
            &org,
            ctx,
            TRANSFER,
            vec![party("ORGANIZATION", &org.id), party("ACCOUNT", &target)],
            resources,
        );
        let transfer = types::ResponsibilityTransfer {
            arn: Some(format!(
                "arn:{}:organizations::{}:transfer/{}/{}/inbound/{transfer_id}",
                ctx.partition,
                org.management_account,
                org.id,
                input.r#type.to_lowercase()
            )),
            name: Some(input.source_name),
            id: Some(transfer_id.clone()),
            r#type: Some(input.r#type),
            status: Some("REQUESTED".into()),
            source: Some(participant(&state, &target)),
            target: Some(participant(&state, &org.management_account)),
            start_timestamp: Some(start),
            end_timestamp: None,
            active_handshake_id: handshake.id.clone(),
        };
        state
            .transfers
            .insert(transfer_id, TransferRec { source_org: target_org, target_org: org.id.clone(), transfer, tags });
        state.handshakes.insert(
            handshake.id.clone().unwrap_or_default(),
            HandshakeRec { org_id: org.id.clone(), handshake: handshake.clone(), tags: Tags::new() },
        );
        Ok(types::InviteOrganizationToTransferResponsibilityResponse { handshake: Some(handshake) })
    }

    /// A transfer the caller's organization is a party to.
    fn caller_transfer<'a>(state: &'a State, ctx: &RequestContext, id: &str) -> Result<&'a TransferRec, ServiceError> {
        let org = state.org_of(&ctx.caller.account_id).ok_or_else(not_in_use)?;
        if org.management_account != ctx.caller.account_id {
            return Err(access_denied());
        }
        state
            .transfers
            .get(id)
            .filter(|t| t.source_org == org.id || t.target_org == org.id)
            .ok_or_else(transfer_not_found)
    }

    pub(crate) fn describe_responsibility_transfer(
        &self,
        ctx: &RequestContext,
        input: types::DescribeResponsibilityTransferRequest,
    ) -> Result<types::DescribeResponsibilityTransferResponse, ServiceError> {
        self.authorize(ctx, "DescribeResponsibilityTransfer", "*", ConditionContext::new())?;
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let t = Self::caller_transfer(&state, ctx, &input.id)?;
        Ok(types::DescribeResponsibilityTransferResponse { responsibility_transfer: Some(t.transfer.clone()) })
    }

    pub(crate) fn update_responsibility_transfer(
        &self,
        ctx: &RequestContext,
        input: types::UpdateResponsibilityTransferRequest,
    ) -> Result<types::UpdateResponsibilityTransferResponse, ServiceError> {
        self.authorize(ctx, "UpdateResponsibilityTransfer", "*", ConditionContext::new())?;
        let mut state = self.lock();
        Self::caller_transfer(&state, ctx, &input.id)?;
        let t = state.transfers.get_mut(&input.id).expect("checked above");
        t.transfer.name = Some(input.name);
        Ok(types::UpdateResponsibilityTransferResponse { responsibility_transfer: Some(t.transfer.clone()) })
    }

    pub(crate) fn terminate_responsibility_transfer(
        &self,
        ctx: &RequestContext,
        input: types::TerminateResponsibilityTransferRequest,
    ) -> Result<types::TerminateResponsibilityTransferResponse, ServiceError> {
        self.authorize(ctx, "TerminateResponsibilityTransfer", "*", ConditionContext::new())?;
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        Self::caller_transfer(&state, ctx, &input.id)?;
        let t = state.transfers.get(&input.id).expect("checked above").clone();
        match t.transfer.status.as_deref() {
            Some("REQUESTED") => {
                if let Some(h) = t.transfer.active_handshake_id.as_ref().and_then(|h| state.handshakes.get_mut(h)) {
                    h.handshake.state = Some("CANCELED".into());
                }
                state.transfers.get_mut(&input.id).expect("exists").transfer.status = Some("WITHDRAWN".into());
            }
            Some("ACCEPTED") => {
                if t.transfer.end_timestamp.is_some() {
                    return Err(errors::responsibility_transfer_already_in_status(
                        "The responsibility transfer is already ending.",
                    ));
                }
                let end = input.end_timestamp.unwrap_or(ctx.received_at);
                if end < ctx.received_at - TimeDelta::minutes(5) {
                    return Err(invalid("END_DATE_TOO_EARLY", "The end date can't be in the past."));
                }
                state.transfers.get_mut(&input.id).expect("exists").transfer.end_timestamp = Some(end);
            }
            _ => {
                return Err(errors::invalid_responsibility_transfer_transition(
                    "You can't terminate the responsibility transfer in its current status.",
                ))
            }
        }
        let t = &state.transfers[&input.id];
        Ok(types::TerminateResponsibilityTransferResponse { responsibility_transfer: Some(t.transfer.clone()) })
    }

    fn list_transfers(
        &self,
        ctx: &RequestContext,
        action: &str,
        ty: &str,
        inbound: bool,
        id: Option<&str>,
    ) -> Result<Vec<types::ResponsibilityTransfer>, ServiceError> {
        self.authorize(ctx, action, "*", ConditionContext::new())?;
        let mut state = self.lock();
        Self::expire(&mut state, ctx.received_at);
        let org_id = self.caller_org(&state, ctx, action, "*", Need::Management)?.id.clone();
        let out: Vec<_> = state
            .transfers
            .values()
            .filter(|t| if inbound { t.target_org == org_id } else { t.source_org == org_id })
            .filter(|t| t.transfer.r#type.as_deref() == Some(ty))
            .filter(|t| id.is_none_or(|id| t.transfer.id.as_deref() == Some(id)))
            .map(|t| t.transfer.clone())
            .collect();
        if id.is_some() && out.is_empty() {
            return Err(transfer_not_found());
        }
        Ok(out)
    }

    pub(crate) fn list_inbound_responsibility_transfers(
        &self,
        ctx: &RequestContext,
        input: types::ListInboundResponsibilityTransfersRequest,
    ) -> Result<types::ListInboundResponsibilityTransfersResponse, ServiceError> {
        let all =
            self.list_transfers(ctx, "ListInboundResponsibilityTransfers", &input.r#type, true, input.id.as_deref())?;
        let (transfers, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListInboundResponsibilityTransfersResponse { responsibility_transfers: Some(transfers), next_token })
    }

    pub(crate) fn list_outbound_responsibility_transfers(
        &self,
        ctx: &RequestContext,
        input: types::ListOutboundResponsibilityTransfersRequest,
    ) -> Result<types::ListOutboundResponsibilityTransfersResponse, ServiceError> {
        let all = self.list_transfers(ctx, "ListOutboundResponsibilityTransfers", &input.r#type, false, None)?;
        let (transfers, next_token) = page(all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListOutboundResponsibilityTransfersResponse { responsibility_transfers: Some(transfers), next_token })
    }
}
