//! Temporary delegation requests, and their human-readable summaries.
//!
//! Lifecycle: a partner creates a request (UNASSIGNED, or ASSIGNED when
//! created by the owner account itself); AssociateDelegationRequest makes the
//! caller its owner (ASSIGNED); UpdateDelegationRequest adds notes
//! (PENDING_APPROVAL); the owner accepts (ACCEPTED) or rejects (REJECTED);
//! SendDelegationToken finalizes an accepted one (FINALIZED). Requests not
//! finalized within 7 days become EXPIRED.

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{DelegationRequest, State};
use crate::Iam;

const EXPIRY_DAYS: i64 = 7;
const MAX_NOTES: usize = 1024;

fn no_such_request(id: &str) -> ServiceError {
    errors::no_such_entity(format!("The delegation request with id {id} cannot be found."))
}

/// The request's state at `now` (the emulated clock): requests not
/// finalized or rejected by their expiration time are EXPIRED.
fn state_of(r: &types::DelegationRequest, now: DateTime<Utc>) -> String {
    let live = !matches!(r.state.as_deref(), Some("FINALIZED" | "REJECTED"));
    if live && r.expiration_time.is_some_and(|t| t <= now) {
        return "EXPIRED".into();
    }
    r.state.clone().unwrap_or_default()
}

fn wire(d: &DelegationRequest, now: DateTime<Utc>) -> types::DelegationRequest {
    types::DelegationRequest { state: Some(state_of(&d.request, now)), notes: d.notes.clone(), ..d.request.clone() }
}

impl Iam {
    fn delegation_arn(&self, id: &str) -> String {
        self.arn(&format!("delegation-request/{id}"))
    }

    fn with_request<T>(
        &self,
        ctx: &RequestContext,
        id: &str,
        f: impl FnOnce(&mut DelegationRequest, &mut State) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let mut state = self.write();
        let mut req = state.delegation_requests.get(id).cloned().ok_or_else(|| no_such_request(id))?;
        let out = f(&mut req, &mut state)?;
        req.request.updated_time = Some(ctx.received_at);
        state.delegation_requests.insert(id.to_string(), req);
        Ok(out)
    }

    pub fn create_delegation_request(
        &self,
        ctx: &RequestContext,
        input: types::CreateDelegationRequestRequest,
    ) -> Result<types::CreateDelegationRequestResponse, ServiceError> {
        self.authorize(ctx, "CreateDelegationRequest", "*")?;
        if !(900..=43200).contains(&input.session_duration) {
            return Err(errors::invalid_input("SessionDuration must be between 900 and 43200 seconds."));
        }
        let mut state = self.write();
        if state
            .delegation_requests
            .values()
            .any(|d| d.request.requestor_id.as_deref() == Some(input.requestor_workflow_id.as_str()))
        {
            return Err(errors::entity_already_exists(format!(
                "A delegation request with workflow id {} already exists.",
                input.requestor_workflow_id
            )));
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let now = ctx.received_at;
        let request = types::DelegationRequest {
            delegation_request_id: Some(id.clone()),
            owner_account_id: input.owner_account_id,
            description: Some(input.description),
            request_message: input.request_message,
            permissions: Some(input.permissions),
            permission_policy: None,
            role_permission_restriction_arns: None,
            owner_id: None,
            approver_id: None,
            state: Some("UNASSIGNED".into()),
            expiration_time: Some(now + Duration::days(EXPIRY_DAYS)),
            requestor_id: Some(input.requestor_workflow_id),
            requestor_name: Some(ctx.caller.arn.clone()),
            create_date: Some(now),
            session_duration: Some(input.session_duration),
            redirect_url: input.redirect_url.clone(),
            notes: None,
            rejection_reason: None,
            only_send_by_owner: input.only_send_by_owner,
            updated_time: Some(now),
        };
        state
            .delegation_requests
            .insert(id.clone(), DelegationRequest { request, notes: None, token: None, redeemed: false });
        let link = format!("https://console.aws.amazon.com/iam/home#/delegation/requests/{id}");
        Ok(types::CreateDelegationRequestResponse { console_deep_link: Some(link), delegation_request_id: Some(id) })
    }

    pub fn get_delegation_request(
        &self,
        ctx: &RequestContext,
        input: types::GetDelegationRequestRequest,
    ) -> Result<types::GetDelegationRequestResponse, ServiceError> {
        self.authorize(ctx, "GetDelegationRequest", &self.delegation_arn(&input.delegation_request_id))?;
        let state = self.read();
        let d = state
            .delegation_requests
            .get(&input.delegation_request_id)
            .ok_or_else(|| no_such_request(&input.delegation_request_id))?;
        let check = input.delegation_permission_check;
        Ok(types::GetDelegationRequestResponse {
            delegation_request: Some(wire(d, ctx.received_at)),
            permission_check_status: check.then(|| "COMPLETE".into()),
            permission_check_result: check.then(|| "ALLOWED".into()),
        })
    }

    pub fn list_delegation_requests(
        &self,
        ctx: &RequestContext,
        input: types::ListDelegationRequestsRequest,
    ) -> Result<types::ListDelegationRequestsResponse, ServiceError> {
        self.authorize(ctx, "ListDelegationRequests", "*")?;
        let state = self.read();
        let owner = input.owner_id.unwrap_or_else(|| ctx.caller.arn.clone());
        let all: Vec<types::DelegationRequest> = state
            .delegation_requests
            .values()
            .filter(|d| d.request.owner_id.as_deref() == Some(owner.as_str()))
            .map(|d| wire(d, ctx.received_at))
            .collect();
        let (page, truncated, marker) = paginate(
            &all,
            |d| d.delegation_request_id.clone().unwrap_or_default(),
            input.marker.as_deref(),
            input.max_items,
        )?;
        Ok(types::ListDelegationRequestsResponse { delegation_requests: Some(page), marker, is_truncated: truncated })
    }

    pub fn associate_delegation_request(
        &self,
        ctx: &RequestContext,
        input: types::AssociateDelegationRequestRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "AssociateDelegationRequest", &self.delegation_arn(&input.delegation_request_id))?;
        let caller = ctx.caller.arn.clone();
        let account = self.account_id().to_string();
        let now = ctx.received_at;
        self.with_request(ctx, &input.delegation_request_id, |d, _| {
            let r = &mut d.request;
            if state_of(r, now) != "UNASSIGNED" {
                return Err(errors::invalid_input("The delegation request is already associated with an owner."));
            }
            if r.owner_account_id.as_deref().is_some_and(|a| a != account) {
                return Err(errors::invalid_input("The delegation request belongs to another account."));
            }
            r.owner_account_id = Some(account);
            r.owner_id = Some(caller);
            r.state = Some("ASSIGNED".into());
            Ok(())
        })
    }

    pub fn update_delegation_request(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDelegationRequestRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UpdateDelegationRequest", &self.delegation_arn(&input.delegation_request_id))?;
        if input.notes.as_ref().is_some_and(|n| n.len() > MAX_NOTES) {
            return Err(errors::invalid_input(format!("Notes cannot exceed {MAX_NOTES} characters.")));
        }
        let now = ctx.received_at;
        self.with_request(ctx, &input.delegation_request_id, |d, _| {
            if !matches!(state_of(&d.request, now).as_str(), "ASSIGNED" | "PENDING_APPROVAL") {
                return Err(errors::invalid_input(format!(
                    "The delegation request cannot be updated in state {}.",
                    state_of(&d.request, now)
                )));
            }
            d.notes = input.notes;
            d.request.state = Some("PENDING_APPROVAL".into());
            Ok(())
        })
    }

    pub fn accept_delegation_request(
        &self,
        ctx: &RequestContext,
        input: types::AcceptDelegationRequestRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "AcceptDelegationRequest", &self.delegation_arn(&input.delegation_request_id))?;
        let caller = ctx.caller.arn.clone();
        let now = ctx.received_at;
        self.with_request(ctx, &input.delegation_request_id, |d, _| {
            if !matches!(state_of(&d.request, now).as_str(), "ASSIGNED" | "PENDING_APPROVAL") {
                return Err(errors::concurrent_modification(format!(
                    "The delegation request cannot be accepted in state {}.",
                    state_of(&d.request, now)
                )));
            }
            d.request.state = Some("ACCEPTED".into());
            d.request.approver_id = Some(caller);
            Ok(())
        })
    }

    pub fn reject_delegation_request(
        &self,
        ctx: &RequestContext,
        input: types::RejectDelegationRequestRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "RejectDelegationRequest", &self.delegation_arn(&input.delegation_request_id))?;
        let now = ctx.received_at;
        self.with_request(ctx, &input.delegation_request_id, |d, _| {
            if !matches!(
                state_of(&d.request, now).as_str(),
                "UNASSIGNED" | "ASSIGNED" | "PENDING_APPROVAL" | "ACCEPTED"
            ) {
                return Err(errors::invalid_input(format!(
                    "The delegation request cannot be rejected in state {}.",
                    state_of(&d.request, now)
                )));
            }
            d.request.state = Some("REJECTED".into());
            d.request.rejection_reason = input.notes;
            Ok(())
        })
    }

    pub fn send_delegation_token(
        &self,
        ctx: &RequestContext,
        input: types::SendDelegationTokenRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "SendDelegationToken", &self.delegation_arn(&input.delegation_request_id))?;
        let now = ctx.received_at;
        self.with_request(ctx, &input.delegation_request_id, |d, _| {
            if state_of(&d.request, now) != "ACCEPTED" {
                return Err(errors::invalid_input("The delegation request must be in the ACCEPTED state."));
            }
            d.request.state = Some("FINALIZED".into());
            d.token = Some(format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()));
            Ok(())
        })
    }

    pub fn get_human_readable_summary(
        &self,
        ctx: &RequestContext,
        input: types::GetHumanReadableSummaryRequest,
    ) -> Result<types::GetHumanReadableSummaryResponse, ServiceError> {
        self.authorize(ctx, "GetHumanReadableSummary", &input.entity_arn)?;
        let Some(id) = input.entity_arn.split_once(":delegation-request/").map(|(_, id)| id.to_string()) else {
            return Err(errors::invalid_input("Only delegation-request entities are supported."));
        };
        let state = self.read();
        let d = state.delegation_requests.get(&id).ok_or_else(|| no_such_request(&id))?;
        let r = &d.request;
        let template =
            r.permissions.as_ref().and_then(|p| p.policy_template_arn.clone()).unwrap_or_else(|| "none".into());
        let summary = format!(
            "{} requests temporary access for {} seconds using policy template {}. Description: {}",
            r.requestor_name.as_deref().unwrap_or("A partner"),
            r.session_duration.unwrap_or_default(),
            template,
            r.description.as_deref().unwrap_or_default()
        );
        Ok(types::GetHumanReadableSummaryResponse {
            summary_content: Some(summary),
            locale: Some(input.locale.unwrap_or_else(|| "en".into())),
            summary_state: Some("AVAILABLE".into()),
        })
    }
}
