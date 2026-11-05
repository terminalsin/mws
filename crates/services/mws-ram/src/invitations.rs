//! Invitations to accounts outside the owner's organization.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::{Invitation, State};
use crate::util::{self, paginate};
use crate::Ram;

fn not_found(arn: &str) -> ServiceError {
    errors::resource_share_invitation_arn_not_found(format!("ResourceShareInvitation {arn} could not be found."))
}

impl Ram {
    fn wire_invitation(&self, st: &State, inv: &Invitation) -> types::ResourceShareInvitation {
        let principal = inv.receiver_arn.clone().unwrap_or_else(|| inv.receiver.clone());
        let associations = st.shares.get(&inv.share_arn).map(|s| {
            s.principals.iter().filter(|p| p.entity == principal).map(|p| s.wire_association(p, "PRINCIPAL")).collect()
        });
        types::ResourceShareInvitation {
            resource_share_invitation_arn: Some(inv.arn.clone()),
            resource_share_name: Some(inv.share_name.clone()),
            resource_share_arn: Some(inv.share_arn.clone()),
            sender_account_id: Some(inv.sender.clone()),
            receiver_account_id: Some(inv.receiver.clone()),
            invitation_timestamp: inv.created,
            status: Some(inv.status.clone()),
            resource_share_associations: associations,
            receiver_arn: inv.receiver_arn.clone(),
        }
    }

    /// The caller's invitation at `arn`.
    fn received<'s>(&self, st: &'s State, ctx: &RequestContext, arn: &str) -> Result<&'s Invitation, ServiceError> {
        util::check_arn(arn)?;
        st.invitations
            .get(arn)
            .filter(|i| {
                i.receiver == ctx.caller.account_id
                    && util::arn_region_account(arn).is_some_and(|(r, _)| r == ctx.region)
            })
            .ok_or_else(|| not_found(arn))
    }

    fn respond(
        &self,
        ctx: &RequestContext,
        arn: &str,
        accept: bool,
    ) -> Result<(types::ResourceShareInvitation, Vec<String>), ServiceError> {
        let action = if accept { "ram:AcceptResourceShareInvitation" } else { "ram:RejectResourceShareInvitation" };
        let (share_arn, receiver) =
            self.lock().invitations.get(arn).map(|i| (i.share_arn.clone(), i.receiver.clone())).unwrap_or_default();
        let mut cond = ConditionContext::new();
        cond.insert(
            "ram:ShareOwnerAccountId".into(),
            vec![util::arn_region_account(&share_arn).map(|(_, a)| a.to_string()).unwrap_or_default()],
        );
        // The invitation lives in the sender's account but is addressed to
        // the receiver, whose own IAM policies decide who may answer it.
        let addressed = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": format!("arn:{}:iam::{receiver}:root", ctx.partition) },
                "Action": action,
                "Resource": arn,
            }]
        })
        .to_string();
        ctx.authorize_with_resource_policy(action, arn, Some(&addressed), cond)?;
        let mut st = self.lock();
        let inv = self.received(&st, ctx, arn)?.clone();
        match inv.status.as_str() {
            "PENDING" => {}
            "ACCEPTED" => {
                return Err(errors::resource_share_invitation_already_accepted(format!(
                    "The invitation {arn} was already accepted."
                )))
            }
            "REJECTED" => {
                return Err(errors::resource_share_invitation_already_rejected(format!(
                    "The invitation {arn} was already rejected."
                )))
            }
            _ => return Err(errors::resource_share_invitation_expired(format!("The invitation {arn} has expired."))),
        }
        let now = ctx.received_at;
        let principal = inv.receiver_arn.clone().unwrap_or_else(|| inv.receiver.clone());
        let mut resources = Vec::new();
        if let Some(share) = st.shares.get_mut(&inv.share_arn) {
            for p in share.principals.iter_mut().filter(|p| p.entity == principal && p.status == "ASSOCIATING") {
                p.status = if accept { "ASSOCIATED" } else { "DISASSOCIATED" }.into();
                p.status_message = (!accept).then(|| "The invitation was rejected.".to_string());
                p.updated = now;
            }
            share.updated = Some(now);
            resources = share.resources.iter().map(|r| r.entity.clone()).collect();
        }
        let stored = st.invitations.get_mut(arn).expect("found above");
        stored.status = if accept { "ACCEPTED" } else { "REJECTED" }.into();
        let stored = stored.clone();
        Ok((self.wire_invitation(&st, &stored), resources))
    }

    pub(crate) fn accept_resource_share_invitation(
        &self,
        ctx: &RequestContext,
        input: types::AcceptResourceShareInvitationRequest,
    ) -> Result<types::AcceptResourceShareInvitationResponse, ServiceError> {
        let (inv, resources) = self.respond(ctx, &input.resource_share_invitation_arn, true)?;
        self.push_policies(&ctx.partition, resources);
        Ok(types::AcceptResourceShareInvitationResponse {
            resource_share_invitation: Some(inv),
            client_token: input.client_token,
        })
    }

    pub(crate) fn reject_resource_share_invitation(
        &self,
        ctx: &RequestContext,
        input: types::RejectResourceShareInvitationRequest,
    ) -> Result<types::RejectResourceShareInvitationResponse, ServiceError> {
        let (inv, resources) = self.respond(ctx, &input.resource_share_invitation_arn, false)?;
        self.push_policies(&ctx.partition, resources);
        Ok(types::RejectResourceShareInvitationResponse {
            resource_share_invitation: Some(inv),
            client_token: input.client_token,
        })
    }

    pub(crate) fn get_resource_share_invitations(
        &self,
        ctx: &RequestContext,
        input: types::GetResourceShareInvitationsRequest,
    ) -> Result<types::GetResourceShareInvitationsResponse, ServiceError> {
        ctx.authorize("ram:GetResourceShareInvitations", "*", ConditionContext::new())?;
        if input.resource_share_invitation_arns.is_some() && input.resource_share_arns.is_some() {
            return Err(errors::invalid_parameter(
                "You can specify resourceShareInvitationArns or resourceShareArns, but not both.",
            ));
        }
        let st = self.lock();
        let account = ctx.caller.account_id.as_str();
        if let Some(arns) = &input.resource_share_invitation_arns {
            for a in arns {
                if !st.invitations.get(a).is_some_and(|i| i.receiver == account) {
                    return Err(not_found(a));
                }
            }
        }
        let out: Vec<types::ResourceShareInvitation> = st
            .invitations
            .values()
            .filter(|i| i.receiver == account && util::arn_region_account(&i.arn).is_some_and(|(r, _)| r == ctx.region))
            .filter(|i| input.resource_share_invitation_arns.as_ref().is_none_or(|a| a.contains(&i.arn)))
            .filter(|i| input.resource_share_arns.as_ref().is_none_or(|a| a.contains(&i.share_arn)))
            .map(|i| self.wire_invitation(&st, i))
            .collect();
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::GetResourceShareInvitationsResponse { resource_share_invitations: Some(page), next_token: next })
    }

    pub(crate) fn list_pending_invitation_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListPendingInvitationResourcesRequest,
    ) -> Result<types::ListPendingInvitationResourcesResponse, ServiceError> {
        let arn = &input.resource_share_invitation_arn;
        ctx.authorize("ram:ListPendingInvitationResources", "*", ConditionContext::new())?;
        let st = self.lock();
        let inv = self.received(&st, ctx, arn)?;
        match inv.status.as_str() {
            "PENDING" => {}
            "ACCEPTED" => {
                return Err(errors::resource_share_invitation_already_accepted(format!(
                    "The invitation {arn} was already accepted."
                )))
            }
            "REJECTED" => {
                return Err(errors::resource_share_invitation_already_rejected(format!(
                    "The invitation {arn} was already rejected."
                )))
            }
            _ => return Err(errors::resource_share_invitation_expired(format!("The invitation {arn} has expired."))),
        }
        if input.resource_region_scope.as_deref() == Some("GLOBAL") {
            return Ok(types::ListPendingInvitationResourcesResponse { resources: Some(Vec::new()), next_token: None });
        }
        let out: Vec<types::Resource> = st
            .shares
            .get(&inv.share_arn)
            .map(|s| {
                s.resources
                    .iter()
                    .filter(|r| r.status == "ASSOCIATED")
                    .map(|r| crate::shares::wire_resource(s, r))
                    .collect()
            })
            .unwrap_or_default();
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPendingInvitationResourcesResponse { resources: Some(page), next_token: next })
    }
}
