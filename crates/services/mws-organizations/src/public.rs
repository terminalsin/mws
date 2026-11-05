//! What other MWS services may ask of Organizations directly, where AWS
//! couples them: services with delegated administration (GuardDuty,
//! Security Hub, ...) read the organization's accounts and enable their
//! own trusted access and delegated administrator with the caller's
//! permissions, as AWS does when such a service calls Organizations on
//! the caller's behalf.

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::generated::types;
use crate::Organizations;

/// An account of an organization.
#[derive(Debug, Clone)]
pub struct OrganizationAccount {
    pub id: String,
    pub email: String,
    /// `ACTIVE`, `SUSPENDED`, `PENDING_CLOSURE`.
    pub status: String,
    pub joined: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OrganizationSummary {
    pub id: String,
    pub management_account: String,
    /// `ALL` or `CONSOLIDATED_BILLING`.
    pub feature_set: String,
    /// Every account, the management account included.
    pub accounts: Vec<OrganizationAccount>,
}

impl Organizations {
    /// The organization `account` belongs to.
    pub fn organization_of(&self, account: &str) -> Option<OrganizationSummary> {
        let state = self.lock();
        let org = state.org_of(account)?;
        let accounts = org
            .members
            .iter()
            .map(|(id, m)| {
                let info = state.accounts.get(id);
                OrganizationAccount {
                    id: id.clone(),
                    email: info.map(|i| i.email.clone()).unwrap_or_default(),
                    status: info.map(|i| i.status.clone()).unwrap_or_else(|| "ACTIVE".into()),
                    joined: m.joined,
                }
            })
            .collect();
        Some(OrganizationSummary {
            id: org.id.clone(),
            management_account: org.management_account.clone(),
            feature_set: org.feature_set.clone(),
            accounts,
        })
    }

    /// `EnableAWSServiceAccess` for `service_principal`, then
    /// `RegisterDelegatedAdministrator` of `account` for it, both
    /// authorized as the caller. An account already registered for the
    /// service is not an error.
    pub fn register_delegated_administrator_for_service(
        &self,
        ctx: &RequestContext,
        account: &str,
        service_principal: &str,
    ) -> Result<(), ServiceError> {
        self.enable_aws_service_access(
            ctx,
            types::EnableAWSServiceAccessRequest { service_principal: service_principal.to_string() },
        )?;
        match self.register_delegated_administrator(
            ctx,
            types::RegisterDelegatedAdministratorRequest {
                account_id: account.to_string(),
                service_principal: service_principal.to_string(),
            },
        ) {
            Err(e) if e.code == "AccountAlreadyRegisteredException" => Ok(()),
            other => other,
        }
    }

    /// `DeregisterDelegatedAdministrator` of `account` for
    /// `service_principal`, authorized as the caller.
    pub fn deregister_delegated_administrator_for_service(
        &self,
        ctx: &RequestContext,
        account: &str,
        service_principal: &str,
    ) -> Result<(), ServiceError> {
        self.deregister_delegated_administrator(
            ctx,
            types::DeregisterDelegatedAdministratorRequest {
                account_id: account.to_string(),
                service_principal: service_principal.to_string(),
            },
        )
    }
}
