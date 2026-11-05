//! What other AWS services see of Organizations: the organization an
//! account belongs to, and delegated administrators registered on a
//! service's behalf (Security Hub's `EnableOrganizationAdminAccount`
//! enables trusted access and registers the account, as AWS does).

use chrono::{DateTime, Utc};

use crate::Organizations;

/// An organization as a service integrating with it sees it.
#[derive(Debug, Clone)]
pub struct OrganizationSnapshot {
    pub id: String,
    pub arn: String,
    pub management_account: String,
    pub accounts: Vec<OrganizationAccount>,
}

#[derive(Debug, Clone)]
pub struct OrganizationAccount {
    pub id: String,
    pub email: String,
    /// `o-.../r-.../ou-.../<account>/`.
    pub path: String,
    /// `ACTIVE`, `SUSPENDED` or `PENDING_CLOSURE`.
    pub status: String,
}

/// Why a delegated administrator could not be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// The caller is not the management account of an organization.
    NotManagementAccount,
    /// The account is not in the caller's organization.
    AccountNotInOrganization,
    /// The management account cannot be its own delegated administrator.
    ManagementAccount,
    /// The organization only has consolidated billing features.
    NotAllFeatures,
}

impl Organizations {
    /// The organization `account` belongs to, if any.
    pub fn organization_of(&self, account: &str) -> Option<OrganizationSnapshot> {
        let state = self.lock();
        let org = state.org_of(account)?;
        let accounts = org
            .members
            .keys()
            .map(|id| {
                let info = state.accounts.get(id);
                OrganizationAccount {
                    id: id.clone(),
                    email: info.map(|a| a.email.clone()).unwrap_or_default(),
                    path: org.account_path(id),
                    status: info.map(|a| a.status.clone()).unwrap_or_else(|| "ACTIVE".into()),
                }
            })
            .collect();
        Some(OrganizationSnapshot {
            arn: org.arn(self.iam.partition()),
            id: org.id.clone(),
            management_account: org.management_account.clone(),
            accounts,
        })
    }

    /// Enable trusted access for `service_principal` and register `account`
    /// as its delegated administrator, on behalf of `management_account`
    /// (a service doing this for its own API, like Security Hub's
    /// `EnableOrganizationAdminAccount`). Registering an account that
    /// already is the delegated administrator succeeds.
    pub fn register_delegated_administrator_for_service(
        &self,
        management_account: &str,
        account: &str,
        service_principal: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DelegationError> {
        let mut state = self.lock();
        let org_id = match state.org_of(management_account) {
            Some(o) if o.management_account == management_account => o.id.clone(),
            _ => return Err(DelegationError::NotManagementAccount),
        };
        let org = state.organizations.get_mut(&org_id).expect("organization exists");
        if org.feature_set != "ALL" {
            return Err(DelegationError::NotAllFeatures);
        }
        if !org.members.contains_key(account) {
            return Err(DelegationError::AccountNotInOrganization);
        }
        if org.management_account == account {
            return Err(DelegationError::ManagementAccount);
        }
        org.services.entry(service_principal.to_string()).or_insert(now);
        org.delegated.entry(account.to_string()).or_default().entry(service_principal.to_string()).or_insert(now);
        Ok(())
    }

    /// Deregister `account` as `service_principal`'s delegated
    /// administrator. Trusted access stays enabled.
    pub fn deregister_delegated_administrator_for_service(
        &self,
        management_account: &str,
        account: &str,
        service_principal: &str,
    ) -> Result<(), DelegationError> {
        let mut state = self.lock();
        let org_id = match state.org_of(management_account) {
            Some(o) if o.management_account == management_account => o.id.clone(),
            _ => return Err(DelegationError::NotManagementAccount),
        };
        let org = state.organizations.get_mut(&org_id).expect("organization exists");
        if let Some(services) = org.delegated.get_mut(account) {
            services.remove(service_principal);
            if services.is_empty() {
                org.delegated.remove(account);
            }
        }
        Ok(())
    }

    /// The delegated administrators of `service_principal` in the
    /// organization `account` belongs to.
    pub fn delegated_administrators_for_service(&self, account: &str, service_principal: &str) -> Vec<String> {
        let state = self.lock();
        let Some(org) = state.org_of(account) else { return Vec::new() };
        org.delegated.iter().filter(|(_, s)| s.contains_key(service_principal)).map(|(a, _)| a.clone()).collect()
    }
}
