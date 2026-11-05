//! What other services read from Organizations: the accounts of an
//! organization (IAM Identity Center lists them in the AWS access portal)
//! and trusted access they turn on for themselves.

use chrono::{DateTime, Utc};

use crate::Organizations;

/// An account as the AWS access portal shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    pub id: String,
    pub name: String,
    pub email: String,
    pub status: String,
}

impl Organizations {
    /// What Organizations knows about `account_id`.
    pub fn account_summary(&self, account_id: &str) -> Option<AccountSummary> {
        let state = self.lock();
        let a = state.accounts.get(account_id)?;
        Some(AccountSummary { id: a.id.clone(), name: a.name.clone(), email: a.email.clone(), status: a.status.clone() })
    }

    /// The ids of every account in the organization `account_id` belongs to.
    pub fn organization_accounts(&self, account_id: &str) -> Vec<String> {
        let state = self.lock();
        state.org_of(account_id).map(|o| o.members.keys().cloned().collect()).unwrap_or_default()
    }

    /// Turn on trusted access for `service_principal` in the organization
    /// `account_id` manages, as a service does when it is enabled for the
    /// organization. Returns whether the organization exists.
    pub fn enable_trusted_access(&self, account_id: &str, service_principal: &str, now: DateTime<Utc>) -> bool {
        let mut state = self.lock();
        let Some(org) = state.organizations.values_mut().find(|o| o.management_account == account_id) else {
            return false;
        };
        org.services.entry(service_principal.to_string()).or_insert(now);
        true
    }
}
