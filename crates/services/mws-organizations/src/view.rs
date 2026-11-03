//! What IAM sees of an account's organization.

use std::sync::{Arc, Mutex};

use mws_iam::org::PolicyLevel;
use mws_iam::{AccountOrganization, OrganizationView};

use crate::state::{Org, State, RCP, SCP};

pub(crate) struct View {
    pub state: Arc<Mutex<State>>,
}

/// The policies of `ty` at every level from the root down to `account`.
fn levels(org: &Org, account: &str, ty: &str) -> Option<Vec<PolicyLevel>> {
    if !org.type_enabled(ty) || org.management_account == account {
        return None;
    }
    let levels = org
        .lineage(account)
        .iter()
        .map(|target| {
            org.attached(target)
                .iter()
                .filter_map(|id| org.policy(id))
                .filter(|p| p.ty == ty)
                .map(|p| (p.id, p.content))
                .collect()
        })
        .collect();
    Some(levels)
}

pub(crate) fn account_organization(state: &State, account: &str) -> Option<AccountOrganization> {
    let org = state.org_of(account)?;
    let parent = org.members.get(account).map(|m| m.parent.clone()).unwrap_or_else(|| org.root_id.clone());
    Some(AccountOrganization {
        organization_id: org.id.clone(),
        management_account_id: org.management_account.clone(),
        org_path: org.path_of_container(&parent),
        all_features: org.feature_set == "ALL",
        service_control_policies: levels(org, account, SCP),
        resource_control_policies: levels(org, account, RCP),
        trusted_services: org.services.keys().cloned().collect(),
        delegated_admin_for: org.delegated.get(account).map(|d| d.keys().cloned().collect()).unwrap_or_default(),
        suspended: state.accounts.get(account).is_some_and(|a| a.status != "ACTIVE"),
    })
}

impl OrganizationView for View {
    fn account(&self, account_id: &str) -> Option<AccountOrganization> {
        let state = self.state.lock().expect("Organizations state lock poisoned");
        account_organization(&state, account_id)
    }
}
