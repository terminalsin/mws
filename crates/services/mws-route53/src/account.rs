//! Route 53 resources belong to the account that created them. Resource ids
//! are global (and resource ARNs carry no account), so each account's
//! resources are kept apart here: a caller sees and counts only its own,
//! and an id that belongs to another account is refused with Route 53's
//! `AccessDenied` rather than reported missing.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::MutexGuard;

use mws_core::{RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::health::no_such_health_check;
use crate::state::{HealthCheck, State, Zone};
use crate::zones::no_such_zone;

/// Every account's Route 53 state.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Accounts {
    /// By account id. The empty key holds state saved before Route 53
    /// kept accounts apart; the first account to use Route 53 adopts it.
    pub accounts: BTreeMap<String, State>,
}

impl Accounts {
    /// Load saved state, in this format or the older single-account one.
    pub fn from_saved(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        if value.get("accounts").is_some() {
            return serde_json::from_value(value);
        }
        let legacy: State = serde_json::from_value(value)?;
        Ok(Accounts { accounts: BTreeMap::from([(String::new(), legacy)]) })
    }

    /// Every zone of every account, with its owner.
    pub fn all_zones(&self) -> impl Iterator<Item = (&str, &Zone)> {
        self.accounts.iter().flat_map(|(a, s)| s.zones.values().map(move |z| (a.as_str(), z)))
    }

    /// The owner of hosted zone `id`.
    pub fn zone_owner(&self, id: &str) -> Option<&str> {
        self.accounts.iter().find(|(_, s)| s.zones.contains_key(id)).map(|(a, _)| a.as_str())
    }
}

/// The state lock, opened on the caller's account. Derefs to that
/// account's [`State`]; [`AccountGuard::zone`] and friends also tell
/// another account's ids apart from missing ones.
pub struct AccountGuard<'a> {
    pub(crate) all: MutexGuard<'a, Accounts>,
    pub(crate) account: String,
    caller_arn: String,
}

impl<'a> AccountGuard<'a> {
    pub(crate) fn new(mut all: MutexGuard<'a, Accounts>, ctx: &RequestContext) -> Self {
        let account = ctx.caller.account_id.clone();
        if !all.accounts.contains_key(&account) {
            let adopted = all.accounts.remove("").unwrap_or_default();
            all.accounts.insert(account.clone(), adopted);
        }
        AccountGuard { all, account, caller_arn: ctx.caller.arn.clone() }
    }

    /// Route 53's answer for another account's resource.
    pub(crate) fn access_denied(&self) -> ServiceError {
        ServiceError::client(
            "AccessDenied",
            403,
            format!("User: {} is not authorized to access this resource", self.caller_arn),
        )
    }

    fn elsewhere(&self, exists: impl Fn(&State) -> bool) -> bool {
        self.all.accounts.iter().any(|(a, s)| *a != self.account && exists(s))
    }

    fn missing(&self, exists: impl Fn(&State) -> bool, not_found: ServiceError) -> ServiceError {
        if self.elsewhere(exists) {
            self.access_denied()
        } else {
            not_found
        }
    }

    pub(crate) fn zone(&self, id: &str) -> Result<&Zone, ServiceError> {
        if !self.zones.contains_key(id) {
            return Err(self.missing(|s| s.zones.contains_key(id), no_such_zone(id)));
        }
        Ok(&self.zones[id])
    }

    pub(crate) fn zone_mut(&mut self, id: &str) -> Result<&mut Zone, ServiceError> {
        if !self.zones.contains_key(id) {
            return Err(self.missing(|s| s.zones.contains_key(id), no_such_zone(id)));
        }
        Ok(self.zones.get_mut(id).expect("checked"))
    }

    pub(crate) fn health_check(&self, id: &str) -> Result<&HealthCheck, ServiceError> {
        if !self.health_checks.contains_key(id) {
            return Err(self.missing(|s| s.health_checks.contains_key(id), no_such_health_check(id)));
        }
        Ok(&self.health_checks[id])
    }

    pub(crate) fn health_check_mut(&mut self, id: &str) -> Result<&mut HealthCheck, ServiceError> {
        self.health_check(id)?;
        Ok(self.health_checks.get_mut(id).expect("checked"))
    }
}

impl Deref for AccountGuard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.all.accounts[&self.account]
    }
}

impl DerefMut for AccountGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.all.accounts.get_mut(&self.account).expect("account state exists")
    }
}
