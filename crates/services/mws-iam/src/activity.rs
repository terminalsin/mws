//! Activity that IAM reports back: when each access key was last used and
//! when each user or role last authenticated to each service (access
//! advisor, Organizations access reports).
//!
//! The authorizer sees every request, but it must not take the IAM state
//! lock for writing (handlers may hold it for reading while they ask), so it
//! notes activity in a separate pending log that IAM folds into its state
//! before it serves a request or exports its state.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{AuthzRequest, CallerKind};

use crate::state::{AccountServiceAccess, ServiceAccess};
use crate::Inner;

/// Services whose individual actions access advisor tracks.
pub(crate) const ACTION_TRACKED: &[&str] = &["s3", "iam", "ec2", "lambda"];

/// (account, entity ARN, namespace, tracked action).
type ServiceKey = (String, String, String, Option<String>);

/// Pending activity, newest wins, keyed so repeated requests take no more
/// room.
#[derive(Default)]
pub(crate) struct Pending {
    /// (account, access key id) → (when, service, region).
    keys: BTreeMap<(String, String), (DateTime<Utc>, String, String)>,
    /// (account, entity ARN, namespace, tracked action) → (when, region).
    services: BTreeMap<ServiceKey, (DateTime<Utc>, String)>,
    /// (account, namespace) → (when, region, entity ARN).
    accounts: BTreeMap<(String, String), (DateTime<Utc>, String, String)>,
}

impl Inner {
    /// Note that the caller of `req` authenticated to the action's service.
    pub(crate) fn note_activity(&self, req: &AuthzRequest<'_>, entity: Option<String>) {
        let caller = req.caller;
        if matches!(caller.kind, CallerKind::Anonymous) {
            return;
        }
        let Some((namespace, action)) = req.action.split_once(':') else { return };
        let namespace = namespace.to_ascii_lowercase();
        let region = req
            .context
            .get("aws:RequestedRegion")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| "us-east-1".into());
        let now = Utc::now();
        let account = caller.account_id.clone();
        let mut pending = self.activity.lock().expect("IAM activity lock poisoned");
        // Long-term keys only: session credentials are not IAM access keys.
        let long_term = caller.session.is_none() && matches!(caller.kind, CallerKind::User { .. } | CallerKind::Root);
        if long_term && !caller.access_key_id.is_empty() {
            pending
                .keys
                .insert((account.clone(), caller.access_key_id.clone()), (now, namespace.clone(), region.clone()));
        }
        let entity_arn = entity.clone().unwrap_or_else(|| caller.arn.clone());
        pending.accounts.insert((account.clone(), namespace.clone()), (now, region.clone(), entity_arn));
        if let Some(entity) = entity {
            let tracked = ACTION_TRACKED.contains(&namespace.as_str()).then(|| action.to_string());
            pending.services.insert((account.clone(), entity.clone(), namespace.clone(), None), (now, region.clone()));
            if tracked.is_some() {
                pending.services.insert((account, entity, namespace, tracked), (now, region));
            }
        }
    }

    /// Fold pending activity into the account states.
    pub(crate) fn flush_activity(&self) {
        let pending = std::mem::take(&mut *self.activity.lock().expect("IAM activity lock poisoned"));
        if pending.keys.is_empty() && pending.services.is_empty() && pending.accounts.is_empty() {
            return;
        }
        let mut accounts = self.accounts.write().expect("IAM state lock poisoned");
        for ((account, key), used) in pending.keys {
            if let Some(k) = accounts.get_mut(&account).and_then(|s| s.access_keys.get_mut(&key)) {
                k.last_used = Some(used);
            }
        }
        for ((account, entity, namespace, action), (at, region)) in pending.services {
            let Some(state) = accounts.get_mut(&account) else { continue };
            let entry = state
                .service_access
                .entry(entity)
                .or_default()
                .entry(namespace)
                .or_insert_with(|| ServiceAccess { at, region: region.clone(), actions: BTreeMap::new() });
            match action {
                Some(a) => {
                    entry.actions.insert(a, (at, region));
                }
                None if at >= entry.at => {
                    entry.at = at;
                    entry.region = region;
                }
                None => {}
            }
        }
        for ((account, namespace), (at, region, entity)) in pending.accounts {
            let Some(state) = accounts.get_mut(&account) else { continue };
            let entry = state.account_service_access.entry(namespace).or_insert_with(|| AccountServiceAccess {
                at,
                region: region.clone(),
                entity: entity.clone(),
                entities: Default::default(),
            });
            if at >= entry.at {
                entry.at = at;
                entry.region = region;
                entry.entity = entity.clone();
            }
            if entity.contains(":user/") || entity.contains(":role/") {
                entry.entities.insert(entity);
            }
        }
    }

    pub(crate) fn clear_activity(&self) {
        *self.activity.lock().expect("IAM activity lock poisoned") = Pending::default();
    }
}
