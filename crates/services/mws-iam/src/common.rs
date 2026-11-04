//! Helpers shared by the IAM operation modules.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::{LazyLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind};

use crate::generated::{errors, types};
use crate::state::Tags;
use crate::{Iam, Inner, State};

pub const DEFAULT_MAX_ITEMS: usize = 100;
pub const MAX_TAGS: usize = 50;
pub const MAX_MANAGED_POLICIES_PER_ENTITY: usize = 10;
pub const MAX_POLICY_VERSIONS: usize = 5;
pub const MANAGED_POLICY_MAX_SIZE: usize = 6144;
/// Default quota for a role trust policy (`ACLSizePerRole`).
pub const TRUST_POLICY_MAX_SIZE: usize = 2048;

/// Read access to one account's IAM namespace.
pub(crate) struct StateRead<'a> {
    guard: RwLockReadGuard<'a, BTreeMap<String, State>>,
    account: String,
}

impl Deref for StateRead<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        static EMPTY: LazyLock<State> = LazyLock::new(State::default);
        self.guard.get(&self.account).unwrap_or(&EMPTY)
    }
}

/// Write access to one account's IAM namespace.
pub(crate) struct StateWrite<'a> {
    guard: RwLockWriteGuard<'a, BTreeMap<String, State>>,
    account: String,
}

impl Deref for StateWrite<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.guard[&self.account]
    }
}

impl StateWrite<'_> {
    /// Every account's namespace, for changes that cross accounts.
    pub(crate) fn every_account(&mut self) -> &mut BTreeMap<String, State> {
        &mut self.guard
    }
}

impl DerefMut for StateWrite<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.guard.get_mut(&self.account).expect("account namespace exists")
    }
}

impl Inner {
    pub(crate) fn read_account(&self, account: &str) -> StateRead<'_> {
        StateRead { guard: self.accounts.read().expect("IAM state lock poisoned"), account: account.to_string() }
    }

    pub(crate) fn write_account(&self, account: &str) -> StateWrite<'_> {
        let mut guard = self.accounts.write().expect("IAM state lock poisoned");
        if !guard.contains_key(account) {
            let mut state = State::default();
            crate::ops::seed_aws_managed_policies(&self.config.partition, &mut state);
            guard.insert(account.to_string(), state);
        }
        StateWrite { guard, account: account.to_string() }
    }
}

impl Iam {
    /// The current account's namespace (see [`Iam::in_account`]).
    pub(crate) fn read(&self) -> StateRead<'_> {
        self.inner.read_account(&self.current_account())
    }

    pub(crate) fn write(&self) -> StateWrite<'_> {
        self.inner.write_account(&self.current_account())
    }

    pub(crate) fn account_id(&self) -> String {
        self.current_account()
    }

    /// Ask the authorizer. Never call this while holding the state lock: the
    /// IAM authorizer reads the same state.
    pub(crate) fn authorize(&self, ctx: &RequestContext, action: &str, resource: &str) -> Result<(), ServiceError> {
        ctx.authorize(&format!("iam:{action}"), resource, ConditionContext::new())
    }

    pub(crate) fn authorize_with(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        ctx.authorize(&format!("iam:{action}"), resource, extra)
    }

    pub(crate) fn entity_arn(&self, kind: &str, path: &str, name: &str) -> String {
        self.arn(&format!("{kind}{path}{name}"))
    }

    /// ARN of an existing user, or the ARN it would have at path `/`.
    pub(crate) fn user_arn_or_default(&self, name: &str) -> String {
        self.read().user(name).map(|u| u.arn.clone()).unwrap_or_else(|| self.entity_arn("user", "/", name))
    }
    pub(crate) fn group_arn_or_default(&self, name: &str) -> String {
        self.read().group(name).map(|g| g.arn.clone()).unwrap_or_else(|| self.entity_arn("group", "/", name))
    }
    pub(crate) fn role_arn_or_default(&self, name: &str) -> String {
        self.read().role(name).map(|r| r.arn.clone()).unwrap_or_else(|| self.entity_arn("role", "/", name))
    }
    pub(crate) fn instance_profile_arn_or_default(&self, name: &str) -> String {
        self.read()
            .instance_profile(name)
            .map(|r| r.arn.clone())
            .unwrap_or_else(|| self.entity_arn("instance-profile", "/", name))
    }
}

pub fn no_such_user(name: &str) -> ServiceError {
    errors::no_such_entity(format!("The user with name {name} cannot be found."))
}
pub fn no_such_group(name: &str) -> ServiceError {
    errors::no_such_entity(format!("The group with name {name} cannot be found."))
}
pub fn no_such_role(name: &str) -> ServiceError {
    errors::no_such_entity(format!("The role with name {name} cannot be found."))
}
pub fn no_such_instance_profile(name: &str) -> ServiceError {
    errors::no_such_entity(format!("Instance Profile {name} cannot be found."))
}
pub fn no_such_policy(arn: &str) -> ServiceError {
    errors::no_such_entity(format!("Policy {arn} was not found."))
}
pub fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationError", 400, message)
}

/// Validate a policy document the way IAM does before storing it.
pub fn validate_policy(document: &str, kind: PolicyKind) -> Result<Policy, ServiceError> {
    Policy::parse(document, kind).map_err(|e| errors::malformed_policy_document(e.0))
}

/// IAM returns stored policy documents URL-encoded (RFC 3986).
pub fn encode_document(doc: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(doc.len() * 2);
    for b in doc.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Tags from a request. Tag keys are case-insensitive, so one request may
/// not name a key twice in different cases.
pub fn tags_from_wire(tags: Option<Vec<types::Tag>>) -> Result<Tags, ServiceError> {
    let tags: Tags = tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
    let mut seen = std::collections::HashSet::new();
    if !tags.iter().all(|(k, _)| seen.insert(k.to_lowercase())) {
        return Err(errors::invalid_input("Duplicate tag keys found. Please note that Tag keys are case insensitive."));
    }
    Ok(tags)
}

pub fn tags_to_wire(tags: &Tags) -> Option<Vec<types::Tag>> {
    (!tags.is_empty()).then(|| tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect())
}

pub fn tags_list(tags: &Tags) -> Vec<types::Tag> {
    tags_to_wire(tags).unwrap_or_default()
}

/// Merge `new` into `existing` (keys are case-insensitive for replacement)
/// and enforce the quota.
pub fn merge_tags(existing: &mut Tags, new: Tags, quota_name: &str) -> Result<(), ServiceError> {
    let mut merged = existing.clone();
    for (k, v) in new {
        match merged.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(&k)) {
            Some(slot) => *slot = (k, v),
            None => merged.push((k, v)),
        }
    }
    if merged.len() > MAX_TAGS {
        return Err(errors::limit_exceeded(format!("Cannot exceed quota for {quota_name}: {MAX_TAGS}")));
    }
    *existing = merged;
    Ok(())
}

pub fn remove_tags(existing: &mut Tags, keys: &[String]) {
    existing.retain(|(k, _)| !keys.iter().any(|r| r.eq_ignore_ascii_case(k)));
}

/// `aws:RequestTag/*` and `aws:TagKeys` for operations that set tags.
pub fn request_tag_context(tags: &Tags) -> ConditionContext {
    let mut ctx = ConditionContext::new();
    if tags.is_empty() {
        return ctx;
    }
    for (k, v) in tags {
        ctx.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
    }
    ctx.insert("aws:TagKeys".into(), tags.iter().map(|(k, _)| k.clone()).collect());
    ctx
}

/// `aws:ResourceTag/*` and `iam:ResourceTag/*` for a tagged resource.
pub fn resource_tag_context(tags: &Tags) -> ConditionContext {
    let mut ctx = ConditionContext::new();
    for (k, v) in tags {
        ctx.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
        ctx.insert(format!("iam:ResourceTag/{k}"), vec![v.clone()]);
    }
    ctx
}

pub fn single(key: &str, value: impl Into<String>) -> ConditionContext {
    let mut ctx = ConditionContext::new();
    ctx.insert(key.to_string(), vec![value.into()]);
    ctx
}

/// IAM-style `Marker`/`MaxItems` pagination over items sorted by `key`.
/// Returns the page, whether it is truncated, and the next marker.
pub fn paginate<T: Clone>(
    items: &[T],
    key: impl Fn(&T) -> String,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<(Vec<T>, bool, Option<String>), ServiceError> {
    let start = match marker {
        None => 0,
        Some(m) => {
            let after = decode_marker(m).ok_or_else(|| validation("Invalid Marker."))?;
            items.iter().position(|i| key(i) >= after).unwrap_or(items.len())
        }
    };
    let max = max_items.map(|m| m.max(1) as usize).unwrap_or(DEFAULT_MAX_ITEMS);
    let end = (start + max).min(items.len());
    let page = items[start..end].to_vec();
    let truncated = end < items.len();
    let next = truncated.then(|| encode_marker(&key(&items[end])));
    Ok((page, truncated, next))
}

fn encode_marker(key: &str) -> String {
    key.bytes().map(|b| format!("{b:02X}")).collect()
}

fn decode_marker(marker: &str) -> Option<String> {
    if !marker.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> =
        (0..marker.len()).step_by(2).map(|i| u8::from_str_radix(marker.get(i..i + 2)?, 16).ok()).collect();
    String::from_utf8(bytes?).ok()
}

pub fn status_str(active: bool) -> &'static str {
    if active {
        "Active"
    } else {
        "Inactive"
    }
}

/// Rewrite every role trust policy that names `arn` as an AWS principal to
/// name `unique_id` instead. IAM stores principals by unique id, so once a
/// user or role is deleted its trust grants show (and act as) the old id: a
/// new entity with the same name does not inherit them.
pub fn retire_principal(accounts: &mut BTreeMap<String, State>, arn: &str, unique_id: &str) {
    for state in accounts.values_mut() {
        for role in state.roles.values_mut() {
            if role.trust_policy.contains(arn) {
                if let Some(doc) = replace_principal(&role.trust_policy, arn, unique_id) {
                    role.trust_policy = doc;
                }
            }
        }
    }
}

fn replace_principal(doc: &str, arn: &str, unique_id: &str) -> Option<String> {
    use serde_json::Value;
    let mut root: Value = serde_json::from_str(doc).ok()?;
    let statements: Vec<&mut Value> = match root.get_mut("Statement")? {
        Value::Array(a) => a.iter_mut().collect(),
        o @ Value::Object(_) => vec![o],
        _ => return None,
    };
    let mut changed = false;
    for s in statements {
        for key in ["Principal", "NotPrincipal"] {
            match s.get_mut(key).and_then(|p| p.get_mut("AWS")) {
                Some(Value::String(v)) if v == arn => {
                    *v = unique_id.to_string();
                    changed = true;
                }
                Some(Value::Array(list)) => {
                    for v in list.iter_mut().filter(|v| v.as_str() == Some(arn)) {
                        *v = Value::String(unique_id.to_string());
                        changed = true;
                    }
                }
                _ => {}
            }
        }
    }
    if changed {
        serde_json::to_string(&root).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_round_trips_markers() {
        let items: Vec<String> = (0..5).map(|i| format!("u{i}")).collect();
        let (p1, t1, m1) = paginate(&items, |s| s.clone(), None, Some(2)).unwrap();
        assert_eq!((p1, t1), (vec!["u0".to_string(), "u1".to_string()], true));
        let (p2, _, m2) = paginate(&items, |s| s.clone(), m1.as_deref(), Some(2)).unwrap();
        assert_eq!(p2, vec!["u2".to_string(), "u3".to_string()]);
        let (p3, t3, m3) = paginate(&items, |s| s.clone(), m2.as_deref(), Some(2)).unwrap();
        assert_eq!((p3, t3, m3), (vec!["u4".to_string()], false, None));
        assert!(paginate(&items, |s| s.clone(), Some("zz"), None).is_err());
    }

    #[test]
    fn documents_are_url_encoded_like_iam() {
        assert_eq!(encode_document("{\"a\": \"b/c\"}"), "%7B%22a%22%3A%20%22b%2Fc%22%7D");
    }
}
