//! KMS operations and the helpers they share: resolving key identifiers,
//! authorizing through grants and key policies, state checks, pagination.

mod aliases;
pub(crate) mod cryptographic;
mod grants;
mod import;
mod keys;
mod stores;

use std::collections::BTreeMap;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};

use crate::crypto::Spec;
use crate::generated::{errors, types};
use crate::state::{Grant, Key, State};
use crate::Kms;

pub(crate) use keys::new_material;

pub(crate) fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationException", 400, message)
}

pub(crate) fn key_not_found(arn: &str) -> ServiceError {
    errors::not_found(format!("Key '{arn}' does not exist"))
}

pub(crate) fn invalid_key_id(input: &str) -> ServiceError {
    errors::not_found(format!("Invalid keyId '{input}'"))
}

pub(crate) fn dry_run() -> ServiceError {
    errors::dry_run_operation("The request would have succeeded, but the DryRun option is set.")
}

pub(crate) fn key_arn(partition: &str, region: &str, account: &str, key_id: &str) -> String {
    format!("arn:{partition}:kms:{region}:{account}:key/{key_id}")
}

pub(crate) fn alias_arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:kms:{region}:{account}:{name}")
}

/// What a `KeyId` parameter named.
pub(crate) struct Target {
    pub arn: String,
    /// The alias name, when the caller identified the key by alias.
    pub alias: Option<String>,
}

/// A parsed `arn:...:kms:region:account:resource` ARN.
struct KmsArn<'a> {
    region: &'a str,
    account: &'a str,
    resource: &'a str,
}

fn parse_kms_arn(s: &str) -> Option<KmsArn<'_>> {
    let parts: Vec<&str> = s.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "kms" {
        return None;
    }
    Some(KmsArn { region: parts[3], account: parts[4], resource: parts[5] })
}

impl State {
    /// Apply everything that happens with the passage of time: scheduled
    /// deletions, automatic rotations and expiring imported material.
    pub(crate) fn sweep(&mut self, now: DateTime<Utc>) {
        // Primaries waiting for their replicas start their own window once
        // the last replica is gone.
        let waiting: Vec<String> =
            self.keys.values().filter(|k| k.state == "PendingReplicaDeletion").map(|k| k.arn.clone()).collect();
        for arn in waiting {
            if self.replicas_of(&arn).is_empty() {
                let k = self.keys.get_mut(&arn).expect("listed");
                k.state = "PendingDeletion".into();
                k.deletion_date = Some(now + Duration::days(k.pending_window_days.unwrap_or(30) as i64));
            }
        }
        let expired: Vec<String> = self
            .keys
            .values()
            .filter(|k| k.state == "PendingDeletion" && k.deletion_date.is_some_and(|d| d <= now))
            .map(|k| k.arn.clone())
            .collect();
        for arn in expired {
            self.delete_key(&arn);
        }
        let mut rotated = Vec::new();
        for key in self.keys.values_mut() {
            if let (Some(period), Some(next)) = (key.rotation_period_days, key.next_rotation) {
                if next <= now && key.state == "Enabled" {
                    if let Ok(secret) = crate::crypto::generate(Spec::Symmetric) {
                        key.materials.push(crate::state::Material {
                            id: crate::crypto::material_id(&secret),
                            secret,
                            created_at: next,
                            rotation_type: Some("AUTOMATIC".into()),
                            imported: false,
                            description: None,
                            expiration_model: None,
                            valid_to: None,
                            pending: false,
                        });
                        rotated.push(key.arn.clone());
                        key.current_material = key.materials.last().map(|m| m.id.clone());
                    }
                    key.next_rotation = Some(now + Duration::days(period as i64));
                }
            }
            if key.origin == "EXTERNAL" {
                for m in key.materials.iter_mut().filter(|m| m.valid_to.is_some_and(|t| t <= now)) {
                    m.secret.clear();
                }
                if key.current().is_none() && matches!(key.state.as_str(), "Enabled" | "Disabled") {
                    key.state = "PendingImport".into();
                }
            }
        }
        for arn in rotated {
            self.sync_replicas(&arn);
        }
        self.imports.retain(|_, p| p.valid_to > now);
    }

    /// Remove a key and everything that refers to it.
    pub(crate) fn delete_key(&mut self, arn: &str) {
        self.keys.remove(arn);
        self.aliases.retain(|_, a| !alias_targets(a, arn));
        self.grants.retain(|_, g| g.key_arn != arn);
        self.imports.retain(|_, p| p.key_arn != arn);
    }

    /// The ARN of every other key in a multi-Region key's set.
    pub(crate) fn replicas_of(&self, arn: &str) -> Vec<String> {
        let Some(key) = self.keys.get(arn) else { return vec![] };
        if !key.multi_region {
            return vec![];
        }
        self.keys
            .values()
            .filter(|k| k.key_id == key.key_id && k.account == key.account && k.arn != key.arn)
            .map(|k| k.arn.clone())
            .collect()
    }

    pub(crate) fn key(&self, arn: &str) -> Result<&Key, ServiceError> {
        self.keys.get(arn).ok_or_else(|| key_not_found(arn))
    }

    pub(crate) fn key_mut(&mut self, arn: &str) -> Result<&mut Key, ServiceError> {
        self.keys.get_mut(arn).ok_or_else(|| key_not_found(arn))
    }

    /// Alias names that point at `arn`.
    pub(crate) fn aliases_for(&self, arn: &str) -> Vec<String> {
        self.aliases.values().filter(|a| alias_targets(a, arn)).map(|a| a.name.clone()).collect()
    }

    /// Resolve a `KeyId` parameter: a key id, key ARN, alias name or alias
    /// ARN (aliases only where the operation accepts them).
    pub(crate) fn resolve(&self, ctx: &RequestContext, input: &str, allow_alias: bool) -> Result<Target, ServiceError> {
        let partition = &ctx.partition;
        if let Some(arn) = parse_kms_arn(input) {
            if let Some(id) = arn.resource.strip_prefix("key/") {
                let full = key_arn(partition, arn.region, arn.account, id);
                if arn.region != ctx.region || !self.keys.contains_key(&full) {
                    return Err(key_not_found(&full));
                }
                return Ok(Target { arn: full, alias: None });
            }
            if arn.resource.starts_with("alias/") && allow_alias {
                return self.resolve_alias(&alias_arn(partition, arn.region, arn.account, arn.resource), arn.resource);
            }
            return Err(invalid_key_id(input));
        }
        if input.starts_with("alias/") {
            if !allow_alias {
                return Err(invalid_key_id(input));
            }
            let account = &ctx.caller.account_id;
            return self.resolve_alias(&alias_arn(partition, &ctx.region, account, input), input);
        }
        if input.contains(':') || input.contains('/') {
            return Err(invalid_key_id(input));
        }
        let full = key_arn(partition, &ctx.region, &ctx.caller.account_id, input);
        if !self.keys.contains_key(&full) {
            return Err(key_not_found(&full));
        }
        Ok(Target { arn: full, alias: None })
    }

    fn resolve_alias(&self, alias_arn: &str, name: &str) -> Result<Target, ServiceError> {
        let alias =
            self.aliases.get(alias_arn).ok_or_else(|| errors::not_found(format!("Alias {alias_arn} is not found.")))?;
        let (region, account) = arn_scope(alias_arn);
        let arn = key_arn(arn_partition(alias_arn), region, account, &alias.target_key_id);
        if !self.keys.contains_key(&arn) {
            return Err(key_not_found(&arn));
        }
        Ok(Target { arn, alias: Some(name.to_string()) })
    }
}

fn arn_partition(arn: &str) -> &str {
    arn.split(':').nth(1).unwrap_or("aws")
}

/// `(region, account)` of a KMS ARN.
pub(crate) fn arn_scope(arn: &str) -> (&str, &str) {
    let mut parts = arn.split(':').skip(3);
    (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
}

/// Whether `alias` points at the key `key_arn` (same account and Region).
fn alias_targets(alias: &crate::state::Alias, key_arn: &str) -> bool {
    arn_scope(&alias.arn) == arn_scope(key_arn) && key_arn.rsplit('/').next() == Some(alias.target_key_id.as_str())
}

/// Fail unless the key can be used for cryptographic operations.
pub(crate) fn require_enabled(key: &Key) -> Result<(), ServiceError> {
    match key.state.as_str() {
        "Enabled" => Ok(()),
        "Disabled" => Err(errors::disabled(format!("{} is disabled.", key.arn))),
        state => Err(invalid_state(key, state)),
    }
}

pub(crate) fn invalid_state(key: &Key, state: &str) -> ServiceError {
    let what = match state {
        "PendingDeletion" => "pending deletion",
        "PendingImport" => "pending import",
        "PendingReplicaDeletion" => "pending replica deletion",
        "Unavailable" => "unavailable",
        "Disabled" => "disabled",
        "Enabled" => "enabled",
        other => other,
    };
    errors::kms_invalid_state(format!("{} is {what}.", key.arn))
}

/// Fail for keys that are pending deletion (most management operations).
pub(crate) fn require_not_pending_deletion(key: &Key) -> Result<(), ServiceError> {
    match key.state.as_str() {
        s @ ("PendingDeletion" | "PendingReplicaDeletion") => Err(invalid_state(key, s)),
        _ => Ok(()),
    }
}

pub(crate) fn require_usage(key: &Key, usage: &str, operation: &str) -> Result<(), ServiceError> {
    if key.key_usage != usage {
        return Err(errors::invalid_key_usage(format!(
            "{} key usage is {} which is not valid for {operation}.",
            key.arn, key.key_usage
        )));
    }
    Ok(())
}

pub(crate) fn spec(key: &Key) -> Spec {
    Spec::parse(&key.key_spec).expect("stored key specs are valid")
}

/// Condition keys describing the key, for policy evaluation.
fn key_conditions(key: &Key, aliases: &[String]) -> ConditionContext {
    let mut c = ConditionContext::new();
    c.insert("kms:KeySpec".into(), vec![key.key_spec.clone()]);
    c.insert("kms:CustomerMasterKeySpec".into(), vec![key.key_spec.clone()]);
    c.insert("kms:KeyUsage".into(), vec![key.key_usage.clone()]);
    c.insert("kms:CustomerMasterKeyUsage".into(), vec![key.key_usage.clone()]);
    c.insert("kms:KeyOrigin".into(), vec![key.origin.clone()]);
    c.insert("kms:MultiRegion".into(), vec![key.multi_region.to_string()]);
    if key.multi_region {
        let ty = if key.primary_region.as_deref() == Some(key.region.as_str()) { "PRIMARY" } else { "REPLICA" };
        c.insert("kms:MultiRegionKeyType".into(), vec![ty.into()]);
    }
    for (k, v) in &key.tags {
        c.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
    }
    if !aliases.is_empty() {
        c.insert("kms:ResourceAliases".into(), aliases.to_vec());
    }
    c
}

/// Condition keys for an encryption context.
pub(crate) fn context_conditions(enc: &BTreeMap<String, String>) -> ConditionContext {
    let mut c = ConditionContext::new();
    for (k, v) in enc {
        c.insert(format!("kms:EncryptionContext:{k}"), vec![v.clone()]);
    }
    if !enc.is_empty() {
        c.insert("kms:EncryptionContextKeys".into(), enc.keys().cloned().collect());
    }
    c
}

/// ARNs that identify the caller as a grantee or retiring principal.
pub(crate) fn caller_principals(ctx: &RequestContext) -> Vec<String> {
    let c = &ctx.caller;
    let mut out = vec![c.arn.clone()];
    match &c.kind {
        CallerKind::AssumedRole { role_name, .. } => {
            out.push(format!("arn:{}:iam::{}:role/{role_name}", ctx.partition, c.account_id));
        }
        CallerKind::Root => out.push(format!("arn:{}:iam::{}:root", ctx.partition, c.account_id)),
        _ => {}
    }
    out
}

fn grant_allows(grant: &Grant, principals: &[String], op: &str, enc: Option<&BTreeMap<String, String>>) -> bool {
    let grantee = grant.grantee_principal.as_ref().is_some_and(|g| principals.iter().any(|p| p == g));
    if !grantee || !grant.operations.iter().any(|o| o == op) {
        return false;
    }
    let Some(constraints) = &grant.constraints else { return true };
    let empty = BTreeMap::new();
    let enc = enc.unwrap_or(&empty);
    if let Some(equals) = &constraints.encryption_context_equals {
        if equals != enc {
            return false;
        }
    }
    if let Some(subset) = &constraints.encryption_context_subset {
        if !subset.iter().all(|(k, v)| enc.get(k) == Some(v)) {
            return false;
        }
    }
    true
}

/// How an operation is authorized against a key.
pub(crate) struct Access<'a> {
    /// The IAM action without the `kms:` prefix.
    pub action: &'a str,
    /// The grant operation that also allows it, if any.
    pub grant_op: Option<&'a str>,
    pub allow_alias: bool,
    pub encryption_context: Option<&'a BTreeMap<String, String>>,
    pub extra: ConditionContext,
}

impl<'a> Access<'a> {
    pub fn new(action: &'a str) -> Self {
        Self { action, grant_op: None, allow_alias: false, encryption_context: None, extra: ConditionContext::new() }
    }

    /// Cryptographic operations: grants apply and aliases are accepted.
    pub fn crypto(action: &'a str) -> Self {
        Self { grant_op: Some(action), allow_alias: true, ..Self::new(action) }
    }

    pub fn grant(mut self, op: &'a str) -> Self {
        self.grant_op = Some(op);
        self
    }

    pub fn aliases(mut self) -> Self {
        self.allow_alias = true;
        self
    }

    pub fn context(mut self, enc: Option<&'a BTreeMap<String, String>>) -> Self {
        self.encryption_context = enc;
        self
    }

    pub fn condition(mut self, key: &str, values: Vec<String>) -> Self {
        self.extra.insert(key.to_string(), values);
        self
    }
}

impl Kms {
    /// Resolve `key_id` and authorize `access` on it: a grant for the caller
    /// allows on its own; otherwise the key policy must allow, directly or
    /// together with IAM policies. Returns the key ARN.
    pub(crate) fn authorize_key(
        &self,
        ctx: &RequestContext,
        key_id: &str,
        access: Access<'_>,
    ) -> Result<Target, ServiceError> {
        let (target, policy, mut cond, granted) = {
            let st = self.lock();
            let target = st.resolve(ctx, key_id, access.allow_alias)?;
            let key = st.key(&target.arn)?;
            let mut cond = key_conditions(key, &st.aliases_for(&target.arn));
            let principals = caller_principals(ctx);
            let granted = access.grant_op.is_some_and(|op| {
                st.grants
                    .values()
                    .any(|g| g.key_arn == target.arn && grant_allows(g, &principals, op, access.encryption_context))
            });
            if let Some(alias) = &target.alias {
                cond.insert("kms:RequestAlias".into(), vec![alias.clone()]);
            }
            (target, key.policy.clone(), cond, granted)
        };
        if granted {
            return Ok(target);
        }
        cond.insert("kms:CallerAccount".into(), vec![ctx.caller.account_id.clone()]);
        if let Some(enc) = access.encryption_context {
            cond.extend(context_conditions(enc));
        }
        cond.extend(access.extra);
        ctx.authorize_with_required_resource_policy(&format!("kms:{}", access.action), &target.arn, &policy, cond)?;
        Ok(target)
    }

    /// Authorize an action that has no key resource (`CreateKey`,
    /// `ListKeys`, ...).
    pub(crate) fn authorize_account(
        &self,
        ctx: &RequestContext,
        action: &str,
        mut cond: ConditionContext,
    ) -> Result<(), ServiceError> {
        cond.insert("kms:CallerAccount".into(), vec![ctx.caller.account_id.clone()]);
        ctx.authorize(&format!("kms:{action}"), "*", cond)
    }

    /// Record a cryptographic use of the key for `GetKeyLastUsage`.
    pub(crate) fn record_use(&self, ctx: &RequestContext, arn: &str, operation: &str) {
        if let Some(k) = self.lock().keys.get_mut(arn) {
            k.last_usage = Some(crate::state::LastUsage {
                operation: operation.into(),
                at: Utc::now(),
                request_id: ctx.request_id.clone(),
            });
        }
    }
}

/// The wire `KeyMetadata` for a key.
pub(crate) fn metadata(st: &State, key: &Key) -> types::KeyMetadata {
    let s = spec(key);
    let usage = key.key_usage.as_str();
    let some_if = |v: Vec<String>, u: &str| (usage == u).then_some(v);
    let mrc = key.multi_region.then(|| {
        let primary_region = key.primary_region.clone().unwrap_or_else(|| key.region.clone());
        let primary_arn = key_arn(arn_partition(&key.arn), &primary_region, &key.account, &key.key_id);
        let replicas: Vec<types::MultiRegionKey> = st
            .keys
            .values()
            .filter(|k| k.key_id == key.key_id && k.account == key.account && k.region != primary_region)
            .map(|k| types::MultiRegionKey { arn: Some(k.arn.clone()), region: Some(k.region.clone()) })
            .collect();
        types::MultiRegionConfiguration {
            multi_region_key_type: Some(if key.region == primary_region { "PRIMARY" } else { "REPLICA" }.into()),
            primary_key: Some(types::MultiRegionKey { arn: Some(primary_arn), region: Some(primary_region) }),
            replica_keys: Some(replicas),
        }
    });
    let pending = matches!(key.state.as_str(), "PendingDeletion" | "PendingReplicaDeletion");
    let store = key.custom_key_store_id.as_ref().and_then(|id| st.custom_key_stores.get(id));
    types::KeyMetadata {
        aws_account_id: Some(key.account.clone()),
        key_id: key.key_id.clone(),
        arn: Some(key.arn.clone()),
        creation_date: Some(key.created_at),
        enabled: key.state == "Enabled",
        description: Some(key.description.clone()),
        key_usage: Some(key.key_usage.clone()),
        key_state: Some(key.state.clone()),
        deletion_date: if key.state == "PendingDeletion" { key.deletion_date } else { None },
        valid_to: key.current().and_then(|m| m.valid_to),
        origin: Some(key.origin.clone()),
        custom_key_store_id: key.custom_key_store_id.clone(),
        cloud_hsm_cluster_id: store.and_then(|s| s.cloud_hsm_cluster_id.clone()),
        expiration_model: key
            .current()
            .filter(|_| key.origin == "EXTERNAL")
            .map(|m| m.expiration_model.clone().unwrap_or_else(|| "KEY_MATERIAL_DOES_NOT_EXPIRE".into())),
        key_manager: Some(key.key_manager.clone()),
        customer_master_key_spec: Some(key.key_spec.clone()),
        key_spec: Some(key.key_spec.clone()),
        encryption_algorithms: some_if(s.encryption_algorithms(), "ENCRYPT_DECRYPT"),
        signing_algorithms: some_if(s.signing_algorithms(), "SIGN_VERIFY"),
        key_agreement_algorithms: some_if(vec!["ECDH".into()], "KEY_AGREEMENT"),
        encapsulation_algorithms: some_if(vec!["ML_KEM".into()], "ENCAPSULATE_DECAPSULATE"),
        multi_region: Some(key.multi_region),
        multi_region_configuration: mrc,
        pending_deletion_window_in_days: if pending { key.pending_window_days } else { None },
        mac_algorithms: some_if(s.mac_algorithms(), "GENERATE_VERIFY_MAC"),
        xks_key_configuration: key.xks_key_id.clone().map(|id| types::XksKeyConfigurationType { id: Some(id) }),
        current_key_material_id: key.current_material.clone(),
    }
}

/// One page of `items` (already in order, with their sort keys): the page,
/// the next marker and whether there is more.
pub(crate) fn page<T>(
    items: Vec<(String, T)>,
    limit: Option<i32>,
    default_limit: usize,
    marker: Option<&str>,
) -> Result<(Vec<T>, Option<String>, bool), ServiceError> {
    let limit = limit.map(|l| l as usize).unwrap_or(default_limit);
    let start = match marker {
        Some(m) => {
            let after = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(m)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| errors::invalid_marker("Invalid marker"))?;
            items.iter().position(|(k, _)| *k >= after).unwrap_or(items.len())
        }
        None => 0,
    };
    let rest: Vec<(String, T)> = items.into_iter().skip(start).collect();
    let truncated = rest.len() > limit;
    let next = if truncated {
        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rest[limit].0.as_bytes()))
    } else {
        None
    };
    Ok((rest.into_iter().take(limit).map(|(_, v)| v).collect(), next, truncated))
}

/// Tags as the request supplied them, rejecting reserved keys.
pub(crate) fn validate_tags(tags: &[types::Tag]) -> Result<(), ServiceError> {
    for t in tags {
        if t.tag_key.starts_with("aws:") {
            return Err(errors::tag("Tags beginning with aws: are reserved."));
        }
    }
    if tags.len() > 50 {
        return Err(errors::tag("Too many tags. A KMS key can have at most 50 tags."));
    }
    Ok(())
}

/// `aws:RequestTag/...` and `aws:TagKeys` for tags in a request.
pub(crate) fn request_tag_conditions(tags: &[types::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for t in tags {
        c.insert(format!("aws:RequestTag/{}", t.tag_key), vec![t.tag_value.clone()]);
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.tag_key.clone()).collect());
    }
    c
}
