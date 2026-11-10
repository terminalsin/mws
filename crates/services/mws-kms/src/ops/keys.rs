//! Key lifecycle: creation, metadata, state, deletion, tags, key policies,
//! rotation and multi-Region replication.

use chrono::{Duration, Utc};
use mws_core::{AuthzDecision, ConditionContext, RequestContext, ResourcePolicyMode, ServiceError};
use mws_iam_policy::{Policy, PolicyKind};
use serde_json::Value;

use super::{
    invalid_state, key_arn, metadata, page, request_tag_conditions, require_enabled, require_not_pending_deletion,
    require_settled, validate_tags, validation, Access,
};
use crate::crypto::{self, Spec};
use crate::generated::{errors, types};
use crate::state::{Key, Material, State, Transition};
use crate::Kms;

const MAX_ON_DEMAND_ROTATIONS: usize = 25;
const DEFAULT_ROTATION_DAYS: i32 = 365;

/// The policy KMS gives a key created without one, formatted as KMS
/// returns it.
pub(crate) fn default_policy(partition: &str, account: &str) -> String {
    format!(
        "{{\n  \"Version\" : \"2012-10-17\",\n  \"Id\" : \"key-default-1\",\n  \"Statement\" : [ {{\n    \"Sid\" : \"Enable IAM User Permissions\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : {{\n      \"AWS\" : \"arn:{partition}:iam::{account}:root\"\n    }},\n    \"Action\" : \"kms:*\",\n    \"Resource\" : \"*\"\n  }} ]\n}}"
    )
}

/// The `AWS` principals a policy document names.
fn aws_principals(doc: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(doc) else { return Vec::new() };
    let statements = match &v["Statement"] {
        serde_json::Value::Array(a) => a.clone(),
        s @ serde_json::Value::Object(_) => vec![s.clone()],
        _ => Vec::new(),
    };
    let mut out = Vec::new();
    for s in statements {
        for key in ["Principal", "NotPrincipal"] {
            match &s[key]["AWS"] {
                serde_json::Value::String(p) => out.push(p.clone()),
                serde_json::Value::Array(a) => out.extend(a.iter().filter_map(|p| p.as_str().map(str::to_string))),
                _ => {}
            }
        }
    }
    out
}

impl Kms {
    /// Ask the store's proxy about the external key a new KMS key will use:
    /// it must exist, be an enabled AES-256 key for encryption and
    /// decryption, and not back another KMS key in the store.
    fn check_external_key(&self, ctx: &RequestContext, store_id: &str, xks_key: &str) -> Result<(), ServiceError> {
        let proxy = {
            let st = self.lock();
            if st.keys.values().any(|k| {
                k.custom_key_store_id.as_deref() == Some(store_id)
                    && k.xks_key_id.as_deref() == Some(xks_key)
                    && k.state != "PendingDeletion"
            }) {
                return Err(errors::xks_key_already_in_use(format!(
                    "The external key {xks_key} is already associated with a KMS key in this external key store."
                )));
            }
            st.custom_key_stores.get(store_id).and_then(super::stores::proxy_of)
        };
        let Some(proxy) = proxy else { return Ok(()) };
        let meta = crate::xks::Meta {
            principal: ctx.caller.arn.clone(),
            operation: "CreateKey".into(),
            request_id: ctx.request_id.clone(),
            key_arn: None,
        };
        let md = match crate::xks::key_metadata(&self.xks_transport(), &proxy, xks_key, &meta) {
            Ok(md) => md,
            Err(crate::xks::XksError::Proxy { name, .. }) if name == "KeyNotFoundException" => {
                return Err(errors::xks_key_not_found(format!(
                    "The external key store proxy could not find the external key {xks_key}."
                )));
            }
            Err(crate::xks::XksError::TimedOut) => {
                return Err(errors::dependency_timeout("The external key store proxy did not respond in time."));
            }
            Err(e) => {
                return Err(errors::custom_key_store_invalid_state(format!("CreateKey failed: {}.", e.describe())))
            }
        };
        let usages: Vec<&str> = md["keyUsage"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if md["keySpec"].as_str() != Some("AES_256")
            || !usages.contains(&"ENCRYPT")
            || !usages.contains(&"DECRYPT")
            || md["keyStatus"].as_str() != Some("ENABLED")
        {
            return Err(errors::xks_key_invalid_configuration(format!(
                "The external key {xks_key} must be an enabled AES_256 key with ENCRYPT and DECRYPT usages."
            )));
        }
        Ok(())
    }

    /// Parse a key policy and check that the IAM users and roles it names
    /// exist, as KMS does.
    fn parse_policy(&self, doc: &str) -> Result<(), ServiceError> {
        Policy::parse(doc, PolicyKind::Resource).map_err(|e| errors::malformed_policy_document(e.0))?;
        if let Some(dir) = self.principals() {
            if aws_principals(doc).iter().any(|p| !dir.principal_exists(p)) {
                return Err(errors::malformed_policy_document(
                    "Policy contains a statement with one or more invalid principals.",
                ));
            }
        }
        Ok(())
    }
}

/// The policy lockout safety check: the caller must still be able to
/// change the policy once it is in place.
fn lockout_check(ctx: &RequestContext, arn: &str, policy: &str) -> Result<(), ServiceError> {
    let mut cond = ConditionContext::new();
    cond.insert("kms:CallerAccount".into(), vec![ctx.caller.account_id.clone()]);
    match ctx.check("kms:PutKeyPolicy", arn, Some(policy), ResourcePolicyMode::Required, cond) {
        AuthzDecision::Allow => Ok(()),
        AuthzDecision::Deny { .. } => Err(errors::malformed_policy_document(
            "The new key policy will not allow you to update the key policy in the future.",
        )),
    }
}

/// `kms:TagResource` on a key that CreateKey or ReplicateKey is about to
/// create: IAM policies only, since there is no key policy yet. `region`
/// is the Region the key is created in, when it is not the request's.
fn authorize_tagging(
    ctx: &RequestContext,
    arn: &str,
    tags: &[types::Tag],
    region: Option<&str>,
) -> Result<(), ServiceError> {
    let mut cond = request_tag_conditions(tags);
    cond.insert("kms:CallerAccount".into(), vec![ctx.caller.account_id.clone()]);
    if let Some(region) = region {
        cond.insert("aws:RequestedRegion".into(), vec![region.to_string()]);
    }
    ctx.authorize("kms:TagResource", arn, cond)
}

fn new_key_id(multi_region: bool) -> String {
    if multi_region {
        format!("mrk-{}", crypto::random_hex(16))
    } else {
        uuid::Uuid::new_v4().to_string()
    }
}

pub(crate) fn new_material(secret: Vec<u8>, rotation_type: Option<&str>, now: chrono::DateTime<Utc>) -> Material {
    Material {
        id: crypto::material_id(&secret),
        secret,
        created_at: now,
        rotation_type: rotation_type.map(str::to_string),
        imported: false,
        description: None,
        expiration_model: None,
        valid_to: None,
        pending: false,
    }
}

impl State {
    /// Copy a primary key's material to its replicas (they share it).
    pub(crate) fn sync_replicas(&mut self, arn: &str) {
        let Some(primary) = self.keys.get(arn).cloned() else { return };
        for r in self.replicas_of(arn) {
            let k = self.keys.get_mut(&r).expect("listed");
            k.materials = primary.materials.clone();
            k.current_material = primary.current_material.clone();
            if k.state == "PendingImport" && primary.current_material.is_some() {
                k.state = "Enabled".into();
            }
            if let Some(t) = k.transition.as_mut().filter(|t| t.to == "PendingImport") {
                if primary.current_material.is_some() {
                    t.to = "Enabled".into();
                }
            }
        }
    }
}

/// Services with a predefined `alias/aws/<service>` alias, which AWS backs
/// with an AWS managed key on first use.
pub(crate) const PREDEFINED_AWS_ALIASES: &[&str] = &[
    "acm",
    "backup",
    "codeartifact",
    "codecommit",
    "connect",
    "dynamodb",
    "ebs",
    "ecr",
    "elasticfilesystem",
    "es",
    "firehose",
    "fsx",
    "glue",
    "kafka",
    "kinesis",
    "kinesisvideo",
    "lambda",
    "lightsail",
    "rds",
    "redshift",
    "route53",
    "s3",
    "secretsmanager",
    "sns",
    "sqs",
    "ssm",
    "timestream",
    "xray",
];

/// The service of a predefined AWS alias in the caller's account and
/// Region (`alias/aws/s3` or its ARN).
fn predefined_aws_alias<'a>(ctx: &RequestContext, key_id: &'a str) -> Option<&'a str> {
    let name = match key_id.strip_prefix("arn:") {
        Some(_) => {
            let parts: Vec<&str> = key_id.splitn(6, ':').collect();
            if parts.len() != 6 || parts[3] != ctx.region || parts[4] != ctx.caller.account_id {
                return None;
            }
            parts[5]
        }
        None => key_id,
    };
    let service = name.strip_prefix("alias/aws/")?;
    PREDEFINED_AWS_ALIASES.contains(&service).then_some(service)
}

fn is_primary(key: &Key) -> bool {
    !key.multi_region || key.primary_region.as_deref() == Some(key.region.as_str())
}

impl Kms {
    pub(crate) fn create_key(
        &self,
        ctx: &RequestContext,
        input: types::CreateKeyRequest,
    ) -> Result<types::CreateKeyResponse, ServiceError> {
        if input.key_spec.is_some() && input.customer_master_key_spec.is_some() {
            return Err(validation(
                "You cannot specify KeySpec and CustomerMasterKeySpec in the same request. CustomerMasterKeySpec parameter is deprecated. Use KeySpec instead.",
            ));
        }
        let key_spec = input.key_spec.or(input.customer_master_key_spec).unwrap_or_else(|| "SYMMETRIC_DEFAULT".into());
        let s = Spec::parse(&key_spec).ok_or_else(|| validation(format!("Invalid KeySpec {key_spec}")))?;
        let usage = input.key_usage.unwrap_or_else(|| "ENCRYPT_DECRYPT".into());
        if !s.usages().contains(&usage.as_str()) {
            return Err(validation(format!("KeyUsage {usage} is not compatible with KeySpec {key_spec}")));
        }
        let origin = input.origin.unwrap_or_else(|| "AWS_KMS".into());
        let multi_region = input.multi_region.unwrap_or(false);
        let tags = input.tags.unwrap_or_default();

        let mut cond = request_tag_conditions(&tags);
        cond.insert("kms:KeySpec".into(), vec![key_spec.clone()]);
        cond.insert("kms:CustomerMasterKeySpec".into(), vec![key_spec.clone()]);
        cond.insert("kms:KeyUsage".into(), vec![usage.clone()]);
        cond.insert("kms:CustomerMasterKeyUsage".into(), vec![usage.clone()]);
        cond.insert("kms:KeyOrigin".into(), vec![origin.clone()]);
        cond.insert("kms:MultiRegion".into(), vec![multi_region.to_string()]);
        cond.insert(
            "kms:BypassPolicyLockoutSafetyCheck".into(),
            vec![input.bypass_policy_lockout_safety_check.to_string()],
        );
        self.authorize_account(ctx, "CreateKey", cond)?;
        validate_tags(&tags)?;

        match origin.as_str() {
            "AWS_KMS" | "EXTERNAL" => {
                if input.custom_key_store_id.is_some() {
                    return Err(validation(
                        "CustomKeyStoreId can be specified only when Origin is AWS_CLOUDHSM or EXTERNAL_KEY_STORE.",
                    ));
                }
            }
            "AWS_CLOUDHSM" | "EXTERNAL_KEY_STORE" => {
                if s != Spec::Symmetric {
                    return Err(errors::unsupported_operation(format!(
                        "KeySpec {key_spec} is not supported for Origin {origin}"
                    )));
                }
                if multi_region {
                    return Err(errors::unsupported_operation(
                        "Multi-Region keys are not supported in custom key stores.",
                    ));
                }
                let id = input
                    .custom_key_store_id
                    .as_deref()
                    .ok_or_else(|| validation(format!("CustomKeyStoreId is required when Origin is {origin}.")))?;
                let st = self.lock();
                let store =
                    st.custom_key_stores.get(id).filter(|s| s.account == ctx.caller.account_id).ok_or_else(|| {
                        errors::custom_key_store_not_found(format!("Custom key store {id} not found."))
                    })?;
                if store.connection_state != "CONNECTED" {
                    return Err(errors::custom_key_store_invalid_state(format!(
                        "The custom key store {id} is not connected."
                    )));
                }
            }
            other => return Err(validation(format!("Invalid Origin {other}"))),
        }
        if origin == "EXTERNAL_KEY_STORE" && input.xks_key_id.is_none() {
            return Err(validation("XksKeyId is required when Origin is EXTERNAL_KEY_STORE."));
        }
        if let (Some(store_id), Some(xks_key)) = (input.custom_key_store_id.as_deref(), input.xks_key_id.as_deref()) {
            self.check_external_key(ctx, store_id, xks_key)?;
        }

        let key_id = new_key_id(multi_region);
        let account = ctx.caller.account_id.clone();
        let arn = key_arn(&ctx.partition, &ctx.region, &account, &key_id);
        if !tags.is_empty() {
            // The key does not exist yet, so only IAM policies can allow
            // tagging it.
            authorize_tagging(ctx, &arn, &tags, None)?;
        }
        let policy = match input.policy {
            Some(p) => {
                self.parse_policy(&p)?;
                if !input.bypass_policy_lockout_safety_check {
                    lockout_check(ctx, &arn, &p)?;
                }
                p
            }
            None => default_policy(&ctx.partition, &account),
        };
        let (materials, state) = if origin == "EXTERNAL" {
            (vec![], "PendingImport")
        } else {
            (vec![new_material(crypto::generate(s)?, None, ctx.received_at)], "Enabled")
        };
        let key = Key {
            arn: arn.clone(),
            key_id,
            account,
            region: ctx.region.clone(),
            created_at: ctx.received_at,
            description: input.description.unwrap_or_default(),
            key_usage: usage,
            key_spec,
            origin,
            key_manager: "CUSTOMER".into(),
            state: state.into(),
            enabled_flag: true,
            deletion_date: None,
            pending_window_days: None,
            policy,
            tags: tags.into_iter().map(|t| (t.tag_key, t.tag_value)).collect(),
            current_material: materials.last().map(|m| m.id.clone()),
            materials,
            rotation_period_days: None,
            next_rotation: None,
            multi_region,
            primary_region: multi_region.then(|| ctx.region.clone()),
            custom_key_store_id: input.custom_key_store_id,
            xks_key_id: input.xks_key_id,
            last_usage: None,
            transition: None,
        };
        let mut st = self.lock();
        let md = metadata(&st, &key);
        st.keys.insert(arn, key);
        Ok(types::CreateKeyResponse { key_metadata: Some(md) })
    }

    pub(crate) fn describe_key(
        &self,
        ctx: &RequestContext,
        input: types::DescribeKeyRequest,
    ) -> Result<types::DescribeKeyResponse, ServiceError> {
        // DescribeKey on a predefined AWS alias that no key backs yet
        // creates the AWS managed key, as AWS does.
        if let Some(service) = predefined_aws_alias(ctx, &input.key_id) {
            self.aws_managed_key(ctx, service);
        }
        let t = self.authorize_key(ctx, &input.key_id, Access::new("DescribeKey").grant("DescribeKey").aliases())?;
        let st = self.lock();
        Ok(types::DescribeKeyResponse { key_metadata: Some(metadata(&st, st.key(&t.arn)?)) })
    }

    pub(crate) fn list_keys(
        &self,
        ctx: &RequestContext,
        input: types::ListKeysRequest,
    ) -> Result<types::ListKeysResponse, ServiceError> {
        self.authorize_account(ctx, "ListKeys", ConditionContext::new())?;
        let st = self.lock();
        let items = st
            .keys
            .values()
            .filter(|k| k.account == ctx.caller.account_id && k.region == ctx.region)
            .map(|k| {
                (k.key_id.clone(), types::KeyListEntry { key_id: Some(k.key_id.clone()), key_arn: Some(k.arn.clone()) })
            })
            .collect();
        let (keys, next_marker, truncated) = page(items, input.limit, 100, input.marker.as_deref())?;
        Ok(types::ListKeysResponse { keys: Some(keys), next_marker, truncated })
    }

    fn set_enabled(&self, ctx: &RequestContext, key_id: &str, action: &str, enable: bool) -> Result<(), ServiceError> {
        let t = self.authorize_key(ctx, key_id, Access::new(action))?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        match key.state.as_str() {
            "Enabled" | "Disabled" => key.state = if enable { "Enabled" } else { "Disabled" }.into(),
            s => return Err(invalid_state(key, s)),
        }
        key.enabled_flag = enable;
        // A key re-enabled after its rotation date rotates at once, then
        // every period after that (rotation pauses while it is disabled).
        if enable && key.next_rotation.is_some_and(|n| n < ctx.received_at) {
            key.next_rotation = Some(ctx.received_at);
        }
        Ok(())
    }

    pub(crate) fn enable_key(&self, ctx: &RequestContext, input: types::EnableKeyRequest) -> Result<(), ServiceError> {
        self.set_enabled(ctx, &input.key_id, "EnableKey", true)
    }

    pub(crate) fn disable_key(
        &self,
        ctx: &RequestContext,
        input: types::DisableKeyRequest,
    ) -> Result<(), ServiceError> {
        self.set_enabled(ctx, &input.key_id, "DisableKey", false)
    }

    pub(crate) fn schedule_key_deletion(
        &self,
        ctx: &RequestContext,
        input: types::ScheduleKeyDeletionRequest,
    ) -> Result<types::ScheduleKeyDeletionResponse, ServiceError> {
        let days = input.pending_window_in_days.unwrap_or(30);
        let mut cond = ConditionContext::new();
        cond.insert("kms:ScheduleKeyDeletionPendingWindowInDays".into(), vec![days.to_string()]);
        let mut access = Access::new("ScheduleKeyDeletion");
        access.extra = cond;
        let t = self.authorize_key(ctx, &input.key_id, access)?;
        if !(7..=30).contains(&days) {
            return Err(validation("PendingWindowInDays must be between 7 and 30."));
        }
        let mut st = self.lock();
        let has_replicas = !st.replicas_of(&t.arn).is_empty();
        let key = st.key_mut(&t.arn)?;
        require_not_pending_deletion(key)?;
        require_settled(key)?;
        if key.key_manager == "AWS" {
            return Err(errors::unsupported_operation(format!("{} is an AWS managed key.", key.arn)));
        }
        key.pending_window_days = Some(days);
        if has_replicas && is_primary(key) {
            key.state = "PendingReplicaDeletion".into();
            key.deletion_date = None;
        } else {
            key.state = "PendingDeletion".into();
            key.deletion_date = Some(ctx.received_at + Duration::days(days as i64));
        }
        Ok(types::ScheduleKeyDeletionResponse {
            key_id: Some(key.arn.clone()),
            deletion_date: key.deletion_date,
            key_state: Some(key.state.clone()),
            pending_window_in_days: Some(days),
        })
    }

    pub(crate) fn cancel_key_deletion(
        &self,
        ctx: &RequestContext,
        input: types::CancelKeyDeletionRequest,
    ) -> Result<types::CancelKeyDeletionResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("CancelKeyDeletion"))?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        if !matches!(key.state.as_str(), "PendingDeletion" | "PendingReplicaDeletion") {
            return Err(errors::kms_invalid_state(format!("{} is not pending deletion.", key.arn)));
        }
        key.state =
            if key.origin == "EXTERNAL" && key.current().is_none() { "PendingImport" } else { "Disabled" }.into();
        key.enabled_flag = false;
        key.deletion_date = None;
        key.pending_window_days = None;
        Ok(types::CancelKeyDeletionResponse { key_id: Some(key.arn.clone()) })
    }

    pub(crate) fn update_key_description(
        &self,
        ctx: &RequestContext,
        input: types::UpdateKeyDescriptionRequest,
    ) -> Result<(), ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("UpdateKeyDescription"))?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        require_not_pending_deletion(key)?;
        key.description = input.description;
        Ok(())
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        let mut access = Access::new("TagResource");
        access.extra = request_tag_conditions(&input.tags);
        let t = self.authorize_key(ctx, &input.key_id, access)?;
        validate_tags(&input.tags)?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        require_not_pending_deletion(key)?;
        let mut tags = key.tags.clone();
        for tag in input.tags {
            tags.insert(tag.tag_key, tag.tag_value);
        }
        if tags.len() > 50 {
            return Err(errors::tag("Too many tags. A KMS key can have at most 50 tags."));
        }
        key.tags = tags;
        Ok(())
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        let t = self.authorize_key(
            ctx,
            &input.key_id,
            Access::new("UntagResource").condition("aws:TagKeys", input.tag_keys.clone()),
        )?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        require_not_pending_deletion(key)?;
        for k in &input.tag_keys {
            key.tags.remove(k);
        }
        Ok(())
    }

    pub(crate) fn list_resource_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceTagsRequest,
    ) -> Result<types::ListResourceTagsResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("ListResourceTags"))?;
        let st = self.lock();
        let items = st
            .key(&t.arn)?
            .tags
            .iter()
            .map(|(k, v)| (k.clone(), types::Tag { tag_key: k.clone(), tag_value: v.clone() }))
            .collect();
        let (tags, next_marker, truncated) = page(items, input.limit, 50, input.marker.as_deref())?;
        Ok(types::ListResourceTagsResponse { tags: Some(tags), next_marker, truncated })
    }

    // ---- key policies -------------------------------------------------------

    pub(crate) fn get_key_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetKeyPolicyRequest,
    ) -> Result<types::GetKeyPolicyResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("GetKeyPolicy"))?;
        let name = input.policy_name.unwrap_or_else(|| "default".into());
        if name != "default" {
            return Err(errors::not_found("No such policy exists"));
        }
        let st = self.lock();
        Ok(types::GetKeyPolicyResponse { policy: Some(st.key(&t.arn)?.policy.clone()), policy_name: Some(name) })
    }

    pub(crate) fn list_key_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListKeyPoliciesRequest,
    ) -> Result<types::ListKeyPoliciesResponse, ServiceError> {
        self.authorize_key(ctx, &input.key_id, Access::new("ListKeyPolicies"))?;
        let (names, next_marker, truncated) =
            page(vec![("default".to_string(), "default".to_string())], input.limit, 100, input.marker.as_deref())?;
        Ok(types::ListKeyPoliciesResponse { policy_names: Some(names), next_marker, truncated })
    }

    pub(crate) fn put_key_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutKeyPolicyRequest,
    ) -> Result<(), ServiceError> {
        let t = self.authorize_key(
            ctx,
            &input.key_id,
            Access::new("PutKeyPolicy").condition(
                "kms:BypassPolicyLockoutSafetyCheck",
                vec![input.bypass_policy_lockout_safety_check.to_string()],
            ),
        )?;
        if input.policy_name.as_deref().is_some_and(|n| n != "default") {
            return Err(errors::not_found("No such policy exists"));
        }
        self.parse_policy(&input.policy)?;
        if !input.bypass_policy_lockout_safety_check {
            lockout_check(ctx, &t.arn, &input.policy)?;
        }
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        require_not_pending_deletion(key)?;
        key.policy = input.policy;
        Ok(())
    }

    // ---- rotation -----------------------------------------------------------

    fn rotatable<'a>(key: &'a Key, what: &str) -> Result<&'a Key, ServiceError> {
        if !key.is_symmetric() {
            return Err(errors::unsupported_operation(format!(
                "{} key spec {} is not valid for {what}.",
                key.arn, key.key_spec
            )));
        }
        if key.custom_key_store_id.is_some() {
            return Err(errors::unsupported_operation(format!(
                "{} is in a custom key store, which does not support {what}.",
                key.arn
            )));
        }
        if !is_primary(key) {
            return Err(errors::unsupported_operation(format!(
                "{} is a multi-Region replica key. Rotation is managed by its primary key.",
                key.arn
            )));
        }
        Ok(key)
    }

    pub(crate) fn enable_key_rotation(
        &self,
        ctx: &RequestContext,
        input: types::EnableKeyRotationRequest,
    ) -> Result<(), ServiceError> {
        let period = input.rotation_period_in_days.unwrap_or(DEFAULT_ROTATION_DAYS);
        let t = self.authorize_key(
            ctx,
            &input.key_id,
            Access::new("EnableKeyRotation").condition("kms:RotationPeriodInDays", vec![period.to_string()]),
        )?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        Self::rotatable(key, "automatic rotation")?;
        if key.origin != "AWS_KMS" {
            return Err(errors::unsupported_operation(format!(
                "{} origin is {} which is not valid for this operation.",
                key.arn, key.origin
            )));
        }
        require_enabled(key)?;
        if key.key_manager == "AWS" {
            return Err(errors::unsupported_operation(format!("{} is an AWS managed key.", key.arn)));
        }
        key.rotation_period_days = Some(period);
        key.next_rotation = Some(ctx.received_at + Duration::days(period as i64));
        Ok(())
    }

    pub(crate) fn disable_key_rotation(
        &self,
        ctx: &RequestContext,
        input: types::DisableKeyRotationRequest,
    ) -> Result<(), ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("DisableKeyRotation"))?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        Self::rotatable(key, "automatic rotation")?;
        if key.origin != "AWS_KMS" {
            return Err(errors::unsupported_operation(format!(
                "{} origin is {} which is not valid for this operation.",
                key.arn, key.origin
            )));
        }
        require_enabled(key)?;
        key.rotation_period_days = None;
        key.next_rotation = None;
        Ok(())
    }

    pub(crate) fn get_key_rotation_status(
        &self,
        ctx: &RequestContext,
        input: types::GetKeyRotationStatusRequest,
    ) -> Result<types::GetKeyRotationStatusResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("GetKeyRotationStatus"))?;
        let st = self.lock();
        let key = st.key(&t.arn)?;
        if !key.is_symmetric() {
            return Err(errors::unsupported_operation(format!(
                "{} key spec {} is not valid for this operation.",
                key.arn, key.key_spec
            )));
        }
        // Replicas report their primary's rotation settings.
        let source = if is_primary(key) {
            key
        } else {
            let primary_region = key.primary_region.clone().unwrap_or_default();
            let parn = key_arn(&ctx.partition, &primary_region, &key.account, &key.key_id);
            st.keys.get(&parn).unwrap_or(key)
        };
        // A key pending deletion reports rotation as off (and is not
        // rotated); cancelling the deletion restores the old status.
        let pending = matches!(key.state.as_str(), "PendingDeletion" | "PendingReplicaDeletion");
        Ok(types::GetKeyRotationStatusResponse {
            key_rotation_enabled: source.rotation_period_days.is_some() && !pending,
            key_id: Some(key.arn.clone()),
            rotation_period_in_days: source.rotation_period_days,
            next_rotation_date: source.next_rotation.filter(|_| !pending),
            on_demand_rotation_start_date: None,
        })
    }

    pub(crate) fn rotate_key_on_demand(
        &self,
        ctx: &RequestContext,
        input: types::RotateKeyOnDemandRequest,
    ) -> Result<types::RotateKeyOnDemandResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("RotateKeyOnDemand"))?;
        let mut st = self.lock();
        let key = st.key_mut(&t.arn)?;
        Self::rotatable(key, "on-demand rotation")?;
        require_enabled(key)?;
        if key.key_manager == "AWS" {
            return Err(errors::unsupported_operation(format!("{} is an AWS managed key.", key.arn)));
        }
        let done = key.materials.iter().filter(|m| m.rotation_type.as_deref() == Some("ON_DEMAND")).count();
        if done >= MAX_ON_DEMAND_ROTATIONS {
            return Err(errors::limit_exceeded(format!(
                "The on-demand rotations limit has been reached for the given key {}.",
                key.arn
            )));
        }
        if key.origin == "EXTERNAL" {
            let pending = key.materials.iter_mut().find(|m| m.pending).ok_or_else(|| {
                errors::kms_invalid_state(format!(
                    "{} has no key material pending rotation. Import new key material first.",
                    t.arn
                ))
            })?;
            pending.pending = false;
            pending.rotation_type = Some("ON_DEMAND".into());
            pending.created_at = ctx.received_at;
            key.current_material = Some(pending.id.clone());
        } else {
            let m = new_material(crypto::generate(Spec::Symmetric)?, Some("ON_DEMAND"), ctx.received_at);
            key.current_material = Some(m.id.clone());
            key.materials.push(m);
        }
        let key_id = key.key_id.clone();
        st.sync_replicas(&t.arn);
        Ok(types::RotateKeyOnDemandResponse { key_id: Some(key_id) })
    }

    pub(crate) fn list_key_rotations(
        &self,
        ctx: &RequestContext,
        input: types::ListKeyRotationsRequest,
    ) -> Result<types::ListKeyRotationsResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("ListKeyRotations"))?;
        let st = self.lock();
        let key = st.key(&t.arn)?;
        if !key.is_symmetric() {
            return Err(errors::unsupported_operation(format!(
                "{} key spec {} is not valid for this operation.",
                key.arn, key.key_spec
            )));
        }
        let all = input.include_key_material.as_deref() == Some("ALL_KEY_MATERIAL");
        let items = key
            .materials
            .iter()
            .filter(|m| all || m.rotation_type.is_some() || m.pending)
            .enumerate()
            .map(|(i, m)| {
                let state = if m.pending {
                    "PENDING_ROTATION"
                } else if key.current_material.as_deref() == Some(m.id.as_str()) {
                    "CURRENT"
                } else {
                    "NON_CURRENT"
                };
                let entry = types::RotationsListEntry {
                    key_id: Some(key.key_id.clone()),
                    key_material_id: Some(m.id.clone()),
                    key_material_description: m.description.clone(),
                    import_state: (key.origin == "EXTERNAL").then(|| "IMPORTED".into()),
                    key_material_state: Some(state.into()),
                    expiration_model: m.expiration_model.clone(),
                    valid_to: m.valid_to,
                    rotation_date: m.rotation_type.as_ref().map(|_| m.created_at),
                    rotation_type: m.rotation_type.clone(),
                };
                (format!("{i:08}"), entry)
            })
            .collect();
        let (rotations, next_marker, truncated) = page(items, input.limit, 100, input.marker.as_deref())?;
        Ok(types::ListKeyRotationsResponse { rotations: Some(rotations), next_marker, truncated })
    }

    pub(crate) fn get_key_last_usage(
        &self,
        ctx: &RequestContext,
        input: types::GetKeyLastUsageRequest,
    ) -> Result<types::GetKeyLastUsageResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("GetKeyLastUsage"))?;
        let st = self.lock();
        let key = st.key(&t.arn)?;
        Ok(types::GetKeyLastUsageResponse {
            key_id: Some(key.arn.clone()),
            key_last_usage: key.last_usage.as_ref().map(|u| types::KeyLastUsageData {
                operation: Some(u.operation.clone()),
                timestamp: Some(u.at),
                cloud_trail_event_id: None,
                kms_request_id: Some(u.request_id.clone()),
            }),
            tracking_start_date: Some(key.created_at),
            key_creation_date: Some(key.created_at),
        })
    }

    // ---- multi-Region keys --------------------------------------------------

    pub(crate) fn replicate_key(
        &self,
        ctx: &RequestContext,
        input: types::ReplicateKeyRequest,
    ) -> Result<types::ReplicateKeyResponse, ServiceError> {
        let t = self.authorize_key(
            ctx,
            &input.key_id,
            Access::new("ReplicateKey").condition("kms:ReplicaRegion", vec![input.replica_region.clone()]),
        )?;
        let tags = input.tags.unwrap_or_default();
        let primary = self.lock().key(&t.arn)?.clone();
        let arn = key_arn(&ctx.partition, &input.replica_region, &primary.account, &primary.key_id);
        // The replica is created in its own Region: that takes kms:CreateKey
        // there (and kms:TagResource for tags), from IAM policies.
        let mut cond = request_tag_conditions(&tags);
        cond.insert("aws:RequestedRegion".into(), vec![input.replica_region.clone()]);
        cond.insert("kms:KeySpec".into(), vec![primary.key_spec.clone()]);
        cond.insert("kms:CustomerMasterKeySpec".into(), vec![primary.key_spec.clone()]);
        cond.insert("kms:KeyUsage".into(), vec![primary.key_usage.clone()]);
        cond.insert("kms:CustomerMasterKeyUsage".into(), vec![primary.key_usage.clone()]);
        cond.insert("kms:KeyOrigin".into(), vec![primary.origin.clone()]);
        cond.insert("kms:MultiRegion".into(), vec!["true".into()]);
        cond.insert(
            "kms:BypassPolicyLockoutSafetyCheck".into(),
            vec![input.bypass_policy_lockout_safety_check.to_string()],
        );
        self.authorize_account(ctx, "CreateKey", cond)?;
        if !tags.is_empty() {
            authorize_tagging(ctx, &arn, &tags, Some(&input.replica_region))?;
        }
        validate_tags(&tags)?;
        if !primary.multi_region {
            return Err(errors::unsupported_operation(format!("{} is not a multi-Region key.", primary.arn)));
        }
        if !is_primary(&primary) {
            return Err(errors::unsupported_operation(format!("{} is not a multi-Region primary key.", primary.arn)));
        }
        require_not_pending_deletion(&primary)?;
        require_settled(&primary)?;
        if input.replica_region == primary.region {
            return Err(validation(format!(
                "The replica region {} must be different from the primary key's region.",
                input.replica_region
            )));
        }
        let policy = match input.policy {
            Some(p) => {
                self.parse_policy(&p)?;
                if !input.bypass_policy_lockout_safety_check {
                    lockout_check(ctx, &arn, &p)?;
                }
                p
            }
            None => default_policy(&ctx.partition, &primary.account),
        };
        let mut st = self.lock();
        if st.keys.contains_key(&arn) {
            return Err(errors::already_exists(format!("Replica key {arn} already exists.")));
        }
        let replica = Key {
            arn: arn.clone(),
            region: input.replica_region,
            created_at: ctx.received_at,
            description: input.description.unwrap_or_else(|| primary.description.clone()),
            // Creating until KMS has set the replica up.
            state: "Creating".into(),
            transition: Some(Transition {
                since: ctx.received_at,
                to: if primary.current_material.is_some() { "Enabled" } else { "PendingImport" }.into(),
                primary_region: None,
            }),
            enabled_flag: true,
            deletion_date: None,
            pending_window_days: None,
            policy: policy.clone(),
            tags: tags.iter().map(|t| (t.tag_key.clone(), t.tag_value.clone())).collect(),
            rotation_period_days: None,
            next_rotation: None,
            last_usage: None,
            ..primary
        };
        st.keys.insert(arn.clone(), replica);
        st.settle_transitions(ctx.received_at);
        let md = metadata(&st, st.key(&arn)?);
        Ok(types::ReplicateKeyResponse {
            replica_key_metadata: Some(md),
            replica_policy: Some(policy),
            replica_tags: Some(tags),
        })
    }

    pub(crate) fn update_primary_region(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePrimaryRegionRequest,
    ) -> Result<(), ServiceError> {
        let t = self.authorize_key(
            ctx,
            &input.key_id,
            Access::new("UpdatePrimaryRegion").condition("kms:PrimaryRegion", vec![input.primary_region.clone()]),
        )?;
        let mut st = self.lock();
        let key = st.key(&t.arn)?.clone();
        if !key.multi_region {
            return Err(errors::unsupported_operation(format!("{} is not a multi-Region key.", key.arn)));
        }
        if !is_primary(&key) {
            return Err(errors::unsupported_operation(format!("{} is not a multi-Region primary key.", key.arn)));
        }
        require_settled(&key)?;
        require_enabled(&key).or_else(|e| if key.state == "Disabled" { Ok(()) } else { Err(e) })?;
        let new_arn = key_arn(&ctx.partition, &input.primary_region, &key.account, &key.key_id);
        let replica =
            st.keys.get(&new_arn).ok_or_else(|| errors::not_found(format!("Key '{new_arn}' does not exist")))?;
        require_settled(replica)?;
        require_enabled(replica).or_else(|e| if replica.state == "Disabled" { Ok(()) } else { Err(e) })?;
        // Both keys are Updating until the switch is done; the primary
        // Region changes when it settles.
        for arn in [&t.arn, &new_arn] {
            let k = st.keys.get_mut(arn).expect("checked");
            let to = std::mem::replace(&mut k.state, "Updating".into());
            k.transition = Some(Transition {
                since: ctx.received_at,
                to,
                primary_region: (*arn == t.arn).then(|| input.primary_region.clone()),
            });
        }
        st.settle_transitions(ctx.received_at);
        Ok(())
    }
}
