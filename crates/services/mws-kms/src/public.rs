//! How other AWS services use KMS keys.
//!
//! Two patterns exist in AWS. Some services act as themselves (a service
//! principal such as `dnssec-route53.amazonaws.com`), and the key policy
//! must allow that principal. Others act for the caller, with the caller's
//! permissions plus the `kms:ViaService` condition key (S3 SSE-KMS, EBS,
//! ...); AWS managed keys (`alias/aws/<service>`) allow exactly that.

use std::collections::BTreeMap;

use chrono::Utc;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind, PrincipalInfo, Request};

use crate::crypto::{self, Message, Spec};
use crate::generated::errors;
use crate::ops::{self, Access};
use crate::state::Key;
use crate::Kms;

/// A key as a service sees it after looking it up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceKey {
    pub arn: String,
    pub key_id: String,
    pub key_spec: String,
    pub key_usage: String,
    /// `Enabled`, `Disabled`, `PendingDeletion`, ...
    pub key_state: String,
    /// `CUSTOMER` or `AWS`.
    pub key_manager: String,
    /// DER SubjectPublicKeyInfo, for asymmetric keys.
    pub public_key: Option<Vec<u8>>,
    /// The uncompressed EC point (`04 || X || Y`), for ECC keys.
    pub ec_point: Option<Vec<u8>>,
}

/// A data key generated for a service acting for the caller.
#[derive(Debug, Clone)]
pub struct DataKey {
    pub key_arn: String,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

fn service_key(key: &Key) -> ServiceKey {
    let spec = Spec::parse(&key.key_spec).expect("stored key specs are valid");
    let material = key.current().map(|m| m.secret.as_slice());
    ServiceKey {
        arn: key.arn.clone(),
        key_id: key.key_id.clone(),
        key_spec: key.key_spec.clone(),
        key_usage: key.key_usage.clone(),
        key_state: key.state.clone(),
        key_manager: key.key_manager.clone(),
        public_key: material.filter(|_| spec.is_asymmetric()).and_then(|m| crypto::public_key_der(spec, m).ok()),
        ec_point: material.and_then(|m| crypto::ec_public_point(spec, m)),
    }
}

/// The policy of an AWS managed key for `service`.
fn aws_managed_policy(partition: &str, account: &str, region: &str, service: &str) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Id": format!("auto-{service}-2"),
        "Statement": [
            {
                "Sid": format!("Allow access through {service} for all principals in the account that are authorized to use {service}"),
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:CreateGrant", "kms:DescribeKey"],
                "Resource": "*",
                "Condition": {"StringEquals": {
                    "kms:ViaService": format!("{service}.{region}.amazonaws.com"),
                    "kms:CallerAccount": account
                }}
            },
            {
                "Sid": "Allow direct access to key metadata to the account",
                "Effect": "Allow",
                "Principal": {"AWS": format!("arn:{partition}:iam::{account}:root")},
                "Action": ["kms:Describe*", "kms:Get*", "kms:List*"],
                "Resource": "*"
            }
        ]
    })
    .to_string()
}

fn via(service: &str, region: &str) -> String {
    format!("{service}.{region}.amazonaws.com")
}

impl Kms {
    /// Look up a key (by key or alias ARN) for an AWS service principal and
    /// check that the key policy allows it every one of `actions` (e.g.
    /// `kms:Sign`). `conditions` carries `aws:SourceAccount`,
    /// `aws:SourceArn` and the like.
    pub fn key_for_service(
        &self,
        key: &str,
        service_principal: &str,
        actions: &[&str],
        conditions: &ConditionContext,
    ) -> Result<ServiceKey, ServiceError> {
        let st = self.lock();
        let arn = Self::arn_from_reference(&st, key)?;
        let key = st.key(&arn)?;
        let policy =
            Policy::parse(&key.policy, PolicyKind::Resource).map_err(|e| errors::malformed_policy_document(e.0))?;
        let principal = PrincipalInfo { service: Some(service_principal.to_string()), ..Default::default() };
        let mut context = mws_iam_policy::ConditionContext::new();
        for (k, v) in conditions {
            context.insert(k, v.clone());
        }
        for action in actions {
            let e = policy.evaluate(&Request { action, resource: &arn, principal: &principal, context: &context });
            if e.denied() || !e.allowed() {
                return Err(ServiceError::client(
                    "AccessDeniedException",
                    400,
                    format!("{service_principal} is not authorized to perform: {action} on resource: {arn}"),
                ));
            }
        }
        Ok(service_key(key))
    }

    /// Sign as a service principal, after [`Kms::key_for_service`] allowed
    /// `kms:Sign`.
    pub fn sign_for_service(&self, key_arn: &str, algorithm: &str, message: &[u8]) -> Result<Vec<u8>, ServiceError> {
        let st = self.lock();
        let key = st.key(key_arn)?;
        ops::require_enabled(key)?;
        let m = key.current().ok_or_else(|| ops::invalid_state(key, &key.state))?;
        crypto::sign(ops::spec(key), &m.secret, algorithm, Message::Raw(message))
    }

    /// Generate a data key as a service principal, after
    /// [`Kms::key_for_service`] allowed `kms:GenerateDataKey` (S3 writing
    /// SSE-KMS inventory reports, ...).
    pub fn generate_data_key_for_service(
        &self,
        key_arn: &str,
        context: &BTreeMap<String, String>,
        number_of_bytes: usize,
    ) -> Result<DataKey, ServiceError> {
        let key = {
            let st = self.lock();
            let key = st.key(key_arn)?;
            ops::require_enabled(key)?;
            key.clone()
        };
        let plaintext = crypto::random_bytes(number_of_bytes);
        let out = ops::cryptographic::encrypt_with(&key, &plaintext, context, None)?;
        Ok(DataKey { key_arn: key.arn, plaintext, ciphertext: out.ciphertext })
    }

    /// A key ARN for a key or alias ARN.
    fn arn_from_reference(st: &crate::state::State, key: &str) -> Result<String, ServiceError> {
        if key.contains(":alias/") {
            let alias = st.aliases.get(key).ok_or_else(|| errors::not_found(format!("Alias {key} is not found.")))?;
            let (region, account) = ops::arn_scope(key);
            let partition = key.split(':').nth(1).unwrap_or("aws");
            return Ok(ops::key_arn(partition, region, account, &alias.target_key_id));
        }
        if !key.starts_with("arn:") || !key.contains(":key/") {
            return Err(ops::invalid_key_id(key));
        }
        st.key(key)?;
        Ok(key.to_string())
    }

    /// The AWS managed key for `service` (`alias/aws/<service>`) in the
    /// caller's account and Region, created on first use as AWS does.
    pub fn aws_managed_key(&self, ctx: &RequestContext, service: &str) -> String {
        let account = &ctx.caller.account_id;
        let name = format!("alias/aws/{service}");
        let alias_arn = ops::alias_arn(&ctx.partition, &ctx.region, account, &name);
        let mut st = self.lock();
        if let Some(a) = st.aliases.get(&alias_arn) {
            return ops::key_arn(&ctx.partition, &ctx.region, account, &a.target_key_id);
        }
        let key_id = uuid::Uuid::new_v4().to_string();
        let arn = ops::key_arn(&ctx.partition, &ctx.region, account, &key_id);
        let secret = crypto::generate(Spec::Symmetric).expect("symmetric keys always generate");
        let now = Utc::now();
        let material = ops::new_material(secret, None);
        st.keys.insert(
            arn.clone(),
            Key {
                arn: arn.clone(),
                key_id: key_id.clone(),
                account: account.clone(),
                region: ctx.region.clone(),
                created_at: now,
                description: format!("Default key that protects my {service} data when no other key is defined"),
                key_usage: "ENCRYPT_DECRYPT".into(),
                key_spec: "SYMMETRIC_DEFAULT".into(),
                origin: "AWS_KMS".into(),
                key_manager: "AWS".into(),
                state: "Enabled".into(),
                enabled_flag: true,
                deletion_date: None,
                pending_window_days: None,
                policy: aws_managed_policy(&ctx.partition, account, &ctx.region, service),
                tags: BTreeMap::new(),
                current_material: Some(material.id.clone()),
                materials: vec![material],
                // AWS managed keys rotate every year.
                rotation_period_days: Some(365),
                next_rotation: Some(now + chrono::Duration::days(365)),
                multi_region: false,
                primary_region: None,
                custom_key_store_id: None,
                xks_key_id: None,
                last_usage: None,
            },
        );
        st.aliases.insert(
            alias_arn.clone(),
            crate::state::Alias { arn: alias_arn, name, target_key_id: key_id, created_at: now, updated_at: now },
        );
        arn
    }

    /// Encrypt for the caller through `service` (`kms:ViaService`).
    /// Returns the key ARN and the ciphertext.
    pub fn encrypt_via(
        &self,
        ctx: &RequestContext,
        service: &str,
        key_id: &str,
        plaintext: &[u8],
        context: &BTreeMap<String, String>,
    ) -> Result<(String, Vec<u8>), ServiceError> {
        let key = self.usable_key(
            ctx,
            key_id,
            Access::crypto("Encrypt")
                .context(Some(context))
                .condition("kms:ViaService", vec![via(service, &ctx.region)])
                .condition("aws:ViaAWSService", vec!["true".into()]),
        )?;
        let out = ops::cryptographic::encrypt_with(&key, plaintext, context, None)?;
        self.record_use(ctx, &key.arn, "Encrypt");
        Ok((key.arn, out.ciphertext))
    }

    /// Decrypt for the caller through `service`. Returns the key ARN and the
    /// plaintext.
    pub fn decrypt_via(
        &self,
        ctx: &RequestContext,
        service: &str,
        ciphertext: &[u8],
        context: &BTreeMap<String, String>,
    ) -> Result<(String, Vec<u8>), ServiceError> {
        let (header, _) = crypto::parse_header(ciphertext).ok_or_else(|| errors::invalid_ciphertext(""))?;
        let arn = ops::key_arn(&ctx.partition, &ctx.region, &header.account, &header.key_id);
        let key = self.usable_key(
            ctx,
            &arn,
            Access::crypto("Decrypt")
                .context(Some(context))
                .condition("kms:ViaService", vec![via(service, &ctx.region)])
                .condition("aws:ViaAWSService", vec!["true".into()]),
        )?;
        let out = ops::cryptographic::decrypt_with(&key, ciphertext, context, None)?;
        self.record_use(ctx, &key.arn, "Decrypt");
        Ok((out.key_arn, out.plaintext))
    }

    /// Generate a data key for the caller through `service`.
    pub fn generate_data_key_via(
        &self,
        ctx: &RequestContext,
        service: &str,
        key_id: &str,
        context: &BTreeMap<String, String>,
        number_of_bytes: usize,
    ) -> Result<DataKey, ServiceError> {
        let key = self.usable_key(
            ctx,
            key_id,
            Access::crypto("GenerateDataKey")
                .context(Some(context))
                .condition("kms:ViaService", vec![via(service, &ctx.region)])
                .condition("aws:ViaAWSService", vec!["true".into()]),
        )?;
        let plaintext = crypto::random_bytes(number_of_bytes);
        let out = ops::cryptographic::encrypt_with(&key, &plaintext, context, None)?;
        self.record_use(ctx, &key.arn, "GenerateDataKey");
        Ok(DataKey { key_arn: key.arn, plaintext, ciphertext: out.ciphertext })
    }
}
