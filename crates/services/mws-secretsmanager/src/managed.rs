//! Secrets managed by another service (`OwningService`), such as the master
//! user passwords RDS keeps in `rds!db-...` secrets. The owning service
//! creates them on the caller's behalf (the caller needs
//! `secretsmanager:CreateSecret` and the KMS key, as in AWS), updates their
//! value, and rotates them itself: `RotateSecret` and scheduled rotations of
//! a managed secret call the owner's [`ManagedRotation`] instead of a
//! Lambda function.

use std::sync::Arc;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::names;
use crate::seal::Plain;
use crate::state::{Rotation, Secret, Version, CURRENT};
use crate::SecretsManager;

/// Rotates the secrets a service owns.
pub trait ManagedRotation: Send + Sync {
    /// Rotate `secret_arn` now: the owner sets a new value through
    /// [`SecretsManager::put_managed_secret_value`] and returns the new
    /// version id.
    fn rotate(&self, ctx: &RequestContext, secret_arn: &str) -> Result<String, String>;
}

/// A secret another service creates.
#[derive(Debug, Clone)]
pub struct ManagedSecretSpec {
    /// The owning service (`rds`).
    pub owning_service: String,
    pub name: String,
    pub description: String,
    pub secret_string: String,
    /// The key to encrypt with; `aws/secretsmanager` when `None`.
    pub kms_key_id: Option<String>,
    pub tags: Vec<(String, String)>,
    /// Rotate automatically every this many days.
    pub rotation_days: Option<i64>,
}

impl SecretsManager {
    /// Let `service` rotate the secrets it owns.
    pub fn set_managed_rotation(&self, service: &str, rotation: Arc<dyn ManagedRotation>) {
        self.inner.managed.lock().expect("managed rotation lock").insert(service.to_string(), rotation);
    }

    pub(crate) fn managed_rotation(&self, service: &str) -> Option<Arc<dyn ManagedRotation>> {
        self.inner.managed.lock().expect("managed rotation lock").get(service).cloned()
    }

    /// Create a managed secret as the caller. Returns its ARN and version.
    pub fn create_managed_secret(
        &self,
        ctx: &RequestContext,
        spec: ManagedSecretSpec,
    ) -> Result<(String, String), ServiceError> {
        let account = names::account_of(ctx);
        let arn = names::new_arn(&ctx.partition, &ctx.region, &account, &spec.name);
        let mut c = ConditionContext::new();
        c.insert("secretsmanager:Name".into(), vec![spec.name.clone()]);
        if let Some(k) = &spec.kms_key_id {
            c.insert("secretsmanager:KmsKeyArn".into(), vec![k.clone()]);
        }
        for (k, v) in &spec.tags {
            c.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        }
        c.insert("aws:TagKeys".into(), spec.tags.iter().map(|t| t.0.clone()).collect());
        ctx.authorize("secretsmanager:CreateSecret", &arn, c.clone())?;
        ctx.authorize("secretsmanager:TagResource", &arn, c)?;
        let now = ctx.received_at;
        let token = names::new_token();
        let sealed = self.seal(
            ctx,
            &ctx.region,
            spec.kms_key_id.as_deref(),
            &arn,
            &token,
            &Plain::String(spec.secret_string.clone()),
        )?;
        let rules = spec.rotation_days.map(|d| types::RotationRulesType {
            automatically_after_days: Some(d),
            schedule_expression: Some(format!("rate({d} days)")),
            ..Default::default()
        });
        let next = spec.rotation_days.map(|d| now + chrono::Duration::days(d));
        let secret = Secret {
            arn: arn.clone(),
            name: spec.name.clone(),
            account,
            region: ctx.region.clone(),
            description: Some(spec.description),
            kms_key_id: spec.kms_key_id,
            owning_service: Some(spec.owning_service),
            created: now,
            last_changed: now,
            tags: spec.tags.into_iter().map(|(k, v)| types::Tag { key: Some(k), value: Some(v) }).collect(),
            versions: vec![Version {
                id: token.clone(),
                stages: vec![CURRENT.into()],
                created: now,
                last_accessed: None,
                value: Some(sealed),
            }],
            rotation: Rotation {
                enabled: rules.is_some(),
                rules,
                last_rotated: Some(now),
                window_start: next,
                next,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut st = self.lock();
        if st.secrets.contains_key(&arn) {
            return Err(crate::generated::errors::resource_exists(format!(
                "The operation failed because the secret {} already exists.",
                spec.name
            )));
        }
        st.secrets.insert(arn.clone(), secret);
        Ok((arn, token))
    }

    /// Set a managed secret's current value (the owner rotating it).
    /// Returns the new version id.
    pub fn put_managed_secret_value(
        &self,
        ctx: &RequestContext,
        arn: &str,
        secret_string: &str,
    ) -> Result<String, ServiceError> {
        let s = self.lock().secrets.get(arn).cloned().ok_or_else(names::not_found)?;
        let token = names::new_token();
        self.add_version(ctx, &s, &token, &Plain::String(secret_string.to_string()), &[CURRENT.into()], true)?;
        let now = ctx.received_at;
        self.update(arn, |st| {
            st.rotation.last_rotated = Some(now);
            if let Some(d) = st.rotation.rules.as_ref().and_then(|r| r.automatically_after_days) {
                st.rotation.window_start = Some(now + chrono::Duration::days(d));
                st.rotation.next = st.rotation.window_start;
            }
            Ok(())
        })?;
        Ok(token)
    }

    /// The current value of a managed secret, read by its owner.
    pub fn managed_secret_value(&self, ctx: &RequestContext, arn: &str) -> Result<String, ServiceError> {
        let s = self.lock().secrets.get(arn).cloned().ok_or_else(names::not_found)?;
        let (_, plain) = self.read_value(ctx, &s, None, None)?;
        match plain {
            Plain::String(v) => Ok(v),
            Plain::Binary(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
        }
    }

    /// Delete a managed secret at once (its owner's resource is gone).
    pub fn delete_managed_secret(&self, arn: &str) {
        self.lock().secrets.remove(arn);
    }

    /// Rotate managed secrets whose schedule has come due.
    pub(crate) fn tick_managed(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let due: Vec<(String, String)> = {
            let st = self.lock();
            st.secrets
                .values()
                .filter(|s| {
                    s.deletion_date.is_none()
                        && s.rotation.enabled
                        && s.rotation.lambda_arn.is_none()
                        && s.rotation.window_start.is_some_and(|w| w <= now)
                })
                .filter_map(|s| s.owning_service.clone().map(|o| (s.arn.clone(), o)))
                .collect()
        };
        for (arn, owner) in due {
            let Some(r) = self.managed_rotation(&owner) else { continue };
            if let Err(e) = r.rotate(&names::in_region(ctx, arn.split(':').nth(3).unwrap_or(&ctx.region)), &arn) {
                tracing::warn!(secret = %arn, "managed rotation failed: {e}");
                // Try again at the next window rather than on every request.
                let _ = self.update(&arn, |st| {
                    st.rotation.window_start = Some(now + chrono::Duration::hours(1));
                    Ok(())
                });
            }
        }
    }
}
