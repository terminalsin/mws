//! Master user passwords that RDS manages in Secrets Manager
//! (`ManageMasterUserPassword`): an `rds!db-...` or `rds!cluster-...`
//! secret holding `{"username", "password"}`, rotated every seven days (or
//! on `RotateSecret`, or `RotateMasterUserPassword`) by RDS itself, which
//! sets the new password in the database.

use mws_core::{RequestContext, ServiceError};
use mws_secretsmanager::{ManagedRotation, ManagedSecretSpec};

use super::generate_password;
use crate::generated::types as t;
use crate::state::State;
use crate::util::account_of;
use crate::Rds;

/// Rotates RDS-managed secrets for Secrets Manager.
pub struct Rotator(pub Rds);

impl ManagedRotation for Rotator {
    fn rotate(&self, ctx: &RequestContext, secret_arn: &str) -> Result<String, String> {
        self.0.rotate_master_secret(ctx, secret_arn).map_err(|e| e.message)
    }
}

fn secret_value(username: &str, password: &str) -> String {
    serde_json::json!({ "username": username, "password": password }).to_string()
}

impl Rds {
    /// Create the secret for a new managed master password. `kind` is `db`
    /// or `cluster`.
    pub(crate) fn create_master_secret(
        &self,
        ctx: &RequestContext,
        kind: &str,
        resource_arn: &str,
        username: &str,
        password: &str,
        kms_key_id: Option<String>,
    ) -> Result<t::MasterUserSecret, ServiceError> {
        let key_arn = match &kms_key_id {
            Some(k) => k.clone(),
            None => self.kms().aws_managed_key(ctx, "secretsmanager"),
        };
        let (tag, what) = if kind == "cluster" {
            ("aws:rds:primaryDBClusterArn", "cluster")
        } else {
            ("aws:rds:primaryDBInstanceArn", "DB instance")
        };
        let (arn, _) = self.secrets().create_managed_secret(
            ctx,
            ManagedSecretSpec {
                owning_service: "rds".into(),
                name: format!("rds!{kind}-{}", uuid::Uuid::new_v4()),
                description: format!("Secret associated with primary RDS {what}: {resource_arn}"),
                secret_string: secret_value(username, password),
                kms_key_id,
                tags: vec![
                    (tag.into(), resource_arn.into()),
                    ("aws:secretsmanager:owningService".into(), "rds".into()),
                ],
                rotation_days: Some(7),
            },
        )?;
        Ok(t::MasterUserSecret {
            secret_arn: Some(arn),
            secret_status: Some("active".into()),
            kms_key_id: Some(key_arn),
        })
    }

    pub(crate) fn delete_master_secret(&self, secret: &Option<t::MasterUserSecret>) {
        if let Some(arn) = secret.as_ref().and_then(|s| s.secret_arn.as_deref()) {
            self.secrets().delete_managed_secret(arn);
        }
    }

    /// Rotate a managed master password: a new password in the database and
    /// in the secret. Returns the secret's new version id.
    pub(crate) fn rotate_master_secret(&self, ctx: &RequestContext, secret_arn: &str) -> Result<String, ServiceError> {
        let password = generate_password();
        let account = account_of(ctx);
        let found = {
            let mut st = self.lock();
            let key = State::key(&account, &ctx.region);
            let r = st.regions.entry(key).or_default();
            let owns =
                |s: &Option<t::MasterUserSecret>| s.as_ref().and_then(|s| s.secret_arn.as_deref()) == Some(secret_arn);
            if let Some(rec) = r.instances.values_mut().find(|i| owns(&i.db.master_user_secret)) {
                let old = std::mem::replace(&mut rec.master_password, password.clone());
                Some((
                    rec.db.master_username.clone().unwrap_or_default(),
                    old,
                    rec.db.db_instance_identifier.clone(),
                    None,
                ))
            } else if let Some(rec) = r.clusters.values_mut().find(|c| owns(&c.cluster.master_user_secret)) {
                let old = std::mem::replace(&mut rec.master_password, password.clone());
                Some((
                    rec.cluster.master_username.clone().unwrap_or_default(),
                    old,
                    None,
                    rec.cluster.db_cluster_identifier.clone(),
                ))
            } else {
                None
            }
        };
        let Some((username, old, instance, cluster)) = found else {
            return Err(ServiceError::client(
                "InvalidRequestException",
                400,
                "The RDS resource that owns this secret no longer exists.",
            ));
        };
        let version = self.secrets().put_managed_secret_value(ctx, secret_arn, &secret_value(&username, &password))?;
        self.apply_password(ctx, instance, cluster, old);
        Ok(version)
    }

    /// Set the record's (already updated) master password in the running
    /// database.
    pub(crate) fn apply_password(
        &self,
        ctx: &RequestContext,
        instance: Option<String>,
        cluster: Option<String>,
        old_password: String,
    ) {
        if !self.backend().runs_databases() {
            return;
        }
        let spec = self.with_region(ctx, |r| {
            if let Some(id) = &instance {
                let rec = r.instances.get(id)?;
                if let Some(c) = rec.db.db_cluster_identifier.as_ref().and_then(|c| r.clusters.get(c)) {
                    return Some(self.cluster_spec(r, c, ctx));
                }
                return Some(self.instance_spec(r, rec, ctx));
            }
            let c = r.clusters.get(cluster.as_deref()?)?;
            Some(self.cluster_spec(r, c, ctx))
        });
        let Some(spec) = spec else { return };
        let backend = self.backend();
        tokio::spawn(async move {
            // The database may be busy for a moment (a backup pauses it,
            // a restart is finishing): keep trying for a while.
            let mut last = None;
            for _ in 0..30 {
                match backend.set_master_password(&spec, &old_password).await {
                    Ok(()) => return,
                    Err(e) => last = Some(e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            if let Some(e) = last {
                tracing::warn!(db = %spec.identifier, "could not set the new master password: {e}");
            }
        });
    }
}
