//! Secrets Manager state: every secret of every account and Region, keyed by
//! ARN. Replicas are secrets of their own (in their Region, encrypted with
//! their Region's key) that point back at the primary.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

pub const CURRENT: &str = "AWSCURRENT";
pub const PREVIOUS: &str = "AWSPREVIOUS";
pub const PENDING: &str = "AWSPENDING";

/// Replication status values.
pub const IN_SYNC: &str = "InSync";
pub const IN_PROGRESS: &str = "InProgress";
pub const FAILED: &str = "Failed";

/// A secret value sealed under a KMS data key: the data key as KMS
/// encrypted it (with the secret ARN and version id as encryption context)
/// and the value as AES-256-GCM ciphertext under that data key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Sealed {
    /// The KMS key ARN the data key was generated under.
    pub key_arn: String,
    pub encrypted_data_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// `SecretBinary` rather than `SecretString`.
    pub binary: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Version {
    pub id: String,
    /// Staging labels, in the order they were attached.
    pub stages: Vec<String>,
    pub created: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    /// `None` for a version rotation created that has no value yet.
    pub value: Option<Sealed>,
}

/// Where a primary secret is replicated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Replica {
    pub region: String,
    /// The key as given; `None` for `aws/secretsmanager`.
    pub kms_key_id: Option<String>,
    pub status: String,
    pub status_message: String,
    /// When replication started: `InProgress` until it settles (see
    /// `mws_core::settle`), then `InSync`.
    pub since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Rotation {
    pub enabled: bool,
    pub lambda_arn: Option<String>,
    pub rules: Option<types::RotationRulesType>,
    pub last_rotated: Option<DateTime<Utc>>,
    /// When the next rotation window opens.
    pub window_start: Option<DateTime<Utc>>,
    /// `NextRotationDate`: when that window closes.
    pub next: Option<DateTime<Utc>>,
    pub external_metadata: Option<Vec<types::ExternalSecretRotationMetadataItem>>,
    pub external_role_arn: Option<String>,
    /// The `RotationToken` of the rotation in progress.
    pub token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Secret {
    pub arn: String,
    pub name: String,
    pub account: String,
    pub region: String,
    pub description: Option<String>,
    /// The key as reported (`KmsKeyId`); `None` for `aws/secretsmanager`.
    pub kms_key_id: Option<String>,
    pub secret_type: Option<String>,
    pub owning_service: Option<String>,
    pub created: DateTime<Utc>,
    pub last_changed: DateTime<Utc>,
    pub last_accessed: Option<DateTime<Utc>>,
    /// When a scheduled deletion takes effect.
    pub deletion_date: Option<DateTime<Utc>>,
    /// Deleted with `ForceDeleteWithoutRecovery` at this time: the secret
    /// is gone once the deletion settles (see `mws_core::settle`); until
    /// then it is marked for deletion and its name stays taken.
    pub force_deleted: Option<DateTime<Utc>>,
    pub tags: Vec<types::Tag>,
    /// In creation order.
    pub versions: Vec<Version>,
    pub policy: Option<String>,
    pub rotation: Rotation,
    /// Set on replicas: the primary's Region.
    pub primary_region: Option<String>,
    /// Set on primaries.
    pub replicas: Vec<Replica>,
}

impl Secret {
    pub fn version(&self, id: &str) -> Option<&Version> {
        self.versions.iter().find(|v| v.id == id)
    }

    pub fn version_mut(&mut self, id: &str) -> Option<&mut Version> {
        self.versions.iter_mut().find(|v| v.id == id)
    }

    pub fn staged(&self, stage: &str) -> Option<&Version> {
        self.versions.iter().find(|v| v.stages.iter().any(|s| s == stage))
    }

    pub fn tag_map(&self) -> BTreeMap<String, String> {
        self.tags.iter().map(|t| (t.key.clone().unwrap_or_default(), t.value.clone().unwrap_or_default())).collect()
    }

    /// A rotation is in progress while `AWSPENDING` is on a version that
    /// is not `AWSCURRENT`.
    pub fn pending_rotation(&self) -> Option<&Version> {
        self.versions.iter().find(|v| v.stages.iter().any(|s| s == PENDING) && !v.stages.iter().any(|s| s == CURRENT))
    }

    /// Attach `stage` to version `id`, taking it off whichever version has
    /// it. Moving `AWSCURRENT` moves `AWSPREVIOUS` to the version it left.
    pub fn attach(&mut self, stage: &str, id: &str) {
        let previous_holder = self.staged(stage).map(|v| v.id.clone());
        if previous_holder.as_deref() == Some(id) {
            return;
        }
        for v in &mut self.versions {
            v.stages.retain(|s| s != stage);
        }
        if let Some(v) = self.version_mut(id) {
            v.stages.push(stage.to_string());
        }
        if stage == CURRENT {
            if let Some(old) = previous_holder {
                for v in &mut self.versions {
                    v.stages.retain(|s| s != PREVIOUS);
                }
                if let Some(v) = self.version_mut(&old) {
                    v.stages.push(PREVIOUS.to_string());
                }
            }
        }
    }

    /// Drop deprecated (unlabelled) versions beyond the 100 most recent,
    /// keeping those less than a day old, as Secrets Manager does.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        while self.versions.len() > 100 {
            let Some(i) =
                self.versions.iter().position(|v| v.stages.is_empty() && now - v.created > chrono::Duration::hours(24))
            else {
                break;
            };
            self.versions.remove(i);
        }
    }

    pub fn versions_to_stages(&self) -> BTreeMap<String, Vec<String>> {
        self.versions.iter().filter(|v| !v.stages.is_empty()).map(|v| (v.id.clone(), v.stages.clone())).collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub secrets: BTreeMap<String, Secret>,
}

impl State {
    /// Remove secrets whose recovery window has ended or whose forced
    /// deletion has settled, and finish replication that has settled.
    pub fn sweep(&mut self, now: DateTime<Utc>) {
        self.secrets.retain(|_, s| match s.force_deleted {
            Some(at) => !mws_core::settle::settled(at, now),
            None => s.deletion_date.is_none_or(|d| d > now),
        });
        for s in self.secrets.values_mut() {
            for r in &mut s.replicas {
                if r.status == IN_PROGRESS && r.since.is_none_or(|t| mws_core::settle::settled(t, now)) {
                    r.status = IN_SYNC.into();
                    r.status_message = "Replication succeeded".into();
                    r.since = None;
                }
            }
        }
    }
}
