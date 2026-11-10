//! ECR state: one registry per account and Region, holding repositories
//! (settings, policies and their OCI content) and the registry-wide
//! configuration. Times are epoch milliseconds on the emulated clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Signs registry passwords (`GetAuthorizationToken`).
    pub token_key: String,
    /// By `account/region`.
    pub registries: BTreeMap<String, Registry>,
}

impl State {
    pub fn registry(&self, account: &str, region: &str) -> Option<&Registry> {
        self.registries.get(&format!("{account}/{region}"))
    }

    pub fn registry_mut(&mut self, account: &str, region: &str) -> &mut Registry {
        self.registries.entry(format!("{account}/{region}")).or_insert_with(|| Registry {
            account: account.to_string(),
            region: region.to_string(),
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Registry {
    pub account: String,
    pub region: String,
    pub repositories: BTreeMap<String, Repo>,
    pub policy: Option<String>,
    pub replication: Option<types::ReplicationConfiguration>,
    pub scanning: Option<types::RegistryScanningConfiguration>,
    /// By ECR repository prefix.
    pub pull_through: BTreeMap<String, types::PullThroughCacheRule>,
    /// By prefix (`ROOT` for the default template).
    pub templates: BTreeMap<String, types::RepositoryCreationTemplate>,
    /// Account settings that differ from the defaults.
    pub settings: BTreeMap<String, String>,
    pub signing: Option<types::SigningConfiguration>,
    /// Principal ARN to registration time.
    pub pull_time_exclusions: BTreeMap<String, i64>,
    pub backfills: Vec<Backfill>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Repo {
    pub name: String,
    pub arn: String,
    pub created_at: i64,
    pub tag_mutability: String,
    pub exclusion_filters: Vec<types::ImageTagMutabilityExclusionFilter>,
    pub scan_on_push: bool,
    pub encryption: Option<types::EncryptionConfiguration>,
    pub tags: BTreeMap<String, String>,
    pub policy: Option<String>,
    pub lifecycle: Option<String>,
    pub lifecycle_evaluated_at: Option<i64>,
    pub preview: Option<Preview>,
    pub content: mws_oci::Repository,
    /// ECR's own record of each image, by digest.
    pub meta: BTreeMap<String, ImageMeta>,
    /// Pull-through caches: when each tag was last checked upstream.
    pub upstream_checked: BTreeMap<String, i64>,
}

impl Repo {
    /// Whether a tag that already names an image may not move to another.
    pub fn tag_locked(&self, tag: &str) -> bool {
        let excluded = self.exclusion_filters.iter().any(|f| crate::names::wildcard(&f.filter, tag));
        match self.tag_mutability.as_str() {
            "IMMUTABLE" => true,
            "IMMUTABLE_WITH_EXCLUSION" => !excluded,
            "MUTABLE_WITH_EXCLUSION" => excluded,
            _ => false,
        }
    }

    pub fn meta(&self, digest: &str) -> ImageMeta {
        self.meta.get(digest).cloned().unwrap_or_default()
    }

    pub fn status(&self, digest: &str) -> String {
        self.meta.get(digest).map(|m| m.status.clone()).filter(|s| !s.is_empty()).unwrap_or_else(|| "ACTIVE".into())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageMeta {
    pub scan: Option<Scan>,
    /// `ACTIVE` (empty), `ARCHIVED` or `ACTIVATING`.
    pub status: String,
    pub activates_at: Option<i64>,
    pub last_archived_at: Option<i64>,
    pub last_activated_at: Option<i64>,
    pub replication: Vec<types::ImageReplicationStatus>,
    pub signing: Vec<types::ImageSigningStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Scan {
    /// `IN_PROGRESS`, `COMPLETE`, `UNSUPPORTED_IMAGE`, `PENDING`, `ACTIVE`, ...
    pub status: String,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    /// An Amazon Inspector (enhanced) scan rather than a basic one.
    pub enhanced: bool,
    /// For enhanced scans: `SCAN_ON_PUSH` or `CONTINUOUS_SCAN`.
    pub frequency: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Preview {
    pub text: String,
    pub started_at: i64,
    pub results: Vec<PreviewResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PreviewResult {
    pub digest: String,
    pub tags: Vec<String>,
    pub pushed_at: i64,
    /// `EXPIRE` or `TRANSITION`.
    pub action: String,
    pub target_storage_class: Option<String>,
    pub priority: i32,
    pub storage_class: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Backfill {
    pub id: String,
    pub destination: types::ReplicationDestination,
    pub status: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub failure_code: Option<String>,
    pub results: Vec<types::ReplicationBackfillResult>,
}
