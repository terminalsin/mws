//! EFS state: per account and Region, plus replication configurations
//! (which span Regions) and account preferences.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types as t;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `{account}/{region}`.
    pub regions: BTreeMap<String, RegionState>,
    /// `ResourceIdType` by `{account}/{region}`; `LONG_ID` when unset.
    pub preferences: BTreeMap<String, String>,
    /// By source file system ARN.
    pub replications: BTreeMap<String, t::ReplicationConfigurationDescription>,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}/{region}")
    }

    pub fn region(&mut self, account: &str, region: &str) -> &mut RegionState {
        self.regions.entry(Self::key(account, region)).or_default()
    }

    /// A file system by id, in whichever account and Region it lives.
    pub fn find_fs(&self, id: &str) -> Option<(&str, &FileSystem)> {
        self.regions.iter().find_map(|(k, r)| r.file_systems.get(id).map(|f| (k.as_str(), f)))
    }

    /// The replication a file system is the source or destination of.
    pub fn replication_of(&self, fs_id: &str) -> Option<&t::ReplicationConfigurationDescription> {
        self.replications
            .values()
            .find(|r| r.source_file_system_id == fs_id || r.destinations.iter().any(|d| d.file_system_id == fs_id))
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionState {
    pub file_systems: BTreeMap<String, FileSystem>,
    pub mount_targets: BTreeMap<String, MountTarget>,
    pub access_points: BTreeMap<String, t::AccessPointDescription>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileSystem {
    /// Everything but the live counters (mount targets, size).
    pub description: t::FileSystemDescription,
    pub policy: Option<String>,
    /// `ENABLED` / `DISABLED`.
    pub backup: String,
    pub lifecycle: Vec<t::LifecyclePolicy>,
    /// When the throughput mode or provisioned throughput last changed.
    pub throughput_changed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl FileSystem {
    pub fn id(&self) -> &str {
        &self.description.file_system_id
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MountTarget {
    pub description: t::MountTargetDescription,
    pub security_groups: Vec<String>,
}
