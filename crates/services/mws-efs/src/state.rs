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
    /// When the file system last switched to provisioned throughput or had
    /// it increased: for 24 hours after, the mode can't change and the
    /// provisioned throughput can't decrease.
    pub throughput_restricted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When a `creating` or `deleting` file system finishes; `None` once
    /// it is `available`.
    pub transition_ends: Option<chrono::DateTime<chrono::Utc>>,
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
    /// When a `creating` mount target becomes `available`, or a
    /// `deleting` one goes away.
    pub transition_ends: Option<chrono::DateTime<chrono::Utc>>,
}

/// How long a new file system stays `creating` (AWS: a few seconds).
pub fn file_system_create() -> chrono::Duration {
    chrono::Duration::milliseconds(mws_core::settle::window_ms(2_000))
}
/// How long a deleted file system stays `deleting`.
pub fn file_system_delete() -> chrono::Duration {
    chrono::Duration::milliseconds(mws_core::settle::window_ms(2_000))
}
/// How long a new mount target stays `creating`. AWS takes about 90
/// seconds; MWS keeps it short, and advancing the emulated clock
/// (`/_mws/clock`) finishes it at once, as does `MWS_ASYNC_DELAY_MS=0`.
pub fn mount_target_create() -> chrono::Duration {
    chrono::Duration::milliseconds(mws_core::settle::window_ms(4_000))
}
/// How long a deleted mount target stays `deleting` (AWS: tens of
/// seconds), its network interface with it.
pub fn mount_target_delete() -> chrono::Duration {
    chrono::Duration::milliseconds(mws_core::settle::window_ms(4_000))
}

impl State {
    /// Finish the transitions due by `now`: `creating` file systems and
    /// mount targets become `available`, `deleting` file systems go away
    /// (with their access points), and so do `deleting` mount targets.
    /// Returns the ids of the file systems that went away, whose data the
    /// caller removes, and the network interfaces (region key, interface
    /// id) of the mount targets that did, which the caller deletes.
    pub fn settle(&mut self, now: chrono::DateTime<chrono::Utc>) -> (Vec<String>, Vec<(String, String)>) {
        let mut gone = Vec::new();
        let mut enis = Vec::new();
        for (key, r) in self.regions.iter_mut() {
            for fs in r.file_systems.values_mut() {
                if fs.transition_ends.is_some_and(|t| t <= now) {
                    fs.transition_ends = None;
                    if fs.description.life_cycle_state == "deleting" {
                        gone.push(fs.id().to_string());
                    } else {
                        fs.description.life_cycle_state = "available".into();
                    }
                }
            }
            for id in &gone {
                r.file_systems.remove(id);
                r.access_points.retain(|_, a| a.file_system_id.as_deref() != Some(id.as_str()));
            }
            let mut deleted = Vec::new();
            for (id, m) in r.mount_targets.iter_mut() {
                if m.transition_ends.is_some_and(|t| t <= now) {
                    m.transition_ends = None;
                    if m.description.life_cycle_state == "deleting" {
                        deleted.push(id.clone());
                        enis.extend(m.description.network_interface_id.clone().map(|e| (key.clone(), e)));
                    } else {
                        m.description.life_cycle_state = "available".into();
                    }
                }
            }
            for id in deleted {
                r.mount_targets.remove(&id);
            }
        }
        (gone, enis)
    }
}
