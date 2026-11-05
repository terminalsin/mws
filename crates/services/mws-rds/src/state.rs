//! RDS state: one [`RegionState`] per account and Region. Resources are kept
//! in their API shapes (the generated types), plus what the API does not
//! show (passwords, backend names, parameter values).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types as t;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `{account}/{region}`.
    pub regions: BTreeMap<String, RegionState>,
    /// Global clusters span Regions; keyed by `{account}/{identifier}`.
    pub global_clusters: BTreeMap<String, GlobalRecord>,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}/{region}")
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionState {
    pub instances: BTreeMap<String, InstanceRecord>,
    pub clusters: BTreeMap<String, ClusterRecord>,
    pub subnet_groups: BTreeMap<String, Tagged<t::DBSubnetGroup>>,
    pub parameter_groups: BTreeMap<String, ParamGroup>,
    pub cluster_parameter_groups: BTreeMap<String, ParamGroup>,
    pub option_groups: BTreeMap<String, Tagged<t::OptionGroup>>,
    pub snapshots: BTreeMap<String, SnapshotRecord>,
    pub cluster_snapshots: BTreeMap<String, ClusterSnapshotRecord>,
    pub cluster_endpoints: BTreeMap<String, Tagged<t::DBClusterEndpoint>>,
    pub event_subscriptions: BTreeMap<String, Tagged<t::EventSubscription>>,
    /// Automated backups kept after their instance was deleted, by
    /// resource id.
    pub retained_backups: BTreeMap<String, t::DBInstanceAutomatedBackup>,
    /// The same for clusters.
    pub retained_cluster_backups: BTreeMap<String, t::DBClusterAutomatedBackup>,
    pub events: Vec<t::Event>,
}

/// A resource whose shape has no tag list of its own.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Tagged<T> {
    pub item: T,
    pub tags: Vec<t::Tag>,
}

/// Where a database really listens, when a backend runs it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Listen {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InstanceRecord {
    pub db: t::DBInstance,
    pub master_password: String,
    /// The backend's name for the database (instances of a cluster use the
    /// cluster's).
    pub backend_name: String,
    pub listen: Option<Listen>,
    /// Bumped on every state change, so a background task finishing late
    /// does not overwrite a newer state.
    pub generation: u64,
    /// The port asked for (`Endpoint.Port` when no backend runs it).
    pub port: i32,
    pub image: String,
    /// Parameter changes wait for a reboot.
    pub pending_reboot: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterRecord {
    pub cluster: t::DBCluster,
    pub master_password: String,
    pub backend_name: String,
    pub listen: Option<Listen>,
    pub generation: u64,
    pub image: String,
    pub pending_reboot: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ParamGroup {
    pub name: String,
    pub family: String,
    pub description: String,
    pub arn: String,
    /// Values set by the user.
    pub values: BTreeMap<String, String>,
    pub tags: Vec<t::Tag>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SnapshotRecord {
    pub snapshot: t::DBSnapshot,
    pub master_password: String,
    pub db_name: Option<String>,
    pub image: String,
    pub db_instance_class: String,
    /// Account ids (or `all`) allowed to restore it.
    pub restore: Vec<String>,
    /// Whether the backend holds data for it.
    pub has_data: bool,
    /// The backend's name for the snapshot data.
    pub backend_name: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterSnapshotRecord {
    pub snapshot: t::DBClusterSnapshot,
    pub master_password: String,
    pub database_name: Option<String>,
    pub image: String,
    pub restore: Vec<String>,
    pub has_data: bool,
    pub backend_name: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalRecord {
    pub global: t::GlobalCluster,
}
