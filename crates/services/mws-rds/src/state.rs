//! RDS state: one [`RegionState`] per account and Region. Resources are kept
//! in their API shapes (the generated types), plus what the API does not
//! show (passwords, backend names, parameter values).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
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
    /// A deleted database's last data and transaction log, kept with its
    /// retained automated backup (by resource id): the backend snapshot
    /// name and when it was taken (wall clock).
    pub retained_logs: BTreeMap<String, RetainedLog>,
    pub events: Vec<t::Event>,
    pub proxies: BTreeMap<String, ProxyRecord>,
    /// Custom proxy endpoints, by name.
    pub proxy_endpoints: BTreeMap<String, Tagged<t::DBProxyEndpoint>>,
    /// Blue/Green deployments, by identifier.
    pub blue_green: BTreeMap<String, t::BlueGreenDeployment>,
    /// Reserved DB instances, by reservation id.
    pub reserved: BTreeMap<String, Tagged<t::ReservedDBInstance>>,
    /// Snapshot exports to S3, by identifier.
    pub export_tasks: BTreeMap<String, t::ExportTask>,
    /// Aurora MySQL backtracks, by cluster identifier (oldest first).
    pub backtracks: BTreeMap<String, Vec<t::DBClusterBacktrack>>,
    /// Aurora Limitless shard groups, by identifier.
    pub shard_groups: BTreeMap<String, t::DBShardGroup>,
    /// Zero-ETL integrations, by name.
    pub integrations: BTreeMap<String, t::Integration>,
    /// DB capacity reservations, by identifier.
    pub capacity_reservations: BTreeMap<String, t::DBCapacityReservation>,
    /// Custom engine versions (RDS Custom), by (engine, version).
    pub custom_engine_versions: BTreeMap<String, t::DBEngineVersion>,
    /// Automated backups replicated into this Region, by source resource id.
    pub replicated_backups: BTreeMap<String, t::DBInstanceAutomatedBackup>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyRecord {
    pub proxy: t::DBProxy,
    pub tags: Vec<t::Tag>,
    pub target_group: t::DBProxyTargetGroup,
    /// Registered targets: DB instance or cluster identifiers.
    pub instances: Vec<String>,
    pub clusters: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetainedLog {
    pub backend_name: String,
    pub data_time: Option<DateTime<Utc>>,
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
    /// When the oldest change in `PendingModifiedValues` was requested
    /// (emulated clock); they are applied in the first maintenance window
    /// after it.
    pub pending_since: Option<DateTime<Utc>>,
    /// The last storage change is optimized until then (emulated clock):
    /// the instance shows `storage-optimization` and refuses further
    /// storage changes.
    pub storage_optimized_until: Option<DateTime<Utc>>,
    /// `ApplyPendingMaintenanceAction` opt-in for the pending engine
    /// upgrade (`next-maintenance`).
    pub maintenance_opt_in: Option<String>,
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
    /// As for instances: when the pending changes were requested.
    pub pending_since: Option<DateTime<Utc>>,
    pub maintenance_opt_in: Option<String>,
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
    /// Wall-clock time the data was copied (a point-in-time restore
    /// replays the log from here).
    pub data_time: Option<DateTime<Utc>>,
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
    pub data_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalRecord {
    pub global: t::GlobalCluster,
}
