//! ElastiCache state: one [`RegionState`] per account and Region, plus
//! global datastores (which span Regions) per account.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::backend::EngineKind;
use crate::generated::types as t;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub regions: BTreeMap<String, RegionState>,
    /// Global datastores per account, by id.
    pub globals: BTreeMap<String, BTreeMap<String, crate::ops::global::Global>>,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}/{region}")
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionState {
    pub initialized: bool,
    pub clusters: BTreeMap<String, Cluster>,
    pub replication_groups: BTreeMap<String, ReplicationGroup>,
    /// Custom parameter groups (default groups are computed).
    pub parameter_groups: BTreeMap<String, ParameterGroup>,
    pub subnet_groups: BTreeMap<String, t::CacheSubnetGroup>,
    pub snapshots: BTreeMap<String, Snapshot>,
    pub users: BTreeMap<String, User>,
    pub user_groups: BTreeMap<String, t::UserGroup>,
    pub serverless: BTreeMap<String, Serverless>,
    pub serverless_snapshots: BTreeMap<String, ServerlessSnapshot>,
    pub reserved: BTreeMap<String, t::ReservedCacheNode>,
    pub events: Vec<t::Event>,
    /// Tags by resource ARN.
    pub tags: BTreeMap<String, Vec<t::Tag>>,
    /// Service update actions by `<update>/<resource id>`: status and when
    /// it last changed.
    pub update_actions: BTreeMap<String, (String, DateTime<Utc>)>,
}

impl RegionState {
    pub fn event(&mut self, id: &str, source_type: &str, message: impl Into<String>, at: DateTime<Utc>) {
        self.events.push(t::Event {
            source_identifier: Some(id.to_string()),
            source_type: Some(source_type.to_string()),
            message: Some(message.into()),
            date: Some(at),
        });
        // AWS keeps 14 days of events; keep the list bounded.
        if self.events.len() > 5000 {
            self.events.drain(..1000);
        }
    }
}

/// The AUTH token(s) a cluster accepts: rotation keeps the previous one
/// valid until the next change.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AuthTokens {
    pub current: Option<String>,
    pub previous: Option<String>,
}

impl AuthTokens {
    pub fn enabled(&self) -> bool {
        self.current.is_some()
    }
}

/// What a backend runs for one cache node.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeRuntime {
    pub handle: Option<String>,
    /// The engine's port (published on the host under the same number).
    pub port: u16,
    /// Where other nodes reach it.
    pub peer: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Cluster {
    /// What DescribeCacheClusters returns (with node info).
    pub info: t::CacheCluster,
    pub engine: Option<EngineKind>,
    pub port: u16,
    pub auth: AuthTokens,
    /// Password of the internal ACL user MWS manages the engine as.
    pub internal_password: Option<String>,
    /// Runtime of each cache node, by cache node id (`0001`).
    pub nodes: BTreeMap<String, NodeRuntime>,
    /// For members of a replication group: the shard (`0001`).
    pub node_group_id: Option<String>,
    /// `primary` or `replica` within its shard.
    pub role: Option<String>,
    /// Snapshot to seed from at creation.
    pub seed_snapshot: Option<String>,
    /// RDB files from S3 to seed from at creation.
    pub seed_rdb: Option<Vec<String>>,
}

impl Cluster {
    pub fn id(&self) -> &str {
        self.info.cache_cluster_id.as_deref().unwrap_or_default()
    }
    pub fn status(&self) -> &str {
        self.info.cache_cluster_status.as_deref().unwrap_or_default()
    }
    pub fn set_status(&mut self, s: &str) {
        self.info.cache_cluster_status = Some(s.to_string());
        for n in self.info.cache_nodes.iter_mut().flatten() {
            n.cache_node_status = Some(if s == "available" || s == "modifying" || s == "snapshotting" {
                "available".to_string()
            } else {
                s.to_string()
            });
        }
    }
    pub fn engine(&self) -> EngineKind {
        self.engine.unwrap_or(EngineKind::Redis)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationGroup {
    pub info: t::ReplicationGroup,
    pub engine_version: String,
    pub parameter_group: String,
    pub subnet_group: Option<String>,
    pub port: u16,
    pub auth: AuthTokens,
    pub internal_password: Option<String>,
    /// Ports of the primary and reader endpoint proxies (cluster mode
    /// disabled), or the configuration endpoint's (cluster mode enabled).
    pub primary_port: u16,
    pub reader_port: u16,
    /// Shard slot ranges by node group id.
    pub slots: BTreeMap<String, String>,
    /// Online migration from a self-managed endpoint.
    pub migration: Option<(String, u16)>,
}

impl ReplicationGroup {
    pub fn id(&self) -> &str {
        self.info.replication_group_id.as_deref().unwrap_or_default()
    }
    pub fn status(&self) -> &str {
        self.info.status.as_deref().unwrap_or_default()
    }
    pub fn cluster_enabled(&self) -> bool {
        self.info.cluster_enabled == Some(true)
    }
    pub fn engine(&self) -> EngineKind {
        self.info.engine.as_deref().and_then(EngineKind::parse).unwrap_or(EngineKind::Redis)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ParameterGroup {
    pub info: t::CacheParameterGroup,
    /// Values changed from the family's defaults.
    pub values: BTreeMap<String, String>,
}

/// One key of a snapshot: its database, name, `DUMP` payload and
/// remaining time to live (ms, 0 for none).
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Entry {
    pub db: u32,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
    #[serde(with = "b64")]
    pub dump: Vec<u8>,
    pub pttl: i64,
}

/// The data of a snapshot: the keys of each shard.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SnapshotData {
    pub shards: Vec<Vec<Entry>>,
}

impl SnapshotData {
    pub fn size_bytes(&self) -> u64 {
        self.shards.iter().flatten().map(|e| (e.key.len() + e.dump.len()) as u64).sum()
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub info: t::Snapshot,
    pub data: SnapshotData,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    pub info: t::User,
    pub passwords: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Serverless {
    pub info: t::ServerlessCache,
    pub node: NodeRuntime,
    pub reader_port: u16,
    pub internal_password: Option<String>,
    pub seed_snapshot: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerlessSnapshot {
    pub info: t::ServerlessCacheSnapshot,
    pub data: SnapshotData,
}

mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
