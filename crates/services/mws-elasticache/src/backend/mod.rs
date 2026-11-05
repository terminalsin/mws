//! Engine backends: what actually runs a cache node behind the ElastiCache
//! API.
//!
//! The API contract (clusters, replication groups, shards, users, snapshots,
//! failover) lives in this crate, and MWS drives the engines itself over the
//! Redis protocol (replication, cluster slots, ACLs). A backend only turns
//! "run this node" into something real: [`DockerBackend`] runs each node as
//! a Redis OSS, Valkey or Memcached container; [`MetadataBackend`] runs
//! nothing and keeps ElastiCache a pure control plane.

mod docker;

use std::sync::Arc;

pub use docker::DockerBackend;

/// The engine a node runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    Redis,
    Valkey,
    Memcached,
}

impl EngineKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "redis" => Some(Self::Redis),
            "valkey" => Some(Self::Valkey),
            "memcached" => Some(Self::Memcached),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Redis => "redis",
            Self::Valkey => "valkey",
            Self::Memcached => "memcached",
        }
    }

    /// Redis OSS and Valkey speak the same protocol and replicate the same
    /// way.
    pub fn is_redis_like(self) -> bool {
        !matches!(self, Self::Memcached)
    }
}

/// Everything a backend needs to run one cache node.
#[derive(Debug, Clone)]
pub struct NodeSpec {
    /// Unique node name, `<cache-cluster-id>-<cache-node-id>`.
    pub name: String,
    pub account_id: String,
    pub region: String,
    pub engine: EngineKind,
    /// The ElastiCache engine version (`7.1`, `8.0`, `1.6.22`).
    pub engine_version: String,
    /// Whether the node runs in a cluster-mode-enabled replication group
    /// (it needs an engine that can announce host names).
    pub cluster_mode: bool,
    /// The port the engine listens on. Backends publish it on the host
    /// under the same number, so what the engine announces (cluster
    /// redirects, `CLUSTER SLOTS`) is what clients can reach.
    pub port: u16,
    /// The host address the port is published on.
    pub bind_address: String,
    /// Engine command line arguments (after the server binary).
    pub args: Vec<String>,
    pub memory_mib: u64,
    pub vcpus: u32,
    /// Files to place in the node before it starts (absolute paths), such
    /// as an RDB file to load or TLS certificates.
    pub files: Vec<(String, Vec<u8>)>,
}

/// A running node, as the backend knows it.
#[derive(Debug, Clone)]
pub struct RunningNode {
    /// The backend's own handle (container id).
    pub handle: String,
    /// The address other nodes reach this node at (replication, cluster
    /// bus).
    pub peer_address: String,
}

#[derive(Debug, Clone)]
pub struct BackendError(pub String);

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BackendError {}

/// Runs cache nodes. ElastiCache calls these from background tasks while
/// the API reports `creating`, `modifying`, `rebooting cache cluster nodes`
/// and so on, as AWS does.
#[async_trait::async_trait]
pub trait EngineBackend: Send + Sync {
    /// A short name for logs (`docker`, `metadata`).
    fn name(&self) -> &'static str;

    /// Whether nodes really run (and MWS should talk to them).
    fn runs_engines(&self) -> bool {
        true
    }

    /// Create and start a node.
    async fn launch(&self, spec: &NodeSpec) -> Result<RunningNode, BackendError>;

    /// Restart a node. Its data is lost, as on a rebooted ElastiCache node
    /// without persistence. Returns the node's (possibly new) peer address.
    async fn reboot(&self, handle: &str) -> Result<String, BackendError>;

    /// Destroy a node.
    async fn terminate(&self, handle: &str) -> Result<(), BackendError>;

    /// Destroy several nodes at once.
    async fn terminate_all(&self, handles: &[String]) -> Result<(), BackendError> {
        for h in handles {
            self.terminate(h).await?;
        }
        Ok(())
    }

    /// What the node logged (engine log).
    async fn logs(&self, handle: &str) -> Result<String, BackendError>;
}

/// Runs nothing: caches exist only as ElastiCache metadata and become
/// `available` at once.
#[derive(Debug, Default, Clone)]
pub struct MetadataBackend;

#[async_trait::async_trait]
impl EngineBackend for MetadataBackend {
    fn name(&self) -> &'static str {
        "metadata"
    }
    fn runs_engines(&self) -> bool {
        false
    }
    async fn launch(&self, spec: &NodeSpec) -> Result<RunningNode, BackendError> {
        Ok(RunningNode { handle: spec.name.clone(), peer_address: spec.bind_address.clone() })
    }
    async fn reboot(&self, _handle: &str) -> Result<String, BackendError> {
        Ok(String::new())
    }
    async fn terminate(&self, _handle: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn logs(&self, _handle: &str) -> Result<String, BackendError> {
        Ok(String::new())
    }
}

/// Which backend to use (`MWS_ELASTICACHE_BACKEND`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BackendChoice {
    /// Docker when a daemon answers at startup, metadata only otherwise.
    Auto,
    Docker,
    #[default]
    Metadata,
}

impl BackendChoice {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "auto" => Some(Self::Auto),
            "docker" | "podman" | "container" => Some(Self::Docker),
            "none" | "metadata" | "noop" => Some(Self::Metadata),
            _ => None,
        }
    }

    /// The backend this choice resolves to. `Auto` probes the Docker CLI
    /// (`docker_cli`, default `docker`) once.
    pub fn resolve(&self, docker_cli: Option<&str>) -> Arc<dyn EngineBackend> {
        let docker = || DockerBackend::new(docker_cli.unwrap_or("docker"));
        match self {
            Self::Metadata => Arc::new(MetadataBackend),
            Self::Docker => Arc::new(docker()),
            Self::Auto => {
                let d = docker();
                if d.daemon_available() {
                    Arc::new(d)
                } else {
                    Arc::new(MetadataBackend)
                }
            }
        }
    }
}
