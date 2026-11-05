//! Database backends: what actually runs a DB instance or cluster behind
//! the RDS API.
//!
//! The RDS API contract (states, endpoints, parameter groups, snapshots,
//! events) lives in this crate; a [`DatabaseBackend`] only turns "create /
//! start / stop / delete / snapshot this database" into something real.
//! [`DockerBackend`] runs each database as a PostgreSQL, MySQL or MariaDB
//! container you can connect to; [`MetadataBackend`] runs nothing and keeps
//! RDS a pure control plane.

mod docker;

use std::sync::Arc;

pub use crate::catalog::Kind;
pub use docker::DockerBackend;

/// Everything a backend needs to run one database (a DB instance, or an
/// Aurora cluster's shared storage and writer).
#[derive(Debug, Clone)]
pub struct DatabaseSpec {
    /// Unique and stable for the database's life (the lower-cased
    /// resource id).
    pub name: String,
    pub account_id: String,
    pub region: String,
    /// The RDS identifier, for labels and logs.
    pub identifier: String,
    pub engine: String,
    pub kind: Kind,
    /// Container image to run (`postgres:16-alpine`, `mysql:8.0`, ...).
    pub image: String,
    pub master_username: String,
    pub master_password: String,
    pub database_name: Option<String>,
    /// Server settings from the parameter groups (`name`, `value`).
    pub parameters: Vec<(String, String)>,
    pub memory_mib: u64,
}

/// Where a running database listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listening {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct BackendError(pub String);

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BackendError {}

/// Where a point-in-time recovery reads the transaction log (PostgreSQL's
/// archived WAL, MySQL's binary log) from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    /// A database that exists (by its backend name).
    Database(String),
    /// A snapshot holding a deleted database's last data and log.
    Snapshot(String),
}

/// One table's contents, read from a snapshot for an export.
#[derive(Debug, Clone, Default)]
pub struct TableData {
    pub database: String,
    /// The PostgreSQL schema; MySQL has none (the database).
    pub schema: Option<String>,
    pub table: String,
    /// Column names and their SQL types, in order.
    pub columns: Vec<(String, String)>,
    /// Each row as a JSON object (column name to value).
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
}

/// Runs databases. Every method may take a while (pulling an image,
/// initializing a data directory); RDS calls them from background tasks
/// while the API reports `creating`, `stopping` and so on, as AWS does.
#[async_trait::async_trait]
pub trait DatabaseBackend: Send + Sync {
    /// A short name for logs (`docker`, `metadata`).
    fn name(&self) -> &'static str;

    /// Whether databases really run (and so have their own endpoints).
    /// When `false`, RDS reports AWS-style endpoint names.
    fn runs_databases(&self) -> bool;

    /// Create a database and wait until it accepts connections. With
    /// `from_snapshot`, its data starts as a copy of that snapshot (and the
    /// master credentials are the snapshot's).
    async fn create(&self, spec: &DatabaseSpec, from_snapshot: Option<&str>) -> Result<Listening, BackendError>;

    /// Start a stopped (or rebooting) database with `spec`'s settings,
    /// keeping its data.
    async fn start(&self, spec: &DatabaseSpec) -> Result<Listening, BackendError>;

    /// Stop a database, keeping its data.
    async fn stop(&self, name: &str) -> Result<(), BackendError>;

    /// Destroy a database and its data.
    async fn delete(&self, name: &str) -> Result<(), BackendError>;

    /// Copy a database's data into snapshot `snapshot`.
    async fn snapshot(&self, name: &str, snapshot: &str) -> Result<(), BackendError>;

    /// Copy snapshot `source` to a new snapshot `target`.
    async fn copy_snapshot(&self, source: &str, target: &str) -> Result<(), BackendError>;

    async fn delete_snapshot(&self, snapshot: &str) -> Result<(), BackendError>;

    /// Change the master user's password (`spec` carries the new one,
    /// `old_password` the current one).
    async fn set_master_password(&self, spec: &DatabaseSpec, old_password: &str) -> Result<(), BackendError>;

    /// What the database server logged.
    async fn logs(&self, name: &str) -> Result<String, BackendError>;

    /// Make everything the database committed so far readable from its
    /// transaction log (archive the current WAL segment, rotate the binary
    /// log), so a recovery can replay up to now.
    async fn seal_log(&self, _spec: &DatabaseSpec) -> Result<(), BackendError> {
        Ok(())
    }

    /// Build snapshot `target`: snapshot `base`'s data rolled forward with
    /// the transaction log in `log` up to `until` (wall clock), its master
    /// password set to `spec`'s. `spec` describes the source database.
    /// Read every user table out of snapshot `snapshot`, which holds a
    /// database run as `spec` (whose `name` is free to use meanwhile).
    async fn export_tables(&self, _spec: &DatabaseSpec, _snapshot: &str) -> Result<Vec<TableData>, BackendError> {
        Ok(Vec::new())
    }

    async fn recover(
        &self,
        _spec: &DatabaseSpec,
        _base: &str,
        _log: &LogSource,
        _target: &str,
        _until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BackendError> {
        Ok(())
    }
}

/// Runs nothing: databases exist only as RDS metadata and move through
/// their states at once.
#[derive(Debug, Default, Clone)]
pub struct MetadataBackend;

#[async_trait::async_trait]
impl DatabaseBackend for MetadataBackend {
    fn name(&self) -> &'static str {
        "metadata"
    }
    fn runs_databases(&self) -> bool {
        false
    }
    async fn create(&self, _spec: &DatabaseSpec, _from: Option<&str>) -> Result<Listening, BackendError> {
        Ok(Listening { host: String::new(), port: 0 })
    }
    async fn start(&self, _spec: &DatabaseSpec) -> Result<Listening, BackendError> {
        Ok(Listening { host: String::new(), port: 0 })
    }
    async fn stop(&self, _name: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn delete(&self, _name: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn snapshot(&self, _name: &str, _snapshot: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn copy_snapshot(&self, _source: &str, _target: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn delete_snapshot(&self, _snapshot: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn set_master_password(&self, _spec: &DatabaseSpec, _old: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn logs(&self, _name: &str) -> Result<String, BackendError> {
        Ok(String::new())
    }
}

/// Which backend to use (`MWS_RDS_BACKEND`).
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
    /// once. `bind` is the host address database ports are published on
    /// (`127.0.0.1` when `None`).
    pub fn resolve(&self, docker_cli: Option<&str>, bind: Option<&str>) -> Arc<dyn DatabaseBackend> {
        let docker = || DockerBackend::new(docker_cli.unwrap_or("docker"), bind.unwrap_or("127.0.0.1"));
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
