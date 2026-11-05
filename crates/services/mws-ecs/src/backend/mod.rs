//! Container backends: what actually runs a task's containers behind the
//! ECS API.
//!
//! The ECS contract (task lifecycle, scheduling, deployments) lives in this
//! crate; a [`ContainerBackend`] only turns "prepare this task, start this
//! container, wait for it, stop it" into something real. [`DockerBackend`]
//! runs each container with the Docker CLI (Podman works too);
//! [`MetadataBackend`] runs nothing, so ECS stays a pure control plane on
//! machines without a container runtime.

mod docker;

use std::sync::Arc;

pub use docker::DockerBackend;

/// How a task is networked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskNetwork {
    /// `awsvpc`: the task's containers share one network namespace with
    /// the address of the task's network interface, on the VPC's network.
    Awsvpc { vpc_id: String, vpc_cidr: String, ip: String },
    /// `bridge`: each container on a network of the task's own, reachable
    /// by the other containers under its name, with port mappings
    /// published on the host.
    Bridge,
    /// `host`: the host's network.
    Host,
    /// `none`: no networking.
    None,
}

#[derive(Debug, Clone)]
pub struct PortSpec {
    pub container_port: i32,
    /// `0` asks for a dynamic host port.
    pub host_port: i32,
    pub protocol: String,
}

/// A host path or a task volume mounted into a container.
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// A host path (`host.sourcePath`) or a task volume's name.
    pub source: String,
    pub host_path: bool,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct HealthCheckSpec {
    /// `["CMD-SHELL", "..."]` or `["CMD", ...]`.
    pub command: Vec<String>,
    pub interval: i32,
    pub timeout: i32,
    pub retries: i32,
    pub start_period: i32,
}

/// One container to start.
#[derive(Debug, Clone, Default)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub entry_point: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    pub env: Vec<(String, String)>,
    pub working_directory: Option<String>,
    pub user: Option<String>,
    pub ports: Vec<PortSpec>,
    pub mounts: Vec<MountSpec>,
    /// Containers of the same task whose volumes this one mounts.
    pub volumes_from: Vec<(String, bool)>,
    pub links: Vec<String>,
    pub cpu: i32,
    /// Hard limit in MiB.
    pub memory: Option<i32>,
    pub memory_reservation: Option<i32>,
    pub privileged: bool,
    pub read_only_root: bool,
    pub hostname: Option<String>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub extra_hosts: Vec<(String, String)>,
    pub labels: Vec<(String, String)>,
    pub ulimits: Vec<(String, i32, i32)>,
    pub init: bool,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub sysctls: Vec<(String, String)>,
    pub tmpfs: Vec<(String, i32, Vec<String>)>,
    pub shared_memory_mib: Option<i32>,
    pub interactive: bool,
    pub tty: bool,
    pub stop_timeout: i32,
    pub health_check: Option<HealthCheckSpec>,
}

/// Everything a backend needs to know about a task.
#[derive(Debug, Clone)]
pub struct TaskSpec {
    pub task_id: String,
    pub task_arn: String,
    pub cluster: String,
    pub family: String,
    pub revision: i32,
    pub account_id: String,
    pub region: String,
    pub network: TaskNetwork,
    /// Task volumes without a host path, which the backend makes per task.
    pub volumes: Vec<String>,
    pub pid_mode: Option<String>,
    pub ipc_mode: Option<String>,
}

/// A started container.
#[derive(Debug, Clone, Default)]
pub struct StartedContainer {
    pub runtime_id: String,
    /// `(container port, host port, protocol, bind address)` as published.
    pub bindings: Vec<(i32, i32, String, String)>,
    pub image_digest: Option<String>,
}

/// A log line a container wrote.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub timestamp_ms: i64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct BackendError(pub String);

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BackendError {}

/// Runs task containers. ECS calls these from background tasks while the
/// API reports `PROVISIONING`, `PENDING`, `RUNNING`, `STOPPING` and so on,
/// as AWS does.
#[async_trait::async_trait]
pub trait ContainerBackend: Send + Sync {
    /// A short name for logs (`docker`, `metadata`).
    fn name(&self) -> &'static str;

    /// Pull an image; returns its digest when known.
    async fn pull(&self, image: &str) -> Result<Option<String>, BackendError>;

    /// Set up what the task's containers share (network, volumes) and
    /// return a handle for it.
    async fn prepare(&self, task: &TaskSpec) -> Result<String, BackendError>;

    async fn start(
        &self,
        task: &TaskSpec,
        handle: &str,
        container: &ContainerSpec,
    ) -> Result<StartedContainer, BackendError>;

    /// Wait for a container to exit and return its exit code. Backends
    /// that run nothing never return.
    async fn wait(&self, runtime_id: &str) -> Result<i32, BackendError>;

    /// The container's health (`HEALTHY`, `UNHEALTHY` or `UNKNOWN`).
    async fn health(&self, runtime_id: &str) -> String;

    /// Stop a container, killing it after `timeout_secs`.
    async fn stop(&self, runtime_id: &str, timeout_secs: i32) -> Result<(), BackendError>;

    /// Follow what a container writes to stdout and stderr, until it exits.
    async fn follow_logs(&self, runtime_id: &str) -> Option<tokio::sync::mpsc::Receiver<LogLine>>;

    /// Run a command in a container (`ExecuteCommand`).
    async fn exec(&self, runtime_id: &str, command: &str) -> Result<String, BackendError>;

    /// Remove the task's containers and what [`ContainerBackend::prepare`]
    /// made.
    async fn cleanup(&self, task: &TaskSpec, handle: &str, runtime_ids: &[String]);
}

/// Runs nothing: tasks exist only as ECS metadata, reach `RUNNING` at
/// once and stop when told to.
#[derive(Debug, Default, Clone)]
pub struct MetadataBackend;

#[async_trait::async_trait]
impl ContainerBackend for MetadataBackend {
    fn name(&self) -> &'static str {
        "metadata"
    }
    async fn pull(&self, _image: &str) -> Result<Option<String>, BackendError> {
        Ok(None)
    }
    async fn prepare(&self, task: &TaskSpec) -> Result<String, BackendError> {
        Ok(task.task_id.clone())
    }
    async fn start(
        &self,
        task: &TaskSpec,
        _handle: &str,
        container: &ContainerSpec,
    ) -> Result<StartedContainer, BackendError> {
        let bindings = match task.network {
            TaskNetwork::Bridge | TaskNetwork::Host => container
                .ports
                .iter()
                .map(|p| {
                    let host = if p.host_port == 0 { 32768 + (p.container_port % 28000) } else { p.host_port };
                    (p.container_port, host, p.protocol.clone(), "0.0.0.0".to_string())
                })
                .collect(),
            _ => Vec::new(),
        };
        Ok(StartedContainer {
            runtime_id: format!("{}-{}", task.task_id, container.name),
            bindings,
            image_digest: None,
        })
    }
    async fn wait(&self, _runtime_id: &str) -> Result<i32, BackendError> {
        std::future::pending().await
    }
    async fn health(&self, _runtime_id: &str) -> String {
        "HEALTHY".into()
    }
    async fn stop(&self, _runtime_id: &str, _timeout_secs: i32) -> Result<(), BackendError> {
        Ok(())
    }
    async fn follow_logs(&self, _runtime_id: &str) -> Option<tokio::sync::mpsc::Receiver<LogLine>> {
        None
    }
    async fn exec(&self, _runtime_id: &str, _command: &str) -> Result<String, BackendError> {
        Ok(String::new())
    }
    async fn cleanup(&self, _task: &TaskSpec, _handle: &str, _runtime_ids: &[String]) {}
}

/// Which backend to use (`MWS_ECS_BACKEND`).
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
    pub fn resolve(&self, docker_cli: Option<&str>) -> Arc<dyn ContainerBackend> {
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
