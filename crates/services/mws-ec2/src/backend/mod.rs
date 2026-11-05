//! Compute backends: what actually runs an instance behind the EC2 API.
//!
//! The EC2 API contract (state machine, networking, metadata) lives in this
//! crate; a [`ComputeBackend`] only turns "launch / stop / start / reboot /
//! terminate this instance" into something real. [`DockerBackend`] runs each
//! instance as a container (any Docker-compatible CLI works, so Podman
//! too); [`MetadataBackend`] runs nothing and keeps EC2 a pure control plane,
//! for machines without a container runtime.

mod docker;

use std::sync::Arc;

pub use docker::{DockerBackend, DEFAULT_NETFILTER_IMAGE};

/// The VPC network an instance joins. Backends that isolate networks give
/// each VPC its own.
#[derive(Debug, Clone)]
pub struct NetworkSpec {
    pub vpc_id: String,
    /// The VPC's primary IPv4 CIDR block.
    pub cidr_block: String,
}

/// Everything a backend needs to run one instance.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub instance_id: String,
    pub account_id: String,
    pub region: String,
    /// The image to run (a container image reference for Docker).
    pub image: String,
    /// Whether the image is a plain OS image MWS boots itself (running user
    /// data, installing the key pair, then idling), rather than an image
    /// with its own entrypoint that should run as is.
    pub boot: bool,
    pub network: NetworkSpec,
    pub private_ip: String,
    pub hostname: String,
    pub instance_type: String,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub user_data: Option<Vec<u8>>,
    /// The key pair's public key, in OpenSSH `authorized_keys` form.
    pub ssh_public_key: Option<String>,
    /// Environment for the instance (SDK endpoint, Region, IMDS endpoint).
    pub env: Vec<(String, String)>,
}

/// An IP protocol (and ports) a filter rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    All,
    /// TCP to a destination port range.
    Tcp(u16, u16),
    Udp(u16, u16),
    /// ICMP of a type (and code); `None` matches any.
    Icmp(Option<u8>, Option<u8>),
    /// Any other IP protocol number.
    Number(u8),
}

/// A security group rule, flattened: traffic of `protocol` from (ingress)
/// or to (egress) `cidr` is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllowRule {
    pub protocol: Protocol,
    pub cidr: String,
}

/// A network ACL entry, in rule number order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AclRule {
    pub protocol: Protocol,
    pub cidr: String,
    pub allow: bool,
}

/// Whether traffic leaving the VPC for `cidr` has somewhere to go (a route
/// to an internet gateway with a public address, a working NAT gateway, a
/// gateway endpoint), by longest prefix first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteRule {
    pub cidr: String,
    pub reachable: bool,
}

/// What may reach an instance and what it may reach, as EC2 decides it:
/// its security groups (stateful), its subnet's network ACL (stateless,
/// for traffic crossing the subnet boundary) and its subnet's route table
/// (for traffic leaving the VPC). MWS itself (the AWS APIs and instance
/// metadata) and DNS stay reachable, as the metadata service and the
/// Amazon DNS server are in EC2.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Firewall {
    pub subnet_cidr: String,
    pub vpc_cidrs: Vec<String>,
    pub ingress: Vec<AllowRule>,
    pub egress: Vec<AllowRule>,
    pub acl_ingress: Vec<AclRule>,
    pub acl_egress: Vec<AclRule>,
    pub routes: Vec<RouteRule>,
    /// The TCP port MWS serves on (always reachable on the host).
    pub service_port: Option<u16>,
}

/// A running instance, as the backend knows it.
#[derive(Debug, Clone)]
pub struct Launched {
    /// The backend's own handle (container id).
    pub handle: String,
}

#[derive(Debug, Clone)]
pub struct BackendError(pub String);

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BackendError {}

/// Runs instances. Every method may take a while (pulling an image); EC2
/// calls them from background tasks while the API reports `pending`,
/// `stopping` and so on, as AWS does.
#[async_trait::async_trait]
pub trait ComputeBackend: Send + Sync {
    /// A short name for logs and `/_mws` (`docker`, `metadata`).
    fn name(&self) -> &'static str;

    /// Create and boot an instance.
    async fn launch(&self, spec: &LaunchSpec) -> Result<Launched, BackendError>;

    /// Boot a stopped instance again.
    async fn start(&self, handle: &str) -> Result<(), BackendError>;

    /// Shut an instance down, keeping its disk. `force` skips a graceful
    /// shutdown.
    async fn stop(&self, handle: &str, force: bool) -> Result<(), BackendError>;

    async fn reboot(&self, handle: &str) -> Result<(), BackendError>;

    /// Destroy an instance and its disk.
    async fn terminate(&self, handle: &str) -> Result<(), BackendError>;

    /// What the instance wrote to its console.
    async fn console_output(&self, handle: &str) -> Result<String, BackendError>;

    /// Capture an instance's disk as a new image named `image_ref`, and
    /// return the reference to launch it by.
    async fn create_image(&self, handle: &str, image_ref: &str) -> Result<String, BackendError>;

    /// Remove an image made by [`ComputeBackend::create_image`].
    async fn delete_image(&self, image_ref: &str) -> Result<(), BackendError>;

    /// Tear down the network of a deleted VPC, if the backend made one.
    async fn delete_network(&self, vpc_id: &str) -> Result<(), BackendError>;

    /// Whether instances have real network traffic for
    /// [`ComputeBackend::apply_firewall`] to filter.
    fn filters_traffic(&self) -> bool {
        false
    }

    /// Make an instance's traffic follow `firewall`, replacing what an
    /// earlier call set.
    async fn apply_firewall(&self, _handle: &str, _firewall: &Firewall) -> Result<(), BackendError> {
        Ok(())
    }

    /// Tell a booting instance its network is set up (it waits for this
    /// before running user data).
    async fn network_ready(&self, _handle: &str) -> Result<(), BackendError> {
        Ok(())
    }
}

/// Runs nothing: instances exist only as EC2 metadata and move through
/// their states at once.
#[derive(Debug, Default, Clone)]
pub struct MetadataBackend;

#[async_trait::async_trait]
impl ComputeBackend for MetadataBackend {
    fn name(&self) -> &'static str {
        "metadata"
    }
    async fn launch(&self, spec: &LaunchSpec) -> Result<Launched, BackendError> {
        Ok(Launched { handle: spec.instance_id.clone() })
    }
    async fn start(&self, _handle: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn stop(&self, _handle: &str, _force: bool) -> Result<(), BackendError> {
        Ok(())
    }
    async fn reboot(&self, _handle: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn terminate(&self, _handle: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn console_output(&self, _handle: &str) -> Result<String, BackendError> {
        Ok(String::new())
    }
    async fn create_image(&self, _handle: &str, image_ref: &str) -> Result<String, BackendError> {
        Ok(image_ref.to_string())
    }
    async fn delete_image(&self, _image_ref: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn delete_network(&self, _vpc_id: &str) -> Result<(), BackendError> {
        Ok(())
    }
}

/// Which backend to use (`MWS_EC2_BACKEND`).
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
    pub fn resolve(&self, docker_cli: Option<&str>) -> Arc<dyn ComputeBackend> {
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
