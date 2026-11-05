//! Kubernetes control planes behind EKS clusters.
//!
//! The EKS API contract lives in this crate; a [`ControlPlane`] only runs
//! "a Kubernetes API server for this cluster". [`K3s`] runs each cluster's
//! API server as a k3s container (server only, no agent), publishes it on
//! the host and points its token and authorization webhooks back at MWS,
//! which answers them from the cluster's access entries, as EKS does.

mod k3s;
pub(crate) mod nodes;
pub(crate) mod webhook;

use std::collections::BTreeMap;
use std::sync::Arc;

pub use k3s::K3s;

/// What a control plane needs to run one cluster's API server.
#[derive(Debug, Clone)]
pub struct ControlPlaneSpec {
    /// Unique and stable for the cluster's life (the container's name).
    pub id: String,
    pub cluster_arn: String,
    /// Kubernetes minor version (`1.34`).
    pub version: String,
    /// The cluster's service IPv4 CIDR.
    pub service_cidr: String,
    /// The URL MWS answers the API server's token review webhook on, as the
    /// API server sees it.
    pub authenticate_url: String,
    /// The URL of the subject access review (authorization) webhook.
    pub authorize_url: String,
}

/// Where a running API server listens, and the CA that signs its serving
/// certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    /// `https://127.0.0.1:<port>`.
    pub endpoint: String,
    /// PEM.
    pub ca_pem: String,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneError(pub String);

impl std::fmt::Display for ControlPlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ControlPlaneError {}

/// A node the control plane should list: a node group's EC2 instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeObject {
    /// The instance's private DNS name.
    pub name: String,
    pub provider_id: String,
    pub labels: BTreeMap<String, String>,
    /// `(key, value, effect)` in Kubernetes form (`NoSchedule`).
    pub taints: Vec<(String, Option<String>, String)>,
    pub internal_ip: String,
    pub kubelet_version: String,
    pub cpu: String,
    pub memory: String,
    pub pods: String,
}

/// Runs Kubernetes API servers. Every method may take a while (pulling an
/// image, waiting for the server to answer); EKS calls them from
/// background tasks while the API reports `CREATING` or `UPDATING`.
#[async_trait::async_trait]
pub trait ControlPlane: Send + Sync {
    /// A short name for logs (`k3s`).
    fn name(&self) -> &'static str;

    /// Start (or, when it already runs, find) the API server and wait until
    /// it is ready.
    async fn ensure(&self, spec: &ControlPlaneSpec) -> Result<Running, ControlPlaneError>;

    /// Restart the API server at `spec.version`, keeping its data.
    async fn upgrade(&self, spec: &ControlPlaneSpec) -> Result<Running, ControlPlaneError>;

    /// Stop the API server and remove its data.
    async fn delete(&self, id: &str);

    /// Make the nodes labelled with node group `nodegroup` exactly `nodes`.
    async fn sync_nodes(&self, id: &str, nodegroup: &str, nodes: &[NodeObject]) -> Result<(), ControlPlaneError>;
}

/// Which control plane to run (`MWS_EKS_BACKEND`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BackendChoice {
    /// k3s when a Docker daemon answers at startup, none otherwise.
    Auto,
    K3s,
    /// No API server: clusters are EKS metadata only.
    #[default]
    Metadata,
}

impl BackendChoice {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "auto" => Some(Self::Auto),
            "k3s" | "docker" => Some(Self::K3s),
            "none" | "metadata" | "noop" => Some(Self::Metadata),
            _ => None,
        }
    }

    /// The control plane this choice resolves to. `Auto` probes the Docker
    /// CLI once. `bind` is the host address API servers are published on.
    pub fn resolve(&self, docker_cli: Option<&str>, bind: Option<&str>) -> Option<Arc<dyn ControlPlane>> {
        let k3s = || K3s::new(docker_cli.unwrap_or("docker"), bind.unwrap_or("127.0.0.1"));
        match self {
            Self::Metadata => None,
            Self::K3s => Some(Arc::new(k3s())),
            Self::Auto => {
                let k = k3s();
                k.daemon_available().then(|| Arc::new(k) as Arc<dyn ControlPlane>)
            }
        }
    }
}

/// The k3s image for a Kubernetes minor version.
pub(crate) fn k3s_image(version: &str) -> String {
    if let Ok(template) = std::env::var("MWS_EKS_K3S_IMAGE") {
        if !template.is_empty() {
            return template.replace("{version}", version);
        }
    }
    let tag = match version {
        "1.28" => "v1.28.15-k3s1",
        "1.29" => "v1.29.15-k3s1",
        "1.30" => "v1.30.14-k3s2",
        "1.31" => "v1.31.14-k3s1",
        "1.32" => "v1.32.13-k3s1",
        "1.33" => "v1.33.13-k3s2",
        "1.35" => "v1.35.10-k3s1",
        _ => "v1.34.13-k3s1",
    };
    format!("rancher/k3s:{tag}")
}
