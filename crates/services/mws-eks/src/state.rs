//! Persistent EKS state: per account and Region, the clusters and
//! everything that hangs off them, and EKS Anywhere subscriptions.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct State {
    /// Keyed by `account/region`.
    pub regions: BTreeMap<String, Region>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Region {
    pub clusters: BTreeMap<String, ClusterRec>,
    pub subscriptions: BTreeMap<String, types::EksAnywhereSubscription>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ClusterRec {
    pub cluster: types::Cluster,
    /// Registered through EKS Connector rather than created.
    pub registered: bool,
    /// The cluster security group was created by EKS (and is deleted with
    /// the cluster).
    pub owns_security_group: bool,
    pub nodegroups: BTreeMap<String, NodegroupRec>,
    pub addons: BTreeMap<String, types::Addon>,
    pub fargate_profiles: BTreeMap<String, types::FargateProfile>,
    pub identity_providers: BTreeMap<String, types::OidcIdentityProviderConfig>,
    /// Keyed by principal ARN.
    pub access_entries: BTreeMap<String, AccessEntryRec>,
    /// Keyed by association id.
    pub pod_identities: BTreeMap<String, types::PodIdentityAssociation>,
    pub capabilities: BTreeMap<String, types::Capability>,
    pub certificate_authorities: Vec<CaRec>,
    pub updates: Vec<UpdateRec>,
    pub insights_refresh: Option<InsightsRefresh>,
    /// The Kubernetes API server, when a control plane backend runs one.
    pub control_plane: Option<ControlPlaneRec>,
    /// When each transition in progress finishes on the emulated clock,
    /// keyed by what is moving (`cluster`, `nodegroup/<name>`,
    /// `addon/<name>`, `fargate/<name>`, `idp/<name>`, `capability/<name>`,
    /// `certs`, `insights`). A transition without an entry (state saved by
    /// an older MWS) finishes on the next request.
    pub settle_at: BTreeMap<String, DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ControlPlaneRec {
    /// The backend's name for it (the container).
    pub id: String,
    /// Kubernetes minor version the server runs (or is being moved to).
    pub version: String,
    pub ready: bool,
    /// Why it failed to start.
    pub error: Option<String>,
    /// The cluster creator's principal ARN: in `CONFIG_MAP` and
    /// `API_AND_CONFIG_MAP` clusters, an implicit `system:masters` member.
    pub creator: Option<String>,
    /// Where it was asked to call MWS's webhooks.
    pub webhook_base: String,
    pub service_cidr: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct NodegroupRec {
    pub nodegroup: types::Nodegroup,
    /// The EKS-managed launch template the Auto Scaling group launches.
    pub launch_template_id: Option<String>,
    pub launch_template_version: Option<String>,
    pub instance_profile: Option<String>,
    pub image_id: Option<String>,
    /// Security groups the nodes run in.
    pub security_groups: Vec<String>,
    /// The remote access security group was created by EKS.
    pub owns_remote_access_group: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct AccessEntryRec {
    pub entry: types::AccessEntry,
    /// Keyed by access policy ARN.
    pub policies: BTreeMap<String, types::AssociatedAccessPolicy>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct UpdateRec {
    pub update: types::Update,
    pub nodegroup: Option<String>,
    pub addon: Option<String>,
    pub capability: Option<String>,
    /// When the update finishes on the emulated clock (`None`: on the next
    /// request).
    pub done_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct CaRec {
    pub ca: types::CertificateAuthority,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct InsightsRefresh {
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// How long transitions take on the emulated clock, in seconds. Real EKS
/// takes about ten minutes for a cluster and a few for a node group; these
/// are shorter so SDK waiters finish within a few polls, and advancing
/// `/_mws/clock` skips them; `MWS_ASYNC_DELAY_MS=0` makes them instant.
pub(crate) mod durations {
    pub const CLUSTER_CREATE: i64 = 120;
    pub const CLUSTER_UPDATE: i64 = 60;
    pub const CLUSTER_VERSION_UPDATE: i64 = 120;
    pub const CLUSTER_DELETE: i64 = 60;
    pub const NODEGROUP_CREATE: i64 = 90;
    pub const NODEGROUP_UPDATE: i64 = 60;
    pub const NODEGROUP_DELETE: i64 = 60;
    pub const ADDON: i64 = 30;
    pub const FARGATE_PROFILE: i64 = 60;
    pub const IDENTITY_PROVIDER: i64 = 60;
    pub const CAPABILITY: i64 = 60;
    pub const CERTIFICATE_AUTHORITY: i64 = 30;
    pub const INSIGHTS_REFRESH: i64 = 30;
}

impl ClusterRec {
    /// Start a transition of `key` that lasts `secs` from `now`; returns
    /// when it finishes.
    pub fn begin(&mut self, key: impl Into<String>, now: DateTime<Utc>, secs: i64) -> DateTime<Utc> {
        let at = now + chrono::Duration::milliseconds(mws_core::settle::window_ms(secs * 1000));
        self.settle_at.insert(key.into(), at);
        at
    }

    /// Whether the transition of `key` is over at `now`.
    pub fn due(&self, key: &str, now: DateTime<Utc>) -> bool {
        self.settle_at.get(key).is_none_or(|at| now >= *at)
    }
}

impl State {
    pub fn region(&mut self, account: &str, region: &str) -> &mut Region {
        self.regions.entry(format!("{account}/{region}")).or_default()
    }
}
