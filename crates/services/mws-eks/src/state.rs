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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct NodegroupRec {
    pub nodegroup: types::Nodegroup,
    /// The node instances, in launch order.
    pub instances: Vec<String>,
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

impl State {
    pub fn region(&mut self, account: &str, region: &str) -> &mut Region {
        self.regions.entry(format!("{account}/{region}")).or_default()
    }
}
