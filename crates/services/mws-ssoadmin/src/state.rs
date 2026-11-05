//! IAM Identity Center state: instances and everything configured in them.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

pub type Tags = BTreeMap<String, String>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by instance ARN.
    pub instances: BTreeMap<String, Instance>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceKind {
    /// Enabled in an organization's management account: assigns access to
    /// the organization's accounts.
    #[default]
    Organization,
    /// A standalone or member account's own instance.
    Account,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Instance {
    pub arn: String,
    /// `ssoins-` and sixteen hex digits.
    pub id: String,
    pub kind: InstanceKind,
    pub name: Option<String>,
    pub owner: String,
    pub identity_store_id: String,
    pub created: DateTime<Utc>,
    pub primary_region: String,
    /// Regions besides the primary one, with when they were added.
    pub regions: BTreeMap<String, DateTime<Utc>>,
    pub tags: Tags,
    pub encryption: Option<types::EncryptionConfiguration>,
    pub permission_sets_enabled: bool,
    pub access_control: Option<types::InstanceAccessControlAttributeConfiguration>,
    /// Keyed by permission set ARN.
    pub permission_sets: BTreeMap<String, PermissionSet>,
    pub assignments: BTreeSet<Assignment>,
    /// Where each permission set is provisioned: (permission set ARN,
    /// account) → role.
    #[serde(with = "pairs")]
    pub provisioned: BTreeMap<(String, String), Provisioned>,
    /// Account assignment creation and deletion requests, by request id.
    pub creations: BTreeMap<String, types::AccountAssignmentOperationStatus>,
    pub deletions: BTreeMap<String, types::AccountAssignmentOperationStatus>,
    pub provisionings: BTreeMap<String, types::PermissionSetProvisioningStatus>,
    /// Keyed by application ARN.
    pub applications: BTreeMap<String, Application>,
    /// Keyed by trusted token issuer ARN.
    pub token_issuers: BTreeMap<String, TokenIssuer>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PermissionSet {
    pub arn: String,
    pub name: String,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub session_duration: String,
    pub relay_state: Option<String>,
    pub tags: Tags,
    /// AWS managed policy ARNs, in attachment order.
    pub managed: Vec<String>,
    /// Customer managed policy references: (name, path).
    pub customer_managed: Vec<(String, String)>,
    pub inline: Option<String>,
    pub boundary: Option<types::PermissionsBoundary>,
    /// Bumped by every change ProvisionPermissionSet has to apply.
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Assignment {
    pub account: String,
    pub permission_set: String,
    /// `USER` or `GROUP`.
    pub principal_type: String,
    pub principal_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Provisioned {
    pub role_name: String,
    /// The permission set version the role reflects.
    pub version: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Application {
    pub arn: String,
    pub account: String,
    pub provider: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub portal_options: Option<types::PortalOptions>,
    pub created: DateTime<Utc>,
    pub tags: Tags,
    pub assignment_required: bool,
    /// (principal type, principal id).
    pub assignments: BTreeSet<(String, String)>,
    /// Scope → authorized target application ARNs.
    pub scopes: BTreeMap<String, Vec<String>>,
    /// Authentication method type → method.
    pub auth_methods: BTreeMap<String, types::AuthenticationMethod>,
    /// Grant type → grant.
    pub grants: BTreeMap<String, types::Grant>,
    pub background_sessions: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenIssuer {
    pub arn: String,
    pub name: String,
    pub kind: String,
    pub config: types::OidcJwtConfiguration,
    pub tags: Tags,
}

/// (De)serialize a map with tuple keys as a list of pairs.
mod pairs {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<K: Serialize + Ord, V: Serialize, S: Serializer>(
        map: &BTreeMap<K, V>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let v: Vec<(&K, &V)> = map.iter().collect();
        v.serialize(s)
    }

    pub fn deserialize<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<K, V>, D::Error> {
        let v: Vec<(K, V)> = Vec::deserialize(d)?;
        Ok(v.into_iter().collect())
    }
}
