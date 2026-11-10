//! Parameter Store state: a [`Region`] per account and Region, keyed
//! `"{account}/{region}"`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One parameter policy as stored: its JSON text, type and status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredPolicy {
    pub text: String,
    pub policy_type: String,
    pub status: String,
}

/// One version of a parameter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Version {
    pub version: i64,
    /// The name as written by the `PutParameter` that made this version.
    pub name: String,
    /// `String`, `StringList` or `SecureString`.
    pub param_type: String,
    /// Plain text, or for `SecureString` the encrypted value as base64.
    pub value: String,
    pub key_id: Option<String>,
    pub description: Option<String>,
    pub allowed_pattern: Option<String>,
    /// `Standard` or `Advanced`.
    pub tier: String,
    pub policies: Vec<StoredPolicy>,
    pub data_type: String,
    pub labels: Vec<String>,
    pub last_modified_date: DateTime<Utc>,
    pub last_modified_user: String,
}

/// A resource policy attached to a parameter (sharing with other accounts).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourcePolicy {
    pub id: String,
    pub hash: String,
    pub policy: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Parameter {
    /// Oldest first; at most 100.
    pub versions: Vec<Version>,
    pub tags: BTreeMap<String, String>,
    pub resource_policies: Vec<ResourcePolicy>,
}

impl Parameter {
    pub fn latest(&self) -> &Version {
        self.versions.last().expect("parameters always have a version")
    }

    pub fn version(&self, v: i64) -> Option<&Version> {
        self.versions.iter().find(|x| x.version == v)
    }

    pub fn labelled(&self, label: &str) -> Option<&Version> {
        self.versions.iter().find(|x| x.labels.iter().any(|l| l == label))
    }

    /// The merged resource policy document, if any.
    pub fn policy_document(&self) -> Option<String> {
        match self.resource_policies.len() {
            0 => None,
            1 => Some(self.resource_policies[0].policy.clone()),
            _ => {
                let mut statements = Vec::new();
                for p in &self.resource_policies {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&p.policy) {
                        match v.get("Statement") {
                            Some(serde_json::Value::Array(a)) => statements.extend(a.iter().cloned()),
                            Some(s) => statements.push(s.clone()),
                            None => {}
                        }
                    }
                }
                Some(serde_json::json!({"Version": "2012-10-17", "Statement": statements}).to_string())
            }
        }
    }
}

/// A service setting the caller changed from its default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Setting {
    pub value: String,
    pub last_modified_date: Option<DateTime<Utc>>,
    pub last_modified_user: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Region {
    /// By normalized name (see [`crate::names::key`]).
    pub parameters: BTreeMap<String, Parameter>,
    /// Customized service settings, by setting id.
    pub settings: BTreeMap<String, Setting>,
    /// Documents the account owns, by name.
    pub documents: BTreeMap<String, crate::documents::Document>,
    /// Patch baselines, defaults and patch groups.
    pub patch: crate::patch::PatchState,
    /// Hybrid activations, by id.
    pub activations: BTreeMap<String, crate::activations::ActivationRecord>,
    /// Maintenance windows, by id.
    pub windows: BTreeMap<String, crate::maintenance::Window>,
    /// Window execution state changes not yet handed out.
    #[serde(skip)]
    pub window_events: Vec<crate::maintenance::WindowEvent>,
    /// State Manager associations, by id.
    pub associations: BTreeMap<String, crate::associations::AssociationRecord>,
    /// Inventory collected from managed nodes.
    pub inventory: crate::inventory::InventoryState,
    /// Compliance by `"{type}|{resource type}|{resource id}"`.
    pub compliance: BTreeMap<String, crate::compliance::ComplianceRecord>,
    /// Patch baseline results by node.
    pub patch_states: BTreeMap<String, crate::compliance::PatchRecord>,
    /// Resource data syncs, by name.
    pub data_syncs: BTreeMap<String, crate::nodes::SyncRecord>,
    /// Document reviews, by `"{name}#{version}"`.
    pub document_reviews: BTreeMap<String, crate::nodes::ReviewRecord>,
    /// Automation executions, by id.
    pub automations: BTreeMap<String, crate::automation::AutomationRecord>,
    /// Execution previews, by id.
    pub previews: BTreeMap<String, crate::automation::PreviewRecord>,
    /// OpsCenter and Application Manager.
    pub ops: crate::ops::OpsState,
    pub sessions: BTreeMap<String, crate::sessions::SessionRecord>,
    pub connectors: BTreeMap<String, crate::sessions::ConnectorRecord>,
    /// Run Command commands, newest first.
    pub commands: Vec<crate::commands::CommandRecord>,
    /// `Expiration` events of parameters deleted since they were last
    /// handed out.
    #[serde(skip)]
    pub expired: Vec<crate::policies::PolicyEvent>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By `"{account}/{region}"`.
    pub regions: BTreeMap<String, Region>,
}

impl State {
    pub fn region(&mut self, account: &str, region: &str) -> &mut Region {
        self.regions.entry(format!("{account}/{region}")).or_default()
    }

    pub fn region_ref(&self, account: &str, region: &str) -> Option<&Region> {
        self.regions.get(&format!("{account}/{region}"))
    }
}
