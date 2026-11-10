use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

/// `(sort key of name, type, set identifier)`: Route 53's listing order.
pub type RecordKey = (String, String, String);

pub fn record_key(name: &str, ty: &str, set_identifier: Option<&str>) -> RecordKey {
    (crate::names::sort_key(name), ty.to_string(), set_identifier.unwrap_or_default().to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    /// Normalized: lowercase with trailing dot.
    pub name: String,
    pub caller_reference: String,
    pub comment: Option<String>,
    pub private: bool,
    pub vpcs: Vec<types::VPC>,
    pub name_servers: Vec<String>,
    /// Record sets with normalized names. Saved as a list: the key is
    /// derived from each record set.
    #[serde(with = "records_as_list")]
    pub records: BTreeMap<RecordKey, types::ResourceRecordSet>,
    pub tags: BTreeMap<String, String>,
    #[serde(default)]
    /// The reusable delegation set whose name servers the zone uses.
    pub delegation_set_id: Option<String>,
    #[serde(default)]
    /// DNSSEC key-signing keys by name.
    pub ksks: BTreeMap<String, KeySigningKey>,
    #[serde(default)]
    /// Whether DNSSEC signing is enabled.
    pub dnssec_signing: bool,
    #[serde(default)]
    /// VPCs other accounts are authorized to associate.
    pub vpc_authorizations: Vec<types::VPC>,
    #[serde(default)]
    pub accelerated_recovery: bool,
    #[serde(default)]
    /// VPCs another account associated (through an authorization), by
    /// `"{region}/{vpc id}"`: that account may list and disassociate them.
    pub vpc_accounts: BTreeMap<String, String>,
}

/// The key of a VPC in [`Zone::vpc_accounts`].
pub fn vpc_key(vpc: &types::VPC) -> String {
    format!("{}/{}", vpc.vpc_region.as_deref().unwrap_or_default(), vpc.vpc_id.as_deref().unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySigningKey {
    pub key: types::KeySigningKey,
    pub caller_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationSet {
    pub id: String,
    pub caller_reference: String,
    pub name_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrCollection {
    pub id: String,
    pub name: String,
    pub caller_reference: String,
    pub version: i64,
    /// Location name → CIDR blocks.
    pub locations: BTreeMap<String, std::collections::BTreeSet<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPolicy {
    pub id: String,
    pub name: String,
    pub record_type: String,
    /// Versions by number; deleted versions are removed.
    pub versions: BTreeMap<i32, types::TrafficPolicy>,
    pub latest_version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub submitted_at: DateTime<Utc>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub check: types::HealthCheck,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub zones: BTreeMap<String, Zone>,
    pub changes: HashMap<String, Change>,
    pub health_checks: BTreeMap<String, HealthCheck>,
    pub delegation_sets: BTreeMap<String, DelegationSet>,
    /// Query logging configurations by id.
    pub query_logging: BTreeMap<String, types::QueryLoggingConfig>,
    pub cidr_collections: BTreeMap<String, CidrCollection>,
    pub traffic_policies: BTreeMap<String, TrafficPolicy>,
    pub traffic_policy_instances: BTreeMap<String, types::TrafficPolicyInstance>,
}

impl State {
    /// Record a change submitted at `now` and return its `ChangeInfo`
    /// (PENDING, as Route 53 reports right after a change; `GetChange`
    /// reports INSYNC once it has propagated, see [`change_propagation`]).
    pub fn new_change(&mut self, comment: Option<String>, now: chrono::DateTime<Utc>) -> types::ChangeInfo {
        let id = crate::new_id('C');
        let submitted_at = now;
        self.changes.insert(id.clone(), Change { submitted_at, comment: comment.clone() });
        types::ChangeInfo { id: format!("/change/{id}"), status: "PENDING".into(), submitted_at, comment }
    }
}

/// How long a change is PENDING before it is INSYNC (AWS: usually
/// within 60 seconds). Advancing the emulated clock finishes it, as does
/// `MWS_ASYNC_DELAY_MS=0`.
pub fn change_propagation() -> chrono::Duration {
    chrono::Duration::milliseconds(mws_core::settle::window_ms(1_000))
}

mod records_as_list {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{record_key, types, RecordKey};

    pub fn serialize<S: Serializer>(
        records: &BTreeMap<RecordKey, types::ResourceRecordSet>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        records.values().collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<RecordKey, types::ResourceRecordSet>, D::Error> {
        let list = Vec::<types::ResourceRecordSet>::deserialize(d)?;
        Ok(list.into_iter().map(|r| (record_key(&r.name, &r.r#type, r.set_identifier.as_deref()), r)).collect())
    }
}
