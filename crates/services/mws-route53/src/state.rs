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
}

impl State {
    /// Record a change and return its `ChangeInfo` (PENDING, as Route 53
    /// reports right after a change; `GetChange` then reports INSYNC).
    pub fn new_change(&mut self, comment: Option<String>) -> types::ChangeInfo {
        let id = crate::new_id('C');
        let submitted_at = Utc::now();
        self.changes.insert(id.clone(), Change { submitted_at, comment: comment.clone() });
        types::ChangeInfo { id: format!("/change/{id}"), status: "PENDING".into(), submitted_at, comment }
    }
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
