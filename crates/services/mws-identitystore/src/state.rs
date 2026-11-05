//! Identity Store state: every identity store and what it holds.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by identity store id (`d-1234567890`).
    pub stores: BTreeMap<String, Store>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Store {
    pub id: String,
    pub account: String,
    pub region: String,
    pub partition: String,
    pub network: Option<types::NetworkConfigurationDetails>,
    /// Keyed by user id.
    pub users: BTreeMap<String, types::User>,
    pub groups: BTreeMap<String, types::Group>,
    pub memberships: BTreeMap<String, Membership>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Membership {
    pub id: String,
    pub group_id: String,
    pub user_id: String,
    pub created_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
}

impl Store {
    pub fn arn(&self) -> String {
        format!("arn:{}:identitystore::{}:identitystore/{}", self.partition, self.account, self.id)
    }

    pub fn user_arn(&self, id: &str) -> String {
        format!("arn:{}:identitystore:::user/{id}", self.partition)
    }

    pub fn group_arn(&self, id: &str) -> String {
        format!("arn:{}:identitystore:::group/{id}", self.partition)
    }

    pub fn membership_arn(&self, id: &str) -> String {
        format!("arn:{}:identitystore:::membership/{id}", self.partition)
    }

    pub fn groups_of(&self, user_id: &str) -> Vec<String> {
        self.memberships.values().filter(|m| m.user_id == user_id).map(|m| m.group_id.clone()).collect()
    }
}
