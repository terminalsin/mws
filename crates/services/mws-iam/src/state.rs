//! In-memory IAM state for one account.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub path: String,
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub permissions_boundary: Option<String>,
    pub tags: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct AccessKey {
    pub id: String,
    pub secret: String,
    /// `None` for the root user's keys.
    pub user_name: Option<String>,
    pub active: bool,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct State {
    /// Keyed by lower-cased name: IAM names are case-insensitive for
    /// uniqueness but keep the case they were created with.
    pub users: BTreeMap<String, User>,
    pub access_keys: BTreeMap<String, AccessKey>,
}

impl State {
    pub fn user(&self, name: &str) -> Option<&User> {
        self.users.get(&name.to_lowercase())
    }

    pub fn keys_for(&self, user_name: Option<&str>) -> Vec<&AccessKey> {
        let wanted = user_name.map(str::to_lowercase);
        let mut keys: Vec<&AccessKey> =
            self.access_keys.values().filter(|k| k.user_name.as_deref().map(str::to_lowercase) == wanted).collect();
        keys.sort_by_key(|k| k.created);
        keys
    }
}
