//! In-memory IAM state for one account.
//!
//! Maps are keyed by lower-cased name: IAM names are unique ignoring case
//! but keep the case they were created with.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

pub type Tags = Vec<(String, String)>;

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub path: String,
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub permissions_boundary: Option<String>,
    pub tags: Tags,
    /// Inline policies by name (original case) → document.
    pub inline: BTreeMap<String, String>,
    pub attached: BTreeSet<String>,
    pub login_profile: Option<LoginProfile>,
    pub password_last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct LoginProfile {
    pub created: DateTime<Utc>,
    pub password: String,
    pub reset_required: bool,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub path: String,
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub inline: BTreeMap<String, String>,
    pub attached: BTreeSet<String>,
    /// Lower-cased member user names.
    pub members: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub path: String,
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub trust_policy: String,
    pub description: Option<String>,
    pub max_session_duration: i32,
    pub permissions_boundary: Option<String>,
    pub tags: Tags,
    pub inline: BTreeMap<String, String>,
    pub attached: BTreeSet<String>,
    pub last_used: Option<(DateTime<Utc>, String)>,
}

#[derive(Debug, Clone)]
pub struct PolicyVersion {
    pub id: String,
    pub document: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ManagedPolicy {
    pub name: String,
    pub path: String,
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub description: Option<String>,
    pub default_version: String,
    /// Oldest first.
    pub versions: Vec<PolicyVersion>,
    pub next_version: u32,
    pub tags: Tags,
    pub aws_managed: bool,
}

impl ManagedPolicy {
    pub fn default_document(&self) -> &str {
        self.versions.iter().find(|v| v.id == self.default_version).map(|v| v.document.as_str()).unwrap_or("{}")
    }
}

#[derive(Debug, Clone)]
pub struct InstanceProfile {
    pub name: String,
    pub path: String,
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    /// Lower-cased role names (at most one).
    pub roles: Vec<String>,
    pub tags: Tags,
}

#[derive(Debug, Clone)]
pub struct OidcProvider {
    pub arn: String,
    /// Without the `https://` scheme, as IAM stores it.
    pub url: String,
    pub client_ids: Vec<String>,
    pub thumbprints: Vec<String>,
    pub created: DateTime<Utc>,
    pub tags: Tags,
}

#[derive(Debug, Clone)]
pub struct AccessKey {
    pub id: String,
    pub secret: String,
    /// `None` for the root user's keys.
    pub user_name: Option<String>,
    pub active: bool,
    pub created: DateTime<Utc>,
    pub last_used: Option<(DateTime<Utc>, String, String)>,
}

#[derive(Debug, Default)]
pub struct State {
    pub users: BTreeMap<String, User>,
    pub groups: BTreeMap<String, Group>,
    pub roles: BTreeMap<String, Role>,
    /// Keyed by ARN.
    pub policies: BTreeMap<String, ManagedPolicy>,
    pub instance_profiles: BTreeMap<String, InstanceProfile>,
    /// Keyed by ARN.
    pub oidc_providers: BTreeMap<String, OidcProvider>,
    pub access_keys: BTreeMap<String, AccessKey>,
    pub account_aliases: Vec<String>,
}

impl State {
    pub fn user(&self, name: &str) -> Option<&User> {
        self.users.get(&name.to_lowercase())
    }
    pub fn user_mut(&mut self, name: &str) -> Option<&mut User> {
        self.users.get_mut(&name.to_lowercase())
    }
    pub fn group(&self, name: &str) -> Option<&Group> {
        self.groups.get(&name.to_lowercase())
    }
    pub fn group_mut(&mut self, name: &str) -> Option<&mut Group> {
        self.groups.get_mut(&name.to_lowercase())
    }
    pub fn role(&self, name: &str) -> Option<&Role> {
        self.roles.get(&name.to_lowercase())
    }
    pub fn role_mut(&mut self, name: &str) -> Option<&mut Role> {
        self.roles.get_mut(&name.to_lowercase())
    }
    pub fn instance_profile(&self, name: &str) -> Option<&InstanceProfile> {
        self.instance_profiles.get(&name.to_lowercase())
    }

    pub fn keys_for(&self, user_name: Option<&str>) -> Vec<&AccessKey> {
        let wanted = user_name.map(str::to_lowercase);
        let mut keys: Vec<&AccessKey> =
            self.access_keys.values().filter(|k| k.user_name.as_deref().map(str::to_lowercase) == wanted).collect();
        keys.sort_by_key(|k| k.created);
        keys
    }

    pub fn groups_for_user(&self, user_name: &str) -> Vec<&Group> {
        let key = user_name.to_lowercase();
        self.groups.values().filter(|g| g.members.contains(&key)).collect()
    }

    /// Users, groups and roles a managed policy is attached to.
    pub fn attachment_count(&self, arn: &str) -> usize {
        self.users.values().filter(|u| u.attached.contains(arn)).count()
            + self.groups.values().filter(|g| g.attached.contains(arn)).count()
            + self.roles.values().filter(|r| r.attached.contains(arn)).count()
    }

    pub fn boundary_usage_count(&self, arn: &str) -> usize {
        self.users.values().filter(|u| u.permissions_boundary.as_deref() == Some(arn)).count()
            + self.roles.values().filter(|r| r.permissions_boundary.as_deref() == Some(arn)).count()
    }
}
