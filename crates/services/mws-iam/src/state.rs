//! In-memory IAM state for one account.
//!
//! Maps are keyed by lower-cased name: IAM names are unique ignoring case
//! but keep the case they were created with.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type Tags = Vec<(String, String)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginProfile {
    pub created: DateTime<Utc>,
    pub password: String,
    pub reset_required: bool,
    /// When the password was last set, for expiry.
    #[serde(default)]
    pub changed: Option<DateTime<Utc>>,
    /// Earlier passwords, newest last, for `PasswordReusePrevention`.
    #[serde(default)]
    pub history: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub id: String,
    pub document: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProvider {
    pub arn: String,
    /// Without the `https://` scheme, as IAM stores it.
    pub url: String,
    pub client_ids: Vec<String>,
    pub thumbprints: Vec<String>,
    pub created: DateTime<Utc>,
    pub tags: Tags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKey {
    pub id: String,
    pub secret: String,
    /// `None` for the root user's keys.
    pub user_name: Option<String>,
    pub active: bool,
    pub created: DateTime<Utc>,
    pub last_used: Option<(DateTime<Utc>, String, String)>,
}

/// A virtual MFA device: a TOTP seed (RFC 6238, SHA-1, 6 digits, 30 s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaDevice {
    pub serial: String,
    pub path: String,
    pub name: String,
    pub seed: Vec<u8>,
    /// Lower-cased user name it is enabled for.
    pub user: Option<String>,
    pub enabled: Option<DateTime<Utc>>,
    pub tags: Tags,
    /// The last time step a code was accepted for, to refuse replays.
    pub last_step: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshPublicKey {
    pub id: String,
    pub user: String,
    pub body: String,
    pub fingerprint: String,
    pub active: bool,
    pub uploaded: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningCertificate {
    pub id: String,
    /// Lower-cased user name, or `None` for the root user.
    pub user: Option<String>,
    pub body: String,
    pub active: bool,
    pub uploaded: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCredential {
    pub id: String,
    pub user: String,
    pub service: String,
    pub service_user_name: String,
    pub password: String,
    pub active: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCertificate {
    pub name: String,
    pub path: String,
    pub id: String,
    pub arn: String,
    pub body: String,
    pub chain: Option<String>,
    pub uploaded: DateTime<Utc>,
    pub expiration: Option<DateTime<Utc>>,
    pub tags: Tags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlProvider {
    pub arn: String,
    pub uuid: String,
    pub metadata: String,
    pub created: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub tags: Tags,
    pub assertion_encryption_mode: Option<String>,
    /// Private keys for encrypted assertions: (key id, PEM, added).
    pub private_keys: Vec<(String, String, DateTime<Utc>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub minimum_length: i32,
    pub require_symbols: bool,
    pub require_numbers: bool,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub allow_users_to_change: bool,
    pub max_age: Option<i32>,
    pub reuse_prevention: Option<i32>,
    pub hard_expiry: Option<bool>,
}

/// An asynchronous IAM report job (service last accessed, Organizations
/// access).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportJob {
    pub id: String,
    pub kind: String,
    pub arn: String,
    pub granularity: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionTask {
    pub id: String,
    pub role: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRequest {
    pub request: crate::generated::types::DelegationRequest,
    pub notes: Option<String>,
    /// The exchange token SendDelegationToken issued (AWS posts it to the
    /// partner's notification channel; MWS keeps it in state).
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub redeemed: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
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
    /// Virtual MFA devices by serial number (ARN).
    pub mfa_devices: BTreeMap<String, MfaDevice>,
    pub ssh_keys: BTreeMap<String, SshPublicKey>,
    pub signing_certificates: BTreeMap<String, SigningCertificate>,
    pub service_credentials: BTreeMap<String, ServiceCredential>,
    /// Keyed by lower-cased name.
    pub server_certificates: BTreeMap<String, ServerCertificate>,
    /// Keyed by ARN.
    pub saml_providers: BTreeMap<String, SamlProvider>,
    pub password_policy: Option<PasswordPolicy>,
    /// When the credential report was last generated.
    pub credential_report: Option<DateTime<Utc>>,
    pub report_jobs: BTreeMap<String, ReportJob>,
    pub deletion_tasks: BTreeMap<String, DeletionTask>,
    pub delegation_requests: BTreeMap<String, DelegationRequest>,
    pub account_properties: BTreeMap<String, String>,
    pub global_endpoint_token_version: Option<String>,
    /// Outbound web identity federation issuer, when enabled.
    pub outbound_issuer: Option<String>,
    pub outbound_enabled: bool,
    /// Outbound federation signing keys (PKCS#8 DER) by JWS algorithm.
    pub outbound_keys: BTreeMap<String, Vec<u8>>,
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
