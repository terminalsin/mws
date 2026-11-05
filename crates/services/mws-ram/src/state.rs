use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One principal, resource or source associated with a share.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Association {
    /// Account id, principal ARN, service principal or resource ARN.
    pub entity: String,
    pub status: String,
    pub status_message: Option<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    /// The principal is outside the owner's organization (or sharing with
    /// the organization is off), so it had to accept an invitation.
    pub external: bool,
    /// For resources: `acm-pca:CertificateAuthority`.
    pub resource_type: Option<String>,
    /// For sources: `ACCOUNT` or `ARN`.
    pub source_type: Option<String>,
}

impl Default for Association {
    fn default() -> Self {
        Self {
            entity: String::new(),
            status: "ASSOCIATED".into(),
            status_message: None,
            created: DateTime::<Utc>::UNIX_EPOCH,
            updated: DateTime::<Utc>::UNIX_EPOCH,
            external: false,
            resource_type: None,
            source_type: None,
        }
    }
}

/// A managed permission attached to a share.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SharePermission {
    pub arn: String,
    pub version: u32,
    pub resource_type: String,
    pub updated: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Share {
    pub arn: String,
    pub name: String,
    pub owner: String,
    pub region: String,
    pub allow_external: bool,
    pub status: String,
    pub feature_set: String,
    pub retain_on_leave: Option<bool>,
    pub created: Option<DateTime<Utc>>,
    pub updated: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
    pub resources: Vec<Association>,
    pub principals: Vec<Association>,
    pub sources: Vec<Association>,
    pub permissions: Vec<SharePermission>,
    /// For a share created from a resource policy (`PutPolicy`): the
    /// resource whose policy it mirrors.
    pub from_policy_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Invitation {
    pub arn: String,
    pub share_arn: String,
    pub share_name: String,
    pub sender: String,
    pub receiver: String,
    /// The IAM principal invited, when not a whole account.
    pub receiver_arn: Option<String>,
    pub status: String,
    pub created: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PermissionVersion {
    pub template: String,
    pub created: Option<DateTime<Utc>>,
    pub updated: Option<DateTime<Utc>>,
    pub status: String,
}

/// A customer managed permission (or one created from a resource policy).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Permission {
    pub arn: String,
    pub name: String,
    pub owner: String,
    pub region: String,
    pub resource_type: String,
    pub feature_set: String,
    pub status: String,
    pub default_version: u32,
    pub versions: BTreeMap<u32, PermissionVersion>,
    pub tags: BTreeMap<String, String>,
    pub created: Option<DateTime<Utc>>,
    pub updated: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ReplaceWork {
    pub id: String,
    pub owner: String,
    pub from_arn: String,
    pub from_version: Option<u32>,
    pub to_arn: String,
    pub to_version: u32,
    pub status: String,
    pub status_message: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub updated: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct State {
    pub shares: BTreeMap<String, Share>,
    pub invitations: BTreeMap<String, Invitation>,
    pub permissions: BTreeMap<String, Permission>,
    pub replace_work: BTreeMap<String, ReplaceWork>,
    /// `{account}/{token}` -> the ARN a create call made.
    pub client_tokens: HashMap<String, String>,
}
