//! Organizations state: every organization, the accounts Organizations knows,
//! and the handshakes and responsibility transfers between them.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

pub type Tags = BTreeMap<String, String>;

pub const SCP: &str = "SERVICE_CONTROL_POLICY";
pub const RCP: &str = "RESOURCE_CONTROL_POLICY";
pub const FULL_AWS_ACCESS: &str = "p-FullAWSAccess";
pub const RCP_FULL_AWS_ACCESS: &str = "p-RCPFullAWSAccess";

/// An AWS account as Organizations records it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    /// `ACTIVE`, `SUSPENDED` or `PENDING_CLOSURE`.
    pub status: String,
    /// `ACTIVE`, `SUSPENDED`, `PENDING_CLOSURE`, `CLOSED`, ...
    pub state: String,
    /// When CloseAccount closed it (for the rolling 30-day closure quota).
    #[serde(default)]
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ou {
    pub id: String,
    pub name: String,
    pub parent: String,
    #[serde(default)]
    pub tags: Tags,
}

/// An account's membership of an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub parent: String,
    pub joined_method: String,
    pub joined: DateTime<Utc>,
    #[serde(default)]
    pub tags: Tags,
}

/// A customer managed policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRec {
    pub id: String,
    pub name: String,
    pub description: String,
    pub ty: String,
    pub content: String,
    #[serde(default)]
    pub tags: Tags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePolicyRec {
    pub id: String,
    pub content: String,
    #[serde(default)]
    pub tags: Tags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub id: String,
    pub management_account: String,
    /// `ALL` or `CONSOLIDATED_BILLING`.
    pub feature_set: String,
    pub created: DateTime<Utc>,
    pub root_id: String,
    #[serde(default)]
    pub root_tags: Tags,
    /// Policy types enabled in the root, with their status.
    #[serde(default)]
    pub policy_types: BTreeMap<String, String>,
    #[serde(default)]
    pub ous: BTreeMap<String, Ou>,
    /// Every account in the organization, the management account included.
    #[serde(default)]
    pub members: BTreeMap<String, Member>,
    #[serde(default)]
    pub policies: BTreeMap<String, PolicyRec>,
    /// Policy ids attached to each target (root, OU or account), in
    /// attachment order.
    #[serde(default)]
    pub attachments: BTreeMap<String, Vec<String>>,
    /// Service principals with trusted access, and when it was enabled.
    #[serde(default)]
    pub services: BTreeMap<String, DateTime<Utc>>,
    /// Delegated administrators: account → service principal → since.
    #[serde(default)]
    pub delegated: BTreeMap<String, BTreeMap<String, DateTime<Utc>>>,
    #[serde(default)]
    pub create_statuses: BTreeMap<String, types::CreateAccountStatus>,
    #[serde(default)]
    pub resource_policy: Option<ResourcePolicyRec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRec {
    /// The organization that sent it.
    pub org_id: String,
    pub handshake: types::Handshake,
    /// Tags for the account once an invitation is accepted.
    #[serde(default)]
    pub tags: Tags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRec {
    pub source_org: String,
    pub target_org: String,
    pub transfer: types::ResponsibilityTransfer,
    #[serde(default)]
    pub tags: Tags,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub organizations: BTreeMap<String, Org>,
    /// Accounts Organizations has seen (created, invited, management).
    pub accounts: BTreeMap<String, AccountInfo>,
    pub handshakes: BTreeMap<String, HandshakeRec>,
    pub transfers: BTreeMap<String, TransferRec>,
}

impl State {
    /// The organization `account` belongs to.
    pub fn org_of(&self, account: &str) -> Option<&Org> {
        self.organizations.values().find(|o| o.members.contains_key(account))
    }

    pub fn org_id_of(&self, account: &str) -> Option<String> {
        self.org_of(account).map(|o| o.id.clone())
    }
}

impl Org {
    pub fn is_ou(&self, id: &str) -> bool {
        self.ous.contains_key(id)
    }

    /// Whether `id` is the root, an OU or an account of this organization.
    pub fn has_target(&self, id: &str) -> bool {
        id == self.root_id || self.ous.contains_key(id) || self.members.contains_key(id)
    }

    pub fn has_parent(&self, id: &str) -> bool {
        id == self.root_id || self.ous.contains_key(id)
    }

    pub fn parent_of(&self, id: &str) -> Option<&str> {
        if let Some(ou) = self.ous.get(id) {
            return Some(&ou.parent);
        }
        self.members.get(id).map(|m| m.parent.as_str())
    }

    /// The root, every OU above `id`, and `id` itself, root first.
    pub fn lineage(&self, id: &str) -> Vec<String> {
        let mut out = vec![id.to_string()];
        let mut cur = id.to_string();
        while let Some(p) = self.parent_of(&cur) {
            out.push(p.to_string());
            cur = p.to_string();
        }
        out.reverse();
        out
    }

    /// `o-.../r-.../ou-.../` for a parent container.
    pub fn path_of_container(&self, id: &str) -> String {
        let mut path = format!("{}/", self.id);
        for p in self.lineage(id) {
            path.push_str(&p);
            path.push('/');
        }
        path
    }

    /// The `Paths` value of an account: its container path plus its id.
    pub fn account_path(&self, account: &str) -> String {
        let parent = self.members.get(account).map(|m| m.parent.clone()).unwrap_or_else(|| self.root_id.clone());
        format!("{}{account}/", self.path_of_container(&parent))
    }

    /// Depth of an OU below the root (a child of the root is 1).
    pub fn ou_depth(&self, id: &str) -> usize {
        self.lineage(id).len().saturating_sub(1)
    }

    /// The tags of a root, OU or account (`aws:ResourceTag/...`).
    pub fn target_tags(&self, id: &str) -> Tags {
        if id == self.root_id {
            return self.root_tags.clone();
        }
        if let Some(ou) = self.ous.get(id) {
            return ou.tags.clone();
        }
        self.members.get(id).map(|m| m.tags.clone()).unwrap_or_default()
    }

    pub fn type_enabled(&self, ty: &str) -> bool {
        self.policy_types.get(ty).is_some_and(|s| s == "ENABLED")
    }

    pub fn attached(&self, target: &str) -> &[String] {
        self.attachments.get(target).map(Vec::as_slice).unwrap_or_default()
    }

    pub fn targets_of(&self, policy: &str) -> Vec<String> {
        self.attachments.iter().filter(|(_, ps)| ps.iter().any(|p| p == policy)).map(|(t, _)| t.clone()).collect()
    }

    /// Every target in the organization: the root, OUs and accounts.
    pub fn all_targets(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        out.insert(self.root_id.clone());
        out.extend(self.ous.keys().cloned());
        out.extend(self.members.keys().cloned());
        out
    }

    pub fn arn(&self, partition: &str) -> String {
        format!("arn:{partition}:organizations::{}:organization/{}", self.management_account, self.id)
    }

    pub fn root_arn(&self, partition: &str) -> String {
        format!("arn:{partition}:organizations::{}:root/{}/{}", self.management_account, self.id, self.root_id)
    }

    pub fn ou_arn(&self, partition: &str, ou: &str) -> String {
        format!("arn:{partition}:organizations::{}:ou/{}/{ou}", self.management_account, self.id)
    }

    pub fn account_arn(&self, partition: &str, account: &str) -> String {
        format!("arn:{partition}:organizations::{}:account/{}/{account}", self.management_account, self.id)
    }

    pub fn target_arn(&self, partition: &str, target: &str) -> String {
        if target == self.root_id {
            self.root_arn(partition)
        } else if self.is_ou(target) {
            self.ou_arn(partition, target)
        } else {
            self.account_arn(partition, target)
        }
    }

    pub fn policy_arn(&self, partition: &str, id: &str, ty: &str) -> String {
        if is_aws_managed(id) {
            return format!("arn:{partition}:organizations::aws:policy/{}/{id}", ty.to_lowercase());
        }
        format!(
            "arn:{partition}:organizations::{}:policy/{}/{}/{id}",
            self.management_account,
            self.id,
            ty.to_lowercase()
        )
    }

    pub fn handshake_arn(&self, partition: &str, action: &str, id: &str) -> String {
        format!(
            "arn:{partition}:organizations::{}:handshake/{}/{}/{id}",
            self.management_account,
            self.id,
            action.to_lowercase()
        )
    }

    pub fn resource_policy_arn(&self, partition: &str, id: &str) -> String {
        format!("arn:{partition}:organizations::{}:resourcepolicy/{}/{id}", self.management_account, self.id)
    }

    /// A policy by id: customer managed, or one of AWS's.
    pub fn policy(&self, id: &str) -> Option<PolicyRec> {
        if let Some(p) = self.policies.get(id) {
            return Some(p.clone());
        }
        aws_managed(id)
    }
}

pub fn is_aws_managed(id: &str) -> bool {
    id == FULL_AWS_ACCESS || id == RCP_FULL_AWS_ACCESS
}

/// The AWS managed policies every organization has.
pub fn aws_managed(id: &str) -> Option<PolicyRec> {
    match id {
        FULL_AWS_ACCESS => Some(PolicyRec {
            id: FULL_AWS_ACCESS.into(),
            name: "FullAWSAccess".into(),
            description: "Allows access to every operation".into(),
            ty: SCP.into(),
            content: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#.into(),
            tags: Tags::new(),
        }),
        RCP_FULL_AWS_ACCESS => Some(PolicyRec {
            id: RCP_FULL_AWS_ACCESS.into(),
            name: "RCPFullAWSAccess".into(),
            description: "Allows access to every operation".into(),
            ty: RCP.into(),
            content:
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}"#
                    .into(),
            tags: Tags::new(),
        }),
        _ => None,
    }
}

/// The AWS managed policy attached everywhere when a policy type is enabled.
pub fn default_policy_for(ty: &str) -> Option<&'static str> {
    match ty {
        SCP => Some(FULL_AWS_ACCESS),
        RCP => Some(RCP_FULL_AWS_ACCESS),
        _ => None,
    }
}
