//! Roles AWS services manage in customer accounts under `/aws-reserved/`.
//!
//! IAM Identity Center provisions each permission set into an account as an
//! `AWSReservedSSO_*` role trusted through a SAML provider it also creates.
//! AWS couples Identity Center to IAM the same way: only the service may
//! change those roles (IAM answers `UnmodifiableEntity` to everyone else).

use chrono::Utc;

use crate::api::RoleView;
use crate::state::{Role, SamlProvider};
use crate::{ids, Iam};

/// What a reserved role should look like.
#[derive(Debug, Clone, Default)]
pub struct ReservedRoleSpec {
    pub name: String,
    /// Starts with `/aws-reserved/`.
    pub path: String,
    pub trust_policy: String,
    pub description: Option<String>,
    pub max_session_duration: i32,
    /// ARNs of managed policies (AWS managed, or customer managed in the
    /// role's account) to attach.
    pub managed_policies: Vec<String>,
    /// Inline policies by name.
    pub inline_policies: Vec<(String, String)>,
    pub permissions_boundary: Option<String>,
}

impl Iam {
    /// Create `spec`'s role in `account`, or bring an existing one in line
    /// with it (keeping its id and creation date).
    pub fn put_reserved_role(&self, account: &str, spec: ReservedRoleSpec) -> RoleView {
        let partition = self.inner.config.partition.clone();
        let mut state = self.inner.write_account(account);
        let key = spec.name.to_lowercase();
        let arn = format!("arn:{partition}:iam::{account}:role{}{}", spec.path, spec.name);
        let existing = state.roles.get(&key).cloned();
        let role = Role {
            name: spec.name.clone(),
            path: spec.path,
            id: existing.as_ref().map(|r| r.id.clone()).unwrap_or_else(|| ids::unique_id("AROA")),
            arn,
            created: existing.as_ref().map(|r| r.created).unwrap_or_else(Utc::now),
            trust_policy: spec.trust_policy,
            description: spec.description,
            max_session_duration: spec.max_session_duration,
            permissions_boundary: spec.permissions_boundary,
            tags: existing.as_ref().map(|r| r.tags.clone()).unwrap_or_default(),
            inline: spec.inline_policies.into_iter().collect(),
            attached: spec.managed_policies.into_iter().collect(),
            last_used: existing.and_then(|r| r.last_used),
        };
        let view = RoleView {
            account_id: account.to_string(),
            name: role.name.clone(),
            arn: role.arn.clone(),
            id: role.id.clone(),
            trust_policy: role.trust_policy.clone(),
            max_session_duration: role.max_session_duration,
            tags: role.tags.iter().cloned().collect(),
        };
        state.roles.insert(key, role);
        view
    }

    /// Delete a reserved role. Returns whether it existed.
    pub fn delete_reserved_role(&self, account: &str, name: &str) -> bool {
        if !self.account_exists(account) {
            return false;
        }
        let mut state = self.inner.write_account(account);
        let key = name.to_lowercase();
        match state.roles.get(&key) {
            Some(r) if r.path.starts_with("/aws-reserved/") => {
                state.roles.remove(&key);
                true
            }
            _ => false,
        }
    }

    /// Create the SAML provider `name` in `account` with `metadata` unless it
    /// exists, and return its ARN.
    pub fn ensure_saml_provider(&self, account: &str, name: &str, metadata: &str) -> String {
        let partition = self.inner.config.partition.clone();
        let arn = format!("arn:{partition}:iam::{account}:saml-provider/{name}");
        let mut state = self.inner.write_account(account);
        state.saml_providers.entry(arn.clone()).or_insert_with(|| {
            let now = Utc::now();
            SamlProvider {
                arn: arn.clone(),
                uuid: format!("a-{}", uuid::Uuid::new_v4().simple()),
                metadata: metadata.to_string(),
                created: now,
                valid_until: now + chrono::Duration::days(365 * 100),
                tags: vec![],
                assertion_encryption_mode: None,
                private_keys: vec![],
            }
        });
        arn
    }

    /// Whether `account` has a SAML provider with this ARN.
    pub fn saml_provider_exists(&self, account: &str, arn: &str) -> bool {
        self.account_exists(account) && self.inner.read_account(account).saml_providers.contains_key(arn)
    }

    /// The ARN of `account`'s customer managed policy at `path` (`/` when
    /// `None`) named `name`, if it exists.
    pub fn customer_managed_policy(&self, account: &str, path: Option<&str>, name: &str) -> Option<String> {
        let partition = &self.inner.config.partition;
        let arn = format!("arn:{partition}:iam::{account}:policy{}{name}", path.unwrap_or("/"));
        (self.account_exists(account) && self.inner.read_account(account).policies.contains_key(&arn)).then_some(arn)
    }

    /// Whether IAM knows the AWS managed policy `arn`.
    pub fn aws_managed_policy_exists(&self, arn: &str) -> bool {
        let account = self.primary_account_id().to_string();
        self.inner.read_account(&account).policies.get(arn).is_some_and(|p| p.aws_managed)
    }
}
