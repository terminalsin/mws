//! How IAM sees AWS Organizations.
//!
//! AWS couples IAM policy evaluation to Organizations: service control
//! policies limit what principals in member accounts may do, resource control
//! policies limit what may be done to their resources, and the
//! `aws:PrincipalOrg*` / `aws:ResourceOrg*` condition keys describe an
//! account's place in its organization. IAM defines the view it needs here;
//! the Organizations service implements it and is registered with
//! [`Iam::set_organizations`](crate::Iam::set_organizations).
//!
//! The other direction is the account lifecycle: Organizations creates member
//! accounts, which get their own IAM namespace and an access role trusted by
//! the management account.

use chrono::Utc;

use crate::state::Role;
use crate::{ids, Iam};

/// Policies at one level of the organization tree, as `(policy id, document)`.
pub type PolicyLevel = Vec<(String, String)>;

/// An account's membership of an organization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountOrganization {
    pub organization_id: String,
    pub management_account_id: String,
    /// `aws:PrincipalOrgPaths` / `aws:ResourceOrgPaths` value, e.g.
    /// `o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/`.
    pub org_path: String,
    /// Whether all features are enabled (not just consolidated billing).
    pub all_features: bool,
    /// SCPs from the root down to the account itself, one entry per level,
    /// or `None` when SCPs do not apply (the type is not enabled, or this is
    /// the management account).
    pub service_control_policies: Option<Vec<PolicyLevel>>,
    /// RCPs, likewise.
    pub resource_control_policies: Option<Vec<PolicyLevel>>,
    /// Service principals with trusted access to the organization.
    pub trusted_services: Vec<String>,
    /// Service principals this account is a delegated administrator for.
    pub delegated_admin_for: Vec<String>,
    /// The account was closed: nothing in it may act.
    pub suspended: bool,
}

impl AccountOrganization {
    pub fn is_management(&self, account_id: &str) -> bool {
        self.management_account_id == account_id
    }
}

/// Implemented by the Organizations service. Calls must not call back into
/// IAM: the authorizer asks before it takes the IAM state lock.
pub trait OrganizationView: Send + Sync {
    /// The organization `account_id` belongs to, if any.
    fn account(&self, account_id: &str) -> Option<AccountOrganization>;
}

/// Name of the role Organizations creates in new member accounts unless told
/// otherwise.
pub const DEFAULT_ACCESS_ROLE: &str = "OrganizationAccountAccessRole";

impl Iam {
    /// Whether `account_id` has an IAM namespace (the configured account, or
    /// one Organizations created).
    pub fn account_exists(&self, account_id: &str) -> bool {
        self.inner.accounts.read().expect("IAM state lock poisoned").contains_key(account_id)
    }

    /// The configured account (the one whose root keys MWS was started with).
    pub fn primary_account_id(&self) -> &str {
        &self.inner.config.account_id
    }

    /// Create an empty IAM namespace for a new member account, with
    /// `access_role` (`OrganizationAccountAccessRole` by default) granting
    /// administrator access to the management account, as
    /// `organizations:CreateAccount` does.
    pub fn create_member_account(&self, account_id: &str, access_role: &str, management_account_id: &str) {
        let partition = self.inner.config.partition.clone();
        let mut state = self.inner.write_account(account_id);
        let trust = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:{partition}:iam::{management_account_id}:root"}},"Action":"sts:AssumeRole"}}]}}"#
        );
        let key = access_role.to_lowercase();
        state.roles.entry(key).or_insert_with(|| Role {
            name: access_role.to_string(),
            path: "/".into(),
            id: ids::unique_id("AROA"),
            arn: format!("arn:{partition}:iam::{account_id}:role/{access_role}"),
            created: Utc::now(),
            trust_policy: trust,
            description: None,
            max_session_duration: 3600,
            permissions_boundary: None,
            tags: vec![],
            inline: [(
                "AdministratorAccess".to_string(),
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#.to_string(),
            )]
            .into_iter()
            .collect(),
            attached: Default::default(),
            last_used: None,
        });
    }

    /// Create the service-linked role a service uses in `account_id`, if it
    /// is not there yet (Organizations creates `AWSServiceRoleForOrganizations`
    /// in the management account, and in accounts that join).
    pub fn ensure_service_linked_role(&self, account_id: &str, service: &str, policy_name: &str) {
        let partition = self.inner.config.partition.clone();
        let mut state = self.inner.write_account(account_id);
        let name = format!("AWSServiceRoleFor{}", crate::ops::service_roles::stem(service));
        let key = name.to_lowercase();
        if state.roles.contains_key(&key) {
            return;
        }
        let path = format!("/aws-service-role/{service}/");
        let policy_arn = format!("arn:{partition}:iam::aws:policy/aws-service-role/{policy_name}");
        let attached = state.policies.contains_key(&policy_arn).then_some(policy_arn).into_iter().collect();
        state.roles.insert(
            key,
            Role {
                arn: format!("arn:{partition}:iam::{account_id}:role{path}{name}"),
                name,
                path,
                id: ids::unique_id("AROA"),
                created: Utc::now(),
                trust_policy: format!(
                    r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
                ),
                description: None,
                max_session_duration: 3600,
                permissions_boundary: None,
                tags: vec![],
                inline: Default::default(),
                attached,
                last_used: None,
            },
        );
    }

    /// The execution role service-managed CloudFormation StackSets deploy
    /// with in a member account (`stacksets-exec-<hash>`), created on first
    /// use as AWS does when it first deploys there. Returns its ARN.
    pub fn ensure_stacksets_execution_role(&self, account_id: &str, management_account_id: &str) -> String {
        use std::hash::{Hash, Hasher};
        let partition = self.inner.config.partition.clone();
        let mut h = std::collections::hash_map::DefaultHasher::new();
        management_account_id.hash(&mut h);
        let name = format!("stacksets-exec-{:016x}", h.finish());
        let arn = format!("arn:{partition}:iam::{account_id}:role/{name}");
        let mut state = self.inner.write_account(account_id);
        state.roles.entry(name.to_lowercase()).or_insert_with(|| Role {
            name: name.clone(),
            path: "/".into(),
            id: ids::unique_id("AROA"),
            arn: arn.clone(),
            created: Utc::now(),
            trust_policy: format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"member.org.stacksets.cloudformation.amazonaws.com"}},"Action":"sts:AssumeRole","Condition":{{"StringEquals":{{"aws:SourceAccount":"{management_account_id}"}}}}}}]}}"#
            ),
            description: None,
            max_session_duration: 3600,
            permissions_boundary: None,
            tags: vec![],
            inline: [(
                "AdministratorAccess".to_string(),
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#.to_string(),
            )]
            .into_iter()
            .collect(),
            attached: Default::default(),
            last_used: None,
        });
        arn
    }

    /// Whether centralized root access lets the management account (or the
    /// IAM delegated administrator) start root sessions in member accounts.
    pub fn org_root_sessions_enabled(&self, management_account_id: &str) -> bool {
        self.inner.read_account(management_account_id).org_root_sessions
    }
}
