//! Read-only views other services (STS) use. AWS couples STS to IAM
//! identities, so this is the one sanctioned cross-service API.

use std::collections::BTreeMap;

use mws_core::ServiceError;
use mws_iam_policy::PolicyKind;

use crate::Iam;

#[derive(Debug, Clone)]
pub struct RoleView {
    pub name: String,
    pub arn: String,
    pub id: String,
    pub trust_policy: String,
    pub max_session_duration: i32,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct UserView {
    pub name: String,
    pub arn: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct OidcProviderView {
    pub arn: String,
    pub url: String,
    pub client_ids: Vec<String>,
}

impl Iam {
    pub fn account_id_str(&self) -> &str {
        &self.inner.config.account_id
    }

    pub fn partition(&self) -> &str {
        &self.inner.config.partition
    }

    /// Look up a role by ARN (path included).
    pub fn role_by_arn(&self, arn: &str) -> Option<RoleView> {
        let state = self.read();
        state.roles.values().find(|r| r.arn == arn).map(|r| RoleView {
            name: r.name.clone(),
            arn: r.arn.clone(),
            id: r.id.clone(),
            trust_policy: r.trust_policy.clone(),
            max_session_duration: r.max_session_duration,
            tags: r.tags.iter().cloned().collect(),
        })
    }

    pub fn user_by_name(&self, name: &str) -> Option<UserView> {
        self.read().user(name).map(|u| UserView { name: u.name.clone(), arn: u.arn.clone(), id: u.id.clone() })
    }

    /// Find the OIDC provider whose URL (without scheme) is `issuer`.
    pub fn oidc_provider_for_issuer(&self, issuer: &str) -> Option<OidcProviderView> {
        let wanted = issuer.trim_start_matches("https://").trim_end_matches('/');
        self.read().oidc_providers.values().find(|p| p.url == wanted).map(|p| OidcProviderView {
            arn: p.arn.clone(),
            url: p.url.clone(),
            client_ids: p.client_ids.clone(),
        })
    }

    /// The default version of a managed policy.
    pub fn managed_policy_document(&self, arn: &str) -> Option<String> {
        self.read().policies.get(arn).map(|p| p.default_document().to_string())
    }

    /// Validate a session or identity policy document as IAM would.
    pub fn validate_identity_policy(&self, doc: &str) -> Result<(), ServiceError> {
        crate::common::validate_policy(doc, PolicyKind::Identity).map(|_| ())
    }

    /// Record that a role was used (for `RoleLastUsed`).
    pub fn note_role_used(&self, role_name: &str, region: &str) {
        if let Some(r) = self.write().role_mut(role_name) {
            r.last_used = Some((chrono::Utc::now(), region.to_string()));
        }
    }
}
