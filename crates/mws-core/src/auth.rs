use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::ServiceError;

/// The authenticated identity behind a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub account_id: String,
    /// The principal ARN as `sts:GetCallerIdentity` would report it.
    pub arn: String,
    /// The unique id (`AIDA...`, `AROA...:session`, or the account id for root).
    pub user_id: String,
    pub access_key_id: String,
    pub kind: CallerKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerKind {
    Root,
    User {
        name: String,
    },
    AssumedRole {
        role_name: String,
        session_name: String,
    },
    FederatedUser {
        name: String,
    },
    /// An unsigned request, for the few operations AWS accepts without a
    /// signature (e.g. `sts:AssumeRoleWithWebIdentity`).
    Anonymous,
}

impl Caller {
    pub fn anonymous() -> Self {
        Self {
            account_id: String::new(),
            arn: "anonymous".into(),
            user_id: "anonymous".into(),
            access_key_id: String::new(),
            kind: CallerKind::Anonymous,
        }
    }
}

/// What a credential store hands back for an access key.
#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    pub secret_access_key: String,
    pub caller: Caller,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// No store recognises the key.
    UnknownAccessKey,
    /// The key exists but is disabled, or the session token is wrong.
    Invalid,
    /// Temporary credentials whose expiry has passed.
    Expired,
}

impl CredentialError {
    pub fn into_service_error(self) -> ServiceError {
        match self {
            CredentialError::UnknownAccessKey | CredentialError::Invalid => ServiceError::invalid_client_token_id(),
            CredentialError::Expired => ServiceError::expired_token(),
        }
    }
}

/// Resolves access key ids to secrets and identities.
pub trait CredentialStore: Send + Sync {
    /// Return `Ok(None)` when this store does not own the key, so the next
    /// store can try.
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<ResolvedCredential>, CredentialError>;
}

/// Global and service-specific condition keys and their values, e.g.
/// `aws:SourceIp` or `iam:PassedToService`.
pub type ConditionContext = BTreeMap<String, Vec<String>>;

/// One authorization question: may `caller` perform `action` on `resource`?
#[derive(Debug, Clone)]
pub struct AuthzRequest<'a> {
    pub caller: &'a Caller,
    /// Fully qualified action, e.g. `iam:CreateUser`.
    pub action: &'a str,
    /// Resource ARN, or `*` for actions without a resource.
    pub resource: &'a str,
    /// Resource-based policy attached to the resource, if the service has one.
    pub resource_policy: Option<&'a str>,
    pub context: ConditionContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    /// Denied. `reason` follows AWS's wording, e.g.
    /// `because no identity-based policy allows the iam:CreateUser action`.
    Deny {
        reason: String,
    },
}

/// Decides whether a request is allowed. Services call this from their
/// handlers; MWS's IAM crate provides the real implementation.
pub trait Authorizer: Send + Sync {
    fn authorize(&self, request: &AuthzRequest<'_>) -> AuthzDecision;
}

/// Allows everything. Used until a real authorizer is plugged in.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(&self, _request: &AuthzRequest<'_>) -> AuthzDecision {
        AuthzDecision::Allow
    }
}
