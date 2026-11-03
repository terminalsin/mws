use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::ServiceError;

/// The authenticated identity behind a request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Caller {
    pub account_id: String,
    /// The principal ARN as `sts:GetCallerIdentity` would report it.
    pub arn: String,
    /// The unique id (`AIDA...`, `AROA...:session`, or the account id for root).
    pub user_id: String,
    pub access_key_id: String,
    pub kind: CallerKind,
    /// Set when the caller signed with temporary credentials.
    pub session: Option<SessionInfo>,
}

/// How temporary credentials were obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionKind {
    AssumeRole,
    AssumeRoleWithWebIdentity,
    GetSessionToken,
    GetFederationToken,
    AssumeRoleWithSAML,
    AssumeRoot,
    GetDelegatedAccessToken,
}

/// Facts about a temporary-credential session that affect authorization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub kind: SessionKind,
    /// Session policy documents (inline and resolved managed ones). Empty
    /// means no session policy was passed.
    pub policies: Vec<String>,
    /// Session tags (`aws:PrincipalTag/...`).
    pub tags: BTreeMap<String, String>,
    /// Tag keys that carry over when this session assumes another role.
    pub transitive_tag_keys: Vec<String>,
    pub source_identity: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub mfa_authenticated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallerKind {
    Root,
    User {
        name: String,
    },
    AssumedRole {
        role_name: String,
        session_name: String,
    },
    /// `GetFederationToken`. `parent_user` is the IAM user that called it,
    /// or `None` for the root user.
    FederatedUser {
        name: String,
        parent_user: Option<String>,
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
            session: None,
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
    /// How the resource policy takes part in the decision.
    pub resource_policy_mode: ResourcePolicyMode,
    pub context: ConditionContext,
}

/// How a resource policy combines with identity policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResourcePolicyMode {
    /// Either the resource policy or identity policies may grant access
    /// (bucket policies, CA policies, ...).
    #[default]
    Optional,
    /// The resource policy must allow the caller, directly or through its
    /// account; in the latter case identity policies must allow too. KMS key
    /// policies work this way.
    Required,
    /// A role trust policy: required, and parsed with trust-policy rules.
    Trust,
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
