//! What Amplify reaches in other services, as AWS couples them: IAM roles
//! (`iamServiceRoleArn`, `computeRoleArn`), STS (builds run with the app's
//! service role), SSM Parameter Store (Amplify secrets) and ACM (custom
//! certificates). MWS wires an implementation in; on its own, Amplify skips
//! those checks and builds run without credentials or secrets.

use mws_core::RequestContext;

/// Temporary credentials for a role session, and a request context that
/// acts as that session.
#[derive(Clone)]
pub struct RoleSession {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub context: RequestContext,
}

/// The ACM certificate a custom domain names.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub account: String,
    pub region: String,
    /// `ISSUED`, `PENDING_VALIDATION`, `EXPIRED`, ...
    pub status: String,
    pub domain_name: String,
    pub subject_alternative_names: Vec<String>,
}

#[async_trait::async_trait]
pub trait AmplifyPlatform: Send + Sync {
    /// Whether `role_arn` names an existing IAM role.
    fn role_exists(&self, role_arn: &str) -> bool;

    /// Assume `role_arn` as `amplify.amazonaws.com`, judged by its trust
    /// policy with `aws:SourceAccount`/`aws:SourceArn` (the app). The
    /// session's context is `template` with the role's identity.
    fn assume_role(
        &self,
        template: &RequestContext,
        role_arn: &str,
        session_name: &str,
        source_account: &str,
        source_arn: &str,
    ) -> Result<RoleSession, String>;

    /// The SSM parameters under `path` (recursively, decrypted), as
    /// `(name, value)`, read with `ctx`'s identity.
    async fn parameters_by_path(&self, ctx: &RequestContext, path: &str) -> Result<Vec<(String, String)>, String>;

    /// The ACM certificate `arn`.
    fn certificate(&self, arn: &str) -> Option<CertificateInfo>;
}
