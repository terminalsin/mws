//! Credentials STS issues to AWS service principals that assume customer
//! roles (Lambda running a function as its execution role). AWS couples
//! those services to STS the same way.

use chrono::{DateTime, Utc};
use mws_core::{SessionInfo, SessionKind};
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::Sts;

/// Temporary credentials for a role session.
#[derive(Debug, Clone)]
pub struct ServiceCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime<Utc>,
    /// `arn:aws:sts::<account>:assumed-role/<role>/<session>`.
    pub assumed_role_arn: String,
}

/// Why a service could not assume a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceAssumeError {
    NoSuchRole,
    /// The role's trust policy does not let the service assume it.
    NotTrusted,
}

/// A service principal assuming a role.
#[derive(Debug, Clone)]
pub struct ServiceAssume<'a> {
    pub role_arn: &'a str,
    /// e.g. `lambda.amazonaws.com`.
    pub service_principal: &'a str,
    pub session_name: &'a str,
    pub duration_seconds: i32,
    /// `aws:SourceAccount` / `aws:SourceArn` for the trust policy.
    pub source_account: Option<&'a str>,
    pub source_arn: Option<&'a str>,
    pub now: DateTime<Utc>,
}

impl Sts {
    /// Whether `service` may assume `role_arn` according to its trust
    /// policy.
    pub fn service_can_assume(&self, a: &ServiceAssume<'_>) -> Result<(), ServiceAssumeError> {
        let role = self.iam().role_by_arn(a.role_arn).ok_or(ServiceAssumeError::NoSuchRole)?;
        let policy =
            Policy::parse(&role.trust_policy, PolicyKind::Trust).map_err(|_| ServiceAssumeError::NotTrusted)?;
        let principal = PrincipalInfo { service: Some(a.service_principal.to_string()), ..Default::default() };
        let mut context = ConditionContext::new();
        context.insert("aws:PrincipalServiceName", vec![a.service_principal.to_string()]);
        if let Some(acct) = a.source_account {
            context.insert("aws:SourceAccount", vec![acct.to_string()]);
        }
        if let Some(arn) = a.source_arn {
            context.insert("aws:SourceArn", vec![arn.to_string()]);
        }
        let eval = policy.evaluate(&Request {
            action: "sts:AssumeRole",
            resource: &role.arn,
            principal: &principal,
            context: &context,
        });
        if eval.allowed() && !eval.denied() {
            Ok(())
        } else {
            Err(ServiceAssumeError::NotTrusted)
        }
    }

    /// Issue role credentials to a service principal, as `AssumeRole`
    /// called by that service would.
    pub fn assume_role_as_service(&self, a: &ServiceAssume<'_>) -> Result<ServiceCredentials, ServiceAssumeError> {
        self.assume_role_as_service_with_policy(a, None)
    }

    /// Like [`Sts::assume_role_as_service`], with a session policy that
    /// narrows what the credentials may do (S3 Access Grants scope the
    /// credentials they vend this way).
    pub fn assume_role_as_service_with_policy(
        &self,
        a: &ServiceAssume<'_>,
        session_policy: Option<String>,
    ) -> Result<ServiceCredentials, ServiceAssumeError> {
        self.service_can_assume(a)?;
        let role = self.iam().role_by_arn(a.role_arn).ok_or(ServiceAssumeError::NoSuchRole)?;
        let caller = self.assumed_role_caller(&role, a.session_name);
        let arn = caller.arn.clone();
        let issued = self.issue(
            caller,
            a.duration_seconds,
            SessionInfo {
                kind: SessionKind::AssumeRole,
                policies: session_policy.into_iter().collect(),
                tags: Default::default(),
                transitive_tag_keys: Vec::new(),
                source_identity: None,
                issued_at: a.now,
                expires_at: a.now,
                mfa_authenticated: false,
            },
        );
        let c = issued.credentials;
        Ok(ServiceCredentials {
            access_key_id: c.access_key_id,
            secret_access_key: c.secret_access_key,
            session_token: c.session_token,
            expiration: c.expiration,
            assumed_role_arn: arn,
        })
    }
}

/// A service that federates its own users into a role through a SAML
/// provider it controls (IAM Identity Center signing users in to
/// `AWSReservedSSO_*` roles), as if it called `AssumeRoleWithSAML` with an
/// assertion its identity provider signed.
#[derive(Debug, Clone)]
pub struct SamlFederation<'a> {
    pub role_arn: &'a str,
    /// The SAML provider in the role's account the trust policy names.
    pub provider_arn: &'a str,
    /// The assertion's audience (`SAML:aud`).
    pub audience: &'a str,
    pub session_name: &'a str,
    pub duration_seconds: i32,
    /// Session tags the assertion carries (`aws:PrincipalTag/...`).
    pub tags: std::collections::BTreeMap<String, String>,
    /// Where the role was used from, for its last-used data.
    pub region: &'a str,
    pub now: DateTime<Utc>,
}

impl Sts {
    /// Issue credentials for a SAML federation, judged by the role's trust
    /// policy as `AssumeRoleWithSAML` (and `TagSession`, with tags) would be.
    pub fn assume_role_with_saml_as_service(
        &self,
        a: &SamlFederation<'_>,
    ) -> Result<ServiceCredentials, ServiceAssumeError> {
        let role = self.iam().role_by_arn(a.role_arn).ok_or(ServiceAssumeError::NoSuchRole)?;
        let policy =
            Policy::parse(&role.trust_policy, PolicyKind::Trust).map_err(|_| ServiceAssumeError::NotTrusted)?;
        let principal = PrincipalInfo { federated: Some(a.provider_arn.to_string()), ..Default::default() };
        let mut context = ConditionContext::new();
        context.insert("SAML:aud", vec![a.audience.to_string()]);
        for (k, v) in &a.tags {
            context.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        }
        if !a.tags.is_empty() {
            context.insert("aws:TagKeys", a.tags.keys().cloned().collect());
        }
        let mut actions = vec!["sts:AssumeRoleWithSAML"];
        if !a.tags.is_empty() {
            actions.push("sts:TagSession");
        }
        for action in actions {
            let eval =
                policy.evaluate(&Request { action, resource: &role.arn, principal: &principal, context: &context });
            if !eval.allowed() || eval.denied() {
                return Err(ServiceAssumeError::NotTrusted);
            }
        }
        let caller = self.assumed_role_caller(&role, a.session_name);
        let arn = caller.arn.clone();
        let issued = self.issue(
            caller,
            a.duration_seconds,
            SessionInfo {
                kind: SessionKind::AssumeRoleWithSAML,
                policies: Vec::new(),
                tags: a.tags.clone(),
                transitive_tag_keys: Vec::new(),
                source_identity: None,
                issued_at: a.now,
                expires_at: a.now,
                mfa_authenticated: false,
            },
        );
        self.iam().note_role_used(&role, a.region);
        let c = issued.credentials;
        Ok(ServiceCredentials {
            access_key_id: c.access_key_id,
            secret_access_key: c.secret_access_key,
            session_token: c.session_token,
            expiration: c.expiration,
            assumed_role_arn: arn,
        })
    }
}

impl Sts {
    /// Check a JWT's signature as `AssumeRoleWithWebIdentity` does (MWS's own
    /// keys for tokens MWS issued, else the issuer's JWKS through OpenID
    /// Connect discovery), for services that also accept tokens from
    /// external identity providers (IAM Identity Center trusted token
    /// issuers). Honours `MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION`.
    pub async fn verify_identity_provider_token(&self, token: &str, issuer: &str) -> Result<(), String> {
        if !self.inner.verify_federation_signatures {
            return Ok(());
        }
        self.verify_web_identity_signature(token, issuer, &[]).await.map_err(|e| e.message)
    }
}
