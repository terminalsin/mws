//! What other services need from Private CA beyond its API: AWS RAM writes
//! the policies of shared CAs, and AWS services that issue from a shared CA
//! (Connector for SCEP) call it as their service principal. AWS couples the
//! services the same way: a RAM share of a CA is a resource policy on it,
//! and `PutPolicy` shows up in RAM as a share created from a policy.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use mws_core::ServiceError;
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::generated::types;
use crate::PrivateCa;

/// Told when `PutPolicy` or `DeletePolicy` changes a CA's own policy (AWS
/// RAM lists such policies as resource shares created from a policy).
pub trait CaPolicyListener: Send + Sync {
    fn policy_changed(&self, ca_arn: &str, owner_account: &str, policy: Option<&str>, now: DateTime<Utc>);
}

/// What a sharing service needs to know about a CA.
#[derive(Debug, Clone)]
pub struct CaInfo {
    pub arn: String,
    pub owner: String,
    pub status: String,
    pub usage_mode: String,
    pub key_algorithm: String,
    pub not_after: Option<DateTime<Utc>>,
    /// The CA's certificate, PEM, once it has one.
    pub certificate_pem: Option<String>,
    /// Certificates above the CA's own, PEM, nearest first.
    pub chain_pem: Option<String>,
}

/// An `IssueCertificate` made by an AWS service principal on behalf of
/// `source_account`.
#[derive(Debug, Clone)]
pub struct ServiceIssue<'a> {
    pub service_principal: &'a str,
    pub source_account: &'a str,
    pub source_arn: &'a str,
    pub ca_arn: &'a str,
    /// PEM.
    pub csr: &'a [u8],
    pub template_arn: &'a str,
    pub not_after: DateTime<Utc>,
    pub api_passthrough: Option<types::ApiPassthrough>,
    pub now: DateTime<Utc>,
}

/// Why a service principal could not issue.
#[derive(Debug, Clone)]
pub enum ServiceIssueError {
    NotFound,
    AccessDenied,
    /// Any other Private CA error (invalid state, bad CSR, ...).
    Refused(ServiceError),
}

impl From<ServiceError> for ServiceIssueError {
    fn from(e: ServiceError) -> Self {
        Self::Refused(e)
    }
}

/// A certificate issued for a service principal.
#[derive(Debug, Clone)]
pub struct ServiceIssued {
    pub certificate_arn: String,
    pub certificate_pem: String,
    /// The issuing CA's certificate and its chain, PEM.
    pub chain_pem: String,
}

fn signing_algorithm(key_algorithm: &str) -> &'static str {
    match key_algorithm {
        "EC_prime256v1" => "SHA256WITHECDSA",
        "EC_secp384r1" => "SHA384WITHECDSA",
        "EC_secp521r1" => "SHA512WITHECDSA",
        _ => "SHA256WITHRSA",
    }
}

impl PrivateCa {
    /// Register who hears about `PutPolicy` and `DeletePolicy`.
    pub fn set_policy_listener(&self, listener: Arc<dyn CaPolicyListener>) {
        *self.policy_listener.write().expect("listener lock poisoned") = Some(listener);
    }

    pub(crate) fn notify_policy(&self, arn: &str, owner: &str, policy: Option<&str>, now: DateTime<Utc>) {
        let listener = self.policy_listener.read().expect("listener lock poisoned").clone();
        if let Some(l) = listener {
            l.policy_changed(arn, owner, policy, now);
        }
    }

    /// The CA at `arn`, unless it does not exist or was deleted.
    pub fn ca_info(&self, arn: &str) -> Option<CaInfo> {
        let st = self.lock();
        let ca = st.cas.get(arn).filter(|c| c.status != "DELETED")?;
        Some(CaInfo {
            arn: ca.arn.clone(),
            owner: ca.owner.clone(),
            status: ca.status.clone(),
            usage_mode: ca.usage_mode.clone().unwrap_or_else(|| "GENERAL_PURPOSE".into()),
            key_algorithm: ca.config.key_algorithm.clone(),
            not_after: ca.not_after,
            certificate_pem: ca.cert_pem.clone(),
            chain_pem: ca.chain_pem.clone(),
        })
    }

    /// Install (or with `None` remove) the policy AWS RAM computed from the
    /// shares the CA is in. Kept apart from the `PutPolicy` policy; both
    /// are evaluated and `GetPolicy` shows them together.
    pub fn set_shared_policy(&self, arn: &str, policy: Option<String>) {
        if let Some(ca) = self.lock().cas.get_mut(arn) {
            ca.ram_policy = policy;
        }
    }

    /// Whether `service_principal`, acting for `source_account`, may perform
    /// `acm-pca:{action}` on the CA: its resource policy alone decides, as
    /// for any service principal.
    pub fn service_allowed(
        &self,
        service_principal: &str,
        source_account: &str,
        source_arn: &str,
        ca_arn: &str,
        action: &str,
        template_arn: Option<&str>,
    ) -> bool {
        let Some(doc) = self.lock().cas.get(ca_arn).and_then(|c| c.effective_policy()) else { return false };
        let Ok(policy) = Policy::parse(&doc, PolicyKind::Resource) else { return false };
        let principal = PrincipalInfo { service: Some(service_principal.to_string()), ..Default::default() };
        let mut context = ConditionContext::new();
        context.insert("aws:SourceAccount", vec![source_account.to_string()]);
        context.insert("aws:SourceArn", vec![source_arn.to_string()]);
        context.insert("aws:PrincipalServiceName", vec![service_principal.to_string()]);
        context.insert("aws:PrincipalIsAWSService", vec!["true".to_string()]);
        if let Some(t) = template_arn {
            context.insert("acm-pca:TemplateArn", vec![t.to_string()]);
        }
        let action = format!("acm-pca:{action}");
        let eval = policy.evaluate(&Request { action: &action, resource: ca_arn, principal: &principal, context: &context });
        eval.allowed() && !eval.denied()
    }

    /// Issue a certificate as an AWS service principal. The CA's policy
    /// must allow `acm-pca:IssueCertificate` (and `acm-pca:GetCertificate`)
    /// for the principal.
    pub fn issue_as_service(&self, req: ServiceIssue<'_>) -> Result<ServiceIssued, ServiceIssueError> {
        self.advance(req.now);
        let key_algorithm = match self.lock().cas.get(req.ca_arn) {
            Some(ca) if ca.status != "DELETED" => ca.config.key_algorithm.clone(),
            _ => return Err(ServiceIssueError::NotFound),
        };
        let allowed = |action: &str, template: Option<&str>| {
            self.service_allowed(req.service_principal, req.source_account, req.source_arn, req.ca_arn, action, template)
        };
        if !allowed("IssueCertificate", Some(req.template_arn)) || !allowed("GetCertificate", None) {
            return Err(ServiceIssueError::AccessDenied);
        }
        let issued = self.issue_authorized(
            types::IssueCertificateRequest {
                certificate_authority_arn: req.ca_arn.to_string(),
                csr: req.csr.to_vec(),
                signing_algorithm: signing_algorithm(&key_algorithm).into(),
                template_arn: Some(req.template_arn.into()),
                validity: types::Validity { value: req.not_after.timestamp(), r#type: "ABSOLUTE".into() },
                api_passthrough: req.api_passthrough,
                ..Default::default()
            },
            req.now,
        )?;
        let certificate_arn = issued.certificate_arn.unwrap_or_default();
        let st = self.lock();
        let ca = st.ca(req.ca_arn)?;
        let id = certificate_arn.rsplit('/').next().unwrap_or_default();
        let certificate_pem = ca.certs.get(id).map(|c| c.pem.clone()).unwrap_or_default();
        let chain_pem = ca.full_chain_pem().unwrap_or_default();
        Ok(ServiceIssued { certificate_arn, certificate_pem, chain_pem })
    }
}
