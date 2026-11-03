//! What AWS Certificate Manager needs from Private CA: issuing end-entity
//! certificates for key pairs ACM generated. AWS couples the two services
//! the same way (ACM private certificates are issued by Private CA).

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::ops::check_arn;
use crate::PrivateCa;

const END_ENTITY_TEMPLATE: &str = "arn:aws:acm-pca:::template/EndEntityCertificate/V1";

/// Who ACM is acting as when it asks for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmIssuer {
    /// `RequestCertificate`: ACM calls Private CA with the requester's
    /// credentials, so IAM and the CA policy must allow
    /// `acm-pca:IssueCertificate` (and `acm-pca:GetCertificate`).
    Caller,
    /// Managed renewal: ACM's service principal, which needs a
    /// `CreatePermission` grant for `acm.amazonaws.com` on the CA (or a CA
    /// policy allowing it) for the certificate's account.
    ServicePrincipal,
}

/// A certificate Private CA issued for ACM.
#[derive(Debug, Clone)]
pub struct AcmIssued {
    pub certificate_arn: String,
    pub certificate_pem: String,
    /// The issuing CA's certificate and its chain, PEM.
    pub chain_pem: String,
}

/// What ACM shows about the CA behind a private certificate.
#[derive(Debug, Clone)]
pub struct AcmCaSummary {
    pub status: String,
    pub key_algorithm: String,
    pub owner: String,
    pub not_after: Option<DateTime<Utc>>,
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
    /// The CA at `arn`, if it exists.
    pub fn ca_for_acm(&self, arn: &str) -> Option<AcmCaSummary> {
        let st = self.lock();
        let ca = st.cas.get(arn)?;
        Some(AcmCaSummary {
            status: ca.status.clone(),
            key_algorithm: ca.config.key_algorithm.clone(),
            owner: ca.owner.clone(),
            not_after: ca.not_after,
        })
    }

    /// Issue an end-entity certificate for `csr_pem`, valid until
    /// `not_after`, as `issuer`. `account` is the account the certificate
    /// is for (the requester's).
    pub fn issue_for_acm(
        &self,
        ctx: &RequestContext,
        ca_arn: &str,
        csr_pem: &str,
        not_after: DateTime<Utc>,
        issuer: AcmIssuer,
        account: &str,
    ) -> Result<AcmIssued, ServiceError> {
        check_arn(ctx, ca_arn)?;
        let mut cond = ConditionContext::new();
        cond.insert("acm-pca:TemplateArn".into(), vec![END_ENTITY_TEMPLATE.into()]);
        match issuer {
            AcmIssuer::Caller => {
                self.authorize_with(ctx, "IssueCertificate", ca_arn, cond)?;
                self.authorize(ctx, "GetCertificate", ca_arn)?;
            }
            AcmIssuer::ServicePrincipal => self.check_acm_permission(ca_arn, account)?,
        }
        let key_algorithm = {
            let st = self.lock();
            st.ca(ca_arn)?.config.key_algorithm.clone()
        };
        let issued = self.issue_authorized(types::IssueCertificateRequest {
            certificate_authority_arn: ca_arn.to_string(),
            csr: csr_pem.as_bytes().to_vec(),
            signing_algorithm: signing_algorithm(&key_algorithm).into(),
            template_arn: Some(END_ENTITY_TEMPLATE.into()),
            validity: types::Validity { value: not_after.timestamp(), r#type: "ABSOLUTE".into() },
            ..Default::default()
        })?;
        let certificate_arn = issued.certificate_arn.unwrap_or_default();
        let st = self.lock();
        let ca = st.ca(ca_arn)?;
        let id = certificate_arn.rsplit('/').next().unwrap_or_default();
        let certificate_pem = ca.certs.get(id).map(|c| c.pem.clone()).unwrap_or_default();
        let chain_pem = ca.full_chain_pem().unwrap_or_default();
        Ok(AcmIssued { certificate_arn, certificate_pem, chain_pem })
    }

    /// Whether ACM's service principal may issue from `ca_arn` for
    /// `account` (managed renewal).
    fn check_acm_permission(&self, ca_arn: &str, account: &str) -> Result<(), ServiceError> {
        let st = self.lock();
        let ca = st.ca(ca_arn)?;
        let granted = ca.permissions.iter().any(|p| {
            p.principal.as_deref() == Some("acm.amazonaws.com")
                && p.source_account.as_deref().is_none_or(|a| a == account)
                && p.actions.as_ref().is_some_and(|a| a.iter().any(|x| x == "IssueCertificate"))
        });
        if granted {
            Ok(())
        } else {
            Err(ServiceError::client(
                "AccessDeniedException",
                400,
                format!("The certificate authority {ca_arn} has not granted acm.amazonaws.com permission to issue certificates."),
            ))
        }
    }
}
