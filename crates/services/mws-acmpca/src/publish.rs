//! Writing CRLs and audit reports into S3, as ACM PCA does: the service
//! principal `acm-pca.amazonaws.com` puts objects into the customer's
//! bucket, which the bucket policy must allow. ACM PCA checks that access
//! when a CRL bucket is configured, and when an audit report is requested.

use mws_core::ServiceError;
use mws_s3::{ServicePutError, ServicePutObject};

use crate::generated::{errors, types};
use crate::revocation::{crl_config, crl_key};
use crate::state::Ca;
use crate::PrivateCa;

pub const SERVICE_PRINCIPAL: &str = "acm-pca.amazonaws.com";

fn partition(arn: &str) -> &str {
    arn.split(':').nth(1).unwrap_or("aws")
}

fn account(arn: &str) -> &str {
    arn.split(':').nth(4).unwrap_or_default()
}

/// The canned ACL for a CRL configuration's `S3ObjectAcl`.
fn crl_acl(c: &types::CrlConfiguration) -> &'static str {
    match c.s3_object_acl.as_deref() {
        Some("BUCKET_OWNER_FULL_CONTROL") => "bucket-owner-full-control",
        _ => "public-read",
    }
}

fn access_error(bucket: &str, e: ServicePutError) -> ServiceError {
    match e {
        ServicePutError::NoSuchBucket => errors::invalid_args(format!("The S3 bucket {bucket} does not exist.")),
        ServicePutError::AccessDenied { action } => errors::invalid_args(format!(
            "The ACM Private CA Service Principal '{SERVICE_PRINCIPAL}' requires '{action}' permissions for the S3 bucket '{bucket}'."
        )),
        ServicePutError::AclRefused => errors::invalid_args(format!(
            "The S3 bucket {bucket} does not allow the object ACL ACM Private CA uses. Block Public Access or ACLs disabled on the bucket prevent public-read CRLs; set S3ObjectAcl to BUCKET_OWNER_FULL_CONTROL."
        )),
        ServicePutError::Kms(m) => errors::invalid_args(m),
    }
}

impl PrivateCa {
    /// Check that ACM PCA could publish CRLs for `ca_arn` with `config`.
    pub(crate) fn check_crl_bucket(
        &self,
        ca_arn: &str,
        config: Option<&types::RevocationConfiguration>,
    ) -> Result<(), ServiceError> {
        let Some(s3) = &self.s3 else { return Ok(()) };
        let Some(c) = config.and_then(|r| r.crl_configuration.as_ref()).filter(|c| c.enabled) else {
            return Ok(());
        };
        let Some(bucket) = c.s3_bucket_name.as_deref() else { return Ok(()) };
        let acl = crl_acl(c);
        let put = ServicePutObject {
            bucket,
            key: "crl/",
            body: Vec::new(),
            content_type: "application/pkix-crl",
            service_principal: SERVICE_PRINCIPAL,
            source_account: account(ca_arn),
            source_arn: ca_arn,
            acl: Some(acl),
            partition: partition(ca_arn),
        };
        let mut actions = vec!["s3:GetBucketAcl", "s3:GetBucketLocation", "s3:PutObject"];
        if acl == "public-read" {
            actions.push("s3:PutObjectAcl");
        }
        s3.check_service_access(&put, &actions).map_err(|e| access_error(bucket, e))
    }

    /// Write the CA's current CRL to its bucket. Like ACM PCA, a failed
    /// publish does not fail the operation that changed the CRL.
    pub(crate) fn publish_crl(&self, ca: &Ca) {
        let (Some(s3), Some(c), Some(key), Some(crl)) = (&self.s3, crl_config(ca), crl_key(ca), &ca.crl) else {
            return;
        };
        let Some(bucket) = c.s3_bucket_name.as_deref() else { return };
        let result = s3.put_object_as_service(ServicePutObject {
            bucket,
            key: &key,
            body: crl.der.clone(),
            content_type: "application/pkix-crl",
            service_principal: SERVICE_PRINCIPAL,
            source_account: &ca.owner,
            source_arn: &ca.arn,
            acl: Some(crl_acl(c)),
            partition: partition(&ca.arn),
        });
        if let Err(e) = result {
            tracing::warn!(ca = %ca.arn, bucket, "CRL not published: {e}");
        }
    }

    /// Write an audit report to `bucket`.
    pub(crate) fn publish_audit_report(
        &self,
        ca: &Ca,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), ServiceError> {
        let Some(s3) = &self.s3 else { return Ok(()) };
        let put = ServicePutObject {
            bucket,
            key,
            body,
            content_type,
            service_principal: SERVICE_PRINCIPAL,
            source_account: &ca.owner,
            source_arn: &ca.arn,
            acl: None,
            partition: partition(&ca.arn),
        };
        s3.check_service_access(&put, &["s3:GetBucketAcl", "s3:GetBucketLocation", "s3:PutObject"])
            .and_then(|()| s3.put_object_as_service(put).map(|_| ()))
            .map_err(|e| access_error(bucket, e))
    }
}
