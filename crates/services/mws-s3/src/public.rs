//! What other MWS services may do to S3 directly, where AWS couples them:
//! AWS service principals (e.g. `acm-pca.amazonaws.com` publishing CRLs
//! and audit reports) writing objects into customer buckets. Access is
//! decided by the bucket policy alone, as for service principals in AWS.

use std::fmt;

use bytes::Bytes;
use chrono::Utc;
use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::acl;
use crate::checksum;
use crate::state::{Bucket, Checksum, ObjectVersion, Sse};
use crate::S3;

/// An object written by an AWS service principal.
#[derive(Debug, Clone)]
pub struct ServicePutObject<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub body: Vec<u8>,
    pub content_type: &'a str,
    /// The service principal, e.g. `acm-pca.amazonaws.com`.
    pub service_principal: &'a str,
    /// `aws:SourceAccount` and `aws:SourceArn` for the bucket policy.
    pub source_account: &'a str,
    pub source_arn: &'a str,
    /// Canned ACL to apply (`public-read`, `bucket-owner-full-control`).
    pub acl: Option<&'a str>,
    /// Partition for ARNs, normally `aws`.
    pub partition: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicePutError {
    NoSuchBucket,
    /// The bucket policy does not let the service principal perform this
    /// action.
    AccessDenied {
        action: String,
    },
    /// The ACL was refused (ACLs disabled, or public ACLs blocked).
    AclRefused,
}

impl fmt::Display for ServicePutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServicePutError::NoSuchBucket => write!(f, "The specified bucket does not exist"),
            ServicePutError::AccessDenied { action } => write!(f, "Access Denied for {action}"),
            ServicePutError::AclRefused => write!(f, "The bucket does not allow the requested ACL"),
        }
    }
}

impl std::error::Error for ServicePutError {}

fn service_allowed(
    b: &Bucket,
    put: &ServicePutObject<'_>,
    action: &str,
    resource: &str,
    account: Option<&str>,
) -> bool {
    let Some(doc) = &b.policy else { return false };
    let Ok(policy) = Policy::parse(doc, PolicyKind::Resource) else { return false };
    let principal = match account {
        // An AWS-owned account delivering for the service: policies name
        // it as `{"AWS": "arn:aws:iam::<account>:root"}`.
        Some(a) => PrincipalInfo {
            account_id: a.to_string(),
            arns: vec![format!("arn:{}:iam::{a}:root", put.partition)],
            ..Default::default()
        },
        None => PrincipalInfo { service: Some(put.service_principal.to_string()), ..Default::default() },
    };
    let mut context = ConditionContext::new();
    context.insert("aws:SourceAccount", vec![put.source_account.to_string()]);
    context.insert("aws:SourceArn", vec![put.source_arn.to_string()]);
    context.insert("aws:PrincipalServiceName", vec![put.service_principal.to_string()]);
    context.insert("aws:PrincipalIsAWSService", vec!["true".to_string()]);
    if let Some(a) = put.acl {
        context.insert("s3:x-amz-acl", vec![a.to_string()]);
    }
    let eval = policy.evaluate(&Request { action, resource, principal: &principal, context: &context });
    eval.allowed() && !eval.denied()
}

impl S3 {
    /// Check that a service principal may write to `bucket` the way AWS
    /// services verify before relying on a bucket (`s3:PutObject`, plus
    /// `s3:GetBucketAcl`, `s3:GetBucketLocation` and `s3:PutObjectAcl` when
    /// listed in `actions`).
    pub fn check_service_access(&self, put: &ServicePutObject<'_>, actions: &[&str]) -> Result<(), ServicePutError> {
        self.check_access_as(put, actions, None)
    }

    /// [`S3::check_service_access`] for an AWS-owned account that delivers
    /// on the service's behalf, as the bucket policy names it (Elastic Load
    /// Balancing's log delivery accounts in older Regions).
    pub fn check_service_account_access(
        &self,
        put: &ServicePutObject<'_>,
        actions: &[&str],
        account: &str,
    ) -> Result<(), ServicePutError> {
        self.check_access_as(put, actions, Some(account))
    }

    fn check_access_as(
        &self,
        put: &ServicePutObject<'_>,
        actions: &[&str],
        account: Option<&str>,
    ) -> Result<(), ServicePutError> {
        let st = self.read();
        let b = st.buckets.get(put.bucket).ok_or(ServicePutError::NoSuchBucket)?;
        for action in actions {
            let resource = if matches!(*action, "s3:PutObject" | "s3:PutObjectAcl") {
                format!("arn:{}:s3:::{}/{}", put.partition, b.name, put.key)
            } else {
                format!("arn:{}:s3:::{}", put.partition, b.name)
            };
            if !service_allowed(b, put, action, &resource, account) {
                return Err(ServicePutError::AccessDenied { action: action.to_string() });
            }
        }
        Ok(())
    }

    /// Write an object as an AWS service principal. Returns the ETag.
    pub fn put_object_as_service(&self, put: ServicePutObject<'_>) -> Result<String, ServicePutError> {
        self.put_object_as_service_with(put, Sse::default())
    }

    /// [`S3::put_object_as_service`] authorized for an AWS-owned delivery
    /// account instead of the service principal (see
    /// [`S3::check_service_account_access`]).
    pub fn put_object_as_service_account(
        &self,
        put: ServicePutObject<'_>,
        account: &str,
    ) -> Result<String, ServicePutError> {
        self.check_service_account_access(&put, &["s3:PutObject"], account)?;
        self.store_service_object(put, Sse::default())
    }

    /// [`S3::put_object_as_service`], encrypted with SSE-KMS under
    /// `kms_key` (a key id, alias or ARN). The service principal must be
    /// allowed `kms:GenerateDataKey` on the key, with the put's source
    /// account and ARN as conditions.
    pub fn put_object_as_service_kms(&self, put: ServicePutObject<'_>, kms_key: &str) -> Result<String, String> {
        let sse = self.service_kms_sse(&put, kms_key)?;
        self.put_object_as_service_with(put, sse).map_err(|e| e.to_string())
    }

    /// SSE-KMS for an object a service principal writes.
    pub(crate) fn service_kms_sse(&self, put: &ServicePutObject<'_>, kms_key: &str) -> Result<Sse, String> {
        let Some(kms) = &self.kms else {
            return Ok(Sse { algorithm: Some("aws:kms".into()), kms_key_id: Some(kms_key.into()), ..Sse::default() });
        };
        let mut conditions = mws_core::ConditionContext::new();
        conditions.insert("aws:SourceArn".into(), vec![put.source_arn.to_string()]);
        conditions.insert("aws:SourceAccount".into(), vec![put.source_account.to_string()]);
        let k = kms
            .key_for_service(kms_key, put.service_principal, &["kms:GenerateDataKey"], &conditions)
            .map_err(|e| e.message)?;
        let context = std::collections::BTreeMap::from([(
            "aws:s3:arn".to_string(),
            format!("arn:{}:s3:::{}/{}", put.partition, put.bucket, put.key),
        )]);
        let dk = kms.generate_data_key_for_service(&k.arn, &context, 32).map_err(|e| e.message)?;
        Ok(Sse {
            algorithm: Some("aws:kms".into()),
            kms_key_id: Some(dk.key_arn),
            kms_data_key: Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &dk.ciphertext)),
            ..Sse::default()
        })
    }

    /// [`S3::put_object_as_service`] with the object's encryption.
    pub(crate) fn put_object_as_service_with(
        &self,
        put: ServicePutObject<'_>,
        sse: Sse,
    ) -> Result<String, ServicePutError> {
        // As for any PutObject, an `x-amz-acl` needs only `s3:PutObject`
        // (policies can test it with the `s3:x-amz-acl` condition key).
        self.check_service_access(&put, &["s3:PutObject"])?;
        self.store_service_object(put, sse)
    }

    /// Write an object a service is allowed to put.
    fn store_service_object(&self, put: ServicePutObject<'_>, sse: Sse) -> Result<String, ServicePutError> {
        let mut st = self.write();
        let b = st.buckets.get_mut(put.bucket).ok_or(ServicePutError::NoSuchBucket)?;
        let grants = match put.acl {
            None | Some("bucket-owner-full-control") => acl::canned("private", &b.owner, &b.owner).unwrap_or_default(),
            Some(a) => {
                if !b.acls_enabled() {
                    return Err(ServicePutError::AclRefused);
                }
                let g = acl::canned(a, &b.owner, &b.owner).map_err(|_| ServicePutError::AclRefused)?;
                if b.pab().block_public_acls.unwrap_or(false) && acl::is_public(&g) {
                    return Err(ServicePutError::AclRefused);
                }
                g
            }
        };
        let data = Bytes::from(put.body);
        let etag = checksum::etag(&data);
        let version = ObjectVersion {
            last_modified: Utc::now(),
            etag: etag.clone(),
            owner: b.owner.clone(),
            content_type: Some(put.content_type.to_string()),
            checksum: Some(Checksum {
                algorithm: "CRC64NVME".into(),
                value: checksum::compute("CRC64NVME", &data).unwrap_or_default(),
                kind: "FULL_OBJECT".into(),
            }),
            acl: grants,
            sse,
            data,
            ..ObjectVersion::default()
        };
        b.insert_version(put.key, version);
        Ok(etag)
    }

    /// The latest content of an object, bypassing authorization: for tests
    /// and for services that read what they wrote.
    pub fn object_bytes(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
        let st = self.read();
        let v = st.buckets.get(bucket)?.latest(key)?;
        (!v.delete_marker).then(|| v.data.to_vec())
    }
}

impl S3 {
    /// `GetObject` with the caller's own permissions, for services that
    /// read an object the caller names (ELB trust store bundles and
    /// revocation lists): S3 authorizes it as the caller's request.
    pub fn get_object_as_caller(
        &self,
        ctx: &mws_core::RequestContext,
        input: crate::generated::types::GetObjectRequest,
    ) -> Result<crate::generated::types::GetObjectOutput, mws_core::ServiceError> {
        self.call(ctx, None).get_object(ctx, input)
    }

    /// The account that owns `bucket`, if it exists (S3 Control checks
    /// this when creating access points).
    pub fn bucket_owner(&self, bucket: &str) -> Option<String> {
        self.read().buckets.get(bucket).map(|b| b.owner.clone())
    }

    /// The Region `bucket` lives in, if it exists.
    pub fn bucket_region(&self, bucket: &str) -> Option<String> {
        self.read().buckets.get(bucket).map(|b| b.region.clone())
    }
}
