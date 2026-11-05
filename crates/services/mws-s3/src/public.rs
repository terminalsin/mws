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

fn service_allowed(b: &Bucket, put: &ServicePutObject<'_>, action: &str, resource: &str) -> bool {
    let Some(doc) = &b.policy else { return false };
    let Ok(policy) = Policy::parse(doc, PolicyKind::Resource) else { return false };
    let principal = PrincipalInfo { service: Some(put.service_principal.to_string()), ..Default::default() };
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
        let st = self.read();
        let b = st.buckets.get(put.bucket).ok_or(ServicePutError::NoSuchBucket)?;
        for action in actions {
            let resource = if matches!(*action, "s3:PutObject" | "s3:PutObjectAcl") {
                format!("arn:{}:s3:::{}/{}", put.partition, b.name, put.key)
            } else {
                format!("arn:{}:s3:::{}", put.partition, b.name)
            };
            if !service_allowed(b, put, action, &resource) {
                return Err(ServicePutError::AccessDenied { action: action.to_string() });
            }
        }
        Ok(())
    }

    /// Write an object as an AWS service principal. Returns the ETag.
    pub fn put_object_as_service(&self, put: ServicePutObject<'_>) -> Result<String, ServicePutError> {
        self.put_object_as_service_with(put, Sse::default())
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

/// An AWS service principal reading from a customer bucket (Amplify
/// deploying a site from a bucket). Access is decided by the bucket policy
/// alone, as for service principals in AWS.
#[derive(Debug, Clone)]
pub struct ServiceRead<'a> {
    pub bucket: &'a str,
    /// The service principal, e.g. `amplify.amazonaws.com`.
    pub service_principal: &'a str,
    /// `aws:SourceAccount` and `aws:SourceArn` for the bucket policy.
    pub source_account: &'a str,
    pub source_arn: &'a str,
    /// Partition for ARNs, normally `aws`.
    pub partition: &'a str,
}

impl ServiceRead<'_> {
    fn as_put(&self) -> ServicePutObject<'_> {
        ServicePutObject {
            bucket: self.bucket,
            key: "",
            body: Vec::new(),
            content_type: "",
            service_principal: self.service_principal,
            source_account: self.source_account,
            source_arn: self.source_arn,
            acl: None,
            partition: self.partition,
        }
    }
}

impl S3 {
    /// Read the latest version of `key` as an AWS service principal
    /// (`s3:GetObject` from the bucket policy). `Ok(None)` when there is no
    /// such object.
    pub fn get_object_as_service(&self, read: &ServiceRead<'_>, key: &str) -> Result<Option<Vec<u8>>, ServicePutError> {
        let st = self.read();
        let b = st.buckets.get(read.bucket).ok_or(ServicePutError::NoSuchBucket)?;
        let resource = format!("arn:{}:s3:::{}/{key}", read.partition, b.name);
        if !service_allowed(b, &read.as_put(), "s3:GetObject", &resource) {
            return Err(ServicePutError::AccessDenied { action: "s3:GetObject".into() });
        }
        Ok(b.latest(key).filter(|v| !v.delete_marker).map(|v| v.data.to_vec()))
    }

    /// The keys under `prefix`, as an AWS service principal
    /// (`s3:ListBucket` from the bucket policy, with `s3:prefix`).
    pub fn list_objects_as_service(
        &self,
        read: &ServiceRead<'_>,
        prefix: &str,
    ) -> Result<Vec<String>, ServicePutError> {
        let st = self.read();
        let b = st.buckets.get(read.bucket).ok_or(ServicePutError::NoSuchBucket)?;
        let Some(doc) = &b.policy else {
            return Err(ServicePutError::AccessDenied { action: "s3:ListBucket".into() });
        };
        let put = read.as_put();
        let allowed = Policy::parse(doc, PolicyKind::Resource).is_ok_and(|policy| {
            let principal = PrincipalInfo { service: Some(put.service_principal.to_string()), ..Default::default() };
            let mut context = ConditionContext::new();
            context.insert("aws:SourceAccount", vec![put.source_account.to_string()]);
            context.insert("aws:SourceArn", vec![put.source_arn.to_string()]);
            context.insert("aws:PrincipalServiceName", vec![put.service_principal.to_string()]);
            context.insert("aws:PrincipalIsAWSService", vec!["true".to_string()]);
            context.insert("s3:prefix", vec![prefix.to_string()]);
            let resource = format!("arn:{}:s3:::{}", put.partition, b.name);
            let eval = policy.evaluate(&Request {
                action: "s3:ListBucket",
                resource: &resource,
                principal: &principal,
                context: &context,
            });
            eval.allowed() && !eval.denied()
        });
        if !allowed {
            return Err(ServicePutError::AccessDenied { action: "s3:ListBucket".into() });
        }
        Ok(b.objects
            .iter()
            .filter(|(k, v)| k.starts_with(prefix) && v.last().is_some_and(|v| !v.delete_marker))
            .map(|(k, _)| k.clone())
            .collect())
    }
}
