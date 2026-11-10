//! What Bedrock jobs read and write in S3, as the job's service role.
//!
//! Customization, import and evaluation jobs assume the role the caller
//! passed (as `bedrock.amazonaws.com`) and read their training data,
//! model weights and datasets from S3 with that role's permissions, as
//! AWS does. bedrock-runtime, which already reads S3 for batch inference,
//! installs the implementation ([`crate::Bedrock::set_job_storage`]);
//! without it the control plane skips those checks.

use std::sync::Arc;

use mws_core::RequestContext;

/// Opens S3 as a job's role.
pub trait JobStorage: Send + Sync {
    /// Assume `role_arn` as Bedrock for the job `source_arn` (the
    /// caller's account is the source account). The error is the message
    /// AWS gives when Bedrock cannot assume the role.
    fn assume(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        source_arn: &str,
        session: &str,
    ) -> Result<Arc<dyn RoleStorage>, String>;
}

/// S3 with one role's permissions. Errors are S3's messages.
pub trait RoleStorage: Send + Sync {
    fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, String>;
    /// Every key under `prefix`.
    fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, String>;
    fn put(&self, bucket: &str, key: &str, body: Vec<u8>, content_type: &str) -> Result<(), String>;
}

/// `s3://bucket/key` -> (bucket, key without a trailing slash).
pub fn s3_location(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("s3://")?;
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    (!bucket.is_empty()).then(|| (bucket.to_string(), key.trim_end_matches('/').to_string()))
}

pub fn join_key(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// The objects a URI names: the object itself, or every object under it
/// as a prefix.
pub fn objects(io: &dyn RoleStorage, uri: &str) -> Result<Vec<(String, String)>, String> {
    let (bucket, key) = s3_location(uri).ok_or_else(|| format!("The S3 URI {uri} is invalid."))?;
    if !key.is_empty() && !uri.ends_with('/') && io.get(&bucket, &key).is_ok() {
        return Ok(vec![(bucket, key)]);
    }
    let prefix = if key.is_empty() { String::new() } else { format!("{key}/") };
    Ok(io.list(&bucket, &prefix)?.into_iter().map(|k| (bucket.clone(), k)).collect())
}
