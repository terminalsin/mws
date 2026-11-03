//! Directory buckets (S3 Express One Zone): zonal buckets named
//! `name--zone-id--x-s3`, sessions from `CreateSession`, and
//! `RenameObject`.
//!
//! As in AWS, bucket management (create, delete, policy, encryption,
//! lifecycle) is authorized with `s3express:` actions on the bucket's
//! `arn:aws:s3express:region:account:bucket/name` ARN, while object
//! operations are authorized by a session: `CreateSession` checks
//! `s3express:CreateSession` (with `s3express:SessionMode`) once and hands
//! out short-lived credentials that the SDKs then sign with, sending the
//! token as `x-amz-s3session-token`. A `ReadOnly` session cannot write.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use mws_core::{
    AuthzDecision, Caller, CredentialError, CredentialStore, RequestContext, ResolvedCredential, ResourcePolicyMode,
    ServiceError,
};

use crate::errors;
use crate::generated::types;
use crate::state::{random_id, Bucket, DirectoryBucket};
use crate::{Call, S3};

/// How long session credentials last.
const SESSION_LIFETIME: Duration = Duration::minutes(5);

/// Object operations a `ReadOnly` session may perform.
const SESSION_READ: &[&str] = &[
    "s3:GetObject",
    "s3:GetObjectAttributes",
    "s3:ListBucket",
    "s3:ListBucketMultipartUploads",
    "s3:ListMultipartUploadParts",
];

/// Object operations that need a `ReadWrite` session.
const SESSION_WRITE: &[&str] = &["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:RenameObject"];

/// Bucket operations on the regional endpoint, authorized as `s3express:`.
const REGIONAL: &[&str] = &[
    "s3:DeleteBucket",
    "s3:PutBucketPolicy",
    "s3:GetBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:PutEncryptionConfiguration",
    "s3:GetEncryptionConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:GetLifecycleConfiguration",
];

#[derive(Debug, Clone)]
pub(crate) struct Session {
    secret: String,
    token: String,
    bucket: String,
    read_only: bool,
    caller: Caller,
    expires: DateTime<Utc>,
}

/// Live sessions by access key id.
pub(crate) type Sessions = Arc<Mutex<HashMap<String, Session>>>;

/// Resolves the credentials `CreateSession` handed out.
pub struct SessionStore(Sessions);

impl CredentialStore for SessionStore {
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<ResolvedCredential>, CredentialError> {
        let Ok(mut sessions) = self.0.lock() else { return Ok(None) };
        sessions.retain(|_, s| s.expires + Duration::minutes(1) > now);
        let Some(s) = sessions.get(access_key_id) else { return Ok(None) };
        if session_token != Some(s.token.as_str()) {
            return Err(CredentialError::Invalid);
        }
        if s.expires <= now {
            return Err(CredentialError::Expired);
        }
        let mut caller = s.caller.clone();
        caller.access_key_id = access_key_id.to_string();
        Ok(Some(ResolvedCredential { secret_access_key: s.secret.clone(), caller }))
    }
}

pub fn directory_arn(ctx: &RequestContext, bucket: &Bucket) -> String {
    format!("arn:{}:s3express:{}:{}:bucket/{}", ctx.partition, bucket.region, bucket.owner, bucket.name)
}

/// Whether `name` is a directory bucket name (`base--zone--x-s3`).
pub fn is_directory_name(name: &str) -> bool {
    name.ends_with("--x-s3")
}

fn not_implemented() -> ServiceError {
    ServiceError::client("NotImplemented", 501, "This operation is not supported for directory buckets.")
}

/// Validate a directory bucket's name and configuration.
pub fn directory_config(
    name: &str,
    config: &types::CreateBucketConfiguration,
) -> Result<Option<DirectoryBucket>, ServiceError> {
    let bucket_type = config.bucket.as_ref().and_then(|b| b.r#type.as_deref());
    if bucket_type.is_none() && config.location.is_none() {
        if is_directory_name(name) {
            return Err(errors::invalid_bucket_name(name));
        }
        return Ok(None);
    }
    if bucket_type != Some("Directory") {
        return Err(errors::invalid_request("Bucket type must be Directory when a Location is given."));
    }
    let location = config
        .location
        .as_ref()
        .ok_or_else(|| errors::invalid_request("A Location is required to create a directory bucket."))?;
    let location_type = location.r#type.clone().unwrap_or_default();
    let zone = location.name.clone().unwrap_or_default();
    let redundancy = match (location_type.as_str(), config.bucket.as_ref().and_then(|b| b.data_redundancy.as_deref())) {
        ("AvailabilityZone", None | Some("SingleAvailabilityZone")) => "SingleAvailabilityZone",
        ("LocalZone", None | Some("SingleLocalZone")) => "SingleLocalZone",
        _ => {
            return Err(errors::invalid_request(
                "The location type and data redundancy of the directory bucket do not match.",
            ))
        }
    };
    let base = name.strip_suffix(&format!("--{zone}--x-s3"));
    let valid = !zone.is_empty()
        && name.len() <= 63
        && base.is_some_and(|b| {
            b.len() >= 3
                && b.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !b.starts_with('-')
                && !b.ends_with('-')
        });
    if !valid {
        return Err(errors::invalid_bucket_name(name));
    }
    Ok(Some(DirectoryBucket { location_type, location: zone, data_redundancy: redundancy.into() }))
}

impl S3 {
    /// The credential store for directory bucket sessions; register it with
    /// the gateway so session credentials sign requests.
    pub fn credential_store(&self) -> Arc<dyn CredentialStore> {
        Arc::new(SessionStore(self.sessions.clone()))
    }

    fn session(&self, access_key_id: &str) -> Option<Session> {
        self.sessions.lock().ok()?.get(access_key_id).cloned()
    }
}

impl Call {
    fn check_create_session(&self, ctx: &RequestContext, bucket: &Bucket, read_only: bool) -> Result<(), ServiceError> {
        let mut context = mws_core::ConditionContext::new();
        context.insert("aws:ResourceAccount".into(), vec![bucket.owner.clone()]);
        context
            .insert("s3express:SessionMode".into(), vec![if read_only { "ReadOnly" } else { "ReadWrite" }.to_string()]);
        let arn = directory_arn(ctx, bucket);
        match ctx.check(
            "s3express:CreateSession",
            &arn,
            bucket.policy.as_deref(),
            ResourcePolicyMode::Optional,
            context,
        ) {
            AuthzDecision::Allow => Ok(()),
            _ => Err(errors::access_denied(format!(
                "User: {} is not authorized to perform: s3express:CreateSession on resource: \"{arn}\"",
                ctx.caller.arn
            ))),
        }
    }

    /// Authorize `action` on a directory bucket.
    pub(crate) fn authorize_directory(
        &self,
        ctx: &RequestContext,
        action: &str,
        bucket: &Bucket,
    ) -> Result<(), ServiceError> {
        let read = SESSION_READ.contains(&action);
        let write = SESSION_WRITE.contains(&action);
        let session = self.session(&ctx.caller.access_key_id).filter(|_| read || write);
        if let Some(session) = session {
            if session.bucket == bucket.name {
                if write && session.read_only {
                    return Err(errors::access_denied("Access Denied"));
                }
                return Ok(());
            }
            // Another directory bucket (the source of a copy): the session's
            // identity must be able to open a session there.
            return self.check_create_session(ctx, bucket, read);
        }
        if read || write {
            return Err(errors::access_denied(
                "Access Denied: requests to directory bucket objects must be signed with CreateSession credentials",
            ));
        }
        if !REGIONAL.contains(&action) {
            return Err(not_implemented());
        }
        let express = format!("s3express:{}", action.trim_start_matches("s3:"));
        let mut context = mws_core::ConditionContext::new();
        context.insert("aws:ResourceAccount".into(), vec![bucket.owner.clone()]);
        let arn = directory_arn(ctx, bucket);
        match ctx.check(&express, &arn, bucket.policy.as_deref(), ResourcePolicyMode::Optional, context) {
            AuthzDecision::Allow => Ok(()),
            _ => Err(errors::access_denied(format!(
                "User: {} is not authorized to perform: {express} on resource: \"{arn}\"",
                ctx.caller.arn
            ))),
        }
    }

    pub fn create_session(
        &self,
        ctx: &RequestContext,
        input: types::CreateSessionRequest,
    ) -> Result<types::CreateSessionOutput, ServiceError> {
        if self.session(&ctx.caller.access_key_id).is_some() {
            return Err(errors::access_denied("Access Denied"));
        }
        let read_only = match input.session_mode.as_deref() {
            None | Some("ReadWrite") => false,
            Some("ReadOnly") => true,
            Some(other) => {
                return Err(errors::invalid_argument("Invalid session mode", "x-amz-create-session-mode", other))
            }
        };
        let st = self.read();
        // Pointed at a custom endpoint, the SDKs open a session before
        // CreateBucket too, so a session may name a bucket that does not
        // exist yet: it is judged against the caller's own account.
        let pending;
        let b = match st.buckets.get(&input.bucket) {
            Some(b) => b,
            None if is_directory_name(&input.bucket) => {
                pending = Bucket {
                    name: input.bucket.clone(),
                    region: ctx.region.clone(),
                    owner: ctx.caller.account_id.clone(),
                    ..Bucket::default()
                };
                &pending
            }
            None => return Err(errors::no_such_bucket(&input.bucket)),
        };
        if b.directory.is_none() && st.buckets.contains_key(&input.bucket) {
            return Err(errors::invalid_request("CreateSession is only supported for directory buckets."));
        }
        self.check_create_session(ctx, b, read_only)?;
        let default_sse = b
            .encryption
            .as_ref()
            .and_then(|e| e.rules.first())
            .and_then(|r| r.apply_server_side_encryption_by_default.as_ref());
        let sse = input
            .server_side_encryption
            .clone()
            .or_else(|| default_sse.map(|d| d.sse_algorithm.clone()))
            .unwrap_or_else(|| "AES256".into());
        let kms_key = input.ssekms_key_id.clone().or_else(|| default_sse.and_then(|d| d.kms_master_key_id.clone()));
        if sse == "aws:kms" && kms_key.is_none() {
            return Err(errors::invalid_argument(
                "x-amz-server-side-encryption-aws-kms-key-id is required for aws:kms on directory buckets",
                "x-amz-server-side-encryption-aws-kms-key-id",
                "",
            ));
        }
        drop(st);

        let access_key_id = format!("ASIA{}", random_id(16).to_ascii_uppercase().replace(['.', '_'], "X"));
        let secret = random_id(40);
        let token = format!("mws-s3express-{}", random_id(64));
        // Session lifetimes follow the wall clock, like the SDKs' caches.
        let expires = Utc::now() + SESSION_LIFETIME;
        let session = Session {
            secret: secret.clone(),
            token: token.clone(),
            bucket: input.bucket.clone(),
            read_only,
            caller: ctx.caller.clone(),
            expires,
        };
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(access_key_id.clone(), session);
        }
        Ok(types::CreateSessionOutput {
            server_side_encryption: Some(sse.clone()),
            ssekms_key_id: (sse == "aws:kms").then_some(kms_key).flatten(),
            ssekms_encryption_context: input.ssekms_encryption_context.clone().filter(|_| sse == "aws:kms"),
            bucket_key_enabled: (sse == "aws:kms").then_some(true),
            credentials: types::SessionCredentials {
                access_key_id,
                secret_access_key: secret,
                session_token: token,
                expiration: expires,
            },
        })
    }

    pub(crate) fn create_directory_bucket(
        &self,
        ctx: &RequestContext,
        name: &str,
        directory: DirectoryBucket,
    ) -> Result<types::CreateBucketOutput, ServiceError> {
        let bucket = Bucket {
            name: name.to_string(),
            region: ctx.region.clone(),
            owner: ctx.caller.account_id.clone(),
            created: ctx.received_at,
            ownership: Some("BucketOwnerEnforced".into()),
            acl: crate::acl::canned("private", &ctx.caller.account_id, &ctx.caller.account_id)?,
            public_access_block: Some(types::PublicAccessBlockConfiguration {
                block_public_acls: Some(true),
                ignore_public_acls: Some(true),
                block_public_policy: Some(true),
                restrict_public_buckets: Some(true),
            }),
            directory: Some(directory),
            ..Bucket::default()
        };
        let arn = directory_arn(ctx, &bucket);
        self.authorize_plain(ctx, "s3express:CreateBucket", &arn, mws_core::ConditionContext::new())?;
        let mut st = self.write();
        if let Some(existing) = st.buckets.get(name) {
            return Err(if existing.owner == bucket.owner {
                errors::bucket_already_owned_by_you(name)
            } else {
                errors::bucket_already_exists(name)
            });
        }
        st.buckets.insert(name.to_string(), bucket);
        Ok(types::CreateBucketOutput { location: Some(format!("/{name}")), bucket_arn: Some(arn) })
    }

    pub fn list_directory_buckets(
        &self,
        ctx: &RequestContext,
        input: types::ListDirectoryBucketsRequest,
    ) -> Result<types::ListDirectoryBucketsOutput, ServiceError> {
        self.authorize_plain(ctx, "s3express:ListAllMyDirectoryBuckets", "*", mws_core::ConditionContext::new())?;
        let max = input.max_directory_buckets.unwrap_or(1000).clamp(1, 1000) as usize;
        let st = self.read();
        let mut buckets: Vec<&Bucket> = st
            .buckets
            .values()
            .filter(|b| b.directory.is_some() && b.owner == ctx.caller.account_id)
            .filter(|b| input.continuation_token.as_deref().is_none_or(|t| b.name.as_str() > t))
            .collect();
        let more = buckets.len() > max;
        buckets.truncate(max);
        let token = more.then(|| buckets.last().map(|b| b.name.clone())).flatten();
        Ok(types::ListDirectoryBucketsOutput {
            buckets: Some(
                buckets
                    .into_iter()
                    .map(|b| types::Bucket {
                        name: Some(b.name.clone()),
                        creation_date: Some(b.created),
                        bucket_region: Some(b.region.clone()),
                        bucket_arn: Some(directory_arn(ctx, b)),
                    })
                    .collect(),
            ),
            continuation_token: token,
        })
    }

    pub fn rename_object(
        &self,
        ctx: &RequestContext,
        input: types::RenameObjectRequest,
    ) -> Result<types::RenameObjectOutput, ServiceError> {
        let source = percent_encoding::percent_decode_str(&input.rename_source).decode_utf8_lossy().into_owned();
        let source = source.trim_start_matches('/');
        let source = source.strip_prefix(&format!("{}/", input.bucket)).unwrap_or(source).to_string();
        let mut st = self.write();
        let b = st.bucket_mut(&input.bucket)?;
        if b.directory.is_none() {
            return Err(not_implemented());
        }
        self.authorize_directory(ctx, "s3:RenameObject", b)?;
        crate::objects::validate_key(&input.key)?;
        let src =
            b.latest(&source).filter(|v| !v.delete_marker).cloned().ok_or_else(|| errors::no_such_key(&source))?;
        let etag_matches = |etag: &str, want: &str| want == "*" || want.trim_matches('"') == etag.trim_matches('"');
        let failed = |what: &str| errors::precondition_failed(what);
        if input.source_if_match.as_deref().is_some_and(|m| !etag_matches(&src.etag, m)) {
            return Err(failed("x-amz-rename-source-if-match"));
        }
        if input.source_if_none_match.as_deref().is_some_and(|m| etag_matches(&src.etag, m)) {
            return Err(failed("x-amz-rename-source-if-none-match"));
        }
        if input.source_if_modified_since.is_some_and(|t| src.last_modified <= t) {
            return Err(failed("x-amz-rename-source-if-modified-since"));
        }
        if input.source_if_unmodified_since.is_some_and(|t| src.last_modified > t) {
            return Err(failed("x-amz-rename-source-if-unmodified-since"));
        }
        let dest = b.latest(&input.key).filter(|v| !v.delete_marker);
        match (&input.destination_if_match, dest) {
            (Some(_), None) => return Err(errors::no_such_key(&input.key)),
            (Some(m), Some(d)) if !etag_matches(&d.etag, m) => return Err(failed("If-Match")),
            _ => {}
        }
        if input.destination_if_none_match.as_deref().is_some_and(|m| dest.is_some_and(|d| etag_matches(&d.etag, m))) {
            return Err(failed("If-None-Match"));
        }
        if let (Some(t), Some(d)) = (input.destination_if_modified_since, dest) {
            if d.last_modified <= t {
                return Err(failed("If-Modified-Since"));
            }
        }
        if let (Some(t), Some(d)) = (input.destination_if_unmodified_since, dest) {
            if d.last_modified > t {
                return Err(failed("If-Unmodified-Since"));
            }
        }
        if source == input.key {
            return Ok(types::RenameObjectOutput {});
        }
        b.objects.remove(&source);
        let mut moved = src;
        moved.last_modified = ctx.received_at;
        b.insert_version(&input.key, moved);
        Ok(types::RenameObjectOutput {})
    }
}

/// `GET /` signed for `s3express` is ListDirectoryBuckets: AWS tells it
/// from ListBuckets by host (`s3express-control`), and botocore sends it
/// without `x-id` to a custom endpoint.
pub(crate) fn control_plane_listing(mut request: mws_core::HttpRequest) -> mws_core::HttpRequest {
    let query = request.uri().query().unwrap_or_default().to_string();
    if request.method() != http::Method::GET || request.uri().path() != "/" || query.contains("x-id=") {
        return request;
    }
    let credential = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| crate::form_urlencoded_get(&query, "X-Amz-Credential"))
        .unwrap_or_default();
    if !credential.contains("/s3express/aws4_request") {
        return request;
    }
    let query = if query.is_empty() {
        "x-id=ListDirectoryBuckets".to_string()
    } else {
        format!("{query}&x-id=ListDirectoryBuckets")
    };
    if let Ok(uri) = format!("/?{query}").parse() {
        *request.uri_mut() = uri;
    }
    request
}

/// The `x-amz-s3session-token` header or query parameter.
pub(crate) fn session_token(request: &mws_core::HttpRequest) -> Option<String> {
    if let Some(v) = request.headers().get("x-amz-s3session-token").and_then(|v| v.to_str().ok()) {
        return Some(v.to_string());
    }
    crate::form_urlencoded_get(request.uri().query().unwrap_or_default(), "X-Amz-S3session-Token")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(zone: &str) -> types::CreateBucketConfiguration {
        types::CreateBucketConfiguration {
            location: Some(types::LocationInfo { r#type: Some("AvailabilityZone".into()), name: Some(zone.into()) }),
            bucket: Some(types::BucketInfo { r#type: Some("Directory".into()), data_redundancy: None }),
            ..Default::default()
        }
    }

    #[test]
    fn directory_names() {
        assert!(directory_config("logs--usw2-az1--x-s3", &config("usw2-az1")).unwrap().is_some());
        assert!(directory_config("logs--usw2-az1--x-s3", &config("use1-az4")).is_err());
        assert!(directory_config("Logs--usw2-az1--x-s3", &config("usw2-az1")).is_err());
        assert!(directory_config("logs--usw2-az1--x-s3", &Default::default()).is_err());
        assert_eq!(directory_config("plain", &Default::default()).unwrap(), None);
    }
}
