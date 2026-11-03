//! Replication rules, acted on.
//!
//! After a request writes a new object version or delete marker, S3
//! replicates it to the destination bucket of the highest-priority matching
//! rule, with the same version id, acting as the configuration's IAM role:
//! the role's policies must allow `s3:GetObjectVersionForReplication` on the
//! source and `s3:ReplicateObject` (`s3:ReplicateDelete` for delete markers)
//! on the destination, and a destination bucket in another account must
//! allow the role in its bucket policy. The source version then reports
//! `x-amz-replication-status: COMPLETED` (or `FAILED`), the replica
//! `REPLICA`. AWS replicates asynchronously; MWS does it before answering.
//!
//! As in S3: replicas are not replicated again, SSE-C objects are never
//! replicated, SSE-KMS objects only when the rule opts in, and lifecycle
//! actions are not replicated.

use chrono::Duration;
use mws_core::{AuthzDecision, Caller, CallerKind, ConditionContext, RequestContext, ResourcePolicyMode, SessionInfo};

use crate::auth::object_arn;
use crate::generated::types;
use crate::state::{Bucket, ObjectVersion, State};
use crate::S3;

fn filter_prefix(rule: &types::ReplicationRule) -> &str {
    match &rule.filter {
        Some(f) => f.and.as_ref().and_then(|a| a.prefix.as_deref()).or(f.prefix.as_deref()).unwrap_or_default(),
        None => rule.prefix.as_deref().unwrap_or_default(),
    }
}

fn rule_matches(rule: &types::ReplicationRule, key: &str, v: &ObjectVersion) -> bool {
    if rule.status != "Enabled" || !key.starts_with(filter_prefix(rule)) {
        return false;
    }
    let has_tag = |t: &types::Tag| v.tags.iter().any(|x| x.key == t.key && x.value == t.value);
    match &rule.filter {
        Some(f) => match &f.and {
            Some(and) => and.tags.iter().flatten().all(has_tag),
            None => f.tag.as_ref().is_none_or(has_tag),
        },
        None => true,
    }
}

/// Whether a rule replicates delete markers: V1 rules (a bare `Prefix`)
/// always do; V2 rules (with `Filter`) only with `DeleteMarkerReplication`.
fn replicates_delete_markers(rule: &types::ReplicationRule) -> bool {
    match &rule.filter {
        None => true,
        Some(_) => rule.delete_marker_replication.as_ref().and_then(|d| d.status.as_deref()) == Some("Enabled"),
    }
}

fn kms_opt_in(rule: &types::ReplicationRule) -> bool {
    rule.source_selection_criteria
        .as_ref()
        .and_then(|c| c.sse_kms_encrypted_objects.as_ref())
        .is_some_and(|s| s.status == "Enabled")
}

/// The caller S3 acts as: a session of the replication role.
fn role_caller(role_arn: &str, ctx: &RequestContext) -> Option<Caller> {
    let mut parts = role_arn.splitn(6, ':');
    let (_, _, _, _, account, resource) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let role_name = resource.strip_prefix("role/")?.rsplit('/').next()?.to_string();
    let session_name = "s3-replication".to_string();
    Some(Caller {
        account_id: account.to_string(),
        arn: format!("arn:{}:sts::{account}:assumed-role/{role_name}/{session_name}", ctx.partition),
        user_id: format!("AROAMWSS3REPLICATION:{session_name}"),
        access_key_id: String::new(),
        kind: CallerKind::AssumedRole { role_name, session_name },
        session: Some(SessionInfo {
            kind: mws_core::SessionKind::AssumeRole,
            policies: Vec::new(),
            tags: Default::default(),
            transitive_tag_keys: Vec::new(),
            source_identity: None,
            issued_at: ctx.received_at,
            expires_at: ctx.received_at + Duration::hours(1),
            mfa_authenticated: false,
        }),
    })
}

fn allowed(ctx: &RequestContext, action: &str, resource: &str, bucket: &Bucket) -> bool {
    let mut context = ConditionContext::new();
    context.insert("aws:ResourceAccount".into(), vec![bucket.owner.clone()]);
    matches!(
        ctx.check(action, resource, bucket.policy.as_deref(), ResourcePolicyMode::Optional, context),
        AuthzDecision::Allow
    )
}

impl S3 {
    /// Replicate the versions a request wrote.
    pub(crate) fn replicate(&self, ctx: &RequestContext, written: Vec<(String, String, String)>) {
        if written.is_empty() {
            return;
        }
        let mut st = self.write();
        for (bucket, key, version_id) in written {
            replicate_one(ctx, &mut st, &bucket, &key, &version_id);
        }
    }
}

fn replicate_one(ctx: &RequestContext, st: &mut State, bucket: &str, key: &str, version_id: &str) {
    let Some(src) = st.buckets.get(bucket) else { return };
    let Some(config) = src.replication.clone() else { return };
    let Some(v) = src.version(key, version_id).cloned() else { return };
    if v.replication_status.as_deref() == Some("REPLICA") || v.sse.customer_key_md5.is_some() {
        return;
    }
    let Some(rule) =
        config.rules.iter().filter(|r| rule_matches(r, key, &v)).max_by_key(|r| r.priority.unwrap_or(0)).cloned()
    else {
        return;
    };
    if v.delete_marker && !replicates_delete_markers(&rule) {
        return;
    }
    let kms = v.sse.algorithm.as_deref().is_some_and(|a| a.starts_with("aws:kms"));
    if kms && !kms_opt_in(&rule) {
        return;
    }
    let dest_name = rule.destination.bucket.rsplit(':').next().unwrap_or_default().to_string();
    let ok = (|| {
        let role = role_caller(&config.role, ctx)?;
        let mut role_ctx = ctx.clone();
        role_ctx.caller = role;
        let dest = st.buckets.get(&dest_name).filter(|d| d.versioning_enabled())?;
        let read = allowed(&role_ctx, "s3:GetObjectVersionForReplication", &object_arn(ctx, bucket, key), src);
        let action = if v.delete_marker { "s3:ReplicateDelete" } else { "s3:ReplicateObject" };
        let write = allowed(&role_ctx, action, &object_arn(ctx, &dest_name, key), dest);
        (read && write).then_some(dest.owner.clone())
    })();
    match ok {
        Some(dest_owner) => {
            let mut replica = v.clone();
            replica.replication_status = Some("REPLICA".into());
            if let Some(class) = &rule.destination.storage_class {
                replica.storage_class = class.clone();
            }
            if rule.destination.access_control_translation.is_some() {
                replica.owner = dest_owner;
            }
            if let Some(d) = st.buckets.get_mut(&dest_name) {
                let versions = d.objects.entry(key.to_string()).or_default();
                versions.retain(|x| x.version_id != replica.version_id);
                versions.push(replica);
            }
            set_status(st, bucket, key, version_id, v.delete_marker, "COMPLETED");
        }
        None => set_status(st, bucket, key, version_id, v.delete_marker, "FAILED"),
    }
}

fn set_status(st: &mut State, bucket: &str, key: &str, version_id: &str, marker: bool, status: &str) {
    // Delete markers carry no replication status.
    if marker {
        return;
    }
    if let Some(v) = st.buckets.get_mut(bucket).and_then(|b| b.version_mut(key, Some(version_id))) {
        v.replication_status = Some(status.to_string());
    }
}
