//! Replication rules, acted on.
//!
//! After a request writes a new object version or delete marker that a
//! rule covers, the source version reports `x-amz-replication-status:
//! PENDING` and S3 replicates it in the background, as AWS does: once the
//! settle window (`mws_core::settle`, measured on the emulated clock) has
//! passed, the version is copied to the destination bucket of the
//! highest-priority matching rule, with the same version id, acting as the
//! configuration's IAM role. The role's policies must allow
//! `s3:GetObjectVersionForReplication` on the source and
//! `s3:ReplicateObject` (`s3:ReplicateDelete` for delete markers) on the
//! destination, and a destination bucket in another account must allow the
//! role in its bucket policy. SSE-KMS objects are re-encrypted under the
//! rule's `ReplicaKmsKeyID`, which needs the role to have `kms:Decrypt` on
//! the source key and `kms:Encrypt` on the replica key. The source version
//! then reports `COMPLETED` (or `FAILED`, with an
//! `s3:Replication:OperationFailedReplication` event), the replica
//! `REPLICA`. Until then the replica does not exist.
//!
//! Pending work is settled before every S3 request and by a background
//! task once the window has passed, so a replica appears whether or not
//! anyone asks.
//!
//! As in S3: replicas are not replicated again, SSE-C objects are never
//! replicated, SSE-KMS objects only when the rule opts in, and lifecycle
//! actions are not replicated.

use base64::Engine;
use chrono::Duration;
use mws_core::{AuthzDecision, Caller, CallerKind, ConditionContext, RequestContext, ResourcePolicyMode, SessionInfo};
use serde_json::json;

use crate::auth::object_arn;
use crate::generated::types;
use crate::notifications::Emit;
use crate::state::{Bucket, ObjectVersion, PendingWork, State};
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
            provided_context: Default::default(),
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

/// The rule that replicates a version, if any.
fn matching_rule(st: &State, bucket: &str, key: &str, version_id: &str) -> Option<types::ReplicationRule> {
    let src = st.buckets.get(bucket)?;
    let config = src.replication.as_ref()?;
    let v = src.version(key, version_id)?;
    if v.replication_status.as_deref() == Some("REPLICA") || v.sse.customer_key_md5.is_some() {
        return None;
    }
    let rule =
        config.rules.iter().filter(|r| rule_matches(r, key, v)).max_by_key(|r| r.priority.unwrap_or(0)).cloned()?;
    if v.delete_marker && !replicates_delete_markers(&rule) {
        return None;
    }
    let kms = v.sse.algorithm.as_deref().is_some_and(|a| a.starts_with("aws:kms"));
    if kms && !kms_opt_in(&rule) {
        return None;
    }
    Some(rule)
}

/// What replicating one version came to.
struct Outcome {
    rule_id: String,
    destination: String,
    delete_marker: bool,
    /// S3's replication failure reason, when it failed.
    failure: Option<&'static str>,
}

/// The failure reason for a KMS error on the source (`Src`) or
/// destination (`Dst`) side.
fn kms_failure(e: &mws_core::ServiceError, source: bool) -> &'static str {
    match (&*e.code, source) {
        ("NotFoundException", true) => "SrcKmsKeyNotFound",
        ("NotFoundException", false) => "DstKmsKeyNotFound",
        ("DisabledException" | "KMSInvalidStateException", true) => "SrcKmsKeyInvalidState",
        ("DisabledException" | "KMSInvalidStateException", false) => "DstKmsKeyInvalidState",
        (_, true) => "SrcGetObjectNotPermitted",
        (_, false) => "DstPutObjectNotPermitted",
    }
}

impl S3 {
    /// Queue the versions a request wrote for replication: each one a rule
    /// covers reports `PENDING` until it settles.
    pub(crate) fn replicate(&self, ctx: &RequestContext, written: Vec<(String, String, String)>) {
        if written.is_empty() {
            return;
        }
        let mut queued = false;
        {
            let mut st = self.write();
            for (bucket, key, version_id) in written {
                if matching_rule(&st, &bucket, &key, &version_id).is_none() {
                    continue;
                }
                set_status(&mut st, &bucket, &key, &version_id, "PENDING");
                st.pending_replication.push(PendingWork { bucket, key, version_id, since: ctx.received_at });
                queued = true;
            }
        }
        if queued {
            self.pending_work_started(ctx);
        }
    }

    /// After background work was queued: settle it now when the settle
    /// window is zero, otherwise once the window has passed.
    pub(crate) fn pending_work_started(&self, ctx: &RequestContext) {
        let delay = mws_core::settle::delay();
        if delay <= Duration::zero() {
            self.settle(ctx);
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let s3 = self.clone();
        let mut ctx = ctx.clone();
        runtime.spawn(async move {
            let started = std::time::Instant::now();
            tokio::time::sleep(delay.to_std().unwrap_or_default() + std::time::Duration::from_millis(10)).await;
            ctx.received_at += Duration::from_std(started.elapsed()).unwrap_or(delay);
            s3.settle(&ctx);
        });
    }

    /// Settle background work that is due and send the events it causes.
    pub(crate) fn settle(&self, ctx: &RequestContext) {
        for e in self.settle_pending(ctx) {
            self.emit(ctx, e);
        }
    }

    /// Finish the replications and restores whose settle window has passed
    /// by `ctx.received_at`. Returns the events they cause.
    pub(crate) fn settle_pending(&self, ctx: &RequestContext) -> Vec<Emit> {
        let now = ctx.received_at;
        {
            let st = self.read();
            let due = |w: &PendingWork| mws_core::settle::settled(w.since, now);
            if !st.pending_replication.iter().any(due) && !st.pending_restores.iter().any(due) {
                return Vec::new();
            }
        }
        let mut events = Vec::new();
        let mut st = self.write();
        let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut st.pending_replication)
            .into_iter()
            .partition(|w| mws_core::settle::settled(w.since, now));
        st.pending_replication = rest;
        for w in due {
            match self.replicate_one(ctx, &mut st, &w.bucket, &w.key, &w.version_id) {
                Some(o) => {
                    if let Some(reason) = o.failure {
                        events.push(failure_event(&st, &w, &o, reason));
                    }
                }
                None => {
                    // The rule went away while the version was pending.
                    if let Some(v) =
                        st.buckets.get_mut(&w.bucket).and_then(|b| b.version_mut(&w.key, Some(&w.version_id)))
                    {
                        if v.replication_status.as_deref() == Some("PENDING") {
                            v.replication_status = Some("FAILED".into());
                        }
                    }
                }
            }
        }
        events.extend(crate::objects::settle_restores(&mut st, now));
        events
    }
}

/// `s3:Replication:OperationFailedReplication` for a version.
fn failure_event(st: &State, w: &PendingWork, o: &Outcome, reason: &str) -> Emit {
    let v = st.buckets.get(&w.bucket).and_then(|b| b.version(&w.key, &w.version_id));
    Emit {
        bucket: w.bucket.clone(),
        key: w.key.clone(),
        version_id: Some(w.version_id.clone()),
        event_name: "Replication:OperationFailedReplication".into(),
        reason: "Replication".into(),
        size: v.filter(|v| !v.delete_marker).map(ObjectVersion::size),
        etag: v.filter(|v| !v.delete_marker).map(|v| v.etag.trim_matches('"').to_string()),
        by_s3: true,
        record_data: Some((
            "replicationEventData",
            json!({
                "replicationRuleId": o.rule_id,
                "destinationBucket": o.destination,
                "s3Operation": if o.delete_marker { "OBJECT_DELETE" } else { "OBJECT_PUT" },
                "requestTime": w.since.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                "failureReason": reason,
            }),
        )),
        ..Emit::default()
    }
}

impl S3 {
    /// Replicate an existing version on request (S3 Batch Replication):
    /// `ctx` must be allowed `s3:InitiateReplication`; the copy itself is
    /// made as the bucket's replication role, at once. Returns the result
    /// message.
    pub fn replicate_existing(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<&'static str, mws_core::ServiceError> {
        let mut st = self.write();
        let b = st.bucket(bucket)?;
        let policy = b.policy.clone();
        ctx.authorize_with_resource_policy(
            "s3:InitiateReplication",
            &object_arn(ctx, bucket, key),
            policy.as_deref(),
            ConditionContext::new(),
        )?;
        if b.replication.is_none() {
            return Err(crate::errors::invalid_request("Replication configuration is not found on the source bucket"));
        }
        let version = match version_id {
            Some(v) => b.version(key, v).map(|v| v.version_id.clone()),
            None => b.latest(key).map(|v| v.version_id.clone()),
        }
        .ok_or_else(|| crate::errors::no_such_key(key))?;
        match self.replicate_one(ctx, &mut st, bucket, key, &version) {
            Some(Outcome { failure: None, .. }) => Ok("Successful"),
            _ => Err(mws_core::ServiceError::client(
                "ReplicationFailed",
                400,
                "The object could not be replicated: no rule matched or the replication role was denied",
            )),
        }
    }

    /// Replicate one version now. `None` when no rule covers it.
    fn replicate_one(
        &self,
        ctx: &RequestContext,
        st: &mut State,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Option<Outcome> {
        let rule = matching_rule(st, bucket, key, version_id)?;
        let src = st.buckets.get(bucket)?;
        let config = src.replication.clone()?;
        let v = src.version(key, version_id)?.clone();
        let dest_name = rule.destination.bucket.rsplit(':').next().unwrap_or_default().to_string();
        let mut outcome = Outcome {
            rule_id: rule.id.clone().unwrap_or_default(),
            destination: rule.destination.bucket.clone(),
            delete_marker: v.delete_marker,
            failure: None,
        };
        let result = (|| -> Result<(ObjectVersion, String), &'static str> {
            let role = role_caller(&config.role, ctx).ok_or("AssumeRoleNotPermitted")?;
            let mut role_ctx = ctx.clone();
            role_ctx.caller = role;
            let dest = st.buckets.get(&dest_name).ok_or("DstBucketNotFound")?;
            if !dest.versioning_enabled() {
                return Err("DstBucketUnversioned");
            }
            if !allowed(&role_ctx, "s3:GetObjectVersionForReplication", &object_arn(ctx, bucket, key), src) {
                return Err("SrcGetObjectNotPermitted");
            }
            let (action, denied) = if v.delete_marker {
                ("s3:ReplicateDelete", "DstDelObjNotPermitted")
            } else {
                ("s3:ReplicateObject", "DstPutObjectNotPermitted")
            };
            if !allowed(&role_ctx, action, &object_arn(ctx, &dest_name, key), dest) {
                return Err(denied);
            }
            let mut replica = v.clone();
            replica.replication_status = Some("REPLICA".into());
            if let Some(class) = &rule.destination.storage_class {
                replica.storage_class = class.clone();
            }
            if rule.destination.access_control_translation.is_some() {
                replica.owner = dest.owner.clone();
            }
            let replica_key =
                rule.destination.encryption_configuration.as_ref().and_then(|e| e.replica_kms_key_id.clone());
            if let (Some(kms), Some(data_key), Some(replica_key)) = (&self.kms, &v.sse.kms_data_key, replica_key) {
                // Re-encrypt the object's data key under the replica key,
                // as the role: kms:Decrypt on the source key, kms:Encrypt on
                // the replica key.
                let blob = base64::engine::general_purpose::STANDARD.decode(data_key).unwrap_or_default();
                let mut src_ctx = role_ctx.clone();
                src_ctx.region = src.region.clone();
                let context = crate::kms::encryption_context(&v.sse, &ctx.partition, bucket, key);
                let (_, plaintext) =
                    kms.decrypt_via(&src_ctx, "s3", &blob, &context).map_err(|e| kms_failure(&e, true))?;
                let mut dst_ctx = role_ctx.clone();
                dst_ctx.region = dest.region.clone();
                let context = crate::kms::encryption_context(&v.sse, &ctx.partition, &dest_name, key);
                let (arn, ciphertext) = kms
                    .encrypt_via(&dst_ctx, "s3", &replica_key, &plaintext, &context)
                    .map_err(|e| kms_failure(&e, false))?;
                replica.sse.kms_key_id = Some(arn);
                replica.sse.kms_data_key = Some(base64::engine::general_purpose::STANDARD.encode(ciphertext));
            }
            Ok((replica, dest_name.clone()))
        })();
        match result {
            Ok((replica, dest_name)) => {
                if let Some(d) = st.buckets.get_mut(&dest_name) {
                    let versions = d.objects.entry(key.to_string()).or_default();
                    versions.retain(|x| x.version_id != replica.version_id);
                    versions.push(replica);
                }
                set_status(st, bucket, key, version_id, "COMPLETED");
            }
            Err(reason) => {
                outcome.failure = Some(reason);
                set_status(st, bucket, key, version_id, "FAILED");
            }
        }
        Some(outcome)
    }
}

fn set_status(st: &mut State, bucket: &str, key: &str, version_id: &str, status: &str) {
    if let Some(v) = st.buckets.get_mut(bucket).and_then(|b| b.version_mut(key, Some(version_id))) {
        // Delete markers carry no replication status.
        if !v.delete_marker {
            v.replication_status = Some(status.to_string());
        }
    }
}
