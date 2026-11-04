//! S3 Batch Operations: jobs that run one operation over every object of a
//! manifest (a CSV or S3 Inventory manifest, or one generated from a bucket
//! listing), as the job's IAM role, and write a completion report.
//!
//! Jobs run in the background once created, as on AWS: `New`, `Preparing`,
//! then `Active` until every task has run, then `Complete` (or `Failed` when
//! the manifest cannot be read). Jobs that need confirmation wait as
//! `Suspended` until `UpdateJobStatus` moves them to `Ready`.

use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::generated::types;
use crate::S3Control;

const SERVICE_PRINCIPAL: &str = "batchoperations.s3.amazonaws.com";

fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

fn not_found(id: &str) -> ServiceError {
    err("NotFoundException", 404, format!("Job {id} does not exist"))
}

fn bad_request(message: impl Into<String>) -> ServiceError {
    err("BadRequestException", 400, message)
}

/// A Batch Operations job.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Job {
    pub id: String,
    pub arn: String,
    pub account_id: String,
    pub region: String,
    pub status: String,
    pub request: types::CreateJobRequest,
    pub tags: Vec<types::S3Tag>,
    pub created: Option<DateTime<Utc>>,
    pub terminated: Option<DateTime<Utc>>,
    pub suspended: Option<DateTime<Utc>>,
    pub suspended_cause: Option<String>,
    pub status_update_reason: Option<String>,
    pub failures: Vec<(String, String)>,
    pub total: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub active_seconds: i64,
    pub generated_manifest: Option<types::S3GeneratedManifestDescriptor>,
}

impl Job {
    fn operation_name(&self) -> &'static str {
        let o = &self.request.operation;
        if o.lambda_invoke.is_some() {
            "LambdaInvoke"
        } else if o.s3_put_object_copy.is_some() {
            "S3PutObjectCopy"
        } else if o.s3_put_object_acl.is_some() {
            "S3PutObjectAcl"
        } else if o.s3_put_object_tagging.is_some() {
            "S3PutObjectTagging"
        } else if o.s3_delete_object_tagging.is_some() {
            "S3DeleteObjectTagging"
        } else if o.s3_initiate_restore_object.is_some() {
            "S3InitiateRestoreObject"
        } else if o.s3_put_object_legal_hold.is_some() {
            "S3PutObjectLegalHold"
        } else if o.s3_put_object_retention.is_some() {
            "S3PutObjectRetention"
        } else if o.s3_replicate_object.is_some() {
            "S3ReplicateObject"
        } else if o.s3_compute_object_checksum.is_some() {
            "S3ComputeObjectChecksum"
        } else {
            "S3UpdateObjectEncryption"
        }
    }

    fn progress(&self) -> types::JobProgressSummary {
        types::JobProgressSummary {
            total_number_of_tasks: Some(self.total),
            number_of_tasks_succeeded: Some(self.succeeded),
            number_of_tasks_failed: Some(self.failed),
            timers: Some(types::JobTimers { elapsed_time_in_active_seconds: Some(self.active_seconds) }),
        }
    }

    fn terminal(&self) -> bool {
        matches!(self.status.as_str(), "Complete" | "Failed" | "Cancelled")
    }
}

/// One object of the manifest.
#[derive(Debug, Clone)]
struct Task {
    bucket: String,
    key: String,
    version_id: Option<String>,
}

/// How one task went.
struct Outcome {
    succeeded: bool,
    http_status: u16,
    error_code: String,
    message: String,
}

impl Outcome {
    fn ok(message: impl Into<String>) -> Self {
        Outcome { succeeded: true, http_status: 200, error_code: String::new(), message: message.into() }
    }

    fn from_error(e: &ServiceError) -> Self {
        Outcome { succeeded: false, http_status: e.status, error_code: e.code.to_string(), message: e.message.clone() }
    }
}

/// A job failure: (code, reason).
type Failure = (String, String);

fn bucket_of(arn: &str) -> Option<&str> {
    arn.strip_prefix("arn:").and_then(|r| r.rsplit_once(":::").map(|(_, b)| b)).filter(|b| !b.is_empty())
}

fn csv_line(fields: &[&str]) -> String {
    fields
        .iter()
        .map(|f| if f.contains([',', '"', '\n']) { format!("\"{}\"", f.replace('"', "\"\"")) } else { f.to_string() })
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => out.push(std::mem::take(&mut cur)),
            (c, _) => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn url_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned()
}

fn url_encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn decode_body(out: &Value) -> Vec<u8> {
    out.get("Body")
        .and_then(Value::as_str)
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .unwrap_or_default()
}

impl S3Control {
    fn job_arn(ctx: &RequestContext, account: &str, id: &str) -> String {
        format!("arn:{}:s3:{}:{account}:job/{id}", ctx.partition, ctx.region)
    }

    fn job(&self, account: &str, id: &str) -> Result<Job, ServiceError> {
        self.read().jobs.get(id).filter(|j| j.account_id == account).cloned().ok_or_else(|| not_found(id))
    }

    pub(crate) async fn create_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateJobRequest,
    ) -> Result<types::CreateJobResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let tags = input.tags.clone().unwrap_or_default();
        let mut condition = ConditionContext::new();
        for t in &tags {
            condition.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone()]);
        }
        if !tags.is_empty() {
            condition.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
        }
        ctx.authorize("s3:CreateJob", "*", condition)?;
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec![SERVICE_PRINCIPAL.into()]);
        ctx.authorize("iam:PassRole", &input.role_arn, pass)?;

        let o = &input.operation;
        let operations = [
            o.lambda_invoke.is_some(),
            o.s3_put_object_copy.is_some(),
            o.s3_put_object_acl.is_some(),
            o.s3_put_object_tagging.is_some(),
            o.s3_delete_object_tagging.is_some(),
            o.s3_initiate_restore_object.is_some(),
            o.s3_put_object_legal_hold.is_some(),
            o.s3_put_object_retention.is_some(),
            o.s3_replicate_object.is_some(),
            o.s3_compute_object_checksum.is_some(),
            o.s3_update_object_encryption.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if operations != 1 {
            return Err(bad_request("Exactly one operation must be specified"));
        }
        match (&input.manifest, &input.manifest_generator) {
            (None, None) => return Err(bad_request("Either Manifest or ManifestGenerator must be specified")),
            (Some(_), Some(_)) => {
                return Err(bad_request("Only one of Manifest or ManifestGenerator may be specified"))
            }
            _ => {}
        }
        if let Some(m) = &input.manifest {
            if bucket_of(&m.location.object_arn).is_none() || !m.location.object_arn.contains('/') {
                return Err(bad_request(format!("Invalid manifest object ARN: {}", m.location.object_arn)));
            }
        }
        if o.s3_replicate_object.is_some() && input.manifest.is_some() && input.manifest_generator.is_none() {
            // Allowed: replicate the objects a manifest lists.
        }
        let r = &input.report;
        if r.enabled && (r.bucket.is_none() || r.format.is_none()) {
            return Err(bad_request("Report Bucket and Format are required when the report is enabled"));
        }
        if o.s3_put_object_copy.as_ref().is_some_and(|c| c.target_resource.is_none()) {
            return Err(bad_request("TargetResource is required for S3PutObjectCopy"));
        }
        if let Some(l) = &o.lambda_invoke {
            if l.function_arn.is_none() {
                return Err(bad_request("FunctionArn is required for LambdaInvoke"));
            }
            if l.user_arguments.is_some() && l.invocation_schema_version.as_deref() != Some("2.0") {
                return Err(bad_request("UserArguments require InvocationSchemaVersion 2.0"));
            }
        }

        let id = {
            let mut st = self.write();
            if let Some(existing) = st
                .jobs
                .values()
                .find(|j| j.account_id == account && j.request.client_request_token == input.client_request_token)
            {
                return Ok(types::CreateJobResult { job_id: Some(existing.id.clone()) });
            }
            let id = uuid::Uuid::new_v4().to_string();
            let confirm = input.confirmation_required.unwrap_or(false);
            let job = Job {
                id: id.clone(),
                arn: Self::job_arn(ctx, &account, &id),
                account_id: account.clone(),
                region: ctx.region.clone(),
                status: if confirm { "Suspended".into() } else { "New".into() },
                tags,
                created: Some(ctx.received_at),
                suspended: confirm.then_some(ctx.received_at),
                suspended_cause: confirm.then(|| "AWAITING_CONFIRMATION".into()),
                request: input,
                ..Default::default()
            };
            st.jobs.insert(id.clone(), job);
            id
        };
        if !self.read().jobs[&id].request.confirmation_required.unwrap_or(false) {
            self.start(ctx, &id);
        }
        Ok(types::CreateJobResult { job_id: Some(id) })
    }

    fn start(&self, ctx: &RequestContext, id: &str) {
        let this = self.clone();
        let ctx = ctx.clone();
        let id = id.to_string();
        tokio::spawn(async move { this.run(&ctx, &id).await });
    }

    fn set_status(&self, id: &str, status: &str) -> bool {
        let mut st = self.write();
        match st.jobs.get_mut(id) {
            Some(j) if j.status != "Cancelled" => {
                j.status = status.to_string();
                true
            }
            _ => false,
        }
    }

    fn fail(&self, id: &str, failure: Failure, now: DateTime<Utc>) {
        let mut st = self.write();
        if let Some(j) = st.jobs.get_mut(id) {
            j.status = "Failed".into();
            j.failures.push(failure);
            j.terminated = Some(now);
        }
    }

    /// The job's role, as Batch Operations gets it by assuming it.
    fn role_context(&self, ctx: &RequestContext, job: &Job) -> Result<RequestContext, Failure> {
        let cannot = || {
            (
                "AccessDenied".to_string(),
                format!(
                    "Unable to assume role {}: the role does not exist or does not trust {SERVICE_PRINCIPAL}",
                    job.request.role_arn
                ),
            )
        };
        let sts = self.sts.get().ok_or_else(cannot)?;
        let creds = sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: &job.request.role_arn,
                service_principal: SERVICE_PRINCIPAL,
                session_name: "s3-batch-operations",
                duration_seconds: 3600,
                source_account: Some(&job.account_id),
                source_arn: Some(&job.arn),
                now: ctx.received_at,
            })
            .map_err(|_| cannot())?;
        let resolved = sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .ok()
            .flatten()
            .ok_or_else(cannot)?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    async fn s3_call(&self, ctx: &RequestContext, operation: &str, input: Value) -> Result<Value, ServiceError> {
        let Some(s3) = &self.s3 else { return Err(err("InternalError", 500, "S3 is not available")) };
        mws_core::Service::invoke(s3, ctx.clone(), operation, input).await
    }

    async fn run(&self, ctx: &RequestContext, id: &str) {
        let started = std::time::Instant::now();
        let Ok(job) = self.read().jobs.get(id).cloned().ok_or(()) else { return };
        if !self.set_status(id, "Preparing") {
            return;
        }
        let role = match self.role_context(ctx, &job) {
            Ok(r) => r,
            Err(f) => return self.fail(id, f, ctx.received_at),
        };
        let tasks = match self.tasks(&role, &job).await {
            Ok(t) => t,
            Err(f) => return self.fail(id, f, ctx.received_at),
        };
        {
            let mut st = self.write();
            let Some(j) = st.jobs.get_mut(id) else { return };
            if j.status == "Cancelled" {
                return;
            }
            j.total = tasks.len() as i64;
            j.status = "Active".into();
        }
        let mut results = Vec::new();
        for task in &tasks {
            if self.read().jobs.get(id).is_none_or(|j| j.status == "Cancelled") {
                break;
            }
            let outcome = self.run_task(&role, &job, task).await;
            {
                let mut st = self.write();
                if let Some(j) = st.jobs.get_mut(id) {
                    if outcome.succeeded {
                        j.succeeded += 1;
                    } else {
                        j.failed += 1;
                    }
                }
            }
            results.push((task.clone(), outcome));
        }
        let cancelled = self.read().jobs.get(id).is_none_or(|j| j.status == "Cancelled");
        if !cancelled {
            self.set_status(id, "Completing");
        }
        if job.request.report.enabled {
            if let Err(f) = self.write_report(&role, &job, &results).await {
                let mut st = self.write();
                if let Some(j) = st.jobs.get_mut(id) {
                    j.failures.push(f);
                }
            }
        }
        let mut st = self.write();
        if let Some(j) = st.jobs.get_mut(id) {
            if !cancelled {
                j.status = "Complete".into();
            }
            j.terminated = Some(ctx.received_at + chrono::Duration::milliseconds(started.elapsed().as_millis() as i64));
            j.active_seconds = started.elapsed().as_secs() as i64;
        }
    }

    /// Read the manifest (or generate one) as the job's role.
    async fn tasks(&self, role: &RequestContext, job: &Job) -> Result<Vec<Task>, Failure> {
        if let Some(types::JobManifestGenerator::S3JobManifestGenerator(g)) = &job.request.manifest_generator {
            return self.generate(role, job, g).await;
        }
        let Some(manifest) = &job.request.manifest else { return Ok(Vec::new()) };
        let read_failed =
            |e: &ServiceError| (e.code.to_string(), format!("Reading the manifest failed: {}: {}", e.code, e.message));
        let (bucket, key) = split_object_arn(&manifest.location.object_arn)
            .ok_or_else(|| ("InvalidManifest".to_string(), "The manifest object ARN is not valid".to_string()))?;
        let mut get = json!({"Bucket": bucket, "Key": key});
        if let Some(v) = &manifest.location.object_version_id {
            get["VersionId"] = json!(v);
        }
        let out = self.s3_call(role, "GetObject", get).await.map_err(|e| read_failed(&e))?;
        let etag = out.get("ETag").and_then(Value::as_str).unwrap_or_default().trim_matches('"').to_string();
        if etag != manifest.location.e_tag.trim_matches('"') {
            return Err((
                "ManifestETagMismatch".into(),
                format!("The ETag {} does not match the manifest's ETag {etag}", manifest.location.e_tag),
            ));
        }
        let body = decode_body(&out);
        match manifest.spec.format.as_str() {
            "S3InventoryReport_CSV_20161130" => self.inventory_tasks(role, &body).await,
            _ => {
                let fields = manifest.spec.fields.clone().unwrap_or_else(|| vec!["Bucket".into(), "Key".into()]);
                Ok(csv_tasks(&String::from_utf8_lossy(&body), &fields, true))
            }
        }
    }

    async fn inventory_tasks(&self, role: &RequestContext, manifest: &[u8]) -> Result<Vec<Task>, Failure> {
        let invalid = || ("InvalidManifest".to_string(), "The inventory manifest is not valid".to_string());
        let doc: Value = serde_json::from_slice(manifest).map_err(|_| invalid())?;
        let schema: Vec<String> = doc
            .get("fileSchema")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        let dest = doc.get("destinationBucket").and_then(Value::as_str).and_then(bucket_of).ok_or_else(invalid)?;
        let mut tasks = Vec::new();
        for f in doc.get("files").and_then(Value::as_array).into_iter().flatten() {
            let Some(key) = f.get("key").and_then(Value::as_str) else { continue };
            let out = self
                .s3_call(role, "GetObject", json!({"Bucket": dest, "Key": key}))
                .await
                .map_err(|e| (e.code.to_string(), format!("Reading the manifest failed: {}", e.message)))?;
            let raw = decode_body(&out);
            let mut text = String::new();
            if flate2::read::GzDecoder::new(raw.as_slice()).read_to_string(&mut text).is_err() {
                text = String::from_utf8_lossy(&raw).into_owned();
            }
            let fields: Vec<String> = schema
                .iter()
                .map(|c| match c.as_str() {
                    "Bucket" | "Key" | "VersionId" => c.clone(),
                    _ => "Ignore".to_string(),
                })
                .collect();
            tasks.extend(csv_tasks(&text, &fields, true));
        }
        Ok(tasks)
    }

    async fn generate(
        &self,
        role: &RequestContext,
        job: &Job,
        g: &types::S3JobManifestGenerator,
    ) -> Result<Vec<Task>, Failure> {
        let bucket = bucket_of(&g.source_bucket)
            .ok_or_else(|| ("InvalidManifest".to_string(), "The source bucket ARN is not valid".to_string()))?
            .to_string();
        let filter = g.filter.clone().unwrap_or_default();
        let mut tasks = Vec::new();
        let mut marker: Option<(String, String)> = None;
        loop {
            let mut req = json!({"Bucket": bucket});
            if let Some((k, v)) = &marker {
                req["KeyMarker"] = json!(k);
                req["VersionIdMarker"] = json!(v);
            }
            let out = self
                .s3_call(role, "ListObjectVersions", req)
                .await
                .map_err(|e| (e.code.to_string(), format!("Listing the source bucket failed: {}", e.message)))?;
            for v in out.get("Versions").and_then(Value::as_array).into_iter().flatten() {
                if v.get("IsLatest").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
                let key = v.get("Key").and_then(Value::as_str).unwrap_or_default().to_string();
                let size = v.get("Size").and_then(Value::as_i64).unwrap_or(0);
                let class = v.get("StorageClass").and_then(Value::as_str).unwrap_or("STANDARD");
                let modified = v.get("LastModified").and_then(|m| {
                    m.as_str()
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc)))
                        .or_else(|| m.as_f64().and_then(|e| DateTime::from_timestamp(e as i64, 0)))
                });
                if !generator_matches(&filter, &key, size, class, modified) {
                    continue;
                }
                let version = v.get("VersionId").and_then(Value::as_str).filter(|v| *v != "null").map(str::to_string);
                if filter.match_any_object_encryption.is_some() || filter.object_replication_statuses.is_some() {
                    let head = self
                        .s3_call(role, "HeadObject", json!({"Bucket": bucket, "Key": key}))
                        .await
                        .unwrap_or(Value::Null);
                    if !head_matches(&filter, &head) {
                        continue;
                    }
                }
                tasks.push(Task { bucket: bucket.clone(), key, version_id: version });
            }
            if out.get("IsTruncated").and_then(Value::as_bool) != Some(true) {
                break;
            }
            let k = out.get("NextKeyMarker").and_then(Value::as_str).unwrap_or_default().to_string();
            let v = out.get("NextVersionIdMarker").and_then(Value::as_str).unwrap_or_default().to_string();
            marker = Some((k, v));
        }
        if g.enable_manifest_output {
            if let Some(loc) = &g.manifest_output_location {
                let descriptor = self.write_generated_manifest(role, job, loc, &bucket, &tasks).await?;
                let mut st = self.write();
                if let Some(j) = st.jobs.get_mut(&job.id) {
                    j.generated_manifest = Some(descriptor);
                }
            }
        }
        Ok(tasks)
    }

    async fn put(
        &self,
        role: &RequestContext,
        bucket: &str,
        key: &str,
        body: &[u8],
        expected_owner: Option<&str>,
        kms: Option<&str>,
    ) -> Result<String, ServiceError> {
        let mut req = json!({
            "Bucket": bucket,
            "Key": key,
            "Body": base64::engine::general_purpose::STANDARD.encode(body),
        });
        if let Some(o) = expected_owner {
            req["ExpectedBucketOwner"] = json!(o);
        }
        if let Some(k) = kms {
            req["ServerSideEncryption"] = json!("aws:kms");
            req["SSEKMSKeyId"] = json!(k);
        }
        let out = self.s3_call(role, "PutObject", req).await?;
        Ok(out.get("ETag").and_then(Value::as_str).unwrap_or_default().to_string())
    }

    async fn write_generated_manifest(
        &self,
        role: &RequestContext,
        job: &Job,
        loc: &types::S3ManifestOutputLocation,
        source: &str,
        tasks: &[Task],
    ) -> Result<types::S3GeneratedManifestDescriptor, Failure> {
        let fail =
            |e: ServiceError| (e.code.to_string(), format!("Writing the generated manifest failed: {}", e.message));
        let bucket = bucket_of(&loc.bucket).unwrap_or_default().to_string();
        let prefix =
            loc.manifest_prefix.as_deref().map(|p| format!("{}/", p.trim_end_matches('/'))).unwrap_or_default();
        let base = format!("{prefix}job-{}", job.id);
        let mut csv = String::new();
        for t in tasks {
            csv.push_str(&csv_line(&[&t.bucket, &url_encode(&t.key), t.version_id.as_deref().unwrap_or("")]));
            csv.push('\n');
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, csv.as_bytes()).ok();
        let data = gz.finish().unwrap_or_default();
        let data_key = format!("{base}/data/{}.csv.gz", uuid::Uuid::new_v4());
        let kms = loc.manifest_encryption.as_ref().and_then(|e| e.ssekms.as_ref()).map(|k| k.key_id.as_str());
        let owner = loc.expected_manifest_bucket_owner.as_deref();
        self.put(role, &bucket, &data_key, &data, owner, kms).await.map_err(fail)?;
        let md5 = {
            use md5::Digest;
            hex::encode(md5::Md5::digest(&data))
        };
        let manifest = json!({
            "sourceBucket": source,
            "destinationBucket": loc.bucket,
            "version": "2021-11-30",
            "creationTimestamp": job.created.map(|c| c.timestamp_millis().to_string()),
            "fileFormat": "CSV",
            "fileSchema": "Bucket, Key, VersionId",
            "files": [{"key": data_key, "size": data.len(), "MD5checksum": md5}],
        });
        let manifest_key = format!("{base}/manifest.json");
        let etag =
            self.put(role, &bucket, &manifest_key, manifest.to_string().as_bytes(), owner, kms).await.map_err(fail)?;
        Ok(types::S3GeneratedManifestDescriptor {
            format: Some(loc.manifest_format.clone()),
            location: Some(types::JobManifestLocation {
                object_arn: format!("arn:{}:s3:::{bucket}/{manifest_key}", role.partition),
                object_version_id: None,
                e_tag: etag.trim_matches('"').to_string(),
            }),
        })
    }

    async fn write_report(&self, role: &RequestContext, job: &Job, results: &[(Task, Outcome)]) -> Result<(), Failure> {
        let r = &job.request.report;
        let fail = |e: ServiceError| {
            (
                "ReportWriteFailed".to_string(),
                format!("Writing the completion report failed: {}: {}", e.code, e.message),
            )
        };
        let bucket = r.bucket.as_deref().and_then(bucket_of).unwrap_or_default().to_string();
        let prefix = r.prefix.as_deref().map(|p| format!("{}/", p.trim_end_matches('/'))).unwrap_or_default();
        let base = format!("{prefix}job-{}", job.id);
        let failed_only = r.report_scope.as_deref() == Some("FailedTasksOnly");
        let mut files = Vec::new();
        for (status, wanted) in [("succeeded", true), ("failed", false)] {
            if wanted && failed_only {
                continue;
            }
            let rows: Vec<&(Task, Outcome)> = results.iter().filter(|(_, o)| o.succeeded == wanted).collect();
            if rows.is_empty() {
                continue;
            }
            let mut csv = String::new();
            for (t, o) in rows {
                let http = o.http_status.to_string();
                csv.push_str(&csv_line(&[
                    &t.bucket,
                    &url_encode(&t.key),
                    t.version_id.as_deref().unwrap_or(""),
                    status,
                    &http,
                    &o.error_code,
                    &o.message,
                ]));
                csv.push('\n');
            }
            let key = format!("{base}/results/{}.csv", uuid::Uuid::new_v4());
            self.put(role, &bucket, &key, csv.as_bytes(), r.expected_bucket_owner.as_deref(), None)
                .await
                .map_err(fail)?;
            let md5 = {
                use md5::Digest;
                hex::encode(md5::Md5::digest(csv.as_bytes()))
            };
            files.push(json!({"TaskExecutionStatus": status, "Bucket": bucket, "MD5Checksum": md5, "Key": key}));
        }
        let manifest = json!({
            "Format": r.format.clone().unwrap_or_else(|| "Report_CSV_20180820".into()),
            "ReportCreationDate": Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            "Results": files,
            "ReportSchema": "Bucket, Key, VersionId, TaskStatus, HTTPStatusCode, ErrorCode, ResultMessage",
        });
        self.put(
            role,
            &bucket,
            &format!("{base}/manifest.json"),
            manifest.to_string().as_bytes(),
            r.expected_bucket_owner.as_deref(),
            None,
        )
        .await
        .map_err(fail)?;
        Ok(())
    }

    async fn run_task(&self, role: &RequestContext, job: &Job, task: &Task) -> Outcome {
        let o = &job.request.operation;
        let mut target = json!({"Bucket": task.bucket, "Key": task.key});
        if let Some(v) = &task.version_id {
            target["VersionId"] = json!(v);
        }
        let result = if let Some(l) = &o.lambda_invoke {
            return self.invoke_lambda(role, job, task, l).await;
        } else if let Some(c) = &o.s3_put_object_copy {
            let dest = c.target_resource.as_deref().and_then(bucket_of).unwrap_or_default();
            let key = format!("{}{}", c.target_key_prefix.as_deref().unwrap_or(""), task.key);
            let mut source = format!("{}/{}", task.bucket, url_encode(&task.key).replace("%2F", "/"));
            if let Some(v) = &task.version_id {
                source.push_str(&format!("?versionId={v}"));
            }
            let mut req = json!({"Bucket": dest, "Key": key, "CopySource": source});
            let set = |req: &mut Value, k: &str, v: Option<Value>| {
                if let Some(v) = v {
                    req[k] = v;
                }
            };
            set(&mut req, "ACL", c.canned_access_control_list.clone().map(Value::from));
            set(&mut req, "StorageClass", c.storage_class.clone().map(Value::from));
            set(&mut req, "WebsiteRedirectLocation", c.redirect_location.clone().map(Value::from));
            set(&mut req, "ChecksumAlgorithm", c.checksum_algorithm.clone().map(Value::from));
            set(&mut req, "ObjectLockMode", c.object_lock_mode.clone().map(Value::from));
            set(&mut req, "ObjectLockLegalHoldStatus", c.object_lock_legal_hold_status.clone().map(Value::from));
            set(&mut req, "ObjectLockRetainUntilDate", c.object_lock_retain_until_date.map(|d| json!(d.to_rfc3339())));
            set(&mut req, "CopySourceIfModifiedSince", c.modified_since_constraint.map(|d| json!(d.to_rfc3339())));
            set(&mut req, "CopySourceIfUnmodifiedSince", c.un_modified_since_constraint.map(|d| json!(d.to_rfc3339())));
            if let Some(k) = &c.sse_aws_kms_key_id {
                req["ServerSideEncryption"] = json!("aws:kms");
                req["SSEKMSKeyId"] = json!(k);
                req["BucketKeyEnabled"] = json!(c.bucket_key_enabled);
            }
            if c.requester_pays {
                req["RequestPayer"] = json!("requester");
            }
            if let Some(tags) = &c.new_object_tagging {
                let mut s = form_urlencoded::Serializer::new(String::new());
                for t in tags {
                    s.append_pair(&t.key, &t.value);
                }
                req["Tagging"] = json!(s.finish());
                req["TaggingDirective"] = json!("REPLACE");
            }
            let replace = c.metadata_directive.as_deref() == Some("REPLACE") || c.new_object_metadata.is_some();
            if let Some(m) = c.new_object_metadata.as_ref().filter(|_| replace) {
                req["MetadataDirective"] = json!("REPLACE");
                set(&mut req, "CacheControl", m.cache_control.clone().map(Value::from));
                set(&mut req, "ContentDisposition", m.content_disposition.clone().map(Value::from));
                set(&mut req, "ContentEncoding", m.content_encoding.clone().map(Value::from));
                set(&mut req, "ContentLanguage", m.content_language.clone().map(Value::from));
                set(&mut req, "ContentType", m.content_type.clone().map(Value::from));
                set(&mut req, "Expires", m.http_expires_date.map(|d| json!(d.to_rfc3339())));
                set(&mut req, "Metadata", m.user_metadata.clone().map(|u| json!(u)));
            }
            self.s3_call(role, "CopyObject", req).await.map(|_| "Successful".to_string())
        } else if let Some(a) = &o.s3_put_object_acl {
            let mut req = target.clone();
            match &a.access_control_policy {
                Some(p) if p.canned_access_control_list.is_some() => {
                    req["ACL"] = json!(p.canned_access_control_list);
                }
                Some(p) => {
                    let list = p.access_control_list.clone().unwrap_or_default();
                    let grants: Vec<Value> = list
                        .grants
                        .unwrap_or_default()
                        .into_iter()
                        .map(|g| {
                            let grantee = g.grantee.unwrap_or_default();
                            let mut ge = match grantee.type_identifier.as_deref() {
                                Some("uri") => json!({"Type": "Group", "URI": grantee.identifier}),
                                Some("emailAddress") => {
                                    json!({"Type": "AmazonCustomerByEmail", "EmailAddress": grantee.identifier})
                                }
                                _ => json!({"Type": "CanonicalUser", "ID": grantee.identifier}),
                            };
                            if let Some(d) = grantee.display_name {
                                ge["DisplayName"] = json!(d);
                            }
                            json!({"Grantee": ge, "Permission": g.permission})
                        })
                        .collect();
                    req["AccessControlPolicy"] = json!({"Owner": {"ID": list.owner.id, "DisplayName": list.owner.display_name}, "Grants": grants});
                }
                None => {}
            }
            self.s3_call(role, "PutObjectAcl", req).await.map(|_| "Successful".to_string())
        } else if let Some(t) = &o.s3_put_object_tagging {
            let tags: Vec<Value> =
                t.tag_set.iter().flatten().map(|t| json!({"Key": t.key, "Value": t.value})).collect();
            let mut req = target.clone();
            req["Tagging"] = json!({"TagSet": tags});
            self.s3_call(role, "PutObjectTagging", req).await.map(|_| "Successful".to_string())
        } else if o.s3_delete_object_tagging.is_some() {
            self.s3_call(role, "DeleteObjectTagging", target.clone()).await.map(|_| "Successful".to_string())
        } else if let Some(r) = &o.s3_initiate_restore_object {
            let mut req = target.clone();
            let tier = match r.glacier_job_tier.as_deref() {
                Some("BULK") => "Bulk",
                _ => "Standard",
            };
            let mut restore = json!({"GlacierJobParameters": {"Tier": tier}});
            if let Some(d) = r.expiration_in_days {
                restore["Days"] = json!(d);
            }
            req["RestoreRequest"] = restore;
            self.s3_call(role, "RestoreObject", req).await.map(|_| "Successful".to_string())
        } else if let Some(h) = &o.s3_put_object_legal_hold {
            let mut req = target.clone();
            req["LegalHold"] = json!({"Status": h.legal_hold.status});
            self.s3_call(role, "PutObjectLegalHold", req).await.map(|_| "Successful".to_string())
        } else if let Some(r) = &o.s3_put_object_retention {
            let mut req = target.clone();
            let mut retention = json!({});
            if let Some(m) = &r.retention.mode {
                retention["Mode"] = json!(m);
            }
            if let Some(d) = r.retention.retain_until_date {
                retention["RetainUntilDate"] = json!(d.to_rfc3339());
            }
            req["Retention"] = retention;
            if r.bypass_governance_retention == Some(true) {
                req["BypassGovernanceRetention"] = json!(true);
            }
            self.s3_call(role, "PutObjectRetention", req).await.map(|_| "Successful".to_string())
        } else if o.s3_replicate_object.is_some() {
            match &self.s3 {
                Some(s3) => s3
                    .replicate_existing(role, &task.bucket, &task.key, task.version_id.as_deref())
                    .map(|status| status.to_string()),
                None => Err(err("InternalError", 500, "S3 is not available")),
            }
        } else if let Some(c) = &o.s3_compute_object_checksum {
            self.compute_checksum(role, &target, c).await
        } else if let Some(e) = &o.s3_update_object_encryption {
            let mut req = target.clone();
            if let Some(k) = e.object_encryption.as_ref().and_then(|e| e.ssekms.as_ref()) {
                req["ObjectEncryption"] =
                    json!({"SSEKMS": {"KMSKeyArn": k.kms_key_arn, "BucketKeyEnabled": k.bucket_key_enabled}});
            }
            self.s3_call(role, "UpdateObjectEncryption", req).await.map(|_| "Successful".to_string())
        } else {
            Ok("Successful".to_string())
        };
        match result {
            Ok(m) => Outcome::ok(m),
            Err(e) => Outcome::from_error(&e),
        }
    }

    async fn compute_checksum(
        &self,
        role: &RequestContext,
        target: &Value,
        c: &types::S3ComputeObjectChecksumOperation,
    ) -> Result<String, ServiceError> {
        let out = self.s3_call(role, "GetObject", target.clone()).await?;
        let data = decode_body(&out);
        let algorithm = c.checksum_algorithm.clone().unwrap_or_else(|| "CRC64NVME".into());
        let checksum = mws_s3::compute_checksum(&algorithm, &data)
            .ok_or_else(|| bad_request(format!("Checksum algorithm {algorithm} is not supported")))?;
        Ok(json!({
            "checksum_base64": checksum,
            "checksumAlgorithm": algorithm,
            "checksumType": c.checksum_type.clone().unwrap_or_else(|| "FULL_OBJECT".into()),
        })
        .to_string())
    }

    async fn invoke_lambda(
        &self,
        role: &RequestContext,
        job: &Job,
        task: &Task,
        l: &types::LambdaInvokeOperation,
    ) -> Outcome {
        let Some(lambda) = self.lambda.get() else {
            return Outcome::from_error(&err("InternalError", 500, "Lambda is not available"));
        };
        let task_id = uuid::Uuid::new_v4().to_string();
        let schema = l.invocation_schema_version.clone().unwrap_or_else(|| "1.0".into());
        let event = if schema == "2.0" {
            json!({
                "invocationSchemaVersion": "2.0",
                "invocationId": uuid::Uuid::new_v4().to_string(),
                "job": {"id": job.id, "userArguments": l.user_arguments.clone().unwrap_or_default()},
                "tasks": [{"taskId": task_id, "s3Bucket": task.bucket, "s3Key": task.key, "s3VersionId": task.version_id}],
            })
        } else {
            json!({
                "invocationSchemaVersion": "1.0",
                "invocationId": uuid::Uuid::new_v4().to_string(),
                "job": {"id": job.id},
                "tasks": [{"taskId": task_id, "s3Key": task.key, "s3VersionId": task.version_id,
                           "s3BucketArn": format!("arn:{}:s3:::{}", role.partition, task.bucket)}],
            })
        };
        let function = l.function_arn.clone().unwrap_or_default();
        let (name, qualifier) = match function.rsplit_once(':') {
            Some((base, q)) if base.matches(':').count() == 6 => (base.to_string(), Some(q.to_string())),
            _ => (function.clone(), None),
        };
        let request = mws_lambda::generated::types::InvocationRequest {
            function_name: name,
            qualifier: qualifier.filter(|q| q != "$LATEST"),
            payload: Some(event.to_string().into_bytes()),
            ..Default::default()
        };
        let response = match <mws_lambda::Lambda as mws_lambda::generated::Handler>::invoke(lambda, role, request).await
        {
            Ok(r) => r,
            Err(e) => return Outcome::from_error(&e),
        };
        let payload = response.payload.unwrap_or_default();
        if response.function_error.is_some() {
            return Outcome {
                succeeded: false,
                http_status: 200,
                error_code: "Lambda.FunctionError".into(),
                message: String::from_utf8_lossy(&payload).into_owned(),
            };
        }
        let Ok(out) = serde_json::from_slice::<Value>(&payload) else {
            return Outcome {
                succeeded: false,
                http_status: 200,
                error_code: "Lambda.InvalidResponse".into(),
                message: "The Lambda function's response is not valid JSON".into(),
            };
        };
        let result = out
            .get("results")
            .and_then(Value::as_array)
            .and_then(|r| r.iter().find(|r| r.get("taskId").and_then(Value::as_str) == Some(task_id.as_str())));
        let treat_missing = out.get("treatMissingKeysAs").and_then(Value::as_str).unwrap_or("PermanentFailure");
        let (code, message) = match result {
            Some(r) => (
                r.get("resultCode").and_then(Value::as_str).unwrap_or(treat_missing).to_string(),
                r.get("resultString").and_then(Value::as_str).unwrap_or_default().to_string(),
            ),
            None => (treat_missing.to_string(), String::new()),
        };
        if code == "Succeeded" {
            Outcome::ok(message)
        } else {
            Outcome { succeeded: false, http_status: 200, error_code: code, message }
        }
    }

    pub(crate) async fn describe_job(
        &self,
        ctx: &RequestContext,
        input: types::DescribeJobRequest,
    ) -> Result<types::DescribeJobResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::job_arn(ctx, &account, &input.job_id);
        ctx.authorize("s3:DescribeJob", &arn, ConditionContext::new())?;
        let j = self.job(&account, &input.job_id)?;
        Ok(types::DescribeJobResult {
            job: Some(types::JobDescriptor {
                job_id: Some(j.id.clone()),
                confirmation_required: j.request.confirmation_required,
                description: j.request.description.clone(),
                job_arn: Some(j.arn.clone()),
                status: Some(j.status.clone()),
                manifest: j.request.manifest.clone(),
                operation: Some(j.request.operation.clone()),
                priority: j.request.priority,
                progress_summary: Some(j.progress()),
                status_update_reason: j.status_update_reason.clone(),
                failure_reasons: (!j.failures.is_empty()).then(|| {
                    j.failures
                        .iter()
                        .map(|(c, r)| types::JobFailure {
                            failure_code: Some(c.clone()),
                            failure_reason: Some(r.clone()),
                        })
                        .collect()
                }),
                report: Some(j.request.report.clone()),
                creation_time: j.created,
                termination_date: j.terminated,
                role_arn: Some(j.request.role_arn.clone()),
                suspended_date: j.suspended,
                suspended_cause: j.suspended_cause.clone(),
                manifest_generator: j.request.manifest_generator.clone(),
                generated_manifest_descriptor: j.generated_manifest.clone(),
            }),
        })
    }

    pub(crate) async fn list_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListJobsRequest,
    ) -> Result<types::ListJobsResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListJobs", "*", ConditionContext::new())?;
        let max = input.max_results.unwrap_or(1000).clamp(1, 1000) as usize;
        let st = self.read();
        let mut jobs: Vec<&Job> = st
            .jobs
            .values()
            .filter(|j| j.account_id == account)
            .filter(|j| input.job_statuses.as_ref().is_none_or(|s| s.is_empty() || s.contains(&j.status)))
            .collect();
        // Newest first, ties by id.
        jobs.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
        let start = match &input.next_token {
            Some(t) => jobs.iter().position(|j| &j.id == t).ok_or_else(|| bad_request("The NextToken is invalid"))?,
            None => 0,
        };
        let page: Vec<types::JobListDescriptor> = jobs
            .iter()
            .skip(start)
            .take(max)
            .map(|j| types::JobListDescriptor {
                job_id: Some(j.id.clone()),
                description: j.request.description.clone(),
                operation: Some(j.operation_name().to_string()),
                priority: j.request.priority,
                status: Some(j.status.clone()),
                creation_time: j.created,
                termination_date: j.terminated,
                progress_summary: Some(j.progress()),
            })
            .collect();
        let next = jobs.get(start + max).map(|j| j.id.clone());
        Ok(types::ListJobsResult { next_token: next, jobs: Some(page) })
    }

    pub(crate) async fn update_job_priority(
        &self,
        ctx: &RequestContext,
        input: types::UpdateJobPriorityRequest,
    ) -> Result<types::UpdateJobPriorityResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::job_arn(ctx, &account, &input.job_id);
        ctx.authorize("s3:UpdateJobPriority", &arn, ConditionContext::new())?;
        self.job(&account, &input.job_id)?;
        let mut st = self.write();
        let j = st.jobs.get_mut(&input.job_id).ok_or_else(|| not_found(&input.job_id))?;
        j.request.priority = input.priority;
        Ok(types::UpdateJobPriorityResult { job_id: j.id.clone(), priority: input.priority })
    }

    pub(crate) async fn update_job_status(
        &self,
        ctx: &RequestContext,
        input: types::UpdateJobStatusRequest,
    ) -> Result<types::UpdateJobStatusResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::job_arn(ctx, &account, &input.job_id);
        ctx.authorize("s3:UpdateJobStatus", &arn, ConditionContext::new())?;
        let job = self.job(&account, &input.job_id)?;
        let invalid = |to: &str| {
            err("JobStatusException", 400, format!("Job {} cannot be moved from {} to {to}", job.id, job.status))
        };
        let start = match input.requested_job_status.as_str() {
            "Ready" => {
                if job.status != "Suspended" {
                    return Err(invalid("Ready"));
                }
                true
            }
            "Cancelled" => {
                if job.terminal() || job.status == "Completing" {
                    return Err(invalid("Cancelled"));
                }
                false
            }
            other => return Err(bad_request(format!("Invalid requested job status: {other}"))),
        };
        let status = {
            let mut st = self.write();
            let j = st.jobs.get_mut(&input.job_id).ok_or_else(|| not_found(&input.job_id))?;
            j.status_update_reason = input.status_update_reason.clone();
            if start {
                j.status = "Ready".into();
                j.suspended_cause = None;
            } else {
                j.status = "Cancelled".into();
                j.terminated = Some(ctx.received_at);
            }
            j.status.clone()
        };
        if start {
            self.start(ctx, &input.job_id);
        }
        Ok(types::UpdateJobStatusResult {
            job_id: Some(input.job_id),
            status: Some(status),
            status_update_reason: input.status_update_reason,
        })
    }

    pub(crate) async fn get_job_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetJobTaggingRequest,
    ) -> Result<types::GetJobTaggingResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::job_arn(ctx, &account, &input.job_id);
        ctx.authorize("s3:GetJobTagging", &arn, ConditionContext::new())?;
        let j = self.job(&account, &input.job_id)?;
        Ok(types::GetJobTaggingResult { tags: Some(j.tags) })
    }

    pub(crate) async fn put_job_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutJobTaggingRequest,
    ) -> Result<types::PutJobTaggingResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::job_arn(ctx, &account, &input.job_id);
        let mut condition = ConditionContext::new();
        for t in &input.tags {
            condition.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone()]);
        }
        ctx.authorize("s3:PutJobTagging", &arn, condition)?;
        self.job(&account, &input.job_id)?;
        if input.tags.len() > 50 {
            return Err(err("TooManyTagsException", 400, "The number of tags exceeds the limit of 50 tags"));
        }
        let mut st = self.write();
        let j = st.jobs.get_mut(&input.job_id).ok_or_else(|| not_found(&input.job_id))?;
        j.tags = input.tags;
        Ok(types::PutJobTaggingResult::default())
    }

    pub(crate) async fn delete_job_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteJobTaggingRequest,
    ) -> Result<types::DeleteJobTaggingResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::job_arn(ctx, &account, &input.job_id);
        ctx.authorize("s3:DeleteJobTagging", &arn, ConditionContext::new())?;
        self.job(&account, &input.job_id)?;
        let mut st = self.write();
        if let Some(j) = st.jobs.get_mut(&input.job_id) {
            j.tags.clear();
        }
        Ok(types::DeleteJobTaggingResult::default())
    }
}

fn split_object_arn(arn: &str) -> Option<(String, String)> {
    let rest = arn.strip_prefix("arn:")?.split_once(":::")?.1;
    let (bucket, key) = rest.split_once('/')?;
    Some((bucket.to_string(), key.to_string()))
}

/// Tasks from CSV rows whose columns are `fields`. Keys are URL-encoded in
/// both manifest formats.
fn csv_tasks(text: &str, fields: &[String], encoded: bool) -> Vec<Task> {
    let mut tasks = Vec::new();
    for line in text.lines().map(str::trim_end).filter(|l| !l.is_empty()) {
        let cols = parse_csv_line(line);
        let mut row: BTreeMap<&str, String> = BTreeMap::new();
        for (f, v) in fields.iter().zip(cols) {
            row.insert(f.as_str(), v);
        }
        let (Some(bucket), Some(key)) = (row.get("Bucket"), row.get("Key")) else { continue };
        let key = if encoded { url_decode(key) } else { key.clone() };
        let version_id = row.get("VersionId").filter(|v| !v.is_empty()).cloned();
        tasks.push(Task { bucket: bucket.clone(), key, version_id });
    }
    tasks
}

fn generator_matches(
    f: &types::JobManifestGeneratorFilter,
    key: &str,
    size: i64,
    class: &str,
    modified: Option<DateTime<Utc>>,
) -> bool {
    if let Some(k) = &f.key_name_constraint {
        let any = |list: &Option<Vec<String>>, test: &dyn Fn(&str) -> bool| {
            list.as_ref().is_none_or(|l| l.iter().any(|v| test(v)))
        };
        if !any(&k.match_any_prefix, &|p| key.starts_with(p))
            || !any(&k.match_any_suffix, &|s| key.ends_with(s))
            || !any(&k.match_any_substring, &|s| key.contains(s))
        {
            return false;
        }
    }
    if f.object_size_greater_than_bytes.is_some_and(|n| size <= n)
        || f.object_size_less_than_bytes.is_some_and(|n| size >= n)
    {
        return false;
    }
    if f.match_any_storage_class.as_ref().is_some_and(|c| !c.is_empty() && !c.iter().any(|c| c == class)) {
        return false;
    }
    if let Some(m) = modified {
        if f.created_after.is_some_and(|a| m <= a) || f.created_before.is_some_and(|b| m >= b) {
            return false;
        }
    }
    true
}

fn head_matches(f: &types::JobManifestGeneratorFilter, head: &Value) -> bool {
    if let Some(statuses) = &f.object_replication_statuses {
        let s = head.get("ReplicationStatus").and_then(Value::as_str).unwrap_or("NONE");
        let s = if s == "COMPLETE" { "COMPLETED" } else { s };
        if !statuses.iter().any(|w| w == s) {
            return false;
        }
    }
    if let Some(encs) = &f.match_any_object_encryption {
        let sse = head.get("ServerSideEncryption").and_then(Value::as_str);
        let ssec = head.get("SSECustomerAlgorithm").is_some();
        let ok = encs.iter().any(|e| match e {
            types::ObjectEncryptionFilter::SSES3(_) => sse == Some("AES256"),
            types::ObjectEncryptionFilter::SSEKMS(_) => sse == Some("aws:kms"),
            types::ObjectEncryptionFilter::DSSEKMS(_) => sse == Some("aws:kms:dsse"),
            types::ObjectEncryptionFilter::SSEC(_) => ssec,
            types::ObjectEncryptionFilter::NOTSSE(_) => sse.is_none() && !ssec,
        });
        if !ok {
            return false;
        }
    }
    true
}
