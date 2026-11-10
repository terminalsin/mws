//! Running batch inference jobs: read the JSONL records from S3, answer
//! each, and write `<file>.out` and `manifest.json.out` under
//! `<output>/<job id>/`, as Bedrock does.

use std::sync::{Arc, Weak};

use mws_bedrock::storage::{JobStorage, RoleStorage};
use mws_bedrock::BatchJob;
use mws_core::RequestContext;
use mws_s3::generated::types::{GetObjectRequest, ListObjectsV2Request, PutObjectRequest};
use mws_s3::S3;
use serde_json::{json, Value};

use crate::{join_key, s3_location, BedrockRuntime, Guards};

impl BedrockRuntime {
    pub(crate) async fn run_batch(&self, job: BatchJob) {
        let bedrock = self.inner.bedrock.clone();
        if !bedrock.start_invocation_job(&job.account, &job.region, &job.job_arn, job.submitted) {
            return;
        }
        let result = self.batch_records(&job).await;
        let now = job.submitted + chrono::Duration::seconds(1);
        match result {
            Ok(counts) => bedrock.finish_invocation_job(&job.account, &job.region, &job.job_arn, now, counts, None),
            // Validation failures end the job at once.
            Err(message) => bedrock.finish_invocation_job(
                &job.account,
                &job.region,
                &job.job_arn,
                job.submitted,
                (0, 0, 0),
                Some(message),
            ),
        }
    }

    async fn batch_records(&self, job: &BatchJob) -> Result<(i64, i64, i64), String> {
        let (in_bucket, in_key) =
            s3_location(&job.input_uri).ok_or_else(|| format!("The input S3 URI {} is invalid.", job.input_uri))?;
        let (out_bucket, out_prefix) =
            s3_location(&job.output_uri).ok_or_else(|| format!("The output S3 URI {} is invalid.", job.output_uri))?;
        // Bedrock reads and writes S3 as the job's service role.
        let mut ctx = job.context.clone();
        ctx.received_at = job.submitted;
        let role = self.role_context(&ctx, &job.role_arn, &job.job_arn, "BedrockBatchInference")?;
        let io = RoleS3 { s3: self.inner.s3.clone(), ctx: role };
        let keys = match io.get(&in_bucket, &in_key) {
            Ok(_) if !in_key.is_empty() => vec![in_key.clone()],
            _ => {
                let prefix = if in_key.is_empty() { String::new() } else { format!("{in_key}/") };
                io.list(&in_bucket, &prefix)
                    .map_err(|e| format!("Unable to list the input S3 location {}: {e}", job.input_uri))?
                    .into_iter()
                    .filter(|k| k.ends_with(".jsonl"))
                    .collect()
            }
        };
        if keys.is_empty() {
            return Err(format!("No .jsonl input files were found at {}.", job.input_uri));
        }
        // Validate: read every file and count its records first.
        let mut files = Vec::new();
        for key in keys {
            let body = io
                .get(&in_bucket, &key)
                .map_err(|e| format!("Unable to read the input S3 object s3://{in_bucket}/{key}: {e}"))?;
            files.push((key, body));
        }
        let records = files
            .iter()
            .map(|(_, b)| String::from_utf8_lossy(b).lines().filter(|l| !l.trim().is_empty()).count())
            .sum::<usize>();
        let min = self.inner.quotas.value(&job.account, &job.region, "bedrock", MIN_RECORDS_QUOTA, job.submitted);
        if min.is_finite() && (records as f64) < min {
            return Err(format!(
                "The number of records in the job's input files ({records}) is less than the minimum number of records per batch inference job ({min}). Add records and try again."
            ));
        }
        let guards = Guards { list: Vec::new(), trace: false };
        let (mut total, mut ok, mut errors, mut tokens_in, mut tokens_out) = (0i64, 0i64, 0i64, 0i64, 0i64);
        for (key, body) in files {
            let mut out = String::new();
            for line in String::from_utf8_lossy(&body).lines().filter(|l| !l.trim().is_empty()) {
                total += 1;
                let record: Value = serde_json::from_str(line).unwrap_or(Value::Null);
                let record_id = record.get("recordId").cloned().unwrap_or(Value::Null);
                let input = record.get("modelInput").cloned().unwrap_or(Value::Null);
                let line_out =
                    match self.invoke_native(job.family, &job.model_id, input.to_string().as_bytes(), &guards).await {
                        Ok((output, run)) => {
                            ok += 1;
                            if let Some(run) = run {
                                tokens_in += run.completion.input_tokens as i64;
                                tokens_out += run.completion.output_tokens as i64;
                            }
                            json!({"recordId": record_id, "modelInput": input, "modelOutput": output})
                        }
                        Err(e) => {
                            errors += 1;
                            json!({"recordId": record_id, "modelInput": input,
                               "error": {"errorCode": e.status, "errorMessage": e.message}})
                        }
                    };
                out.push_str(&line_out.to_string());
                out.push('\n');
            }
            let name = key.rsplit('/').next().unwrap_or(&key);
            let out_key = join_key(&join_key(&out_prefix, &job.job_id), &format!("{name}.out"));
            io.put(&out_bucket, &out_key, out.into_bytes(), "application/jsonl")
                .map_err(|e| format!("Unable to write to the output S3 location {}: {e}", job.output_uri))?;
        }
        let manifest = json!({
            "totalRecordCount": total, "processedRecordCount": total, "successRecordCount": ok,
            "errorRecordCount": errors, "inputTokenCount": tokens_in, "outputTokenCount": tokens_out,
        });
        let key = join_key(&join_key(&out_prefix, &job.job_id), "manifest.json.out");
        io.put(&out_bucket, &key, manifest.to_string().into_bytes(), "application/json")
            .map_err(|e| format!("Unable to write to the output S3 location {}: {e}", job.output_uri))?;
        Ok((total, ok, errors))
    }
}

/// The Service Quotas code of "Minimum number of records per batch
/// inference job".
const MIN_RECORDS_QUOTA: &str = "L-29806334";

/// S3 as a job role sees it.
struct RoleS3 {
    s3: S3,
    ctx: RequestContext,
}

/// Customization, import and evaluation jobs' S3 access, for the control
/// plane: the job role assumed through STS.
pub(crate) struct JobS3 {
    pub(crate) runtime: Weak<crate::Inner>,
}

impl JobStorage for JobS3 {
    fn assume(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        source_arn: &str,
        session: &str,
    ) -> Result<Arc<dyn RoleStorage>, String> {
        let inner = self.runtime.upgrade().ok_or("Bedrock is shutting down")?;
        let runtime = BedrockRuntime { inner };
        let role = runtime.role_context(ctx, role_arn, source_arn, session)?;
        Ok(Arc::new(RoleS3 { s3: runtime.inner.s3.clone(), ctx: role }))
    }
}

impl RoleStorage for RoleS3 {
    fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        RoleS3::get(self, bucket, key)
    }

    fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, String> {
        RoleS3::list(self, bucket, prefix)
    }

    fn put(&self, bucket: &str, key: &str, body: Vec<u8>, content_type: &str) -> Result<(), String> {
        RoleS3::put(self, bucket, key, body, content_type)
    }
}

impl RoleS3 {
    fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        let input = GetObjectRequest { bucket: bucket.into(), key: key.into(), ..Default::default() };
        self.s3.get_object_as_caller(&self.ctx, input).map(|o| o.body).map_err(|e| e.message)
    }

    fn list(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, String> {
        let mut keys = Vec::new();
        let mut token = None;
        loop {
            let input = ListObjectsV2Request {
                bucket: bucket.into(),
                prefix: Some(prefix.into()),
                continuation_token: token.take(),
                ..Default::default()
            };
            let out = self.s3.list_objects_as_caller(&self.ctx, input).map_err(|e| e.message)?;
            keys.extend(out.contents.unwrap_or_default().into_iter().filter_map(|o| o.key));
            match out.next_continuation_token {
                Some(t) if out.is_truncated == Some(true) => token = Some(t),
                _ => return Ok(keys),
            }
        }
    }

    fn put(&self, bucket: &str, key: &str, body: Vec<u8>, content_type: &str) -> Result<(), String> {
        let input = PutObjectRequest {
            bucket: bucket.into(),
            key: key.into(),
            body,
            content_type: Some(content_type.into()),
            ..Default::default()
        };
        self.s3.put_object_as_caller(&self.ctx, input).map(|_| ()).map_err(|e| e.message)
    }
}
