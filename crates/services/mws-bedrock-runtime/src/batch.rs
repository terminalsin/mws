//! Running batch inference jobs: read the JSONL records from S3, answer
//! each, and write `<file>.out` and `manifest.json.out` under
//! `<output>/<job id>/`, as Bedrock does.

use mws_bedrock::BatchJob;
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
            Err(message) => {
                bedrock.finish_invocation_job(&job.account, &job.region, &job.job_arn, now, (0, 0, 0), Some(message))
            }
        }
    }

    async fn batch_records(&self, job: &BatchJob) -> Result<(i64, i64, i64), String> {
        let s3 = &self.inner.s3;
        let (in_bucket, in_key) =
            s3_location(&job.input_uri).ok_or_else(|| format!("The input S3 URI {} is invalid.", job.input_uri))?;
        let (out_bucket, out_prefix) =
            s3_location(&job.output_uri).ok_or_else(|| format!("The output S3 URI {} is invalid.", job.output_uri))?;
        let keys = match s3.object_bytes(&in_bucket, &in_key) {
            Some(_) if !in_key.is_empty() => vec![in_key.clone()],
            _ => {
                let prefix = if in_key.is_empty() { String::new() } else { format!("{in_key}/") };
                s3.object_keys(&in_bucket, &prefix)
                    .ok_or_else(|| format!("The specified bucket {in_bucket} does not exist."))?
                    .into_iter()
                    .filter(|k| k.ends_with(".jsonl"))
                    .collect()
            }
        };
        if keys.is_empty() {
            return Err(format!("No .jsonl input files were found at {}.", job.input_uri));
        }
        let guards = Guards { list: Vec::new(), trace: false };
        let (mut total, mut ok, mut errors, mut tokens_in, mut tokens_out) = (0i64, 0i64, 0i64, 0i64, 0i64);
        for key in keys {
            let body = s3.object_bytes(&in_bucket, &key).unwrap_or_default();
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
            s3.put_object_with_role(&out_bucket, &out_key, out.into_bytes(), "application/jsonl")
                .map_err(|e| format!("Unable to write to the output S3 location {}: {e}", job.output_uri))?;
        }
        let manifest = json!({
            "totalRecordCount": total, "processedRecordCount": total, "successRecordCount": ok,
            "errorRecordCount": errors, "inputTokenCount": tokens_in, "outputTokenCount": tokens_out,
        });
        let key = join_key(&join_key(&out_prefix, &job.job_id), "manifest.json.out");
        s3.put_object_with_role(&out_bucket, &key, manifest.to_string().into_bytes(), "application/json")
            .map_err(|e| format!("Unable to write to the output S3 location {}: {e}", job.output_uri))?;
        Ok((total, ok, errors))
    }
}
