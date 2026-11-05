//! Model invocation logging: each successful invocation becomes a
//! `ModelInvocationLog` record (schema 1.0), written to CloudWatch Logs as
//! the configured role and to S3 as `bedrock.amazonaws.com`, as the
//! account's logging configuration says.

use std::io::Write as _;

use mws_bedrock::generated::types::{CloudWatchConfig, S3Config};
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::BedrockRuntime;

pub(crate) const SERVICE_PRINCIPAL: &str = "bedrock.amazonaws.com";
const LOG_STREAM: &str = "aws/bedrock/modelinvocations";

tokio::task_local! {
    /// The body of the request being handled, which invocation logs quote.
    pub(crate) static REQUEST_BODY: Vec<u8>;
}

/// The request body, as JSON, when the request had one.
pub(crate) fn request_json() -> Option<Value> {
    REQUEST_BODY.try_with(|b| serde_json::from_slice(b).ok()).ok().flatten()
}

/// What kind of data an invocation carries, which decides whether the
/// bodies are logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Modality {
    Text,
    Image,
    Embedding,
    Video,
}

/// One invocation to log.
pub(crate) struct Invocation<'a> {
    pub operation: &'a str,
    /// The identifier the caller invoked (a model id, profile or ARN).
    pub model_id: &'a str,
    pub modality: Modality,
    pub input: Option<Value>,
    pub output: Value,
    pub input_tokens: i64,
    pub output_tokens: i64,
}

impl BedrockRuntime {
    /// Deliver `inv` to the destinations the logging configuration names.
    /// Failures are dropped (and traced), as Bedrock does not fail the
    /// invocation over its logs.
    pub(crate) fn log_invocation(&self, ctx: &RequestContext, inv: Invocation<'_>) {
        let Some(cfg) = self.bedrock().invocation_logging(&ctx.caller.account_id, &ctx.region) else { return };
        let bodies = match inv.modality {
            Modality::Text => cfg.text_data_delivery_enabled,
            Modality::Image => cfg.image_data_delivery_enabled,
            Modality::Embedding => cfg.embedding_data_delivery_enabled,
            Modality::Video => cfg.video_data_delivery_enabled,
        }
        .unwrap_or(true);
        let mut input = json!({"inputContentType": "application/json", "inputTokenCount": inv.input_tokens});
        let mut output = json!({"outputContentType": "application/json", "outputTokenCount": inv.output_tokens});
        if bodies {
            input["inputBodyJson"] = inv.input.unwrap_or(Value::Null);
            output["outputBodyJson"] = inv.output;
        }
        let record = json!({
            "schemaType": "ModelInvocationLog",
            "schemaVersion": "1.0",
            "timestamp": ctx.received_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "accountId": ctx.caller.account_id,
            "identity": {"arn": ctx.caller.arn},
            "region": ctx.region,
            "requestId": ctx.request_id,
            "operation": inv.operation,
            "modelId": inv.model_id,
            "input": input,
            "output": output,
        });
        if let Some(cw) = &cfg.cloud_watch_config {
            if let Err(e) = self.log_to_cloudwatch(ctx, cw, &record) {
                tracing::warn!(log_group = %cw.log_group_name, "Bedrock invocation log not delivered: {e}");
            }
        }
        if let Some(s3) = &cfg.s3_config {
            if let Err(e) = self.log_to_s3(ctx, s3, &record) {
                tracing::warn!(bucket = %s3.bucket_name, "Bedrock invocation log not delivered: {e}");
            }
        }
    }

    /// `aws:SourceArn` for what Bedrock does on the account's behalf.
    pub(crate) fn source_arn(ctx: &RequestContext, account: &str) -> String {
        format!("arn:{}:bedrock:{}:{account}:*", ctx.partition, ctx.region)
    }

    fn log_to_cloudwatch(&self, ctx: &RequestContext, cw: &CloudWatchConfig, record: &Value) -> Result<(), String> {
        let logs = self.inner.logs.get().ok_or("CloudWatch Logs is not available")?;
        let account = ctx.caller.account_id.clone();
        let role = self.role_context(ctx, &cw.role_arn, &Self::source_arn(ctx, &account), "BedrockLogging")?;
        let event =
            mws_logs::ServiceLogEvent { timestamp: ctx.received_at.timestamp_millis(), message: record.to_string() };
        logs.put_log_events_as_caller(&role, &cw.log_group_name, LOG_STREAM, vec![event]).map_err(|e| e.message)
    }

    fn log_to_s3(&self, ctx: &RequestContext, s3: &S3Config, record: &Value) -> Result<(), String> {
        let account = ctx.caller.account_id.as_str();
        let t = ctx.received_at;
        let prefix = s3.key_prefix.as_deref().map(|p| p.trim_matches('/')).filter(|p| !p.is_empty());
        let key = format!(
            "{}AWSLogs/{account}/BedrockModelInvocationLogs/{}/{}/{}_{}.json.gz",
            prefix.map(|p| format!("{p}/")).unwrap_or_default(),
            ctx.region,
            t.format("%Y/%m/%d/%H"),
            t.format("%Y%m%dT%H%M%S%3fZ"),
            uuid::Uuid::new_v4().simple(),
        );
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(format!("{record}\n").as_bytes()).map_err(|e| e.to_string())?;
        let body = gz.finish().map_err(|e| e.to_string())?;
        let source_arn = Self::source_arn(ctx, account);
        self.inner
            .s3
            .put_object_as_service(mws_s3::ServicePutObject {
                bucket: &s3.bucket_name,
                key: &key,
                body,
                content_type: "application/x-gzip",
                service_principal: SERVICE_PRINCIPAL,
                source_account: account,
                source_arn: &source_arn,
                acl: None,
                partition: &ctx.partition,
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// `ctx` acting as `role`, assumed by Bedrock's service principal.
    pub(crate) fn role_context(
        &self,
        ctx: &RequestContext,
        role: &str,
        source_arn: &str,
        session: &str,
    ) -> Result<RequestContext, String> {
        let sts = self.inner.sts.get().ok_or("STS is not available")?;
        let cannot = || format!("Bedrock is unable to assume role {role}. Check the role's trust policy.");
        let creds = sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: role,
                service_principal: SERVICE_PRINCIPAL,
                session_name: session,
                duration_seconds: 3600,
                source_account: Some(&ctx.caller.account_id),
                source_arn: Some(source_arn),
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
}
