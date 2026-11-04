//! What Firehose reports about itself: `AWS/Firehose` metrics in
//! CloudWatch, and delivery errors written to the destination's
//! CloudWatch Logs log stream (with the delivery role, as AWS does).

use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::Firehose;

/// A metric data point: name, unit, value.
pub(crate) type Point = (String, &'static str, f64);

pub(crate) fn point(name: impl Into<String>, unit: &'static str, value: f64) -> Point {
    (name.into(), unit, value)
}

/// The metric name prefix of a destination kind (`DeliveryToS3`, ...).
pub(crate) fn delivery_metric(kind: &str) -> &'static str {
    match kind {
        "extended_s3" => "DeliveryToS3",
        "redshift" => "DeliveryToRedshift",
        "http_endpoint" => "DeliveryToHttpEndpoint",
        "splunk" => "DeliveryToSplunk",
        "elasticsearch" => "DeliveryToElasticsearch",
        "amazonopensearchservice" => "DeliveryToAmazonOpenSearchService",
        "amazon_open_search_serverless" => "DeliveryToAmazonOpenSearchServerless",
        "snowflake" => "DeliveryToSnowflake",
        _ => "DeliveryToIceberg",
    }
}

/// What an error log entry names as the destination.
pub(crate) fn destination_label(kind: &str, effective: &Value) -> String {
    let s = |p: &str| effective.pointer(p).and_then(Value::as_str).map(str::to_string);
    match kind {
        "extended_s3" => s("/bucket_arn"),
        "http_endpoint" => s("/endpoint_configuration/url"),
        "splunk" => s("/hec_endpoint"),
        "elasticsearch" | "amazonopensearchservice" => s("/domain_arn").or_else(|| s("/cluster_endpoint")),
        "amazon_open_search_serverless" => s("/collection_endpoint"),
        "redshift" => s("/cluster_jdbcurl"),
        "snowflake" => s("/account_url"),
        _ => s("/catalog_configuration/catalog_arn"),
    }
    .unwrap_or_default()
}

/// One error log entry, in Firehose's format.
pub(crate) struct ErrorLog<'a> {
    pub stream_arn: &'a str,
    pub account: &'a str,
    pub version: u64,
    pub destination: String,
    pub code: &'a str,
    pub message: &'a str,
    pub processor: Option<&'a str>,
}

impl Firehose {
    /// Publish `AWS/Firehose` data points for a delivery stream.
    pub(crate) fn metrics(&self, ctx: &RequestContext, account: &str, stream: &str, points: Vec<Point>) {
        let Some(cw) = self.inner.cloudwatch.get() else { return };
        for (name, unit, value) in points {
            cw.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: account.to_string(),
                region: ctx.region.clone(),
                namespace: "AWS/Firehose".into(),
                metric_name: name,
                dimensions: vec![("DeliveryStreamName".into(), stream.to_string())],
                unit: Some(unit.into()),
                timestamp: ctx.received_at,
                values: vec![(value, 1.0)],
            });
        }
    }

    /// Write a delivery error to the destination's CloudWatch Logs log
    /// stream, when error logging is enabled. Firehose writes with the
    /// delivery role; when the role may not, or the log group or stream
    /// does not exist, the entry is lost, as in AWS.
    pub(crate) async fn log_error(&self, ctx: &RequestContext, effective: &Value, e: ErrorLog<'_>) {
        let Some(logs) = self.inner.logs.get() else { return };
        let options = effective.get("cloud_watch_logging_options");
        if !options.and_then(|o| o.get("enabled")).and_then(Value::as_bool).unwrap_or(false) {
            return;
        }
        let name = |k: &str| options.and_then(|o| o.get(k)).and_then(Value::as_str).filter(|s| !s.is_empty());
        let (Some(group), Some(stream)) = (name("log_group_name"), name("log_stream_name")) else { return };
        let Some(role) = effective.get("role_arn").and_then(Value::as_str) else { return };
        let rctx = match self.role_context(ctx, role, e.stream_arn, e.account) {
            Ok(c) => c,
            Err(m) => {
                tracing::info!(stream = e.stream_arn, "Firehose could not log a delivery error: {m}");
                return;
            }
        };
        let mut entry = json!({
            "deliveryStreamARN": e.stream_arn,
            "destination": e.destination,
            "deliveryStreamVersionId": e.version,
            "message": e.message,
            "errorCode": e.code,
        });
        if let Some(p) = e.processor {
            entry["processor"] = json!(p);
        }
        let request = json!({
            "logGroupName": group,
            "logStreamName": stream,
            "logEvents": [{"timestamp": ctx.received_at.timestamp_millis(), "message": entry.to_string()}],
        });
        if let Err(err) = mws_core::Service::invoke(logs, rctx, "PutLogEvents", request).await {
            tracing::info!(stream = e.stream_arn, "Firehose could not log a delivery error: {}", err.message);
        }
    }

    /// The value of `key` in a Secrets Manager secret (a JSON object), read
    /// with the configuration's role (or the destination's).
    pub(crate) async fn secret_value(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        account: &str,
        config: &Value,
        fallback_role: Option<&str>,
        key: &str,
    ) -> Result<Option<String>, String> {
        if !config.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
            return Ok(None);
        }
        let secret = config.get("secret_arn").and_then(Value::as_str).unwrap_or_default();
        let role = config.get("role_arn").and_then(Value::as_str).or(fallback_role).unwrap_or_default();
        let Some(sm) = self.inner.secrets_manager.get() else { return Err("Secrets Manager is not available.".into()) };
        let rctx = self.role_context(ctx, role, stream_arn, account)?;
        let out = mws_core::Service::invoke(sm, rctx, "GetSecretValue", json!({"SecretId": secret}))
            .await
            .map_err(|e| format!("Firehose is unable to get the secret {secret}: {}", e.message))?;
        let text = out.get("SecretString").and_then(Value::as_str).unwrap_or_default();
        let doc: Value =
            serde_json::from_str(text).map_err(|_| format!("The secret {secret} is not a valid JSON object."))?;
        match doc.get(key).and_then(Value::as_str) {
            Some(v) => Ok(Some(v.to_string())),
            None => Err(format!("The secret {secret} does not contain the key {key}.")),
        }
    }
}
