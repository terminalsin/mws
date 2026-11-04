//! Data transformation: the processors of a destination's
//! `ProcessingConfiguration`, run in Firehose's order — record
//! de-aggregation, decompression, CloudWatch Logs message extraction, the
//! Lambda function, metadata extraction (dynamic partitioning keys) and
//! the delimiter appended to each record.

use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine;
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::generated::types;
use crate::state::Buffered;
use crate::Firehose;

/// A record ready to deliver.
#[derive(Debug, Clone)]
pub struct Out {
    pub data: Vec<u8>,
    pub source: Buffered,
    pub query_keys: BTreeMap<String, String>,
    pub lambda_keys: BTreeMap<String, String>,
}

/// A record that could not be processed, for the error output.
#[derive(Debug, Clone)]
pub struct Failed {
    pub source: Buffered,
    pub data: Vec<u8>,
    /// `processing-failed` or `partitioning-failed`.
    pub output_type: &'static str,
    pub error_code: String,
    pub error_message: String,
    pub lambda_arn: Option<String>,
}

#[derive(Debug, Default)]
pub struct Processed {
    pub ok: Vec<Out>,
    pub failed: Vec<Failed>,
}

fn param<'a>(p: &'a types::Processor, name: &str) -> Option<&'a str> {
    p.parameters.iter().flatten().find(|x| x.parameter_name == name).map(|x| x.parameter_value.as_str())
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// `\n`, `\t` and `\r` in a delimiter parameter mean the characters.
fn unescape(s: &str) -> String {
    s.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
}

/// Split concatenated JSON objects (`{"a":1}{"a":2}`) into records.
fn split_json(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for v in serde_json::Deserializer::from_slice(data).into_iter::<Value>() {
        out.push(serde_json::to_vec(&v.ok()?).ok()?);
    }
    Some(out)
}

/// Evaluate a metadata extraction query of the form
/// `{key: .path.to.field, other: .x}` against a JSON record.
pub fn extract(query: &str, record: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let doc: Value = serde_json::from_slice(record).map_err(|_| "Non JSON record provided".to_string())?;
    let body = query.trim().strip_prefix('{').and_then(|q| q.strip_suffix('}')).ok_or("Invalid JQ query")?;
    let mut out = BTreeMap::new();
    for part in body.split(',') {
        let (key, path) = part.split_once(':').ok_or("Invalid JQ query")?;
        let key = key.trim().trim_matches('"').to_string();
        let path = path.trim();
        let mut v = &doc;
        for seg in path.strip_prefix('.').ok_or("Invalid JQ query")?.split('.').filter(|s| !s.is_empty()) {
            let seg = seg.trim_matches('"');
            v = v.get(seg).ok_or_else(|| format!("The partition key {key} was not found in the record"))?;
        }
        let s = match v {
            Value::String(s) => s.clone(),
            Value::Null => return Err(format!("The partition key {key} is null")),
            other => other.to_string(),
        };
        out.insert(key, s);
    }
    Ok(out)
}

impl Firehose {
    /// Run a destination's processors over a batch. `role` is the
    /// destination's role, which Lambda processors use unless they name
    /// their own.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn process(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        account: &str,
        role: Option<&str>,
        processing: Option<&types::ProcessingConfiguration>,
        dynamic: bool,
        records: Vec<Buffered>,
    ) -> Processed {
        let mut batch: Vec<Out> = records
            .into_iter()
            .map(|r| Out { data: r.data.clone(), source: r, query_keys: BTreeMap::new(), lambda_keys: BTreeMap::new() })
            .collect();
        let mut failed = Vec::new();
        let processors: Vec<&types::Processor> = match processing {
            Some(p) if p.enabled.unwrap_or(false) => p.processors.iter().flatten().collect(),
            _ => Vec::new(),
        };
        let of = |t: &str| processors.iter().copied().find(|p| p.r#type == t);

        if let Some(p) = of("RecordDeAggregation") {
            let delimited = param(p, "SubRecordType") == Some("DELIMITED");
            let delimiter = unescape(param(p, "Delimiter").unwrap_or("\\n"));
            let mut next = Vec::new();
            for r in batch {
                let parts = if delimited {
                    Some(
                        String::from_utf8_lossy(&r.data)
                            .split(delimiter.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.as_bytes().to_vec())
                            .collect(),
                    )
                } else if param(p, "SubRecordType") == Some("JSON") {
                    split_json(&r.data)
                } else {
                    Some(vec![r.data.clone()])
                };
                match parts {
                    Some(parts) => next.extend(parts.into_iter().map(|data| Out { data, ..r.clone() })),
                    None => failed.push(Failed {
                        source: r.source.clone(),
                        data: r.data,
                        output_type: "processing-failed",
                        error_code: "RecordDeAggregation.InvalidRecord".into(),
                        error_message: "The record could not be de-aggregated.".into(),
                        lambda_arn: None,
                    }),
                }
            }
            batch = next;
        }

        if of("Decompression").is_some() {
            let mut next = Vec::new();
            for mut r in batch {
                let mut out = Vec::new();
                match flate2::read::MultiGzDecoder::new(r.data.as_slice()).read_to_end(&mut out) {
                    Ok(_) => {
                        r.data = out;
                        next.push(r);
                    }
                    Err(_) => failed.push(Failed {
                        source: r.source.clone(),
                        data: r.data,
                        output_type: "processing-failed",
                        error_code: "Decompression.InvalidRecord".into(),
                        error_message: "The record is not GZIP-compressed.".into(),
                        lambda_arn: None,
                    }),
                }
            }
            batch = next;
        }

        if let Some(p) = of("CloudWatchLogProcessing") {
            if param(p, "DataMessageExtraction").is_none_or(|v| v.eq_ignore_ascii_case("true")) {
                let mut next = Vec::new();
                for r in batch {
                    let Ok(v) = serde_json::from_slice::<Value>(&r.data) else {
                        next.push(r);
                        continue;
                    };
                    if v.get("messageType").and_then(Value::as_str) == Some("CONTROL_MESSAGE") {
                        continue;
                    }
                    for e in v.get("logEvents").and_then(Value::as_array).into_iter().flatten() {
                        let message = e.get("message").and_then(Value::as_str).unwrap_or_default();
                        next.push(Out { data: format!("{message}\n").into_bytes(), ..r.clone() });
                    }
                }
                batch = next;
            }
        }

        if let Some(p) = of("Lambda") {
            let arn = param(p, "LambdaArn").unwrap_or_default().to_string();
            let role = param(p, "RoleArn").or(role);
            let (ok, bad) = self.run_lambda(ctx, stream_arn, account, role, &arn, batch).await;
            batch = ok;
            failed.extend(bad);
        }

        if dynamic {
            if let Some(p) = of("MetadataExtraction") {
                let query = param(p, "MetadataExtractionQuery").unwrap_or("{}");
                let mut next = Vec::new();
                for mut r in batch {
                    match extract(query, &r.data) {
                        Ok(keys) => {
                            r.query_keys = keys;
                            next.push(r);
                        }
                        Err(m) => failed.push(Failed {
                            source: r.source.clone(),
                            data: r.data,
                            output_type: "partitioning-failed",
                            error_code: "DynamicPartitioning.MetadataExtractionFailed".into(),
                            error_message: m,
                            lambda_arn: None,
                        }),
                    }
                }
                batch = next;
            }
        }

        if let Some(p) = of("AppendDelimiterToRecord") {
            let delimiter = unescape(param(p, "Delimiter").unwrap_or("\\n"));
            for r in &mut batch {
                r.data.extend_from_slice(delimiter.as_bytes());
            }
        }
        Processed { ok: batch, failed }
    }

    /// Invoke a transformation function with a batch, as Firehose does:
    /// records go in base64 with their ids; each comes back `Ok` (with new
    /// data and optional partition keys), `Dropped` or `ProcessingFailed`.
    async fn run_lambda(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        account: &str,
        role: Option<&str>,
        function: &str,
        batch: Vec<Out>,
    ) -> (Vec<Out>, Vec<Failed>) {
        if batch.is_empty() {
            return (batch, Vec::new());
        }
        let fail_all = |batch: Vec<Out>, code: &str, message: &str| {
            let failed = batch
                .into_iter()
                .map(|r| Failed {
                    source: r.source.clone(),
                    data: r.data,
                    output_type: "processing-failed",
                    error_code: code.to_string(),
                    error_message: message.to_string(),
                    lambda_arn: Some(function.to_string()),
                })
                .collect();
            (Vec::new(), failed)
        };
        let Some(lambda) = self.inner.lambda.get() else {
            return fail_all(batch, "Lambda.InvokeAccessDenied", "Lambda is not available.");
        };
        let Some(role) = role else {
            return fail_all(batch, "Lambda.InvokeAccessDenied", "No role to invoke the function with.");
        };
        let rctx = match self.role_context(ctx, role, stream_arn, account) {
            Ok(c) => c,
            Err(m) => return fail_all(batch, "Lambda.InvokeAccessDenied", &m),
        };
        let region = ctx.region.clone();
        let records: Vec<Value> = batch
            .iter()
            .map(|r| {
                let mut v = json!({
                    "recordId": r.source.record_id,
                    "approximateArrivalTimestamp": r.source.arrival,
                    "data": b64().encode(&r.data),
                });
                if let Some(k) = &r.source.kinesis {
                    v["kinesisRecordMetadata"] = json!({
                        "shardId": k.shard_id,
                        "partitionKey": k.partition_key,
                        "approximateArrivalTimestamp": k.arrival,
                        "sequenceNumber": k.sequence_number,
                        "subsequenceNumber": "",
                    });
                }
                v
            })
            .collect();
        let mut event = json!({
            "invocationId": uuid::Uuid::new_v4().to_string(),
            "deliveryStreamArn": stream_arn,
            "region": region,
            "records": records,
        });
        if let Some(k) = batch.iter().find_map(|r| r.source.kinesis.as_ref()) {
            let _ = k;
            if let Some(src) = self.source_stream_arn(stream_arn) {
                event["sourceKinesisStreamArn"] = json!(src);
            }
        }
        let (name, qualifier) = match function.rsplit_once(':') {
            Some((base, q)) if base.matches(':').count() == 6 => (base.to_string(), Some(q.to_string())),
            _ => (function.to_string(), None),
        };
        let request = mws_lambda::generated::types::InvocationRequest {
            function_name: name,
            qualifier: qualifier.filter(|q| q != "$LATEST"),
            payload: Some(event.to_string().into_bytes()),
            ..Default::default()
        };
        let response =
            match <mws_lambda::Lambda as mws_lambda::generated::Handler>::invoke(lambda, &rctx, request).await {
                Ok(r) => r,
                Err(e) => {
                    let code = if e.code.contains("AccessDenied") {
                        "Lambda.InvokeAccessDenied"
                    } else if e.code.contains("NotFound") {
                        "Lambda.FunctionNotFound"
                    } else {
                        "Lambda.InvokeFailed"
                    };
                    return fail_all(batch, code, &e.message);
                }
            };
        if response.function_error.is_some() {
            let payload = String::from_utf8_lossy(response.payload.as_deref().unwrap_or_default()).to_string();
            return fail_all(
                batch,
                "Lambda.FunctionError",
                &format!("The Lambda function was successfully invoked but it returned an error result. {payload}"),
            );
        }
        let Ok(out) = serde_json::from_slice::<Value>(response.payload.as_deref().unwrap_or_default()) else {
            return fail_all(batch, "Lambda.JsonProcessingException", "The Lambda function returned malformed JSON.");
        };
        let returned: BTreeMap<String, &Value> = out
            .get("records")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| Some((r.get("recordId")?.as_str()?.to_string(), r)))
            .collect();
        let mut ok = Vec::new();
        let mut failed = Vec::new();
        for mut r in batch {
            let Some(v) = returned.get(&r.source.record_id) else {
                failed.push(Failed {
                    source: r.source.clone(),
                    data: r.data,
                    output_type: "processing-failed",
                    error_code: "Lambda.MissingRecordId".into(),
                    error_message: "One or more record Ids were not returned. Ensure that the Lambda function returns all received record Ids.".into(),
                    lambda_arn: Some(function.to_string()),
                });
                continue;
            };
            match v.get("result").and_then(Value::as_str) {
                Some("Ok") => {
                    let data = v.get("data").and_then(Value::as_str).and_then(|d| b64().decode(d).ok());
                    let Some(data) = data else {
                        failed.push(Failed {
                            source: r.source.clone(),
                            data: r.data,
                            output_type: "processing-failed",
                            error_code: "Lambda.InvalidReturnedData".into(),
                            error_message: "The data returned by the Lambda function is not base64 encoded.".into(),
                            lambda_arn: Some(function.to_string()),
                        });
                        continue;
                    };
                    r.data = data;
                    if let Some(keys) = v.pointer("/metadata/partitionKeys").and_then(Value::as_object) {
                        r.lambda_keys = keys
                            .iter()
                            .map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                            .collect();
                    }
                    ok.push(r);
                }
                Some("Dropped") => {}
                Some("ProcessingFailed") => failed.push(Failed {
                    source: r.source.clone(),
                    data: r.data,
                    output_type: "processing-failed",
                    error_code: "Lambda.ProcessingFailedStatus".into(),
                    error_message: "ProcessingFailed status set for record".into(),
                    lambda_arn: Some(function.to_string()),
                }),
                other => failed.push(Failed {
                    source: r.source.clone(),
                    data: r.data,
                    output_type: "processing-failed",
                    error_code: "Lambda.InvalidRecordStatus".into(),
                    error_message: format!("Invalid record status {}", other.unwrap_or("null")),
                    lambda_arn: Some(function.to_string()),
                }),
            }
        }
        (ok, failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_queries() {
        let keys =
            extract("{customer: .customer_id, region: .geo.region}", br#"{"customer_id":7,"geo":{"region":"eu"}}"#)
                .unwrap();
        assert_eq!(keys["customer"], "7");
        assert_eq!(keys["region"], "eu");
        assert!(extract("{a: .missing}", br#"{"b":1}"#).is_err());
        assert!(extract("{a: .a}", b"not json").is_err());
    }

    #[test]
    fn concatenated_json_splits() {
        let parts = split_json(br#"{"a":1}{"a":2} {"a":3}"#).unwrap();
        assert_eq!(parts.len(), 3);
        assert!(split_json(b"{bad").is_none());
    }
}
