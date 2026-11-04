//! Event source mappings on Kinesis data streams: Lambda's pollers read
//! every shard as the function's execution role, from the mapping's
//! starting position, invoke the function with batches of records in
//! Lambda's Kinesis event format, and checkpoint per shard. As in AWS:
//!
//! - `CreateEventSourceMapping` needs a `StartingPosition` and checks the
//!   role may read the stream.
//! - A failed batch is retried (in order, blocking the shard) until
//!   `MaximumRetryAttempts` or `MaximumRecordAgeInSeconds` runs out;
//!   `BisectBatchOnFunctionError` halves it on each failure.
//! - With `ReportBatchItemFailures`, processing resumes at the first
//!   sequence number the function reports.
//! - `FilterCriteria` match on the record, with `data` parsed as JSON when
//!   it is JSON.
//!
//! The stream side is the [`StreamSource`] trait, which the `mws` crate
//! implements over Kinesis.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde_json::{json, Value};

use crate::generated::{errors, types};
use crate::names;
use crate::Lambda;

/// A record a poller read.
#[derive(Debug, Clone, Default)]
pub struct StreamRecord {
    pub sequence_number: String,
    pub partition_key: String,
    pub data: Vec<u8>,
    pub approximate_arrival: DateTime<Utc>,
    pub encryption_type: Option<String>,
}

/// A shard of a stream.
#[derive(Debug, Clone, Default)]
pub struct StreamShard {
    pub shard_id: String,
    pub parent_shard_id: Option<String>,
    pub adjacent_parent_shard_id: Option<String>,
}

/// Where a poller starts reading a shard.
#[derive(Debug, Clone)]
pub enum StreamPosition {
    TrimHorizon,
    Latest,
    AtTimestamp(DateTime<Utc>),
    AfterSequenceNumber(String),
}

/// One read of a shard.
#[derive(Debug, Clone, Default)]
pub struct StreamRead {
    pub records: Vec<StreamRecord>,
    /// `None` once a closed shard has been read to its end.
    pub next_iterator: Option<String>,
}

/// A stream service Lambda can poll. Every call is made as `ctx.caller`
/// (the function's execution role).
pub trait StreamSource: Send + Sync {
    /// Whether the caller may perform `action` (`kinesis:GetRecords`, ...)
    /// on the stream; fails like the stream's own operations when it does
    /// not exist.
    fn authorize(&self, ctx: &RequestContext, stream_arn: &str, action: &str) -> Result<(), ServiceError>;
    fn shards(&self, ctx: &RequestContext, stream_arn: &str) -> Result<Vec<StreamShard>, ServiceError>;
    fn iterator(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        shard_id: &str,
        position: StreamPosition,
    ) -> Result<String, ServiceError>;
    fn read(&self, ctx: &RequestContext, iterator: &str, limit: i32) -> Result<StreamRead, ServiceError>;
}

pub(crate) fn is_kinesis(arn: &str) -> bool {
    arn.split(':').nth(2) == Some("kinesis")
}

/// The stream of an event source ARN, which may name an enhanced fan-out
/// consumer (`.../stream/<name>/consumer/<consumer>:<time>`).
pub(crate) fn stream_of(arn: &str) -> &str {
    arn.find("/consumer/").map(|i| &arn[..i]).unwrap_or(arn)
}

/// Where a mapping is in each shard, and how its retries are going.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ShardProgress {
    /// The last sequence number processed.
    pub checkpoint: Option<String>,
    /// The closed shard has been read to its end.
    pub finished: bool,
    /// Failed attempts at the current batch.
    pub attempts: i32,
    /// The current batch's size, when bisecting.
    pub batch_limit: Option<i32>,
}

const STREAM_ACTIONS: [&str; 4] = ["DescribeStream", "GetRecords", "GetShardIterator", "ListShards"];

impl Lambda {
    /// Poll Kinesis data streams for event source mappings through
    /// `source`.
    pub fn set_stream_source(&self, source: std::sync::Arc<dyn StreamSource>) {
        let _ = self.inner.streams.set(source);
    }

    /// The checks `CreateEventSourceMapping` makes for a Kinesis source.
    pub(crate) fn check_stream_source(
        &self,
        ctx: &RequestContext,
        source_arn: &str,
        function_arn: &str,
        starting_position: Option<&str>,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<(), ServiceError> {
        match starting_position {
            None => {
                return Err(errors::invalid_parameter_value(
                    "1 validation error detected: Value null at 'startingPosition' failed to satisfy constraint: Member must not be null",
                ))
            }
            Some("AT_TIMESTAMP") if timestamp.is_none() => {
                return Err(errors::invalid_parameter_value(
                    "StartingPositionTimestamp must be set when StartingPosition is AT_TIMESTAMP.",
                ))
            }
            Some("TRIM_HORIZON" | "LATEST" | "AT_TIMESTAMP") => {}
            Some(other) => {
                return Err(errors::invalid_parameter_value(format!(
                    "Unsupported starting position {other} for a Kinesis event source."
                )))
            }
        }
        let Some(source) = self.inner.streams.get() else { return Ok(()) };
        let role_ctx = self.role_context(ctx, function_arn)?;
        let stream = stream_of(source_arn);
        for action in STREAM_ACTIONS {
            source.authorize(&role_ctx, stream, &format!("kinesis:{action}")).map_err(|e| {
                if e.code == "ResourceNotFoundException" {
                    errors::invalid_parameter_value(format!("Stream not found: {stream}"))
                } else {
                    errors::invalid_parameter_value(format!(
                        "The provided execution role does not have permissions to call {action} on Kinesis"
                    ))
                }
            })?;
        }
        Ok(())
    }

    /// One round for a Kinesis mapping: a batch from each shard that has
    /// records.
    pub(crate) async fn poll_stream(
        &self,
        uuid: &str,
        config: &types::EventSourceMappingConfiguration,
        account: &str,
        region: &str,
    ) -> Result<(), ServiceError> {
        let (Some(source), Some(source_arn), Some(function_arn)) =
            (self.inner.streams.get().cloned(), config.event_source_arn.as_deref(), config.function_arn.as_deref())
        else {
            return Ok(());
        };
        let stream = stream_of(source_arn).to_string();
        let Some(ctx) = self.poller_context(account, region) else { return Ok(()) };
        let role_ctx = self.role_context(&ctx, function_arn)?;
        let role = role_ctx.caller.arn.clone();
        let invoke_identity = self.function_role(&ctx, function_arn).unwrap_or(role);
        let shards = source.shards(&role_ctx, &stream)?;
        let created = {
            let st = self.read();
            st.event_source_mappings
                .get(uuid)
                .and_then(|m| m.created)
                .or(config.last_modified)
                .unwrap_or(ctx.received_at)
        };
        for shard in &shards {
            let progress = self.progress(uuid, &shard.shard_id);
            if progress.finished {
                continue;
            }
            // Children wait until their parents are read to the end.
            let parents = [&shard.parent_shard_id, &shard.adjacent_parent_shard_id];
            if parents
                .iter()
                .filter_map(|p| p.as_deref())
                .any(|p| shards.iter().any(|s| s.shard_id == p) && !self.progress(uuid, p).finished)
            {
                continue;
            }
            let position = match (&progress.checkpoint, config.starting_position.as_deref()) {
                (Some(seq), _) => StreamPosition::AfterSequenceNumber(seq.clone()),
                // A child shard of a split or merge is read from its start.
                (None, _) if shard.parent_shard_id.is_some() => StreamPosition::TrimHorizon,
                (None, Some("TRIM_HORIZON")) => StreamPosition::TrimHorizon,
                (None, Some("AT_TIMESTAMP")) => {
                    StreamPosition::AtTimestamp(config.starting_position_timestamp.unwrap_or(created))
                }
                // LATEST: what arrived after the mapping was created.
                (None, _) => StreamPosition::AtTimestamp(created),
            };
            let iterator = source.iterator(&role_ctx, &stream, &shard.shard_id, position)?;
            let batch_size = config.batch_size.unwrap_or(100).max(1);
            let limit = progress.batch_limit.unwrap_or(batch_size).clamp(1, batch_size);
            let read = source.read(&role_ctx, &iterator, limit)?;
            if read.records.is_empty() {
                if read.next_iterator.is_none() {
                    self.update_progress(uuid, &shard.shard_id, |p| p.finished = true);
                }
                continue;
            }
            let now = ctx.received_at;
            let filters = crate::esm::compile_filters(config.filter_criteria.as_ref()).unwrap_or_default();
            let all: Vec<Value> =
                read.records.iter().map(|r| record(r, &shard.shard_id, source_arn, region, &invoke_identity)).collect();
            let last = read.records.last().map(|r| r.sequence_number.clone());
            let batch: Vec<(Value, &StreamRecord)> =
                all.into_iter().zip(&read.records).filter(|(v, _)| passes(&filters, v)).collect();
            if batch.is_empty() {
                self.update_progress(uuid, &shard.shard_id, |p| p.checkpoint = last.clone());
                continue;
            }
            let payload = serde_json::to_vec(&json!({"Records": batch.iter().map(|(v, _)| v).collect::<Vec<_>>()}))
                .expect("records serialize");
            let f = names::parse_function(&ctx, function_arn, None)?;
            let ran = self.run(&ctx, &f, payload, None).await;
            let failed = match &ran {
                Ok(r) if r.outcome.function_error.is_none() => {
                    let reports =
                        config.function_response_types.iter().flatten().any(|t| t == "ReportBatchItemFailures");
                    if reports {
                        first_failure(&r.outcome.payload, &batch)
                    } else {
                        None
                    }
                }
                _ => Some(batch[0].1.sequence_number.clone()),
            };
            match failed {
                None => self.update_progress(uuid, &shard.shard_id, |p| {
                    p.checkpoint = last.clone();
                    p.attempts = 0;
                    p.batch_limit = None;
                }),
                Some(at) => {
                    // Resume at the first failed record: checkpoint the
                    // record before it.
                    let before = read
                        .records
                        .iter()
                        .take_while(|r| r.sequence_number != at)
                        .last()
                        .map(|r| r.sequence_number.clone());
                    let oldest = batch[0].1.approximate_arrival;
                    let max_age = config.maximum_record_age_in_seconds.unwrap_or(-1);
                    let too_old = max_age >= 0 && (now - oldest).num_seconds() > i64::from(max_age);
                    let max_attempts = config.maximum_retry_attempts.unwrap_or(-1);
                    let bisect = config.bisect_batch_on_function_error.unwrap_or(false);
                    let attempts = progress.attempts + 1;
                    let give_up = too_old || (max_attempts >= 0 && attempts > max_attempts);
                    self.update_progress(uuid, &shard.shard_id, |p| {
                        if let Some(b) = &before {
                            p.checkpoint = Some(b.clone());
                        }
                        p.attempts += 1;
                        if bisect {
                            p.batch_limit = Some((limit / 2).max(1));
                        }
                        if too_old || (max_attempts >= 0 && p.attempts > max_attempts) {
                            // Give up on the batch: skip past it.
                            tracing::info!(mapping = %uuid, "discarding a Kinesis batch the function failed");
                            p.checkpoint = last.clone();
                            p.attempts = 0;
                            p.batch_limit = None;
                        }
                    });
                    let destination = config
                        .destination_config
                        .as_ref()
                        .and_then(|d| d.on_failure.as_ref())
                        .and_then(|d| d.destination.clone());
                    if let (true, Some(destination)) = (give_up, destination) {
                        let condition = if too_old { "RecordAgeExceeded" } else { "RetryAttemptsExhausted" };
                        let executed = ran.as_ref().map(|r| r.executed_version.clone()).unwrap_or("$LATEST".into());
                        let error = ran.as_ref().ok().and_then(|r| r.outcome.function_error.clone());
                        let records: Vec<&StreamRecord> = batch.iter().map(|(_, r)| *r).collect();
                        let info = BatchInfo { shard_id: &shard.shard_id, stream_arn: &stream, records: &records };
                        let body = failure_record(&ctx, function_arn, &executed, error, condition, attempts, &info);
                        let message = crate::DestinationMessage {
                            body: body.to_string(),
                            function_arn: function_arn.to_string(),
                            detail_type: "Lambda Function Invocation Result - Failure".into(),
                            ..Default::default()
                        };
                        self.send_to_destination(&ctx, function_arn, &destination, &message).await;
                    }
                }
            }
        }
        Ok(())
    }

    fn function_role(&self, ctx: &RequestContext, function_arn: &str) -> Option<String> {
        let f = names::parse_function(ctx, function_arn, None).ok()?;
        let st = self.read();
        let func = Self::function(&st, &f).ok()?;
        func.version_for(f.qualifier.as_deref()).and_then(|v| v.config.role.clone())
    }

    fn progress(&self, uuid: &str, shard: &str) -> ShardProgress {
        let st = self.read();
        st.event_source_mappings.get(uuid).and_then(|m| m.shards.get(shard).cloned()).unwrap_or_default()
    }

    fn update_progress(&self, uuid: &str, shard: &str, f: impl FnOnce(&mut ShardProgress)) {
        let mut st = self.write();
        if let Some(m) = st.event_source_mappings.get_mut(uuid) {
            f(m.shards.entry(shard.to_string()).or_default());
            m.config.last_processing_result = Some("OK".into());
        }
    }
}

/// The batch a stream mapping gave up on.
struct BatchInfo<'a> {
    shard_id: &'a str,
    stream_arn: &'a str,
    records: &'a [&'a StreamRecord],
}

/// The record a stream mapping's on-failure destination gets: what
/// failed, and where the batch is in the shard (the records themselves
/// stay in the stream).
fn failure_record(
    ctx: &RequestContext,
    function_arn: &str,
    executed_version: &str,
    function_error: Option<String>,
    condition: &str,
    attempts: i32,
    batch: &BatchInfo<'_>,
) -> Value {
    let time = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let first = batch.records.first();
    let last = batch.records.last();
    let mut response = json!({ "statusCode": 200, "executedVersion": executed_version });
    if let Some(e) = function_error {
        response["functionError"] = json!(e);
    }
    json!({
        "requestContext": {
            "requestId": uuid::Uuid::new_v4().to_string(),
            "functionArn": function_arn,
            "condition": condition,
            "approximateInvokeCount": attempts,
        },
        "responseContext": response,
        "version": "1.0",
        "timestamp": time(ctx.received_at),
        "KinesisBatchInfo": {
            "shardId": batch.shard_id,
            "startSequenceNumber": first.map(|r| r.sequence_number.clone()),
            "endSequenceNumber": last.map(|r| r.sequence_number.clone()),
            "approximateArrivalOfFirstRecord": first.map(|r| time(r.approximate_arrival)),
            "approximateArrivalOfLastRecord": last.map(|r| time(r.approximate_arrival)),
            "batchSize": batch.records.len(),
            "streamArn": batch.stream_arn,
        },
    })
}

/// The sequence number of the first item the function reported failed, or
/// `None` when the batch succeeded. An unusable report fails the batch.
fn first_failure(payload: &[u8], batch: &[(Value, &StreamRecord)]) -> Option<String> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let items = match v.get("batchItemFailures") {
        None | Some(Value::Null) => return None,
        Some(Value::Array(items)) => items,
        Some(_) => return Some(batch[0].1.sequence_number.clone()),
    };
    let mut first: Option<usize> = None;
    for i in items {
        let Some(id) = i.get("itemIdentifier").and_then(Value::as_str) else {
            return Some(batch[0].1.sequence_number.clone());
        };
        let Some(pos) = batch.iter().position(|(_, r)| r.sequence_number == id) else {
            return Some(batch[0].1.sequence_number.clone());
        };
        first = Some(first.map_or(pos, |f: usize| f.min(pos)));
    }
    first.map(|i| batch[i].1.sequence_number.clone())
}

/// Whether a record passes the mapping's filters; `data` that is JSON is
/// filtered as JSON.
fn passes(filters: &[mws_event_pattern::Pattern], record: &Value) -> bool {
    if filters.is_empty() {
        return true;
    }
    let mut view = record.get("kinesis").cloned().unwrap_or_default();
    if let Some(data) = view.get("data").and_then(Value::as_str) {
        let decoded = base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default();
        if let Ok(parsed @ Value::Object(_)) = serde_json::from_slice::<Value>(&decoded) {
            view["data"] = parsed;
        }
    }
    let mut full = record.clone();
    full["kinesis"] = view;
    filters.iter().any(|f| f.matches(&full))
}

/// A Kinesis record as Lambda delivers it.
fn record(r: &StreamRecord, shard_id: &str, source_arn: &str, region: &str, invoke_identity: &str) -> Value {
    let arrival = r.approximate_arrival.timestamp_millis() as f64 / 1000.0;
    let mut kinesis = json!({
        "kinesisSchemaVersion": "1.0",
        "partitionKey": r.partition_key,
        "sequenceNumber": r.sequence_number,
        "data": base64::engine::general_purpose::STANDARD.encode(&r.data),
        "approximateArrivalTimestamp": arrival,
    });
    if let Some(e) = r.encryption_type.as_deref().filter(|e| *e != "NONE") {
        kinesis["encryptionType"] = json!(e);
    }
    json!({
        "kinesis": kinesis,
        "eventSource": "aws:kinesis",
        "eventVersion": "1.0",
        "eventID": format!("{shard_id}:{}", r.sequence_number),
        "eventName": "aws:kinesis:record",
        "invokeIdentityArn": invoke_identity,
        "awsRegion": region,
        "eventSourceARN": stream_of(source_arn),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_failures() {
        let r = StreamRecord {
            sequence_number: "49".into(),
            partition_key: "k".into(),
            data: br#"{"n":1}"#.to_vec(),
            approximate_arrival: DateTime::from_timestamp_millis(1_545_084_650_987).unwrap(),
            encryption_type: None,
        };
        let v = record(&r, "shardId-000000000000", "arn:aws:kinesis:us-east-1:1:stream/s", "us-east-1", "role");
        assert_eq!(v["eventID"], "shardId-000000000000:49");
        assert_eq!(v["kinesis"]["approximateArrivalTimestamp"], 1_545_084_650.987);
        let p = mws_event_pattern::Pattern::parse(r#"{"kinesis":{"data":{"n":[1]}}}"#).unwrap();
        assert!(passes(&[p], &v));
        let batch = vec![(v.clone(), &r)];
        assert_eq!(first_failure(br#"{"batchItemFailures":[]}"#, &batch), None);
        assert_eq!(first_failure(br#"{"batchItemFailures":[{"itemIdentifier":"49"}]}"#, &batch).as_deref(), Some("49"));
        assert_eq!(
            stream_of("arn:aws:kinesis:us-east-1:1:stream/s/consumer/c:1"),
            "arn:aws:kinesis:us-east-1:1:stream/s"
        );
    }
}
