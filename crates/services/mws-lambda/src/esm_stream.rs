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

use std::collections::BTreeMap;

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
    /// The last sequence number processed (with lanes: the last one every
    /// lane is done with).
    pub checkpoint: Option<String>,
    /// The closed shard has been read to its end.
    pub finished: bool,
    /// Failed attempts at the current batch.
    pub attempts: i32,
    /// The current batch's size, when bisecting.
    pub batch_limit: Option<i32>,
    /// The tumbling window open in the shard (its only lane).
    pub window: Option<TumblingWindow>,
    /// With a `ParallelizationFactor` above 1, each lane's progress, by
    /// lane number.
    pub lanes: BTreeMap<String, LaneProgress>,
    /// The `ParallelizationFactor` the lanes are for (0 or 1: one lane).
    pub factor: u32,
}

/// Where one lane of a shard is. With a `ParallelizationFactor` of N, Lambda
/// hashes each record's partition key to one of N lanes and processes the
/// lanes concurrently, each in order, so records with one partition key stay
/// in order.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LaneProgress {
    /// The last sequence number the lane processed.
    pub checkpoint: Option<String>,
    pub attempts: i32,
    pub batch_limit: Option<i32>,
    pub window: Option<TumblingWindow>,
}

/// A tumbling window a lane has open: when it started, and the state the
/// function returned last.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct TumblingWindow {
    pub start: DateTime<Utc>,
    /// The state, as JSON.
    pub state: String,
    /// The state outgrew its limit: the window ends at the next invocation.
    pub terminated_early: bool,
}

impl TumblingWindow {
    fn state(&self) -> Value {
        serde_json::from_str(&self.state).unwrap_or_else(|_| json!({}))
    }
}

/// The most state a tumbling window keeps (1 MB).
const MAX_WINDOW_STATE: usize = 1_048_576;

impl ShardProgress {
    fn lane(&self, lane: u32) -> LaneProgress {
        if self.factor <= 1 {
            LaneProgress {
                checkpoint: self.checkpoint.clone(),
                attempts: self.attempts,
                batch_limit: self.batch_limit,
                window: self.window.clone(),
            }
        } else {
            self.lanes.get(&lane.to_string()).cloned().unwrap_or_default()
        }
    }

    fn set_lane(&mut self, lane: u32, lp: LaneProgress) {
        if self.factor <= 1 {
            self.checkpoint = lp.checkpoint;
            self.attempts = lp.attempts;
            self.batch_limit = lp.batch_limit;
            self.window = lp.window;
        } else {
            self.lanes.insert(lane.to_string(), lp);
        }
    }
}

/// What one lane's batch needs.
struct LaneJob {
    ctx: RequestContext,
    uuid: String,
    config: types::EventSourceMappingConfiguration,
    function_arn: String,
    shard_id: String,
    stream: String,
    source_arn: String,
    region: String,
    invoke_identity: String,
    lane: LaneProgress,
    pending: Vec<StreamRecord>,
    batch_size: i32,
}

/// The lane a partition key hashes to.
fn lane_of(partition_key: &str, factor: u32) -> u32 {
    use sha2::Digest;
    let d = sha2::Sha256::digest(partition_key.as_bytes());
    u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % factor.max(1)
}

/// Whether sequence number `a` comes after `b` (both decimal).
fn seq_after(a: &str, b: &str) -> bool {
    (a.len(), a) > (b.len(), b)
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

    /// One round for a Kinesis mapping: from each shard, a batch for each
    /// of its `ParallelizationFactor` lanes that has records (or a tumbling
    /// window to close), the lanes run concurrently. Returns whether any
    /// shard returned records (the poller then reads again at once, as
    /// Lambda does while a shard has a backlog; otherwise it waits about a
    /// second, leaving the shard's read limit to other consumers).
    pub(crate) async fn poll_stream(
        &self,
        uuid: &str,
        config: &types::EventSourceMappingConfiguration,
        account: &str,
        region: &str,
    ) -> Result<bool, ServiceError> {
        let (Some(source), Some(source_arn), Some(function_arn)) =
            (self.inner.streams.get().cloned(), config.event_source_arn.as_deref(), config.function_arn.as_deref())
        else {
            return Ok(false);
        };
        let stream = stream_of(source_arn).to_string();
        let Some(ctx) = self.poller_context(account, region) else { return Ok(false) };
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
        let factor = config.parallelization_factor.unwrap_or(1).clamp(1, 10) as u32;
        let batch_size = config.batch_size.unwrap_or(100).max(1);
        let mut busy = false;
        for shard in &shards {
            let mut progress = self.progress(uuid, &shard.shard_id);
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
            if progress.factor.max(1) != factor {
                // Records hash to other lanes now: start them again from
                // the shard's checkpoint.
                self.update_progress(uuid, &shard.shard_id, |p| {
                    p.lanes.clear();
                    p.factor = factor;
                    p.attempts = 0;
                    p.batch_limit = None;
                    p.window = None;
                });
                progress = self.progress(uuid, &shard.shard_id);
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
            let limit = if factor == 1 {
                progress.batch_limit.unwrap_or(batch_size).clamp(1, batch_size)
            } else {
                batch_size.saturating_mul(factor as i32).min(10_000)
            };
            let read = match source.read(&role_ctx, &iterator, limit) {
                Ok(read) => read,
                // The shard's read limit is spent (other consumers share
                // it): try this shard again next round, read the others.
                Err(e) if e.code.contains("ProvisionedThroughputExceeded") => continue,
                Err(e) => return Err(e),
            };
            let mut lanes = Vec::new();
            for lane in 0..factor {
                let lp = progress.lane(lane);
                let pending: Vec<StreamRecord> = read
                    .records
                    .iter()
                    .filter(|r| factor == 1 || lane_of(&r.partition_key, factor) == lane)
                    .filter(|r| lp.checkpoint.as_deref().is_none_or(|c| seq_after(&r.sequence_number, c)))
                    .cloned()
                    .collect();
                if pending.is_empty() && lp.window.is_none() {
                    continue;
                }
                busy |= !pending.is_empty();
                let job = LaneJob {
                    ctx: ctx.clone(),
                    uuid: uuid.to_string(),
                    config: config.clone(),
                    function_arn: function_arn.to_string(),
                    shard_id: shard.shard_id.clone(),
                    stream: stream.clone(),
                    source_arn: source_arn.to_string(),
                    region: region.to_string(),
                    invoke_identity: invoke_identity.clone(),
                    lane: lp,
                    pending,
                    batch_size,
                };
                let lambda = self.clone();
                lanes.push((lane, tokio::spawn(async move { lambda.process_lane(job).await })));
            }
            let mut results = Vec::new();
            for (lane, handle) in lanes {
                match handle.await {
                    Ok(Ok(lp)) => results.push((lane, lp)),
                    Ok(Err(e)) => tracing::debug!(mapping = %uuid, "Kinesis batch failed: {}", e.message),
                    Err(e) => tracing::debug!(mapping = %uuid, "Kinesis batch failed: {e}"),
                }
            }
            let closed = read.records.is_empty() && read.next_iterator.is_none();
            self.update_progress(uuid, &shard.shard_id, |p| {
                for (lane, lp) in results {
                    p.set_lane(lane, lp);
                }
                if factor > 1 {
                    // The shard's checkpoint moves past the records every
                    // lane is done with.
                    for r in &read.records {
                        let lp = p.lane(lane_of(&r.partition_key, factor));
                        if lp.checkpoint.as_deref().is_some_and(|c| !seq_after(&r.sequence_number, c)) {
                            p.checkpoint = Some(r.sequence_number.clone());
                        } else {
                            break;
                        }
                    }
                }
                if closed && (0..factor).all(|l| p.lane(l).window.is_none()) {
                    p.finished = true;
                }
            });
        }
        Ok(busy)
    }

    /// One batch of one lane of a shard: invoke the function with the
    /// lane's next records (or close its tumbling window), and work out
    /// where the lane is afterwards.
    async fn process_lane(&self, job: LaneJob) -> Result<LaneProgress, ServiceError> {
        let LaneJob { ctx, uuid, config, function_arn, shard_id, stream, source_arn, region, invoke_identity, .. } =
            &job;
        let mut lp = job.lane.clone();
        let now = ctx.received_at;
        let limit = lp.batch_limit.unwrap_or(job.batch_size).clamp(1, job.batch_size) as usize;
        let tumbling = i64::from(config.tumbling_window_in_seconds.unwrap_or(0).max(0));
        let window_of = |t: DateTime<Utc>| {
            let s = t.timestamp();
            DateTime::from_timestamp(s - s.rem_euclid(tumbling), 0).unwrap_or(t)
        };
        // A tumbling window: the records of one window, then a final
        // invocation with no records once it has ended.
        let mut window: Option<(DateTime<Utc>, Value, bool)> = None;
        let batch: Vec<&StreamRecord> = if tumbling > 0 {
            let first = job.pending.first().map(|r| window_of(r.approximate_arrival));
            match &lp.window {
                Some(w) if first == Some(w.start) && !w.terminated_early => {
                    window = Some((w.start, w.state(), false));
                    job.pending.iter().take_while(|r| window_of(r.approximate_arrival) == w.start).take(limit).collect()
                }
                Some(w) if w.terminated_early || now >= w.start + chrono::Duration::seconds(tumbling) => {
                    window = Some((w.start, w.state(), true));
                    Vec::new()
                }
                Some(_) => return Ok(lp),
                None => match first {
                    Some(start) => {
                        window = Some((start, json!({}), false));
                        job.pending
                            .iter()
                            .take_while(|r| window_of(r.approximate_arrival) == start)
                            .take(limit)
                            .collect()
                    }
                    None => return Ok(lp),
                },
            }
        } else {
            job.pending.iter().take(limit).collect()
        };
        let is_final = window.as_ref().is_some_and(|w| w.2);
        if batch.is_empty() && !is_final {
            return Ok(lp);
        }
        let last = batch.last().map(|r| r.sequence_number.clone());
        let filters = crate::esm::compile_filters(config.filter_criteria.as_ref()).unwrap_or_default();
        let batch: Vec<(Value, &StreamRecord)> = batch
            .into_iter()
            .map(|r| (record(r, shard_id, source_arn, region, invoke_identity), r))
            .filter(|(v, _)| passes(&filters, v))
            .collect();
        if batch.is_empty() && !is_final {
            lp.checkpoint = last.or(lp.checkpoint);
            return Ok(lp);
        }
        let mut event = json!({"Records": batch.iter().map(|(v, _)| v).collect::<Vec<_>>()});
        if let Some((start, state, _)) = &window {
            let time = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            event["window"] = json!({"start": time(*start), "end": time(*start + chrono::Duration::seconds(tumbling))});
            event["state"] = state.clone();
            event["shardId"] = json!(shard_id);
            event["eventSourceARN"] = json!(stream_of(source_arn));
            event["isFinalInvokeForWindow"] = json!(is_final);
            event["isWindowTerminatedEarly"] =
                json!(is_final && lp.window.as_ref().is_some_and(|w| w.terminated_early));
        }
        let payload = serde_json::to_vec(&event).expect("records serialize");
        let f = names::parse_function(ctx, function_arn, None)?;
        let ran = self.run(ctx, &f, payload.clone(), None).await;
        if let Some((_, newest)) = batch.last() {
            let age = (now - newest.approximate_arrival).num_milliseconds().max(0) as f64;
            self.publish_function_metric(ctx, &f, "IteratorAge", "Milliseconds", age);
        }
        let failed = match &ran {
            Ok(r) if r.outcome.function_error.is_none() => {
                let reports = config.function_response_types.iter().flatten().any(|t| t == "ReportBatchItemFailures");
                if reports && !batch.is_empty() {
                    first_failure(&r.outcome.payload, &batch)
                } else {
                    None
                }
            }
            _ => Some(batch.first().map(|(_, r)| r.sequence_number.clone()).unwrap_or_default()),
        };
        let Some(at) = failed else {
            if let Some(last) = last {
                lp.checkpoint = Some(last);
            }
            lp.attempts = 0;
            lp.batch_limit = None;
            if let (Some((start, _, fin)), Ok(r)) = (&window, &ran) {
                lp.window = if *fin {
                    None
                } else {
                    // The state the function returned carries on to the
                    // window's next invocation.
                    let returned: Value = serde_json::from_slice(&r.outcome.payload).unwrap_or_default();
                    let state = returned.get("state").filter(|s| !s.is_null()).cloned().unwrap_or_else(|| json!({}));
                    let state = state.to_string();
                    Some(TumblingWindow { start: *start, terminated_early: state.len() > MAX_WINDOW_STATE, state })
                };
            }
            return Ok(lp);
        };
        // Resume at the first failed record: checkpoint the record before
        // it.
        let before = batch
            .iter()
            .map(|(_, r)| *r)
            .take_while(|r| r.sequence_number != at)
            .last()
            .map(|r| r.sequence_number.clone());
        let oldest = batch.first().map_or(now, |(_, r)| r.approximate_arrival);
        let max_age = config.maximum_record_age_in_seconds.unwrap_or(-1);
        let too_old = max_age >= 0 && (now - oldest).num_seconds() > i64::from(max_age);
        let max_attempts = config.maximum_retry_attempts.unwrap_or(-1);
        let bisect = config.bisect_batch_on_function_error.unwrap_or(false);
        if let Some(b) = &before {
            lp.checkpoint = Some(b.clone());
        }
        lp.attempts += 1;
        let attempts = lp.attempts;
        if bisect {
            lp.batch_limit = Some((limit as i32 / 2).max(1));
        }
        let give_up = too_old || (max_attempts >= 0 && attempts > max_attempts);
        if give_up {
            // Give up on the batch: skip past it.
            tracing::info!(mapping = %uuid, "discarding a Kinesis batch the function failed");
            if let Some(last) = &last {
                lp.checkpoint = Some(last.clone());
            }
            lp.attempts = 0;
            lp.batch_limit = None;
            if is_final {
                lp.window = None;
            }
        }
        let destination =
            config.destination_config.as_ref().and_then(|d| d.on_failure.as_ref()).and_then(|d| d.destination.clone());
        if let (true, Some(destination)) = (give_up, destination) {
            let condition = if too_old { "RecordAgeExceeded" } else { "RetryAttemptsExhausted" };
            let executed = ran.as_ref().map(|r| r.executed_version.clone()).unwrap_or("$LATEST".into());
            let error = ran.as_ref().ok().and_then(|r| r.outcome.function_error.clone());
            let records: Vec<&StreamRecord> = batch.iter().map(|(_, r)| *r).collect();
            let info = BatchInfo { shard_id, stream_arn: stream, records: &records };
            let mut body = failure_record(ctx, function_arn, &executed, error, condition, attempts, &info);
            let to_bucket = destination.split(':').nth(2) == Some("s3");
            if to_bucket {
                // S3 destinations get the whole invocation payload.
                body["payload"] = Value::String(String::from_utf8_lossy(&payload).into_owned());
            }
            let message = crate::DestinationMessage {
                body: body.to_string(),
                function_arn: function_arn.to_string(),
                detail_type: "Lambda Function Invocation Result - Failure".into(),
                s3_key: to_bucket.then(|| {
                    format!("aws/lambda/{uuid}/{shard_id}/{}", crate::destinations::s3_key_suffix(ctx.received_at))
                }),
                ..Default::default()
            };
            self.send_to_destination(ctx, function_arn, &destination, &message).await;
        }
        Ok(lp)
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

    #[test]
    fn lanes_and_sequence_numbers() {
        assert!(seq_after("49590338271490256608559692538361571095921575989136588898", "4959"));
        assert!(seq_after("200", "199"));
        assert!(!seq_after("199", "199"));
        assert_eq!(lane_of("anything", 1), 0);
        let lanes: std::collections::HashSet<u32> = (0..100).map(|i| lane_of(&format!("k{i}"), 10)).collect();
        assert_eq!(lanes.len(), 10);
        assert_eq!(lane_of("k1", 10), lane_of("k1", 10));
        let mut p = ShardProgress { factor: 3, ..Default::default() };
        p.set_lane(2, LaneProgress { checkpoint: Some("7".into()), ..Default::default() });
        assert_eq!(p.lane(2).checkpoint.as_deref(), Some("7"));
        assert_eq!(p.checkpoint, None);
        let mut one = ShardProgress::default();
        one.set_lane(0, LaneProgress { checkpoint: Some("9".into()), attempts: 1, ..Default::default() });
        assert_eq!((one.checkpoint.as_deref(), one.attempts), (Some("9"), 1));
    }
}
