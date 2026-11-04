//! Kinesis data streams as a source: Firehose reads every shard with the
//! source role, from the delivery stream's creation time on, and buffers
//! the records with their Kinesis metadata.

use mws_core::{RequestContext, ServiceError};
use mws_kinesis::generated::types as kt;
use serde_json::Value;

use crate::names::invalid_argument;
use crate::records::{buffer, record_id};
use crate::state::{Buffered, KinesisOrigin};
use crate::Firehose;

/// A Kinesis source to read, copied out of the state.
struct Source {
    arn: String,
    account: String,
    kinesis_arn: String,
    role: String,
    positions: std::collections::BTreeMap<String, String>,
    start: Option<i64>,
}

impl Firehose {
    /// The Kinesis data stream a delivery stream reads, if any.
    pub(crate) fn source_stream_arn(&self, stream_arn: &str) -> Option<String> {
        let st = self.lock();
        let s = st.streams.get(stream_arn)?;
        s.source.pointer("/kinesis/kinesis_stream_arn").and_then(Value::as_str).map(str::to_string)
    }

    /// CreateDeliveryStream checks that the source role can read the
    /// stream.
    pub(crate) fn check_kinesis_source(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        kinesis_arn: &str,
        role_arn: &str,
    ) -> Result<(), ServiceError> {
        let Some(kinesis) = self.inner.kinesis.get() else { return Ok(()) };
        let account = ctx.caller.account_id.clone();
        let rctx = self.role_context(ctx, role_arn, stream_arn, &account).map_err(invalid_argument)?;
        kinesis
            .describe_stream_summary(
                &rctx,
                kt::DescribeStreamSummaryInput { stream_arn: Some(kinesis_arn.to_string()), ..Default::default() },
            )
            .map_err(|e| {
                invalid_argument(format!(
                    "Firehose is unable to access the Kinesis stream {kinesis_arn} with role {role_arn}: {}",
                    e.message
                ))
            })?;
        Ok(())
    }

    /// Read new records from every Kinesis source into the buffers.
    pub(crate) async fn poll_sources(&self) {
        let Some(kinesis) = self.inner.kinesis.get() else { return };
        let sources: Vec<Source> = {
            let st = self.lock();
            st.streams
                .values()
                .filter(|s| s.active() && s.kind == "KinesisStreamAsSource")
                .filter_map(|s| {
                    let k = s.source.get("kinesis")?;
                    Some(Source {
                        arn: s.arn.clone(),
                        account: s.account.clone(),
                        kinesis_arn: k.get("kinesis_stream_arn")?.as_str()?.to_string(),
                        role: k.get("role_arn")?.as_str()?.to_string(),
                        positions: s.kinesis_positions.clone(),
                        start: s.delivery_start,
                    })
                })
                .collect()
        };
        for src in sources {
            let region = src.kinesis_arn.split(':').nth(3).unwrap_or("us-east-1").to_string();
            let Some(ctx) = self.background_context(&region) else { return };
            let rctx = match self.role_context(&ctx, &src.role, &src.arn, &src.account) {
                Ok(c) => c,
                Err(m) => {
                    tracing::info!(stream = %src.arn, "Firehose cannot read its Kinesis source: {m}");
                    continue;
                }
            };
            let shards = match kinesis.list_shards(
                &rctx,
                kt::ListShardsInput { stream_arn: Some(src.kinesis_arn.clone()), ..Default::default() },
            ) {
                Ok(out) => out.shards.unwrap_or_default(),
                Err(e) => {
                    tracing::info!(stream = %src.arn, "Firehose cannot list its Kinesis source's shards: {}", e.message);
                    continue;
                }
            };
            let mut read = Vec::new();
            let mut positions = Vec::new();
            for shard in shards {
                let mut request = kt::GetShardIteratorInput {
                    stream_arn: Some(src.kinesis_arn.clone()),
                    shard_id: shard.shard_id.clone(),
                    ..Default::default()
                };
                match src.positions.get(&shard.shard_id) {
                    Some(seq) => {
                        request.shard_iterator_type = "AFTER_SEQUENCE_NUMBER".into();
                        request.starting_sequence_number = Some(seq.clone());
                    }
                    None => {
                        request.shard_iterator_type = "AT_TIMESTAMP".into();
                        request.timestamp =
                            Some(chrono::DateTime::from_timestamp_millis(src.start.unwrap_or(0)).unwrap_or_default());
                    }
                }
                let Ok(it) = kinesis.get_shard_iterator(&rctx, request) else { continue };
                let Some(mut iterator) = it.shard_iterator else { continue };
                loop {
                    let out = match kinesis.get_records(
                        &rctx,
                        kt::GetRecordsInput { shard_iterator: iterator.clone(), ..Default::default() },
                    ) {
                        Ok(out) => out,
                        Err(e) => {
                            tracing::info!(stream = %src.arn, "Firehose cannot read its Kinesis source: {}", e.message);
                            break;
                        }
                    };
                    let done = out.records.is_empty();
                    for r in out.records {
                        let arrival = r
                            .approximate_arrival_timestamp
                            .map(|t| t.timestamp_millis())
                            .unwrap_or_else(|| ctx.received_at.timestamp_millis());
                        positions.push((shard.shard_id.clone(), r.sequence_number.clone()));
                        read.push(Buffered {
                            record_id: record_id(),
                            data: r.data,
                            arrival: ctx.received_at.timestamp_millis(),
                            kinesis: Some(KinesisOrigin {
                                shard_id: shard.shard_id.clone(),
                                partition_key: r.partition_key.unwrap_or_default(),
                                sequence_number: r.sequence_number,
                                arrival,
                            }),
                        });
                    }
                    match out.next_shard_iterator {
                        Some(next) if !done => iterator = next,
                        _ => break,
                    }
                }
            }
            if read.is_empty() {
                continue;
            }
            let mut st = self.lock();
            let Some(s) = st.streams.get_mut(&src.arn) else { continue };
            for (shard, seq) in positions {
                s.kinesis_positions.insert(shard, seq);
            }
            buffer(s, read);
        }
    }
}
