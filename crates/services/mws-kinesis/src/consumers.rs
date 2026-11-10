//! Enhanced fan-out: registered consumers and `SubscribeToShard`, whose
//! response stays open for five minutes and pushes records as they
//! arrive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use mws_core::{ConditionContext, HttpResponse, RequestContext, ServiceError, StreamingBody};

use crate::generated::{self, errors, types};
use crate::metrics::Batch;
use crate::names::{authorize, authorize_stream, invalid_argument, now_ms, request_tag_context, valid_name, StreamRef};
use crate::records::{children, iterator_age, position, read_from};
use crate::state::{Consumer, State, TRANSITION_MS};
use crate::throughput::{Bucket, FAN_OUT_BYTES};
use crate::Kinesis;

/// Consumers per stream.
const CONSUMER_LIMIT: usize = 20;
/// A subscription lasts this long.
const SUBSCRIPTION_LIMIT: Duration = Duration::from_secs(300);
/// With no new records, an event still goes out this often.
const HEARTBEAT: Duration = Duration::from_secs(5);

/// The record bytes an event carries, against the fan-out rate.
fn event_bytes(records: &[types::Record]) -> f64 {
    records.iter().map(|r| r.data.len() as f64).sum()
}

fn time(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

/// A newer `SubscribeToShard` for the same consumer and shard within this
/// long of a successful one fails; after it, the newer one takes over.
const TAKEOVER_AFTER: Duration = Duration::from_secs(5);

type SubscriptionKey = (String, String);
/// The last generation handed out, and the open subscriptions.
type SubscriptionTable = (u64, HashMap<SubscriptionKey, (u64, tokio::time::Instant)>);

/// Open subscriptions, by (consumer ARN, shard id): a generation number
/// and when it started. Not persisted.
#[derive(Clone, Default)]
pub struct Subscriptions(Arc<Mutex<SubscriptionTable>>);

impl Subscriptions {
    /// Start a subscription, taking over an older one: its generation, or
    /// `None` when another started less than five seconds ago.
    fn add(&self, key: SubscriptionKey) -> Option<u64> {
        let mut g = self.0.lock().expect("subscription lock");
        if g.1.get(&key).is_some_and(|(_, started)| started.elapsed() < TAKEOVER_AFTER) {
            return None;
        }
        g.0 += 1;
        let generation = g.0;
        g.1.insert(key, (generation, tokio::time::Instant::now()));
        Some(generation)
    }

    /// Whether `generation` is still the subscription for `key`.
    fn current(&self, key: &SubscriptionKey, generation: u64) -> bool {
        self.0.lock().expect("subscription lock").1.get(key).is_some_and(|(g, _)| *g == generation)
    }

    fn remove(&self, key: &SubscriptionKey, generation: u64) {
        let mut g = self.0.lock().expect("subscription lock");
        if g.1.get(key).is_some_and(|(g, _)| *g == generation) {
            g.1.remove(key);
        }
    }

    pub fn clear(&self) {
        self.0.lock().expect("subscription lock").1.clear();
    }
}

fn consumer_not_found(what: &str) -> ServiceError {
    errors::resource_not_found(format!("Consumer {what} not found."))
}

/// The consumer a request names: by ARN, or by stream ARN and name.
fn find<'a>(
    st: &'a State,
    stream_arn: Option<&str>,
    name: Option<&str>,
    arn: Option<&str>,
) -> Result<&'a Consumer, ServiceError> {
    match (arn, stream_arn, name) {
        (Some(arn), _, _) => st.consumers.get(arn).ok_or_else(|| consumer_not_found(arn)),
        (None, Some(stream), Some(name)) => st
            .consumers
            .values()
            .find(|c| c.stream_arn == stream && c.name == name)
            .ok_or_else(|| consumer_not_found(name)),
        _ => Err(invalid_argument("Either ConsumerARN or both ConsumerName and StreamARN must be provided.")),
    }
}

fn description(c: &Consumer) -> types::ConsumerDescription {
    types::ConsumerDescription {
        consumer_name: c.name.clone(),
        consumer_arn: c.arn.clone(),
        consumer_status: c.status.clone(),
        consumer_creation_timestamp: time(c.created_at),
        stream_arn: c.stream_arn.clone(),
    }
}

fn summary(c: &Consumer) -> types::Consumer {
    types::Consumer {
        consumer_name: c.name.clone(),
        consumer_arn: c.arn.clone(),
        consumer_status: c.status.clone(),
        consumer_creation_timestamp: time(c.created_at),
    }
}

/// Authorize an action on a consumer: its own policy, or the stream's.
fn authorize_consumer(ctx: &RequestContext, st: &State, action: &str, c: &Consumer) -> Result<(), ServiceError> {
    let policy = c.policy.clone().or_else(|| st.streams.get(&c.stream_arn).and_then(|s| s.policy.clone()));
    authorize(ctx, &format!("kinesis:{action}"), &c.arn, policy.as_deref(), &c.tags, ConditionContext::new())
}

impl Kinesis {
    pub fn register_stream_consumer(
        &self,
        ctx: &RequestContext,
        input: types::RegisterStreamConsumerInput,
    ) -> Result<types::RegisterStreamConsumerOutput, ServiceError> {
        let r = StreamRef::from_arn(&input.stream_arn)?;
        let tags = input.tags.unwrap_or_default();
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "RegisterStreamConsumer", &r, request_tag_context(&tags))?;
        if !valid_name(&input.consumer_name) {
            return Err(invalid_argument(format!("Invalid consumer name {}.", input.consumer_name)));
        }
        crate::names::validate_tags(&tags)?;
        let s = r.get(&st)?;
        if s.status != "ACTIVE" && s.status != "UPDATING" {
            return Err(crate::names::not_active(s));
        }
        let existing: Vec<&Consumer> = st.consumers.values().filter(|c| c.stream_arn == r.arn).collect();
        if existing.iter().any(|c| c.name == input.consumer_name) {
            return Err(errors::resource_in_use(format!(
                "Consumer {} under stream {} already exists.",
                input.consumer_name, r.arn
            )));
        }
        if existing.len() >= CONSUMER_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "Stream {} has reached the limit of {CONSUMER_LIMIT} registered consumers.",
                r.arn
            )));
        }
        let now = now_ms(ctx);
        let arn = format!("{}/consumer/{}:{}", r.arn, input.consumer_name, now / 1000);
        let c = Consumer {
            name: input.consumer_name,
            arn: arn.clone(),
            stream_arn: r.arn.clone(),
            created_at: now,
            status: "CREATING".into(),
            settles_at: now + TRANSITION_MS,
            policy: None,
            tags,
        };
        let out = summary(&c);
        st.consumers.insert(arn, c);
        Ok(types::RegisterStreamConsumerOutput { consumer: out })
    }

    pub fn deregister_stream_consumer(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterStreamConsumerInput,
    ) -> Result<(), ServiceError> {
        let mut st = self.settled(ctx);
        let c = find(&st, input.stream_arn.as_deref(), input.consumer_name.as_deref(), input.consumer_arn.as_deref())?;
        authorize_consumer(ctx, &st, "DeregisterStreamConsumer", c)?;
        let arn = c.arn.clone();
        if let Some(c) = st.consumers.get_mut(&arn) {
            c.status = "DELETING".into();
            c.settles_at = now_ms(ctx) + TRANSITION_MS;
        }
        Ok(())
    }

    pub fn describe_stream_consumer(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStreamConsumerInput,
    ) -> Result<types::DescribeStreamConsumerOutput, ServiceError> {
        let st = self.settled(ctx);
        let c = find(&st, input.stream_arn.as_deref(), input.consumer_name.as_deref(), input.consumer_arn.as_deref())?;
        authorize_consumer(ctx, &st, "DescribeStreamConsumer", c)?;
        Ok(types::DescribeStreamConsumerOutput { consumer_description: description(c) })
    }

    pub fn list_stream_consumers(
        &self,
        ctx: &RequestContext,
        input: types::ListStreamConsumersInput,
    ) -> Result<types::ListStreamConsumersOutput, ServiceError> {
        let r = StreamRef::from_arn(&input.stream_arn)?;
        let st = self.settled(ctx);
        authorize_stream(ctx, &st, "ListStreamConsumers", &r, ConditionContext::new())?;
        r.get(&st)?;
        let after = input.next_token.as_deref().unwrap_or_default();
        let mut consumers: Vec<&Consumer> =
            st.consumers.values().filter(|c| c.stream_arn == r.arn && c.name.as_str() > after).collect();
        consumers.sort_by(|a, b| a.name.cmp(&b.name));
        let limit = input.max_results.unwrap_or(100).clamp(1, 10_000) as usize;
        let more = consumers.len() > limit;
        consumers.truncate(limit);
        Ok(types::ListStreamConsumersOutput {
            next_token: more.then(|| consumers.last().map(|c| c.name.clone()).unwrap_or_default()),
            consumers: Some(consumers.into_iter().map(summary).collect()),
        })
    }

    /// Validate a subscription: the consumer is active, the shard exists,
    /// and the starting position is valid. Returns the stream ARN, the
    /// consumer's name, the shard index and the counter to start reading
    /// at.
    fn open_subscription(
        &self,
        ctx: &RequestContext,
        input: &types::SubscribeToShardInput,
    ) -> Result<(String, String, u32, u64), ServiceError> {
        let mut st = self.settled(ctx);
        let c = st.consumers.get(&input.consumer_arn).ok_or_else(|| consumer_not_found(&input.consumer_arn))?;
        authorize_consumer(ctx, &st, "SubscribeToShard", c)?;
        if c.status != "ACTIVE" {
            return Err(errors::resource_in_use(format!(
                "Consumer {} under stream {} is not ACTIVE, instead in state {}",
                c.arn, c.stream_arn, c.status
            )));
        }
        let stream_arn = c.stream_arn.clone();
        let consumer = c.name.clone();
        let r = StreamRef::from_arn(&stream_arn)?;
        let s = r.get_mut(&mut st)?;
        let Some(sh) = s.shard(&input.shard_id) else {
            return Err(errors::resource_not_found(format!(
                "Shard {} in stream {} under account {} does not exist",
                input.shard_id, s.name, s.account
            )));
        };
        let p = &input.starting_position;
        let counter =
            position(s, sh, &p.r#type, p.sequence_number.as_deref(), p.timestamp.map(|t| t.timestamp_millis()))?;
        let index = sh.index;
        let data_key = s.encrypted().then(|| s.data_key.clone());
        drop(st);
        if let Some(dk) = data_key {
            self.check_decrypt(ctx, &stream_arn, &dk)?;
        }
        if input.dry_run == Some(true) {
            return Err(errors::dry_run_operation("The request would have succeeded, but the DryRun flag is set."));
        }
        Ok((stream_arn, consumer, index, counter))
    }

    /// One event of a subscription from `counter`; the counter to continue
    /// from, whether the shard has ended, and the stream's metrics batch.
    fn subscription_event(
        &self,
        stream_arn: &str,
        index: u32,
        counter: u64,
        now: i64,
    ) -> Option<(types::SubscribeToShardEvent, u64, bool, Batch)> {
        let st = self.lock();
        let s = st.streams.get(stream_arn)?;
        let sh = s.shards.iter().find(|x| x.index == index)?;
        let read = read_from(s, sh, counter, 10_000, now);
        let continuation = crate::shards::sequence_number(s.created_at, sh.index, read.next_counter.saturating_sub(1));
        let child_shards = read.end_of_closed_shard.then(|| children(s, sh));
        Some((
            types::SubscribeToShardEvent {
                records: read.records,
                continuation_sequence_number: continuation,
                millis_behind_latest: read.millis_behind,
                child_shards,
            },
            read.next_counter,
            read.end_of_closed_shard,
            Batch::new(s, now),
        ))
    }

    /// The consumer is still registered and `ACTIVE`.
    fn consumer_active(&self, consumer_arn: &str) -> bool {
        self.lock().consumers.get(consumer_arn).is_some_and(|c| c.status == "ACTIVE")
    }

    /// Publish the metrics of one event a subscription sent.
    fn event_metrics(
        &self,
        mut batch: Batch,
        consumer: &str,
        shard: &str,
        event: &types::SubscribeToShardEvent,
        now: i64,
    ) {
        let bytes: f64 = event.records.iter().map(|r| r.data.len() as f64).sum();
        let count = event.records.len() as f64;
        batch.consumer(consumer, "SubscribeToShardEvent.Bytes", "Bytes", bytes);
        batch.consumer(consumer, "SubscribeToShardEvent.Records", "Count", count);
        batch.consumer(
            consumer,
            "SubscribeToShardEvent.MillisBehindLatest",
            "Milliseconds",
            event.millis_behind_latest as f64,
        );
        batch.consumer(consumer, "SubscribeToShardEvent.Success", "Count", 1.0);
        batch.shard(shard, "OutgoingBytes", "Bytes", bytes);
        batch.shard(shard, "OutgoingRecords", "Count", count);
        batch.shard(shard, "IteratorAgeMilliseconds", "Milliseconds", iterator_age(&event.records, now));
        self.publish(batch);
    }

    /// The wire path: an `initial-response`, then events as records
    /// arrive, for up to five minutes. A newer subscription for the same
    /// consumer and shard takes over after five seconds, and the older one
    /// ends with `ResourceInUseException`; deregistering the consumer ends
    /// it with `ResourceNotFoundException`.
    pub(crate) fn subscribe_to_shard_streaming(
        &self,
        ctx: &RequestContext,
        input: types::SubscribeToShardInput,
    ) -> Result<HttpResponse, ServiceError> {
        let (stream_arn, consumer, index, counter) = self.open_subscription(ctx, &input)?;
        let key = (input.consumer_arn.clone(), input.shard_id.clone());
        let Some(generation) = self.subscriptions.add(key.clone()) else {
            return Err(errors::resource_in_use(format!(
                "Another active subscription exists for this consumer: {}",
                input.consumer_arn
            )));
        };
        let offset = ctx.received_at - chrono::Utc::now();
        let now = move || (chrono::Utc::now() + offset).timestamp_millis();
        let started_at = now();
        let Some((first, mut counter, mut ended, batch)) =
            self.subscription_event(&stream_arn, index, counter, started_at)
        else {
            self.subscriptions.remove(&key, generation);
            return Err(errors::resource_not_found(format!("Stream {stream_arn} not found.")));
        };
        let mut opened = Batch::new_like(&batch);
        opened.consumer(&consumer, "SubscribeToShard.Success", "Count", 1.0);
        self.publish(opened);
        self.event_metrics(batch, &consumer, &input.shard_id, &first, started_at);
        let first_bytes = event_bytes(&first.records);
        let head = generated::encode_event_subscribe_to_shard_event_stream(
            &types::SubscribeToShardEventStream::SubscribeToShardEvent(first),
        );
        let (tx, body) = StreamingBody::channel(16);
        let me = self.clone();
        let consumer_arn = input.consumer_arn.clone();
        let shard_id = input.shard_id.clone();
        // Enhanced fan-out delivers up to 2 MiB/s per consumer and shard.
        let mut budget = Bucket::full(FAN_OUT_BYTES);
        budget.take(first_bytes);
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            let mut last_sent = tokio::time::Instant::now();
            while !ended && started.elapsed() < SUBSCRIPTION_LIMIT {
                let notified = me.arrivals.notified();
                let _ = tokio::time::timeout(Duration::from_millis(200), notified).await;
                budget.refill(FAN_OUT_BYTES);
                let wait = budget.wait(FAN_OUT_BYTES);
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                    budget.refill(FAN_OUT_BYTES);
                }
                if !me.subscriptions.current(&key, generation) {
                    let taken =
                        types::SubscribeToShardEventStream::ResourceInUseException(types::ResourceInUseException {
                            message: Some(format!(
                                "Another active subscription exists for this consumer: {consumer_arn}"
                            )),
                        });
                    let _ = tx.send(Bytes::from(generated::encode_event_subscribe_to_shard_event_stream(&taken))).await;
                    return;
                }
                if !me.consumer_active(&consumer_arn) {
                    let gone = types::SubscribeToShardEventStream::ResourceNotFoundException(
                        types::ResourceNotFoundException {
                            message: Some(format!("Consumer {consumer_arn} not found.")),
                        },
                    );
                    let _ = tx.send(Bytes::from(generated::encode_event_subscribe_to_shard_event_stream(&gone))).await;
                    break;
                }
                let at = now();
                let Some((event, next, end, batch)) = me.subscription_event(&stream_arn, index, counter, at) else {
                    let gone = types::SubscribeToShardEventStream::ResourceNotFoundException(
                        types::ResourceNotFoundException { message: Some(format!("Stream {stream_arn} not found.")) },
                    );
                    let _ = tx.send(Bytes::from(generated::encode_event_subscribe_to_shard_event_stream(&gone))).await;
                    break;
                };
                if event.records.is_empty() && !end && last_sent.elapsed() < HEARTBEAT {
                    continue;
                }
                counter = next;
                ended = end;
                budget.take(event_bytes(&event.records));
                me.event_metrics(batch, &consumer, &shard_id, &event, at);
                let frame = generated::encode_event_subscribe_to_shard_event_stream(
                    &types::SubscribeToShardEventStream::SubscribeToShardEvent(event),
                );
                if tx.send(Bytes::from(frame)).await.is_err() {
                    break;
                }
                last_sent = tokio::time::Instant::now();
            }
            me.subscriptions.remove(&key, generation);
        });
        let mut resp = mws_proto_json::event_stream_response(&generated::SERVICE_INFO, &ctx.request_id, head);
        resp.extensions_mut().insert(body);
        Ok(resp)
    }

    /// The scenario/invoke path: the first event only.
    pub fn subscribe_to_shard(
        &self,
        ctx: &RequestContext,
        input: types::SubscribeToShardInput,
    ) -> Result<types::SubscribeToShardOutput, ServiceError> {
        let (stream_arn, _, index, counter) = self.open_subscription(ctx, &input)?;
        let (event, _, _, _) = self
            .subscription_event(&stream_arn, index, counter, now_ms(ctx))
            .ok_or_else(|| errors::resource_not_found(format!("Stream {stream_arn} not found.")))?;
        Ok(types::SubscribeToShardOutput {
            event_stream: vec![types::SubscribeToShardEventStream::SubscribeToShardEvent(event)],
        })
    }
}
