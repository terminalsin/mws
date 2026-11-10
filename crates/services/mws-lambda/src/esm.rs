//! Event source mappings that poll: Lambda's pollers read SQS queues as the
//! function's execution role, invoke the function synchronously with a
//! batch of records, and delete what the function processed. As in AWS:
//!
//! - `CreateEventSourceMapping` checks the queue exists, that the role may
//!   `sqs:ReceiveMessage`, `sqs:DeleteMessage` and `sqs:GetQueueAttributes`,
//!   and that the queue's visibility timeout is not shorter than the
//!   function's timeout.
//! - A batch the function fails is left alone: its messages become visible
//!   again when their visibility timeout ends, and the queue's redrive
//!   policy moves them to a dead-letter queue.
//! - With `FunctionResponseTypes: ["ReportBatchItemFailures"]`, only the
//!   messages named in `batchItemFailures` are kept.
//!
//! The queue side is the [`QueueSource`] trait, which the `mws` crate
//! implements over SQS, so this crate does not depend on SQS.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use mws_core::{RequestContext, ServiceError};
use serde_json::{json, Map, Value};

use crate::generated::{errors, types};
use crate::names;
use crate::Lambda;

/// A message a poller received.
#[derive(Debug, Clone, Default)]
pub struct QueueMessage {
    pub message_id: String,
    pub receipt_handle: String,
    pub body: String,
    pub md5_of_body: String,
    pub md5_of_message_attributes: Option<String>,
    /// System attributes (`ApproximateReceiveCount`, `SentTimestamp`, ...).
    pub attributes: BTreeMap<String, String>,
    pub message_attributes: BTreeMap<String, QueueMessageAttribute>,
}

#[derive(Debug, Clone, Default)]
pub struct QueueMessageAttribute {
    pub data_type: String,
    pub string_value: Option<String>,
    pub binary_value: Option<Vec<u8>>,
}

/// What a poller needs to know about a queue.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueFacts {
    pub visibility_timeout: i64,
    pub fifo: bool,
}

/// A queue service Lambda can poll. Every call is made as `ctx.caller`
/// (the function's execution role), so identity and queue policies decide
/// exactly as they would for the role's own SDK calls.
#[async_trait::async_trait]
pub trait QueueSource: Send + Sync {
    /// The queue's attributes; fails like `GetQueueAttributes`.
    fn facts(&self, ctx: &RequestContext, queue_arn: &str) -> Result<QueueFacts, ServiceError>;
    /// Whether the caller may perform `action` (`sqs:ReceiveMessage`, ...)
    /// on the queue.
    fn authorize(&self, ctx: &RequestContext, queue_arn: &str, action: &str) -> Result<(), ServiceError>;
    /// Receive up to `max` (at most 10) messages without waiting.
    async fn receive(&self, ctx: &RequestContext, queue_arn: &str, max: i32)
        -> Result<Vec<QueueMessage>, ServiceError>;
    /// Delete messages by receipt handle.
    fn delete(&self, ctx: &RequestContext, queue_arn: &str, receipt_handles: &[String]) -> Result<(), ServiceError>;
}

/// The poller's view of the service: the last request's context (for the
/// authorizer, the endpoint functions see and the emulated clock), which
/// stream mappings are mid-batch, and how far each queue mapping has
/// scaled.
#[derive(Default)]
pub(crate) struct Pollers {
    template: Mutex<Option<(RequestContext, chrono::Duration)>>,
    busy: Mutex<HashSet<String>>,
    queues: Mutex<HashMap<String, Scaling>>,
    started: std::sync::OnceLock<()>,
}

/// How many batches a queue mapping has in flight, and how many it may.
/// As in AWS, a mapping starts with five concurrent batches, adds more
/// while the queue has a backlog (whole batches keep coming back), and
/// gives them up again when receives come back empty, within
/// `ScalingConfig.MaximumConcurrency` and the function's reserved
/// concurrency. On a FIFO queue a message group with a batch in flight
/// returns nothing more until the batch is done, so each group stays in
/// order.
#[derive(Debug, Clone, Copy)]
struct Scaling {
    inflight: usize,
    target: usize,
    backlog: bool,
    idle: bool,
}

/// The concurrent batches a queue mapping starts with.
const INITIAL_QUEUE_CONCURRENCY: usize = 5;
/// The most concurrent invocations a queue mapping scales to.
const MAX_QUEUE_CONCURRENCY: usize = 1_250;

const POLL_INTERVAL: Duration = Duration::from_millis(250);

fn is_sqs(arn: &str) -> bool {
    arn.split(':').nth(2) == Some("sqs")
}

impl Lambda {
    /// Poll SQS queues for event source mappings through `source`.
    pub fn set_queue_source(&self, source: std::sync::Arc<dyn QueueSource>) {
        let _ = self.inner.queues.set(source);
    }

    /// Remember the context of a request (so pollers can act later) and
    /// start the pollers if they are not running.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        if self.inner.queues.get().is_none() && self.inner.streams.get().is_none() {
            return;
        }
        let offset = ctx.received_at - chrono::Utc::now();
        *self.inner.pollers.template.lock().expect("poller lock poisoned") = Some((ctx.clone(), offset));
        self.start_pollers();
    }

    /// Start the pollers if they are not running. Mappings poll whenever
    /// they are `Enabled`, however they were made (API, CloudFormation,
    /// scenario files or restored state).
    pub(crate) fn start_pollers(&self) {
        if self.inner.queues.get().is_none() && self.inner.streams.get().is_none() {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        self.inner.pollers.started.get_or_init(|| {
            let weak = std::sync::Arc::downgrade(&self.inner);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    let Some(inner) = weak.upgrade() else { return };
                    Lambda { inner }.poll_all();
                }
            });
        });
    }

    fn poll_all(&self) {
        let mappings: Vec<(String, types::EventSourceMappingConfiguration, String, String)> = {
            let st = self.read();
            st.event_source_mappings
                .iter()
                .filter(|(_, m)| m.config.state.as_deref() == Some("Enabled"))
                .filter(|(_, m)| {
                    m.config.event_source_arn.as_deref().is_some_and(|a| is_sqs(a) || crate::esm_stream::is_kinesis(a))
                })
                .map(|(uuid, m)| (uuid.clone(), m.config.clone(), m.account_id.clone(), m.region.clone()))
                .collect()
        };
        self.inner
            .pollers
            .queues
            .lock()
            .expect("poller lock poisoned")
            .retain(|uuid, s| s.inflight > 0 || mappings.iter().any(|(u, ..)| u == uuid));
        for (uuid, config, account, region) in mappings {
            let stream = config.event_source_arn.as_deref().is_some_and(crate::esm_stream::is_kinesis);
            if !stream {
                self.poll_queue(uuid, config, account, region);
                continue;
            }
            if !self.inner.pollers.busy.lock().expect("poller lock poisoned").insert(uuid.clone()) {
                continue;
            }
            let lambda = self.clone();
            tokio::spawn(async move {
                if let Err(e) = lambda.poll_stream(&uuid, &config, &account, &region).await {
                    tracing::debug!(mapping = %uuid, "event source mapping poll failed: {}", e.message);
                }
                lambda.inner.pollers.busy.lock().expect("poller lock poisoned").remove(&uuid);
            });
        }
    }

    /// The most batches a queue mapping may have in flight:
    /// `MaximumConcurrency`, and no more than the function's reserved
    /// concurrency.
    fn queue_concurrency_cap(
        &self,
        config: &types::EventSourceMappingConfiguration,
        account: &str,
        region: &str,
    ) -> usize {
        let mut cap = config
            .scaling_config
            .as_ref()
            .and_then(|s| s.maximum_concurrency)
            .map_or(MAX_QUEUE_CONCURRENCY, |m| m.max(0) as usize);
        let reserved = config.function_arn.as_deref().and_then(|arn| {
            let ctx = self.poller_context(account, region)?;
            let f = names::parse_function(&ctx, arn, None).ok()?;
            let st = self.read();
            st.functions.get(&f.arn())?.reserved_concurrency
        });
        if let Some(r) = reserved {
            cap = cap.min(r.max(0) as usize);
        }
        cap
    }

    /// Start as many batches for a queue mapping as its scaling allows.
    fn poll_queue(
        &self,
        uuid: String,
        config: types::EventSourceMappingConfiguration,
        account: String,
        region: String,
    ) {
        let cap = self.queue_concurrency_cap(&config, &account, &region);
        let start = {
            let mut queues = self.inner.pollers.queues.lock().expect("poller lock poisoned");
            let s = queues.entry(uuid.clone()).or_insert(Scaling {
                inflight: 0,
                target: INITIAL_QUEUE_CONCURRENCY,
                backlog: false,
                idle: false,
            });
            if s.backlog {
                s.target += 1;
            } else if s.idle {
                s.target = s.target.saturating_sub(1);
            }
            s.target = s.target.clamp(INITIAL_QUEUE_CONCURRENCY, MAX_QUEUE_CONCURRENCY).min(cap);
            s.backlog = false;
            s.idle = false;
            let start = s.target.saturating_sub(s.inflight);
            s.inflight += start;
            start
        };
        for _ in 0..start {
            let lambda = self.clone();
            let (uuid, config, account, region) = (uuid.clone(), config.clone(), account.clone(), region.clone());
            tokio::spawn(async move {
                let polled = lambda.poll_once(&config, &account, &region).await;
                if let Err(e) = &polled {
                    tracing::debug!(mapping = %uuid, "event source mapping poll failed: {}", e.message);
                }
                let mut queues = lambda.inner.pollers.queues.lock().expect("poller lock poisoned");
                if let Some(s) = queues.get_mut(&uuid) {
                    s.inflight = s.inflight.saturating_sub(1);
                    match polled {
                        Ok(Polled::Full) => s.backlog = true,
                        Ok(Polled::Empty) | Err(_) => s.idle = true,
                        Ok(Polled::Partial) => {}
                    }
                }
            });
        }
    }

    /// The emulated clock minus the wall clock, as last seen.
    pub(crate) fn clock_skew(&self) -> chrono::Duration {
        self.inner.pollers.template.lock().expect("poller lock poisoned").as_ref().map(|(_, o)| *o).unwrap_or_default()
    }

    /// A context for work done on behalf of `account` in `region`, at the
    /// emulated time now.
    pub(crate) fn poller_context(&self, account: &str, region: &str) -> Option<RequestContext> {
        let template = self.inner.pollers.template.lock().expect("poller lock poisoned").clone();
        let (mut ctx, offset) = match template {
            Some(t) => t,
            // No request seen yet (state restored at startup).
            None => (self.background_template(region)?, chrono::Duration::zero()),
        };
        if ctx.endpoint.is_none() {
            ctx.endpoint = self.background_endpoint();
        }
        ctx.request_id = uuid::Uuid::new_v4().to_string();
        ctx.region = region.to_string();
        ctx.received_at = chrono::Utc::now() + offset;
        ctx.caller = mws_core::Caller { account_id: account.to_string(), ..mws_core::Caller::anonymous() };
        ctx.source_ip = None;
        Some(ctx)
    }

    /// The function's execution role as a caller, with `ctx`'s other facts.
    pub(crate) fn role_context(
        &self,
        ctx: &RequestContext,
        function_arn: &str,
    ) -> Result<RequestContext, ServiceError> {
        let f = names::parse_function(ctx, function_arn, None)?;
        let role = {
            let st = self.read();
            let func = Self::function(&st, &f)?;
            func.version_for(f.qualifier.as_deref()).and_then(|v| v.config.role.clone())
        };
        let (Some(sts), Some(role)) = (&self.inner.sts, role) else {
            return Err(errors::invalid_parameter_value("The function has no execution role."));
        };
        let cannot_assume =
            || errors::invalid_parameter_value("The role defined for the function cannot be assumed by Lambda.");
        let creds = sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: &role,
                service_principal: "lambda.amazonaws.com",
                session_name: &f.name,
                duration_seconds: 3_600,
                source_account: Some(&f.account),
                source_arn: Some(&f.arn()),
                now: ctx.received_at,
            })
            .map_err(|_| cannot_assume())?;
        let resolved = sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .ok()
            .flatten()
            .ok_or_else(cannot_assume)?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    /// The checks `CreateEventSourceMapping` and
    /// `UpdateEventSourceMapping` make for an SQS source.
    pub(crate) fn check_queue_source(
        &self,
        ctx: &RequestContext,
        queue_arn: &str,
        function_arn: &str,
        batch_size: i32,
        window: i32,
    ) -> Result<(), ServiceError> {
        let Some(source) = self.inner.queues.get() else { return Ok(()) };
        if batch_size > 10 && window < 1 {
            return Err(errors::invalid_parameter_value(
                "Maximum batch window in seconds must be greater than 0 if maximum batch size is greater than 10",
            ));
        }
        let role_ctx = self.role_context(ctx, function_arn)?;
        for action in ["ReceiveMessage", "DeleteMessage", "GetQueueAttributes"] {
            source.authorize(&role_ctx, queue_arn, &format!("sqs:{action}")).map_err(|e| {
                if e.code.contains("NonExistentQueue") || e.code == "QueueDoesNotExist" {
                    missing_queue()
                } else {
                    errors::invalid_parameter_value(format!(
                        "The provided execution role does not have permissions to call {action} on SQS"
                    ))
                }
            })?;
        }
        let facts = source.facts(&role_ctx, queue_arn).map_err(|_| missing_queue())?;
        if facts.fifo && batch_size > 10 {
            return Err(errors::invalid_parameter_value("Batch size must be between 1 and 10 for FIFO queues."));
        }
        let timeout = {
            let f = names::parse_function(ctx, function_arn, None)?;
            let st = self.read();
            let func = Self::function(&st, &f)?;
            func.version_for(f.qualifier.as_deref())
                .and_then(|v| v.config.timeout)
                .unwrap_or(crate::functions::DEFAULT_TIMEOUT)
        };
        if facts.visibility_timeout < i64::from(timeout) {
            return Err(errors::invalid_parameter_value(format!(
                "Queue visibility timeout: {} seconds is less than Function timeout: {timeout} seconds",
                facts.visibility_timeout
            )));
        }
        Ok(())
    }

    /// Receive one batch for a mapping, invoke the function with it, and
    /// delete what it processed.
    async fn poll_once(
        &self,
        config: &types::EventSourceMappingConfiguration,
        account: &str,
        region: &str,
    ) -> Result<Polled, ServiceError> {
        let (Some(source), Some(queue_arn), Some(function_arn)) =
            (self.inner.queues.get().cloned(), config.event_source_arn.as_deref(), config.function_arn.as_deref())
        else {
            return Ok(Polled::Empty);
        };
        let Some(ctx) = self.poller_context(account, region) else { return Ok(Polled::Empty) };
        let role_ctx = self.role_context(&ctx, function_arn)?;
        let batch_size = config.batch_size.unwrap_or(10).max(1) as usize;
        let window = Duration::from_secs(config.maximum_batching_window_in_seconds.unwrap_or(0).max(0) as u64);
        let started = std::time::Instant::now();
        let mut batch: Vec<QueueMessage> = Vec::new();
        loop {
            let want = (batch_size - batch.len()).min(10) as i32;
            let got = source.receive(&role_ctx, queue_arn, want).await?;
            let empty = got.is_empty();
            batch.extend(got);
            if batch.len() >= batch_size || (empty && started.elapsed() >= window) {
                break;
            }
            if empty {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
        if batch.is_empty() {
            return Ok(Polled::Empty);
        }
        let polled = if batch.len() >= batch_size { Polled::Full } else { Polled::Partial };

        // Records no filter matches are dropped: deleted without invoking.
        let filters = compile_filters(config.filter_criteria.as_ref()).unwrap_or_default();
        let (batch, dropped): (Vec<QueueMessage>, Vec<QueueMessage>) =
            batch.into_iter().partition(|m| passes(&filters, &record(m, queue_arn, region)));
        if !dropped.is_empty() {
            let handles: Vec<String> = dropped.iter().map(|m| m.receipt_handle.clone()).collect();
            source.delete(&role_ctx, queue_arn, &handles)?;
        }
        if batch.is_empty() {
            return Ok(polled);
        }
        let records: Vec<Value> = batch.iter().map(|m| record(m, queue_arn, region)).collect();
        let payload = serde_json::to_vec(&json!({ "Records": records })).expect("records serialize");
        let f = names::parse_function(&ctx, function_arn, None)?;
        // The messages' X-Ray headers say how deep in a chain of requests
        // the batch is; a batch that would continue a recursive loop is not
        // delivered, and comes back (to the queue's dead-letter queue, in
        // time) like a failed one.
        let hash = crate::recursion::function_hash(&f.arn());
        let deepest = batch
            .iter()
            .filter_map(|m| m.attributes.get("AWSTraceHeader"))
            .max_by_key(|h| crate::recursion::count(Some(h), &hash));
        let Some(trace) = self.recursion_check(&ctx, &f, deepest.map(String::as_str)) else {
            return Ok(polled);
        };
        let ran = mws_core::trace_header::scope(Some(trace), self.run(&ctx, &f, payload, None)).await?;
        if ran.outcome.function_error.is_some() {
            // The batch comes back when its visibility timeout ends.
            return Ok(polled);
        }
        let reports = config.function_response_types.iter().flatten().any(|t| t == "ReportBatchItemFailures");
        let keep: Option<HashSet<String>> = if reports { failed_items(&ran.outcome.payload, &batch) } else { None };
        let done: Vec<String> = match keep {
            Some(failed) => {
                batch.iter().filter(|m| !failed.contains(&m.message_id)).map(|m| m.receipt_handle.clone()).collect()
            }
            None if reports && reported_unusable(&ran.outcome.payload) => Vec::new(),
            None => batch.iter().map(|m| m.receipt_handle.clone()).collect(),
        };
        if !done.is_empty() {
            source.delete(&role_ctx, queue_arn, &done)?;
        }
        Ok(polled)
    }
}

/// What one batch of a queue mapping found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Polled {
    /// Nothing to receive.
    Empty,
    /// Less than a whole batch.
    Partial,
    /// A whole batch: the queue has a backlog.
    Full,
}

/// The ids a function reported in `batchItemFailures`, or `None` when it
/// reported none (or an empty list): the whole batch succeeded.
fn failed_items(payload: &[u8], batch: &[QueueMessage]) -> Option<HashSet<String>> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let items = v.get("batchItemFailures")?.as_array()?;
    if items.is_empty() {
        return None;
    }
    let ids: HashSet<String> =
        items.iter().filter_map(|i| i.get("itemIdentifier").and_then(Value::as_str).map(str::to_string)).collect();
    // An item without an identifier, or naming no message of the batch,
    // fails the whole batch, as AWS does.
    if ids.len() != items.len() || ids.iter().any(|id| batch.iter().all(|m| &m.message_id != id)) {
        return Some(batch.iter().map(|m| m.message_id.clone()).collect());
    }
    Some(ids)
}

/// Whether a `ReportBatchItemFailures` response was malformed enough to
/// fail the batch: `batchItemFailures` present but not a list.
fn reported_unusable(payload: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<Value>(payload) else { return false };
    v.get("batchItemFailures").is_some_and(|f| !f.is_array() && !f.is_null())
}

/// The patterns of a mapping's `FilterCriteria`, checked the way
/// `CreateEventSourceMapping` checks them.
pub(crate) fn compile_filters(
    criteria: Option<&types::FilterCriteria>,
) -> Result<Vec<mws_event_pattern::Pattern>, ServiceError> {
    criteria
        .and_then(|c| c.filters.as_ref())
        .into_iter()
        .flatten()
        .map(|f| {
            let source = f.pattern.as_deref().unwrap_or_default();
            mws_event_pattern::Pattern::parse(source)
                .map_err(|_| errors::invalid_parameter_value("Invalid filter pattern definition."))
        })
        .collect()
}

/// Whether a record passes a mapping's filters: any one must match. A body
/// that is JSON is filtered as JSON; any other body only as a string.
fn passes(filters: &[mws_event_pattern::Pattern], record: &Value) -> bool {
    if filters.is_empty() {
        return true;
    }
    let mut view = record.clone();
    if let Some(body) = view.get("body").and_then(Value::as_str) {
        if let Ok(parsed @ Value::Object(_)) = serde_json::from_str::<Value>(body) {
            view["body"] = parsed;
        }
    }
    filters.iter().any(|f| f.matches(&view))
}

fn missing_queue() -> ServiceError {
    errors::invalid_parameter_value(
        "Error occurred while ReceiveMessage. SQS Error Code: AWS.SimpleQueueService.NonExistentQueue. SQS Error Message: The specified queue does not exist or you do not have access to it.",
    )
}

/// An SQS record as Lambda delivers it.
fn record(m: &QueueMessage, queue_arn: &str, region: &str) -> Value {
    let attributes: Map<String, Value> =
        m.attributes.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    let message_attributes: Map<String, Value> = m
        .message_attributes
        .iter()
        .map(|(k, a)| {
            let mut v = Map::new();
            if let Some(s) = &a.string_value {
                v.insert("stringValue".into(), Value::String(s.clone()));
            }
            if let Some(b) = &a.binary_value {
                v.insert("binaryValue".into(), Value::String(base64::engine::general_purpose::STANDARD.encode(b)));
            }
            v.insert("stringListValues".into(), json!([]));
            v.insert("binaryListValues".into(), json!([]));
            v.insert("dataType".into(), Value::String(a.data_type.clone()));
            (k.clone(), Value::Object(v))
        })
        .collect();
    let mut r = Map::new();
    r.insert("messageId".into(), Value::String(m.message_id.clone()));
    r.insert("receiptHandle".into(), Value::String(m.receipt_handle.clone()));
    r.insert("body".into(), Value::String(m.body.clone()));
    r.insert("attributes".into(), Value::Object(attributes));
    r.insert("messageAttributes".into(), Value::Object(message_attributes));
    if let Some(md5) = &m.md5_of_message_attributes {
        r.insert("md5OfMessageAttributes".into(), Value::String(md5.clone()));
    }
    r.insert("md5OfBody".into(), Value::String(m.md5_of_body.clone()));
    r.insert("eventSource".into(), Value::String("aws:sqs".into()));
    r.insert("eventSourceARN".into(), Value::String(queue_arn.to_string()));
    r.insert("awsRegion".into(), Value::String(region.to_string()));
    Value::Object(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str) -> QueueMessage {
        QueueMessage { message_id: id.into(), receipt_handle: format!("h-{id}"), ..Default::default() }
    }

    #[test]
    fn batch_item_failures() {
        let batch = [msg("a"), msg("b")];
        assert_eq!(failed_items(br#"{"batchItemFailures":[]}"#, &batch), None);
        assert_eq!(failed_items(b"null", &batch), None);
        let one = failed_items(br#"{"batchItemFailures":[{"itemIdentifier":"b"}]}"#, &batch).unwrap();
        assert_eq!(one, HashSet::from(["b".to_string()]));
        let all = failed_items(br#"{"batchItemFailures":[{"itemIdentifier":"zzz"}]}"#, &batch).unwrap();
        assert_eq!(all.len(), 2);
        assert!(reported_unusable(br#"{"batchItemFailures":"x"}"#));
    }

    #[test]
    fn filters_match_json_and_plain_bodies() {
        let criteria = types::FilterCriteria {
            filters: Some(vec![
                types::Filter { pattern: Some(r#"{"body":{"kind":["order"]}}"#.into()) },
                types::Filter { pattern: Some(r#"{"body":[{"prefix":"urgent"}]}"#.into()) },
            ]),
        };
        let filters = compile_filters(Some(&criteria)).unwrap();
        let with = |body: &str| {
            let mut m = msg("a");
            m.body = body.into();
            record(&m, "arn:aws:sqs:us-east-1:123456789012:q", "us-east-1")
        };
        assert!(passes(&filters, &with(r#"{"kind":"order","n":1}"#)));
        assert!(!passes(&filters, &with(r#"{"kind":"refund"}"#)));
        assert!(passes(&filters, &with("urgent: call back")));
        assert!(!passes(&filters, &with("later")));
        assert!(passes(&[], &with("anything")));
        let bad = types::FilterCriteria { filters: Some(vec![types::Filter { pattern: Some("{".into()) }]) };
        assert_eq!(compile_filters(Some(&bad)).unwrap_err().message, "Invalid filter pattern definition.");
    }

    #[test]
    fn records_look_like_lambdas() {
        let mut m = msg("a");
        m.body = "hi".into();
        m.attributes.insert("ApproximateReceiveCount".into(), "1".into());
        m.message_attributes.insert(
            "k".into(),
            QueueMessageAttribute { data_type: "String".into(), string_value: Some("v".into()), binary_value: None },
        );
        let r = record(&m, "arn:aws:sqs:us-east-1:123456789012:q", "us-east-1");
        assert_eq!(r["eventSource"], "aws:sqs");
        assert_eq!(r["attributes"]["ApproximateReceiveCount"], "1");
        assert_eq!(r["messageAttributes"]["k"]["stringValue"], "v");
        assert_eq!(r["messageAttributes"]["k"]["stringListValues"], json!([]));
    }
}
