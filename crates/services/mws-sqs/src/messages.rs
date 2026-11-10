//! Sending, receiving, deleting and hiding messages.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use mws_core::{RequestContext, ServiceError};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::generated::{errors, types};
use crate::md5::{md5_of_attributes, md5_of_body};
use crate::names::{
    arn_for_url, authorize_queue, check_batch, invalid_parameter, invalid_parameter_value, missing_parameter, now_ms,
    parse_receipt_handle, wire_code,
};
use crate::state::{attributes_size, Attr, Dedup, Message, Queue, ReceiveAttempt, State};
use crate::Sqs;

/// A message about to be sent, from any source.
#[derive(Debug, Clone, Default)]
pub struct Outgoing {
    pub body: String,
    pub attributes: BTreeMap<String, Attr>,
    pub trace_header: Option<String>,
    pub delay: Option<i32>,
    pub group_id: Option<String>,
    pub dedup_id: Option<String>,
}

/// What a send reports back.
#[derive(Debug, Clone, Default)]
pub struct Sent {
    pub message_id: String,
    pub md5_of_body: String,
    pub md5_of_attributes: Option<String>,
    pub md5_of_system_attributes: Option<String>,
    pub sequence_number: Option<String>,
    /// A FIFO duplicate: accepted, not enqueued again.
    pub duplicate: bool,
    /// Body and attribute bytes, for `SentMessageSize`.
    pub size: usize,
}

const ALLOWED_CHARS: &str = "#x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF";

fn allowed_char(c: char) -> bool {
    matches!(c as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn check_chars(s: &str, what: &str) -> Result<(), ServiceError> {
    match s.chars().find(|c| !allowed_char(*c)) {
        Some(c) => Err(errors::invalid_message_contents(format!(
            "Invalid binary character '#x{:X}' was found in the {what}, the set of allowed characters is {ALLOWED_CHARS}",
            c as u32
        ))),
        None => Ok(()),
    }
}

/// Validate user message attributes as SQS does.
pub fn message_attributes(
    given: Option<&BTreeMap<String, types::MessageAttributeValue>>,
) -> Result<BTreeMap<String, Attr>, ServiceError> {
    let Some(given) = given else { return Ok(BTreeMap::new()) };
    if given.len() > 10 {
        return Err(invalid_parameter_value(format!(
            "Number of message attributes [{}] exceeds the allowed maximum [10].",
            given.len()
        )));
    }
    let mut out = BTreeMap::new();
    for (name, v) in given {
        let lower = name.to_ascii_lowercase();
        let valid_name = !name.is_empty()
            && name.len() <= 256
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            && !name.starts_with('.')
            && !name.ends_with('.')
            && !name.contains("..")
            && !lower.starts_with("aws.")
            && !lower.starts_with("amazon.");
        if !valid_name {
            return Err(invalid_parameter_value(format!(
                "Message (user) attribute name '{name}' is invalid. The attribute name can contain only the following characters: A-Z, a-z, 0-9, underscore (_), hyphen (-), and period (.). The name must not start or end with a period, and it must not have successive periods. The name must not start with AWS. or Amazon."
            )));
        }
        let base = v.data_type.split('.').next().unwrap_or_default();
        if !matches!(base, "String" | "Number" | "Binary") || v.data_type.len() > 256 {
            return Err(invalid_parameter_value(format!(
                "The type of message (user) attribute '{name}' is invalid. You must use only the following supported type prefixes: Binary, Number, String."
            )));
        }
        if v.string_list_values.is_some() || v.binary_list_values.is_some() {
            return Err(invalid_parameter_value(format!(
                "Message (user) attribute '{name}' uses list values, which are not supported."
            )));
        }
        let empty = || {
            invalid_parameter_value(format!(
                "Message (user) attribute '{name}' must contain a non-empty value of type '{base}'."
            ))
        };
        match base {
            "Binary" => {
                if v.binary_value.as_ref().is_none_or(Vec::is_empty) || v.string_value.is_some() {
                    return Err(empty());
                }
            }
            _ => {
                let s = v.string_value.as_deref().filter(|s| !s.is_empty()).ok_or_else(empty)?;
                if v.binary_value.is_some() {
                    return Err(empty());
                }
                check_chars(s, &format!("message (user) attribute '{name}'"))?;
                if base == "Number" && !valid_number(s) {
                    return Err(invalid_parameter_value(format!(
                        "Can't cast the value of message (user) attribute '{name}' to a number."
                    )));
                }
            }
        }
        out.insert(name.clone(), Attr::from(v));
    }
    Ok(out)
}

/// SQS numbers: up to 38 significant digits, exponent within ±128.
fn valid_number(s: &str) -> bool {
    s.trim().parse::<f64>().is_ok_and(f64::is_finite)
}

/// The `AWSTraceHeader` system attribute, the only one senders may set.
pub fn system_attributes(
    given: Option<&BTreeMap<String, types::MessageSystemAttributeValue>>,
) -> Result<Option<String>, ServiceError> {
    let Some(given) = given else { return Ok(None) };
    let mut trace = None;
    for (name, v) in given {
        if name != "AWSTraceHeader" {
            return Err(invalid_parameter_value(format!("Message system attribute name '{name}' is invalid.")));
        }
        let value = v.string_value.as_deref().filter(|s| !s.is_empty());
        if v.data_type != "String" || value.is_none() {
            return Err(invalid_parameter_value(
                "Message system attribute 'AWSTraceHeader' must contain a non-empty value of type 'String'.",
            ));
        }
        trace = value.map(str::to_string);
    }
    Ok(trace)
}

fn trace_map(trace: &Option<String>) -> BTreeMap<String, Attr> {
    trace
        .iter()
        .map(|t| {
            (
                "AWSTraceHeader".to_string(),
                Attr { data_type: "String".into(), string_value: Some(t.clone()), binary_value: None },
            )
        })
        .collect()
}

fn fifo_id(name: &str, v: &str) -> Result<(), ServiceError> {
    let ok =
        !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b.is_ascii_punctuation());
    if ok {
        Ok(())
    } else {
        Err(invalid_parameter(
            name,
            v,
            &format!("{name} can only include alphanumeric and punctuation characters. 1 to 128 in length."),
        ))
    }
}

/// Checks that depend on the queue.
pub fn check_outgoing(q: &Queue, o: &Outgoing) -> Result<(), ServiceError> {
    if o.body.is_empty() {
        return Err(missing_parameter("MessageBody"));
    }
    check_chars(&o.body, "message body")?;
    let max = q.int_attr("MaximumMessageSize") as usize;
    if o.body.len() + attributes_size(&o.attributes) > max {
        return Err(invalid_parameter_value(format!(
            "One or more parameters are invalid. Reason: Message must be shorter than {max} bytes."
        )));
    }
    if let Some(d) = o.delay {
        if q.fifo {
            return Err(invalid_parameter(
                "DelaySeconds",
                d,
                "The request include parameter that is not valid for this queue type.",
            ));
        }
        if !(0..=900).contains(&d) {
            return Err(invalid_parameter("DelaySeconds", d, "DelaySeconds must be >= 0 and <= 900."));
        }
    }
    if let Some(g) = &o.group_id {
        fifo_id("MessageGroupId", g)?;
    }
    if q.fifo {
        if o.group_id.is_none() {
            return Err(missing_parameter("MessageGroupId"));
        }
        match &o.dedup_id {
            Some(d) => fifo_id("MessageDeduplicationId", d)?,
            None if q.bool_attr("ContentBasedDeduplication") => {}
            None => {
                return Err(invalid_parameter_value(
                    "The queue should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                ))
            }
        }
    } else if let Some(d) = &o.dedup_id {
        return Err(invalid_parameter(
            "MessageDeduplicationId",
            d,
            "The request includes a parameter that is not valid for this queue type.",
        ));
    }
    Ok(())
}

/// Put a checked message on the queue (or, for a FIFO duplicate, report
/// the original).
pub fn enqueue(q: &mut Queue, o: Outgoing, sender_id: &str, now: i64, data_key: Option<String>) -> Sent {
    let md5_of_body = md5_of_body(&o.body);
    let md5_of_system_attributes = md5_of_attributes(&trace_map(&o.trace_header));
    let md5_of_attributes = md5_of_attributes(&o.attributes);
    let size = o.body.len() + attributes_size(&o.attributes);
    q.expire(now);
    let mut dedup_key = None;
    if q.fifo {
        let dedup = o.dedup_id.clone().unwrap_or_else(|| hex::encode(Sha256::digest(o.body.as_bytes())));
        let key = if q.attr("DeduplicationScope") == Some("messageGroup") {
            format!("{}\n{dedup}", o.group_id.as_deref().unwrap_or_default())
        } else {
            dedup.clone()
        };
        if let Some(d) = q.dedup.get(&key) {
            return Sent {
                message_id: d.message_id.clone(),
                md5_of_body,
                md5_of_attributes,
                md5_of_system_attributes,
                sequence_number: Some(d.sequence_number.clone()),
                duplicate: true,
                size,
            };
        }
        dedup_key = Some((key, dedup));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let sequence_number = q.fifo.then(|| {
        q.next_sequence += 1;
        (18_000_000_000_000_000_000u128 + q.next_sequence as u128).to_string()
    });
    let delay = o.delay.map(i64::from).unwrap_or_else(|| q.int_attr("DelaySeconds"));
    let deduplication_id = dedup_key.as_ref().map(|(_, d)| d.clone());
    if let (Some((key, _)), Some(seq)) = (dedup_key, &sequence_number) {
        q.dedup.insert(key, Dedup { message_id: id.clone(), sequence_number: seq.clone(), at: now });
    }
    q.messages.push(Message {
        id: id.clone(),
        body: o.body,
        attributes: o.attributes,
        trace_header: o.trace_header,
        md5_of_body: md5_of_body.clone(),
        md5_of_system_attributes: md5_of_system_attributes.clone(),
        sender_id: sender_id.to_string(),
        sent_at: now,
        visible_at: now + delay * 1000,
        group_id: o.group_id,
        deduplication_id,
        sequence_number: sequence_number.clone(),
        kms_data_key: data_key,
        ..Message::default()
    });
    Sent {
        message_id: id,
        md5_of_body,
        md5_of_attributes,
        md5_of_system_attributes,
        sequence_number,
        duplicate: false,
        size,
    }
}

/// A KMS error as SQS reports it.
pub fn kms_error(e: ServiceError) -> ServiceError {
    let message = e.message.clone();
    match e.code.as_ref() {
        "NotFoundException" | "InvalidArnException" => errors::kms_not_found(message),
        "DisabledException" => errors::kms_disabled(message),
        "KMSInvalidStateException" => errors::kms_invalid_state(message),
        "InvalidKeyUsageException" => errors::kms_invalid_key_usage(message),
        "AccessDeniedException" | "AccessDenied" => errors::kms_access_denied(message),
        "ThrottlingException" => errors::kms_throttled(message),
        _ => e,
    }
}

pub fn kms_context(arn: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("aws:sqs:arn".to_string(), arn.to_string())])
}

impl Sqs {
    /// The SSE-KMS data key to encrypt a new message under, generated for
    /// the caller (and reused for `KmsDataKeyReusePeriodSeconds`).
    fn data_key_for_send(&self, ctx: &RequestContext, q: &mut Queue, now: i64) -> Result<Option<String>, ServiceError> {
        let (Some(kms), Some(key)) = (&self.kms, q.attr("KmsMasterKeyId").map(str::to_string)) else {
            return Ok(None);
        };
        let reuse = q.int_attr("KmsDataKeyReusePeriodSeconds").max(60) * 1000;
        if let Some(k) = q.data_keys.get(&ctx.caller.arn).filter(|k| k.generated_at + reuse > now) {
            return Ok(Some(k.ciphertext.clone()));
        }
        let key = if key == "alias/aws/sqs" || key.ends_with(":alias/aws/sqs") {
            kms.aws_managed_key(ctx, "sqs")
        } else {
            key
        };
        let dk = kms.generate_data_key_via(ctx, "sqs", &key, &kms_context(&q.arn), 32).map_err(kms_error)?;
        use base64::Engine;
        let ciphertext = crate::names::b64().encode(&dk.ciphertext);
        q.data_keys.insert(
            ctx.caller.arn.clone(),
            crate::state::DataKey { key_arn: dk.key_arn, ciphertext: ciphertext.clone(), generated_at: now },
        );
        Ok(Some(ciphertext))
    }

    /// Receivers of SSE-KMS messages need `kms:Decrypt` on their data keys.
    fn decrypt_data_keys<'a>(
        &self,
        ctx: &RequestContext,
        arn: &str,
        keys: impl Iterator<Item = &'a String>,
    ) -> Result<(), ServiceError> {
        let Some(kms) = &self.kms else { return Ok(()) };
        use base64::Engine;
        let distinct: BTreeSet<&String> = keys.collect();
        for k in distinct {
            let blob = crate::names::b64().decode(k).map_err(|_| errors::kms_invalid_state("Corrupt data key"))?;
            kms.decrypt_via(ctx, "sqs", &blob, &kms_context(arn)).map_err(kms_error)?;
        }
        Ok(())
    }

    pub fn send_message(
        &self,
        ctx: &RequestContext,
        input: types::SendMessageRequest,
    ) -> Result<types::SendMessageResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let out = Outgoing {
            attributes: message_attributes(input.message_attributes.as_ref())?,
            // SQS keeps the request's X-Ray header (which SDKs in Lambda
            // functions send) as `AWSTraceHeader` unless one is given.
            trace_header: system_attributes(input.message_system_attributes.as_ref())?
                .or_else(mws_core::trace_header::current),
            body: input.message_body,
            delay: input.delay_seconds,
            group_id: input.message_group_id,
            dedup_id: input.message_deduplication_id,
        };
        let now = now_ms(ctx);
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:SendMessage", q)?;
        check_outgoing(q, &out)?;
        let data_key = self.data_key_for_send(ctx, q, now)?;
        let sent = enqueue(q, out, &ctx.caller.user_id, now, data_key);
        self.meter.count(&arn, now, |c| crate::metrics::count_send(c, sent.size, sent.duplicate));
        drop(st);
        self.arrivals.notify_waiters();
        Ok(types::SendMessageResult {
            md5_of_message_body: Some(sent.md5_of_body),
            md5_of_message_attributes: sent.md5_of_attributes,
            md5_of_message_system_attributes: sent.md5_of_system_attributes,
            message_id: Some(sent.message_id),
            sequence_number: sent.sequence_number,
        })
    }

    pub fn send_message_batch(
        &self,
        ctx: &RequestContext,
        input: types::SendMessageBatchRequest,
    ) -> Result<types::SendMessageBatchResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        check_batch("SendMessageBatchRequestEntry", input.entries.iter().map(|e| e.id.as_str()))?;
        let total: usize = input
            .entries
            .iter()
            .map(|e| {
                e.message_body.len()
                    + e.message_attributes
                        .as_ref()
                        .map(|a| attributes_size(&a.iter().map(|(k, v)| (k.clone(), Attr::from(v))).collect()))
                        .unwrap_or(0)
            })
            .sum();
        if total > 1_048_576 {
            return Err(errors::batch_request_too_long(format!(
                "Batch requests cannot be longer than 1048576 bytes. You have sent {total} bytes."
            )));
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:SendMessage", q)?;
        let data_key = self.data_key_for_send(ctx, q, now)?;
        let mut result = types::SendMessageBatchResult::default();
        for e in input.entries {
            let id = e.id.clone();
            let out = (|| {
                let out = Outgoing {
                    attributes: message_attributes(e.message_attributes.as_ref())?,
                    trace_header: system_attributes(e.message_system_attributes.as_ref())?
                        .or_else(mws_core::trace_header::current),
                    body: e.message_body,
                    delay: e.delay_seconds,
                    group_id: e.message_group_id,
                    dedup_id: e.message_deduplication_id,
                };
                check_outgoing(q, &out)?;
                Ok::<_, ServiceError>(out)
            })();
            match out {
                Ok(out) => {
                    let sent = enqueue(q, out, &ctx.caller.user_id, now, data_key.clone());
                    self.meter.count(&arn, now, |c| crate::metrics::count_send(c, sent.size, sent.duplicate));
                    result.successful.push(types::SendMessageBatchResultEntry {
                        id,
                        message_id: sent.message_id,
                        md5_of_message_body: sent.md5_of_body,
                        md5_of_message_attributes: sent.md5_of_attributes,
                        md5_of_message_system_attributes: sent.md5_of_system_attributes,
                        sequence_number: sent.sequence_number,
                    });
                }
                Err(err) => result.failed.push(failure(id, &err)),
            }
        }
        drop(st);
        self.arrivals.notify_waiters();
        Ok(result)
    }

    pub async fn receive_message(
        &self,
        ctx: &RequestContext,
        input: types::ReceiveMessageRequest,
    ) -> Result<types::ReceiveMessageResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        if let Some(n) = input.max_number_of_messages {
            if !(1..=10).contains(&n) {
                return Err(invalid_parameter("MaxNumberOfMessages", n, "Must be between 1 and 10, if provided."));
            }
        }
        if let Some(v) = input.visibility_timeout {
            if !(0..=43_200).contains(&v) {
                return Err(invalid_parameter("VisibilityTimeout", v, "Must be between 0 and 43200, if provided."));
            }
        }
        if let Some(w) = input.wait_time_seconds {
            if !(0..=20).contains(&w) {
                return Err(invalid_parameter("WaitTimeSeconds", w, "Must be >= 0 and <= 20, if provided."));
            }
        }
        let wait = {
            let st = self.lock();
            let q = st.queue(&arn)?;
            authorize_queue(ctx, "sqs:ReceiveMessage", q)?;
            input.wait_time_seconds.map(i64::from).unwrap_or_else(|| q.int_attr("ReceiveMessageWaitTimeSeconds"))
        };
        let start = Instant::now();
        let deadline = start + Duration::from_secs(wait.max(0) as u64);
        loop {
            let notified = self.arrivals.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let now = now_ms(ctx) + start.elapsed().as_millis() as i64;
            let messages = self.try_receive(ctx, &arn, &input, now, wait <= 0)?;
            let left = deadline.saturating_duration_since(Instant::now());
            if !messages.is_empty() || left.is_zero() {
                self.meter.count(&arn, now, |c| match messages.len() {
                    0 => c.empty_receives += 1,
                    n => c.received += n as u64,
                });
                return Ok(types::ReceiveMessageResult { messages: (!messages.is_empty()).then_some(messages) });
            }
            // Delays and visibility timeouts end without a wake-up.
            let _ = tokio::time::timeout(left.min(Duration::from_millis(200)), notified).await;
        }
    }

    fn try_receive(
        &self,
        ctx: &RequestContext,
        arn: &str,
        input: &types::ReceiveMessageRequest,
        now: i64,
        short_poll: bool,
    ) -> Result<Vec<types::Message>, ServiceError> {
        let mut st = self.lock();
        self.progress(&mut st, now);
        redrive_exhausted(&mut st, arn, now)?;
        let q = st.queue_mut(arn)?;
        q.expire(now);
        let max = input.max_number_of_messages.unwrap_or(1) as usize;
        let visibility = input.visibility_timeout.map(i64::from).unwrap_or_else(|| q.int_attr("VisibilityTimeout"));
        let mut sys_names: Vec<String> = input.attribute_names.clone().unwrap_or_default();
        sys_names.extend(input.message_system_attribute_names.clone().unwrap_or_default());
        let attr_names = input.message_attribute_names.clone().unwrap_or_default();

        // A FIFO retry with the same attempt id gets the same messages.
        let attempt = input.receive_request_attempt_id.as_ref().filter(|_| q.fifo);
        if let Some(a) = attempt.and_then(|a| q.receive_attempts.get(a)) {
            let same: Vec<types::Message> = a
                .message_ids
                .iter()
                .zip(&a.handles)
                .filter_map(|(id, h)| {
                    q.messages
                        .iter()
                        .find(|m| &m.id == id && m.receipt_handle.as_deref() == Some(h.as_str()) && m.in_flight(now))
                        .map(|m| render(q, m, h, &sys_names, &attr_names))
                })
                .collect();
            if same.len() == a.message_ids.len() && !same.is_empty() {
                return Ok(same);
            }
        }

        let picked = select(q, now, max, short_poll);
        if picked.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<String> = picked.iter().filter_map(|&i| q.messages[i].kms_data_key.clone()).collect();
        if !keys.is_empty() {
            self.decrypt_data_keys(ctx, arn, keys.iter())?;
        }
        let mut out = Vec::new();
        let mut record = ReceiveAttempt { at: now, ..Default::default() };
        for i in picked {
            let handle = crate::names::new_receipt_handle(arn, &q.messages[i].id);
            let m = &mut q.messages[i];
            m.receive_count += 1;
            m.first_receive_at.get_or_insert(now);
            m.visible_at = now + visibility * 1000;
            m.receipt_handle = Some(handle.clone());
            record.message_ids.push(m.id.clone());
            record.handles.push(handle.clone());
            out.push(render(q, &q.messages[i], &handle, &sys_names, &attr_names));
        }
        if let Some(a) = attempt {
            q.receive_attempts.insert(a.clone(), record);
        }
        Ok(out)
    }

    pub fn delete_message(&self, ctx: &RequestContext, input: types::DeleteMessageRequest) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:DeleteMessage", q)?;
        let now = now_ms(ctx);
        delete_one(q, &arn, &input.receipt_handle, now, false)?;
        self.meter.count(&arn, now, |c| c.deleted += 1);
        Ok(())
    }

    pub fn delete_message_batch(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMessageBatchRequest,
    ) -> Result<types::DeleteMessageBatchResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        check_batch("DeleteMessageBatchRequestEntry", input.entries.iter().map(|e| e.id.as_str()))?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:DeleteMessage", q)?;
        let mut result = types::DeleteMessageBatchResult::default();
        for e in input.entries {
            match delete_one(q, &arn, &e.receipt_handle, now, true) {
                Ok(()) => {
                    self.meter.count(&arn, now, |c| c.deleted += 1);
                    result.successful.push(types::DeleteMessageBatchResultEntry { id: e.id })
                }
                Err(err) => result.failed.push(failure(e.id, &err)),
            }
        }
        Ok(result)
    }

    pub fn change_message_visibility(
        &self,
        ctx: &RequestContext,
        input: types::ChangeMessageVisibilityRequest,
    ) -> Result<(), ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:ChangeMessageVisibility", q)?;
        change_one(q, &arn, &input.receipt_handle, input.visibility_timeout, now_ms(ctx), false)?;
        drop(st);
        self.arrivals.notify_waiters();
        Ok(())
    }

    pub fn change_message_visibility_batch(
        &self,
        ctx: &RequestContext,
        input: types::ChangeMessageVisibilityBatchRequest,
    ) -> Result<types::ChangeMessageVisibilityBatchResult, ServiceError> {
        let arn = arn_for_url(ctx, &input.queue_url)?;
        check_batch("ChangeMessageVisibilityBatchRequestEntry", input.entries.iter().map(|e| e.id.as_str()))?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let q = st.queue_mut(&arn)?;
        authorize_queue(ctx, "sqs:ChangeMessageVisibility", q)?;
        let mut result = types::ChangeMessageVisibilityBatchResult::default();
        for e in input.entries {
            let timeout = e.visibility_timeout.unwrap_or(0);
            match change_one(q, &arn, &e.receipt_handle, timeout, now, true) {
                Ok(()) => result.successful.push(types::ChangeMessageVisibilityBatchResultEntry { id: e.id }),
                Err(err) => result.failed.push(failure(e.id, &err)),
            }
        }
        drop(st);
        self.arrivals.notify_waiters();
        Ok(result)
    }
}

fn failure(id: String, e: &ServiceError) -> types::BatchResultErrorEntry {
    types::BatchResultErrorEntry {
        id,
        sender_fault: e.fault == mws_core::ErrorFault::Client,
        code: wire_code(e),
        message: Some(e.message.clone()),
    }
}

/// A receipt handle SQS no longer accepts. Single calls answer
/// `InvalidParameterValue`; batch entries carry `ReceiptHandleIsInvalid`
/// with the bare reason.
fn handle_rejected(handle: &str, reason: &str, batch: bool) -> ServiceError {
    if batch {
        errors::receipt_handle_is_invalid(reason.to_string())
    } else {
        invalid_parameter("ReceiptHandle", handle, reason)
    }
}

/// The handle must name a message of this queue.
fn handle_message_id(arn: &str, handle: &str) -> Result<String, ServiceError> {
    let (handle_arn, id) = parse_receipt_handle(handle)?;
    if handle_arn != arn {
        return Err(errors::receipt_handle_is_invalid(format!(
            "The receipt handle \"{handle}\" is not valid for this queue."
        )));
    }
    Ok(id)
}

const EXPIRED: &str = "The receipt handle has expired.";

fn delete_one(q: &mut Queue, arn: &str, handle: &str, now: i64, batch: bool) -> Result<(), ServiceError> {
    let id = handle_message_id(arn, handle)?;
    let Some(pos) = q.messages.iter().position(|m| m.id == id) else { return Ok(()) };
    let m = &q.messages[pos];
    let current = m.receipt_handle.as_deref() == Some(handle);
    // FIFO handles stop working when the visibility timeout ends; standard
    // queues accept an old handle but only the latest one deletes.
    if q.fifo && (!current || !m.in_flight(now)) {
        return Err(handle_rejected(handle, EXPIRED, batch));
    }
    if current {
        q.messages.remove(pos);
    }
    Ok(())
}

fn change_one(q: &mut Queue, arn: &str, handle: &str, timeout: i32, now: i64, batch: bool) -> Result<(), ServiceError> {
    let id = handle_message_id(arn, handle)?;
    if !(0..=43_200).contains(&timeout) {
        return Err(invalid_parameter("VisibilityTimeout", timeout, "Must be between 0 and 43200, if provided."));
    }
    let m = q.messages.iter_mut().find(|m| m.id == id).ok_or_else(|| {
        handle_rejected(handle, "Message does not exist or is not available for visibility timeout change.", batch)
    })?;
    if m.receipt_handle.as_deref() != Some(handle) || !m.in_flight(now) {
        return Err(handle_rejected(handle, EXPIRED, batch));
    }
    let first = m.first_receive_at.unwrap_or(now);
    if now + i64::from(timeout) * 1000 > first + 43_200_000 {
        return Err(invalid_parameter(
            "VisibilityTimeout",
            timeout,
            "Total VisibilityTimeout for the message is beyond the limit [43200 seconds]",
        ));
    }
    m.visible_at = now + i64::from(timeout) * 1000;
    Ok(())
}

/// Move visible messages that were received `maxReceiveCount` times to the
/// dead-letter queue instead of handing them out again.
fn redrive_exhausted(st: &mut State, arn: &str, now: i64) -> Result<(), ServiceError> {
    let q = st.queue_mut(arn)?;
    let Some((dlq, max)) = q.redrive() else { return Ok(()) };
    if !st.queues.contains_key(&dlq) || dlq == arn {
        return Ok(());
    }
    let q = st.queue_mut(arn)?;
    let mut moved = Vec::new();
    let mut i = 0;
    while i < q.messages.len() {
        let m = &q.messages[i];
        if m.visible(now) && m.receive_count >= max {
            moved.push(q.messages.remove(i));
        } else {
            i += 1;
        }
    }
    if moved.is_empty() {
        return Ok(());
    }
    let target = st.queue_mut(&dlq)?;
    for mut m in moved {
        m.receipt_handle = None;
        m.visible_at = now;
        m.dead_letter_source_arn = Some(arn.to_string());
        if target.fifo {
            // Standard queues keep the original enqueue time for retention;
            // FIFO queues restart it in the dead-letter queue.
            m.enqueued_at = Some(now);
            target.next_sequence += 1;
            m.sequence_number = Some((18_000_000_000_000_000_000u128 + target.next_sequence as u128).to_string());
        }
        target.messages.push(m);
    }
    Ok(())
}

/// Indices of up to `max` messages to hand out. FIFO queues keep each
/// message group in order: a group with a message in flight (or not yet
/// visible) yields nothing further.
///
/// Standard queues behave like SQS's distributed store: order is best
/// effort, and a short poll asks only a random subset of the servers, so
/// it can return fewer messages than are visible.
fn select(q: &Queue, now: i64, max: usize, short_poll: bool) -> Vec<usize> {
    if q.fifo {
        return select_fifo(q, now, max);
    }
    let mut rng = rand::thread_rng();
    let visible: Vec<usize> = (0..q.messages.len()).filter(|&i| q.messages[i].visible(now)).collect();
    if visible.is_empty() {
        return visible;
    }
    let mut picked: Vec<usize> = if short_poll {
        let sampled: Vec<usize> = visible.iter().copied().filter(|_| rng.gen_bool(SHORT_POLL_SAMPLE)).collect();
        // A simplification: a short poll with a message visible returns at
        // least one, where SQS can return none.
        if sampled.is_empty() {
            vec![visible[rng.gen_range(0..visible.len())]]
        } else {
            sampled
        }
    } else {
        visible
    };
    // Best-effort order: each message may move a few places.
    let mut keyed: Vec<(f64, usize)> =
        picked.drain(..).enumerate().map(|(n, i)| (n as f64 + rng.gen_range(0.0..REORDER_SPREAD), i)).collect();
    keyed.sort_by(|a, b| a.0.total_cmp(&b.0));
    keyed.into_iter().map(|(_, i)| i).take(max).collect()
}

/// The share of a standard queue's messages one short poll sees.
const SHORT_POLL_SAMPLE: f64 = 0.5;
/// How far (in places) a standard queue's messages may be reordered.
const REORDER_SPREAD: f64 = 2.5;

fn select_fifo(q: &Queue, now: i64, max: usize) -> Vec<usize> {
    let mut blocked: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for (i, m) in q.messages.iter().enumerate() {
        let group = m.group_id.as_deref().unwrap_or_default();
        if !m.visible(now) {
            if q.fifo {
                blocked.insert(group);
            }
            continue;
        }
        if q.fifo && blocked.contains(group) {
            continue;
        }
        out.push(i);
        if out.len() == max {
            break;
        }
    }
    out
}

fn wants(names: &[String], name: &str) -> bool {
    names.iter().any(|n| n == "All" || n == name)
}

fn render(q: &Queue, m: &Message, handle: &str, sys_names: &[String], attr_names: &[String]) -> types::Message {
    let mut attributes = BTreeMap::new();
    let mut put = |name: &str, value: Option<String>| {
        if let Some(v) = value.filter(|_| wants(sys_names, name)) {
            attributes.insert(name.to_string(), v);
        }
    };
    put("SenderId", Some(m.sender_id.clone()));
    put("SentTimestamp", Some(m.sent_at.to_string()));
    put("ApproximateReceiveCount", Some(m.receive_count.to_string()));
    put("ApproximateFirstReceiveTimestamp", m.first_receive_at.map(|t| t.to_string()));
    put("SequenceNumber", m.sequence_number.clone());
    put("MessageDeduplicationId", m.deduplication_id.clone());
    put("MessageGroupId", m.group_id.clone());
    put("AWSTraceHeader", m.trace_header.clone());
    put("DeadLetterQueueSourceArn", m.dead_letter_source_arn.clone());
    let selected: BTreeMap<String, Attr> = m
        .attributes
        .iter()
        .filter(|(name, _)| {
            attr_names.iter().any(|n| {
                n == "All"
                    || n == ".*"
                    || n == *name
                    || n.strip_suffix(".*").is_some_and(|prefix| name.starts_with(&format!("{prefix}.")))
            })
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let _ = q;
    types::Message {
        message_id: Some(m.id.clone()),
        receipt_handle: Some(handle.to_string()),
        md5_of_body: Some(m.md5_of_body.clone()),
        body: Some(m.body.clone()),
        attributes: (!attributes.is_empty()).then_some(attributes),
        md5_of_message_attributes: md5_of_attributes(&selected),
        message_attributes: (!selected.is_empty())
            .then(|| selected.iter().map(|(k, v)| (k.clone(), v.to_wire())).collect()),
    }
}
