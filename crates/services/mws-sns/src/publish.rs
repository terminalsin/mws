//! Publish and PublishBatch: validation, FIFO ordering and deduplication,
//! and handing messages to delivery.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use sha2::Digest;

use crate::generated::types::{self, MessageAttributeValue};
use crate::names::{self, account_of};
use crate::outbox::{PlatformMessage, SmsMessage};
use crate::state::{Dedup, Topic};
use crate::{errors, Sns};

const MAX_MESSAGE: usize = 262_144;

/// A FIFO verdict: `Ok((sequence number, deduplication id))` for a new
/// message, `Err(earlier)` for a duplicate.
type Sequenced = Result<(Option<String>, Option<String>), Dedup>;
const MAX_BATCH: usize = 10;
const DEDUP_WINDOW_MS: i64 = 5 * 60 * 1000;

/// A message on its way out (and, for archiving topics, in the archive).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Outgoing {
    pub message_id: String,
    pub subject: Option<String>,
    /// The `default` message.
    pub message: String,
    /// Per-protocol messages when `MessageStructure` is `json`.
    pub structure: Option<BTreeMap<String, String>>,
    pub attributes: BTreeMap<String, MessageAttributeValue>,
    pub group_id: Option<String>,
    pub dedup_id: Option<String>,
    pub sequence_number: Option<String>,
    pub timestamp: DateTime<Utc>,
    /// Redelivered from the archive by a replay.
    #[serde(default)]
    pub replayed: bool,
}

impl Outgoing {
    /// The message for a protocol (or platform) key.
    pub fn message_for(&self, key: &str) -> &str {
        self.structure.as_ref().and_then(|s| s.get(key)).map(String::as_str).unwrap_or(&self.message)
    }
}

/// What one Publish asks for, before it is checked.
pub(crate) struct Request<'a> {
    pub message: &'a str,
    pub subject: Option<&'a str>,
    pub structure: Option<&'a str>,
    pub attributes: Option<&'a BTreeMap<String, MessageAttributeValue>>,
    pub group_id: Option<&'a str>,
    pub dedup_id: Option<&'a str>,
}

fn valid_subject(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() < 100
        && s.chars().all(|c| c.is_ascii() && !c.is_ascii_control())
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation())
}

/// Check message attributes as SNS does.
pub(crate) fn check_attributes(attrs: &BTreeMap<String, MessageAttributeValue>) -> Result<(), ServiceError> {
    for (name, a) in attrs {
        let lower = name.to_ascii_lowercase();
        let reserved = (lower.starts_with("aws.") || lower.starts_with("amazon."))
            && !(name.starts_with("AWS.SNS.") || name.starts_with("AWS.MM."));
        let bad_name = name.is_empty()
            || name.len() > 256
            || name.starts_with('.')
            || name.ends_with('.')
            || name.contains("..")
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
        if bad_name || reserved {
            return Err(errors::invalid_parameter_value(format!(
                "The message attribute name '{name}' is invalid. Message attribute names can contain only alphanumeric characters, hyphens (-), underscores (_), and periods (.). They can't start or end with a period and can't have successive periods."
            )));
        }
        let base = a.data_type.split('.').next().unwrap_or("");
        if !matches!(base, "String" | "Number" | "Binary") || a.data_type.len() > 256 {
            return Err(errors::invalid_parameter_value(format!(
                "The message attribute '{name}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String."
            )));
        }
        let empty = match base {
            "Binary" => a.binary_value.as_ref().is_none_or(|b| b.is_empty()),
            _ => a.string_value.as_ref().is_none_or(|s| s.is_empty()),
        };
        if empty {
            return Err(errors::invalid_parameter_value(format!(
                "The message attribute '{name}' must contain non-empty message attribute value for message attribute type '{base}'."
            )));
        }
        if base == "Number" {
            let v = a.string_value.as_deref().unwrap_or("");
            if !v.parse::<f64>().is_ok_and(|n| n.is_finite() && n.abs() <= 1e9 && v.len() <= 32) {
                return Err(errors::invalid_parameter_value(format!(
                    "Could not cast message attribute '{name}' value to number."
                )));
            }
        }
        if a.data_type.starts_with("String.Array") {
            let v = a.string_value.as_deref().unwrap_or("");
            let ok = serde_json::from_str::<serde_json::Value>(v).ok().is_some_and(|j| {
                j.as_array().is_some_and(|items| items.iter().all(|i| !i.is_array() && !i.is_object()))
            });
            if !ok {
                return Err(errors::invalid_parameter_value(format!(
                    "The message attribute '{name}' with type 'String.Array' has an invalid value."
                )));
            }
        }
    }
    Ok(())
}

fn attributes_size(attrs: &BTreeMap<String, MessageAttributeValue>) -> usize {
    attrs
        .iter()
        .map(|(k, a)| {
            k.len()
                + a.data_type.len()
                + a.string_value.as_ref().map_or(0, String::len)
                + a.binary_value.as_ref().map_or(0, Vec::len)
        })
        .sum()
}

/// Validate the parts every Publish shares, returning the per-protocol
/// messages when the structure is `json`.
pub(crate) fn check_message(r: &Request<'_>) -> Result<Option<BTreeMap<String, String>>, ServiceError> {
    if r.message.is_empty() {
        return Err(errors::invalid("Empty message"));
    }
    if let Some(s) = r.subject {
        if !valid_subject(s) {
            return Err(errors::invalid("Subject"));
        }
    }
    let empty = BTreeMap::new();
    let attrs = r.attributes.unwrap_or(&empty);
    check_attributes(attrs)?;
    if r.message.len() + attributes_size(attrs) > MAX_MESSAGE {
        return Err(errors::invalid("Message too long"));
    }
    let structure = match r.structure {
        None | Some("") => None,
        Some("json") => {
            let v: serde_json::Value = serde_json::from_str(r.message)
                .map_err(|_| errors::invalid("Message Structure - JSON message body failed to parse"))?;
            let obj = v
                .as_object()
                .ok_or_else(|| errors::invalid("Message Structure - JSON message body failed to parse"))?;
            let mut out = BTreeMap::new();
            for (k, v) in obj {
                let s = v
                    .as_str()
                    .ok_or_else(|| errors::invalid("Message Structure - JSON message body failed to parse"))?;
                out.insert(k.clone(), s.to_string());
            }
            if !out.contains_key("default") {
                return Err(errors::invalid("Message Structure - No default entry in JSON message body"));
            }
            Some(out)
        }
        Some(_) => return Err(errors::invalid("MessageStructure")),
    };
    for (what, v) in [("MessageGroupId", r.group_id), ("MessageDeduplicationId", r.dedup_id)] {
        if let Some(v) = v {
            if v.is_empty() || v.len() > 128 || !v.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(errors::invalid(format!(
                    "{what} Reason: {what} can only include alphanumeric and punctuation characters. 1 to 128 in length."
                )));
            }
        }
    }
    Ok(structure)
}

impl Sns {
    /// Run FIFO rules against `topic`, returning `Err(Some(...))` for a
    /// duplicate (already published) and the sequence number otherwise.
    fn sequence(topic: &mut Topic, r: &Request<'_>, message_id: &str, now_ms: i64) -> Result<Sequenced, ServiceError> {
        if !topic.is_fifo() {
            if r.dedup_id.is_some() {
                return Err(errors::invalid(
                    "MessageDeduplicationId Reason: The request includes MessageDeduplicationId parameter that is not valid for this topic type",
                ));
            }
            return Ok(Ok((None, None)));
        }
        if r.group_id.is_none() {
            return Err(errors::invalid("The MessageGroupId parameter is required for FIFO topics"));
        }
        let content_based = topic.attributes.get("ContentBasedDeduplication").is_some_and(|v| v == "true");
        let dedup = match r.dedup_id {
            Some(d) => d.to_string(),
            None if content_based => {
                sha2::Sha256::digest(r.message.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
            }
            None => {
                return Err(errors::invalid(
                    "The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                ))
            }
        };
        topic.dedup.retain(|_, d| now_ms - d.at_ms < DEDUP_WINDOW_MS);
        // With `FifoThroughputScope` = `MessageGroup`, deduplication is
        // scoped to each message group; otherwise to the whole topic.
        let per_group = topic.attributes.get("FifoThroughputScope").is_some_and(|s| s == "MessageGroup");
        let key = if per_group { format!("{}\n{dedup}", r.group_id.unwrap_or_default()) } else { dedup.clone() };
        if let Some(prev) = topic.dedup.get(&key) {
            return Ok(Err(prev.clone()));
        }
        topic.sequence += 1;
        let seq = format!("{}", 10_000_000_000_000_000_000u128 + u128::from(topic.sequence));
        topic
            .dedup
            .insert(key, Dedup { at_ms: now_ms, message_id: message_id.to_string(), sequence_number: seq.clone() });
        Ok(Ok((Some(seq), Some(dedup))))
    }

    /// Publish one message to a topic the caller may publish to.
    pub(crate) fn publish_to_topic(
        &self,
        ctx: &RequestContext,
        topic_arn: &str,
        principal: &str,
        r: &Request<'_>,
        structure: Option<BTreeMap<String, String>>,
    ) -> Result<types::PublishResponse, ServiceError> {
        let message_id = uuid::Uuid::new_v4().to_string();
        let now_ms = ctx.received_at.timestamp_millis();
        // The data protection policy judges the message before it is
        // sequenced, so a denied message takes no deduplication id.
        let inbound = {
            let current = {
                let st = self.lock();
                Self::topic(&st, topic_arn)?.clone()
            };
            self.protect_inbound(ctx, &current, principal, r.message, structure)?
        };
        let structure = inbound.structure.clone();
        let (topic, sequence, dedup) = {
            let mut st = self.lock();
            let topic = Self::topic_mut(&mut st, topic_arn)?;
            match Self::sequence(topic, r, &message_id, now_ms)? {
                Err(prev) => {
                    return Ok(types::PublishResponse {
                        message_id: Some(prev.message_id),
                        sequence_number: Some(prev.sequence_number),
                    })
                }
                Ok((seq, dedup)) => (topic.clone(), seq, dedup),
            }
        };
        let out = Outgoing {
            message_id: message_id.clone(),
            subject: r.subject.map(str::to_string),
            message: structure
                .as_ref()
                .and_then(|s| s.get("default").cloned())
                .unwrap_or_else(|| inbound.message.clone()),
            structure,
            attributes: r.attributes.cloned().unwrap_or_default(),
            group_id: r.group_id.map(str::to_string),
            dedup_id: dedup,
            sequence_number: sequence.clone(),
            timestamp: ctx.received_at,
            replayed: false,
        };
        if topic.archive_since.is_some() {
            if let Some(t) = self.lock().topics.get_mut(topic_arn) {
                t.archive_message(&out, ctx.received_at);
            }
        }
        self.write_audit(ctx, &topic, &inbound, &message_id);
        self.fan_out(ctx, &topic, out);
        Ok(types::PublishResponse { message_id: Some(message_id), sequence_number: sequence })
    }

    pub(crate) async fn publish_impl(
        &self,
        ctx: &RequestContext,
        input: types::PublishInput,
    ) -> Result<types::PublishResponse, ServiceError> {
        let targets = [&input.topic_arn, &input.target_arn, &input.phone_number]
            .iter()
            .filter(|t| t.as_deref().is_some_and(|v| !v.is_empty()))
            .count();
        if targets == 0 {
            return Err(errors::invalid("TopicArn or TargetArn Reason: no value for required parameter"));
        }
        if targets > 1 {
            return Err(errors::invalid(
                "TopicArn or TargetArn Reason: Only one of TopicArn, TargetArn or PhoneNumber may be specified",
            ));
        }
        let r = Request {
            message: &input.message,
            subject: input.subject.as_deref(),
            structure: input.message_structure.as_deref(),
            attributes: input.message_attributes.as_ref(),
            group_id: input.message_group_id.as_deref(),
            dedup_id: input.message_deduplication_id.as_deref(),
        };
        if let Some(phone) = input.phone_number.as_deref().filter(|p| !p.is_empty()) {
            let structure = check_message(&r)?;
            return self.publish_sms(ctx, phone, &r, structure);
        }
        let arn = input.topic_arn.as_deref().or(input.target_arn.as_deref()).unwrap_or_default().to_string();
        let param = if input.topic_arn.is_some() { "TopicArn" } else { "TargetArn" };
        let parsed = names::parse_sns_arn(&arn).ok_or_else(|| errors::invalid(param))?;
        if parsed.resource.starts_with("endpoint/") {
            let structure = check_message(&r)?;
            return self.publish_to_endpoint(ctx, &arn, &r, structure);
        }
        names::check_topic_arn(ctx, &arn, param)?;
        self.authorize_topic(ctx, "sns:Publish", &arn, ConditionContext::new())?;
        let structure = check_message(&r)?;
        let topic = {
            let st = self.lock();
            Self::topic(&st, &arn)?.clone()
        };
        self.seal_for_caller(ctx, &topic)?;
        self.publish_to_topic(ctx, &arn, &ctx.caller.arn, &r, structure)
    }

    fn publish_sms(
        &self,
        ctx: &RequestContext,
        phone: &str,
        r: &Request<'_>,
        structure: Option<BTreeMap<String, String>>,
    ) -> Result<types::PublishResponse, ServiceError> {
        let account = account_of(ctx);
        ctx.authorize("sns:Publish", "*", ConditionContext::new())?;
        let normalized: String = phone.chars().filter(|c| !matches!(c, ' ' | '-' | '(' | ')')).collect();
        if !names::valid_phone_number(&normalized) {
            return Err(errors::invalid(format!("PhoneNumber Reason: {phone} is not valid to publish to")));
        }
        let message_id = uuid::Uuid::new_v4().to_string();
        let message = structure
            .as_ref()
            .and_then(|s| s.get("sms").or(s.get("default")).cloned())
            .unwrap_or_else(|| r.message.to_string());
        let attr = |k: &str| r.attributes.and_then(|a| a.get(k)).and_then(|v| v.string_value.clone());
        let mut st = self.lock();
        if !st.opted_out.contains(&normalized) {
            let defaults = st.sms.get(&account).map(|a| a.attributes.clone()).unwrap_or_default();
            st.outbox.sms(SmsMessage {
                message_id: message_id.clone(),
                phone_number: normalized,
                message,
                sender_id: attr("AWS.SNS.SMS.SenderID").or_else(|| defaults.get("DefaultSenderID").cloned()),
                sms_type: attr("AWS.SNS.SMS.SMSType").or_else(|| defaults.get("DefaultSMSType").cloned()),
                origination_number: attr("AWS.MM.SMS.OriginationNumber"),
                topic_arn: None,
                account_id: account,
                region: ctx.region.clone(),
                timestamp: crate::delivery::timestamp(&ctx.received_at),
            });
        }
        Ok(types::PublishResponse { message_id: Some(message_id), sequence_number: None })
    }

    fn publish_to_endpoint(
        &self,
        ctx: &RequestContext,
        arn: &str,
        r: &Request<'_>,
        structure: Option<BTreeMap<String, String>>,
    ) -> Result<types::PublishResponse, ServiceError> {
        ctx.authorize("sns:Publish", arn, ConditionContext::new())?;
        let message_id = uuid::Uuid::new_v4().to_string();
        let out = Outgoing {
            message_id: message_id.clone(),
            subject: r.subject.map(str::to_string),
            message: structure
                .as_ref()
                .and_then(|s| s.get("default").cloned())
                .unwrap_or_else(|| r.message.to_string()),
            structure,
            attributes: r.attributes.cloned().unwrap_or_default(),
            group_id: None,
            dedup_id: None,
            sequence_number: None,
            timestamp: ctx.received_at,
            replayed: false,
        };
        let mut st = self.lock();
        let endpoint = st
            .endpoints
            .get(arn)
            .cloned()
            .ok_or_else(|| errors::invalid("TargetArn Reason: No endpoint found for the target arn specified"))?;
        if endpoint.attributes.get("Enabled").is_some_and(|e| e == "false") {
            return Err(errors::endpoint_disabled("Endpoint is disabled"));
        }
        let app = st.applications.get(&endpoint.application_arn).cloned().unwrap_or_default();
        if app.attributes.get("Enabled").is_some_and(|e| e == "false") {
            return Err(errors::platform_application_disabled("Platform application is disabled"));
        }
        st.outbox.platform(platform_message(&out, &endpoint, &app.platform, None));
        Ok(types::PublishResponse { message_id: Some(message_id), sequence_number: None })
    }

    pub(crate) async fn publish_batch_impl(
        &self,
        ctx: &RequestContext,
        input: types::PublishBatchInput,
    ) -> Result<types::PublishBatchResponse, ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        self.authorize_topic(ctx, "sns:Publish", &input.topic_arn, ConditionContext::new())?;
        let entries = input.publish_batch_request_entries;
        if entries.is_empty() {
            return Err(errors::empty_batch_request("The batch request doesn't contain any entries"));
        }
        if entries.len() > MAX_BATCH {
            return Err(errors::too_many_entries_in_batch_request(
                "The batch request contains more entries than permissible.",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for e in &entries {
            if !ids.insert(e.id.as_str()) {
                return Err(errors::batch_entry_ids_not_distinct(
                    "Two or more batch entries in the request have the same Id.",
                ));
            }
            if e.id.is_empty()
                || e.id.len() > 80
                || !e.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(errors::invalid_batch_entry_id(
                    "A batch entry id can only contain alphanumeric characters, hyphens and underscores. It can be at most 80 letters long.",
                ));
            }
        }
        let total: usize =
            entries.iter().map(|e| e.message.len() + e.message_attributes.as_ref().map_or(0, attributes_size)).sum();
        if total > MAX_MESSAGE {
            return Err(errors::batch_request_too_long(
                "The length of all the messages put together is more than the limit.",
            ));
        }
        let topic = {
            let st = self.lock();
            Self::topic(&st, &input.topic_arn)?.clone()
        };
        self.seal_for_caller(ctx, &topic)?;
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        for e in entries {
            let r = Request {
                message: &e.message,
                subject: e.subject.as_deref(),
                structure: e.message_structure.as_deref(),
                attributes: e.message_attributes.as_ref(),
                group_id: e.message_group_id.as_deref(),
                dedup_id: e.message_deduplication_id.as_deref(),
            };
            let result =
                check_message(&r).and_then(|s| self.publish_to_topic(ctx, &input.topic_arn, &ctx.caller.arn, &r, s));
            match result {
                Ok(out) => successful.push(types::PublishBatchResultEntry {
                    id: Some(e.id.clone()),
                    message_id: out.message_id,
                    sequence_number: out.sequence_number,
                }),
                Err(err) => failed.push(types::BatchResultErrorEntry {
                    id: e.id.clone(),
                    code: err.code.to_string(),
                    message: Some(err.message),
                    sender_fault: err.fault == mws_core::ErrorFault::Client,
                }),
            }
        }
        Ok(types::PublishBatchResponse { successful: Some(successful), failed: Some(failed) })
    }
}

/// The outbox record of a push notification.
pub(crate) fn platform_message(
    out: &Outgoing,
    endpoint: &crate::state::PlatformEndpoint,
    platform: &str,
    topic_arn: Option<&str>,
) -> PlatformMessage {
    let attrs: serde_json::Map<String, serde_json::Value> =
        out.attributes.iter().map(|(k, v)| (k.clone(), crate::delivery::attribute_json(v))).collect();
    PlatformMessage {
        message_id: out.message_id.clone(),
        endpoint_arn: endpoint.arn.clone(),
        platform: platform.to_string(),
        token: endpoint.attributes.get("Token").cloned().unwrap_or_default(),
        message: out.message_for(platform).to_string(),
        message_attributes: serde_json::Value::Object(attrs),
        topic_arn: topic_arn.map(str::to_string),
        timestamp: crate::delivery::timestamp(&out.timestamp),
    }
}
