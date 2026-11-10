//! Delivering messages to subscriptions, in the formats SNS uses: the JSON
//! envelope (with signature), raw messages, and the Lambda event.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::RequestContext;
use serde_json::{json, Map, Value};

use crate::generated::types::MessageAttributeValue;
use crate::outbox::{EmailMessage, SmsMessage};
use crate::public::{QueueMessage, QueueMessageAttribute};
use crate::publish::{platform_message, Outgoing};
use crate::state::{Subscription, Topic};
use crate::{filter, Sns};

const SERVICE_PRINCIPAL: &str = "sns.amazonaws.com";

pub fn timestamp(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn attribute_json(a: &MessageAttributeValue) -> Value {
    let value = match &a.binary_value {
        Some(b) if a.data_type.starts_with("Binary") => base64::engine::general_purpose::STANDARD.encode(b),
        _ => a.string_value.clone().unwrap_or_default(),
    };
    json!({ "Type": a.data_type, "Value": value })
}

fn base_url(ctx: &RequestContext) -> String {
    ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".to_string())
}

fn enc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Facts about the topic a delivery comes from.
#[derive(Debug, Clone)]
struct Origin {
    topic_arn: String,
    account: String,
    signature_version: String,
    fifo: bool,
    display_name: String,
}

impl Origin {
    fn of(topic: &Topic) -> Self {
        Self {
            topic_arn: topic.arn.clone(),
            account: topic.account.clone(),
            signature_version: topic.attributes.get("SignatureVersion").cloned().unwrap_or_else(|| "1".into()),
            fifo: topic.is_fifo(),
            display_name: topic.attributes.get("DisplayName").cloned().unwrap_or_default(),
        }
    }
}

impl Sns {
    fn signed(
        &self,
        ctx: &RequestContext,
        version: &str,
        mut fields: Vec<(&'static str, String)>,
    ) -> Map<String, Value> {
        // The string to sign lists the signed fields in alphabetical order.
        let mut sorted = fields.clone();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let text: String = sorted.iter().map(|(k, v)| format!("{k}\n{v}\n")).collect();
        let signature = self.inner.signer.sign(&text, version);
        fields.push(("SignatureVersion", version.to_string()));
        fields.push(("Signature", signature));
        fields.push(("SigningCertURL", format!("{}{}", base_url(ctx), self.inner.signer.cert_path())));
        let mut out = Map::new();
        for (k, v) in fields {
            out.insert(k.to_string(), Value::String(v));
        }
        out
    }

    /// The JSON envelope of a notification.
    fn envelope(&self, ctx: &RequestContext, origin: &Origin, sub: &Subscription, msg: &Outgoing, body: &str) -> Value {
        let mut fields = vec![("Type", "Notification".to_string()), ("MessageId", msg.message_id.clone())];
        if let Some(seq) = &msg.sequence_number {
            fields.push(("SequenceNumber", seq.clone()));
        }
        fields.push(("TopicArn", origin.topic_arn.clone()));
        if let Some(s) = &msg.subject {
            fields.push(("Subject", s.clone()));
        }
        fields.push(("Message", body.to_string()));
        fields.push(("Timestamp", timestamp(&msg.timestamp)));
        // SequenceNumber is not part of the signed string.
        let signed_fields: Vec<(&'static str, String)> =
            fields.iter().filter(|(k, _)| *k != "SequenceNumber").cloned().collect();
        let mut signed = self.signed(ctx, &origin.signature_version, signed_fields);
        let mut out = Map::new();
        for (k, v) in &fields {
            out.insert(k.to_string(), Value::String(v.clone()));
        }
        for k in ["SignatureVersion", "Signature", "SigningCertURL"] {
            if let Some(v) = signed.remove(k) {
                out.insert(k.to_string(), v);
            }
        }
        out.insert(
            "UnsubscribeURL".into(),
            Value::String(format!("{}/?Action=Unsubscribe&SubscriptionArn={}", base_url(ctx), enc(&sub.arn))),
        );
        if msg.replayed {
            out.insert("Replayed".into(), Value::Bool(true));
        }
        if !msg.attributes.is_empty() {
            let attrs: Map<String, Value> =
                msg.attributes.iter().map(|(k, v)| (k.clone(), attribute_json(v))).collect();
            out.insert("MessageAttributes".into(), Value::Object(attrs));
        }
        Value::Object(out)
    }

    /// The event Lambda functions receive.
    fn lambda_event(&self, ctx: &RequestContext, origin: &Origin, sub: &Subscription, msg: &Outgoing) -> Value {
        let body = msg.message_for("lambda");
        let env = self.envelope(ctx, origin, sub, msg, body);
        let get = |k: &str| env.get(k).cloned().unwrap_or(Value::Null);
        let attrs = env.get("MessageAttributes").cloned().unwrap_or_else(|| json!({}));
        json!({
            "Records": [{
                "EventSource": "aws:sns",
                "EventVersion": "1.0",
                "EventSubscriptionArn": sub.arn,
                "Sns": {
                    "Type": "Notification",
                    "MessageId": msg.message_id,
                    "TopicArn": origin.topic_arn,
                    "Subject": get("Subject"),
                    "Message": body,
                    "Timestamp": get("Timestamp"),
                    "SignatureVersion": get("SignatureVersion"),
                    "Signature": get("Signature"),
                    "SigningCertUrl": get("SigningCertURL"),
                    "UnsubscribeUrl": get("UnsubscribeURL"),
                    "MessageAttributes": attrs,
                }
            }]
        })
    }

    /// Send a message to every confirmed subscription whose filter policy
    /// it passes.
    pub(crate) fn fan_out(&self, ctx: &RequestContext, topic: &Topic, msg: Outgoing) {
        let origin = Origin::of(topic);
        let subs: Vec<Subscription> = {
            let st = self.lock();
            st.subscriptions
                .values()
                .filter(|s| s.topic_arn == topic.arn && !s.pending && !crate::archive::paused(s))
                .cloned()
                .collect()
        };
        for sub in subs {
            if let Some(policy) = sub.attributes.get("FilterPolicy").filter(|p| !p.is_empty()) {
                let body_scope = sub.attributes.get("FilterPolicyScope").is_some_and(|s| s == "MessageBody");
                let parsed: Value = serde_json::from_str(policy).unwrap_or(Value::Null);
                if !filter::matches(&parsed, body_scope, &msg.attributes, msg.message_for(&sub.protocol)) {
                    let scoped = if body_scope {
                        "NumberOfNotificationsFilteredOut-MessageBody"
                    } else {
                        "NumberOfNotificationsFilteredOut-MessageAttributes"
                    };
                    self.topic_metric(ctx, &topic.arn, "NumberOfNotificationsFilteredOut", "Count", 1.0);
                    self.topic_metric(ctx, &topic.arn, scoped, "Count", 1.0);
                    continue;
                }
            }
            self.deliver_protected(ctx, topic, &origin, &sub, &msg);
        }
    }

    /// Deliver one message to one subscription (archive replays).
    pub(crate) fn deliver_one(&self, ctx: &RequestContext, topic: &Topic, sub: &Subscription, msg: &Outgoing) {
        self.deliver_protected(ctx, topic, &Origin::of(topic), sub, msg);
    }

    /// Deliver through the topic's outbound data protection statements.
    fn deliver_protected(
        &self,
        ctx: &RequestContext,
        topic: &Topic,
        origin: &Origin,
        sub: &Subscription,
        msg: &Outgoing,
    ) {
        match Self::protect_outbound(topic, sub, msg) {
            Some(out) => self.deliver(ctx, origin, sub, &out),
            None => {
                let response = format!(
                    "The topic's data protection policy prohibits this message from being delivered to {}",
                    sub.arn
                );
                self.log_delivery(ctx, msg, self.attempt(origin, sub, false, 403, response, 1));
            }
        }
    }

    fn attempt<'a>(
        &self,
        origin: &'a Origin,
        sub: &'a Subscription,
        success: bool,
        status_code: u16,
        provider_response: String,
        attempts: u32,
    ) -> crate::status_log::Attempt<'a> {
        crate::status_log::Attempt {
            topic_arn: &origin.topic_arn,
            protocol: &sub.protocol,
            destination: &sub.endpoint,
            success,
            status_code,
            provider_response,
            attempts,
        }
    }

    fn raw(sub: &Subscription) -> bool {
        sub.attributes.get("RawMessageDelivery").is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    fn deliver(&self, ctx: &RequestContext, origin: &Origin, sub: &Subscription, msg: &Outgoing) {
        let body = msg.message_for(&sub.protocol).to_string();
        match sub.protocol.as_str() {
            "lambda" => {
                let Some(lambda) = self.inner.lambda.get() else {
                    tracing::warn!(subscription = %sub.arn, "Lambda is not wired in; dropping the message");
                    return;
                };
                let event = self.lambda_event(ctx, origin, sub, msg);
                let inv = mws_lambda::ServiceInvocation {
                    function: &sub.endpoint,
                    service_principal: SERVICE_PRINCIPAL,
                    source_account: Some(&origin.account),
                    source_arn: Some(&origin.topic_arn),
                    payload: event.to_string().into_bytes(),
                };
                let outcome = lambda.invoke_event_as_service(ctx, inv);
                let (success, status_code, response) = match &outcome {
                    Ok(()) => (true, 202, json!({"lambdaRequestId": uuid::Uuid::new_v4().to_string()})),
                    Err(mws_lambda::ServiceInvokeError::NotFound) => (
                        false,
                        404,
                        json!({"ErrorCode": "ResourceNotFoundException", "ErrorMessage": "Function not found"}),
                    ),
                    Err(mws_lambda::ServiceInvokeError::AccessDenied) => {
                        (false, 403, json!({"ErrorCode": "AccessDeniedException", "ErrorMessage": "Access denied"}))
                    }
                    Err(mws_lambda::ServiceInvokeError::Failed(m)) => {
                        (false, 500, json!({"ErrorCode": "ServiceException", "ErrorMessage": m}))
                    }
                };
                self.log_delivery(ctx, msg, self.attempt(origin, sub, success, status_code, response.to_string(), 1));
                if let Err(e) = outcome {
                    tracing::warn!(subscription = %sub.arn, "SNS could not invoke {}: {e}", sub.endpoint);
                    self.redrive(ctx, origin, sub, msg);
                }
            }
            "sqs" => {
                let message = if Self::raw(sub) {
                    self.queue_message(origin, &sub.endpoint, body, msg, true)
                } else {
                    let env = self.envelope(ctx, origin, sub, msg, &body).to_string();
                    self.queue_message(origin, &sub.endpoint, env, msg, false)
                };
                match self.send_to_queue(message) {
                    Ok(id) => {
                        let response = json!({"sqsRequestId": "Unrecorded", "sqsMessageId": id}).to_string();
                        self.log_delivery(ctx, msg, self.attempt(origin, sub, true, 200, response, 1));
                    }
                    Err(e) => {
                        let response = json!({"ErrorCode": "AccessDenied", "ErrorMessage": e}).to_string();
                        self.log_delivery(ctx, msg, self.attempt(origin, sub, false, 403, response, 1));
                        tracing::warn!(subscription = %sub.arn, "SNS could not deliver to {}: {e}", sub.endpoint);
                        self.redrive(ctx, origin, sub, msg);
                    }
                }
            }
            "http" | "https" => {
                let raw = Self::raw(sub);
                let payload = if raw { body } else { self.envelope(ctx, origin, sub, msg, &body).to_string() };
                let mut headers = vec![
                    ("x-amz-sns-message-type".to_string(), "Notification".to_string()),
                    ("x-amz-sns-message-id".to_string(), msg.message_id.clone()),
                    ("x-amz-sns-topic-arn".to_string(), origin.topic_arn.clone()),
                    ("x-amz-sns-subscription-arn".to_string(), sub.arn.clone()),
                ];
                if raw {
                    headers.push(("x-amz-sns-rawdelivery".to_string(), "true".to_string()));
                }
                self.post_with_retries(ctx.clone(), origin.clone(), sub.clone(), msg.clone(), headers, payload);
            }
            "email" | "email-json" => {
                let (content_type, text) = if sub.protocol == "email-json" {
                    ("application/json", self.envelope(ctx, origin, sub, msg, &body).to_string())
                } else {
                    let unsubscribe =
                        format!("{}/?Action=Unsubscribe&SubscriptionArn={}", base_url(ctx), enc(&sub.arn));
                    (
                        "text/plain",
                        format!(
                            "{body}\n\n--\nIf you wish to stop receiving notifications from this topic, please click or visit the link below to unsubscribe:\n{unsubscribe}\n\nPlease do not reply directly to this email. If you have any questions or comments regarding this email, please contact us at https://aws.amazon.com/support"
                        ),
                    )
                };
                let subject = msg.subject.clone().unwrap_or_else(|| {
                    if origin.display_name.is_empty() {
                        "AWS Notification Message".to_string()
                    } else {
                        origin.display_name.clone()
                    }
                });
                self.lock().outbox.email(EmailMessage {
                    message_id: msg.message_id.clone(),
                    to: sub.endpoint.clone(),
                    subject,
                    body: text,
                    content_type: content_type.to_string(),
                    topic_arn: origin.topic_arn.clone(),
                    subscription_arn: sub.arn.clone(),
                    timestamp: timestamp(&msg.timestamp),
                });
            }
            "sms" => {
                let mut st = self.lock();
                let number: String =
                    sub.endpoint.chars().filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '.')).collect();
                if st.opted_out.contains(&number) {
                    return;
                }
                let defaults = st.sms.get(&origin.account).map(|a| a.attributes.clone()).unwrap_or_default();
                let text =
                    if origin.display_name.is_empty() { body } else { format!("{}> {body}", origin.display_name) };
                st.outbox.sms(SmsMessage {
                    message_id: msg.message_id.clone(),
                    phone_number: number,
                    message: text,
                    sender_id: defaults.get("DefaultSenderID").cloned(),
                    sms_type: defaults.get("DefaultSMSType").cloned(),
                    origination_number: None,
                    topic_arn: Some(origin.topic_arn.clone()),
                    account_id: origin.account.clone(),
                    region: ctx.region.clone(),
                    timestamp: timestamp(&msg.timestamp),
                });
            }
            "application" => {
                let mut st = self.lock();
                let Some(endpoint) = st.endpoints.get(&sub.endpoint).cloned() else { return };
                if endpoint.attributes.get("Enabled").is_some_and(|e| e == "false") {
                    return;
                }
                let platform =
                    st.applications.get(&endpoint.application_arn).map(|a| a.platform.clone()).unwrap_or_default();
                st.outbox.platform(platform_message(msg, &endpoint, &platform, Some(&origin.topic_arn)));
                drop(st);
                let response = json!({"messageId": uuid::Uuid::new_v4().to_string()}).to_string();
                self.log_delivery(ctx, msg, self.attempt(origin, sub, true, 200, response, 1));
            }
            "firehose" => {
                // Firehose records carry the envelope without a signature
                // (or the raw message), each ending in a newline.
                let mut record = if Self::raw(sub) {
                    body
                } else {
                    let mut env = self.envelope(ctx, origin, sub, msg, &body);
                    if let Some(o) = env.as_object_mut() {
                        for k in ["SignatureVersion", "Signature", "SigningCertURL"] {
                            o.remove(k);
                        }
                    }
                    env.to_string()
                };
                record.push('\n');
                match self.put_to_firehose(ctx, origin, sub, record.into_bytes()) {
                    Ok(id) => {
                        let response = json!({"firehoseRecordId": id}).to_string();
                        self.log_delivery(ctx, msg, self.attempt(origin, sub, true, 200, response, 1));
                    }
                    Err((status, e)) => {
                        let response = json!({"ErrorCode": "DeliveryFailed", "ErrorMessage": e}).to_string();
                        self.log_delivery(ctx, msg, self.attempt(origin, sub, false, status, response, 1));
                        tracing::warn!(subscription = %sub.arn, "SNS could not deliver to {}: {e}", sub.endpoint);
                        self.redrive(ctx, origin, sub, msg);
                    }
                }
            }
            _ => {
                tracing::warn!(subscription = %sub.arn, "MWS does not deliver to {} subscriptions", sub.protocol);
            }
        }
    }

    fn queue_message(&self, origin: &Origin, queue_arn: &str, body: String, msg: &Outgoing, raw: bool) -> QueueMessage {
        let attributes = if raw {
            msg.attributes
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        QueueMessageAttribute {
                            data_type: v.data_type.clone(),
                            string_value: v.string_value.clone(),
                            binary_value: v.binary_value.clone(),
                        },
                    )
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        QueueMessage {
            queue_arn: queue_arn.to_string(),
            service_principal: SERVICE_PRINCIPAL.to_string(),
            source_arn: origin.topic_arn.clone(),
            source_account: origin.account.clone(),
            body,
            message_attributes: attributes,
            // Standard topics forward a MessageGroupId to standard queues
            // (SQS fair queues); FIFO topics need it for FIFO queues.
            message_group_id: msg.group_id.clone(),
            message_deduplication_id: if origin.fifo { msg.dedup_id.clone() } else { None },
            now: msg.timestamp,
        }
    }

    /// Put one record into a subscription's delivery stream as its
    /// `SubscriptionRoleArn`. Returns the record id, or the status code
    /// and reason of the failure.
    fn put_to_firehose(
        &self,
        ctx: &RequestContext,
        origin: &Origin,
        sub: &Subscription,
        data: Vec<u8>,
    ) -> Result<String, (u16, String)> {
        let (Some(firehose), Some(sts)) = (self.inner.firehose.get(), self.sts()) else {
            return Err((500, "Firehose is not wired in".to_string()));
        };
        let role = sub.attributes.get("SubscriptionRoleArn").cloned().unwrap_or_default();
        let rctx = crate::status_log::role_context(sts, ctx, &role, &origin.topic_arn, "SNSFirehoseDelivery")
            .map_err(|e| (403, e))?;
        let name = sub.endpoint.rsplit_once("deliverystream/").map(|(_, n)| n).unwrap_or(&sub.endpoint);
        firehose
            .put_record(
                &rctx,
                mws_firehose::generated::types::PutRecordInput {
                    delivery_stream_name: name.to_string(),
                    record: mws_firehose::generated::types::Record { data },
                },
            )
            .map(|out| out.record_id)
            .map_err(|e| (e.status, format!("{}: {}", e.code, e.message)))
    }

    fn send_to_queue(&self, m: QueueMessage) -> Result<String, String> {
        match self.inner.queues.get() {
            Some(q) => q.send(m),
            None => Err("the queue service is not wired in".to_string()),
        }
    }

    /// Send a message that could not be delivered to the subscription's
    /// dead-letter queue, if it has one.
    fn redrive(&self, ctx: &RequestContext, origin: &Origin, sub: &Subscription, msg: &Outgoing) {
        let Some(policy) = sub.attributes.get("RedrivePolicy") else { return };
        let Some(dlq) = serde_json::from_str::<Value>(policy)
            .ok()
            .and_then(|v| v.get("deadLetterTargetArn").and_then(Value::as_str).map(str::to_string))
        else {
            return;
        };
        let body = msg.message_for(&sub.protocol).to_string();
        let m = if Self::raw(sub) {
            self.queue_message(origin, &dlq, body, msg, true)
        } else {
            let env = self.envelope(ctx, origin, sub, msg, &body).to_string();
            self.queue_message(origin, &dlq, env, msg, false)
        };
        if let Err(e) = self.send_to_queue(m) {
            tracing::warn!(subscription = %sub.arn, "SNS could not move a message to {dlq}: {e}");
        }
    }

    fn post_with_retries(
        &self,
        ctx: RequestContext,
        origin: Origin,
        sub: Subscription,
        msg: Outgoing,
        headers: Vec<(String, String)>,
        payload: String,
    ) {
        let policy = self.http_policy(&sub);
        let sns = self.clone();
        tokio::spawn(async move {
            let attempts = 1 + policy.retries;
            let mut last = (0u16, String::new());
            let mut made = 0;
            for attempt in 0..attempts {
                if attempt > 0 {
                    tokio::time::sleep(policy.delay).await;
                }
                made += 1;
                match crate::webhook::post(&sub.endpoint, &headers, &policy.content_type, payload.as_bytes()).await {
                    Ok(status) if (200..300).contains(&status) => {
                        let a = sns.attempt(&origin, &sub, true, status, "Accepted".into(), made);
                        sns.log_delivery(&ctx, &msg, a);
                        return;
                    }
                    Ok(status) if (400..500).contains(&status) && !matches!(status, 404 | 408 | 429) => {
                        last = (status, format!("Response status code {status}"));
                        break;
                    }
                    Ok(status) => {
                        last = (status, format!("Response status code {status}"));
                        tracing::debug!(endpoint = %sub.endpoint, "HTTP delivery answered {status}")
                    }
                    Err(e) => {
                        last = (0, e.to_string());
                        tracing::debug!(endpoint = %sub.endpoint, "HTTP delivery failed: {e}")
                    }
                }
            }
            let a = sns.attempt(&origin, &sub, false, last.0, last.1, made);
            sns.log_delivery(&ctx, &msg, a);
            sns.redrive(&ctx, &origin, &sub, &msg);
        });
    }

    fn http_policy(&self, sub: &Subscription) -> HttpPolicy {
        let topic_policy = {
            let st = self.lock();
            st.topics.get(&sub.topic_arn).and_then(|t| t.attributes.get("DeliveryPolicy").cloned())
        };
        let parsed = sub
            .attributes
            .get("DeliveryPolicy")
            .and_then(|p| serde_json::from_str::<Value>(p).ok())
            .or_else(|| topic_policy.and_then(|p| serde_json::from_str::<Value>(&p).ok()?.get("http").cloned()));
        let retry = parsed.as_ref().and_then(|p| p.get("healthyRetryPolicy").or(p.get("defaultHealthyRetryPolicy")));
        let retries = retry.and_then(|r| r.get("numRetries")).and_then(Value::as_u64).unwrap_or(3).min(100) as u32;
        let delay = retry.and_then(|r| r.get("minDelayTarget")).and_then(Value::as_u64).unwrap_or(20);
        let content_type = parsed
            .as_ref()
            .and_then(|p| p.get("requestPolicy").or(p.get("defaultRequestPolicy")))
            .and_then(|r| r.get("headerContentType"))
            .and_then(Value::as_str)
            .unwrap_or("text/plain; charset=UTF-8")
            .to_string();
        HttpPolicy { retries, delay: Duration::from_secs(delay), content_type }
    }

    /// Ask a new subscription's endpoint to confirm it.
    pub(crate) fn send_confirmation(&self, ctx: &RequestContext, topic: &Topic, sub: &Subscription) {
        let token = sub.token.clone().unwrap_or_default();
        let origin = Origin::of(topic);
        let message_id = uuid::Uuid::new_v4().to_string();
        let subscribe_url =
            format!("{}/?Action=ConfirmSubscription&TopicArn={}&Token={}", base_url(ctx), enc(&topic.arn), enc(&token));
        let message = format!(
            "You have chosen to subscribe to the topic {}.\nTo confirm the subscription, visit the SubscribeURL included in this message.",
            topic.arn
        );
        let fields = vec![
            ("Type", "SubscriptionConfirmation".to_string()),
            ("MessageId", message_id.clone()),
            ("Token", token.clone()),
            ("TopicArn", topic.arn.clone()),
            ("Message", message),
            ("SubscribeURL", subscribe_url.clone()),
            ("Timestamp", timestamp(&ctx.received_at)),
        ];
        let doc = Value::Object(self.signed(ctx, &origin.signature_version, fields)).to_string();
        match sub.protocol.as_str() {
            "http" | "https" => {
                let headers = vec![
                    ("x-amz-sns-message-type".to_string(), "SubscriptionConfirmation".to_string()),
                    ("x-amz-sns-message-id".to_string(), message_id),
                    ("x-amz-sns-topic-arn".to_string(), topic.arn.clone()),
                ];
                let endpoint = sub.endpoint.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::webhook::post(&endpoint, &headers, "text/plain; charset=UTF-8", doc.as_bytes()).await
                    {
                        tracing::debug!(%endpoint, "SNS could not send the subscription confirmation: {e}");
                    }
                });
            }
            "email" | "email-json" => {
                let name =
                    if origin.display_name.is_empty() { "AWS Notifications".to_string() } else { origin.display_name };
                let body = if sub.protocol == "email-json" {
                    doc
                } else {
                    format!(
                        "You have chosen to subscribe to the topic: \n{}\n\nTo confirm this subscription, click or visit the link below (If this was in error no action is necessary): \nConfirm subscription: {subscribe_url}\n\nPlease do not reply directly to this email.",
                        topic.arn
                    )
                };
                self.lock().outbox.email(EmailMessage {
                    message_id,
                    to: sub.endpoint.clone(),
                    subject: format!("{name} - Subscription Confirmation"),
                    body,
                    content_type: if sub.protocol == "email-json" { "application/json" } else { "text/plain" }.into(),
                    topic_arn: topic.arn.clone(),
                    subscription_arn: sub.arn.clone(),
                    timestamp: timestamp(&ctx.received_at),
                });
            }
            "sqs" => {
                let m = QueueMessage {
                    queue_arn: sub.endpoint.clone(),
                    service_principal: SERVICE_PRINCIPAL.to_string(),
                    source_arn: topic.arn.clone(),
                    source_account: topic.account.clone(),
                    body: doc,
                    message_attributes: BTreeMap::new(),
                    message_group_id: origin.fifo.then(|| "SubscriptionConfirmation".to_string()),
                    message_deduplication_id: origin.fifo.then(|| sub.arn.clone()),
                    now: ctx.received_at,
                };
                if let Err(e) = self.send_to_queue(m) {
                    tracing::warn!(subscription = %sub.arn, "SNS could not send the confirmation: {e}");
                }
            }
            _ => {}
        }
    }

    /// Tell an HTTP endpoint it was unsubscribed.
    pub(crate) fn send_unsubscribe_confirmation(&self, ctx: &RequestContext, topic: &Topic, sub: &Subscription) {
        if !matches!(sub.protocol.as_str(), "http" | "https") || sub.pending {
            return;
        }
        let origin = Origin::of(topic);
        let token = crate::subscriptions::new_token();
        let message_id = uuid::Uuid::new_v4().to_string();
        let fields = vec![
            ("Type", "UnsubscribeConfirmation".to_string()),
            ("MessageId", message_id.clone()),
            ("Token", token.clone()),
            ("TopicArn", topic.arn.clone()),
            (
                "Message",
                format!(
                    "You have chosen to deactivate subscription {}.\nTo cancel this operation and restore the subscription, visit the SubscribeURL included in this message.",
                    sub.arn
                ),
            ),
            (
                "SubscribeURL",
                format!("{}/?Action=ConfirmSubscription&TopicArn={}&Token={}", base_url(ctx), enc(&topic.arn), enc(&token)),
            ),
            ("Timestamp", timestamp(&ctx.received_at)),
        ];
        let doc = Value::Object(self.signed(ctx, &origin.signature_version, fields)).to_string();
        let headers = vec![
            ("x-amz-sns-message-type".to_string(), "UnsubscribeConfirmation".to_string()),
            ("x-amz-sns-message-id".to_string(), message_id),
            ("x-amz-sns-topic-arn".to_string(), topic.arn.clone()),
            ("x-amz-sns-subscription-arn".to_string(), sub.arn.clone()),
        ];
        let endpoint = sub.endpoint.clone();
        tokio::spawn(async move {
            let _ = crate::webhook::post(&endpoint, &headers, "text/plain; charset=UTF-8", doc.as_bytes()).await;
        });
    }
}

struct HttpPolicy {
    retries: u32,
    delay: Duration,
    content_type: String,
}
