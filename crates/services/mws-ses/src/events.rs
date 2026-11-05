//! What happens to sent mail, told to the world: configuration set event
//! destinations (SNS, Firehose, EventBridge, CloudWatch), identity
//! notification topics, `AWS/SES` metrics, and the statistics SES keeps.
//! Records follow SES's event publishing and notification formats.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::names::{self, iso};
use crate::public::{BusEvent, Metric};
use crate::state::{region_key, ConfigurationSet, Identity};
use crate::Ses;

const REPORTING_MTA: &str = "a8-70.smtp-out.amazonses.com";

/// The `mail` object of events and notifications.
#[derive(Debug, Clone, Default)]
pub struct MailInfo {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub timestamp: DateTime<Utc>,
    pub message_id: String,
    pub source: String,
    pub source_arn: String,
    pub source_ip: String,
    pub caller_identity: String,
    pub destination: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub reply_to: Vec<String>,
    pub subject: String,
    pub date: String,
    /// The identity that sent it (its notification topics apply), and the
    /// account that owns it (another account's, for delegated sending).
    pub identity: String,
    pub identity_account: String,
    pub configuration_set: Option<String>,
    pub tags: BTreeMap<String, Vec<String>>,
}

impl MailInfo {
    fn common_headers(&self) -> Value {
        let mut c = json!({
            "from": self.from,
            "date": self.date,
            "messageId": format!("<{}@email.amazonses.com>", self.message_id),
            "subject": self.subject,
        });
        if !self.to.is_empty() {
            c["to"] = json!(self.to);
        }
        if !self.cc.is_empty() {
            c["cc"] = json!(self.cc);
        }
        if !self.reply_to.is_empty() {
            c["replyTo"] = json!(self.reply_to);
        }
        c
    }

    fn headers_json(&self) -> Value {
        Value::Array(self.headers.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect())
    }

    /// The event publishing `mail` object (always with headers and tags).
    pub fn event_json(&self) -> Value {
        json!({
            "timestamp": iso(self.timestamp),
            "source": self.source,
            "sourceArn": self.source_arn,
            "sendingAccountId": self.account,
            "messageId": self.message_id,
            "destination": self.destination,
            "headersTruncated": false,
            "headers": self.headers_json(),
            "commonHeaders": self.common_headers(),
            "tags": self.tags,
        })
    }

    /// The notification `mail` object; headers only when asked for.
    pub fn notification_json(&self, with_headers: bool) -> Value {
        let mut m = json!({
            "timestamp": iso(self.timestamp),
            "messageId": self.message_id,
            "source": self.source,
            "sourceArn": self.source_arn,
            "sourceIp": self.source_ip,
            "callerIdentity": self.caller_identity,
            "sendingAccountId": self.account,
            "destination": self.destination,
        });
        if with_headers {
            m["headersTruncated"] = json!(false);
            m["headers"] = self.headers_json();
            m["commonHeaders"] = self.common_headers();
        }
        m
    }
}

#[derive(Debug, Clone)]
pub enum EventKind {
    Send,
    /// SES rejects mail it finds a virus in; MWS scans nothing.
    #[allow(dead_code)]
    Reject {
        reason: String,
    },
    Delivery {
        recipients: Vec<String>,
    },
    /// `(address, status, diagnostic code)` per recipient.
    Bounce {
        bounce_type: String,
        sub_type: String,
        recipients: Vec<(String, String, String)>,
    },
    Complaint {
        recipients: Vec<String>,
        feedback_type: Option<String>,
    },
    RenderingFailure {
        template: String,
        error: String,
    },
    /// Mail to remote servers is never delayed in MWS.
    #[allow(dead_code)]
    DeliveryDelay {
        recipients: Vec<String>,
        delay_type: String,
    },
    Subscription {
        contact_list: String,
        recipient: String,
        topic: Option<String>,
        unsubscribe_all: bool,
    },
}

impl EventKind {
    /// The v2 event type name, as event destinations match it.
    pub fn v2_type(&self) -> &'static str {
        match self {
            EventKind::Send => "SEND",
            EventKind::Reject { .. } => "REJECT",
            EventKind::Delivery { .. } => "DELIVERY",
            EventKind::Bounce { .. } => "BOUNCE",
            EventKind::Complaint { .. } => "COMPLAINT",
            EventKind::RenderingFailure { .. } => "RENDERING_FAILURE",
            EventKind::DeliveryDelay { .. } => "DELIVERY_DELAY",
            EventKind::Subscription { .. } => "SUBSCRIPTION",
        }
    }

    fn event_type(&self) -> &'static str {
        match self {
            EventKind::Send => "Send",
            EventKind::Reject { .. } => "Reject",
            EventKind::Delivery { .. } => "Delivery",
            EventKind::Bounce { .. } => "Bounce",
            EventKind::Complaint { .. } => "Complaint",
            EventKind::RenderingFailure { .. } => "Rendering Failure",
            EventKind::DeliveryDelay { .. } => "DeliveryDelay",
            EventKind::Subscription { .. } => "Subscription",
        }
    }

    fn detail_type(&self) -> &'static str {
        match self {
            EventKind::Send => "Email Sent",
            EventKind::Reject { .. } => "Email Rejected",
            EventKind::Delivery { .. } => "Email Delivered",
            EventKind::Bounce { .. } => "Email Bounced",
            EventKind::Complaint { .. } => "Email Complaint Received",
            EventKind::RenderingFailure { .. } => "Email Rendering Failed",
            EventKind::DeliveryDelay { .. } => "Email Delivery Delayed",
            EventKind::Subscription { .. } => "Email Subscribed",
        }
    }

    fn metric(&self) -> &'static str {
        match self {
            EventKind::Send => "Send",
            EventKind::Reject { .. } => "Reject",
            EventKind::Delivery { .. } => "Delivery",
            EventKind::Bounce { .. } => "Bounce",
            EventKind::Complaint { .. } => "Complaint",
            EventKind::RenderingFailure { .. } => "RenderingFailure",
            EventKind::DeliveryDelay { .. } => "DeliveryDelay",
            EventKind::Subscription { .. } => "Subscription",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MailEvent {
    pub mail: MailInfo,
    pub kind: EventKind,
    pub time: DateTime<Utc>,
}

impl MailEvent {
    fn feedback_id(&self) -> String {
        format!("{}-{}-000000", self.mail.message_id.split('-').next().unwrap_or("0100"), uuid::Uuid::new_v4())
    }

    /// The body (`bounce`, `delivery`, ...) both formats share.
    fn body(&self, feedback_id: &str) -> (&'static str, Value) {
        let t = iso(self.time);
        match &self.kind {
            EventKind::Send => ("send", json!({})),
            EventKind::Reject { reason } => ("reject", json!({ "reason": reason })),
            EventKind::Delivery { recipients } => (
                "delivery",
                json!({
                    "timestamp": t,
                    "processingTimeMillis": (self.time - self.mail.timestamp).num_milliseconds().max(0),
                    "recipients": recipients,
                    "smtpResponse": "250 2.6.0 Message received",
                    "remoteMtaIp": "127.0.0.1",
                    "reportingMTA": REPORTING_MTA,
                }),
            ),
            EventKind::Bounce { bounce_type, sub_type, recipients } => (
                "bounce",
                json!({
                    "bounceType": bounce_type,
                    "bounceSubType": sub_type,
                    "bouncedRecipients": recipients.iter().map(|(a, s, d)| json!({
                        "emailAddress": a,
                        "action": "failed",
                        "status": s,
                        "diagnosticCode": d,
                    })).collect::<Vec<_>>(),
                    "timestamp": t,
                    "feedbackId": feedback_id,
                    "reportingMTA": format!("dns; {REPORTING_MTA}"),
                }),
            ),
            EventKind::Complaint { recipients, feedback_type } => {
                let mut c = json!({
                    "complainedRecipients": recipients.iter().map(|a| json!({ "emailAddress": a })).collect::<Vec<_>>(),
                    "timestamp": t,
                    "feedbackId": feedback_id,
                    "userAgent": "Amazon SES Mailbox Simulator",
                    "arrivalDate": t,
                });
                if let Some(f) = feedback_type {
                    c["complaintFeedbackType"] = json!(f);
                }
                ("complaint", c)
            }
            EventKind::RenderingFailure { template, error } => {
                ("failure", json!({ "templateName": template, "errorMessage": error }))
            }
            EventKind::DeliveryDelay { recipients, delay_type } => (
                "deliveryDelay",
                json!({
                    "timestamp": t,
                    "delayType": delay_type,
                    "expirationTime": iso(self.time + chrono::Duration::hours(14)),
                    "delayedRecipients": recipients.iter().map(|a| json!({
                        "emailAddress": a,
                        "status": "4.4.1",
                        "diagnosticCode": "smtp; 421 4.4.1 Unable to connect to remote host",
                    })).collect::<Vec<_>>(),
                }),
            ),
            EventKind::Subscription { contact_list, recipient, topic, unsubscribe_all } => (
                "subscription",
                json!({
                    "contactList": contact_list,
                    "timestamp": t,
                    "source": "UnsubscribeHeader",
                    "newTopicPreferences": {
                        "unsubscribeAll": unsubscribe_all,
                        "topicSubscriptionStatus": topic.iter().map(|t| json!({
                            "topicName": t,
                            "subscriptionStatus": "OptOut",
                        })).collect::<Vec<_>>(),
                    },
                    "emailAddress": recipient,
                }),
            ),
        }
    }

    /// The event publishing record.
    pub fn event_record(&self, feedback_id: &str) -> Value {
        let (key, body) = self.body(feedback_id);
        let mut v = json!({ "eventType": self.kind.event_type(), "mail": self.mail.event_json() });
        v[key] = body;
        v
    }

    /// The identity notification record, for kinds that have one.
    pub fn notification(&self, feedback_id: &str, with_headers: bool) -> Option<Value> {
        let kind = match self.kind {
            EventKind::Bounce { .. } => "Bounce",
            EventKind::Complaint { .. } => "Complaint",
            EventKind::Delivery { .. } => "Delivery",
            _ => return None,
        };
        let (key, body) = self.body(feedback_id);
        let mut v = json!({ "notificationType": kind, "mail": self.mail.notification_json(with_headers) });
        v[key] = body;
        Some(v)
    }
}

impl Ses {
    /// Tell everyone who listens about `events`, in order.
    pub(crate) fn publish_events(&self, ctx: &RequestContext, events: Vec<MailEvent>) {
        if events.is_empty() {
            return;
        }
        let links = self.links();
        for e in events {
            let feedback_id = e.feedback_id();
            let key = region_key(&e.mail.account, &e.mail.region);
            let (cs, identity, forwarding): (Option<ConfigurationSet>, Option<Identity>, bool) = {
                let mut st = self.lock();
                let r = st.regions.entry(key).or_default();
                if let Some(rec) = r.sends.iter_mut().rev().find(|s| s.message_id == e.mail.message_id) {
                    let detail = match &e.kind {
                        EventKind::Bounce { bounce_type, .. } => Some(bounce_type.clone()),
                        EventKind::Complaint { feedback_type, .. } => feedback_type.clone(),
                        _ => None,
                    };
                    for recipient in event_recipients(&e.kind) {
                        rec.events.push((recipient, e.kind.v2_type().to_string(), e.time, detail.clone()));
                    }
                    if matches!(e.kind, EventKind::Send | EventKind::Reject { .. } | EventKind::RenderingFailure { .. })
                    {
                        rec.events.push((String::new(), e.kind.v2_type().to_string(), e.time, None));
                    }
                }
                let cs = e.mail.configuration_set.as_ref().and_then(|n| r.configuration_sets.get(n).cloned());
                let identity = if e.mail.identity_account == e.mail.account || e.mail.identity_account.is_empty() {
                    r.identities.get(&e.mail.identity).cloned()
                } else {
                    st.regions
                        .get(&region_key(&e.mail.identity_account, &e.mail.region))
                        .and_then(|o| o.identities.get(&e.mail.identity).cloned())
                };
                let forwarding = identity.as_ref().is_none_or(|i| i.feedback_forwarding);
                (cs, identity, forwarding)
            };
            let wctx = RequestContext { region: e.mail.region.clone(), ..ctx.clone() };
            // Event destinations.
            if let Some(cs) = &cs {
                let cs_arn = names::arn_in(
                    &e.mail.partition,
                    &e.mail.region,
                    &e.mail.account,
                    &format!("configuration-set/{}", cs.name),
                );
                let record = e.event_record(&feedback_id);
                for d in cs.event_destinations.iter().filter(|d| d.enabled) {
                    if !d.matching_event_types.iter().any(|t| t == e.kind.v2_type()) {
                        continue;
                    }
                    if let Some(topic) = &d.sns {
                        if let Err(err) =
                            links.publish_sns(&wctx, topic, None, record.to_string(), &e.mail.account, &cs_arn)
                        {
                            tracing::info!(topic, "SES could not publish an event: {err}");
                        }
                    }
                    if let Some(f) = &d.firehose {
                        let mut data = record.to_string().into_bytes();
                        data.push(b'\n');
                        if let Err(err) = links.put_firehose(
                            &wctx,
                            &f.iam_role_arn,
                            &f.delivery_stream_arn,
                            data,
                            &e.mail.account,
                            &cs_arn,
                        ) {
                            tracing::info!(stream = f.delivery_stream_arn, "SES could not deliver an event: {err}");
                        }
                    }
                    if d.eventbridge.is_some() {
                        links.put_event(
                            &wctx,
                            BusEvent {
                                account: e.mail.account.clone(),
                                region: e.mail.region.clone(),
                                detail_type: e.kind.detail_type().into(),
                                resources: vec![cs_arn.clone()],
                                detail: record.clone(),
                                time: e.time,
                            },
                        );
                    }
                    if let Some(cw) = &d.cloudwatch {
                        let dims = cw
                            .dimension_configurations
                            .iter()
                            .map(|c| {
                                let value = match c.dimension_value_source.as_str() {
                                    "MESSAGE_TAG" => {
                                        e.mail.tags.get(&c.dimension_name).and_then(|v| v.first().cloned())
                                    }
                                    "EMAIL_HEADER" => e
                                        .mail
                                        .headers
                                        .iter()
                                        .find(|(k, _)| k.eq_ignore_ascii_case(&c.dimension_name))
                                        .map(|(_, v)| v.clone()),
                                    _ => None,
                                };
                                (c.dimension_name.clone(), value.unwrap_or_else(|| c.default_dimension_value.clone()))
                            })
                            .collect();
                        links.put_metric(Metric {
                            account: e.mail.account.clone(),
                            region: e.mail.region.clone(),
                            namespace: "AWS/SES".into(),
                            name: e.kind.metric().into(),
                            dimensions: dims,
                            value: metric_count(&e.kind),
                            unit: "Count".into(),
                            time: e.time,
                        });
                    }
                }
            }
            // Identity notifications.
            if let Some(i) = &identity {
                let (topic, headers) = match e.kind {
                    EventKind::Bounce { .. } => (i.bounce_topic.as_ref(), i.headers_in_bounce),
                    EventKind::Complaint { .. } => (i.complaint_topic.as_ref(), i.headers_in_complaint),
                    EventKind::Delivery { .. } => (i.delivery_topic.as_ref(), i.headers_in_delivery),
                    _ => (None, false),
                };
                if let (Some(topic), Some(n)) = (topic, e.notification(&feedback_id, headers)) {
                    let owner =
                        if e.mail.identity_account.is_empty() { &e.mail.account } else { &e.mail.identity_account };
                    let arn = names::arn_in(&e.mail.partition, &e.mail.region, owner, &format!("identity/{}", i.name));
                    if let Err(err) = links.publish_sns(&wctx, topic, None, n.to_string(), owner, &arn) {
                        tracing::info!(topic, "SES could not publish a notification: {err}");
                    }
                }
            }
            // Feedback forwarding: bounces and complaints mailed back.
            if forwarding && matches!(e.kind, EventKind::Bounce { .. } | EventKind::Complaint { .. }) {
                self.forward_feedback(&wctx, &e);
            }
            // Account-wide metrics.
            if !matches!(e.kind, EventKind::Subscription { .. }) {
                links.put_metric(Metric {
                    account: e.mail.account.clone(),
                    region: e.mail.region.clone(),
                    namespace: "AWS/SES".into(),
                    name: e.kind.metric().into(),
                    dimensions: Vec::new(),
                    value: metric_count(&e.kind),
                    unit: "Count".into(),
                    time: e.time,
                });
            }
            // Bounces and complaints go on the account's suppression list.
            self.suppress_from_event(&e, &cs, &feedback_id);
        }
    }

    fn suppress_from_event(&self, e: &MailEvent, cs: &Option<ConfigurationSet>, feedback_id: &str) {
        let (reason, addrs): (&str, Vec<String>) = match &e.kind {
            EventKind::Bounce { bounce_type, sub_type, recipients }
                if bounce_type == "Permanent" && !sub_type.starts_with("On") && sub_type != "Suppressed" =>
            {
                ("BOUNCE", recipients.iter().map(|r| r.0.clone()).collect())
            }
            EventKind::Complaint { recipients, .. } => ("COMPLAINT", recipients.clone()),
            _ => return,
        };
        let mut st = self.lock();
        let r = st.regions.entry(region_key(&e.mail.account, &e.mail.region)).or_default();
        let reasons = match cs.as_ref().and_then(|c| c.suppression.as_ref()).and_then(|s| s.suppressed_reasons.clone())
        {
            Some(r) => r,
            None => r.account.suppressed_reasons.clone(),
        };
        if !reasons.iter().any(|x| x == reason) {
            return;
        }
        for a in addrs.into_iter().filter(|a| !names::is_simulator(a)) {
            r.suppressed.insert(
                a.to_ascii_lowercase(),
                crate::state::Suppressed {
                    email: a,
                    reason: reason.into(),
                    last_update: e.time,
                    message_id: Some(e.mail.message_id.clone()),
                    feedback_id: Some(feedback_id.to_string()),
                    tenant: None,
                },
            );
        }
    }

    fn forward_feedback(&self, ctx: &RequestContext, e: &MailEvent) {
        let to = e.mail.source.clone();
        let (subject, text) = match &e.kind {
            EventKind::Bounce { recipients, .. } => (
                "Delivery Status Notification (Failure)".to_string(),
                format!(
                    "An error occurred while trying to deliver the mail to the following recipients:\r\n{}\r\n",
                    recipients.iter().map(|r| format!("{} ({})", r.0, r.2)).collect::<Vec<_>>().join("\r\n")
                ),
            ),
            EventKind::Complaint { recipients, .. } => (
                "Complaint about your message".to_string(),
                format!("The following recipients complained about your message:\r\n{}\r\n", recipients.join("\r\n")),
            ),
            _ => return,
        };
        let mut st = self.lock();
        crate::outbox::system_mail(
            &mut st,
            ctx,
            &e.mail.account,
            "MAILER-DAEMON@amazonses.com",
            &to,
            &subject,
            &text,
            "FeedbackForwarding",
        );
    }
}

fn metric_count(kind: &EventKind) -> f64 {
    match kind {
        EventKind::Delivery { recipients } => recipients.len() as f64,
        EventKind::Bounce { recipients, .. } => recipients.len() as f64,
        EventKind::Complaint { recipients, .. } => recipients.len() as f64,
        _ => 1.0,
    }
}

fn event_recipients(kind: &EventKind) -> Vec<String> {
    match kind {
        EventKind::Delivery { recipients } | EventKind::Complaint { recipients, .. } => recipients.clone(),
        EventKind::DeliveryDelay { recipients, .. } => recipients.clone(),
        EventKind::Bounce { recipients, .. } => recipients.iter().map(|r| r.0.clone()).collect(),
        _ => Vec::new(),
    }
}
