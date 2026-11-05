//! Email receiving: the active receipt rule set of the account and Region
//! that hosts a recipient acts on mail arriving over SMTP, through
//! `POST /_aws/ses/inbound`, or sent through SES itself to such an address.

use std::collections::BTreeMap;

use base64::Engine;
use chrono::Utc;
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::events::{EventKind, MailEvent, MailInfo};
use crate::names;
use crate::outbox::{self, ReceivedMessage};
use crate::public::S3Put;
use crate::receipt::{cidr_contains, rule_arn};
use crate::send::hosted_in;
use crate::state::split_region_key;
use crate::v1::types as t1;
use crate::Ses;

/// The largest message SES accepts, and the largest an SNS action carries.
pub const MAX_MESSAGE: usize = 40 * 1024 * 1024;
const MAX_SNS_CONTENT: usize = 150 * 1024;

/// A message arriving for receiving.
#[derive(Debug, Clone)]
pub struct Inbound {
    pub raw: Vec<u8>,
    /// The SMTP envelope sender (`MAIL FROM`).
    pub mail_from: String,
    /// The SMTP envelope recipients (`RCPT TO`).
    pub recipients: Vec<String>,
    pub source_ip: String,
    pub tls: bool,
    /// The message as sent, when it was sent through SES in this emulator:
    /// bounce actions then raise the sender's bounce events.
    pub origin: Option<MailInfo>,
}

/// What receiving did with a message.
#[derive(Debug, Clone, Default)]
pub struct Received {
    pub message_id: String,
    pub accepted: Vec<String>,
    pub rejected: Vec<String>,
}

/// An SMTP error: reply code and text.
pub type SmtpError = (u16, String);

/// Whether a rule's recipient condition matches `address`: an address, a
/// domain, or `.domain` for its subdomains.
pub fn recipient_matches(condition: &str, address: &str) -> bool {
    let c = condition.to_ascii_lowercase();
    let a = address.to_ascii_lowercase();
    if c.contains('@') {
        return c == a;
    }
    let Some(domain) = names::domain_of(&a) else { return false };
    match c.strip_prefix('.') {
        Some(parent) => domain.ends_with(&format!(".{parent}")),
        None => domain == c,
    }
}

/// Whether `ip` may connect, given a Region's IP filters: an `Allow`
/// filter wins over a `Block` one.
pub fn ip_allowed(filters: &[t1::ReceiptFilter], ip: &str) -> bool {
    let allowed = filters.iter().any(|f| f.ip_filter.policy == "Allow" && cidr_contains(&f.ip_filter.cidr, ip));
    let blocked = filters.iter().any(|f| f.ip_filter.policy == "Block" && cidr_contains(&f.ip_filter.cidr, ip));
    allowed || !blocked
}

/// SES's receiving message ids: 40 lower-case letters and digits.
fn receiving_message_id() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..40).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

/// `ctx` as the account `account` in `region`, for the work receiving does
/// on its behalf.
fn context_for(ctx: &RequestContext, account: &str, region: &str) -> RequestContext {
    let mut c = ctx.clone();
    c.region = region.to_string();
    c.caller = mws_core::Caller {
        account_id: account.to_string(),
        arn: format!("arn:{}:iam::{account}:root", ctx.partition),
        user_id: account.to_string(),
        access_key_id: String::new(),
        kind: mws_core::CallerKind::Root,
        session: None,
    };
    c
}

/// The parts of one received message that rules and notifications use.
struct Message {
    id: String,
    raw: Vec<u8>,
    mail_from: String,
    timestamp: chrono::DateTime<Utc>,
    verdict: &'static str,
}

impl Message {
    fn mail_json(&self, destination: &[String]) -> Value {
        let parsed = crate::mime::parse(&self.raw);
        let headers: Vec<Value> = parsed.headers.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect();
        let mut common = serde_json::Map::new();
        common.insert("returnPath".into(), json!(self.mail_from));
        for (key, header) in [
            ("from", "From"),
            ("to", "To"),
            ("cc", "Cc"),
            ("bcc", "Bcc"),
            ("replyTo", "Reply-To"),
            ("sender", "Sender"),
        ] {
            let a = parsed.addresses(header);
            if !a.is_empty() {
                common.insert(key.into(), json!(a));
            }
        }
        if let Some(d) = parsed.header("Date") {
            common.insert("date".into(), json!(d));
        }
        if let Some(m) = parsed.header("Message-ID") {
            common.insert("messageId".into(), json!(m));
        }
        common.insert("subject".into(), json!(parsed.subject()));
        json!({
            "timestamp": names::iso(self.timestamp),
            "source": self.mail_from,
            "messageId": self.id,
            "destination": destination,
            "headersTruncated": false,
            "headers": headers,
            "commonHeaders": common,
        })
    }

    fn receipt_json(&self, recipients: &[String], action: Value, now: chrono::DateTime<Utc>) -> Value {
        let verdict = |s: &str| json!({ "status": s });
        json!({
            "timestamp": names::iso(self.timestamp),
            "processingTimeMillis": (now - self.timestamp).num_milliseconds().max(1),
            "recipients": recipients,
            "spamVerdict": verdict("PASS"),
            "virusVerdict": verdict("PASS"),
            "spfVerdict": verdict(self.verdict),
            "dkimVerdict": verdict(self.verdict),
            "dmarcVerdict": verdict(self.verdict),
            "action": action,
        })
    }

    /// The `Received` notification SES publishes to an action's topic.
    fn notification(
        &self,
        recipients: &[String],
        destination: &[String],
        action: Value,
        content: Option<String>,
    ) -> String {
        let mut n = json!({
            "notificationType": "Received",
            "mail": self.mail_json(destination),
            "receipt": self.receipt_json(recipients, action, Utc::now()),
        });
        if let Some(c) = content {
            n["content"] = json!(c);
        }
        n.to_string()
    }
}

impl Ses {
    /// Receive one message: run the active receipt rule set of each
    /// account and Region hosting a recipient.
    pub(crate) async fn receive(&self, ctx: &RequestContext, inbound: Inbound) -> Result<Received, SmtpError> {
        if inbound.raw.len() > MAX_MESSAGE {
            return Err((552, "5.3.4 Message too big".into()));
        }
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut rejected = Vec::new();
        {
            let st = self.lock();
            for r in &inbound.recipients {
                let r = names::bare_address(r);
                match hosted_in(&st, &r) {
                    Some(key) => groups.entry(key).or_default().push(r),
                    None => rejected.push(r),
                }
            }
        }
        if groups.is_empty() {
            return Err((550, "5.1.1 Requested action not taken: mailbox unavailable".into()));
        }
        let message_id = receiving_message_id();
        let mut accepted = Vec::new();
        for (key, recipients) in groups {
            let (account, region) = split_region_key(&key);
            let rctx = context_for(ctx, account, region);
            let filters = self.lock().regions.get(&key).map(|r| r.receipt_filters.clone()).unwrap_or_default();
            if !ip_allowed(&filters, &inbound.source_ip) {
                rejected.extend(recipients);
                continue;
            }
            self.run_rules(&rctx, &key, &message_id, &inbound, &recipients).await;
            accepted.extend(recipients);
        }
        if accepted.is_empty() {
            return Err((554, "5.7.1 Access denied".into()));
        }
        Ok(Received { message_id, accepted, rejected })
    }

    async fn run_rules(
        &self,
        ctx: &RequestContext,
        key: &str,
        message_id: &str,
        inbound: &Inbound,
        recipients: &[String],
    ) {
        let (rule_set, rules) = {
            let st = self.lock();
            let Some(r) = st.regions.get(key) else { return };
            let Some(name) = r.active_rule_set.clone() else { return };
            let rules = r.rule_sets.get(&name).map(|s| s.rules.clone()).unwrap_or_default();
            (name, rules)
        };
        let now = ctx.received_at;
        let parsed = crate::mime::parse(&inbound.raw);
        let mut prefix = vec![(
            "Received".to_string(),
            format!(
                "from {} ([{}]) by inbound-smtp.{}.amazonaws.com with SMTP id {message_id} for {}; {}",
                names::domain_of(&inbound.mail_from).unwrap_or_else(|| "localhost".into()),
                inbound.source_ip,
                ctx.region,
                recipients.join(", "),
                now.to_rfc2822()
            ),
        )];
        if parsed.header("Return-Path").is_none() {
            prefix.insert(0, ("Return-Path".to_string(), format!("<{}>", inbound.mail_from)));
        }
        let mut msg = Message {
            id: message_id.to_string(),
            raw: crate::mime::prepend_headers(&inbound.raw, &prefix),
            mail_from: inbound.mail_from.clone(),
            timestamp: now,
            verdict: if inbound.origin.is_some() { "PASS" } else { "GRAY" },
        };
        let account = ctx.caller.account_id.clone();
        let links = self.links();
        let mut matched = Vec::new();
        let mut notes = Vec::new();
        let mut bounced: Vec<(String, String, String)> = Vec::new();
        'rules: for rule in rules.iter().filter(|r| r.enabled) {
            let conditions = rule.recipients.as_deref().unwrap_or_default();
            let mine: Vec<String> = recipients
                .iter()
                .filter(|a| conditions.is_empty() || conditions.iter().any(|c| recipient_matches(c, a)))
                .cloned()
                .collect();
            if mine.is_empty() {
                continue;
            }
            matched.push(rule.name.clone());
            if rule.tls_policy.as_deref() == Some("Require") && !inbound.tls {
                notes.push(format!("{}: bounced, TLS required", rule.name));
                for m in &mine {
                    bounced.push((
                        m.clone(),
                        "5.7.1".into(),
                        "smtp; 530 5.7.0 Must issue a STARTTLS command first".into(),
                    ));
                }
                continue;
            }
            if rule.scan_enabled {
                msg.raw = crate::mime::prepend_headers(
                    &msg.raw,
                    &[
                        ("X-SES-Spam-Verdict".to_string(), "PASS".to_string()),
                        ("X-SES-Virus-Verdict".to_string(), "PASS".to_string()),
                    ],
                );
            }
            let source_arn = rule_arn(&ctx.partition, &ctx.region, &account, &rule_set, &rule.name);
            let notify = |topic: &Option<String>, action: Value, content: Option<String>, msg: &Message| {
                if let Some(t) = topic {
                    let n = msg.notification(&mine, recipients, action, content);
                    if let Err(e) = links.publish_sns(
                        ctx,
                        t,
                        Some("Amazon SES Email Receipt Notification"),
                        n,
                        &account,
                        &source_arn,
                    ) {
                        tracing::info!("SES receipt notification to {t} failed: {e}");
                    }
                }
            };
            for action in rule.actions.as_deref().unwrap_or_default() {
                if let Some(s3) = &action.s3_action {
                    let key = format!("{}{}", s3.object_key_prefix.as_deref().unwrap_or_default(), msg.id);
                    let put = S3Put {
                        bucket: &s3.bucket_name,
                        key: &key,
                        body: msg.raw.clone(),
                        source_account: &account,
                        source_arn: &source_arn,
                        kms_key_arn: s3.kms_key_arn.as_deref(),
                        role_arn: s3.iam_role_arn.as_deref(),
                    };
                    match links.put_s3(ctx, put).await {
                        Ok(()) => notes.push(format!("{}: S3 {}/{key}", rule.name, s3.bucket_name)),
                        Err(e) => notes.push(format!("{}: S3 {}/{key} failed: {e}", rule.name, s3.bucket_name)),
                    }
                    let mut a = json!({ "type": "S3", "bucketName": s3.bucket_name, "objectKey": key });
                    if let Some(t) = &s3.topic_arn {
                        a["topicArn"] = json!(t);
                    }
                    if let Some(p) = &s3.object_key_prefix {
                        a["objectKeyPrefix"] = json!(p);
                    }
                    notify(&s3.topic_arn, a, None, &msg);
                }
                if let Some(sns) = &action.sns_action {
                    let encoding = sns.encoding.clone().unwrap_or_else(|| "UTF-8".into());
                    if msg.raw.len() > MAX_SNS_CONTENT {
                        notes.push(format!("{}: SNS {} skipped, message over 150 KB", rule.name, sns.topic_arn));
                    } else {
                        let content = if encoding == "Base64" {
                            base64::engine::general_purpose::STANDARD.encode(&msg.raw)
                        } else {
                            String::from_utf8_lossy(&msg.raw).into_owned()
                        };
                        let a = json!({ "type": "SNS", "topicArn": sns.topic_arn, "encoding": encoding });
                        let n = msg.notification(&mine, recipients, a, Some(content));
                        match links.publish_sns(
                            ctx,
                            &sns.topic_arn,
                            Some("Amazon SES Email Receipt Notification"),
                            n,
                            &account,
                            &source_arn,
                        ) {
                            Ok(()) => notes.push(format!("{}: SNS {}", rule.name, sns.topic_arn)),
                            Err(e) => notes.push(format!("{}: SNS {} failed: {e}", rule.name, sns.topic_arn)),
                        }
                    }
                }
                if let Some(l) = &action.lambda_action {
                    let invocation = l.invocation_type.clone().unwrap_or_else(|| "Event".into());
                    let mut a =
                        json!({ "type": "Lambda", "functionArn": l.function_arn, "invocationType": invocation });
                    if let Some(t) = &l.topic_arn {
                        a["topicArn"] = json!(t);
                    }
                    let event = json!({
                        "Records": [{
                            "eventSource": "aws:ses",
                            "eventVersion": "1.0",
                            "ses": {
                                "mail": msg.mail_json(recipients),
                                "receipt": msg.receipt_json(&mine, a.clone(), Utc::now()),
                            },
                        }],
                    });
                    let sync = invocation == "RequestResponse";
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        links.invoke_lambda(
                            ctx,
                            &l.function_arn,
                            event.to_string().into_bytes(),
                            sync,
                            &account,
                            &source_arn,
                        ),
                    )
                    .await
                    .unwrap_or_else(|_| Err("timed out after 30 seconds".into()));
                    notify(&l.topic_arn, a, None, &msg);
                    match result {
                        Err(e) => notes.push(format!("{}: Lambda {} failed: {e}", rule.name, l.function_arn)),
                        Ok(out) => {
                            let disposition =
                                out.and_then(|o| serde_json::from_slice::<Value>(&o).ok()).and_then(|v| {
                                    v.get("disposition").and_then(Value::as_str).map(str::to_ascii_uppercase)
                                });
                            notes.push(format!(
                                "{}: Lambda {}{}",
                                rule.name,
                                l.function_arn,
                                disposition.as_deref().map(|d| format!(" {d}")).unwrap_or_default()
                            ));
                            if sync {
                                match disposition.as_deref() {
                                    Some("STOP_RULE") => continue 'rules,
                                    Some("STOP_RULE_SET") => break 'rules,
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                if let Some(b) = &action.bounce_action {
                    let status = b.status_code.clone().unwrap_or_else(|| "5.0.0".into());
                    let text = format!(
                        "{}\r\n\r\nReporting-MTA: dns; inbound-smtp.{}.amazonaws.com\r\n\r\n{}\r\n",
                        b.message,
                        ctx.region,
                        mine.iter()
                            .map(|r| format!("Final-Recipient: rfc822; {r}\r\nAction: failed\r\nStatus: {status}\r\nDiagnostic-Code: smtp; {} {}", b.smtp_reply_code, b.message))
                            .collect::<Vec<_>>()
                            .join("\r\n\r\n")
                    );
                    {
                        let mut st = self.lock();
                        outbox::system_mail(
                            &mut st,
                            ctx,
                            &account,
                            &b.sender,
                            &inbound.mail_from,
                            "Delivery Status Notification (Failure)",
                            &text,
                            "Bounce",
                        );
                    }
                    for m in &mine {
                        bounced.push((m.clone(), status.clone(), format!("smtp; {} {}", b.smtp_reply_code, b.message)));
                    }
                    notes.push(format!("{}: Bounce to {}", rule.name, inbound.mail_from));
                    let mut a = json!({ "type": "Bounce", "smtpReplyCode": b.smtp_reply_code, "statusCode": status, "message": b.message, "sender": b.sender });
                    if let Some(t) = &b.topic_arn {
                        a["topicArn"] = json!(t);
                    }
                    notify(&b.topic_arn, a, None, &msg);
                }
                if let Some(h) = &action.add_header_action {
                    msg.raw =
                        crate::mime::prepend_headers(&msg.raw, &[(h.header_name.clone(), h.header_value.clone())]);
                    notes.push(format!("{}: AddHeader {}", rule.name, h.header_name));
                }
                if let Some(w) = &action.workmail_action {
                    notes.push(format!("{}: WorkMail {} not emulated", rule.name, w.organization_arn));
                    notify(
                        &w.topic_arn,
                        json!({ "type": "WorkMail", "organizationArn": w.organization_arn }),
                        None,
                        &msg,
                    );
                }
                if let Some(c) = &action.connect_action {
                    notes.push(format!("{}: Connect {} not emulated", rule.name, c.instance_arn));
                }
                if let Some(s) = &action.stop_action {
                    let mut a = json!({ "type": "Stop", "scope": s.scope });
                    if let Some(t) = &s.topic_arn {
                        a["topicArn"] = json!(t);
                    }
                    notify(&s.topic_arn, a, None, &msg);
                    notes.push(format!("{}: Stop", rule.name));
                    break 'rules;
                }
            }
        }
        let subject = crate::mime::parse(&msg.raw).subject();
        {
            let mut st = self.lock();
            outbox::push_received(
                &mut st,
                ReceivedMessage {
                    message_id: msg.id.clone(),
                    account_id: account.clone(),
                    region: ctx.region.clone(),
                    timestamp: names::iso(now),
                    source: inbound.mail_from.clone(),
                    recipients: recipients.to_vec(),
                    subject,
                    rule_set,
                    matched_rules: matched,
                    actions: notes,
                    raw_data: String::from_utf8_lossy(&msg.raw).into_owned(),
                },
            );
        }
        // A bounce of mail sent through SES is a bounce event for its sender.
        if let (Some(origin), false) = (&inbound.origin, bounced.is_empty()) {
            let sender_ctx = context_for(ctx, &origin.account, &origin.region);
            self.publish_events(
                &sender_ctx,
                vec![MailEvent {
                    mail: origin.clone(),
                    kind: EventKind::Bounce {
                        bounce_type: "Permanent".into(),
                        sub_type: "General".into(),
                        recipients: bounced,
                    },
                    time: Utc::now(),
                }],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipients() {
        assert!(recipient_matches("example.com", "a@example.com"));
        assert!(!recipient_matches("example.com", "a@sub.example.com"));
        assert!(recipient_matches(".example.com", "a@sub.example.com"));
        assert!(!recipient_matches(".example.com", "a@example.com"));
        assert!(recipient_matches("A@Example.com", "a@example.com"));
    }

    #[test]
    fn filters() {
        let f = |name: &str, policy: &str, cidr: &str| t1::ReceiptFilter {
            name: name.into(),
            ip_filter: t1::ReceiptIpFilter { policy: policy.into(), cidr: cidr.into() },
        };
        let filters = vec![f("block", "Block", "10.0.0.0/8"), f("allow", "Allow", "10.1.0.0/16")];
        assert!(!ip_allowed(&filters, "10.2.3.4"));
        assert!(ip_allowed(&filters, "10.1.3.4"));
        assert!(ip_allowed(&filters, "127.0.0.1"));
    }
}
