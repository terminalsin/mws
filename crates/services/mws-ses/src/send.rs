//! Sending: every check SES makes before it accepts a message, then the
//! message goes to the outbox, events are published, the mailbox
//! simulator and suppression list act, and mail to addresses this emulator
//! receives for is handed to receiving.

use std::collections::BTreeMap;

use chrono::Duration;
use mws_core::{ConditionContext, ErrorValue, RequestContext, ServiceError};

use crate::events::{EventKind, MailEvent, MailInfo};
use crate::mime;
use crate::names;
use crate::outbox::{self, OutboxMessage};
use crate::receive::Inbound;
use crate::state::region_key;
use crate::state::{Region, SendRecord, State, Template, UnsubscribeLink};
use crate::templates::{self, Rendered};
use crate::v1::types as t1;
use crate::v2::types as t2;
use crate::{v1, v2, Ses};

const MAX_RECIPIENTS: usize = 50;
const SANDBOX_QUOTA: f64 = 200.0;
const PRODUCTION_QUOTA: f64 = 50_000.0;

/// What a message is made of.
#[derive(Debug, Clone)]
pub enum Content {
    Simple { subject: String, text: Option<String>, html: Option<String> },
    Raw(Vec<u8>),
    Template { name: Option<String>, arn: Option<String>, inline: Option<t2::EmailTemplateContent>, data: String },
}

/// One message to send, from either API.
#[derive(Debug, Clone)]
pub struct Outgoing {
    pub version: &'static str,
    pub action: &'static str,
    pub from: String,
    pub source_arn: Option<String>,
    pub feedback_address: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    /// Envelope recipients of a raw message given apart from its headers.
    pub envelope: Option<Vec<String>>,
    pub reply_to: Vec<String>,
    pub content: Content,
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<mime::Attachment>,
    pub tags: Vec<(String, String)>,
    pub configuration_set: Option<String>,
    pub tenant: Option<String>,
    pub list_management: Option<(String, Option<String>)>,
}

impl Outgoing {
    pub fn new(version: &'static str, action: &'static str, from: String, content: Content) -> Self {
        Self {
            version,
            action,
            from,
            source_arn: None,
            feedback_address: None,
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            envelope: None,
            reply_to: Vec::new(),
            content,
            headers: Vec::new(),
            attachments: Vec::new(),
            tags: Vec::new(),
            configuration_set: None,
            tenant: None,
            list_management: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SendError {
    Invalid(String),
    Rejected(String),
    AccountPaused,
    SetPaused(String),
    NoSet(String),
    NoTemplate(String),
    MailFromNotVerified(String),
    Quota,
    /// More messages in the last second than the maximum send rate.
    Throttled,
    NotFound(String),
    Denied(ServiceError),
}

impl SendError {
    pub fn v1(self) -> ServiceError {
        match self {
            SendError::Invalid(m) => names::invalid_parameter(m),
            SendError::Rejected(m) => v1::errors::message_rejected(m),
            SendError::AccountPaused => {
                v1::errors::account_sending_paused("Email sending is disabled for this account.")
            }
            SendError::SetPaused(n) => v1::errors::configuration_set_sending_paused(format!(
                "Email sending is disabled for configuration set {n}."
            ))
            .with_field("ConfigurationSetName", ErrorValue::String(n)),
            SendError::NoSet(n) => {
                v1::errors::configuration_set_does_not_exist(format!("Configuration set <{n}> does not exist."))
                    .with_field("ConfigurationSetName", ErrorValue::String(n))
            }
            SendError::NoTemplate(n) => v1::errors::template_does_not_exist(format!("Template {n} does not exist."))
                .with_field("TemplateName", ErrorValue::String(n)),
            SendError::MailFromNotVerified(m) => v1::errors::mail_from_domain_not_verified(m),
            SendError::Quota => ServiceError::client("Throttling", 400, "Daily message quota exceeded."),
            SendError::Throttled => ServiceError::client("Throttling", 400, "Maximum sending rate exceeded."),
            SendError::NotFound(m) => names::invalid_parameter(m),
            SendError::Denied(e) => e,
        }
    }

    pub fn v2(self) -> ServiceError {
        match self {
            SendError::Invalid(m) => v2::errors::bad_request(m),
            SendError::Rejected(m) => v2::errors::message_rejected(m),
            SendError::AccountPaused => v2::errors::sending_paused("Email sending is disabled for this account."),
            SendError::SetPaused(n) => {
                v2::errors::sending_paused(format!("Email sending is disabled for configuration set {n}."))
            }
            SendError::NoSet(n) => v2::errors::not_found(format!("Configuration set <{n}> does not exist.")),
            SendError::NoTemplate(n) => v2::errors::not_found(format!("Template {n} does not exist.")),
            SendError::MailFromNotVerified(m) => v2::errors::mail_from_domain_not_verified(m),
            SendError::Quota => v2::errors::limit_exceeded("Daily message quota exceeded."),
            SendError::Throttled => v2::errors::too_many_requests("Maximum sending rate exceeded."),
            SendError::NotFound(m) => v2::errors::not_found(m),
            SendError::Denied(e) => e,
        }
    }

    fn v1_bulk_status(&self) -> &'static str {
        match self {
            SendError::Invalid(_) => "InvalidParameterValue",
            SendError::Rejected(_) => "MessageRejected",
            SendError::AccountPaused => "AccountSendingPaused",
            SendError::SetPaused(_) => "ConfigurationSetSendingPaused",
            SendError::NoSet(_) => "ConfigurationSetDoesNotExist",
            SendError::NoTemplate(_) => "TemplateDoesNotExist",
            SendError::MailFromNotVerified(_) => "MailFromDomainNotVerified",
            SendError::Quota => "AccountDailyQuotaExceeded",
            SendError::Throttled => "AccountThrottled",
            SendError::NotFound(_) | SendError::Denied(_) => "Failed",
        }
    }

    fn v2_bulk_status(&self) -> &'static str {
        match self {
            SendError::Invalid(_) => "INVALID_PARAMETER",
            SendError::Rejected(_) => "MESSAGE_REJECTED",
            SendError::AccountPaused => "ACCOUNT_SENDING_PAUSED",
            SendError::SetPaused(_) => "CONFIGURATION_SET_SENDING_PAUSED",
            SendError::NoSet(_) => "CONFIGURATION_SET_NOT_FOUND",
            SendError::NoTemplate(_) => "TEMPLATE_NOT_FOUND",
            SendError::MailFromNotVerified(_) => "MAIL_FROM_DOMAIN_NOT_VERIFIED",
            SendError::Quota => "ACCOUNT_DAILY_QUOTA_EXCEEDED",
            SendError::Throttled => "ACCOUNT_THROTTLED",
            SendError::NotFound(_) | SendError::Denied(_) => "FAILED",
        }
    }

    pub fn message(&self) -> String {
        match self {
            SendError::Denied(e) => e.message.clone(),
            other => other.clone().v1().message,
        }
    }
}

/// What a send produced, to be acted on after the state lock is gone.
pub struct Sent {
    pub message_id: String,
    pub events: Vec<MailEvent>,
    pub local: Vec<Inbound>,
}

/// The local part without `+label`, for the mailbox simulator.
fn simulator_box(address: &str) -> Option<String> {
    if !names::is_simulator(address) {
        return None;
    }
    let addr = names::bare_address(address);
    let local = addr.split('@').next().unwrap_or("").to_ascii_lowercase();
    Some(local.split('+').next().unwrap_or("").to_string())
}

/// Recipients sent to in the last 24 hours.
pub fn sent_last_24h(r: &Region, now: chrono::DateTime<chrono::Utc>) -> f64 {
    r.sends
        .iter()
        .filter(|s| !s.rejected && now - s.timestamp < Duration::hours(24))
        .map(|s| s.recipients.len() as f64)
        .sum()
}

/// Recipients of messages accepted in the second before `now`: what the
/// maximum send rate is measured against.
pub fn sent_last_second(r: &Region, now: chrono::DateTime<chrono::Utc>) -> f64 {
    r.sends
        .iter()
        .rev()
        .take_while(|s| now - s.timestamp < Duration::seconds(1))
        .filter(|s| !s.rejected && s.timestamp <= now)
        .map(|s| s.recipients.len() as f64)
        .sum()
}

pub fn max_24h(r: &Region) -> f64 {
    if r.account.production_access {
        PRODUCTION_QUOTA
    } else {
        SANDBOX_QUOTA
    }
}

pub fn max_rate(r: &Region) -> f64 {
    if r.account.production_access {
        14.0
    } else {
        1.0
    }
}

/// Where in the emulator mail to `address` is received, if anywhere: the
/// `account:region` with an active rule set and a verified identity for
/// the address or its domain.
pub fn hosted_in(st: &State, address: &str) -> Option<String> {
    let addr = names::bare_address(address);
    for (key, r) in &st.regions {
        if r.active_rule_set.is_none() {
            continue;
        }
        if crate::identities::sending_identity(r, &addr).is_some() {
            return Some(key.clone());
        }
    }
    None
}

impl Ses {
    /// Send one message; publish its events and start local deliveries.
    pub(crate) fn send(&self, ctx: &RequestContext, out: Outgoing) -> Result<String, SendError> {
        let sent = self.prepare(ctx, out)?;
        let id = sent.message_id.clone();
        self.finish(ctx, sent);
        Ok(id)
    }

    pub(crate) fn finish(&self, ctx: &RequestContext, sent: Sent) {
        self.publish_events(ctx, sent.events);
        for inbound in sent.local {
            let ses = self.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err((code, m)) = ses.receive(&ctx, inbound).await {
                    tracing::info!(code, "SES receiving refused locally sent mail: {m}");
                }
            });
        }
    }

    /// Check, record and compose a message.
    fn prepare(&self, ctx: &RequestContext, mut out: Outgoing) -> Result<Sent, SendError> {
        // The message itself: raw messages name their own addresses.
        let mut parsed_raw = None;
        if let Content::Raw(raw) = &out.content {
            let limit = if out.version == "1" { 10 * 1024 * 1024 } else { 40 * 1024 * 1024 };
            if raw.len() > limit {
                return Err(SendError::Rejected(format!(
                    "Message length is more than {limit} bytes long: '{}'.",
                    raw.len()
                )));
            }
            let p = mime::parse(raw);
            if out.from.is_empty() {
                out.from = p.header("From").map(mime::decode_header).unwrap_or_default();
            }
            if out.reply_to.is_empty() {
                out.reply_to = p.addresses("Reply-To");
            }
            out.to = p.addresses("To");
            out.cc = p.addresses("Cc");
            out.bcc = p.addresses("Bcc");
            parsed_raw = Some(p);
        }
        if out.from.trim().is_empty() {
            return Err(SendError::Invalid("Missing required header 'From'.".into()));
        }
        let recipients: Vec<String> = match &out.envelope {
            Some(e) if !e.is_empty() => e.clone(),
            _ => out.to.iter().chain(&out.cc).chain(&out.bcc).cloned().collect(),
        };
        if recipients.is_empty() {
            return Err(SendError::Invalid("Missing required header 'To'.".into()));
        }
        if recipients.len() > MAX_RECIPIENTS {
            return Err(SendError::Invalid(format!("Recipient count exceeds {MAX_RECIPIENTS}.")));
        }
        for a in recipients.iter().chain(std::iter::once(&out.from)).chain(&out.reply_to) {
            names::check_address(a).map_err(SendError::Invalid)?;
        }
        let from_addr = names::bare_address(&out.from);
        let recipient_addrs: Vec<String> = recipients.iter().map(|r| names::bare_address(r)).collect();

        // Who owns the sending identity.
        let (owner, owner_region) = match &out.source_arn {
            Some(arn) => {
                let parts: Vec<&str> = arn.splitn(6, ':').collect();
                if parts.len() != 6 || parts[2] != "ses" || !parts[5].starts_with("identity/") {
                    return Err(SendError::Invalid(format!("Invalid source ARN: {arn}")));
                }
                if parts[3] != ctx.region {
                    return Err(SendError::Invalid(format!(
                        "The Region in the source ARN ({}) does not match the Region of the request ({}).",
                        parts[3], ctx.region
                    )));
                }
                (parts[4].to_string(), parts[3].to_string())
            }
            None => (ctx.caller.account_id.clone(), ctx.region.clone()),
        };
        let sender = ctx.caller.account_id.clone();
        let now = ctx.received_at;

        let mut st = self.lock();
        // The identity, refreshed against DNS.
        let identity = {
            let owner_r = st.regions.entry(region_key(&owner, &owner_region)).or_default();
            self.refresh_identities(owner_r, ctx);
            let named = out
                .source_arn
                .as_ref()
                .and_then(|a| a.split_once(":identity/"))
                .map(|(_, n)| names::canonical_identity(n));
            let found = match &named {
                Some(n) => owner_r.identities.get(n).filter(|i| {
                    i.verified()
                        && (i.name == names::canonical_identity(&from_addr)
                            || names::domain_of(&from_addr)
                                .is_some_and(|d| d == i.name || d.ends_with(&format!(".{}", i.name))))
                }),
                None => crate::identities::sending_identity(owner_r, &from_addr),
            };
            found.cloned()
        };
        let identity_arn = names::arn_in(
            &ctx.partition,
            &owner_region,
            &owner,
            &format!("identity/{}", identity.as_ref().map(|i| i.name.clone()).unwrap_or_else(|| from_addr.clone())),
        );

        // Authorization, on the identity (and its sending policies), the
        // configuration set and the template.
        let mut cond = ConditionContext::new();
        cond.insert("ses:ApiVersion".into(), vec![out.version.into()]);
        cond.insert("ses:FromAddress".into(), vec![from_addr.clone()]);
        cond.insert("ses:Recipients".into(), recipient_addrs.clone());
        if let Some(n) = names::display_name(&out.from) {
            cond.insert("ses:FromDisplayName".into(), vec![n]);
        }
        if let Some(f) = &out.feedback_address {
            cond.insert("ses:FeedbackAddress".into(), vec![names::bare_address(f)]);
        }
        let action = format!("ses:{}", out.action);
        let policy = identity.as_ref().and_then(|i| i.policy_document());
        ctx.authorize_with_resource_policy(&action, &identity_arn, policy.as_deref(), cond.clone())
            .map_err(SendError::Denied)?;

        let r = st.regions.entry(region_key(&sender, &ctx.region)).or_default();
        if sender != owner {
            self.refresh_identities(r, ctx);
        }
        if !r.account.sending_enabled {
            return Err(SendError::AccountPaused);
        }
        // Configuration set: the one named, or the identity's default.
        let cs_name =
            out.configuration_set.clone().or_else(|| identity.as_ref().and_then(|i| i.configuration_set.clone()));
        if let Some(n) = &cs_name {
            let cs = r.configuration_sets.get(n).ok_or_else(|| SendError::NoSet(n.clone()))?;
            ctx.authorize(&action, &names::arn(ctx, &format!("configuration-set/{n}")), cond.clone())
                .map_err(SendError::Denied)?;
            if !cs.sending_enabled {
                return Err(SendError::SetPaused(n.clone()));
            }
        }
        if let Some(t) = &out.tenant {
            let tenant = r.tenants.get(t).ok_or_else(|| SendError::NotFound(format!("Tenant {t} does not exist.")))?;
            if tenant.sending_status == "DISABLED" {
                return Err(SendError::Rejected(format!("Sending is disabled for tenant {t}.")));
            }
        }
        // Verified sender.
        let Some(identity) = identity else {
            return Err(SendError::Rejected(format!(
                "Email address is not verified. The following identities failed the check in region {}: {}",
                names::upper_region(ctx),
                from_addr
            )));
        };
        if identity.mail_from_domain.is_some()
            && identity.mail_from_status != "Success"
            && identity.behavior_on_mx_failure == "RejectMessage"
        {
            return Err(SendError::MailFromNotVerified(format!(
                "The MAIL FROM domain {} of identity {} is not verified.",
                identity.mail_from_domain.clone().unwrap_or_default(),
                identity.name
            )));
        }
        // The sandbox: recipients must be verified too.
        if !r.account.production_access {
            let unverified: Vec<&String> = recipient_addrs
                .iter()
                .filter(|a| !names::is_simulator(a) && crate::identities::sending_identity(r, a).is_none())
                .collect();
            if !unverified.is_empty() {
                return Err(SendError::Rejected(format!(
                    "Email address is not verified. The following identities failed the check in region {}: {}",
                    names::upper_region(ctx),
                    unverified.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                )));
            }
        }
        if sent_last_24h(r, now) + recipients.len() as f64 > max_24h(r) {
            return Err(SendError::Quota);
        }
        // The maximum send rate, per second and counted in recipients. A
        // message on its own always fits, whatever its recipient count.
        let last_second = sent_last_second(r, now);
        if last_second > 0.0 && last_second + recipients.len() as f64 > max_rate(r) {
            return Err(SendError::Throttled);
        }

        // The template, if any.
        let mut rendering_failure = None;
        let (subject, text, html, template_name, template_data) = match &out.content {
            Content::Simple { subject, text, html } => (subject.clone(), text.clone(), html.clone(), None, None),
            Content::Raw(_) => {
                let p = parsed_raw.as_ref().expect("raw message parsed");
                (p.subject(), p.text.clone(), p.html.clone(), None, None)
            }
            Content::Template { name, arn, inline, data } => {
                let t = match (inline, name, arn) {
                    (Some(c), _, _) => Template {
                        name: "inline".into(),
                        subject: c.subject.clone(),
                        text: c.text.clone(),
                        html: c.html.clone(),
                        ..Default::default()
                    },
                    (None, Some(n), _) | (None, None, Some(n)) => {
                        let n = n.rsplit_once("template/").map_or(n.as_str(), |(_, n)| n);
                        let t = r.templates.get(n).cloned().ok_or_else(|| SendError::NoTemplate(n.to_string()))?;
                        ctx.authorize(&action, &names::arn(ctx, &format!("template/{n}")), cond.clone())
                            .map_err(SendError::Denied)?;
                        t
                    }
                    (None, None, None) => return Err(SendError::Invalid("A template name or ARN is required.".into())),
                };
                let rendered = match templates::render(&t, data) {
                    Ok(r) => r,
                    Err(e) => {
                        rendering_failure = Some((t.name.clone(), e.message()));
                        Rendered::default()
                    }
                };
                (rendered.subject, rendered.text, rendered.html, Some(t.name.clone()), Some(data.clone()))
            }
        };

        let message_id = names::message_id(ctx);
        // List management: headers, and contacts who opted out.
        let mut skip: Vec<String> = Vec::new();
        let mut headers = out.headers.clone();
        let mut unsubscribe_url = None;
        let mut pending_link: Option<UnsubscribeLink> = None;
        if let Some((list, topic)) = &out.list_management {
            let l =
                r.contact_lists.get(list).ok_or_else(|| SendError::NotFound(format!("List {list} does not exist.")))?;
            if let Some(t) = topic {
                if !l.topics.iter().any(|x| &x.topic_name == t) {
                    return Err(SendError::NotFound(format!("Topic {t} does not exist in list {list}.")));
                }
            }
            for a in &recipient_addrs {
                let Some(c) = l.contacts.get(&a.to_ascii_lowercase()) else { continue };
                let opted_out = c.unsubscribe_all
                    || topic.as_ref().is_some_and(|t| {
                        let pref = c
                            .topic_preferences
                            .iter()
                            .find(|p| &p.topic_name == t)
                            .map(|p| p.subscription_status.clone());
                        let default =
                            l.topics.iter().find(|x| &x.topic_name == t).map(|x| x.default_subscription_status.clone());
                        pref.or(default).as_deref() == Some("OPT_OUT")
                    });
                if opted_out {
                    skip.push(a.clone());
                }
            }
            let token = uuid::Uuid::new_v4().simple().to_string();
            let endpoint = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
            let url = format!("{endpoint}{}unsubscribe/{token}", outbox::PREFIX);
            headers.push(("List-Unsubscribe".into(), format!("<{url}>")));
            headers.push(("List-Unsubscribe-Post".into(), "List-Unsubscribe=One-Click".into()));
            unsubscribe_url = Some(url);
            let first = recipient_addrs.first().cloned().unwrap_or_default();
            pending_link = Some(UnsubscribeLink {
                account: sender.clone(),
                region: ctx.region.clone(),
                contact_list: list.clone(),
                topic: topic.clone(),
                email: first,
                message_id: message_id.clone(),
                configuration_set: cs_name.clone(),
            });
        }
        let substitute = |s: Option<String>| match (&unsubscribe_url, s) {
            (Some(u), Some(s)) => Some(s.replace("{{amazonSESUnsubscribeUrl}}", u)),
            (_, s) => s,
        };
        let (text, html) = (substitute(text), substitute(html));

        // Compose (or take) the wire message.
        let raw = match &out.content {
            Content::Raw(raw) => {
                let mut raw = mime::strip_bcc(raw);
                if !headers.is_empty() {
                    raw = mime::prepend_headers(&raw, &headers);
                }
                String::from_utf8_lossy(&raw).into_owned()
            }
            _ => mime::compose(
                ctx,
                &mime::Compose {
                    message_id: &message_id,
                    from: &out.from,
                    to: &out.to,
                    cc: &out.cc,
                    reply_to: &out.reply_to,
                    subject: &subject,
                    text: text.as_deref(),
                    html: html.as_deref(),
                    headers: headers.clone(),
                    attachments: out.attachments.clone(),
                },
            ),
        };
        let parsed = mime::parse(raw.as_bytes());

        // Tags SES adds, then the caller's.
        let mut tags: BTreeMap<String, Vec<String>> = BTreeMap::new();
        tags.insert("ses:operation".into(), vec![out.action.into()]);
        if let Some(n) = &cs_name {
            tags.insert("ses:configuration-set".into(), vec![n.clone()]);
        }
        tags.insert("ses:source-ip".into(), vec![ctx.source_ip.clone().unwrap_or_else(|| "127.0.0.1".into())]);
        tags.insert("ses:from-domain".into(), vec![names::domain_of(&from_addr).unwrap_or_default()]);
        tags.insert("ses:caller-identity".into(), vec![caller_name(ctx)]);
        tags.insert("ses:outgoing-ip".into(), vec!["127.0.0.1".into()]);
        if let Some(t) = &out.tenant {
            tags.insert("ses:tenant".into(), vec![t.clone()]);
        }
        for (k, v) in &out.tags {
            if k.starts_with("ses:") {
                return Err(SendError::Invalid(format!("Tag name {k} is reserved.")));
            }
            tags.insert(k.clone(), vec![v.clone()]);
        }
        let mail = MailInfo {
            partition: ctx.partition.clone(),
            account: sender.clone(),
            region: ctx.region.clone(),
            timestamp: now,
            message_id: message_id.clone(),
            source: out.from.clone(),
            source_arn: identity_arn.clone(),
            source_ip: ctx.source_ip.clone().unwrap_or_else(|| "127.0.0.1".into()),
            caller_identity: caller_name(ctx),
            destination: recipients.clone(),
            headers: parsed.headers.clone(),
            from: vec![out.from.clone()],
            to: out.to.clone(),
            cc: out.cc.clone(),
            reply_to: out.reply_to.clone(),
            subject: subject.clone(),
            date: now.format("%a, %d %b %Y %H:%M:%S +0000").to_string(),
            identity: identity.name.clone(),
            identity_account: owner.clone(),
            configuration_set: cs_name.clone(),
            tags: tags.clone(),
        };
        let event = |kind: EventKind| MailEvent { mail: mail.clone(), kind, time: now };
        let mut events = vec![event(EventKind::Send)];
        r.sends.push(SendRecord {
            message_id: message_id.clone(),
            timestamp: now,
            from: from_addr.clone(),
            subject: subject.clone(),
            identity: identity.name.clone(),
            configuration_set: cs_name.clone(),
            tenant: out.tenant.clone(),
            tags: tags.clone(),
            recipients: recipient_addrs.clone(),
            events: Vec::new(),
            rejected: false,
        });
        if r.sends.len() > 10_000 {
            r.sends.remove(0);
        }
        if let Some((template, error)) = rendering_failure {
            events.push(event(EventKind::RenderingFailure { template, error }));
            return Ok(Sent { message_id, events, local: Vec::new() });
        }

        // What happens to each recipient.
        let suppression_reasons = match cs_name
            .as_ref()
            .and_then(|n| r.configuration_sets.get(n))
            .and_then(|c| c.suppression.as_ref())
            .and_then(|s| s.suppressed_reasons.clone())
        {
            Some(r) => r,
            None => r.account.suppressed_reasons.clone(),
        };
        let mut delivered = Vec::new();
        let mut bounced = Vec::new();
        let mut suppressed = Vec::new();
        let mut simulator_suppressed = Vec::new();
        let mut complained = Vec::new();
        let mut ooto = false;
        for a in &recipient_addrs {
            if skip.contains(a) {
                continue;
            }
            match simulator_box(a).as_deref() {
                Some("bounce") => bounced.push(a.clone()),
                Some("complaint") => {
                    delivered.push(a.clone());
                    complained.push(a.clone());
                }
                Some("ooto") => {
                    delivered.push(a.clone());
                    ooto = true;
                }
                Some("suppressionlist") => simulator_suppressed.push(a.clone()),
                Some(_) => delivered.push(a.clone()),
                None => {
                    let listed = r.suppressed.get(&a.to_ascii_lowercase());
                    if listed.is_some_and(|s| suppression_reasons.iter().any(|x| x == &s.reason)) {
                        suppressed.push(a.clone());
                    } else {
                        delivered.push(a.clone());
                    }
                }
            }
        }
        if !delivered.is_empty() {
            events.push(event(EventKind::Delivery { recipients: delivered.clone() }));
        }
        if !bounced.is_empty() {
            events.push(event(EventKind::Bounce {
                bounce_type: "Permanent".into(),
                sub_type: "General".into(),
                recipients: bounced
                    .iter()
                    .map(|a| (a.clone(), "5.1.1".to_string(), "smtp; 550 5.1.1 user unknown".to_string()))
                    .collect(),
            }));
        }
        if !simulator_suppressed.is_empty() {
            events.push(event(EventKind::Bounce {
                bounce_type: "Permanent".into(),
                sub_type: "Suppressed".into(),
                recipients: simulator_suppressed
                    .iter()
                    .map(|a| {
                        (
                            a.clone(),
                            "5.1.1".to_string(),
                            "Amazon SES has suppressed sending to this address because it has a recent history of bouncing as an invalid address.".to_string(),
                        )
                    })
                    .collect(),
            }));
        }
        if !suppressed.is_empty() {
            events.push(event(EventKind::Bounce {
                bounce_type: "Permanent".into(),
                sub_type: "OnAccountSuppressionList".into(),
                recipients: suppressed
                    .iter()
                    .map(|a| {
                        (
                            a.clone(),
                            "5.1.1".to_string(),
                            "Amazon SES did not send the message to this address because it is on the suppression list for your account.".to_string(),
                        )
                    })
                    .collect(),
            }));
        }
        if !complained.is_empty() {
            events.push(event(EventKind::Complaint { recipients: complained, feedback_type: Some("abuse".into()) }));
        }

        // Into the outbox.
        outbox::push(
            &mut st,
            OutboxMessage {
                id: message_id.clone(),
                region: ctx.region.clone(),
                account_id: sender.clone(),
                source: out.from.clone(),
                destination: outbox::Destination {
                    to_addresses: out.to.clone(),
                    cc_addresses: out.cc.clone(),
                    bcc_addresses: out.bcc.clone(),
                },
                subject: subject.clone(),
                body: outbox::Body { text_part: text.clone(), html_part: html.clone() },
                raw_data: raw.clone(),
                template: template_name,
                template_data,
                configuration_set_name: cs_name.clone(),
                tags: out.tags.iter().cloned().collect(),
                timestamp: names::iso(now),
                kind: "Email".into(),
                verification_link: None,
            },
        );
        if let Some(link) = pending_link {
            let token = unsubscribe_url.as_ref().and_then(|u| u.rsplit('/').next()).unwrap_or_default().to_string();
            st.unsubscribe_links.insert(token, link);
        }
        if ooto {
            outbox::system_mail(
                &mut st,
                ctx,
                &sender,
                "ooto@simulator.amazonses.com",
                &out.from,
                "Out of the office",
                "I am out of the office and will reply when I return.\r\n",
                "AutoReply",
            );
        }
        // Mail for addresses this emulator receives.
        let mut local = Vec::new();
        let hosted: Vec<String> =
            delivered.iter().filter(|a| !names::is_simulator(a) && hosted_in(&st, a).is_some()).cloned().collect();
        if !hosted.is_empty() {
            let mut raw_bytes = raw.into_bytes();
            if !matches!(out.content, Content::Raw(_)) || parsed.header("Message-ID").is_none() {
                raw_bytes = mime::prepend_headers(&raw_bytes, &[]);
            }
            local.push(Inbound {
                raw: raw_bytes,
                mail_from: identity
                    .mail_from_domain
                    .as_ref()
                    .map_or_else(|| from_addr.clone(), |d| format!("bounce@{d}")),
                recipients: hosted,
                source_ip: "127.0.0.1".into(),
                tls: true,
                origin: Some(mail.clone()),
            });
        }
        Ok(Sent { message_id, events, local })
    }
}

/// `ses:caller-identity`: the IAM user or role session name.
fn caller_name(ctx: &RequestContext) -> String {
    match &ctx.caller.kind {
        mws_core::CallerKind::User { name } => name.clone(),
        mws_core::CallerKind::AssumedRole { role_name, .. } => role_name.clone(),
        mws_core::CallerKind::FederatedUser { name, .. } => name.clone(),
        mws_core::CallerKind::Root => "root".into(),
        mws_core::CallerKind::Anonymous | mws_core::CallerKind::Service { .. } => String::new(),
    }
}

fn v1_destination(d: &t1::Destination) -> (Vec<String>, Vec<String>, Vec<String>) {
    (
        d.to_addresses.clone().unwrap_or_default(),
        d.cc_addresses.clone().unwrap_or_default(),
        d.bcc_addresses.clone().unwrap_or_default(),
    )
}

fn v2_destination(d: Option<&t2::Destination>) -> (Vec<String>, Vec<String>, Vec<String>) {
    match d {
        Some(d) => (
            d.to_addresses.clone().unwrap_or_default(),
            d.cc_addresses.clone().unwrap_or_default(),
            d.bcc_addresses.clone().unwrap_or_default(),
        ),
        None => Default::default(),
    }
}

fn v1_tags(tags: Option<&[t1::MessageTag]>) -> Vec<(String, String)> {
    tags.unwrap_or_default().iter().map(|t| (t.name.clone(), t.value.clone())).collect()
}

fn v2_tags(tags: Option<&[t2::MessageTag]>) -> Vec<(String, String)> {
    tags.unwrap_or_default().iter().map(|t| (t.name.clone(), t.value.clone())).collect()
}

fn check_tags(tags: &[(String, String)]) -> Result<(), SendError> {
    for (k, v) in tags {
        let ok = |s: &str| {
            !s.is_empty()
                && s.len() <= 256
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '@')
        };
        if !ok(k) || !ok(v) {
            return Err(SendError::Invalid(format!(
                "Invalid tag name <{k}>: only alphanumeric ASCII characters, '_', and '-' are allowed."
            )));
        }
    }
    Ok(())
}

fn v2_headers(h: Option<&[t2::MessageHeader]>) -> Result<Vec<(String, String)>, SendError> {
    let h = h.unwrap_or_default();
    if h.len() > 15 {
        return Err(SendError::Invalid("Too many headers. The maximum is 15.".into()));
    }
    h.iter()
        .map(|h| {
            if mime::is_reserved_header(&h.name) {
                Err(SendError::Invalid(format!("Header {} is not allowed.", h.name)))
            } else {
                Ok((h.name.clone(), h.value.clone()))
            }
        })
        .collect()
}

fn v2_attachments(a: Option<&[t2::Attachment]>) -> Vec<mime::Attachment> {
    a.unwrap_or_default()
        .iter()
        .map(|a| mime::Attachment {
            file_name: a.file_name.clone(),
            content_type: a.content_type.clone().unwrap_or_else(|| guess_type(&a.file_name)),
            disposition: a.content_disposition.clone().unwrap_or_else(|| "ATTACHMENT".into()),
            content_id: a.content_id.clone(),
            description: a.content_description.clone(),
            data: a.raw_content.clone(),
        })
        .collect()
}

fn guess_type(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "csv" => "text/csv",
        "json" => "application/json",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .into()
}

impl Ses {
    // ------------------------------------------------------------ v1

    pub(crate) fn send_email_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SendEmailRequest,
    ) -> Result<t1::SendEmailResponse, ServiceError> {
        let (to, cc, bcc) = v1_destination(&input.destination);
        let m = input.message;
        let mut out = Outgoing::new(
            "1",
            "SendEmail",
            input.source,
            Content::Simple {
                subject: m.subject.data,
                text: m.body.text.map(|c| c.data),
                html: m.body.html.map(|c| c.data),
            },
        );
        out.to = to;
        out.cc = cc;
        out.bcc = bcc;
        out.reply_to = input.reply_to_addresses.unwrap_or_default();
        out.source_arn = input.source_arn;
        out.feedback_address = input.return_path;
        out.tags = v1_tags(input.tags.as_deref());
        out.configuration_set = input.configuration_set_name;
        check_tags(&out.tags).map_err(SendError::v1)?;
        let id = self.send(ctx, out).map_err(SendError::v1)?;
        Ok(t1::SendEmailResponse { message_id: id })
    }

    pub(crate) fn send_raw_email_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SendRawEmailRequest,
    ) -> Result<t1::SendRawEmailResponse, ServiceError> {
        let mut out =
            Outgoing::new("1", "SendRawEmail", input.source.unwrap_or_default(), Content::Raw(input.raw_message.data));
        out.envelope = input.destinations;
        out.source_arn = input.source_arn.or(input.from_arn);
        out.tags = v1_tags(input.tags.as_deref());
        out.configuration_set = input.configuration_set_name;
        check_tags(&out.tags).map_err(SendError::v1)?;
        let id = self.send(ctx, out).map_err(SendError::v1)?;
        Ok(t1::SendRawEmailResponse { message_id: id })
    }

    pub(crate) fn send_templated_email_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SendTemplatedEmailRequest,
    ) -> Result<t1::SendTemplatedEmailResponse, ServiceError> {
        let (to, cc, bcc) = v1_destination(&input.destination);
        let mut out = Outgoing::new(
            "1",
            "SendTemplatedEmail",
            input.source,
            Content::Template {
                name: Some(input.template),
                arn: input.template_arn,
                inline: None,
                data: input.template_data,
            },
        );
        out.to = to;
        out.cc = cc;
        out.bcc = bcc;
        out.reply_to = input.reply_to_addresses.unwrap_or_default();
        out.source_arn = input.source_arn;
        out.feedback_address = input.return_path;
        out.tags = v1_tags(input.tags.as_deref());
        out.configuration_set = input.configuration_set_name;
        check_tags(&out.tags).map_err(SendError::v1)?;
        let id = self.send(ctx, out).map_err(SendError::v1)?;
        Ok(t1::SendTemplatedEmailResponse { message_id: id })
    }

    pub(crate) fn send_bulk_templated_email_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SendBulkTemplatedEmailRequest,
    ) -> Result<t1::SendBulkTemplatedEmailResponse, ServiceError> {
        if input.destinations.len() > MAX_RECIPIENTS {
            return Err(names::invalid_parameter(format!("Destination count exceeds {MAX_RECIPIENTS}.")));
        }
        if let Some(cs) = &input.configuration_set_name {
            if self.configuration_set(ctx, cs).is_none() {
                return Err(SendError::NoSet(cs.clone()).v1());
            }
        }
        let tname = input.template.rsplit_once("template/").map_or(input.template.as_str(), |(_, n)| n).to_string();
        if self.find_template(ctx, &tname).is_none() {
            return Err(SendError::NoTemplate(tname).v1());
        }
        let defaults = v1_tags(input.default_tags.as_deref());
        let mut status = Vec::new();
        for d in input.destinations {
            let (to, cc, bcc) = v1_destination(&d.destination);
            let data = match (
                &d.replacement_template_data,
                serde_json::from_str::<serde_json::Value>(&input.default_template_data),
            ) {
                (Some(r), Ok(serde_json::Value::Object(mut base))) => {
                    if let Ok(serde_json::Value::Object(over)) = serde_json::from_str::<serde_json::Value>(r) {
                        base.extend(over);
                    }
                    serde_json::Value::Object(base).to_string()
                }
                (Some(r), _) => r.clone(),
                (None, _) => input.default_template_data.clone(),
            };
            let mut out = Outgoing::new(
                "1",
                "SendBulkTemplatedEmail",
                input.source.clone(),
                Content::Template { name: Some(tname.clone()), arn: input.template_arn.clone(), inline: None, data },
            );
            out.to = to;
            out.cc = cc;
            out.bcc = bcc;
            out.reply_to = input.reply_to_addresses.clone().unwrap_or_default();
            out.source_arn = input.source_arn.clone();
            out.feedback_address = input.return_path.clone();
            let mut tags = defaults.clone();
            for (k, v) in v1_tags(d.replacement_tags.as_deref()) {
                tags.retain(|(x, _)| x != &k);
                tags.push((k, v));
            }
            out.tags = tags;
            out.configuration_set = input.configuration_set_name.clone();
            match check_tags(&out.tags).and_then(|_| self.send(ctx, out)) {
                Ok(id) => status.push(t1::BulkEmailDestinationStatus {
                    status: Some("Success".into()),
                    error: None,
                    message_id: Some(id),
                }),
                Err(SendError::Denied(e)) => return Err(e),
                Err(e) => status.push(t1::BulkEmailDestinationStatus {
                    status: Some(e.v1_bulk_status().into()),
                    error: Some(e.message()),
                    message_id: None,
                }),
            }
        }
        Ok(t1::SendBulkTemplatedEmailResponse { status })
    }

    pub(crate) fn send_bounce_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SendBounceRequest,
    ) -> Result<t1::SendBounceResponse, ServiceError> {
        authorize_send_bounce(ctx, &input.bounce_sender, input.bounce_sender_arn.as_deref())?;
        if !self.is_verified_sender(ctx, &input.bounce_sender) {
            return Err(v1::errors::message_rejected(format!(
                "Email address is not verified. The following identities failed the check in region {}: {}",
                names::upper_region(ctx),
                input.bounce_sender
            )));
        }
        let original = {
            let st = self.lock();
            st.received
                .iter()
                .find(|m| m.message_id == input.original_message_id && m.account_id == ctx.caller.account_id)
                .cloned()
        };
        let Some(original) = original else {
            return Err(v1::errors::message_rejected(format!(
                "Could not find original message with message id {}.",
                input.original_message_id
            )));
        };
        if input.bounced_recipient_info_list.is_empty() {
            return Err(names::invalid_parameter("BouncedRecipientInfoList must not be empty."));
        }
        let mut lines = Vec::new();
        for b in &input.bounced_recipient_info_list {
            if b.bounce_type.is_none() && b.recipient_dsn_fields.is_none() {
                return Err(names::invalid_parameter("Either BounceType or RecipientDsnFields is required."));
            }
            let status = b
                .recipient_dsn_fields
                .as_ref()
                .map(|f| f.status.clone())
                .unwrap_or_else(|| bounce_status(b.bounce_type.as_deref().unwrap_or("Undefined")).into());
            lines.push(format!("Final-Recipient: rfc822; {}\r\nAction: failed\r\nStatus: {status}", b.recipient));
        }
        let text = format!(
            "{}\r\n\r\nReporting-MTA: dns; {}\r\n\r\n{}\r\n",
            input.explanation.unwrap_or_else(|| "The message could not be delivered.".into()),
            input.message_dsn.map(|d| d.reporting_mta).unwrap_or_else(|| "dns; amazonses.com".into()),
            lines.join("\r\n\r\n")
        );
        let mut st = self.lock();
        outbox::system_mail(
            &mut st,
            ctx,
            &ctx.caller.account_id,
            &input.bounce_sender,
            &original.source,
            "Delivery Status Notification (Failure)",
            &text,
            "Bounce",
        );
        let id = st.outbox.last().map(|m| m.id.clone());
        Ok(t1::SendBounceResponse { message_id: id })
    }

    // ------------------------------------------------------------ v2

    fn v2_outgoing(
        action: &'static str,
        from: Option<String>,
        content: &t2::EmailContent,
    ) -> Result<Outgoing, SendError> {
        let kinds = [content.simple.is_some(), content.raw.is_some(), content.template.is_some()]
            .iter()
            .filter(|b| **b)
            .count();
        if kinds != 1 {
            return Err(SendError::Invalid("Exactly one of Simple, Raw or Template content is required.".into()));
        }
        if let Some(m) = &content.simple {
            let mut out = Outgoing::new(
                "2",
                action,
                from.clone().unwrap_or_default(),
                Content::Simple {
                    subject: m.subject.data.clone(),
                    text: m.body.text.as_ref().map(|c| c.data.clone()),
                    html: m.body.html.as_ref().map(|c| c.data.clone()),
                },
            );
            out.headers = v2_headers(m.headers.as_deref())?;
            out.attachments = v2_attachments(m.attachments.as_deref());
            return Ok(out);
        }
        if let Some(r) = &content.raw {
            return Ok(Outgoing::new("2", action, from.unwrap_or_default(), Content::Raw(r.data.clone())));
        }
        let t = content.template.as_ref().expect("one content kind");
        let mut out = Outgoing::new(
            "2",
            action,
            from.unwrap_or_default(),
            Content::Template {
                name: t.template_name.clone(),
                arn: t.template_arn.clone(),
                inline: t.template_content.clone(),
                data: t.template_data.clone().unwrap_or_else(|| "{}".into()),
            },
        );
        out.headers = v2_headers(t.headers.as_deref())?;
        out.attachments = v2_attachments(t.attachments.as_deref());
        Ok(out)
    }

    pub(crate) fn send_email_v2(
        &self,
        ctx: &RequestContext,
        input: t2::SendEmailRequest,
    ) -> Result<t2::SendEmailResponse, ServiceError> {
        if input.content.raw.is_none() && input.from_email_address.is_none() {
            return Err(v2::errors::bad_request("FromEmailAddress is required."));
        }
        let mut out =
            Self::v2_outgoing("SendEmail", input.from_email_address, &input.content).map_err(SendError::v2)?;
        let (to, cc, bcc) = v2_destination(input.destination.as_ref());
        if out.content_is_raw() {
            if input.destination.is_some() {
                out.envelope = Some(to.iter().chain(&cc).chain(&bcc).cloned().collect());
            }
        } else {
            out.to = to;
            out.cc = cc;
            out.bcc = bcc;
        }
        out.reply_to = input.reply_to_addresses.unwrap_or_default();
        out.source_arn = input.from_email_address_identity_arn;
        out.feedback_address = input.feedback_forwarding_email_address;
        out.tags = v2_tags(input.email_tags.as_deref());
        out.configuration_set = input.configuration_set_name;
        out.tenant = input.tenant_name;
        out.list_management = input.list_management_options.map(|l| (l.contact_list_name, l.topic_name));
        if let Some(e) = &input.endpoint_id {
            self.check_endpoint(ctx, e).map_err(SendError::v2)?;
        }
        check_tags(&out.tags).map_err(SendError::v2)?;
        let id = self.send(ctx, out).map_err(SendError::v2)?;
        Ok(t2::SendEmailResponse { message_id: Some(id) })
    }

    fn check_endpoint(&self, ctx: &RequestContext, id: &str) -> Result<(), SendError> {
        let ok = self
            .lock()
            .regions
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}:", ctx.caller.account_id)))
            .any(|(_, r)| r.multi_region_endpoints.values().any(|m| m.id == id));
        if ok {
            Ok(())
        } else {
            Err(SendError::NotFound(format!("Endpoint {id} does not exist.")))
        }
    }

    pub(crate) fn send_bulk_email_v2(
        &self,
        ctx: &RequestContext,
        input: t2::SendBulkEmailRequest,
    ) -> Result<t2::SendBulkEmailResponse, ServiceError> {
        if input.bulk_email_entries.len() > MAX_RECIPIENTS {
            return Err(v2::errors::bad_request(format!("Destination count exceeds {MAX_RECIPIENTS}.")));
        }
        let Some(template) = input.default_content.template.clone() else {
            return Err(v2::errors::bad_request("DefaultContent must contain a Template."));
        };
        if let Some(cs) = &input.configuration_set_name {
            if self.configuration_set(ctx, cs).is_none() {
                return Err(SendError::NoSet(cs.clone()).v2());
            }
        }
        if let Some(e) = &input.endpoint_id {
            self.check_endpoint(ctx, e).map_err(SendError::v2)?;
        }
        if template.template_content.is_none() {
            let name = template.template_name.clone().or_else(|| template.template_arn.clone()).unwrap_or_default();
            let n = name.rsplit_once("template/").map_or(name.as_str(), |(_, n)| n).to_string();
            if self.find_template(ctx, &n).is_none() {
                return Err(SendError::NoTemplate(n).v2());
            }
        }
        let defaults = v2_tags(input.default_email_tags.as_deref());
        let mut results = Vec::new();
        for entry in input.bulk_email_entries {
            let mut t = template.clone();
            if let Some(data) = entry
                .replacement_email_content
                .as_ref()
                .and_then(|c| c.replacement_template.as_ref())
                .and_then(|r| r.replacement_template_data.clone())
            {
                t.template_data = Some(data);
            }
            if let Some(h) = &entry.replacement_headers {
                t.headers = Some(h.clone());
            }
            let content = t2::EmailContent { template: Some(t), ..Default::default() };
            let built =
                Self::v2_outgoing("SendBulkEmail", input.from_email_address.clone(), &content).and_then(|mut out| {
                    let (to, cc, bcc) = v2_destination(Some(&entry.destination));
                    out.to = to;
                    out.cc = cc;
                    out.bcc = bcc;
                    out.reply_to = input.reply_to_addresses.clone().unwrap_or_default();
                    out.source_arn = input.from_email_address_identity_arn.clone();
                    out.feedback_address = input.feedback_forwarding_email_address.clone();
                    let mut tags = defaults.clone();
                    for (k, v) in v2_tags(entry.replacement_tags.as_deref()) {
                        tags.retain(|(x, _)| x != &k);
                        tags.push((k, v));
                    }
                    out.tags = tags;
                    out.configuration_set = input.configuration_set_name.clone();
                    out.tenant = input.tenant_name.clone();
                    check_tags(&out.tags)?;
                    Ok(out)
                });
            match built.and_then(|out| self.send(ctx, out)) {
                Ok(id) => results.push(t2::BulkEmailEntryResult {
                    status: Some("SUCCESS".into()),
                    error: None,
                    message_id: Some(id),
                }),
                Err(SendError::Denied(e)) => return Err(e),
                Err(e) => results.push(t2::BulkEmailEntryResult {
                    status: Some(e.v2_bulk_status().into()),
                    error: Some(e.message()),
                    message_id: None,
                }),
            }
        }
        Ok(t2::SendBulkEmailResponse { bulk_email_entry_results: results })
    }

    /// An authenticated SMTP submission: `SendRawEmail` as the caller.
    pub(crate) fn send_smtp(
        &self,
        ctx: &RequestContext,
        mail_from: &str,
        recipients: Vec<String>,
        raw: Vec<u8>,
    ) -> Result<String, SendError> {
        let parsed = mime::parse(&raw);
        let mut out = Outgoing::new("1", "SendRawEmail", String::new(), Content::Raw(raw));
        if parsed.header("From").is_none() {
            out.from = mail_from.to_string();
        }
        out.envelope = Some(recipients);
        if let Some(cs) = parsed.header("X-SES-CONFIGURATION-SET") {
            out.configuration_set = Some(cs.trim().to_string());
        }
        if let Some(tags) = parsed.header("X-SES-MESSAGE-TAGS") {
            out.tags = tags
                .split(',')
                .filter_map(|t| t.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
                .collect();
        }
        if let Some(arn) = parsed.header("X-SES-SOURCE-ARN").or(parsed.header("X-SES-FROM-ARN")) {
            out.source_arn = Some(arn.trim().to_string());
        }
        self.send(ctx, out)
    }
}

impl Outgoing {
    fn content_is_raw(&self) -> bool {
        matches!(self.content, Content::Raw(_))
    }
}

fn bounce_status(bounce_type: &str) -> &'static str {
    match bounce_type {
        "DoesNotExist" => "5.1.1",
        "MessageTooLarge" => "5.3.4",
        "ExceededQuota" => "5.2.2",
        "ContentRejected" => "5.6.1",
        "TemporaryFailure" => "4.0.0",
        _ => "5.0.0",
    }
}

fn authorize_send_bounce(ctx: &RequestContext, sender: &str, arn: Option<&str>) -> Result<(), ServiceError> {
    let resource = arn.map(str::to_string).unwrap_or_else(|| names::identity_arn(ctx, &names::bare_address(sender)));
    names::authorize(ctx, "1", "SendBounce", &resource)
}
