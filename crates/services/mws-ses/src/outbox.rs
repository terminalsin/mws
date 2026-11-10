//! MWS's window into SES, served without a signature at `/_aws/ses`:
//!
//! * `GET /_aws/ses[?id=...][&email=<source>][&to=<recipient>]`: mail SES
//!   sent, as `{"messages": [...]}` (the shape LocalStack uses);
//!   `DELETE` clears it (or one message, with `id`).
//! * `GET /_aws/ses/verify/<token>`: the verification link SES mails to
//!   email identities.
//! * `POST /_aws/ses/inbound?from=<sender>&to=<a,b>`: deliver the raw
//!   message in the body to SES receiving, as if it arrived over SMTP;
//!   `GET` lists received mail and what the receipt rules did with it.
//! * `POST /_aws/ses/verify-identity?identity=...&account=...&region=...`:
//!   mark an identity verified without DNS records or a click.
//! * `GET|POST /_aws/ses/unsubscribe/<token>`: the one-click unsubscribe
//!   link of list management.
//! * `POST /_aws/ses/production-access?status=GRANTED|DENIED&account=...&region=...`:
//!   decide the account's production access review now instead of 24
//!   hours after `PutAccountDetails` (`GRANTED` is the default; with no
//!   pending request, a case is opened and decided at once).

use std::collections::BTreeMap;

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use serde::{Deserialize, Serialize};

use crate::names;
use crate::state::State;
use crate::Ses;

pub const PREFIX: &str = "/_aws/ses/";
pub const ROOT: &str = "/_aws/ses";
const LIMIT: usize = 5000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct OutboxMessage {
    pub id: String,
    pub region: String,
    pub account_id: String,
    pub source: String,
    pub destination: Destination,
    pub subject: String,
    pub body: Body,
    pub raw_data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_set_name: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    pub timestamp: String,
    /// `Email` for what callers sent; `VerificationEmail`,
    /// `CustomVerificationEmail`, `FeedbackForwarding`, `Bounce` and
    /// `AutoReply` for mail SES sends itself.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_link: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Destination {
    pub to_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cc_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bcc_addresses: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Body {
    pub text_part: Option<String>,
    pub html_part: Option<String>,
}

/// Mail that arrived for SES receiving.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct ReceivedMessage {
    pub message_id: String,
    pub account_id: String,
    pub region: String,
    pub timestamp: String,
    pub source: String,
    pub recipients: Vec<String>,
    pub subject: String,
    pub rule_set: String,
    pub matched_rules: Vec<String>,
    /// What each action did: `S3 my-bucket/prefix/id`, `Lambda ... OK`,
    /// `SNS ... failed: ...`.
    pub actions: Vec<String>,
    pub raw_data: String,
}

pub fn push(st: &mut State, m: OutboxMessage) {
    st.outbox.push(m);
    if st.outbox.len() > LIMIT {
        st.outbox.remove(0);
    }
}

pub fn push_received(st: &mut State, m: ReceivedMessage) {
    st.received.push(m);
    if st.received.len() > LIMIT {
        st.received.remove(0);
    }
}

/// Mail SES itself sends (bounces, auto-replies, feedback).
#[allow(clippy::too_many_arguments)]
pub fn system_mail(
    st: &mut State,
    ctx: &RequestContext,
    account: &str,
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
    kind: &str,
) {
    let id = names::message_id(ctx);
    let raw = crate::mime::compose(
        ctx,
        &crate::mime::Compose {
            message_id: &id,
            from,
            to: &[to.to_string()],
            subject,
            text: Some(text),
            ..Default::default()
        },
    );
    push(
        st,
        OutboxMessage {
            id,
            region: ctx.region.clone(),
            account_id: account.to_string(),
            source: from.to_string(),
            destination: Destination { to_addresses: vec![to.to_string()], ..Default::default() },
            subject: subject.to_string(),
            body: Body { text_part: Some(text.to_string()), html_part: None },
            raw_data: raw,
            timestamp: names::iso(ctx.received_at),
            kind: kind.to_string(),
            ..Default::default()
        },
    );
}

fn json(status: u16, v: serde_json::Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(v.to_string()))
        .expect("valid response")
}

fn html(status: u16, body: &str) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(Bytes::from(body.to_string()))
        .expect("valid response")
}

fn redirect(url: &str) -> HttpResponse {
    http::Response::builder().status(302).header("location", url).body(Bytes::new()).expect("valid response")
}

fn query(request: &HttpRequest) -> BTreeMap<String, String> {
    form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes()).into_owned().collect()
}

impl Ses {
    pub(crate) async fn serve_side_channel(&self, ctx: &RequestContext, request: &HttpRequest) -> Option<HttpResponse> {
        let path = request.uri().path();
        if path != ROOT && !path.starts_with(PREFIX) {
            return None;
        }
        let rest = path.strip_prefix(ROOT).unwrap_or("").trim_start_matches('/');
        let q = query(request);
        let method = request.method().clone();
        Some(match (method.as_str(), rest.split_once('/').map_or((rest, ""), |(a, b)| (a, b))) {
            ("GET", ("", _)) => {
                let st = self.lock();
                let messages: Vec<&OutboxMessage> = st
                    .outbox
                    .iter()
                    .filter(|m| q.get("id").is_none_or(|id| &m.id == id))
                    .filter(|m| q.get("email").is_none_or(|e| names::bare_address(&m.source).eq_ignore_ascii_case(e)))
                    .filter(|m| {
                        q.get("to").is_none_or(|to| {
                            m.destination
                                .to_addresses
                                .iter()
                                .chain(&m.destination.cc_addresses)
                                .chain(&m.destination.bcc_addresses)
                                .any(|a| names::bare_address(a).eq_ignore_ascii_case(to))
                        })
                    })
                    .collect();
                json(200, serde_json::json!({ "messages": messages }))
            }
            ("DELETE", ("", _)) => {
                let mut st = self.lock();
                match q.get("id") {
                    Some(id) => st.outbox.retain(|m| &m.id != id),
                    None => st.outbox.clear(),
                }
                http::Response::builder().status(204).body(Bytes::new()).expect("valid response")
            }
            ("GET", ("verify", token)) => match self.follow_verification_link(token) {
                Some(Ok(Some(url))) => redirect(&url),
                Some(Ok(None)) => html(
                    200,
                    "<html><body><h1>Congratulations!</h1><p>You have successfully verified an email address. You can now start sending email from this address.</p></body></html>",
                ),
                Some(Err(Some(url))) => redirect(&url),
                _ => html(
                    400,
                    "<html><body><h1>Verification failed</h1><p>The link is invalid or has expired.</p></body></html>",
                ),
            },
            ("POST", ("verify-identity", _)) => {
                let Some(identity) = q.get("identity") else {
                    return Some(json(400, serde_json::json!({ "message": "identity is required" })));
                };
                let account = q.get("account").cloned().unwrap_or_else(|| self.default_account());
                let region = q.get("region").cloned().unwrap_or_else(|| ctx.region.clone());
                if self.force_verify(&account, &region, identity, ctx.received_at) {
                    json(200, serde_json::json!({ "identity": identity, "verificationStatus": "Success" }))
                } else {
                    json(404, serde_json::json!({ "message": format!("Identity {identity} does not exist.") }))
                }
            }
            ("POST", ("production-access", _)) => {
                let status = q.get("status").map(|s| s.to_ascii_uppercase()).unwrap_or_else(|| "GRANTED".into());
                if !matches!(status.as_str(), "GRANTED" | "DENIED") {
                    return Some(json(400, serde_json::json!({ "message": "status must be GRANTED or DENIED" })));
                }
                let account = q.get("account").cloned().unwrap_or_else(|| self.default_account());
                let region = q.get("region").cloned().unwrap_or_else(|| ctx.region.clone());
                let mut st = self.lock();
                let r = st.regions.entry(crate::state::region_key(&account, &region)).or_default();
                crate::account::decide_review(r, &status);
                let case_id = r
                    .account
                    .details
                    .as_ref()
                    .and_then(|d| d.review_details.as_ref())
                    .and_then(|v| v.case_id.clone());
                json(
                    200,
                    serde_json::json!({
                        "account": account,
                        "region": region,
                        "status": status,
                        "caseId": case_id,
                        "productionAccessEnabled": r.account.production_access,
                    }),
                )
            }
            ("GET", ("inbound", _)) => {
                let st = self.lock();
                let messages: Vec<&ReceivedMessage> = st
                    .received
                    .iter()
                    .filter(|m| q.get("to").is_none_or(|to| m.recipients.iter().any(|r| r.eq_ignore_ascii_case(to))))
                    .collect();
                json(200, serde_json::json!({ "messages": messages }))
            }
            ("DELETE", ("inbound", _)) => {
                self.lock().received.clear();
                http::Response::builder().status(204).body(Bytes::new()).expect("valid response")
            }
            ("POST", ("inbound", _)) => {
                let raw = request.body().to_vec();
                let parsed = crate::mime::parse(&raw);
                let from = q
                    .get("from")
                    .cloned()
                    .or_else(|| parsed.header("Return-Path").map(names::bare_address))
                    .or_else(|| parsed.header("From").map(names::bare_address))
                    .unwrap_or_default();
                let to: Vec<String> = match q.get("to") {
                    Some(t) => t.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                    None => parsed
                        .addresses("To")
                        .into_iter()
                        .chain(parsed.addresses("Cc"))
                        .map(|a| names::bare_address(&a))
                        .collect(),
                };
                let inbound = crate::receive::Inbound {
                    raw,
                    mail_from: from,
                    recipients: to,
                    source_ip: ctx.source_ip.clone().unwrap_or_else(|| "127.0.0.1".into()),
                    tls: false,
                    origin: None,
                };
                match self.receive(ctx, inbound).await {
                    Ok(r) => json(200, serde_json::json!({ "messageId": r.message_id, "accepted": r.accepted, "rejected": r.rejected })),
                    Err((code, message)) => json(400, serde_json::json!({ "smtpCode": code, "message": message })),
                }
            }
            ("GET" | "POST", ("unsubscribe", token)) => match self.unsubscribe_link(ctx, token) {
                Some(()) => html(200, "<html><body><p>You have been unsubscribed.</p></body></html>"),
                None => html(404, "<html><body><p>Unknown unsubscribe link.</p></body></html>"),
            },
            _ => json(404, serde_json::json!({ "message": format!("No such MWS SES resource: {path}") })),
        })
    }

    /// The account SMTP and side-channel work defaults to: the one that
    /// made the most recent request.
    pub(crate) fn default_account(&self) -> String {
        self.inner
            .template
            .lock()
            .expect("SES template lock poisoned")
            .as_ref()
            .map(|(c, _)| c.caller.account_id.clone())
            .unwrap_or_else(|| "123456789012".into())
    }
}
