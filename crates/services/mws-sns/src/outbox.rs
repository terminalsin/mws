//! Messages SNS would hand to people or devices (SMS, email, mobile push)
//! and the links SNS puts in messages, served at `/_aws/sns/...` without a
//! signature so tests can read them:
//!
//! * `GET /_aws/sns/sms-messages[?phoneNumber=...]`
//! * `GET /_aws/sns/email-messages[?email=...]`
//! * `GET /_aws/sns/platform-endpoint-messages[?endpointArn=...]`
//!   (`DELETE` on any of these clears it)
//! * `GET /_aws/sns/subscription-tokens/<subscription arn>`: the pending
//!   confirmation token, as the confirmation message carries it
//! * `POST /_aws/sns/sms-opt-out?phoneNumber=...`: the number replies STOP
//! * `GET /_aws/sns/SimpleNotificationService-<id>.pem`: the signing
//!   certificate

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use serde::{Deserialize, Serialize};

use crate::Sns;

pub const PREFIX: &str = "/_aws/sns/";
const LIMIT: usize = 1000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Outbox {
    pub sms: Vec<SmsMessage>,
    pub email: Vec<EmailMessage>,
    pub platform: Vec<PlatformMessage>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SmsMessage {
    pub message_id: String,
    pub phone_number: String,
    pub message: String,
    pub sender_id: Option<String>,
    pub sms_type: Option<String>,
    pub origination_number: Option<String>,
    pub topic_arn: Option<String>,
    pub account_id: String,
    pub region: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EmailMessage {
    pub message_id: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    pub content_type: String,
    pub topic_arn: String,
    pub subscription_arn: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PlatformMessage {
    pub message_id: String,
    pub endpoint_arn: String,
    pub platform: String,
    pub token: String,
    pub message: String,
    pub message_attributes: serde_json::Value,
    pub topic_arn: Option<String>,
    pub timestamp: String,
}

fn push<T>(list: &mut Vec<T>, item: T) {
    list.push(item);
    if list.len() > LIMIT {
        list.remove(0);
    }
}

impl Outbox {
    pub fn sms(&mut self, m: SmsMessage) {
        push(&mut self.sms, m);
    }
    pub fn email(&mut self, m: EmailMessage) {
        push(&mut self.email, m);
    }
    pub fn platform(&mut self, m: PlatformMessage) {
        push(&mut self.platform, m);
    }
}

fn json(status: u16, body: serde_json::Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body.to_string()))
        .expect("static response parts are valid")
}

fn query(request: &HttpRequest, name: &str) -> Option<String> {
    let q = request.uri().query()?;
    form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

impl Sns {
    /// Serve the outbox and the signing certificate.
    pub(crate) fn serve_side_channel(&self, _ctx: &RequestContext, request: &HttpRequest) -> Option<HttpResponse> {
        let path = request.uri().path();
        let rest = path.strip_prefix(PREFIX)?;
        let method = request.method().clone();
        if rest.ends_with(".pem") && method == http::Method::GET {
            return Some(match self.inner.signer.cert_pem(path) {
                Some(pem) => http::Response::builder()
                    .status(200)
                    .header(http::header::CONTENT_TYPE, "application/x-x509-ca-cert")
                    .body(Bytes::from(pem))
                    .expect("static response parts are valid"),
                None => json(404, serde_json::json!({ "message": "no such certificate" })),
            });
        }
        let mut st = self.lock();
        let response = match (rest, method) {
            ("sms-messages", http::Method::GET) => {
                let phone = query(request, "phoneNumber");
                let list: Vec<_> =
                    st.outbox.sms.iter().filter(|m| phone.as_ref().is_none_or(|p| &m.phone_number == p)).collect();
                json(200, serde_json::json!({ "smsMessages": list }))
            }
            ("sms-messages", http::Method::DELETE) => {
                st.outbox.sms.clear();
                json(204, serde_json::json!({}))
            }
            ("email-messages", http::Method::GET) => {
                let to = query(request, "email");
                let list: Vec<_> = st.outbox.email.iter().filter(|m| to.as_ref().is_none_or(|t| &m.to == t)).collect();
                json(200, serde_json::json!({ "emailMessages": list }))
            }
            ("email-messages", http::Method::DELETE) => {
                st.outbox.email.clear();
                json(204, serde_json::json!({}))
            }
            ("platform-endpoint-messages", http::Method::GET) => {
                let arn = query(request, "endpointArn");
                let list: Vec<_> =
                    st.outbox.platform.iter().filter(|m| arn.as_ref().is_none_or(|a| &m.endpoint_arn == a)).collect();
                json(200, serde_json::json!({ "platformEndpointMessages": list }))
            }
            ("platform-endpoint-messages", http::Method::DELETE) => {
                st.outbox.platform.clear();
                json(204, serde_json::json!({}))
            }
            ("sms-opt-out", http::Method::POST) => match query(request, "phoneNumber") {
                Some(n) if crate::names::valid_phone_number(&n) => {
                    st.opted_out.insert(n);
                    json(200, serde_json::json!({}))
                }
                _ => json(400, serde_json::json!({ "message": "phoneNumber must be an E.164 number" })),
            },
            (r, http::Method::GET) if r.starts_with("subscription-tokens/") => {
                let raw = &r["subscription-tokens/".len()..];
                let arn = percent_decode(raw);
                match st.subscriptions.get(&arn) {
                    Some(s) => match &s.token {
                        Some(t) => json(200, serde_json::json!({ "subscriptionArn": arn, "subscriptionToken": t })),
                        None => json(404, serde_json::json!({ "message": "the subscription needs no confirmation" })),
                    },
                    None => json(404, serde_json::json!({ "message": "Subscription does not exist" })),
                }
            }
            _ => json(404, serde_json::json!({ "message": "not found" })),
        };
        Some(response)
    }
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}
