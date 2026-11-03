//! Email validation approvals.
//!
//! ACM emails the domain's contacts a link to approve a certificate
//! request. MWS sends no mail: it logs each "email" with its link, and
//! opening the link (an unsigned `GET` or `POST` to
//! `/_acm/approvals?certificate=<arn>&domain=<domain>`) approves that
//! domain, as clicking "I Approve" does.

use bytes::Bytes;
use http::{Method, StatusCode};
use mws_core::{HttpRequest, HttpResponse, RequestContext};

use crate::Acm;

pub const PATH: &str = "/_acm/approvals";

pub fn is_approval_request(request: &HttpRequest) -> bool {
    request.uri().path() == PATH && matches!(*request.method(), Method::GET | Method::POST)
}

fn encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// The link the validation email for `domain` carries.
pub fn approval_link(base: &str, arn: &str, domain: &str) -> String {
    format!("{base}{PATH}?certificate={}&domain={}", encode(arn), encode(domain))
}

fn page(status: StatusCode, message: &str) -> HttpResponse {
    let body = format!(
        "<!doctype html><html><head><title>Certificate approval</title></head><body><p>{message}</p></body></html>"
    );
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Bytes::from(body))
        .expect("valid response")
}

impl Acm {
    pub(crate) async fn approval_http(&self, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
        let query = request.uri().query().unwrap_or_default();
        let mut arn = None;
        let mut domain = None;
        for (k, v) in form_pairs(query) {
            match k.as_str() {
                "certificate" => arn = Some(v),
                "domain" => domain = Some(v.to_ascii_lowercase()),
                _ => {}
            }
        }
        let (Some(arn), Some(domain)) = (arn, domain) else {
            return page(StatusCode::BAD_REQUEST, "The approval link is incomplete.");
        };
        match self.approve_email(&arn, &domain, ctx.received_at) {
            Ok(()) => page(StatusCode::OK, &format!("Success! You approved the certificate for {domain}.")),
            Err(e) => page(StatusCode::BAD_REQUEST, &format!("The approval could not be completed: {e}.")),
        }
    }
}

fn form_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let dec =
                |s: &str| percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned();
            (dec(k), dec(v))
        })
        .collect()
}
