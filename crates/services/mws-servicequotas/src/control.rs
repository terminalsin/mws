//! Scripting the review of increase requests, served unsigned at
//! `/_aws/servicequotas/`:
//!
//! * `GET /_aws/servicequotas/review`: the review policy.
//! * `POST /_aws/servicequotas/review` with any of `{"autoApprove": true,
//!   "approvalSeconds": 1, "caseThresholdFactor": 20, "caseReviewSeconds":
//!   86400, "caseOutcome": "APPROVED"}`: change it. `autoApprove: false`
//!   leaves every request open until it is decided here; the threshold is
//!   a multiple of the quota's starting value above which a request goes to
//!   `CASE_OPENED` instead of being approved; `caseOutcome` is what a
//!   reviewed case ends as (`APPROVED`, `DENIED`, `NOT_APPROVED`,
//!   `INVALID_REQUEST`, `CASE_CLOSED`).
//! * `GET /_aws/servicequotas/requests[?account=]`: every request.
//! * `POST /_aws/servicequotas/requests/{id}` with `{"status": "DENIED"}`:
//!   decide an open request now (`APPROVED` applies the value;
//!   `CASE_OPENED` escalates it).

use bytes::Bytes;
use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};

use crate::state::{Review, CLOSED_STATUSES};
use crate::ServiceQuotas;

pub const PREFIX: &str = "/_aws/servicequotas/";

fn respond(status: u16, body: Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body.to_string()))
        .expect("static response parts are valid")
}

fn error(status: u16, message: impl Into<String>) -> HttpResponse {
    respond(status, json!({ "message": message.into() }))
}

fn review_doc(r: &Review) -> Value {
    json!({
        "autoApprove": r.auto_approve,
        "approvalSeconds": r.approval_ms as f64 / 1000.0,
        "caseThresholdFactor": r.case_threshold_factor,
        "caseReviewSeconds": r.case_review_ms as f64 / 1000.0,
        "caseOutcome": r.case_outcome,
    })
}

fn query(request: &HttpRequest, name: &str) -> Option<String> {
    request.uri().query()?.split('&').filter_map(|p| p.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.into())
}

impl ServiceQuotas {
    pub(crate) fn serve_control(&self, request: &HttpRequest, now: i64) -> HttpResponse {
        let rest = request.uri().path().strip_prefix(PREFIX).unwrap_or_default().trim_end_matches('/');
        let body: Value = if request.body().is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(request.body()) {
                Ok(v) => v,
                Err(e) => return error(400, format!("invalid JSON: {e}")),
            }
        };
        let method = request.method().clone();
        match (method, rest.split('/').collect::<Vec<_>>().as_slice()) {
            (http::Method::GET, ["review"]) => respond(200, review_doc(&self.review())),
            (http::Method::POST, ["review"]) => {
                let mut st = self.lock();
                let r = &mut st.review;
                if let Some(v) = body.get("autoApprove").and_then(Value::as_bool) {
                    r.auto_approve = v;
                }
                if let Some(v) = body.get("approvalSeconds").and_then(Value::as_f64) {
                    r.approval_ms = (v * 1000.0) as i64;
                }
                if let Some(v) = body.get("caseThresholdFactor").and_then(Value::as_f64) {
                    r.case_threshold_factor = v;
                }
                if let Some(v) = body.get("caseReviewSeconds").and_then(Value::as_f64) {
                    r.case_review_ms = (v * 1000.0) as i64;
                }
                if let Some(v) = body.get("caseOutcome").and_then(Value::as_str) {
                    if !CLOSED_STATUSES.contains(&v) {
                        return error(400, format!("caseOutcome must be one of {}", CLOSED_STATUSES.join(", ")));
                    }
                    r.case_outcome = v.into();
                }
                respond(200, review_doc(r))
            }
            (http::Method::GET, ["requests"]) => {
                let account = query(request, "account");
                let st = self.lock();
                let list: Vec<Value> = st
                    .accounts
                    .iter()
                    .filter(|(a, _)| account.as_ref().is_none_or(|x| x == *a))
                    .flat_map(|(a, acct)| {
                        acct.requests.values().map(move |r| {
                            json!({"account": a, "id": r.id, "serviceCode": r.service, "quotaCode": r.code,
                                "region": r.region, "desiredValue": r.desired, "status": r.status,
                                "caseId": r.case_id})
                        })
                    })
                    .collect();
                respond(200, json!({ "requests": list }))
            }
            (http::Method::POST, ["requests", id]) => {
                let Some(status) = body.get("status").and_then(Value::as_str) else {
                    return error(400, "give a status");
                };
                if status != "CASE_OPENED" && !CLOSED_STATUSES.contains(&status) {
                    return error(400, format!("status must be CASE_OPENED or one of {}", CLOSED_STATUSES.join(", ")));
                }
                let mut st = self.lock();
                let review = st.review.clone();
                let Some(acct) = st.accounts.values_mut().find(|a| a.requests.contains_key(*id)) else {
                    return error(404, format!("no request {id}"));
                };
                acct.settle(now, &review);
                match acct.decide(id, status, now, &review) {
                    Ok(r) => respond(200, json!({"id": r.id, "status": r.status, "caseId": r.case_id})),
                    Err(e) => error(409, e),
                }
            }
            _ => error(404, "not found"),
        }
    }
}
