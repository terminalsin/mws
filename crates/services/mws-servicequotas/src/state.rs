//! Service Quotas state, per account. Times are epoch milliseconds on the
//! emulated clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How increase requests are reviewed (set through
/// `/_aws/servicequotas/review`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Review {
    /// Requests settle by themselves; when false they stay open until the
    /// control endpoint decides them.
    pub auto_approve: bool,
    /// How long a request within the automatic-approval threshold stays
    /// `PENDING` before it is approved, in milliseconds.
    pub approval_ms: i64,
    /// Requests for more than this many times the AWS default value are
    /// not approved automatically: they go to `CASE_OPENED`.
    pub case_threshold_factor: f64,
    /// How long a support case is reviewed, in milliseconds.
    pub case_review_ms: i64,
    /// What a reviewed case ends as: `APPROVED`, `DENIED`, `NOT_APPROVED`,
    /// `INVALID_REQUEST` or `CASE_CLOSED`.
    pub case_outcome: String,
}

impl Default for Review {
    fn default() -> Self {
        Self {
            auto_approve: true,
            approval_ms: 1_000,
            case_threshold_factor: 20.0,
            case_review_ms: 24 * 3_600_000,
            case_outcome: "APPROVED".into(),
        }
    }
}

/// The statuses a request can be closed with.
pub const CLOSED_STATUSES: &[&str] = &["APPROVED", "DENIED", "NOT_APPROVED", "INVALID_REQUEST", "CASE_CLOSED"];

/// The key of a quota value: `region|service|code`, with `global` for
/// quotas that apply across Regions.
pub fn key(region: &str, global: bool, service: &str, code: &str) -> String {
    let region = if global { "global" } else { region };
    format!("{region}|{service}|{code}")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Request {
    pub id: String,
    pub service: String,
    pub code: String,
    /// The Region the request was made in.
    pub region: String,
    pub global: bool,
    pub desired: f64,
    /// `PENDING`, `CASE_OPENED`, `APPROVED`, `DENIED`, `CASE_CLOSED`,
    /// `NOT_APPROVED`, `INVALID_REQUEST`.
    pub status: String,
    pub created: i64,
    pub updated: i64,
    pub case_id: Option<String>,
    /// `{"accountId":..,"callerArn":..}`.
    pub requester: String,
    /// `AutomaticManagement` for requests made by automatic management.
    pub request_type: Option<String>,
    pub settles_at: i64,
    /// Too large to approve automatically: the request becomes a support
    /// case once its first review is over.
    pub escalate: bool,
}

impl Request {
    pub fn open(&self) -> bool {
        matches!(self.status.as_str(), "PENDING" | "CASE_OPENED")
    }

    /// Open a support case for the request at `now`.
    pub fn open_case(&mut self, now: i64, review: &Review) {
        self.case_id.get_or_insert_with(|| format!("{}", 10_000_000_000u64 + (now as u64 % 1_000_000_000)));
        self.status = "CASE_OPENED".into();
        self.updated = now;
        self.settles_at = now + review.case_review_ms;
    }
}

/// A new `PENDING` request's review: when it settles, and whether it
/// needs a support case (more than the threshold times AWS's default).
pub fn review_of(review: &Review, created: i64, desired: f64, default: f64) -> (i64, bool) {
    let escalate = default > 0.0 && desired > default * review.case_threshold_factor;
    (created + review.approval_ms, escalate)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoManagement {
    pub opt_in_level: String,
    pub opt_in_type: String,
    pub notification_arn: Option<String>,
    /// Excluded quotas by service code.
    pub exclusions: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportEntry {
    pub service: String,
    pub code: String,
    pub usage: f64,
    pub applied: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub id: String,
    pub generated_at: i64,
    pub entries: Vec<ReportEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    /// Applied values that differ from the default, by [`key`].
    pub applied: BTreeMap<String, f64>,
    /// Increase requests by id.
    pub requests: BTreeMap<String, Request>,
    /// Tags by quota ARN.
    pub tags: BTreeMap<String, BTreeMap<String, String>>,
    /// The organization's quota request template (management accounts):
    /// desired values by [`key`].
    pub template: BTreeMap<String, f64>,
    /// When the template was associated with the organization.
    pub template_associated_at: Option<i64>,
    /// The template's requests were made for this (member) account.
    pub template_applied: bool,
    pub auto_management: Option<AutoManagement>,
    pub reports: BTreeMap<String, Report>,
}

impl Account {
    /// Move on requests whose review is over: small ones are approved,
    /// large ones become support cases, and reviewed cases end as the
    /// review policy says.
    pub fn settle(&mut self, now: i64, review: &Review) {
        if !review.auto_approve {
            return;
        }
        let mut approved = Vec::new();
        for r in self.requests.values_mut() {
            while r.open() && r.settles_at <= now {
                let at = r.settles_at;
                if r.status == "PENDING" && r.escalate {
                    r.open_case(at, review);
                    continue;
                }
                let outcome = if r.status == "CASE_OPENED" { review.case_outcome.as_str() } else { "APPROVED" };
                r.status = outcome.to_string();
                r.updated = at;
                if outcome == "APPROVED" {
                    approved.push(r.clone());
                }
            }
        }
        for r in approved {
            self.applied.insert(key(&r.region, r.global, &r.service, &r.code), r.desired);
        }
    }

    /// Close request `id` with `status` (one of [`CLOSED_STATUSES`]), or
    /// escalate it with `CASE_OPENED`.
    pub fn decide(&mut self, id: &str, status: &str, now: i64, review: &Review) -> Result<Request, String> {
        let r = self.requests.get_mut(id).ok_or_else(|| format!("no request {id}"))?;
        if !r.open() {
            return Err(format!("request {id} is already {}", r.status));
        }
        if status == "CASE_OPENED" {
            r.open_case(now, review);
            return Ok(r.clone());
        }
        r.status = status.to_string();
        r.updated = now;
        let r = r.clone();
        if status == "APPROVED" {
            self.applied.insert(key(&r.region, r.global, &r.service, &r.code), r.desired);
        }
        Ok(r)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub accounts: BTreeMap<String, Account>,
    pub review: Review,
}
