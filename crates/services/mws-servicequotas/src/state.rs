//! Service Quotas state, per account. Times are epoch milliseconds on the
//! emulated clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How long an increase request stays `PENDING` before it is approved.
pub const APPROVAL_MS: i64 = 1_000;

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
}

impl Request {
    pub fn open(&self) -> bool {
        matches!(self.status.as_str(), "PENDING" | "CASE_OPENED")
    }
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
    /// Approve requests whose review is over.
    pub fn settle(&mut self, now: i64) {
        for r in self.requests.values_mut() {
            if r.open() && r.settles_at <= now {
                r.status = "APPROVED".into();
                r.updated = r.settles_at;
                self.applied.insert(key(&r.region, r.global, &r.service, &r.code), r.desired);
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub accounts: BTreeMap<String, Account>,
}
