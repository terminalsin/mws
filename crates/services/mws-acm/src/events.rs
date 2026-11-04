//! What ACM tells other services on the emulated clock: the EventBridge
//! events it sends (`ACM Certificate Available`, `... Expired`,
//! `... Renewal Action Required` and the daily `... Approaching
//! Expiration`) and the daily `DaysToExpiry` metric it publishes to
//! CloudWatch in `AWS/CertificateManager`.

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

use crate::certs::validation_method;
use crate::state::Certificate;
use crate::{pki, Acm};

/// One event for the account's default event bus, with source `aws.acm`.
#[derive(Debug, Clone, PartialEq)]
pub struct AcmEvent {
    pub account: String,
    pub region: String,
    pub detail_type: String,
    pub resources: Vec<String>,
    pub detail: Value,
    pub time: DateTime<Utc>,
}

/// One `AWS/CertificateManager` `DaysToExpiry` data point, with the
/// `CertificateArn` dimension.
#[derive(Debug, Clone, PartialEq)]
pub struct DaysToExpiry {
    pub account: String,
    pub region: String,
    pub certificate_arn: String,
    pub days: f64,
    pub time: DateTime<Utc>,
}

fn timestamp(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn event(c: &Certificate, detail_type: &str, detail: Value, now: DateTime<Utc>) -> AcmEvent {
    AcmEvent {
        account: c.account.clone(),
        region: c.region.clone(),
        detail_type: detail_type.into(),
        resources: vec![c.arn.clone()],
        detail,
        time: now,
    }
}

/// The fields every certificate event carries.
fn base_detail(c: &Certificate, not_after: Option<DateTime<Utc>>) -> serde_json::Map<String, Value> {
    let mut d = serde_json::Map::new();
    d.insert("CertificateType".into(), json!(c.ty));
    d.insert("CommonName".into(), json!(c.domain_name));
    if let Some(m) = validation_method(c) {
        d.insert("DomainValidationMethod".into(), json!(m));
    }
    if let Some(t) = c.created_at.or(c.imported_at) {
        d.insert("CertificateCreatedDate".into(), json!(timestamp(t)));
    }
    if let Some(t) = not_after {
        d.insert("CertificateExpirationDate".into(), json!(timestamp(t)));
    }
    d.insert("InUse".into(), json!(false));
    d.insert("Exported".into(), json!(c.exported));
    d
}

/// Whole days left, counted from the second (certificate times have no
/// fractions).
fn days_to_expiry(end: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    let now = DateTime::from_timestamp(now.timestamp(), 0).unwrap_or(now);
    (end - now).num_days()
}

fn not_after(c: &Certificate) -> Option<DateTime<Utc>> {
    c.cert_pem.as_deref().and_then(pki::inspect_pem).map(|i| i.not_after)
}

/// Whether ACM reports on `c` (ACME certificates are the ACME client's).
fn reported(c: &Certificate) -> bool {
    c.origin != "ACME"
}

/// `ACM Certificate Available` after `ISSUANCE`, `RENEWAL`, `IMPORT` or
/// `REIMPORT`.
pub(crate) fn available(c: &Certificate, action: &str, now: DateTime<Utc>) -> Option<AcmEvent> {
    if !reported(c) {
        return None;
    }
    let end = not_after(c);
    let mut d = base_detail(c, end);
    d.insert("Action".into(), json!(action));
    if let Some(end) = end {
        d.insert("DaysToExpiry".into(), json!(days_to_expiry(end, now)));
    }
    Some(event(c, "ACM Certificate Available", Value::Object(d), now))
}

/// `ACM Certificate Expired`.
pub(crate) fn expired(c: &Certificate, now: DateTime<Utc>) -> Option<AcmEvent> {
    reported(c).then(|| event(c, "ACM Certificate Expired", Value::Object(base_detail(c, not_after(c))), now))
}

/// `ACM Certificate Renewal Action Required`: managed renewal cannot
/// finish without the owner (validation records or approvals missing, or
/// the private CA refused).
pub(crate) fn renewal_action_required(c: &Certificate, now: DateTime<Utc>) -> Option<AcmEvent> {
    if !reported(c) {
        return None;
    }
    let end = not_after(c);
    let mut d = base_detail(c, end);
    if let Some(r) = &c.renewal {
        d.insert("RenewalStatus".into(), json!(r.status));
        if let Some(reason) = &r.reason {
            d.insert("RenewalStatusReason".into(), json!(reason));
        }
    }
    if let Some(end) = end {
        d.insert("DaysToExpiry".into(), json!(days_to_expiry(end, now)));
    }
    Some(event(c, "ACM Certificate Renewal Action Required", Value::Object(d), now))
}

impl Acm {
    /// Bring every account's certificates up to date with the clock (as
    /// ACM does in the background), then hand out the events due by `now`,
    /// each once.
    pub fn take_events(&self, now: DateTime<Utc>) -> Vec<AcmEvent> {
        self.advance_all(now);
        let mut st = self.lock();
        let configs = st.account_configs.clone();
        let mut out = std::mem::take(&mut st.pending_events);
        for c in st.certificates.values_mut() {
            if c.status != "ISSUED" {
                continue;
            }
            let Some(info) = c.cert_pem.as_deref().and_then(pki::inspect_pem) else { continue };
            let days = configs.get(&c.account).cloned().unwrap_or_default().days_before_expiry;
            if now >= info.not_after || now < info.not_after - Duration::days(days.into()) {
                continue;
            }
            if c.expiry_event_at.is_some_and(|t| now - t < Duration::days(1)) {
                continue;
            }
            c.expiry_event_at = Some(now);
            out.push(AcmEvent {
                account: c.account.clone(),
                region: c.region.clone(),
                detail_type: "ACM Certificate Approaching Expiration".into(),
                resources: vec![c.arn.clone()],
                detail: json!({
                    "DaysToExpiry": days_to_expiry(info.not_after, now),
                    "CommonName": info.subject_cn.clone().unwrap_or_else(|| c.domain_name.clone()),
                }),
                time: now,
            });
        }
        out
    }

    /// The `DaysToExpiry` data points due by `now`: one a day for each
    /// certificate that has not expired.
    pub fn take_days_to_expiry(&self, now: DateTime<Utc>) -> Vec<DaysToExpiry> {
        let mut st = self.lock();
        let mut out = Vec::new();
        for c in st.certificates.values_mut() {
            if c.status != "ISSUED" || !reported(c) {
                continue;
            }
            let Some(end) = not_after(c) else { continue };
            if end <= now || c.metric_at.is_some_and(|t| now - t < Duration::days(1)) {
                continue;
            }
            c.metric_at = Some(now);
            out.push(DaysToExpiry {
                account: c.account.clone(),
                region: c.region.clone(),
                certificate_arn: c.arn.clone(),
                days: ((end - now).num_seconds() as f64 / 86400.0).floor(),
                time: now,
            });
        }
        out
    }

    /// Run the clock-driven lifecycle for every account, as the last
    /// request's context (only its partition and endpoint matter here).
    fn advance_all(&self, now: DateTime<Utc>) {
        let Some(template) = self.template.lock().expect("ACM template lock poisoned").clone() else { return };
        let accounts: std::collections::BTreeSet<String> = {
            let st = self.lock();
            st.certificates
                .values()
                .map(|c| c.account.clone())
                .chain(st.endpoints.values().map(|e| e.account.clone()))
                .collect()
        };
        for account in accounts {
            let mut ctx = template.clone();
            ctx.received_at = now;
            ctx.caller.account_id = account;
            self.refresh(&ctx);
        }
    }
}
