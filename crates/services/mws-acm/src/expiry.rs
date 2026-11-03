//! "ACM Certificate Approaching Expiration" events: ACM sends one a day
//! for each certificate from the account's `DaysBeforeExpiry` until it
//! expires.

use chrono::{DateTime, Duration, Utc};

use crate::{pki, Acm};

/// One approaching-expiration event, for EventBridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryEvent {
    pub account: String,
    pub region: String,
    pub certificate_arn: String,
    pub common_name: String,
    pub days_to_expiry: i64,
    pub time: DateTime<Utc>,
}

impl Acm {
    /// The approaching-expiration events due by `now` (the emulated
    /// clock), each handed out once.
    pub fn take_expiry_events(&self, now: DateTime<Utc>) -> Vec<ExpiryEvent> {
        let mut st = self.lock();
        let configs = st.account_configs.clone();
        let mut out = Vec::new();
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
            out.push(ExpiryEvent {
                account: c.account.clone(),
                region: c.region.clone(),
                certificate_arn: c.arn.clone(),
                common_name: info.subject_cn.clone().unwrap_or_else(|| c.domain_name.clone()),
                days_to_expiry: (info.not_after - now).num_days(),
                time: now,
            });
        }
        out
    }
}
