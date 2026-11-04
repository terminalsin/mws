//! What the passage of time does to CAs, on MWS's emulated clock.
//!
//! ACM PCA does these in the background; MWS applies them lazily before
//! each request, so moving `/_mws/clock` forward has the same effect:
//!
//! - a CA whose certificate has expired becomes `EXPIRED`;
//! - a `DELETED` CA whose restoration period has ended is gone for good;
//! - CRLs are regenerated (and republished to S3) before they lapse.

use chrono::{DateTime, Utc};

use crate::revocation;
use crate::PrivateCa;

impl PrivateCa {
    pub(crate) fn advance(&self, now: DateTime<Utc>) {
        let mut st = self.lock();
        st.cas.retain(|_, ca| !(ca.status == "DELETED" && ca.restorable_until.is_some_and(|t| t <= now)));
        for ca in st.cas.values_mut() {
            if let Some(end) = ca.not_after.filter(|end| *end <= now) {
                if matches!(ca.status.as_str(), "ACTIVE" | "DISABLED") {
                    ca.status = "EXPIRED".into();
                    ca.last_state_change_at = end;
                }
            }
            if !matches!(ca.status.as_str(), "ACTIVE" | "DISABLED") {
                continue;
            }
            // A new CRL once half of the current one's validity has passed,
            // so relying parties never hold a lapsed CRL.
            let stale = ca.crl.as_ref().is_some_and(|c| now >= c.this_update + (c.next_update - c.this_update) / 2);
            if stale && revocation::refresh_crl(ca, now).is_ok() {
                self.publish_crl(ca);
            }
        }
    }
}
