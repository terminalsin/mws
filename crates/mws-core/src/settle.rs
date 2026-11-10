//! How long work that AWS does asynchronously takes here.
//!
//! Many AWS operations return before the work they start is done: the
//! resource is `CREATING`/`PENDING` first, reads answer
//! `RequestInProgressException`, and SDK waiters poll until it settles. MWS
//! keeps that window short but real, so code that forgets to wait fails
//! locally the way it would against AWS.
//!
//! The window is measured on the emulated clock (`RequestContext::received_at`),
//! so advancing the clock settles pending work at once. It defaults to
//! [`DEFAULT_DELAY_MS`] and is set with `MWS_ASYNC_DELAY_MS` (`0` makes such
//! work complete inside the call that starts it).

use std::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Duration, Utc};

/// The default settle window, in milliseconds.
pub const DEFAULT_DELAY_MS: i64 = 500;

const UNSET: i64 = -1;
static DELAY_MS: AtomicI64 = AtomicI64::new(UNSET);

/// The settle window.
pub fn delay() -> Duration {
    let mut ms = DELAY_MS.load(Ordering::Relaxed);
    if ms == UNSET {
        ms = std::env::var("MWS_ASYNC_DELAY_MS")
            .ok()
            .and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|v| *v >= 0)
            .unwrap_or(DEFAULT_DELAY_MS);
        DELAY_MS.store(ms, Ordering::Relaxed);
    }
    Duration::milliseconds(ms)
}

/// Override the settle window for this process (tests, embedders).
pub fn set_delay(delay: Duration) {
    DELAY_MS.store(delay.num_milliseconds().max(0), Ordering::Relaxed);
}

/// When work started at `since` is done.
pub fn settles_at(since: DateTime<Utc>) -> DateTime<Utc> {
    since + delay()
}

/// Whether work started at `since` is done at `now`.
///
/// When `now` is earlier than `since` the emulated clock was moved back past
/// the start; the work counts as done rather than pending until the clock
/// catches up again.
pub fn settled(since: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now < since || now - since >= delay()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows() {
        set_delay(Duration::milliseconds(500));
        let t = Utc::now();
        assert!(!settled(t, t));
        assert!(!settled(t, t + Duration::milliseconds(499)));
        assert!(settled(t, t + Duration::milliseconds(500)));
        assert!(settled(t, t - Duration::seconds(1)));
        assert_eq!(settles_at(t), t + Duration::milliseconds(500));
    }
}
