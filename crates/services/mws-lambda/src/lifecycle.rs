//! Function states, as Lambda moves through them: a new function is
//! `Pending` until its execution environment is set up, then `Active`; an
//! update leaves `LastUpdateStatus: InProgress` until it is applied, then
//! `Successful`. While a function is `Pending`, invoking it fails; while it
//! is `Pending` or an update is in progress, further updates fail with
//! `ResourceConflictException`, exactly the error that AWS's
//! `function_active_v2` and `function_updated_v2` waiters exist to avoid.
//! Invocations during an update run the code and configuration from before
//! it, as on AWS.
//!
//! The transition takes `MWS_LAMBDA_STATE_TRANSITION_MS` milliseconds (one
//! second unless set; `MWS_ASYNC_DELAY_MS=0` also makes it instant).

use std::time::Duration;

use chrono::{DateTime, Utc};
use mws_core::ServiceError;

use crate::generated::{errors, types};
use crate::names::FunctionRef;
use crate::state::{Function, Version};
use crate::Lambda;

/// How long a create or an update takes to complete.
pub(crate) fn transition() -> Duration {
    static MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    Duration::from_millis(*MS.get_or_init(|| {
        std::env::var("MWS_LAMBDA_STATE_TRANSITION_MS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| mws_core::settle::window(Duration::from_millis(1000)).as_millis() as u64)
    }))
}

/// The longest a service-initiated invocation waits for a `Pending`
/// function to become `Active`.
const WAIT_FOR_ACTIVE: Duration = Duration::from_secs(60);

fn in_flight(func: &Function, now: DateTime<Utc>) -> bool {
    func.settles_at.is_some_and(|t| t > now)
}

/// Mark a configuration `Pending` (a function being created).
pub(crate) fn mark_pending(c: &mut types::FunctionConfiguration) {
    c.state = Some("Pending".into());
    c.state_reason = Some("The function is being created.".into());
    c.state_reason_code = Some("Creating".into());
}

/// Mark a configuration's last update `InProgress`.
pub(crate) fn mark_in_progress(c: &mut types::FunctionConfiguration) {
    c.last_update_status = Some("InProgress".into());
    c.last_update_status_reason = Some("The function is being created.".into());
    c.last_update_status_reason_code = Some("Creating".into());
}

fn settle_config(c: &mut types::FunctionConfiguration) {
    if c.state.as_deref() == Some("Pending") {
        c.state = Some("Active".into());
        c.state_reason = None;
        c.state_reason_code = None;
    }
    if c.last_update_status.as_deref() == Some("InProgress") {
        c.last_update_status = Some("Successful".into());
        c.last_update_status_reason = None;
        c.last_update_status_reason_code = None;
    }
}

/// Complete whatever create or update the function has in flight.
pub(crate) fn settle(func: &mut Function) {
    settle_config(&mut func.latest.config);
    for v in func.versions.values_mut() {
        settle_config(&mut v.config);
    }
    func.previous = None;
    func.settles_at = None;
}

/// Complete what is due by `now` (a transition whose timer never ran).
pub(crate) fn settle_if_due(func: &mut Function, now: DateTime<Utc>) {
    if func.settles_at.is_some_and(|t| t <= now) {
        settle(func);
    }
}

/// Fails like Lambda when the function cannot be updated now: it is still
/// being created, or an earlier update is in progress.
pub(crate) fn check_updatable(func: &Function) -> Result<(), ServiceError> {
    if in_flight(func, Utc::now()) {
        return Err(errors::resource_conflict(format!(
            "The operation cannot be performed at this time. An update is in progress for resource: {}",
            func.arn
        )));
    }
    Ok(())
}

/// Fails like Lambda's `Invoke` when the version is not yet `Active`.
pub(crate) fn check_invocable(func: &Function, qualifier: Option<&str>) -> Result<(), ServiceError> {
    let Some(v) = func.version_for(qualifier) else { return Ok(()) };
    if in_flight(func, Utc::now()) && v.config.state.as_deref() == Some("Pending") {
        return Err(errors::resource_conflict(
            "The operation cannot be performed at this time. The function is currently in the following state: Pending",
        ));
    }
    Ok(())
}

/// The version an invocation of `version` runs: during an update of
/// `$LATEST`, the one from before the update.
pub(crate) fn running_version<'a>(func: &'a Function, version: &str) -> Option<&'a Version> {
    if version == "$LATEST" && in_flight(func, Utc::now()) {
        if let Some(p) = &func.previous {
            return Some(p);
        }
    }
    func.version_for(Some(version))
}

impl Lambda {
    /// Start a create or an update of `function_arn`: it completes after
    /// [`transition`].
    pub(crate) fn begin_transition(&self, func: &mut Function) {
        let delay = transition();
        func.settles_at = Some(Utc::now() + chrono::Duration::from_std(delay).unwrap_or_default());
        let arn = func.arn.clone();
        let handle = match tokio::runtime::Handle::try_current() {
            Ok(h) if !delay.is_zero() => h,
            _ => {
                settle(func);
                return;
            }
        };
        let weak = std::sync::Arc::downgrade(&self.inner);
        handle.spawn(async move {
            tokio::time::sleep(delay).await;
            let Some(inner) = weak.upgrade() else { return };
            let lambda = Lambda { inner };
            let mut st = lambda.write();
            if let Some(func) = st.functions.get_mut(&arn) {
                settle_if_due(func, Utc::now());
            }
        });
    }

    /// Wait (for a service-initiated invocation) until the function is no
    /// longer `Pending`.
    pub(crate) async fn wait_until_invocable(&self, f: &FunctionRef) {
        let started = std::time::Instant::now();
        loop {
            let pending = {
                let st = self.read();
                st.functions.get(&f.arn()).is_some_and(|func| check_invocable(func, f.qualifier.as_deref()).is_err())
            };
            if !pending || started.elapsed() > WAIT_FOR_ACTIVE {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
