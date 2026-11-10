//! What EC2 tells other services about instances on its own: `EC2 Instance
//! State-change Notification` events (EventBridge), the `AWS/EC2` metrics
//! (CloudWatch, see [`crate::metrics`]), and the emulated clock that drives
//! them.
//!
//! State-change events come from comparing every instance's state before
//! and after each change to a Region's state, so every transition is
//! reported once, whichever operation (or background settle) made it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;

use crate::state::RegionState;
use crate::Ec2;

/// One instance state transition, as EC2 reports it to EventBridge
/// (`aws.ec2` / `EC2 Instance State-change Notification`).
#[derive(Debug, Clone, PartialEq)]
pub struct InstanceStateChange {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub instance_id: String,
    pub instance_arn: String,
    /// `pending`, `running`, `stopping`, `stopped`, `shutting-down` or
    /// `terminated`.
    pub state: String,
    pub time: DateTime<Utc>,
}

/// Where instance state-change events go (EventBridge, in MWS).
pub trait StateChangeSink: Send + Sync {
    fn put(&self, ctx: &RequestContext, change: InstanceStateChange);
}

#[derive(Default)]
pub(crate) struct Signals {
    events: OnceLock<Arc<dyn StateChangeSink>>,
    /// How far the emulated clock runs ahead of the wall clock.
    offset_ms: AtomicI64,
    scheduler: AtomicBool,
    /// How long the metadata backend takes to settle a transition
    /// (pending to running, stopping to stopped, shutting-down to
    /// terminated), in milliseconds. 0 settles at once.
    transition_ms: AtomicU64,
    pub(crate) meter: crate::metrics::Meter,
    /// A request's context, for the state changes the background tick
    /// reports.
    template: std::sync::Mutex<Option<RequestContext>>,
}

/// Every instance's state, by id.
pub(crate) fn instance_states(r: &RegionState) -> BTreeMap<String, String> {
    r.instances.iter().map(|(id, i)| (id.clone(), crate::ops::instance::state_name(i))).collect()
}

/// The instances whose state differs from `before` (new ones included).
pub(crate) fn changed_states(before: &BTreeMap<String, String>, r: &RegionState) -> Vec<(String, String)> {
    r.instances
        .iter()
        .filter_map(|(id, i)| {
            let now = crate::ops::instance::state_name(i);
            (!now.is_empty() && before.get(id) != Some(&now)).then(|| (id.clone(), now))
        })
        .collect()
}

impl Ec2 {
    /// Put `EC2 Instance State-change Notification` events through `sink`.
    pub fn set_state_change_sink(&self, sink: Arc<dyn StateChangeSink>) {
        let _ = self.inner.signals.events.set(sink);
    }

    pub(crate) fn wants_state_changes(&self) -> bool {
        self.inner.signals.events.get().is_some()
    }

    /// How long instances on the metadata backend take to finish a
    /// transition (`pending` to `running`, `stopping` to `stopped`,
    /// `shutting-down` to `terminated`). Zero, the default, settles at
    /// once; MWS itself sets a short delay so code has to wait the way it
    /// does on AWS.
    pub fn set_transition_delay(&self, delay: std::time::Duration) {
        self.inner.signals.transition_ms.store(delay.as_millis() as u64, Ordering::Relaxed);
    }

    pub(crate) fn transition_delay(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.inner.signals.transition_ms.load(Ordering::Relaxed))
    }

    /// Keep `ctx` for the state changes settled with no request.
    pub(crate) fn remember_context(&self, ctx: &RequestContext) {
        let mut t = self.inner.signals.template.lock().unwrap_or_else(|e| e.into_inner());
        if t.is_none() {
            *t = Some(ctx.clone());
        }
    }

    pub(crate) fn remembered_context(&self) -> Option<RequestContext> {
        self.inner.signals.template.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The emulated clock's current time, as last seen on a request.
    pub(crate) fn clock_now(&self) -> DateTime<Utc> {
        Utc::now() + Duration::milliseconds(self.inner.signals.offset_ms.load(Ordering::Relaxed))
    }

    /// Learn the emulated clock from a request received at `at` (any
    /// service's: MWS reports every request), start the background loop
    /// that publishes metrics, and publish what came due.
    pub fn observe_time(&self, at: DateTime<Utc>) {
        let offset = (at - Utc::now()).num_milliseconds().max(0);
        let signals = &self.inner.signals;
        // A request's time ages while it is handled; small steps back are
        // that, not the clock moving back.
        let known = signals.offset_ms.load(Ordering::Relaxed);
        if offset > known || known - offset > 5_000 {
            signals.offset_ms.store(offset, Ordering::Relaxed);
        }
        if tokio::runtime::Handle::try_current().is_ok() && !signals.scheduler.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move {
                let mut tick = 0u64;
                loop {
                    if tick == 0 && me.metrics_wanted() {
                        me.sample_usage().await;
                    }
                    tick = (tick + 1) % 10;
                    me.settle_due_everywhere();
                    me.publish_metrics(me.clock_now());
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
        }
        if self.metrics_wanted() {
            self.publish_metrics(self.clock_now().max(at));
        }
    }

    /// Report the state changes a call made.
    pub(crate) fn emit_state_changes(
        &self,
        ctx: &RequestContext,
        account: &str,
        region: &str,
        changes: Vec<(String, String)>,
    ) {
        let Some(sink) = self.inner.signals.events.get() else { return };
        let time = self.clock_now().max(ctx.received_at);
        for (id, state) in changes {
            let ctx = RequestContext { region: region.to_string(), ..ctx.clone() };
            sink.put(
                &ctx,
                InstanceStateChange {
                    partition: ctx.partition.clone(),
                    account: account.to_string(),
                    region: region.to_string(),
                    instance_arn: format!("arn:{}:ec2:{region}:{account}:instance/{id}", ctx.partition),
                    instance_id: id,
                    state,
                    time,
                },
            );
        }
    }
}
