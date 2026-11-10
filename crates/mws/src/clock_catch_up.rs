//! Background work that AWS does on its own clock, run without waiting
//! for a request to the service that owns it.
//!
//! S3 lifecycle rules (and the event notifications they send), settled
//! replications and restores, and Secrets Manager's scheduled rotations
//! and deletions are caught up whenever *any* API call moves the emulated
//! clock, and once a second while MWS is idle, so a test that advances the
//! clock and then waits on an SQS queue sees the lifecycle event arrive.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use mws_core::{ApiCall, Caller, RequestContext, RequestObserver, ServiceClient};

pub(crate) struct CatchUp {
    s3: mws_s3::S3,
    secrets: mws_secretsmanager::SecretsManager,
    client: ServiceClient,
    partition: String,
    region: String,
    /// The emulated time last caught up to, in milliseconds.
    last_ms: AtomicI64,
    /// Emulated minus wall time, in milliseconds, as of the last call.
    offset_ms: AtomicI64,
    ticking: AtomicBool,
}

impl CatchUp {
    pub(crate) fn new(
        s3: mws_s3::S3,
        secrets: mws_secretsmanager::SecretsManager,
        client: ServiceClient,
        partition: String,
        region: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            s3,
            secrets,
            client,
            partition,
            region,
            last_ms: AtomicI64::new(0),
            offset_ms: AtomicI64::new(0),
            ticking: AtomicBool::new(false),
        })
    }

    /// Run the catch-up at `at` unless it already ran within this second.
    /// `skip` names a service that just caught itself up.
    fn run(&self, at: DateTime<Utc>, region: &str, skip: Option<&str>) {
        let ms = at.timestamp_millis();
        let last = self.last_ms.load(Ordering::Relaxed);
        if ms < last + 1000 || self.last_ms.compare_exchange(last, ms, Ordering::SeqCst, Ordering::Relaxed).is_err() {
            return;
        }
        let Some(authorizer) = self.client.authorizer() else { return };
        let ctx = RequestContext {
            request_id: mws_core::ids::request_id(),
            region: region.to_string(),
            partition: self.partition.clone(),
            received_at: at,
            caller: Caller::service("mws.amazonaws.com", "", None),
            source_ip: None,
            secure_transport: true,
            authorizer,
            endpoint: None,
        };
        if skip != Some("s3") {
            self.s3.catch_up(&ctx);
        }
        if skip != Some("secretsmanager") {
            self.secrets.catch_up(&ctx);
        }
    }

    fn start_ticking(self: &Arc<Self>) {
        if self.ticking.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.ticking.store(false, Ordering::SeqCst);
            return;
        };
        let weak = Arc::downgrade(self);
        handle.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(me) = weak.upgrade() else { return };
                let now = Utc::now() + chrono::Duration::milliseconds(me.offset_ms.load(Ordering::Relaxed));
                let region = me.region.clone();
                me.run(now, &region, None);
            }
        });
    }
}

/// The observer half: every answered call carries the emulated time.
pub(crate) struct Observer(pub Arc<CatchUp>);

impl RequestObserver for Observer {
    fn observe(&self, call: &ApiCall) {
        let offset = (call.at - Utc::now()).num_milliseconds().max(0);
        // Never move the idle clock backwards on a stale request time.
        self.0.offset_ms.fetch_max(offset, Ordering::Relaxed);
        self.0.start_ticking();
        let region = if call.region.is_empty() { self.0.region.clone() } else { call.region.clone() };
        self.0.run(call.at, &region, Some(call.service));
    }
}
