//! Deliveries one service makes to another that failed for a reason worth
//! retrying (the target was throttled or erred), kept and retried on the
//! emulated clock, as AWS services retry their deliveries.
//!
//! [`ServiceClient::deliver`] makes the first attempt at once. When it
//! fails with a retryable error, the call is queued with its retry policy.
//! A background task retries due calls every second, following the clock
//! that `/_mws/clock` moves; `POST /_mws/deliveries/drain` retries every
//! pending call now. Queued calls are part of the emulator's state (the
//! `deliveries` entry of `/_mws/state`), so snapshots and `MWS_DB` keep
//! them. `GET /_mws/deliveries` lists pending and failed calls.

use std::sync::atomic::Ordering;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Caller, HttpRequest, HttpResponse, RequestContext, Service, ServiceClient, ServiceError};

/// How long and how often a failed delivery is retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryPolicy {
    /// Attempts in all, including the first.
    pub max_attempts: u32,
    /// Delay before the first retry; it doubles each time.
    pub base_delay_secs: i64,
    pub max_delay_secs: i64,
    /// Give up once the first attempt is this old.
    pub max_age_secs: i64,
}

impl Default for RetryPolicy {
    /// EventBridge's default: 185 attempts over at most 24 hours.
    fn default() -> Self {
        Self { max_attempts: 185, base_delay_secs: 1, max_delay_secs: 300, max_age_secs: 86_400 }
    }
}

/// One queued call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Delivery {
    pub id: String,
    pub service: String,
    pub operation: String,
    pub input: Value,
    pub caller: Caller,
    pub region: String,
    pub partition: String,
    pub attempts: u32,
    pub first_attempt_at: DateTime<Utc>,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    /// `pending`, or `failed` once the policy gave up.
    pub status: String,
    pub policy: RetryPolicy,
}

impl Default for Delivery {
    fn default() -> Self {
        Self {
            id: String::new(),
            service: String::new(),
            operation: String::new(),
            input: Value::Null,
            caller: Caller::anonymous(),
            region: String::new(),
            partition: "aws".into(),
            attempts: 0,
            first_attempt_at: DateTime::<Utc>::UNIX_EPOCH,
            next_attempt_at: DateTime::<Utc>::UNIX_EPOCH,
            last_error: None,
            status: "pending".into(),
            policy: RetryPolicy::default(),
        }
    }
}

/// How many given-up deliveries are kept for inspection.
const FAILED_KEPT: usize = 1000;

/// Whether a failed call is worth retrying: the target erred or throttled,
/// rather than refusing the call.
pub fn retryable(e: &ServiceError) -> bool {
    e.status >= 500 || e.status == 429 || e.code.contains("Throttl") || e.code.contains("TooManyRequests")
}

fn backoff(policy: &RetryPolicy, attempts: u32) -> chrono::Duration {
    let exp = attempts.saturating_sub(1).min(20);
    let secs = policy.base_delay_secs.max(0).saturating_mul(1i64 << exp).min(policy.max_delay_secs.max(0));
    chrono::Duration::seconds(secs.max(1))
}

impl ServiceClient {
    /// Call `operation` of `service` like [`ServiceClient::call`]; when an
    /// AWS service principal's call fails with a retryable error, queue it
    /// to be retried under `policy`. The first attempt's result is returned
    /// either way.
    pub async fn deliver(
        &self,
        ctx: &RequestContext,
        service: &str,
        operation: &str,
        input: Value,
        policy: RetryPolicy,
    ) -> Result<Value, ServiceError> {
        let result = self.call(ctx, service, operation, input.clone()).await;
        if let Err(e) = &result {
            if retryable(e) && ctx.caller.service_principal().is_some() {
                self.queue(ctx, service, operation, input, policy, e);
            }
        }
        result
    }

    fn queue(
        &self,
        ctx: &RequestContext,
        service: &str,
        operation: &str,
        input: Value,
        policy: RetryPolicy,
        error: &ServiceError,
    ) {
        let now = ctx.received_at;
        self.learn_clock(now);
        let d = Delivery {
            id: crate::ids::request_id(),
            service: service.to_string(),
            operation: operation.to_string(),
            input,
            caller: ctx.caller.clone(),
            region: ctx.region.clone(),
            partition: ctx.partition.clone(),
            attempts: 1,
            first_attempt_at: now,
            next_attempt_at: now + backoff(&policy, 1),
            last_error: Some(format!("{}: {}", error.code, error.message)),
            status: "pending".into(),
            policy,
        };
        if let Ok(mut q) = self.outbox.deliveries.lock() {
            q.push(d);
        }
        self.start_retrying();
    }

    fn learn_clock(&self, emulated_now: DateTime<Utc>) {
        let offset = (emulated_now - Utc::now()).num_milliseconds().max(0);
        self.outbox.clock_offset_ms.fetch_max(offset, Ordering::Relaxed);
    }

    fn now(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::milliseconds(self.outbox.clock_offset_ms.load(Ordering::Relaxed))
    }

    fn start_retrying(&self) {
        if self.outbox.retrying.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.outbox.retrying.store(false, Ordering::SeqCst);
            return;
        };
        let weak = std::sync::Arc::downgrade(&self.outbox);
        let client = self.without_outbox_ref();
        handle.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(outbox) = weak.upgrade() else { return };
                let me = ServiceClient { registry: client.registry.clone(), outbox };
                let now = me.now();
                me.retry_due(now, false).await;
            }
        });
    }

    /// A clone that does not keep the queue alive (for the retry task).
    fn without_outbox_ref(&self) -> ServiceClient {
        ServiceClient { registry: self.registry.clone(), outbox: std::sync::Arc::default() }
    }

    /// Retry queued calls that are due at `now` (all pending ones with
    /// `all`). Returns how many succeeded.
    pub async fn retry_due(&self, now: DateTime<Utc>, all: bool) -> usize {
        let due: Vec<Delivery> = match self.outbox.deliveries.lock() {
            Ok(mut q) => {
                let (due, rest): (Vec<_>, Vec<_>) =
                    q.drain(..).partition(|d| d.status == "pending" && (all || d.next_attempt_at <= now));
                *q = rest;
                due
            }
            Err(_) => return 0,
        };
        let mut delivered = 0;
        for mut d in due {
            let ctx = self.retry_context(&d, now);
            match self.call(&ctx, &d.service, &d.operation, d.input.clone()).await {
                Ok(_) => delivered += 1,
                Err(e) => {
                    d.attempts += 1;
                    d.last_error = Some(format!("{}: {}", e.code, e.message));
                    let next = now + backoff(&d.policy, d.attempts);
                    let too_old = (next - d.first_attempt_at).num_seconds() > d.policy.max_age_secs;
                    if !retryable(&e) || d.attempts >= d.policy.max_attempts || too_old {
                        d.status = "failed".into();
                    } else {
                        d.next_attempt_at = next;
                    }
                    if let Ok(mut q) = self.outbox.deliveries.lock() {
                        q.push(d);
                        let failed = q.iter().filter(|d| d.status == "failed").count();
                        if failed > FAILED_KEPT {
                            if let Some(i) = q.iter().position(|d| d.status == "failed") {
                                q.remove(i);
                            }
                        }
                    }
                }
            }
        }
        delivered
    }

    fn retry_context(&self, d: &Delivery, now: DateTime<Utc>) -> RequestContext {
        let authorizer = self
            .registry
            .read()
            .ok()
            .and_then(|r| r.authorizer.clone())
            .unwrap_or_else(|| std::sync::Arc::new(crate::AllowAll));
        RequestContext {
            request_id: crate::ids::request_id(),
            region: d.region.clone(),
            partition: d.partition.clone(),
            received_at: now,
            caller: d.caller.clone(),
            source_ip: None,
            secure_transport: true,
            authorizer,
            endpoint: self.endpoint(),
        }
    }

    /// The queued calls, pending and failed.
    pub fn deliveries(&self) -> Vec<Delivery> {
        self.outbox.deliveries.lock().map(|q| q.clone()).unwrap_or_default()
    }

    /// A pseudo-service that keeps the queue in the emulator's state and
    /// answers the `/_mws/deliveries` control endpoints.
    pub fn deliveries_service(&self) -> std::sync::Arc<dyn Service> {
        std::sync::Arc::new(Deliveries(self.clone()))
    }
}

struct Deliveries(ServiceClient);

fn respond(status: u16, body: Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body.to_string()))
        .expect("valid response")
}

#[async_trait::async_trait]
impl Service for Deliveries {
    fn signing_name(&self) -> &'static str {
        "mws-deliveries"
    }

    fn name(&self) -> &'static str {
        "deliveries"
    }

    fn claims(&self, _request: &HttpRequest) -> bool {
        false
    }

    /// `GET` lists the queue; `POST .../drain` retries every pending call
    /// now (at `ctx`'s emulated time).
    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.0.learn_clock(ctx.received_at);
        if request.method() == http::Method::POST && request.uri().path().trim_end_matches('/').ends_with("/drain") {
            let delivered = self.0.retry_due(ctx.received_at, true).await;
            let left = self.0.deliveries().iter().filter(|d| d.status == "pending").count();
            return respond(200, json!({ "delivered": delivered, "pending": left }));
        }
        respond(200, json!({ "deliveries": self.0.deliveries() }))
    }

    fn render_error(&self, _request_id: &str, error: &ServiceError) -> HttpResponse {
        respond(error.status, json!({ "error": error.message }))
    }

    fn export_state(&self) -> Option<Value> {
        let q = self.0.deliveries();
        (!q.is_empty()).then(|| json!({ "deliveries": q }))
    }

    fn import_state(&self, state: Value) -> Result<(), String> {
        let q: Vec<Delivery> = match state.get("deliveries") {
            Some(v) => serde_json::from_value(v.clone()).map_err(|e| e.to_string())?,
            None => Vec::new(),
        };
        let pending = q.iter().any(|d| d.status == "pending");
        if let Ok(mut d) = self.0.outbox.deliveries.lock() {
            *d = q;
        }
        if pending {
            self.0.start_retrying();
        }
        Ok(())
    }

    fn reset_state(&self) {
        if let Ok(mut d) = self.0.outbox.deliveries.lock() {
            d.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let p = RetryPolicy { max_attempts: 10, base_delay_secs: 2, max_delay_secs: 10, max_age_secs: 100 };
        let secs: Vec<i64> = (1..6).map(|a| backoff(&p, a).num_seconds()).collect();
        assert_eq!(secs, vec![2, 4, 8, 10, 10]);
    }

    #[test]
    fn only_target_failures_are_retried() {
        assert!(retryable(&ServiceError::internal("boom")));
        assert!(retryable(&ServiceError::client("ThrottlingException", 400, "slow down")));
        assert!(!retryable(&ServiceError::client("AccessDenied", 403, "no")));
    }
}
