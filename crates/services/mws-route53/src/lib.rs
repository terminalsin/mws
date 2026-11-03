//! Amazon Route 53 for MWS.
//!
//! Public and private hosted zones, atomic `ChangeResourceRecordSets` with
//! Route 53's validation messages, record listing in Route 53's order,
//! change tracking, health checks and tags, reusable delegation sets,
//! traffic policies and instances, DNSSEC key-signing keys, CIDR
//! collections, query logging configurations, VPC association
//! authorizations, limits and the geolocation catalogue. Every operation is authorized
//! through the configured [`Authorizer`](mws_core::Authorizer) with
//! Route 53's actions, resource ARNs and condition keys.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/route53_generated.rs"));
}

mod cidr;
mod delegation;
mod dns;
mod dnssec;
mod handler;
mod health;
mod limits;
mod names;
mod query_logging;
mod records;
mod state;
mod tags;
mod traffic;
mod vpc_authorizations;
mod zones;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use rand::Rng;

pub use dns::{answer as dns_answer, serve as serve_dns};
use generated::types;
pub use names::{display as display_name, normalize as normalize_name};
use state::State;

/// The Route 53 service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Route53 {
    state: Arc<Mutex<State>>,
}

impl Route53 {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Route 53 state lock poisoned")
    }

    /// Ask the authorizer. Route 53 state is not involved, but keep the
    /// habit of authorizing before taking the lock.
    fn authorize(&self, ctx: &RequestContext, action: &str, resource: &str) -> Result<(), ServiceError> {
        ctx.authorize(&format!("route53:{action}"), resource, ConditionContext::new())
    }

    /// A read-only view of the record sets of every zone, for an optional
    /// DNS front end or tests: `(zone name, record sets)`.
    pub fn snapshot(&self) -> Vec<(String, Vec<types::ResourceRecordSet>)> {
        let st = self.lock();
        st.zones.values().map(|z| (z.name.clone(), z.records.values().cloned().collect())).collect()
    }
}

/// `arn:{partition}:route53:::{kind}/{id}`
fn arn(ctx: &RequestContext, kind: &str, id: &str) -> String {
    format!("arn:{}:route53:::{kind}/{id}", ctx.partition)
}

/// Route 53 style id: a prefix letter and uppercase alphanumerics.
fn new_id(prefix: char) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::thread_rng();
    let mut id = String::with_capacity(21);
    id.push(prefix);
    for _ in 0..20 {
        id.push(ALPHABET[rng.gen_range(0..ALPHABET.len())] as char);
    }
    id
}

/// SDKs strip `/hostedzone/` and friends, but raw callers may not.
fn strip_id(id: &str) -> &str {
    for p in ["/hostedzone/", "hostedzone/", "/change/", "change/", "/delegationset/", "delegationset/"] {
        if let Some(rest) = id.strip_prefix(p) {
            return rest;
        }
    }
    id
}

/// Clamp a `MaxItems` value to Route 53's default and ceiling.
fn max_items(requested: Option<i32>, default: usize, ceiling: usize) -> usize {
    match requested {
        Some(n) if n > 0 => (n as usize).min(ceiling),
        _ => default,
    }
}

#[async_trait::async_trait]
impl Service for Route53 {
    fn signing_name(&self) -> &'static str {
        "route53"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restxml::error_response(&generated::SERVICE_INFO, request_id, error)
    }
    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("Route 53 state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Route 53 state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
