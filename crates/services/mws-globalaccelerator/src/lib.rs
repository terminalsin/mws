//! AWS Global Accelerator for MWS.
//!
//! Standard accelerators get two static anycast IPv4 addresses (plus two
//! IPv6 addresses for dual stack), one from each network zone, unique
//! across accounts, and a DNS name. Listeners take TCP or UDP port ranges;
//! endpoint groups (one per Region per listener) hold Application and
//! Network Load Balancers, EC2 instances and Elastic IP addresses. Endpoint
//! ids are checked against the services that own them through
//! [`EndpointDirectory`], which also reports their health, so a stopped
//! instance or a load balancer that is gone shows as `UNHEALTHY`.
//!
//! Custom routing accelerators map listener ports deterministically onto
//! every address and destination port of their VPC subnet endpoints
//! (`ListCustomRoutingPortMappings`), with per-destination allow/deny.
//!
//! BYOIP address ranges move through their provisioning and advertising
//! states on the emulated clock and their addresses can be given to
//! accelerators; cross-account attachments let other accounts (or
//! accelerators) use an account's endpoints and address ranges. Every
//! change puts the accelerator `IN_PROGRESS` until it deploys, and every
//! call is authorized through IAM.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/globalaccelerator_generated.rs"));
}

mod accelerators;
mod attachments;
mod byoip;
mod custom;
mod groups;
mod handler;
mod ips;
mod listeners;
mod names;
mod state;

use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

/// What a directory knows about an endpoint or subnet id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// This directory does not handle ids of this kind.
    NotMine,
    /// This directory handles the kind, and the resource does not exist.
    Missing,
    Found(T),
}

/// An endpoint's health, as Global Accelerator would see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHealth {
    pub healthy: bool,
    /// Why it is unhealthy.
    pub reason: Option<String>,
}

impl EndpointHealth {
    pub fn healthy() -> Self {
        Self { healthy: true, reason: None }
    }

    pub fn unhealthy(reason: impl Into<String>) -> Self {
        Self { healthy: false, reason: Some(reason.into()) }
    }
}

/// Where endpoints live: EC2 (instances, Elastic IPs, subnets) and Elastic
/// Load Balancing. MWS wires these to the services that own them.
pub trait EndpointDirectory: Send + Sync {
    /// The endpoint `id` (a load balancer ARN, instance id or Elastic IP
    /// allocation id) in `account` and `region`.
    fn endpoint(&self, account: &str, region: &str, id: &str) -> Lookup<EndpointHealth> {
        let _ = (account, region, id);
        Lookup::NotMine
    }

    /// The IPv4 CIDR block of VPC subnet `id`.
    fn subnet(&self, account: &str, region: &str, id: &str) -> Lookup<String> {
        let _ = (account, region, id);
        Lookup::NotMine
    }
}

#[derive(Default)]
pub(crate) struct Inner {
    state: Mutex<State>,
    directories: RwLock<Vec<Arc<dyn EndpointDirectory>>>,
}

/// The Global Accelerator service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct GlobalAccelerator {
    inner: Arc<Inner>,
}

/// An accelerator's addresses, for DNS: its DNS names and static IPs.
#[derive(Debug, Clone)]
pub struct AcceleratorAddresses {
    pub dns_name: String,
    pub dual_stack_dns_name: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub enabled: bool,
}

impl GlobalAccelerator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Endpoints and subnets are looked up here, in the order added.
    pub fn add_endpoint_directory(&self, directory: Arc<dyn EndpointDirectory>) {
        self.inner.directories.write().expect("directory lock poisoned").push(directory);
    }

    /// The accelerator whose DNS name (or dual-stack DNS name) is `name`.
    pub fn addresses_for_dns_name(&self, name: &str) -> Option<AcceleratorAddresses> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let st = self.lock();
        st.accelerators
            .values()
            .find(|a| a.dns_name == name || a.dual_stack_dns_name.as_deref() == Some(name.as_str()))
            .map(|a| {
                let dual = a.dual_stack_dns_name.as_deref() == Some(name.as_str());
                AcceleratorAddresses {
                    dns_name: a.dns_name.clone(),
                    dual_stack_dns_name: a.dual_stack_dns_name.clone(),
                    ipv4: a.ipv4.clone(),
                    // The plain DNS name answers IPv4 only.
                    ipv6: if dual { a.ipv6.clone() } else { Vec::new() },
                    enabled: a.enabled,
                }
            })
    }

    pub(crate) fn lookup_endpoint(&self, account: &str, region: &str, id: &str) -> Lookup<EndpointHealth> {
        let dirs = self.inner.directories.read().expect("directory lock poisoned").clone();
        for d in dirs {
            match d.endpoint(account, region, id) {
                Lookup::NotMine => continue,
                other => return other,
            }
        }
        Lookup::NotMine
    }

    pub(crate) fn lookup_subnet(&self, account: &str, region: &str, id: &str) -> Lookup<String> {
        let dirs = self.inner.directories.read().expect("directory lock poisoned").clone();
        for d in dirs {
            match d.subnet(account, region, id) {
                Lookup::NotMine => continue,
                other => return other,
            }
        }
        Lookup::NotMine
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("Global Accelerator state lock poisoned")
    }

    pub(crate) fn settled(&self, ctx: &RequestContext) -> MutexGuard<'_, State> {
        let mut st = self.lock();
        st.settle(names::now_ms(ctx));
        st
    }
}

#[async_trait::async_trait]
impl Service for GlobalAccelerator {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "globalaccelerator"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, &names::denial(error.clone()))
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
        Some(serde_json::to_value(state).expect("Global Accelerator state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State =
            serde_json::from_value(state).map_err(|e| format!("invalid Global Accelerator state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
