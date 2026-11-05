//! Amazon EKS for MWS.
//!
//! Clusters, managed node groups, add-ons, Fargate profiles, access
//! entries, identity provider configs, Pod Identity associations,
//! capabilities, certificate authorities, insights, EKS Anywhere
//! subscriptions and registered (EKS Connector) clusters behave as the EKS
//! API describes them. Resources move through their transitional states
//! (`CREATING`, `UPDATING`, `DELETING`) and settle on the next request, so
//! SDK waiters finish on their first poll.
//!
//! What a cluster owns in the account is real when an [`Infrastructure`]
//! is wired in (MWS wires EC2 and IAM): subnets are checked and give the
//! cluster its VPC, the cluster security group is created in that VPC, and
//! a managed node group runs EC2 instances from the EKS-optimized AMI with
//! an instance profile for its node role, scaling them as its scaling
//! configuration changes. There is no Kubernetes API server behind the
//! cluster endpoint.
//!
//! AWS couples EKS to IAM (cluster, node and pod roles, `iam:PassRole`) and
//! STS (whether `eks.amazonaws.com` and friends may assume those roles), so
//! this crate uses STS's public API.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/eks_generated.rs"));
}

mod access;
mod addons;
mod anywhere;
mod capabilities;
mod catalog;
mod certs;
mod clusters;
mod fargate;
mod handler;
mod identity;
mod infra;
mod insights;
mod nodegroups;
mod state;
mod tags;
mod updates;
mod util;

use std::sync::{Arc, OnceLock, RwLock, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use infra::{Infrastructure, InfrastructureError, NodeLaunch, Scope, SubnetFacts};
use state::State;

pub(crate) struct Inner {
    state: RwLock<State>,
    sts: Option<mws_sts::Sts>,
    infra: OnceLock<Arc<dyn Infrastructure>>,
}

/// The EKS service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Eks {
    inner: Arc<Inner>,
}

impl Default for Eks {
    fn default() -> Self {
        Self::new()
    }
}

impl Eks {
    /// EKS on its own: roles are not checked and clusters own nothing in
    /// EC2.
    pub fn new() -> Self {
        Self { inner: Arc::new(Inner { state: RwLock::new(State::default()), sts: None, infra: OnceLock::new() }) }
    }

    /// EKS that checks roles the way AWS does: they must exist and trust
    /// the service that will assume them.
    pub fn with_sts(sts: mws_sts::Sts) -> Self {
        Self { inner: Arc::new(Inner { state: RwLock::new(State::default()), sts: Some(sts), infra: OnceLock::new() }) }
    }

    /// Where clusters and node groups get their VPC facts, security groups,
    /// instance profiles and instances.
    pub fn set_infrastructure(&self, infra: Arc<dyn Infrastructure>) {
        let _ = self.inner.infra.set(infra);
    }

    pub(crate) fn infra(&self) -> Option<&Arc<dyn Infrastructure>> {
        self.inner.infra.get()
    }

    pub(crate) fn sts(&self) -> Option<&mws_sts::Sts> {
        self.inner.sts.as_ref()
    }

    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.state.write().expect("EKS state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for Eks {
    fn signing_name(&self) -> &'static str {
        "eks"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.settle(&ctx);
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.settle(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.inner.state.read().expect("EKS state lock poisoned");
        Some(serde_json::to_value(&*state).expect("EKS state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid EKS state: {e}"))?;
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
    }
}
