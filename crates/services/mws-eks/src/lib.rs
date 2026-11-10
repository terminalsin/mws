//! Amazon EKS for MWS.
//!
//! Clusters, managed node groups, add-ons, Fargate profiles, access
//! entries, identity provider configs, Pod Identity associations,
//! capabilities, certificate authorities, insights, EKS Anywhere
//! subscriptions and registered (EKS Connector) clusters behave as the EKS
//! API describes them. Resources stay in their transitional states
//! (`CREATING`, `UPDATING`, `DELETING`) for a while on the emulated clock
//! (see `state::durations`; advancing `/_mws/clock` skips the wait), and
//! calls that need a settled resource fail meanwhile as they do on AWS.
//!
//! What a cluster owns in the account is real when an [`Infrastructure`]
//! is wired in (MWS wires EC2 and IAM): subnets are checked and give the
//! cluster its VPC, the cluster security group is created in that VPC, and
//! a managed node group runs EC2 instances from the EKS-optimized AMI with
//! an instance profile for its node role, scaling them as its scaling
//! configuration changes. There is no Kubernetes API server behind the
//! cluster endpoint.
//!
//! AWS couples EKS to IAM (cluster, node and pod roles, `iam:PassRole`),
//! STS (whether `eks.amazonaws.com` and friends may assume those roles) and
//! KMS (envelope encryption keys, used as the caller), so this crate uses
//! STS's and KMS's public APIs.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/eks_generated.rs"));
}

mod access;
mod addons;
mod anywhere;
mod billing;
mod capabilities;
mod catalog;
mod certs;
mod clusters;
mod control;
mod fargate;
mod handler;
mod identity;
mod infra;
mod insights;
pub mod kube;
mod nodegroups;
mod state;
mod tags;
mod updates;
mod util;

use std::sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use billing::BillableCluster;
pub use infra::{
    GroupState, Infrastructure, InfrastructureError, InstanceFacts, LaunchTemplateRef, NodeGroupSpec,
    NodeGroupTemplate, Scope, SubnetFacts,
};
use kube::ControlPlane;
use mws_core::CredentialStore;
use state::State;

pub(crate) struct Inner {
    state: RwLock<State>,
    sts: Option<mws_sts::Sts>,
    /// KMS, for the keys of envelope encryption.
    kms: OnceLock<mws_kms::Kms>,
    infra: OnceLock<Arc<dyn Infrastructure>>,
    /// Service Quotas: clusters, node groups and Fargate profiles.
    quotas: mws_servicequotas::QuotaLink,
    control_plane: OnceLock<Arc<dyn ControlPlane>>,
    credentials: OnceLock<Vec<Arc<dyn CredentialStore>>>,
    /// Control plane log followers, by control plane id.
    log_followers: std::sync::Mutex<std::collections::HashMap<String, tokio::task::AbortHandle>>,
}

impl Inner {
    fn new(sts: Option<mws_sts::Sts>) -> Self {
        Self {
            state: RwLock::new(State::default()),
            sts,
            kms: OnceLock::new(),
            infra: OnceLock::new(),
            quotas: Default::default(),
            control_plane: OnceLock::new(),
            credentials: OnceLock::new(),
            log_followers: Default::default(),
        }
    }
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
        Self { inner: Arc::new(Inner::new(None)) }
    }

    /// EKS that checks roles the way AWS does: they must exist and trust
    /// the service that will assume them.
    pub fn with_sts(sts: mws_sts::Sts) -> Self {
        Self { inner: Arc::new(Inner::new(Some(sts))) }
    }

    /// KMS, which envelope encryption keys are looked up in (as the
    /// caller: `kms:DescribeKey` and `kms:CreateGrant`). Without it only
    /// the shape of the key ARN is checked.
    pub fn set_kms(&self, kms: mws_kms::Kms) {
        let _ = self.inner.kms.set(kms);
    }

    pub(crate) fn kms(&self) -> Option<&mws_kms::Kms> {
        self.inner.kms.get()
    }

    /// Service Quotas, whose applied values limit clusters, node groups
    /// and Fargate profiles.
    pub fn set_service_quotas(&self, quotas: mws_servicequotas::ServiceQuotas) {
        self.inner.quotas.set(quotas);
    }

    /// The applied value of an EKS quota for the caller. Never call with
    /// the state lock held.
    pub(crate) fn quota(&self, ctx: &RequestContext, code: &str) -> usize {
        self.inner.quotas.limit(util::account(ctx), &ctx.region, "eks", code, ctx.received_at)
    }

    /// Where clusters and node groups get their VPC facts, security groups,
    /// instance profiles and instances.
    pub fn set_infrastructure(&self, infra: Arc<dyn Infrastructure>) {
        let _ = self.inner.infra.set(infra);
    }

    /// What runs each cluster's Kubernetes API server. Without one,
    /// clusters are EKS metadata only.
    pub fn set_control_plane(&self, control_plane: Arc<dyn ControlPlane>) {
        let _ = self.inner.control_plane.set(control_plane);
    }

    /// The credential stores that check `aws eks get-token` tokens.
    pub fn set_credentials(&self, stores: Vec<Arc<dyn CredentialStore>>) {
        let _ = self.inner.credentials.set(stores);
    }

    pub(crate) fn control_plane(&self) -> Option<&Arc<dyn ControlPlane>> {
        self.inner.control_plane.get()
    }

    pub(crate) fn credentials(&self) -> &[Arc<dyn CredentialStore>] {
        self.inner.credentials.get().map(Vec::as_slice).unwrap_or_default()
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner.state.read().expect("EKS state lock poisoned")
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

    fn serves_unauthenticated(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(kube::webhook::PREFIX)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path().starts_with(kube::webhook::PREFIX) {
            return self.serve_webhook(&request, ctx.received_at, &ctx.partition, ctx.source_ip.as_deref()).await;
        }
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
        let before = self.control_plane_ids();
        *self.write() = state;
        let after = self.control_plane_ids();
        for id in before.into_iter().filter(|id| !after.contains(id)) {
            self.remove_control_plane(id);
        }
        self.resume_control_planes();
        Ok(())
    }

    fn reset_state(&self) {
        let ids = self.control_plane_ids();
        *self.write() = State::default();
        for id in ids {
            self.remove_control_plane(id);
        }
    }
}
