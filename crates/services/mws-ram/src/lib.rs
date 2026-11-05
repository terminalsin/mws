//! AWS Resource Access Manager (RAM) for MWS.
//!
//! Resource shares grant other principals access to resources an account
//! owns: AWS accounts (which accept an invitation unless they are in the
//! owner's organization and sharing with the organization is on), whole
//! organizations or organizational units, IAM roles and users, and AWS
//! service principals (with the accounts they act for as sources).
//!
//! Sharing is real. For each shared resource RAM turns the share's managed
//! permissions and principals into a resource-based policy and installs it
//! on the resource through the [`ShareableResourceType`] its service
//! registered, so the owning service's own authorization (and the IAM
//! authorizer, for cross-account calls) decides with it. Removing a
//! principal, resource or share takes the access away again.
//!
//! A resource policy set directly on a shareable resource (Private CA's
//! `PutPolicy`) shows up as a share "created from policy", which
//! `PromoteResourceShareCreatedFromPolicy` turns into a standard one.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ram_generated.rs"));
}

mod catalog;
mod handler;
mod invitations;
mod permissions;
mod policies;
mod principals;
mod shares;
mod state;
mod util;

use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_iam::Iam;
use mws_organizations::Organizations;

use state::State;

/// Where a shareable resource lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLocation {
    pub owner_account: String,
    pub region: String,
}

/// A kind of resource RAM can share, implemented by the service that owns
/// it and registered with [`Ram::register_resource_type`].
pub trait ShareableResourceType: Send + Sync {
    /// `service:Type`, e.g. `acm-pca:CertificateAuthority`.
    fn resource_type(&self) -> &'static str;
    /// The service prefix, e.g. `acm-pca`.
    fn service_name(&self) -> &'static str;
    /// Whether `arn` names a resource of this type (it may not exist).
    fn matches(&self, arn: &str) -> bool;
    /// The resource's owner and region, if it exists.
    fn locate(&self, arn: &str) -> Option<ResourceLocation>;
    /// Install the policy RAM computed for the resource; `None` removes it.
    fn set_shared_policy(&self, arn: &str, policy: Option<String>);
    /// The actions a RAM permission for this type may grant.
    fn shareable_actions(&self) -> &'static [&'static str];
    /// The action the sharer needs on the resource to share it (RAM
    /// writes the resource's policy on their behalf).
    fn share_action(&self) -> &'static str;
}

/// The RAM service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Ram {
    state: Arc<Mutex<State>>,
    iam: Iam,
    organizations: Organizations,
    types: Arc<RwLock<Vec<Arc<dyn ShareableResourceType>>>>,
}

impl Ram {
    pub fn new(iam: Iam, organizations: Organizations) -> Self {
        Self { state: Arc::default(), iam, organizations, types: Arc::default() }
    }

    /// Make a resource type shareable.
    pub fn register_resource_type(&self, ty: Arc<dyn ShareableResourceType>) {
        self.types.write().expect("RAM types lock poisoned").push(ty);
    }

    fn resource_types(&self) -> Vec<Arc<dyn ShareableResourceType>> {
        self.types.read().expect("RAM types lock poisoned").clone()
    }

    fn type_for_arn(&self, arn: &str) -> Option<Arc<dyn ShareableResourceType>> {
        self.resource_types().into_iter().find(|t| t.matches(arn))
    }

    fn type_named(&self, name: &str) -> Option<Arc<dyn ShareableResourceType>> {
        self.resource_types().into_iter().find(|t| t.resource_type().eq_ignore_ascii_case(name))
    }

    /// Never hold this while calling `ctx.authorize` or a resource type:
    /// the IAM authorizer and the owning services take their own locks.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("RAM state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for Ram {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        generated::operation_for(request).is_some()
    }

    fn signing_name(&self) -> &'static str {
        "ram"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.advance(&ctx);
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
        self.advance(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("RAM state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid RAM state: {e}"))?;
        *self.lock() = state;
        self.push_all_policies();
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
