//! AWS CloudFormation for MWS.
//!
//! Stacks deploy real resources: each resource type's handlers call the
//! other MWS services' APIs (through [`mws_core::Service::invoke`]) as the
//! caller or the stack's service role, so they are validated and
//! authorized like SDK calls, with `aws:CalledVia` naming
//! `cloudformation.amazonaws.com`. The composition root hands this crate
//! the services with [`CloudFormation::set_services`] and a way to assume
//! service roles with [`CloudFormation::set_role_assumer`]; it depends on
//! no other service crate.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/cloudformation_generated.rs"));
}

mod callback;
mod changes;
mod dynamic;
mod engine;
mod intrinsics;
mod ops;
mod parameters;
mod policy;
mod providers;
mod stacksets;
mod state;
mod template;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use mws_core::{
    Authorizer, AuthzDecision, AuthzRequest, Caller, HttpRequest, HttpResponse, RequestContext, Service, ServiceError,
};
use serde_json::Value;

pub(crate) use crate::ops::{imports as ops_imports, new_stack_id as ops_new_stack_id};
use crate::providers::Provider;
use crate::state::State;

/// Assumes a stack's service role (`RoleARN`) as
/// `cloudformation.amazonaws.com`, giving the identity to deploy with.
pub trait RoleAssumer: Send + Sync {
    fn assume(&self, role_arn: &str, session_name: &str, now: chrono::DateTime<chrono::Utc>) -> Result<Caller, String>;

    /// The caller that signs with credentials STS issued (role chaining:
    /// a StackSets administration role assuming execution roles).
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<Caller> {
        let _ = (access_key_id, session_token, now);
        None
    }

    /// The identity service-managed StackSets deploy with in an
    /// Organizations member account: the account's StackSets execution
    /// role, created on first use as AWS's service-linked role does.
    fn org_member(
        &self,
        member_account: &str,
        management_account: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Caller, String> {
        let _ = (now, management_account);
        Err(format!("Account {member_account} cannot be deployed to"))
    }
}

pub(crate) struct Inner {
    state: Mutex<State>,
    services: RwLock<BTreeMap<String, Arc<dyn Service>>>,
    roles: RwLock<Option<Arc<dyn RoleAssumer>>>,
    providers: BTreeMap<&'static str, Arc<dyn Provider>>,
    /// Signals received for custom resources, wait conditions and
    /// creation policies, by key.
    signals: Mutex<HashMap<String, Vec<Value>>>,
    signalled: tokio::sync::Notify,
    /// Stacks with an operation running, and those asked to cancel.
    running: Mutex<BTreeSet<String>>,
    cancel: Mutex<BTreeSet<String>>,
    idle: tokio::sync::Notify,
}

/// The CloudFormation service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct CloudFormation {
    inner: Arc<Inner>,
}

impl Default for CloudFormation {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudFormation {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                services: RwLock::new(BTreeMap::new()),
                roles: RwLock::new(None),
                providers: providers::registry(),
                signals: Mutex::new(HashMap::new()),
                signalled: tokio::sync::Notify::new(),
                running: Mutex::new(BTreeSet::new()),
                cancel: Mutex::new(BTreeSet::new()),
                idle: tokio::sync::Notify::new(),
            }),
        }
    }

    /// The services resource handlers call, by [`Service::name`].
    pub fn set_services(&self, services: impl IntoIterator<Item = Arc<dyn Service>>) {
        let mut m = self.inner.services.write().expect("services lock poisoned");
        for s in services {
            m.insert(s.name().to_string(), s);
        }
    }

    pub fn set_role_assumer(&self, roles: Arc<dyn RoleAssumer>) {
        *self.inner.roles.write().expect("roles lock poisoned") = Some(roles);
    }

    /// Resource types this emulator deploys.
    pub fn resource_types(&self) -> Vec<&'static str> {
        self.inner.providers.keys().copied().collect()
    }

    /// Wait until no stack operation is running (tests, shutdown).
    pub async fn wait_idle(&self) {
        loop {
            let notified = self.inner.idle.notified();
            if self.inner.running.lock().expect("lock").is_empty() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("CloudFormation state lock poisoned")
    }

    pub(crate) fn provider(&self, type_name: &str) -> Option<Arc<dyn Provider>> {
        if providers::is_custom(type_name) {
            return Some(providers::custom_resource_provider());
        }
        self.inner.providers.get(type_name).cloned()
    }

    pub(crate) fn resource_type_of(&self, stack_id: &str, logical_id: &str) -> Option<String> {
        let st = self.state();
        let s = st.stacks.get(stack_id)?;
        let t = crate::template::Template::parse(&s.template_body).ok()?;
        t.resource_type(logical_id).map(str::to_string)
    }

    pub(crate) fn has_type(&self, type_name: &str) -> bool {
        providers::is_custom(type_name) || self.inner.providers.contains_key(type_name)
    }

    /// Run another service's operation with `ctx`'s identity, marked as
    /// called via CloudFormation.
    pub(crate) async fn call(
        &self,
        ctx: &RequestContext,
        service: &str,
        operation: &str,
        input: Value,
    ) -> Result<Value, ServiceError> {
        let svc = self.inner.services.read().expect("services lock poisoned").get(service).cloned();
        let Some(svc) = svc else {
            return Err(ServiceError::client(
                "InvalidRequest",
                400,
                format!("MWS does not emulate the service {service} that this resource needs"),
            ));
        };
        let mut c = ctx.clone();
        c.request_id = uuid::Uuid::new_v4().to_string();
        svc.invoke(c, operation, input).await
    }

    pub(crate) fn role_assumer(&self) -> Option<Arc<dyn RoleAssumer>> {
        self.inner.roles.read().expect("roles lock poisoned").clone()
    }

    /// `ctx` with calls marked as made via CloudFormation.
    pub(crate) fn via(&self, ctx: &RequestContext) -> RequestContext {
        let mut c = ctx.clone();
        c.authorizer = Arc::new(ViaCloudFormation(ctx.authorizer.clone()));
        c
    }

    /// The identity a stack deploys with: `ctx` marked as called via
    /// CloudFormation, or the service role's session.
    pub(crate) fn deploy_context(
        &self,
        ctx: &RequestContext,
        role_arn: Option<&str>,
    ) -> Result<RequestContext, ServiceError> {
        let mut c = ctx.clone();
        if let Some(role) = role_arn {
            let roles = self.inner.roles.read().expect("roles lock poisoned").clone();
            let Some(roles) = roles else {
                return Err(ServiceError::client(
                    "ValidationError",
                    400,
                    format!("Role {role} is invalid or cannot be assumed"),
                ));
            };
            let caller = roles.assume(role, "AWSCloudFormation", ctx.received_at).map_err(|_| {
                ServiceError::client("ValidationError", 400, format!("Role {role} is invalid or cannot be assumed"))
            })?;
            c.caller = caller;
        }
        c.authorizer = Arc::new(ViaCloudFormation(ctx.authorizer.clone()));
        Ok(c)
    }

    pub(crate) fn start(&self, stack_id: &str) {
        self.inner.running.lock().expect("lock").insert(stack_id.to_string());
        self.inner.cancel.lock().expect("lock").remove(stack_id);
    }

    pub(crate) fn finished(&self, stack_id: &str) {
        self.inner.running.lock().expect("lock").remove(stack_id);
        self.inner.cancel.lock().expect("lock").remove(stack_id);
        self.inner.idle.notify_waiters();
    }

    pub(crate) fn request_cancel(&self, stack_id: &str) {
        self.inner.cancel.lock().expect("lock").insert(stack_id.to_string());
    }

    pub(crate) fn cancel_requested(&self, stack_id: &str) -> bool {
        self.inner.cancel.lock().expect("lock").contains(stack_id)
    }

    /// Record a signal (custom resource response, wait condition signal,
    /// `SignalResource`).
    pub(crate) fn signal(&self, key: &str, body: Value) {
        self.inner.signals.lock().expect("lock").entry(key.to_string()).or_default().push(body);
        self.inner.signalled.notify_waiters();
    }

    pub(crate) fn signals(&self, key: &str) -> Vec<Value> {
        self.inner.signals.lock().expect("lock").get(key).cloned().unwrap_or_default()
    }

    pub(crate) fn forget_signals(&self, key: &str) {
        self.inner.signals.lock().expect("lock").remove(key);
    }

    /// Wait for `count` signals under `key`, at most `timeout_secs`.
    pub(crate) async fn wait_for_signals(&self, key: &str, count: usize, timeout_secs: u64) -> Result<Vec<Value>, ()> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.max(1));
        loop {
            let notified = self.inner.signalled.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let got = self.signals(key);
            if got.len() >= count || got.iter().any(|s| s.get("Status").and_then(Value::as_str) == Some("FAILURE")) {
                return Ok(got);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(());
            }
        }
    }
}

/// The key `SignalResource` and creation policies use.
pub(crate) fn signal_key(stack_id: &str, logical_id: &str) -> String {
    format!("signal|{stack_id}|{logical_id}")
}

/// Stacks (by name) in `account`/`region` importing `export`.
pub(crate) fn importers(st: &State, account: &str, region: &str, export: &str) -> Vec<String> {
    st.stacks
        .values()
        .filter(|s| !s.is_deleted() && s.account == account && s.region == region)
        .filter(|s| s.imports.iter().any(|i| i == export))
        .map(|s| s.name.clone())
        .collect()
}

/// Adds the condition keys AWS sets on requests a service makes with the
/// caller's credentials.
struct ViaCloudFormation(Arc<dyn Authorizer>);

impl Authorizer for ViaCloudFormation {
    fn authorize(&self, request: &AuthzRequest<'_>) -> AuthzDecision {
        let mut context = request.context.clone();
        let via = "cloudformation.amazonaws.com".to_string();
        context.insert("aws:CalledVia".into(), vec![via.clone()]);
        context.insert("aws:CalledViaFirst".into(), vec![via.clone()]);
        context.insert("aws:CalledViaLast".into(), vec![via]);
        context.insert("aws:ViaAWSService".into(), vec!["true".into()]);
        self.0.authorize(&AuthzRequest {
            caller: request.caller,
            action: request.action,
            resource: request.resource,
            resource_policy: request.resource_policy,
            resource_policy_mode: request.resource_policy_mode,
            context,
        })
    }
}

#[async_trait::async_trait]
impl Service for CloudFormation {
    fn signing_name(&self) -> &'static str {
        "cloudformation"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path().starts_with(callback::PREFIX) {
            return callback::handle(self, &request);
        }
        let params = mws_proto_query::read_params(&request);
        generated::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(callback::PREFIX)
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
        serde_json::to_value(&*self.state()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let st: State = serde_json::from_value(state).map_err(|e| format!("invalid CloudFormation state: {e}"))?;
        *self.state() = st;
        Ok(())
    }

    fn reset_state(&self) {
        *self.state() = State::default();
        self.inner.signals.lock().expect("lock").clear();
    }
}
