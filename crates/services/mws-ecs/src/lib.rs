//! Amazon Elastic Container Service for MWS.
//!
//! The ECS API contract lives here: clusters, task definitions, tasks and
//! their lifecycle (`PROVISIONING` through `STOPPED`), services kept at
//! their desired count by a scheduler with rolling deployments, service
//! deployments and revisions, the deployment circuit breaker, task sets for
//! external deployment controllers, container instances with resource
//! accounting and placement, capacity providers, attributes, account
//! settings, task protection, daemons, gateways and Express services. Every
//! call is authorized through IAM.
//!
//! What actually runs a task's containers is a pluggable
//! [`backend::ContainerBackend`]: [`backend::DockerBackend`] runs them as
//! Docker containers (awsvpc tasks share a network namespace on their VPC's
//! network), [`backend::MetadataBackend`] runs nothing. Through
//! [`platform::TaskPlatform`] MWS gives `awsvpc` tasks real EC2 network
//! interfaces, task and execution role credentials from STS, container
//! secrets from Secrets Manager and Parameter Store, and `awslogs` output in
//! CloudWatch Logs. Containers find the task metadata endpoint (v4) and their
//! credentials at `/_aws/ecs/` (see [`metadata`]).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ecs_generated.rs"));
}

mod asg;
pub mod backend;
mod billing;
mod capacity;
mod clusters;
mod console;
mod daemons;
mod express;
mod gateways;
mod handler;
mod instances;
mod loadbalancing;
pub mod metadata;
mod names;
pub mod platform;
mod runner;
mod scheduler;
mod services;
mod settings;
mod state;
mod tags;
mod taskdefs;
mod tasks;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use backend::{BackendChoice, ContainerBackend, DockerBackend, MetadataBackend};
pub use billing::BillableTask;
pub use platform::TaskPlatform;
use state::{Region, State};

pub(crate) struct Inner {
    state: Mutex<State>,
    backend: Arc<dyn ContainerBackend>,
    platform: OnceLock<Arc<dyn TaskPlatform>>,
    /// Stop signals of the tasks this process runs, by task ARN.
    runners: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    /// The latest request's context and the emulated clock's offset from
    /// the wall clock, for work done in the background.
    template: Mutex<Option<(RequestContext, chrono::Duration)>>,
    scheduler_started: AtomicBool,
    /// Wakes the scheduler early.
    kick: tokio::sync::Notify,
    /// Since when each Auto Scaling capacity provider (`account/region/name`)
    /// has wanted fewer instances, for managed scale-in.
    low_reservation: Mutex<HashMap<String, chrono::DateTime<chrono::Utc>>>,
}

/// `(lastStatus, desiredStatus)` of every task, by region key and ARN.
type TaskStatuses = HashMap<(String, String), (Option<String>, Option<String>)>;

fn task_statuses(st: &State) -> TaskStatuses {
    st.regions
        .iter()
        .flat_map(|(key, r)| {
            r.tasks.iter().map(move |(arn, t)| {
                ((key.clone(), arn.clone()), (t.task.last_status.clone(), t.task.desired_status.clone()))
            })
        })
        .collect()
}

/// The locked ECS state; see [`Ecs::lock`].
pub(crate) struct StateGuard<'a> {
    ecs: &'a Ecs,
    guard: Option<MutexGuard<'a, State>>,
    before: Option<TaskStatuses>,
}

impl std::ops::Deref for StateGuard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.guard.as_ref().expect("held")
    }
}

impl std::ops::DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.guard.as_mut().expect("held")
    }
}

impl Drop for StateGuard<'_> {
    fn drop(&mut self) {
        let Some(guard) = self.guard.take() else { return };
        let Some(before) = self.before.take() else { return };
        let mut changes = Vec::new();
        for (key, r) in &guard.regions {
            for (arn, rec) in &r.tasks {
                let now = (rec.task.last_status.clone(), rec.task.desired_status.clone());
                if before.get(&(key.clone(), arn.clone())) != Some(&now) {
                    changes.push((key.clone(), tasks::render(r, rec, false)));
                }
            }
        }
        drop(guard);
        if !changes.is_empty() {
            self.ecs.report_task_changes(changes);
        }
    }
}

/// The ECS service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Ecs {
    inner: Arc<Inner>,
}

impl Default for Ecs {
    fn default() -> Self {
        Self::new(Arc::new(MetadataBackend))
    }
}

impl Ecs {
    pub fn new(backend: Arc<dyn ContainerBackend>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                backend,
                platform: OnceLock::new(),
                runners: Mutex::new(HashMap::new()),
                template: Mutex::new(None),
                scheduler_started: AtomicBool::new(false),
                kick: tokio::sync::Notify::new(),
                low_reservation: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Give tasks network interfaces, credentials, secrets and logs.
    pub fn set_platform(&self, platform: Arc<dyn TaskPlatform>) {
        let _ = self.inner.platform.set(platform);
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend.name()
    }

    pub(crate) fn backend(&self) -> Arc<dyn ContainerBackend> {
        self.inner.backend.clone()
    }

    pub(crate) fn platform(&self) -> Option<Arc<dyn TaskPlatform>> {
        self.inner.platform.get().cloned()
    }

    /// The state. Every task whose `lastStatus` or `desiredStatus` changes
    /// while it is held is reported (`ECS Task State Change`) once it is
    /// released.
    pub(crate) fn lock(&self) -> StateGuard<'_> {
        let guard = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let before = self.platform().map(|_| task_statuses(&guard));
        StateGuard { ecs: self, guard: Some(guard), before }
    }

    /// Report task state changes to the platform (EventBridge).
    fn report_task_changes(&self, changes: Vec<(String, generated::types::Task)>) {
        let Some(platform) = self.platform() else { return };
        let Some((template, offset)) = self.inner.template.lock().expect("ECS template lock poisoned").clone() else {
            return;
        };
        let time = chrono::Utc::now() + offset;
        for (key, task) in changes {
            let Some((account, region)) = key.split_once('/') else { continue };
            let ctx = RequestContext { region: region.to_string(), ..template.clone() };
            let detail = generated::ser::ser_task(&task);
            platform.task_state_change(&ctx, account, task.task_arn.as_deref().unwrap_or_default(), detail, time);
        }
    }

    /// Remember `ctx` for background work, and start the scheduler.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = ctx.received_at - chrono::Utc::now();
        *self.inner.template.lock().expect("ECS template lock poisoned") = Some((ctx.clone(), offset));
        if !self.inner.scheduler_started.swap(true, Ordering::SeqCst) {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let me = self.clone();
                rt.spawn(async move { me.scheduler_loop().await });
            } else {
                self.inner.scheduler_started.store(false, Ordering::SeqCst);
            }
        }
    }

    /// A context for background work in `account` and `region`, at the
    /// emulated time now.
    pub(crate) fn background_context(&self, account: &str, region: &str) -> Option<RequestContext> {
        let (mut ctx, offset) = self.inner.template.lock().expect("ECS template lock poisoned").clone()?;
        ctx.request_id = uuid::Uuid::new_v4().to_string();
        ctx.region = region.to_string();
        ctx.received_at = chrono::Utc::now() + offset;
        ctx.caller = mws_core::Caller { account_id: account.to_string(), ..mws_core::Caller::anonymous() };
        ctx.source_ip = None;
        Some(ctx)
    }

    /// The emulated time now.
    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        let offset = self
            .inner
            .template
            .lock()
            .expect("ECS template lock poisoned")
            .as_ref()
            .map(|(_, o)| *o)
            .unwrap_or_else(chrono::Duration::zero);
        chrono::Utc::now() + offset
    }

    /// Run `f` on the caller's account and Region, with due transitions
    /// applied first.
    pub(crate) fn with_region<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut Region, &names::Scope) -> R) -> R {
        let scope = names::Scope::of(ctx);
        let mut st = self.lock();
        let r = st.region(&scope.key());
        tasks::expire(r, ctx.received_at);
        services::settle(r, ctx.received_at);
        f(r, &scope)
    }
}

#[async_trait::async_trait]
impl Service for Ecs {
    fn signing_name(&self) -> &'static str {
        "ecs"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(metadata::PREFIX)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path().starts_with(metadata::PREFIX) {
            return metadata::serve(self, &request);
        }
        if request.uri().path().starts_with(console::PREFIX) {
            return console::serve(self, &ctx, &request).await;
        }
        self.observe(&ctx);
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, &names::ecs_denial(error.clone()))
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.observe(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&*self.lock()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid ECS state: {e}"))?;
        let old = std::mem::replace(&mut *self.inner.state.lock().unwrap_or_else(|e| e.into_inner()), state);
        self.tear_down(old);
        Ok(())
    }

    fn reset_state(&self) {
        let old = std::mem::take(&mut *self.inner.state.lock().unwrap_or_else(|e| e.into_inner()));
        self.tear_down(old);
    }
}

impl Ecs {
    /// Stop what the backend runs for state that was replaced.
    fn tear_down(&self, old: State) {
        let signals: Vec<_> = self.inner.runners.lock().expect("ECS runner lock poisoned").drain().collect();
        for (_, s) in &signals {
            s.notify_one();
        }
        let backend = self.backend();
        if backend.name() == "metadata" {
            return;
        }
        let leftovers: Vec<(backend::TaskSpec, String, Vec<String>)> = old
            .regions
            .values()
            .flat_map(|r| r.tasks.values())
            .filter(|t| t.task.last_status.as_deref() != Some("STOPPED"))
            .filter_map(|t| {
                let handle = t.handle.clone()?;
                Some((runner::spec_of(t), handle, t.runtime_ids.values().cloned().collect()))
            })
            .collect();
        if leftovers.is_empty() {
            return;
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                for (spec, handle, ids) in leftovers {
                    backend.cleanup(&spec, &handle, &ids).await;
                }
            });
        }
    }
}
