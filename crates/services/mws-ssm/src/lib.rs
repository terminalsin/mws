//! AWS Systems Manager for MWS: Parameter Store, documents, Run Command,
//! maintenance windows and patch baselines.
//!
//! Parameters keep up to 100 versions with labels, tags, descriptions and
//! allowed patterns, in the standard or advanced tier (or chosen by
//! Intelligent-Tiering), and are found by name, ARN, `name:version`,
//! `name:label`, path or filters. `SecureString` values are really
//! encrypted with MWS's KMS for the caller ([`secure`]). Parameter policies
//! are validated, and `Expiration` deletes parameters when the emulated
//! clock passes it ([`policies`]). Advanced parameters can be shared with
//! other accounts through resource policies. `/aws/reference/secretsmanager/`
//! names resolve Secrets Manager secrets through a
//! [`SecretsManagerReferences`] the composition root provides. Every call is
//! authorized through IAM, with `aws:ResourceTag` conditions. Creating,
//! updating, deleting and labelling parameters reports "Parameter Store
//! Change" events through a [`ParameterChangeSink`].
//!
//! Documents and Run Command run
//! `aws:runShellScript` steps on managed nodes, the EC2 instances with an
//! instance profile that a [`ManagedNodes`] reports. Maintenance windows
//! run on the emulated clock. Patch Manager keeps baselines and patch
//! groups, and `AWS-RunPatchBaseline` really scans (and patches) nodes.
//! State Manager associations apply documents on their schedule
//! ([`associations`]); inventory and compliance come from the nodes
//! ([`inventory`], [`compliance`]); resource data syncs write inventory into
//! S3 ([`nodes`]). Automation runbooks run step by step through the other
//! services' APIs ([`automation`], [`engine`]), Change Manager change
//! requests wait for approval, and OpsCenter keeps OpsItems ([`ops`]).
//! Sessions answer `NotImplemented`.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ssm_generated.rs"));
}

mod activations;
mod associations;
mod automation;
mod changes;
mod commands;
mod compliance;
mod documents;
mod engine;
mod events;
mod handler;
mod inventory;
mod maintenance;
mod names;
mod nodes;
mod ops;
mod outputs;
mod params;
mod patch;
mod plugins;
pub mod policies;
mod public;
mod query;
mod references;
pub mod secure;
mod service_ops;
mod sessions;
mod settings;
mod sharing;
mod state;
mod tags;

use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;

pub use automation::{AutomationRuntime, ScriptCredentials};
pub use changes::{ParameterChange, ParameterChangeSink};
pub use commands::{ManagedNode, ManagedNodes, ShellOutput};
pub use events::SsmEvent;
pub use maintenance::{TaskInvoker, WindowEvent};
pub use nodes::DataSyncDestination;
pub use outputs::{CommandNotification, CommandOutputs, NodeRef};
pub use references::{ReferencedSecret, SecretsManagerReferences};
pub use service_ops::ServiceOpsItem;
pub use sessions::{SessionIo, SessionKind};

use names::{now, resource_tag_conditions, ParamRef};
use state::{Parameter, State};

/// The Parameter Store service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Ssm {
    state: Arc<Mutex<State>>,
    kms: Kms,
    secrets: Arc<RwLock<Option<Arc<dyn SecretsManagerReferences>>>>,
    changes: Arc<RwLock<Option<Arc<dyn ParameterChangeSink>>>>,
    nodes: Arc<RwLock<Option<Arc<dyn ManagedNodes>>>>,
    invoker: Arc<RwLock<Option<Arc<dyn TaskInvoker>>>>,
    data_sync: Arc<RwLock<Option<Arc<dyn DataSyncDestination>>>>,
    automation: Arc<RwLock<Option<Arc<dyn AutomationRuntime>>>>,
    sessions: Arc<sessions::SessionHub>,
    /// The most recent request, as a template for work the clock starts
    /// (maintenance window Lambda tasks).
    template: Arc<RwLock<Option<RequestContext>>>,
    /// How far the emulated clock ran ahead at the last request.
    clock_offset_ms: Arc<std::sync::atomic::AtomicI64>,
    /// Whether the maintenance window ticker runs.
    ticking: Arc<std::sync::atomic::AtomicBool>,
    /// EventBridge events waiting for the composition root.
    events: Arc<Mutex<Vec<SsmEvent>>>,
    /// Each change calendar's last known state (open or not).
    calendar_states: Arc<Mutex<std::collections::HashMap<String, bool>>>,
    /// Where command output and notifications go (S3, Logs, SNS).
    outputs: Arc<RwLock<Option<Arc<dyn CommandOutputs>>>>,
    /// The authorizer clock-driven work uses before SSM has seen a request
    /// (after restoring saved state).
    authorizer: Arc<std::sync::OnceLock<Arc<dyn mws_core::Authorizer>>>,
}

impl Ssm {
    /// SecureString parameters are encrypted with keys from `kms`.
    pub fn new(kms: Kms) -> Self {
        Self {
            state: Arc::default(),
            kms,
            secrets: Arc::default(),
            changes: Arc::default(),
            nodes: Arc::default(),
            invoker: Arc::default(),
            data_sync: Arc::default(),
            automation: Arc::default(),
            sessions: Arc::default(),
            template: Arc::default(),
            clock_offset_ms: Arc::default(),
            ticking: Arc::default(),
            events: Arc::default(),
            calendar_states: Arc::default(),
            outputs: Arc::default(),
            authorizer: Arc::default(),
        }
    }

    /// The authorizer clock-driven work (maintenance windows,
    /// associations) uses before SSM has seen a request, as after
    /// restoring saved state.
    pub fn set_authorizer(&self, authorizer: Arc<dyn mws_core::Authorizer>) {
        let _ = self.authorizer.set(authorizer);
    }

    /// Start the ticker that runs maintenance windows, associations, data
    /// syncs and change calendars on the emulated clock (once).
    fn start_ticking(&self) {
        if tokio::runtime::Handle::try_current().is_err()
            || self.ticking.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let ssm = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let offset = ssm.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed);
                let at = chrono::Utc::now() + chrono::Duration::milliseconds(offset);
                ssm.run_windows(at, false);
                ssm.run_associations(at);
                ssm.run_data_syncs(at);
                ssm.check_calendars(at);
            }
        });
    }

    /// Resolve `/aws/reference/secretsmanager/...` names through `secrets`.
    pub fn set_secrets_manager(&self, secrets: Arc<dyn SecretsManagerReferences>) {
        *self.secrets.write().expect("SSM secrets lock poisoned") = Some(secrets);
    }

    /// Manage these nodes (EC2 instances with an instance profile) and run
    /// commands on them.
    pub fn set_managed_nodes(&self, nodes: Arc<dyn ManagedNodes>) {
        *self.nodes.write().expect("SSM nodes lock poisoned") = Some(nodes);
    }

    /// The last request's context, or (before any request) one made from
    /// the authorizer set with [`Ssm::set_authorizer`].
    pub(crate) fn template(&self) -> Option<RequestContext> {
        if let Some(t) = self.template.read().expect("SSM template lock poisoned").clone() {
            return Some(t);
        }
        let authorizer = self.authorizer.get()?.clone();
        let offset = self.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed);
        Some(RequestContext {
            request_id: String::new(),
            region: String::new(),
            partition: "aws".into(),
            received_at: chrono::Utc::now() + chrono::Duration::milliseconds(offset),
            caller: mws_core::Caller::anonymous(),
            source_ip: None,
            secure_transport: true,
            authorizer,
            endpoint: None,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("SSM state lock poisoned")
    }

    /// Delete the parameters of the caller's Region whose `Expiration`
    /// policy has passed, then return a copy of `r`'s parameter.
    fn snapshot(&self, ctx: &RequestContext, r: &ParamRef) -> Option<Parameter> {
        let mut st = self.lock();
        let region = st.region(&r.account, &r.region);
        sweep(region, now(ctx));
        region.parameters.get(&r.key()).cloned()
    }

    /// Authorize `ssm:{action}` on `r`, with its tags and resource policy.
    fn authorize_param(
        &self,
        ctx: &RequestContext,
        action: &str,
        r: &ParamRef,
        param: Option<&Parameter>,
        mut extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let policy = param.and_then(Parameter::policy_document);
        if let Some(p) = param {
            extra.extend(resource_tag_conditions(&p.tags));
        }
        ctx.authorize_with_resource_policy(&format!("ssm:{action}"), &r.arn(), policy.as_deref(), extra)
    }
}

/// Drop expired parameters, keeping their `Expiration` events.
fn sweep(region: &mut state::Region, now: chrono::DateTime<chrono::Utc>) {
    let mut expired = Vec::new();
    region.parameters.retain(|_, p| {
        let latest = p.latest();
        let Some(at) = latest.policies.iter().filter_map(policies::expiration).find(|t| *t <= now) else {
            return true;
        };
        expired.push((latest.name.clone(), latest.param_type.clone(), at));
        false
    });
    region.expired.extend(expired.into_iter().map(|(name, parameter_type, time)| policies::PolicyEvent {
        account: String::new(),
        region: String::new(),
        name,
        parameter_type,
        policy_type: "Expiration".into(),
        action_status: "Finished".into(),
        action_reason: "The parameter has expired and was deleted.".into(),
        time,
    }));
}

impl Ssm {
    /// The parameter policy events due by `now` (the emulated clock), each
    /// handed out once: expirations (deleting the parameters), and
    /// `ExpirationNotification`/`NoChangeNotification` notices, whose
    /// policies are then `Finished`.
    pub fn take_policy_events(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<policies::PolicyEvent> {
        let mut out = Vec::new();
        let mut st = self.lock();
        for (key, region) in st.regions.iter_mut() {
            let Some((account, region_name)) = key.split_once('/') else { continue };
            sweep(region, now);
            for mut e in region.expired.drain(..) {
                e.account = account.to_string();
                e.region = region_name.to_string();
                out.push(e);
            }
            for p in region.parameters.values_mut() {
                let Some(latest) = p.versions.last_mut() else { continue };
                let snapshot = latest.clone();
                for policy in latest.policies.iter_mut().filter(|p| p.status == "Pending") {
                    let Some((due, reason)) = policies::notification_due(policy, &snapshot) else { continue };
                    if due > now {
                        continue;
                    }
                    policy.status = "Finished".into();
                    out.push(policies::PolicyEvent {
                        account: account.to_string(),
                        region: region_name.to_string(),
                        name: snapshot.name.clone(),
                        parameter_type: snapshot.param_type.clone(),
                        policy_type: policy.policy_type.clone(),
                        action_status: "Pending".into(),
                        action_reason: reason,
                        time: due,
                    });
                }
            }
        }
        out
    }
}

#[async_trait::async_trait]
impl Service for Ssm {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "ssm"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        *self.template.write().expect("SSM template lock poisoned") = Some(ctx.clone());
        let offset = (ctx.received_at - chrono::Utc::now()).num_milliseconds().max(0);
        self.clock_offset_ms.store(offset, std::sync::atomic::Ordering::Relaxed);
        // Maintenance windows come due on the emulated clock.
        self.start_ticking();
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        // What CloudFormation or a scenario file makes ticks too. Only
        // HTTP requests move the clock.
        {
            let mut t = self.template.write().expect("SSM template lock poisoned");
            if t.is_none() {
                *t = Some(ctx.clone());
            }
        }
        self.start_ticking();
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("SSM state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid SSM state: {e}"))?;
        *self.lock() = state;
        // Restored windows, associations and calendars keep running.
        self.start_ticking();
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
