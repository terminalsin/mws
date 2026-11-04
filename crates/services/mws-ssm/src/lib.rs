//! AWS Systems Manager Parameter Store for MWS.
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
//! Only the Parameter Store part of the SSM API is implemented; the other
//! operations of the model answer `NotImplemented`.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ssm_generated.rs"));
}

mod changes;
mod handler;
mod names;
mod params;
pub mod policies;
mod public;
mod query;
mod references;
pub mod secure;
mod settings;
mod sharing;
mod state;
mod tags;

use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;

pub use changes::{ParameterChange, ParameterChangeSink};
pub use references::{ReferencedSecret, SecretsManagerReferences};

use names::{now, resource_tag_conditions, ParamRef};
use state::{Parameter, State};

/// The Parameter Store service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Ssm {
    state: Arc<Mutex<State>>,
    kms: Kms,
    secrets: Arc<RwLock<Option<Arc<dyn SecretsManagerReferences>>>>,
    changes: Arc<RwLock<Option<Arc<dyn ParameterChangeSink>>>>,
}

impl Ssm {
    /// SecureString parameters are encrypted with keys from `kms`.
    pub fn new(kms: Kms) -> Self {
        Self { state: Arc::default(), kms, secrets: Arc::default(), changes: Arc::default() }
    }

    /// Resolve `/aws/reference/secretsmanager/...` names through `secrets`.
    pub fn set_secrets_manager(&self, secrets: Arc<dyn SecretsManagerReferences>) {
        *self.secrets.write().expect("SSM secrets lock poisoned") = Some(secrets);
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
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("SSM state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid SSM state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
