//! Service Quotas for MWS.
//!
//! A catalog of AWS service and quota codes with their default values, the
//! values applied to each account (raised by increase requests, which are
//! approved after a short review on the emulated clock), the
//! organization's quota request template, automatic management settings,
//! utilization reports and tags.
//!
//! Other services read applied values through [`ServiceQuotas::applied_value`]
//! and enforce them (EC2 vCPUs, Elastic IPs and VPCs, S3 buckets, IAM roles,
//! Lambda concurrency). Usage comes back through a [`UsageSource`]: it feeds
//! utilization reports and the `AWS/Usage` `ResourceCount` metrics, which
//! are published with the `CallCount` metric of every API call (the gateway
//! reports calls through [`mws_core::RequestObserver`]) to a
//! [`MetricPublisher`] (CloudWatch). CloudWatch's `SERVICE_QUOTA()` metric
//! math function asks [`ServiceQuotas::quota_for_metric`].

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/servicequotas_generated.rs"));
}

pub mod catalog;
mod ops;
mod state;
mod usage;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use chrono::{DateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use usage::{MetricPublisher, UsageDatum, UsageSource};

use state::State;

/// An account's place in its organization, as the quota request template
/// needs it.
#[derive(Debug, Clone)]
pub struct OrgAccount {
    pub management_account_id: String,
    pub all_features: bool,
    /// `CREATED` or `INVITED`.
    pub joined_method: String,
    pub joined: DateTime<Utc>,
}

/// Implemented over Organizations. Must not call back into Service Quotas.
pub trait OrganizationDirectory: Send + Sync {
    fn account(&self, account_id: &str) -> Option<OrgAccount>;
}

#[derive(Default)]
pub(crate) struct Inner {
    state: Mutex<State>,
    usage: OnceLock<Arc<dyn UsageSource>>,
    metrics: OnceLock<Arc<dyn MetricPublisher>>,
    organizations: OnceLock<Arc<dyn OrganizationDirectory>>,
    profile: OnceLock<catalog::Profile>,
    monitor: usage::Monitor,
}

/// The Service Quotas service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct ServiceQuotas {
    inner: Arc<Inner>,
}

impl ServiceQuotas {
    pub fn new() -> Self {
        Self::default()
    }

    /// Where resource usage comes from.
    pub fn set_usage_source(&self, source: Arc<dyn UsageSource>) {
        let _ = self.inner.usage.set(source);
    }

    /// Where `AWS/Usage` metrics go (CloudWatch).
    pub fn set_metric_publisher(&self, publisher: Arc<dyn MetricPublisher>) {
        let _ = self.inner.metrics.set(publisher);
    }

    /// Organizations, for the quota request template.
    pub fn set_organizations(&self, directory: Arc<dyn OrganizationDirectory>) {
        let _ = self.inner.organizations.set(directory);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("Service Quotas state lock poisoned")
    }

    /// The value of a quota applied to `account` in `region`: the default
    /// unless an increase was approved. Quotas Service Quotas does not know
    /// are unlimited.
    pub fn applied_value(&self, account: &str, region: &str, service: &str, code: &str, now: DateTime<Utc>) -> f64 {
        let Some(def) = catalog::quota(service, code) else { return f64::INFINITY };
        self.apply_template(account, now);
        let mut st = self.lock();
        let start = def.starting_value(region, self.profile());
        let Some(acct) = st.accounts.get_mut(account) else { return start };
        acct.settle(now.timestamp_millis());
        acct.applied.get(&state::key(region, def.global, service, code)).copied().unwrap_or(start)
    }

    /// Which values accounts start with; set once, before serving.
    pub fn set_profile(&self, profile: catalog::Profile) {
        let _ = self.inner.profile.set(profile);
    }

    pub(crate) fn profile(&self) -> catalog::Profile {
        self.inner.profile.get().copied().unwrap_or_default()
    }

    /// The applied value of the quota whose usage metric is the given
    /// metric, for CloudWatch's `SERVICE_QUOTA()`.
    pub fn quota_for_metric(
        &self,
        account: &str,
        region: &str,
        namespace: &str,
        metric_name: &str,
        dimensions: &[(String, String)],
        now: DateTime<Utc>,
    ) -> Option<f64> {
        let mut dims: Vec<(&str, &str)> = dimensions.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        dims.sort();
        let def = catalog::QUOTAS.iter().find(|d| {
            d.usage.is_some_and(|u| {
                let mut want = u.dimensions.to_vec();
                want.sort();
                u.namespace == namespace && u.name == metric_name && want == dims
            })
        })?;
        Some(self.applied_value(account, region, def.service, def.code, now))
    }

    /// Make the organization's template requests for a member account the
    /// organization created after the template was associated.
    fn apply_template(&self, account: &str, now: DateTime<Utc>) {
        if self.lock().accounts.get(account).is_some_and(|a| a.template_applied) {
            return;
        }
        let Some(org) = self.inner.organizations.get().and_then(|o| o.account(account)) else { return };
        if org.management_account_id == account || org.joined_method != "CREATED" {
            return;
        }
        let mut st = self.lock();
        let (associated, template) = match st.accounts.get(&org.management_account_id) {
            Some(m) => (m.template_associated_at, m.template.clone()),
            None => return,
        };
        let Some(associated) = associated else { return };
        if org.joined.timestamp_millis() < associated {
            return;
        }
        let at = now.timestamp_millis();
        let acct = st.accounts.entry(account.to_string()).or_default();
        acct.template_applied = true;
        for (k, desired) in template {
            let mut parts = k.splitn(3, '|');
            let (Some(region), Some(service), Some(code)) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            let Some(def) = catalog::quota(service, code) else { continue };
            let id = ops::new_request_id();
            acct.requests.insert(
                id.clone(),
                state::Request {
                    id,
                    service: service.into(),
                    code: code.into(),
                    region: region.into(),
                    global: def.global,
                    desired,
                    status: "PENDING".into(),
                    created: at,
                    updated: at,
                    case_id: None,
                    requester: format!(
                        "{{\"accountId\":\"{}\",\"callerArn\":\"arn:aws:iam::{}:root\"}}",
                        org.management_account_id, org.management_account_id
                    ),
                    request_type: None,
                    settles_at: at + state::APPROVAL_MS,
                },
            );
        }
    }

    /// Usage of every quota the usage source measures, for `account` in
    /// `region`.
    fn measure(&self, account: &str, region: &str) -> BTreeMap<(&'static str, &'static str), f64> {
        let mut out = BTreeMap::new();
        let Some(source) = self.inner.usage.get() else { return out };
        for def in catalog::QUOTAS {
            if let Some(v) = source.usage(account, region, def.service, def.code) {
                out.insert((def.service, def.code), v);
            }
        }
        out
    }
}

#[async_trait::async_trait]
impl Service for ServiceQuotas {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "servicequotas"
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
        Some(serde_json::to_value(state).expect("Service Quotas state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Service Quotas state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
