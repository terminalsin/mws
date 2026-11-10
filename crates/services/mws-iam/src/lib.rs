//! AWS Identity and Access Management for MWS.
//!
//! The wire layer (types, validation, XML) is generated from AWS's Smithy
//! model at build time. This crate adds the state and behaviour. It owns the
//! account's identities, so it is also the gateway's
//! [`CredentialStore`](mws_core::CredentialStore) for long-term keys and its
//! [`Authorizer`](mws_core::Authorizer) for every service.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/iam_generated.rs"));
}

mod activity;
mod api;
mod authz;
mod common;
mod credentials;
mod handler;
mod ids;
mod managed;
mod ops;
pub mod org;
mod reserved;
mod state;
mod wire;

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use chrono::{DateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError, SessionKind};

pub use api::{arn_account, DelegationGrant, InstanceProfileView, OidcProviderView, OutboundKey, RoleView, UserView};
pub use ops::service_roles::{RoleUsage, ServiceLinkedRoleUsage};
pub use org::{AccountOrganization, OrganizationView};
pub use reserved::ReservedRoleSpec;
pub use state::State;

tokio::task_local! {
    /// The account whose IAM namespace the running request works in: the
    /// caller's account.
    static CURRENT_ACCOUNT: String;
}

/// Settings for the emulated account.
#[derive(Debug, Clone)]
pub struct IamConfig {
    pub account_id: String,
    pub partition: String,
    /// Access key pair for the account root user.
    pub root_access_key_id: String,
    pub root_secret_access_key: String,
}

impl Default for IamConfig {
    fn default() -> Self {
        Self {
            account_id: "123456789012".into(),
            partition: "aws".into(),
            root_access_key_id: "AKIAMWSROOTEXAMPLE00".into(),
            root_secret_access_key: "mwsRootSecretAccessKeyEXAMPLEKEY00000000".into(),
        }
    }
}

/// The IAM service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Iam {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub config: IamConfig,
    pub created_at: DateTime<Utc>,
    /// Every account's IAM namespace, by account id. The configured account
    /// is always present; AWS Organizations adds member accounts.
    pub accounts: RwLock<BTreeMap<String, State>>,
    pub organizations: OnceLock<Arc<dyn OrganizationView>>,
    /// Applied quota values (roles per account, managed policies per role).
    pub quotas: OnceLock<mws_servicequotas::ServiceQuotas>,
    /// Activity the authorizer noted and IAM has yet to fold into `accounts`.
    pub activity: Mutex<activity::Pending>,
    /// Services that report which of their resources use a service-linked
    /// role (DeleteServiceLinkedRole fails while any does).
    pub slr_usage: RwLock<Vec<Arc<dyn ServiceLinkedRoleUsage>>>,
}

/// Saved IAM state: the configured account's namespace at the top level (the
/// format before member accounts existed) plus every other account.
#[derive(serde::Serialize, serde::Deserialize)]
struct SavedState {
    #[serde(flatten)]
    primary: State,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    member_accounts: BTreeMap<String, State>,
}

impl Iam {
    pub fn new(config: IamConfig) -> Self {
        let iam = Self {
            inner: Arc::new(Inner {
                config,
                created_at: Utc::now(),
                accounts: RwLock::new(BTreeMap::new()),
                organizations: OnceLock::new(),
                quotas: OnceLock::new(),
                activity: Mutex::new(activity::Pending::default()),
                slr_usage: RwLock::new(Vec::new()),
            }),
        };
        iam.reset_state();
        iam
    }

    /// Run `f` with `account` as the IAM namespace that unqualified lookups
    /// (and ARNs of new entities) use. IAM scopes each request to the
    /// caller's account; STS uses this for its own lookups.
    pub async fn in_account<F: Future>(&self, account: String, f: F) -> F::Output {
        CURRENT_ACCOUNT.scope(account, f).await
    }

    /// The account the running request works in.
    pub(crate) fn current_account(&self) -> String {
        CURRENT_ACCOUNT.try_with(String::clone).unwrap_or_else(|_| self.inner.config.account_id.clone())
    }

    /// Let AWS Organizations tell IAM which organization each account
    /// belongs to and which SCPs and RCPs apply.
    pub fn set_organizations(&self, view: Arc<dyn OrganizationView>) {
        let _ = self.inner.organizations.set(view);
    }

    /// Read applied quota values from Service Quotas (defaults otherwise).
    pub fn set_service_quotas(&self, quotas: mws_servicequotas::ServiceQuotas) {
        let _ = self.inner.quotas.set(quotas);
    }

    /// Let a service report which of its resources still use a
    /// service-linked role, so `DeleteServiceLinkedRole` fails while they do.
    pub fn register_service_linked_role_usage(&self, usage: Arc<dyn ServiceLinkedRoleUsage>) {
        self.inner.slr_usage.write().expect("IAM SLR usage lock poisoned").push(usage);
    }

    /// The applied value of an IAM quota for the current account: the
    /// Service Quotas value when its catalog has `code`, `default`
    /// otherwise. Never call with the IAM state lock held.
    pub(crate) fn quota(&self, ctx: &RequestContext, code: &str, default: usize) -> usize {
        if mws_servicequotas::catalog::quota("iam", code).is_none() {
            return default;
        }
        let value = match self.inner.quotas.get() {
            Some(q) => q.applied_value(&self.current_account(), "us-east-1", "iam", code, ctx.received_at),
            None => mws_servicequotas::catalog::quota("iam", code).map_or(f64::INFINITY, |d| d.value),
        };
        value.clamp(0.0, usize::MAX as f64) as usize
    }

    /// The number of roles in `account`.
    pub fn role_count(&self, account: &str) -> usize {
        self.inner.accounts.read().expect("IAM state lock poisoned").get(account).map_or(0, |s| s.roles.len())
    }

    /// The organization `account_id` belongs to, if any.
    pub fn organization_of(&self, account_id: &str) -> Option<AccountOrganization> {
        self.inner.organizations.get().and_then(|o| o.account(account_id))
    }

    pub fn config(&self) -> &IamConfig {
        &self.inner.config
    }

    /// A credential store backed by this account's root and user keys.
    pub fn credential_store(&self) -> Arc<dyn mws_core::CredentialStore> {
        Arc::new(credentials::IamCredentials { inner: self.inner.clone() })
    }

    /// The authorizer that evaluates IAM policies for every service.
    pub fn authorizer(&self) -> Arc<dyn mws_core::Authorizer> {
        Arc::new(authz::IamAuthorizer { inner: self.inner.clone() })
    }

    pub(crate) fn arn(&self, resource: &str) -> String {
        format!("arn:{}:iam::{}:{resource}", self.inner.config.partition, self.current_account())
    }
}

#[async_trait::async_trait]
impl Service for Iam {
    fn signing_name(&self) -> &'static str {
        "iam"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        // Credentials from GetSessionToken cannot call IAM without MFA.
        if ctx.caller.session.as_ref().is_some_and(|s| s.kind == SessionKind::GetSessionToken && !s.mfa_authenticated) {
            return self.render_error(&ctx.request_id, &ServiceError::invalid_client_token_id());
        }
        self.inner.flush_activity();
        self.settle_deletion_tasks(ctx.received_at);
        let params = mws_proto_query::read_params(&request);
        let account = ctx.caller.account_id.clone();
        self.in_account(account, generated::dispatch(self, &ctx, &params)).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.inner.flush_activity();
        self.settle_deletion_tasks(ctx.received_at);
        let account = ctx.caller.account_id.clone();
        self.in_account(account, generated::invoke(self, &ctx, operation, input)).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        self.inner.flush_activity();
        let mut accounts = self.inner.accounts.read().expect("IAM state lock poisoned").clone();
        let primary = accounts.remove(&self.inner.config.account_id).unwrap_or_default();
        let saved = SavedState { primary, member_accounts: accounts };
        Some(serde_json::to_value(saved).expect("IAM state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let saved: SavedState = serde_json::from_value(state).map_err(|e| format!("invalid IAM state: {e}"))?;
        let mut accounts = saved.member_accounts;
        accounts.insert(self.inner.config.account_id.clone(), saved.primary);
        for (account, state) in accounts.iter_mut() {
            self.seed_aws_managed_policies(state);
            ops::service_roles::migrate_role_names(&self.inner.config.partition, account, state);
        }
        *self.inner.accounts.write().expect("IAM state lock poisoned") = accounts;
        self.inner.clear_activity();
        Ok(())
    }

    fn reset_state(&self) {
        let mut state = State::default();
        self.seed_aws_managed_policies(&mut state);
        let mut accounts = BTreeMap::new();
        accounts.insert(self.inner.config.account_id.clone(), state);
        *self.inner.accounts.write().expect("IAM state lock poisoned") = accounts;
        self.inner.clear_activity();
    }
}
