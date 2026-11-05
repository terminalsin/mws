//! Amazon GuardDuty for MWS.
//!
//! Detectors with their protection plans (features and data sources),
//! findings, suppression and filter rules, threat lists, publishing
//! destinations, multi-account management (invitations and AWS
//! Organizations delegated administration), malware protection plans and
//! scans, custom detection rule associations and investigations, all over
//! restJson1 generated from the official model, with every call authorized
//! through IAM.
//!
//! MWS does not watch CloudTrail, VPC flow logs or DNS queries, so the
//! findings that exist are the ones `CreateSampleFindings` makes (one per
//! finding type, shaped like AWS's samples: `[SAMPLE]` titles,
//! `service.additionalInfo` saying `sample: true`) and those of malware
//! scans. New and updated findings go to EventBridge as `GuardDuty Finding`
//! events (source `aws.guardduty`) in the account and in its administrator
//! account, unless a suppression rule archives them, and to S3 publishing
//! destinations; see [`EventSink`] and [`FindingExporter`].
//!
//! Organizations integration goes through [`OrganizationLink`]:
//! `EnableOrganizationAdminAccount` enables trusted access for
//! `guardduty.amazonaws.com` and registers the delegated administrator with
//! the caller's permissions, as AWS does, and the delegated administrator
//! manages organization accounts as members without invitations
//! (`AutoEnableOrganizationMembers` `ALL` or `NEW` adds them as they
//! appear).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/guardduty_generated.rs"));
}

mod common;
pub use common::SERVICE_PRINCIPAL;
mod detectors;
mod findings;
mod handler;
mod lists;
mod malware;
mod members;
mod org;
mod rules;
mod samples;
mod state;
mod tags;

use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use serde_json::Value;

use state::State;

/// An event GuardDuty sends to an account's default event bus.
#[derive(Debug, Clone)]
pub struct GuardDutyEvent {
    pub partition: String,
    pub account: String,
    pub region: String,
    /// `GuardDuty Finding`, ...
    pub detail_type: String,
    pub detail: Value,
    pub time: DateTime<Utc>,
}

/// Where GuardDuty's EventBridge events go (source `aws.guardduty`).
pub trait EventSink: Send + Sync {
    fn put_event(&self, ctx: &RequestContext, event: GuardDutyEvent);
}

/// An S3 publishing destination's export of findings.
#[derive(Debug, Clone)]
pub struct FindingExport {
    pub partition: String,
    pub account: String,
    pub region: String,
    /// `arn:aws:s3:::bucket[/prefix]`.
    pub destination_arn: String,
    pub kms_key_arn: String,
    pub detector_arn: String,
    /// The object key under the destination.
    pub key: String,
    /// JSON Lines, gzip-compressed.
    pub body: Vec<u8>,
}

/// Writes publishing destination exports into S3 as
/// `guardduty.amazonaws.com`, KMS-encrypted with the destination's key.
pub trait FindingExporter: Send + Sync {
    /// `Err` carries why the destination cannot be written.
    fn export(&self, ctx: &RequestContext, export: FindingExport) -> Result<(), String>;
}

/// An account of an organization, as GuardDuty sees it.
#[derive(Debug, Clone)]
pub struct OrgAccount {
    pub id: String,
    pub email: String,
    pub joined: DateTime<Utc>,
    /// `ACTIVE`, `SUSPENDED`, ...
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct OrgInfo {
    pub id: String,
    pub management_account: String,
    pub accounts: Vec<OrgAccount>,
}

/// What GuardDuty needs from AWS Organizations.
pub trait OrganizationLink: Send + Sync {
    /// The organization `account` belongs to.
    fn organization(&self, account: &str) -> Option<OrgInfo>;
    /// Enable trusted access for `guardduty.amazonaws.com` and register
    /// `admin` as its delegated administrator, with the caller's
    /// permissions (the management account's).
    fn register_admin(&self, ctx: &RequestContext, admin: &str) -> Result<(), ServiceError>;
    /// Deregister `admin` as GuardDuty's delegated administrator.
    fn deregister_admin(&self, ctx: &RequestContext, admin: &str) -> Result<(), ServiceError>;
}

/// The GuardDuty service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct GuardDuty {
    state: Arc<Mutex<State>>,
    links: Arc<RwLock<Links>>,
}

#[derive(Default)]
struct Links {
    events: Option<Arc<dyn EventSink>>,
    exporter: Option<Arc<dyn FindingExporter>>,
    organizations: Option<Arc<dyn OrganizationLink>>,
}

impl GuardDuty {
    pub fn new() -> Self {
        Self::default()
    }

    /// Send findings to EventBridge through `sink`.
    pub fn set_event_sink(&self, sink: Arc<dyn EventSink>) {
        self.links.write().expect("GuardDuty links lock poisoned").events = Some(sink);
    }

    /// Export findings to S3 publishing destinations through `exporter`.
    pub fn set_finding_exporter(&self, exporter: Arc<dyn FindingExporter>) {
        self.links.write().expect("GuardDuty links lock poisoned").exporter = Some(exporter);
    }

    /// Use this AWS Organizations for delegated administration.
    pub fn set_organizations(&self, link: Arc<dyn OrganizationLink>) {
        self.links.write().expect("GuardDuty links lock poisoned").organizations = Some(link);
    }

    fn events(&self) -> Option<Arc<dyn EventSink>> {
        self.links.read().expect("GuardDuty links lock poisoned").events.clone()
    }

    fn exporter(&self) -> Option<Arc<dyn FindingExporter>> {
        self.links.read().expect("GuardDuty links lock poisoned").exporter.clone()
    }

    fn organizations(&self) -> Option<Arc<dyn OrganizationLink>> {
        self.links.read().expect("GuardDuty links lock poisoned").organizations.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("GuardDuty state lock poisoned")
    }

    /// `ctx.authorize("guardduty:{action}", ...)`.
    fn authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        cond: ConditionContext,
    ) -> Result<(), ServiceError> {
        ctx.authorize(&format!("guardduty:{action}"), resource, cond)
    }
}

#[async_trait::async_trait]
impl Service for GuardDuty {
    fn signing_name(&self) -> &'static str {
        "guardduty"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.sync_organization(&ctx);
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(&self, ctx: RequestContext, operation: &str, input: Value) -> Result<Value, ServiceError> {
        self.sync_organization(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("GuardDuty state serializes"))
    }

    fn import_state(&self, state: Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid GuardDuty state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}
