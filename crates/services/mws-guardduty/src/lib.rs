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
//! Threat detection analyses the CloudTrail management events fed to
//! [`GuardDuty::observe_management_event`] in every account and Region
//! with an enabled detector ([`detection`]): root credential use, trails
//! stopped or deleted, password policies weakened, S3 Block Public Access
//! turned off, anonymous bucket access granted, server access logging
//! turned off, and calls from IP addresses on the account's active threat
//! lists (which GuardDuty reads from S3 through [`ThreatListSource`]).
//! Repeats aggregate into one finding (`service.count`). VPC flow logs,
//! DNS logs, EKS audit logs and runtime events are not analysed. Other
//! findings come from `CreateSampleFindings` (one per finding type, shaped
//! like AWS's samples: `[SAMPLE]` titles, `service.additionalInfo` saying
//! `sample: true`) and malware scans.
//!
//! Findings go to EventBridge as `GuardDuty Finding` events (source
//! `aws.guardduty`) in the account and in its administrator account,
//! unless a suppression rule archives them, and to S3 publishing
//! destinations and Security Hub; see [`EventSink`], [`FindingExporter`]
//! and [`SecurityHubSink`]. Detected findings are published five minutes
//! after they are first seen and their updates on the detector's
//! `FindingPublishingFrequency`, on the emulated clock.
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

mod asff;
mod common;
pub use common::SERVICE_PRINCIPAL;
mod detection;
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
mod threatlists;

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

/// Where GuardDuty sends findings for AWS Security Hub (product
/// `aws/guardduty`).
pub trait SecurityHubSink: Send + Sync {
    /// Import ASFF `findings` into `account`'s hub in `region`.
    fn import_findings(&self, ctx: &RequestContext, account: &str, region: &str, findings: Vec<Value>);
}

/// An S3 object Malware Protection read for a scan.
#[derive(Debug, Clone)]
pub struct ScannedObject {
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub version_id: Option<String>,
}

/// What Malware Protection for S3 does in S3, as a protection plan's role.
#[async_trait::async_trait]
pub trait MalwareObjectStore: Send + Sync {
    /// Assume `role_arn` as `malware-protection-plan.guardduty.amazonaws.com`
    /// for the plan `plan_arn`.
    fn assume(&self, ctx: &RequestContext, role_arn: &str, plan_arn: &str) -> Result<RequestContext, String>;
    /// Turn on EventBridge notifications for `bucket`, which deliver the
    /// object-created events scans start from.
    async fn enable_eventbridge(&self, role: &RequestContext, bucket: &str) -> Result<(), String>;
    /// Read an object; `Err` carries S3's error code (`AccessDenied`,
    /// `NoSuchKey`, ...).
    async fn get_object(
        &self,
        role: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<ScannedObject, String>;
    /// Set the object tag `tag_key` to `value`, keeping its other tags.
    async fn tag_object(
        &self,
        role: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        tag_key: &str,
        value: &str,
    ) -> Result<(), String>;
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

/// GuardDuty's service-linked role, `AWSServiceRoleForAmazonGuardDuty`,
/// in IAM.
pub trait ServiceLinkedRoles: Send + Sync {
    /// Whether the role exists in `account`.
    fn exists(&self, account: &str) -> bool;
    /// Create the role in `account` if it is not there yet.
    fn ensure(&self, account: &str);
}

/// Where GuardDuty reads threat list and trusted list files: S3, as the
/// account's GuardDuty service-linked role.
pub trait ThreatListSource: Send + Sync {
    /// The object `key` in `bucket`, for the detector `detector_arn` of
    /// `account`. `Err` carries S3's error code (`NoSuchBucket`,
    /// `NoSuchKey`, `AccessDenied`, ...).
    fn read(
        &self,
        partition: &str,
        account: &str,
        detector_arn: &str,
        bucket: &str,
        key: &str,
        expected_bucket_owner: Option<&str>,
    ) -> Result<Vec<u8>, String>;
}

/// The GuardDuty service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct GuardDuty {
    state: Arc<Mutex<State>>,
    links: Arc<RwLock<Links>>,
    background: Arc<Background>,
}

/// What background publishing needs: a request context to act from, how
/// far the emulated clock ran ahead of the wall clock when it was taken,
/// and whether the loop runs.
#[derive(Default)]
struct Background {
    template: Mutex<Option<(RequestContext, i64)>>,
    started: std::sync::OnceLock<()>,
}

#[derive(Default)]
struct Links {
    events: Option<Arc<dyn EventSink>>,
    exporter: Option<Arc<dyn FindingExporter>>,
    organizations: Option<Arc<dyn OrganizationLink>>,
    security_hub: Option<Arc<dyn SecurityHubSink>>,
    objects: Option<Arc<dyn MalwareObjectStore>>,
    roles: Option<Arc<dyn ServiceLinkedRoles>>,
    lists: Option<Arc<dyn ThreatListSource>>,
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

    /// Send findings to Security Hub through `sink`.
    pub fn set_security_hub(&self, sink: Arc<dyn SecurityHubSink>) {
        self.links.write().expect("GuardDuty links lock poisoned").security_hub = Some(sink);
    }

    /// Read, scan and tag S3 objects for Malware Protection through
    /// `store`.
    pub fn set_malware_object_store(&self, store: Arc<dyn MalwareObjectStore>) {
        self.links.write().expect("GuardDuty links lock poisoned").objects = Some(store);
    }

    /// Create and check GuardDuty's service-linked role in IAM through
    /// `roles`.
    pub fn set_service_linked_roles(&self, roles: Arc<dyn ServiceLinkedRoles>) {
        self.links.write().expect("GuardDuty links lock poisoned").roles = Some(roles);
    }

    /// Read threat list files through `source`.
    pub fn set_threat_list_source(&self, source: Arc<dyn ThreatListSource>) {
        self.links.write().expect("GuardDuty links lock poisoned").lists = Some(source);
    }

    fn roles(&self) -> Option<Arc<dyn ServiceLinkedRoles>> {
        self.links.read().expect("GuardDuty links lock poisoned").roles.clone()
    }

    fn list_source(&self) -> Option<Arc<dyn ThreatListSource>> {
        self.links.read().expect("GuardDuty links lock poisoned").lists.clone()
    }

    fn objects(&self) -> Option<Arc<dyn MalwareObjectStore>> {
        self.links.read().expect("GuardDuty links lock poisoned").objects.clone()
    }

    fn security_hub(&self) -> Option<Arc<dyn SecurityHubSink>> {
        self.links.read().expect("GuardDuty links lock poisoned").security_hub.clone()
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
