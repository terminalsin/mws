//! Resource providers: each resource type's create, update, delete and
//! read handlers, written against the other MWS services' APIs.

mod acm;
mod autoscaling;
mod cfn;
mod cloudwatch;
mod ec2;
mod ecr;
mod ecs;
mod efs;
mod eks;
mod elasticache;
mod elb;
mod events;
mod guardduty;
mod iam;
mod kinesis;
mod kms;
mod lambda;
mod logs;
mod pca;
mod rds;
mod route53;
mod s3;
pub mod scan;
mod secrets;
mod securityhub;
mod ses;
mod sns;
mod sqs;
mod ssm;

use std::collections::BTreeMap;
use std::sync::Arc;

use mws_core::{RequestContext, ServiceError};
use rand::Rng;
use serde_json::{json, Map, Value};

use crate::CloudFormation;

pub type Props = Map<String, Value>;

/// A resource a handler created.
#[derive(Debug, Clone, Default)]
pub struct Created {
    pub physical_id: String,
    pub attributes: Props,
}

impl Created {
    pub fn new(physical_id: impl Into<String>) -> Self {
        Self { physical_id: physical_id.into(), attributes: Props::new() }
    }

    pub fn attr(mut self, name: &str, v: impl Into<Value>) -> Self {
        self.attributes.insert(name.to_string(), v.into());
        self
    }
}

/// Why a handler failed, worded as CloudFormation reports it.
#[derive(Debug, Clone)]
pub struct HandlerError {
    pub message: String,
    pub not_found: bool,
    /// The service's error code, when a service call failed.
    pub code: String,
    /// The physical id of a resource the handler created before it
    /// failed (for example while waiting for it to stabilize), so the
    /// rollback deletes it.
    pub physical_id: Option<String>,
}

impl HandlerError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self { message: message.into(), not_found: false, code: String::new(), physical_id: None }
    }

    /// Note that the resource `id` already exists in the target service.
    pub fn created(mut self, id: &str) -> Self {
        self.physical_id.get_or_insert_with(|| id.to_string());
        self
    }

    pub fn from_service(service: &str, e: &ServiceError) -> Self {
        let code = handler_error_code(e);
        Self {
            message: format!(
                "Resource handler returned message: \"{} (Service: {}, Status Code: {}, Request ID: {})\" (RequestToken: {}, HandlerErrorCode: {code})",
                e.message,
                service_display(service),
                e.status,
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
            ),
            not_found: code == "NotFound",
            code: e.code.to_string(),
            physical_id: None,
        }
    }

    /// A failure the handler found itself (`HandlerErrorCode` given).
    pub fn handler(code: &str, message: impl std::fmt::Display) -> Self {
        Self {
            message: format!(
                "Resource handler returned message: \"{message}\" (RequestToken: {}, HandlerErrorCode: {code})",
                uuid::Uuid::new_v4()
            ),
            not_found: code == "NotFound",
            code: String::new(),
            physical_id: None,
        }
    }
}

fn service_display(service: &str) -> String {
    match service {
        "s3" | "s3control" => "S3".into(),
        "acm-pca" => "AcmPca".into(),
        "acm" => "Acm".into(),
        "monitoring" => "CloudWatch".into(),
        "logs" => "CloudWatchLogs".into(),
        "events" => "EventBridge".into(),
        "secretsmanager" => "SecretsManager".into(),
        "ec2" => "Ec2".into(),
        other => {
            let mut c = other.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        }
    }
}

fn handler_error_code(e: &ServiceError) -> &'static str {
    let c = e.code.as_ref();
    if c.contains("NotFound") || c.starts_with("NoSuch") || c == "AWS.SimpleQueueService.NonExistentQueue" {
        "NotFound"
    } else if c.contains("AlreadyExists") || c.contains("AlreadyOwned") || c == "QueueAlreadyExists" {
        "AlreadyExists"
    } else if c.starts_with("AccessDenied") || c == "UnauthorizedOperation" || c == "AuthorizationError" {
        "AccessDenied"
    } else if c.contains("LimitExceeded") && !c.contains("RequestLimitExceeded") {
        "ServiceLimitExceeded"
    } else if c.contains("Throttl") || c.contains("RequestLimitExceeded") {
        "Throttling"
    } else if e.status >= 500 {
        "ServiceInternalError"
    } else {
        "InvalidRequest"
    }
}

pub type HResult<T> = Result<T, HandlerError>;

/// What a handler works with.
pub struct Cx<'a> {
    pub cfn: &'a CloudFormation,
    pub ctx: &'a RequestContext,
    pub stack_name: &'a str,
    pub stack_id: &'a str,
    pub logical_id: &'a str,
    /// Stack-level tags, which CloudFormation propagates to resources that
    /// take tags.
    pub stack_tags: &'a [(String, String)],
    /// The emulated clock's offset from the wall clock: calls made later
    /// in a deployment carry the time they are made.
    pub offset: chrono::Duration,
    /// When the stack operation times out (`TimeoutInMinutes`), on the
    /// emulated clock: waits for signals end then.
    pub deadline: Option<chrono::DateTime<chrono::Utc>>,
}

impl Cx<'_> {
    pub fn account(&self) -> &str {
        &self.ctx.caller.account_id
    }

    pub fn region(&self) -> &str {
        &self.ctx.region
    }

    pub fn partition(&self) -> &str {
        &self.ctx.partition
    }

    /// Call another service's operation as the stack's identity.
    pub async fn call(&self, service: &str, operation: &str, input: Value) -> HResult<Value> {
        let mut ctx = self.ctx.clone();
        // The clock as it is now (it may have moved since the deployment
        // started), so services settle work that is due.
        ctx.received_at = (chrono::Utc::now() + self.offset).max(self.cfn.now());
        self.cfn.call(&ctx, service, operation, input).await.map_err(|e| HandlerError::from_service(service, &e))
    }

    /// A physical name CloudFormation would generate:
    /// `<stack>-<logical id>-<random>`, shortened to `max` characters.
    pub fn physical_name(&self, max: usize) -> String {
        let suffix: String = {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            let mut rng = rand::thread_rng();
            (0..12).map(|_| A[rng.gen_range(0..A.len())] as char).collect()
        };
        let room = max.saturating_sub(suffix.len() + 2);
        let stack_room = room.saturating_sub(room / 2).max(1);
        let mut stack: String = self.stack_name.chars().take(stack_room).collect();
        let logical_room = room.saturating_sub(stack.len());
        let logical: String = self.logical_id.chars().take(logical_room).collect();
        if stack.len() + logical.len() < room {
            stack = self.stack_name.chars().take(room - logical.len()).collect();
        }
        format!("{stack}-{logical}-{suffix}")
    }

    /// A lowercase generated name (S3 buckets).
    pub fn physical_name_lower(&self, max: usize) -> String {
        self.physical_name(max).to_lowercase()
    }

    /// The resource's `Tags` (a `[{Key, Value}]` list) plus the stack's.
    pub fn tags(&self, props: &Props) -> Vec<Value> {
        let mut out: Vec<Value> = Vec::new();
        for (k, v) in self.stack_tags {
            out.push(json!({"Key": k, "Value": v}));
        }
        if let Some(Value::Array(tags)) = props.get("Tags") {
            for t in tags {
                let k = t.get("Key").map(text).unwrap_or_default();
                out.retain(|x| x["Key"] != Value::String(k.clone()));
                out.push(json!({"Key": k, "Value": t.get("Value").map(text).unwrap_or_default()}));
            }
        }
        out
    }

    /// Tags as a `{key: value}` map (Lambda, SQS, SSM).
    pub fn tag_map(&self, props: &Props) -> Map<String, Value> {
        let mut out = Map::new();
        for (k, v) in self.stack_tags {
            out.insert(k.clone(), Value::String(v.clone()));
        }
        match props.get("Tags") {
            Some(Value::Array(tags)) => {
                for t in tags {
                    out.insert(
                        t.get("Key").map(text).unwrap_or_default(),
                        Value::String(t.get("Value").map(text).unwrap_or_default()),
                    );
                }
            }
            Some(Value::Object(m)) => {
                for (k, v) in m {
                    out.insert(k.clone(), Value::String(text(v)));
                }
            }
            _ => {}
        }
        out
    }

    pub fn arn(&self, service: &str, resource: &str) -> String {
        format!("arn:{}:{service}:{}:{}:{resource}", self.partition(), self.region(), self.account())
    }
}

/// A value as text, as CloudFormation coerces scalars for string
/// properties.
pub fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn s(props: &Props, key: &str) -> Option<String> {
    props.get(key).filter(|v| !v.is_null()).map(text)
}

pub fn req(props: &Props, key: &str) -> HResult<String> {
    s(props, key).ok_or_else(|| {
        HandlerError::invalid(format!(
            "Properties validation failed for resource with message: #: required key [{key}] not found"
        ))
    })
}

pub fn int(props: &Props, key: &str) -> Option<i64> {
    match props.get(key)? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

pub fn boolean(props: &Props, key: &str) -> Option<bool> {
    match props.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => Some(s.eq_ignore_ascii_case("true")),
        _ => None,
    }
}

pub fn list(props: &Props, key: &str) -> Vec<String> {
    match props.get(key) {
        Some(Value::Array(a)) => a.iter().map(text).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// A policy document property: objects are serialized, strings kept.
pub fn document(props: &Props, key: &str) -> Option<String> {
    match props.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(serde_json::to_string(other).unwrap_or_default()),
    }
}

/// Copy `keys` from `props` into `out`, converting scalars to what the
/// API member expects is the service's job; values are copied as given.
pub fn copy(props: &Props, out: &mut Map<String, Value>, keys: &[&str]) {
    for k in keys {
        if let Some(v) = props.get(*k).filter(|v| !v.is_null()) {
            out.insert((*k).to_string(), v.clone());
        }
    }
}

/// Integer members given as strings become numbers.
pub fn numbers(out: &mut Map<String, Value>, keys: &[&str]) {
    for k in keys {
        if let Some(Value::String(s)) = out.get(*k) {
            if let Ok(n) = s.parse::<i64>() {
                out.insert((*k).to_string(), Value::from(n));
            } else if let Ok(f) = s.parse::<f64>() {
                out.insert((*k).to_string(), json!(f));
            }
        }
    }
}

/// Boolean members given as strings become booleans.
pub fn bools(out: &mut Map<String, Value>, keys: &[&str]) {
    for k in keys {
        if let Some(Value::String(s)) = out.get(*k) {
            out.insert((*k).to_string(), Value::Bool(s.eq_ignore_ascii_case("true")));
        }
    }
}

/// Whether a value changed between two property sets.
pub fn changed(old: &Props, new: &Props, key: &str) -> bool {
    old.get(key) != new.get(key)
}

/// Ignore NotFound on delete: the resource is already gone.
pub fn gone_ok(r: HResult<Value>) -> HResult<()> {
    match r {
        Ok(_) => Ok(()),
        Err(e) if e.not_found => Ok(()),
        Err(e) => Err(e),
    }
}

/// One resource type's handlers.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// Properties whose change replaces the resource.
    fn create_only(&self) -> &'static [&'static str] {
        &[]
    }

    /// Properties that must be present.
    fn required(&self) -> &'static [&'static str] {
        &[]
    }

    /// Names of `Fn::GetAtt` attributes.
    fn attributes(&self) -> &'static [&'static str] {
        &[]
    }

    /// Whether any attribute name is accepted (custom resources, nested
    /// stacks' `Outputs.*`).
    fn open_attributes(&self) -> bool {
        false
    }

    /// Whether changes other than to create-only properties are applied
    /// in place. When false, every change replaces the resource.
    fn updatable(&self) -> bool {
        true
    }

    /// The property that holds a custom (user-chosen) physical name, such
    /// as `BucketName` or `QueueName`. CloudFormation refuses to replace a
    /// resource whose template sets it, because the new resource could not
    /// take the same name.
    fn name_property(&self) -> Option<&'static str> {
        None
    }

    /// Take a final snapshot before deletion (`DeletionPolicy: Snapshot`).
    /// `None` when the type does not support snapshots, which template
    /// validation reports like AWS does.
    async fn snapshot(&self, cx: &Cx<'_>, physical_id: &str, props: &Props, attrs: &Props) -> Option<HResult<()>> {
        let _ = (cx, physical_id, props, attrs);
        None
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created>;

    /// Apply a change in place; returns the new attributes.
    async fn update(&self, cx: &Cx<'_>, physical_id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let _ = (cx, physical_id, old, new);
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, physical_id: &str, props: &Props, attrs: &Props) -> HResult<()>;

    /// The resource's live properties, for drift detection. `None` when
    /// the type does not support drift detection.
    async fn read(&self, cx: &Cx<'_>, physical_id: &str, props: &Props) -> Option<HResult<Props>> {
        let _ = (cx, physical_id, props);
        None
    }
}

/// Every resource type MWS can deploy.
pub fn registry() -> BTreeMap<&'static str, Arc<dyn Provider>> {
    let mut m: BTreeMap<&'static str, Arc<dyn Provider>> = BTreeMap::new();
    iam::register(&mut m);
    s3::register(&mut m);
    sqs::register(&mut m);
    sns::register(&mut m);
    lambda::register(&mut m);
    kms::register(&mut m);
    ssm::register(&mut m);
    secrets::register(&mut m);
    logs::register(&mut m);
    events::register(&mut m);
    kinesis::register(&mut m);
    cloudwatch::register(&mut m);
    route53::register(&mut m);
    acm::register(&mut m);
    pca::register(&mut m);
    rds::register(&mut m);
    elasticache::register(&mut m);
    autoscaling::register(&mut m);
    eks::register(&mut m);
    guardduty::register(&mut m);
    securityhub::register(&mut m);
    ec2::register(&mut m);
    ecs::register(&mut m);
    ecr::register(&mut m);
    efs::register(&mut m);
    elb::register(&mut m);
    ses::register(&mut m);
    cfn::register(&mut m);
    m
}

/// Whether `type_name` is a custom resource (`Custom::*` or
/// `AWS::CloudFormation::CustomResource`).
pub fn is_custom(type_name: &str) -> bool {
    type_name.starts_with("Custom::") || type_name == "AWS::CloudFormation::CustomResource"
}

pub use cfn::{custom_resource_provider, CUSTOM_RESOURCE, NEW_PHYSICAL_ID};
