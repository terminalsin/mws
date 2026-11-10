//! Deploying stacks: creating, updating, rolling back and deleting their
//! resources, with the events CloudFormation records along the way.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use mws_core::RequestContext;
use serde_json::{Map, Value};

use crate::intrinsics::{EvalError, Evaluator, Lookup, Pseudo, Resources};
use crate::providers::{self, Cx, Props, Provider};
use crate::state::{Event, Resource, Snapshot, Stack, StackOutput};
use crate::template::Template;
use crate::{policy, CloudFormation};

pub const STACK_TYPE: &str = "AWS::CloudFormation::Stack";

/// Values intrinsic functions read that do not depend on resources.
#[derive(Clone)]
pub struct EvalData {
    pub params: BTreeMap<String, Value>,
    pub pseudo: Pseudo,
    pub conditions: BTreeMap<String, bool>,
    pub exports: BTreeMap<String, String>,
    pub azs: Vec<String>,
    pub language_extensions: bool,
}

impl EvalData {
    pub fn included(&self, template: &Template, logical_id: &str) -> bool {
        match template.resource(logical_id).and_then(|r| r.get("Condition")).and_then(Value::as_str) {
            Some(c) => self.conditions.get(c).copied().unwrap_or(false),
            None => true,
        }
    }

    pub fn evaluator<'a>(&'a self, template: &'a Template, resources: &'a dyn Resources) -> Evaluator<'a> {
        Evaluator {
            params: &self.params,
            pseudo: &self.pseudo,
            mappings: template.section("Mappings"),
            conditions: &self.conditions,
            resources,
            exports: &self.exports,
            azs: &self.azs,
            language_extensions: self.language_extensions,
        }
    }
}

/// `Ref` and `Fn::GetAtt` over a stack's resources.
pub struct StackResources<'a> {
    pub resources: &'a [Resource],
    pub template: &'a Template,
    pub data: &'a EvalData,
    /// Resources whose values change on the next deployment (change set
    /// previews): their values are unknown.
    pub pending: &'a BTreeSet<String>,
    /// Whether missing resources are unknown (previews) or errors.
    pub preview: bool,
    pub cfn: &'a CloudFormation,
    pub account: &'a str,
    pub region: &'a str,
}

impl Resources for StackResources<'_> {
    fn ref_value(&self, logical_id: &str) -> Lookup {
        if self.template.resource(logical_id).is_none() || !self.data.included(self.template, logical_id) {
            return Lookup::Error(crate::template::format_error(format!(
                "Unresolved resource dependencies [{logical_id}] in the Resources block of the template"
            )));
        }
        if self.pending.contains(logical_id) {
            return Lookup::Unknown;
        }
        match self.resources.iter().find(|r| r.logical_id == logical_id && r.exists()) {
            Some(r) => Lookup::Value(Value::String(r.physical_id.clone().unwrap_or_default())),
            None if self.preview => Lookup::Unknown,
            None => Lookup::Error(format!("Template error: resource {logical_id} has not been created")),
        }
    }

    fn attribute(&self, logical_id: &str, attribute: &str) -> Lookup {
        let Some(ty) = self.template.resource_type(logical_id) else {
            return Lookup::Error(format!(
                "Template error: instance of Fn::GetAtt references undefined resource {logical_id}"
            ));
        };
        if !self.data.included(self.template, logical_id) {
            return Lookup::Error(format!(
                "Template error: instance of Fn::GetAtt references undefined resource {logical_id}"
            ));
        }
        if let Some(p) = self.cfn.provider_in(self.account, self.region, ty) {
            if !p.open_attributes() && !p.attributes().contains(&attribute) {
                return Lookup::Error(format!(
                    "Template error: resource {logical_id} does not support attribute type {attribute} in Fn::GetAtt"
                ));
            }
        }
        if self.pending.contains(logical_id) {
            return Lookup::Unknown;
        }
        match self.resources.iter().find(|r| r.logical_id == logical_id && r.exists()) {
            Some(r) => match r.attributes.get(attribute) {
                Some(v) => Lookup::Value(v.clone()),
                None if providers::is_custom(ty) => Lookup::Error(format!(
                    "CustomResource attribute error: Vendor response doesn't contain {attribute} key in object {}|{logical_id}|{} in S3 bucket cloudformation-custom-resource-storage-{}",
                    self.data.pseudo.stack_id,
                    r.physical_id.clone().unwrap_or_default(),
                    self.data.pseudo.region.replace('-', ""),
                )),
                None => Lookup::Error(format!(
                    "Template error: resource {logical_id} does not support attribute type {attribute} in Fn::GetAtt"
                )),
            },
            None if self.preview => Lookup::Unknown,
            None => Lookup::Error(format!("Template error: resource {logical_id} has not been created")),
        }
    }
}

/// One stack operation running in the background.
#[derive(Clone)]
pub struct Deployment {
    pub cfn: CloudFormation,
    pub stack_id: String,
    /// The identity resources are created with: the caller, or the stack's
    /// service role.
    pub ctx: RequestContext,
    pub token: Option<String>,
    /// Emulated clock minus wall clock.
    pub offset: chrono::Duration,
}

/// What a failed resource step reports.
struct Failure {
    logical_id: Option<String>,
    reason: String,
}

impl Deployment {
    pub fn now(&self) -> DateTime<Utc> {
        Utc::now() + self.offset
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Stack) -> R) -> R {
        let mut st = self.cfn.state();
        let stack = st.stacks.get_mut(&self.stack_id).expect("deployments run on stored stacks");
        f(stack)
    }

    fn snapshot(&self) -> Stack {
        self.with(|s| s.clone())
    }

    /// Record an event and send it to the stack's notification topics.
    pub async fn event(
        &self,
        logical_id: &str,
        resource_type: &str,
        physical_id: Option<&str>,
        status: &str,
        reason: Option<&str>,
        properties: Option<&Props>,
    ) {
        let now = self.now();
        let (event, stack_name, topics) = self.with(|s| {
            let is_stack = resource_type == STACK_TYPE && logical_id == s.name;
            let id = if is_stack {
                uuid::Uuid::new_v4().to_string()
            } else {
                format!("{logical_id}-{status}-{}", now.format("%Y-%m-%dT%H:%M:%S%.3fZ"))
            };
            let e = Event {
                id,
                logical_id: logical_id.to_string(),
                physical_id: physical_id.map(str::to_string),
                resource_type: resource_type.to_string(),
                timestamp: now,
                status: status.to_string(),
                reason: reason.map(str::to_string),
                properties: properties.map(|p| serde_json::to_string(p).unwrap_or_default()),
                client_request_token: self.token.clone(),
                operation_id: s.last_operation.as_ref().map(|o| o.1.clone()),
                ..Default::default()
            };
            s.events.push(e.clone());
            (e, s.name.clone(), s.notification_arns.clone())
        });
        for topic in topics {
            let message = format!(
                "StackId='{}'\nTimestamp='{}'\nEventId='{}'\nLogicalResourceId='{}'\nNamespace='{}'\nPhysicalResourceId='{}'\nPrincipalId='{}'\nResourceProperties='{}'\nResourceStatus='{}'\nResourceStatusReason='{}'\nResourceType='{}'\nStackName='{}'\nClientRequestToken='{}'\n",
                self.stack_id,
                event.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                event.id,
                event.logical_id,
                self.ctx.caller.account_id,
                event.physical_id.clone().unwrap_or_default(),
                self.ctx.caller.user_id,
                event.properties.clone().unwrap_or_default(),
                event.status,
                event.reason.clone().unwrap_or_default(),
                event.resource_type,
                stack_name,
                event.client_request_token.clone().unwrap_or_else(|| "null".into()),
            );
            let input = serde_json::json!({
                "TopicArn": topic,
                "Subject": "AWS CloudFormation Notification",
                "Message": message,
            });
            if let Err(e) = self.cfn.call(&self.ctx, "sns", "Publish", input).await {
                tracing::debug!("stack notification to {topic} failed: {}", e.message);
            }
        }
    }

    /// Set the stack's status and record the stack event.
    pub async fn stack_status(&self, status: &str, reason: Option<&str>) {
        let (name, id) = self.with(|s| {
            s.status = status.to_string();
            s.status_reason = reason.map(str::to_string);
            (s.name.clone(), s.id.clone())
        });
        self.event(&name, STACK_TYPE, Some(&id), status, reason, None).await;
    }

    fn set_resource(&self, r: Resource) {
        self.with(|s| match s.resources.iter_mut().find(|x| x.logical_id == r.logical_id) {
            Some(x) => *x = r,
            None => s.resources.push(r),
        });
    }

    fn update_resource(&self, logical_id: &str, f: impl FnOnce(&mut Resource)) {
        self.with(|s| {
            if let Some(r) = s.resource_mut(logical_id) {
                f(r);
            }
        });
    }

    fn cx<'a>(&'a self, stack: &'a Stack, logical_id: &'a str, tags: &'a [(String, String)]) -> Cx<'a> {
        Cx {
            cfn: &self.cfn,
            ctx: &self.ctx,
            stack_name: &stack.name,
            stack_id: &stack.id,
            logical_id,
            stack_tags: tags,
            offset: self.offset,
        }
    }

    fn provider(&self, ty: &str) -> Result<Arc<dyn Provider>, String> {
        self.cfn
            .provider_in(&self.ctx.caller.account_id, &self.ctx.region, ty)
            .ok_or_else(|| crate::template::format_error(format!("Unrecognized resource types: [{ty}]")))
    }

    /// Evaluate a resource's properties against the stack as it is now.
    pub(crate) async fn properties(
        &self,
        template: &Template,
        data: &EvalData,
        logical_id: &str,
    ) -> Result<Props, String> {
        let stack = self.snapshot();
        let def = template.resource(logical_id).cloned().unwrap_or_default();
        let pending = BTreeSet::new();
        let lookup = StackResources {
            resources: &stack.resources,
            template,
            data,
            pending: &pending,
            preview: false,
            cfn: &self.cfn,
            account: &self.ctx.caller.account_id,
            region: &self.ctx.region,
        };
        let props =
            data.evaluator(template, &lookup).eval_properties(def.get("Properties")).map_err(EvalError::message)?;
        let props = crate::dynamic::resolve(&self.cfn, &self.ctx, Value::Object(props)).await?;
        let Value::Object(props) = props else { unreachable!("objects stay objects") };
        let ty = def.get("Type").and_then(Value::as_str).unwrap_or_default();
        if let Some(p) = self.cfn.provider_in(&self.ctx.caller.account_id, &self.ctx.region, ty) {
            let missing: Vec<&str> = p.required().iter().copied().filter(|k| !props.contains_key(*k)).collect();
            if !missing.is_empty() {
                return Err(format!(
                    "Properties validation failed for resource {logical_id} with message:\n#: required key [{}] not found",
                    missing.join(", ")
                ));
            }
        }
        Ok(props)
    }

    fn stack_tags(stack: &Stack) -> Vec<(String, String)> {
        stack.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect()
    }

    /// Run the account's hooks for a resource about to be provisioned,
    /// recording their progress as stack events.
    async fn hooks(
        &self,
        logical_id: &str,
        ty: &str,
        action: &str,
        props: &Props,
        previous: Option<&Props>,
    ) -> Result<(), String> {
        let events = std::sync::Mutex::new(Vec::new());
        let result = self
            .cfn
            .run_hooks(&self.ctx, &self.stack_id, logical_id, ty, action, props, previous, |e| {
                events.lock().expect("lock").push(e)
            })
            .await;
        let now = self.now();
        let token = self.token.clone();
        self.with(|s| {
            for e in events.into_inner().expect("lock") {
                s.events.push(crate::state::Event {
                    id: uuid::Uuid::new_v4().to_string(),
                    logical_id: logical_id.to_string(),
                    physical_id: None,
                    resource_type: ty.to_string(),
                    timestamp: now,
                    status: match action {
                        "CREATE" => "CREATE_IN_PROGRESS",
                        "UPDATE" => "UPDATE_IN_PROGRESS",
                        _ => "DELETE_IN_PROGRESS",
                    }
                    .into(),
                    client_request_token: token.clone(),
                    operation_id: s.last_operation.as_ref().map(|o| o.1.clone()),
                    hook_type: Some(e.hook_type),
                    hook_status: Some(e.status),
                    hook_status_reason: e.reason,
                    hook_invocation_point: Some(e.point),
                    hook_invocation_id: Some(e.invocation_id),
                    hook_failure_mode: Some(e.failure_mode),
                    ..Default::default()
                });
            }
        });
        result
    }

    /// Create one resource. `replacing` names the record it replaces.
    async fn create_resource(
        &self,
        template: &Template,
        data: &EvalData,
        logical_id: &str,
        replacing: bool,
    ) -> Result<(), Failure> {
        let fail = |reason: String| Failure { logical_id: Some(logical_id.to_string()), reason };
        let def = template.resource(logical_id).cloned().unwrap_or_default();
        let ty = def.get("Type").and_then(Value::as_str).unwrap_or_default().to_string();
        let provider = self.provider(&ty).map_err(fail)?;
        let props = match self.properties(template, data, logical_id).await {
            Ok(p) => p,
            Err(reason) => {
                self.event(
                    logical_id,
                    &ty,
                    None,
                    if replacing { "UPDATE_FAILED" } else { "CREATE_FAILED" },
                    Some(&reason),
                    None,
                )
                .await;
                if !replacing {
                    self.set_resource(Resource {
                        logical_id: logical_id.into(),
                        resource_type: ty.clone(),
                        status: "CREATE_FAILED".into(),
                        status_reason: Some(reason.clone()),
                        updated: self.now(),
                        ..Default::default()
                    });
                }
                return Err(fail(reason));
            }
        };
        let (in_progress, complete, failed) = if replacing {
            ("UPDATE_IN_PROGRESS", "UPDATE_COMPLETE", "UPDATE_FAILED")
        } else {
            ("CREATE_IN_PROGRESS", "CREATE_COMPLETE", "CREATE_FAILED")
        };
        let old_physical = self.with(|s| s.resource(logical_id).and_then(|r| r.physical_id.clone()));
        if replacing {
            self.event(
                logical_id,
                &ty,
                old_physical.as_deref(),
                in_progress,
                Some("Requested update requires the creation of a new physical resource; hence creating one."),
                Some(&props),
            )
            .await;
        } else {
            self.event(logical_id, &ty, None, in_progress, None, Some(&props)).await;
            self.set_resource(Resource {
                logical_id: logical_id.into(),
                resource_type: ty.clone(),
                status: in_progress.into(),
                updated: self.now(),
                metadata: def.get("Metadata").cloned(),
                description: def.get("Description").and_then(Value::as_str).map(str::to_string),
                ..Default::default()
            });
        }
        let stack = self.snapshot();
        let tags = Self::stack_tags(&stack);
        let cx = self.cx(&stack, logical_id, &tags);
        let created = match self.hooks(logical_id, &ty, "CREATE", &props, None).await {
            Ok(()) => provider.create(&cx, &props).await,
            Err(reason) => Err(providers::HandlerError::invalid(reason)),
        };
        let created = match created {
            Ok(c) => c,
            Err(e) => {
                self.event(logical_id, &ty, old_physical.as_deref(), failed, Some(&e.message), None).await;
                if !replacing {
                    self.update_resource(logical_id, |r| {
                        r.status = failed.into();
                        r.status_reason = Some(e.message.clone());
                    });
                }
                return Err(fail(e.message));
            }
        };
        let initiated = if replacing { None } else { Some("Resource creation Initiated") };
        if !replacing {
            self.event(logical_id, &ty, Some(&created.physical_id), in_progress, initiated, None).await;
        }
        // Signals a CreationPolicy waits for.
        if let Some(policy) = def.get("CreationPolicy").and_then(|p| p.get("ResourceSignal")) {
            let count = policy.get("Count").and_then(|c| c.as_u64().or_else(|| c.as_str()?.parse().ok())).unwrap_or(1);
            let timeout = policy.get("Timeout").and_then(Value::as_str).map(parse_iso_duration).unwrap_or(300);
            let key = crate::signal_key(&self.stack_id, logical_id);
            match self.cfn.wait_for_signals(&key, count as usize, timeout).await {
                Ok(signals) => {
                    for s in &signals {
                        if s.get("Status").and_then(Value::as_str) == Some("FAILURE") {
                            let reason = format!(
                                "Received FAILURE signal with UniqueId {}",
                                s.get("UniqueId").and_then(Value::as_str).unwrap_or_default()
                            );
                            self.record_created(logical_id, &ty, &props, &created, failed, Some(&reason), &def).await;
                            return Err(fail(reason));
                        }
                    }
                }
                Err(()) => {
                    let reason = format!("Failed to receive {count} resource signal(s) within the specified duration");
                    self.record_created(logical_id, &ty, &props, &created, failed, Some(&reason), &def).await;
                    return Err(fail(reason));
                }
            }
        }
        self.record_created(logical_id, &ty, &props, &created, complete, None, &def).await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_created(
        &self,
        logical_id: &str,
        ty: &str,
        props: &Props,
        created: &providers::Created,
        status: &str,
        reason: Option<&str>,
        def: &Map<String, Value>,
    ) {
        self.set_resource(Resource {
            logical_id: logical_id.into(),
            resource_type: ty.into(),
            physical_id: Some(created.physical_id.clone()),
            status: status.into(),
            status_reason: reason.map(str::to_string),
            updated: self.now(),
            properties: props.clone(),
            attributes: created.attributes.clone(),
            metadata: def.get("Metadata").cloned(),
            description: def.get("Description").and_then(Value::as_str).map(str::to_string),
            drift_status: None,
            drift_checked: None,
        });
        self.event(logical_id, ty, Some(&created.physical_id), status, reason, None).await;
    }

    /// Delete one resource record's physical resource, taking a final
    /// snapshot first when `snapshot` is set and the type supports it
    /// (types that do not are deleted, as AWS falls back to `Delete`).
    async fn delete_physical(&self, r: &Resource, events: bool, snapshot: bool) -> Result<(), String> {
        let Some(physical) = r.physical_id.clone() else { return Ok(()) };
        let provider = match self.cfn.provider_in(&self.ctx.caller.account_id, &self.ctx.region, &r.resource_type) {
            Some(p) => p,
            None => return Ok(()),
        };
        if events {
            self.event(&r.logical_id, &r.resource_type, Some(&physical), "DELETE_IN_PROGRESS", None, None).await;
        }
        let stack = self.snapshot();
        let tags = Self::stack_tags(&stack);
        let cx = self.cx(&stack, &r.logical_id, &tags);
        let deleted = match self.hooks(&r.logical_id, &r.resource_type, "DELETE", &r.properties, None).await {
            Ok(()) => {
                let snapped = match snapshot {
                    true => provider.snapshot(&cx, &physical, &r.properties, &r.attributes).await,
                    false => None,
                };
                match snapped {
                    Some(Err(e)) => Err(e),
                    _ => provider.delete(&cx, &physical, &r.properties, &r.attributes).await,
                }
            }
            Err(reason) => Err(providers::HandlerError::invalid(reason)),
        };
        match deleted {
            Ok(()) => {
                if events {
                    self.event(&r.logical_id, &r.resource_type, Some(&physical), "DELETE_COMPLETE", None, None).await;
                }
                Ok(())
            }
            Err(e) if e.not_found => {
                if events {
                    self.event(&r.logical_id, &r.resource_type, Some(&physical), "DELETE_COMPLETE", None, None).await;
                }
                Ok(())
            }
            Err(e) => {
                if events {
                    self.event(
                        &r.logical_id,
                        &r.resource_type,
                        Some(&physical),
                        "DELETE_FAILED",
                        Some(&e.message),
                        None,
                    )
                    .await;
                }
                Err(e.message)
            }
        }
    }

    /// The deletion policies that keep resources when an operation rolls
    /// back what it created: `Retain`, unless the stack was created or
    /// updated with `RetainExceptOnCreate`. Resources whose policy is
    /// `RetainExceptOnCreate` are always deleted then.
    fn rollback_retains(&self) -> &'static [&'static str] {
        if self.with(|s| s.retain_except_on_create) {
            &[]
        } else {
            &["Retain"]
        }
    }

    /// Delete existing resources in reverse dependency order. Resources
    /// whose `DeletionPolicy` is in `retain_policies` are kept
    /// (`DELETE_SKIPPED`); `snapshots` honours `DeletionPolicy: Snapshot`.
    /// Returns the logical ids that failed.
    async fn delete_resources(
        &self,
        template: Option<&Template>,
        only: Option<&BTreeSet<String>>,
        retain: &BTreeSet<String>,
        retain_policies: &[&str],
        snapshots: bool,
    ) -> Vec<String> {
        let stack = self.snapshot();
        let mut order: Vec<String> = match template {
            Some(t) => t.creation_order(&|_| true).unwrap_or_else(|_| t.resources().keys().cloned().collect()),
            None => Vec::new(),
        };
        for r in &stack.resources {
            if !order.contains(&r.logical_id) {
                order.insert(0, r.logical_id.clone());
            }
        }
        order.reverse();
        let mut failed: Vec<String> = Vec::new();
        for logical in order {
            if only.is_some_and(|o| !o.contains(&logical)) {
                continue;
            }
            let Some(r) = self.with(|s| s.resource(&logical).cloned()) else { continue };
            // Resources that depend on one that failed to delete stay.
            if let Some(t) = template {
                let blocked = failed.iter().any(|f| t.dependencies(f).contains(&logical));
                if blocked {
                    continue;
                }
            }
            if !r.exists() {
                if r.status != "DELETE_COMPLETE" && r.status != "DELETE_SKIPPED" {
                    self.update_resource(&logical, |x| x.status = "DELETE_COMPLETE".into());
                    if r.status == "CREATE_FAILED" {
                        self.event(&logical, &r.resource_type, r.physical_id.as_deref(), "DELETE_COMPLETE", None, None)
                            .await;
                    }
                }
                continue;
            }
            let policy = template
                .and_then(|t| t.resource(&logical))
                .and_then(|d| d.get("DeletionPolicy"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| default_deletion_policy(&r));
            if retain.contains(&logical) || retain_policies.contains(&policy) {
                self.event(&logical, &r.resource_type, r.physical_id.as_deref(), "DELETE_SKIPPED", None, None).await;
                self.update_resource(&logical, |x| x.status = "DELETE_SKIPPED".into());
                continue;
            }
            self.update_resource(&logical, |x| x.status = "DELETE_IN_PROGRESS".into());
            match self.delete_physical(&r, true, snapshots && policy == "Snapshot").await {
                Ok(()) => self.update_resource(&logical, |x| {
                    x.status = "DELETE_COMPLETE".into();
                    x.status_reason = None;
                }),
                Err(reason) => {
                    self.update_resource(&logical, |x| {
                        x.status = "DELETE_FAILED".into();
                        x.status_reason = Some(reason.clone());
                    });
                    failed.push(logical);
                }
            }
        }
        failed
    }

    /// Evaluate the template's outputs.
    pub(crate) fn outputs(&self, template: &Template, data: &EvalData) -> Result<Vec<StackOutput>, String> {
        let stack = self.snapshot();
        let pending = BTreeSet::new();
        let lookup = StackResources {
            resources: &stack.resources,
            template,
            data,
            pending: &pending,
            preview: false,
            cfn: &self.cfn,
            account: &self.ctx.caller.account_id,
            region: &self.ctx.region,
        };
        let ev = data.evaluator(template, &lookup);
        let mut out = Vec::new();
        let Some(outputs) = template.section("Outputs") else { return Ok(out) };
        for (key, o) in outputs {
            if let Some(c) = o.get("Condition").and_then(Value::as_str) {
                if !data.conditions.get(c).copied().unwrap_or(false) {
                    continue;
                }
            }
            let value = ev.eval(&o["Value"]).map_err(EvalError::message)?;
            let value = match value {
                Value::String(s) => s,
                Value::Array(a) => a.iter().map(providers::text).collect::<Vec<_>>().join(","),
                other => providers::text(&other),
            };
            let export_name = match o.get("Export").and_then(|e| e.get("Name")) {
                Some(n) => Some(providers::text(&ev.eval(n).map_err(EvalError::message)?)),
                None => None,
            };
            let description = o.get("Description").and_then(Value::as_str).map(str::to_string);
            out.push(StackOutput { key: key.clone(), value, description, export_name });
        }
        Ok(out)
    }

    /// Check that the outputs' exports neither clash with other stacks'
    /// nor break stacks importing the ones being changed or removed.
    fn check_exports(&self, old: &[StackOutput], new: &[StackOutput]) -> Result<(), String> {
        let st = self.cfn.state();
        let me = &st.stacks[&self.stack_id];
        for o in new {
            let Some(name) = &o.export_name else { continue };
            for s in st.stacks.values() {
                if s.id == me.id || s.is_deleted() || s.account != me.account || s.region != me.region {
                    continue;
                }
                if s.outputs.iter().any(|x| x.export_name.as_deref() == Some(name)) {
                    return Err(format!("Export with name {name} is already exported by stack {}", s.name));
                }
            }
        }
        for o in old {
            let Some(name) = &o.export_name else { continue };
            let still = new.iter().find(|n| n.export_name.as_deref() == Some(name));
            if still.is_some_and(|n| n.value == o.value) {
                continue;
            }
            if let Some(importer) =
                crate::importers(&st, &me.account, &me.region, name).into_iter().find(|i| i != &me.name)
            {
                return Err(match still {
                    Some(_) => format!("Cannot update export {name} as it is in use by {importer}"),
                    None => format!("Export {name} cannot be deleted as it is in use by {importer}"),
                });
            }
        }
        Ok(())
    }

    // ----- Stack operations -----

    /// Create every resource of a new stack.
    pub async fn create(self, template: Template, data: EvalData) {
        let timeout = self.with(|s| s.timeout_in_minutes);
        let work = self.create_resources(&template, &data);
        let result = match timeout {
            Some(m) if m > 0 => match tokio::time::timeout(std::time::Duration::from_secs(m as u64 * 60), work).await {
                Ok(r) => r,
                Err(_) => Err(Failure { logical_id: None, reason: "Resource creation cancelled".into() }),
            },
            _ => work.await,
        };
        let result = match result {
            Ok(()) => match self.outputs(&template, &data).and_then(|o| self.check_exports(&[], &o).map(|_| o)) {
                Ok(outputs) => {
                    self.with(|s| s.outputs = outputs);
                    Ok(())
                }
                Err(reason) => Err(Failure { logical_id: None, reason }),
            },
            Err(f) => Err(f),
        };
        match result {
            Ok(()) => self.stack_status("CREATE_COMPLETE", None).await,
            Err(f) => {
                let reason = match &f.logical_id {
                    Some(l) => format!("The following resource(s) failed to create: [{l}]. "),
                    None => f.reason.clone(),
                };
                let (disable, on_failure) = self.with(|s| (s.disable_rollback, s.on_failure.clone()));
                match on_failure.as_deref() {
                    Some("DO_NOTHING") => self.stack_status("CREATE_FAILED", Some(&reason)).await,
                    Some("DELETE") => {
                        self.stack_status("DELETE_IN_PROGRESS", Some(&reason)).await;
                        let retains = self.rollback_retains();
                        let failed =
                            self.delete_resources(Some(&template), None, &BTreeSet::new(), retains, false).await;
                        if failed.is_empty() {
                            self.with(|s| s.deleted = Some(Utc::now() + self.offset));
                            self.stack_status("DELETE_COMPLETE", None).await;
                        } else {
                            let r = format!("The following resource(s) failed to delete: [{}]. ", failed.join(", "));
                            self.stack_status("DELETE_FAILED", Some(&r)).await;
                        }
                    }
                    _ if disable => self.stack_status("CREATE_FAILED", Some(&reason)).await,
                    _ => self.rollback_create(&template, &format!("{reason}Rollback requested by user.")).await,
                }
            }
        }
        self.cfn.finished(&self.stack_id);
    }

    /// Bring existing resources under the stack (an IMPORT change set).
    pub async fn import(self, template: Template, data: EvalData, imports: Vec<(String, providers::scan::Scanned)>) {
        let mut done: Vec<String> = Vec::new();
        let mut failure: Option<String> = None;
        for (logical, found) in &imports {
            let def = template.resource(logical).cloned().unwrap_or_default();
            let ty = def.get("Type").and_then(Value::as_str).unwrap_or_default().to_string();
            self.event(logical, &ty, Some(&found.physical_id), "IMPORT_IN_PROGRESS", None, None).await;
            let props = match self.properties(&template, &data, logical).await {
                Ok(p) => p,
                Err(reason) => {
                    self.event(logical, &ty, Some(&found.physical_id), "IMPORT_FAILED", Some(&reason), None).await;
                    failure = Some(logical.clone());
                    break;
                }
            };
            self.set_resource(Resource {
                logical_id: logical.clone(),
                resource_type: ty.clone(),
                physical_id: Some(found.physical_id.clone()),
                status: "IMPORT_COMPLETE".into(),
                updated: self.now(),
                properties: props,
                attributes: found.attributes.clone(),
                metadata: def.get("Metadata").cloned(),
                description: def.get("Description").and_then(Value::as_str).map(str::to_string),
                ..Default::default()
            });
            self.event(logical, &ty, Some(&found.physical_id), "IMPORT_COMPLETE", None, None).await;
            done.push(logical.clone());
        }
        let result = match failure {
            Some(l) => Err(format!("The following resource(s) failed to import: [{l}]. ")),
            None => self.outputs(&template, &data),
        };
        match result {
            Ok(outputs) => {
                self.with(|s| {
                    s.outputs = outputs;
                    s.previous = None;
                });
                self.stack_status("IMPORT_COMPLETE", None).await;
            }
            Err(reason) => {
                self.stack_status("IMPORT_ROLLBACK_IN_PROGRESS", Some(&reason)).await;
                // Imported resources are released, never deleted.
                self.with(|s| {
                    s.resources.retain(|r| !done.contains(&r.logical_id));
                    if let Some(p) = s.previous.take() {
                        s.template_body = p.template_body;
                        s.parameters = p.parameters;
                        s.outputs = p.outputs;
                    }
                });
                self.stack_status("IMPORT_ROLLBACK_COMPLETE", None).await;
            }
        }
        self.cfn.finished(&self.stack_id);
    }

    async fn create_resources(&self, template: &Template, data: &EvalData) -> Result<(), Failure> {
        let order = template
            .creation_order(&|l| data.included(template, l))
            .map_err(|reason| Failure { logical_id: None, reason })?;
        for logical in order {
            self.check_triggers().await?;
            self.create_resource(template, data, &logical, false).await?;
        }
        self.monitor().await
    }

    /// Roll a failed creation back: delete what was created.
    pub async fn rollback_create(&self, template: &Template, reason: &str) {
        self.stack_status("ROLLBACK_IN_PROGRESS", Some(reason)).await;
        let retains = self.rollback_retains();
        let failed = self.delete_resources(Some(template), None, &BTreeSet::new(), retains, false).await;
        if failed.is_empty() {
            self.stack_status("ROLLBACK_COMPLETE", None).await;
        } else {
            let r = format!("The following resource(s) failed to delete: [{}]. ", failed.join(", "));
            self.stack_status("ROLLBACK_FAILED", Some(&r)).await;
        }
    }

    /// Delete the stack.
    pub async fn delete(self, retain: BTreeSet<String>) {
        let stack = self.snapshot();
        // Exports other stacks import cannot go.
        let blocked = {
            let st = self.cfn.state();
            stack.outputs.iter().find_map(|o| {
                let name = o.export_name.as_ref()?;
                let importer = crate::importers(&st, &stack.account, &stack.region, name)
                    .into_iter()
                    .find(|i| i != &stack.name)?;
                Some(format!("Export {name} cannot be deleted as it is in use by {importer}"))
            })
        };
        if let Some(reason) = blocked {
            self.stack_status("DELETE_FAILED", Some(&reason)).await;
            self.cfn.finished(&self.stack_id);
            return;
        }
        let template = Template::parse(&stack.template_body).ok();
        let failed =
            self.delete_resources(template.as_ref(), None, &retain, &["Retain", "RetainExceptOnCreate"], true).await;
        if failed.is_empty() {
            self.with(|s| s.deleted = Some(Utc::now() + self.offset));
            self.stack_status("DELETE_COMPLETE", None).await;
        } else {
            let r = format!("The following resource(s) failed to delete: [{}]. ", failed.join(", "));
            self.stack_status("DELETE_FAILED", Some(&r)).await;
        }
        self.cfn.finished(&self.stack_id);
    }

    /// Update the stack to `template` (already stored on the stack, with
    /// the previous deployment in `Stack::previous`).
    pub async fn update(self, template: Template, data: EvalData, policy_override: Option<String>) {
        let result = self.update_resources(&template, &data, policy_override.as_deref()).await;
        let previous = self.with(|s| s.previous.clone()).expect("updates keep the previous deployment");
        let result = match result {
            Ok(()) => {
                match self.outputs(&template, &data).and_then(|o| self.check_exports(&previous.outputs, &o).map(|_| o))
                {
                    Ok(outputs) => {
                        self.with(|s| s.outputs = outputs);
                        Ok(())
                    }
                    Err(reason) => Err(Failure { logical_id: None, reason }),
                }
            }
            Err(f) => Err(f),
        };
        match result {
            Ok(()) => {
                self.stack_status("UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", None).await;
                self.cleanup_after_update(&template, &data, &previous).await;
                self.with(|s| {
                    s.previous = None;
                    s.resources.retain(|r| r.status != "DELETE_COMPLETE" && r.status != "DELETE_SKIPPED");
                });
                self.stack_status("UPDATE_COMPLETE", None).await;
            }
            Err(f) => {
                let reason = match &f.logical_id {
                    Some(l) => format!("The following resource(s) failed to update: [{l}]. "),
                    None => f.reason.clone(),
                };
                if self.with(|s| s.disable_rollback) {
                    self.stack_status("UPDATE_FAILED", Some(&reason)).await;
                } else {
                    self.rollback_update(&reason, &BTreeSet::new()).await;
                }
            }
        }
        self.cfn.finished(&self.stack_id);
    }

    async fn update_resources(
        &self,
        template: &Template,
        data: &EvalData,
        policy_override: Option<&str>,
    ) -> Result<(), Failure> {
        let order = template
            .creation_order(&|l| data.included(template, l))
            .map_err(|reason| Failure { logical_id: None, reason })?;
        let stack_policy = self.with(|s| s.policy.clone());
        let policy = policy_override.map(str::to_string).or(stack_policy);
        let previous = self.with(|s| s.previous.clone()).expect("updates keep the previous deployment");
        for logical in order {
            self.check_triggers().await?;
            if self.cfn.cancel_requested(&self.stack_id) {
                return Err(Failure { logical_id: Some(logical.clone()), reason: "Resource update cancelled".into() });
            }
            let fail = |reason: String| Failure { logical_id: Some(logical.clone()), reason };
            let existing = self.with(|s| s.resource(&logical).filter(|r| r.exists()).cloned());
            let ty = template.resource_type(&logical).unwrap_or_default().to_string();
            let Some(old) = existing else {
                self.create_resource(template, data, &logical, false).await?;
                continue;
            };
            if old.resource_type != ty {
                return Err(fail(format!(
                    "Update of resource type is not permitted. The new template modifies resource type of the following resources: [{logical}]"
                )));
            }
            let props = match self.properties(template, data, &logical).await {
                Ok(p) => p,
                Err(reason) => {
                    self.event(&logical, &ty, old.physical_id.as_deref(), "UPDATE_FAILED", Some(&reason), None).await;
                    return Err(fail(reason));
                }
            };
            let new_def = template.resource(&logical).cloned().unwrap_or_default();
            let metadata_changed = new_def.get("Metadata") != old.metadata.as_ref();
            if props == old.properties {
                if metadata_changed {
                    self.update_resource(&logical, |r| r.metadata = new_def.get("Metadata").cloned());
                }
                continue;
            }
            let provider = self.provider(&ty).map_err(fail)?;
            let replace = needs_replacement(provider.as_ref(), &old.properties, &props);
            if let Some(p) = &policy {
                let action = if replace { "Update:Replace" } else { "Update:Modify" };
                if let Err(reason) = policy::check(p, action, &logical, &ty) {
                    self.event(&logical, &ty, old.physical_id.as_deref(), "UPDATE_FAILED", Some(&reason), None).await;
                    return Err(fail(reason));
                }
            }
            if replace {
                // A new resource cannot take a name the template fixes.
                if let Some(key) = provider.name_property() {
                    if let Some(name) = props.get(key).filter(|v| !v.is_null() && old.properties.get(key) == Some(*v)) {
                        let reason = format!(
                            "CloudFormation cannot update a stack when a custom-named resource requires replacing. Rename {} and update the stack again.",
                            providers::text(name)
                        );
                        self.event(&logical, &ty, old.physical_id.as_deref(), "UPDATE_FAILED", Some(&reason), None)
                            .await;
                        return Err(fail(reason));
                    }
                }
                self.create_resource(template, data, &logical, true).await?;
                // Keep the old physical resource for the cleanup phase.
                self.with(|s| s.replaced.push(old.clone()));
                continue;
            }
            let physical = old.physical_id.clone().unwrap_or_default();
            self.event(&logical, &ty, Some(&physical), "UPDATE_IN_PROGRESS", None, Some(&props)).await;
            self.update_resource(&logical, |r| r.status = "UPDATE_IN_PROGRESS".into());
            let stack = self.snapshot();
            let tags = Self::stack_tags(&stack);
            let cx = self.cx(&stack, &logical, &tags);
            let updated = match self.hooks(&logical, &ty, "UPDATE", &props, Some(&old.properties)).await {
                Ok(()) => provider.update(&cx, &physical, &old.properties, &props, &old.attributes).await,
                Err(reason) => Err(providers::HandlerError::invalid(reason)),
            };
            match updated {
                Ok(mut attrs) => {
                    let now = self.now();
                    // A custom resource may answer an update with a new
                    // physical id; the old one is deleted in cleanup.
                    if let Some(Value::String(p)) = attrs.remove(providers::NEW_PHYSICAL_ID) {
                        self.with(|s| s.replaced.push(old.clone()));
                        self.update_resource(&logical, |r| r.physical_id = Some(p));
                    }
                    self.update_resource(&logical, |r| {
                        r.status = "UPDATE_COMPLETE".into();
                        r.status_reason = None;
                        r.properties = props.clone();
                        r.attributes = attrs;
                        r.updated = now;
                        r.metadata = new_def.get("Metadata").cloned();
                    });
                    self.event(&logical, &ty, Some(&physical), "UPDATE_COMPLETE", None, None).await;
                }
                Err(e) => {
                    self.update_resource(&logical, |r| {
                        r.status = "UPDATE_FAILED".into();
                        r.status_reason = Some(e.message.clone());
                    });
                    self.event(&logical, &ty, Some(&physical), "UPDATE_FAILED", Some(&e.message), None).await;
                    return Err(fail(e.message));
                }
            }
        }
        let _ = previous;
        self.monitor().await
    }

    /// Fail the operation when a rollback trigger's alarm is in ALARM.
    async fn check_triggers(&self) -> Result<(), Failure> {
        let config = self.with(|s| s.rollback_configuration.clone());
        let Some(config) = config.filter(|c| !c.triggers.is_empty()) else { return Ok(()) };
        let names: Vec<String> = config
            .triggers
            .iter()
            .filter_map(|(arn, _)| arn.split_once(":alarm:").map(|(_, n)| n.to_string()))
            .collect();
        let input = serde_json::json!({"AlarmNames": names, "AlarmTypes": ["MetricAlarm", "CompositeAlarm"]});
        let out = match self.cfn.call(&self.ctx, "monitoring", "DescribeAlarms", input).await {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!("rollback trigger check failed: {}", e.message);
                return Ok(());
            }
        };
        let alarming: Vec<String> = ["MetricAlarms", "CompositeAlarms"]
            .iter()
            .flat_map(|k| out[*k].as_array().cloned().unwrap_or_default())
            .filter(|a| a["StateValue"] == "ALARM")
            .filter_map(|a| a["AlarmArn"].as_str().map(str::to_string))
            .collect();
        if alarming.is_empty() {
            return Ok(());
        }
        Err(Failure {
            logical_id: None,
            reason: format!(
                "Rollback triggered: the rollback trigger alarm(s) [{}] went into ALARM state. ",
                alarming.join(", ")
            ),
        })
    }

    /// Watch the rollback triggers for `MonitoringTimeInMinutes` (on the
    /// emulated clock) after the resources are deployed.
    async fn monitor(&self) -> Result<(), Failure> {
        let config = self.with(|s| s.rollback_configuration.clone());
        let Some(config) = config.filter(|c| !c.triggers.is_empty()) else { return Ok(()) };
        self.check_triggers().await?;
        let minutes = config.monitoring_minutes.unwrap_or(0).max(0);
        let deadline = self.cfn.now().max(self.now()) + chrono::Duration::minutes(minutes as i64);
        while self.cfn.now() < deadline {
            if self.cfn.cancel_requested(&self.stack_id) {
                return Err(Failure { logical_id: None, reason: "Resource update cancelled".into() });
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            self.check_triggers().await?;
        }
        Ok(())
    }

    /// Delete what the update removed or replaced.
    async fn cleanup_after_update(&self, template: &Template, data: &EvalData, previous: &Snapshot) {
        let old_template = Template::parse(&previous.template_body).ok();
        let keep: BTreeSet<String> =
            template.resources().keys().filter(|l| data.included(template, l)).cloned().collect();
        let removed: BTreeSet<String> = self
            .with(|s| s.resources.iter().map(|r| r.logical_id.clone()).collect::<Vec<_>>())
            .into_iter()
            .filter(|l| !keep.contains(l))
            .collect();
        if !removed.is_empty() {
            self.delete_resources(
                old_template.as_ref(),
                Some(&removed),
                &BTreeSet::new(),
                &["Retain", "RetainExceptOnCreate"],
                true,
            )
            .await;
        }
        for old in self.with(|s| std::mem::take(&mut s.replaced)) {
            let policy = template
                .resource(&old.logical_id)
                .and_then(|d| d.get("UpdateReplacePolicy"))
                .and_then(Value::as_str)
                .unwrap_or("Delete");
            if matches!(policy, "Retain" | "RetainExceptOnCreate") {
                continue;
            }
            let _ = self.delete_physical(&old, true, policy == "Snapshot").await;
        }
    }

    /// Roll an update back to the previous deployment.
    pub async fn rollback_update(&self, reason: &str, skip: &BTreeSet<String>) {
        self.stack_status("UPDATE_ROLLBACK_IN_PROGRESS", Some(reason)).await;
        let Some(previous) = self.with(|s| s.previous.clone()) else {
            self.stack_status("UPDATE_ROLLBACK_COMPLETE", None).await;
            return;
        };
        self.with(|s| s.replaced.clear());
        let new_template = Template::parse(&self.with(|s| s.template_body.clone())).ok();
        let mut created_now: Vec<Resource> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let old_template = Template::parse(&previous.template_body).ok();
        let order: Vec<String> = old_template
            .as_ref()
            .and_then(|t| t.creation_order(&|l| previous.resources.iter().any(|r| r.logical_id == l)).ok())
            .unwrap_or_else(|| previous.resources.iter().map(|r| r.logical_id.clone()).collect());
        // Put back what was replaced or changed.
        for logical in &order {
            let Some(old) = previous.resources.iter().find(|r| &r.logical_id == logical).cloned() else { continue };
            let Some(current) = self.with(|s| s.resource(logical).cloned()) else {
                self.set_resource(old);
                continue;
            };
            if skip.contains(logical) {
                self.set_resource(Resource { status: "UPDATE_COMPLETE".into(), ..old });
                continue;
            }
            if current.physical_id != old.physical_id {
                // Replaced: go back to the old physical resource and delete
                // the new one afterwards.
                if current.exists() {
                    created_now.push(current.clone());
                }
                self.event(logical, &old.resource_type, old.physical_id.as_deref(), "UPDATE_COMPLETE", None, None)
                    .await;
                self.set_resource(Resource { status: "UPDATE_COMPLETE".into(), ..old });
                continue;
            }
            if current.properties == old.properties && current.status != "UPDATE_FAILED" {
                continue;
            }
            let physical = old.physical_id.clone().unwrap_or_default();
            self.event(logical, &old.resource_type, Some(&physical), "UPDATE_IN_PROGRESS", None, Some(&old.properties))
                .await;
            let Some(provider) =
                self.cfn.provider_in(&self.ctx.caller.account_id, &self.ctx.region, &old.resource_type)
            else {
                continue;
            };
            let stack = self.snapshot();
            let tags: Vec<(String, String)> = previous.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect();
            let cx = self.cx(&stack, logical, &tags);
            match provider.update(&cx, &physical, &current.properties, &old.properties, &current.attributes).await {
                Ok(attrs) => {
                    self.event(logical, &old.resource_type, Some(&physical), "UPDATE_COMPLETE", None, None).await;
                    self.set_resource(Resource { status: "UPDATE_COMPLETE".into(), attributes: attrs, ..old });
                }
                Err(e) => {
                    self.event(logical, &old.resource_type, Some(&physical), "UPDATE_FAILED", Some(&e.message), None)
                        .await;
                    self.update_resource(logical, |r| {
                        r.status = "UPDATE_FAILED".into();
                        r.status_reason = Some(e.message.clone());
                    });
                    errors.push(logical.clone());
                }
            }
        }
        if !errors.is_empty() {
            let r = format!("The following resource(s) failed to update: [{}]. ", errors.join(", "));
            self.stack_status("UPDATE_ROLLBACK_FAILED", Some(&r)).await;
            return;
        }
        // Restore the previous template, parameters, outputs and tags.
        self.with(|s| {
            s.template_body = previous.template_body.clone();
            s.parameters = previous.parameters.clone();
            s.outputs = previous.outputs.clone();
            s.tags = previous.tags.clone();
            s.original_template = previous.original_template.clone();
            s.description = old_template.as_ref().and_then(Template::description);
        });
        self.stack_status("UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", None).await;
        // Delete what the update added, and replacements made.
        let added: BTreeSet<String> = self
            .with(|s| s.resources.iter().map(|r| r.logical_id.clone()).collect::<Vec<_>>())
            .into_iter()
            .filter(|l| !previous.resources.iter().any(|r| &r.logical_id == l))
            .collect();
        if !added.is_empty() {
            let retains = self.rollback_retains();
            self.delete_resources(new_template.as_ref(), Some(&added), &BTreeSet::new(), retains, false).await;
        }
        for r in created_now {
            let _ = self.delete_physical(&r, true, false).await;
        }
        self.with(|s| {
            s.previous = None;
            s.resources.retain(|r| r.status != "DELETE_COMPLETE" && r.status != "DELETE_SKIPPED");
        });
        self.stack_status("UPDATE_ROLLBACK_COMPLETE", None).await;
    }
}

/// The `DeletionPolicy` AWS applies when a template gives none: `Snapshot`
/// for database clusters and stand-alone DB instances, `Delete` otherwise.
fn default_deletion_policy(r: &Resource) -> &'static str {
    match r.resource_type.as_str() {
        "AWS::RDS::DBCluster" | "AWS::Redshift::Cluster" | "AWS::Neptune::DBCluster" | "AWS::DocDB::DBCluster" => {
            "Snapshot"
        }
        "AWS::RDS::DBInstance" if !r.properties.contains_key("DBClusterIdentifier") => "Snapshot",
        _ => "Delete",
    }
}

/// Whether changing `old` to `new` replaces the resource.
pub fn needs_replacement(provider: &dyn Provider, old: &Props, new: &Props) -> bool {
    if !provider.updatable() {
        return true;
    }
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    keys.into_iter().any(|k| old.get(k) != new.get(k) && provider.create_only().contains(&k.as_str()))
}

/// Seconds in an ISO 8601 duration such as `PT15M`.
pub fn parse_iso_duration(s: &str) -> u64 {
    let s = s.trim_start_matches('P');
    let (days, time) = match s.split_once('T') {
        Some((d, t)) => (d, t),
        None => (s, ""),
    };
    let mut total = 0u64;
    let mut num = String::new();
    for c in days.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else if c == 'D' {
            total += num.parse::<u64>().unwrap_or(0) * 86_400;
            num.clear();
        }
    }
    for c in time.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n = num.parse::<u64>().unwrap_or(0);
            num.clear();
            total += match c {
                'H' => n * 3600,
                'M' => n * 60,
                'S' => n,
                _ => 0,
            };
        }
    }
    total
}
