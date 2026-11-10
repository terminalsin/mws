//! State Manager associations: a document bound to targets, applied when
//! the association is created or updated, on its schedule (on the emulated
//! clock), when `StartAssociationsOnce` asks, and to managed nodes that
//! start matching its targets later. Command documents really run on the
//! nodes through Run Command; each application is an association execution
//! with per-node targets, and the nodes' association statuses follow it.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_schedule::Schedule;
use serde::{Deserialize, Serialize};

use crate::commands::{spawn, Launch};
use crate::documents::parse_content;
use crate::generated::{errors, types};
use crate::names::{now, page, request_tag_conditions};
use crate::Ssm;

const MAX_VERSIONS: usize = 1000;

/// One application of an association to its targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecutionRecord {
    pub execution: types::AssociationExecution,
    pub targets: Vec<types::AssociationExecutionTarget>,
    pub command_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AssociationRecord {
    pub description: types::AssociationDescription,
    /// Oldest first.
    pub versions: Vec<types::AssociationVersionInfo>,
    pub tags: BTreeMap<String, String>,
    /// Newest first.
    pub executions: Vec<ExecutionRecord>,
    /// The latest status on each node it applies to.
    pub instance_status: BTreeMap<String, types::InstanceAssociationStatusInfo>,
    /// When the schedule last came due.
    pub last_fired: Option<DateTime<Utc>>,
}

fn not_found() -> ServiceError {
    errors::association_does_not_exist("The specified association does not exist.")
}

fn association_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ssm:{}:{}:association/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

fn validate_name(name: &Option<String>) -> Result<(), ServiceError> {
    if let Some(n) = name {
        let ok = (3..=128).contains(&n.len())
            && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
        if !ok {
            return Err(errors::validation(format!(
                "1 validation error detected: Value '{n}' at 'associationName' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9_\\-.]{{3,128}}$"
            )));
        }
    }
    Ok(())
}

fn validate_schedule(expr: &Option<String>) -> Result<(), ServiceError> {
    if let Some(e) = expr.as_deref().filter(|e| !e.is_empty()) {
        if Schedule::parse(e).is_none() {
            return Err(errors::invalid_schedule(format!("Schedule expression {e} is invalid.")));
        }
    }
    Ok(())
}

/// The fields every create and update shares.
#[derive(Debug, Clone, Default)]
struct Spec {
    name: String,
    document_version: Option<String>,
    instance_id: Option<String>,
    parameters: Option<BTreeMap<String, Vec<String>>>,
    targets: Option<Vec<types::Target>>,
    schedule_expression: Option<String>,
    output_location: Option<types::InstanceAssociationOutputLocation>,
    association_name: Option<String>,
    automation_target_parameter_name: Option<String>,
    max_errors: Option<String>,
    max_concurrency: Option<String>,
    compliance_severity: Option<String>,
    sync_compliance: Option<String>,
    apply_only_at_cron_interval: bool,
    calendar_names: Option<Vec<String>>,
    target_locations: Option<Vec<types::TargetLocation>>,
    schedule_offset: Option<i32>,
    duration: Option<i32>,
    target_maps: Option<Vec<BTreeMap<String, Vec<String>>>>,
    alarm_configuration: Option<types::AlarmConfiguration>,
    association_dispatch_assume_role: Option<String>,
}

impl From<types::CreateAssociationRequest> for Spec {
    fn from(i: types::CreateAssociationRequest) -> Self {
        Spec {
            name: i.name,
            document_version: i.document_version,
            instance_id: i.instance_id,
            parameters: i.parameters,
            targets: i.targets,
            schedule_expression: i.schedule_expression,
            output_location: i.output_location,
            association_name: i.association_name,
            automation_target_parameter_name: i.automation_target_parameter_name,
            max_errors: i.max_errors,
            max_concurrency: i.max_concurrency,
            compliance_severity: i.compliance_severity,
            sync_compliance: i.sync_compliance,
            apply_only_at_cron_interval: i.apply_only_at_cron_interval,
            calendar_names: i.calendar_names,
            target_locations: i.target_locations,
            schedule_offset: i.schedule_offset,
            duration: i.duration,
            target_maps: i.target_maps,
            alarm_configuration: i.alarm_configuration,
            association_dispatch_assume_role: i.association_dispatch_assume_role,
        }
    }
}

impl From<types::CreateAssociationBatchRequestEntry> for Spec {
    fn from(i: types::CreateAssociationBatchRequestEntry) -> Self {
        Spec {
            name: i.name,
            document_version: i.document_version,
            instance_id: i.instance_id,
            parameters: i.parameters,
            targets: i.targets,
            schedule_expression: i.schedule_expression,
            output_location: i.output_location,
            association_name: i.association_name,
            automation_target_parameter_name: i.automation_target_parameter_name,
            max_errors: i.max_errors,
            max_concurrency: i.max_concurrency,
            compliance_severity: i.compliance_severity,
            sync_compliance: i.sync_compliance,
            apply_only_at_cron_interval: i.apply_only_at_cron_interval,
            calendar_names: i.calendar_names,
            target_locations: i.target_locations,
            schedule_offset: i.schedule_offset,
            duration: i.duration,
            target_maps: i.target_maps,
            alarm_configuration: i.alarm_configuration,
            association_dispatch_assume_role: None,
        }
    }
}

fn version_info(d: &types::AssociationDescription) -> types::AssociationVersionInfo {
    types::AssociationVersionInfo {
        association_id: d.association_id.clone(),
        association_version: d.association_version.clone(),
        created_date: d.last_update_association_date.or(d.date),
        name: d.name.clone(),
        document_version: d.document_version.clone(),
        parameters: d.parameters.clone(),
        targets: d.targets.clone(),
        schedule_expression: d.schedule_expression.clone(),
        output_location: d.output_location.clone(),
        association_name: d.association_name.clone(),
        max_errors: d.max_errors.clone(),
        max_concurrency: d.max_concurrency.clone(),
        compliance_severity: d.compliance_severity.clone(),
        sync_compliance: d.sync_compliance.clone(),
        apply_only_at_cron_interval: d.apply_only_at_cron_interval,
        calendar_names: d.calendar_names.clone(),
        target_locations: d.target_locations.clone(),
        schedule_offset: d.schedule_offset,
        duration: d.duration,
        target_maps: d.target_maps.clone(),
        association_dispatch_assume_role: d.association_dispatch_assume_role.clone(),
    }
}

fn summary(d: &types::AssociationDescription) -> types::Association {
    types::Association {
        name: d.name.clone(),
        instance_id: d.instance_id.clone(),
        association_id: d.association_id.clone(),
        association_version: d.association_version.clone(),
        document_version: d.document_version.clone(),
        targets: d.targets.clone(),
        last_execution_date: d.last_execution_date,
        overview: d.overview.clone(),
        schedule_expression: d.schedule_expression.clone(),
        association_name: d.association_name.clone(),
        schedule_offset: d.schedule_offset,
        duration: d.duration,
        target_maps: d.target_maps.clone(),
    }
}

fn overview(status: &str, detailed: &str, counts: BTreeMap<String, i32>) -> types::AssociationOverview {
    types::AssociationOverview {
        status: Some(status.into()),
        detailed_status: Some(detailed.into()),
        association_status_aggregated_count: Some(counts),
    }
}

/// `{"Success":2,"Failed":1}`, as `ResourceCountByStatus` shows it.
fn counts_json(counts: &BTreeMap<String, i32>) -> String {
    serde_json::to_string(counts).unwrap_or_else(|_| "{}".into())
}

impl Ssm {
    fn association(&self, ctx: &RequestContext, id: &str) -> Result<AssociationRecord, ServiceError> {
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.associations.get(id))
            .cloned()
            .ok_or_else(not_found)
    }

    /// The association an `AssociationId`, or a `Name` and `InstanceId`,
    /// names.
    fn find_association(
        &self,
        ctx: &RequestContext,
        id: Option<&str>,
        name: Option<&str>,
        instance: Option<&str>,
    ) -> Result<AssociationRecord, ServiceError> {
        if let Some(id) = id {
            return self.association(ctx, id);
        }
        let (Some(name), Some(instance)) = (name, instance) else {
            return Err(errors::invalid_parameters("Specify either AssociationId, or both Name and InstanceId."));
        };
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| {
                r.associations.values().find(|a| {
                    a.description.name.as_deref() == Some(name)
                        && a.description.instance_id.as_deref() == Some(instance)
                })
            })
            .cloned()
            .ok_or_else(not_found)
    }

    fn check_spec(&self, ctx: &RequestContext, s: &Spec) -> Result<String, ServiceError> {
        validate_name(&s.association_name)?;
        validate_schedule(&s.schedule_expression)?;
        let found = self
            .find_document(ctx, &s.name)
            .ok_or_else(|| errors::invalid_document("The specified document does not exist."))?;
        if !matches!(found.doc.document_type.as_str(), "Command" | "Automation" | "Policy") {
            return Err(errors::invalid_document(format!(
                "Document type {} is not supported for associations.",
                found.doc.document_type
            )));
        }
        if let Some(v) = s.document_version.as_deref() {
            crate::documents::pick_version(&found.doc, Some(v), None)?;
        }
        let has_targets = s.targets.as_ref().is_some_and(|t| !t.is_empty());
        if s.instance_id.is_some() && has_targets {
            return Err(errors::invalid_parameters("Specify either InstanceId or Targets, but not both."));
        }
        if let Some(c) = s.compliance_severity.as_deref() {
            if !["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSPECIFIED"].contains(&c) {
                return Err(errors::validation(format!("Invalid ComplianceSeverity: {c}")));
            }
        }
        if s.apply_only_at_cron_interval && s.schedule_expression.as_deref().is_none_or(|e| !e.starts_with("cron(")) {
            return Err(errors::invalid_parameters(
                "ApplyOnlyAtCronInterval can only be set with a cron schedule expression.",
            ));
        }
        let doc_arn = if found.doc.amazon() {
            crate::documents::arn(&ctx.partition, &ctx.region, "", &found.doc.name)
        } else {
            crate::documents::arn(&ctx.partition, &ctx.region, &found.owner_account, &found.doc.name)
        };
        Ok(doc_arn)
    }

    fn describe_spec(
        s: Spec,
        id: &str,
        version: usize,
        created: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> types::AssociationDescription {
        types::AssociationDescription {
            name: Some(s.name),
            instance_id: s.instance_id,
            association_version: Some(version.to_string()),
            date: Some(created),
            last_update_association_date: Some(now),
            status: None,
            overview: Some(overview("Pending", "Creating", BTreeMap::new())),
            document_version: Some(s.document_version.unwrap_or_else(|| "$DEFAULT".into())),
            automation_target_parameter_name: s.automation_target_parameter_name,
            parameters: s.parameters,
            association_id: Some(id.to_string()),
            targets: s.targets,
            schedule_expression: s.schedule_expression,
            output_location: s.output_location,
            last_execution_date: None,
            last_successful_execution_date: None,
            association_name: s.association_name,
            max_errors: s.max_errors,
            max_concurrency: s.max_concurrency,
            compliance_severity: s.compliance_severity,
            sync_compliance: Some(s.sync_compliance.unwrap_or_else(|| "AUTO".into())),
            apply_only_at_cron_interval: s.apply_only_at_cron_interval,
            calendar_names: s.calendar_names,
            target_locations: s.target_locations,
            schedule_offset: s.schedule_offset,
            duration: s.duration,
            target_maps: s.target_maps,
            alarm_configuration: s.alarm_configuration,
            triggered_alarms: None,
            association_dispatch_assume_role: s.association_dispatch_assume_role,
        }
    }

    fn create_from_spec(
        &self,
        ctx: &RequestContext,
        s: Spec,
        tags: BTreeMap<String, String>,
    ) -> Result<types::AssociationDescription, ServiceError> {
        let doc_arn = self.check_spec(ctx, &s)?;
        let id = uuid::Uuid::new_v4().to_string();
        let mut cond = request_tag_conditions(&tags);
        cond.extend(ConditionContext::new());
        ctx.authorize("ssm:CreateAssociation", &doc_arn, cond.clone())?;
        if let Some(i) = &s.instance_id {
            let arn = format!("arn:{}:ec2:{}:{}:instance/{i}", ctx.partition, ctx.region, ctx.caller.account_id);
            ctx.authorize("ssm:CreateAssociation", &arn, cond)?;
        }
        let t = now(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(i) = &s.instance_id {
            if region.associations.values().any(|a| {
                a.description.instance_id.as_deref() == Some(i) && a.description.name.as_deref() == Some(&s.name)
            }) {
                return Err(errors::association_already_exists("The specified association already exists."));
            }
        }
        let run_now = !s.apply_only_at_cron_interval;
        let description = Self::describe_spec(s, &id, 1, t, t);
        region.associations.insert(
            id.clone(),
            AssociationRecord {
                versions: vec![version_info(&description)],
                description: description.clone(),
                tags,
                last_fired: Some(t),
                ..Default::default()
            },
        );
        drop(st);
        if run_now {
            self.apply_association(&ctx.caller.account_id, &ctx.region, &id, t, None);
        }
        Ok(description)
    }

    pub(crate) fn create_association(
        &self,
        ctx: &RequestContext,
        input: types::CreateAssociationRequest,
    ) -> Result<types::CreateAssociationResult, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
        let d = self.create_from_spec(ctx, input.into(), tags)?;
        Ok(types::CreateAssociationResult { association_description: Some(d) })
    }

    pub(crate) fn create_association_batch(
        &self,
        ctx: &RequestContext,
        input: types::CreateAssociationBatchRequest,
    ) -> Result<types::CreateAssociationBatchResult, ServiceError> {
        let mut successful = Vec::new();
        let mut failed = Vec::new();
        for entry in input.entries {
            let mut spec: Spec = entry.clone().into();
            spec.association_dispatch_assume_role = input.association_dispatch_assume_role.clone();
            match self.create_from_spec(ctx, spec, BTreeMap::new()) {
                Ok(d) => successful.push(d),
                Err(e) if e.code == "AccessDeniedException" => return Err(e),
                Err(e) => {
                    let fault = if e.status >= 500 { "Server" } else { "Client" };
                    failed.push(types::FailedCreateAssociation {
                        entry: Some(entry),
                        message: Some(e.message),
                        fault: Some(fault.into()),
                    });
                }
            }
        }
        Ok(types::CreateAssociationBatchResult { successful: Some(successful), failed: Some(failed) })
    }

    pub(crate) fn describe_association(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAssociationRequest,
    ) -> Result<types::DescribeAssociationResult, ServiceError> {
        let a = self.find_association(
            ctx,
            input.association_id.as_deref(),
            input.name.as_deref(),
            input.instance_id.as_deref(),
        )?;
        let id = a.description.association_id.clone().unwrap_or_default();
        ctx.authorize("ssm:DescribeAssociation", &association_arn(ctx, &id), ConditionContext::new())?;
        let mut d = a.description.clone();
        if let Some(v) = input.association_version.as_deref().filter(|v| *v != "$LATEST") {
            let info = a.versions.iter().find(|x| x.association_version.as_deref() == Some(v)).ok_or_else(|| {
                errors::invalid_association_version(format!("Association version {v} does not exist."))
            })?;
            d.association_version = info.association_version.clone();
            d.document_version = info.document_version.clone();
            d.parameters = info.parameters.clone();
            d.targets = info.targets.clone();
            d.schedule_expression = info.schedule_expression.clone();
            d.association_name = info.association_name.clone();
            d.name = info.name.clone();
        }
        Ok(types::DescribeAssociationResult { association_description: Some(d) })
    }

    pub(crate) fn delete_association(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAssociationRequest,
    ) -> Result<types::DeleteAssociationResult, ServiceError> {
        let a = self.find_association(
            ctx,
            input.association_id.as_deref(),
            input.name.as_deref(),
            input.instance_id.as_deref(),
        )?;
        let id = a.description.association_id.clone().unwrap_or_default();
        ctx.authorize("ssm:DeleteAssociation", &association_arn(ctx, &id), ConditionContext::new())?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).associations.remove(&id);
        Ok(types::DeleteAssociationResult {})
    }

    pub(crate) fn list_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListAssociationsRequest,
    ) -> Result<types::ListAssociationsResult, ServiceError> {
        ctx.authorize("ssm:ListAssociations", &association_arn(ctx, "*"), ConditionContext::new())?;
        let filters = input.association_filter_list.unwrap_or_default();
        const KEYS: &[&str] = &[
            "InstanceId",
            "Name",
            "AssociationId",
            "AssociationStatusName",
            "LastExecutedBefore",
            "LastExecutedAfter",
            "AssociationName",
            "ResourceGroupName",
        ];
        for f in &filters {
            if !KEYS.contains(&f.key.as_str()) {
                return Err(errors::validation(format!("Invalid AssociationFilterKey: {}", f.key)));
            }
        }
        let st = self.lock();
        let mut all: Vec<types::AssociationDescription> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| r.associations.values().map(|a| a.description.clone()).collect())
            .unwrap_or_default();
        drop(st);
        all.sort_by_key(|d| d.date);
        let time = |v: &str| DateTime::parse_from_rfc3339(v).ok().map(|t| t.with_timezone(&Utc));
        let all: Vec<types::Association> = all
            .iter()
            .filter(|d| {
                filters.iter().all(|f| match f.key.as_str() {
                    "InstanceId" => {
                        d.instance_id.as_deref() == Some(&f.value)
                            || d.targets.iter().flatten().any(|t| {
                                t.key.as_deref() == Some("InstanceIds")
                                    && t.values.iter().flatten().any(|v| v == &f.value || v == "*")
                            })
                    }
                    "Name" => d.name.as_deref() == Some(&f.value),
                    "AssociationId" => d.association_id.as_deref() == Some(&f.value),
                    "AssociationStatusName" => d.overview.as_ref().and_then(|o| o.status.as_deref()) == Some(&f.value),
                    "AssociationName" => d.association_name.as_deref() == Some(&f.value),
                    "LastExecutedBefore" => d.last_execution_date.zip(time(&f.value)).is_some_and(|(a, b)| a < b),
                    "LastExecutedAfter" => d.last_execution_date.zip(time(&f.value)).is_some_and(|(a, b)| a > b),
                    _ => false,
                })
            })
            .map(summary)
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::ListAssociationsResult { associations: Some(items), next_token: next })
    }

    pub(crate) fn update_association(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAssociationRequest,
    ) -> Result<types::UpdateAssociationResult, ServiceError> {
        let a = self.association(ctx, &input.association_id)?;
        ctx.authorize("ssm:UpdateAssociation", &association_arn(ctx, &input.association_id), ConditionContext::new())?;
        if let Some(v) = &input.association_version {
            if a.description.association_version.as_deref() != Some(v.as_str()) && v != "$LATEST" {
                return Err(errors::invalid_association_version(
                    "The association version you specified isn't the latest version of the association.",
                ));
            }
        }
        if a.versions.len() >= MAX_VERSIONS {
            return Err(errors::association_version_limit_exceeded(
                "You have reached the maximum number versions allowed for an association.",
            ));
        }
        let d = &a.description;
        let spec = Spec {
            name: input.name.unwrap_or_else(|| d.name.clone().unwrap_or_default()),
            document_version: input.document_version.or_else(|| d.document_version.clone()),
            instance_id: d.instance_id.clone(),
            parameters: input.parameters.or_else(|| d.parameters.clone()),
            targets: input.targets.or_else(|| d.targets.clone()),
            schedule_expression: input.schedule_expression.or_else(|| d.schedule_expression.clone()),
            output_location: input.output_location.or_else(|| d.output_location.clone()),
            association_name: input.association_name.or_else(|| d.association_name.clone()),
            automation_target_parameter_name: input
                .automation_target_parameter_name
                .or_else(|| d.automation_target_parameter_name.clone()),
            max_errors: input.max_errors.or_else(|| d.max_errors.clone()),
            max_concurrency: input.max_concurrency.or_else(|| d.max_concurrency.clone()),
            compliance_severity: input.compliance_severity.or_else(|| d.compliance_severity.clone()),
            sync_compliance: input.sync_compliance.or_else(|| d.sync_compliance.clone()),
            apply_only_at_cron_interval: input.apply_only_at_cron_interval,
            calendar_names: input.calendar_names.or_else(|| d.calendar_names.clone()),
            target_locations: input.target_locations.or_else(|| d.target_locations.clone()),
            schedule_offset: input.schedule_offset.or(d.schedule_offset),
            duration: input.duration.or(d.duration),
            target_maps: input.target_maps.or_else(|| d.target_maps.clone()),
            alarm_configuration: input.alarm_configuration.or_else(|| d.alarm_configuration.clone()),
            association_dispatch_assume_role: input
                .association_dispatch_assume_role
                .or_else(|| d.association_dispatch_assume_role.clone()),
        };
        self.check_spec(ctx, &spec)?;
        let t = now(ctx);
        let run_now = !spec.apply_only_at_cron_interval;
        let mut description =
            Self::describe_spec(spec, &input.association_id, a.versions.len() + 1, d.date.unwrap_or(t), t);
        description.overview = d.overview.clone();
        description.last_execution_date = d.last_execution_date;
        description.last_successful_execution_date = d.last_successful_execution_date;
        {
            let mut st = self.lock();
            let r = st.region(&ctx.caller.account_id, &ctx.region);
            let rec = r.associations.get_mut(&input.association_id).ok_or_else(not_found)?;
            rec.description = description.clone();
            rec.versions.push(version_info(&description));
            rec.last_fired = Some(t);
        }
        if run_now {
            self.apply_association(&ctx.caller.account_id, &ctx.region, &input.association_id, t, None);
        }
        Ok(types::UpdateAssociationResult { association_description: Some(description) })
    }

    pub(crate) fn update_association_status(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAssociationStatusRequest,
    ) -> Result<types::UpdateAssociationStatusResult, ServiceError> {
        let a = self.find_association(ctx, None, Some(&input.name), Some(&input.instance_id))?;
        let id = a.description.association_id.clone().unwrap_or_default();
        ctx.authorize("ssm:UpdateAssociationStatus", &association_arn(ctx, &id), ConditionContext::new())?;
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let rec = r.associations.get_mut(&id).ok_or_else(not_found)?;
        let status = input.association_status;
        rec.description.status = Some(status.clone());
        rec.description.overview =
            Some(overview(&status.name, &status.name, BTreeMap::from([(status.name.clone(), 1)])));
        Ok(types::UpdateAssociationStatusResult { association_description: Some(rec.description.clone()) })
    }

    pub(crate) fn list_association_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListAssociationVersionsRequest,
    ) -> Result<types::ListAssociationVersionsResult, ServiceError> {
        let a = self.association(ctx, &input.association_id)?;
        ctx.authorize(
            "ssm:ListAssociationVersions",
            &association_arn(ctx, &input.association_id),
            ConditionContext::new(),
        )?;
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(a.versions, input.next_token.as_deref(), limit)?;
        Ok(types::ListAssociationVersionsResult { association_versions: Some(items), next_token: next })
    }

    pub(crate) fn describe_association_executions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAssociationExecutionsRequest,
    ) -> Result<types::DescribeAssociationExecutionsResult, ServiceError> {
        let a = self.association(ctx, &input.association_id)?;
        ctx.authorize(
            "ssm:DescribeAssociationExecutions",
            &association_arn(ctx, &input.association_id),
            ConditionContext::new(),
        )?;
        let filters = input.filters.unwrap_or_default();
        let time = |v: &str| DateTime::parse_from_rfc3339(v).ok().map(|t| t.with_timezone(&Utc));
        for f in &filters {
            if !["ExecutionId", "Status", "CreatedTime"].contains(&f.key.as_str()) {
                return Err(errors::validation(format!("Invalid AssociationExecutionFilterKey: {}", f.key)));
            }
        }
        let all: Vec<types::AssociationExecution> = a
            .executions
            .into_iter()
            .map(|e| e.execution)
            .filter(|e| {
                filters.iter().all(|f| match f.key.as_str() {
                    "ExecutionId" => e.execution_id.as_deref() == Some(&f.value),
                    "Status" => e.status.as_deref() == Some(&f.value),
                    _ => {
                        let (Some(c), Some(v)) = (e.created_time, time(&f.value)) else { return false };
                        match f.r#type.as_str() {
                            "LESS_THAN" => c < v,
                            "GREATER_THAN" => c > v,
                            _ => c == v,
                        }
                    }
                })
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeAssociationExecutionsResult { association_executions: Some(items), next_token: next })
    }

    pub(crate) fn describe_association_execution_targets(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAssociationExecutionTargetsRequest,
    ) -> Result<types::DescribeAssociationExecutionTargetsResult, ServiceError> {
        let a = self.association(ctx, &input.association_id)?;
        ctx.authorize(
            "ssm:DescribeAssociationExecutionTargets",
            &association_arn(ctx, &input.association_id),
            ConditionContext::new(),
        )?;
        let e = a
            .executions
            .into_iter()
            .find(|e| e.execution.execution_id.as_deref() == Some(&input.execution_id))
            .ok_or_else(|| {
                errors::association_execution_does_not_exist("The specified execution ID does not exist.")
            })?;
        let filters = input.filters.unwrap_or_default();
        let all: Vec<types::AssociationExecutionTarget> = e
            .targets
            .into_iter()
            .filter(|t| {
                filters.iter().all(|f| match f.key.as_str() {
                    "Status" => t.status.as_deref() == Some(&f.value),
                    "ResourceId" => t.resource_id.as_deref() == Some(&f.value),
                    "ResourceType" => t.resource_type.as_deref() == Some(&f.value),
                    _ => false,
                })
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeAssociationExecutionTargetsResult {
            association_execution_targets: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn describe_effective_instance_associations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEffectiveInstanceAssociationsRequest,
    ) -> Result<types::DescribeEffectiveInstanceAssociationsResult, ServiceError> {
        let arn = format!(
            "arn:{}:ec2:{}:{}:instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:DescribeEffectiveInstanceAssociations", &arn, ConditionContext::new())?;
        let records: Vec<AssociationRecord> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.associations.values().cloned().collect())
                .unwrap_or_default()
        };
        let mut out = Vec::new();
        for a in records {
            let d = &a.description;
            if !self.association_targets(&ctx.caller.account_id, &ctx.region, d).contains(&input.instance_id) {
                continue;
            }
            let content = self.find_document(ctx, d.name.as_deref().unwrap_or_default()).and_then(|f| {
                let v = crate::documents::pick_version(&f.doc, d.document_version.as_deref(), None).ok()?;
                let value = parse_content(&v.content, &v.format).ok()?;
                serde_json::to_string(&value).ok()
            });
            out.push(types::InstanceAssociation {
                association_id: d.association_id.clone(),
                instance_id: Some(input.instance_id.clone()),
                content,
                association_version: d.association_version.clone(),
            });
        }
        let limit = input.max_results.unwrap_or(5).clamp(1, 5) as usize;
        let (items, next) = page(out, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeEffectiveInstanceAssociationsResult { associations: Some(items), next_token: next })
    }

    pub(crate) fn describe_instance_associations_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceAssociationsStatusRequest,
    ) -> Result<types::DescribeInstanceAssociationsStatusResult, ServiceError> {
        let arn = format!(
            "arn:{}:ec2:{}:{}:instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:DescribeInstanceAssociationsStatus", &arn, ConditionContext::new())?;
        let st = self.lock();
        let all: Vec<types::InstanceAssociationStatusInfo> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.associations.values().filter_map(|a| a.instance_status.get(&input.instance_id).cloned()).collect()
            })
            .unwrap_or_default();
        drop(st);
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeInstanceAssociationsStatusResult {
            instance_association_status_infos: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn start_associations_once(
        &self,
        ctx: &RequestContext,
        input: types::StartAssociationsOnceRequest,
    ) -> Result<types::StartAssociationsOnceResult, ServiceError> {
        for id in &input.association_ids {
            self.association(ctx, id)?;
            ctx.authorize("ssm:StartAssociationsOnce", &association_arn(ctx, id), ConditionContext::new())?;
        }
        let t = now(ctx);
        for id in &input.association_ids {
            self.apply_association(&ctx.caller.account_id, &ctx.region, id, t, None);
        }
        Ok(types::StartAssociationsOnceResult {})
    }

    /// The managed nodes an association applies to.
    pub(crate) fn association_targets(
        &self,
        account: &str,
        region: &str,
        d: &types::AssociationDescription,
    ) -> Vec<String> {
        let nodes = self.nodes_of(account, region);
        if let Some(i) = &d.instance_id {
            return nodes.iter().filter(|n| &n.instance_id == i).map(|n| n.instance_id.clone()).collect();
        }
        let targets = d.targets.clone().unwrap_or_default();
        let all = targets
            .iter()
            .any(|t| t.key.as_deref() == Some("InstanceIds") && t.values.iter().flatten().any(|v| v == "*"));
        if all {
            return nodes.iter().filter(|n| n.ping_status == "Online").map(|n| n.instance_id.clone()).collect();
        }
        let explicit: Vec<types::Target> =
            targets.into_iter().filter(|t| t.key.as_deref() != Some("ResourceGroup")).collect();
        let ids = self.resolve_targets(account, region, &explicit).unwrap_or_default();
        ids.into_iter().filter(|id| nodes.iter().any(|n| &n.instance_id == id && n.ping_status == "Online")).collect()
    }

    /// Apply an association now: to all its targets, or only to `only`
    /// (nodes that started matching). Runs in the background.
    pub(crate) fn apply_association(
        &self,
        account: &str,
        region: &str,
        id: &str,
        at: DateTime<Utc>,
        only: Option<Vec<String>>,
    ) {
        let Some(d) = ({
            let st = self.lock();
            st.region_ref(account, region).and_then(|r| r.associations.get(id)).map(|a| a.description.clone())
        }) else {
            return;
        };
        // Change calendars hold associations while they are closed.
        if let Some(calendars) = d.calendar_names.as_ref().filter(|c| !c.is_empty()) {
            if !self.calendars_open(account, region, calendars, at) {
                return;
            }
        }
        let mut nodes = self.association_targets(account, region, &d);
        if let Some(only) = &only {
            nodes.retain(|n| only.contains(n));
        }
        if nodes.is_empty() {
            let mut st = self.lock();
            if let Some(a) = st.region(account, region).associations.get_mut(id) {
                if a.executions.is_empty() {
                    a.description.overview = Some(overview("Pending", "Associated", BTreeMap::new()));
                }
            }
            return;
        }
        let execution_id = uuid::Uuid::new_v4().to_string();
        let doc = self.find_document_in(account, region, d.name.as_deref().unwrap_or_default());
        let doc_type = doc.as_ref().map(|f| f.doc.document_type.clone()).unwrap_or_default();
        let launched = if doc_type == "Command" || doc_type == "Policy" {
            self.launch(
                account,
                region,
                at,
                Launch {
                    document_name: d.name.clone().unwrap_or_default(),
                    document_version: d.document_version.clone().filter(|v| v != "$DEFAULT"),
                    parameters: d.parameters.clone().unwrap_or_default(),
                    instance_ids: nodes.clone(),
                    explicit: false,
                    targets: d.targets.clone().unwrap_or_default(),
                    comment: Some(format!("Association {id}")),
                    output_s3_region: d
                        .output_location
                        .as_ref()
                        .and_then(|o| o.s3_location.as_ref())
                        .and_then(|s| s.output_s3_region.clone()),
                    output_s3_bucket_name: d
                        .output_location
                        .as_ref()
                        .and_then(|o| o.s3_location.as_ref())
                        .and_then(|s| s.output_s3_bucket_name.clone()),
                    output_s3_key_prefix: d
                        .output_location
                        .as_ref()
                        .and_then(|o| o.s3_location.as_ref())
                        .and_then(|s| s.output_s3_key_prefix.clone()),
                    max_concurrency: d.max_concurrency.clone(),
                    max_errors: d.max_errors.clone(),
                    policy_ok: true,
                    ..Default::default()
                },
            )
            .map(|c| c.command_id.unwrap_or_default())
            .map_err(|e| e.message)
        } else {
            Err(format!("Documents of type {doc_type} are not applied by associations yet."))
        };
        let pending: BTreeMap<String, i32> = BTreeMap::from([("Pending".into(), nodes.len() as i32)]);
        let targets = nodes
            .iter()
            .map(|n| types::AssociationExecutionTarget {
                association_id: Some(id.to_string()),
                association_version: d.association_version.clone(),
                execution_id: Some(execution_id.clone()),
                resource_id: Some(n.clone()),
                resource_type: Some("ManagedInstance".into()),
                status: Some("Pending".into()),
                detailed_status: Some("Pending".into()),
                last_execution_date: Some(at),
                output_source: None,
            })
            .collect();
        let record = ExecutionRecord {
            execution: types::AssociationExecution {
                association_id: Some(id.to_string()),
                association_version: d.association_version.clone(),
                execution_id: Some(execution_id.clone()),
                status: Some("Pending".into()),
                detailed_status: Some("Pending".into()),
                created_time: Some(at),
                last_execution_date: None,
                resource_count_by_status: Some(counts_json(&pending)),
                alarm_configuration: d.alarm_configuration.clone(),
                triggered_alarms: None,
            },
            targets,
            command_id: launched.as_ref().ok().cloned(),
        };
        {
            let mut st = self.lock();
            let Some(a) = st.region(account, region).associations.get_mut(id) else { return };
            a.executions.insert(0, record);
            a.executions.truncate(100);
            a.description.overview = Some(overview("Pending", "InProgress", pending));
            for n in &nodes {
                a.instance_status.insert(
                    n.clone(),
                    types::InstanceAssociationStatusInfo {
                        association_id: Some(id.to_string()),
                        name: d.name.clone(),
                        document_version: d.document_version.clone(),
                        association_version: d.association_version.clone(),
                        instance_id: Some(n.clone()),
                        execution_date: Some(at),
                        status: Some("Pending".into()),
                        detailed_status: Some("Pending".into()),
                        execution_summary: Some("Pending".into()),
                        error_code: None,
                        output_url: None,
                        association_name: d.association_name.clone(),
                    },
                );
            }
        }
        match launched {
            Ok(command_id) => {
                let ssm = self.clone();
                let (account, region, id) = (account.to_string(), region.to_string(), id.to_string());
                spawn(async move { ssm.follow_execution(&account, &region, &id, &execution_id, &command_id).await });
            }
            Err(message) => {
                let results = nodes.iter().map(|n| (n.clone(), "Failed".to_string(), message.clone())).collect();
                self.finish_execution(account, region, id, &execution_id, results, at);
            }
        }
    }

    /// Follow an execution's command to its end.
    async fn follow_execution(&self, account: &str, region: &str, id: &str, execution_id: &str, command_id: &str) {
        let mut marked_running = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let Some((command, invocations)) = self.command_status(account, region, command_id) else { return };
            if !marked_running {
                marked_running = true;
                let mut st = self.lock();
                if let Some(e) = st.region(account, region).associations.get_mut(id).and_then(|a| {
                    a.executions.iter_mut().find(|e| e.execution.execution_id.as_deref() == Some(execution_id))
                }) {
                    e.execution.status = Some("InProgress".into());
                    e.execution.detailed_status = Some("InProgress".into());
                }
            }
            let done = !matches!(command.status.as_deref(), Some("Pending" | "InProgress" | "Cancelling"));
            if done {
                let results = invocations
                    .iter()
                    .map(|i| {
                        let status = match i.status.as_str() {
                            "Success" => "Success",
                            "Cancelled" => "Cancelled",
                            "TimedOut" => "TimedOut",
                            _ => "Failed",
                        };
                        let summary = i
                            .plugins
                            .iter()
                            .map(|p| format!("{}: {}", p.name, p.status))
                            .collect::<Vec<_>>()
                            .join(", ");
                        (i.instance_id.clone(), status.to_string(), summary)
                    })
                    .collect();
                let at = Utc::now() + chrono::Duration::milliseconds(self.clock_offset_ms());
                self.finish_execution(account, region, id, execution_id, results, at);
                return;
            }
        }
    }

    /// Record how an execution ended on each node.
    fn finish_execution(
        &self,
        account: &str,
        region: &str,
        id: &str,
        execution_id: &str,
        results: Vec<(String, String, String)>,
        at: DateTime<Utc>,
    ) {
        let mut st = self.lock();
        let Some(a) = st.region(account, region).associations.get_mut(id) else { return };
        let mut counts: BTreeMap<String, i32> = BTreeMap::new();
        for (_, status, _) in &results {
            *counts.entry(status.clone()).or_default() += 1;
        }
        let ok = results.iter().all(|(_, s, _)| s == "Success");
        let status = if ok { "Success" } else { "Failed" };
        if let Some(e) = a.executions.iter_mut().find(|e| e.execution.execution_id.as_deref() == Some(execution_id)) {
            e.execution.status = Some(status.into());
            e.execution.detailed_status = Some(status.into());
            e.execution.last_execution_date = Some(at);
            e.execution.resource_count_by_status = Some(counts_json(&counts));
            for t in e.targets.iter_mut() {
                if let Some((_, s, _)) = results.iter().find(|(n, _, _)| Some(n) == t.resource_id.as_ref()) {
                    t.status = Some(s.clone());
                    t.detailed_status = Some(s.clone());
                    t.last_execution_date = Some(at);
                    t.output_source = e.command_id.as_ref().map(|c| types::OutputSource {
                        output_source_id: Some(c.clone()),
                        output_source_type: Some("RunCommand".into()),
                    });
                }
            }
        }
        for (node, s, summary) in &results {
            if let Some(info) = a.instance_status.get_mut(node) {
                info.status = Some(s.clone());
                info.detailed_status = Some(s.clone());
                info.execution_date = Some(at);
                info.execution_summary = Some(summary.clone());
                info.error_code = (s != "Success").then(|| summary.clone());
            }
        }
        // Association compliance, unless the association syncs it manually.
        let compliance = (a.description.sync_compliance.as_deref() != Some("MANUAL")).then(|| {
            (
                a.description.compliance_severity.clone().unwrap_or_else(|| "UNSPECIFIED".into()),
                a.description.name.clone().unwrap_or_default(),
                a.description.document_version.clone().unwrap_or_default(),
                a.description.association_name.clone(),
            )
        });
        // The overview counts each node's latest status.
        let mut latest: BTreeMap<String, i32> = BTreeMap::new();
        for info in a.instance_status.values() {
            *latest.entry(info.status.clone().unwrap_or_default()).or_default() += 1;
        }
        let all_ok = a.instance_status.values().all(|i| i.status.as_deref() == Some("Success"));
        let overall = if all_ok { "Success" } else { "Failed" };
        a.description.overview = Some(overview(overall, overall, latest));
        a.description.last_execution_date = Some(at);
        if ok {
            a.description.last_successful_execution_date = Some(at);
        }
        drop(st);
        if let Some((severity, document, version, name)) = compliance {
            for (node, s, _) in &results {
                let entry = types::ComplianceItemEntry {
                    id: Some(id.to_string()),
                    title: name.clone().or_else(|| Some(document.clone())),
                    severity: severity.clone(),
                    status: if s == "Success" { "COMPLIANT" } else { "NON_COMPLIANT" }.into(),
                    details: Some(BTreeMap::from([
                        ("DocumentName".to_string(), document.clone()),
                        ("DocumentVersion".to_string(), version.clone()),
                    ])),
                };
                self.record_compliance(
                    account,
                    region,
                    "ManagedInstance",
                    node,
                    "Association",
                    types::ComplianceExecutionSummary {
                        execution_time: at,
                        execution_id: Some(execution_id.to_string()),
                        execution_type: Some("Command".into()),
                    },
                    vec![entry],
                    true,
                );
            }
        }
    }

    fn clock_offset_ms(&self) -> i64 {
        self.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Apply associations whose schedule came due by `now`, and apply
    /// associations to nodes that started matching their targets.
    pub(crate) fn run_associations(&self, now: DateTime<Utc>) {
        let mut due = Vec::new();
        {
            let mut st = self.lock();
            for (key, region) in st.regions.iter_mut() {
                let Some((account, region_name)) = key.split_once('/') else { continue };
                for (id, a) in region.associations.iter_mut() {
                    let Some(expr) = a.description.schedule_expression.clone().filter(|e| !e.is_empty()) else {
                        continue;
                    };
                    let Some(schedule) = Schedule::parse(&expr) else { continue };
                    let last = a.last_fired.unwrap_or(now);
                    let anchor = a.description.date.unwrap_or(last);
                    let offset = chrono::Duration::days(i64::from(a.description.schedule_offset.unwrap_or(0)));
                    let fired = schedule.fires_between(anchor, last - offset, now - offset, 1);
                    if !fired.is_empty() {
                        a.last_fired = Some(now);
                        due.push((account.to_string(), region_name.to_string(), id.clone(), None));
                    }
                }
            }
        }
        // Nodes that match an association's targets but it never ran on.
        let all: Vec<(String, String, String, types::AssociationDescription, Vec<String>)> = {
            let st = self.lock();
            st.regions
                .iter()
                .filter_map(|(k, r)| k.split_once('/').map(|(a, rg)| (a.to_string(), rg.to_string(), r)))
                .flat_map(|(a, rg, r)| {
                    r.associations
                        .iter()
                        .filter(|(_, x)| !x.executions.is_empty() || !x.description.apply_only_at_cron_interval)
                        .map(|(id, x)| {
                            (
                                a.clone(),
                                rg.clone(),
                                id.clone(),
                                x.description.clone(),
                                x.instance_status.keys().cloned().collect(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        for (account, region, id, d, known) in all {
            if d.apply_only_at_cron_interval {
                continue;
            }
            let fresh: Vec<String> =
                self.association_targets(&account, &region, &d).into_iter().filter(|n| !known.contains(n)).collect();
            if !fresh.is_empty() && !due.iter().any(|(_, _, x, _)| x == &id) {
                due.push((account, region, id, Some(fresh)));
            }
        }
        for (account, region, id, only) in due {
            self.apply_association(&account, &region, &id, now, only);
        }
    }

    pub(crate) fn association_tags_mut<'a>(
        r: &'a mut crate::state::Region,
        id: &str,
    ) -> Option<&'a mut BTreeMap<String, String>> {
        r.associations.get_mut(id).map(|a| &mut a.tags)
    }
}
