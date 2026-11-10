//! Managed node views (`ListNodes`, `ListNodesSummary`,
//! `DescribeInstanceProperties`), change calendars (`GetCalendarState`,
//! which also holds State Manager associations while a calendar is
//! closed), document reviews, hybrid node roles and resource data syncs,
//! which really write the account's inventory into an S3 bucket through a
//! [`DataSyncDestination`].

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::commands::{ManagedNode, AGENT_VERSION};
use crate::generated::{errors, types};
use crate::names::{now, page};
use crate::Ssm;

/// Where resource data syncs write: S3 buckets, as `ssm.amazonaws.com`.
pub trait DataSyncDestination: Send + Sync {
    /// Whether `ssm.amazonaws.com` may write into the bucket for `account`.
    fn check(&self, partition: &str, account: &str, bucket: &str, key: &str, source_arn: &str) -> Result<(), String>;

    /// Write one object.
    #[allow(clippy::too_many_arguments)]
    fn put(
        &self,
        partition: &str,
        account: &str,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        source_arn: &str,
        kms_key_arn: Option<&str>,
    ) -> Result<(), String>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncRecord {
    pub item: types::ResourceDataSyncItem,
    /// Whether the account's data changed since the last sync.
    pub dirty: bool,
}

/// Reviews of a document, by version.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReviewRecord {
    pub author: String,
    pub responses: Vec<types::DocumentReviewerResponseSource>,
}

fn node_view(n: &ManagedNode, account: &str, region: &str) -> types::Node {
    types::Node {
        capture_time: Some(n.last_ping),
        id: Some(n.instance_id.clone()),
        owner: Some(types::NodeOwnerInfo { account_id: Some(account.into()), ..Default::default() }),
        region: Some(region.into()),
        node_type: Some(types::NodeType::Instance(types::InstanceInfo {
            agent_type: Some("amazon-ssm-agent".into()),
            agent_version: Some(AGENT_VERSION.into()),
            computer_name: n.computer_name.clone(),
            instance_status: Some(if n.ping_status == "Online" { "Active" } else { "Stopped" }.into()),
            ip_address: n.ip_address.clone(),
            managed_status: Some("Managed".into()),
            name: n.tags.get("Name").cloned(),
            platform_type: Some(n.platform_type.clone()),
            platform_name: Some(n.platform_name.clone()),
            platform_version: Some(n.platform_version.clone()),
            resource_type: Some("EC2Instance".into()),
            ..Default::default()
        })),
    }
}

/// The value of a node attribute `ListNodes` filters and aggregates by.
fn node_attribute(n: &ManagedNode, key: &str) -> Option<String> {
    Some(match key {
        "AgentType" => "amazon-ssm-agent".into(),
        "AgentVersion" => AGENT_VERSION.into(),
        "ComputerName" => n.computer_name.clone()?,
        "InstanceId" => n.instance_id.clone(),
        "InstanceStatus" => if n.ping_status == "Online" { "Active" } else { "Stopped" }.into(),
        "IpAddress" => n.ip_address.clone()?,
        "ManagedStatus" => "Managed".into(),
        "PlatformName" => n.platform_name.clone(),
        "PlatformType" => n.platform_type.clone(),
        "PlatformVersion" => n.platform_version.clone(),
        "ResourceType" => "EC2Instance".into(),
        k => n.tags.get(k.strip_prefix("tag:")?).cloned()?,
    })
}

fn node_filter(n: &ManagedNode, f: &types::NodeFilter) -> bool {
    let v = node_attribute(n, &f.key);
    match f.r#type.as_deref().unwrap_or("Equal") {
        "NotEqual" => v.is_none_or(|v| !f.values.contains(&v)),
        "BeginWith" => v.is_some_and(|v| f.values.iter().any(|p| v.starts_with(p.as_str()))),
        _ => v.is_some_and(|v| f.values.contains(&v)),
    }
}

/// When an iCalendar date-time happens (`20250101T090000Z`,
/// `20250101T090000` with a `TZID`, or a `VALUE=DATE` day).
fn ics_time(params: &str, value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if let Some(v) = value.strip_suffix('Z') {
        return NaiveDateTime::parse_from_str(v, "%Y%m%dT%H%M%S").ok().map(|t| Utc.from_utc_datetime(&t));
    }
    let tz: chrono_tz::Tz =
        params.split(';').find_map(|p| p.strip_prefix("TZID=")).and_then(|t| t.parse().ok()).unwrap_or(chrono_tz::UTC);
    let naive = NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S")
        .ok()
        .or_else(|| NaiveDate::parse_from_str(value, "%Y%m%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)))?;
    tz.from_local_datetime(&naive).earliest().map(|t| t.with_timezone(&Utc))
}

/// A calendar event's start and end.
type Event = (DateTime<Utc>, DateTime<Utc>);
/// A node's association status, last execution and last success.
type NodeAssociations = (String, Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// A change calendar: whether it is open by default, and its events.
pub(crate) fn parse_calendar(content: &str) -> (bool, Vec<Event>) {
    let mut default_open = true;
    let mut events = Vec::new();
    let (mut start, mut end) = (None, None);
    // Unfold continuation lines.
    let unfolded = content.replace("\r\n ", "").replace("\n ", "");
    for line in unfolded.lines() {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else { continue };
        let (key, params) = name.split_once(';').unwrap_or((name, ""));
        match key {
            "X-CALENDAR-TYPE" => default_open = value.trim() != "DEFAULT_CLOSED",
            "BEGIN" if value == "VEVENT" => (start, end) = (None, None),
            "DTSTART" => start = ics_time(params, value),
            "DTEND" => end = ics_time(params, value),
            "END" if value == "VEVENT" => {
                if let (Some(s), Some(e)) = (start, end) {
                    events.push((s, e));
                }
            }
            _ => {}
        }
    }
    (default_open, events)
}

/// A calendar's state at `at` (`OPEN` or `CLOSED`) and its next change.
pub(crate) fn calendar_state(content: &str, at: DateTime<Utc>) -> (bool, Option<DateTime<Utc>>) {
    let (default_open, events) = parse_calendar(content);
    let in_event = events.iter().any(|(s, e)| *s <= at && at < *e);
    let open = default_open != in_event;
    let next = events.iter().flat_map(|(s, e)| [*s, *e]).filter(|t| *t > at).min();
    (open, next)
}

impl Ssm {
    /// Where resource data syncs write.
    pub fn set_data_sync_destination(&self, destination: Arc<dyn DataSyncDestination>) {
        *self.data_sync.write().expect("SSM data sync lock poisoned") = Some(destination);
    }

    pub(crate) fn list_nodes(
        &self,
        ctx: &RequestContext,
        input: types::ListNodesRequest,
    ) -> Result<types::ListNodesResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:ListNodes", &list_arn, ConditionContext::new())?;
        self.check_sync_name(ctx, input.sync_name.as_deref())?;
        let filters = input.filters.unwrap_or_default();
        let all: Vec<types::Node> = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .iter()
            .filter(|n| filters.iter().all(|f| node_filter(n, f)))
            .map(|n| node_view(n, &ctx.caller.account_id, &ctx.region))
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::ListNodesResult { nodes: Some(items), next_token: next })
    }

    pub(crate) fn list_nodes_summary(
        &self,
        ctx: &RequestContext,
        input: types::ListNodesSummaryRequest,
    ) -> Result<types::ListNodesSummaryResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:ListNodesSummary", &list_arn, ConditionContext::new())?;
        self.check_sync_name(ctx, input.sync_name.as_deref())?;
        let filters = input.filters.unwrap_or_default();
        let nodes: Vec<ManagedNode> = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .into_iter()
            .filter(|n| filters.iter().all(|f| node_filter(n, f)))
            .collect();
        let Some(agg) = input.aggregators.first() else {
            return Err(errors::validation("At least one aggregator is required."));
        };
        if agg.aggregator_type != "Count" {
            return Err(errors::validation(format!("Invalid AggregatorType: {}", agg.aggregator_type)));
        }
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for n in &nodes {
            let v = node_attribute(n, &agg.attribute_name).unwrap_or_default();
            *counts.entry(v).or_default() += 1;
        }
        let all: Vec<BTreeMap<String, String>> = counts
            .into_iter()
            .map(|(v, c)| BTreeMap::from([(agg.attribute_name.clone(), v), ("Count".to_string(), c.to_string())]))
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::ListNodesSummaryResult { summary: Some(items), next_token: next })
    }

    fn check_sync_name(&self, ctx: &RequestContext, name: Option<&str>) -> Result<(), ServiceError> {
        let Some(name) = name else { return Ok(()) };
        let st = self.lock();
        if st.region_ref(&ctx.caller.account_id, &ctx.region).is_some_and(|r| r.data_syncs.contains_key(name)) {
            Ok(())
        } else {
            Err(errors::resource_data_sync_not_found(format!("Resource data sync {name} not found.")))
        }
    }

    pub(crate) fn describe_instance_properties(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstancePropertiesRequest,
    ) -> Result<types::DescribeInstancePropertiesResult, ServiceError> {
        let list_arn = format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize("ssm:DescribeInstanceProperties", &list_arn, ConditionContext::new())?;
        let mut filters: Vec<(String, Vec<String>, String)> = Vec::new();
        for f in input.instance_property_filter_list.unwrap_or_default() {
            filters.push((f.key, f.value_set, "Equal".into()));
        }
        for f in input.filters_with_operator.unwrap_or_default() {
            filters.push((f.key, f.values, f.operator.unwrap_or_else(|| "Equal".into())));
        }
        let statuses: BTreeMap<String, NodeAssociations> = {
            let st = self.lock();
            let mut out = BTreeMap::new();
            if let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
                for a in r.associations.values() {
                    for (node, info) in &a.instance_status {
                        let e = out.entry(node.clone()).or_insert((String::from("Success"), None, None));
                        if info.status.as_deref() != Some("Success") {
                            e.0 = info.status.clone().unwrap_or_default();
                        }
                        e.1 = e.1.max(info.execution_date);
                        if info.status.as_deref() == Some("Success") {
                            e.2 = e.2.max(info.execution_date);
                        }
                    }
                }
            }
            out
        };
        let all: Vec<types::InstanceProperty> = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .into_iter()
            .filter(|n| {
                filters.iter().all(|(k, values, op)| {
                    let v = match k.as_str() {
                        "InstanceIds" | "InstanceId" => Some(n.instance_id.clone()),
                        "PingStatus" => Some(n.ping_status.clone()),
                        "PlatformTypes" | "PlatformType" => Some(n.platform_type.clone()),
                        "IamRole" => Some(n.iam_role.clone()),
                        "ResourceType" => Some("EC2Instance".into()),
                        "AgentVersion" => Some(AGENT_VERSION.into()),
                        "AssociationStatus" => statuses.get(&n.instance_id).map(|s| s.0.clone()),
                        k => k.strip_prefix("tag:").and_then(|t| n.tags.get(t).cloned()),
                    };
                    match op.as_str() {
                        "NotEqual" => v.is_none_or(|v| !values.contains(&v)),
                        "BeginWith" => v.is_some_and(|v| values.iter().any(|p| v.starts_with(p.as_str()))),
                        "LessThan" => v.is_some_and(|v| values.iter().any(|x| v.as_str() < x.as_str())),
                        "GreaterThan" => v.is_some_and(|v| values.iter().any(|x| v.as_str() > x.as_str())),
                        _ => v.is_some_and(|v| values.contains(&v)),
                    }
                })
            })
            .map(|n| {
                let status = statuses.get(&n.instance_id);
                types::InstanceProperty {
                    name: n.tags.get("Name").cloned(),
                    instance_id: Some(n.instance_id.clone()),
                    instance_role: Some(n.iam_role.clone()),
                    instance_state: Some(if n.ping_status == "Online" { "running" } else { "stopped" }.into()),
                    ip_address: n.ip_address.clone(),
                    launch_time: Some(n.registration_date),
                    ping_status: Some(n.ping_status.clone()),
                    last_ping_date_time: Some(n.last_ping),
                    agent_version: Some(AGENT_VERSION.into()),
                    platform_type: Some(n.platform_type.clone()),
                    platform_name: Some(n.platform_name.clone()),
                    platform_version: Some(n.platform_version.clone()),
                    iam_role: Some(n.iam_role.clone()),
                    registration_date: Some(n.registration_date),
                    resource_type: Some("EC2Instance".into()),
                    computer_name: n.computer_name.clone(),
                    association_status: status.map(|s| s.0.clone()),
                    last_association_execution_date: status.and_then(|s| s.1),
                    last_successful_association_execution_date: status.and_then(|s| s.2),
                    source_id: Some(n.instance_id.clone()),
                    source_type: Some("AWS::EC2::Instance".into()),
                    ..Default::default()
                }
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(5, 1000) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeInstancePropertiesResult { instance_properties: Some(items), next_token: next })
    }

    /// The content of a change calendar the caller can read.
    fn calendar_content(&self, account: &str, region: &str, name: &str) -> Result<String, ServiceError> {
        let name = name.rsplit('/').next().unwrap_or(name);
        let found = self.find_document_in(account, region, name).ok_or_else(|| {
            errors::invalid_document_type(format!("Calendar {name} does not exist or is not a change calendar."))
        })?;
        if found.doc.document_type != "ChangeCalendar" {
            return Err(errors::unsupported_calendar(format!("{name} is not a change calendar.")));
        }
        Ok(found.doc.default().content.clone())
    }

    /// Whether every one of `calendars` is open at `at`.
    pub(crate) fn calendars_open(&self, account: &str, region: &str, calendars: &[String], at: DateTime<Utc>) -> bool {
        calendars.iter().all(|c| match self.calendar_content(account, region, c) {
            Ok(content) => calendar_state(&content, at).0,
            Err(_) => true,
        })
    }

    pub(crate) fn get_calendar_state(
        &self,
        ctx: &RequestContext,
        input: types::GetCalendarStateRequest,
    ) -> Result<types::GetCalendarStateResponse, ServiceError> {
        let at = match input.at_time.as_deref() {
            Some(t) => DateTime::parse_from_rfc3339(t)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| errors::invalid_document_content(format!("Invalid AtTime: {t}")))?,
            None => now(ctx),
        };
        let mut open = true;
        let mut next: Option<DateTime<Utc>> = None;
        for name in &input.calendar_names {
            let arn = if name.starts_with("arn:") {
                name.clone()
            } else {
                crate::documents::arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, name)
            };
            ctx.authorize("ssm:GetCalendarState", &arn, ConditionContext::new())?;
            let content = self.calendar_content(&ctx.caller.account_id, &ctx.region, name)?;
            let (o, n) = calendar_state(&content, at);
            open &= o;
            next = match (next, n) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        let fmt = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        Ok(types::GetCalendarStateResponse {
            state: Some(if open { "OPEN" } else { "CLOSED" }.into()),
            at_time: Some(fmt(at)),
            next_transition_time: next.map(fmt),
        })
    }

    pub(crate) fn update_document_metadata(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDocumentMetadataRequest,
    ) -> Result<types::UpdateDocumentMetadataResponse, ServiceError> {
        let arn = crate::documents::arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.name);
        ctx.authorize("ssm:UpdateDocumentMetadata", &arn, ConditionContext::new())?;
        let found = self
            .find_document(ctx, &input.name)
            .filter(|f| f.owner_account == ctx.caller.account_id)
            .ok_or_else(|| errors::invalid_document("The specified document does not exist."))?;
        let version = crate::documents::pick_version(&found.doc, input.document_version.as_deref(), None)?.version;
        let status = match input.document_reviews.action.as_str() {
            "SendForReview" => "PENDING",
            "UpdateReview" => "PENDING",
            "Approve" => "APPROVED",
            "Reject" => "REJECTED",
            a => return Err(errors::validation(format!("Invalid DocumentReviewAction: {a}"))),
        };
        let t = now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let rec = r
            .document_reviews
            .entry(format!("{}#{version}", input.name))
            .or_insert_with(|| ReviewRecord { author: ctx.caller.arn.clone(), responses: Vec::new() });
        rec.responses.push(types::DocumentReviewerResponseSource {
            create_time: Some(t),
            updated_time: Some(t),
            review_status: Some(status.into()),
            comment: input.document_reviews.comment,
            reviewer: Some(ctx.caller.arn.clone()),
        });
        Ok(types::UpdateDocumentMetadataResponse {})
    }

    pub(crate) fn list_document_metadata_history(
        &self,
        ctx: &RequestContext,
        input: types::ListDocumentMetadataHistoryRequest,
    ) -> Result<types::ListDocumentMetadataHistoryResponse, ServiceError> {
        let arn = crate::documents::arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.name);
        ctx.authorize("ssm:ListDocumentMetadataHistory", &arn, ConditionContext::new())?;
        if input.metadata != "DocumentReviews" {
            return Err(errors::validation(format!("Invalid DocumentMetadataEnum: {}", input.metadata)));
        }
        let found = self
            .find_document(ctx, &input.name)
            .ok_or_else(|| errors::invalid_document("The specified document does not exist."))?;
        let version = crate::documents::pick_version(&found.doc, input.document_version.as_deref(), None)?.version;
        let rec = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .and_then(|r| r.document_reviews.get(&format!("{}#{version}", input.name)).cloned())
                .unwrap_or_default()
        };
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let mut responses = rec.responses;
        responses.reverse();
        let (items, next) = page(responses, input.next_token.as_deref(), limit)?;
        Ok(types::ListDocumentMetadataHistoryResponse {
            name: Some(input.name),
            document_version: Some(version.to_string()),
            author: (!rec.author.is_empty()).then_some(rec.author),
            metadata: Some(types::DocumentMetadataResponseInfo { reviewer_response: Some(items) }),
            next_token: next,
        })
    }

    pub(crate) fn update_managed_instance_role(
        &self,
        ctx: &RequestContext,
        input: types::UpdateManagedInstanceRoleRequest,
    ) -> Result<types::UpdateManagedInstanceRoleResult, ServiceError> {
        let target = format!(
            "arn:{}:ssm:{}:{}:managed-instance/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.instance_id
        );
        ctx.authorize("ssm:UpdateManagedInstanceRole", &target, ConditionContext::new())?;
        ctx.authorize("iam:PassRole", &input.iam_role, ConditionContext::new())?;
        // Only hybrid nodes (mi-...) have a role SSM manages; EC2 instances
        // take theirs from the instance profile.
        Err(errors::invalid_instance_id(""))
    }

    // ---- Resource data sync ----

    fn sync_arn(ctx: &RequestContext, name: &str) -> String {
        format!("arn:{}:ssm:{}:{}:resource-data-sync/{name}", ctx.partition, ctx.region, ctx.caller.account_id)
    }

    fn destination(&self) -> Option<Arc<dyn DataSyncDestination>> {
        self.data_sync.read().expect("SSM data sync lock poisoned").clone()
    }

    pub(crate) fn create_resource_data_sync(
        &self,
        ctx: &RequestContext,
        input: types::CreateResourceDataSyncRequest,
    ) -> Result<types::CreateResourceDataSyncResult, ServiceError> {
        let arn = Self::sync_arn(ctx, &input.sync_name);
        ctx.authorize("ssm:CreateResourceDataSync", &arn, ConditionContext::new())?;
        let sync_type = input.sync_type.clone().unwrap_or_else(|| "SyncToDestination".into());
        match sync_type.as_str() {
            "SyncToDestination" => {
                let Some(dest) = &input.s3_destination else {
                    return Err(errors::resource_data_sync_invalid_configuration(
                        "S3Destination is required for SyncToDestination.",
                    ));
                };
                if dest.sync_format != "JsonSerDe" {
                    return Err(errors::resource_data_sync_invalid_configuration("SyncFormat must be JsonSerDe."));
                }
                if let Some(d) = self.destination() {
                    let key = format!("{}/", dest.prefix.clone().unwrap_or_default());
                    d.check(&ctx.partition, &ctx.caller.account_id, &dest.bucket_name, &key, &arn).map_err(|e| {
                        errors::resource_data_sync_invalid_configuration(format!(
                            "SSM can't write to bucket {}: {e}",
                            dest.bucket_name
                        ))
                    })?;
                }
            }
            "SyncFromSource" => {
                if input.sync_source.is_none() {
                    return Err(errors::resource_data_sync_invalid_configuration(
                        "SyncSource is required for SyncFromSource.",
                    ));
                }
            }
            t => return Err(errors::resource_data_sync_invalid_configuration(format!("Invalid SyncType: {t}"))),
        }
        let t = now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if r.data_syncs.contains_key(&input.sync_name) {
            return Err(errors::resource_data_sync_already_exists(input.sync_name.clone()));
        }
        if r.data_syncs.len() >= 5 {
            return Err(errors::resource_data_sync_count_exceeded(
                "You have exceeded the allowed maximum sync configurations.",
            ));
        }
        r.data_syncs.insert(
            input.sync_name.clone(),
            SyncRecord {
                item: types::ResourceDataSyncItem {
                    sync_name: Some(input.sync_name.clone()),
                    sync_type: Some(sync_type),
                    sync_source: input.sync_source.map(|s| types::ResourceDataSyncSourceWithState {
                        source_type: Some(s.source_type),
                        aws_organizations_source: s.aws_organizations_source,
                        source_regions: Some(s.source_regions),
                        include_future_regions: s.include_future_regions,
                        state: Some("Active".into()),
                        enable_all_ops_data_sources: s.enable_all_ops_data_sources,
                    }),
                    s3_destination: input.s3_destination,
                    last_sync_time: None,
                    last_successful_sync_time: None,
                    sync_last_modified_time: Some(t),
                    last_status: Some("InProgress".into()),
                    sync_created_time: Some(t),
                    last_sync_status_message: None,
                },
                dirty: true,
            },
        );
        drop(st);
        self.run_data_syncs(t);
        Ok(types::CreateResourceDataSyncResult {})
    }

    pub(crate) fn delete_resource_data_sync(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourceDataSyncRequest,
    ) -> Result<types::DeleteResourceDataSyncResult, ServiceError> {
        ctx.authorize("ssm:DeleteResourceDataSync", &Self::sync_arn(ctx, &input.sync_name), ConditionContext::new())?;
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        match r.data_syncs.get(&input.sync_name) {
            Some(s) if input.sync_type.as_ref().is_none_or(|t| s.item.sync_type.as_ref() == Some(t)) => {
                r.data_syncs.remove(&input.sync_name);
                Ok(types::DeleteResourceDataSyncResult {})
            }
            _ => {
                Err(errors::resource_data_sync_not_found(format!("Resource data sync {} not found.", input.sync_name)))
            }
        }
    }

    pub(crate) fn list_resource_data_sync(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceDataSyncRequest,
    ) -> Result<types::ListResourceDataSyncResult, ServiceError> {
        ctx.authorize("ssm:ListResourceDataSync", &Self::sync_arn(ctx, "*"), ConditionContext::new())?;
        let st = self.lock();
        let wanted = input.sync_type.clone().unwrap_or_else(|| "SyncToDestination".into());
        let all: Vec<types::ResourceDataSyncItem> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.data_syncs
                    .values()
                    .filter(|s| s.item.sync_type.as_deref() == Some(&wanted))
                    .map(|s| s.item.clone())
                    .collect()
            })
            .unwrap_or_default();
        drop(st);
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(all, input.next_token.as_deref(), limit)?;
        Ok(types::ListResourceDataSyncResult { resource_data_sync_items: Some(items), next_token: next })
    }

    pub(crate) fn update_resource_data_sync(
        &self,
        ctx: &RequestContext,
        input: types::UpdateResourceDataSyncRequest,
    ) -> Result<types::UpdateResourceDataSyncResult, ServiceError> {
        ctx.authorize("ssm:UpdateResourceDataSync", &Self::sync_arn(ctx, &input.sync_name), ConditionContext::new())?;
        let t = now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let s = r.data_syncs.get_mut(&input.sync_name).ok_or_else(|| {
            errors::resource_data_sync_not_found(format!("Resource data sync {} not found.", input.sync_name))
        })?;
        if s.item.sync_type.as_deref() != Some(&input.sync_type) || input.sync_type != "SyncFromSource" {
            return Err(errors::resource_data_sync_conflict("Only SyncFromSource resource data syncs can be updated."));
        }
        s.item.sync_source = Some(types::ResourceDataSyncSourceWithState {
            source_type: Some(input.sync_source.source_type),
            aws_organizations_source: input.sync_source.aws_organizations_source,
            source_regions: Some(input.sync_source.source_regions),
            include_future_regions: input.sync_source.include_future_regions,
            state: Some("Active".into()),
            enable_all_ops_data_sources: input.sync_source.enable_all_ops_data_sources,
        });
        s.item.sync_last_modified_time = Some(t);
        Ok(types::UpdateResourceDataSyncResult {})
    }

    /// Mark the account's resource data syncs as having new data.
    pub(crate) fn data_changed(&self, account: &str, region: &str) {
        let mut st = self.lock();
        for s in st.region(account, region).data_syncs.values_mut() {
            s.dirty = true;
        }
    }

    /// Write the inventory and compliance of accounts whose data changed
    /// into their sync buckets.
    pub(crate) fn run_data_syncs(&self, at: DateTime<Utc>) {
        let Some(dest) = self.destination() else { return };
        let partition = self.template().map(|t| t.partition).unwrap_or_else(|| "aws".into());
        let jobs: Vec<(String, String, String, types::ResourceDataSyncS3Destination)> = {
            let mut st = self.lock();
            let mut out = Vec::new();
            for (key, r) in st.regions.iter_mut() {
                let Some((account, region)) = key.split_once('/') else { continue };
                for (name, s) in r.data_syncs.iter_mut().filter(|(_, s)| s.dirty) {
                    s.dirty = false;
                    if let Some(d) = &s.item.s3_destination {
                        out.push((account.to_string(), region.to_string(), name.clone(), d.clone()));
                    }
                }
            }
            out
        };
        for (account, region, name, d) in jobs {
            let source_arn = format!("arn:{partition}:ssm:{region}:{account}:resource-data-sync/{name}");
            let inventory = self.inventory_of_all(&account, &region, at);
            let mut result: Result<(), String> = Ok(());
            for (type_name, by_node) in inventory {
                for (node, (item, content)) in by_node {
                    let lines: Vec<String> = content
                        .into_iter()
                        .map(|c| {
                            let mut m = serde_json::Map::new();
                            for (k, v) in c {
                                let mut chars = k.chars();
                                let key = match chars.next() {
                                    Some(f) => f.to_lowercase().collect::<String>() + chars.as_str(),
                                    None => k,
                                };
                                m.insert(key, serde_json::Value::String(v));
                            }
                            m.insert("resourceId".into(), node.clone().into());
                            m.insert("captureTime".into(), item.0.clone().into());
                            m.insert("schemaVersion".into(), item.1.clone().into());
                            serde_json::Value::Object(m).to_string()
                        })
                        .collect();
                    let prefix =
                        d.prefix.clone().filter(|p| !p.is_empty()).map(|p| format!("{p}/")).unwrap_or_default();
                    let key = format!(
                        "{prefix}{type_name}/accountid={account}/region={region}/resourcetype=ManagedInstanceInventory/{node}.json"
                    );
                    if let Err(e) = dest.put(
                        &partition,
                        &account,
                        &d.bucket_name,
                        &key,
                        lines.join("\n").into_bytes(),
                        &source_arn,
                        d.awskms_key_arn.as_deref(),
                    ) {
                        result = Err(e);
                    }
                }
            }
            let mut st = self.lock();
            if let Some(s) = st.region(&account, &region).data_syncs.get_mut(&name) {
                s.item.last_sync_time = Some(at);
                match result {
                    Ok(()) => {
                        s.item.last_status = Some("Successful".into());
                        s.item.last_successful_sync_time = Some(at);
                        s.item.last_sync_status_message = None;
                    }
                    Err(e) => {
                        s.item.last_status = Some("Failed".into());
                        s.item.last_sync_status_message = Some(e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::calendar_state;
    use chrono::{TimeZone, Utc};

    const CALENDAR: &str = "BEGIN:VCALENDAR\r\nX-CALENDAR-TYPE:DEFAULT_OPEN\r\nBEGIN:VEVENT\r\nDTSTART:20261224T000000Z\r\nDTEND:20261227T000000Z\r\nSUMMARY:Holidays\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn events_close_default_open_calendars() {
        let before = Utc.with_ymd_and_hms(2026, 12, 20, 0, 0, 0).unwrap();
        let during = Utc.with_ymd_and_hms(2026, 12, 25, 0, 0, 0).unwrap();
        assert_eq!(
            calendar_state(CALENDAR, before),
            (true, Some(Utc.with_ymd_and_hms(2026, 12, 24, 0, 0, 0).unwrap()))
        );
        assert_eq!(
            calendar_state(CALENDAR, during),
            (false, Some(Utc.with_ymd_and_hms(2026, 12, 27, 0, 0, 0).unwrap()))
        );
        let closed = CALENDAR.replace("DEFAULT_OPEN", "DEFAULT_CLOSED");
        assert!(calendar_state(&closed, during).0);
    }
}
