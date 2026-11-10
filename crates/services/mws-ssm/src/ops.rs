//! OpsCenter (OpsItems, their related resources and events), Explorer's
//! `GetOpsSummary` and Application Manager's OpsMetadata. Change Manager
//! change requests are OpsItems of type `/aws/changerequest` whose status
//! follows their execution, and EventBridge rules can create OpsItems from
//! events ([`Ssm::create_ops_item_from_event`]).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, ErrorValue, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::engine::Run;
use crate::generated::{errors, types};
use crate::names::{now, page, request_tag_conditions, resource_tag_conditions};
use crate::Ssm;

const MAX_METADATA_KEYS: usize = 5;
const MAX_OPS_METADATA: usize = 200;
const CATEGORIES: &[&str] = &["Availability", "Cost", "Performance", "Recovery", "Security"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsItemRecord {
    pub item: types::OpsItem,
    pub tags: BTreeMap<String, String>,
    pub related: Vec<types::OpsItemRelatedItemSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsMetadataRecord {
    pub metadata: types::OpsMetadata,
    pub values: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsState {
    pub items: BTreeMap<String, OpsItemRecord>,
    /// Newest last.
    pub events: Vec<types::OpsItemEventSummary>,
    /// By resource id.
    pub metadata: BTreeMap<String, OpsMetadataRecord>,
}

/// One OpsData entity: its id and attributes.
type Row = (String, BTreeMap<String, String>);

fn ops_item_arn(partition: &str, region: &str, account: &str, id: &str) -> String {
    format!("arn:{partition}:ssm:{region}:{account}:opsitem/{id}")
}

fn metadata_arn(ctx: &RequestContext, resource_id: &str) -> String {
    format!(
        "arn:{}:ssm:{}:{}:opsmetadata/{}",
        ctx.partition,
        ctx.region,
        ctx.caller.account_id,
        resource_id.trim_start_matches('/')
    )
}

fn not_found(id: &str) -> ServiceError {
    errors::ops_item_not_found(format!("OpsItemId {id} not found."))
}

fn new_id() -> String {
    let hex: String = uuid::Uuid::new_v4().simple().to_string();
    format!("oi-{}", &hex[..12])
}

fn invalid(names: &[&str], message: impl Into<String>) -> ServiceError {
    errors::ops_item_invalid_parameter_with_parameter_names(message, names.iter().map(|s| s.to_string()).collect())
}

fn check_operational_data(data: &BTreeMap<String, types::OpsItemDataValue>) -> Result<(), ServiceError> {
    const RESERVED: &[&str] = &["/aws/dedup", "/aws/resources", "/aws/automations", "/aws/changerequest"];
    let mut size = 0;
    for (k, v) in data {
        let lower = k.to_ascii_lowercase();
        let reserved =
            ["amazon", "aws", "amzn", "ssm", "/amazon", "/aws", "/amzn", "/ssm"].iter().any(|p| lower.starts_with(p));
        if reserved && !RESERVED.contains(&k.as_str()) {
            return Err(invalid(
                &["OperationalData"],
                format!("Operational data keys can't begin with amazon, aws, amzn, ssm, /amazon, /aws, /amzn or /ssm ({k})."),
            ));
        }
        if let Some(t) = &v.r#type {
            if t != "SearchableString" && t != "String" {
                return Err(invalid(&["OperationalData"], format!("Operational data type {t} isn't valid.")));
            }
        }
        size += k.len() + v.value.as_deref().map_or(0, str::len);
    }
    if size > 20_000 {
        return Err(invalid(&["OperationalData"], "Operational data can't be larger than 20 KB."));
    }
    Ok(())
}

fn dedup_string(data: &BTreeMap<String, types::OpsItemDataValue>) -> Option<String> {
    let v = data.get("/aws/dedup")?.value.as_deref()?;
    serde_json::from_str::<Value>(v).ok()?.get("dedupString")?.as_str().map(str::to_string)
}

fn summary(i: &types::OpsItem) -> types::OpsItemSummary {
    types::OpsItemSummary {
        created_by: i.created_by.clone(),
        created_time: i.created_time,
        last_modified_by: i.last_modified_by.clone(),
        last_modified_time: i.last_modified_time,
        priority: i.priority,
        source: i.source.clone(),
        status: i.status.clone(),
        ops_item_id: i.ops_item_id.clone(),
        title: i.title.clone(),
        operational_data: i.operational_data.clone(),
        category: i.category.clone(),
        severity: i.severity.clone(),
        ops_item_type: i.ops_item_type.clone(),
        actual_start_time: i.actual_start_time,
        actual_end_time: i.actual_end_time,
        planned_start_time: i.planned_start_time,
        planned_end_time: i.planned_end_time,
    }
}

/// An OpsItem attribute as a string, for filters and summaries.
fn attribute(i: &types::OpsItem, key: &str) -> Option<String> {
    let t = |d: Option<DateTime<Utc>>| d.map(|d| d.to_rfc3339());
    match key {
        "Status" => i.status.clone(),
        "CreatedBy" => i.created_by.clone(),
        "Source" => i.source.clone(),
        "Priority" => i.priority.map(|p| p.to_string()),
        "Title" => i.title.clone(),
        "OpsItemId" => i.ops_item_id.clone(),
        "CreatedTime" => t(i.created_time),
        "LastModifiedTime" => t(i.last_modified_time),
        "ActualStartTime" => t(i.actual_start_time),
        "ActualEndTime" => t(i.actual_end_time),
        "PlannedStartTime" => t(i.planned_start_time),
        "PlannedEndTime" => t(i.planned_end_time),
        "Category" => i.category.clone(),
        "Severity" => i.severity.clone(),
        "OpsItemType" => i.ops_item_type.clone(),
        _ => None,
    }
}

fn filter_matches(i: &types::OpsItem, f: &types::OpsItemFilter) -> bool {
    let op = f.operator.as_str();
    let data = i.operational_data.clone().unwrap_or_default();
    let cmp = |have: &str, want: &str| -> bool {
        match op {
            "Contains" => have.contains(want),
            "GreaterThan" => compare(have, want) == std::cmp::Ordering::Greater,
            "LessThan" => compare(have, want) == std::cmp::Ordering::Less,
            _ => have == want,
        }
    };
    match f.key.as_str() {
        "OperationalData" => f.values.iter().any(|v| {
            serde_json::from_str::<Value>(v).ok().is_some_and(|kv| {
                let key = kv.get("key").and_then(Value::as_str).unwrap_or_default();
                let value = kv.get("value").and_then(Value::as_str).unwrap_or_default();
                data.get(key).and_then(|d| d.value.as_deref()).is_some_and(|have| cmp(have, value))
            })
        }),
        "OperationalDataKey" => f.values.iter().any(|v| data.keys().any(|k| cmp(k, v))),
        "OperationalDataValue" => {
            f.values.iter().any(|v| data.values().any(|d| d.value.as_deref().is_some_and(|have| cmp(have, v))))
        }
        "ResourceId" => f.values.iter().any(|v| {
            data.get("/aws/resources").and_then(|d| d.value.as_deref()).is_some_and(|r| r.contains(v.as_str()))
        }),
        "AutomationId" => f.values.iter().any(|v| {
            data.get("/aws/automations").and_then(|d| d.value.as_deref()).is_some_and(|r| r.contains(v.as_str()))
        }),
        "ChangeRequestByTemplate" => f.values.iter().any(|v| {
            data.get("/aws/changerequest").and_then(|d| d.value.as_deref()).is_some_and(|r| r.contains(v.as_str()))
        }),
        "ChangeRequestByRequesterArn" => f.values.iter().any(|v| i.created_by.as_deref().is_some_and(|c| cmp(c, v))),
        "AccountId" => true,
        key => {
            let Some(have) = attribute(i, key) else { return false };
            f.values.iter().any(|v| cmp(&have, v))
        }
    }
}

fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    match (a.parse::<f64>(), b.parse::<f64>()) {
        (Ok(x), Ok(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        _ => {
            let parse = |s: &str| DateTime::parse_from_rfc3339(s).ok();
            match (parse(a), parse(b)) {
                (Some(x), Some(y)) => x.cmp(&y),
                _ => a.cmp(b),
            }
        }
    }
}

impl Ssm {
    fn authorize_ops_item(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        extra: ConditionContext,
    ) -> Result<OpsItemRecord, ServiceError> {
        let rec =
            self.lock().region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.ops.items.get(id)).cloned();
        let mut cond = extra;
        if let Some(r) = &rec {
            cond.extend(resource_tag_conditions(&r.tags));
        }
        ctx.authorize(
            &format!("ssm:{action}"),
            &ops_item_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, id),
            cond,
        )?;
        rec.ok_or_else(|| not_found(id))
    }

    /// Create an OpsItem in `account` and `region` (already authorized).
    fn insert_ops_item(
        &self,
        partition: &str,
        account: &str,
        region: &str,
        mut item: types::OpsItem,
        tags: BTreeMap<String, String>,
    ) -> Result<(String, String), ServiceError> {
        let data = item.operational_data.clone().unwrap_or_default();
        let mut st = self.lock();
        let r = st.region(account, region);
        if let Some(dedup) = dedup_string(&data) {
            if let Some(existing) = r.ops.items.values().find(|x| {
                matches!(x.item.status.as_deref(), Some("Open" | "InProgress"))
                    && x.item.operational_data.as_ref().and_then(dedup_string).as_deref() == Some(dedup.as_str())
            }) {
                let id = existing.item.ops_item_id.clone().unwrap_or_default();
                return Err(errors::ops_item_already_exists(format!("The OpsItem already exists: {id}"))
                    .with_field("OpsItemId", ErrorValue::String(id)));
            }
        }
        let id = new_id();
        let arn = ops_item_arn(partition, region, account, &id);
        item.ops_item_id = Some(id.clone());
        item.ops_item_arn = Some(arn.clone());
        item.version = Some(uuid::Uuid::new_v4().to_string());
        r.ops.items.insert(id.clone(), OpsItemRecord { item, tags, related: Vec::new() });
        Ok((id, arn))
    }

    pub(crate) fn create_ops_item(
        &self,
        ctx: &RequestContext,
        input: types::CreateOpsItemRequest,
    ) -> Result<types::CreateOpsItemResponse, ServiceError> {
        let tags: BTreeMap<String, String> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        let cond = request_tag_conditions(tags.iter());
        ctx.authorize(
            "ssm:CreateOpsItem",
            &format!("arn:{}:ssm:{}:{}:opsitem/*", ctx.partition, ctx.region, ctx.caller.account_id),
            cond,
        )?;
        if let Some(a) = input.account_id.as_ref().filter(|a| **a != ctx.caller.account_id) {
            return Err(errors::ops_item_access_denied(format!(
                "You don't have permission to create OpsItems in account {a}."
            )));
        }
        let source = input.source.to_ascii_lowercase();
        if ["aws", "amazon", "amzn"].iter().any(|p| source.contains(p)) {
            return Err(invalid(&["Source"], "The source can't contain aws, amazon or amzn."));
        }
        if let Some(c) = &input.category {
            if !CATEGORIES.contains(&c.as_str()) {
                return Err(invalid(&["Category"], format!("Category {c} isn't valid.")));
            }
        }
        if let Some(s) = &input.severity {
            if !["1", "2", "3", "4"].contains(&s.as_str()) {
                return Err(invalid(&["Severity"], format!("Severity {s} isn't valid.")));
            }
        }
        let data = input.operational_data.clone().unwrap_or_default();
        check_operational_data(&data)?;
        let kind = input.ops_item_type.clone().unwrap_or_else(|| "/aws/issues".into());
        let at = now(ctx);
        let item = types::OpsItem {
            created_by: Some(ctx.caller.arn.clone()),
            ops_item_type: Some(kind),
            created_time: Some(at),
            description: Some(input.description),
            last_modified_by: Some(ctx.caller.arn.clone()),
            last_modified_time: Some(at),
            notifications: input.notifications,
            priority: input.priority,
            related_ops_items: input.related_ops_items,
            status: Some("Open".into()),
            title: Some(input.title),
            source: Some(input.source),
            operational_data: (!data.is_empty()).then_some(data),
            category: input.category,
            severity: input.severity,
            actual_start_time: input.actual_start_time,
            actual_end_time: input.actual_end_time,
            planned_start_time: input.planned_start_time,
            planned_end_time: input.planned_end_time,
            ..Default::default()
        };
        let (id, arn) = self.insert_ops_item(&ctx.partition, &ctx.caller.account_id, &ctx.region, item, tags)?;
        Ok(types::CreateOpsItemResponse { ops_item_id: Some(id), ops_item_arn: Some(arn) })
    }

    pub(crate) fn get_ops_item(
        &self,
        ctx: &RequestContext,
        input: types::GetOpsItemRequest,
    ) -> Result<types::GetOpsItemResponse, ServiceError> {
        let rec = self.authorize_ops_item(ctx, "GetOpsItem", &input.ops_item_id, ConditionContext::new())?;
        Ok(types::GetOpsItemResponse { ops_item: Some(rec.item) })
    }

    pub(crate) fn update_ops_item(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOpsItemRequest,
    ) -> Result<types::UpdateOpsItemResponse, ServiceError> {
        let id = input.ops_item_id.clone();
        let rec = self.authorize_ops_item(ctx, "UpdateOpsItem", &id, ConditionContext::new())?;
        if let Some(c) = &input.category {
            if !CATEGORIES.contains(&c.as_str()) {
                return Err(invalid(&["Category"], format!("Category {c} isn't valid.")));
            }
        }
        if let Some(s) = &input.status {
            let kind = rec.item.ops_item_type.as_deref().unwrap_or("/aws/issues");
            if matches!(kind, "/aws/issues" | "/aws/insight")
                && !matches!(s.as_str(), "Open" | "InProgress" | "Resolved")
            {
                return Err(invalid(&["Status"], format!("Status {s} isn't valid for OpsItems of type {kind}.")));
            }
        }
        let mut data = rec.item.operational_data.clone().unwrap_or_default();
        if let Some(add) = &input.operational_data {
            check_operational_data(add)?;
            data.extend(add.clone());
        }
        for k in input.operational_data_to_delete.iter().flatten() {
            data.remove(k);
        }
        let at = now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let item = &mut r.ops.items.get_mut(&id).ok_or_else(|| not_found(&id))?.item;
        macro_rules! set {
            ($($f:ident),*) => { $( if input.$f.is_some() { item.$f = input.$f.clone(); } )* };
        }
        set!(
            description,
            notifications,
            priority,
            related_ops_items,
            status,
            title,
            category,
            severity,
            actual_start_time,
            actual_end_time,
            planned_start_time,
            planned_end_time
        );
        item.operational_data = (!data.is_empty()).then_some(data);
        item.last_modified_by = Some(ctx.caller.arn.clone());
        item.last_modified_time = Some(at);
        item.version = Some(uuid::Uuid::new_v4().to_string());
        Ok(types::UpdateOpsItemResponse::default())
    }

    pub(crate) fn delete_ops_item(
        &self,
        ctx: &RequestContext,
        input: types::DeleteOpsItemRequest,
    ) -> Result<types::DeleteOpsItemResponse, ServiceError> {
        let arn = ops_item_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.ops_item_id);
        ctx.authorize("ssm:DeleteOpsItem", &arn, ConditionContext::new())?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).ops.items.remove(&input.ops_item_id);
        Ok(types::DeleteOpsItemResponse::default())
    }

    pub(crate) fn describe_ops_items(
        &self,
        ctx: &RequestContext,
        input: types::DescribeOpsItemsRequest,
    ) -> Result<types::DescribeOpsItemsResponse, ServiceError> {
        ctx.authorize("ssm:DescribeOpsItems", "*", ConditionContext::new())?;
        let filters = input.ops_item_filters.unwrap_or_default();
        for f in &filters {
            if !types::OPS_ITEM_FILTER_KEY.contains(&f.key.as_str()) {
                return Err(invalid(&["OpsItemFilters"], format!("Filter key {} isn't valid.", f.key)));
            }
        }
        let mut items: Vec<types::OpsItem> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.ops.items.values().map(|x| x.item.clone()).collect())
                .unwrap_or_default()
        };
        items.retain(|i| filters.iter().all(|f| filter_matches(i, f)));
        items.sort_by_key(|i| std::cmp::Reverse(i.created_time));
        let list: Vec<types::OpsItemSummary> = items.iter().map(summary).collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (page_items, next) = page(list, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeOpsItemsResponse { next_token: next, ops_item_summaries: Some(page_items) })
    }

    pub(crate) fn associate_ops_item_related_item(
        &self,
        ctx: &RequestContext,
        input: types::AssociateOpsItemRelatedItemRequest,
    ) -> Result<types::AssociateOpsItemRelatedItemResponse, ServiceError> {
        let id = input.ops_item_id.clone();
        let rec = self.authorize_ops_item(ctx, "AssociateOpsItemRelatedItem", &id, ConditionContext::new())?;
        if rec.related.iter().any(|r| r.resource_uri.as_deref() == Some(input.resource_uri.as_str())) {
            return Err(errors::ops_item_related_item_already_exists(format!(
                "The resource {} is already associated with the OpsItem {id}.",
                input.resource_uri
            ))
            .with_field("ResourceUri", ErrorValue::String(input.resource_uri.clone()))
            .with_field("OpsItemId", ErrorValue::String(id.clone())));
        }
        let at = now(ctx);
        let association = uuid::Uuid::new_v4().to_string();
        let who = Some(types::OpsItemIdentity { arn: Some(ctx.caller.arn.clone()) });
        let entry = types::OpsItemRelatedItemSummary {
            ops_item_id: Some(id.clone()),
            association_id: Some(association.clone()),
            resource_type: Some(input.resource_type),
            association_type: Some(input.association_type),
            resource_uri: Some(input.resource_uri),
            created_by: who.clone(),
            created_time: Some(at),
            last_modified_by: who,
            last_modified_time: Some(at),
        };
        let mut st = self.lock();
        if let Some(r) = st.region(&ctx.caller.account_id, &ctx.region).ops.items.get_mut(&id) {
            r.related.push(entry);
        }
        Ok(types::AssociateOpsItemRelatedItemResponse { association_id: Some(association) })
    }

    pub(crate) fn disassociate_ops_item_related_item(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateOpsItemRelatedItemRequest,
    ) -> Result<types::DisassociateOpsItemRelatedItemResponse, ServiceError> {
        let id = input.ops_item_id.clone();
        self.authorize_ops_item(ctx, "DisassociateOpsItemRelatedItem", &id, ConditionContext::new())?;
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region).ops.items.get_mut(&id).ok_or_else(|| not_found(&id))?;
        let before = r.related.len();
        r.related.retain(|x| x.association_id.as_deref() != Some(input.association_id.as_str()));
        if r.related.len() == before {
            return Err(errors::ops_item_related_item_association_not_found(format!(
                "The association {} wasn't found.",
                input.association_id
            )));
        }
        Ok(types::DisassociateOpsItemRelatedItemResponse::default())
    }

    pub(crate) fn list_ops_item_related_items(
        &self,
        ctx: &RequestContext,
        input: types::ListOpsItemRelatedItemsRequest,
    ) -> Result<types::ListOpsItemRelatedItemsResponse, ServiceError> {
        let mut list = match &input.ops_item_id {
            Some(id) => self.authorize_ops_item(ctx, "ListOpsItemRelatedItems", id, ConditionContext::new())?.related,
            None => {
                ctx.authorize("ssm:ListOpsItemRelatedItems", "*", ConditionContext::new())?;
                let st = self.lock();
                st.region_ref(&ctx.caller.account_id, &ctx.region)
                    .map(|r| r.ops.items.values().flat_map(|x| x.related.clone()).collect())
                    .unwrap_or_default()
            }
        };
        for f in input.filters.iter().flatten() {
            list.retain(|r| {
                let have = match f.key.as_str() {
                    "ResourceType" => r.resource_type.as_deref(),
                    "AssociationId" => r.association_id.as_deref(),
                    "ResourceUri" => r.resource_uri.as_deref(),
                    _ => None,
                };
                have.is_some_and(|h| f.values.iter().any(|v| v == h))
            });
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(list, input.next_token.as_deref(), limit)?;
        Ok(types::ListOpsItemRelatedItemsResponse { next_token: next, summaries: Some(items) })
    }

    pub(crate) fn list_ops_item_events(
        &self,
        ctx: &RequestContext,
        input: types::ListOpsItemEventsRequest,
    ) -> Result<types::ListOpsItemEventsResponse, ServiceError> {
        ctx.authorize("ssm:ListOpsItemEvents", "*", ConditionContext::new())?;
        let mut list: Vec<types::OpsItemEventSummary> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region).map(|r| r.ops.events.clone()).unwrap_or_default()
        };
        for f in input.filters.iter().flatten() {
            if f.key != "OpsItemId" {
                return Err(invalid(&["Filters"], format!("Filter key {} isn't valid.", f.key)));
            }
            list.retain(|e| e.ops_item_id.as_ref().is_some_and(|id| f.values.contains(id)));
        }
        list.reverse();
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(list, input.next_token.as_deref(), limit)?;
        Ok(types::ListOpsItemEventsResponse { next_token: next, summaries: Some(items) })
    }

    /// Create (or, with the same dedup string, add to) an OpsItem from an
    /// EventBridge event delivered to an OpsItem target.
    pub fn create_ops_item_from_event(
        &self,
        partition: &str,
        account: &str,
        region: &str,
        created_by: &str,
        event: &Value,
    ) -> Result<String, String> {
        let detail_type = event.get("detail-type").and_then(Value::as_str).unwrap_or("Event").to_string();
        let source = event.get("source").and_then(Value::as_str).unwrap_or("events").to_string();
        let at = event
            .get("time")
            .and_then(Value::as_str)
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|| self.clock_now());
        let resources: Vec<Value> = event
            .get("resources")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| r.as_str().map(|a| json!({ "arn": a })))
            .collect();
        let dedup =
            format!("{source}|{detail_type}|{}", serde_json::to_string(&event.get("resources")).unwrap_or_default());
        let mut data = BTreeMap::from([(
            "/aws/dedup".to_string(),
            types::OpsItemDataValue {
                value: Some(json!({ "dedupString": dedup }).to_string()),
                r#type: Some("SearchableString".into()),
            },
        )]);
        if !resources.is_empty() {
            data.insert(
                "/aws/resources".into(),
                types::OpsItemDataValue {
                    value: Some(Value::Array(resources).to_string()),
                    r#type: Some("SearchableString".into()),
                },
            );
        }
        let item = types::OpsItem {
            created_by: Some(created_by.into()),
            ops_item_type: Some("/aws/issues".into()),
            created_time: Some(at),
            description: Some(event.to_string().chars().take(2048).collect()),
            last_modified_by: Some(created_by.into()),
            last_modified_time: Some(at),
            status: Some("Open".into()),
            title: Some(detail_type.chars().take(1024).collect()),
            source: Some(source.clone()),
            operational_data: Some(data),
            ..Default::default()
        };
        let id = match self.insert_ops_item(partition, account, region, item, BTreeMap::new()) {
            Ok((id, _)) => id,
            Err(e) => match e.fields.iter().find(|f| f.name == "OpsItemId").map(|f| f.value.clone()) {
                Some(ErrorValue::String(id)) => id,
                _ => return Err(e.message),
            },
        };
        let mut st = self.lock();
        st.region(account, region).ops.events.push(types::OpsItemEventSummary {
            ops_item_id: Some(id.clone()),
            event_id: event.get("id").and_then(Value::as_str).map(str::to_string),
            source: Some(source),
            detail_type: Some(detail_type),
            detail: event.get("detail").map(Value::to_string),
            created_by: Some(types::OpsItemIdentity { arn: Some(created_by.into()) }),
            created_time: Some(at),
        });
        Ok(id)
    }

    /// The OpsItem a change request is tracked by.
    pub(crate) fn create_change_ops_item(
        &self,
        ctx: &RequestContext,
        execution: &str,
        title: &str,
        template: &str,
        change: &crate::automation::ChangeSpec,
    ) -> Option<String> {
        let info = json!({
            "templateName": template,
            "executionId": execution,
            "runbooks": change.runbooks.iter().map(|r| r.document_name.clone()).collect::<Vec<_>>(),
            "scheduledTime": change.scheduled_time.map(|t| t.to_rfc3339()),
            "scheduledEndTime": change.scheduled_end_time.map(|t| t.to_rfc3339()),
            "changeDetails": change.change_details,
        });
        let data = BTreeMap::from([
            (
                "/aws/changerequest".to_string(),
                types::OpsItemDataValue { value: Some(info.to_string()), r#type: Some("SearchableString".into()) },
            ),
            (
                "/aws/automations".to_string(),
                types::OpsItemDataValue {
                    value: Some(
                        json!([{ "automationId": execution, "automationType": "AWS:SSM:Automation" }]).to_string(),
                    ),
                    r#type: Some("SearchableString".into()),
                },
            ),
        ]);
        let at = self.clock_now();
        let item = types::OpsItem {
            created_by: Some(ctx.caller.arn.clone()),
            ops_item_type: Some("/aws/changerequest".into()),
            created_time: Some(at),
            description: Some(change.change_details.clone().unwrap_or_else(|| title.to_string())),
            last_modified_by: Some(ctx.caller.arn.clone()),
            last_modified_time: Some(at),
            status: Some("PendingApproval".into()),
            title: Some(title.to_string()),
            source: Some("SSM".into()),
            operational_data: Some(data),
            planned_start_time: change.scheduled_time,
            planned_end_time: change.scheduled_end_time,
            ..Default::default()
        };
        self.insert_ops_item(&ctx.partition, &ctx.caller.account_id, &ctx.region, item, BTreeMap::new())
            .ok()
            .map(|(id, _)| id)
    }

    /// Mirror a change request's status onto its OpsItem.
    pub(crate) fn mirror_ops_item_status(&self, run: &Run, status: &str) {
        let Some(id) = self.automation(&run.account, &run.region, &run.id).and_then(|r| r.execution.ops_item_id) else {
            return;
        };
        if !types::OPS_ITEM_STATUS.contains(&status) {
            return;
        }
        let at = self.clock_now();
        let mut st = self.lock();
        if let Some(r) = st.region(&run.account, &run.region).ops.items.get_mut(&id) {
            r.item.status = Some(status.into());
            r.item.last_modified_time = Some(at);
            if status == "RunbookInProgress" {
                r.item.actual_start_time = Some(at);
            }
            if matches!(status, "CompletedWithSuccess" | "CompletedWithFailure" | "Rejected" | "Cancelled") {
                r.item.actual_end_time = Some(at);
            }
        }
    }

    pub(crate) fn get_ops_summary(
        &self,
        ctx: &RequestContext,
        input: types::GetOpsSummaryRequest,
    ) -> Result<types::GetOpsSummaryResult, ServiceError> {
        ctx.authorize("ssm:GetOpsSummary", "*", ConditionContext::new())?;
        if let Some(sync) = &input.sync_name {
            let exists = self
                .lock()
                .region_ref(&ctx.caller.account_id, &ctx.region)
                .is_some_and(|r| r.data_syncs.contains_key(sync));
            if !exists {
                return Err(errors::resource_data_sync_not_found(format!("Resource data sync {sync} doesn't exist."))
                    .with_field("SyncName", ErrorValue::String(sync.clone())));
            }
        }
        let capture = now(ctx).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Rows of every OpsData type, by type name.
        let mut rows: BTreeMap<&str, Vec<Row>> = BTreeMap::new();
        {
            let st = self.lock();
            if let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
                rows.insert(
                    "AWS:OpsItem",
                    r.ops
                        .items
                        .values()
                        .map(|x| {
                            let i = &x.item;
                            let mut m = BTreeMap::new();
                            for k in [
                                "OpsItemId",
                                "Title",
                                "Status",
                                "Source",
                                "Priority",
                                "Severity",
                                "Category",
                                "OpsItemType",
                                "CreatedTime",
                                "LastModifiedTime",
                                "CreatedBy",
                            ] {
                                if let Some(v) = attribute(i, k) {
                                    m.insert(k.to_string(), v);
                                }
                            }
                            (i.ops_item_id.clone().unwrap_or_default(), m)
                        })
                        .collect(),
                );
            }
        }
        let nodes = self.nodes_of(&ctx.caller.account_id, &ctx.region);
        rows.insert(
            "AWS:EC2InstanceInformation",
            nodes
                .iter()
                .map(|n| {
                    let m = BTreeMap::from([
                        ("InstanceId".to_string(), n.instance_id.clone()),
                        ("PingStatus".to_string(), n.ping_status.clone()),
                        ("PlatformType".to_string(), n.platform_type.clone()),
                        ("PlatformName".to_string(), n.platform_name.clone()),
                        ("PlatformVersion".to_string(), n.platform_version.clone()),
                        ("IamRole".to_string(), n.iam_role.clone()),
                    ]);
                    (n.instance_id.clone(), m)
                })
                .collect(),
        );
        let filters = input.filters.clone().unwrap_or_default();
        let keep = |type_name: &str, row: &BTreeMap<String, String>| {
            filters.iter().all(|f| {
                let (t, attr) = f.key.split_once('.').unwrap_or((f.key.as_str(), ""));
                if t != type_name {
                    return true;
                }
                let have = row.get(attr);
                match f.r#type.as_deref().unwrap_or("Equal") {
                    "Exists" => have.is_some(),
                    "NotEqual" => have.is_none_or(|h| !f.values.contains(h)),
                    "BeginWith" => have.is_some_and(|h| f.values.iter().any(|v| h.starts_with(v.as_str()))),
                    "LessThan" => have.is_some_and(|h| f.values.iter().any(|v| compare(h, v).is_lt())),
                    "GreaterThan" => have.is_some_and(|h| f.values.iter().any(|v| compare(h, v).is_gt())),
                    _ => have.is_some_and(|h| f.values.contains(h)),
                }
            })
        };
        let wanted: Vec<String> = input
            .result_attributes
            .iter()
            .flatten()
            .map(|a| a.type_name.clone())
            .chain(input.aggregators.iter().flatten().filter_map(|a| a.type_name.clone()))
            .chain(filters.iter().filter_map(|f| f.key.split_once('.').map(|(t, _)| t.to_string())))
            .collect();
        let types_shown: Vec<&str> = if wanted.is_empty() {
            vec!["AWS:OpsItem"]
        } else {
            rows.keys().copied().filter(|k| wanted.iter().any(|w| w == k)).collect()
        };
        for w in &wanted {
            if !rows.contains_key(w.as_str()) {
                return Err(errors::invalid_type_name(format!("The type name {w} isn't valid.")));
            }
        }
        let mut entities = Vec::new();
        if let Some(aggs) = input.aggregators.as_ref().filter(|a| !a.is_empty()) {
            for a in aggs {
                let t = a.type_name.clone().unwrap_or_else(|| "AWS:OpsItem".into());
                let attr = a.attribute_name.clone().unwrap_or_default();
                let mut counts: BTreeMap<String, usize> = BTreeMap::new();
                for (_, row) in rows.get(t.as_str()).into_iter().flatten().filter(|(_, r)| keep(&t, r)) {
                    if let Some(v) = row.get(&attr) {
                        *counts.entry(v.clone()).or_default() += 1;
                    }
                }
                for (value, n) in counts {
                    entities.push(types::OpsEntity {
                        id: Some(value.clone()),
                        data: Some(BTreeMap::from([(
                            t.clone(),
                            types::OpsEntityItem {
                                capture_time: Some(capture.clone()),
                                content: Some(vec![BTreeMap::from([
                                    (attr.clone(), value),
                                    ("Count".to_string(), n.to_string()),
                                ])]),
                            },
                        )])),
                    });
                }
            }
        } else {
            for t in types_shown {
                for (id, row) in rows.get(t).into_iter().flatten().filter(|(_, r)| keep(t, r)) {
                    entities.push(types::OpsEntity {
                        id: Some(id.clone()),
                        data: Some(BTreeMap::from([(
                            t.to_string(),
                            types::OpsEntityItem {
                                capture_time: Some(capture.clone()),
                                content: Some(vec![row.clone()]),
                            },
                        )])),
                    });
                }
            }
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(entities, input.next_token.as_deref(), limit)?;
        Ok(types::GetOpsSummaryResult { entities: Some(items), next_token: next })
    }

    pub(crate) fn create_ops_metadata(
        &self,
        ctx: &RequestContext,
        input: types::CreateOpsMetadataRequest,
    ) -> Result<types::CreateOpsMetadataResult, ServiceError> {
        let tags: BTreeMap<String, String> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        let arn = metadata_arn(ctx, &input.resource_id);
        ctx.authorize("ssm:CreateOpsMetadata", &arn, request_tag_conditions(tags.iter()))?;
        let values: BTreeMap<String, String> =
            input.metadata.unwrap_or_default().into_iter().map(|(k, v)| (k, v.value.unwrap_or_default())).collect();
        if values.len() > MAX_METADATA_KEYS {
            return Err(errors::ops_metadata_key_limit_exceeded(format!(
                "OpsMetadata can have at most {MAX_METADATA_KEYS} keys."
            )));
        }
        let at = now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if r.ops.metadata.contains_key(&input.resource_id) {
            return Err(errors::ops_metadata_already_exists(format!(
                "OpsMetadata for resource {} already exists.",
                input.resource_id
            )));
        }
        if r.ops.metadata.len() >= MAX_OPS_METADATA {
            return Err(errors::ops_metadata_limit_exceeded(
                "The account has the maximum number of OpsMetadata objects.",
            ));
        }
        r.ops.metadata.insert(
            input.resource_id.clone(),
            OpsMetadataRecord {
                metadata: types::OpsMetadata {
                    resource_id: Some(input.resource_id),
                    ops_metadata_arn: Some(arn.clone()),
                    last_modified_date: Some(at),
                    last_modified_user: Some(ctx.caller.arn.clone()),
                    creation_date: Some(at),
                },
                values,
                tags,
            },
        );
        Ok(types::CreateOpsMetadataResult { ops_metadata_arn: Some(arn) })
    }

    fn metadata_by_arn(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
    ) -> Result<OpsMetadataRecord, ServiceError> {
        let rec = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .and_then(|r| r.ops.metadata.values().find(|m| m.metadata.ops_metadata_arn.as_deref() == Some(arn)))
                .cloned()
        };
        let cond = rec.as_ref().map(|r| resource_tag_conditions(&r.tags)).unwrap_or_default();
        ctx.authorize(&format!("ssm:{action}"), arn, cond)?;
        rec.ok_or_else(|| errors::ops_metadata_not_found(format!("OpsMetadata {arn} not found.")))
    }

    pub(crate) fn get_ops_metadata(
        &self,
        ctx: &RequestContext,
        input: types::GetOpsMetadataRequest,
    ) -> Result<types::GetOpsMetadataResult, ServiceError> {
        let rec = self.metadata_by_arn(ctx, "GetOpsMetadata", &input.ops_metadata_arn)?;
        let entries: Vec<(String, String)> = rec.values.into_iter().collect();
        let limit = input.max_results.unwrap_or(10).clamp(1, 10) as usize;
        let (items, next) = page(entries, input.next_token.as_deref(), limit)?;
        Ok(types::GetOpsMetadataResult {
            resource_id: rec.metadata.resource_id,
            metadata: Some(items.into_iter().map(|(k, v)| (k, types::MetadataValue { value: Some(v) })).collect()),
            next_token: next,
        })
    }

    pub(crate) fn update_ops_metadata(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOpsMetadataRequest,
    ) -> Result<types::UpdateOpsMetadataResult, ServiceError> {
        let rec = self.metadata_by_arn(ctx, "UpdateOpsMetadata", &input.ops_metadata_arn)?;
        let mut values = rec.values.clone();
        for (k, v) in input.metadata_to_update.unwrap_or_default() {
            values.insert(k, v.value.unwrap_or_default());
        }
        for k in input.keys_to_delete.iter().flatten() {
            values.remove(k);
        }
        if values.len() > MAX_METADATA_KEYS {
            return Err(errors::ops_metadata_key_limit_exceeded(format!(
                "OpsMetadata can have at most {MAX_METADATA_KEYS} keys."
            )));
        }
        let at = now(ctx);
        let id = rec.metadata.resource_id.clone().unwrap_or_default();
        let mut st = self.lock();
        if let Some(m) = st.region(&ctx.caller.account_id, &ctx.region).ops.metadata.get_mut(&id) {
            m.values = values;
            m.metadata.last_modified_date = Some(at);
            m.metadata.last_modified_user = Some(ctx.caller.arn.clone());
        }
        Ok(types::UpdateOpsMetadataResult { ops_metadata_arn: Some(input.ops_metadata_arn) })
    }

    pub(crate) fn delete_ops_metadata(
        &self,
        ctx: &RequestContext,
        input: types::DeleteOpsMetadataRequest,
    ) -> Result<types::DeleteOpsMetadataResult, ServiceError> {
        let rec = self.metadata_by_arn(ctx, "DeleteOpsMetadata", &input.ops_metadata_arn)?;
        let id = rec.metadata.resource_id.unwrap_or_default();
        self.lock().region(&ctx.caller.account_id, &ctx.region).ops.metadata.remove(&id);
        Ok(types::DeleteOpsMetadataResult::default())
    }

    pub(crate) fn list_ops_metadata(
        &self,
        ctx: &RequestContext,
        input: types::ListOpsMetadataRequest,
    ) -> Result<types::ListOpsMetadataResult, ServiceError> {
        ctx.authorize("ssm:ListOpsMetadata", "*", ConditionContext::new())?;
        let mut list: Vec<types::OpsMetadata> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.ops.metadata.values().map(|m| m.metadata.clone()).collect())
                .unwrap_or_default()
        };
        for f in input.filters.iter().flatten() {
            if f.key != "ResourceId" && f.key != "AppManager/Type" {
                return Err(errors::ops_metadata_invalid_argument(format!("Filter key {} isn't valid.", f.key)));
            }
            if f.key == "ResourceId" {
                list.retain(|m| {
                    m.resource_id
                        .as_ref()
                        .is_some_and(|id| f.values.iter().any(|v| id == v || id.starts_with(v.as_str())))
                });
            }
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(list, input.next_token.as_deref(), limit)?;
        Ok(types::ListOpsMetadataResult { ops_metadata_list: Some(items), next_token: next })
    }

    pub(crate) fn ops_item_tags_mut<'a>(
        region: &'a mut crate::state::Region,
        id: &str,
    ) -> Option<&'a mut BTreeMap<String, String>> {
        region.ops.items.get_mut(id).map(|r| &mut r.tags)
    }

    pub(crate) fn ops_metadata_tags_mut<'a>(
        region: &'a mut crate::state::Region,
        id: &str,
    ) -> Option<&'a mut BTreeMap<String, String>> {
        region
            .ops
            .metadata
            .values_mut()
            .find(|m| {
                m.metadata.resource_id.as_deref() == Some(id) || m.metadata.ops_metadata_arn.as_deref() == Some(id)
            })
            .map(|m| &mut m.tags)
    }
}
