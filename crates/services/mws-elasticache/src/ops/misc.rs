//! Tags, events, engine versions, reserved nodes and service updates.

use mws_core::{RequestContext, ServiceError};

use super::*;
use crate::backend::EngineKind;
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::state::RegionState;
use crate::ElastiCache;

// ---- tags -------------------------------------------------------------------------

fn bad_arn(a: &str) -> ServiceError {
    errors::invalid_arn_fault(format!("The ARN {a} is not valid."))
}

/// Check that a taggable resource exists, returning the error ElastiCache
/// gives for a missing one.
fn check_resource(svc: &ElastiCache, ctx: &RequestContext, r: &RegionState, a: &str) -> Result<(), ServiceError> {
    let parts: Vec<&str> = a.splitn(7, ':').collect();
    if parts.len() != 7 || parts[0] != "arn" || parts[2] != "elasticache" {
        return Err(bad_arn(a));
    }
    let (kind, id) = (parts[5], parts[6]);
    if kind == "globalreplicationgroup" {
        let exists = svc.lock().globals.get(&crate::account_of(ctx)).is_some_and(|m| m.contains_key(id));
        return if exists {
            Ok(())
        } else {
            Err(errors::global_replication_group_not_found_fault(format!("Global replication group {id} not found.")))
        };
    }
    if parts[3] != ctx.region || parts[4] != crate::account_of(ctx) {
        return Err(bad_arn(a));
    }
    let missing: Option<ServiceError> = match kind {
        "cluster" => (!r.clusters.contains_key(id)).then(|| super::clusters::not_found(id)),
        "replicationgroup" => (!r.replication_groups.contains_key(id)).then(|| super::replication::not_found(id)),
        "parametergroup" => (!r.parameter_groups.contains_key(id))
            .then(|| errors::cache_parameter_group_not_found_fault(format!("CacheParameterGroup {id} not found."))),
        "subnetgroup" => (!r.subnet_groups.contains_key(id))
            .then(|| errors::cache_subnet_group_not_found_fault(format!("Cache subnet group {id} not found."))),
        "snapshot" => (!r.snapshots.contains_key(id)).then(|| super::snapshots::not_found(id)),
        "user" => (!r.users.contains_key(id)).then(|| errors::user_not_found_fault(format!("User {id} not found."))),
        "usergroup" => (!r.user_groups.contains_key(id)).then(|| super::users::group_not_found(id)),
        "serverlesscache" => (!r.serverless.contains_key(id))
            .then(|| errors::serverless_cache_not_found_fault(format!("Serverless cache {id} not found."))),
        "serverlesscachesnapshot" => (!r.serverless_snapshots.contains_key(id)).then(|| {
            errors::serverless_cache_snapshot_not_found_fault(format!("Serverless cache snapshot {id} not found."))
        }),
        "reserved-instance" => (!r.reserved.contains_key(id))
            .then(|| errors::reserved_cache_node_not_found_fault(format!("ReservedCacheNode {id} not found."))),
        _ => Some(bad_arn(a)),
    };
    match missing {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

pub(crate) async fn add_tags(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::AddTagsToResourceMessage,
) -> Result<t::TagListMessage, ServiceError> {
    check_tags(&input.tags)?;
    svc.with_region(ctx, |r| {
        check_resource(svc, ctx, r, &input.resource_name)?;
        let extra = request_tag_context(&input.tags);
        authorize(ctx, r, "AddTagsToResource", &input.resource_name, extra)?;
        let tags = r.tags.entry(input.resource_name.clone()).or_default();
        for tag in &input.tags {
            match tags.iter_mut().find(|x| x.key == tag.key) {
                Some(x) => x.value = tag.value.clone(),
                None => tags.push(tag.clone()),
            }
        }
        if tags.len() > 50 {
            return Err(errors::tag_quota_per_resource_exceeded("TagQuotaPerResource has been exceeded"));
        }
        Ok(t::TagListMessage { tag_list: Some(tags.clone()) })
    })
}

pub(crate) async fn list_tags(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ListTagsForResourceMessage,
) -> Result<t::TagListMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        check_resource(svc, ctx, r, &input.resource_name)?;
        authorize(ctx, r, "ListTagsForResource", &input.resource_name, Default::default())?;
        Ok(t::TagListMessage { tag_list: Some(r.tags.get(&input.resource_name).cloned().unwrap_or_default()) })
    })
}

pub(crate) async fn remove_tags(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::RemoveTagsFromResourceMessage,
) -> Result<t::TagListMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        check_resource(svc, ctx, r, &input.resource_name)?;
        let mut extra = mws_core::ConditionContext::new();
        if !input.tag_keys.is_empty() {
            extra.insert("aws:TagKeys".into(), input.tag_keys.clone());
        }
        authorize(ctx, r, "RemoveTagsFromResource", &input.resource_name, extra)?;
        let tags = r.tags.entry(input.resource_name.clone()).or_default();
        for k in &input.tag_keys {
            if !tags.iter().any(|x| x.key.as_deref() == Some(k)) {
                return Err(errors::tag_not_found_fault(format!("Tag {k} not found.")));
            }
        }
        tags.retain(|x| !input.tag_keys.iter().any(|k| x.key.as_deref() == Some(k)));
        let left = tags.clone();
        if left.is_empty() {
            r.tags.remove(&input.resource_name);
        }
        Ok(t::TagListMessage { tag_list: Some(left) })
    })
}

// ---- events -----------------------------------------------------------------------

const SOURCE_TYPES: &[&str] = &[
    "cache-cluster",
    "cache-parameter-group",
    "cache-security-group",
    "cache-subnet-group",
    "replication-group",
    "serverless-cache",
    "serverless-cache-snapshot",
    "user",
    "user-group",
];

pub(crate) async fn describe_events(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeEventsMessage,
) -> Result<t::EventsMessage, ServiceError> {
    ctx.authorize("elasticache:DescribeEvents", "*", Default::default())?;
    if let Some(st) = &input.source_type {
        if !SOURCE_TYPES.contains(&st.as_str()) {
            return Err(invalid(format!(
                "Invalid value for SourceType: {st}. Valid values are: {}",
                SOURCE_TYPES.join(", ")
            )));
        }
    }
    if input.source_identifier.is_some() && input.source_type.is_none() {
        return Err(combination("SourceType must be specified when SourceIdentifier is specified."));
    }
    let now = now(ctx).max(chrono::Utc::now());
    let end = input.end_time.unwrap_or(now);
    let start = match (input.start_time, input.duration) {
        (Some(s), _) => s,
        (None, Some(d)) => {
            if !(0..=20160).contains(&d) {
                return Err(invalid("Duration must be between 0 and 20160 minutes."));
            }
            end - chrono::Duration::minutes(d as i64)
        }
        (None, None) => end - chrono::Duration::minutes(60),
    };
    svc.with_region(ctx, |r| {
        let items: Vec<t::Event> = r
            .events
            .iter()
            .filter(|e| e.date.is_some_and(|d| d >= start && d <= end))
            .filter(|e| input.source_type.as_deref().is_none_or(|s| e.source_type.as_deref() == Some(s)))
            .filter(|e| {
                input
                    .source_identifier
                    .as_deref()
                    .is_none_or(|s| e.source_identifier.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(s)))
            })
            .cloned()
            .collect();
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::EventsMessage { marker, events: Some(page) })
    })
}

// ---- engine versions --------------------------------------------------------------------

pub(crate) async fn describe_engine_versions(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeCacheEngineVersionsMessage,
) -> Result<t::CacheEngineVersionMessage, ServiceError> {
    ctx.authorize("elasticache:DescribeCacheEngineVersions", "*", Default::default())?;
    let engine = match input.engine.as_deref() {
        None => None,
        Some(e) => Some(EngineKind::parse(e).ok_or_else(|| invalid(format!("Invalid engine: {e}")))?),
    };
    if let Some(f) = &input.cache_parameter_group_family {
        if !catalog::families().contains(&f.as_str()) {
            return Err(invalid(format!("Invalid parameter group family: {f}")));
        }
    }
    let mut items: Vec<&catalog::EngineVersion> = catalog::ENGINE_VERSIONS
        .iter()
        .filter(|v| engine.is_none_or(|e| v.engine == e))
        .filter(|v| input.engine_version.as_deref().is_none_or(|x| v.version == x || v.aliases.contains(&x)))
        .filter(|v| input.cache_parameter_group_family.as_deref().is_none_or(|f| v.family == f))
        .collect();
    if input.default_only == Some(true) {
        // The default (latest) version of each engine, or of each family
        // when a family or version is named.
        let by_family = input.cache_parameter_group_family.is_some() || input.engine_version.is_some();
        let mut seen = std::collections::BTreeMap::new();
        for v in &items {
            let k = if by_family { v.family.to_string() } else { v.engine.as_str().to_string() };
            seen.insert(k, *v);
        }
        let keep: Vec<&str> = seen.values().map(|v| v.version).collect();
        items.retain(|v| keep.contains(&v.version));
    }
    let wire: Vec<t::CacheEngineVersion> = items
        .iter()
        .map(|v| t::CacheEngineVersion {
            engine: Some(v.engine.as_str().into()),
            engine_version: Some(v.version.into()),
            cache_parameter_group_family: Some(v.family.into()),
            cache_engine_description: Some(catalog::engine_description(v.engine).into()),
            cache_engine_version_description: Some(format!("{} {}", catalog::engine_description(v.engine), v.version)),
        })
        .collect();
    let (page, marker) = page(wire, input.marker.as_deref(), input.max_records)?;
    Ok(t::CacheEngineVersionMessage { marker, cache_engine_versions: Some(page) })
}

// ---- reserved nodes ------------------------------------------------------------------------

fn duration_matches(filter: Option<&str>, seconds: Option<i32>) -> Result<bool, ServiceError> {
    let Some(f) = filter else { return Ok(true) };
    let want = match f {
        "1" | "31536000" => 31_536_000,
        "3" | "94608000" => 94_608_000,
        _ => return Err(invalid(format!("Invalid duration: {f}. Valid values are 1, 3, 31536000 and 94608000."))),
    };
    Ok(seconds == Some(want))
}

fn offering_type_ok(f: Option<&str>) -> Result<(), ServiceError> {
    match f {
        Some(o)
            if !catalog::OFFERING_TYPES.contains(&o)
                && !["Light Utilization", "Medium Utilization", "Heavy Utilization"].contains(&o) =>
        {
            Err(invalid(format!("Invalid offering type: {o}")))
        }
        _ => Ok(()),
    }
}

pub(crate) async fn describe_offerings(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeReservedCacheNodesOfferingsMessage,
) -> Result<t::ReservedCacheNodesOfferingMessage, ServiceError> {
    ctx.authorize("elasticache:DescribeReservedCacheNodesOfferings", "*", Default::default())?;
    offering_type_ok(input.offering_type.as_deref())?;
    duration_matches(input.duration.as_deref(), None)?;
    let items: Vec<t::ReservedCacheNodesOffering> = catalog::offerings()
        .into_iter()
        .filter(|o| {
            input
                .reserved_cache_nodes_offering_id
                .as_ref()
                .is_none_or(|x| o.reserved_cache_nodes_offering_id.as_ref() == Some(x))
        })
        .filter(|o| input.cache_node_type.as_ref().is_none_or(|x| o.cache_node_type.as_ref() == Some(x)))
        .filter(|o| input.product_description.as_ref().is_none_or(|x| o.product_description.as_ref() == Some(x)))
        .filter(|o| input.offering_type.as_ref().is_none_or(|x| o.offering_type.as_ref() == Some(x)))
        .filter(|o| duration_matches(input.duration.as_deref(), o.duration).unwrap_or(false))
        .collect();
    if items.is_empty() {
        if let Some(id) = &input.reserved_cache_nodes_offering_id {
            return Err(errors::reserved_cache_nodes_offering_not_found_fault(format!(
                "ReservedCacheNodesOffering {id} not found."
            )));
        }
    }
    let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
    Ok(t::ReservedCacheNodesOfferingMessage { marker, reserved_cache_nodes_offerings: Some(page) })
}

pub(crate) async fn purchase_offering(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::PurchaseReservedCacheNodesOfferingMessage,
) -> Result<t::PurchaseReservedCacheNodesOfferingResult, ServiceError> {
    let offering = catalog::offerings()
        .into_iter()
        .find(|o| {
            o.reserved_cache_nodes_offering_id.as_deref() == Some(input.reserved_cache_nodes_offering_id.as_str())
        })
        .ok_or_else(|| {
            errors::reserved_cache_nodes_offering_not_found_fault(format!(
                "ReservedCacheNodesOffering {} not found.",
                input.reserved_cache_nodes_offering_id
            ))
        })?;
    let id = input.reserved_cache_node_id.clone().unwrap_or_else(|| format!("ri-{}", random_hex(12)));
    let count = input.cache_node_count.unwrap_or(1);
    if !(1..=100).contains(&count) {
        return Err(invalid("CacheNodeCount must be between 1 and 100."));
    }
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "reserved-instance", &id);
    authorize_create(ctx, "PurchaseReservedCacheNodesOffering", &resource, &tags, Default::default())?;
    svc.with_region(ctx, |r| {
        if r.reserved.contains_key(&id) {
            return Err(errors::reserved_cache_node_already_exists_fault(format!(
                "ReservedCacheNode {id} already exists."
            )));
        }
        let total: i32 = r.reserved.values().filter_map(|n| n.cache_node_count).sum();
        if total + count > 300 {
            return Err(errors::reserved_cache_node_quota_exceeded_fault("ReservedCacheNodeQuota has been exceeded."));
        }
        let node = t::ReservedCacheNode {
            reserved_cache_node_id: Some(id.clone()),
            reserved_cache_nodes_offering_id: offering.reserved_cache_nodes_offering_id.clone(),
            cache_node_type: offering.cache_node_type.clone(),
            start_time: Some(now(ctx)),
            duration: offering.duration,
            fixed_price: offering.fixed_price,
            usage_price: offering.usage_price,
            cache_node_count: Some(count),
            product_description: offering.product_description.clone(),
            offering_type: offering.offering_type.clone(),
            state: Some("payment-pending".into()),
            recurring_charges: offering.recurring_charges.clone(),
            reservation_arn: Some(resource.clone()),
        };
        let mut stored = node.clone();
        stored.state = Some("active".into());
        r.reserved.insert(id.clone(), stored);
        set_tags(r, &resource, input.tags.clone());
        Ok(t::PurchaseReservedCacheNodesOfferingResult { reserved_cache_node: Some(node) })
    })
}

pub(crate) async fn describe_reserved(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeReservedCacheNodesMessage,
) -> Result<t::ReservedCacheNodeMessage, ServiceError> {
    ctx.authorize("elasticache:DescribeReservedCacheNodes", &arn(ctx, "reserved-instance", "*"), Default::default())?;
    offering_type_ok(input.offering_type.as_deref())?;
    duration_matches(input.duration.as_deref(), None)?;
    svc.with_region(ctx, |r| {
        if let Some(id) = &input.reserved_cache_node_id {
            if !r.reserved.contains_key(id) {
                return Err(errors::reserved_cache_node_not_found_fault(format!("ReservedCacheNode {id} not found.")));
            }
        }
        let items: Vec<t::ReservedCacheNode> = r
            .reserved
            .values()
            .filter(|o| {
                input.reserved_cache_node_id.as_ref().is_none_or(|x| o.reserved_cache_node_id.as_ref() == Some(x))
            })
            .filter(|o| {
                input
                    .reserved_cache_nodes_offering_id
                    .as_ref()
                    .is_none_or(|x| o.reserved_cache_nodes_offering_id.as_ref() == Some(x))
            })
            .filter(|o| input.cache_node_type.as_ref().is_none_or(|x| o.cache_node_type.as_ref() == Some(x)))
            .filter(|o| input.product_description.as_ref().is_none_or(|x| o.product_description.as_ref() == Some(x)))
            .filter(|o| input.offering_type.as_ref().is_none_or(|x| o.offering_type.as_ref() == Some(x)))
            .filter(|o| duration_matches(input.duration.as_deref(), o.duration).unwrap_or(false))
            .cloned()
            .collect();
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::ReservedCacheNodeMessage { marker, reserved_cache_nodes: Some(page) })
    })
}

// ---- service updates ------------------------------------------------------------------------

fn service_update_wire(u: &catalog::ServiceUpdate, now: chrono::DateTime<chrono::Utc>) -> t::ServiceUpdate {
    let recommended = catalog::parse_time(u.recommended_by);
    t::ServiceUpdate {
        service_update_name: Some(u.name.into()),
        service_update_release_date: Some(catalog::parse_time(u.released)),
        service_update_end_date: None,
        service_update_severity: Some(u.severity.into()),
        service_update_recommended_apply_by_date: Some(recommended),
        service_update_status: Some("available".into()),
        service_update_description: Some(u.description.into()),
        service_update_type: Some(u.kind.into()),
        engine: Some(u.engine.as_str().into()),
        engine_version: Some(u.engine_version.into()),
        auto_update_after_recommended_apply_by_date: Some(now > recommended),
        estimated_update_time: Some("10 minutes per node".into()),
    }
}

const SERVICE_UPDATE_STATUSES: &[&str] = &["available", "cancelled", "expired"];
const UPDATE_ACTION_STATUSES: &[&str] = &[
    "not-applied",
    "waiting-to-start",
    "in-progress",
    "stopping",
    "stopped",
    "complete",
    "scheduling",
    "scheduled",
    "not-applicable",
];

fn check_statuses(given: Option<&Vec<String>>, valid: &[&str], name: &str) -> Result<(), ServiceError> {
    for s in given.into_iter().flatten() {
        if !valid.contains(&s.as_str()) {
            return Err(invalid(format!("Invalid value for {name}: {s}")));
        }
    }
    Ok(())
}

pub(crate) async fn describe_service_updates(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeServiceUpdatesMessage,
) -> Result<t::ServiceUpdatesMessage, ServiceError> {
    ctx.authorize("elasticache:DescribeServiceUpdates", "*", Default::default())?;
    check_statuses(input.service_update_status.as_ref(), SERVICE_UPDATE_STATUSES, "ServiceUpdateStatus")?;
    if let Some(n) = &input.service_update_name {
        if catalog::service_update(n).is_none() {
            return Err(errors::service_update_not_found_fault(format!("Service update {n} not found.")));
        }
    }
    let at = now(ctx);
    let items: Vec<t::ServiceUpdate> = catalog::SERVICE_UPDATES
        .iter()
        .filter(|u| input.service_update_name.as_deref().is_none_or(|n| u.name == n))
        .map(|u| service_update_wire(u, at))
        .filter(|u| {
            input
                .service_update_status
                .as_ref()
                .is_none_or(|l| l.is_empty() || l.iter().any(|s| u.service_update_status.as_deref() == Some(s)))
        })
        .collect();
    let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
    Ok(t::ServiceUpdatesMessage { marker, service_updates: Some(page) })
}

/// A resource a service update applies to: `(replication group, cluster)`
/// (one of them is set), its engine and version, and its node ids.
struct Target {
    rg: Option<String>,
    cluster: Option<String>,
    engine: EngineKind,
    version: String,
    nodes: Vec<(Option<String>, String, String)>,
}

fn targets(r: &RegionState) -> Vec<Target> {
    let mut out = Vec::new();
    for g in r.replication_groups.values() {
        let nodes = r
            .clusters
            .values()
            .filter(|c| c.info.replication_group_id.as_deref() == Some(g.id()))
            .flat_map(|c| {
                c.nodes.keys().map(|n| (c.node_group_id.clone(), c.id().to_string(), n.clone())).collect::<Vec<_>>()
            })
            .collect();
        out.push(Target {
            rg: Some(g.id().to_string()),
            cluster: None,
            engine: g.engine(),
            version: g.engine_version.clone(),
            nodes,
        });
    }
    for c in r.clusters.values().filter(|c| c.info.replication_group_id.is_none()) {
        out.push(Target {
            rg: None,
            cluster: Some(c.id().to_string()),
            engine: c.engine(),
            version: c.info.engine_version.clone().unwrap_or_default(),
            nodes: c.nodes.keys().map(|n| (None, c.id().to_string(), n.clone())).collect(),
        });
    }
    out
}

fn target_id(t: &Target) -> &str {
    t.rg.as_deref().or(t.cluster.as_deref()).unwrap_or_default()
}

/// The status of `update` on a target, or `None` when it does not apply.
fn action_status(
    r: &RegionState,
    u: &catalog::ServiceUpdate,
    tg: &Target,
) -> Option<(String, Option<chrono::DateTime<chrono::Utc>>)> {
    let key = format!("{}/{}", u.name, target_id(tg));
    if let Some((s, at)) = r.update_actions.get(&key) {
        return Some((s.clone(), Some(*at)));
    }
    let same_line = tg.engine == u.engine
        && tg.version.split('.').next() == u.engine_version.split('.').next()
        && super::clusters::version_cmp(&tg.version, u.engine_version) == std::cmp::Ordering::Less;
    same_line.then(|| ("not-applied".to_string(), None))
}

pub(crate) async fn describe_update_actions(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeUpdateActionsMessage,
) -> Result<t::UpdateActionsMessage, ServiceError> {
    ctx.authorize("elasticache:DescribeUpdateActions", "*", Default::default())?;
    check_statuses(input.service_update_status.as_ref(), SERVICE_UPDATE_STATUSES, "ServiceUpdateStatus")?;
    check_statuses(input.update_action_status.as_ref(), UPDATE_ACTION_STATUSES, "UpdateActionStatus")?;
    if let Some(e) = &input.engine {
        EngineKind::parse(e).ok_or_else(|| invalid(format!("Invalid engine: {e}")))?;
    }
    let show_nodes = input.show_node_level_update_status == Some(true);
    let at = now(ctx);
    svc.with_region(ctx, |r| {
        let mut items = Vec::new();
        for u in catalog::SERVICE_UPDATES {
            if input.service_update_name.as_deref().is_some_and(|n| n != u.name) {
                continue;
            }
            if input.engine.as_deref().is_some_and(|e| EngineKind::parse(e) != Some(u.engine)) {
                continue;
            }
            let released = catalog::parse_time(u.released);
            if let Some(f) = &input.service_update_time_range {
                if f.start_time.is_some_and(|s| released < s) || f.end_time.is_some_and(|e| released > e) {
                    continue;
                }
            }
            for tg in targets(r) {
                if let Some(l) = &input.replication_group_ids {
                    if tg.rg.as_ref().is_none_or(|g| !l.contains(g)) {
                        continue;
                    }
                }
                if let Some(l) = &input.cache_cluster_ids {
                    if tg.cluster.as_ref().is_none_or(|c| !l.contains(c)) {
                        continue;
                    }
                }
                let Some((status, changed)) = action_status(r, u, &tg) else { continue };
                if input.update_action_status.as_ref().is_some_and(|l| !l.is_empty() && !l.contains(&status)) {
                    continue;
                }
                let node_status = |s: &str| if s == "complete" { "complete" } else { "not-applied" }.to_string();
                let node_groups = (show_nodes && tg.rg.is_some()).then(|| {
                    let mut by_ng: std::collections::BTreeMap<String, Vec<t::NodeGroupMemberUpdateStatus>> =
                        Default::default();
                    for (ng, cluster, node) in &tg.nodes {
                        by_ng.entry(ng.clone().unwrap_or_else(|| "0001".into())).or_default().push(
                            t::NodeGroupMemberUpdateStatus {
                                cache_cluster_id: Some(cluster.clone()),
                                cache_node_id: Some(node.clone()),
                                node_update_status: Some(node_status(&status)),
                                node_update_end_date: (status == "complete").then_some(changed).flatten(),
                                node_update_initiated_by: (status == "complete").then(|| "customer".into()),
                                ..Default::default()
                            },
                        );
                    }
                    by_ng
                        .into_iter()
                        .map(|(ng, members)| t::NodeGroupUpdateStatus {
                            node_group_id: Some(ng),
                            node_group_member_update_status: Some(members),
                        })
                        .collect()
                });
                let cache_nodes = (show_nodes && tg.cluster.is_some()).then(|| {
                    tg.nodes
                        .iter()
                        .map(|(_, _, node)| t::CacheNodeUpdateStatus {
                            cache_node_id: Some(node.clone()),
                            node_update_status: Some(node_status(&status)),
                            node_update_end_date: (status == "complete").then_some(changed).flatten(),
                            node_update_initiated_by: (status == "complete").then(|| "customer".into()),
                            ..Default::default()
                        })
                        .collect()
                });
                let total = tg.nodes.len();
                items.push(t::UpdateAction {
                    replication_group_id: tg.rg.clone(),
                    cache_cluster_id: tg.cluster.clone(),
                    service_update_name: Some(u.name.into()),
                    service_update_release_date: Some(released),
                    service_update_severity: Some(u.severity.into()),
                    service_update_status: Some("available".into()),
                    service_update_recommended_apply_by_date: Some(catalog::parse_time(u.recommended_by)),
                    service_update_type: Some(u.kind.into()),
                    update_action_available_date: Some(released),
                    update_action_status: Some(status.clone()),
                    nodes_updated: Some(format!("{}/{total}", if status == "complete" { total } else { 0 })),
                    update_action_status_modified_date: changed.or(Some(released)),
                    sla_met: Some(
                        if status == "complete" {
                            if changed.is_some_and(|c| c <= catalog::parse_time(u.recommended_by)) {
                                "yes"
                            } else {
                                "no"
                            }
                        } else if at > catalog::parse_time(u.recommended_by) {
                            "no"
                        } else {
                            "n/a"
                        }
                        .into(),
                    ),
                    node_group_update_status: node_groups,
                    cache_node_update_status: cache_nodes,
                    estimated_update_time: Some("10 minutes per node".into()),
                    engine: Some(u.engine.as_str().into()),
                });
            }
        }
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::UpdateActionsMessage { marker, update_actions: Some(page) })
    })
}

async fn batch(
    svc: &ElastiCache,
    ctx: &RequestContext,
    action: &str,
    update: &str,
    rgs: Option<Vec<String>>,
    clusters: Option<Vec<String>>,
) -> Result<t::UpdateActionResultsMessage, ServiceError> {
    let u = catalog::service_update(update)
        .ok_or_else(|| errors::service_update_not_found_fault(format!("Service update {update} not found.")))?;
    let rgs: Vec<String> = rgs.unwrap_or_default().iter().map(|x| x.to_ascii_lowercase()).collect();
    let clusters: Vec<String> = clusters.unwrap_or_default().iter().map(|x| x.to_ascii_lowercase()).collect();
    if rgs.is_empty() && clusters.is_empty() {
        return Err(combination("At least one of ReplicationGroupIds or CacheClusterIds must be specified."));
    }
    if rgs.len() + clusters.len() > 20 {
        return Err(invalid("At most 20 replication groups and cache clusters can be specified."));
    }
    let at = now(ctx).max(chrono::Utc::now());
    let apply = action == "BatchApplyUpdateAction";
    svc.with_region(ctx, |r| {
        let mut processed = Vec::new();
        let mut unprocessed = Vec::new();
        let all = targets(r);
        let wanted =
            rgs.iter().map(|g| (Some(g.clone()), None)).chain(clusters.iter().map(|c| (None, Some(c.clone()))));
        for (rg, cluster) in wanted.collect::<Vec<(Option<String>, Option<String>)>>() {
            let id = rg.clone().or(cluster.clone()).unwrap_or_default();
            let resource = if rg.is_some() { arn(ctx, "replicationgroup", &id) } else { arn(ctx, "cluster", &id) };
            let fail = |kind: &str, msg: String| t::UnprocessedUpdateAction {
                replication_group_id: rg.clone(),
                cache_cluster_id: cluster.clone(),
                service_update_name: Some(update.into()),
                error_type: Some(kind.into()),
                error_message: Some(msg),
            };
            if authorize(ctx, r, action, &resource, Default::default()).is_err() {
                unprocessed.push(fail("AccessDenied", format!("Not authorized to perform {action} on {id}.")));
                continue;
            }
            let Some(tg) = all.iter().find(|x| x.rg == rg && x.cluster == cluster) else {
                let what = if rg.is_some() { "Replication group" } else { "Cache cluster" };
                unprocessed.push(fail("ResourceNotFound", format!("{what} {id} not found.")));
                continue;
            };
            let Some((status, _)) = action_status(r, u, tg) else {
                unprocessed
                    .push(fail("InvalidParameterValue", format!("Service update {update} is not applicable to {id}.")));
                continue;
            };
            let next = match (apply, status.as_str()) {
                (true, "complete") | (false, "complete") => {
                    unprocessed.push(fail(
                        "InvalidParameterValue",
                        format!("Service update {update} is already complete for {id}."),
                    ));
                    continue;
                }
                (true, _) => "complete",
                (false, "stopped") => "stopped",
                (false, "not-applied") => {
                    unprocessed.push(fail(
                        "InvalidParameterValue",
                        format!("Service update {update} is not in progress for {id}."),
                    ));
                    continue;
                }
                (false, _) => "stopped",
            };
            r.update_actions.insert(format!("{update}/{id}"), (next.to_string(), at));
            if apply {
                // The update installs the engine patch.
                if let Some(g) = rg.as_ref().and_then(|g| r.replication_groups.get_mut(g)) {
                    g.engine_version = u.engine_version.into();
                }
                for c in r.clusters.values_mut() {
                    let mine = match (&rg, &cluster) {
                        (Some(g), _) => c.info.replication_group_id.as_ref() == Some(g),
                        (None, Some(id)) => c.id() == id,
                        _ => false,
                    };
                    if mine {
                        c.info.engine_version = Some(u.engine_version.into());
                    }
                }
                if let Some(g) = &rg {
                    super::replication::refresh(svc, r, g);
                }
            }
            processed.push(t::ProcessedUpdateAction {
                replication_group_id: rg.clone(),
                cache_cluster_id: cluster.clone(),
                service_update_name: Some(update.into()),
                update_action_status: Some(if apply { "in-progress" } else { "stopping" }.into()),
            });
        }
        Ok(t::UpdateActionResultsMessage {
            processed_update_actions: Some(processed),
            unprocessed_update_actions: Some(unprocessed),
        })
    })
}

pub(crate) async fn batch_apply(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::BatchApplyUpdateActionMessage,
) -> Result<t::UpdateActionResultsMessage, ServiceError> {
    batch(
        svc,
        ctx,
        "BatchApplyUpdateAction",
        &input.service_update_name,
        input.replication_group_ids,
        input.cache_cluster_ids,
    )
    .await
}

pub(crate) async fn batch_stop(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::BatchStopUpdateActionMessage,
) -> Result<t::UpdateActionResultsMessage, ServiceError> {
    batch(
        svc,
        ctx,
        "BatchStopUpdateAction",
        &input.service_update_name,
        input.replication_group_ids,
        input.cache_cluster_ids,
    )
    .await
}
