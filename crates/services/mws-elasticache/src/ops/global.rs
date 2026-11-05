//! Global datastores: replication groups linked across Regions.
//!
//! A global datastore lives at account level. Its members are ordinary
//! replication groups in their Regions; what Describe shows about them
//! (members, node groups) is read from those groups each time.

use mws_core::{RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use super::*;
use crate::backend::EngineKind;
use crate::engine;
use crate::generated::{errors, types as t};
use crate::ElastiCache;

/// What a global datastore records; the rest is derived from its members.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Global {
    pub info: t::GlobalReplicationGroup,
    /// `(region, replication group id, role)`, primary first.
    pub members: Vec<(String, String, String)>,
}

fn not_found(id: &str) -> ServiceError {
    errors::global_replication_group_not_found_fault(format!("Global replication group {id} not found."))
}

fn bad_state(id: &str) -> ServiceError {
    errors::invalid_global_replication_group_state_fault(format!(
        "Global replication group {id} is not in available state."
    ))
}

/// The prefix ElastiCache gives global datastore ids created from a Region.
fn prefix(region: &str) -> String {
    let known = [
        ("us-east-1", "ldgnf"),
        ("us-east-2", "fpkhr"),
        ("us-west-1", "virxk"),
        ("us-west-2", "sgaui"),
        ("eu-west-1", "dsfbp"),
        ("eu-central-1", "erpgt"),
        ("ap-northeast-1", "quwsw"),
        ("ap-southeast-1", "vlqxn"),
        ("ap-southeast-2", "lfqnh"),
    ];
    if let Some((_, p)) = known.iter().find(|(r, _)| *r == region) {
        return (*p).to_string();
    }
    let h = sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(region.as_bytes()));
    h.iter().take(5).map(|b| (b'a' + b % 26) as char).collect()
}

fn ctx_in(ctx: &RequestContext, region: &str) -> RequestContext {
    let mut c = ctx.clone();
    c.region = region.to_string();
    c
}

fn global_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:elasticache::{}:globalreplicationgroup:{id}", ctx.partition, crate::account_of(ctx))
}

fn with_globals<R>(
    svc: &ElastiCache,
    ctx: &RequestContext,
    f: impl FnOnce(&mut std::collections::BTreeMap<String, Global>) -> R,
) -> R {
    let account = crate::account_of(ctx);
    let mut state = svc.lock();
    f(state.globals.entry(account).or_default())
}

fn get(svc: &ElastiCache, ctx: &RequestContext, id: &str) -> Result<Global, ServiceError> {
    with_globals(svc, ctx, |g| g.get(id).cloned()).ok_or_else(|| not_found(id))
}

fn put(svc: &ElastiCache, ctx: &RequestContext, g: Global) {
    let id = g.info.global_replication_group_id.clone().unwrap_or_default();
    with_globals(svc, ctx, |m| m.insert(id, g));
}

/// Set (or clear) a member group's GlobalReplicationGroupInfo.
fn set_member_info(svc: &ElastiCache, ctx: &RequestContext, region: &str, rg: &str, info: Option<(String, &str)>) {
    let rctx = ctx_in(ctx, region);
    svc.with_region(&rctx, |r| {
        if let Some(g) = r.replication_groups.get_mut(rg) {
            g.info.global_replication_group_info = info.map(|(id, role)| t::GlobalReplicationGroupInfo {
                global_replication_group_id: Some(id),
                global_replication_group_member_role: Some(role.into()),
            });
        }
    });
}

/// The view Describe returns, with members and node groups read from the
/// member replication groups.
fn render(svc: &ElastiCache, ctx: &RequestContext, g: &Global, members: bool) -> t::GlobalReplicationGroup {
    let mut info = g.info.clone();
    let id = info.global_replication_group_id.clone().unwrap_or_default();
    let mut shown = Vec::new();
    let mut node_groups = None;
    for (region, rg, role) in &g.members {
        let rctx = ctx_in(ctx, region);
        let state = svc.with_region(&rctx, |r| {
            r.replication_groups.get(rg).map(|x| {
                let ngs: Vec<t::GlobalNodeGroup> = x
                    .slots
                    .iter()
                    .map(|(ng, slots)| t::GlobalNodeGroup {
                        global_node_group_id: Some(format!("{id}-{ng}")),
                        slots: Some(slots.clone()),
                    })
                    .collect();
                (x.info.status.clone(), x.info.automatic_failover.clone(), x.info.cache_node_type.clone(), ngs)
            })
        });
        let Some((status, af, node_type, ngs)) = state else { continue };
        if role == "PRIMARY" {
            if info.cluster_enabled == Some(true) {
                node_groups = Some(ngs);
            }
            if node_type.is_some() {
                info.cache_node_type = node_type;
            }
        }
        shown.push(t::GlobalReplicationGroupMember {
            replication_group_id: Some(rg.clone()),
            replication_group_region: Some(region.clone()),
            role: Some(role.clone()),
            automatic_failover: af,
            status: Some(if status.as_deref() == Some("available") { "associated" } else { "associating" }.into()),
        });
    }
    info.members = members.then_some(shown);
    info.global_node_groups = node_groups;
    info
}

/// Settings a new secondary takes from the global datastore's primary.
pub(crate) struct SecondarySettings {
    pub id: String,
    pub engine: EngineKind,
    pub engine_version: String,
    pub node_type: String,
    pub shards: usize,
    pub replicas: i32,
    pub cluster_enabled: bool,
    pub transit: bool,
}

pub(crate) fn secondary_settings(
    svc: &ElastiCache,
    ctx: &RequestContext,
    gid: &str,
) -> Result<SecondarySettings, ServiceError> {
    let g = get(svc, ctx, gid)?;
    if g.info.status.as_deref() != Some("available") && g.info.status.as_deref() != Some("primary-only") {
        return Err(bad_state(gid));
    }
    if g.members.iter().any(|(region, _, _)| region == &ctx.region) {
        return Err(combination(format!(
            "Global replication group {gid} already has a member in Region {}.",
            ctx.region
        )));
    }
    if g.members.len() >= 3 {
        return Err(combination(format!("Global replication group {gid} already has the maximum of 2 secondaries.")));
    }
    let (region, rg, _) = g.members.first().cloned().ok_or_else(|| bad_state(gid))?;
    let pctx = ctx_in(ctx, &region);
    svc.with_region(&pctx, |r| {
        let p = r.replication_groups.get(&rg).ok_or_else(|| bad_state(gid))?;
        let shards = p.slots.len().max(1);
        let members =
            r.clusters.values().filter(|c| c.info.replication_group_id.as_deref() == Some(rg.as_str())).count();
        Ok(SecondarySettings {
            id: gid.to_string(),
            engine: p.engine(),
            engine_version: p.engine_version.clone(),
            node_type: p.info.cache_node_type.clone().unwrap_or_default(),
            shards,
            replicas: (members / shards).saturating_sub(1) as i32,
            cluster_enabled: p.cluster_enabled(),
            transit: p.info.transit_encryption_enabled == Some(true),
        })
    })
}

/// Record a new secondary member (CreateReplicationGroup with
/// GlobalReplicationGroupId).
pub(crate) fn add_secondary(svc: &ElastiCache, ctx: &RequestContext, gid: &str, rg: &str) {
    with_globals(svc, ctx, |m| {
        if let Some(g) = m.get_mut(gid) {
            g.members.push((ctx.region.clone(), rg.to_string(), "SECONDARY".into()));
            g.info.status = Some("available".into());
        }
    });
}

/// Start replicating a secondary from the global primary.
pub(crate) fn link_secondary(svc: &ElastiCache, ctx: &RequestContext, gid: &str, key: &str, rg: &str) {
    let Ok(g) = get(svc, ctx, gid) else { return };
    let Some((region, primary, _)) = g.members.first().cloned() else { return };
    let source = svc.with_region(&ctx_in(ctx, &region), |r| engine::global_source(r, &primary));
    if source.is_some() {
        engine::link_global(svc, ctx, key, rg, source);
    }
}

/// Point every secondary at the current primary (after a failover).
fn relink(svc: &ElastiCache, ctx: &RequestContext, g: &Global) {
    let Some((pregion, primary, _)) = g.members.first().cloned() else { return };
    let pctx = ctx_in(ctx, &pregion);
    engine::link_global(svc, &pctx, &region_key(&pctx), &primary, None);
    for (region, rg, _) in g.members.iter().skip(1) {
        let source = svc.with_region(&pctx, |r| engine::global_source(r, &primary));
        let rctx = ctx_in(ctx, region);
        if source.is_some() {
            engine::link_global(svc, &rctx, &region_key(&rctx), rg, source);
        }
    }
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateGlobalReplicationGroupMessage,
) -> Result<t::CreateGlobalReplicationGroupResult, ServiceError> {
    let suffix = &input.global_replication_group_id_suffix;
    if suffix.is_empty() || suffix.len() > 40 || !suffix.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(invalid(format!("Invalid GlobalReplicationGroupIdSuffix: {suffix}")));
    }
    let id = format!("{}-{}", prefix(&ctx.region), suffix.to_ascii_lowercase());
    let resource = global_arn(ctx, &id);
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let rg = input.primary_replication_group_id.to_ascii_lowercase();
    authorize_create(ctx, "CreateGlobalReplicationGroup", &resource, &tags, Default::default())?;
    let info = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&rg).ok_or_else(|| super::replication::not_found(&rg))?;
        authorize(
            ctx,
            r,
            "CreateGlobalReplicationGroup",
            g.info.arn.as_deref().unwrap_or_default(),
            Default::default(),
        )?;
        if g.status() != "available" {
            return Err(errors::invalid_replication_group_state_fault(format!(
                "Replication group {rg} is not in available state."
            )));
        }
        if g.info.global_replication_group_info.is_some() {
            return Err(combination(format!(
                "Replication group {rg} is already a member of a global replication group."
            )));
        }
        if g.engine() == EngineKind::Redis
            && super::clusters::version_cmp(&g.engine_version, "5.0.6") == std::cmp::Ordering::Less
        {
            return Err(combination("Global datastores require Redis OSS 5.0.6 or later."));
        }
        let node_type = g.info.cache_node_type.clone().unwrap_or_default();
        if node_type.starts_with("cache.t") {
            return Err(combination(format!("Global datastores are not supported for node type {node_type}.")));
        }
        Ok(t::GlobalReplicationGroup {
            global_replication_group_id: Some(id.clone()),
            global_replication_group_description: input.global_replication_group_description.clone(),
            status: Some("creating".into()),
            cache_node_type: g.info.cache_node_type.clone(),
            engine: Some(g.engine().as_str().into()),
            engine_version: Some(g.engine_version.clone()),
            members: None,
            cluster_enabled: Some(g.cluster_enabled()),
            global_node_groups: None,
            auth_token_enabled: g.info.auth_token_enabled,
            transit_encryption_enabled: g.info.transit_encryption_enabled,
            at_rest_encryption_enabled: g.info.at_rest_encryption_enabled,
            arn: Some(resource.clone()),
        })
    })?;
    let exists = with_globals(svc, ctx, |m| m.contains_key(&id));
    if exists {
        return Err(errors::global_replication_group_already_exists_fault(format!(
            "Global replication group {id} already exists."
        )));
    }
    let mut g = Global { info: info.clone(), members: vec![(ctx.region.clone(), rg.clone(), "PRIMARY".into())] };
    g.info.status = Some("primary-only".into());
    put(svc, ctx, g);
    set_member_info(svc, ctx, &ctx.region, &rg, Some((id.clone(), "PRIMARY")));
    svc.with_region(ctx, |r| set_tags(r, &resource, input.tags.clone()));
    Ok(t::CreateGlobalReplicationGroupResult { global_replication_group: Some(info) })
}

pub(crate) async fn describe(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeGlobalReplicationGroupsMessage,
) -> Result<t::DescribeGlobalReplicationGroupsResult, ServiceError> {
    let show = input.show_member_info == Some(true);
    let all: Vec<Global> = match &input.global_replication_group_id {
        Some(id) => vec![get(svc, ctx, id)?],
        None => with_globals(svc, ctx, |m| m.values().cloned().collect()),
    };
    ctx.authorize("elasticache:DescribeGlobalReplicationGroups", &global_arn(ctx, "*"), Default::default())?;
    let items: Vec<t::GlobalReplicationGroup> = all.iter().map(|g| render(svc, ctx, g, show)).collect();
    let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
    Ok(t::DescribeGlobalReplicationGroupsResult { marker, global_replication_groups: Some(page) })
}

fn authorize_global(ctx: &RequestContext, action: &str, g: &Global) -> Result<(), ServiceError> {
    ctx.authorize(&format!("elasticache:{action}"), g.info.arn.as_deref().unwrap_or_default(), Default::default())
}

pub(crate) async fn modify(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyGlobalReplicationGroupMessage,
) -> Result<t::ModifyGlobalReplicationGroupResult, ServiceError> {
    let id = input.global_replication_group_id.clone();
    let mut g = get(svc, ctx, &id)?;
    authorize_global(ctx, "ModifyGlobalReplicationGroup", &g)?;
    if !input.apply_immediately {
        return Err(invalid("ApplyImmediately must be true for ModifyGlobalReplicationGroup."));
    }
    if let Some(d) = &input.global_replication_group_description {
        g.info.global_replication_group_description = Some(d.clone());
    }
    if let Some(nt) = &input.cache_node_type {
        super::clusters::check_node_type(Some(nt))?;
        g.info.cache_node_type = Some(nt.clone());
    }
    let engine = EngineKind::parse(g.info.engine.as_deref().unwrap_or_default()).unwrap_or(EngineKind::Redis);
    let target_engine = super::clusters::engine_of(input.engine.as_deref(), engine)?;
    if target_engine != engine && !(engine == EngineKind::Redis && target_engine == EngineKind::Valkey) {
        return Err(combination(format!(
            "Cannot change engine from {} to {}.",
            engine.as_str(),
            target_engine.as_str()
        )));
    }
    if input.engine_version.is_some() || input.engine.is_some() {
        let v = super::clusters::version_of(target_engine, input.engine_version.as_deref())?;
        g.info.engine = Some(target_engine.as_str().into());
        g.info.engine_version = Some(v.version.into());
    }
    // Apply to every member group.
    for (region, rg, _) in g.members.clone() {
        let rctx = ctx_in(ctx, &region);
        let mut m = t::ModifyReplicationGroupMessage {
            replication_group_id: rg.clone(),
            apply_immediately: Some(true),
            cache_node_type: input.cache_node_type.clone(),
            automatic_failover_enabled: input.automatic_failover_enabled,
            ..Default::default()
        };
        if input.engine.is_some() || input.engine_version.is_some() {
            m.engine = g.info.engine.clone();
            m.engine_version = g.info.engine_version.clone();
        }
        if let Some(pg) = &input.cache_parameter_group_name {
            m.cache_parameter_group_name = Some(pg.clone());
        }
        if m.cache_node_type.is_some()
            || m.automatic_failover_enabled.is_some()
            || m.engine_version.is_some()
            || m.cache_parameter_group_name.is_some()
        {
            super::replication::modify(svc, &rctx, m).await?;
        }
    }
    put(svc, ctx, g.clone());
    Ok(t::ModifyGlobalReplicationGroupResult { global_replication_group: Some(render(svc, ctx, &g, false)) })
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteGlobalReplicationGroupMessage,
) -> Result<t::DeleteGlobalReplicationGroupResult, ServiceError> {
    let id = input.global_replication_group_id.clone();
    let g = get(svc, ctx, &id)?;
    authorize_global(ctx, "DeleteGlobalReplicationGroup", &g)?;
    if g.members.len() > 1 {
        return Err(errors::invalid_global_replication_group_state_fault(format!(
            "Global replication group {id} still has secondary members; disassociate them first."
        )));
    }
    if !input.retain_primary_replication_group {
        return Err(invalid("RetainPrimaryReplicationGroup must be true."));
    }
    for (region, rg, _) in &g.members {
        set_member_info(svc, ctx, region, rg, None);
    }
    with_globals(svc, ctx, |m| m.remove(&id));
    svc.with_region(ctx, |r| r.tags.remove(g.info.arn.as_deref().unwrap_or_default()));
    let mut shown = render(svc, ctx, &g, false);
    shown.status = Some("deleting".into());
    Ok(t::DeleteGlobalReplicationGroupResult { global_replication_group: Some(shown) })
}

pub(crate) async fn disassociate(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DisassociateGlobalReplicationGroupMessage,
) -> Result<t::DisassociateGlobalReplicationGroupResult, ServiceError> {
    let id = input.global_replication_group_id.clone();
    let mut g = get(svc, ctx, &id)?;
    authorize_global(ctx, "DisassociateGlobalReplicationGroup", &g)?;
    let rg = input.replication_group_id.to_ascii_lowercase();
    let pos = g
        .members
        .iter()
        .position(|(region, r, _)| r == &rg && region == &input.replication_group_region)
        .ok_or_else(|| super::replication::not_found(&rg))?;
    if g.members[pos].2 == "PRIMARY" {
        return Err(combination(
            "The primary replication group cannot be disassociated; delete the global replication group instead.",
        ));
    }
    g.members.remove(pos);
    if g.members.len() == 1 {
        g.info.status = Some("primary-only".into());
    }
    set_member_info(svc, ctx, &input.replication_group_region, &rg, None);
    let rctx = ctx_in(ctx, &input.replication_group_region);
    engine::link_global(svc, &rctx, &region_key(&rctx), &rg, None);
    put(svc, ctx, g.clone());
    Ok(t::DisassociateGlobalReplicationGroupResult { global_replication_group: Some(render(svc, ctx, &g, true)) })
}

pub(crate) async fn failover(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::FailoverGlobalReplicationGroupMessage,
) -> Result<t::FailoverGlobalReplicationGroupResult, ServiceError> {
    let id = input.global_replication_group_id.clone();
    let mut g = get(svc, ctx, &id)?;
    authorize_global(ctx, "FailoverGlobalReplicationGroup", &g)?;
    let rg = input.primary_replication_group_id.to_ascii_lowercase();
    let pos = g
        .members
        .iter()
        .position(|(region, r, _)| r == &rg && region == &input.primary_region)
        .ok_or_else(|| super::replication::not_found(&rg))?;
    if pos == 0 {
        return Err(combination(format!("Replication group {rg} is already the primary of {id}.")));
    }
    let mut new_primary = g.members.remove(pos);
    new_primary.2 = "PRIMARY".into();
    for m in g.members.iter_mut() {
        m.2 = "SECONDARY".into();
    }
    g.members.insert(0, new_primary);
    for (region, r, role) in &g.members {
        set_member_info(svc, ctx, region, r, Some((id.clone(), role.as_str())));
    }
    put(svc, ctx, g.clone());
    relink(svc, ctx, &g);
    Ok(t::FailoverGlobalReplicationGroupResult { global_replication_group: Some(render(svc, ctx, &g, true)) })
}

async fn reshard_members(
    svc: &ElastiCache,
    ctx: &RequestContext,
    g: &Global,
    count: i32,
    remove: Option<Vec<String>>,
    retain: Option<Vec<String>>,
    regional: Option<Vec<t::RegionalConfiguration>>,
) -> Result<(), ServiceError> {
    let gid = g.info.global_replication_group_id.clone().unwrap_or_default();
    let strip = |l: Option<Vec<String>>| {
        l.map(|v| v.into_iter().map(|x| x.strip_prefix(&format!("{gid}-")).map(str::to_string).unwrap_or(x)).collect())
    };
    let (remove, retain) = (strip(remove), strip(retain));
    for (region, rg, _) in &g.members {
        let rctx = ctx_in(ctx, region);
        let resharding = regional.as_ref().and_then(|l| {
            l.iter()
                .find(|c| c.replication_group_region == *region && c.replication_group_id.eq_ignore_ascii_case(rg))
                .map(|c| c.resharding_configuration.clone())
        });
        super::replication::modify_shards(
            svc,
            &rctx,
            t::ModifyReplicationGroupShardConfigurationMessage {
                replication_group_id: rg.clone(),
                node_group_count: count,
                apply_immediately: true,
                resharding_configuration: resharding,
                node_groups_to_remove: remove.clone(),
                node_groups_to_retain: retain.clone(),
            },
        )
        .await?;
    }
    Ok(())
}

fn check_cluster_mode(g: &Global, id: &str) -> Result<(), ServiceError> {
    if g.info.cluster_enabled != Some(true) {
        return Err(combination(format!("Global replication group {id} is not cluster mode enabled.")));
    }
    Ok(())
}

pub(crate) async fn increase_node_groups(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::IncreaseNodeGroupsInGlobalReplicationGroupMessage,
) -> Result<t::IncreaseNodeGroupsInGlobalReplicationGroupResult, ServiceError> {
    let id = input.global_replication_group_id.clone();
    let g = get(svc, ctx, &id)?;
    authorize_global(ctx, "IncreaseNodeGroupsInGlobalReplicationGroup", &g)?;
    check_cluster_mode(&g, &id)?;
    if !input.apply_immediately {
        return Err(invalid("ApplyImmediately must be true."));
    }
    reshard_members(svc, ctx, &g, input.node_group_count, None, None, input.regional_configurations.clone()).await?;
    let mut shown = render(svc, ctx, &g, false);
    shown.status = Some("modifying".into());
    Ok(t::IncreaseNodeGroupsInGlobalReplicationGroupResult { global_replication_group: Some(shown) })
}

pub(crate) async fn decrease_node_groups(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DecreaseNodeGroupsInGlobalReplicationGroupMessage,
) -> Result<t::DecreaseNodeGroupsInGlobalReplicationGroupResult, ServiceError> {
    let id = input.global_replication_group_id.clone();
    let g = get(svc, ctx, &id)?;
    authorize_global(ctx, "DecreaseNodeGroupsInGlobalReplicationGroup", &g)?;
    check_cluster_mode(&g, &id)?;
    if !input.apply_immediately {
        return Err(invalid("ApplyImmediately must be true."));
    }
    if input.global_node_groups_to_remove.is_none() && input.global_node_groups_to_retain.is_none() {
        return Err(combination("Either GlobalNodeGroupsToRemove or GlobalNodeGroupsToRetain must be specified."));
    }
    reshard_members(
        svc,
        ctx,
        &g,
        input.node_group_count,
        input.global_node_groups_to_remove.clone(),
        input.global_node_groups_to_retain.clone(),
        None,
    )
    .await?;
    let mut shown = render(svc, ctx, &g, false);
    shown.status = Some("modifying".into());
    Ok(t::DecreaseNodeGroupsInGlobalReplicationGroupResult { global_replication_group: Some(shown) })
}

pub(crate) async fn rebalance(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::RebalanceSlotsInGlobalReplicationGroupMessage,
) -> Result<t::RebalanceSlotsInGlobalReplicationGroupResult, ServiceError> {
    let id = input.global_replication_group_id.clone();
    let g = get(svc, ctx, &id)?;
    authorize_global(ctx, "RebalanceSlotsInGlobalReplicationGroup", &g)?;
    check_cluster_mode(&g, &id)?;
    if !input.apply_immediately {
        return Err(invalid("ApplyImmediately must be true."));
    }
    // Member groups always keep their slots evenly spread.
    Ok(t::RebalanceSlotsInGlobalReplicationGroupResult { global_replication_group: Some(render(svc, ctx, &g, false)) })
}
