//! Snapshots (backups) of Redis OSS and Valkey clusters and replication
//! groups. With real engines a snapshot holds the data (every key's `DUMP`
//! payload and TTL), restores into new clusters, and exports to S3 as RDB
//! files.

use mws_core::{RequestContext, ServiceError};

use super::*;
use crate::engine;
use crate::generated::{errors, types as t};
use crate::state::{RegionState, Snapshot, SnapshotData};
use crate::ElastiCache;

pub(crate) fn not_found(name: &str) -> ServiceError {
    errors::snapshot_not_found_fault(format!("Snapshot {name} not found."))
}

fn check_name(name: &str) -> Result<(), ServiceError> {
    let ok = !name.is_empty()
        && name.len() <= 255
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("Invalid snapshot name: {name}")))
    }
}

/// Start a snapshot of a replication group or cluster: record it as
/// `creating` (the caller starts the capture).
#[allow(clippy::too_many_arguments)]
pub(crate) fn start(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    r: &mut RegionState,
    name: &str,
    rg: Option<&str>,
    cluster: Option<&str>,
    source: &str,
    kms: Option<String>,
) -> Result<String, ServiceError> {
    check_name(name)?;
    if r.snapshots.contains_key(name) {
        return Err(errors::snapshot_already_exists_fault(format!("Snapshot {name} already exists.")));
    }
    if r.snapshots.len() >= 1000 {
        return Err(errors::snapshot_quota_exceeded_fault("Snapshot quota exceeded."));
    }
    let at = now(ctx);
    let mut info = t::Snapshot {
        snapshot_name: Some(name.into()),
        snapshot_status: Some("creating".into()),
        snapshot_source: Some(source.into()),
        arn: Some(arn(ctx, "snapshot", name)),
        kms_key_id: kms,
        ..Default::default()
    };
    let members: Vec<crate::state::Cluster> = match (rg, cluster) {
        (Some(g), _) => {
            r.clusters.values().filter(|c| c.info.replication_group_id.as_deref() == Some(g)).cloned().collect()
        }
        (None, Some(c)) => r.clusters.get(c).cloned().into_iter().collect(),
        _ => vec![],
    };
    let first = members.first().cloned().unwrap_or_default();
    if let Some(g) = rg.and_then(|g| r.replication_groups.get(g)) {
        info.replication_group_id = g.info.replication_group_id.clone();
        info.replication_group_description = g.info.description.clone();
        info.num_node_groups = Some(g.slots.len().max(1) as i32);
        info.automatic_failover = g.info.automatic_failover.clone();
        info.data_tiering = g.info.data_tiering.clone();
        info.durability = g.info.durability.clone();
        if info.kms_key_id.is_none() {
            info.kms_key_id = g.info.kms_key_id.clone();
        }
    } else {
        info.cache_cluster_id = cluster.map(str::to_string);
        info.replication_group_id = first.info.replication_group_id.clone();
        info.num_cache_nodes = first.info.num_cache_nodes;
    }
    info.cache_node_type = first.info.cache_node_type.clone();
    info.engine = first.info.engine.clone();
    info.engine_version = first.info.engine_version.clone();
    info.preferred_availability_zone = first.info.preferred_availability_zone.clone();
    info.cache_cluster_create_time = first.info.cache_cluster_create_time;
    info.preferred_maintenance_window = first.info.preferred_maintenance_window.clone();
    info.topic_arn = first.info.notification_configuration.as_ref().and_then(|n| n.topic_arn.clone());
    info.port = Some(first.port as i32);
    info.cache_parameter_group_name =
        first.info.cache_parameter_group.as_ref().and_then(|g| g.cache_parameter_group_name.clone());
    info.cache_subnet_group_name = first.info.cache_subnet_group_name.clone();
    info.vpc_id =
        first.info.cache_subnet_group_name.as_ref().and_then(|g| r.subnet_groups.get(g)).and_then(|g| g.vpc_id.clone());
    info.auto_minor_version_upgrade = first.info.auto_minor_version_upgrade;
    info.snapshot_retention_limit = first.info.snapshot_retention_limit;
    info.snapshot_window = first.info.snapshot_window.clone();
    let mut nodes = Vec::new();
    for c in members.iter().filter(|c| rg.is_none() || c.role.as_deref() == Some("primary")) {
        let ng = c.node_group_id.clone();
        let slots = ng
            .as_ref()
            .and_then(|n| rg.and_then(|g| r.replication_groups.get(g)).and_then(|g| g.slots.get(n).cloned()));
        nodes.push(t::NodeSnapshot {
            cache_cluster_id: Some(c.id().to_string()),
            node_group_id: ng.clone(),
            cache_node_id: Some("0001".into()),
            node_group_configuration: ng.map(|n| t::NodeGroupConfiguration {
                node_group_id: Some(n),
                slots,
                replica_count: None,
                primary_availability_zone: c.info.preferred_availability_zone.clone(),
                ..Default::default()
            }),
            cache_size: Some("0 MB".into()),
            cache_node_create_time: c.info.cache_cluster_create_time,
            snapshot_create_time: Some(at),
        });
    }
    info.node_snapshots = Some(nodes);
    r.snapshots.insert(name.to_string(), Snapshot { info, data: SnapshotData::default() });
    for c in &members {
        if let Some(c) = r.clusters.get_mut(c.id()) {
            if c.status() == "available" {
                c.info.cache_cluster_status = Some("snapshotting".into());
            }
        }
    }
    if let Some(g) = rg.and_then(|g| r.replication_groups.get_mut(g)) {
        if g.status() == "available" {
            g.info.status = Some("snapshotting".into());
        }
    }
    Ok(name.to_string())
}

/// A snapshot's capture finished.
pub(crate) fn finished(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    r: &mut RegionState,
    name: &str,
    data: SnapshotData,
    error: Option<String>,
) {
    let at = now(ctx).max(chrono::Utc::now());
    let Some(s) = r.snapshots.get_mut(name) else { return };
    let size = data.size_bytes();
    s.info.snapshot_status = Some(if error.is_some() { "failed" } else { "available" }.into());
    for (i, n) in s.info.node_snapshots.iter_mut().flatten().enumerate() {
        let bytes =
            data.shards.get(i).map(|e| e.iter().map(|x| (x.key.len() + x.dump.len()) as u64).sum::<u64>()).unwrap_or(0);
        n.cache_size = Some(format!("{} MB", bytes.div_ceil(1024 * 1024)));
    }
    let _ = size;
    s.data = data;
    let rg = s.info.replication_group_id.clone();
    let cluster = s.info.cache_cluster_id.clone();
    if let Some(g) = rg.as_deref().and_then(|g| r.replication_groups.get_mut(g)) {
        if g.status() == "snapshotting" {
            g.info.status = Some("available".into());
        }
    }
    let ids: Vec<String> = r
        .clusters
        .values()
        .filter(|c| c.info.replication_group_id == rg && rg.is_some() || Some(c.id().to_string()) == cluster)
        .map(|c| c.id().to_string())
        .collect();
    for id in ids {
        if let Some(c) = r.clusters.get_mut(&id) {
            if c.status() == "snapshotting" {
                c.info.cache_cluster_status = Some("available".into());
            }
        }
    }
    let (source, kind) = match (&rg, &cluster) {
        (_, Some(c)) => (c.clone(), "cache cluster"),
        (Some(g), None) => (g.clone(), "replication group"),
        _ => (String::new(), "cache cluster"),
    };
    let source_type = if kind == "cache cluster" { "cache-cluster" } else { "replication-group" };
    match error {
        None => r.event(
            &source,
            source_type,
            format!("Snapshot succeeded for snapshot with ID '{name}' of {kind} with ID '{source}'"),
            at,
        ),
        Some(e) => r.event(&source, source_type, format!("Snapshot failed for snapshot with ID '{name}': {e}"), at),
    }
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateSnapshotMessage,
) -> Result<t::CreateSnapshotResult, ServiceError> {
    let key = region_key(ctx);
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "snapshot", &input.snapshot_name);
    authorize_create(ctx, "CreateSnapshot", &resource, &tags, Default::default())?;
    let rg = input.replication_group_id.as_deref().map(str::to_ascii_lowercase);
    let cluster = input.cache_cluster_id.as_deref().map(str::to_ascii_lowercase);
    let (info, sources) = svc.with_region(ctx, |r| {
        match (&rg, &cluster) {
            (Some(_), Some(_)) => {
                return Err(combination("Only one of ReplicationGroupId or CacheClusterId can be specified."))
            }
            (None, None) => return Err(invalid("Either ReplicationGroupId or CacheClusterId must be specified.")),
            (Some(g), None) => {
                let grp = r.replication_groups.get(g).ok_or_else(|| super::replication::not_found(g))?;
                if grp.status() != "available" {
                    return Err(errors::invalid_replication_group_state_fault(format!(
                        "Replication group {g} is not in available state."
                    )));
                }
            }
            (None, Some(c)) => {
                let cl = r.clusters.get(c).ok_or_else(|| super::clusters::not_found(c))?;
                if !cl.engine().is_redis_like() {
                    return Err(errors::snapshot_feature_not_supported_fault(
                        "Snapshots are not supported for the memcached engine.",
                    ));
                }
                if let Some(g) = cl.info.replication_group_id.as_deref() {
                    if r.replication_groups.get(g).is_some_and(|g| g.cluster_enabled()) {
                        return Err(combination(
                            "Snapshots of cluster mode enabled replication groups must name the ReplicationGroupId.",
                        ));
                    }
                }
                if cl.status() != "available" {
                    return Err(errors::invalid_cache_cluster_state_fault(format!(
                        "Cache cluster {c} is not in available state."
                    )));
                }
            }
        }
        let sources = engine::snapshot_sources(r, rg.as_deref(), cluster.as_deref());
        start(
            svc,
            ctx,
            r,
            &input.snapshot_name,
            rg.as_deref(),
            cluster.as_deref(),
            "manual",
            input.kms_key_id.clone(),
        )?;
        set_tags(r, &resource, input.tags.clone());
        Ok((r.snapshots.get(&input.snapshot_name).map(|s| s.info.clone()).unwrap_or_default(), sources))
    })?;
    engine::snapshot(svc, ctx, &key, &input.snapshot_name, sources, vec![]);
    Ok(t::CreateSnapshotResult { snapshot: Some(info) })
}

pub(crate) async fn copy(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CopySnapshotMessage,
) -> Result<t::CopySnapshotResult, ServiceError> {
    let source = input.source_snapshot_name.clone();
    let target = input.target_snapshot_name.clone();
    check_name(&target)?;
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "snapshot", &target);
    let src = svc.with_region(ctx, |r| {
        let s = r.snapshots.get(&source).cloned().ok_or_else(|| not_found(&source))?;
        authorize(ctx, r, "CopySnapshot", s.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if s.info.snapshot_status.as_deref() != Some("available") {
            return Err(errors::invalid_snapshot_state_fault(format!("Snapshot {source} is not in available state.")));
        }
        Ok(s)
    })?;
    if let Some(bucket) = input.target_bucket.as_deref().filter(|b| !b.is_empty()) {
        // Export: one RDB file per shard.
        let exporter = svc.bucket().ok_or_else(|| invalid(format!("The S3 bucket {bucket} does not exist.")))?;
        let now_ms = now(ctx).timestamp_millis();
        let shards = if src.data.shards.is_empty() { vec![vec![]] } else { src.data.shards.clone() };
        for (i, shard) in shards.iter().enumerate() {
            let entries: Vec<&crate::state::Entry> = shard.iter().collect();
            let body = engine::rdb_file(&entries, now_ms);
            exporter.export(
                ctx,
                bucket,
                &format!("{target}-{:04}.rdb", i + 1),
                body,
                src.info.arn.as_deref().unwrap_or_default(),
            )?;
        }
        let mut info = src.info.clone();
        info.snapshot_name = Some(target);
        return Ok(t::CopySnapshotResult { snapshot: Some(info) });
    }
    authorize_create(ctx, "CopySnapshot", &resource, &tags, Default::default())?;
    svc.with_region(ctx, |r| {
        if r.snapshots.contains_key(&target) {
            return Err(errors::snapshot_already_exists_fault(format!("Snapshot {target} already exists.")));
        }
        let mut copy = src.clone();
        copy.info.snapshot_name = Some(target.clone());
        copy.info.snapshot_source = Some("manual".into());
        copy.info.arn = Some(resource.clone());
        if let Some(k) = &input.kms_key_id {
            copy.info.kms_key_id = Some(k.clone());
        }
        r.snapshots.insert(target.clone(), copy.clone());
        set_tags(r, &resource, input.tags.clone());
        Ok(t::CopySnapshotResult { snapshot: Some(copy.info) })
    })
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteSnapshotMessage,
) -> Result<t::DeleteSnapshotResult, ServiceError> {
    let name = input.snapshot_name.clone();
    svc.with_region(ctx, |r| {
        let s = r.snapshots.get(&name).ok_or_else(|| not_found(&name))?;
        authorize(ctx, r, "DeleteSnapshot", s.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if s.info.snapshot_status.as_deref() == Some("creating") {
            return Err(errors::invalid_snapshot_state_fault(format!("Snapshot {name} is not in available state.")));
        }
        let mut s = r.snapshots.remove(&name).unwrap_or_default();
        r.tags.remove(s.info.arn.as_deref().unwrap_or_default());
        s.info.snapshot_status = Some("deleting".into());
        Ok(t::DeleteSnapshotResult { snapshot: Some(s.info) })
    })
}

pub(crate) async fn describe(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeSnapshotsMessage,
) -> Result<t::DescribeSnapshotsListMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        ctx.authorize("elasticache:DescribeSnapshots", &arn(ctx, "snapshot", "*"), Default::default())?;
        if let Some(n) = &input.snapshot_name {
            if !r.snapshots.contains_key(n) {
                return Err(not_found(n));
            }
        }
        if let Some(g) = &input.replication_group_id {
            if !r.replication_groups.contains_key(&g.to_ascii_lowercase()) {
                return Err(super::replication::not_found(g));
            }
        }
        if let Some(c) = &input.cache_cluster_id {
            if !r.clusters.contains_key(&c.to_ascii_lowercase()) {
                return Err(super::clusters::not_found(c));
            }
        }
        let show = input.show_node_group_config == Some(true);
        let items: Vec<t::Snapshot> = r
            .snapshots
            .values()
            .filter(|s| input.snapshot_name.as_deref().is_none_or(|n| s.info.snapshot_name.as_deref() == Some(n)))
            .filter(|s| {
                input
                    .replication_group_id
                    .as_deref()
                    .is_none_or(|g| s.info.replication_group_id.as_deref() == Some(&g.to_ascii_lowercase()))
            })
            .filter(|s| {
                input.cache_cluster_id.as_deref().is_none_or(|c| {
                    let c = c.to_ascii_lowercase();
                    s.info.cache_cluster_id.as_deref() == Some(&c)
                        || s.info.node_snapshots.iter().flatten().any(|n| n.cache_cluster_id.as_deref() == Some(&c))
                })
            })
            .filter(|s| {
                input.snapshot_source.as_deref().is_none_or(|src| s.info.snapshot_source.as_deref() == Some(src))
            })
            .map(|s| {
                let mut info = s.info.clone();
                if !show {
                    for n in info.node_snapshots.iter_mut().flatten() {
                        n.node_group_configuration = None;
                    }
                }
                info
            })
            .collect();
        let max = match input.max_records {
            None => 50,
            Some(m) if (20..=50).contains(&m) => m as usize,
            Some(_) => return Err(invalid("Invalid value for parameter MaxRecords: must be between 20 and 50.")),
        };
        let (page, marker) = page_with(items, input.marker.as_deref(), max, "Marker")?;
        Ok(t::DescribeSnapshotsListMessage { marker, snapshots: Some(page) })
    })
}
