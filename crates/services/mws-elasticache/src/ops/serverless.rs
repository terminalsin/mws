//! Serverless caches, their snapshots, and migrations into them.

use mws_core::{RequestContext, ServiceError};

use super::*;
use crate::backend::EngineKind;
use crate::engine;
use crate::generated::{errors, types as t};
use crate::state::{NodeRuntime, RegionState, Serverless, ServerlessSnapshot, SnapshotData};
use crate::ElastiCache;

fn not_found(name: &str) -> ServiceError {
    errors::serverless_cache_not_found_fault(format!("Serverless cache {name} not found."))
}

fn snapshot_not_found(name: &str) -> ServiceError {
    errors::serverless_cache_snapshot_not_found_fault(format!("Serverless cache snapshot {name} not found."))
}

fn proxy_key(key: &str, name: &str) -> String {
    format!("{key}/serverless/{name}/reader")
}

/// `(major, full)` engine version of a serverless cache.
fn versions(engine: EngineKind, major: Option<&str>) -> Result<(String, String), ServiceError> {
    let pick = |m: &str, f: &str| Ok((m.to_string(), f.to_string()));
    match (engine, major.unwrap_or_default()) {
        (EngineKind::Redis, "" | "7") => pick("7", "7.1"),
        (EngineKind::Valkey, "" | "8") => pick("8", "8.0"),
        (EngineKind::Valkey, "7") => pick("7", "7.2"),
        (EngineKind::Memcached, "" | "1.6") => pick("1.6", "1.6"),
        (e, m) => Err(invalid(format!("Unsupported major engine version {m} for {}.", e.as_str()))),
    }
}

fn check_limits(l: &Option<t::CacheUsageLimits>) -> Result<(), ServiceError> {
    let Some(l) = l else { return Ok(()) };
    if let Some(d) = &l.data_storage {
        if d.unit != "GB" {
            return Err(invalid("DataStorage Unit must be GB."));
        }
        for v in [d.maximum, d.minimum].into_iter().flatten() {
            if !(1..=5000).contains(&v) {
                return Err(invalid("DataStorage limits must be between 1 and 5000 GB."));
            }
        }
    }
    if let Some(e) = &l.ecpu_per_second {
        for v in [e.maximum, e.minimum].into_iter().flatten() {
            if !(1000..=15_000_000).contains(&v) {
                return Err(invalid("ECPUPerSecond limits must be between 1000 and 15000000."));
            }
        }
    }
    Ok(())
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateServerlessCacheRequest,
) -> Result<t::CreateServerlessCacheResponse, ServiceError> {
    let name = identifier("ServerlessCacheName", &input.serverless_cache_name, 40)?;
    let engine = super::clusters::engine_of(Some(&input.engine), EngineKind::Valkey)?;
    let (major, full) = versions(engine, input.major_engine_version.as_deref())?;
    check_limits(&input.cache_usage_limits)?;
    if let Some(n) = input.snapshot_retention_limit {
        if !(0..=35).contains(&n) {
            return Err(invalid("SnapshotRetentionLimit must be between 0 and 35."));
        }
    }
    if engine == EngineKind::Memcached && (input.user_group_id.is_some() || input.snapshot_arns_to_restore.is_some()) {
        return Err(combination("User groups and snapshots are not supported for memcached serverless caches."));
    }
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "serverlesscache", &name);
    let limits = input.cache_usage_limits.clone();
    authorize_create(
        ctx,
        "CreateServerlessCache",
        &resource,
        &tags,
        cond(&[
            ("EngineType", Some(engine.as_str().into())),
            ("EngineVersion", Some(major.clone())),
            ("KmsKeyId", input.kms_key_id.clone()),
            (
                "DataStorageMaximum",
                limits.as_ref().and_then(|l| l.data_storage.as_ref()).and_then(|d| d.maximum).map(|v| v.to_string()),
            ),
            (
                "ECPUPerSecondMaximum",
                limits.as_ref().and_then(|l| l.ecpu_per_second.as_ref()).and_then(|e| e.maximum).map(|v| v.to_string()),
            ),
            ("UserGroupId", input.user_group_id.clone()),
        ]),
    )?;
    let key = region_key(ctx);
    let account = crate::account_of(ctx);
    let shown = svc.with_region(ctx, |r| {
        if r.serverless.contains_key(&name) {
            return Err(errors::serverless_cache_already_exists_fault(format!(
                "Serverless cache {name} already exists."
            )));
        }
        if r.serverless.len() >= 40 {
            return Err(errors::serverless_cache_quota_for_customer_exceeded_fault("Serverless cache quota exceeded."));
        }
        if let Some(ug) = &input.user_group_id {
            r.user_groups.get(ug).ok_or_else(|| super::users::group_not_found(ug))?;
        }
        let seed = match input.snapshot_arns_to_restore.as_ref().and_then(|a| a.first()) {
            Some(a) => {
                let s = r
                    .serverless_snapshots
                    .values()
                    .find(|s| {
                        s.info.arn.as_deref() == Some(a) || s.info.serverless_cache_snapshot_name.as_deref() == Some(a)
                    })
                    .ok_or_else(|| snapshot_not_found(a))?;
                Some(s.info.serverless_cache_snapshot_name.clone().unwrap_or_default())
            }
            None => None,
        };
        let subnets = match &input.subnet_ids {
            Some(ids) if !ids.is_empty() => {
                if let Some(n) = svc.network() {
                    for id in ids {
                        n.subnet(&account, &ctx.region, id)
                            .ok_or_else(|| errors::invalid_subnet(format!("The subnet ID {id} does not exist")))?;
                    }
                }
                ids.clone()
            }
            _ => svc
                .network()
                .map(|n| n.default_subnets(&account, &ctx.region).into_iter().map(|s| s.subnet_id).take(3).collect())
                .unwrap_or_default(),
        };
        let sgs = input.security_group_ids.clone().unwrap_or_default();
        let default_port = if engine == EngineKind::Memcached { 11211 } else { 6379 };
        let port = alloc_port(svc, default_port);
        let reader_port = if engine == EngineKind::Memcached {
            0
        } else if svc.runs_engines() {
            svc.proxies().open(&proxy_key(&key, &name), &svc.options().bind_address, 0).unwrap_or(0)
        } else {
            6380
        };
        let info = t::ServerlessCache {
            serverless_cache_name: Some(name.clone()),
            description: input.description.clone(),
            create_time: Some(now(ctx)),
            status: Some("creating".into()),
            engine: Some(engine.as_str().into()),
            major_engine_version: Some(major.clone()),
            full_engine_version: Some(full.clone()),
            cache_usage_limits: input.cache_usage_limits.clone(),
            kms_key_id: input.kms_key_id.clone(),
            storage_encryption_type: None,
            security_group_ids: Some(sgs),
            endpoint: Some(endpoint(svc, port)),
            reader_endpoint: (reader_port != 0).then(|| endpoint(svc, reader_port)),
            arn: Some(resource.clone()),
            user_group_id: input.user_group_id.clone(),
            subnet_ids: Some(subnets),
            snapshot_retention_limit: (engine != EngineKind::Memcached)
                .then(|| input.snapshot_retention_limit.unwrap_or(0)),
            daily_snapshot_time: (engine != EngineKind::Memcached)
                .then(|| input.daily_snapshot_time.clone().unwrap_or_else(|| "04:00".into())),
            network_type: input.network_type.clone(),
            connection_type: input.connection_type.clone(),
            migration: None,
        };
        r.serverless.insert(
            name.clone(),
            Serverless {
                info: info.clone(),
                node: NodeRuntime { handle: None, port, peer: None },
                reader_port,
                seed_snapshot: seed,
                internal_password: engine.is_redis_like().then(random_password),
            },
        );
        if let Some(ug) = &input.user_group_id {
            if let Some(g) = r.user_groups.get_mut(ug) {
                g.serverless_caches.get_or_insert_with(Vec::new).push(name.clone());
            }
        }
        set_tags(r, &resource, input.tags.clone());
        Ok(info)
    })?;
    engine::start_serverless(svc, ctx, &key, &name);
    Ok(t::CreateServerlessCacheResponse { serverless_cache: Some(shown) })
}

pub(crate) fn became_available(svc: &ElastiCache, ctx: &RequestContext, r: &mut RegionState, name: &str) {
    let Some(c) = r.serverless.get_mut(name) else { return };
    c.info.status = Some("available".into());
    if svc.runs_engines() && c.reader_port != 0 {
        let key = region_key(ctx);
        svc.proxies().set_targets(&proxy_key(&key, name), vec![(engine::connect_host(svc), c.node.port)]);
    }
    let at = now(ctx).max(chrono::Utc::now());
    r.event(name, "serverless-cache", format!("Serverless cache {name} created"), at);
}

pub(crate) async fn describe(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeServerlessCachesRequest,
) -> Result<t::DescribeServerlessCachesResponse, ServiceError> {
    svc.with_region(ctx, |r| {
        let items: Vec<t::ServerlessCache> = match input.serverless_cache_name.as_deref() {
            Some(n) => {
                let n = n.to_ascii_lowercase();
                let c = r.serverless.get(&n).ok_or_else(|| not_found(&n))?;
                authorize(
                    ctx,
                    r,
                    "DescribeServerlessCaches",
                    c.info.arn.as_deref().unwrap_or_default(),
                    Default::default(),
                )?;
                vec![c.info.clone()]
            }
            None => {
                ctx.authorize(
                    "elasticache:DescribeServerlessCaches",
                    &arn(ctx, "serverlesscache", "*"),
                    Default::default(),
                )?;
                r.serverless.values().map(|c| c.info.clone()).collect()
            }
        };
        let max = input.max_results.map(|m| m.clamp(1, 100) as usize).unwrap_or(50);
        let (page, next) = page_with(items, input.next_token.as_deref(), max, "NextToken")?;
        Ok(t::DescribeServerlessCachesResponse { next_token: next, serverless_caches: Some(page) })
    })
}

pub(crate) async fn modify(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyServerlessCacheRequest,
) -> Result<t::ModifyServerlessCacheResponse, ServiceError> {
    let name = input.serverless_cache_name.to_ascii_lowercase();
    check_limits(&input.cache_usage_limits)?;
    let (shown, commands, node) = svc.with_region(ctx, |r| {
        let c = r.serverless.get(&name).cloned().ok_or_else(|| not_found(&name))?;
        authorize(ctx, r, "ModifyServerlessCache", c.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if c.info.status.as_deref() != Some("available") {
            return Err(errors::invalid_serverless_cache_state_fault(format!(
                "Serverless cache {name} is not in available state."
            )));
        }
        let mut c = c;
        let mut commands = Vec::new();
        if let Some(d) = &input.description {
            c.info.description = Some(d.clone());
        }
        if input.cache_usage_limits.is_some() {
            c.info.cache_usage_limits = input.cache_usage_limits.clone();
        }
        if let Some(sgs) = &input.security_group_ids {
            c.info.security_group_ids = Some(sgs.clone());
        }
        if let Some(v) = input.snapshot_retention_limit {
            if !(0..=35).contains(&v) {
                return Err(invalid("SnapshotRetentionLimit must be between 0 and 35."));
            }
            c.info.snapshot_retention_limit = Some(v);
        }
        if let Some(t) = &input.daily_snapshot_time {
            c.info.daily_snapshot_time = Some(t.clone());
        }
        let engine = EngineKind::parse(c.info.engine.as_deref().unwrap_or_default()).unwrap_or(EngineKind::Valkey);
        if input.engine.is_some() || input.major_engine_version.is_some() {
            let target = super::clusters::engine_of(input.engine.as_deref(), engine)?;
            if target != engine && !(engine == EngineKind::Redis && target == EngineKind::Valkey) {
                return Err(combination(format!(
                    "Cannot change engine from {} to {}.",
                    engine.as_str(),
                    target.as_str()
                )));
            }
            let (major, full) = versions(target, input.major_engine_version.as_deref())?;
            c.info.engine = Some(target.as_str().into());
            c.info.major_engine_version = Some(major);
            c.info.full_engine_version = Some(full);
        }
        let old_group = c.info.user_group_id.clone();
        if input.remove_user_group == Some(true) {
            c.info.user_group_id = None;
        }
        if let Some(ug) = &input.user_group_id {
            r.user_groups.get(ug).ok_or_else(|| super::users::group_not_found(ug))?;
            c.info.user_group_id = Some(ug.clone());
        }
        if c.info.user_group_id != old_group {
            for g in old_group.iter() {
                if let Some(u) = r.user_groups.get_mut(g) {
                    if let Some(l) = u.serverless_caches.as_mut() {
                        l.retain(|x| x != &name);
                    }
                }
            }
            if let Some(g) = c.info.user_group_id.clone() {
                if let Some(u) = r.user_groups.get_mut(&g) {
                    u.serverless_caches.get_or_insert_with(Vec::new).push(name.clone());
                }
            }
            commands.extend(super::users::reset_acl_commands(r, old_group.as_slice(), c.info.user_group_id.as_slice()));
            commands.extend(super::users::acl_commands(r, c.info.user_group_id.as_slice()));
        }
        let node = c.node.handle.is_some().then(|| (c.node.port, engine::serverless_auth(&c)));
        r.serverless.insert(name.clone(), c.clone());
        Ok((c.info, commands, node))
    })?;
    if let Some(n) = node {
        engine::run_everywhere(svc, vec![n], commands);
    }
    Ok(t::ModifyServerlessCacheResponse { serverless_cache: Some(shown) })
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteServerlessCacheRequest,
) -> Result<t::DeleteServerlessCacheResponse, ServiceError> {
    let name = input.serverless_cache_name.to_ascii_lowercase();
    let key = region_key(ctx);
    let final_snapshot = input.final_snapshot_name.clone();
    if let Some(snap) = &final_snapshot {
        create_snapshot(
            svc,
            ctx,
            t::CreateServerlessCacheSnapshotRequest {
                serverless_cache_snapshot_name: snap.clone(),
                serverless_cache_name: name.clone(),
                ..Default::default()
            },
        )
        .await?;
    }
    let (shown, handle) = svc.with_region(ctx, |r| {
        let c = r.serverless.get(&name).cloned().ok_or_else(|| not_found(&name))?;
        authorize(ctx, r, "DeleteServerlessCache", c.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if !matches!(c.info.status.as_deref(), Some("available" | "create-failed")) {
            return Err(errors::invalid_serverless_cache_state_fault(format!(
                "Serverless cache {name} is not in available state."
            )));
        }
        if let Some(ug) = &c.info.user_group_id {
            if let Some(u) = r.user_groups.get_mut(ug) {
                if let Some(l) = u.serverless_caches.as_mut() {
                    l.retain(|x| x != &name);
                }
            }
        }
        r.serverless.remove(&name);
        r.tags.remove(c.info.arn.as_deref().unwrap_or_default());
        let mut info = c.info;
        info.status = Some("deleting".into());
        Ok((info, c.node.handle))
    })?;
    svc.proxies().close(&proxy_key(&key, &name));
    if let Some(h) = handle {
        let svc = svc.clone();
        tokio::spawn(async move {
            // Let a final snapshot read the data first.
            if let Some(snap) = final_snapshot {
                for _ in 0..600 {
                    let done = svc
                        .with_existing(&key, |r| {
                            r.serverless_snapshots
                                .get(&snap)
                                .is_none_or(|s| s.info.status.as_deref() != Some("creating"))
                        })
                        .unwrap_or(true);
                    if done {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            let _ = svc.backend().terminate(&h).await;
        });
    }
    Ok(t::DeleteServerlessCacheResponse { serverless_cache: Some(shown) })
}

// ---- snapshots ------------------------------------------------------------------

pub(crate) fn snapshot_finished(r: &mut RegionState, name: &str, data: SnapshotData, error: Option<String>) {
    if let Some(s) = r.serverless_snapshots.get_mut(name) {
        s.info.status = Some(if error.is_some() { "failed" } else { "available" }.into());
        s.info.bytes_used_for_cache = Some(data.size_bytes().to_string());
        s.data = data;
    }
}

pub(crate) async fn create_snapshot(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateServerlessCacheSnapshotRequest,
) -> Result<t::CreateServerlessCacheSnapshotResponse, ServiceError> {
    let snap = identifier("ServerlessCacheSnapshotName", &input.serverless_cache_snapshot_name, 255)?;
    let cache = input.serverless_cache_name.to_ascii_lowercase();
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "serverlesscachesnapshot", &snap);
    authorize_create(ctx, "CreateServerlessCacheSnapshot", &resource, &tags, Default::default())?;
    let key = region_key(ctx);
    let info = svc.with_region(ctx, |r| {
        let c = r.serverless.get(&cache).ok_or_else(|| not_found(&cache))?;
        if c.info.engine.as_deref() == Some("memcached") {
            return Err(combination("Snapshots are not supported for memcached serverless caches."));
        }
        if c.info.status.as_deref() != Some("available") {
            return Err(errors::invalid_serverless_cache_state_fault(format!(
                "Serverless cache {cache} is not in available state."
            )));
        }
        if r.serverless_snapshots.contains_key(&snap) {
            return Err(errors::serverless_cache_snapshot_already_exists_fault(format!(
                "Serverless cache snapshot {snap} already exists."
            )));
        }
        if r.serverless_snapshots.len() >= 1000 {
            return Err(errors::serverless_cache_snapshot_quota_exceeded_fault(
                "Serverless cache snapshot quota exceeded.",
            ));
        }
        let info = t::ServerlessCacheSnapshot {
            serverless_cache_snapshot_name: Some(snap.clone()),
            arn: Some(resource.clone()),
            kms_key_id: input.kms_key_id.clone().or(c.info.kms_key_id.clone()),
            snapshot_type: Some("manual".into()),
            status: Some("creating".into()),
            create_time: Some(now(ctx)),
            expiry_time: None,
            bytes_used_for_cache: Some("0".into()),
            serverless_cache_configuration: Some(t::ServerlessCacheConfiguration {
                serverless_cache_name: Some(cache.clone()),
                engine: c.info.engine.clone(),
                major_engine_version: c.info.major_engine_version.clone(),
            }),
        };
        r.serverless_snapshots
            .insert(snap.clone(), ServerlessSnapshot { info: info.clone(), data: Default::default() });
        set_tags(r, &resource, input.tags.clone());
        Ok(info)
    })?;
    engine::serverless_snapshot(svc, ctx, &key, &snap);
    Ok(t::CreateServerlessCacheSnapshotResponse { serverless_cache_snapshot: Some(info) })
}

pub(crate) async fn copy_snapshot(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CopyServerlessCacheSnapshotRequest,
) -> Result<t::CopyServerlessCacheSnapshotResponse, ServiceError> {
    let src = input.source_serverless_cache_snapshot_name.clone();
    let target = identifier("TargetServerlessCacheSnapshotName", &input.target_serverless_cache_snapshot_name, 255)?;
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "serverlesscachesnapshot", &target);
    authorize_create(ctx, "CopyServerlessCacheSnapshot", &resource, &tags, Default::default())?;
    svc.with_region(ctx, |r| {
        let s = r.serverless_snapshots.get(&src).cloned().ok_or_else(|| snapshot_not_found(&src))?;
        if s.info.status.as_deref() != Some("available") {
            return Err(errors::invalid_serverless_cache_snapshot_state_fault(format!(
                "Serverless cache snapshot {src} is not in available state."
            )));
        }
        if r.serverless_snapshots.contains_key(&target) {
            return Err(errors::serverless_cache_snapshot_already_exists_fault(format!(
                "Serverless cache snapshot {target} already exists."
            )));
        }
        let mut copy = s;
        copy.info.serverless_cache_snapshot_name = Some(target.clone());
        copy.info.arn = Some(resource.clone());
        copy.info.snapshot_type = Some("manual".into());
        copy.info.create_time = Some(now(ctx));
        if let Some(k) = &input.kms_key_id {
            copy.info.kms_key_id = Some(k.clone());
        }
        r.serverless_snapshots.insert(target.clone(), copy.clone());
        set_tags(r, &resource, input.tags.clone());
        Ok(t::CopyServerlessCacheSnapshotResponse { serverless_cache_snapshot: Some(copy.info) })
    })
}

pub(crate) async fn delete_snapshot(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteServerlessCacheSnapshotRequest,
) -> Result<t::DeleteServerlessCacheSnapshotResponse, ServiceError> {
    let name = input.serverless_cache_snapshot_name;
    svc.with_region(ctx, |r| {
        let s = r.serverless_snapshots.get(&name).ok_or_else(|| snapshot_not_found(&name))?;
        authorize(
            ctx,
            r,
            "DeleteServerlessCacheSnapshot",
            s.info.arn.as_deref().unwrap_or_default(),
            Default::default(),
        )?;
        if s.info.status.as_deref() == Some("creating") {
            return Err(errors::invalid_serverless_cache_snapshot_state_fault(format!(
                "Serverless cache snapshot {name} is not in available state."
            )));
        }
        let mut s = r.serverless_snapshots.remove(&name).unwrap_or_default();
        r.tags.remove(s.info.arn.as_deref().unwrap_or_default());
        s.info.status = Some("deleting".into());
        Ok(t::DeleteServerlessCacheSnapshotResponse { serverless_cache_snapshot: Some(s.info) })
    })
}

pub(crate) async fn describe_snapshots(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeServerlessCacheSnapshotsRequest,
) -> Result<t::DescribeServerlessCacheSnapshotsResponse, ServiceError> {
    svc.with_region(ctx, |r| {
        ctx.authorize(
            "elasticache:DescribeServerlessCacheSnapshots",
            &arn(ctx, "serverlesscachesnapshot", "*"),
            Default::default(),
        )?;
        if let Some(n) = &input.serverless_cache_snapshot_name {
            if !r.serverless_snapshots.contains_key(n) {
                return Err(snapshot_not_found(n));
            }
        }
        if let Some(c) = &input.serverless_cache_name {
            if !r.serverless.contains_key(&c.to_ascii_lowercase()) {
                return Err(not_found(c));
            }
        }
        let items: Vec<t::ServerlessCacheSnapshot> = r
            .serverless_snapshots
            .values()
            .filter(|s| {
                input
                    .serverless_cache_snapshot_name
                    .as_deref()
                    .is_none_or(|n| s.info.serverless_cache_snapshot_name.as_deref() == Some(n))
            })
            .filter(|s| {
                input.serverless_cache_name.as_deref().is_none_or(|c| {
                    s.info.serverless_cache_configuration.as_ref().and_then(|x| x.serverless_cache_name.as_deref())
                        == Some(&c.to_ascii_lowercase())
                })
            })
            .filter(|s| input.snapshot_type.as_deref().is_none_or(|ty| s.info.snapshot_type.as_deref() == Some(ty)))
            .map(|s| s.info.clone())
            .collect();
        let max = input.max_results.map(|m| m.clamp(1, 50) as usize).unwrap_or(50);
        let (page, next) = page_with(items, input.next_token.as_deref(), max, "NextToken")?;
        Ok(t::DescribeServerlessCacheSnapshotsResponse { next_token: next, serverless_cache_snapshots: Some(page) })
    })
}

pub(crate) async fn export_snapshot(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ExportServerlessCacheSnapshotRequest,
) -> Result<t::ExportServerlessCacheSnapshotResponse, ServiceError> {
    let name = input.serverless_cache_snapshot_name.clone();
    let s = svc.with_region(ctx, |r| {
        let s = r.serverless_snapshots.get(&name).cloned().ok_or_else(|| snapshot_not_found(&name))?;
        authorize(
            ctx,
            r,
            "ExportServerlessCacheSnapshot",
            s.info.arn.as_deref().unwrap_or_default(),
            Default::default(),
        )?;
        if s.info.status.as_deref() != Some("available") {
            return Err(errors::invalid_serverless_cache_snapshot_state_fault(format!(
                "Serverless cache snapshot {name} is not in available state."
            )));
        }
        Ok(s)
    })?;
    let exporter =
        svc.bucket().ok_or_else(|| invalid(format!("The S3 bucket {} does not exist.", input.s3_bucket_name)))?;
    let entries: Vec<&crate::state::Entry> = s.data.shards.iter().flatten().collect();
    let body = engine::rdb_file(&entries, now(ctx).timestamp_millis());
    exporter.export(
        ctx,
        &input.s3_bucket_name,
        &format!("{name}-0001.rdb"),
        body,
        s.info.arn.as_deref().unwrap_or_default(),
    )?;
    Ok(t::ExportServerlessCacheSnapshotResponse { serverless_cache_snapshot: Some(s.info) })
}

// ---- migration into a serverless cache ------------------------------------------------

fn migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    name: &str,
    action: &str,
    f: impl FnOnce(&mut Serverless) -> Result<(), ServiceError>,
) -> Result<t::ServerlessCache, ServiceError> {
    svc.with_region(ctx, |r| {
        let c = r.serverless.get(name).cloned().ok_or_else(|| not_found(name))?;
        authorize(ctx, r, action, c.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        let c = r.serverless.get_mut(name).expect("checked");
        f(c)?;
        Ok(c.info.clone())
    })
}

fn under_migration(c: &Serverless) -> bool {
    c.info.migration.as_ref().is_some_and(|m| !matches!(m.status.as_deref(), Some("completed" | "stopped")))
}

pub(crate) async fn prepare_migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::PrepareMigrationRequest,
) -> Result<t::PrepareMigrationResponse, ServiceError> {
    let name = input.serverless_cache_name.to_ascii_lowercase();
    if input.customer_node_endpoint_list.is_empty() {
        return Err(invalid("At least one customer node endpoint must be specified."));
    }
    let info = migration(svc, ctx, &name, "PrepareMigration", |c| {
        if under_migration(c) {
            return Err(errors::serverless_cache_already_under_migration_fault(format!(
                "Serverless cache {name} is already under migration."
            )));
        }
        let port = c.node.port;
        c.info.migration = Some(t::MigrationSummary {
            status: Some("ready".into()),
            migration_endpoint: Some(endpoint(svc, port)),
            cutover_mode: Some("manual".into()),
        });
        Ok(())
    })?;
    Ok(t::PrepareMigrationResponse { serverless_cache: Some(info) })
}

pub(crate) async fn start_migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::StartMigrationMessage,
) -> Result<t::StartMigrationResponse, ServiceError> {
    let Some(name) = input.serverless_cache_name.clone().map(|n| n.to_ascii_lowercase()) else {
        return Err(combination("Either ReplicationGroupId or ServerlessCacheName must be specified."));
    };
    let info = migration(svc, ctx, &name, "StartMigration", |c| {
        let m = c.info.migration.get_or_insert_with(Default::default);
        if m.status.as_deref() == Some("in-progress") {
            return Err(errors::serverless_cache_already_under_migration_fault(format!(
                "Serverless cache {name} is already under migration."
            )));
        }
        m.status = Some("in-progress".into());
        m.cutover_mode = Some(if input.auto_cutover == Some(true) { "auto" } else { "manual" }.into());
        if input.auto_cutover == Some(true) {
            m.status = Some("completed".into());
        }
        Ok(())
    })?;
    Ok(t::StartMigrationResponse { replication_group: None, serverless_cache: Some(info) })
}

pub(crate) async fn stop_migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::StopMigrationRequest,
) -> Result<t::StopMigrationResponse, ServiceError> {
    let name = input.serverless_cache_name.to_ascii_lowercase();
    let info = migration(svc, ctx, &name, "StopMigration", |c| {
        if !under_migration(c) {
            return Err(errors::serverless_cache_not_under_migration_fault(format!(
                "Serverless cache {name} is not under migration."
            )));
        }
        if let Some(m) = c.info.migration.as_mut() {
            m.status = Some("stopped".into());
        }
        Ok(())
    })?;
    Ok(t::StopMigrationResponse { serverless_cache: Some(info) })
}

pub(crate) async fn complete_migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CompleteMigrationMessage,
) -> Result<t::CompleteMigrationResponse, ServiceError> {
    let Some(name) = input.serverless_cache_name.clone().map(|n| n.to_ascii_lowercase()) else {
        return Err(combination("Either ReplicationGroupId or ServerlessCacheName must be specified."));
    };
    let info = migration(svc, ctx, &name, "CompleteMigration", |c| {
        if !under_migration(c) {
            return Err(errors::serverless_cache_not_under_migration_fault(format!(
                "Serverless cache {name} is not under migration."
            )));
        }
        if let Some(m) = c.info.migration.as_mut() {
            m.status = Some("completed".into());
        }
        Ok(())
    })?;
    Ok(t::CompleteMigrationResponse { replication_group: None, serverless_cache: Some(info) })
}
