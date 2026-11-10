//! Cache clusters: CreateCacheCluster, DescribeCacheClusters,
//! ModifyCacheCluster, DeleteCacheCluster, RebootCacheCluster and
//! ListAllowedNodeTypeModifications.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use super::*;
use crate::backend::EngineKind;
use crate::catalog::{self, EngineVersion};
use crate::engine;
use crate::generated::{errors, types as t};
use crate::state::{AuthTokens, Cluster, NodeRuntime, RegionState};
use crate::ElastiCache;

pub(crate) fn not_found(id: &str) -> ServiceError {
    errors::cache_cluster_not_found_fault(format!("CacheCluster not found: {id}"))
}

pub(crate) fn engine_of(name: Option<&str>, default: EngineKind) -> Result<EngineKind, ServiceError> {
    match name {
        None | Some("") => Ok(default),
        Some(e) => EngineKind::parse(&e.to_ascii_lowercase()).ok_or_else(|| invalid(format!("Invalid engine: {e}"))),
    }
}

pub(crate) fn version_of(engine: EngineKind, v: Option<&str>) -> Result<&'static EngineVersion, ServiceError> {
    catalog::engine_version(engine, v)
        .ok_or_else(|| combination(format!("Cannot find version {} for {}", v.unwrap_or_default(), engine.as_str())))
}

pub(crate) fn check_node_type(node_type: Option<&str>) -> Result<String, ServiceError> {
    match node_type {
        None | Some("") => Err(invalid("The parameter CacheNodeType must be provided and must not be blank.")),
        Some(n) if catalog::node_type(n).is_none() => Err(invalid(format!("Invalid CacheNodeType: {n}"))),
        Some(n) => Ok(n.to_string()),
    }
}

pub(crate) fn check_auth_token(token: &str) -> Result<(), ServiceError> {
    let ok = (16..=128).contains(&token.len())
        && token.chars().all(|c| c.is_ascii_graphic() && !matches!(c, '@' | '"' | '/'));
    if ok {
        Ok(())
    } else {
        Err(invalid("Invalid AuthToken provided."))
    }
}

/// The parameter group a new cluster uses, checked against its version.
pub(crate) fn parameter_group_for(
    r: &RegionState,
    requested: Option<&str>,
    version: &EngineVersion,
    cluster_mode: bool,
) -> Result<String, ServiceError> {
    let name = match requested.filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None if cluster_mode => format!("default.{}.cluster.on", version.family),
        None => format!("default.{}", version.family),
    };
    let family = super::params::family_of(r, &name).ok_or_else(|| {
        errors::cache_parameter_group_not_found_fault(format!("CacheParameterGroup {name} not found."))
    })?;
    if family != version.family {
        return Err(combination(format!(
            "The parameter group {name} has family {family}, which is not compatible with engine version {}.",
            version.version
        )));
    }
    Ok(name)
}

/// Settings shared by every cluster a request creates.
#[derive(Clone)]
pub(crate) struct Template {
    pub engine: EngineKind,
    pub version: &'static EngineVersion,
    pub node_type: String,
    pub port: u16,
    pub parameter_group: String,
    pub subnet_group: String,
    pub security_groups: Vec<String>,
    pub maintenance_window: String,
    pub snapshot_window: Option<String>,
    pub snapshot_retention: i32,
    pub notification_topic: Option<String>,
    pub auto_minor_version_upgrade: bool,
    pub transit_encryption: bool,
    pub at_rest_encryption: bool,
    pub auth_token_enabled: bool,
    pub network_type: String,
    pub ip_discovery: String,
    pub log_delivery: Vec<t::LogDeliveryConfiguration>,
}

/// A new cluster record with `nodes` cache nodes.
pub(crate) fn build(
    svc: &ElastiCache,
    ctx: &RequestContext,
    id: &str,
    tpl: &Template,
    azs: &[String],
    nodes: usize,
    replication_group: Option<&str>,
) -> Cluster {
    let at = now(ctx);
    let mut runtime = BTreeMap::new();
    let mut cache_nodes = Vec::new();
    for i in 0..nodes {
        let node_id = format!("{:04}", i + 1);
        let port = alloc_port(svc, tpl.port);
        let az = azs.get(i % azs.len().max(1)).cloned().unwrap_or_else(|| format!("{}a", ctx.region));
        cache_nodes.push(t::CacheNode {
            cache_node_id: Some(node_id.clone()),
            cache_node_status: Some("creating".into()),
            cache_node_create_time: Some(at),
            endpoint: Some(endpoint(svc, port)),
            parameter_group_status: Some("in-sync".into()),
            source_cache_node_id: None,
            customer_availability_zone: Some(az),
            customer_outpost_arn: None,
        });
        runtime.insert(node_id, NodeRuntime { handle: None, port, peer: None });
    }
    let first_az = azs.first().cloned().unwrap_or_else(|| format!("{}a", ctx.region));
    let distinct: std::collections::BTreeSet<&String> = azs.iter().take(nodes).collect();
    let memcached = tpl.engine == EngineKind::Memcached;
    let info = t::CacheCluster {
        cache_cluster_id: Some(id.to_string()),
        // With real nodes, the configuration endpoint is MWS's own listener
        // answering `config get cluster` (see `discovery`).
        configuration_endpoint: memcached
            .then(|| match svc.runs_engines() {
                true => Some(endpoint(svc, crate::proxy::free_port(&svc.options().bind_address))),
                false => runtime.values().next().map(|n: &NodeRuntime| endpoint(svc, n.port)),
            })
            .flatten(),
        client_download_landing_page: Some("https://console.aws.amazon.com/elasticache/home#client-download:".into()),
        cache_node_type: Some(tpl.node_type.clone()),
        engine: Some(tpl.engine.as_str().into()),
        engine_version: Some(tpl.version.version.into()),
        cache_cluster_status: Some("creating".into()),
        num_cache_nodes: Some(nodes as i32),
        preferred_availability_zone: Some(if distinct.len() > 1 { "Multiple".into() } else { first_az }),
        preferred_outpost_arn: None,
        cache_cluster_create_time: Some(at),
        preferred_maintenance_window: Some(tpl.maintenance_window.clone()),
        pending_modified_values: Some(t::PendingModifiedValues::default()),
        notification_configuration: tpl
            .notification_topic
            .clone()
            .map(|topic| t::NotificationConfiguration { topic_arn: Some(topic), topic_status: Some("active".into()) }),
        cache_security_groups: Some(vec![]),
        cache_parameter_group: Some(t::CacheParameterGroupStatus {
            cache_parameter_group_name: Some(tpl.parameter_group.clone()),
            parameter_apply_status: Some("in-sync".into()),
            cache_node_ids_to_reboot: Some(vec![]),
        }),
        cache_subnet_group_name: Some(tpl.subnet_group.clone()),
        cache_nodes: Some(cache_nodes),
        auto_minor_version_upgrade: Some(tpl.auto_minor_version_upgrade),
        security_groups: Some(
            tpl.security_groups
                .iter()
                .map(|g| t::SecurityGroupMembership {
                    security_group_id: Some(g.clone()),
                    status: Some("active".into()),
                })
                .collect(),
        ),
        replication_group_id: replication_group.map(str::to_string),
        snapshot_retention_limit: (!memcached).then_some(tpl.snapshot_retention),
        snapshot_window: if memcached { None } else { tpl.snapshot_window.clone() },
        auth_token_enabled: Some(tpl.auth_token_enabled),
        auth_token_last_modified_date: tpl.auth_token_enabled.then_some(at),
        transit_encryption_enabled: Some(tpl.transit_encryption),
        at_rest_encryption_enabled: Some(tpl.at_rest_encryption),
        arn: Some(arn(ctx, "cluster", id)),
        replication_group_log_delivery_enabled: Some(replication_group.is_some() && !tpl.log_delivery.is_empty()),
        log_delivery_configurations: Some(tpl.log_delivery.clone()),
        network_type: Some(tpl.network_type.clone()),
        ip_discovery: Some(tpl.ip_discovery.clone()),
        transit_encryption_mode: tpl.transit_encryption.then(|| "required".to_string()),
    };
    Cluster { info, engine: Some(tpl.engine), port: tpl.port, nodes: runtime, ..Default::default() }
}

/// Default maintenance window, as AWS picks one per Region.
pub(crate) fn default_maintenance_window() -> String {
    let days = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
    let d = days[rand::thread_rng().gen_range(0..7)];
    let h = rand::thread_rng().gen_range(0..23);
    format!("{d}:{h:02}:00-{d}:{:02}:00", h + 1)
}

pub(crate) fn default_snapshot_window() -> String {
    let h = rand::thread_rng().gen_range(0..23);
    format!("{h:02}:30-{:02}:30", h + 1)
}

pub(crate) fn log_delivery(
    reqs: &Option<Vec<t::LogDeliveryConfigurationRequest>>,
) -> Result<Vec<t::LogDeliveryConfiguration>, ServiceError> {
    let mut out = Vec::new();
    for r in reqs.iter().flatten() {
        if r.enabled == Some(false) {
            continue;
        }
        let log_type = r.log_type.clone().ok_or_else(|| invalid("LogType is required"))?;
        if !matches!(log_type.as_str(), "slow-log" | "engine-log") {
            return Err(invalid(format!("Invalid LogType: {log_type}")));
        }
        let dest = r.destination_type.clone().ok_or_else(|| invalid("DestinationType is required"))?;
        if !matches!(dest.as_str(), "cloudwatch-logs" | "kinesis-firehose") {
            return Err(invalid(format!("Invalid DestinationType: {dest}")));
        }
        out.push(t::LogDeliveryConfiguration {
            log_type: Some(log_type),
            destination_type: Some(dest),
            destination_details: r.destination_details.clone(),
            log_format: Some(r.log_format.clone().unwrap_or_else(|| "text".into())),
            status: Some("active".into()),
            message: None,
        });
    }
    Ok(out)
}

/// The subnet group, availability zones and security groups for a new
/// cluster or replication group.
pub(crate) fn placement(
    svc: &ElastiCache,
    ctx: &RequestContext,
    r: &mut RegionState,
    subnet_group: Option<&str>,
    security_group_ids: &Option<Vec<String>>,
    cache_security_groups: &Option<Vec<String>>,
) -> Result<(String, Vec<String>, Vec<String>), ServiceError> {
    if cache_security_groups.as_ref().is_some_and(|g| !g.is_empty()) {
        return Err(invalid("Use of cache security groups is not permitted in this API version for your account."));
    }
    let group = match subnet_group.filter(|g| !g.is_empty()) {
        Some(g) => g.to_ascii_lowercase(),
        None => super::subnets::ensure_default(svc, ctx, r)?,
    };
    let g = r.subnet_groups.get(&group).cloned().ok_or_else(|| {
        errors::cache_subnet_group_not_found_fault(format!("Cache subnet group '{group}' does not exist."))
    })?;
    let azs: Vec<String> = g
        .subnets
        .iter()
        .flatten()
        .filter_map(|s| s.subnet_availability_zone.as_ref().and_then(|a| a.name.clone()))
        .collect();
    let vpc = g.vpc_id.clone().unwrap_or_default();
    let account = crate::account_of(ctx);
    let sgs = match security_group_ids.as_ref().filter(|g| !g.is_empty()) {
        Some(ids) => {
            if let Some(n) = svc.network() {
                let bad: Vec<&String> =
                    ids.iter().filter(|id| n.security_group_vpc(&account, &ctx.region, id).is_none()).collect();
                if !bad.is_empty() {
                    return Err(invalid(format!(
                        "Some security group Id(s) are not valid: {}",
                        bad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    )));
                }
                if let Some(other) =
                    ids.iter().find(|id| n.security_group_vpc(&account, &ctx.region, id).as_deref() != Some(&vpc))
                {
                    return Err(errors::invalid_vpc_network_state_fault(format!(
                        "The security group {other} does not belong to VPC {vpc} of the cache subnet group {group}."
                    )));
                }
            } else if let Some(bad) = ids.iter().find(|id| !id.starts_with("sg-")) {
                return Err(invalid(format!("Some security group Id(s) are not valid: {bad}")));
            }
            ids.clone()
        }
        None => svc.network().and_then(|n| n.default_security_group(&account, &ctx.region, &vpc)).into_iter().collect(),
    };
    Ok((group, if azs.is_empty() { catalog::zones(&ctx.region) } else { azs }, sgs))
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateCacheClusterMessage,
) -> Result<t::CreateCacheClusterResult, ServiceError> {
    let id = identifier("CacheClusterId", &input.cache_cluster_id, 50)?;
    if let Some(rg) = input.replication_group_id.clone().filter(|g| !g.is_empty()) {
        return super::replication::add_cluster(svc, ctx, &id, &rg.to_ascii_lowercase(), input).await;
    }
    let engine = engine_of(input.engine.as_deref(), EngineKind::Memcached)?;
    let version = version_of(engine, input.engine_version.as_deref())?;
    let node_type = check_node_type(input.cache_node_type.as_deref())?;
    let nodes = input.num_cache_nodes.unwrap_or(1);
    if engine.is_redis_like() && nodes > 1 {
        return Err(invalid(format!(
            "Cannot create a {} cluster with a NumCacheNodes parameter greater than 1.",
            catalog::engine_description(engine)
        )));
    }
    if nodes < 1 {
        return Err(invalid("The parameter NumCacheNodes must be a positive integer."));
    }
    if nodes > 40 {
        return Err(errors::node_quota_for_cluster_exceeded_fault("Quota exceeded for nodes per cluster."));
    }
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    if let Some(tok) = &input.auth_token {
        if !engine.is_redis_like() {
            return Err(combination("The AuthToken parameter is not supported for memcached."));
        }
        check_auth_token(tok)?;
        if input.transit_encryption_enabled != Some(true) {
            return Err(combination("AuthToken can only be specified when TransitEncryptionEnabled is true."));
        }
    }
    if let Some(w) = &input.preferred_maintenance_window {
        check_window("PreferredMaintenanceWindow", w, true)?;
    }
    if let Some(w) = &input.snapshot_window {
        check_window("SnapshotWindow", w, false)?;
    }
    if engine == EngineKind::Memcached && (input.snapshot_name.is_some() || input.snapshot_arns.is_some()) {
        return Err(combination("Snapshot operations are not supported for the memcached engine."));
    }
    let resource = arn(ctx, "cluster", &id);
    authorize_create(
        ctx,
        "CreateCacheCluster",
        &resource,
        &tags,
        cond(&[
            ("CacheNodeType", Some(node_type.clone())),
            ("EngineVersion", Some(version.version.into())),
            ("EngineType", Some(engine.as_str().into())),
            ("CacheParameterGroupName", input.cache_parameter_group_name.clone()),
            ("AuthTokenEnabled", Some(input.auth_token.is_some().to_string())),
            ("TransitEncryptionEnabled", b(input.transit_encryption_enabled)),
            ("SnapshotRetentionLimit", input.snapshot_retention_limit.map(|v| v.to_string())),
        ]),
    )?;
    let key = region_key(ctx);
    let log = log_delivery(&input.log_delivery_configurations)?;
    let out = svc.with_region(ctx, |r| {
        if r.clusters.contains_key(&id) {
            return Err(errors::cache_cluster_already_exists_fault(format!("Cache cluster {id} already exists.")));
        }
        let parameter_group = parameter_group_for(r, input.cache_parameter_group_name.as_deref(), version, false)?;
        if parameter_group.ends_with(".cluster.on") {
            return Err(combination(
                "Cluster mode enabled parameter groups are only supported for replication groups.",
            ));
        }
        let seed = match input.snapshot_name.as_deref() {
            Some(s) => {
                let snap = r.snapshots.get(s).ok_or_else(|| super::snapshots::not_found(s))?;
                if snap.info.snapshot_status.as_deref() != Some("available") {
                    return Err(errors::invalid_snapshot_state_fault(format!(
                        "Snapshot {s} is not in available state."
                    )));
                }
                Some(s.to_string())
            }
            None => None,
        };
        let (subnet_group, mut azs, sgs) = placement(
            svc,
            ctx,
            r,
            input.cache_subnet_group_name.as_deref(),
            &input.security_group_ids,
            &input.cache_security_group_names,
        )?;
        if let Some(pref) = input.preferred_availability_zones.clone().filter(|z| !z.is_empty()) {
            azs = pref;
        } else if let Some(z) = input.preferred_availability_zone.clone() {
            azs = vec![z];
        } else if input.az_mode.as_deref() != Some("cross-az") {
            azs.truncate(1);
        }
        let tpl = Template {
            engine,
            version,
            node_type: node_type.clone(),
            port: input.port.map(|p| p as u16).unwrap_or(if engine.is_redis_like() { 6379 } else { 11211 }),
            parameter_group,
            subnet_group,
            security_groups: sgs,
            maintenance_window: input.preferred_maintenance_window.clone().unwrap_or_else(default_maintenance_window),
            snapshot_window: Some(input.snapshot_window.clone().unwrap_or_else(default_snapshot_window)),
            snapshot_retention: input.snapshot_retention_limit.unwrap_or(0),
            notification_topic: input.notification_topic_arn.clone(),
            auto_minor_version_upgrade: input.auto_minor_version_upgrade.unwrap_or(true),
            transit_encryption: input.transit_encryption_enabled.unwrap_or(false),
            at_rest_encryption: false,
            auth_token_enabled: input.auth_token.is_some(),
            network_type: input.network_type.clone().unwrap_or_else(|| "ipv4".into()),
            ip_discovery: input.ip_discovery.clone().unwrap_or_else(|| "ipv4".into()),
            log_delivery: log.clone(),
        };
        let mut c = build(svc, ctx, &id, &tpl, &azs, nodes as usize, None);
        c.auth = AuthTokens { current: input.auth_token.clone(), previous: None };
        c.internal_password = engine.is_redis_like().then(random_password);
        c.seed_snapshot = seed;
        c.seed_rdb = input.snapshot_arns.clone().filter(|a| !a.is_empty());
        let shown = c.info.clone();
        r.clusters.insert(id.clone(), c);
        set_tags(r, &resource, input.tags.clone());
        Ok(shown)
    })?;
    if let Some(port) = out.configuration_endpoint.as_ref().and_then(|e| e.port) {
        svc.open_discovery(&key, &id, port as u16, out.transit_encryption_enabled == Some(true));
    }
    engine::start_cluster(svc, ctx, &key, &id);
    Ok(t::CreateCacheClusterResult { cache_cluster: Some(without_nodes(out)) })
}

pub(crate) fn without_nodes(mut c: t::CacheCluster) -> t::CacheCluster {
    c.cache_nodes = None;
    c
}

/// A cluster's nodes are up (after creation, or after nodes were added).
pub(crate) fn became_available(svc: &ElastiCache, ctx: &RequestContext, r: &mut RegionState, id: &str, created: bool) {
    let at = now(ctx).max(chrono::Utc::now());
    let Some(c) = r.clusters.get_mut(id) else { return };
    let added: Vec<(String, String)> = c
        .info
        .cache_nodes
        .iter()
        .flatten()
        .filter(|n| n.cache_node_status.as_deref() == Some("creating"))
        .map(|n| {
            (n.cache_node_id.clone().unwrap_or_default(), n.customer_availability_zone.clone().unwrap_or_default())
        })
        .collect();
    c.set_status("available");
    let topic = c.info.notification_configuration.as_ref().and_then(|n| n.topic_arn.clone());
    let resource = c.info.arn.clone().unwrap_or_default();
    if created {
        r.event(id, "cache-cluster", "Cache cluster created", at);
        notify(svc, ctx, topic.as_deref(), &resource, "ElastiCache:CacheClusterCreated");
    }
    for (node, az) in added {
        r.event(id, "cache-cluster", format!("Added cache node {node} in availability zone {az}"), at);
        if !created {
            notify(svc, ctx, topic.as_deref(), &resource, "ElastiCache:AddCacheNodeComplete");
        }
    }
}

pub(crate) async fn describe(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeCacheClustersMessage,
) -> Result<t::CacheClusterMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        let show_nodes = input.show_cache_node_info == Some(true);
        let list: Vec<&Cluster> = match input.cache_cluster_id.as_deref() {
            Some(id) => {
                let id = id.to_ascii_lowercase();
                let c = r.clusters.get(&id).ok_or_else(|| not_found(&id))?;
                authorize(
                    ctx,
                    r,
                    "DescribeCacheClusters",
                    c.info.arn.as_deref().unwrap_or_default(),
                    Default::default(),
                )?;
                vec![c]
            }
            None => {
                ctx.authorize("elasticache:DescribeCacheClusters", &arn(ctx, "cluster", "*"), Default::default())?;
                r.clusters
                    .values()
                    .filter(|c| {
                        input.show_cache_clusters_not_in_replication_groups != Some(true)
                            || c.info.replication_group_id.is_none()
                    })
                    .collect()
            }
        };
        let items: Vec<t::CacheCluster> =
            list.into_iter().map(|c| if show_nodes { c.info.clone() } else { without_nodes(c.info.clone()) }).collect();
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::CacheClusterMessage { marker, cache_clusters: Some(page) })
    })
}

pub(crate) async fn modify(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyCacheClusterMessage,
) -> Result<t::ModifyCacheClusterResult, ServiceError> {
    let id = input.cache_cluster_id.to_ascii_lowercase();
    let key = region_key(ctx);
    let apply_now = input.apply_immediately == Some(true);
    enum After {
        Nothing,
        AddNodes,
        Commands(Vec<Vec<String>>),
        /// Replace the nodes with ones running a new engine version.
        Upgrade,
    }
    let (out, after, removed) = svc.with_region(ctx, |r| {
        let c = r.clusters.get(&id).ok_or_else(|| not_found(&id))?;
        let resource = c.info.arn.clone().unwrap_or_default();
        authorize(
            ctx,
            r,
            "ModifyCacheCluster",
            &resource,
            cond(&[
                ("CacheNodeType", input.cache_node_type.clone()),
                ("EngineVersion", input.engine_version.clone()),
                ("CacheParameterGroupName", input.cache_parameter_group_name.clone()),
                ("SnapshotRetentionLimit", input.snapshot_retention_limit.map(|v| v.to_string())),
            ]),
        )?;
        if c.status() != "available" {
            return Err(errors::invalid_cache_cluster_state_fault(format!(
                "Cache cluster {id} is not in available state."
            )));
        }
        let engine = c.engine();
        let mut c = c.clone();
        let mut after = After::Nothing;
        let mut upgrade = false;
        let mut commands: Vec<Vec<String>> = Vec::new();
        let mut removed_handles = Vec::new();
        let mut pending = c.info.pending_modified_values.clone().unwrap_or_default();
        // ApplyImmediately also applies the changes already pending, unless
        // this request replaces them.
        let mut input = input;
        if apply_now {
            let old = std::mem::take(&mut pending);
            if input.num_cache_nodes.is_none() {
                input.num_cache_nodes = old.num_cache_nodes;
                if input.cache_node_ids_to_remove.is_none() {
                    input.cache_node_ids_to_remove = old.cache_node_ids_to_remove;
                }
            }
            input.cache_node_type = input.cache_node_type.or(old.cache_node_type);
            if input.engine.is_none() {
                input.engine_version = input.engine_version.or(old.engine_version);
            }
        }
        if let Some(n) = input.num_cache_nodes {
            let cur = c.info.num_cache_nodes.unwrap_or(1);
            if engine.is_redis_like() && n != 1 {
                return Err(invalid(format!(
                    "Cannot modify a {} cluster to have a NumCacheNodes parameter greater than 1.",
                    catalog::engine_description(engine)
                )));
            }
            if n > 40 {
                return Err(errors::node_quota_for_cluster_exceeded_fault("Quota exceeded for nodes per cluster."));
            }
            if n < cur {
                let remove = input.cache_node_ids_to_remove.clone().unwrap_or_default();
                if remove.len() as i32 != cur - n {
                    return Err(invalid(format!(
                        "The number of cache node ids to remove ({}) must be equal to the decrease in the number of cache nodes ({}).",
                        remove.len(),
                        cur - n
                    )));
                }
                for node in &remove {
                    if !c.nodes.contains_key(node) {
                        return Err(invalid(format!("Cache node id {node} does not exist in cluster {id}.")));
                    }
                }
                if apply_now {
                    removed_handles.extend(remove_nodes(&mut c, &remove, n));
                } else {
                    pending.num_cache_nodes = Some(n);
                    pending.cache_node_ids_to_remove = Some(remove);
                }
            } else if n > cur {
                if apply_now {
                    add_nodes(svc, &mut c, n, input.new_availability_zones.clone(), &ctx.region, now(ctx));
                    after = After::AddNodes;
                } else {
                    pending.num_cache_nodes = Some(n);
                }
            }
        }
        if let Some(nt) = &input.cache_node_type {
            check_node_type(Some(nt))?;
            if apply_now {
                c.info.cache_node_type = Some(nt.clone());
                if engine.is_redis_like() {
                    let mem = catalog::node_type(nt).map(|n| n.maxmemory()).unwrap_or(0);
                    commands.push(vec!["CONFIG".into(), "SET".into(), "maxmemory".into(), mem.to_string()]);
                }
            } else {
                pending.cache_node_type = Some(nt.clone());
            }
        }
        let target_engine = engine_of(input.engine.as_deref(), engine)?;
        if target_engine != engine && !(engine == EngineKind::Redis && target_engine == EngineKind::Valkey) {
            return Err(combination(format!(
                "Cannot change engine from {} to {}.",
                engine.as_str(),
                target_engine.as_str()
            )));
        }
        if let Some(v) = input.engine_version.as_deref().or(input.engine.as_deref().map(|_| "")) {
            let target = version_of(target_engine, Some(v).filter(|v| !v.is_empty()))?;
            let cur = c.info.engine_version.clone().unwrap_or_default();
            if target_engine == engine && version_cmp(target.version, &cur) == std::cmp::Ordering::Less {
                return Err(combination(format!(
                    "Cannot modify engine version from {cur} to {} because downgrades are not supported.",
                    target.version
                )));
            }
            if apply_now || target_engine != engine {
                upgrade = target.version != cur || target_engine != engine;
                c.info.engine = Some(target_engine.as_str().into());
                c.engine = Some(target_engine);
                c.info.engine_version = Some(target.version.into());
                if let Some(pg) = c.info.cache_parameter_group.as_mut() {
                    if pg.cache_parameter_group_name.as_deref().is_some_and(|n| n.starts_with("default.")) {
                        pg.cache_parameter_group_name = Some(format!("default.{}", target.family));
                    }
                }
            } else {
                pending.engine_version = Some(target.version.into());
            }
        }
        if let Some(pg) = &input.cache_parameter_group_name {
            let family = super::params::family_of(r, pg)
                .ok_or_else(|| errors::cache_parameter_group_not_found_fault(format!("CacheParameterGroup {pg} not found.")))?;
            let version = c.info.engine_version.clone().unwrap_or_default();
            let want = catalog::ENGINE_VERSIONS.iter().find(|v| v.version == version).map(|v| v.family).unwrap_or_default();
            if family != want {
                return Err(combination(format!(
                    "The parameter group {pg} has family {family}, which is not compatible with engine version {version}."
                )));
            }
            c.info.cache_parameter_group = Some(t::CacheParameterGroupStatus {
                cache_parameter_group_name: Some(pg.clone()),
                parameter_apply_status: Some("in-sync".into()),
                cache_node_ids_to_reboot: Some(vec![]),
            });
            for (k, v) in super::params::engine_values(r, pg) {
                commands.push(vec!["CONFIG".into(), "SET".into(), k, v]);
            }
        }
        if let Some(sgs) = &input.security_group_ids {
            c.info.security_groups = Some(
                sgs.iter()
                    .map(|g| t::SecurityGroupMembership { security_group_id: Some(g.clone()), status: Some("active".into()) })
                    .collect(),
            );
        }
        if input.cache_security_group_names.as_ref().is_some_and(|g| !g.is_empty()) {
            return Err(invalid("Use of cache security groups is not permitted in this API version for your account."));
        }
        if let Some(w) = &input.preferred_maintenance_window {
            check_window("PreferredMaintenanceWindow", w, true)?;
            c.info.preferred_maintenance_window = Some(w.clone());
        }
        if let Some(topic) = &input.notification_topic_arn {
            c.info.notification_configuration =
                Some(t::NotificationConfiguration { topic_arn: Some(topic.clone()), topic_status: Some("active".into()) });
        }
        if let Some(status) = &input.notification_topic_status {
            if let Some(n) = c.info.notification_configuration.as_mut() {
                n.topic_status = Some(status.clone());
            }
        }
        if let Some(v) = input.auto_minor_version_upgrade {
            c.info.auto_minor_version_upgrade = Some(v);
        }
        if let Some(v) = input.snapshot_retention_limit {
            if engine == EngineKind::Memcached {
                return Err(combination("Snapshot operations are not supported for the memcached engine."));
            }
            c.info.snapshot_retention_limit = Some(v);
        }
        if let Some(w) = &input.snapshot_window {
            check_window("SnapshotWindow", w, false)?;
            c.info.snapshot_window = Some(w.clone());
        }
        if input.auth_token.is_some() || input.auth_token_update_strategy.is_some() {
            if c.info.replication_group_id.is_some() {
                return Err(combination("Use ModifyReplicationGroup to change the AUTH token of a replication group member."));
            }
            let acl = acl_ok(&c);
            commands.extend(super::replication::change_auth(
                &mut c.auth,
                input.auth_token.as_deref(),
                input.auth_token_update_strategy.as_deref(),
                c.info.transit_encryption_enabled == Some(true),
                acl,
            )?);
            c.info.auth_token_enabled = Some(c.auth.enabled());
            c.info.auth_token_last_modified_date = Some(now(ctx));
        }
        if input.log_delivery_configurations.is_some() {
            c.info.log_delivery_configurations = Some(merge_log_delivery(
                c.info.log_delivery_configurations.clone().unwrap_or_default(),
                &input.log_delivery_configurations,
            )?);
        }
        if let Some(ip) = &input.ip_discovery {
            c.info.ip_discovery = Some(ip.clone());
        }
        let has_pending = pending != t::PendingModifiedValues::default();
        c.info.pending_modified_values = Some(pending);
        c.pending_since = if has_pending { c.pending_since.or(Some(now(ctx))) } else { None };
        if !commands.is_empty() {
            after = match after {
                After::AddNodes => After::AddNodes,
                _ => After::Commands(commands.clone()),
            };
        }
        if upgrade {
            after = After::Upgrade;
            if svc.runs_engines() {
                c.set_status("modifying");
            }
        }
        let shown = c.info.clone();
        r.clusters.insert(id.clone(), c);
        r.event(&id, "cache-cluster", "Cache cluster modified", now(ctx));
        Ok((shown, after, (removed_handles, commands)))
    })?;
    let (removed_handles, commands) = removed;
    engine::terminate(svc, removed_handles, None);
    match after {
        After::AddNodes => {
            engine::add_nodes(svc, ctx, &key, &id);
            let nodes = svc.with_key(&key, ctx, |r| engine::nodes_of(r, None, Some(&id)));
            engine::run_everywhere(svc, nodes, commands);
        }
        After::Commands(cmds) => {
            let nodes = svc.with_key(&key, ctx, |r| engine::nodes_of(r, None, Some(&id)));
            engine::run_everywhere(svc, nodes, cmds);
        }
        After::Upgrade => engine::upgrade(svc, ctx, &key, None, Some(&id)),
        After::Nothing => {}
    }
    Ok(t::ModifyCacheClusterResult { cache_cluster: Some(without_nodes(out)) })
}

/// Remove `remove` from the cluster's nodes, leaving `n`. Returns the
/// engine handles to terminate.
fn remove_nodes(c: &mut Cluster, remove: &[String], n: i32) -> Vec<String> {
    let mut handles = Vec::new();
    for node in remove {
        if let Some(rt) = c.nodes.remove(node) {
            handles.extend(rt.handle);
        }
    }
    if let Some(list) = c.info.cache_nodes.as_mut() {
        list.retain(|x| !remove.contains(x.cache_node_id.as_ref().unwrap_or(&String::new())));
    }
    c.info.num_cache_nodes = Some(n);
    handles
}

/// Grow the cluster to `n` nodes, spread over `azs` (or the first node's
/// zone); the new nodes are `creating` and the cluster `modifying`.
fn add_nodes(
    svc: &ElastiCache,
    c: &mut Cluster,
    n: i32,
    azs: Option<Vec<String>>,
    region: &str,
    at: chrono::DateTime<chrono::Utc>,
) {
    let cur = c.info.num_cache_nodes.unwrap_or(1);
    let azs = azs.filter(|z| !z.is_empty()).unwrap_or_else(|| {
        vec![c
            .info
            .cache_nodes
            .iter()
            .flatten()
            .next()
            .and_then(|x| x.customer_availability_zone.clone())
            .unwrap_or_else(|| format!("{region}a"))]
    });
    let next = c.nodes.keys().filter_map(|k| k.parse::<u32>().ok()).max().unwrap_or(0);
    for i in 0..(n - cur).max(0) as u32 {
        let node_id = format!("{:04}", next + i + 1);
        let port = alloc_port(svc, c.port);
        c.nodes.insert(node_id.clone(), NodeRuntime { handle: None, port, peer: None });
        c.info.cache_nodes.get_or_insert_with(Vec::new).push(t::CacheNode {
            cache_node_id: Some(node_id),
            cache_node_status: Some("creating".into()),
            cache_node_create_time: Some(at),
            endpoint: Some(endpoint(svc, port)),
            parameter_group_status: Some("in-sync".into()),
            source_cache_node_id: None,
            customer_availability_zone: Some(azs[i as usize % azs.len()].clone()),
            customer_outpost_arn: None,
        });
    }
    c.info.num_cache_nodes = Some(n);
    c.info.cache_cluster_status = Some("modifying".into());
}

/// What applying a cluster's pending changes leaves to do outside the
/// state lock.
#[derive(Default)]
pub(crate) struct Applied {
    pub removed_handles: Vec<String>,
    pub add_nodes: bool,
    pub upgrade: bool,
    pub commands: Vec<Vec<String>>,
}

/// Apply a standalone cluster's pending node count, node type and engine
/// version changes in its maintenance window, as `ModifyCacheCluster` with
/// `ApplyImmediately` would have.
pub(crate) fn apply_pending(
    svc: &ElastiCache,
    r: &mut RegionState,
    id: &str,
    region: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Applied {
    let mut out = Applied::default();
    let Some(c) = r.clusters.get_mut(id) else { return out };
    let pending = c.info.pending_modified_values.take().unwrap_or_default();
    c.info.pending_modified_values = Some(t::PendingModifiedValues::default());
    c.pending_since = None;
    let engine = c.engine();
    if let Some(n) = pending.num_cache_nodes {
        let cur = c.info.num_cache_nodes.unwrap_or(1);
        if n < cur {
            let remove = pending.cache_node_ids_to_remove.clone().unwrap_or_default();
            out.removed_handles = remove_nodes(c, &remove, n);
        } else if n > cur {
            add_nodes(svc, c, n, None, region, at);
            out.add_nodes = true;
        }
    }
    if let Some(nt) = &pending.cache_node_type {
        c.info.cache_node_type = Some(nt.clone());
        if engine.is_redis_like() {
            let mem = catalog::node_type(nt).map(|n| n.maxmemory()).unwrap_or(0);
            out.commands.push(vec!["CONFIG".into(), "SET".into(), "maxmemory".into(), mem.to_string()]);
        }
    }
    if let Some(v) = &pending.engine_version {
        if let Ok(target) = version_of(engine, Some(v)) {
            out.upgrade = c.info.engine_version.as_deref() != Some(target.version);
            c.info.engine_version = Some(target.version.into());
            if let Some(pg) = c.info.cache_parameter_group.as_mut() {
                if pg.cache_parameter_group_name.as_deref().is_some_and(|n| n.starts_with("default.")) {
                    pg.cache_parameter_group_name = Some(format!("default.{}", target.family));
                }
            }
            if out.upgrade && svc.runs_engines() {
                c.set_status("modifying");
            }
        }
    }
    r.event(id, "cache-cluster", format!("Cache cluster {id} modified"), at);
    out
}

fn acl_ok(c: &Cluster) -> bool {
    engine::acl_capable(c.engine(), c.info.engine_version.as_deref().unwrap_or_default())
}

pub(crate) fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| s.split('.').map(|p| p.parse::<u32>().unwrap_or(0)).collect::<Vec<_>>();
    parse(a).cmp(&parse(b))
}

pub(crate) fn merge_log_delivery(
    mut current: Vec<t::LogDeliveryConfiguration>,
    reqs: &Option<Vec<t::LogDeliveryConfigurationRequest>>,
) -> Result<Vec<t::LogDeliveryConfiguration>, ServiceError> {
    for r in reqs.iter().flatten() {
        let log_type = r.log_type.clone().unwrap_or_default();
        current.retain(|c| c.log_type.as_deref() != Some(&log_type));
        if r.enabled != Some(false) {
            current.extend(log_delivery(&Some(vec![r.clone()]))?);
        }
    }
    Ok(current)
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteCacheClusterMessage,
) -> Result<t::DeleteCacheClusterResult, ServiceError> {
    let id = input.cache_cluster_id.to_ascii_lowercase();
    let key = region_key(ctx);
    let (shown, handles, snapshot) = svc.with_region(ctx, |r| {
        let c = r.clusters.get(&id).ok_or_else(|| not_found(&id))?;
        let resource = c.info.arn.clone().unwrap_or_default();
        authorize(ctx, r, "DeleteCacheCluster", &resource, Default::default())?;
        if !matches!(c.status(), "available" | "create-failed" | "incompatible-parameters" | "restore-failed") {
            return Err(errors::invalid_cache_cluster_state_fault(format!(
                "Cache cluster {id} is not in a valid state to be deleted."
            )));
        }
        if let Some(rg) = c.info.replication_group_id.clone() {
            if c.role.as_deref() == Some("primary") {
                return Err(errors::invalid_cache_cluster_state_fault(format!(
                    "Cannot delete the primary cluster {id} of replication group {rg}. Delete the replication group or promote another cluster first."
                )));
            }
            if r.replication_groups.get(&rg).is_some_and(|g| g.cluster_enabled()) {
                return Err(combination("Use DecreaseReplicaCount to remove replicas of a cluster mode enabled replication group."));
            }
        }
        let snapshot = match input.final_snapshot_identifier.as_deref() {
            Some(name) => {
                if c.engine() == EngineKind::Memcached {
                    return Err(combination("Snapshot operations are not supported for the memcached engine."));
                }
                let sources = engine::snapshot_sources(r, None, Some(&id));
                Some((super::snapshots::start(svc, ctx, r, name, None, Some(&id), "manual", None)?, sources))
            }
            None => None,
        };
        let mut c = r.clusters.remove(&id).unwrap_or_default();
        c.set_status("deleting");
        let handles: Vec<String> = c.nodes.values().filter_map(|n| n.handle.clone()).collect();
        r.tags.remove(&resource);
        if let Some(rg) = c.info.replication_group_id.clone() {
            super::replication::forget_member(r, &rg, &id);
        }
        r.event(&id, "cache-cluster", "Cache cluster deleted", now(ctx));
        let topic = c.info.notification_configuration.as_ref().and_then(|n| n.topic_arn.clone());
        notify(svc, ctx, topic.as_deref(), &resource, "ElastiCache:CacheClusterDeleted");
        Ok((c.info, handles, snapshot))
    })?;
    svc.close_discovery(&key, &id);
    match snapshot {
        // The nodes stay up until the final snapshot has their data.
        Some((name, sources)) => engine::snapshot(svc, ctx, &key, &name, sources, handles),
        None => engine::terminate(svc, handles, None),
    }
    Ok(t::DeleteCacheClusterResult { cache_cluster: Some(without_nodes(shown)) })
}

pub(crate) async fn reboot(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::RebootCacheClusterMessage,
) -> Result<t::RebootCacheClusterResult, ServiceError> {
    let id = input.cache_cluster_id.to_ascii_lowercase();
    let key = region_key(ctx);
    let shown = svc.with_region(ctx, |r| {
        let c = r.clusters.get_mut(&id).ok_or_else(|| not_found(&id))?;
        let resource = c.info.arn.clone().unwrap_or_default();
        if c.status() != "available" {
            return Err(errors::invalid_cache_cluster_state_fault(format!(
                "Cache cluster {id} is not in available state."
            )));
        }
        for n in &input.cache_node_ids_to_reboot {
            if !c.nodes.contains_key(n) {
                return Err(invalid(format!("Cache node id {n} does not exist in cluster {id}.")));
            }
        }
        if input.cache_node_ids_to_reboot.is_empty() {
            return Err(invalid("The parameter CacheNodeIdsToReboot must be provided and must not be empty."));
        }
        c.info.cache_cluster_status = Some("rebooting cache cluster nodes".into());
        for n in c.info.cache_nodes.iter_mut().flatten() {
            if input.cache_node_ids_to_reboot.contains(n.cache_node_id.as_ref().unwrap_or(&String::new())) {
                n.cache_node_status = Some("rebooting".into());
            }
        }
        let shown = c.info.clone();
        let rr: &RegionState = r;
        authorize(ctx, rr, "RebootCacheCluster", &resource, Default::default())?;
        Ok(shown)
    })?;
    engine::reboot(svc, ctx, &key, &id, input.cache_node_ids_to_reboot.clone());
    Ok(t::RebootCacheClusterResult { cache_cluster: Some(without_nodes(shown)) })
}

pub(crate) fn rebooted(svc: &ElastiCache, ctx: &RequestContext, r: &mut RegionState, id: &str, nodes: &[String]) {
    let Some(c) = r.clusters.get_mut(id) else { return };
    c.set_status("available");
    let topic = c.info.notification_configuration.as_ref().and_then(|n| n.topic_arn.clone());
    let resource = c.info.arn.clone().unwrap_or_default();
    let at = chrono::Utc::now().max(now(ctx));
    for n in nodes {
        r.event(id, "cache-cluster", format!("Cache node {n} restarted"), at);
    }
    notify(svc, ctx, topic.as_deref(), &resource, "ElastiCache:CacheClusterRebooted");
}

pub(crate) async fn allowed_node_types(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ListAllowedNodeTypeModificationsMessage,
) -> Result<t::AllowedNodeTypeModificationsMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        let (resource, node_type) = match (&input.cache_cluster_id, &input.replication_group_id) {
            (Some(id), _) => {
                let c = r.clusters.get(&id.to_ascii_lowercase()).ok_or_else(|| not_found(id))?;
                (c.info.arn.clone().unwrap_or_default(), c.info.cache_node_type.clone().unwrap_or_default())
            }
            (None, Some(g)) => {
                let rg = r
                    .replication_groups
                    .get(&g.to_ascii_lowercase())
                    .ok_or_else(|| super::replication::not_found(g))?;
                (rg.info.arn.clone().unwrap_or_default(), rg.info.cache_node_type.clone().unwrap_or_default())
            }
            (None, None) => {
                return Err(combination("Either CacheClusterId or ReplicationGroupId must be specified."));
            }
        };
        authorize(ctx, r, "ListAllowedNodeTypeModifications", &resource, Default::default())?;
        let (up, down) = catalog::scaling(&node_type);
        Ok(t::AllowedNodeTypeModificationsMessage {
            scale_up_modifications: Some(up),
            scale_down_modifications: Some(down),
        })
    })
}
