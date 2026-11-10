//! Replication groups (Redis OSS and Valkey, cluster mode disabled and
//! enabled), their replicas, shards, failover and online migration.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use super::clusters::{self, Template};
use super::*;
use crate::backend::EngineKind;
use crate::catalog;
use crate::engine;
use crate::generated::{errors, types as t};
use crate::state::{AuthTokens, Cluster, RegionState, ReplicationGroup};
use crate::ElastiCache;

pub(crate) fn not_found(id: &str) -> ServiceError {
    errors::replication_group_not_found_fault(format!("ReplicationGroup {id} not found."))
}

fn not_available(id: &str) -> ServiceError {
    errors::invalid_replication_group_state_fault(format!("Replication group {id} is not in available state."))
}

fn enabled(v: bool) -> String {
    if v { "enabled" } else { "disabled" }.to_string()
}

fn proxy_key(key: &str, rg: &str, which: &str) -> String {
    format!("{key}/rg/{rg}/{which}")
}

/// Members of a replication group, ordered by id.
fn members<'a>(r: &'a RegionState, rg: &str) -> Vec<&'a Cluster> {
    r.clusters.values().filter(|c| c.info.replication_group_id.as_deref() == Some(rg)).collect()
}

/// Rebuild what DescribeReplicationGroups shows from the member clusters.
pub(crate) fn refresh(svc: &ElastiCache, r: &mut RegionState, rg_id: &str) {
    let Some(g) = r.replication_groups.get(rg_id) else { return };
    let cluster_mode = g.cluster_enabled();
    let status = g.info.status.clone().unwrap_or_default();
    let (pport, rport) = (g.primary_port, g.reader_port);
    let slots = g.slots.clone();
    let mut groups: BTreeMap<String, t::NodeGroup> = BTreeMap::new();
    let mut member_ids = Vec::new();
    for c in members(r, rg_id) {
        member_ids.push(c.id().to_string());
        let ng = c.node_group_id.clone().unwrap_or_else(|| "0001".into());
        let node = c.info.cache_nodes.iter().flatten().next();
        let group = groups.entry(ng.clone()).or_insert_with(|| t::NodeGroup {
            node_group_id: Some(ng.clone()),
            status: Some(if status == "available" { "available".into() } else { status.clone() }),
            primary_endpoint: (!cluster_mode).then(|| endpoint(svc, pport)),
            reader_endpoint: (!cluster_mode).then(|| endpoint(svc, rport)),
            slots: if cluster_mode { slots.get(&ng).cloned() } else { None },
            node_group_members: Some(vec![]),
        });
        group.node_group_members.get_or_insert_with(Vec::new).push(t::NodeGroupMember {
            cache_cluster_id: Some(c.id().to_string()),
            cache_node_id: node.and_then(|n| n.cache_node_id.clone()),
            read_endpoint: node.and_then(|n| n.endpoint.clone()),
            preferred_availability_zone: node.and_then(|n| n.customer_availability_zone.clone()),
            preferred_outpost_arn: None,
            current_role: (!cluster_mode).then(|| c.role.clone().unwrap_or_else(|| "replica".into())),
        });
    }
    for g in groups.values_mut() {
        // The primary first, as AWS lists them.
        if let Some(m) = g.node_group_members.as_mut() {
            m.sort_by_key(|x| (x.current_role.as_deref() != Some("primary"), x.cache_cluster_id.clone()));
        }
    }
    if let Some(g) = r.replication_groups.get_mut(rg_id) {
        g.info.member_clusters = Some(member_ids);
        g.info.node_groups = Some(groups.into_values().collect());
        g.info.configuration_endpoint = cluster_mode.then(|| endpoint(svc, pport));
    }
}

/// Open (or reopen, on their saved ports) a group's endpoint proxies.
pub(crate) fn open_proxies(svc: &ElastiCache, key: &str, rg_id: &str, reopen: bool) {
    if !svc.runs_engines() {
        return;
    }
    let bind = svc.options().bind_address.clone();
    let (cluster_mode, pport, rport) = {
        let state = svc.lock();
        let Some(g) = state.regions.get(key).and_then(|r| r.replication_groups.get(rg_id)) else { return };
        (g.cluster_enabled(), g.primary_port, g.reader_port)
    };
    let open = |which: &str, port: u16| {
        svc.proxies().open(&proxy_key(key, rg_id, which), &bind, if reopen { port } else { 0 }).unwrap_or(port)
    };
    let p = open(if cluster_mode { "configuration" } else { "primary" }, pport);
    let rp = if cluster_mode { 0 } else { open("reader", rport) };
    let mut state = svc.lock();
    if let Some(r) = state.regions.get_mut(key) {
        if let Some(g) = r.replication_groups.get_mut(rg_id) {
            g.primary_port = p;
            g.reader_port = rp;
        }
        drop(state);
        svc.with_existing(key, |r| {
            refresh(svc, r, rg_id);
            route(svc, key, r, rg_id);
        });
    }
}

/// Point a group's endpoints at its current primaries and replicas.
pub(crate) fn route(svc: &ElastiCache, key: &str, r: &RegionState, rg_id: &str) {
    if !svc.runs_engines() {
        return;
    }
    let Some(g) = r.replication_groups.get(rg_id) else { return };
    let host = engine::connect_host(svc);
    let running = |c: &&Cluster| c.nodes.values().any(|n| n.handle.is_some());
    let primaries: Vec<(String, u16)> = members(r, rg_id)
        .into_iter()
        .filter(running)
        .filter(|c| c.role.as_deref() == Some("primary"))
        .filter_map(|c| c.nodes.values().next().map(|n| (host.clone(), n.port)))
        .collect();
    let replicas: Vec<(String, u16)> = members(r, rg_id)
        .into_iter()
        .filter(running)
        .filter(|c| c.role.as_deref() != Some("primary"))
        .filter_map(|c| c.nodes.values().next().map(|n| (host.clone(), n.port)))
        .collect();
    if g.cluster_enabled() {
        svc.proxies().set_targets(&proxy_key(key, rg_id, "configuration"), primaries);
    } else {
        svc.proxies().set_targets(&proxy_key(key, rg_id, "primary"), primaries.clone());
        let readers = if replicas.is_empty() { primaries } else { replicas };
        svc.proxies().set_targets(&proxy_key(key, rg_id, "reader"), readers);
    }
}

/// The group's work finished: everything is available again.
pub(crate) fn became_available(svc: &ElastiCache, ctx: &RequestContext, r: &mut RegionState, rg_id: &str) {
    let at = now(ctx).max(chrono::Utc::now());
    let Some(g) = r.replication_groups.get_mut(rg_id) else { return };
    let created = g.status() == "creating";
    g.info.status = Some("available".into());
    g.info.pending_modified_values = Some(t::ReplicationGroupPendingModifiedValues::default());
    let topic = None::<String>;
    let resource = g.info.arn.clone().unwrap_or_default();
    let ids: Vec<String> = members(r, rg_id).iter().map(|c| c.id().to_string()).collect();
    let mut topic = topic;
    for id in &ids {
        if let Some(c) = r.clusters.get_mut(id) {
            let was_creating = c.status() == "creating";
            c.set_status("available");
            topic = topic.or_else(|| c.info.notification_configuration.as_ref().and_then(|n| n.topic_arn.clone()));
            if was_creating {
                let az = c
                    .info
                    .cache_nodes
                    .iter()
                    .flatten()
                    .next()
                    .and_then(|n| n.customer_availability_zone.clone())
                    .unwrap_or_default();
                r.event(id, "cache-cluster", "Cache cluster created", at);
                r.event(id, "cache-cluster", format!("Added cache node 0001 in availability zone {az}"), at);
            }
        }
    }
    if created {
        r.event(rg_id, "replication-group", format!("Replication group {rg_id} created"), at);
        notify(svc, ctx, topic.as_deref(), &resource, "ElastiCache:ReplicationGroupCreated");
    }
    refresh(svc, r, rg_id);
    route(svc, &region_key_of(r, ctx), r, rg_id);
}

fn region_key_of(_r: &RegionState, ctx: &RequestContext) -> String {
    region_key(ctx)
}

/// Which clusters a new group has: `(cluster id, node group, role, az)`.
fn layout(
    rg: &str,
    cluster_mode: bool,
    shards: &[(String, usize, Vec<String>)],
    primary_cluster: Option<&str>,
) -> Vec<(String, String, String, Option<String>)> {
    let mut out = Vec::new();
    for (ng, replicas, azs) in shards {
        for i in 0..=*replicas {
            let id = if cluster_mode {
                format!("{rg}-{ng}-{:03}", i + 1)
            } else if i == 0 && primary_cluster.is_some() {
                primary_cluster.unwrap_or_default().to_string()
            } else {
                format!("{rg}-{:03}", i + 1)
            };
            let role = if i == 0 { "primary" } else { "replica" };
            out.push((id, ng.clone(), role.to_string(), azs.get(i).cloned()));
        }
    }
    out
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateReplicationGroupMessage,
) -> Result<t::CreateReplicationGroupResult, ServiceError> {
    let id = identifier("ReplicationGroupId", &input.replication_group_id, 40)?;
    if input.replication_group_description.trim().is_empty() {
        return Err(invalid("The parameter ReplicationGroupDescription must be provided and must not be blank."));
    }
    let key = region_key(ctx);
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    // A secondary of a global datastore takes its settings from the
    // primary.
    let global = match input.global_replication_group_id.as_deref() {
        Some(gid) => Some(super::global::secondary_settings(svc, ctx, gid)?),
        None => None,
    };
    let primary_cluster = input.primary_cluster_id.clone().map(|p| p.to_ascii_lowercase());
    let from_primary: Option<Cluster> = match &primary_cluster {
        Some(p) => Some(svc.with_region(ctx, |r| {
            let c = r.clusters.get(p).cloned().ok_or_else(|| clusters::not_found(p))?;
            if c.info.replication_group_id.is_some() {
                return Err(combination(format!("Cache cluster {p} is already a member of a replication group.")));
            }
            if !c.engine().is_redis_like() {
                return Err(combination("Replication groups are not supported for memcached clusters."));
            }
            if c.status() != "available" {
                return Err(errors::invalid_cache_cluster_state_fault(format!(
                    "Cache cluster {p} is not in available state."
                )));
            }
            Ok(c)
        })?),
        None => None,
    };
    let engine = match (&global, &from_primary) {
        (Some(g), _) => g.engine,
        (_, Some(c)) => c.engine(),
        _ => clusters::engine_of(input.engine.as_deref(), EngineKind::Redis)?,
    };
    if !engine.is_redis_like() {
        return Err(invalid("Replication groups are only supported for the redis and valkey engines."));
    }
    let version = match (&global, &from_primary) {
        (Some(g), _) => clusters::version_of(engine, Some(&g.engine_version))?,
        (_, Some(c)) => clusters::version_of(engine, c.info.engine_version.as_deref())?,
        _ => clusters::version_of(engine, input.engine_version.as_deref())?,
    };
    let node_type = match (&global, &from_primary) {
        (Some(g), _) => g.node_type.clone(),
        (_, Some(c)) => c.info.cache_node_type.clone().unwrap_or_default(),
        _ => clusters::check_node_type(input.cache_node_type.as_deref())?,
    };
    if input.data_tiering_enabled == Some(true) && !catalog::supports_data_tiering(&node_type) {
        return Err(combination("Data tiering is only supported for the r6gd node types."));
    }
    let mut pg_name = input.cache_parameter_group_name.clone();
    let ng_count = input
        .node_group_configuration
        .as_ref()
        .map(|c| c.len())
        .filter(|n| *n > 0)
        .or(input.num_node_groups.map(|n| n.max(0) as usize))
        .or(global.as_ref().map(|g| g.shards));
    let wants_cluster = input.cluster_mode.as_deref() == Some("enabled")
        || ng_count.is_some_and(|n| n > 1)
        || global.as_ref().is_some_and(|g| g.cluster_enabled);
    if pg_name.is_none() && wants_cluster {
        pg_name = Some(format!("default.{}.cluster.on", version.family));
    }
    let (pg, cluster_mode) = svc.with_region(ctx, |r| {
        let pg = clusters::parameter_group_for(r, pg_name.as_deref(), version, false)?;
        let on = super::params::cluster_enabled(r, &pg);
        Ok::<_, ServiceError>((pg, on))
    })?;
    if wants_cluster && !cluster_mode {
        return Err(combination(format!(
            "Cluster mode is disabled in parameter group {pg}; use a parameter group with cluster-enabled set to yes for more than one node group."
        )));
    }
    if input.cluster_mode.as_deref() == Some("disabled") && cluster_mode {
        return Err(combination("ClusterMode disabled cannot be used with a cluster mode enabled parameter group."));
    }
    if cluster_mode && from_primary.is_some() {
        return Err(combination("PrimaryClusterId is not supported for cluster mode enabled replication groups."));
    }
    // Shards: (node group id, replicas, AZs).
    let mut shards: Vec<(String, usize, Vec<String>)> = Vec::new();
    let mut slot_ranges: BTreeMap<String, String> = BTreeMap::new();
    if cluster_mode {
        let n = ng_count.unwrap_or(1);
        if n == 0 {
            return Err(invalid("The parameter NumNodeGroups must be greater than 0."));
        }
        if n > 500 {
            return Err(errors::node_groups_per_replication_group_quota_exceeded_fault(
                "The number of node groups per replication group exceeds the quota of 500.",
            ));
        }
        let even = engine::even_slots(n);
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let cfg = input.node_group_configuration.as_ref().and_then(|c| c.get(i));
            let ng = cfg.and_then(|c| c.node_group_id.clone()).unwrap_or_else(|| format!("{:04}", i + 1));
            let replicas = cfg
                .and_then(|c| c.replica_count)
                .or(input.replicas_per_node_group)
                .or(global.as_ref().map(|g| g.replicas))
                .unwrap_or(0);
            if !(0..=5).contains(&replicas) {
                return Err(invalid("The number of replicas per node group must be within 0 and 5."));
            }
            let mut azs: Vec<String> = cfg.and_then(|c| c.primary_availability_zone.clone()).into_iter().collect();
            azs.extend(cfg.and_then(|c| c.replica_availability_zones.clone()).unwrap_or_default());
            let slots = cfg.and_then(|c| c.slots.clone()).unwrap_or_else(|| engine::format_slots(&[even[i]]));
            slot_ranges.insert(ng.clone(), slots);
            shards.push((ng, replicas as usize, azs));
        }
        let mut seen = vec![false; 16384];
        for s in slot_ranges.values() {
            for (a, b) in engine::parse_slots(s) {
                if a > b || b > 16383 {
                    return Err(invalid(format!("Invalid slot range: {s}")));
                }
                for x in a..=b {
                    if std::mem::replace(&mut seen[x as usize], true) {
                        return Err(invalid("Slot ranges of node groups must not overlap."));
                    }
                }
            }
        }
        if seen.iter().any(|s| !s) {
            return Err(invalid("The node groups' slot ranges must cover all 16384 slots."));
        }
    } else {
        let count = input
            .num_cache_clusters
            .or(input.replicas_per_node_group.map(|r| r + 1))
            .or(input
                .node_group_configuration
                .as_ref()
                .and_then(|c| c.first())
                .and_then(|c| c.replica_count)
                .map(|r| r + 1))
            .or(input.preferred_cache_cluster_a_zs.as_ref().map(|z| z.len() as i32).filter(|n| *n > 0))
            .or(global.as_ref().map(|g| g.replicas + 1))
            .unwrap_or(1);
        if !(1..=6).contains(&count) {
            return Err(invalid("The parameter NumCacheClusters must be within 1 and 6."));
        }
        let azs = input.preferred_cache_cluster_a_zs.clone().unwrap_or_default();
        shards.push(("0001".into(), count as usize - 1, azs));
    }
    let per_shard = shards.iter().map(|s| s.1 + 1).min().unwrap_or(1);
    let auto_failover = input.automatic_failover_enabled.unwrap_or(cluster_mode);
    if cluster_mode && input.automatic_failover_enabled == Some(false) {
        return Err(combination("Automatic failover must be enabled for cluster mode enabled replication groups."));
    }
    if auto_failover && per_shard < 2 && !cluster_mode {
        return Err(combination(
            "Must have at least 2 cache clusters in the replication group when automatic failover is enabled.",
        ));
    }
    let multi_az = input.multi_az_enabled.unwrap_or(false);
    if multi_az && !auto_failover {
        return Err(combination("Multi-AZ requires automatic failover to be enabled."));
    }
    let transit = input.transit_encryption_enabled.unwrap_or(false)
        || input.transit_encryption_mode.is_some()
        || global.as_ref().is_some_and(|g| g.transit);
    if let Some(tok) = &input.auth_token {
        clusters::check_auth_token(tok)?;
        if !transit {
            return Err(combination("AuthToken can only be specified when TransitEncryptionEnabled is true."));
        }
    }
    let user_groups = input.user_group_ids.clone().unwrap_or_default();
    if !user_groups.is_empty() {
        if input.auth_token.is_some() {
            return Err(combination("AuthToken and UserGroupIds cannot be specified together."));
        }
        if !transit {
            return Err(combination("UserGroupIds can only be specified when TransitEncryptionEnabled is true."));
        }
        if user_groups.len() > 1 {
            return Err(invalid("Only one user group can be associated with a replication group."));
        }
    }
    if let Some(w) = &input.preferred_maintenance_window {
        check_window("PreferredMaintenanceWindow", w, true)?;
    }
    if let Some(w) = &input.snapshot_window {
        check_window("SnapshotWindow", w, false)?;
    }
    let resource = arn(ctx, "replicationgroup", &id);
    authorize_create(
        ctx,
        "CreateReplicationGroup",
        &resource,
        &tags,
        cond(&[
            ("CacheNodeType", Some(node_type.clone())),
            ("EngineVersion", Some(version.version.into())),
            ("EngineType", Some(engine.as_str().into())),
            ("NumNodeGroups", Some(shards.len().to_string())),
            ("ReplicasPerNodeGroup", Some((per_shard - 1).to_string())),
            ("MultiAZEnabled", Some(multi_az.to_string())),
            ("AutomaticFailoverEnabled", Some(auto_failover.to_string())),
            ("AtRestEncryptionEnabled", Some(input.at_rest_encryption_enabled.unwrap_or(false).to_string())),
            ("TransitEncryptionEnabled", Some(transit.to_string())),
            ("AuthTokenEnabled", Some(input.auth_token.is_some().to_string())),
            ("CacheParameterGroupName", Some(pg.clone())),
            ("SnapshotRetentionLimit", input.snapshot_retention_limit.map(|v| v.to_string())),
            ("KmsKeyId", input.kms_key_id.clone()),
            ("ClusterModeEnabled", Some(cluster_mode.to_string())),
        ]),
    )?;
    if let Some(k) = input.kms_key_id.as_deref() {
        svc.check_kms_key(ctx, k)?;
    }
    let log = clusters::log_delivery(&input.log_delivery_configurations)?;
    let shown = svc.with_region(ctx, |r| {
        if r.replication_groups.contains_key(&id) {
            return Err(errors::replication_group_already_exists_fault(format!(
                "Replication group {id} already exists."
            )));
        }
        for ug in &user_groups {
            let g = r.user_groups.get(ug).ok_or_else(|| super::users::group_not_found(ug))?;
            if g.status.as_deref() != Some("active") {
                return Err(errors::invalid_user_group_state_fault(format!("User group {ug} is not in active state.")));
            }
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
        let (subnet_group, zones, sgs) = clusters::placement(
            svc,
            ctx,
            r,
            input.cache_subnet_group_name.as_deref(),
            &input.security_group_ids,
            &input.cache_security_group_names,
        )?;
        let tpl = Template {
            engine,
            version,
            node_type: node_type.clone(),
            port: input.port.map(|p| p as u16).unwrap_or(6379),
            parameter_group: pg.clone(),
            subnet_group: subnet_group.clone(),
            security_groups: sgs,
            maintenance_window: input
                .preferred_maintenance_window
                .clone()
                .unwrap_or_else(clusters::default_maintenance_window),
            snapshot_window: Some(input.snapshot_window.clone().unwrap_or_else(clusters::default_snapshot_window)),
            snapshot_retention: input.snapshot_retention_limit.unwrap_or(0),
            notification_topic: input.notification_topic_arn.clone(),
            auto_minor_version_upgrade: input.auto_minor_version_upgrade.unwrap_or(true),
            transit_encryption: transit,
            at_rest_encryption: input.at_rest_encryption_enabled.unwrap_or(false),
            auth_token_enabled: input.auth_token.is_some(),
            network_type: input.network_type.clone().unwrap_or_else(|| "ipv4".into()),
            ip_discovery: input.ip_discovery.clone().unwrap_or_else(|| "ipv4".into()),
            log_delivery: log.clone(),
        };
        let plan = layout(&id, cluster_mode, &shards, primary_cluster.as_deref());
        for (cid, _, _, _) in &plan {
            if r.clusters.contains_key(cid) && Some(cid) != primary_cluster.as_ref() {
                return Err(errors::cache_cluster_already_exists_fault(format!("Cache cluster {cid} already exists.")));
            }
        }
        let internal = random_password();
        let at = now(ctx);
        for (i, (cid, ng, role, az)) in plan.iter().enumerate() {
            let azs = vec![az.clone().unwrap_or_else(|| zones[i % zones.len().max(1)].clone())];
            let mut c = if Some(cid) == primary_cluster.as_ref() {
                let mut c = from_primary.clone().unwrap_or_default();
                c.info.replication_group_id = Some(id.clone());
                c
            } else {
                clusters::build(svc, ctx, cid, &tpl, &azs, 1, Some(&id))
            };
            c.node_group_id = Some(ng.clone());
            c.role = Some(role.clone());
            if role == "primary" {
                c.seed_snapshot = seed.clone();
                c.seed_rdb = input.snapshot_arns.clone().filter(|a| !a.is_empty());
            }
            r.clusters.insert(cid.clone(), c);
        }
        let kms = input.kms_key_id.clone();
        let mut g = ReplicationGroup {
            info: t::ReplicationGroup {
                replication_group_id: Some(id.clone()),
                description: Some(input.replication_group_description.clone()),
                global_replication_group_info: global.as_ref().map(|g| t::GlobalReplicationGroupInfo {
                    global_replication_group_id: Some(g.id.clone()),
                    global_replication_group_member_role: Some("SECONDARY".into()),
                }),
                status: Some("creating".into()),
                pending_modified_values: Some(t::ReplicationGroupPendingModifiedValues::default()),
                member_clusters: None,
                node_groups: None,
                snapshotting_cluster_id: (tpl.snapshot_retention > 0 && !cluster_mode)
                    .then(|| plan.last().map(|p| p.0.clone()))
                    .flatten(),
                automatic_failover: Some(enabled(auto_failover)),
                multi_az: Some(enabled(multi_az)),
                configuration_endpoint: None,
                snapshot_retention_limit: Some(tpl.snapshot_retention),
                snapshot_window: tpl.snapshot_window.clone(),
                cluster_enabled: Some(cluster_mode),
                cache_node_type: Some(node_type.clone()),
                auth_token_enabled: Some(input.auth_token.is_some()),
                auth_token_last_modified_date: input.auth_token.is_some().then_some(at),
                transit_encryption_enabled: Some(transit),
                at_rest_encryption_enabled: Some(tpl.at_rest_encryption),
                member_clusters_outpost_arns: None,
                kms_key_id: kms,
                storage_encryption_type: None,
                arn: Some(resource.clone()),
                user_group_ids: Some(user_groups.clone()),
                log_delivery_configurations: Some(log.clone()),
                replication_group_create_time: Some(at),
                data_tiering: Some(enabled(input.data_tiering_enabled == Some(true))),
                auto_minor_version_upgrade: Some(tpl.auto_minor_version_upgrade),
                network_type: Some(tpl.network_type.clone()),
                ip_discovery: Some(tpl.ip_discovery.clone()),
                transit_encryption_mode: transit
                    .then(|| input.transit_encryption_mode.clone().unwrap_or_else(|| "required".into())),
                cluster_mode: Some(input.cluster_mode.clone().unwrap_or_else(|| enabled(cluster_mode))),
                engine: Some(engine.as_str().into()),
                durability: input.durability.clone(),
                effective_durability: input.durability.clone(),
            },
            engine_version: version.version.into(),
            parameter_group: pg.clone(),
            subnet_group: Some(subnet_group),
            port: tpl.port,
            auth: AuthTokens { current: input.auth_token.clone(), previous: None },
            internal_password: Some(internal),
            primary_port: tpl.port,
            reader_port: tpl.port,
            slots: slot_ranges.clone(),
            migration: None,
            pending_since: None,
        };
        if let Some(c) = primary_cluster.as_ref().and_then(|p| r.clusters.get(p)) {
            // The existing cluster keeps its credentials.
            g.auth = c.auth.clone();
            g.internal_password = c.internal_password.clone();
        }
        r.replication_groups.insert(id.clone(), g);
        for ug in &user_groups {
            if let Some(g) = r.user_groups.get_mut(ug) {
                g.replication_groups.get_or_insert_with(Vec::new).push(id.clone());
            }
        }
        set_tags(r, &resource, input.tags.clone());
        refresh(svc, r, &id);
        Ok(r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default())
    })?;
    if let Some(g) = &global {
        super::global::add_secondary(svc, ctx, &g.id, &id);
    }
    open_proxies(svc, &key, &id, false);
    let shown = svc.with_key(&key, ctx, |r| r.replication_groups.get(&id).map(|g| g.info.clone())).unwrap_or(shown);
    if from_primary.is_some() {
        // The primary already runs: only the new replicas start.
        let new: Vec<String> = svc.with_key(&key, ctx, |r| {
            members(r, &id)
                .iter()
                .filter(|c| c.role.as_deref() != Some("primary"))
                .map(|c| c.id().to_string())
                .collect()
        });
        engine::add_replicas(svc, ctx, &key, &id, new);
    } else {
        engine::start_replication_group(svc, ctx, &key, &id);
    }
    if let Some(g) = &global {
        super::global::link_secondary(svc, ctx, &g.id, &key, &id);
    }
    Ok(t::CreateReplicationGroupResult { replication_group: Some(shown) })
}

/// CreateCacheCluster with a ReplicationGroupId: a new read replica.
pub(crate) async fn add_cluster(
    svc: &ElastiCache,
    ctx: &RequestContext,
    id: &str,
    rg: &str,
    input: t::CreateCacheClusterMessage,
) -> Result<t::CreateCacheClusterResult, ServiceError> {
    let key = region_key(ctx);
    let resource = arn(ctx, "cluster", id);
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    authorize_create(ctx, "CreateCacheCluster", &resource, &tags, Default::default())?;
    let shown = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(rg).cloned().ok_or_else(|| not_found(rg))?;
        if g.status() != "available" {
            return Err(not_available(rg));
        }
        if g.cluster_enabled() {
            return Err(combination(
                "Use IncreaseReplicaCount to add replicas to a cluster mode enabled replication group.",
            ));
        }
        if r.clusters.contains_key(id) {
            return Err(errors::cache_cluster_already_exists_fault(format!("Cache cluster {id} already exists.")));
        }
        if members(r, rg).len() >= 6 {
            return Err(errors::node_quota_for_cluster_exceeded_fault(
                "A replication group can have at most 5 read replicas.",
            ));
        }
        let primary =
            members(r, rg).into_iter().find(|c| c.role.as_deref() == Some("primary")).cloned().unwrap_or_default();
        let mut c = replica_like(svc, ctx, &primary, id, input.preferred_availability_zone.clone());
        c.node_group_id = Some("0001".into());
        let shown = c.info.clone();
        r.clusters.insert(id.to_string(), c);
        set_tags(r, &resource, input.tags.clone());
        if let Some(g) = r.replication_groups.get_mut(rg) {
            g.info.status = Some("modifying".into());
        }
        refresh(svc, r, rg);
        Ok(shown)
    })?;
    engine::add_replicas(svc, ctx, &key, rg, vec![id.to_string()]);
    Ok(t::CreateCacheClusterResult { cache_cluster: Some(clusters::without_nodes(shown)) })
}

/// A new replica cluster configured like `primary`.
fn replica_like(svc: &ElastiCache, ctx: &RequestContext, primary: &Cluster, id: &str, az: Option<String>) -> Cluster {
    let at = now(ctx);
    let port = alloc_port(svc, primary.port);
    let mut c = primary.clone();
    c.info.cache_cluster_id = Some(id.to_string());
    c.info.arn = Some(arn(ctx, "cluster", id));
    c.info.cache_cluster_create_time = Some(at);
    c.info.cache_cluster_status = Some("creating".into());
    let az =
        az.or_else(|| primary.info.preferred_availability_zone.clone()).unwrap_or_else(|| format!("{}a", ctx.region));
    c.info.preferred_availability_zone = Some(az.clone());
    c.info.cache_nodes = Some(vec![t::CacheNode {
        cache_node_id: Some("0001".into()),
        cache_node_status: Some("creating".into()),
        cache_node_create_time: Some(at),
        endpoint: Some(endpoint(svc, port)),
        parameter_group_status: Some("in-sync".into()),
        source_cache_node_id: Some("0001".into()),
        customer_availability_zone: Some(az),
        customer_outpost_arn: None,
    }]);
    c.nodes = BTreeMap::from([("0001".to_string(), crate::state::NodeRuntime { handle: None, port, peer: None })]);
    c.role = Some("replica".into());
    c.seed_snapshot = None;
    c.seed_rdb = None;
    c
}

/// A member cluster left its group (deleted).
pub(crate) fn forget_member(r: &mut RegionState, rg: &str, id: &str) {
    if let Some(g) = r.replication_groups.get_mut(rg) {
        if g.info.snapshotting_cluster_id.as_deref() == Some(id) {
            g.info.snapshotting_cluster_id = None;
        }
    }
    let svc_less = r.clusters.contains_key(id);
    let _ = svc_less;
    // Node groups are rebuilt from the remaining members on describe.
    if let Some(g) = r.replication_groups.get_mut(rg) {
        if let Some(m) = g.info.member_clusters.as_mut() {
            m.retain(|x| x != id);
        }
        for ng in g.info.node_groups.iter_mut().flatten() {
            if let Some(list) = ng.node_group_members.as_mut() {
                list.retain(|m| m.cache_cluster_id.as_deref() != Some(id));
            }
        }
    }
}

pub(crate) async fn describe(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeReplicationGroupsMessage,
) -> Result<t::ReplicationGroupMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        let items: Vec<t::ReplicationGroup> = match input.replication_group_id.as_deref() {
            Some(id) => {
                let id = id.to_ascii_lowercase();
                let g = r.replication_groups.get(&id).ok_or_else(|| not_found(&id))?;
                authorize(
                    ctx,
                    r,
                    "DescribeReplicationGroups",
                    g.info.arn.as_deref().unwrap_or_default(),
                    Default::default(),
                )?;
                vec![g.info.clone()]
            }
            None => {
                ctx.authorize(
                    "elasticache:DescribeReplicationGroups",
                    &arn(ctx, "replicationgroup", "*"),
                    Default::default(),
                )?;
                r.replication_groups.values().map(|g| g.info.clone()).collect()
            }
        };
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::ReplicationGroupMessage { marker, replication_groups: Some(page) })
    })
}

/// Apply an AUTH token change; returns the engine commands that make it
/// real. `SET` replaces the token, `ROTATE` adds one (both work until the
/// next change), `DELETE` removes them (only with transit encryption).
pub(crate) fn change_auth(
    auth: &mut AuthTokens,
    token: Option<&str>,
    strategy: Option<&str>,
    transit: bool,
    acl: bool,
) -> Result<Vec<Vec<String>>, ServiceError> {
    let strategy = strategy.unwrap_or("ROTATE");
    if let Some(t) = token {
        clusters::check_auth_token(t)?;
    }
    if !transit {
        return Err(combination("AuthToken can only be modified when TransitEncryptionEnabled is true."));
    }
    let cmd = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    match (strategy, token) {
        ("SET", Some(t)) | ("ROTATE", Some(t)) if !auth.enabled() => {
            auth.current = Some(t.into());
            auth.previous = None;
            Ok(if acl {
                vec![cmd(&["ACL", "SETUSER", "default", "resetpass", &format!(">{t}")])]
            } else {
                vec![cmd(&["CONFIG", "SET", "requirepass", t]), cmd(&["CONFIG", "SET", "masterauth", t])]
            })
        }
        ("ROTATE", Some(t)) => {
            let prev = auth.current.replace(t.into());
            auth.previous = prev.clone();
            Ok(if acl {
                let mut c = cmd(&["ACL", "SETUSER", "default", "resetpass", &format!(">{t}")]);
                if let Some(p) = prev {
                    c.push(format!(">{p}"));
                }
                vec![c]
            } else {
                vec![cmd(&["CONFIG", "SET", "requirepass", t]), cmd(&["CONFIG", "SET", "masterauth", t])]
            })
        }
        ("SET", Some(t)) => {
            auth.current = Some(t.into());
            auth.previous = None;
            Ok(if acl {
                vec![cmd(&["ACL", "SETUSER", "default", "resetpass", &format!(">{t}")])]
            } else {
                vec![cmd(&["CONFIG", "SET", "requirepass", t]), cmd(&["CONFIG", "SET", "masterauth", t])]
            })
        }
        ("DELETE", None) => {
            if !auth.enabled() {
                return Err(combination("The replication group does not have an AUTH token to delete."));
            }
            *auth = AuthTokens::default();
            Ok(if acl {
                vec![cmd(&["ACL", "SETUSER", "default", "resetpass", "nopass"])]
            } else {
                vec![cmd(&["CONFIG", "SET", "requirepass", ""])]
            })
        }
        ("DELETE", Some(_)) => Err(combination("AuthToken cannot be specified with AuthTokenUpdateStrategy DELETE.")),
        (s, None) if s != "DELETE" => {
            Err(combination(format!("AuthToken is required with AuthTokenUpdateStrategy {s}.")))
        }
        (s, _) => Err(invalid(format!("Invalid AuthTokenUpdateStrategy: {s}"))),
    }
}

pub(crate) async fn modify(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyReplicationGroupMessage,
) -> Result<t::ModifyReplicationGroupResult, ServiceError> {
    let id = input.replication_group_id.to_ascii_lowercase();
    let key = region_key(ctx);
    let apply_now = input.apply_immediately == Some(true);
    let mut tls_change = None;
    let (shown, commands, failover_to, users_changed, upgrade) = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        let resource = g.info.arn.clone().unwrap_or_default();
        authorize(
            ctx,
            r,
            "ModifyReplicationGroup",
            &resource,
            cond(&[
                ("CacheNodeType", input.cache_node_type.clone()),
                ("EngineVersion", input.engine_version.clone()),
                ("CacheParameterGroupName", input.cache_parameter_group_name.clone()),
                ("AutomaticFailoverEnabled", b(input.automatic_failover_enabled)),
                ("MultiAZEnabled", b(input.multi_az_enabled)),
                ("TransitEncryptionEnabled", b(input.transit_encryption_enabled)),
                ("SnapshotRetentionLimit", input.snapshot_retention_limit.map(|v| v.to_string())),
            ]),
        )?;
        if g.status() != "available" {
            return Err(not_available(&id));
        }
        let mut g = g;
        let mut commands: Vec<Vec<String>> = Vec::new();
        let mut failover_to = None;
        let mut users_changed = false;
        let member_ids: Vec<String> = members(r, &id).iter().map(|c| c.id().to_string()).collect();
        let shard_min = {
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            for c in members(r, &id) {
                *counts.entry(c.node_group_id.clone().unwrap_or_default()).or_default() += 1;
            }
            counts.values().copied().min().unwrap_or(1)
        };
        if let Some(d) = &input.replication_group_description {
            g.info.description = Some(d.clone());
        }
        if let Some(af) = input.automatic_failover_enabled {
            if af && shard_min < 2 {
                return Err(combination(
                    "Must have at least 2 cache clusters in the replication group when automatic failover is enabled.",
                ));
            }
            if !af && g.cluster_enabled() {
                return Err(combination(
                    "Automatic failover cannot be disabled for cluster mode enabled replication groups.",
                ));
            }
            if !af
                && (input.multi_az_enabled == Some(true)
                    || (g.info.multi_az.as_deref() == Some("enabled") && input.multi_az_enabled != Some(false)))
            {
                return Err(combination("Multi-AZ requires automatic failover to be enabled."));
            }
            g.info.automatic_failover = Some(enabled(af));
        }
        if let Some(maz) = input.multi_az_enabled {
            if maz && g.info.automatic_failover.as_deref() != Some("enabled") {
                return Err(combination("Multi-AZ requires automatic failover to be enabled."));
            }
            g.info.multi_az = Some(enabled(maz));
        }
        if let Some(p) = &input.primary_cluster_id {
            let p = p.to_ascii_lowercase();
            if g.cluster_enabled() {
                return Err(combination(
                    "PrimaryClusterId is not supported for cluster mode enabled replication groups.",
                ));
            }
            if !member_ids.contains(&p) {
                return Err(invalid(format!("Cache cluster {p} is not a member of replication group {id}.")));
            }
            if r.clusters.get(&p).and_then(|c| c.role.clone()).as_deref() != Some("primary") {
                failover_to = Some(p);
            }
        }
        if let Some(s) = &input.snapshotting_cluster_id {
            if !member_ids.contains(s) {
                return Err(invalid(format!("Cache cluster {s} is not a member of replication group {id}.")));
            }
            g.info.snapshotting_cluster_id = Some(s.clone());
        }
        if let Some(v) = input.snapshot_retention_limit {
            g.info.snapshot_retention_limit = Some(v);
        }
        if let Some(w) = &input.snapshot_window {
            check_window("SnapshotWindow", w, false)?;
            g.info.snapshot_window = Some(w.clone());
        }
        // Without ApplyImmediately, node type and engine version changes
        // wait for the maintenance window (see `schedule`), shown meanwhile
        // in the member clusters' PendingModifiedValues.
        let mut pending_type = None;
        let mut pending_version = None;
        if let Some(nt) = &input.cache_node_type {
            clusters::check_node_type(Some(nt))?;
            if apply_now {
                g.info.cache_node_type = Some(nt.clone());
                let mem = catalog::node_type(nt).map(|n| n.maxmemory()).unwrap_or(0);
                commands.push(vec!["CONFIG".into(), "SET".into(), "maxmemory".into(), mem.to_string()]);
            } else if g.info.cache_node_type.as_deref() != Some(nt.as_str()) {
                pending_type = Some(nt.clone());
            }
        }
        let engine = g.engine();
        let target_engine = clusters::engine_of(input.engine.as_deref(), engine)?;
        if target_engine != engine && !(engine == EngineKind::Redis && target_engine == EngineKind::Valkey) {
            return Err(combination(format!(
                "Cannot change engine from {} to {}.",
                engine.as_str(),
                target_engine.as_str()
            )));
        }
        let mut new_version = None;
        if input.engine_version.is_some() || target_engine != engine {
            let target = clusters::version_of(target_engine, input.engine_version.as_deref())?;
            if target_engine == engine
                && clusters::version_cmp(target.version, &g.engine_version) == std::cmp::Ordering::Less
            {
                return Err(combination(format!(
                    "Cannot modify engine version from {} to {} because downgrades are not supported.",
                    g.engine_version, target.version
                )));
            }
            if !apply_now && target_engine == engine {
                if target.version != g.engine_version {
                    pending_version = Some(target.version.to_string());
                }
            } else {
                g.engine_version = target.version.into();
                g.info.engine = Some(target_engine.as_str().into());
                if g.parameter_group.starts_with("default.") {
                    g.parameter_group = if g.cluster_enabled() {
                        format!("default.{}.cluster.on", target.family)
                    } else {
                        format!("default.{}", target.family)
                    };
                }
                new_version = Some((target_engine, target.version));
            }
        }
        if pending_type.is_some() || pending_version.is_some() {
            g.pending_since = Some(now(ctx));
        }
        if let Some(pg) = &input.cache_parameter_group_name {
            let family = super::params::family_of(r, pg).ok_or_else(|| {
                errors::cache_parameter_group_not_found_fault(format!("CacheParameterGroup {pg} not found."))
            })?;
            let want = catalog::ENGINE_VERSIONS
                .iter()
                .find(|v| v.version == g.engine_version)
                .map(|v| v.family)
                .unwrap_or_default();
            if family != want {
                return Err(combination(format!(
                    "The parameter group {pg} has family {family}, which is not compatible with engine version {}.",
                    g.engine_version
                )));
            }
            if super::params::cluster_enabled(r, pg) != g.cluster_enabled() {
                return Err(combination(
                    "The parameter group's cluster-enabled setting does not match the replication group.",
                ));
            }
            g.parameter_group = pg.clone();
            for (k, v) in super::params::engine_values(r, pg) {
                commands.push(vec!["CONFIG".into(), "SET".into(), k, v]);
            }
        }
        if let Some(te) = input.transit_encryption_enabled {
            if (g.info.transit_encryption_enabled == Some(true)) != te {
                if g.cluster_enabled() {
                    return Err(combination(
                        "TransitEncryptionEnabled cannot be changed on a cluster mode enabled replication group.",
                    ));
                }
                tls_change = Some(te);
            }
            g.info.transit_encryption_enabled = Some(te);
            g.info.transit_encryption_mode =
                te.then(|| input.transit_encryption_mode.clone().unwrap_or_else(|| "preferred".into()));
        } else if let Some(mode) = &input.transit_encryption_mode {
            if g.info.transit_encryption_enabled != Some(true) {
                return Err(combination("TransitEncryptionMode requires TransitEncryptionEnabled."));
            }
            g.info.transit_encryption_mode = Some(mode.clone());
        }
        if input.auth_token.is_some() || input.auth_token_update_strategy.is_some() {
            if g.info.user_group_ids.as_ref().is_some_and(|u| !u.is_empty()) {
                return Err(combination("AuthToken cannot be used with a replication group that has user groups."));
            }
            let acl = engine::acl_capable(engine, &g.engine_version);
            commands.extend(change_auth(
                &mut g.auth,
                input.auth_token.as_deref(),
                input.auth_token_update_strategy.as_deref(),
                g.info.transit_encryption_enabled == Some(true),
                acl,
            )?);
            g.info.auth_token_enabled = Some(g.auth.enabled());
            g.info.auth_token_last_modified_date = Some(now(ctx));
        }
        let mut groups = g.info.user_group_ids.clone().unwrap_or_default();
        let before = groups.clone();
        if input.remove_user_groups == Some(true) {
            groups.clear();
        }
        for ug in input.user_group_ids_to_remove.iter().flatten() {
            if !groups.contains(ug) {
                return Err(invalid(format!("User group {ug} is not associated with replication group {id}.")));
            }
            groups.retain(|x| x != ug);
        }
        for ug in input.user_group_ids_to_add.iter().flatten() {
            let u = r.user_groups.get(ug).ok_or_else(|| super::users::group_not_found(ug))?;
            if u.engine.as_deref().is_some_and(|e| e != engine.as_str() && !(e == "redis" || e == "valkey")) {
                return Err(combination(format!("User group {ug} is for another engine.")));
            }
            if g.auth.enabled() {
                return Err(combination("User groups cannot be added to a replication group that uses an AUTH token."));
            }
            if g.info.transit_encryption_enabled != Some(true) {
                return Err(combination("User groups require TransitEncryptionEnabled."));
            }
            if !groups.contains(ug) {
                groups.push(ug.clone());
            }
        }
        if groups.len() > 1 {
            return Err(invalid("Only one user group can be associated with a replication group."));
        }
        if groups != before {
            users_changed = true;
            for ug in &before {
                if !groups.contains(ug) {
                    if let Some(u) = r.user_groups.get_mut(ug) {
                        if let Some(list) = u.replication_groups.as_mut() {
                            list.retain(|x| x != &id);
                        }
                    }
                }
            }
            for ug in &groups {
                if let Some(u) = r.user_groups.get_mut(ug) {
                    let list = u.replication_groups.get_or_insert_with(Vec::new);
                    if !list.contains(&id) {
                        list.push(id.clone());
                    }
                }
            }
            commands.extend(super::users::reset_acl_commands(r, &before, &groups));
            g.info.user_group_ids = Some(groups);
        }
        if input.log_delivery_configurations.is_some() {
            g.info.log_delivery_configurations = Some(clusters::merge_log_delivery(
                g.info.log_delivery_configurations.clone().unwrap_or_default(),
                &input.log_delivery_configurations,
            )?);
        }
        if let Some(ip) = &input.ip_discovery {
            g.info.ip_discovery = Some(ip.clone());
        }
        if let Some(mode) = &input.cluster_mode {
            let cur = g.info.cluster_mode.clone().unwrap_or_default();
            let ok = matches!(
                (cur.as_str(), mode.as_str()),
                ("disabled", "compatible") | ("compatible", "enabled") | ("compatible", "disabled")
            ) || cur == *mode;
            if !ok {
                return Err(combination(format!("Cannot change ClusterMode from {cur} to {mode}.")));
            }
            g.info.cluster_mode = Some(mode.clone());
        }
        if let Some(d) = &input.durability {
            g.info.durability = Some(d.clone());
            g.info.effective_durability = Some(d.clone());
        }
        if failover_to.is_some() {
            g.info.status = Some("modifying".into());
        }
        let pg_name = g.parameter_group.clone();
        r.replication_groups.insert(id.clone(), g.clone());
        // Settings that live on the member clusters.
        for m in &member_ids {
            if let Some(c) = r.clusters.get_mut(m) {
                if let Some(nt) = input.cache_node_type.as_ref().filter(|_| apply_now) {
                    c.info.cache_node_type = Some(nt.clone());
                }
                if pending_type.is_some() || pending_version.is_some() {
                    let p = c.info.pending_modified_values.get_or_insert_with(Default::default);
                    if pending_type.is_some() {
                        p.cache_node_type = pending_type.clone();
                    }
                    if pending_version.is_some() {
                        p.engine_version = pending_version.clone();
                    }
                }
                if apply_now {
                    // What was pending is applied now.
                    if let Some(p) = c.info.pending_modified_values.as_mut() {
                        if input.cache_node_type.is_some() {
                            p.cache_node_type = None;
                        }
                        if input.engine_version.is_some() {
                            p.engine_version = None;
                        }
                    }
                }
                if let Some((e, v)) = new_version {
                    c.info.engine = Some(e.as_str().into());
                    c.engine = Some(e);
                    c.info.engine_version = Some(v.into());
                }
                if let Some(pg) = c.info.cache_parameter_group.as_mut() {
                    pg.cache_parameter_group_name = Some(pg_name.clone());
                }
                if let Some(sgs) = &input.security_group_ids {
                    c.info.security_groups = Some(
                        sgs.iter()
                            .map(|s| t::SecurityGroupMembership {
                                security_group_id: Some(s.clone()),
                                status: Some("active".into()),
                            })
                            .collect(),
                    );
                }
                if let Some(w) = &input.preferred_maintenance_window {
                    c.info.preferred_maintenance_window = Some(w.clone());
                }
                if let Some(topic) = &input.notification_topic_arn {
                    c.info.notification_configuration = Some(t::NotificationConfiguration {
                        topic_arn: Some(topic.clone()),
                        topic_status: Some(input.notification_topic_status.clone().unwrap_or_else(|| "active".into())),
                    });
                }
                if let Some(v) = input.auto_minor_version_upgrade {
                    c.info.auto_minor_version_upgrade = Some(v);
                }
                if let Some(v) = input.snapshot_retention_limit {
                    c.info.snapshot_retention_limit = Some(v);
                }
                c.info.auth_token_enabled = g.info.auth_token_enabled;
                c.info.transit_encryption_enabled = g.info.transit_encryption_enabled;
                c.info.transit_encryption_mode = g.info.transit_encryption_mode.clone();
            }
        }
        if let Some(v) = input.auto_minor_version_upgrade {
            if let Some(g) = r.replication_groups.get_mut(&id) {
                g.info.auto_minor_version_upgrade = Some(v);
            }
        }
        r.event(&id, "replication-group", format!("Replication group {id} modified"), now(ctx));
        if new_version.is_some() && svc.runs_engines() {
            // The nodes are replaced with ones running the new version.
            if let Some(g) = r.replication_groups.get_mut(&id) {
                g.info.status = Some("modifying".into());
            }
            for m in &member_ids {
                if let Some(c) = r.clusters.get_mut(m) {
                    c.set_status("modifying");
                }
            }
        }
        refresh(svc, r, &id);
        let shown = r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default();
        Ok((shown, commands, failover_to, users_changed, new_version.is_some()))
    })?;
    if upgrade {
        // New containers start with every new setting.
        engine::upgrade(svc, ctx, &key, Some(&id), None);
        return Ok(t::ModifyReplicationGroupResult { replication_group: Some(shown) });
    }
    let nodes = svc.with_key(&key, ctx, |r| engine::nodes_of(r, Some(&id), None));
    match tls_change {
        // The nodes still speak the old protocol: run the other changes,
        // then switch their listeners.
        Some(enable) => engine::switch_tls(svc, nodes, commands, enable),
        None => engine::run_everywhere(svc, nodes, commands),
    }
    if users_changed {
        engine::sync_users(svc, ctx, &key, &id);
    }
    if let Some(p) = failover_to {
        start_failover(svc, ctx, &key, &id, &p, false);
    }
    Ok(t::ModifyReplicationGroupResult { replication_group: Some(shown) })
}

/// Promote `new_primary` and record the outcome.
fn start_failover(svc: &ElastiCache, ctx: &RequestContext, key: &str, rg: &str, new_primary: &str, test: bool) {
    let new_primary_s = new_primary.to_string();
    let rg_s = rg.to_string();
    let key_s = key.to_string();
    engine::failover(svc, ctx, key, rg, new_primary, move |svc, ctx, r| {
        let Some(np) = r.clusters.get(&new_primary_s).cloned() else { return };
        let ng = np.node_group_id.clone();
        let old: Vec<String> = members(r, &rg_s)
            .iter()
            .filter(|c| c.node_group_id == ng && c.role.as_deref() == Some("primary"))
            .map(|c| c.id().to_string())
            .collect();
        for o in &old {
            if let Some(c) = r.clusters.get_mut(o) {
                c.role = Some("replica".into());
            }
        }
        if let Some(c) = r.clusters.get_mut(&new_primary_s) {
            c.role = Some("primary".into());
        }
        let at = chrono::Utc::now().max(now(ctx));
        let from = old.first().cloned().unwrap_or_default();
        r.event(
            &rg_s,
            "replication-group",
            format!("Failover from master node {from}-0001 to replica node {new_primary_s}-0001 completed"),
            at,
        );
        if test {
            r.event(&rg_s, "replication-group", format!("Recovering cache nodes 0001 for cluster {from}"), at);
        }
        if let Some(g) = r.replication_groups.get_mut(&rg_s) {
            g.info.status = Some("available".into());
        }
        refresh(svc, r, &rg_s);
        route(svc, &key_s, r, &rg_s);
    });
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteReplicationGroupMessage,
) -> Result<t::DeleteReplicationGroupResult, ServiceError> {
    let id = input.replication_group_id.to_ascii_lowercase();
    let key = region_key(ctx);
    let retain = input.retain_primary_cluster == Some(true);
    let (shown, handles, snapshot) = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        let resource = g.info.arn.clone().unwrap_or_default();
        authorize(ctx, r, "DeleteReplicationGroup", &resource, Default::default())?;
        if !matches!(g.status(), "available" | "create-failed" | "snapshotting") {
            return Err(errors::invalid_replication_group_state_fault(format!(
                "Replication group {id} is not in a valid state to be deleted."
            )));
        }
        if g.info.global_replication_group_info.is_some() {
            return Err(errors::invalid_replication_group_state_fault(format!(
                "Replication group {id} is a member of a global datastore; disassociate it first."
            )));
        }
        if retain && g.cluster_enabled() {
            return Err(combination(
                "RetainPrimaryCluster is not supported for cluster mode enabled replication groups.",
            ));
        }
        let snapshot = match input.final_snapshot_identifier.as_deref() {
            Some(name) => {
                let sources = engine::snapshot_sources(r, Some(&id), None);
                Some((super::snapshots::start(svc, ctx, r, name, Some(&id), None, "manual", None)?, sources))
            }
            None => None,
        };
        let mut handles = Vec::new();
        for m in members(r, &id).iter().map(|c| c.id().to_string()).collect::<Vec<_>>() {
            let keep = retain && r.clusters.get(&m).is_some_and(|c| c.role.as_deref() == Some("primary"));
            if keep {
                if let Some(c) = r.clusters.get_mut(&m) {
                    c.info.replication_group_id = None;
                    c.node_group_id = None;
                    c.role = None;
                    c.auth = g.auth.clone();
                    c.internal_password = g.internal_password.clone();
                }
                continue;
            }
            if let Some(c) = r.clusters.remove(&m) {
                handles.extend(c.nodes.values().filter_map(|n| n.handle.clone()));
                r.tags.remove(c.info.arn.as_deref().unwrap_or_default());
            }
        }
        for ug in g.info.user_group_ids.iter().flatten() {
            if let Some(u) = r.user_groups.get_mut(ug) {
                if let Some(list) = u.replication_groups.as_mut() {
                    list.retain(|x| x != &id);
                }
            }
        }
        r.replication_groups.remove(&id);
        r.tags.remove(&resource);
        r.event(&id, "replication-group", format!("Replication group {id} deleted"), now(ctx));
        let mut shown = g.info.clone();
        shown.status = Some("deleting".into());
        Ok((shown, handles, snapshot))
    })?;
    svc.proxies().close_prefix(&format!("{key}/rg/{id}/"));
    match snapshot {
        Some((name, sources)) => engine::snapshot(svc, ctx, &key, &name, sources, handles),
        None => engine::terminate(svc, handles, None),
    }
    Ok(t::DeleteReplicationGroupResult { replication_group: Some(shown) })
}

/// Replica counts per node group.
fn replica_counts(r: &RegionState, rg: &str) -> BTreeMap<String, usize> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for c in members(r, rg) {
        let e = out.entry(c.node_group_id.clone().unwrap_or_else(|| "0001".into())).or_default();
        if c.role.as_deref() != Some("primary") {
            *e += 1;
        }
    }
    out
}

fn wanted_counts(
    current: &BTreeMap<String, usize>,
    new_count: Option<i32>,
    config: &Option<Vec<t::ConfigureShard>>,
) -> Result<BTreeMap<String, usize>, ServiceError> {
    let mut want = current.clone();
    match (new_count, config) {
        (Some(n), _) => {
            for v in want.values_mut() {
                *v = n.max(0) as usize;
            }
        }
        (None, Some(cfg)) => {
            for s in cfg {
                let e = want.get_mut(&s.node_group_id).ok_or_else(|| {
                    errors::node_group_not_found_fault(format!("Node group {} not found.", s.node_group_id))
                })?;
                *e = s.new_replica_count.max(0) as usize;
            }
        }
        (None, None) => return Err(combination("Either NewReplicaCount or ReplicaConfiguration must be specified.")),
    }
    if want.values().any(|v| *v > 5) {
        return Err(invalid("The number of replicas per node group must be within 0 and 5."));
    }
    Ok(want)
}

pub(crate) async fn increase_replicas(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::IncreaseReplicaCountMessage,
) -> Result<t::IncreaseReplicaCountResult, ServiceError> {
    let id = input.replication_group_id.to_ascii_lowercase();
    let key = region_key(ctx);
    if !input.apply_immediately {
        return Err(invalid("ApplyImmediately must be true for IncreaseReplicaCount."));
    }
    let (shown, new) = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "IncreaseReplicaCount", g.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.status() != "available" {
            return Err(not_available(&id));
        }
        let current = replica_counts(r, &id);
        let want = wanted_counts(&current, input.new_replica_count, &input.replica_configuration)?;
        if want.iter().all(|(k, v)| current.get(k) == Some(v))
            || want.iter().any(|(k, v)| current.get(k).is_some_and(|c| v < c))
        {
            return Err(invalid("The new replica count must be greater than the current replica count."));
        }
        let mut new = Vec::new();
        for (ng, n) in &want {
            let have = current.get(ng).copied().unwrap_or(0);
            let primary = members(r, &id)
                .into_iter()
                .find(|c| c.node_group_id.as_deref() == Some(ng) && c.role.as_deref() == Some("primary"))
                .cloned()
                .unwrap_or_default();
            let mut next = members(r, &id)
                .iter()
                .filter(|c| c.node_group_id.as_deref() == Some(ng))
                .filter_map(|c| c.id().rsplit('-').next().and_then(|n| n.parse::<u32>().ok()))
                .max()
                .unwrap_or(1);
            for _ in have..*n {
                next += 1;
                let cid = if g.cluster_enabled() { format!("{id}-{ng}-{next:03}") } else { format!("{id}-{next:03}") };
                let mut c = replica_like(svc, ctx, &primary, &cid, None);
                c.node_group_id = Some(ng.clone());
                r.clusters.insert(cid.clone(), c);
                new.push(cid);
            }
        }
        if let Some(g) = r.replication_groups.get_mut(&id) {
            g.info.status = Some("modifying".into());
        }
        refresh(svc, r, &id);
        Ok((r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default(), new))
    })?;
    engine::add_replicas(svc, ctx, &key, &id, new);
    Ok(t::IncreaseReplicaCountResult { replication_group: Some(shown) })
}

pub(crate) async fn decrease_replicas(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DecreaseReplicaCountMessage,
) -> Result<t::DecreaseReplicaCountResult, ServiceError> {
    let id = input.replication_group_id.to_ascii_lowercase();
    let key = region_key(ctx);
    if !input.apply_immediately {
        return Err(invalid("ApplyImmediately must be true for DecreaseReplicaCount."));
    }
    let (shown, handles, removed_nodes, remaining) = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "DecreaseReplicaCount", g.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.status() != "available" {
            return Err(not_available(&id));
        }
        let current = replica_counts(r, &id);
        let mut remove: Vec<String> = Vec::new();
        if let Some(list) = &input.replicas_to_remove {
            for cid in list {
                let c =
                    r.clusters.get(cid).filter(|c| c.info.replication_group_id.as_deref() == Some(&id)).ok_or_else(
                        || invalid(format!("Cache cluster {cid} is not a member of replication group {id}.")),
                    )?;
                if c.role.as_deref() == Some("primary") {
                    return Err(combination(format!("Cannot remove the primary cluster {cid}.")));
                }
                remove.push(cid.clone());
            }
        } else {
            let want = wanted_counts(&current, input.new_replica_count, &input.replica_configuration)?;
            if want.iter().any(|(k, v)| current.get(k).is_some_and(|c| v > c)) || want == current {
                return Err(invalid("The new replica count must be less than the current replica count."));
            }
            for (ng, n) in &want {
                let mut reps: Vec<String> = members(r, &id)
                    .iter()
                    .filter(|c| c.node_group_id.as_deref() == Some(ng) && c.role.as_deref() != Some("primary"))
                    .map(|c| c.id().to_string())
                    .collect();
                reps.sort();
                while reps.len() > *n {
                    remove.extend(reps.pop());
                }
            }
        }
        let mut after = current.clone();
        for cid in &remove {
            if let Some(ng) = r.clusters.get(cid).and_then(|c| c.node_group_id.clone()) {
                if let Some(v) = after.get_mut(&ng) {
                    *v = v.saturating_sub(1);
                }
            }
        }
        let auto = g.info.automatic_failover.as_deref() == Some("enabled");
        if auto && after.values().any(|v| *v < 1) && !g.cluster_enabled() {
            return Err(combination(
                "Must have at least 1 replica in each node group when automatic failover is enabled.",
            ));
        }
        let all_ports = engine::nodes_of(r, Some(&id), None);
        let mut handles = Vec::new();
        let mut removed_nodes = Vec::new();
        for cid in &remove {
            if let Some(c) = r.clusters.remove(cid) {
                for n in c.nodes.values() {
                    handles.extend(n.handle.clone());
                    if let Some((_, a)) = all_ports.iter().find(|(p, _)| *p == n.port) {
                        removed_nodes.push((n.port, a.clone()));
                    }
                }
                r.tags.remove(c.info.arn.as_deref().unwrap_or_default());
            }
            forget_member(r, &id, cid);
        }
        let remaining: Vec<_> =
            all_ports.into_iter().filter(|(p, _)| !removed_nodes.iter().any(|(q, _)| q == p)).collect();
        refresh(svc, r, &id);
        route(svc, &key, r, &id);
        let shown = r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default();
        Ok((shown, handles, removed_nodes, remaining))
    })?;
    let cluster_mode = shown.cluster_enabled == Some(true);
    engine::terminate(svc, handles, cluster_mode.then_some((removed_nodes, remaining)));
    Ok(t::DecreaseReplicaCountResult { replication_group: Some(shown) })
}

pub(crate) async fn modify_shards(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyReplicationGroupShardConfigurationMessage,
) -> Result<t::ModifyReplicationGroupShardConfigurationResult, ServiceError> {
    let id = input.replication_group_id.to_ascii_lowercase();
    let key = region_key(ctx);
    if !input.apply_immediately {
        return Err(invalid("ApplyImmediately must be true for ModifyReplicationGroupShardConfiguration."));
    }
    let (shown, new, removed, target) = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        authorize(
            ctx,
            r,
            "ModifyReplicationGroupShardConfiguration",
            g.info.arn.as_deref().unwrap_or_default(),
            cond(&[("NumNodeGroups", Some(input.node_group_count.to_string()))]),
        )?;
        if !g.cluster_enabled() {
            return Err(combination("ModifyReplicationGroupShardConfiguration is only supported for cluster mode enabled replication groups."));
        }
        if g.status() != "available" {
            return Err(not_available(&id));
        }
        let current: Vec<String> = g.slots.keys().cloned().collect();
        let n = input.node_group_count;
        if !(1..=500).contains(&n) {
            return Err(invalid("NodeGroupCount must be within 1 and 500."));
        }
        let n = n as usize;
        if n == current.len() {
            return Err(errors::no_operation_fault("The replication group already has the requested number of node groups."));
        }
        let mut new = Vec::new();
        let mut removed = Vec::new();
        let mut keep: Vec<String> = current.clone();
        if n > current.len() {
            let replicas = replica_counts(r, &id).values().copied().max().unwrap_or(0);
            let tpl_primary = members(r, &id).into_iter().find(|c| c.role.as_deref() == Some("primary")).cloned().unwrap_or_default();
            let mut next = current.iter().filter_map(|x| x.parse::<u32>().ok()).max().unwrap_or(0);
            for _ in current.len()..n {
                next += 1;
                let ng = format!("{next:04}");
                for i in 0..=replicas {
                    let cid = format!("{id}-{ng}-{:03}", i + 1);
                    let mut c = replica_like(svc, ctx, &tpl_primary, &cid, None);
                    c.node_group_id = Some(ng.clone());
                    c.role = Some(if i == 0 { "primary" } else { "replica" }.into());
                    r.clusters.insert(cid.clone(), c);
                    new.push(cid);
                }
                keep.push(ng);
            }
        } else {
            match (&input.node_groups_to_remove, &input.node_groups_to_retain) {
                (Some(rm), _) if !rm.is_empty() => {
                    for x in rm {
                        if !current.contains(x) {
                            return Err(errors::node_group_not_found_fault(format!("Node group {x} not found.")));
                        }
                    }
                    if current.len() - rm.len() != n {
                        return Err(invalid("The number of node groups to remove does not match NodeGroupCount."));
                    }
                    removed = rm.clone();
                }
                (_, Some(keep_list)) if !keep_list.is_empty() => {
                    if keep_list.len() != n {
                        return Err(invalid("The number of node groups to retain does not match NodeGroupCount."));
                    }
                    removed = current.iter().filter(|x| !keep_list.contains(x)).cloned().collect();
                }
                _ => return Err(combination("NodeGroupsToRemove or NodeGroupsToRetain is required to reduce the number of node groups.")),
            }
            keep.retain(|x| !removed.contains(x));
        }
        let even = engine::even_slots(keep.len());
        let mut target = BTreeMap::new();
        for (i, ng) in keep.iter().enumerate() {
            target.insert(ng.clone(), engine::format_slots(&[even[i]]));
        }
        if let Some(g) = r.replication_groups.get_mut(&id) {
            g.info.status = Some("modifying".into());
            g.info.pending_modified_values = Some(t::ReplicationGroupPendingModifiedValues {
                resharding: Some(t::ReshardingStatus { slot_migration: Some(t::SlotMigration { progress_percentage: Some(0.0) }) }),
                ..Default::default()
            });
            for ng in &new {
                let _ = ng;
            }
        }
        refresh(svc, r, &id);
        Ok((r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default(), new, removed, target))
    })?;
    engine::reshard(svc, ctx, &key, &id, new, removed, target);
    Ok(t::ModifyReplicationGroupShardConfigurationResult { replication_group: Some(shown) })
}

/// Slots moved: record the new layout and drop removed shards.
pub(crate) fn resharded(
    svc: &ElastiCache,
    ctx: &RequestContext,
    r: &mut RegionState,
    rg: &str,
    target: &BTreeMap<String, String>,
    removed: &[String],
) {
    let gone: Vec<String> = members(r, rg)
        .iter()
        .filter(|c| c.node_group_id.as_ref().is_some_and(|ng| removed.contains(ng)))
        .map(|c| c.id().to_string())
        .collect();
    for cid in gone {
        if let Some(c) = r.clusters.remove(&cid) {
            r.tags.remove(c.info.arn.as_deref().unwrap_or_default());
        }
    }
    if let Some(g) = r.replication_groups.get_mut(rg) {
        g.slots = target.clone();
    }
    let at = chrono::Utc::now().max(now(ctx));
    r.event(rg, "replication-group", format!("Shard configuration of replication group {rg} modified"), at);
    became_available(svc, ctx, r, rg);
}

pub(crate) async fn test_failover(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::TestFailoverMessage,
) -> Result<t::TestFailoverResult, ServiceError> {
    let id = input.replication_group_id.to_ascii_lowercase();
    let key = region_key(ctx);
    let (shown, new_primary) = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "TestFailover", g.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.status() != "available" {
            return Err(not_available(&id));
        }
        if g.info.automatic_failover.as_deref() != Some("enabled") {
            return Err(errors::invalid_replication_group_state_fault(format!(
                "Replication group {id} does not have automatic failover enabled."
            )));
        }
        let ng = &input.node_group_id;
        if !members(r, &id).iter().any(|c| c.node_group_id.as_deref() == Some(ng)) {
            return Err(errors::node_group_not_found_fault(format!("Node group {ng} not found.")));
        }
        let replica = members(r, &id)
            .into_iter()
            .find(|c| c.node_group_id.as_deref() == Some(ng) && c.role.as_deref() != Some("primary"))
            .map(|c| c.id().to_string())
            .ok_or_else(|| {
                errors::test_failover_not_available_fault(format!("Node group {ng} has no replicas to fail over to."))
            })?;
        if let Some(g) = r.replication_groups.get_mut(&id) {
            g.info.status = Some("modifying".into());
        }
        r.event(&id, "replication-group", format!("Test Failover API called for node group {ng}"), now(ctx));
        refresh(svc, r, &id);
        Ok((r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default(), replica))
    })?;
    start_failover(svc, ctx, &key, &id, &new_primary, true);
    Ok(t::TestFailoverResult { replication_group: Some(shown) })
}

// ---- online migration ---------------------------------------------------------

fn source_of(list: &[t::CustomerNodeEndpoint]) -> Result<(String, u16), ServiceError> {
    if list.len() != 1 {
        return Err(invalid("Exactly one customer node endpoint must be specified."));
    }
    let e = &list[0];
    let host = e
        .address
        .clone()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| invalid("The customer node endpoint needs an Address."))?;
    Ok((host, e.port.unwrap_or(6379) as u16))
}

pub(crate) async fn start_migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::StartMigrationMessage,
) -> Result<t::StartMigrationResponse, ServiceError> {
    let Some(id) = input.replication_group_id.clone().map(|i| i.to_ascii_lowercase()) else {
        return super::serverless::start_migration(svc, ctx, input).await;
    };
    let key = region_key(ctx);
    let source = source_of(input.customer_node_endpoint_list.as_deref().unwrap_or_default())?;
    let shown = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "StartMigration", g.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.migration.is_some() {
            return Err(errors::replication_group_already_under_migration_fault(format!(
                "Replication group {id} is already under migration."
            )));
        }
        if g.status() != "available" {
            return Err(not_available(&id));
        }
        if g.cluster_enabled() || g.info.transit_encryption_enabled == Some(true) || g.auth.enabled() {
            return Err(errors::invalid_replication_group_state_fault(
                "Online migration needs a cluster mode disabled replication group without encryption in transit or AUTH.",
            ));
        }
        let g = r.replication_groups.get_mut(&id).expect("checked");
        g.migration = Some(source.clone());
        g.info.status = Some("modifying".into());
        r.event(&id, "replication-group", format!("Migration started from {}:{}", source.0, source.1), now(ctx));
        refresh(svc, r, &id);
        Ok(r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default())
    })?;
    engine::migrate_from(svc, ctx, &key, &id, Some(source));
    Ok(t::StartMigrationResponse { replication_group: Some(shown), serverless_cache: None })
}

pub(crate) async fn test_migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::TestMigrationMessage,
) -> Result<t::TestMigrationResponse, ServiceError> {
    let id = input.replication_group_id.to_ascii_lowercase();
    let (host, port) = source_of(&input.customer_node_endpoint_list)?;
    let shown = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "TestMigration", g.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.status() != "available" {
            return Err(not_available(&id));
        }
        if g.cluster_enabled() || g.info.transit_encryption_enabled == Some(true) {
            return Err(errors::invalid_replication_group_state_fault(
                "Online migration needs a cluster mode disabled replication group without encryption in transit.",
            ));
        }
        Ok(g.info.clone())
    })?;
    if svc.runs_engines() && !engine::reachable(&host, port).await {
        return Err(errors::migration_health_fault(format!(
            "Unable to connect to the customer node endpoint {host}:{port}."
        )));
    }
    svc.with_region(ctx, |r| {
        r.event(&id, "replication-group", format!("Test migration from {host}:{port} succeeded"), now(ctx));
    });
    Ok(t::TestMigrationResponse { replication_group: Some(shown) })
}

pub(crate) async fn complete_migration(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CompleteMigrationMessage,
) -> Result<t::CompleteMigrationResponse, ServiceError> {
    let Some(id) = input.replication_group_id.clone().map(|i| i.to_ascii_lowercase()) else {
        return super::serverless::complete_migration(svc, ctx, input).await;
    };
    let key = region_key(ctx);
    let shown = svc.with_region(ctx, |r| {
        let g = r.replication_groups.get(&id).cloned().ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "CompleteMigration", g.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.migration.is_none() {
            return Err(errors::replication_group_not_under_migration_fault(format!(
                "Replication group {id} is not under migration."
            )));
        }
        let g = r.replication_groups.get_mut(&id).expect("checked");
        g.migration = None;
        g.info.status = Some("available".into());
        r.event(&id, "replication-group", "Migration completed", now(ctx));
        refresh(svc, r, &id);
        Ok(r.replication_groups.get(&id).map(|g| g.info.clone()).unwrap_or_default())
    })?;
    engine::migrate_from(svc, ctx, &key, &id, None);
    Ok(t::CompleteMigrationResponse { replication_group: Some(shown), serverless_cache: None })
}
