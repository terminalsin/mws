//! Driving real engines: launching nodes through the backend, then setting
//! them up over the Redis protocol the way ElastiCache does (replication,
//! cluster slots, ACL users, failover, snapshots, parameter changes).
//!
//! Every entry point reads what it needs from the state, does its slow work
//! in a background task without holding the state lock, and writes the
//! outcome back. With a backend that runs nothing the outcome is applied at
//! once.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::Utc;
use mws_core::RequestContext;

use crate::backend::{EngineKind, NodeSpec, RunningNode};
use crate::catalog;
use crate::resp::{self, Auth, Client};
use crate::state::{AuthTokens, Cluster, Entry, RegionState, SnapshotData};
use crate::ElastiCache;

pub(crate) const INTERNAL_USER: &str = "mws-internal";
pub(crate) const CLUSTER_BUS_PORT: &str = "16379";
const TLS_CERT: &str = "/tls/server.crt";
const TLS_KEY: &str = "/tls/server.key";
const TLS_CA: &str = "/tls/ca.crt";

/// The certificate files a node with encryption in transit needs.
pub(crate) fn tls_files(svc: &ElastiCache) -> Vec<(String, Vec<u8>)> {
    let pki = svc.pki();
    vec![
        (TLS_CERT.into(), pki.server_cert_pem.into_bytes()),
        (TLS_KEY.into(), pki.server_key_pem.into_bytes()),
        (TLS_CA.into(), pki.ca_cert_pem.into_bytes()),
    ]
}

/// Whether an engine version has ACLs (Redis OSS 6+, every Valkey).
pub(crate) fn acl_capable(engine: EngineKind, version: &str) -> bool {
    match engine {
        EngineKind::Valkey => true,
        EngineKind::Redis => version.split('.').next().and_then(|m| m.parse::<u32>().ok()).unwrap_or(7) >= 6,
        EngineKind::Memcached => false,
    }
}

/// How MWS authenticates to a node.
pub(crate) fn admin_auth(engine: EngineKind, version: &str, internal: Option<&str>, tokens: &AuthTokens) -> Auth {
    match internal {
        Some(pw) if acl_capable(engine, version) => Auth::User(INTERNAL_USER.into(), pw.into()),
        _ => tokens.current.clone().map(Auth::Password).unwrap_or(Auth::None),
    }
}

pub(crate) fn connect_host(svc: &ElastiCache) -> String {
    match svc.options().bind_address.as_str() {
        "0.0.0.0" | "" => "127.0.0.1".into(),
        "::" => "::1".into(),
        b => b.to_string(),
    }
}

async fn connect(svc: &ElastiCache, port: u16, auth: &Auth) -> Result<Client, String> {
    Client::connect_with(&connect_host(svc), port, svc.tls_client_for(port), auth).await.map_err(|e| e.0)
}

/// A raw connection to a node (Memcached), over TLS when the node uses it.
async fn raw_connect(svc: &ElastiCache, port: u16) -> Result<Box<dyn resp::Stream>, String> {
    let host = connect_host(svc);
    let tcp = tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    match svc.tls_client_for(port) {
        None => Ok(Box::new(tcp)),
        Some(config) => {
            let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
            let tls = tokio_rustls::TlsConnector::from(config).connect(name, tcp).await.map_err(|e| e.to_string())?;
            Ok(Box::new(tls))
        }
    }
}

/// A Valkey/Redis OSS node's `INFO everything`, parsed.
pub(crate) async fn redis_info(
    svc: &ElastiCache,
    port: u16,
    auth: &Auth,
) -> Option<(std::collections::HashMap<String, f64>, bool)> {
    let mut c = connect(svc, port, auth).await.ok()?;
    let text = c.ok(&["INFO", "everything"]).await.ok()?.as_text()?;
    Some(crate::metrics::parse_info(&text))
}

/// A Memcached node's `stats`, parsed.
pub(crate) async fn memcached_stats(
    svc: &ElastiCache,
    port: u16,
) -> Option<(std::collections::HashMap<String, f64>, bool)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = raw_connect(svc, port).await.ok()?;
    s.write_all(b"stats\r\n").await.ok()?;
    let mut text = String::new();
    let mut buf = vec![0u8; 8192];
    for _ in 0..50 {
        let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            break;
        }
        text.push_str(&String::from_utf8_lossy(&buf[..n]));
        if text.ends_with("END\r\n") {
            break;
        }
    }
    Some((crate::metrics::parse_stats(&text), true))
}

/// Wait until a node answers (PING, or a TCP connection for Memcached).
async fn wait_ready(svc: &ElastiCache, engine: EngineKind, port: u16, auth: &Auth) -> Result<(), String> {
    let host = connect_host(svc);
    let mut last = String::new();
    for _ in 0..600 {
        if engine == EngineKind::Memcached {
            match raw_connect(svc, port).await {
                Ok(mut s) => {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    if s.write_all(b"version\r\n").await.is_ok() {
                        let mut buf = [0u8; 64];
                        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), s.read(&mut buf)).await {
                            if buf[..n].starts_with(b"VERSION") {
                                return Ok(());
                            }
                        }
                    }
                }
                Err(e) => last = e,
            }
        } else {
            match Client::connect_with(&host, port, svc.tls_client_for(port), auth).await {
                Ok(mut c) => match c.cmd(&["PING"]).await {
                    Ok(resp::Resp::Simple(s)) if s == "PONG" => return Ok(()),
                    Ok(other) => last = format!("{other:?}"),
                    Err(e) => last = e.0,
                },
                Err(e) => last = e.0,
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(format!("node on port {port} never became ready: {last}"))
}

// ---- node specs -------------------------------------------------------------

/// Engine command line flags for one node.
#[allow(clippy::too_many_arguments)]
pub(crate) fn engine_args(
    engine: EngineKind,
    version: &str,
    port: u16,
    node_type: &str,
    params: &[(String, String)],
    cluster_mode: bool,
    tokens: &AuthTokens,
    internal: Option<&str>,
    advertise_host: &str,
    tls: bool,
) -> Vec<String> {
    let nt = catalog::node_type(node_type).unwrap_or(&catalog::NODE_TYPES[3]);
    let mut a: Vec<String> = Vec::new();
    let mut push = |items: &[&str]| a.extend(items.iter().map(|s| s.to_string()));
    if engine == EngineKind::Memcached {
        let get = |n: &str, d: &str| {
            params.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or_else(|| d.to_string())
        };
        let overhead: u64 = get("memcached_connections_overhead", "100").parse().unwrap_or(100);
        let mem = nt.memory_mib().saturating_sub(overhead).max(16);
        push(&["-p", &port.to_string(), "-U", "0", "-m", &mem.to_string()]);
        // memcached raises its open-file limit to the connection limit,
        // which an unprivileged container may not do for ElastiCache's
        // 65000: cap it.
        let conns: u64 = get("max_simultaneous_connections", "65000").parse().unwrap_or(65000);
        push(&["-c", &conns.min(4096).to_string()]);
        push(&["-I", &get("max_item_size", "1048576")]);
        push(&["-n", &get("chunk_size", "48")]);
        push(&["-f", &get("chunk_size_growth_factor", "1.25")]);
        push(&["-b", &get("backlog_queue_limit", "1024")]);
        push(&["-R", &get("requests_per_event", "20")]);
        if get("cas_disabled", "0") == "1" {
            push(&["-C"]);
        }
        if get("error_on_memory_exhausted", "0") == "1" {
            push(&["-M"]);
        }
        if tls {
            let ssl = format!("ssl_chain_cert={TLS_CERT},ssl_key={TLS_KEY},ssl_ca_cert={TLS_CA}");
            push(&["-Z", "-o", &ssl]);
        }
        return a;
    }
    if tls {
        // Encryption in transit: the node's only listener speaks TLS.
        push(&["--port", "0", "--tls-port", &port.to_string()]);
        push(&["--tls-cert-file", TLS_CERT, "--tls-key-file", TLS_KEY, "--tls-ca-cert-file", TLS_CA]);
        push(&["--tls-auth-clients", "no", "--tls-replication", "yes"]);
        if cluster_mode {
            push(&["--tls-cluster", "yes"]);
        }
    } else {
        push(&["--port", &port.to_string()]);
    }
    push(&["--bind", "0.0.0.0", "--protected-mode", "no"]);
    push(&["--save", "", "--appendonly", "no", "--dir", "/data", "--dbfilename", "dump.rdb"]);
    push(&["--maxmemory", &nt.maxmemory().to_string()]);
    let acl = acl_capable(engine, version);
    if let (Some(pw), true) = (internal, acl) {
        let pass = format!(">{pw}");
        let six_zero = engine == EngineKind::Redis && version.starts_with("6.0");
        let mut user = vec!["--user", INTERNAL_USER, "on", pass.as_str(), "~*"];
        if !six_zero {
            user.push("&*");
        }
        user.push("+@all");
        push(&user);
        push(&["--masteruser", INTERNAL_USER, "--masterauth", pw]);
    }
    if let Some(tok) = &tokens.current {
        push(&["--requirepass", tok]);
        if internal.is_none() || !acl {
            push(&["--masterauth", tok]);
        }
    }
    if cluster_mode {
        push(&["--cluster-enabled", "yes", "--cluster-config-file", "nodes.conf"]);
        push(&["--cluster-port", CLUSTER_BUS_PORT, "--cluster-node-timeout", "5000"]);
        push(&["--cluster-announce-hostname", advertise_host, "--cluster-preferred-endpoint-type", "hostname"]);
    }
    for (k, v) in params {
        push(&[&format!("--{k}"), v]);
    }
    a
}

/// One node to launch.
#[derive(Debug, Clone)]
pub(crate) struct NodeJob {
    pub cluster_id: String,
    pub node_id: String,
    pub spec: NodeSpec,
}

/// The launch jobs for the nodes of `cluster_ids` (only nodes without a
/// handle yet).
pub(crate) fn plan(svc: &ElastiCache, key: &str, r: &RegionState, cluster_ids: &[String]) -> Vec<NodeJob> {
    let (account, region) = key.split_once('/').unwrap_or((key, ""));
    let mut jobs = Vec::new();
    for id in cluster_ids {
        let Some(c) = r.clusters.get(id) else { continue };
        let engine = c.engine();
        let version = c.info.engine_version.clone().unwrap_or_default();
        let node_type = c.info.cache_node_type.clone().unwrap_or_default();
        let group = c.info.cache_parameter_group.as_ref().and_then(|g| g.cache_parameter_group_name.clone());
        let params = crate::ops::params::engine_values(r, group.as_deref().unwrap_or_default());
        let rg = c.info.replication_group_id.as_deref().and_then(|g| r.replication_groups.get(g));
        let cluster_mode = rg.is_some_and(|g| g.cluster_enabled());
        let (tokens, internal) = match rg {
            Some(g) => (g.auth.clone(), g.internal_password.clone()),
            None => (c.auth.clone(), c.internal_password.clone()),
        };
        let nt = catalog::node_type(&node_type).unwrap_or(&catalog::NODE_TYPES[3]);
        let tls = c.info.transit_encryption_enabled == Some(true);
        for (node_id, rt) in &c.nodes {
            if rt.handle.is_some() {
                continue;
            }
            let args = engine_args(
                engine,
                &version,
                rt.port,
                &node_type,
                &params,
                cluster_mode,
                &tokens,
                internal.as_deref(),
                &svc.options().advertise_host,
                tls,
            );
            jobs.push(NodeJob {
                cluster_id: id.clone(),
                node_id: node_id.clone(),
                spec: NodeSpec {
                    name: format!("{id}-{node_id}"),
                    account_id: account.to_string(),
                    region: region.to_string(),
                    engine,
                    engine_version: version.clone(),
                    cluster_mode,
                    port: rt.port,
                    bind_address: svc.options().bind_address.clone(),
                    args,
                    memory_mib: (nt.memory_mib() * 5 / 4).max(256),
                    vcpus: nt.vcpus,
                    files: if tls || engine.is_redis_like() { tls_files(svc) } else { Vec::new() },
                },
            });
        }
    }
    jobs
}

/// Launch nodes concurrently.
async fn launch(svc: &ElastiCache, jobs: Vec<NodeJob>) -> Vec<(NodeJob, Result<RunningNode, String>)> {
    let mut set = tokio::task::JoinSet::new();
    for job in jobs {
        let backend = svc.backend();
        set.spawn(async move {
            let res = backend.launch(&job.spec).await.map_err(|e| e.0);
            (job, res)
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(r) = r {
            out.push(r);
        }
    }
    out
}

/// Record launched nodes in the state; the first error, if any.
fn record(
    svc: &ElastiCache,
    key: &str,
    ctx: &RequestContext,
    launched: &[(NodeJob, Result<RunningNode, String>)],
) -> Option<String> {
    let mut err = None;
    svc.with_key(key, ctx, |r| {
        for (job, res) in launched {
            match res {
                Ok(node) => {
                    if let Some(rt) = r.clusters.get_mut(&job.cluster_id).and_then(|c| c.nodes.get_mut(&job.node_id)) {
                        rt.handle = Some(node.handle.clone());
                        rt.peer = Some(node.peer_address.clone());
                    }
                }
                Err(e) => {
                    err.get_or_insert_with(|| e.clone());
                }
            }
        }
    });
    if err.is_some() {
        // Don't leave half a group running.
        let backend = svc.backend();
        let handles: Vec<String> =
            launched.iter().filter_map(|(_, r)| r.as_ref().ok().map(|n| n.handle.clone())).collect();
        tokio::spawn(async move {
            for h in handles {
                let _ = backend.terminate(&h).await;
            }
        });
    }
    err
}

fn spawn<F>(f: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(f);
    }
}

// ---- standalone clusters ----------------------------------------------------

/// Bring up a cache cluster that is not part of a replication group (a
/// Memcached cluster or a single Redis OSS / Valkey node).
pub(crate) fn start_cluster(svc: &ElastiCache, ctx: &RequestContext, key: &str, id: &str) {
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| crate::ops::clusters::became_available(svc, ctx, r, id, true));
        return;
    }
    let (svc, ctx, key, id) = (svc.clone(), ctx.clone(), key.to_string(), id.to_string());
    spawn(async move {
        let (jobs, auth, engine, seed) = svc.with_key(&key, &ctx, |r| {
            let jobs = plan(&svc, &key, r, std::slice::from_ref(&id));
            let c = r.clusters.get(&id).cloned().unwrap_or_default();
            let auth = cluster_auth(&c);
            let seed = c.seed_snapshot.as_ref().and_then(|s| r.snapshots.get(s)).map(|s| s.data.clone());
            (jobs, auth, c.engine(), seed)
        });
        let rdb = seed_rdb(&svc, &key, &ctx, &id);
        let jobs = with_rdb(jobs, rdb);
        let launched = launch(&svc, jobs).await;
        if let Some(e) = record(&svc, &key, &ctx, &launched) {
            return failed(&svc, &ctx, &key, &id, None, &e);
        }
        for (job, _) in &launched {
            if let Err(e) = wait_ready(&svc, engine, job.spec.port, &auth).await {
                return failed(&svc, &ctx, &key, &id, None, &e);
            }
        }
        if let (Some(seed), Some((job, _))) = (seed, launched.first()) {
            if let Err(e) = restore_standalone(&svc, job.spec.port, &auth, &seed).await {
                tracing::warn!("seeding cache cluster {id}: {e}");
            }
        }
        svc.with_key(&key, &ctx, |r| crate::ops::clusters::became_available(&svc, &ctx, r, &id, true));
    });
}

/// Add nodes to a running Memcached cluster.
pub(crate) fn add_nodes(svc: &ElastiCache, ctx: &RequestContext, key: &str, id: &str) {
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| crate::ops::clusters::became_available(svc, ctx, r, id, false));
        return;
    }
    let (svc, ctx, key, id) = (svc.clone(), ctx.clone(), key.to_string(), id.to_string());
    spawn(async move {
        let (jobs, engine) = svc.with_key(&key, &ctx, |r| {
            (plan(&svc, &key, r, std::slice::from_ref(&id)), r.clusters.get(&id).map(Cluster::engine))
        });
        let launched = launch(&svc, jobs).await;
        let _ = record(&svc, &key, &ctx, &launched);
        for (job, res) in &launched {
            if res.is_ok() {
                let _ = wait_ready(&svc, engine.unwrap_or(EngineKind::Memcached), job.spec.port, &Auth::None).await;
            }
        }
        svc.with_key(&key, &ctx, |r| crate::ops::clusters::became_available(&svc, &ctx, r, &id, false));
    });
}

pub(crate) fn cluster_auth(c: &Cluster) -> Auth {
    admin_auth(
        c.engine(),
        c.info.engine_version.as_deref().unwrap_or_default(),
        c.internal_password.as_deref(),
        &c.auth,
    )
}

/// The RDB files a new cluster is seeded from (S3 snapshot ARNs).
fn seed_rdb(svc: &ElastiCache, key: &str, ctx: &RequestContext, id: &str) -> Option<Vec<u8>> {
    let arns = svc.with_key(key, ctx, |r| r.clusters.get(id).and_then(|c| c.seed_rdb.clone()))?;
    let bucket = svc.bucket()?;
    arns.iter().find_map(|a| bucket.read(a))
}

fn with_rdb(mut jobs: Vec<NodeJob>, rdb: Option<Vec<u8>>) -> Vec<NodeJob> {
    if let (Some(rdb), Some(first)) = (rdb, jobs.first_mut()) {
        first.spec.files.push(("/data/dump.rdb".into(), rdb));
    }
    jobs
}

fn failed(svc: &ElastiCache, ctx: &RequestContext, key: &str, cluster: &str, rg: Option<&str>, error: &str) {
    tracing::warn!("ElastiCache could not create {}: {error}", rg.unwrap_or(cluster));
    svc.with_key(key, ctx, |r| {
        let now = Utc::now();
        if let Some(rg) = rg {
            if let Some(g) = r.replication_groups.get_mut(rg) {
                g.info.status = Some("create-failed".into());
            }
            let members: Vec<String> = r
                .clusters
                .values()
                .filter(|c| c.info.replication_group_id.as_deref() == Some(rg))
                .map(|c| c.id().to_string())
                .collect();
            for m in members {
                if let Some(c) = r.clusters.get_mut(&m) {
                    c.set_status("create-failed");
                }
            }
            r.event(rg, "replication-group", format!("Failed to create replication group {rg}: {error}"), now);
        } else if let Some(c) = r.clusters.get_mut(cluster) {
            c.set_status("create-failed");
            r.event(cluster, "cache-cluster", format!("Failed to create cache cluster: {error}"), now);
        }
    });
}

// ---- replication groups -----------------------------------------------------

/// What setting up a replication group needs to know.
#[derive(Debug, Clone)]
struct Topology {
    engine: EngineKind,
    cluster_mode: bool,
    auth: Auth,
    /// Per shard (node group id): slot ranges, primary and replicas as
    /// `(cluster id, port, peer address)`.
    shards: Vec<Shard>,
    users: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
struct Shard {
    id: String,
    slots: Vec<(u16, u16)>,
    primary: Option<(String, u16, String)>,
    replicas: Vec<(String, u16, String)>,
}

fn topology(r: &RegionState, rg_id: &str) -> Option<Topology> {
    let g = r.replication_groups.get(rg_id)?;
    let engine = g.engine();
    let mut shards: BTreeMap<String, Shard> = BTreeMap::new();
    for c in r.clusters.values().filter(|c| c.info.replication_group_id.as_deref() == Some(rg_id)) {
        let ng = c.node_group_id.clone().unwrap_or_else(|| "0001".into());
        let Some(rt) = c.nodes.values().next() else { continue };
        let entry = (c.id().to_string(), rt.port, rt.peer.clone().unwrap_or_default());
        let shard = shards.entry(ng.clone()).or_insert_with(|| Shard {
            id: ng.clone(),
            slots: parse_slots(g.slots.get(&ng).map(String::as_str).unwrap_or_default()),
            ..Default::default()
        });
        if c.role.as_deref() == Some("primary") {
            shard.primary = Some(entry);
        } else {
            shard.replicas.push(entry);
        }
    }
    Some(Topology {
        engine,
        cluster_mode: g.cluster_enabled(),
        auth: admin_auth(engine, &g.engine_version, g.internal_password.as_deref(), &g.auth),
        shards: shards.into_values().collect(),
        users: crate::ops::users::acl_commands(r, g.info.user_group_ids.as_deref().unwrap_or_default()),
    })
}

pub(crate) fn parse_slots(s: &str) -> Vec<(u16, u16)> {
    s.split(',')
        .filter_map(|p| {
            let (a, b) = p.split_once('-').unwrap_or((p, p));
            Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
        })
        .collect()
}

pub(crate) fn format_slots(ranges: &[(u16, u16)]) -> String {
    ranges.iter().map(|(a, b)| if a == b { a.to_string() } else { format!("{a}-{b}") }).collect::<Vec<_>>().join(",")
}

/// Slot ranges for `n` shards, as ElastiCache splits them.
pub(crate) fn even_slots(n: usize) -> Vec<(u16, u16)> {
    let n = n.max(1);
    (0..n)
        .map(|i| {
            let start = (i * 16384).div_ceil(n) as u16;
            let end = (((i + 1) * 16384).div_ceil(n) - 1) as u16;
            (start, end)
        })
        .collect()
}

/// Bring up every member of a new replication group.
pub(crate) fn start_replication_group(svc: &ElastiCache, ctx: &RequestContext, key: &str, rg_id: &str) {
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| crate::ops::replication::became_available(svc, ctx, r, rg_id));
        return;
    }
    let (svc, ctx, key, rg_id) = (svc.clone(), ctx.clone(), key.to_string(), rg_id.to_string());
    spawn(async move {
        let (jobs, seed, primary_seed) = svc.with_key(&key, &ctx, |r| {
            let members: Vec<String> = r
                .clusters
                .values()
                .filter(|c| c.info.replication_group_id.as_deref() == Some(&rg_id))
                .map(|c| c.id().to_string())
                .collect();
            let seed = r
                .clusters
                .values()
                .filter(|c| c.info.replication_group_id.as_deref() == Some(&rg_id))
                .find_map(|c| c.seed_snapshot.clone())
                .and_then(|s| r.snapshots.get(&s).map(|s| s.data.clone()));
            let primary = r
                .clusters
                .values()
                .find(|c| {
                    c.info.replication_group_id.as_deref() == Some(&rg_id) && c.role.as_deref() == Some("primary")
                })
                .map(|c| c.id().to_string());
            (plan(&svc, &key, r, &members), seed, primary)
        });
        let rdb = primary_seed.as_deref().and_then(|p| seed_rdb(&svc, &key, &ctx, p));
        let mut jobs = jobs;
        if let (Some(rdb), Some(p)) = (rdb.clone(), primary_seed.as_deref()) {
            if let Some(j) = jobs.iter_mut().find(|j| j.cluster_id == p) {
                j.spec.files.push(("/data/dump.rdb".into(), rdb));
            }
        }
        let launched = launch(&svc, jobs).await;
        if let Some(e) = record(&svc, &key, &ctx, &launched) {
            return failed(&svc, &ctx, &key, "", Some(&rg_id), &e);
        }
        let Some(topo) = svc.with_key(&key, &ctx, |r| topology(r, &rg_id)) else { return };
        let seed = match (seed, rdb.is_some() && topo.cluster_mode) {
            (Some(s), _) => Some(s),
            _ => None,
        };
        if let Err(e) = configure(&svc, &topo, seed.as_ref()).await {
            return failed(&svc, &ctx, &key, "", Some(&rg_id), &e);
        }
        svc.with_key(&key, &ctx, |r| crate::ops::replication::became_available(&svc, &ctx, r, &rg_id));
    });
}

/// Wait for every node, then set up replication or the cluster, users and
/// data.
async fn configure(svc: &ElastiCache, topo: &Topology, seed: Option<&SnapshotData>) -> Result<(), String> {
    for s in &topo.shards {
        for (_, port, _) in s.primary.iter().chain(&s.replicas) {
            wait_ready(svc, topo.engine, *port, &topo.auth).await?;
        }
    }
    apply_users(svc, topo).await;
    if topo.cluster_mode {
        form_cluster(svc, topo).await?;
        if let Some(seed) = seed {
            restore_cluster(svc, topo, seed).await?;
        }
    } else {
        let shard = topo.shards.first().ok_or("replication group has no nodes")?;
        let (_, pport, ppeer) = shard.primary.clone().ok_or("replication group has no primary")?;
        if let Some(seed) = seed {
            restore_standalone(svc, pport, &topo.auth, seed).await?;
        }
        for (_, port, _) in &shard.replicas {
            let mut c = connect(svc, *port, &topo.auth).await?;
            c.ok(&["REPLICAOF", &ppeer, &pport.to_string()]).await.map_err(|e| e.0)?;
        }
    }
    Ok(())
}

async fn form_cluster(svc: &ElastiCache, topo: &Topology) -> Result<(), String> {
    let nodes: Vec<(String, u16, String)> =
        topo.shards.iter().flat_map(|s| s.primary.iter().chain(&s.replicas).cloned()).collect();
    let Some((_, first_port, _)) = nodes.first().cloned() else { return Ok(()) };
    let mut ids: BTreeMap<u16, String> = BTreeMap::new();
    for (_, port, _) in &nodes {
        let mut c = connect(svc, *port, &topo.auth).await?;
        let id = c.ok(&["CLUSTER", "MYID"]).await.map_err(|e| e.0)?.as_text().unwrap_or_default();
        ids.insert(*port, id);
    }
    let mut first = connect(svc, first_port, &topo.auth).await?;
    for (_, port, peer) in nodes.iter().skip(1) {
        first.ok(&["CLUSTER", "MEET", peer, &port.to_string(), CLUSTER_BUS_PORT]).await.map_err(|e| e.0)?;
    }
    for s in &topo.shards {
        let Some((_, port, _)) = &s.primary else { continue };
        add_slots(svc, *port, &topo.auth, &s.slots).await?;
    }
    // Every node must know every other before replicas can attach.
    wait_until(|| async {
        for (_, port, _) in &nodes {
            let mut c = connect(svc, *port, &topo.auth).await.ok()?;
            let text = c.ok(&["CLUSTER", "NODES"]).await.ok()?.as_text()?;
            if text.lines().filter(|l| !l.contains("handshake") && !l.contains("noaddr")).count() < nodes.len() {
                return None;
            }
        }
        Some(())
    })
    .await
    .ok_or("cluster nodes never met")?;
    for s in &topo.shards {
        let Some((_, pport, _)) = &s.primary else { continue };
        let pid = ids.get(pport).cloned().unwrap_or_default();
        for (_, port, _) in &s.replicas {
            let mut c = connect(svc, *port, &topo.auth).await?;
            replicate_to(&mut c, &pid).await.ok_or("replica could not attach to its primary")?;
        }
    }
    wait_cluster_ok(svc, topo).await
}

async fn wait_cluster_ok(svc: &ElastiCache, topo: &Topology) -> Result<(), String> {
    let ports: Vec<u16> = topo.shards.iter().flat_map(|s| s.primary.iter().chain(&s.replicas).map(|n| n.1)).collect();
    wait_until(|| async {
        for port in &ports {
            let mut c = connect(svc, *port, &topo.auth).await.ok()?;
            let info = c.ok(&["CLUSTER", "INFO"]).await.ok()?.as_text()?;
            if !info.contains("cluster_state:ok") {
                return None;
            }
        }
        Some(())
    })
    .await
    .ok_or_else(|| "the cluster never reached cluster_state:ok".to_string())
}

async fn add_slots(svc: &ElastiCache, port: u16, auth: &Auth, ranges: &[(u16, u16)]) -> Result<(), String> {
    if ranges.is_empty() {
        return Ok(());
    }
    let mut c = connect(svc, port, auth).await?;
    let mut args: Vec<String> = vec!["CLUSTER".into(), "ADDSLOTSRANGE".into()];
    for (a, b) in ranges {
        args.push(a.to_string());
        args.push(b.to_string());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    c.ok(&refs).await.map(drop).map_err(|e| e.0)
}

/// CLUSTER REPLICATE, retried until the replica knows its primary.
async fn replicate_to(c: &mut Client, pid: &str) -> Option<()> {
    for _ in 0..300 {
        if c.ok(&["CLUSTER", "REPLICATE", pid]).await.is_ok() {
            return Some(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

async fn wait_until<F, Fut>(mut f: F) -> Option<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<()>>,
{
    for _ in 0..300 {
        if f().await.is_some() {
            return Some(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

/// Apply a user group's ACLs on every node (ACLs are per node).
async fn apply_users(svc: &ElastiCache, topo: &Topology) {
    if topo.users.is_empty() {
        return;
    }
    for s in &topo.shards {
        for (_, port, _) in s.primary.iter().chain(&s.replicas) {
            if let Ok(mut c) = connect(svc, *port, &topo.auth).await {
                for cmd in &topo.users {
                    let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
                    if let Err(e) = c.ok(&refs).await {
                        tracing::warn!("applying ElastiCache user ACL {:?}: {e}", cmd.get(2));
                    }
                }
            }
        }
    }
}

/// Re-apply a replication group's users (after a user group change).
pub(crate) fn sync_users(svc: &ElastiCache, ctx: &RequestContext, key: &str, rg_id: &str) {
    if !svc.runs_engines() {
        return;
    }
    let Some(topo) = svc.with_key(key, ctx, |r| topology(r, rg_id)) else { return };
    let svc = svc.clone();
    spawn(async move { apply_users(&svc, &topo).await });
}

/// Run raw commands on every node of a replication group (or standalone
/// cluster), e.g. `CONFIG SET` or `ACL SETUSER default`.
pub(crate) fn run_everywhere(svc: &ElastiCache, nodes: Vec<(u16, Auth)>, commands: Vec<Vec<String>>) {
    if !svc.runs_engines() || nodes.is_empty() || commands.is_empty() {
        return;
    }
    let svc = svc.clone();
    spawn(async move {
        for (port, auth) in nodes {
            if let Ok(mut c) = connect(&svc, port, &auth).await {
                for cmd in &commands {
                    let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
                    if let Err(e) = c.ok(&refs).await {
                        tracing::debug!("ElastiCache {:?} on port {port}: {e}", cmd.first());
                    }
                }
            }
        }
    });
}

/// Turn encryption in transit on (or off) on running nodes: they keep
/// their port, which then speaks TLS (or plain RESP). `commands` run
/// first, over the old protocol.
pub(crate) fn switch_tls(svc: &ElastiCache, nodes: Vec<(u16, Auth)>, commands: Vec<Vec<String>>, enable: bool) {
    if !svc.runs_engines() || nodes.is_empty() {
        return;
    }
    let svc = svc.clone();
    spawn(async move {
        let host = connect_host(&svc);
        // Before the switch the state already names the new protocol.
        let old = if enable {
            None
        } else {
            match crate::tls::client_config(&svc.ca_certificate_pem()) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!("ElastiCache TLS switch: {e}");
                    return;
                }
            }
        };
        for (port, auth) in nodes {
            let p = port.to_string();
            let Ok(mut c) = Client::connect_with(&host, port, old.clone(), &auth).await else { continue };
            for cmd in &commands {
                let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
                let _ = c.ok(&refs).await;
            }
            let switch: Vec<&str> = if enable {
                vec![
                    "CONFIG",
                    "SET",
                    "tls-cert-file",
                    TLS_CERT,
                    "tls-key-file",
                    TLS_KEY,
                    "tls-ca-cert-file",
                    TLS_CA,
                    "tls-auth-clients",
                    "no",
                    "tls-replication",
                    "yes",
                ]
            } else {
                vec!["CONFIG", "SET", "tls-replication", "no"]
            };
            if let Err(e) = c.ok(&switch).await {
                tracing::warn!("ElastiCache TLS switch on port {port}: {e}");
                continue;
            }
            // Free the port, then listen on it with the new protocol. The
            // connection survives closing the listener.
            let (close, open) = if enable { ("port", "tls-port") } else { ("tls-port", "port") };
            if let Err(e) = c.ok(&["CONFIG", "SET", close, "0"]).await {
                tracing::warn!("ElastiCache TLS switch on port {port}: {e}");
                continue;
            }
            if let Err(e) = c.ok(&["CONFIG", "SET", open, &p]).await {
                tracing::warn!("ElastiCache TLS switch on port {port}: {e}");
            }
            // Replicas reconnect to their primary with the new protocol.
            let _ = c.cmd(&["CLIENT", "KILL", "TYPE", "master"]).await;
        }
    });
}

/// The ports and admin auth of every running node of a replication group
/// or standalone cluster.
pub(crate) fn nodes_of(r: &RegionState, rg: Option<&str>, cluster: Option<&str>) -> Vec<(u16, Auth)> {
    let mut out = Vec::new();
    for c in r.clusters.values() {
        let mine = match (rg, cluster) {
            (Some(g), _) => c.info.replication_group_id.as_deref() == Some(g),
            (None, Some(id)) => c.id() == id,
            _ => false,
        };
        if !mine {
            continue;
        }
        let auth = match c.info.replication_group_id.as_deref().and_then(|g| r.replication_groups.get(g)) {
            Some(g) => admin_auth(g.engine(), &g.engine_version, g.internal_password.as_deref(), &g.auth),
            None => cluster_auth(c),
        };
        for rt in c.nodes.values().filter(|n| n.handle.is_some()) {
            out.push((rt.port, auth.clone()));
        }
    }
    out
}

/// Bring up new replica clusters of a running replication group.
pub(crate) fn add_replicas(svc: &ElastiCache, ctx: &RequestContext, key: &str, rg_id: &str, new: Vec<String>) {
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| crate::ops::replication::became_available(svc, ctx, r, rg_id));
        return;
    }
    let (svc, ctx, key, rg_id) = (svc.clone(), ctx.clone(), key.to_string(), rg_id.to_string());
    spawn(async move {
        let jobs = svc.with_key(&key, &ctx, |r| plan(&svc, &key, r, &new));
        let launched = launch(&svc, jobs).await;
        let _ = record(&svc, &key, &ctx, &launched);
        if let Some(topo) = svc.with_key(&key, &ctx, |r| topology(r, &rg_id)) {
            if let Err(e) = attach_replicas(&svc, &topo, &new).await {
                tracing::warn!("adding replicas to {rg_id}: {e}");
            }
        }
        svc.with_key(&key, &ctx, |r| crate::ops::replication::became_available(&svc, &ctx, r, &rg_id));
    });
}

async fn attach_replicas(svc: &ElastiCache, topo: &Topology, new: &[String]) -> Result<(), String> {
    for s in &topo.shards {
        let Some((_, pport, ppeer)) = s.primary.clone() else { continue };
        for (id, port, peer) in s.replicas.iter().filter(|(id, _, _)| new.contains(id)) {
            wait_ready(svc, topo.engine, *port, &topo.auth).await?;
            if let Ok(mut c) = connect(svc, *port, &topo.auth).await {
                for cmd in &topo.users {
                    let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
                    let _ = c.ok(&refs).await;
                }
            }
            if topo.cluster_mode {
                let mut p = connect(svc, pport, &topo.auth).await?;
                let pid = p.ok(&["CLUSTER", "MYID"]).await.map_err(|e| e.0)?.as_text().unwrap_or_default();
                p.ok(&["CLUSTER", "MEET", peer, &port.to_string(), CLUSTER_BUS_PORT]).await.map_err(|e| e.0)?;
                let mut c = connect(svc, *port, &topo.auth).await?;
                replicate_to(&mut c, &pid).await.ok_or_else(|| format!("replica {id} could not attach"))?;
            } else {
                let mut c = connect(svc, *port, &topo.auth).await?;
                c.ok(&["REPLICAOF", &ppeer, &pport.to_string()]).await.map_err(|e| e.0)?;
            }
        }
    }
    Ok(())
}

/// Terminate nodes (removed replicas, deleted clusters). Cluster-mode
/// nodes are forgotten by the rest of the cluster first.
/// `(removed nodes, remaining nodes)` as `(port, auth)`.
pub(crate) type Forget = Option<(Vec<(u16, Auth)>, Vec<(u16, Auth)>)>;

pub(crate) fn terminate(svc: &ElastiCache, handles: Vec<String>, forget: Forget) {
    if !svc.runs_engines() || handles.is_empty() {
        return;
    }
    let svc = svc.clone();
    spawn(async move {
        let backend = svc.backend();
        if forget.is_none() {
            let _ = backend.terminate_all(&handles).await;
            return;
        }
        let mut forget_ids = Vec::new();
        if let Some((removed, _)) = &forget {
            for (port, auth) in removed {
                if let Ok(mut c) = connect(&svc, *port, auth).await {
                    if let Ok(id) = c.ok(&["CLUSTER", "MYID"]).await {
                        forget_ids.push(id.as_text().unwrap_or_default());
                    }
                }
            }
        }
        let _ = backend.terminate_all(&handles).await;
        if let Some((_, remaining)) = forget {
            for (port, auth) in remaining {
                if let Ok(mut c) = connect(&svc, port, &auth).await {
                    for id in &forget_ids {
                        let _ = c.ok(&["CLUSTER", "FORGET", id]).await;
                    }
                }
            }
        }
    });
}

// ---- failover -----------------------------------------------------------------

/// Promote `new_primary` (a replica cluster in `node_group`) and point the
/// other replicas and the endpoints at it. Runs `done` with the state once
/// finished.
pub(crate) fn failover<F>(svc: &ElastiCache, ctx: &RequestContext, key: &str, rg_id: &str, new_primary: &str, done: F)
where
    F: FnOnce(&ElastiCache, &RequestContext, &mut RegionState) + Send + 'static,
{
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| done(svc, ctx, r));
        return;
    }
    let (svc, ctx, key, rg_id, new_primary) =
        (svc.clone(), ctx.clone(), key.to_string(), rg_id.to_string(), new_primary.to_string());
    spawn(async move {
        if let Some(topo) = svc.with_key(&key, &ctx, |r| topology(r, &rg_id)) {
            if let Err(e) = promote(&svc, &topo, &new_primary).await {
                tracing::warn!("failover in {rg_id}: {e}");
            }
        }
        svc.with_key(&key, &ctx, |r| done(&svc, &ctx, r));
    });
}

async fn promote(svc: &ElastiCache, topo: &Topology, new_primary: &str) -> Result<(), String> {
    let shard =
        topo.shards.iter().find(|s| s.replicas.iter().any(|(id, _, _)| id == new_primary)).ok_or("no such replica")?;
    let (_, nport, npeer) = shard.replicas.iter().find(|(id, _, _)| id == new_primary).cloned().unwrap_or_default();
    let mut n = connect(svc, nport, &topo.auth).await?;
    if topo.cluster_mode {
        n.ok(&["CLUSTER", "FAILOVER"]).await.map_err(|e| e.0)?;
        wait_until(|| async {
            let mut c = connect(svc, nport, &topo.auth).await.ok()?;
            let role = c.ok(&["ROLE"]).await.ok()?;
            (role.items().first()?.as_text()? == "master").then_some(())
        })
        .await
        .ok_or("the replica never took over")?;
        return Ok(());
    }
    n.ok(&["REPLICAOF", "NO", "ONE"]).await.map_err(|e| e.0)?;
    let others = shard.primary.iter().chain(&shard.replicas).filter(|(id, _, _)| id != new_primary);
    for (_, port, _) in others {
        if let Ok(mut c) = connect(svc, *port, &topo.auth).await {
            let _ = c.ok(&["REPLICAOF", &npeer, &nport.to_string()]).await;
        }
    }
    Ok(())
}

// ---- data: snapshots ------------------------------------------------------------

/// Read every key of a node (`SCAN`, `DUMP`, `PTTL` in every database).
async fn capture_node(svc: &ElastiCache, port: u16, auth: &Auth, cluster: bool) -> Result<Vec<Entry>, String> {
    let mut c = connect(svc, port, auth).await?;
    let keyspace = resp::info(&mut c, "keyspace").await.map_err(|e| e.0)?;
    let dbs: Vec<u32> = if cluster {
        vec![0]
    } else {
        keyspace.iter().filter_map(|(k, _)| k.strip_prefix("db").and_then(|n| n.parse().ok())).collect()
    };
    let mut out = Vec::new();
    for db in dbs {
        if !cluster {
            c.ok(&["SELECT", &db.to_string()]).await.map_err(|e| e.0)?;
        }
        let mut cursor = "0".to_string();
        loop {
            let reply = c.ok(&["SCAN", &cursor, "COUNT", "1000"]).await.map_err(|e| e.0)?;
            let items = reply.items();
            cursor = items.first().and_then(|r| r.as_text()).unwrap_or_else(|| "0".into());
            for k in items.get(1).map(|r| r.items()).unwrap_or_default() {
                let Some(key) = k.as_bytes() else { continue };
                let dump = c.cmd_bytes(&[b"DUMP", &key]).await.map_err(|e| e.0)?;
                let Some(dump) = dump.as_bytes() else { continue };
                let pttl = c.cmd_bytes(&[b"PTTL", &key]).await.map_err(|e| e.0)?.as_int().unwrap_or(-1);
                out.push(Entry { db, key, dump, pttl: pttl.max(0) });
            }
            if cursor == "0" {
                break;
            }
        }
    }
    Ok(out)
}

async fn restore_entries(c: &mut Client, entries: &[&Entry], cluster: bool) -> Result<(), String> {
    let mut db = u32::MAX;
    for e in entries {
        if !cluster && e.db != db {
            c.ok(&["SELECT", &e.db.to_string()]).await.map_err(|x| x.0)?;
            db = e.db;
        }
        let ttl = e.pttl.to_string();
        match c.cmd_bytes(&[b"RESTORE", &e.key, ttl.as_bytes(), &e.dump, b"REPLACE"]).await.map_err(|x| x.0)? {
            resp::Resp::Error(err) => return Err(format!("RESTORE: {err}")),
            _ => continue,
        }
    }
    Ok(())
}

async fn restore_standalone(svc: &ElastiCache, port: u16, auth: &Auth, data: &SnapshotData) -> Result<(), String> {
    let mut c = connect(svc, port, auth).await?;
    let entries: Vec<&Entry> = data.shards.iter().flatten().collect();
    restore_entries(&mut c, &entries, false).await
}

async fn restore_cluster(svc: &ElastiCache, topo: &Topology, data: &SnapshotData) -> Result<(), String> {
    for s in &topo.shards {
        let Some((_, port, _)) = &s.primary else { continue };
        let mine: Vec<&Entry> = data
            .shards
            .iter()
            .flatten()
            .filter(|e| {
                let slot = resp::key_slot(&e.key);
                s.slots.iter().any(|(a, b)| slot >= *a && slot <= *b)
            })
            .collect();
        let mut c = connect(svc, *port, &topo.auth).await?;
        restore_entries(&mut c, &mine, true).await?;
    }
    Ok(())
}

/// Where a snapshot reads its data: each shard primary's port, admin auth
/// and whether it runs in cluster mode.
pub(crate) type Sources = Vec<(u16, Auth, bool)>;

/// The data sources of a replication group or cluster.
pub(crate) fn snapshot_sources(r: &RegionState, rg: Option<&str>, cluster: Option<&str>) -> Sources {
    if let Some(rg) = rg {
        let Some(topo) = topology(r, rg) else { return vec![] };
        topo.shards
            .iter()
            .filter_map(|sh| sh.primary.as_ref().map(|p| (p.1, topo.auth.clone(), topo.cluster_mode)))
            .collect()
    } else if let Some(c) = cluster.and_then(|c| r.clusters.get(c)) {
        let auth = match c.info.replication_group_id.as_deref().and_then(|g| r.replication_groups.get(g)) {
            Some(g) => admin_auth(g.engine(), &g.engine_version, g.internal_password.as_deref(), &g.auth),
            None => cluster_auth(c),
        };
        c.nodes.values().filter(|n| n.handle.is_some()).map(|n| (n.port, auth.clone(), false)).take(1).collect()
    } else {
        vec![]
    }
}

/// Take a snapshot's data from `sources`, mark it available, then
/// terminate `then_terminate` (a deleted cluster's nodes).
pub(crate) fn snapshot(
    svc: &ElastiCache,
    ctx: &RequestContext,
    key: &str,
    name: &str,
    sources: Sources,
    then_terminate: Vec<String>,
) {
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| crate::ops::snapshots::finished(svc, ctx, r, name, SnapshotData::default(), None));
        return;
    }
    let (svc, ctx, key, name) = (svc.clone(), ctx.clone(), key.to_string(), name.to_string());
    spawn(async move {
        let mut data = SnapshotData::default();
        let mut error = None;
        for (port, auth, cluster) in sources {
            match capture_node(&svc, port, &auth, cluster).await {
                Ok(entries) => data.shards.push(entries),
                Err(e) => error = Some(e),
            }
        }
        svc.with_key(&key, &ctx, |r| crate::ops::snapshots::finished(&svc, &ctx, r, &name, data, error));
        if !then_terminate.is_empty() {
            let _ = svc.backend().terminate_all(&then_terminate).await;
        }
    });
}

/// Capture the data of a serverless cache (for its snapshots).
pub(crate) fn serverless_snapshot(svc: &ElastiCache, ctx: &RequestContext, key: &str, name: &str) {
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| crate::ops::serverless::snapshot_finished(r, name, SnapshotData::default(), None));
        return;
    }
    let (svc, ctx, key, name) = (svc.clone(), ctx.clone(), key.to_string(), name.to_string());
    spawn(async move {
        let source = svc.with_key(&key, &ctx, |r| {
            let s = r.serverless_snapshots.get(&name)?;
            let cache = s.info.serverless_cache_configuration.as_ref()?.serverless_cache_name.clone()?;
            let c = r.serverless.get(&cache)?;
            Some((c.node.port, serverless_auth(c), c.node.handle.is_some()))
        });
        let mut data = SnapshotData::default();
        let mut error = None;
        if let Some((port, auth, true)) = source {
            if svc.runs_engines() {
                match capture_node(&svc, port, &auth, true).await {
                    Ok(e) => data.shards.push(e),
                    Err(e) => error = Some(e),
                }
            }
        }
        svc.with_key(&key, &ctx, |r| crate::ops::serverless::snapshot_finished(r, &name, data, error));
    });
}

pub(crate) fn serverless_auth(c: &crate::state::Serverless) -> Auth {
    match &c.internal_password {
        Some(pw) => Auth::User(INTERNAL_USER.into(), pw.clone()),
        None => Auth::None,
    }
}

// ---- serverless ---------------------------------------------------------------

/// Bring up the node behind a serverless cache: one cluster-mode node that
/// owns every slot, so cluster-aware clients work as against ElastiCache
/// Serverless.
pub(crate) fn start_serverless(svc: &ElastiCache, ctx: &RequestContext, key: &str, name: &str) {
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| crate::ops::serverless::became_available(svc, ctx, r, name));
        return;
    }
    let (svc, ctx, key, name) = (svc.clone(), ctx.clone(), key.to_string(), name.to_string());
    spawn(async move {
        let Some((spec, auth, engine, seed, users)) = svc.with_key(&key, &ctx, |r| {
            let c = r.serverless.get(&name)?.clone();
            let engine = EngineKind::parse(c.info.engine.as_deref().unwrap_or("valkey"))?;
            let version = c.info.full_engine_version.clone().unwrap_or_default();
            let cluster_mode = engine.is_redis_like();
            let args = engine_args(
                engine,
                &version,
                c.node.port,
                "cache.r7g.large",
                &[],
                cluster_mode,
                &AuthTokens::default(),
                c.internal_password.as_deref(),
                &svc.options().advertise_host,
                // Serverless caches always encrypt in transit.
                true,
            );
            let (account, region) = key.split_once('/').unwrap_or((&key, ""));
            let seed = c.seed_snapshot.as_ref().and_then(|s| r.serverless_snapshots.get(s)).map(|s| s.data.clone());
            let users = crate::ops::users::acl_commands(r, c.info.user_group_id.as_slice());
            Some((
                NodeSpec {
                    name: format!("serverless-{name}"),
                    account_id: account.into(),
                    region: region.into(),
                    engine,
                    engine_version: version,
                    cluster_mode,
                    port: c.node.port,
                    bind_address: svc.options().bind_address.clone(),
                    args,
                    memory_mib: 1024,
                    vcpus: 2,
                    files: tls_files(&svc),
                },
                serverless_auth(&c),
                engine,
                seed,
                users,
            ))
        }) else {
            return;
        };
        let res = svc.backend().launch(&spec).await;
        let node = match res {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("serverless cache {name}: {e}");
                svc.with_key(&key, &ctx, |r| {
                    if let Some(c) = r.serverless.get_mut(&name) {
                        c.info.status = Some("create-failed".into());
                    }
                });
                return;
            }
        };
        svc.with_key(&key, &ctx, |r| {
            if let Some(c) = r.serverless.get_mut(&name) {
                c.node.handle = Some(node.handle.clone());
                c.node.peer = Some(node.peer_address.clone());
            }
        });
        let ok = async {
            wait_ready(&svc, engine, spec.port, &auth).await?;
            if engine.is_redis_like() {
                add_slots(&svc, spec.port, &auth, &[(0, 16383)]).await?;
                let mut c = connect(&svc, spec.port, &auth).await?;
                for cmd in &users {
                    let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
                    let _ = c.ok(&refs).await;
                }
                wait_until(|| async {
                    let mut c = connect(&svc, spec.port, &auth).await.ok()?;
                    let info = c.ok(&["CLUSTER", "INFO"]).await.ok()?.as_text()?;
                    info.contains("cluster_state:ok").then_some(())
                })
                .await
                .ok_or("cluster never became ok")?;
                if let Some(seed) = &seed {
                    let entries: Vec<&Entry> = seed.shards.iter().flatten().collect();
                    restore_entries(&mut c, &entries, true).await?;
                }
            }
            Ok::<(), String>(())
        }
        .await;
        if let Err(e) = ok {
            tracing::warn!("serverless cache {name}: {e}");
        }
        svc.with_key(&key, &ctx, |r| crate::ops::serverless::became_available(&svc, &ctx, r, &name));
    });
}

// ---- reboot -------------------------------------------------------------------

/// Reboot nodes of a cluster, re-attaching replicas afterwards.
pub(crate) fn reboot(svc: &ElastiCache, ctx: &RequestContext, key: &str, cluster_id: &str, node_ids: Vec<String>) {
    let done = |svc: &ElastiCache, ctx: &RequestContext, r: &mut RegionState, id: &str, nodes: &[String]| {
        crate::ops::clusters::rebooted(svc, ctx, r, id, nodes)
    };
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| done(svc, ctx, r, cluster_id, &node_ids));
        return;
    }
    let (svc, ctx, key, id) = (svc.clone(), ctx.clone(), key.to_string(), cluster_id.to_string());
    spawn(async move {
        let (handles, rg, engine, auth) = svc.with_key(&key, &ctx, |r| {
            let c = r.clusters.get(&id).cloned().unwrap_or_default();
            let handles: Vec<(String, String)> = node_ids
                .iter()
                .filter_map(|n| c.nodes.get(n).and_then(|rt| rt.handle.clone()).map(|h| (n.clone(), h)))
                .collect();
            let auth = nodes_of(r, c.info.replication_group_id.as_deref(), Some(&id))
                .into_iter()
                .next()
                .map(|(_, a)| a)
                .unwrap_or(Auth::None);
            (handles, c.info.replication_group_id.clone(), c.engine(), auth)
        });
        for (node, h) in &handles {
            if let Ok(peer) = svc.backend().reboot(h).await {
                svc.with_key(&key, &ctx, |r| {
                    if let Some(rt) = r.clusters.get_mut(&id).and_then(|c| c.nodes.get_mut(node)) {
                        rt.peer = Some(peer);
                    }
                });
            }
        }
        let ports: Vec<u16> = svc.with_key(&key, &ctx, |r| {
            r.clusters.get(&id).map(|c| c.nodes.values().map(|n| n.port).collect()).unwrap_or_default()
        });
        for p in ports {
            let _ = wait_ready(&svc, engine, p, &auth).await;
        }
        // A rebooted replica re-attaches to its primary; a rebooted
        // primary comes back empty with its replicas re-syncing from it.
        if let Some(rg) = rg {
            if let Some(topo) = svc.with_key(&key, &ctx, |r| topology(r, &rg)) {
                if !topo.cluster_mode {
                    apply_users(&svc, &topo).await;
                    let _ = attach_all(&svc, &topo).await;
                }
            }
        }
        svc.with_key(&key, &ctx, |r| done(&svc, &ctx, r, &id, &node_ids));
    });
}

async fn attach_all(svc: &ElastiCache, topo: &Topology) -> Result<(), String> {
    let ids: Vec<String> = topo.shards.iter().flat_map(|s| s.replicas.iter().map(|r| r.0.clone())).collect();
    attach_replicas(svc, topo, &ids).await
}

// ---- resharding -------------------------------------------------------------------

/// Move slots between shards after shards were added or before they are
/// removed: `target` maps each node group to the slot ranges it should own.
pub(crate) fn reshard(
    svc: &ElastiCache,
    ctx: &RequestContext,
    key: &str,
    rg_id: &str,
    new_clusters: Vec<String>,
    removed: Vec<String>,
    target: BTreeMap<String, String>,
) {
    let finish = {
        let target = target.clone();
        let removed = removed.clone();
        move |svc: &ElastiCache, ctx: &RequestContext, r: &mut RegionState, rg: &str| {
            crate::ops::replication::resharded(svc, ctx, r, rg, &target, &removed)
        }
    };
    if !svc.runs_engines() {
        svc.with_key(key, ctx, |r| finish(svc, ctx, r, rg_id));
        return;
    }
    let (svc, ctx, key, rg_id) = (svc.clone(), ctx.clone(), key.to_string(), rg_id.to_string());
    spawn(async move {
        let jobs = svc.with_key(&key, &ctx, |r| plan(&svc, &key, r, &new_clusters));
        let launched = launch(&svc, jobs).await;
        let _ = record(&svc, &key, &ctx, &launched);
        let res = async {
            let topo = svc.with_key(&key, &ctx, |r| topology(r, &rg_id)).ok_or("no such group")?;
            // Join the new nodes.
            let first = topo
                .shards
                .iter()
                .find_map(|s| s.primary.clone().filter(|p| !new_clusters.contains(&p.0)))
                .ok_or("no primary")?;
            for s in &topo.shards {
                for (id, port, peer) in s.primary.iter().chain(&s.replicas) {
                    if new_clusters.contains(id) {
                        wait_ready(&svc, topo.engine, *port, &topo.auth).await?;
                        let mut c = connect(&svc, first.1, &topo.auth).await?;
                        c.ok(&["CLUSTER", "MEET", peer, &port.to_string(), CLUSTER_BUS_PORT]).await.map_err(|e| e.0)?;
                    }
                }
            }
            apply_users(&svc, &topo).await;
            // Node ids, current slot owners.
            let mut node_ids: BTreeMap<String, (u16, String)> = BTreeMap::new();
            for s in &topo.shards {
                if let Some((_, port, _)) = &s.primary {
                    let mut c = connect(&svc, *port, &topo.auth).await?;
                    let id = c.ok(&["CLUSTER", "MYID"]).await.map_err(|e| e.0)?.as_text().unwrap_or_default();
                    node_ids.insert(s.id.clone(), (*port, id));
                }
            }
            wait_until(|| async {
                let mut c = connect(&svc, first.1, &topo.auth).await.ok()?;
                let text = c.ok(&["CLUSTER", "NODES"]).await.ok()?.as_text()?;
                node_ids.values().all(|(_, id)| text.contains(id.as_str())).then_some(())
            })
            .await
            .ok_or("new shards never joined")?;
            // Replicas of new shards.
            for s in &topo.shards {
                let Some((pid_port, pid)) = node_ids.get(&s.id).cloned() else { continue };
                let _ = pid_port;
                for (id, port, _) in &s.replicas {
                    if new_clusters.contains(id) {
                        let mut c = connect(&svc, *port, &topo.auth).await?;
                        replicate_to(&mut c, &pid).await.ok_or("replica could not attach")?;
                    }
                }
            }
            let owner_of = |slot: u16, map: &BTreeMap<String, String>| {
                map.iter()
                    .find(|(_, ranges)| parse_slots(ranges).iter().any(|(a, b)| slot >= *a && slot <= *b))
                    .map(|(k, _)| k.clone())
            };
            let current: BTreeMap<String, String> =
                topo.shards.iter().map(|s| (s.id.clone(), format_slots(&s.slots))).collect();
            for slot in 0..16384u16 {
                let (Some(from), Some(to)) = (owner_of(slot, &current), owner_of(slot, &target)) else { continue };
                if from == to {
                    continue;
                }
                let (Some(src), Some(dst)) = (node_ids.get(&from).cloned(), node_ids.get(&to).cloned()) else {
                    continue;
                };
                migrate_slot(&svc, &topo, slot, src, dst, node_ids.values().map(|v| v.0).collect()).await?;
            }
            Ok::<(), String>(())
        }
        .await;
        if let Err(e) = res {
            tracing::warn!("resharding {rg_id}: {e}");
        }
        // Forget and remove emptied shards.
        let (handles, removed_nodes, remaining) = svc.with_key(&key, &ctx, |r| {
            let mut handles = Vec::new();
            let mut removed_nodes = Vec::new();
            let mut remaining = Vec::new();
            let auth = topology(r, &rg_id).map(|t| t.auth).unwrap_or(Auth::None);
            for c in r.clusters.values().filter(|c| c.info.replication_group_id.as_deref() == Some(&rg_id)) {
                let gone = c.node_group_id.as_ref().is_some_and(|ng| removed.contains(ng));
                for rt in c.nodes.values() {
                    if gone {
                        handles.extend(rt.handle.clone());
                        removed_nodes.push((rt.port, auth.clone()));
                    } else {
                        remaining.push((rt.port, auth.clone()));
                    }
                }
            }
            (handles, removed_nodes, remaining)
        });
        if !handles.is_empty() {
            terminate(&svc, handles, Some((removed_nodes, remaining)));
        }
        svc.with_key(&key, &ctx, |r| finish(&svc, &ctx, r, &rg_id));
    });
}

async fn migrate_slot(
    svc: &ElastiCache,
    topo: &Topology,
    slot: u16,
    (sport, sid): (u16, String),
    (dport, did): (u16, String),
    all: Vec<u16>,
) -> Result<(), String> {
    let s = slot.to_string();
    let mut src = connect(svc, sport, &topo.auth).await?;
    let mut dst = connect(svc, dport, &topo.auth).await?;
    dst.ok(&["CLUSTER", "SETSLOT", &s, "IMPORTING", &sid]).await.map_err(|e| e.0)?;
    src.ok(&["CLUSTER", "SETSLOT", &s, "MIGRATING", &did]).await.map_err(|e| e.0)?;
    let dpeer = topo
        .shards
        .iter()
        .flat_map(|sh| sh.primary.iter())
        .find(|p| p.1 == dport)
        .map(|p| p.2.clone())
        .unwrap_or_default();
    loop {
        let keys = src.ok(&["CLUSTER", "GETKEYSINSLOT", &s, "100"]).await.map_err(|e| e.0)?;
        let keys: Vec<Vec<u8>> = keys.items().iter().filter_map(|k| k.as_bytes()).collect();
        if keys.is_empty() {
            break;
        }
        let dport_s = dport.to_string();
        let mut args: Vec<&[u8]> =
            vec![b"MIGRATE", dpeer.as_bytes(), dport_s.as_bytes(), b"", b"0", b"5000", b"REPLACE"];
        let auth_parts: Vec<Vec<u8>> = match &topo.auth {
            Auth::None => vec![],
            Auth::Password(p) => vec![b"AUTH".to_vec(), p.as_bytes().to_vec()],
            Auth::User(u, p) => vec![b"AUTH2".to_vec(), u.as_bytes().to_vec(), p.as_bytes().to_vec()],
        };
        args.extend(auth_parts.iter().map(Vec::as_slice));
        args.push(b"KEYS");
        args.extend(keys.iter().map(Vec::as_slice));
        if let resp::Resp::Error(e) = src.cmd_bytes(&args).await.map_err(|e| e.0)? {
            return Err(format!("MIGRATE: {e}"));
        }
    }
    for port in all {
        if let Ok(mut c) = connect(svc, port, &topo.auth).await {
            let _ = c.ok(&["CLUSTER", "SETSLOT", &s, "NODE", &did]).await;
        }
    }
    Ok(())
}

// ---- migration ----------------------------------------------------------------------

/// Replicate a replication group's primary from a self-managed endpoint
/// (online migration), or stop doing so.
pub(crate) fn migrate_from(
    svc: &ElastiCache,
    ctx: &RequestContext,
    key: &str,
    rg_id: &str,
    source: Option<(String, u16)>,
) {
    if !svc.runs_engines() {
        return;
    }
    let Some(topo) = svc.with_key(key, ctx, |r| topology(r, rg_id)) else { return };
    let svc = svc.clone();
    spawn(async move {
        let Some((_, port, _)) = topo.shards.first().and_then(|s| s.primary.clone()) else { return };
        if let Ok(mut c) = connect(&svc, port, &topo.auth).await {
            let res = match &source {
                Some((host, p)) => {
                    // A source on this host is reached through Docker's
                    // host gateway.
                    let host = match host.as_str() {
                        "localhost" | "127.0.0.1" | "::1" => "host.docker.internal",
                        h => h,
                    };
                    c.ok(&["REPLICAOF", host, &p.to_string()]).await
                }
                None => c.ok(&["REPLICAOF", "NO", "ONE"]).await,
            };
            if let Err(e) = res {
                tracing::warn!("ElastiCache migration: {e}");
            }
        }
    });
}

/// Whether a self-managed endpoint answers (TestMigration).
pub(crate) async fn reachable(host: &str, port: u16) -> bool {
    match Client::connect(host, port).await {
        Ok(mut c) => matches!(c.cmd(&["PING"]).await, Ok(resp::Resp::Simple(_)) | Ok(resp::Resp::Error(_))),
        Err(_) => false,
    }
}

// ---- RDB export -----------------------------------------------------------------------

/// An RDB file holding `entries` (as ElastiCache exports snapshots to S3).
pub(crate) fn rdb_file(entries: &[&Entry], now_ms: i64) -> Vec<u8> {
    let version = entries
        .iter()
        .find_map(|e| {
            (e.dump.len() >= 10).then(|| u16::from_le_bytes([e.dump[e.dump.len() - 10], e.dump[e.dump.len() - 9]]))
        })
        .unwrap_or(9);
    let mut out = format!("REDIS{version:04}").into_bytes();
    let mut by_db: BTreeMap<u32, Vec<&Entry>> = BTreeMap::new();
    for e in entries {
        by_db.entry(e.db).or_default().push(e);
    }
    for (db, list) in by_db {
        out.push(0xFE);
        rdb_len(&mut out, db as u64);
        for e in list {
            if e.dump.len() < 11 {
                continue;
            }
            if e.pttl > 0 {
                out.push(0xFC);
                out.extend_from_slice(&(now_ms + e.pttl).to_le_bytes());
            }
            out.push(e.dump[0]);
            rdb_len(&mut out, e.key.len() as u64);
            out.extend_from_slice(&e.key);
            out.extend_from_slice(&e.dump[1..e.dump.len() - 10]);
        }
    }
    out.push(0xFF);
    // A zero checksum tells the loader the file has none.
    out.extend_from_slice(&[0u8; 8]);
    out
}

fn rdb_len(out: &mut Vec<u8>, n: u64) {
    if n < 64 {
        out.push(n as u8);
    } else if n < 16384 {
        out.push(0x40 | (n >> 8) as u8);
        out.push(n as u8);
    } else if n <= u32::MAX as u64 {
        out.push(0x80);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(0x81);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

// ---- restart ----------------------------------------------------------------------------

/// After state was restored: reopen the endpoint proxies on their ports.
pub(crate) fn reattach(svc: &ElastiCache) {
    if !svc.runs_engines() {
        return;
    }
    let keys: Vec<String> = svc.lock().regions.keys().cloned().collect();
    for key in keys {
        let groups: Vec<String> =
            svc.lock().regions.get(&key).map(|r| r.replication_groups.keys().cloned().collect()).unwrap_or_default();
        for g in groups {
            crate::ops::replication::open_proxies(svc, &key, &g, true);
        }
    }
}

// ---- global datastores --------------------------------------------------------------

/// Where a global datastore's secondary replicates from: the primary
/// replication group's primary node (peer address, port) and the
/// credentials of its internal user.
pub(crate) struct GlobalSource {
    pub peer: String,
    pub port: u16,
    pub password: Option<String>,
}

/// The replication source of a (cluster mode disabled) primary group.
pub(crate) fn global_source(r: &RegionState, rg_id: &str) -> Option<GlobalSource> {
    let topo = topology(r, rg_id)?;
    if topo.cluster_mode {
        return None;
    }
    let (_, port, peer) = topo.shards.first()?.primary.clone()?;
    let g = r.replication_groups.get(rg_id)?;
    Some(GlobalSource { peer, port, password: g.internal_password.clone() })
}

/// Make a secondary group's primary replicate from the global primary
/// (`Some`), or stand alone again (`None`). Waits for the secondary to be
/// available first.
pub(crate) fn link_global(
    svc: &ElastiCache,
    ctx: &RequestContext,
    key: &str,
    rg_id: &str,
    source: Option<GlobalSource>,
) {
    if !svc.runs_engines() {
        return;
    }
    let svc = svc.clone();
    let ctx = ctx.clone();
    let key = key.to_string();
    let rg_id = rg_id.to_string();
    spawn(async move {
        let mut topo = None;
        for _ in 0..1200 {
            let ready = svc.with_key(&key, &ctx, |r| {
                let g = r.replication_groups.get(&rg_id)?;
                if g.status() == "available" {
                    topology(r, &rg_id)
                } else {
                    None
                }
            });
            if ready.is_some() {
                topo = ready;
                break;
            }
            let gone = svc.with_key(&key, &ctx, |r| !r.replication_groups.contains_key(&rg_id));
            if gone {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        let Some(topo) = topo else { return };
        if topo.cluster_mode {
            // Cross-shard replication between clusters is not emulated.
            return;
        }
        let Some((_, port, _)) = topo.shards.first().and_then(|s| s.primary.clone()) else { return };
        let Ok(mut c) = connect(&svc, port, &topo.auth).await else { return };
        let res = match &source {
            Some(s) => {
                if let Some(pw) = &s.password {
                    if acl_capable(topo.engine, "7") {
                        let _ = c.ok(&["CONFIG", "SET", "masteruser", INTERNAL_USER]).await;
                    }
                    let _ = c.ok(&["CONFIG", "SET", "masterauth", pw]).await;
                }
                c.ok(&["REPLICAOF", &s.peer, &s.port.to_string()]).await
            }
            None => c.ok(&["REPLICAOF", "NO", "ONE"]).await,
        };
        if let Err(e) = res {
            tracing::warn!("ElastiCache global datastore link for {rg_id}: {e}");
        }
    });
}
