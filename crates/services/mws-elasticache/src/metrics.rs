//! The `AWS/ElastiCache` CloudWatch metrics: one data point per node (and
//! per serverless cache) per minute.
//!
//! With the Docker backend, MWS samples each running node's `INFO`
//! (Valkey, Redis OSS) or `stats` (Memcached) every few seconds; minutes
//! close on the emulated clock, and counters are published as what
//! changed during the minute. With the metadata backend nodes have no
//! activity: counters are zero and gauges describe an idle node.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::backend::EngineKind;
use crate::catalog;
use crate::resp::Auth;
use crate::ElastiCache;

/// One metric data point ElastiCache publishes.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheMetric {
    pub account: String,
    pub region: String,
    pub metric_name: &'static str,
    /// `CacheClusterId` and `CacheNodeId`, or `clusterId` for serverless
    /// caches.
    pub dimensions: Vec<(String, String)>,
    /// `Percent`, `Bytes`, `Count` or `Seconds`.
    pub unit: &'static str,
    /// Epoch milliseconds: the start of the minute.
    pub timestamp: i64,
    pub value: f64,
}

/// Where ElastiCache metrics go (CloudWatch, in MWS).
pub trait MetricPublisher: Send + Sync {
    fn publish(&self, metrics: Vec<CacheMetric>);
}

/// What a node reported, and when (real time).
#[derive(Debug, Clone, Default)]
struct Sample {
    at: f64,
    fields: HashMap<String, f64>,
    role_master: bool,
}

#[derive(Debug, Default)]
struct NodeMeter {
    next_minute: i64,
    /// The sample the last published minute ended with.
    base: Option<Sample>,
}

#[derive(Default)]
pub(crate) struct Meter {
    publisher: OnceLock<Arc<dyn MetricPublisher>>,
    offset_ms: AtomicI64,
    scheduler: AtomicBool,
    samples: Mutex<HashMap<String, Sample>>,
    nodes: Mutex<HashMap<String, NodeMeter>>,
}

/// A node to sample and report.
#[derive(Debug, Clone)]
struct Node {
    /// `account/region/cluster/node`, or `account/region/serverless/name`.
    id: String,
    account: String,
    region: String,
    dimensions: Vec<(String, String)>,
    engine: EngineKind,
    port: u16,
    auth: Auth,
    running: bool,
    memory_bytes: f64,
    maxmemory: f64,
    vcpus: f64,
    serverless: bool,
    created: i64,
}

const GET_COMMANDS: &[&str] = &[
    "get",
    "mget",
    "getex",
    "getrange",
    "strlen",
    "exists",
    "hget",
    "hmget",
    "hgetall",
    "hexists",
    "hlen",
    "hkeys",
    "hvals",
    "lrange",
    "lindex",
    "llen",
    "smembers",
    "sismember",
    "scard",
    "zrange",
    "zrangebyscore",
    "zscore",
    "zcard",
    "ttl",
    "pttl",
    "type",
];
const SET_COMMANDS: &[&str] = &[
    "set",
    "setex",
    "psetex",
    "setnx",
    "mset",
    "msetnx",
    "getset",
    "getdel",
    "append",
    "setrange",
    "incr",
    "incrby",
    "incrbyfloat",
    "decr",
    "decrby",
    "del",
    "unlink",
    "expire",
    "pexpire",
    "expireat",
    "persist",
    "hset",
    "hsetnx",
    "hmset",
    "hdel",
    "hincrby",
    "lpush",
    "rpush",
    "lpop",
    "rpop",
    "lset",
    "ltrim",
    "sadd",
    "srem",
    "spop",
    "zadd",
    "zrem",
    "zincrby",
];

impl ElastiCache {
    /// Publish `AWS/ElastiCache` metrics through `publisher`.
    pub fn set_metric_publisher(&self, publisher: Arc<dyn MetricPublisher>) {
        let _ = self.meter().publisher.set(publisher);
    }

    /// Note the emulated time of a request, start the background sampler,
    /// and publish the minutes that ended before it.
    pub(crate) fn observe_clock(&self, received_at: chrono::DateTime<chrono::Utc>) {
        let meter = self.meter();
        if meter.publisher.get().is_none() {
            return;
        }
        let offset = (received_at - chrono::Utc::now()).num_milliseconds().max(0);
        meter.offset_ms.store(offset, Ordering::Relaxed);
        if tokio::runtime::Handle::try_current().is_ok() && !meter.scheduler.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move {
                let mut tick = 0u64;
                loop {
                    // Sample every 5 seconds.
                    if tick == 0 && me.runs_engines() {
                        me.sample_nodes().await;
                    }
                    tick = (tick + 1) % 5;
                    let now = chrono::Utc::now().timestamp_millis() + me.meter().offset_ms.load(Ordering::Relaxed);
                    me.publish_metrics(now);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
        self.publish_metrics(received_at.timestamp_millis());
    }

    fn metered_nodes(&self) -> Vec<Node> {
        let st = self.lock();
        let mut out = Vec::new();
        for (key, r) in &st.regions {
            let (account, region) = key.split_once('/').unwrap_or((key, ""));
            for c in r.clusters.values() {
                if !matches!(c.status(), "available" | "modifying" | "snapshotting" | "rebooting cache cluster nodes") {
                    continue;
                }
                let nt = catalog::node_type(c.info.cache_node_type.as_deref().unwrap_or_default());
                let rg = c.info.replication_group_id.as_deref().and_then(|g| r.replication_groups.get(g));
                let auth = match rg {
                    Some(g) => crate::engine::admin_auth(
                        g.engine(),
                        &g.engine_version,
                        g.internal_password.as_deref(),
                        &g.auth,
                    ),
                    None => crate::engine::cluster_auth(c),
                };
                let created = c.info.cache_cluster_create_time.map(|t| t.timestamp_millis()).unwrap_or_default();
                for (node_id, rt) in &c.nodes {
                    out.push(Node {
                        id: format!("{key}/{}/{node_id}", c.id()),
                        account: account.into(),
                        region: region.into(),
                        dimensions: vec![
                            ("CacheClusterId".into(), c.id().to_string()),
                            ("CacheNodeId".into(), node_id.clone()),
                        ],
                        engine: c.engine(),
                        port: rt.port,
                        auth: auth.clone(),
                        running: rt.handle.is_some(),
                        memory_bytes: nt.map(|n| n.memory_mib() as f64 * 1024.0 * 1024.0).unwrap_or(0.0),
                        maxmemory: nt.map(|n| n.maxmemory() as f64).unwrap_or(0.0),
                        vcpus: nt.map(|n| n.vcpus as f64).unwrap_or(1.0),
                        serverless: false,
                        created,
                    });
                }
            }
            for s in r.serverless.values() {
                if s.info.status.as_deref() != Some("available") {
                    continue;
                }
                let name = s.info.serverless_cache_name.clone().unwrap_or_default();
                let engine =
                    EngineKind::parse(s.info.engine.as_deref().unwrap_or("valkey")).unwrap_or(EngineKind::Valkey);
                out.push(Node {
                    id: format!("{key}/serverless/{name}"),
                    account: account.into(),
                    region: region.into(),
                    dimensions: vec![("clusterId".into(), name)],
                    engine,
                    port: s.node.port,
                    auth: crate::engine::serverless_auth(s),
                    running: s.node.handle.is_some(),
                    memory_bytes: 0.0,
                    maxmemory: 0.0,
                    vcpus: 2.0,
                    serverless: true,
                    created: s.info.create_time.map(|t| t.timestamp_millis()).unwrap_or_default(),
                });
            }
        }
        out
    }

    /// Read every running node's counters.
    async fn sample_nodes(&self) {
        let nodes = self.metered_nodes();
        let mut fresh = HashMap::new();
        for n in nodes.iter().filter(|n| n.running) {
            let sample = match n.engine {
                EngineKind::Memcached => crate::engine::memcached_stats(self, n.port).await,
                _ => crate::engine::redis_info(self, n.port, &n.auth).await,
            };
            if let Some((fields, master)) = sample {
                let at = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
                fresh.insert(n.id.clone(), Sample { at, fields, role_master: master });
            }
        }
        let mut samples = self.meter().samples.lock().expect("ElastiCache meter lock poisoned");
        samples.retain(|k, _| nodes.iter().any(|n| &n.id == k));
        samples.extend(fresh);
    }

    /// Publish every minute that ended by `now` (epoch milliseconds).
    pub fn publish_metrics(&self, now: i64) {
        let meter = self.meter();
        let Some(publisher) = meter.publisher.get().cloned() else { return };
        let current = now.div_euclid(60_000);
        let nodes = self.metered_nodes();
        let samples = meter.samples.lock().expect("ElastiCache meter lock poisoned").clone();
        let mut out = Vec::new();
        {
            let mut meters = meter.nodes.lock().expect("ElastiCache meter lock poisoned");
            meters.retain(|k, _| nodes.iter().any(|n| &n.id == k));
            for n in &nodes {
                let m = meters.entry(n.id.clone()).or_insert_with(|| NodeMeter {
                    next_minute: n.created.div_euclid(60_000).max(current - 1),
                    base: None,
                });
                if m.next_minute >= current {
                    continue;
                }
                // Missed minutes (a clock jump) collapse into the last one.
                let minute = current - 1;
                m.next_minute = current;
                let latest = samples.get(&n.id).cloned();
                points(n, minute * 60_000, m.base.as_ref(), latest.as_ref(), &mut out);
                if latest.is_some() {
                    m.base = latest;
                }
            }
        }
        if !out.is_empty() {
            publisher.publish(out);
        }
    }
}

fn points(n: &Node, timestamp: i64, base: Option<&Sample>, latest: Option<&Sample>, out: &mut Vec<CacheMetric>) {
    let mut push = |name: &'static str, unit: &'static str, value: f64| {
        out.push(CacheMetric {
            account: n.account.clone(),
            region: n.region.clone(),
            metric_name: name,
            dimensions: n.dimensions.clone(),
            unit,
            timestamp,
            value: if value.is_finite() { value.max(0.0) } else { 0.0 },
        });
    };
    let empty = Sample::default();
    let now = latest.unwrap_or(&empty);
    let field = |s: &Sample, k: &str| s.fields.get(k).copied().unwrap_or(0.0);
    // What changed since the minute before (the first minute counts from
    // the node's start).
    let delta = |k: &str| match base {
        Some(b) => (field(now, k) - field(b, k)).max(0.0),
        None => field(now, k),
    };
    let elapsed = match base {
        Some(b) if now.at > b.at => now.at - b.at,
        _ => 60.0,
    };
    let cpu = |user: &str, sys: &str| (delta(user) + delta(sys)) / elapsed * 100.0;
    match n.engine {
        EngineKind::Memcached => {
            push("CPUUtilization", "Percent", cpu("rusage_user", "rusage_system") / n.vcpus);
            push("CurrConnections", "Count", (field(now, "curr_connections") - 1.0).max(0.0));
            push("NewConnections", "Count", delta("total_connections"));
            push("CurrItems", "Count", field(now, "curr_items"));
            push("BytesUsedForCacheItems", "Bytes", field(now, "bytes"));
            push("GetHits", "Count", delta("get_hits"));
            push("GetMisses", "Count", delta("get_misses"));
            push("CmdGet", "Count", delta("cmd_get"));
            push("CmdSet", "Count", delta("cmd_set"));
            push("Evictions", "Count", delta("evictions"));
            push("Reclaimed", "Count", delta("reclaimed"));
            push("BytesReadIntoMemcached", "Bytes", delta("bytes_read"));
            push("BytesWrittenOutFromMemcached", "Bytes", delta("bytes_written"));
            push("FreeableMemory", "Bytes", n.memory_bytes - field(now, "bytes"));
        }
        _ => {
            let hits = delta("keyspace_hits");
            let misses = delta("keyspace_misses");
            let hit_rate = if hits + misses > 0.0 { hits / (hits + misses) * 100.0 } else { 0.0 };
            let used = field(now, "used_memory");
            let gets: f64 = GET_COMMANDS.iter().map(|c| delta(&format!("cmdstat_{c}"))).sum();
            let sets: f64 = SET_COMMANDS.iter().map(|c| delta(&format!("cmdstat_{c}"))).sum();
            push("CacheHits", "Count", hits);
            push("CacheMisses", "Count", misses);
            push("CacheHitRate", "Percent", hit_rate);
            push("BytesUsedForCache", "Bytes", used);
            push("CurrConnections", "Count", (field(now, "connected_clients") - 1.0).max(0.0));
            push("NetworkBytesIn", "Bytes", delta("total_net_input_bytes"));
            push("NetworkBytesOut", "Bytes", delta("total_net_output_bytes"));
            push("CurrItems", "Count", field(now, "keys"));
            push("GetTypeCmds", "Count", gets);
            push("SetTypeCmds", "Count", sets);
            if n.serverless {
                // One ECPU per simple command.
                push("ElastiCacheProcessingUnits", "Count", delta("total_commands_processed"));
                return;
            }
            push("CPUUtilization", "Percent", cpu("used_cpu_user", "used_cpu_sys") / n.vcpus);
            let engine_cpu = if now.fields.contains_key("used_cpu_user_main_thread") {
                cpu("used_cpu_user_main_thread", "used_cpu_sys_main_thread")
            } else {
                cpu("used_cpu_user", "used_cpu_sys")
            };
            push("EngineCPUUtilization", "Percent", engine_cpu);
            push("FreeableMemory", "Bytes", n.memory_bytes - field(now, "used_memory_rss").max(used));
            let pct = if n.maxmemory > 0.0 { used / n.maxmemory * 100.0 } else { 0.0 };
            push("DatabaseMemoryUsagePercentage", "Percent", pct);
            push("NewConnections", "Count", delta("total_connections_received"));
            push("Evictions", "Count", delta("evicted_keys"));
            push("Reclaimed", "Count", delta("expired_keys"));
            let master = latest.is_none_or(|s| s.role_master);
            push("IsMaster", "Count", if master { 1.0 } else { 0.0 });
            if master {
                push("ReplicationBytes", "Bytes", delta("master_repl_offset"));
            } else {
                push("ReplicationLag", "Seconds", field(now, "master_last_io_seconds_ago"));
            }
            let frag = field(now, "mem_fragmentation_ratio");
            push("MemoryFragmentationRatio", "Count", if frag > 0.0 { frag } else { 1.0 });
        }
    }
}

/// Parse `INFO` output: numeric fields, command counts (`cmdstat_<name>`),
/// the key count (`keys`) and whether the node is a primary.
pub(crate) fn parse_info(text: &str) -> (HashMap<String, f64>, bool) {
    let mut fields = HashMap::new();
    let mut master = true;
    let mut keys = 0.0;
    for line in text.lines() {
        let Some((k, v)) = line.trim().split_once(':') else { continue };
        if k == "role" {
            master = v == "master";
        } else if let Some(cmd) = k.strip_prefix("cmdstat_") {
            // `calls=3,usec=...`
            if let Some(calls) = v.split(',').find_map(|p| p.strip_prefix("calls=")) {
                fields.insert(format!("cmdstat_{}", cmd.to_ascii_lowercase()), calls.parse().unwrap_or(0.0));
            }
        } else if k.starts_with("db") && v.starts_with("keys=") {
            keys += v
                .split(',')
                .next()
                .and_then(|p| p.strip_prefix("keys="))
                .and_then(|n| n.parse::<f64>().ok())
                .unwrap_or(0.0);
        } else if let Ok(n) = v.parse::<f64>() {
            fields.insert(k.to_string(), n);
        }
    }
    fields.insert("keys".into(), keys);
    (fields, master)
}

/// Parse Memcached `stats` output (`STAT name value` lines).
pub(crate) fn parse_stats(text: &str) -> HashMap<String, f64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("STAT") {
            continue;
        }
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if let Ok(n) = v.parse::<f64>() {
                out.insert(k.to_string(), n);
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_info() {
        let (f, master) = parse_info(
            "# Replication\r\nrole:slave\r\nkeyspace_hits:5\r\ncmdstat_get:calls=7,usec=10\r\ndb0:keys=3,expires=0\r\ndb1:keys=2,expires=1\r\n",
        );
        assert!(!master);
        assert_eq!(f["keyspace_hits"], 5.0);
        assert_eq!(f["cmdstat_get"], 7.0);
        assert_eq!(f["keys"], 5.0);
        let s = parse_stats("STAT curr_items 4\r\nSTAT version 1.6.22\r\nEND\r\n");
        assert_eq!(s["curr_items"], 4.0);
    }
}
