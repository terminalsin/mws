//! What ElastiCache offers: engine versions, parameter group families and
//! their parameters, node types, reserved node offerings and service
//! updates.

use crate::backend::EngineKind;
use crate::generated::types as t;

/// One engine version AWS offers.
pub struct EngineVersion {
    pub engine: EngineKind,
    /// The full version clusters report (`7.1.0`).
    pub version: &'static str,
    /// Versions a request may name for it (`7.1`, `6.x`).
    pub aliases: &'static [&'static str],
    pub family: &'static str,
}

pub const ENGINE_VERSIONS: &[EngineVersion] = &[
    EngineVersion { engine: EngineKind::Memcached, version: "1.4.5", aliases: &[], family: "memcached1.4" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.4.14", aliases: &[], family: "memcached1.4" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.4.24", aliases: &[], family: "memcached1.4" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.4.33", aliases: &[], family: "memcached1.4" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.4.34", aliases: &[], family: "memcached1.4" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.5.10", aliases: &[], family: "memcached1.5" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.5.16", aliases: &[], family: "memcached1.5" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.6.6", aliases: &[], family: "memcached1.6" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.6.12", aliases: &[], family: "memcached1.6" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.6.17", aliases: &[], family: "memcached1.6" },
    EngineVersion { engine: EngineKind::Memcached, version: "1.6.22", aliases: &["1.6"], family: "memcached1.6" },
    EngineVersion { engine: EngineKind::Redis, version: "4.0.10", aliases: &["4.0"], family: "redis4.0" },
    EngineVersion { engine: EngineKind::Redis, version: "5.0.6", aliases: &["5.0"], family: "redis5.0" },
    EngineVersion { engine: EngineKind::Redis, version: "6.0.5", aliases: &["6.0"], family: "redis6.x" },
    EngineVersion { engine: EngineKind::Redis, version: "6.2.6", aliases: &["6.2", "6.x"], family: "redis6.x" },
    EngineVersion { engine: EngineKind::Redis, version: "7.0.7", aliases: &["7.0"], family: "redis7" },
    EngineVersion { engine: EngineKind::Redis, version: "7.1.0", aliases: &["7.1", "7"], family: "redis7" },
    EngineVersion { engine: EngineKind::Valkey, version: "7.2.6", aliases: &["7.2", "7"], family: "valkey7" },
    EngineVersion { engine: EngineKind::Valkey, version: "8.0.1", aliases: &["8.0"], family: "valkey8" },
    EngineVersion { engine: EngineKind::Valkey, version: "8.1.0", aliases: &["8.1", "8"], family: "valkey8" },
];

/// The version a request names, or the engine's default (latest).
pub fn engine_version(engine: EngineKind, requested: Option<&str>) -> Option<&'static EngineVersion> {
    let mut of_engine = ENGINE_VERSIONS.iter().filter(|v| v.engine == engine);
    match requested {
        None | Some("") => of_engine.next_back(),
        Some(r) => of_engine.rfind(|v| v.version == r || v.aliases.contains(&r)),
    }
}

pub fn engine_description(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::Redis => "Redis",
        EngineKind::Valkey => "Valkey",
        EngineKind::Memcached => "memcached",
    }
}

pub fn family_engine(family: &str) -> Option<EngineKind> {
    ENGINE_VERSIONS.iter().find(|v| v.family == family).map(|v| v.engine)
}

/// Every parameter group family, in AWS's order.
pub fn families() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for v in ENGINE_VERSIONS {
        if !out.contains(&v.family) {
            out.push(v.family);
        }
    }
    out
}

/// The default parameter groups of a family.
pub fn default_groups(family: &str) -> Vec<String> {
    let mut out = vec![format!("default.{family}")];
    if family_engine(family).is_some_and(EngineKind::is_redis_like) {
        out.push(format!("default.{family}.cluster.on"));
    }
    out
}

/// A cache node type.
pub struct NodeType {
    pub name: &'static str,
    pub vcpus: u32,
    /// Memory in GiB, as AWS lists it.
    pub memory_gib: f64,
    /// Hourly on-demand price (USD, us-east-1).
    pub hourly: f64,
}

impl NodeType {
    /// `maxmemory` on the engine, in bytes.
    pub fn maxmemory(&self) -> u64 {
        (self.memory_gib * 1024.0 * 1024.0 * 1024.0) as u64
    }

    pub fn memory_mib(&self) -> u64 {
        (self.memory_gib * 1024.0) as u64
    }

    fn class(&self) -> &str {
        self.name.split('.').nth(1).unwrap_or_default()
    }
}

macro_rules! nt {
    ($n:literal, $c:literal, $m:literal, $p:literal) => {
        NodeType { name: $n, vcpus: $c, memory_gib: $m, hourly: $p }
    };
}

pub const NODE_TYPES: &[NodeType] = &[
    nt!("cache.t2.micro", 1, 0.555, 0.017),
    nt!("cache.t2.small", 1, 1.55, 0.034),
    nt!("cache.t2.medium", 2, 3.22, 0.068),
    nt!("cache.t3.micro", 2, 0.5, 0.017),
    nt!("cache.t3.small", 2, 1.37, 0.034),
    nt!("cache.t3.medium", 2, 3.09, 0.068),
    nt!("cache.t4g.micro", 2, 0.5, 0.016),
    nt!("cache.t4g.small", 2, 1.37, 0.032),
    nt!("cache.t4g.medium", 2, 3.09, 0.065),
    nt!("cache.m5.large", 2, 6.38, 0.156),
    nt!("cache.m5.xlarge", 4, 12.93, 0.311),
    nt!("cache.m5.2xlarge", 8, 26.04, 0.623),
    nt!("cache.m5.4xlarge", 16, 52.26, 1.245),
    nt!("cache.m6g.large", 2, 6.38, 0.149),
    nt!("cache.m6g.xlarge", 4, 12.93, 0.297),
    nt!("cache.m6g.2xlarge", 8, 26.04, 0.594),
    nt!("cache.m7g.large", 2, 6.38, 0.158),
    nt!("cache.m7g.xlarge", 4, 12.93, 0.315),
    nt!("cache.r5.large", 2, 13.07, 0.216),
    nt!("cache.r5.xlarge", 4, 26.32, 0.431),
    nt!("cache.r5.2xlarge", 8, 52.82, 0.862),
    nt!("cache.r6g.large", 2, 13.07, 0.206),
    nt!("cache.r6g.xlarge", 4, 26.32, 0.411),
    nt!("cache.r6g.2xlarge", 8, 52.82, 0.822),
    nt!("cache.r6gd.xlarge", 4, 26.32, 0.781),
    nt!("cache.r6gd.2xlarge", 8, 52.82, 1.562),
    nt!("cache.r7g.large", 2, 13.07, 0.219),
    nt!("cache.r7g.xlarge", 4, 26.32, 0.437),
    nt!("cache.r7g.2xlarge", 8, 52.82, 0.873),
];

pub fn node_type(name: &str) -> Option<&'static NodeType> {
    NODE_TYPES.iter().find(|n| n.name == name)
}

/// Node types `from` can scale to: bigger ones (up) and smaller ones that
/// still exist in the same generation family (down).
pub fn scaling(from: &str) -> (Vec<String>, Vec<String>) {
    let Some(cur) = node_type(from) else { return (vec![], vec![]) };
    let data_tiering = cur.class().ends_with("gd");
    let mut up = Vec::new();
    let mut down = Vec::new();
    for n in NODE_TYPES {
        if n.name == cur.name || n.class().ends_with("gd") != data_tiering {
            continue;
        }
        if n.memory_gib > cur.memory_gib {
            up.push(n.name.to_string());
        } else if n.memory_gib < cur.memory_gib {
            down.push(n.name.to_string());
        }
    }
    (up, down)
}

pub fn supports_data_tiering(node_type: &str) -> bool {
    node_type.split('.').nth(1).is_some_and(|c| c.ends_with("gd"))
}

/// A parameter of a family.
pub struct Param {
    pub name: &'static str,
    pub default: &'static str,
    pub data_type: &'static str,
    pub allowed: &'static str,
    pub modifiable: bool,
    /// `immediate` or `requires-reboot`.
    pub change_type: &'static str,
    pub min_version: &'static str,
    pub description: &'static str,
    /// Whether the engine has a config of the same name MWS can set.
    pub engine: bool,
}

macro_rules! p {
    ($n:literal, $d:literal, $t:literal, $a:literal, $m:literal, $c:literal, $v:literal, $e:literal, $desc:literal) => {
        Param {
            name: $n,
            default: $d,
            data_type: $t,
            allowed: $a,
            modifiable: $m,
            change_type: $c,
            min_version: $v,
            engine: $e,
            description: $desc,
        }
    };
}

const REDIS_PARAMS: &[Param] = &[
    p!("acllog-max-len", "128", "integer", "1-10000", true, "immediate", "6.0.0", true, "The maximum number of entries in the ACL log."),
    p!("activedefrag", "no", "string", "yes,no", true, "immediate", "4.0.9", false, "Enabled active memory defragmentation"),
    p!("activerehashing", "yes", "string", "yes,no", true, "requires-reboot", "2.6.13", true, "Apply rehashing or not."),
    p!("appendfsync", "everysec", "string", "always,everysec,no", true, "immediate", "2.6.13", false, "fsync policy for AOF persistence"),
    p!("appendonly", "no", "string", "yes,no", true, "immediate", "2.6.13", false, "Enable Redis persistence."),
    p!("client-output-buffer-limit-normal-hard-limit", "0", "integer", "0-", true, "immediate", "2.6.13", false, "Normal client output buffer hard limit in bytes."),
    p!("client-output-buffer-limit-normal-soft-limit", "0", "integer", "0-", true, "immediate", "2.6.13", false, "Normal client output buffer soft limit in bytes."),
    p!("client-output-buffer-limit-normal-soft-seconds", "0", "integer", "0-", true, "immediate", "2.6.13", false, "Normal client output buffer soft limit in seconds."),
    p!("client-output-buffer-limit-pubsub-hard-limit", "33554432", "integer", "0-", true, "immediate", "2.6.13", false, "Pubsub client output buffer hard limit in bytes."),
    p!("client-output-buffer-limit-pubsub-soft-limit", "8388608", "integer", "0-", true, "immediate", "2.6.13", false, "Pubsub client output buffer soft limit in bytes."),
    p!("client-output-buffer-limit-pubsub-soft-seconds", "60", "integer", "0-", true, "immediate", "2.6.13", false, "Pubsub client output buffer soft limit in seconds."),
    p!("client-query-buffer-limit", "1073741824", "integer", "1048576-1073741824", true, "immediate", "4.0.10", true, "Max size of a single client query buffer"),
    p!("close-on-replica-write", "yes", "string", "yes,no", true, "immediate", "2.8.23", false, "If enabled, clients who attempt to write to a read-only replica will be disconnected. Applicable to 2.8.23 and higher."),
    p!("cluster-allow-reads-when-down", "no", "string", "yes,no", true, "immediate", "6.0.0", true, "Allow reads when the cluster is down"),
    p!("cluster-enabled", "no", "string", "yes,no", false, "requires-reboot", "3.2.4", false, "Enable cluster mode"),
    p!("cluster-require-full-coverage", "no", "string", "yes,no", true, "immediate", "3.2.4", true, "Whether cluster becomes unavailable if one or more slots are not covered"),
    p!("databases", "16", "integer", "1-1200000", true, "requires-reboot", "2.6.13", false, "Set the number of databases."),
    p!("hash-max-listpack-entries", "128", "integer", "0-", true, "immediate", "7.0.0", true, "The maximum number of hash entries in order for the dataset to be compressed."),
    p!("hash-max-listpack-value", "64", "integer", "0-", true, "immediate", "7.0.0", true, "The threshold of biggest hash entries in order for the dataset to be compressed."),
    p!("hll-sparse-max-bytes", "3000", "integer", "0-16000", true, "immediate", "2.8.9", true, "HyperLogLog sparse representation bytes limit"),
    p!("latency-tracking", "yes", "string", "yes,no", true, "immediate", "7.0.0", true, "Enable latency tracking"),
    p!("lazyfree-lazy-eviction", "no", "string", "yes,no", true, "immediate", "4.0.10", true, "Perform an asynchronous delete on evictions"),
    p!("lazyfree-lazy-expire", "no", "string", "yes,no", true, "immediate", "4.0.10", true, "Perform an asynchronous delete on expired keys"),
    p!("lazyfree-lazy-server-del", "no", "string", "yes,no", true, "immediate", "4.0.10", true, "Perform an asynchronous delete on key updates"),
    p!("lazyfree-lazy-user-del", "no", "string", "yes,no", true, "immediate", "6.0.0", true, "Specifies whether the default behavior of DEL command acts the same as UNLINK"),
    p!("lazyfree-lazy-user-flush", "no", "string", "yes,no", true, "immediate", "7.0.0", true, "Specifies whether the default behavior of FLUSHDB and FLUSHALL is ASYNC"),
    p!("lfu-decay-time", "1", "integer", "0-", true, "immediate", "4.0.10", true, "The amount of time in minutes to decrement the key counter for LFU eviction policy"),
    p!("lfu-log-factor", "10", "integer", "1-", true, "immediate", "4.0.10", true, "The log factor for incrementing key counter for LFU eviction policy"),
    p!("list-compress-depth", "0", "integer", "0-", true, "immediate", "3.2.4", true, "Number of quicklist ziplist nodes from each side of the list to exclude from compression. The head and tail of the list are always uncompressed for fast push/pop operations"),
    p!("list-max-listpack-size", "-2", "integer", "-5,-4,-3,-2,-1,1-", true, "immediate", "7.0.0", true, "The number of entries allowed per internal list node can be specified as a fixed maximum size or a maximum number of elements"),
    p!("lua-replicate-commands", "yes", "string", "yes,no", true, "immediate", "3.2.4", false, "Always enable Lua effect replication or not"),
    p!("lua-time-limit", "5000", "integer", "5000", false, "immediate", "2.6.13", false, "Max execution time of a Lua script in milliseconds. 0 or negative for unlimited execution without warnings."),
    p!("maxclients", "65000", "integer", "1-65000", false, "requires-reboot", "2.6.13", false, "The maximum number of Redis clients."),
    p!("maxmemory-policy", "volatile-lru", "string", "volatile-lru,allkeys-lru,volatile-lfu,allkeys-lfu,volatile-random,allkeys-random,volatile-ttl,noeviction", true, "immediate", "2.6.13", true, "Max memory policy."),
    p!("maxmemory-samples", "3", "integer", "1-", true, "immediate", "2.6.13", true, "Max memory samples."),
    p!("min-replicas-max-lag", "10", "integer", "0-", true, "immediate", "2.8.23", true, "The maximum amount of replica lag in seconds beyond which the master would stop taking writes. A value of 0 means the master always takes writes."),
    p!("min-replicas-to-write", "0", "integer", "0-", true, "immediate", "2.8.23", true, "Number of replicas that must be connected in order for master to take writes."),
    p!("notify-keyspace-events", "", "string", "", true, "immediate", "2.8.6", true, "The keyspace events for Redis to notify Pub/Sub clients about. By default all notifications are disabled"),
    p!("proto-max-bulk-len", "536870912", "integer", "1048576-536870912", true, "immediate", "4.0.10", true, "Max size of a single element request"),
    p!("rename-commands", "", "string", "", true, "immediate", "2.8.23", false, "Redis commands that can be dynamically renamed by the customer"),
    p!("repl-backlog-size", "1048576", "integer", "16384-", true, "immediate", "2.8.23", true, "The replication backlog size in bytes for PSYNC. This is the size of the buffer which accumulates writes while replicas are disconnected for some time, so that when replicas reconnect again, only transfer the portion of data which the replicas missed. Minimum value is 16K."),
    p!("repl-backlog-ttl", "3600", "integer", "0-", true, "immediate", "2.8.23", true, "The amount of time in seconds after the master no longer have any replicas connected for the master to free the replication backlog. A value of 0 means to never release the backlog."),
    p!("replica-allow-chaining", "no", "string", "yes,no", false, "immediate", "2.8.23", false, "Configures if chaining of replicas is allowed"),
    p!("replica-ignore-maxmemory", "yes", "string", "yes,no", false, "immediate", "5.0.0", true, "Determines whether replica ignores maxmemory setting by not evicting items independent from the master"),
    p!("replica-lazy-flush", "yes", "string", "yes,no", false, "immediate", "5.0.0", true, "Perform an asynchronous flushDB during replica sync"),
    p!("reserved-memory-percent", "25", "integer", "0-100", true, "immediate", "2.8.22", false, "The percent of memory reserved for non-cache memory usage. You may want to increase this parameter for nodes with read replicas, AOF enabled, etc, to reduce swap usage."),
    p!("set-max-intset-entries", "512", "integer", "0-", true, "immediate", "2.6.13", true, "The limit in the size of the set in order for the dataset to be compressed."),
    p!("slowlog-log-slower-than", "10000", "integer", "-", true, "immediate", "2.6.13", true, "The execution time, in microseconds, to exceed in order for the command to get logged. Note that a negative number disables the slow log, while a value of zero forces the logging of every command."),
    p!("slowlog-max-len", "128", "integer", "0-", true, "immediate", "2.6.13", true, "The length of the slow log. There is no limit to this length. Just be aware that it will consume memory. You can reclaim memory used by the slow log with SLOWLOG RESET."),
    p!("stream-node-max-bytes", "4096", "integer", "0-", true, "immediate", "5.0.0", true, "The maximum size of a single node in a stream in bytes"),
    p!("stream-node-max-entries", "100", "integer", "0-", true, "immediate", "5.0.0", true, "The maximum number of items a single node in a stream can contain"),
    p!("tcp-keepalive", "300", "integer", "0-", true, "immediate", "2.6.13", true, "If non-zero, send ACKs every given number of seconds."),
    p!("timeout", "0", "integer", "0,20-", true, "immediate", "2.6.13", true, "Close connection if client is idle for a given number of seconds, or never if 0."),
    p!("zset-max-listpack-entries", "128", "integer", "0-", true, "immediate", "7.0.0", true, "The maximum number of sorted set entries in order for the dataset to be compressed."),
    p!("zset-max-listpack-value", "64", "integer", "0-", true, "immediate", "7.0.0", true, "The threshold of biggest sorted set entries in order for the dataset to be compressed."),
];

const MEMCACHED_PARAMS: &[Param] = &[
    p!("backlog_queue_limit", "1024", "integer", "1-10000", false, "requires-reboot", "1.4.5", false, "The backlog queue limit."),
    p!("binding_protocol", "auto", "string", "ascii,auto", true, "requires-reboot", "1.4.5", false, "Binding protocol."),
    p!("cas_disabled", "0", "boolean", "0,1", true, "requires-reboot", "1.4.5", false, "If true (1), disable check and set (CAS) operations."),
    p!("chunk_size", "48", "integer", "1-", true, "requires-reboot", "1.4.5", false, "The minimum amount, in bytes, of space to allocate for the smallest item's key, value, and flags."),
    p!("chunk_size_growth_factor", "1.25", "float", "1-2", true, "requires-reboot", "1.4.5", false, "The growth factor that controls the size of each successive memcached chunk - each chunk will be chunk_size_growth_factor times larger than the previous chunk."),
    p!("error_on_memory_exhausted", "0", "boolean", "0,1", true, "requires-reboot", "1.4.5", false, "If true (1), when there is no more memory to store items, memcached will return an error rather than evicting items."),
    p!("large_memory_pages", "0", "boolean", "0,1", false, "requires-reboot", "1.4.5", false, "If true (1), try to use large memory pages."),
    p!("lock_down_paged_memory", "0", "boolean", "0,1", false, "requires-reboot", "1.4.5", false, "If true (1), lock down all paged memory."),
    p!("max_item_size", "1048576", "integer", "1048576-134217728", true, "requires-reboot", "1.4.5", false, "The size of the largest item storable in the cache, in bytes."),
    p!("max_simultaneous_connections", "65000", "integer", "3-65000", false, "requires-reboot", "1.4.5", false, "The maximum number of simultaneous connections."),
    p!("maximize_core_file_limit", "0", "boolean", "0,1", false, "requires-reboot", "1.4.5", false, "If true (1), maximize the core file limit."),
    p!("memcached_connections_overhead", "100", "integer", "0-", true, "requires-reboot", "1.4.5", false, "The amount of memory to be reserved for memcached connections and other miscellaneous overhead."),
    p!("requests_per_event", "20", "integer", "1-", false, "requires-reboot", "1.4.5", false, "The maximum number of requests per event for a given connection."),
];

/// The parameters of a family (cluster-mode groups set `cluster-enabled`).
pub fn parameters(family: &str) -> Vec<(&'static Param, String)> {
    let Some(engine) = family_engine(family) else { return vec![] };
    let list = if engine.is_redis_like() { REDIS_PARAMS } else { MEMCACHED_PARAMS };
    let seven = matches!(family, "redis7" | "valkey7" | "valkey8");
    list.iter()
        .filter(|p| seven || !matches!(p.min_version, "7.0.0"))
        .filter(|p| family != "redis4.0" || !matches!(p.min_version, "5.0.0" | "6.0.0"))
        .filter(|p| !matches!(family, "redis5.0") || p.min_version != "6.0.0")
        .map(|p| (p, p.default.to_string()))
        .collect()
}

pub fn parameter(family: &str, name: &str) -> Option<&'static Param> {
    parameters(family).into_iter().map(|(p, _)| p).find(|p| p.name == name)
}

pub fn to_wire(p: &Param, value: &str, source: &str) -> t::Parameter {
    t::Parameter {
        parameter_name: Some(p.name.to_string()),
        parameter_value: Some(value.to_string()),
        description: Some(p.description.to_string()),
        source: Some(source.to_string()),
        data_type: Some(p.data_type.to_string()),
        allowed_values: (!p.allowed.is_empty()).then(|| p.allowed.to_string()),
        is_modifiable: Some(p.modifiable),
        minimum_engine_version: Some(p.min_version.to_string()),
        change_type: Some(p.change_type.to_string()),
    }
}

/// Whether `value` is allowed for `p` (AWS checks ranges and enums).
pub fn value_allowed(p: &Param, value: &str) -> bool {
    if p.allowed.is_empty() || p.allowed == "-" {
        return true;
    }
    match p.data_type {
        "integer" | "float" => {
            let Ok(v) = value.parse::<f64>() else { return false };
            p.allowed.split(',').any(|part| match part.split_once('-') {
                Some((lo, hi)) if !lo.is_empty() || !hi.is_empty() => {
                    let lo = if lo.is_empty() { f64::MIN } else { lo.parse().unwrap_or(f64::MIN) };
                    let hi = if hi.is_empty() { f64::MAX } else { hi.parse().unwrap_or(f64::MAX) };
                    v >= lo && v <= hi
                }
                _ => part.parse::<f64>().is_ok_and(|x| x == v),
            })
        }
        _ => {
            // Comma separated enums (`yes,no`) or free text.
            if p.name == "maxmemory-policy" || p.allowed.contains(',') {
                p.allowed.split(',').any(|a| a == value)
            } else {
                true
            }
        }
    }
}

/// `maxmemory` per node type, as DescribeCacheParameters lists it.
pub fn node_type_specific(engine: EngineKind) -> Vec<t::CacheNodeTypeSpecificParameter> {
    let name = if engine.is_redis_like() { "maxmemory" } else { "max_cache_memory" };
    vec![t::CacheNodeTypeSpecificParameter {
        parameter_name: Some(name.into()),
        description: Some("The maximum configurable amount of memory to use to store items, in megabytes.".into()),
        source: Some("system".into()),
        data_type: Some("integer".into()),
        allowed_values: None,
        is_modifiable: Some(false),
        minimum_engine_version: Some(if engine.is_redis_like() { "2.6.13" } else { "1.4.5" }.into()),
        cache_node_type_specific_values: Some(
            NODE_TYPES
                .iter()
                .map(|n| t::CacheNodeTypeSpecificValue {
                    cache_node_type: Some(n.name.into()),
                    value: Some(if engine.is_redis_like() {
                        n.maxmemory().to_string()
                    } else {
                        n.memory_mib().to_string()
                    }),
                })
                .collect(),
        ),
        change_type: Some("immediate".into()),
    }]
}

// ---- reserved nodes -------------------------------------------------------

pub const OFFERING_TYPES: &[&str] = &["No Upfront", "Partial Upfront", "All Upfront"];
pub const DURATIONS: &[i32] = &[31_536_000, 94_608_000];
pub const PRODUCTS: &[&str] = &["redis", "memcached", "valkey"];

/// Every reserved node offering, with a stable id per combination.
pub fn offerings() -> Vec<t::ReservedCacheNodesOffering> {
    let mut out = Vec::new();
    for n in NODE_TYPES {
        for &duration in DURATIONS {
            for &kind in OFFERING_TYPES {
                for &product in PRODUCTS {
                    let years = if duration == DURATIONS[0] { 1.0 } else { 3.0 };
                    let discount = match kind {
                        "No Upfront" => 0.70,
                        "Partial Upfront" => 0.62,
                        _ => 0.60,
                    } - if years > 1.0 { 0.15 } else { 0.0 };
                    let total = n.hourly * discount * 8760.0 * years * if product == "valkey" { 0.8 } else { 1.0 };
                    let hours = 8760.0 * years;
                    let (fixed, recurring) = match kind {
                        "No Upfront" => (0.0, total / hours),
                        "Partial Upfront" => (total / 2.0, total / 2.0 / hours),
                        _ => (total, 0.0),
                    };
                    let round = |x: f64| (x * 1000.0).round() / 1000.0;
                    out.push(t::ReservedCacheNodesOffering {
                        reserved_cache_nodes_offering_id: Some(offering_id(n.name, duration, kind, product)),
                        cache_node_type: Some(n.name.into()),
                        duration: Some(duration),
                        fixed_price: Some(round(fixed)),
                        usage_price: Some(0.0),
                        product_description: Some(product.into()),
                        offering_type: Some(kind.into()),
                        recurring_charges: Some(vec![t::RecurringCharge {
                            recurring_charge_amount: Some(round(recurring)),
                            recurring_charge_frequency: Some("Hourly".into()),
                        }]),
                    });
                }
            }
        }
    }
    out
}

fn offering_id(node: &str, duration: i32, kind: &str, product: &str) -> String {
    use sha2::Digest;
    let h = sha2::Sha256::digest(format!("{node}/{duration}/{kind}/{product}").as_bytes());
    let x = hex::encode(&h[..16]);
    format!("{}-{}-{}-{}-{}", &x[0..8], &x[8..12], &x[12..16], &x[16..20], &x[20..32])
}

// ---- service updates --------------------------------------------------------

pub struct ServiceUpdate {
    pub name: &'static str,
    pub engine: EngineKind,
    pub engine_version: &'static str,
    pub severity: &'static str,
    pub kind: &'static str,
    pub description: &'static str,
    pub released: &'static str,
    pub recommended_by: &'static str,
}

pub const SERVICE_UPDATES: &[ServiceUpdate] = &[
    ServiceUpdate {
        name: "elc-20250312-001",
        engine: EngineKind::Redis,
        engine_version: "7.1.0",
        severity: "important",
        kind: "security-update",
        description: "Upgrade to the latest Redis OSS 7.1 engine patch, with security fixes",
        released: "2025-03-12T00:00:00Z",
        recommended_by: "2025-04-12T00:00:00Z",
    },
    ServiceUpdate {
        name: "elc-20250312-002",
        engine: EngineKind::Valkey,
        engine_version: "8.0.1",
        severity: "important",
        kind: "security-update",
        description: "Upgrade to the latest Valkey 8.0 engine patch, with security fixes",
        released: "2025-03-12T00:00:00Z",
        recommended_by: "2025-04-12T00:00:00Z",
    },
];

pub fn service_update(name: &str) -> Option<&'static ServiceUpdate> {
    SERVICE_UPDATES.iter().find(|u| u.name == name)
}

pub fn parse_time(s: &str) -> chrono::DateTime<chrono::Utc> {
    s.parse().unwrap_or_default()
}

/// Availability zones of a Region (`us-east-1a` ...).
pub fn zones(region: &str) -> Vec<String> {
    ["a", "b", "c", "d", "e", "f"]
        .iter()
        .take(if region == "us-east-1" { 6 } else { 3 })
        .map(|z| format!("{region}{z}"))
        .collect()
}
