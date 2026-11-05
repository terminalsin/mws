//! What RDS offers: engines and their versions, parameter group families
//! with their default parameters, instance classes, and the CA
//! certificates instances present.

use crate::generated::types as t;

/// The database software family behind an engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Postgres,
    Mysql,
    Mariadb,
}

#[derive(Debug, Clone, Copy)]
pub struct Engine {
    pub name: &'static str,
    pub description: &'static str,
    pub kind: Kind,
    pub aurora: bool,
    pub default_port: i32,
    pub license: &'static str,
    /// Newest last; the last one is the default.
    pub versions: &'static [Version],
    pub log_types: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct Version {
    pub version: &'static str,
    pub major: &'static str,
    pub family: &'static str,
    /// The container image the Docker backend runs.
    pub image: &'static str,
    pub description: &'static str,
}

const PG_LOGS: &[&str] = &["postgresql", "upgrade"];
const MYSQL_LOGS: &[&str] = &["audit", "error", "general", "slowquery"];
const AURORA_PG_LOGS: &[&str] = &["instance", "postgresql"];
const AURORA_MYSQL_LOGS: &[&str] = &["audit", "error", "general", "instance", "slowquery"];

macro_rules! v {
    ($version:expr, $major:expr, $family:expr, $image:expr, $desc:expr) => {
        Version { version: $version, major: $major, family: $family, image: $image, description: $desc }
    };
}

pub const ENGINES: &[Engine] = &[
    Engine {
        name: "postgres",
        description: "PostgreSQL",
        kind: Kind::Postgres,
        aurora: false,
        default_port: 5432,
        license: "postgresql-license",
        versions: &[
            v!("13.20", "13", "postgres13", "postgres:13-alpine", "PostgreSQL 13.20-R1"),
            v!("14.17", "14", "postgres14", "postgres:14-alpine", "PostgreSQL 14.17-R1"),
            v!("15.12", "15", "postgres15", "postgres:15-alpine", "PostgreSQL 15.12-R1"),
            v!("16.8", "16", "postgres16", "postgres:16-alpine", "PostgreSQL 16.8-R1"),
            v!("17.4", "17", "postgres17", "postgres:17-alpine", "PostgreSQL 17.4-R1"),
        ],
        log_types: PG_LOGS,
    },
    Engine {
        name: "mysql",
        description: "MySQL Community Edition",
        kind: Kind::Mysql,
        aurora: false,
        default_port: 3306,
        license: "general-public-license",
        versions: &[
            v!("8.0.41", "8.0", "mysql8.0", "mysql:8.0", "MySQL 8.0.41"),
            v!("8.4.4", "8.4", "mysql8.4", "mysql:8.4", "MySQL 8.4.4"),
        ],
        log_types: MYSQL_LOGS,
    },
    Engine {
        name: "mariadb",
        description: "MariaDB Community Edition",
        kind: Kind::Mariadb,
        aurora: false,
        default_port: 3306,
        license: "general-public-license",
        versions: &[
            v!("10.11.11", "10.11", "mariadb10.11", "mariadb:10.11", "MariaDB 10.11.11"),
            v!("11.4.5", "11.4", "mariadb11.4", "mariadb:11.4", "MariaDB 11.4.5"),
        ],
        log_types: MYSQL_LOGS,
    },
    Engine {
        name: "aurora-postgresql",
        description: "Aurora (PostgreSQL)",
        kind: Kind::Postgres,
        aurora: true,
        default_port: 5432,
        license: "postgresql-license",
        versions: &[
            v!(
                "13.20",
                "13",
                "aurora-postgresql13",
                "postgres:13-alpine",
                "Aurora PostgreSQL (Compatible with PostgreSQL 13.20)"
            ),
            v!(
                "14.17",
                "14",
                "aurora-postgresql14",
                "postgres:14-alpine",
                "Aurora PostgreSQL (Compatible with PostgreSQL 14.17)"
            ),
            v!(
                "15.12",
                "15",
                "aurora-postgresql15",
                "postgres:15-alpine",
                "Aurora PostgreSQL (Compatible with PostgreSQL 15.12)"
            ),
            v!(
                "16.8",
                "16",
                "aurora-postgresql16",
                "postgres:16-alpine",
                "Aurora PostgreSQL (Compatible with PostgreSQL 16.8)"
            ),
            v!(
                "17.4",
                "17",
                "aurora-postgresql17",
                "postgres:17-alpine",
                "Aurora PostgreSQL (Compatible with PostgreSQL 17.4)"
            ),
        ],
        log_types: AURORA_PG_LOGS,
    },
    Engine {
        name: "aurora-mysql",
        description: "Aurora MySQL",
        kind: Kind::Mysql,
        aurora: true,
        default_port: 3306,
        license: "general-public-license",
        versions: &[
            v!(
                "8.0.mysql_aurora.3.04.3",
                "8.0",
                "aurora-mysql8.0",
                "mysql:8.0",
                "Aurora MySQL 3.04.3 (compatible with MySQL 8.0.28)"
            ),
            v!(
                "8.0.mysql_aurora.3.08.1",
                "8.0",
                "aurora-mysql8.0",
                "mysql:8.0",
                "Aurora MySQL 3.08.1 (compatible with MySQL 8.0.39)"
            ),
        ],
        log_types: AURORA_MYSQL_LOGS,
    },
];

pub fn engine(name: &str) -> Option<&'static Engine> {
    ENGINES.iter().find(|e| e.name == name)
}

impl Engine {
    pub fn default_version(&self) -> &'static Version {
        self.versions.last().expect("every engine has versions")
    }

    /// `16`, `16.8` or the full version; a major version picks its newest
    /// minor.
    pub fn version(&self, wanted: &str) -> Option<&'static Version> {
        self.versions
            .iter()
            .find(|v| v.version == wanted)
            .or_else(|| self.versions.iter().rev().find(|v| v.major == wanted))
            .or_else(|| self.versions.iter().rev().find(|v| v.version.starts_with(&format!("{wanted}."))))
    }

    /// The default option group's name (`default:postgres-16`).
    pub fn default_option_group(&self, v: &Version) -> String {
        format!("default:{}-{}", self.name, v.major.replace('.', "-"))
    }

    /// The default (cluster) parameter group of a family.
    pub fn default_parameter_group(&self, v: &Version) -> String {
        format!("default.{}", v.family)
    }

    pub fn character_set(&self) -> Option<&'static str> {
        match self.kind {
            Kind::Postgres => Some("UTF8"),
            Kind::Mysql | Kind::Mariadb => Some("utf8mb4"),
        }
    }
}

/// The engine of a parameter group family (`postgres16` is `postgres`).
pub fn family(family: &str) -> Option<(&'static Engine, &'static Version)> {
    ENGINES.iter().find_map(|e| e.versions.iter().rev().find(|v| v.family == family).map(|v| (e, v)))
}

pub fn engine_version(e: &Engine, v: &Version) -> t::DBEngineVersion {
    let newer: Vec<t::UpgradeTarget> = e
        .versions
        .iter()
        .skip_while(|x| x.version != v.version)
        .skip(1)
        .map(|x| t::UpgradeTarget {
            engine: Some(e.name.into()),
            engine_version: Some(x.version.into()),
            description: Some(x.description.into()),
            auto_upgrade: Some(false),
            is_major_version_upgrade: Some(x.major != v.major),
            supports_global_databases: Some(e.aurora),
            ..Default::default()
        })
        .collect();
    t::DBEngineVersion {
        engine: Some(e.name.into()),
        engine_version: Some(v.version.into()),
        major_engine_version: Some(v.major.into()),
        db_parameter_group_family: Some(v.family.into()),
        db_engine_description: Some(e.description.into()),
        db_engine_version_description: Some(v.description.into()),
        default_character_set: e
            .character_set()
            .map(|c| t::CharacterSet { character_set_name: Some(c.into()), character_set_description: Some(c.into()) }),
        valid_upgrade_target: Some(newer),
        exportable_log_types: Some(e.log_types.iter().map(|s| s.to_string()).collect()),
        supports_log_exports_to_cloudwatch_logs: Some(true),
        supports_read_replica: Some(true),
        supported_engine_modes: Some(vec!["provisioned".into()]),
        supported_feature_names: Some(Vec::new()),
        status: Some("available".into()),
        supports_parallel_query: Some(false),
        supports_global_databases: Some(e.aurora),
        supports_babelfish: Some(false),
        supports_limitless_database: Some(false),
        supports_certificate_rotation_without_restart: Some(true),
        supported_ca_certificate_identifiers: Some(CERTIFICATES.iter().map(|c| c.0.to_string()).collect()),
        supports_local_write_forwarding: Some(false),
        supports_integrations: Some(false),
        tag_list: Some(Vec::new()),
        ..Default::default()
    }
}

// ---- instance classes ------------------------------------------------------

/// (class, vCPUs, memory GiB)
pub const CLASSES: &[(&str, u32, f64)] = &[
    ("db.t3.micro", 2, 1.0),
    ("db.t3.small", 2, 2.0),
    ("db.t3.medium", 2, 4.0),
    ("db.t3.large", 2, 8.0),
    ("db.t4g.micro", 2, 1.0),
    ("db.t4g.small", 2, 2.0),
    ("db.t4g.medium", 2, 4.0),
    ("db.t4g.large", 2, 8.0),
    ("db.m5.large", 2, 8.0),
    ("db.m5.xlarge", 4, 16.0),
    ("db.m5.2xlarge", 8, 32.0),
    ("db.m6g.large", 2, 8.0),
    ("db.m6g.xlarge", 4, 16.0),
    ("db.m6i.large", 2, 8.0),
    ("db.m7g.large", 2, 8.0),
    ("db.m7g.xlarge", 4, 16.0),
    ("db.r5.large", 2, 16.0),
    ("db.r5.xlarge", 4, 32.0),
    ("db.r6g.large", 2, 16.0),
    ("db.r6g.xlarge", 4, 32.0),
    ("db.r6i.large", 2, 16.0),
    ("db.r7g.large", 2, 16.0),
    ("db.r7g.xlarge", 4, 32.0),
    ("db.r7g.2xlarge", 8, 64.0),
    ("db.serverless", 0, 0.0),
];

/// Whether `class` is offered for `engine` (Aurora has no micro or small
/// burstable classes; only Aurora is serverless).
pub fn class_supported(engine: &Engine, class: &str) -> bool {
    if !CLASSES.iter().any(|c| c.0 == class) {
        return false;
    }
    if engine.aurora {
        !class.ends_with(".micro") && !class.ends_with(".small")
    } else {
        class != "db.serverless"
    }
}

/// Memory for the container running a class (MiB), at least 256.
pub fn memory_mib(class: &str) -> u64 {
    CLASSES.iter().find(|c| c.0 == class).map(|c| (c.2 * 1024.0) as u64).filter(|m| *m > 0).unwrap_or(1024).max(256)
}

pub fn storage_range(engine: &Engine, storage_type: &str) -> (i32, i32) {
    match (engine.kind, storage_type) {
        (_, "standard") => (5, 3072),
        (_, "io1" | "io2") => (100, 65536),
        (_, _) => (20, 65536),
    }
}

// ---- CA certificates ---------------------------------------------------------

/// (identifier, type, valid from, valid till)
pub const CERTIFICATES: &[(&str, &str, &str, &str)] = &[
    ("rds-ca-ecc384-g1", "CA", "2021-05-25T22:41:55Z", "2121-05-25T23:41:55Z"),
    ("rds-ca-rsa2048-g1", "CA", "2021-05-25T23:34:57Z", "2061-05-26T00:34:57Z"),
    ("rds-ca-rsa4096-g1", "CA", "2021-05-25T23:38:34Z", "2121-05-26T00:38:34Z"),
];

pub const DEFAULT_CERTIFICATE: &str = "rds-ca-rsa2048-g1";

pub fn certificate_valid_till(id: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    CERTIFICATES.iter().find(|c| c.0 == id).and_then(|c| c.3.parse().ok())
}

// ---- parameters --------------------------------------------------------------

/// A parameter RDS knows for a family. `native` parameters are passed to
/// the database server itself when MWS runs one.
#[derive(Debug, Clone, Copy)]
pub struct Param {
    pub name: &'static str,
    pub value: Option<&'static str>,
    pub description: &'static str,
    pub apply_type: &'static str,
    pub data_type: &'static str,
    pub allowed: Option<&'static str>,
    pub modifiable: bool,
    pub native: bool,
    /// Also a cluster-level parameter on Aurora.
    pub cluster: bool,
}

macro_rules! p {
    ($name:expr, $value:expr, $desc:expr, $apply:expr, $ty:expr, $allowed:expr, $native:expr, $cluster:expr) => {
        Param {
            name: $name,
            value: $value,
            description: $desc,
            apply_type: $apply,
            data_type: $ty,
            allowed: $allowed,
            modifiable: true,
            native: $native,
            cluster: $cluster,
        }
    };
}

const BOOL: Option<&str> = Some("0,1");

pub const POSTGRES_PARAMS: &[Param] = &[
    p!("application_name", None, "Sets the application name to be reported in statistics and logs.", "dynamic", "string", None, true, false),
    p!("autovacuum", Some("1"), "Starts the autovacuum subprocess.", "dynamic", "boolean", BOOL, true, true),
    p!("autovacuum_max_workers", Some("GREATEST({DBInstanceClassMemory/64371566592},3)"), "Sets the maximum number of simultaneously running autovacuum worker processes.", "static", "integer", Some("1-262143"), true, true),
    p!("client_encoding", Some("UTF8"), "Sets the clients character set encoding.", "dynamic", "string", None, true, true),
    p!("default_transaction_isolation", None, "Sets the transaction isolation level of each new transaction.", "dynamic", "string", Some("serializable,repeatable read,read committed,read uncommitted"), true, false),
    p!("effective_cache_size", Some("{DBInstanceClassMemory/16384}"), "Sets the planners assumption about the size of the disk cache.", "dynamic", "integer", Some("1-2147483647"), true, false),
    p!("idle_in_transaction_session_timeout", Some("86400000"), "Sets the maximum allowed duration of any idling transaction.", "dynamic", "integer", Some("0-2147483647"), true, false),
    p!("lock_timeout", None, "Sets the maximum allowed duration (in milliseconds) of any wait for a lock. 0 turns this off.", "dynamic", "integer", Some("0-2147483647"), true, false),
    p!("log_connections", None, "Logs each successful connection.", "dynamic", "boolean", BOOL, true, true),
    p!("log_disconnections", None, "Logs end of a session, including duration.", "dynamic", "boolean", BOOL, true, true),
    p!("log_min_duration_statement", None, "Sets the minimum execution time above which statements will be logged.", "dynamic", "integer", Some("-1-2147483647"), true, false),
    p!("log_min_messages", None, "Sets the message levels that are logged.", "dynamic", "string", Some("debug5,debug4,debug3,debug2,debug1,info,notice,warning,error,log,fatal,panic"), true, false),
    p!("log_statement", None, "Sets the type of statements logged.", "dynamic", "string", Some("none,ddl,mod,all"), true, false),
    p!("maintenance_work_mem", Some("GREATEST({DBInstanceClassMemory*1024/63963136},65536)"), "Sets the maximum memory to be used for maintenance operations.", "dynamic", "integer", Some("1024-2147483647"), true, false),
    p!("max_connections", Some("LEAST({DBInstanceClassMemory/9531392},5000)"), "Sets the maximum number of concurrent connections.", "static", "integer", Some("6-262143"), true, false),
    p!("max_locks_per_transaction", Some("64"), "Sets the maximum number of locks per transaction.", "static", "integer", Some("10-2147483647"), true, false),
    p!("max_wal_size", Some("2048"), "Sets the WAL size that triggers a checkpoint.", "dynamic", "integer", Some("2-2147483647"), true, false),
    p!("password_encryption", Some("scram-sha-256"), "Encrypt passwords.", "dynamic", "string", Some("md5,scram-sha-256"), true, true),
    p!("random_page_cost", None, "Sets the planners estimate of the cost of a nonsequentially fetched disk page.", "dynamic", "real", Some("0-2147483647"), true, false),
    p!("rds.force_ssl", Some("0"), "Force SSL connections.", "dynamic", "boolean", BOOL, false, true),
    p!("rds.logical_replication", Some("0"), "Enables logical decoding.", "static", "boolean", BOOL, false, true),
    p!("search_path", None, "Sets the schema search order for names that are not schema-qualified.", "dynamic", "string", None, true, false),
    p!("shared_buffers", Some("{DBInstanceClassMemory/32768}"), "Sets the number of shared memory buffers used by the server.", "static", "integer", Some("16-1073741823"), true, false),
    p!("shared_preload_libraries", Some("pg_stat_statements"), "Lists shared libraries to preload into server.", "static", "list", Some("auto_explain,orafce,pgaudit,pglogical,pg_bigm,pg_cron,pg_hint_plan,pg_prewarm,pg_similarity,pg_stat_statements,pg_tle,pg_transport,plprofiler"), true, true),
    p!("statement_timeout", None, "Sets the maximum allowed duration of any statement.", "dynamic", "integer", Some("0-2147483647"), true, false),
    p!("timezone", Some("UTC"), "Sets the time zone for displaying and interpreting time stamps.", "dynamic", "string", None, true, true),
    p!("track_activity_query_size", Some("4096"), "Sets the size reserved for pg_stat_activity.query, in bytes.", "static", "integer", Some("100-1048576"), true, false),
    p!("work_mem", None, "Sets the maximum memory to be used for query workspaces.", "dynamic", "integer", Some("64-2147483647"), true, false),
];

pub const MYSQL_PARAMS: &[Param] = &[
    p!("binlog_format", Some("ROW"), "Binary logging format.", "dynamic", "string", Some("ROW,STATEMENT,MIXED,OFF"), false, true),
    p!("character_set_server", None, "The server's default character set.", "dynamic", "string", Some("big5,dec8,cp850,hp8,koi8r,latin1,latin2,swe7,ascii,ujis,sjis,hebrew,tis620,euckr,koi8u,gb2312,greek,cp1250,gbk,latin5,armscii8,utf8,ucs2,cp866,keybcs2,macce,macroman,cp852,latin7,utf8mb4,cp1251,utf16,cp1256,cp1257,utf32,binary,geostd8,cp932,eucjpms"), true, true),
    p!("collation_server", None, "The server's default collation.", "dynamic", "string", None, true, true),
    p!("event_scheduler", None, "Indicates the status of the Event Scheduler", "dynamic", "string", Some("ON,OFF"), true, false),
    p!("general_log", None, "Whether the general query log is enabled", "dynamic", "boolean", BOOL, true, false),
    p!("innodb_buffer_pool_size", Some("{DBInstanceClassMemory*3/4}"), "The size in bytes of the memory buffer innodb uses to cache data and indexes of its tables", "dynamic", "integer", Some("5242880-9223372036854775807"), true, false),
    p!("innodb_lock_wait_timeout", Some("50"), "Timeout in seconds an innodb transaction may wait for a row lock before giving up", "dynamic", "integer", Some("1-1073741824"), true, false),
    p!("log_bin_trust_function_creators", Some("0"), "Enforces restrictions on stored functions / triggers - logging for replication.", "dynamic", "boolean", BOOL, true, false),
    p!("log_output", Some("TABLE"), "Controls where to store query logs", "dynamic", "string", Some("TABLE,FILE,NONE"), true, false),
    p!("long_query_time", None, "Defines what MySQL considers long queries", "dynamic", "float", Some("0-31536000"), true, false),
    p!("lower_case_table_names", None, "Affects how table names are stored and compared.", "static", "integer", Some("0,1"), false, true),
    p!("max_allowed_packet", Some("67108864"), "This value by default is small, to catch large (possibly incorrect) packets. Must be increased if using large BLOB columns or long strings. As big as largest BLOB.", "dynamic", "integer", Some("1024-1073741824"), true, false),
    p!("max_connections", Some("{DBInstanceClassMemory/12582880}"), "The number of simultaneous client connections allowed.", "dynamic", "integer", Some("1-100000"), true, false),
    p!("performance_schema", Some("0"), "Enables or disables the Performance Schema", "static", "boolean", BOOL, true, false),
    p!("require_secure_transport", Some("0"), "Whether client connections to the server are required to use some form of secure transport.", "dynamic", "boolean", BOOL, true, true),
    p!("server_audit_logging", Some("0"), "Enables or disables audit logging.", "dynamic", "boolean", BOOL, false, true),
    p!("slow_query_log", None, "Enable or disable the slow query log", "dynamic", "boolean", BOOL, true, false),
    p!("sql_mode", None, "Current SQL Server Mode.", "dynamic", "list", None, true, false),
    p!("time_zone", None, "The server time zone", "dynamic", "string", None, true, true),
    p!("transaction_isolation", None, "Sets the default transaction isolation level.", "dynamic", "string", Some("READ-UNCOMMITTED,READ-COMMITTED,REPEATABLE-READ,SERIALIZABLE"), true, false),
    p!("wait_timeout", None, "The number of seconds the server waits for activity on a noninteractive TCP/IP or UNIX File connection before closing it.", "dynamic", "integer", Some("1-31536000"), true, false),
];

pub fn params(kind: Kind) -> &'static [Param] {
    match kind {
        Kind::Postgres => POSTGRES_PARAMS,
        Kind::Mysql | Kind::Mariadb => MYSQL_PARAMS,
    }
}

/// The parameters of a family, for a (cluster) parameter group: on Aurora,
/// cluster groups hold the cluster-level parameters and instance groups the
/// rest; other engines put everything in instance groups.
pub fn family_params(family: &str, cluster: bool) -> Vec<Param> {
    let Some((engine, _)) = self::family(family) else { return Vec::new() };
    params(engine.kind).iter().filter(|p| !engine.aurora || p.cluster == cluster).copied().collect()
}

pub fn to_parameter(p: &Param, value: Option<String>, source: &str) -> t::Parameter {
    t::Parameter {
        parameter_name: Some(p.name.into()),
        parameter_value: value.or_else(|| p.value.map(String::from)),
        description: Some(p.description.into()),
        source: Some(source.into()),
        apply_type: Some(p.apply_type.into()),
        data_type: Some(p.data_type.into()),
        allowed_values: p.allowed.map(String::from),
        is_modifiable: Some(p.modifiable),
        apply_method: Some("pending-reboot".into()),
        ..Default::default()
    }
}

/// Event categories RDS publishes, by source type.
pub const EVENT_CATEGORIES: &[(&str, &[&str])] = &[
    (
        "db-instance",
        &[
            "availability",
            "backup",
            "configuration change",
            "creation",
            "deletion",
            "failover",
            "failure",
            "maintenance",
            "notification",
            "read replica",
            "recovery",
            "restoration",
            "security",
            "security patching",
        ],
    ),
    (
        "db-cluster",
        &[
            "configuration change",
            "creation",
            "deletion",
            "failover",
            "failure",
            "global-failover",
            "maintenance",
            "migration",
            "notification",
            "serverless",
        ],
    ),
    ("db-parameter-group", &["configuration change"]),
    ("db-security-group", &["configuration change", "failure"]),
    ("db-snapshot", &["backup", "creation", "deletion", "notification", "restoration"]),
    ("db-cluster-snapshot", &["backup", "notification"]),
    ("db-proxy", &["configuration change", "creation", "deletion"]),
    ("blue-green-deployment", &["creation", "deletion", "notification"]),
    ("custom-engine-version", &["creation", "deletion", "restoration"]),
];
