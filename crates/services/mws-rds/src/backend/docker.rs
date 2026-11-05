//! Databases as containers, driven through the Docker CLI (or anything that
//! speaks its command line, such as Podman).
//!
//! Each database gets a container `mws-rds-<name>` running the engine's
//! official image, with its data in a volume of the same name, and its
//! port published on the host (`127.0.0.1` by default) so clients connect
//! to the endpoint RDS reports. Stopping keeps the volume; starting and
//! rebooting recreate the container on it with the current parameter group
//! settings. Snapshots are copies of the volume, taken with the container
//! paused (crash consistent, as a storage snapshot is).

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use super::{BackendError, DatabaseBackend, DatabaseSpec, Kind, Listening, LogSource, TableData};

#[derive(Debug)]
pub struct DockerBackend {
    cli: String,
    /// Host address published ports bind to.
    bind: String,
}

fn container(name: &str) -> String {
    format!("mws-rds-{name}")
}

fn snapshot_volume(snapshot: &str) -> String {
    format!("mws-rds-snap-{snapshot}")
}

fn internal_port(kind: Kind) -> u16 {
    match kind {
        Kind::Postgres => 5432,
        Kind::Mysql | Kind::Mariadb => 3306,
    }
}

fn data_dir(kind: Kind) -> &'static str {
    match kind {
        Kind::Postgres => "/var/lib/postgresql/data",
        Kind::Mysql | Kind::Mariadb => "/var/lib/mysql",
    }
}

/// Where PostgreSQL archives WAL segments (in the data volume, beside
/// `PGDATA`).
const WAL_ARCHIVE: &str = "/var/lib/postgresql/data/wal-archive";

/// A string as one shell word.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The events of a MySQL binary log file: (offset, timestamp, type).
fn binlog_events(bytes: &[u8]) -> Vec<(u64, u32, u8)> {
    let mut out = Vec::new();
    if bytes.len() < 4 || &bytes[..4] != b"\xfebin" {
        return out;
    }
    let mut at = 4usize;
    while at + 19 <= bytes.len() {
        let ts = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let kind = bytes[at + 4];
        let size = u32::from_le_bytes(bytes[at + 9..at + 13].try_into().expect("4 bytes")) as usize;
        if size < 19 || at + size > bytes.len() {
            break;
        }
        out.push((at as u64, ts, kind));
        at += size;
    }
    out
}

fn sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''"))
}

impl DockerBackend {
    pub fn new(cli: impl Into<String>, bind: impl Into<String>) -> Self {
        Self { cli: cli.into(), bind: bind.into() }
    }

    /// Whether a daemon answers (blocking; used once at startup).
    pub fn daemon_available(&self) -> bool {
        std::process::Command::new(&self.cli)
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Wait while a snapshot has `container` paused (an exec into a paused
    /// container fails).
    async fn wait_unpaused(&self, container: &str) {
        for _ in 0..600 {
            let paused = Command::new(&self.cli)
                .args(["inspect", "--format", "{{.State.Paused}}", container])
                .stdin(Stdio::null())
                .output()
                .await
                .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "true");
            if !paused {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn run(&self, args: &[String]) -> Result<String, BackendError> {
        if args.first().is_some_and(|a| a == "exec") {
            if let Some(c) = args.iter().skip(1).find(|a| !a.starts_with('-')) {
                self.wait_unpaused(c).await;
            }
        }
        let out = Command::new(&self.cli)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(BackendError(format!(
                "{} {} failed: {}",
                self.cli,
                args.first().map(String::as_str).unwrap_or_default(),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    async fn run_strs(&self, args: &[&str]) -> Result<String, BackendError> {
        self.run(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).await
    }

    /// Run a database container on volume `name` (which already holds data
    /// or is empty, in which case the image initializes it).
    async fn run_container(&self, spec: &DatabaseSpec) -> Result<(), BackendError> {
        let name = container(&spec.name);
        let _ = self.run_strs(&["rm", "-f", &name]).await;
        let port = internal_port(spec.kind);
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            name.clone(),
            "--label".into(),
            format!("mws.rds.name={}", spec.name),
            "--label".into(),
            format!("mws.rds.identifier={}", spec.identifier),
            "--label".into(),
            format!("mws.rds.account={}", spec.account_id),
            "--label".into(),
            format!("mws.rds.region={}", spec.region),
            "--memory".into(),
            format!("{}m", spec.memory_mib.max(256)),
            "-v".into(),
            format!("{name}:{}", data_dir(spec.kind)),
            "-p".into(),
            format!("{}::{port}", self.bind),
        ];
        let mut env = |k: &str, v: &str| {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        };
        match spec.kind {
            Kind::Postgres => {
                env("POSTGRES_USER", &spec.master_username);
                env("POSTGRES_PASSWORD", &spec.master_password);
                env("POSTGRES_DB", spec.database_name.as_deref().unwrap_or("postgres"));
                // A subdirectory, so the volume root may hold other files.
                env("PGDATA", "/var/lib/postgresql/data/pgdata");
            }
            Kind::Mysql | Kind::Mariadb => {
                env("MYSQL_ROOT_PASSWORD", &spec.master_password);
                if spec.master_username != "root" {
                    env("MYSQL_USER", &spec.master_username);
                    env("MYSQL_PASSWORD", &spec.master_password);
                }
                if let Some(db) = &spec.database_name {
                    env("MYSQL_DATABASE", db);
                }
            }
        }
        args.push(spec.image.clone());
        // Keep the transaction log point-in-time restores replay: archived
        // WAL segments next to the data directory, or the binary log.
        match spec.kind {
            Kind::Postgres => {
                args.extend(["-c".into(), "archive_mode=on".into(), "-c".into()]);
                args.push(format!("archive_command=mkdir -p {WAL_ARCHIVE} && cp %p {WAL_ARCHIVE}/%f"));
            }
            Kind::Mysql | Kind::Mariadb => args.push("--log-bin=binlog".into()),
        }
        for (k, v) in &spec.parameters {
            match spec.kind {
                Kind::Postgres => {
                    args.push("-c".into());
                    args.push(format!("{k}={v}"));
                }
                Kind::Mysql | Kind::Mariadb => args.push(format!("--{}={v}", k.replace('_', "-"))),
            }
        }
        self.run(&args).await.map(drop)
    }

    /// Wait until the server accepts TCP connections inside the container
    /// (the images first initialize on a socket-only server).
    async fn wait_ready(&self, spec: &DatabaseSpec) -> Result<(), BackendError> {
        let name = container(&spec.name);
        let probe: Vec<String> = match spec.kind {
            Kind::Postgres => {
                ["exec", &name, "pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", &spec.master_username]
                    .map(String::from)
                    .to_vec()
            }
            Kind::Mysql => {
                ["exec", &name, "mysqladmin", "ping", "-h", "127.0.0.1", "--silent"].map(String::from).to_vec()
            }
            Kind::Mariadb => {
                ["exec", &name, "mariadb-admin", "ping", "-h", "127.0.0.1", "--silent"].map(String::from).to_vec()
            }
        };
        for _ in 0..600 {
            if self.run(&probe).await.is_ok() {
                // MySQL answers pings while still refusing logins during
                // its first start; check that the master user gets in.
                if spec.kind == Kind::Postgres || self.mysql(spec, &spec.master_password, "SELECT 1").await.is_ok() {
                    return Ok(());
                }
            }
            let state = self.run_strs(&["inspect", "--format", "{{.State.Status}}", &name]).await.unwrap_or_default();
            if state == "exited" || state == "dead" {
                let logs = self.logs(&spec.name).await.unwrap_or_default();
                let tail: Vec<&str> = logs.lines().rev().take(20).collect();
                return Err(BackendError(format!(
                    "the database container exited: {}",
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                )));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(BackendError("the database did not become ready within 5 minutes".into()))
    }

    async fn mysql(&self, spec: &DatabaseSpec, password: &str, sql: &str) -> Result<String, BackendError> {
        let client = if spec.kind == Kind::Mariadb { "mariadb" } else { "mysql" };
        let user = spec.master_username.clone();
        self.run(&[
            "exec".into(),
            container(&spec.name),
            client.into(),
            "-h".into(),
            "127.0.0.1".into(),
            "-u".into(),
            user,
            format!("-p{password}"),
            "-e".into(),
            sql.into(),
        ])
        .await
    }

    /// The host port the database is published on.
    async fn listening(&self, spec: &DatabaseSpec) -> Result<Listening, BackendError> {
        let out =
            self.run_strs(&["port", &container(&spec.name), &format!("{}/tcp", internal_port(spec.kind))]).await?;
        let line = out.lines().next().unwrap_or_default();
        let port = line
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or_else(|| BackendError(format!("no published port: {out}")))?;
        let host = match self.bind.as_str() {
            "0.0.0.0" | "" => "127.0.0.1".to_string(),
            h => h.to_string(),
        };
        Ok(Listening { host, port })
    }

    /// After a first start: give a MySQL master user what RDS grants it.
    async fn grant_master(&self, spec: &DatabaseSpec) -> Result<(), BackendError> {
        if spec.kind == Kind::Postgres || spec.master_username == "root" {
            return Ok(());
        }
        let client = if spec.kind == Kind::Mariadb { "mariadb" } else { "mysql" };
        let user = sql_literal(&spec.master_username);
        self.run(&[
            "exec".into(),
            container(&spec.name),
            client.into(),
            "-h".into(),
            "127.0.0.1".into(),
            "-u".into(),
            "root".into(),
            format!("-p{}", spec.master_password),
            "-e".into(),
            format!("GRANT ALL PRIVILEGES ON *.* TO {user}@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;"),
        ])
        .await
        .map(drop)
    }

    /// Run `script` with `sh` in a throwaway container of `image` with
    /// `mounts` (`volume:/path[:ro]`).
    async fn shell(&self, image: &str, mounts: &[&str], script: &str) -> Result<String, BackendError> {
        let mut args: Vec<String> = vec!["run".into(), "--rm".into(), "--network".into(), "none".into()];
        for m in mounts {
            args.push("-v".into());
            args.push(m.to_string());
        }
        args.extend(["--entrypoint".into(), "sh".into(), image.into(), "-c".into(), script.into()]);
        self.run(&args).await
    }

    /// Run SQL in a PostgreSQL container over its local socket (trusted
    /// inside the container), returning unaligned tuples.
    async fn psql(&self, container: &str, user: &str, sql: &str) -> Result<String, BackendError> {
        self.run(&[
            "exec".into(),
            container.into(),
            "psql".into(),
            "-v".into(),
            "ON_ERROR_STOP=1".into(),
            "-At".into(),
            "-U".into(),
            user.into(),
            "-d".into(),
            "postgres".into(),
            "-c".into(),
            sql.into(),
        ])
        .await
    }

    async fn running(&self, container: &str) -> bool {
        self.run_strs(&["inspect", "--format", "{{.State.Running}}", container]).await.unwrap_or_default() == "true"
    }

    /// The tail of a container's log, for errors.
    async fn log_tail(&self, container: &str) -> String {
        let out = Command::new(&self.cli)
            .args(["logs", "--tail", "15", container])
            .stdin(Stdio::null())
            .output()
            .await
            .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
            .unwrap_or_default();
        out.trim().to_string()
    }

    /// Roll a PostgreSQL copy forward: archive recovery with the source's
    /// WAL up to `until`, then promote.
    /// Run a query in one PostgreSQL database and return the single value.
    async fn psql_db(&self, container: &str, user: &str, db: &str, sql: &str) -> Result<String, BackendError> {
        self.run(&[
            "exec".into(),
            container.into(),
            "psql".into(),
            "-v".into(),
            "ON_ERROR_STOP=1".into(),
            "-At".into(),
            "-U".into(),
            user.into(),
            "-d".into(),
            db.into(),
            "-c".into(),
            sql.into(),
        ])
        .await
    }

    /// Run a MySQL query, returning raw tab-separated rows without headers.
    async fn mysql_rows(&self, spec: &DatabaseSpec, sql: &str) -> Result<Vec<Vec<String>>, BackendError> {
        let client = if spec.kind == Kind::Mariadb { "mariadb" } else { "mysql" };
        let out = self
            .run(&[
                "exec".into(),
                container(&spec.name),
                client.into(),
                "-h".into(),
                "127.0.0.1".into(),
                "-u".into(),
                spec.master_username.clone(),
                format!("-p{}", spec.master_password),
                "-N".into(),
                "-B".into(),
                "--raw".into(),
                "-e".into(),
                sql.into(),
            ])
            .await?;
        Ok(out.lines().filter(|l| !l.is_empty()).map(|l| l.split('\t').map(str::to_string).collect()).collect())
    }

    /// PostgreSQL can't open an older major version's data directory. When
    /// `spec`'s volume holds one (a restore or a Blue/Green green on a newer
    /// version, or a major version upgrade), dump it with the old server and
    /// leave an empty volume for the new one; the caller loads the dump.
    async fn upgrade_dump(&self, spec: &DatabaseSpec) -> Result<Option<Vec<u8>>, BackendError> {
        if spec.kind != Kind::Postgres {
            // MySQL and MariaDB upgrade their data directory on start.
            return Ok(None);
        }
        let volume = container(&spec.name);
        let mount = format!("{volume}:/var/lib/postgresql/data");
        let old = self
            .shell(&spec.image, &[&mount], "cat /var/lib/postgresql/data/pgdata/PG_VERSION 2>/dev/null || true")
            .await?
            .trim()
            .to_string();
        let Some((repo, tag)) = spec.image.split_once(':') else { return Ok(None) };
        let new: String = tag.chars().take_while(char::is_ascii_digit).collect();
        if old.is_empty() || new.is_empty() || old == new {
            return Ok(None);
        }
        let old_image = format!("{repo}:{old}{}", &tag[new.len()..]);
        tracing::info!(database = %spec.identifier, from = %old, to = %new, "upgrading PostgreSQL data");
        let old_spec = DatabaseSpec { image: old_image, parameters: Vec::new(), ..spec.clone() };
        self.run_container(&old_spec).await?;
        let dumped = match self.wait_ready(&old_spec).await {
            Ok(()) => self.dump(&old_spec).await,
            Err(e) => Err(e),
        };
        let _ = self.run_strs(&["rm", "-f", &volume]).await;
        let dump = dumped?;
        let _ = self.run_strs(&["volume", "rm", "-f", &volume]).await;
        self.run_strs(&["volume", "create", "--label", "mws.rds=1", &volume]).await?;
        Ok(Some(dump))
    }

    /// Bring an older major version's data in `spec`'s volume up to
    /// `spec.image`: a fresh data directory initialized by the new server
    /// (without the database's settings, which may make it read-only) with
    /// the old server's dump loaded. Leaves the server stopped.
    async fn upgrade(&self, spec: &DatabaseSpec) -> Result<(), BackendError> {
        let Some(dump) = self.upgrade_dump(spec).await? else { return Ok(()) };
        let init = DatabaseSpec { parameters: Vec::new(), ..spec.clone() };
        self.run_container(&init).await?;
        self.wait_ready(&init).await?;
        self.grant_master(&init).await?;
        self.restore_dump(&init, dump).await?;
        let _ = self.run_strs(&["stop", &container(&spec.name)]).await;
        Ok(())
    }

    /// Run a command with `input` on its standard input.
    async fn run_stdin(&self, args: &[String], input: Vec<u8>) -> Result<String, BackendError> {
        use tokio::io::AsyncWriteExt;
        let mut child = Command::new(&self.cli)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&input).await.map_err(|e| BackendError(format!("writing to {}: {e}", self.cli)))?;
        }
        let out = child.wait_with_output().await.map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(BackendError(String::from_utf8_lossy(&out.stderr).trim().to_string()))
        }
    }

    /// A logical dump of every user database (SQL text).
    async fn dump(&self, spec: &DatabaseSpec) -> Result<Vec<u8>, BackendError> {
        let c = container(&spec.name);
        match spec.kind {
            Kind::Postgres => {
                self.run_bytes(&["exec".into(), c, "pg_dumpall".into(), "-U".into(), spec.master_username.clone()])
                    .await
            }
            Kind::Mysql | Kind::Mariadb => {
                let dbs: Vec<String> = self
                    .mysql_rows(
                        spec,
                        "SELECT schema_name FROM information_schema.schemata \
                         WHERE schema_name NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')",
                    )
                    .await?
                    .into_iter()
                    .filter_map(|r| r.into_iter().next())
                    .collect();
                if dbs.is_empty() {
                    return Ok(Vec::new());
                }
                let tool = if spec.kind == Kind::Mariadb { "mariadb-dump" } else { "mysqldump" };
                let mut args: Vec<String> = vec![
                    "exec".into(),
                    c,
                    tool.into(),
                    "-h".into(),
                    "127.0.0.1".into(),
                    "-u".into(),
                    spec.master_username.clone(),
                    format!("-p{}", spec.master_password),
                    "--single-transaction".into(),
                    "--routines".into(),
                    "--events".into(),
                ];
                if spec.kind == Kind::Mysql {
                    args.push("--set-gtid-purged=OFF".into());
                }
                args.push("--databases".into());
                args.extend(dbs);
                self.run_bytes(&args).await
            }
        }
    }

    /// Load a logical dump.
    async fn restore_dump(&self, spec: &DatabaseSpec, dump: Vec<u8>) -> Result<(), BackendError> {
        if dump.is_empty() {
            return Ok(());
        }
        let c = container(&spec.name);
        let args: Vec<String> = match spec.kind {
            // Statements that exist already (the master user, the
            // initial database) fail harmlessly; psql carries on.
            Kind::Postgres => {
                vec![
                    "exec".into(),
                    "-i".into(),
                    c,
                    "psql".into(),
                    "-q".into(),
                    "-U".into(),
                    spec.master_username.clone(),
                    "-d".into(),
                    "postgres".into(),
                ]
            }
            Kind::Mysql | Kind::Mariadb => vec![
                "exec".into(),
                "-i".into(),
                c,
                if spec.kind == Kind::Mariadb { "mariadb" } else { "mysql" }.into(),
                "-h".into(),
                "127.0.0.1".into(),
                "-u".into(),
                spec.master_username.clone(),
                format!("-p{}", spec.master_password),
            ],
        };
        self.run_stdin(&args, dump).await.map(drop)
    }

    async fn export_postgres(&self, spec: &DatabaseSpec) -> Result<Vec<TableData>, BackendError> {
        let c = container(&spec.name);
        let user = &spec.master_username;
        let dbs = self
            .psql(
                &c,
                user,
                "SELECT datname FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('rdsadmin') ORDER BY 1",
            )
            .await?;
        let mut out = Vec::new();
        for db in dbs.lines().map(str::trim).filter(|d| !d.is_empty()) {
            let tables = self
                .psql_db(
                    &c,
                    user,
                    db,
                    "SELECT table_schema || chr(9) || table_name FROM information_schema.tables \
                     WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1",
                )
                .await?;
            for line in tables.lines().filter(|l| !l.is_empty()) {
                let Some((schema, table)) = line.split_once('\t') else { continue };
                let columns = self
                    .psql_db(
                        &c,
                        user,
                        db,
                        &format!(
                            "SELECT column_name || chr(9) || data_type FROM information_schema.columns \
                             WHERE table_schema = {} AND table_name = {} ORDER BY ordinal_position",
                            sql_literal(schema),
                            sql_literal(table)
                        ),
                    )
                    .await?
                    .lines()
                    .filter_map(|l| l.split_once('\t').map(|(a, b)| (a.to_string(), b.to_string())))
                    .collect();
                let ident = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
                let json = self
                    .psql_db(
                        &c,
                        user,
                        db,
                        &format!(
                            "SELECT coalesce(json_agg(row_to_json(t)), '[]') FROM {}.{} t",
                            ident(schema),
                            ident(table)
                        ),
                    )
                    .await?;
                let rows = serde_json::from_str::<Vec<serde_json::Map<String, serde_json::Value>>>(json.trim())
                    .map_err(|e| BackendError(format!("reading {db}.{schema}.{table}: {e}")))?;
                out.push(TableData {
                    database: db.to_string(),
                    schema: Some(schema.to_string()),
                    table: table.to_string(),
                    columns,
                    rows,
                });
            }
        }
        Ok(out)
    }

    async fn export_mysql(&self, spec: &DatabaseSpec) -> Result<Vec<TableData>, BackendError> {
        let tables = self
            .mysql_rows(
                spec,
                "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' \
                 AND table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') ORDER BY 1, 2",
            )
            .await?;
        let mut out = Vec::new();
        for row in tables {
            let [db, table] = row.as_slice() else { continue };
            let columns: Vec<(String, String)> = self
                .mysql_rows(
                    spec,
                    &format!(
                        "SELECT column_name, data_type FROM information_schema.columns \
                         WHERE table_schema = {} AND table_name = {} ORDER BY ordinal_position",
                        sql_literal(db),
                        sql_literal(table)
                    ),
                )
                .await?
                .into_iter()
                .filter_map(|r| Some((r.first()?.clone(), r.get(1)?.clone())))
                .collect();
            let ident = |s: &str| format!("`{}`", s.replace('`', "``"));
            let pairs: Vec<String> = columns.iter().map(|(n, _)| format!("{}, {}", sql_literal(n), ident(n))).collect();
            let json = if pairs.is_empty() {
                "[]".to_string()
            } else {
                self.mysql_rows(
                    spec,
                    &format!(
                        "SELECT coalesce(JSON_ARRAYAGG(JSON_OBJECT({})), JSON_ARRAY()) FROM {}.{}",
                        pairs.join(", "),
                        ident(db),
                        ident(table)
                    ),
                )
                .await?
                .into_iter()
                .next()
                .and_then(|r| r.into_iter().next())
                .unwrap_or_else(|| "[]".into())
            };
            let rows = serde_json::from_str::<Vec<serde_json::Map<String, serde_json::Value>>>(json.trim())
                .map_err(|e| BackendError(format!("reading {db}.{table}: {e}")))?;
            out.push(TableData { database: db.clone(), schema: None, table: table.clone(), columns, rows });
        }
        Ok(out)
    }

    async fn recover_postgres(
        &self,
        spec: &DatabaseSpec,
        target: &str,
        log_volume: &str,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BackendError> {
        let volume = snapshot_volume(target);
        let data = "/var/lib/postgresql/data";
        self.shell(
            &spec.image,
            &[&format!("{log_volume}:/from:ro"), &format!("{volume}:{data}")],
            &format!(
                "mkdir -p {WAL_ARCHIVE} && if [ -d /from/wal-archive ]; then cp -a /from/wal-archive/. {WAL_ARCHIVE}/; fi \
                 && touch {data}/pgdata/recovery.signal && chown -R postgres:postgres {WAL_ARCHIVE} {data}/pgdata/recovery.signal"
            ),
        )
        .await?;
        let name = format!("mws-rds-recover-{target}");
        let _ = self.run_strs(&["rm", "-f", &name]).await;
        self.run(&[
            "run".into(),
            "-d".into(),
            "--name".into(),
            name.clone(),
            "--network".into(),
            "none".into(),
            "-v".into(),
            format!("{volume}:{data}"),
            "-e".into(),
            format!("PGDATA={data}/pgdata"),
            "-e".into(),
            format!("POSTGRES_PASSWORD={}", spec.master_password),
            spec.image.clone(),
            "-c".into(),
            format!("restore_command=cp {WAL_ARCHIVE}/%f %p"),
            "-c".into(),
            format!("recovery_target_time={}", until.format("%Y-%m-%d %H:%M:%S%.6f+00")),
            "-c".into(),
            "recovery_target_action=promote".into(),
            "-c".into(),
            "archive_mode=off".into(),
        ])
        .await?;
        let result = async {
            for _ in 0..600 {
                match self.psql(&name, &spec.master_username, "SELECT pg_is_in_recovery()").await {
                    Ok(r) if r == "f" => {
                        let user = format!("\"{}\"", spec.master_username.replace('"', "\"\""));
                        self.psql(
                            &name,
                            &spec.master_username,
                            &format!("ALTER USER {user} WITH PASSWORD {}", sql_literal(&spec.master_password)),
                        )
                        .await?;
                        self.psql(&name, &spec.master_username, "CHECKPOINT").await?;
                        return Ok(());
                    }
                    _ => {}
                }
                if !self.running(&name).await {
                    return Err(BackendError(format!("the recovery failed: {}", self.log_tail(&name).await)));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(BackendError("the recovery did not finish within 5 minutes".into()))
        }
        .await;
        let _ = self.run_strs(&["stop", "-t", "30", &name]).await;
        let _ = self.run_strs(&["rm", "-f", &name]).await;
        result?;
        // The copy keeps no archive of its own.
        self.shell(&spec.image, &[&format!("{volume}:{data}")], &format!("rm -rf {WAL_ARCHIVE}")).await.map(drop)
    }

    /// Run the CLI and return its raw standard output.
    async fn run_bytes(&self, args: &[String]) -> Result<Vec<u8>, BackendError> {
        if let Some(c) = args.get(1).filter(|_| args.first().is_some_and(|a| a == "exec")) {
            self.wait_unpaused(c).await;
        }
        let out = Command::new(&self.cli)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(BackendError(String::from_utf8_lossy(&out.stderr).trim().to_string()))
        }
    }

    /// Roll a MySQL or MariaDB copy forward: the server itself replays the
    /// source's binary log (handed to it as its relay log) from where the
    /// copy's own log ends, up to the last transaction begun by `until`.
    async fn recover_mysql(
        &self,
        spec: &DatabaseSpec,
        target: &str,
        log_volume: &str,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BackendError> {
        let volume = snapshot_volume(target);
        let mariadb = spec.kind == Kind::Mariadb;
        // Where the copy's binary log ends, and the source's log files.
        let tail = self
            .shell(
                &spec.image,
                &[&format!("{volume}:/d:ro")],
                r#"f=$(ls /d | grep -E '^binlog\.[0-9]+$' | sort | tail -1); [ -n "$f" ] && echo "$f $(stat -c %s /d/$f)" || true"#,
            )
            .await?;
        let files = self
            .shell(&spec.image, &[&format!("{log_volume}:/l:ro")], r#"ls /l | grep -E '^binlog\.[0-9]+$' | sort"#)
            .await?;
        let (first, start) = match tail.split_once(' ') {
            Some((f, p)) => (f.to_string(), p.trim().parse::<u64>().unwrap_or(4)),
            None => (String::new(), 4),
        };
        let files: Vec<String> =
            files.lines().filter(|f| first.is_empty() || *f >= first.as_str()).map(String::from).collect();
        // Find where to stop: before the first transaction begun after
        // `until`.
        let cutoff = until.timestamp();
        let mut stop: Option<(String, u64)> = None;
        let mut last_end: Option<(String, u64)> = None;
        'files: for f in &files {
            let bytes = self
                .run_bytes(&[
                    "run".into(),
                    "--rm".into(),
                    "--network".into(),
                    "none".into(),
                    "-v".into(),
                    format!("{log_volume}:/l:ro"),
                    "--entrypoint".into(),
                    "cat".into(),
                    spec.image.clone(),
                    format!("/l/{f}"),
                ])
                .await?;
            let from = if *f == first { start } else { 4 };
            for (offset, timestamp, kind) in binlog_events(&bytes) {
                if offset < from {
                    continue;
                }
                // GTID events (MySQL's 33 and 34, MariaDB's 162) begin
                // transactions.
                if matches!(kind, 33 | 34 | 162) && i64::from(timestamp) > cutoff {
                    stop = Some((f.clone(), offset));
                    break 'files;
                }
            }
            last_end = Some((f.clone(), bytes.len() as u64));
        }
        let until_pos = stop.or(last_end);
        let nothing_to_do = match &until_pos {
            None => true,
            Some((f, p)) => *f == first && *p <= start,
        };
        let name = format!("mws-rds-recover-{target}");
        let _ = self.run_strs(&["rm", "-f", &name]).await;
        // Hand the log over as relay log files, and reset the passwords at
        // startup (the copy has the backup's).
        let pw = sql_literal(&spec.master_password);
        let user = sql_literal(&spec.master_username);
        let mut init = format!("ALTER USER IF EXISTS 'root'@'localhost' IDENTIFIED BY {pw};\nALTER USER IF EXISTS 'root'@'%' IDENTIFIED BY {pw};\n");
        if spec.master_username != "root" {
            init.push_str(&format!("ALTER USER IF EXISTS {user}@'%' IDENTIFIED BY {pw};\n"));
        }
        let mut script = String::from("set -e; cd /var/lib/mysql; rm -f relay-bin.*; : > relay-bin.index; ");
        if !nothing_to_do {
            for f in &files {
                let n = f.trim_start_matches("binlog.");
                script.push_str(&format!("cp /l/{f} relay-bin.{n}; echo ./relay-bin.{n} >> relay-bin.index; "));
                if until_pos.as_ref().is_some_and(|(u, _)| u == f) {
                    break;
                }
            }
        }
        script.push_str(&format!(
            "printf '%s' {} > mws-init.sql; chown mysql:mysql relay-bin.* mws-init.sql",
            shell_quote(&init)
        ));
        self.shell(&spec.image, &[&format!("{volume}:/var/lib/mysql"), &format!("{log_volume}:/l:ro")], &script)
            .await?;
        self.run(&[
            "run".into(),
            "-d".into(),
            "--name".into(),
            name.clone(),
            "--network".into(),
            "none".into(),
            "-v".into(),
            format!("{volume}:/var/lib/mysql"),
            "-e".into(),
            format!("MYSQL_ROOT_PASSWORD={}", spec.master_password),
            "-e".into(),
            format!("MARIADB_ROOT_PASSWORD={}", spec.master_password),
            spec.image.clone(),
            "--skip-log-bin".into(),
            "--relay-log=relay-bin".into(),
            "--server-id=4242".into(),
            if mariadb { "--skip-slave-start".into() } else { "--skip-replica-start".into() },
            "--init-file=/var/lib/mysql/mws-init.sql".into(),
        ])
        .await?;
        let client = if mariadb { "mariadb" } else { "mysql" };
        let sql = |q: String| {
            let name = name.clone();
            let pw = spec.master_password.clone();
            async move {
                self.run(&[
                    "exec".into(),
                    name,
                    client.into(),
                    "-h".into(),
                    "127.0.0.1".into(),
                    "-u".into(),
                    "root".into(),
                    format!("-p{pw}"),
                    "-B".into(),
                    "-e".into(),
                    q,
                ])
                .await
            }
        };
        let result = async {
            let mut ready = false;
            for _ in 0..600 {
                if sql("SELECT 1".into()).await.is_ok() {
                    ready = true;
                    break;
                }
                if !self.running(&name).await {
                    return Err(BackendError(format!("the recovery failed: {}", self.log_tail(&name).await)));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            if !ready {
                return Err(BackendError("the recovery did not start within 5 minutes".into()));
            }
            if let (false, Some((stop_file, stop_pos))) = (nothing_to_do, &until_pos) {
                let first_relay = format!("relay-bin.{}", files[0].trim_start_matches("binlog."));
                let first_pos = if files[0] == first { start } else { 4 };
                let stop_relay = format!("relay-bin.{}", stop_file.trim_start_matches("binlog."));
                let (change, begin, status) = if mariadb {
                    (
                        format!("CHANGE MASTER TO MASTER_HOST='mws-recovery', RELAY_LOG_FILE='{first_relay}', RELAY_LOG_POS={first_pos}"),
                        format!("START SLAVE SQL_THREAD UNTIL RELAY_LOG_FILE='{stop_relay}', RELAY_LOG_POS={stop_pos}"),
                        "SHOW SLAVE STATUS\\G",
                    )
                } else {
                    (
                        format!("CHANGE REPLICATION SOURCE TO SOURCE_HOST='mws-recovery', RELAY_LOG_FILE='{first_relay}', RELAY_LOG_POS={first_pos}"),
                        format!("START REPLICA SQL_THREAD UNTIL RELAY_LOG_FILE='{stop_relay}', RELAY_LOG_POS={stop_pos}"),
                        "SHOW REPLICA STATUS\\G",
                    )
                };
                sql(change).await?;
                sql(begin).await?;
                let mut done = false;
                for _ in 0..1200 {
                    let st = sql(status.into()).await.unwrap_or_default();
                    let field = |k: &str| {
                        st.lines()
                            .find_map(|l| l.trim().strip_prefix(&format!("{k}:")).map(|v| v.trim().to_string()))
                            .unwrap_or_default()
                    };
                    let running = if mariadb { field("Slave_SQL_Running") } else { field("Replica_SQL_Running") };
                    let error = field("Last_SQL_Error");
                    if !error.is_empty() {
                        return Err(BackendError(format!("replaying the binary log failed: {error}")));
                    }
                    if running == "No" {
                        done = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                if !done {
                    return Err(BackendError("replaying the binary log did not finish within 5 minutes".into()));
                }
                let reset = if mariadb { "STOP SLAVE; RESET SLAVE ALL" } else { "STOP REPLICA; RESET REPLICA ALL" };
                sql(reset.into()).await?;
            }
            Ok(())
        }
        .await;
        let _ = self.run_strs(&["stop", "-t", "60", &name]).await;
        let _ = self.run_strs(&["rm", "-f", &name]).await;
        result?;
        self.shell(
            &spec.image,
            &[&format!("{volume}:/var/lib/mysql")],
            "rm -f /var/lib/mysql/relay-bin.* /var/lib/mysql/mws-init.sql",
        )
        .await
        .map(drop)
    }

    /// Copy volume `from` into a new volume `to`, using `image` (the
    /// database's own image, so nothing else needs pulling) for the copy.
    async fn copy_volume(&self, from: &str, to: &str, image: &str) -> Result<(), BackendError> {
        self.run_strs(&["volume", "create", "--label", "mws.rds=1", "--label", &format!("mws.rds.image={image}"), to])
            .await?;
        self.run(&[
            "run".into(),
            "--rm".into(),
            "-v".into(),
            format!("{from}:/from:ro"),
            "-v".into(),
            format!("{to}:/to"),
            "--entrypoint".into(),
            "sh".into(),
            image.into(),
            "-c".into(),
            "cp -a /from/. /to/".into(),
        ])
        .await
        .map(drop)
    }
}

#[async_trait::async_trait]
impl DatabaseBackend for DockerBackend {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn runs_databases(&self) -> bool {
        true
    }

    async fn create(&self, spec: &DatabaseSpec, from_snapshot: Option<&str>) -> Result<Listening, BackendError> {
        let volume = container(&spec.name);
        let _ = self.run_strs(&["rm", "-f", &volume]).await;
        let _ = self.run_strs(&["volume", "rm", "-f", &volume]).await;
        match from_snapshot {
            Some(snap) => {
                self.copy_volume(&snapshot_volume(snap), &volume, &spec.image).await?;
                // The copy starts its own WAL archive.
                if spec.kind == Kind::Postgres {
                    self.shell(
                        &spec.image,
                        &[&format!("{volume}:/var/lib/postgresql/data")],
                        &format!("rm -rf {WAL_ARCHIVE}"),
                    )
                    .await?;
                }
            }
            None => {
                self.run_strs(&["volume", "create", "--label", "mws.rds=1", &volume]).await?;
            }
        }
        if from_snapshot.is_some() {
            self.upgrade(spec).await?;
        }
        self.run_container(spec).await?;
        self.wait_ready(spec).await?;
        if from_snapshot.is_none() {
            self.grant_master(spec).await?;
        }
        self.listening(spec).await
    }

    async fn start(&self, spec: &DatabaseSpec) -> Result<Listening, BackendError> {
        self.upgrade(spec).await?;
        self.run_container(spec).await?;
        self.wait_ready(spec).await?;
        self.listening(spec).await
    }

    async fn stop(&self, name: &str) -> Result<(), BackendError> {
        self.run_strs(&["stop", "-t", "30", &container(name)]).await.map(drop)
    }

    async fn delete(&self, name: &str) -> Result<(), BackendError> {
        let c = container(name);
        let _ = self.run_strs(&["rm", "-f", "-v", &c]).await;
        let _ = self.run_strs(&["volume", "rm", "-f", &c]).await;
        Ok(())
    }

    async fn snapshot(&self, name: &str, snapshot: &str) -> Result<(), BackendError> {
        let c = container(name);
        let target = snapshot_volume(snapshot);
        let _ = self.run_strs(&["volume", "rm", "-f", &target]).await;
        let running =
            self.run_strs(&["inspect", "--format", "{{.State.Running}}", &c]).await.unwrap_or_default() == "true";
        let image = self.run_strs(&["inspect", "--format", "{{.Config.Image}}", &c]).await?;
        if running {
            self.run_strs(&["pause", &c]).await?;
        }
        let r = self.copy_volume(&c, &target, &image).await;
        if running {
            let _ = self.run_strs(&["unpause", &c]).await;
        }
        r
    }

    async fn copy_snapshot(&self, source: &str, target: &str) -> Result<(), BackendError> {
        let t = snapshot_volume(target);
        let s = snapshot_volume(source);
        let _ = self.run_strs(&["volume", "rm", "-f", &t]).await;
        let image =
            self.run_strs(&["volume", "inspect", "--format", "{{index .Labels \"mws.rds.image\"}}", &s]).await?;
        self.copy_volume(&s, &t, &image).await
    }

    async fn delete_snapshot(&self, snapshot: &str) -> Result<(), BackendError> {
        self.run_strs(&["volume", "rm", "-f", &snapshot_volume(snapshot)]).await.map(drop)
    }

    async fn set_master_password(&self, spec: &DatabaseSpec, old_password: &str) -> Result<(), BackendError> {
        let c = container(&spec.name);
        match spec.kind {
            Kind::Postgres => {
                let user = format!("\"{}\"", spec.master_username.replace('"', "\"\""));
                let sql = format!("ALTER USER {user} WITH PASSWORD {}", sql_literal(&spec.master_password));
                // Local socket connections inside the container are trusted.
                self.run(&[
                    "exec".into(),
                    c,
                    "psql".into(),
                    "-v".into(),
                    "ON_ERROR_STOP=1".into(),
                    "-U".into(),
                    spec.master_username.clone(),
                    "-d".into(),
                    "postgres".into(),
                    "-c".into(),
                    sql,
                ])
                .await
                .map(drop)
            }
            Kind::Mysql | Kind::Mariadb => {
                let pw = sql_literal(&spec.master_password);
                let user = sql_literal(&spec.master_username);
                let mut sql = format!("ALTER USER {user}@'%' IDENTIFIED BY {pw};");
                if spec.master_username != "root" {
                    sql.push_str(&format!(
                        " ALTER USER 'root'@'%' IDENTIFIED BY {pw}; ALTER USER 'root'@'localhost' IDENTIFIED BY {pw};"
                    ));
                }
                self.mysql(spec, old_password, &sql).await.map(drop)
            }
        }
    }

    async fn seal_log(&self, spec: &DatabaseSpec) -> Result<(), BackendError> {
        let c = container(&spec.name);
        if !self.running(&c).await {
            return Ok(());
        }
        match spec.kind {
            Kind::Postgres => {
                // A commit stamped now (recovery stops at the first commit
                // past its target, so one must exist), then archive the
                // segment holding it.
                let user = &spec.master_username;
                self.psql(&c, user, "SELECT txid_current()").await?;
                let segment = self.psql(&c, user, "SELECT pg_walfile_name(pg_switch_wal())").await?;
                for _ in 0..120 {
                    let done = self
                        .psql(&c, user, "SELECT coalesce(last_archived_wal, '') FROM pg_stat_archiver")
                        .await
                        .unwrap_or_default();
                    if done.get(8..) >= segment.get(8..) && !done.is_empty() {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(BackendError(format!("WAL segment {segment} was not archived")))
            }
            Kind::Mysql | Kind::Mariadb => self.mysql(spec, &spec.master_password, "FLUSH BINARY LOGS").await.map(drop),
        }
    }

    async fn export_tables(&self, spec: &DatabaseSpec, snapshot: &str) -> Result<Vec<TableData>, BackendError> {
        self.create(spec, Some(snapshot)).await?;
        let r = match spec.kind {
            Kind::Postgres => self.export_postgres(spec).await,
            Kind::Mysql | Kind::Mariadb => self.export_mysql(spec).await,
        };
        let _ = self.delete(&spec.name).await;
        r
    }

    async fn recover(
        &self,
        spec: &DatabaseSpec,
        base: &str,
        log: &LogSource,
        target: &str,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BackendError> {
        let volume = snapshot_volume(target);
        let _ = self.run_strs(&["volume", "rm", "-f", &volume]).await;
        self.copy_volume(&snapshot_volume(base), &volume, &spec.image).await?;
        let log_volume = match log {
            LogSource::Database(name) => container(name),
            LogSource::Snapshot(s) => snapshot_volume(s),
        };
        let r = match spec.kind {
            Kind::Postgres => self.recover_postgres(spec, target, &log_volume, until).await,
            Kind::Mysql | Kind::Mariadb => self.recover_mysql(spec, target, &log_volume, until).await,
        };
        if r.is_err() {
            let _ = self.run_strs(&["volume", "rm", "-f", &volume]).await;
        }
        r
    }

    async fn logs(&self, name: &str) -> Result<String, BackendError> {
        let out = Command::new(&self.cli)
            .args(["logs", "--timestamps", &container(name)])
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if !out.status.success() {
            return Err(BackendError(String::from_utf8_lossy(&out.stderr).trim().to_string()));
        }
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(text)
    }
}
