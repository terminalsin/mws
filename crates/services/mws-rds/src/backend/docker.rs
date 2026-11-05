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

use super::{BackendError, DatabaseBackend, DatabaseSpec, Kind, Listening};

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

    async fn run(&self, args: &[String]) -> Result<String, BackendError> {
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
            Some(snap) => self.copy_volume(&snapshot_volume(snap), &volume, &spec.image).await?,
            None => {
                self.run_strs(&["volume", "create", "--label", "mws.rds=1", &volume]).await?;
            }
        }
        self.run_container(spec).await?;
        self.wait_ready(spec).await?;
        if from_snapshot.is_none() {
            self.grant_master(spec).await?;
        }
        self.listening(spec).await
    }

    async fn start(&self, spec: &DatabaseSpec) -> Result<Listening, BackendError> {
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
