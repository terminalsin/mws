//! Cache nodes as containers, driven through the Docker CLI (or anything
//! that speaks its command line, such as Podman).
//!
//! Each node runs the official engine image for its version (`redis`,
//! `valkey/valkey`, `memcached`), listening on its port inside the
//! container and published on the host under the same number. Nodes reach
//! each other over Docker's default bridge network (replication, the
//! cluster bus); clients reach them on the host.
//!
//! Images can be overridden per engine with `MWS_ELASTICACHE_REDIS_IMAGE`,
//! `MWS_ELASTICACHE_VALKEY_IMAGE` and `MWS_ELASTICACHE_MEMCACHED_IMAGE`.

use std::process::Stdio;

use tokio::process::Command;

use super::{BackendError, EngineBackend, EngineKind, NodeSpec, RunningNode};

#[derive(Debug)]
pub struct DockerBackend {
    cli: String,
}

impl DockerBackend {
    pub fn new(cli: impl Into<String>) -> Self {
        Self { cli: cli.into() }
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

    async fn peer_address(&self, handle: &str) -> Result<String, BackendError> {
        let ip = self
            .run(&[
                "inspect".into(),
                "--format".into(),
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}".into(),
                handle.into(),
            ])
            .await?;
        ip.split_whitespace()
            .next()
            .map(str::to_string)
            .ok_or_else(|| BackendError(format!("container {handle} has no IP address")))
    }
}

/// The container image for an engine version.
pub fn image_for(engine: EngineKind, version: &str, cluster_mode: bool) -> String {
    let env = |var: &str| std::env::var(var).ok().filter(|v| !v.is_empty());
    let mut parts = version.split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(7);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    match engine {
        EngineKind::Redis => {
            if let Some(i) = env("MWS_ELASTICACHE_REDIS_IMAGE") {
                return i;
            }
            // Cluster mode needs `cluster-announce-hostname` (Redis 7).
            // Redis OSS 7.1 is ElastiCache's own release; 7.2 is its
            // nearest open source sibling.
            let tag = match (major, minor) {
                (7, 1..) | (8.., _) => "7.2".to_string(),
                (7, 0) => "7.0".to_string(),
                _ if cluster_mode => "7.0".to_string(),
                (6, m) => format!("6.{}", m.min(2)),
                (5, _) => "5.0".to_string(),
                _ => "6.2".to_string(),
            };
            format!("redis:{tag}-alpine")
        }
        EngineKind::Valkey => {
            if let Some(i) = env("MWS_ELASTICACHE_VALKEY_IMAGE") {
                return i;
            }
            let tag = match (major, minor) {
                (7, _) => "7.2".to_string(),
                (8, m) => format!("8.{}", m.min(1)),
                _ => "8.1".to_string(),
            };
            format!("valkey/valkey:{tag}-alpine")
        }
        EngineKind::Memcached => {
            env("MWS_ELASTICACHE_MEMCACHED_IMAGE").unwrap_or_else(|| "memcached:1.6-alpine".into())
        }
    }
}

fn binary(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::Redis => "redis-server",
        EngineKind::Valkey => "valkey-server",
        EngineKind::Memcached => "memcached",
    }
}

#[async_trait::async_trait]
impl EngineBackend for DockerBackend {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn launch(&self, spec: &NodeSpec) -> Result<RunningNode, BackendError> {
        let name = format!("mws-elasticache-{}", spec.name);
        // Leftovers of an earlier run with the same name.
        let _ = self.run(&["rm".into(), "-f".into(), name.clone()]).await;
        let cpus = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
        let mut args: Vec<String> = vec![
            "create".into(),
            "--name".into(),
            name.clone(),
            "--hostname".into(),
            spec.name.clone(),
            "-p".into(),
            format!("{}:{}:{}", spec.bind_address, spec.port, spec.port),
            "--add-host".into(),
            "host.docker.internal:host-gateway".into(),
            "--cpus".into(),
            spec.vcpus.clamp(1, cpus).to_string(),
            "--memory".into(),
            format!("{}m", spec.memory_mib.max(64)),
            "--label".into(),
            format!("mws.elasticache.node={}", spec.name),
            "--label".into(),
            format!("mws.elasticache.account={}", spec.account_id),
            "--label".into(),
            format!("mws.elasticache.region={}", spec.region),
            image_for(spec.engine, &spec.engine_version, spec.cluster_mode),
            binary(spec.engine).into(),
        ];
        args.extend(spec.args.iter().cloned());
        let id = self.run(&args).await?;
        let handle = id.lines().last().unwrap_or_default().to_string();
        if !spec.files.is_empty() {
            let dir = std::env::temp_dir().join(format!("mws-elasticache-{}-{}", spec.name, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            for (path, data) in &spec.files {
                let local = dir.join(path.trim_start_matches('/'));
                if let Some(parent) = local.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| BackendError(format!("staging {path}: {e}")))?;
                }
                std::fs::write(&local, data).map_err(|e| BackendError(format!("staging {path}: {e}")))?;
            }
            // Copy each top-level directory in.
            let tops: std::collections::BTreeSet<String> = spec
                .files
                .iter()
                .filter_map(|(p, _)| p.trim_start_matches('/').split('/').next().map(str::to_string))
                .collect();
            for top in tops {
                let src = dir.join(&top);
                let res = self.run(&["cp".into(), format!("{}/.", src.display()), format!("{handle}:/{top}")]).await;
                if let Err(e) = res {
                    let _ = std::fs::remove_dir_all(&dir);
                    let _ = self.terminate(&handle).await;
                    return Err(e);
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
        if let Err(e) = self.run(&["start".into(), handle.clone()]).await {
            let _ = self.terminate(&handle).await;
            return Err(e);
        }
        let peer_address = self.peer_address(&handle).await?;
        Ok(RunningNode { handle, peer_address })
    }

    async fn reboot(&self, handle: &str) -> Result<String, BackendError> {
        self.run(&["restart".into(), "-t".into(), "5".into(), handle.into()]).await?;
        self.peer_address(handle).await
    }

    async fn terminate(&self, handle: &str) -> Result<(), BackendError> {
        self.run(&["rm".into(), "-f".into(), "-v".into(), handle.into()]).await.map(drop)
    }

    async fn terminate_all(&self, handles: &[String]) -> Result<(), BackendError> {
        // One command, so it completes even if the caller goes away.
        let mut args = vec!["rm".to_string(), "-f".into(), "-v".into()];
        args.extend(handles.iter().cloned());
        self.run(&args).await.map(drop)
    }

    async fn logs(&self, handle: &str) -> Result<String, BackendError> {
        let out = Command::new(&self.cli)
            .args(["logs", handle])
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(text)
    }
}
