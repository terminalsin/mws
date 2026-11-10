//! Task containers driven through the Docker CLI (or anything that speaks
//! its command line, such as Podman: set `MWS_ECS_DOCKER=podman`).
//!
//! * `awsvpc` tasks get a small "pause" container that owns the task's
//!   network namespace, on the VPC's bridge network `mws-<vpc-id>` (the
//!   same network MWS EC2 puts instances on) with the address of the task's
//!   network interface. The task's containers join that namespace, so they
//!   reach each other on `localhost`, as on Fargate.
//! * `bridge` tasks get a network of their own on which every container is
//!   reachable by its name (what container `links` give), with port
//!   mappings published on the host (`hostPort` 0 picks a free port).
//! * `host` and `none` use Docker's networks of the same names.
//!
//! Task volumes without a host path become Docker volumes that live as
//! long as the task.
//!
//! The task role credentials endpoint is at `169.254.170.2`, as on ECS:
//! containers outside the host network also join the internal network
//! `mws-ecs-credentials`, whose gateway (the host) has that address, so
//! the SDKs' container credentials provider (which only talks plain HTTP
//! to loopback and the ECS link-local addresses) reaches MWS's port there.
//!
//! Images from MWS's own ECR registry are written as an image archive and
//! `docker load`ed (no registry login involved); other images are pulled,
//! with a `repositoryCredentials` login in a throwaway client config.

use std::process::Stdio;

use tokio::io::AsyncBufReadExt;
use tokio::process::Command;

use super::{
    BackendError, ContainerBackend, ContainerSpec, LogLine, RegistryAuth, StartedContainer, TaskNetwork, TaskSpec,
};

/// The internal network whose gateway is the credentials endpoint.
const CREDENTIALS_NETWORK: &str = "mws-ecs-credentials";

/// What the pause container runs.
const PAUSE_SCRIPT: &str = "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done";

#[derive(Debug)]
pub struct DockerBackend {
    cli: String,
    pause_image: String,
    /// Serializes network creation, so concurrent tasks in one VPC do not
    /// race to create its network.
    networks: tokio::sync::Mutex<()>,
}

impl DockerBackend {
    pub fn new(cli: impl Into<String>) -> Self {
        let pause_image = std::env::var("MWS_ECS_PAUSE_IMAGE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "alpine:3.20".to_string());
        Self { cli: cli.into(), pause_image, networks: tokio::sync::Mutex::new(()) }
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
            Err(BackendError(String::from_utf8_lossy(&out.stderr).trim().to_string()))
        }
    }

    async fn run_str(&self, args: &[&str]) -> Result<String, BackendError> {
        self.run(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).await
    }

    fn vpc_network(vpc_id: &str) -> String {
        format!("mws-{vpc_id}")
    }

    fn task_network(task_id: &str) -> String {
        format!("mws-ecs-{task_id}")
    }

    fn pause_name(task_id: &str) -> String {
        format!("mws-ecs-{task_id}-pause")
    }

    fn volume_name(task_id: &str, volume: &str) -> String {
        let clean: String =
            volume.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
        format!("mws-ecs-{task_id}-{clean}")
    }

    /// Make sure the VPC's network exists (as MWS EC2 makes it); `true`
    /// when it uses the VPC's own CIDR, so tasks keep their private IPs.
    async fn ensure_vpc_network(&self, vpc_id: &str, cidr: &str) -> Result<bool, BackendError> {
        let _guard = self.networks.lock().await;
        let name = Self::vpc_network(vpc_id);
        if let Ok(subnets) =
            self.run_str(&["network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", &name]).await
        {
            return Ok(subnets.split_whitespace().any(|s| s == cidr));
        }
        let label = format!("mws.ec2.vpc={vpc_id}");
        let base = ["network", "create", "--driver", "bridge", "--label", &label];
        let mut with_subnet: Vec<&str> = base.to_vec();
        with_subnet.extend(["--subnet", cidr, &name]);
        if self.run_str(&with_subnet).await.is_ok() {
            return Ok(true);
        }
        // An unused network of an earlier run may hold the CIDR.
        let pruned = self.run_str(&["network", "prune", "--force", "--filter", "label=mws.ec2.vpc"]).await.is_ok();
        if pruned && self.run_str(&with_subnet).await.is_ok() {
            return Ok(true);
        }
        let mut plain: Vec<&str> = base.to_vec();
        plain.push(&name);
        self.run_str(&plain).await?;
        Ok(false)
    }

    fn labels(task: &TaskSpec, container: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (k, v) in [
            ("mws.ecs.task", task.task_id.as_str()),
            ("mws.ecs.cluster", task.cluster.as_str()),
            ("mws.ecs.account", task.account_id.as_str()),
            ("mws.ecs.region", task.region.as_str()),
            ("com.amazonaws.ecs.task-arn", task.task_arn.as_str()),
            ("com.amazonaws.ecs.cluster", task.cluster.as_str()),
            ("com.amazonaws.ecs.container-name", container),
            ("com.amazonaws.ecs.task-definition-family", task.family.as_str()),
        ] {
            out.push("--label".into());
            out.push(format!("{k}={v}"));
        }
        out.push("--label".into());
        out.push(format!("com.amazonaws.ecs.task-definition-version={}", task.revision));
        out
    }

    async fn ensure_image(&self, image: &str) -> Result<(), BackendError> {
        if self.run_str(&["image", "inspect", "--format", "{{.Id}}", image]).await.is_ok() {
            return Ok(());
        }
        self.run_str(&["pull", image]).await.map(drop)
    }

    /// `docker pull` logged in with `auth`, through a client config of its
    /// own so the user's stays untouched.
    async fn pull_with_auth(&self, image: &str, auth: &RegistryAuth) -> Result<(), BackendError> {
        use base64::Engine;
        let dir = std::env::temp_dir().join(format!("mws-ecs-auth-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).map_err(|e| BackendError(format!("registry auth: {e}")))?;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.username, auth.password));
        let config = serde_json::json!({ "auths": { registry_of(image): { "auth": token } } });
        let written = std::fs::write(dir.join("config.json"), config.to_string());
        let out = match written {
            Ok(()) => {
                let config_dir = dir.to_string_lossy().to_string();
                self.run_str(&["--config", &config_dir, "pull", image]).await.map(drop)
            }
            Err(e) => Err(BackendError(format!("registry auth: {e}"))),
        };
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    /// Put `container` on the credentials network (made on first use).
    async fn join_credentials_network(&self, container: &str) {
        {
            let _guard = self.networks.lock().await;
            if self.run_str(&["network", "inspect", "--format", "{{.Name}}", CREDENTIALS_NETWORK]).await.is_err() {
                let created = self
                    .run_str(&[
                        "network",
                        "create",
                        "--driver",
                        "bridge",
                        "--internal",
                        "--subnet",
                        "169.254.170.0/24",
                        "--gateway",
                        "169.254.170.2",
                        "--label",
                        "mws.ecs.credentials=true",
                        CREDENTIALS_NETWORK,
                    ])
                    .await;
                if let Err(e) = created {
                    tracing::warn!("ECS cannot create the credentials network {CREDENTIALS_NETWORK}: {e}");
                    return;
                }
            }
        }
        if let Err(e) = self.run_str(&["network", "connect", CREDENTIALS_NETWORK, container]).await {
            tracing::warn!(container, "ECS cannot connect a container to {CREDENTIALS_NETWORK}: {e}");
        }
    }
}

/// The registry an image reference names, as Docker's client config keys
/// it.
fn registry_of(image: &str) -> String {
    match image.split_once('/') {
        Some((host, _)) if host.contains('.') || host.contains(':') || host == "localhost" => host.to_string(),
        _ => "https://index.docker.io/v1/".to_string(),
    }
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=:,@%+".contains(&b)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[async_trait::async_trait]
impl ContainerBackend for DockerBackend {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn pull(&self, image: &str, auth: Option<&RegistryAuth>) -> Result<Option<String>, BackendError> {
        match auth {
            Some(a) => self.pull_with_auth(image, a).await?,
            None => self.ensure_image(image).await?,
        }
        let digests =
            self.run_str(&["image", "inspect", "--format", "{{range .RepoDigests}}{{.}} {{end}}", image]).await?;
        Ok(digests.split_whitespace().next().and_then(|d| d.split_once('@')).map(|(_, d)| d.to_string()))
    }

    async fn load_image(&self, tag: &str, image: &crate::platform::RegistryImage) -> Result<(), BackendError> {
        use tokio::io::AsyncWriteExt;
        if self.run_str(&["image", "inspect", "--format", "{{.Id}}", tag]).await.is_ok() {
            return Ok(());
        }
        let archive = super::archive::image_archive(tag, image);
        let mut child = Command::new(&self.cli)
            .args(["load", "-q"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        let mut stdin = child.stdin.take().expect("piped");
        let writer = tokio::spawn(async move {
            let _ = stdin.write_all(&archive).await;
            let _ = stdin.shutdown().await;
        });
        let out = child.wait_with_output().await.map_err(|e| BackendError(format!("docker load: {e}")))?;
        let _ = writer.await;
        if !out.status.success() {
            return Err(BackendError(format!("docker load: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(())
    }

    async fn prepare(&self, task: &TaskSpec) -> Result<String, BackendError> {
        for v in &task.volumes {
            let name = Self::volume_name(&task.task_id, v);
            let label = format!("mws.ecs.task={}", task.task_id);
            self.run_str(&["volume", "create", "--label", &label, &name]).await?;
        }
        match &task.network {
            TaskNetwork::Awsvpc { vpc_id, vpc_cidr, ip } => {
                // Without a VPC (no EC2 wired in) the task joins Docker's
                // default bridge.
                let (network, own_cidr) = if vpc_id.is_empty() {
                    ("bridge".to_string(), false)
                } else {
                    (Self::vpc_network(vpc_id), self.ensure_vpc_network(vpc_id, vpc_cidr).await?)
                };
                self.ensure_image(&self.pause_image).await?;
                let name = Self::pause_name(&task.task_id);
                let _ = self.run_str(&["rm", "-f", &name]).await;
                let mut args: Vec<String> = vec![
                    "run".into(),
                    "-d".into(),
                    "--name".into(),
                    name.clone(),
                    "--network".into(),
                    network,
                    "--add-host".into(),
                    "host.docker.internal:host-gateway".into(),
                    "--hostname".into(),
                    format!("ip-{}", ip.replace('.', "-")),
                ];
                if own_cidr {
                    args.extend(["--ip".into(), ip.clone()]);
                }
                if task.ipc_mode.as_deref() == Some("task") {
                    args.extend(["--ipc".into(), "shareable".into()]);
                }
                args.extend(Self::labels(task, "~internal~ecs~pause"));
                args.extend([
                    "--entrypoint".into(),
                    "/bin/sh".into(),
                    self.pause_image.clone(),
                    "-c".into(),
                    PAUSE_SCRIPT.into(),
                ]);
                self.run(&args).await?;
                self.join_credentials_network(&name).await;
                Ok(name)
            }
            TaskNetwork::Bridge => {
                let name = Self::task_network(&task.task_id);
                let label = format!("mws.ecs.task={}", task.task_id);
                let _ = self.run_str(&["network", "rm", &name]).await;
                self.run_str(&["network", "create", "--driver", "bridge", "--label", &label, &name]).await?;
                Ok(name)
            }
            TaskNetwork::Host => Ok("host".into()),
            TaskNetwork::None => Ok("none".into()),
        }
    }

    async fn start(&self, task: &TaskSpec, handle: &str, c: &ContainerSpec) -> Result<StartedContainer, BackendError> {
        let name = format!("mws-ecs-{}-{}", task.task_id, c.name);
        let _ = self.run_str(&["rm", "-f", &name]).await;
        let mut args: Vec<String> = vec!["run".into(), "-d".into(), "--name".into(), name.clone()];
        let shared_namespace = matches!(task.network, TaskNetwork::Awsvpc { .. });
        match &task.network {
            TaskNetwork::Awsvpc { .. } => args.extend(["--network".into(), format!("container:{handle}")]),
            TaskNetwork::Bridge => {
                args.extend([
                    "--network".into(),
                    handle.to_string(),
                    "--network-alias".into(),
                    c.name.clone(),
                    "--add-host".into(),
                    "host.docker.internal:host-gateway".into(),
                ]);
                for p in &c.ports {
                    let proto = if p.protocol == "udp" { "/udp" } else { "" };
                    args.push("-p".into());
                    if p.host_port > 0 {
                        args.push(format!("{}:{}{proto}", p.host_port, p.container_port));
                    } else {
                        args.push(format!("{}{proto}", p.container_port));
                    }
                }
            }
            TaskNetwork::Host => args.extend(["--network".into(), "host".into()]),
            TaskNetwork::None => args.extend(["--network".into(), "none".into()]),
        }
        if !shared_namespace {
            if let Some(h) = &c.hostname {
                args.extend(["--hostname".into(), h.clone()]);
            }
            for d in &c.dns_servers {
                args.extend(["--dns".into(), d.clone()]);
            }
            for d in &c.dns_search {
                args.extend(["--dns-search".into(), d.clone()]);
            }
            for (h, ip) in &c.extra_hosts {
                args.extend(["--add-host".into(), format!("{h}:{ip}")]);
            }
        }
        if task.pid_mode.as_deref() == Some("host") {
            args.extend(["--pid".into(), "host".into()]);
        } else if task.pid_mode.as_deref() == Some("task") && shared_namespace {
            args.extend(["--pid".into(), format!("container:{handle}")]);
        }
        match task.ipc_mode.as_deref() {
            Some("host") => args.extend(["--ipc".into(), "host".into()]),
            Some("task") if shared_namespace => args.extend(["--ipc".into(), format!("container:{handle}")]),
            Some("none") => args.extend(["--ipc".into(), "none".into()]),
            _ => {}
        }
        if let Some(m) = c.memory {
            args.extend(["--memory".into(), format!("{}m", m.max(6))]);
        }
        if let Some(m) = c.memory_reservation {
            args.extend(["--memory-reservation".into(), format!("{}m", m.max(6))]);
        }
        if c.cpu >= 2 {
            args.extend(["--cpu-shares".into(), c.cpu.to_string()]);
        }
        for (k, v) in &c.env {
            args.extend(["-e".into(), format!("{k}={v}")]);
        }
        for m in &c.mounts {
            let source = if m.host_path { m.source.clone() } else { Self::volume_name(&task.task_id, &m.source) };
            let ro = if m.read_only { ":ro" } else { "" };
            args.extend(["-v".into(), format!("{source}:{}{ro}", m.container_path)]);
        }
        for (from, ro) in &c.volumes_from {
            let suffix = if *ro { ":ro" } else { "" };
            args.extend(["--volumes-from".into(), format!("mws-ecs-{}-{from}{suffix}", task.task_id)]);
        }
        if let Some(w) = &c.working_directory {
            args.extend(["--workdir".into(), w.clone()]);
        }
        if let Some(u) = &c.user {
            args.extend(["--user".into(), u.clone()]);
        }
        if c.privileged {
            args.push("--privileged".into());
        }
        if c.read_only_root {
            args.push("--read-only".into());
        }
        if c.init {
            args.push("--init".into());
        }
        if c.interactive {
            args.push("-i".into());
        }
        if c.tty {
            args.push("-t".into());
        }
        for cap in &c.cap_add {
            args.extend(["--cap-add".into(), cap.clone()]);
        }
        for cap in &c.cap_drop {
            args.extend(["--cap-drop".into(), cap.clone()]);
        }
        for (k, v) in &c.sysctls {
            args.extend(["--sysctl".into(), format!("{k}={v}")]);
        }
        for (path, size, opts) in &c.tmpfs {
            let mut spec = format!("{path}:size={size}m");
            for o in opts {
                spec.push(',');
                spec.push_str(o);
            }
            args.extend(["--tmpfs".into(), spec]);
        }
        if let Some(shm) = c.shared_memory_mib {
            args.extend(["--shm-size".into(), format!("{shm}m")]);
        }
        for (name, soft, hard) in &c.ulimits {
            args.extend(["--ulimit".into(), format!("{name}={soft}:{hard}")]);
        }
        for (k, v) in &c.labels {
            args.extend(["--label".into(), format!("{k}={v}")]);
        }
        args.extend(Self::labels(task, &c.name));
        if let Some(h) = &c.health_check {
            let cmd = match h.command.first().map(String::as_str) {
                Some("CMD-SHELL") => h.command[1..].join(" "),
                Some("CMD") => h.command[1..].iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" "),
                _ => h.command.join(" "),
            };
            args.extend([
                "--health-cmd".into(),
                cmd,
                "--health-interval".into(),
                format!("{}s", h.interval.max(1)),
                "--health-timeout".into(),
                format!("{}s", h.timeout.max(1)),
                "--health-retries".into(),
                h.retries.max(1).to_string(),
                "--health-start-period".into(),
                format!("{}s", h.start_period.max(0)),
            ]);
        }
        args.extend(["--stop-timeout".into(), c.stop_timeout.max(0).to_string()]);
        if let Some(ep) = &c.entry_point {
            // Docker takes the entrypoint's first word as --entrypoint and
            // the rest as leading arguments.
            if let Some((first, rest)) = ep.split_first() {
                args.extend(["--entrypoint".into(), first.clone()]);
                args.push(c.image.clone());
                args.extend(rest.iter().cloned());
            } else {
                args.extend(["--entrypoint".into(), String::new(), c.image.clone()]);
            }
        } else {
            args.push(c.image.clone());
        }
        if let Some(cmd) = &c.command {
            args.extend(cmd.iter().cloned());
        }
        let id = self.run(&args).await?;
        let runtime_id = id.lines().last().unwrap_or_default().to_string();
        if matches!(task.network, TaskNetwork::Bridge) {
            self.join_credentials_network(&runtime_id).await;
        }
        let mut bindings = Vec::new();
        match task.network {
            TaskNetwork::Bridge => {
                for p in &c.ports {
                    let proto = if p.protocol == "udp" { "udp" } else { "tcp" };
                    let spec = format!("{}/{proto}", p.container_port);
                    if let Ok(out) = self.run_str(&["port", &runtime_id, &spec]).await {
                        if let Some(line) = out.lines().find(|l| l.starts_with("0.0.0.0:")).or(out.lines().next()) {
                            if let Some((ip, port)) = line.rsplit_once(':') {
                                bindings.push((
                                    p.container_port,
                                    port.parse().unwrap_or(0),
                                    p.protocol.clone(),
                                    ip.trim_matches(['[', ']']).to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            TaskNetwork::Host => {
                for p in &c.ports {
                    bindings.push((p.container_port, p.container_port, p.protocol.clone(), "0.0.0.0".into()));
                }
            }
            _ => {}
        }
        Ok(StartedContainer { runtime_id, bindings, image_digest: None })
    }

    async fn wait(&self, runtime_id: &str) -> Result<i32, BackendError> {
        let out = self.run_str(&["wait", runtime_id]).await?;
        out.lines().last().unwrap_or_default().trim().parse().map_err(|_| BackendError(format!("docker wait: {out}")))
    }

    async fn health(&self, runtime_id: &str) -> String {
        let out = self
            .run_str(&["inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{end}}", runtime_id])
            .await
            .unwrap_or_default();
        match out.as_str() {
            "healthy" => "HEALTHY".into(),
            "unhealthy" => "UNHEALTHY".into(),
            _ => "UNKNOWN".into(),
        }
    }

    async fn stop(&self, runtime_id: &str, timeout_secs: i32) -> Result<(), BackendError> {
        self.run_str(&["stop", "-t", &timeout_secs.max(0).to_string(), runtime_id]).await.map(drop)
    }

    async fn follow_logs(&self, runtime_id: &str) -> Option<tokio::sync::mpsc::Receiver<LogLine>> {
        let mut child = Command::new(&self.cli)
            .args(["logs", "-f", "--timestamps", runtime_id])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let parse = |line: String| -> LogLine {
            match line.split_once(' ') {
                Some((ts, rest)) => match chrono::DateTime::parse_from_rfc3339(ts) {
                    Ok(t) => LogLine { timestamp_ms: t.timestamp_millis(), message: rest.to_string() },
                    Err(_) => LogLine { timestamp_ms: chrono::Utc::now().timestamp_millis(), message: line },
                },
                None => LogLine { timestamp_ms: chrono::Utc::now().timestamp_millis(), message: line },
            }
        };
        if let Some(out) = child.stdout.take() {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(out).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    if tx.send(parse(l)).await.is_err() {
                        break;
                    }
                }
            });
        }
        if let Some(err) = child.stderr.take() {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(err).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    if tx.send(parse(l)).await.is_err() {
                        break;
                    }
                }
            });
        }
        tokio::spawn(async move {
            let _ = child.wait().await;
            drop(tx);
        });
        Some(rx)
    }

    async fn exec(&self, runtime_id: &str, command: &str) -> Result<String, BackendError> {
        self.run_str(&["exec", runtime_id, "/bin/sh", "-c", command]).await
    }

    async fn shell(
        &self,
        runtime_id: &str,
        script: &str,
        stdin: Option<&[u8]>,
    ) -> Result<Option<mws_core::shell::Output>, BackendError> {
        use tokio::io::AsyncWriteExt;
        let mut args = vec!["exec"];
        if stdin.is_some() {
            args.push("-i");
        }
        args.extend(["-u", "0", runtime_id, "/bin/sh", "-c", script]);
        let mut child = tokio::process::Command::new(&self.cli)
            .args(&args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(data).await.map_err(|e| BackendError(format!("writing to {runtime_id}: {e}")))?;
            drop(pipe);
        }
        let out = child.wait_with_output().await.map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        Ok(Some(mws_core::shell::Output {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }))
    }

    async fn cleanup(&self, task: &TaskSpec, handle: &str, runtime_ids: &[String]) {
        for id in runtime_ids {
            let _ = self.run_str(&["rm", "-f", "-v", id]).await;
        }
        match task.network {
            TaskNetwork::Awsvpc { .. } => {
                let _ = self.run_str(&["rm", "-f", handle]).await;
            }
            TaskNetwork::Bridge => {
                let _ = self.run_str(&["network", "rm", handle]).await;
            }
            _ => {}
        }
        for v in &task.volumes {
            let _ = self.run_str(&["volume", "rm", "-f", &Self::volume_name(&task.task_id, v)]).await;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn registries_are_keyed_as_docker_keys_them() {
        assert_eq!(super::registry_of("nginx"), "https://index.docker.io/v1/");
        assert_eq!(super::registry_of("library/nginx:1"), "https://index.docker.io/v1/");
        assert_eq!(super::registry_of("ghcr.io/org/app:1"), "ghcr.io");
        assert_eq!(super::registry_of("localhost:5000/app"), "localhost:5000");
    }
}
