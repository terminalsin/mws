//! Instances as containers, driven through the Docker CLI (or anything that
//! speaks its command line, such as Podman: set `MWS_EC2_DOCKER=podman`).
//!
//! Each VPC becomes a bridge network `mws-<vpc-id>` on the VPC's CIDR, so an
//! instance's container gets the instance's private IP address and can
//! reach the other instances in its VPC, but not those in other VPCs. When
//! the CIDR overlaps a network the host already has, the network falls back
//! to an address range Docker picks.
//!
//! OS images (Amazon Linux, Ubuntu, ...) boot through a small init script
//! that does what cloud-init would: install the key pair's public key, run
//! the user data once (its output goes to the console), then idle until
//! stopped.

use std::process::Stdio;

use tokio::process::Command;

use super::{BackendError, CommandOutput, ComputeBackend, LaunchSpec, Launched};

/// What the container runs for OS images. The user data and key arrive as
/// environment variables.
const BOOT_SCRIPT: &str = r#"
mkdir -p /var/lib/cloud/instance /var/log 2>/dev/null
if [ -n "$MWS_SSH_PUBLIC_KEY" ]; then
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  grep -qxF "$MWS_SSH_PUBLIC_KEY" /root/.ssh/authorized_keys 2>/dev/null || echo "$MWS_SSH_PUBLIC_KEY" >> /root/.ssh/authorized_keys
fi
if [ -n "$MWS_USER_DATA" ] && [ ! -f /var/lib/cloud/instance/boot-finished ]; then
  echo "$MWS_USER_DATA" | base64 -d > /var/lib/cloud/instance/user-data.txt 2>/dev/null
  if head -c 2 /var/lib/cloud/instance/user-data.txt | grep -q '#!'; then
    chmod +x /var/lib/cloud/instance/user-data.txt
    /var/lib/cloud/instance/user-data.txt 2>&1 | tee -a /var/log/cloud-init-output.log
  fi
fi
touch /var/lib/cloud/instance/boot-finished
echo "Cloud-init finished"
trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
"#;

#[derive(Debug)]
pub struct DockerBackend {
    cli: String,
    /// Serializes network creation, so concurrent launches into one VPC do
    /// not race to create its network.
    networks: tokio::sync::Mutex<()>,
}

impl DockerBackend {
    pub fn new(cli: impl Into<String>) -> Self {
        Self { cli: cli.into(), networks: tokio::sync::Mutex::new(()) }
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

    fn network_name(vpc_id: &str) -> String {
        format!("mws-{vpc_id}")
    }

    /// Make sure the VPC's network exists; `true` when it uses the VPC's
    /// own CIDR (so instances can keep their private IPs).
    async fn ensure_network(&self, vpc_id: &str, cidr: &str) -> Result<bool, BackendError> {
        let _guard = self.networks.lock().await;
        let name = Self::network_name(vpc_id);
        let inspect = |n: &str| {
            vec![
                "network".to_string(),
                "inspect".into(),
                "--format".into(),
                "{{range .IPAM.Config}}{{.Subnet}} {{end}}".into(),
                n.to_string(),
            ]
        };
        if let Ok(subnets) = self.run(&inspect(&name)).await {
            return Ok(subnets.split_whitespace().any(|s| s == cidr));
        }
        let mut args: Vec<String> = vec![
            "network".into(),
            "create".into(),
            "--driver".into(),
            "bridge".into(),
            "--label".into(),
            format!("mws.ec2.vpc={vpc_id}"),
        ];
        let with_subnet = [args.clone(), vec!["--subnet".into(), cidr.into(), name.clone()]].concat();
        if self.run(&with_subnet).await.is_ok() {
            return Ok(true);
        }
        // The CIDR may be held by an unused network of an earlier MWS run
        // (VPCs restart with the same default CIDR): prune those and retry.
        let prune = ["network", "prune", "--force", "--filter", "label=mws.ec2.vpc"].map(String::from);
        if self.run(&prune).await.is_ok() && self.run(&with_subnet).await.is_ok() {
            return Ok(true);
        }
        args.push(name);
        self.run(&args).await?;
        Ok(false)
    }
}

#[async_trait::async_trait]
impl ComputeBackend for DockerBackend {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn launch(&self, spec: &LaunchSpec) -> Result<Launched, BackendError> {
        let own_cidr = self.ensure_network(&spec.network.vpc_id, &spec.network.cidr_block).await?;
        let name = format!("mws-ec2-{}", spec.instance_id);
        // Leftovers of an earlier run with the same id (restored state).
        let _ = self.run(&["rm".into(), "-f".into(), name.clone()]).await;
        let cpus = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            name,
            "--hostname".into(),
            spec.hostname.clone(),
            "--network".into(),
            Self::network_name(&spec.network.vpc_id),
            "--add-host".into(),
            "host.docker.internal:host-gateway".into(),
            "--cpus".into(),
            spec.vcpus.clamp(1, cpus).to_string(),
            "--memory".into(),
            format!("{}m", spec.memory_mib.max(64)),
            "--label".into(),
            format!("mws.ec2.instance={}", spec.instance_id),
            "--label".into(),
            format!("mws.ec2.account={}", spec.account_id),
            "--label".into(),
            format!("mws.ec2.region={}", spec.region),
            "--label".into(),
            format!("mws.ec2.instance-type={}", spec.instance_type),
        ];
        if own_cidr {
            args.push("--ip".into());
            args.push(spec.private_ip.clone());
        }
        for (k, v) in &spec.env {
            args.push("-e".into());
            args.push(format!("{k}={v}"));
        }
        if spec.boot {
            use base64::Engine;
            if let Some(data) = &spec.user_data {
                args.push("-e".into());
                args.push(format!("MWS_USER_DATA={}", base64::engine::general_purpose::STANDARD.encode(data)));
            }
            if let Some(key) = &spec.ssh_public_key {
                args.push("-e".into());
                args.push(format!("MWS_SSH_PUBLIC_KEY={key}"));
            }
            args.extend(["--entrypoint".into(), "/bin/sh".into(), spec.image.clone(), "-c".into(), BOOT_SCRIPT.into()]);
        } else {
            args.push(spec.image.clone());
        }
        let id = self.run(&args).await?;
        Ok(Launched { handle: id.lines().last().unwrap_or_default().to_string() })
    }

    async fn start(&self, handle: &str) -> Result<(), BackendError> {
        self.run(&["start".into(), handle.into()]).await.map(drop)
    }

    async fn stop(&self, handle: &str, force: bool) -> Result<(), BackendError> {
        if force {
            self.run(&["kill".into(), handle.into()]).await.map(drop)
        } else {
            self.run(&["stop".into(), "-t".into(), "30".into(), handle.into()]).await.map(drop)
        }
    }

    async fn reboot(&self, handle: &str) -> Result<(), BackendError> {
        self.run(&["restart".into(), "-t".into(), "10".into(), handle.into()]).await.map(drop)
    }

    async fn terminate(&self, handle: &str) -> Result<(), BackendError> {
        self.run(&["rm".into(), "-f".into(), "-v".into(), handle.into()]).await.map(drop)
    }

    async fn console_output(&self, handle: &str) -> Result<String, BackendError> {
        let out = Command::new(&self.cli)
            .args(["logs", handle])
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if !out.status.success() {
            return Err(BackendError(String::from_utf8_lossy(&out.stderr).trim().to_string()));
        }
        // The console interleaves both streams; logs gives them apart.
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(text)
    }

    async fn create_image(&self, handle: &str, image_ref: &str) -> Result<String, BackendError> {
        self.run(&["commit".into(), handle.into(), image_ref.into()]).await?;
        Ok(image_ref.to_string())
    }

    async fn exec(&self, handle: &str, script: &str) -> Result<Option<CommandOutput>, BackendError> {
        // Prefer bash, as the SSM agent does; small images only have sh.
        let out = Command::new(&self.cli)
            .args([
                "exec",
                "-u",
                "0",
                handle,
                "/bin/sh",
                "-c",
                "if command -v bash >/dev/null 2>&1; then exec bash -c \"$0\"; else exec sh -c \"$0\"; fi",
                script,
            ])
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        Ok(Some(CommandOutput {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }))
    }

    async fn delete_image(&self, image_ref: &str) -> Result<(), BackendError> {
        self.run(&["rmi".into(), image_ref.into()]).await.map(drop)
    }

    async fn delete_network(&self, vpc_id: &str) -> Result<(), BackendError> {
        let _guard = self.networks.lock().await;
        let name = Self::network_name(vpc_id);
        if self.run(&["network".into(), "inspect".into(), name.clone()]).await.is_err() {
            return Ok(());
        }
        self.run(&["network".into(), "rm".into(), name]).await.map(drop)
    }
}
