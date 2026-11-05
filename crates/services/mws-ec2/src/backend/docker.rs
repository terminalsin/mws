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
//!
//! EBS data volumes are Docker volumes (`mws-ebs-<volume-id>`), mounted in
//! the instance's container at the volume's device name (`/dev/sdf` is a
//! directory holding the volume's files). Snapshots are Docker volumes
//! too, copied with a small helper container (`MWS_EC2_HELPER_IMAGE`,
//! default `alpine:3.20`). Containers cannot gain mounts while they run,
//! so attaching or detaching a volume commits the container's disk and
//! recreates it with the new mounts: processes restart, files stay.

use std::process::Stdio;

use tokio::process::Command;

use std::collections::HashMap;

use super::{BackendError, ComputeBackend, LaunchSpec, Launched, VolumeMount};

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
    helper_image: String,
    /// Serializes network creation, so concurrent launches into one VPC do
    /// not race to create its network.
    networks: tokio::sync::Mutex<()>,
    /// How each container was launched, by handle, so it can be recreated
    /// with other volumes.
    specs: std::sync::Mutex<HashMap<String, LaunchSpec>>,
}

impl DockerBackend {
    pub fn new(cli: impl Into<String>) -> Self {
        Self {
            cli: cli.into(),
            helper_image: std::env::var("MWS_EC2_HELPER_IMAGE")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "alpine:3.20".into()),
            networks: tokio::sync::Mutex::new(()),
            specs: Default::default(),
        }
    }

    fn volume_name(id: &str) -> String {
        format!("mws-ebs-{id}")
    }

    async fn volume_exists(&self, id: &str) -> bool {
        self.run(&["volume".into(), "inspect".into(), Self::volume_name(id)]).await.is_ok()
    }

    async fn ensure_volume(&self, id: &str) -> Result<(), BackendError> {
        self.run(&[
            "volume".into(),
            "create".into(),
            "--label".into(),
            format!("mws.ec2.ebs={id}"),
            Self::volume_name(id),
        ])
        .await
        .map(drop)
    }

    /// Copy one Docker volume's files into another.
    async fn copy_volume(&self, from: &str, to: &str) -> Result<(), BackendError> {
        self.run(&[
            "run".into(),
            "--rm".into(),
            "--network".into(),
            "none".into(),
            "-v".into(),
            format!("{}:/from:ro", Self::volume_name(from)),
            "-v".into(),
            format!("{}:/to", Self::volume_name(to)),
            "--entrypoint".into(),
            "/bin/sh".into(),
            self.helper_image.clone(),
            "-c".into(),
            "cp -a /from/. /to/".into(),
        ])
        .await
        .map(drop)
    }

    /// Create (and with `start`, run) the container for `spec`.
    async fn create_container(&self, spec: &LaunchSpec, start: bool) -> Result<String, BackendError> {
        let own_cidr = self.ensure_network(&spec.network.vpc_id, &spec.network.cidr_block).await?;
        let name = format!("mws-ec2-{}", spec.instance_id);
        // Leftovers of an earlier run with the same id (restored state).
        let _ = self.run(&["rm".into(), "-f".into(), name.clone()]).await;
        for v in &spec.volumes {
            if !self.volume_exists(&v.volume_id).await {
                self.ensure_volume(&v.volume_id).await?;
                if let Some(snap) = &v.snapshot_id {
                    if self.volume_exists(snap).await {
                        self.copy_volume(snap, &v.volume_id).await?;
                    }
                }
            }
        }
        let cpus = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
        let mut args: Vec<String> = if start { vec!["run".into(), "-d".into()] } else { vec!["create".into()] };
        args.extend([
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
        ]);
        if own_cidr {
            args.push("--ip".into());
            args.push(spec.private_ip.clone());
        }
        for v in &spec.volumes {
            args.push("-v".into());
            args.push(format!("{}:{}", Self::volume_name(&v.volume_id), v.device));
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
        let handle = id.lines().last().unwrap_or_default().to_string();
        self.specs.lock().expect("specs lock poisoned").insert(handle.clone(), spec.clone());
        Ok(handle)
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

    /// The image an instance's disk is committed to when its volumes
    /// change.
    fn volumes_image(instance_id: &str) -> String {
        format!("mws-ec2-{instance_id}:volumes")
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
        Ok(Launched { handle: self.create_container(spec, true).await? })
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
        let spec = self.specs.lock().expect("specs lock poisoned").remove(handle);
        self.run(&["rm".into(), "-f".into(), "-v".into(), handle.into()]).await?;
        if let Some(spec) = spec {
            let _ = self.run(&["rmi".into(), Self::volumes_image(&spec.instance_id)]).await;
        }
        Ok(())
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

    async fn delete_image(&self, image_ref: &str) -> Result<(), BackendError> {
        self.run(&["rmi".into(), image_ref.into()]).await.map(drop)
    }

    async fn create_volume(&self, volume_id: &str, snapshot_id: Option<&str>) -> Result<(), BackendError> {
        self.ensure_volume(volume_id).await?;
        if let Some(snap) = snapshot_id {
            if self.volume_exists(snap).await {
                self.copy_volume(snap, volume_id).await?;
            }
        }
        Ok(())
    }

    async fn delete_volume(&self, volume_id: &str) -> Result<(), BackendError> {
        if !self.volume_exists(volume_id).await {
            return Ok(());
        }
        self.run(&["volume".into(), "rm".into(), "-f".into(), Self::volume_name(volume_id)]).await.map(drop)
    }

    async fn create_snapshot(&self, volume_id: &str, snapshot_id: &str) -> Result<(), BackendError> {
        self.ensure_volume(snapshot_id).await?;
        if self.volume_exists(volume_id).await {
            self.copy_volume(volume_id, snapshot_id).await?;
        }
        Ok(())
    }

    async fn copy_snapshot(&self, source_id: &str, snapshot_id: &str) -> Result<(), BackendError> {
        if self.volume_exists(source_id).await {
            self.ensure_volume(snapshot_id).await?;
            self.copy_volume(source_id, snapshot_id).await?;
        }
        Ok(())
    }

    async fn delete_snapshot(&self, snapshot_id: &str) -> Result<(), BackendError> {
        self.delete_volume(snapshot_id).await
    }

    async fn set_volumes(&self, handle: &str, volumes: &[VolumeMount]) -> Result<Option<String>, BackendError> {
        let Some(mut spec) = self.specs.lock().expect("specs lock poisoned").get(handle).cloned() else {
            return Err(BackendError(format!(
                "container {handle} was not started by this MWS process; its volumes change when it is launched again"
            )));
        };
        if spec.volumes == volumes {
            return Ok(None);
        }
        let running =
            self.run(&["inspect".into(), "--format".into(), "{{.State.Running}}".into(), handle.into()]).await?
                == "true";
        let image = Self::volumes_image(&spec.instance_id);
        self.run(&["commit".into(), handle.into(), image.clone()]).await?;
        self.run(&["rm".into(), "-f".into(), handle.into()]).await?;
        self.specs.lock().expect("specs lock poisoned").remove(handle);
        spec.image = image;
        spec.volumes = volumes.to_vec();
        Ok(Some(self.create_container(&spec, running).await?))
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
