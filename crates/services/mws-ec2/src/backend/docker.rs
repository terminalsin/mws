//! Instances as containers, driven through the Docker CLI (or anything that
//! speaks its command line, such as Podman: set `MWS_EC2_DOCKER=podman`).
//!
//! Each VPC becomes a bridge network `mws-<vpc-id>` on the VPC's CIDR, so an
//! instance's container gets the instance's private IP address and can
//! reach the other instances in its VPC, but not those in other VPCs. When
//! the CIDR overlaps a network the host already has, the network falls back
//! to an address range Docker picks.
//!
//! Security groups, network ACLs and route tables filter real traffic: MWS
//! writes them as iptables rules into each instance's network namespace,
//! from a short-lived helper container that joins it
//! (`MWS_EC2_NETFILTER_IMAGE`, any image with `iptables-restore`; the
//! instance itself gets no extra capabilities and cannot change them).
//! `MWS_EC2_FIREWALL=off` leaves traffic unfiltered.
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

use super::{
    AclRule, AllowRule, BackendError, CommandOutput, ComputeBackend, Firewall, LaunchSpec, Launched, Protocol,
    VolumeMount,
};

/// The default helper image: a small Alpine image with iptables.
pub const DEFAULT_NETFILTER_IMAGE: &str = "rancher/klipper-lb:v0.4.13";

/// What the container runs for OS images. The user data and key arrive as
/// environment variables.
const BOOT_SCRIPT: &str = r#"
rm -f /run/mws/network-ready 2>/dev/null
if [ -n "$MWS_WAIT_NETWORK" ]; then
  i=0
  while [ ! -f /run/mws/network-ready ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done
fi
mkdir -p /var/lib/cloud/instance /var/log 2>/dev/null
if [ -n "$MWS_SSH_PUBLIC_KEY" ]; then
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  grep -qxF "$MWS_SSH_PUBLIC_KEY" /root/.ssh/authorized_keys 2>/dev/null || echo "$MWS_SSH_PUBLIC_KEY" >> /root/.ssh/authorized_keys
fi
if [ -n "$MWS_BOOT_HOOKS" ]; then
  echo "$MWS_BOOT_HOOKS" | base64 -d > /var/lib/cloud/instance/mws-boot-hooks.sh 2>/dev/null
  sh /var/lib/cloud/instance/mws-boot-hooks.sh
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
    /// The helper image that writes instances' firewall rules; `None` when
    /// traffic is not filtered.
    netfilter_image: Option<String>,
    /// The address `host-gateway` stands for (where MWS listens), once
    /// looked up.
    host_gateway: std::sync::Mutex<Option<String>>,
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
        let off = std::env::var("MWS_EC2_FIREWALL")
            .is_ok_and(|v| matches!(v.to_ascii_lowercase().as_str(), "off" | "false" | "0" | "no"));
        let image = std::env::var("MWS_EC2_NETFILTER_IMAGE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_NETFILTER_IMAGE.to_string());
        Self {
            cli: cli.into(),
            netfilter_image: (!off).then_some(image),
            host_gateway: std::sync::Mutex::new(None),
            helper_image: std::env::var("MWS_EC2_HELPER_IMAGE")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "alpine:3.20".into()),
            networks: tokio::sync::Mutex::new(()),
            specs: Default::default(),
        }
    }

    /// Run the CLI with `input` on its standard input.
    async fn run_with_input(&self, args: &[String], input: &str) -> Result<String, BackendError> {
        use tokio::io::AsyncWriteExt;
        let mut child = Command::new(&self.cli)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|e| BackendError(format!("writing to {}: {e}", self.cli)))?;
        }
        let out = child.wait_with_output().await.map_err(|e| BackendError(format!("running {}: {e}", self.cli)))?;
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

    /// The host's address as containers see it (`host-gateway`).
    async fn host_gateway(&self, image: &str) -> Option<String> {
        if let Some(ip) = self.host_gateway.lock().expect("lock").clone() {
            return Some(ip);
        }
        let args: Vec<String> =
            ["run", "--rm", "--add-host", "mws-host-gateway:host-gateway", "--entrypoint", "cat", image, "/etc/hosts"]
                .map(String::from)
                .to_vec();
        let hosts = self.run(&args).await.ok()?;
        let ip = hosts
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some("mws-host-gateway"))
            .and_then(|l| l.split_whitespace().next())
            .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())?
            .to_string();
        *self.host_gateway.lock().expect("lock") = Some(ip.clone());
        Some(ip)
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
        for m in &spec.extras.mounts {
            args.push("-v".into());
            args.push(format!("{}:{}", m.source.display(), m.target));
        }
        for c in &spec.extras.capabilities {
            args.push("--cap-add".into());
            args.push(c.clone());
        }
        for o in &spec.extras.security_options {
            args.push("--security-opt".into());
            args.push(o.clone());
        }
        if self.netfilter_image.is_some() {
            args.push("-e".into());
            args.push("MWS_WAIT_NETWORK=1".into());
        }
        if spec.boot {
            use base64::Engine;
            if !spec.extras.boot_hooks.is_empty() {
                let hooks = spec.extras.boot_hooks.join("\n");
                args.push("-e".into());
                args.push(format!("MWS_BOOT_HOOKS={}", base64::engine::general_purpose::STANDARD.encode(hooks)));
            }
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

    fn filters_traffic(&self) -> bool {
        self.netfilter_image.is_some()
    }

    async fn apply_firewall(&self, handle: &str, firewall: &Firewall) -> Result<(), BackendError> {
        let Some(image) = &self.netfilter_image else { return Ok(()) };
        let mut gateways: Vec<String> = self
            .run(&[
                "inspect".into(),
                "--format".into(),
                "{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}".into(),
                handle.into(),
            ])
            .await?
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if let Some(ip) = self.host_gateway(image).await {
            gateways.push(ip);
        }
        gateways.sort();
        gateways.dedup();
        let rules = render_iptables(firewall, &gateways);
        let args: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "-i".into(),
            "--network".into(),
            format!("container:{handle}"),
            "--cap-add".into(),
            "NET_ADMIN".into(),
            "--cap-add".into(),
            "NET_RAW".into(),
            "--label".into(),
            "mws.ec2.netfilter=1".into(),
            "--entrypoint".into(),
            "/bin/sh".into(),
            image.clone(),
            "-c".into(),
            "cat > /tmp/rules && (iptables-restore < /tmp/rules || iptables-legacy-restore < /tmp/rules)".into(),
        ];
        self.run_with_input(&args, &rules).await.map(drop)
    }

    async fn network_ready(&self, handle: &str) -> Result<(), BackendError> {
        self.run(&[
            "exec".into(),
            handle.into(),
            "/bin/sh".into(),
            "-c".into(),
            "mkdir -p /run/mws && touch /run/mws/network-ready".into(),
        ])
        .await
        .map(drop)
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

/// iptables match arguments for a protocol (destination ports).
fn protocol_args(p: &Protocol) -> String {
    match p {
        Protocol::All => String::new(),
        Protocol::Tcp(a, b) | Protocol::Udp(a, b) => {
            let name = if matches!(p, Protocol::Tcp(..)) { "tcp" } else { "udp" };
            if *a == 0 && *b == 65535 {
                format!(" -p {name}")
            } else if a == b {
                format!(" -p {name} --dport {a}")
            } else {
                format!(" -p {name} --dport {a}:{b}")
            }
        }
        Protocol::Icmp(None, _) => " -p icmp".into(),
        Protocol::Icmp(Some(t), None) => format!(" -p icmp --icmp-type {t}"),
        Protocol::Icmp(Some(t), Some(c)) => format!(" -p icmp --icmp-type {t}/{c}"),
        Protocol::Number(n) => format!(" -p {n}"),
    }
}

fn allow_lines(out: &mut String, chain: &str, dir: &str, rules: &[AllowRule]) {
    for r in rules {
        out.push_str(&format!("-A {chain} {dir} {}{} -j ACCEPT\n", r.cidr, protocol_args(&r.protocol)));
    }
}

fn acl_lines(out: &mut String, chain: &str, dir: &str, rules: &[AclRule]) {
    for r in rules {
        let target = if r.allow { "RETURN" } else { "DROP" };
        out.push_str(&format!("-A {chain} {dir} {}{} -j {target}\n", r.cidr, protocol_args(&r.protocol)));
    }
    out.push_str(&format!("-A {chain} -j DROP\n"));
}

/// The `iptables-restore` input for an instance's firewall. `gateways` are
/// where MWS is reached (the network gateway and the host gateway).
pub fn render_iptables(fw: &Firewall, gateways: &[String]) -> String {
    let mut out = String::from(
        "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n\
         :MWS-ACL-IN - [0:0]\n:MWS-ACL-OUT - [0:0]\n:MWS-SG-IN - [0:0]\n:MWS-SG-OUT - [0:0]\n:MWS-ROUTE - [0:0]\n",
    );
    // Loopback, MWS (API and instance metadata) and DNS are never filtered.
    out.push_str("-A INPUT -i lo -j ACCEPT\n-A OUTPUT -o lo -j ACCEPT\n");
    for gw in gateways {
        match fw.service_port {
            Some(port) => {
                out.push_str(&format!("-A INPUT -s {gw}/32 -p tcp --sport {port} -j ACCEPT\n"));
                out.push_str(&format!("-A OUTPUT -d {gw}/32 -p tcp --dport {port} -j ACCEPT\n"));
            }
            None => {
                out.push_str(&format!("-A INPUT -s {gw}/32 -j ACCEPT\n-A OUTPUT -d {gw}/32 -j ACCEPT\n"));
            }
        }
    }
    for p in ["udp", "tcp"] {
        out.push_str(&format!("-A INPUT -p {p} --sport 53 -j ACCEPT\n-A OUTPUT -p {p} --dport 53 -j ACCEPT\n"));
    }
    // The network ACL judges every packet crossing the subnet boundary,
    // replies included.
    out.push_str(&format!("-A INPUT ! -s {} -j MWS-ACL-IN\n", fw.subnet_cidr));
    out.push_str(&format!("-A OUTPUT ! -d {} -j MWS-ACL-OUT\n", fw.subnet_cidr));
    // Security groups are stateful.
    out.push_str("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A INPUT -j MWS-SG-IN\n");
    out.push_str(
        "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A OUTPUT -j MWS-ROUTE\n-A OUTPUT -j MWS-SG-OUT\n",
    );
    acl_lines(&mut out, "MWS-ACL-IN", "-s", &fw.acl_ingress);
    acl_lines(&mut out, "MWS-ACL-OUT", "-d", &fw.acl_egress);
    allow_lines(&mut out, "MWS-SG-IN", "-s", &fw.ingress);
    allow_lines(&mut out, "MWS-SG-OUT", "-d", &fw.egress);
    // Inside the VPC the local route always applies.
    for cidr in &fw.vpc_cidrs {
        out.push_str(&format!("-A MWS-ROUTE -d {cidr} -j RETURN\n"));
    }
    for r in &fw.routes {
        let target = if r.reachable { "RETURN" } else { "DROP" };
        out.push_str(&format!("-A MWS-ROUTE -d {} -j {target}\n", r.cidr));
    }
    out.push_str("-A MWS-ROUTE -j DROP\nCOMMIT\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::RouteRule;

    #[test]
    fn renders_security_groups_acls_and_routes() {
        let fw = Firewall {
            subnet_cidr: "10.0.1.0/24".into(),
            vpc_cidrs: vec!["10.0.0.0/16".into()],
            ingress: vec![AllowRule { protocol: Protocol::Tcp(80, 80), cidr: "10.0.2.5/32".into() }],
            egress: vec![AllowRule { protocol: Protocol::All, cidr: "0.0.0.0/0".into() }],
            acl_ingress: vec![AclRule {
                protocol: Protocol::Icmp(Some(8), None),
                cidr: "0.0.0.0/0".into(),
                allow: false,
            }],
            acl_egress: vec![AclRule { protocol: Protocol::Udp(1024, 65535), cidr: "0.0.0.0/0".into(), allow: true }],
            routes: vec![RouteRule { cidr: "0.0.0.0/0".into(), reachable: true }],
            service_port: Some(4566),
        };
        let rules = render_iptables(&fw, &["172.17.0.1".into()]);
        assert!(rules.contains("-A OUTPUT -d 172.17.0.1/32 -p tcp --dport 4566 -j ACCEPT"));
        assert!(rules.contains("-A MWS-SG-IN -s 10.0.2.5/32 -p tcp --dport 80 -j ACCEPT"));
        assert!(rules.contains("-A MWS-SG-OUT -d 0.0.0.0/0 -j ACCEPT"));
        assert!(rules.contains("-A MWS-ACL-IN -s 0.0.0.0/0 -p icmp --icmp-type 8 -j DROP"));
        assert!(rules.contains("-A MWS-ACL-OUT -d 0.0.0.0/0 -p udp --dport 1024:65535 -j RETURN"));
        assert!(rules.contains("-A MWS-ROUTE -d 10.0.0.0/16 -j RETURN\n-A MWS-ROUTE -d 0.0.0.0/0 -j RETURN"));
        assert!(rules.ends_with("-A MWS-ROUTE -j DROP\nCOMMIT\n"));
    }
}
