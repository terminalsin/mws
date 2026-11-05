//! A k3s server container per cluster, driven through the Docker CLI (or
//! one that speaks its command line, such as Podman).
//!
//! The container runs `k3s server --disable-agent`: the API server,
//! controller manager and scheduler on k3s's SQLite datastore, in a volume
//! of its own so upgrades keep the cluster's objects. No kubelet runs, so
//! the container needs no privileges. The API server authenticates bearer
//! tokens and authorizes requests through webhooks that MWS answers.

use std::process::Stdio;
use std::time::Duration;

use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{k3s_image, ControlPlane, ControlPlaneError, ControlPlaneSpec, NodeObject, Running};

const LABEL: &str = "mws.eks.cluster";
const DATA: &str = "/var/lib/rancher/k3s";

pub struct K3s {
    cli: String,
    /// Host address published API server ports bind to.
    bind: String,
}

fn webhook_config(url: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: mws\n  cluster:\n    server: {url}\nusers:\n- name: kube-apiserver\ncontexts:\n- name: mws\n  context:\n    cluster: mws\n    user: kube-apiserver\ncurrent-context: mws\n"
    )
}

impl K3s {
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

    async fn run(&self, args: &[String], input: Option<&[u8]>) -> Result<String, ControlPlaneError> {
        let mut child = Command::new(&self.cli)
            .args(args)
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ControlPlaneError(format!("running {}: {e}", self.cli)))?;
        if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
            let _ = stdin.write_all(data).await;
        }
        let out =
            child.wait_with_output().await.map_err(|e| ControlPlaneError(format!("running {}: {e}", self.cli)))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(ControlPlaneError(format!(
                "{} {} failed: {}",
                self.cli,
                args.first().map(String::as_str).unwrap_or_default(),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    async fn args(&self, args: &[&str]) -> Result<String, ControlPlaneError> {
        self.run(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>(), None).await
    }

    async fn kubectl(&self, id: &str, args: &[&str], input: Option<&[u8]>) -> Result<String, ControlPlaneError> {
        let mut all: Vec<String> = vec!["exec".into()];
        if input.is_some() {
            all.push("-i".into());
        }
        all.extend([id.to_string(), "kubectl".into()]);
        all.extend(args.iter().map(|s| s.to_string()));
        self.run(&all, input).await
    }

    async fn running(&self, id: &str) -> bool {
        self.args(&["inspect", "--format", "{{.State.Running}}", id]).await.is_ok_and(|s| s == "true")
    }

    async fn start(&self, spec: &ControlPlaneSpec) -> Result<(), ControlPlaneError> {
        let _ = self.args(&["rm", "-f", &spec.id]).await;
        let script = "mkdir -p /etc/mws && printf '%s' \"$MWS_AUTHN\" > /etc/mws/authn.yaml \
            && printf '%s' \"$MWS_AUTHZ\" > /etc/mws/authz.yaml && exec /bin/k3s server \"$@\"";
        let args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            spec.id.clone(),
            "--label".into(),
            format!("{LABEL}={}", spec.cluster_arn),
            "--add-host".into(),
            "host.docker.internal:host-gateway".into(),
            "-p".into(),
            format!("{}::6443", self.bind),
            "-v".into(),
            format!("{}:{DATA}", spec.id),
            "-e".into(),
            format!("MWS_AUTHN={}", webhook_config(&spec.authenticate_url)),
            "-e".into(),
            format!("MWS_AUTHZ={}", webhook_config(&spec.authorize_url)),
            "--entrypoint".into(),
            "/bin/sh".into(),
            k3s_image(&spec.version),
            "-c".into(),
            script.into(),
            "k3s".into(),
            "--disable-agent".into(),
            "--disable=coredns,servicelb,traefik,local-storage,metrics-server".into(),
            "--tls-san=127.0.0.1".into(),
            "--tls-san=localhost".into(),
            format!("--tls-san={}", self.bind),
            format!("--service-cidr={}", spec.service_cidr),
            "--write-kubeconfig-mode=644".into(),
            "--kube-apiserver-arg=authentication-token-webhook-config-file=/etc/mws/authn.yaml".into(),
            "--kube-apiserver-arg=authentication-token-webhook-version=v1".into(),
            "--kube-apiserver-arg=authentication-token-webhook-cache-ttl=10s".into(),
            "--kube-apiserver-arg=authorization-mode=Node,RBAC,Webhook".into(),
            "--kube-apiserver-arg=authorization-webhook-config-file=/etc/mws/authz.yaml".into(),
            "--kube-apiserver-arg=authorization-webhook-version=v1".into(),
            "--kube-apiserver-arg=authorization-webhook-cache-authorized-ttl=10s".into(),
            "--kube-apiserver-arg=authorization-webhook-cache-unauthorized-ttl=1s".into(),
            // The nodes EKS lists have no kubelet to renew their leases.
            "--kube-controller-manager-arg=controllers=*,-nodelifecycle".into(),
        ];
        self.run(&args, None).await.map(|_| ())
    }

    async fn wait_ready(&self, id: &str) -> Result<Running, ControlPlaneError> {
        let mut last = String::new();
        for _ in 0..240 {
            match self.kubectl(id, &["get", "--raw", "/readyz"], None).await {
                Ok(out) if out.trim() == "ok" => {
                    let port = self.args(&["port", id, "6443/tcp"]).await?;
                    let port = port
                        .lines()
                        .next()
                        .and_then(|l| l.rsplit(':').next())
                        .ok_or_else(|| ControlPlaneError(format!("no published port: {port}")))?
                        .to_string();
                    let ca_pem = self.args(&["exec", id, "cat", &format!("{DATA}/server/tls/server-ca.crt")]).await?;
                    let host = if self.bind == "0.0.0.0" { "127.0.0.1" } else { self.bind.as_str() };
                    return Ok(Running { endpoint: format!("https://{host}:{port}"), ca_pem: format!("{ca_pem}\n") });
                }
                Ok(out) => last = out,
                Err(e) => last = e.0,
            }
            if !self.running(id).await {
                let logs = self.run(&["logs".into(), "--tail".into(), "20".into(), id.into()], None).await;
                return Err(ControlPlaneError(format!("the k3s API server exited: {}", logs.unwrap_or_else(|e| e.0))));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(ControlPlaneError(format!("the k3s API server did not become ready: {last}")))
    }
}

#[async_trait::async_trait]
impl ControlPlane for K3s {
    fn name(&self) -> &'static str {
        "k3s"
    }

    async fn ensure(&self, spec: &ControlPlaneSpec) -> Result<Running, ControlPlaneError> {
        if !self.running(&spec.id).await {
            self.start(spec).await?;
        }
        self.wait_ready(&spec.id).await
    }

    async fn upgrade(&self, spec: &ControlPlaneSpec) -> Result<Running, ControlPlaneError> {
        self.start(spec).await?;
        self.wait_ready(&spec.id).await
    }

    async fn delete(&self, id: &str) {
        let _ = self.args(&["rm", "-f", "-v", id]).await;
        let _ = self.args(&["volume", "rm", "-f", id]).await;
    }

    async fn sync_nodes(&self, id: &str, nodegroup: &str, nodes: &[NodeObject]) -> Result<(), ControlPlaneError> {
        let selector = format!("eks.amazonaws.com/nodegroup={nodegroup}");
        let existing = self.kubectl(id, &["get", "nodes", "-l", &selector, "-o", "name"], None).await?;
        for name in existing.lines().filter_map(|l| l.strip_prefix("node/")) {
            if !nodes.iter().any(|n| n.name == name) {
                self.kubectl(id, &["delete", "node", name, "--wait=false"], None).await?;
            }
        }
        for n in nodes {
            let taints: Vec<_> = n.taints.iter().map(|(k, v, e)| json!({"key": k, "value": v, "effect": e})).collect();
            let node = json!({
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": {"name": n.name, "labels": n.labels},
                "spec": {"providerID": n.provider_id, "taints": taints},
            });
            self.kubectl(id, &["apply", "-f", "-"], Some(node.to_string().as_bytes())).await?;
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let resources = json!({"cpu": n.cpu, "memory": n.memory, "pods": n.pods});
            let status = json!({"status": {
                "addresses": [
                    {"type": "InternalIP", "address": n.internal_ip},
                    {"type": "Hostname", "address": n.name},
                    {"type": "InternalDNS", "address": n.name},
                ],
                "capacity": resources,
                "allocatable": resources,
                "conditions": [{
                    "type": "Ready",
                    "status": "True",
                    "reason": "KubeletReady",
                    "message": "kubelet is posting ready status",
                    "lastHeartbeatTime": now,
                    "lastTransitionTime": now,
                }],
                "nodeInfo": {
                    "kubeletVersion": n.kubelet_version,
                    "kubeProxyVersion": n.kubelet_version,
                    "operatingSystem": "linux",
                    "architecture": n.labels.get("kubernetes.io/arch").cloned().unwrap_or_else(|| "amd64".into()),
                    "containerRuntimeVersion": "containerd://1.7.27",
                    "osImage": "Amazon Linux 2023",
                    "kernelVersion": "6.1.0",
                    "machineID": "", "systemUUID": "", "bootID": "",
                },
            }});
            self.kubectl(
                id,
                &["patch", "node", &n.name, "--subresource=status", "--type=merge", "-p", &status.to_string()],
                None,
            )
            .await?;
        }
        Ok(())
    }
}
