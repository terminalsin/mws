//! Running each cluster's Kubernetes API server on the control plane
//! backend, and keeping what EKS reports (endpoint, certificate authority,
//! status, nodes) in step with it.

use std::time::Duration;

use base64::Engine;
use mws_core::RequestContext;

use crate::kube::{nodes, ControlPlaneSpec};
use crate::state::{ClusterRec, ControlPlaneRec};
use crate::{util, Eks};

/// MWS's URL as a container sees it: loopback names become the Docker host
/// gateway.
fn webhook_base(ctx: &RequestContext) -> String {
    let endpoint = ctx.endpoint.clone().unwrap_or_else(|| "http://127.0.0.1:4566".into());
    for local in ["127.0.0.1", "localhost", "0.0.0.0", "[::1]"] {
        if let Some(rest) = endpoint.strip_prefix(&format!("http://{local}")) {
            return format!("http://host.docker.internal{rest}");
        }
    }
    endpoint
}

fn spec(account: &str, region: &str, name: &str, rec: &ClusterRec) -> Option<ControlPlaneSpec> {
    let cp = rec.control_plane.as_ref()?;
    let base = format!("{}{}{account}/{region}/{name}", cp.webhook_base, crate::kube::webhook::PREFIX);
    Some(ControlPlaneSpec {
        id: cp.id.clone(),
        cluster_arn: rec.cluster.arn.clone().unwrap_or_default(),
        version: cp.version.clone(),
        service_cidr: cp.service_cidr.clone(),
        authenticate_url: format!("{base}/authenticate"),
        authorize_url: format!("{base}/authorize"),
    })
}

impl Eks {
    /// Give a new cluster a control plane record, when a backend runs API
    /// servers.
    pub(crate) fn plan_control_plane(&self, ctx: &RequestContext, rec: &mut ClusterRec, creator: Option<String>) {
        if self.control_plane().is_none() {
            return;
        }
        let name = rec.cluster.name.clone().unwrap_or_default();
        let unique = rec
            .cluster
            .identity
            .as_ref()
            .and_then(|i| i.oidc.as_ref())
            .and_then(|o| o.issuer.as_deref())
            .and_then(|i| i.rsplit('/').next())
            .unwrap_or_default()
            .to_ascii_lowercase();
        rec.control_plane = Some(ControlPlaneRec {
            id: format!("mws-eks-{name}-{}", &unique[..unique.len().min(10)]),
            version: rec.cluster.version.clone().unwrap_or_default(),
            ready: false,
            error: None,
            creator,
            webhook_base: webhook_base(ctx),
            service_cidr: rec
                .cluster
                .kubernetes_network_config
                .as_ref()
                .and_then(|k| k.service_ipv4_cidr.clone())
                .unwrap_or_else(|| "10.100.0.0/16".into()),
        });
    }

    /// Start (or upgrade) a cluster's API server in the background; the
    /// cluster becomes `ACTIVE` once it answers.
    pub(crate) fn start_control_plane(&self, account: &str, region: &str, name: &str, upgrade: bool) {
        let Some(backend) = self.control_plane().cloned() else { return };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let (account, region, name) = (account.to_string(), region.to_string(), name.to_string());
        let me = self.clone();
        tokio::spawn(async move {
            let spec = {
                let st = me.read();
                st.regions
                    .get(&format!("{account}/{region}"))
                    .and_then(|r| r.clusters.get(&name))
                    .and_then(|rec| spec(&account, &region, &name, rec))
            };
            let Some(spec) = spec else { return };
            let result = if upgrade { backend.upgrade(&spec).await } else { backend.ensure(&spec).await };
            if !me.record_control_plane(&account, &region, &name, &spec.id, result) {
                // Deleted meanwhile.
                backend.delete(&spec.id).await;
            }
        });
    }

    /// Record how starting a control plane went; `false` when the cluster
    /// is gone.
    fn record_control_plane(
        &self,
        account: &str,
        region: &str,
        name: &str,
        id: &str,
        result: Result<crate::kube::Running, crate::kube::ControlPlaneError>,
    ) -> bool {
        let mut st = self.write();
        let Some(rec) = st.regions.get_mut(&format!("{account}/{region}")).and_then(|r| r.clusters.get_mut(name))
        else {
            return false;
        };
        let Some(cp) = rec.control_plane.as_mut().filter(|c| c.id == id) else { return true };
        {
            match result {
                Ok(running) => {
                    cp.ready = true;
                    cp.error = None;
                    rec.cluster.endpoint = Some(running.endpoint);
                    let data = base64::engine::general_purpose::STANDARD.encode(&running.ca_pem);
                    if let Some(ca) = rec
                        .certificate_authorities
                        .iter_mut()
                        .find(|c| c.ca.signing_status.as_deref() == Some("IN_USE"))
                    {
                        ca.ca.data = Some(data);
                    }
                    crate::certs::refresh_cluster_certificate(rec);
                }
                Err(e) => {
                    tracing::warn!(cluster = %name, "EKS could not start the cluster's API server: {e}");
                    cp.error = Some(e.to_string());
                    cp.ready = true;
                    rec.cluster.status = Some("FAILED".into());
                    let issues =
                        rec.cluster.health.get_or_insert_with(Default::default).issues.get_or_insert_with(Vec::new);
                    issues.push(crate::generated::types::ClusterIssue {
                        code: Some("Unknown".into()),
                        message: Some(format!("The cluster's Kubernetes API server failed to start: {e}")),
                        resource_ids: Some(vec![id.to_string()]),
                    });
                }
            }
        }
        true
    }

    /// Wait (up to a minute) for a starting API server, so a waiter's
    /// first `DescribeCluster` sees the cluster `ACTIVE`.
    pub(crate) async fn await_control_plane(&self, ctx: &RequestContext, name: &str) {
        for _ in 0..240 {
            let pending = {
                let mut st = self.write();
                util::cluster(&mut st, ctx, name)
                    .ok()
                    .and_then(|rec| rec.control_plane.as_ref())
                    .is_some_and(|cp| !cp.ready)
            };
            if !pending {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Stop and remove a cluster's API server.
    pub(crate) fn remove_control_plane(&self, id: String) {
        let Some(backend) = self.control_plane().cloned() else { return };
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move { backend.delete(&id).await });
        } else {
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    rt.block_on(backend.delete(&id));
                }
            });
        }
    }

    /// Every control plane in the state, by id.
    pub(crate) fn control_plane_ids(&self) -> Vec<String> {
        let st = self.read();
        st.regions
            .values()
            .flat_map(|r| r.clusters.values())
            .filter_map(|c| c.control_plane.as_ref().map(|cp| cp.id.clone()))
            .collect()
    }

    /// Restart every control plane in the state (after an import).
    pub(crate) fn resume_control_planes(&self) {
        let clusters: Vec<(String, String, String)> = {
            let mut st = self.write();
            let mut out = Vec::new();
            for (key, region) in st.regions.iter_mut() {
                let Some((account, region_name)) = key.split_once('/') else { continue };
                for (name, rec) in region.clusters.iter_mut() {
                    if let Some(cp) = rec.control_plane.as_mut().filter(|cp| cp.error.is_none()) {
                        cp.ready = false;
                        out.push((account.to_string(), region_name.to_string(), name.clone()));
                    }
                }
            }
            out
        };
        for (account, region, name) in clusters {
            self.start_control_plane(&account, &region, &name, false);
        }
    }

    /// Make the cluster's nodes for node group `nodegroup` the group's
    /// running instances.
    pub(crate) async fn sync_nodes(&self, ctx: &RequestContext, cluster: &str, nodegroup: &str) {
        let (Some(backend), Some(infra)) = (self.control_plane().cloned(), self.infra().cloned()) else { return };
        let (id, ng) = {
            let mut st = self.write();
            let Ok(rec) = util::cluster(&mut st, ctx, cluster) else { return };
            let Some(cp) = rec.control_plane.as_ref().filter(|c| c.ready && c.error.is_none()) else { return };
            (cp.id.clone(), rec.nodegroups.get(nodegroup).map(|n| n.nodegroup.clone()))
        };
        let scope = util::scope(ctx);
        let objects = match &ng {
            Some(ng) if ng.status.as_deref() != Some("DELETING") => {
                let group = ng
                    .resources
                    .as_ref()
                    .and_then(|r| r.auto_scaling_groups.as_ref())
                    .and_then(|g| g.first())
                    .and_then(|g| g.name.clone())
                    .unwrap_or_default();
                let ids = infra.node_group_state(&scope, &group).await.map(|s| s.instance_ids).unwrap_or_default();
                let facts = infra.instances(&scope, &ids).await;
                nodes::node_objects(ng, &ctx.region, &facts)
            }
            _ => Vec::new(),
        };
        if let Err(e) = backend.sync_nodes(&id, nodegroup, &objects).await {
            tracing::warn!(cluster, nodegroup, "EKS could not register the node group's nodes: {e}");
        }
    }
}
