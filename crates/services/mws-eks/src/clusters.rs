//! Clusters: create, describe, list, update, delete, register
//! (EKS Connector), plus Kubernetes versions and the settle step that moves
//! every resource out of its transitional state.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::catalog;
use crate::generated::{errors, types};
use crate::infra::SubnetFacts;
use crate::state::{AccessEntryRec, ClusterRec};
use crate::util::{self, param, text, Tags};
use crate::Eks;

const LOG_TYPES: &[&str] = &["api", "audit", "authenticator", "controllerManager", "scheduler"];

/// Convert between request and response shapes that share their members.
pub(crate) fn convert<A: Serialize, B: DeserializeOwned + Default>(a: &A) -> B {
    serde_json::to_value(a).ok().and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default()
}

impl Eks {
    /// Finish transitions: what was being created, updated or deleted when
    /// the last request ran is done now.
    pub(crate) fn settle(&self, ctx: &RequestContext) {
        let mut st = self.write();
        let Some(region) = st.regions.get_mut(&format!("{}/{}", util::account(ctx), ctx.region)) else { return };
        region.clusters.retain(|_, c| c.cluster.status.as_deref() != Some("DELETING"));
        for rec in region.clusters.values_mut() {
            if matches!(rec.cluster.status.as_deref(), Some("CREATING" | "UPDATING")) {
                rec.cluster.status = Some("ACTIVE".into());
            }
            rec.nodegroups.retain(|_, n| n.nodegroup.status.as_deref() != Some("DELETING"));
            for n in rec.nodegroups.values_mut() {
                if matches!(n.nodegroup.status.as_deref(), Some("CREATING" | "UPDATING")) {
                    n.nodegroup.status = Some("ACTIVE".into());
                }
            }
            rec.addons.retain(|_, a| a.status.as_deref() != Some("DELETING"));
            for a in rec.addons.values_mut() {
                if matches!(a.status.as_deref(), Some("CREATING" | "UPDATING")) {
                    a.status = Some("ACTIVE".into());
                }
            }
            rec.fargate_profiles.retain(|_, f| f.status.as_deref() != Some("DELETING"));
            for f in rec.fargate_profiles.values_mut() {
                if f.status.as_deref() == Some("CREATING") {
                    f.status = Some("ACTIVE".into());
                }
            }
            rec.identity_providers.retain(|_, p| p.status.as_deref() != Some("DELETING"));
            for p in rec.identity_providers.values_mut() {
                if p.status.as_deref() == Some("CREATING") {
                    p.status = Some("ACTIVE".into());
                }
            }
            rec.capabilities.retain(|_, c| c.status.as_deref() != Some("DELETING"));
            for c in rec.capabilities.values_mut() {
                if matches!(c.status.as_deref(), Some("CREATING" | "UPDATING")) {
                    c.status = Some("ACTIVE".into());
                }
            }
            if let Some(r) = rec.insights_refresh.as_mut().filter(|r| r.status == "IN_PROGRESS") {
                r.status = "COMPLETED".into();
                r.ended_at = Some(ctx.received_at);
            }
            crate::certs::settle(rec);
            crate::updates::settle(rec);
        }
        region.subscriptions.retain(|_, s| s.status.as_deref() != Some("DELETING"));
        for s in region.subscriptions.values_mut() {
            if matches!(s.status.as_deref(), Some("CREATING" | "UPDATING")) {
                s.status = Some("ACTIVE".into());
            }
        }
    }

    /// Whether a service may assume a role, as EKS checks before taking
    /// it: `Ok` when STS is not wired in.
    pub(crate) fn check_role(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        service: &str,
        on_missing: impl FnOnce() -> String,
        on_untrusted: impl FnOnce() -> String,
    ) -> Result<(), ServiceError> {
        util::pass_role(ctx, role_arn, service)?;
        let Some(sts) = self.sts() else { return Ok(()) };
        let probe = mws_sts::ServiceAssume {
            role_arn,
            service_principal: service,
            session_name: "eks",
            duration_seconds: 900,
            source_account: Some(util::account(ctx)),
            source_arn: None,
            now: ctx.received_at,
        };
        match sts.service_can_assume(&probe) {
            Ok(()) => Ok(()),
            Err(mws_sts::ServiceAssumeError::NoSuchRole) => Err(errors::invalid_parameter(on_missing())),
            Err(mws_sts::ServiceAssumeError::NotTrusted) => Err(errors::invalid_parameter(on_untrusted())),
        }
    }

    /// The facts of `subnets` (and that they exist), when EC2 is wired in.
    pub(crate) async fn subnet_facts(
        &self,
        ctx: &RequestContext,
        subnets: &[String],
    ) -> Result<Option<Vec<SubnetFacts>>, ServiceError> {
        let Some(infra) = self.infra() else { return Ok(None) };
        infra.subnets(&util::scope(ctx), subnets).await.map(Some).map_err(|e| util::infra_error(&e))
    }

    pub(crate) async fn create_cluster(
        &self,
        ctx: &RequestContext,
        input: types::CreateClusterRequest,
    ) -> Result<types::CreateClusterResponse, ServiceError> {
        let name = input.name.clone();
        let arn = util::cluster_arn(ctx, &name);
        util::authorize(ctx, "CreateCluster", &arn, None, input.tags.as_ref(), ConditionContext::new())?;
        util::check_create_tags(input.tags.as_ref())?;
        {
            let mut st = self.write();
            if let Some(existing) = util::region(&mut st, ctx).clusters.get(&name) {
                if input.client_request_token.is_some()
                    && existing.cluster.client_request_token == input.client_request_token
                {
                    return Ok(types::CreateClusterResponse { cluster: Some(existing.cluster.clone()) });
                }
                return Err(in_use(&name));
            }
        }
        let version = match input.version.as_deref() {
            None => catalog::default_version(),
            Some(v) => catalog::version(v)
                .filter(|k| k.status(ctx.received_at) != "unsupported")
                .ok_or_else(|| errors::invalid_parameter(format!("unsupported Kubernetes version {v}")))?,
        };
        if input.outpost_config.is_some() {
            return Err(errors::invalid_parameter("Local clusters on AWS Outposts are not supported in this Region."));
        }

        // Access configuration.
        let access = input.access_config.clone().unwrap_or_default();
        let mode = access.authentication_mode.clone().unwrap_or_else(|| "CONFIG_MAP".into());
        let bootstrap = access.bootstrap_cluster_creator_admin_permissions.unwrap_or(true);
        if mode == "CONFIG_MAP" && !bootstrap {
            return Err(errors::invalid_parameter(
                "bootstrapClusterCreatorAdminPermissions must be true if cluster authentication mode is set to CONFIG_MAP",
            ));
        }

        // EKS Auto Mode: compute, block storage and load balancing go
        // together.
        let compute = input.compute_config.as_ref().and_then(|c| c.enabled).unwrap_or(false);
        let storage = input
            .storage_config
            .as_ref()
            .and_then(|s| s.block_storage.as_ref())
            .and_then(|b| b.enabled)
            .unwrap_or(false);
        let elb = input
            .kubernetes_network_config
            .as_ref()
            .and_then(|k| k.elastic_load_balancing.as_ref())
            .and_then(|e| e.enabled)
            .unwrap_or(false);
        if !(compute == storage && storage == elb) {
            return Err(auto_mode_mismatch());
        }
        if compute {
            if mode == "CONFIG_MAP" {
                return Err(errors::invalid_parameter(
                    "EKS Auto Mode requires the cluster authentication mode to be API or API_AND_CONFIG_MAP.",
                ));
            }
            let c = input.compute_config.as_ref().expect("checked");
            let pools = c.node_pools.clone().unwrap_or_default();
            if !pools.is_empty() && c.node_role_arn.is_none() {
                return Err(errors::invalid_parameter("nodeRoleArn is required when nodePools are specified."));
            }
            if let Some(pool) = pools.iter().find(|p| !matches!(p.as_str(), "general-purpose" | "system")) {
                return Err(errors::invalid_parameter(format!(
                    "Invalid node pool {pool}. Valid node pools are: general-purpose, system."
                )));
            }
        }

        // Encryption.
        if let Some(enc) = &input.encryption_config {
            check_encryption(enc)?;
        }

        // Roles.
        self.check_role(
            ctx,
            &input.role_arn,
            "eks.amazonaws.com",
            || format!("Role with arn: {}, does not exist.", input.role_arn),
            || format!("Role with arn: {}, cannot be assumed by Amazon EKS.", input.role_arn),
        )?;
        if let Some(role) = input.compute_config.as_ref().and_then(|c| c.node_role_arn.as_deref()) {
            util::pass_role(ctx, role, "ec2.amazonaws.com")?;
        }

        // Networking.
        let vpc = &input.resources_vpc_config;
        let subnets = vpc.subnet_ids.clone().unwrap_or_default();
        if subnets.is_empty() {
            return Err(errors::invalid_parameter("Subnets specified must be in at least two different AZs"));
        }
        let facts = self.subnet_facts(ctx, &subnets).await?;
        let vpc_id = match &facts {
            Some(facts) => vpc_of(facts)?,
            None => format!("vpc-{}", util::random(b"0123456789abcdef", 17)),
        };
        if let Some(facts) = &facts {
            let mut zones: Vec<&str> = facts.iter().map(|f| f.availability_zone.as_str()).collect();
            zones.sort();
            zones.dedup();
            if zones.len() < 2 {
                return Err(errors::invalid_parameter("Subnets specified must be in at least two different AZs"));
            }
        }
        let groups = vpc.security_group_ids.clone().unwrap_or_default();
        if let (Some(infra), false) = (self.infra(), groups.is_empty()) {
            infra.security_groups_exist(&util::scope(ctx), &groups).await.map_err(|e| util::infra_error(&e))?;
        }
        let public = vpc.endpoint_public_access.unwrap_or(true);
        let private = vpc.endpoint_private_access.unwrap_or(false);
        if !public && !private {
            return Err(endpoint_access_error());
        }
        let cidrs = vpc.public_access_cidrs.clone().unwrap_or_else(|| vec!["0.0.0.0/0".into()]);
        check_public_cidrs(&cidrs)?;

        let knc = input.kubernetes_network_config.clone().unwrap_or_default();
        let ip_family = knc.ip_family.clone().unwrap_or_else(|| "ipv4".into());
        let vpc_cidr = facts.as_ref().and_then(|f| f.first()).and_then(|f| f.vpc_cidr.clone());
        let service_cidr = match &knc.service_ipv4_cidr {
            Some(c) => {
                check_service_cidr(c)?;
                c.clone()
            }
            None if vpc_cidr.as_deref().is_some_and(|c| c.starts_with("10.")) => "172.20.0.0/16".into(),
            None => "10.100.0.0/16".into(),
        };

        // The cluster security group, in the cluster's VPC.
        let digits = util::random(b"0123456789", 10);
        let sg_name = format!("eks-cluster-sg-{name}-{digits}");
        let (cluster_sg, owns_sg) = match self.infra() {
            Some(infra) => {
                let tags: Tags = [
                    ("Name".to_string(), sg_name.clone()),
                    (format!("kubernetes.io/cluster/{name}"), "owned".to_string()),
                ]
                .into_iter()
                .collect();
                let id = infra
                    .create_security_group(
                        &util::scope(ctx),
                        &vpc_id,
                        &sg_name,
                        "EKS created security group applied to ENI that is attached to EKS Control Plane master nodes, as well as any managed workloads.",
                        &tags,
                        true,
                        false,
                    )
                    .await
                    .map_err(|e| util::infra_error(&e))?;
                (id, true)
            }
            None => (format!("sg-{}", util::random(b"0123456789abcdef", 17)), false),
        };

        let id = util::random(util::HEX_UPPER, 32);
        let now = ctx.received_at;
        let region = &ctx.region;
        let mut cluster = types::Cluster {
            name: Some(name.clone()),
            arn: Some(arn.clone()),
            created_at: Some(now),
            version: Some(version.version.into()),
            endpoint: Some(format!("https://{id}.gr7.{region}.eks.amazonaws.com")),
            role_arn: Some(input.role_arn.clone()),
            resources_vpc_config: Some(types::VpcConfigResponse {
                subnet_ids: Some(subnets.clone()),
                security_group_ids: Some(groups),
                cluster_security_group_id: Some(cluster_sg),
                vpc_id: Some(vpc_id),
                endpoint_public_access: public,
                endpoint_private_access: private,
                public_access_cidrs: Some(cidrs),
                control_plane_egress_mode: vpc.control_plane_egress_mode.clone(),
            }),
            kubernetes_network_config: Some(types::KubernetesNetworkConfigResponse {
                service_ipv4_cidr: (ip_family == "ipv4").then(|| service_cidr.clone()),
                service_ipv6_cidr: (ip_family == "ipv6").then(|| "fd00:ec2:2b::/108".to_string()),
                ip_family: Some(ip_family),
                elastic_load_balancing: Some(types::ElasticLoadBalancing {
                    enabled: Some(elb),
                    gateway_api: knc.elastic_load_balancing.as_ref().and_then(|e| e.gateway_api.clone()),
                }),
            }),
            logging: Some(normalize_logging(None, input.logging.as_ref())),
            identity: Some(types::Identity {
                oidc: Some(types::OIDC { issuer: Some(format!("https://oidc.eks.{region}.amazonaws.com/id/{id}")) }),
            }),
            status: Some("CREATING".into()),
            client_request_token: input.client_request_token.clone(),
            platform_version: Some(version.platform_version.into()),
            tags: Some(input.tags.clone().unwrap_or_default()),
            encryption_config: input.encryption_config.clone(),
            health: Some(types::ClusterHealth { issues: Some(Vec::new()) }),
            access_config: Some(types::AccessConfigResponse {
                bootstrap_cluster_creator_admin_permissions: Some(bootstrap),
                authentication_mode: Some(mode.clone()),
            }),
            upgrade_policy: Some(types::UpgradePolicyResponse {
                support_type: Some(
                    input
                        .upgrade_policy
                        .as_ref()
                        .and_then(|u| u.support_type.clone())
                        .unwrap_or_else(|| "EXTENDED".into()),
                ),
            }),
            zonal_shift_config: input.zonal_shift_config.as_ref().map(convert),
            remote_network_config: input.remote_network_config.as_ref().map(convert),
            compute_config: input.compute_config.as_ref().map(convert),
            storage_config: input.storage_config.as_ref().map(convert),
            deletion_protection: Some(input.deletion_protection.unwrap_or(false)),
            control_plane_scaling_config: Some(
                input
                    .control_plane_scaling_config
                    .clone()
                    .unwrap_or(types::ControlPlaneScalingConfig { tier: Some("standard".into()) }),
            ),
            kube_api_server_config: input.kube_api_server_config.as_ref().map(convert),
            kube_scheduler_config: input.kube_scheduler_config.as_ref().map(convert),
            kube_controller_manager_config: input.kube_controller_manager_config.as_ref().map(convert),
            ..Default::default()
        };
        if compute {
            cluster.resources_vpc_config.as_mut().expect("set").control_plane_egress_mode = None;
        }
        let ca = crate::certs::new_ca(now, "EKS", true)?;
        let mut rec = ClusterRec {
            cluster,
            owns_security_group: owns_sg,
            certificate_authorities: vec![ca],
            ..Default::default()
        };
        crate::certs::refresh_cluster_certificate(&mut rec);
        if mode != "CONFIG_MAP" && bootstrap {
            let creator = creator_principal(ctx);
            let mut entry = crate::access::new_entry(ctx, &name, &creator, "STANDARD", None, Vec::new(), None);
            let policy = catalog::access_policy_arn(&ctx.partition, "AmazonEKSClusterAdminPolicy");
            let mut policies = BTreeMap::new();
            policies.insert(
                policy.clone(),
                types::AssociatedAccessPolicy {
                    policy_arn: Some(policy),
                    access_scope: Some(types::AccessScope {
                        r#type: Some("cluster".into()),
                        namespaces: Some(Vec::new()),
                    }),
                    associated_at: Some(now),
                    modified_at: Some(now),
                },
            );
            entry.tags = Some(BTreeMap::new());
            rec.access_entries.insert(creator, AccessEntryRec { entry, policies });
        }
        if compute {
            if let Some(role) = input.compute_config.as_ref().and_then(|c| c.node_role_arn.clone()) {
                let entry = crate::access::new_entry(ctx, &name, &role, "EC2", None, Vec::new(), None);
                let policy = catalog::access_policy_arn(&ctx.partition, "AmazonEKSAutoNodePolicy");
                let mut policies = BTreeMap::new();
                policies.insert(
                    policy.clone(),
                    types::AssociatedAccessPolicy {
                        policy_arn: Some(policy),
                        access_scope: Some(types::AccessScope {
                            r#type: Some("cluster".into()),
                            namespaces: Some(Vec::new()),
                        }),
                        associated_at: Some(now),
                        modified_at: Some(now),
                    },
                );
                rec.access_entries.insert(role, AccessEntryRec { entry, policies });
            }
        }
        let response = rec.cluster.clone();
        let mut st = self.write();
        let region = util::region(&mut st, ctx);
        if region.clusters.contains_key(&name) {
            return Err(in_use(&name));
        }
        region.clusters.insert(name, rec);
        Ok(types::CreateClusterResponse { cluster: Some(response) })
    }

    pub(crate) async fn describe_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DescribeClusterRequest,
    ) -> Result<types::DescribeClusterResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.name)?;
        util::authorize(ctx, "DescribeCluster", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        Ok(types::DescribeClusterResponse { cluster: Some(rec.cluster.clone()) })
    }

    pub(crate) async fn list_clusters(
        &self,
        ctx: &RequestContext,
        input: types::ListClustersRequest,
    ) -> Result<types::ListClustersResponse, ServiceError> {
        util::authorize(ctx, "ListClusters", &util::arn(ctx, "cluster/*"), None, None, ConditionContext::new())?;
        let include = input.include.clone().unwrap_or_default();
        if let Some(bad) = include.iter().find(|i| i.as_str() != "all") {
            return Err(errors::invalid_parameter(format!(
                "The include parameter value {bad} is invalid. Use 'all' to include connected clusters."
            )));
        }
        let all = !include.is_empty();
        let mut st = self.write();
        let names: Vec<String> = util::region(&mut st, ctx)
            .clusters
            .iter()
            .filter(|(_, c)| all || !c.registered)
            .map(|(n, _)| n.clone())
            .collect();
        let (items, next) = util::page(&names, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListClustersResponse { clusters: Some(items), next_token: next })
    }

    pub(crate) async fn delete_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DeleteClusterRequest,
    ) -> Result<types::DeleteClusterResponse, ServiceError> {
        let name = input.name.clone();
        let arn = util::cluster_arn(ctx, &name);
        let (response, sg) = {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &name)?;
            util::authorize(ctx, "DeleteCluster", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
            if rec.registered {
                return Err(errors::invalid_request(
                    "This cluster is a registered cluster. Use DeregisterCluster to deregister it.",
                )
                .with_field("clusterName", text(&name)));
            }
            if rec.cluster.deletion_protection == Some(true) {
                return Err(errors::invalid_request(format!(
                    "Cluster {name} has deletion protection enabled. Disable deletion protection before deleting the cluster."
                ))
                .with_field("clusterName", text(&name)));
            }
            if !rec.nodegroups.is_empty() {
                return Err(
                    errors::resource_in_use("Cluster has nodegroups attached").with_field("clusterName", text(&name))
                );
            }
            if !rec.fargate_profiles.is_empty() {
                return Err(errors::resource_in_use("Cluster has fargate profiles attached")
                    .with_field("clusterName", text(&name)));
            }
            rec.cluster.status = Some("DELETING".into());
            for a in rec.addons.values_mut() {
                a.status = Some("DELETING".into());
            }
            let sg = rec
                .owns_security_group
                .then(|| rec.cluster.resources_vpc_config.as_ref().and_then(|v| v.cluster_security_group_id.clone()))
                .flatten();
            (rec.cluster.clone(), sg)
        };
        if let (Some(infra), Some(sg)) = (self.infra(), sg) {
            if let Err(e) = infra.delete_security_group(&util::scope(ctx), &sg).await {
                tracing::warn!(cluster = %name, "EKS could not delete the cluster security group: {e}");
            }
        }
        Ok(types::DeleteClusterResponse { cluster: Some(response) })
    }

    pub(crate) async fn register_cluster(
        &self,
        ctx: &RequestContext,
        input: types::RegisterClusterRequest,
    ) -> Result<types::RegisterClusterResponse, ServiceError> {
        let name = input.name.clone();
        let arn = util::cluster_arn(ctx, &name);
        util::authorize(ctx, "RegisterCluster", &arn, None, input.tags.as_ref(), ConditionContext::new())?;
        util::check_create_tags(input.tags.as_ref())?;
        let role = input.connector_config.role_arn.clone();
        self.check_role(
            ctx,
            &role,
            "ssm.amazonaws.com",
            || format!("Role with arn: {role}, does not exist."),
            || format!("Role with arn: {role}, cannot be assumed by Amazon EKS Connector."),
        )?;
        let now = ctx.received_at;
        let cluster = types::Cluster {
            name: Some(name.clone()),
            arn: Some(arn),
            created_at: Some(now),
            status: Some("PENDING".into()),
            client_request_token: input.client_request_token.clone(),
            tags: Some(input.tags.clone().unwrap_or_default()),
            connector_config: Some(types::ConnectorConfigResponse {
                activation_id: Some(util::uuid()),
                activation_code: Some(util::random(
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                    20,
                )),
                activation_expiry: Some(now + chrono::Duration::days(3)),
                provider: Some(input.connector_config.provider.clone()),
                role_arn: Some(role),
            }),
            ..Default::default()
        };
        let mut st = self.write();
        let region = util::region(&mut st, ctx);
        if let Some(existing) = region.clusters.get(&name) {
            if input.client_request_token.is_some()
                && existing.cluster.client_request_token == input.client_request_token
            {
                return Ok(types::RegisterClusterResponse { cluster: Some(existing.cluster.clone()) });
            }
            return Err(in_use(&name));
        }
        region.clusters.insert(name, ClusterRec { cluster: cluster.clone(), registered: true, ..Default::default() });
        Ok(types::RegisterClusterResponse { cluster: Some(cluster) })
    }

    pub(crate) async fn deregister_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterClusterRequest,
    ) -> Result<types::DeregisterClusterResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.name)?;
        util::authorize(ctx, "DeregisterCluster", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        if !rec.registered {
            return Err(errors::invalid_request(format!(
                "Cluster {} is not a registered cluster. Use DeleteCluster to delete it.",
                input.name
            ))
            .with_field("clusterName", text(&input.name)));
        }
        rec.cluster.status = Some("DELETING".into());
        Ok(types::DeregisterClusterResponse { cluster: Some(rec.cluster.clone()) })
    }

    pub(crate) async fn update_cluster_version(
        &self,
        ctx: &RequestContext,
        input: types::UpdateClusterVersionRequest,
    ) -> Result<types::UpdateClusterVersionResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.name)?;
        util::authorize(ctx, "UpdateClusterVersion", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        check_updatable(rec, &input.name)?;
        let current = rec.cluster.version.clone().unwrap_or_default();
        let target = catalog::version(&input.version)
            .filter(|v| v.status(ctx.received_at) != "unsupported")
            .ok_or_else(|| errors::invalid_parameter(format!("unsupported Kubernetes version {}", input.version)))?;
        if catalog::minor(&current).map(|m| m + 1) != Some(target.minor()) {
            return Err(errors::invalid_parameter(format!(
                "Unsupported Kubernetes minor version update from {current} to {}",
                input.version
            ))
            .with_field("clusterName", text(&input.name)));
        }
        if !input.force {
            let skewed = rec.nodegroups.values().find(|n| {
                let v = n.nodegroup.version.as_deref().and_then(catalog::minor).unwrap_or(0);
                v + 3 <= target.minor()
            });
            if let Some(n) = skewed {
                return Err(errors::invalid_request(format!(
                    "Kubelet version of node group {} is too far behind {}. Upgrade the node group first, or set force to upgrade anyway.",
                    n.nodegroup.nodegroup_name.as_deref().unwrap_or_default(),
                    input.version
                ))
                .with_field("clusterName", text(&input.name)));
            }
        }
        rec.cluster.version = Some(target.version.into());
        rec.cluster.platform_version = Some(target.platform_version.into());
        rec.cluster.status = Some("UPDATING".into());
        let update = crate::updates::push(
            rec,
            ctx.received_at,
            "VersionUpdate",
            vec![param("Version", target.version), param("PlatformVersion", target.platform_version)],
            None,
        );
        Ok(types::UpdateClusterVersionResponse { update: Some(update) })
    }

    pub(crate) async fn update_cluster_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateClusterConfigRequest,
    ) -> Result<types::UpdateClusterConfigResponse, ServiceError> {
        let name = input.name.clone();
        let arn = util::cluster_arn(ctx, &name);
        {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &name)?;
            util::authorize(
                ctx,
                "UpdateClusterConfig",
                &arn,
                rec.cluster.tags.as_ref(),
                None,
                ConditionContext::new(),
            )?;
            check_updatable(rec, &name)?;
        }
        let vpc = input.resources_vpc_config.as_ref();
        let endpoint_change = vpc.is_some_and(|v| {
            v.endpoint_public_access.is_some() || v.endpoint_private_access.is_some() || v.public_access_cidrs.is_some()
        });
        let network_change = vpc.is_some_and(|v| v.subnet_ids.is_some() || v.security_group_ids.is_some());
        let egress_change = vpc.is_some_and(|v| v.control_plane_egress_mode.is_some());
        let auto_mode = input.compute_config.is_some() || input.storage_config.is_some();
        let kinds = [
            endpoint_change,
            network_change,
            egress_change,
            input.logging.is_some(),
            input.access_config.is_some(),
            input.upgrade_policy.is_some(),
            input.zonal_shift_config.is_some(),
            auto_mode || input.kubernetes_network_config.is_some(),
            input.remote_network_config.is_some(),
            input.deletion_protection.is_some(),
            input.control_plane_scaling_config.is_some(),
            input.kube_api_server_config.is_some()
                || input.kube_scheduler_config.is_some()
                || input.kube_controller_manager_config.is_some(),
        ];
        match kinds.iter().filter(|k| **k).count() {
            0 => {
                return Err(errors::invalid_parameter(
                    "No changes needed. Specify at least one configuration to update.",
                ))
            }
            1 => {}
            _ => return Err(errors::invalid_parameter("Only one type of update can be allowed.")),
        }
        // Subnets and security groups are checked against EC2 before the
        // lock is taken again.
        let mut new_vpc_id = None;
        if network_change {
            let v = vpc.expect("checked");
            if let Some(subnets) = &v.subnet_ids {
                if let Some(facts) = self.subnet_facts(ctx, subnets).await? {
                    new_vpc_id = Some(vpc_of(&facts)?);
                }
            }
            if let (Some(infra), Some(groups)) = (self.infra(), &v.security_group_ids) {
                if !groups.is_empty() {
                    infra.security_groups_exist(&util::scope(ctx), groups).await.map_err(|e| util::infra_error(&e))?;
                }
            }
        }
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &name)?;
        let now = ctx.received_at;
        let (kind, params) = if endpoint_change {
            let v = vpc.expect("checked");
            let cfg = rec.cluster.resources_vpc_config.get_or_insert_with(Default::default);
            let public = v.endpoint_public_access.unwrap_or(cfg.endpoint_public_access);
            let private = v.endpoint_private_access.unwrap_or(cfg.endpoint_private_access);
            if !public && !private {
                return Err(endpoint_access_error());
            }
            let mut params = vec![
                param("EndpointPublicAccess", public.to_string()),
                param("EndpointPrivateAccess", private.to_string()),
            ];
            if let Some(cidrs) = &v.public_access_cidrs {
                check_public_cidrs(cidrs)?;
                params.push(param("PublicAccessCidrs", util::json_list(cidrs)));
                cfg.public_access_cidrs = Some(cidrs.clone());
            }
            cfg.endpoint_public_access = public;
            cfg.endpoint_private_access = private;
            ("EndpointAccessUpdate", params)
        } else if network_change {
            let v = vpc.expect("checked");
            let cfg = rec.cluster.resources_vpc_config.get_or_insert_with(Default::default);
            if let (Some(new), Some(old)) = (&new_vpc_id, &cfg.vpc_id) {
                if new != old {
                    return Err(errors::invalid_parameter(format!(
                        "Subnets specified must belong to the cluster VPC {old}."
                    )));
                }
            }
            let mut params = Vec::new();
            if let Some(s) = &v.subnet_ids {
                params.push(param("Subnets", util::json_list(s)));
                cfg.subnet_ids = Some(s.clone());
            }
            if let Some(g) = &v.security_group_ids {
                params.push(param("SecurityGroups", util::json_list(g)));
                cfg.security_group_ids = Some(g.clone());
            }
            ("VpcConfigUpdate", params)
        } else if egress_change {
            let mode = vpc.and_then(|v| v.control_plane_egress_mode.clone()).unwrap_or_default();
            rec.cluster.resources_vpc_config.get_or_insert_with(Default::default).control_plane_egress_mode =
                Some(mode.clone());
            ("ControlPlaneEgressUpdate", vec![param("ControlPlaneEgressMode", mode)])
        } else if let Some(logging) = &input.logging {
            let merged = normalize_logging(rec.cluster.logging.as_ref(), Some(logging));
            let value = serde_json::to_string(&logging_json(&merged)).unwrap_or_default();
            rec.cluster.logging = Some(merged);
            ("LoggingUpdate", vec![param("ClusterLogging", value)])
        } else if let Some(access) = &input.access_config {
            let current = rec
                .cluster
                .access_config
                .as_ref()
                .and_then(|a| a.authentication_mode.clone())
                .unwrap_or_else(|| "CONFIG_MAP".into());
            let target = access.authentication_mode.clone().unwrap_or_else(|| current.clone());
            let rank = |m: &str| match m {
                "CONFIG_MAP" => 0,
                "API_AND_CONFIG_MAP" => 1,
                _ => 2,
            };
            if rank(&target) < rank(&current) {
                return Err(errors::invalid_parameter(format!(
                    "Unsupported authentication mode update from {current} to {target}"
                )));
            }
            if target == current {
                return Err(errors::invalid_parameter(format!(
                    "The cluster authentication mode is already {current}."
                )));
            }
            rec.cluster.access_config.get_or_insert_with(Default::default).authentication_mode = Some(target.clone());
            if current == "CONFIG_MAP" {
                crate::access::backfill_node_entries(ctx, rec);
            }
            ("AccessConfigUpdate", vec![param("AuthenticationMode", target)])
        } else if let Some(u) = &input.upgrade_policy {
            let t = u.support_type.clone().unwrap_or_else(|| "EXTENDED".into());
            rec.cluster.upgrade_policy = Some(types::UpgradePolicyResponse { support_type: Some(t.clone()) });
            ("UpgradePolicyUpdate", vec![param("UpgradePolicy", format!("{{\"supportType\":\"{t}\"}}"))])
        } else if let Some(z) = &input.zonal_shift_config {
            rec.cluster.zonal_shift_config = Some(convert(z));
            ("ZonalShiftConfigUpdate", vec![param("ZonalShiftConfig", json(z))])
        } else if auto_mode || input.kubernetes_network_config.is_some() {
            let compute = input
                .compute_config
                .as_ref()
                .and_then(|c| c.enabled)
                .or_else(|| rec.cluster.compute_config.as_ref().and_then(|c| c.enabled))
                .unwrap_or(false);
            let storage = input
                .storage_config
                .as_ref()
                .and_then(|s| s.block_storage.as_ref())
                .and_then(|b| b.enabled)
                .or_else(|| {
                    rec.cluster.storage_config.as_ref().and_then(|s| s.block_storage.as_ref()).and_then(|b| b.enabled)
                })
                .unwrap_or(false);
            let elb = input
                .kubernetes_network_config
                .as_ref()
                .and_then(|k| k.elastic_load_balancing.as_ref())
                .and_then(|e| e.enabled)
                .or_else(|| {
                    rec.cluster
                        .kubernetes_network_config
                        .as_ref()
                        .and_then(|k| k.elastic_load_balancing.as_ref())
                        .and_then(|e| e.enabled)
                })
                .unwrap_or(false);
            if !(compute == storage && storage == elb) {
                return Err(auto_mode_mismatch());
            }
            let mut params = Vec::new();
            if let Some(c) = &input.compute_config {
                if let Some(role) = &c.node_role_arn {
                    util::pass_role(ctx, role, "ec2.amazonaws.com")?;
                }
                rec.cluster.compute_config = Some(convert(c));
                params.push(param("ComputeConfig", json(c)));
            }
            if let Some(s) = &input.storage_config {
                rec.cluster.storage_config = Some(convert(s));
                params.push(param("StorageConfig", json(s)));
            }
            if let Some(k) = &input.kubernetes_network_config {
                let cfg = rec.cluster.kubernetes_network_config.get_or_insert_with(Default::default);
                if k.elastic_load_balancing.is_some() {
                    cfg.elastic_load_balancing = k.elastic_load_balancing.clone();
                }
                params.push(param("KubernetesNetworkConfig", json(k)));
            }
            ("AutoModeUpdate", params)
        } else if let Some(r) = &input.remote_network_config {
            rec.cluster.remote_network_config = Some(convert(r));
            ("RemoteNetworkConfigUpdate", vec![param("RemoteNetworkConfig", json(r))])
        } else if let Some(d) = input.deletion_protection {
            rec.cluster.deletion_protection = Some(d);
            ("DeletionProtectionUpdate", vec![param("DeletionProtection", d.to_string())])
        } else if let Some(t) = &input.control_plane_scaling_config {
            let previous = rec
                .cluster
                .control_plane_scaling_config
                .as_ref()
                .and_then(|c| c.tier.clone())
                .unwrap_or_else(|| "standard".into());
            let tier = t.tier.clone().unwrap_or_else(|| "standard".into());
            rec.cluster.control_plane_scaling_config = Some(t.clone());
            ("ControlPlaneScalingConfigUpdate", vec![param("UpdatedTier", tier), param("PreviousTier", previous)])
        } else {
            let mut params = Vec::new();
            if let Some(c) = &input.kube_api_server_config {
                rec.cluster.kube_api_server_config = Some(convert(c));
                params.push(param("KubeApiServerConfig", json(c)));
            }
            if let Some(c) = &input.kube_scheduler_config {
                rec.cluster.kube_scheduler_config = Some(convert(c));
                params.push(param("KubeSchedulerConfig", json(c)));
            }
            if let Some(c) = &input.kube_controller_manager_config {
                rec.cluster.kube_controller_manager_config = Some(convert(c));
                params.push(param("KubeControllerManagerConfig", json(c)));
            }
            ("ControlPlaneComponentConfigUpdate", params)
        };
        rec.cluster.status = Some("UPDATING".into());
        let update = crate::updates::push(rec, now, kind, params, None);
        Ok(types::UpdateClusterConfigResponse { update: Some(update) })
    }

    pub(crate) async fn associate_encryption_config(
        &self,
        ctx: &RequestContext,
        input: types::AssociateEncryptionConfigRequest,
    ) -> Result<types::AssociateEncryptionConfigResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(
            ctx,
            "AssociateEncryptionConfig",
            &arn,
            rec.cluster.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        check_updatable(rec, &input.cluster_name)?;
        if rec.cluster.encryption_config.as_ref().is_some_and(|e| !e.is_empty()) {
            return Err(errors::invalid_request("Encryption is already enabled on the cluster")
                .with_field("clusterName", text(&input.cluster_name)));
        }
        check_encryption(&input.encryption_config)?;
        rec.cluster.encryption_config = Some(input.encryption_config.clone());
        rec.cluster.status = Some("UPDATING".into());
        let value = serde_json::to_string(
            &input
                .encryption_config
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "resources": e.resources.clone().unwrap_or_default(),
                        "provider": {"keyArn": e.provider.as_ref().and_then(|p| p.key_arn.clone())},
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();
        let update = crate::updates::push(
            rec,
            ctx.received_at,
            "AssociateEncryptionConfig",
            vec![param("EncryptionConfig", value)],
            None,
        );
        Ok(types::AssociateEncryptionConfigResponse { update: Some(update) })
    }

    pub(crate) async fn describe_cluster_versions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeClusterVersionsRequest,
    ) -> Result<types::DescribeClusterVersionsResponse, ServiceError> {
        util::authorize(ctx, "DescribeClusterVersions", "*", None, None, ConditionContext::new())?;
        if let Some(t) = input.cluster_type.as_deref().filter(|t| !matches!(*t, "eks" | "eks-local-outposts")) {
            return Err(errors::invalid_parameter(format!("Invalid cluster type {t}.")));
        }
        let now = ctx.received_at;
        let wanted = input.cluster_versions.clone().unwrap_or_default();
        let versions: Vec<types::ClusterVersionInformation> = catalog::VERSIONS
            .iter()
            .filter(|v| {
                input.include_all == Some(true)
                    || v.status(now) != "unsupported"
                    || wanted.iter().any(|w| w == v.version)
            })
            .filter(|v| input.default_only != Some(true) || v.default)
            .filter(|v| wanted.is_empty() || wanted.iter().any(|w| w == v.version))
            .filter(|v| input.status.as_deref().is_none_or(|s| s == v.status(now)))
            .filter(|v| input.version_status.as_deref().is_none_or(|s| s == version_status(v.status(now))))
            .map(|v| types::ClusterVersionInformation {
                cluster_version: Some(v.version.into()),
                cluster_type: Some(input.cluster_type.clone().unwrap_or_else(|| "eks".into())),
                default_platform_version: Some(v.platform_version.into()),
                default_version: v.default,
                release_date: Some(v.release_date()),
                end_of_standard_support_date: Some(v.end_of_standard_support()),
                end_of_extended_support_date: Some(v.end_of_extended_support()),
                status: Some(v.status(now).into()),
                version_status: Some(version_status(v.status(now)).into()),
                kubernetes_patch_version: Some(v.patch.into()),
                ..Default::default()
            })
            .collect();
        let (items, next) = util::page(&versions, input.max_results, input.next_token.as_deref())?;
        Ok(types::DescribeClusterVersionsResponse { cluster_versions: Some(items), next_token: next })
    }
}

fn version_status(status: &str) -> &'static str {
    match status {
        "standard-support" => "STANDARD_SUPPORT",
        "extended-support" => "EXTENDED_SUPPORT",
        _ => "UNSUPPORTED",
    }
}

fn json<T: Serialize>(v: &T) -> String {
    // Update params carry the request's JSON (camelCase member names).
    let raw = serde_json::to_value(v).unwrap_or_default();
    serde_json::to_string(&camel(raw)).unwrap_or_default()
}

fn camel(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => serde_json::Value::Object(
            m.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| {
                    let mut out = String::new();
                    let mut upper = false;
                    for c in k.trim_start_matches("r#").chars() {
                        if c == '_' {
                            upper = true;
                        } else if upper {
                            out.extend(c.to_uppercase());
                            upper = false;
                        } else {
                            out.push(c);
                        }
                    }
                    (out, camel(v))
                })
                .collect(),
        ),
        serde_json::Value::Array(a) => serde_json::Value::Array(a.into_iter().map(camel).collect()),
        other => other,
    }
}

pub(crate) fn in_use(name: &str) -> ServiceError {
    errors::resource_in_use(format!("Cluster already exists with name: {name}")).with_field("clusterName", text(name))
}

fn auto_mode_mismatch() -> ServiceError {
    errors::invalid_parameter(
        "For EKS Auto Mode, please ensure that all required configs, including computeConfig, kubernetesNetworkConfig, and blockStorage are all either fully enabled or fully disabled.",
    )
}

fn endpoint_access_error() -> ServiceError {
    errors::invalid_parameter("Cluster must have either public or private API server endpoint access enabled.")
}

fn check_updatable(rec: &ClusterRec, name: &str) -> Result<(), ServiceError> {
    if rec.registered {
        return Err(errors::invalid_request(format!("Cluster {name} is a registered cluster and cannot be updated."))
            .with_field("clusterName", text(name)));
    }
    match rec.cluster.status.as_deref() {
        Some("ACTIVE") => Ok(()),
        Some(s) => Err(errors::resource_in_use(format!("Cluster {name} is in {s} state and cannot be updated."))
            .with_field("clusterName", text(name))),
        None => Ok(()),
    }
}

fn vpc_of(facts: &[SubnetFacts]) -> Result<String, ServiceError> {
    let first = facts.first().map(|f| f.vpc_id.clone()).unwrap_or_default();
    if facts.iter().any(|f| f.vpc_id != first) {
        return Err(errors::invalid_parameter("Subnets specified must belong to the same VPC."));
    }
    Ok(first)
}

fn check_encryption(enc: &[types::EncryptionConfig]) -> Result<(), ServiceError> {
    if enc.len() != 1 {
        return Err(errors::invalid_parameter("Only one encryption configuration is supported."));
    }
    let e = &enc[0];
    if e.resources.as_deref() != Some(&["secrets".to_string()][..]) {
        return Err(errors::invalid_parameter("Encryption is only supported for the resource type: secrets"));
    }
    let key = e.provider.as_ref().and_then(|p| p.key_arn.as_deref()).unwrap_or_default();
    let parts: Vec<&str> = key.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "kms" || !parts[5].starts_with("key/") {
        return Err(errors::invalid_parameter(format!("Invalid KMS key ARN: {key}")));
    }
    Ok(())
}

fn check_public_cidrs(cidrs: &[String]) -> Result<(), ServiceError> {
    for c in cidrs {
        if parse_cidr(c).is_none() {
            return Err(errors::invalid_parameter(format!(
                "The following CIDRs are invalid in publicAccessCidrs: [{c}]"
            )));
        }
    }
    Ok(())
}

fn parse_cidr(c: &str) -> Option<(u32, u8)> {
    let (ip, len) = c.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    (len <= 32).then_some((u32::from(ip), len))
}

fn check_service_cidr(c: &str) -> Result<(), ServiceError> {
    let invalid = || {
        errors::invalid_parameter(format!(
            "The specified serviceIpv4Cidr {c} is invalid. It must be within 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16, with a prefix between /12 and /24."
        ))
    };
    let (ip, len) = parse_cidr(c).ok_or_else(invalid)?;
    let within = |base: u32, bits: u8| len >= bits && (ip >> (32 - bits)) == (base >> (32 - bits));
    let private = within(0x0a00_0000, 8) || within(0xac10_0000, 12) || within(0xc0a8_0000, 16);
    if !private || !(12..=24).contains(&len) {
        return Err(invalid());
    }
    Ok(())
}

/// EKS reports logging as one setup of enabled types and one of disabled
/// ones.
fn normalize_logging(current: Option<&types::Logging>, change: Option<&types::Logging>) -> types::Logging {
    let mut enabled: BTreeMap<&str, bool> = LOG_TYPES.iter().map(|t| (*t, false)).collect();
    for setup in current.into_iter().chain(change).flat_map(|l| l.cluster_logging.iter().flatten()) {
        let on = setup.enabled.unwrap_or(false);
        for t in setup.types.iter().flatten() {
            if let Some(slot) = LOG_TYPES.iter().find(|x| **x == t.as_str()) {
                enabled.insert(slot, on);
            }
        }
    }
    let on: Vec<String> = LOG_TYPES.iter().filter(|t| enabled[*t]).map(|t| t.to_string()).collect();
    let off: Vec<String> = LOG_TYPES.iter().filter(|t| !enabled[*t]).map(|t| t.to_string()).collect();
    let mut setups = Vec::new();
    if !on.is_empty() {
        setups.push(types::LogSetup { types: Some(on), enabled: Some(true) });
    }
    if !off.is_empty() {
        setups.push(types::LogSetup { types: Some(off), enabled: Some(false) });
    }
    types::Logging { cluster_logging: Some(setups) }
}

fn logging_json(l: &types::Logging) -> serde_json::Value {
    serde_json::json!({
        "clusterLogging": l.cluster_logging.iter().flatten().map(|s| serde_json::json!({
            "types": s.types.clone().unwrap_or_default(),
            "enabled": s.enabled.unwrap_or(false),
        })).collect::<Vec<_>>()
    })
}

/// The principal an access entry for the caller names: the IAM role behind
/// an assumed-role session, the IAM user, or the account root.
fn creator_principal(ctx: &RequestContext) -> String {
    let c = &ctx.caller;
    match &c.kind {
        mws_core::CallerKind::AssumedRole { role_name, .. } => {
            format!("arn:{}:iam::{}:role/{role_name}", ctx.partition, c.account_id)
        }
        _ => c.arn.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_cidrs() {
        assert!(check_service_cidr("10.100.0.0/16").is_ok());
        assert!(check_service_cidr("172.20.0.0/16").is_ok());
        assert!(check_service_cidr("192.168.0.0/24").is_ok());
        assert!(check_service_cidr("8.8.0.0/16").is_err());
        assert!(check_service_cidr("10.0.0.0/8").is_err());
        assert!(check_service_cidr("10.0.0.0/28").is_err());
    }

    #[test]
    fn logging_merges() {
        let change = types::Logging {
            cluster_logging: Some(vec![types::LogSetup {
                types: Some(vec!["api".into(), "audit".into()]),
                enabled: Some(true),
            }]),
        };
        let l = normalize_logging(None, Some(&change));
        let setups = l.cluster_logging.unwrap();
        assert_eq!(setups[0].types.as_deref().unwrap(), ["api", "audit"]);
        assert_eq!(setups[1].types.as_deref().unwrap(), ["authenticator", "controllerManager", "scheduler"]);
    }
}
