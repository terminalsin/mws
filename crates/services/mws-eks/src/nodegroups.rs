//! Managed node groups. With infrastructure wired in, a node group is EC2
//! instances from the EKS-optimized AMI for its Kubernetes version, in its
//! subnets and the cluster security group, with an instance profile for the
//! node role; scaling and version updates start and terminate instances.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::catalog;
use crate::generated::{errors, types};
use crate::infra::NodeLaunch;
use crate::state::NodegroupRec;
use crate::updates::Target;
use crate::util::{self, param, text, Tags};
use crate::Eks;

pub(crate) fn not_found(cluster: &str, nodegroup: &str) -> ServiceError {
    errors::resource_not_found(format!("No node group found for name: {nodegroup}."))
        .with_field("clusterName", text(cluster))
        .with_field("nodegroupName", text(nodegroup))
}

/// Facts about the cluster a node group needs.
struct ClusterFacts {
    version: String,
    vpc_id: Option<String>,
    security_group: Option<String>,
    tags: Option<Tags>,
}

fn check_scaling(s: &types::NodegroupScalingConfig) -> Result<(i32, i32, i32), ServiceError> {
    let min = s.min_size.unwrap_or(1);
    let max = s.max_size.unwrap_or(2);
    let desired = s.desired_size.unwrap_or(min.max(1).min(max));
    if min > max {
        return Err(errors::invalid_parameter(format!("Minimum capacity {min} can't be greater than max size {max}")));
    }
    if desired > max {
        return Err(errors::invalid_parameter(format!(
            "Desired capacity {desired} can't be greater than max size {max}"
        )));
    }
    if desired < min {
        return Err(errors::invalid_parameter(format!(
            "Minimum capacity {min} can't be greater than desired size {desired}"
        )));
    }
    Ok((min, max, desired))
}

fn check_update_config(u: &types::NodegroupUpdateConfig) -> Result<(), ServiceError> {
    if u.max_unavailable.is_some() && u.max_unavailable_percentage.is_some() {
        return Err(errors::invalid_parameter(
            "You can specify either maxUnavailable or maxUnavailablePercentage, but not both.",
        ));
    }
    if let Some(m) = u.max_unavailable.filter(|m| *m > 100) {
        return Err(errors::invalid_parameter(format!("maxUnavailable {m} can't be greater than 100.")));
    }
    Ok(())
}

fn check_taints(taints: &[types::Taint]) -> Result<(), ServiceError> {
    if taints.len() > 50 {
        return Err(errors::invalid_parameter("A node group can have at most 50 taints."));
    }
    for t in taints {
        if t.key.as_deref().unwrap_or_default().is_empty() || t.effect.is_none() {
            return Err(errors::invalid_parameter("Taints must have a key and an effect."));
        }
    }
    Ok(())
}

fn node_tags(cluster: &str, nodegroup: &str) -> Tags {
    [
        ("eks:cluster-name".to_string(), cluster.to_string()),
        ("eks:nodegroup-name".to_string(), nodegroup.to_string()),
        (format!("kubernetes.io/cluster/{cluster}"), "owned".to_string()),
        ("k8s.io/cluster-autoscaler/enabled".to_string(), "true".to_string()),
        (format!("k8s.io/cluster-autoscaler/{cluster}"), "owned".to_string()),
    ]
    .into_iter()
    .collect()
}

fn launch_spec(cluster: &str, rec: &NodegroupRec, count: usize) -> Option<NodeLaunch> {
    let ng = &rec.nodegroup;
    Some(NodeLaunch {
        cluster_name: cluster.into(),
        nodegroup_name: ng.nodegroup_name.clone()?,
        group_name: ng.resources.as_ref()?.auto_scaling_groups.as_ref()?.first()?.name.clone()?,
        image_id: rec.image_id.clone()?,
        instance_type: ng
            .instance_types
            .as_ref()
            .and_then(|t| t.first().cloned())
            .unwrap_or_else(|| "t3.medium".into()),
        subnets: ng.subnets.clone().unwrap_or_default(),
        count,
        security_group_ids: rec.security_groups.clone(),
        instance_profile_arn: rec.instance_profile.clone(),
        key_name: ng.remote_access.as_ref().and_then(|r| r.ec2_ssh_key.clone()),
        disk_size_gib: ng.disk_size,
        tags: node_tags(cluster, ng.nodegroup_name.as_deref().unwrap_or_default()),
    })
}

fn degrade(ng: &mut types::Nodegroup, code: &str, message: String, resources: Vec<String>) {
    let issues = ng.health.get_or_insert_with(Default::default).issues.get_or_insert_with(Vec::new);
    issues.push(types::Issue { code: Some(code.into()), message: Some(message), resource_ids: Some(resources) });
}

impl Eks {
    fn cluster_facts(&self, ctx: &RequestContext, cluster: &str) -> Result<ClusterFacts, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, cluster)?;
        if rec.registered {
            return Err(errors::invalid_request(format!(
                "Managed node groups can't be created in registered cluster {cluster}."
            ))
            .with_field("clusterName", text(cluster)));
        }
        if rec.cluster.status.as_deref() != Some("ACTIVE") {
            return Err(errors::invalid_request(format!("Cluster '{cluster}' is not in ACTIVE status"))
                .with_field("clusterName", text(cluster)));
        }
        let vpc = rec.cluster.resources_vpc_config.as_ref();
        Ok(ClusterFacts {
            version: rec.cluster.version.clone().unwrap_or_else(|| catalog::default_version().version.into()),
            vpc_id: vpc.and_then(|v| v.vpc_id.clone()),
            security_group: vpc.and_then(|v| v.cluster_security_group_id.clone()),
            tags: rec.cluster.tags.clone(),
        })
    }

    pub(crate) async fn create_nodegroup(
        &self,
        ctx: &RequestContext,
        input: types::CreateNodegroupRequest,
    ) -> Result<types::CreateNodegroupResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.nodegroup_name.clone();
        let cluster_arn = util::cluster_arn(ctx, &cluster);
        let facts = self.cluster_facts(ctx, &cluster)?;
        util::authorize(
            ctx,
            "CreateNodegroup",
            &cluster_arn,
            facts.tags.as_ref(),
            input.tags.as_ref(),
            ConditionContext::new(),
        )?;
        util::check_create_tags(input.tags.as_ref())?;
        {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            if let Some(existing) = rec.nodegroups.get(&name) {
                if input.client_request_token.is_some()
                    && existing.nodegroup.tags.as_ref() == input.tags.as_ref()
                    && existing.nodegroup.node_role.as_deref() == Some(input.node_role.as_str())
                {
                    return Ok(types::CreateNodegroupResponse { nodegroup: Some(existing.nodegroup.clone()) });
                }
                return Err(errors::resource_in_use(format!(
                    "NodeGroup already exists with name {name} and cluster name {cluster}"
                ))
                .with_field("clusterName", text(&cluster))
                .with_field("nodegroupName", text(&name)));
            }
        }

        // Kubernetes version and AMI.
        let version = input.version.clone().unwrap_or_else(|| facts.version.clone());
        let kube = catalog::version(&version)
            .ok_or_else(|| errors::invalid_parameter(format!("Requested Nodegroup version {version} is invalid.")))?;
        let cluster_minor = catalog::minor(&facts.version).unwrap_or_default();
        if kube.minor() > cluster_minor {
            return Err(errors::invalid_parameter(format!(
                "Requested Nodegroup version {version} is invalid. Nodegroup version must be no greater than the cluster version {}.",
                facts.version
            )));
        }
        if let Some(lt) = &input.launch_template {
            if lt.id.is_some() == lt.name.is_some() {
                return Err(errors::invalid_parameter(
                    "Either the launch template ID or the launch template name must be specified, but not both.",
                ));
            }
            if input.remote_access.is_some() {
                return Err(errors::invalid_parameter(
                    "Remote access configuration cannot be specified with a launch template.",
                ));
            }
            if input.disk_size.is_some() {
                return Err(errors::invalid_parameter("Disk size must be specified within the launch template."));
            }
        }
        let instance_types = input.instance_types.clone().unwrap_or_else(|| vec!["t3.medium".into()]);
        if instance_types.is_empty() {
            return Err(errors::invalid_parameter("instanceTypes must not be empty."));
        }
        let ami_type = input.ami_type.clone().unwrap_or_else(|| {
            let arm = catalog::instance_arch(&instance_types[0]) == "arm64";
            match (kube.minor() >= 30, arm) {
                (true, true) => "AL2023_ARM_64_STANDARD",
                (true, false) => "AL2023_x86_64_STANDARD",
                (false, true) => "AL2_ARM_64",
                (false, false) => "AL2_x86_64",
            }
            .into()
        });
        if ami_type == "CUSTOM" && input.launch_template.is_none() {
            return Err(errors::invalid_parameter("A launch template with an AMI ID is required for amiType CUSTOM."));
        }
        if ami_type.starts_with("AL2_") && kube.minor() > 32 {
            return Err(errors::invalid_parameter(format!(
                "AMI Type {ami_type} is only supported for kubernetes versions 1.32 or earlier"
            )));
        }
        if ami_type != "CUSTOM" {
            let arch = catalog::ami_arch(&ami_type);
            let wrong: Vec<&String> = instance_types.iter().filter(|t| catalog::instance_arch(t) != arch).collect();
            if !wrong.is_empty() {
                return Err(errors::invalid_parameter(format!(
                    "[{}] is not a valid instance type for requested amiType {ami_type}",
                    wrong.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                )));
            }
        }
        let release = match &input.release_version {
            Some(r) => r.clone(),
            None => catalog::release_version(kube, &ami_type),
        };

        // Scaling and update policy.
        let scaling = input.scaling_config.clone().unwrap_or_default();
        let (min, max, desired) = check_scaling(&scaling)?;
        let update_config = input
            .update_config
            .clone()
            .unwrap_or(types::NodegroupUpdateConfig { max_unavailable: Some(1), ..Default::default() });
        check_update_config(&update_config)?;
        let taints = input.taints.clone().unwrap_or_default();
        check_taints(&taints)?;
        if input.subnets.is_empty() {
            return Err(errors::invalid_parameter("Subnets are required."));
        }

        // The node role must exist and trust EC2.
        let role = input.node_role.clone();
        self.check_role(
            ctx,
            &role,
            "ec2.amazonaws.com",
            || format!("The role with name {} cannot be found.", util::arn_name(&role)),
            || format!("Following required service principals [ec2.amazonaws.com] were not found in the trust relationships of nodeRole {role}"),
        )?;

        // Subnets must be in the cluster's VPC.
        if let Some(subnets) = self.subnet_facts(ctx, &input.subnets).await? {
            if let Some(vpc) = &facts.vpc_id {
                if let Some(s) = subnets.iter().find(|s| &s.vpc_id != vpc) {
                    return Err(errors::invalid_parameter(format!(
                        "Subnet {} is not in the same VPC as the cluster ({vpc}).",
                        s.subnet_id
                    )));
                }
            }
        }

        let uuid = util::uuid();
        let arn = util::arn(ctx, &format!("nodegroup/{cluster}/{name}/{uuid}"));
        let now = ctx.received_at;
        let disk_size = match (&input.launch_template, &ami_type) {
            (Some(_), _) => None,
            (None, t) if t.starts_with("WINDOWS") => Some(input.disk_size.unwrap_or(50)),
            (None, t) if t.starts_with("BOTTLEROCKET") => Some(input.disk_size.unwrap_or(4)),
            (None, _) => Some(input.disk_size.unwrap_or(20)),
        };
        let mut nodegroup = types::Nodegroup {
            nodegroup_name: Some(name.clone()),
            nodegroup_arn: Some(arn),
            cluster_name: Some(cluster.clone()),
            version: Some(kube.version.into()),
            release_version: Some(release),
            created_at: Some(now),
            modified_at: Some(now),
            status: Some("CREATING".into()),
            capacity_type: Some(input.capacity_type.clone().unwrap_or_else(|| "ON_DEMAND".into())),
            scaling_config: Some(types::NodegroupScalingConfig {
                min_size: Some(min),
                max_size: Some(max),
                desired_size: Some(desired),
            }),
            instance_types: (input.launch_template.is_none() || input.instance_types.is_some())
                .then_some(instance_types),
            subnets: Some(input.subnets.clone()),
            remote_access: input.remote_access.clone(),
            ami_type: Some(ami_type.clone()),
            node_role: Some(role.clone()),
            labels: Some(input.labels.clone().unwrap_or_default()),
            taints: (!taints.is_empty()).then_some(taints),
            resources: Some(types::NodegroupResources {
                auto_scaling_groups: Some(vec![types::AutoScalingGroup { name: Some(format!("eks-{name}-{uuid}")) }]),
                remote_access_security_group: None,
            }),
            disk_size,
            health: Some(types::NodegroupHealth { issues: Some(Vec::new()) }),
            update_config: Some(update_config),
            node_repair_config: input.node_repair_config.clone(),
            launch_template: input.launch_template.clone().map(|mut lt| {
                lt.version.get_or_insert_with(|| "1".into());
                lt
            }),
            tags: Some(input.tags.clone().unwrap_or_default()),
            warm_pool_config: input.warm_pool_config.clone(),
        };
        let mut rec =
            NodegroupRec { security_groups: facts.security_group.clone().into_iter().collect(), ..Default::default() };

        // The instances.
        if let Some(infra) = self.infra().cloned() {
            let scope = util::scope(ctx);
            if let Some(remote) = &input.remote_access {
                if remote.source_security_groups.as_ref().is_none_or(|g| g.is_empty()) {
                    if let Some(vpc) = &facts.vpc_id {
                        let sg_name = format!("eks-remoteAccess-{uuid}");
                        let tags: Tags = [
                            ("eks:cluster-name".to_string(), cluster.clone()),
                            ("eks:nodegroup-name".to_string(), name.clone()),
                        ]
                        .into_iter()
                        .collect();
                        match infra
                            .create_security_group(
                                &scope,
                                vpc,
                                &sg_name,
                                "Security group for all nodes in the nodeGroup to allow SSH access",
                                &tags,
                                false,
                                true,
                            )
                            .await
                        {
                            Ok(id) => {
                                nodegroup.resources.as_mut().expect("set").remote_access_security_group =
                                    Some(id.clone());
                                rec.security_groups.push(id);
                                rec.owns_remote_access_group = true;
                            }
                            Err(e) => return Err(util::infra_error(&e)),
                        }
                    }
                } else {
                    rec.security_groups.extend(remote.source_security_groups.clone().unwrap_or_default());
                }
            }
            rec.image_id = infra.node_image(&scope, kube.version, &ami_type).await;
            let profile_name = format!("eks-{uuid}");
            match infra.create_instance_profile(&scope, &profile_name, &role).await {
                Ok(arn) => rec.instance_profile = Some(arn),
                Err(e) => degrade(&mut nodegroup, "IamInstanceProfileNotFound", e.message.clone(), Vec::new()),
            }
            rec.nodegroup = nodegroup;
            match (rec.image_id.is_some(), desired) {
                (_, 0) => {}
                (false, _) => {
                    degrade(
                        &mut rec.nodegroup,
                        "AmiIdNotFound",
                        format!("No AMI found for amiType {ami_type} and Kubernetes version {}.", kube.version),
                        Vec::new(),
                    );
                    rec.nodegroup.status = Some("CREATE_FAILED".into());
                }
                (true, n) => {
                    let spec = launch_spec(&cluster, &rec, n as usize).expect("node group is complete");
                    match infra.launch(&scope, &spec).await {
                        Ok(ids) => rec.instances = ids,
                        Err(e) => {
                            let group = spec.group_name.clone();
                            degrade(&mut rec.nodegroup, "NodeCreationFailure", e.to_string(), vec![group]);
                            rec.nodegroup.status = Some("CREATE_FAILED".into());
                        }
                    }
                }
            }
        } else {
            rec.nodegroup = nodegroup;
        }

        let response = rec.nodegroup.clone();
        let mut st = self.write();
        let crec = util::cluster(&mut st, ctx, &cluster)?;
        let kind = if ami_type.starts_with("WINDOWS") { "EC2_WINDOWS" } else { "EC2_LINUX" };
        crate::access::ensure_node_entry(ctx, crec, &cluster, &role, kind);
        crec.nodegroups.insert(name, rec);
        Ok(types::CreateNodegroupResponse { nodegroup: Some(response) })
    }

    pub(crate) async fn describe_nodegroup(
        &self,
        ctx: &RequestContext,
        input: types::DescribeNodegroupRequest,
    ) -> Result<types::DescribeNodegroupResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let n = rec
            .nodegroups
            .get(&input.nodegroup_name)
            .ok_or_else(|| not_found(&input.cluster_name, &input.nodegroup_name))?;
        util::authorize(
            ctx,
            "DescribeNodegroup",
            n.nodegroup.nodegroup_arn.as_deref().unwrap_or_default(),
            n.nodegroup.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribeNodegroupResponse { nodegroup: Some(n.nodegroup.clone()) })
    }

    pub(crate) async fn list_nodegroups(
        &self,
        ctx: &RequestContext,
        input: types::ListNodegroupsRequest,
    ) -> Result<types::ListNodegroupsResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "ListNodegroups", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let names: Vec<String> = rec.nodegroups.keys().cloned().collect();
        let (items, next) = util::page(&names, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListNodegroupsResponse { nodegroups: Some(items), next_token: next })
    }

    /// Bring the node group's instance count to its desired size.
    async fn reconcile_instances(&self, ctx: &RequestContext, cluster: &str, name: &str) {
        let Some(infra) = self.infra().cloned() else { return };
        let scope = util::scope(ctx);
        let (spec, surplus) = {
            let mut st = self.write();
            let Ok(rec) = util::cluster(&mut st, ctx, cluster) else { return };
            let Some(n) = rec.nodegroups.get_mut(name) else { return };
            let desired = n.nodegroup.scaling_config.as_ref().and_then(|s| s.desired_size).unwrap_or(0).max(0) as usize;
            let have = n.instances.len();
            if desired > have {
                (launch_spec(cluster, n, desired - have), Vec::new())
            } else {
                (None, n.instances.split_off(desired))
            }
        };
        if !surplus.is_empty() {
            infra.terminate(&scope, &surplus).await;
        }
        if let Some(spec) = spec {
            let launched = infra.launch(&scope, &spec).await;
            let mut st = self.write();
            let Ok(rec) = util::cluster(&mut st, ctx, cluster) else { return };
            let Some(n) = rec.nodegroups.get_mut(name) else { return };
            match launched {
                Ok(ids) => n.instances.extend(ids),
                Err(e) => degrade(&mut n.nodegroup, "AsgInstanceLaunchFailures", e.to_string(), vec![spec.group_name]),
            }
        }
    }

    pub(crate) async fn update_nodegroup_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateNodegroupConfigRequest,
    ) -> Result<types::UpdateNodegroupConfigResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.nodegroup_name.clone();
        let (update, resize) = {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            let n = rec.nodegroups.get_mut(&name).ok_or_else(|| not_found(&cluster, &name))?;
            util::authorize(
                ctx,
                "UpdateNodegroupConfig",
                n.nodegroup.nodegroup_arn.as_deref().unwrap_or_default(),
                n.nodegroup.tags.as_ref(),
                None,
                ConditionContext::new(),
            )?;
            if n.nodegroup.status.as_deref() != Some("ACTIVE") && n.nodegroup.status.as_deref() != Some("DEGRADED") {
                return Err(errors::resource_in_use(format!(
                    "Nodegroup {name} is in {} state and cannot be updated.",
                    n.nodegroup.status.as_deref().unwrap_or_default()
                ))
                .with_field("clusterName", text(&cluster))
                .with_field("nodegroupName", text(&name)));
            }
            let mut params = Vec::new();
            let ng = &mut n.nodegroup;
            if let Some(labels) = &input.labels {
                let map = ng.labels.get_or_insert_with(BTreeMap::new);
                if let Some(add) = &labels.add_or_update_labels {
                    params.push(param("LabelsToAdd", serde_json::to_string(add).unwrap_or_default()));
                    map.extend(add.clone());
                }
                if let Some(remove) = &labels.remove_labels {
                    params.push(param("LabelsToRemove", util::json_list(remove)));
                    for k in remove {
                        map.remove(k);
                    }
                }
            }
            if let Some(taints) = &input.taints {
                let list = ng.taints.get_or_insert_with(Vec::new);
                let key = |t: &types::Taint| (t.key.clone(), t.effect.clone());
                if let Some(add) = &taints.add_or_update_taints {
                    check_taints(add)?;
                    params.push(param("TaintsToAdd", taints_json(add)));
                    for t in add {
                        list.retain(|x| key(x) != key(t));
                        list.push(t.clone());
                    }
                }
                if let Some(remove) = &taints.remove_taints {
                    params.push(param("TaintsToRemove", taints_json(remove)));
                    list.retain(|x| !remove.iter().any(|t| key(t) == key(x)));
                }
                if list.is_empty() {
                    ng.taints = None;
                }
            }
            let mut resize = false;
            if let Some(s) = &input.scaling_config {
                let current = ng.scaling_config.clone().unwrap_or_default();
                let merged = types::NodegroupScalingConfig {
                    min_size: s.min_size.or(current.min_size),
                    max_size: s.max_size.or(current.max_size),
                    desired_size: s.desired_size.or(current.desired_size),
                };
                let (min, max, desired) = check_scaling(&merged)?;
                if s.min_size.is_some() {
                    params.push(param("MinSize", min.to_string()));
                }
                if s.max_size.is_some() {
                    params.push(param("MaxSize", max.to_string()));
                }
                if s.desired_size.is_some() {
                    params.push(param("DesiredSize", desired.to_string()));
                }
                resize = current.desired_size != Some(desired);
                ng.scaling_config = Some(types::NodegroupScalingConfig {
                    min_size: Some(min),
                    max_size: Some(max),
                    desired_size: Some(desired),
                });
            }
            if let Some(u) = &input.update_config {
                check_update_config(u)?;
                let cfg = ng.update_config.get_or_insert_with(Default::default);
                if let Some(m) = u.max_unavailable {
                    params.push(param("MaxUnavailable", m.to_string()));
                    cfg.max_unavailable = Some(m);
                    cfg.max_unavailable_percentage = None;
                }
                if let Some(p) = u.max_unavailable_percentage {
                    params.push(param("MaxUnavailablePercentage", p.to_string()));
                    cfg.max_unavailable_percentage = Some(p);
                    cfg.max_unavailable = None;
                }
                if let Some(s) = &u.update_strategy {
                    params.push(param("UpdateStrategy", s.clone()));
                    cfg.update_strategy = Some(s.clone());
                }
            }
            if let Some(r) = &input.node_repair_config {
                params.push(param("NodeRepairEnabled", r.enabled.unwrap_or(false).to_string()));
                ng.node_repair_config = Some(r.clone());
            }
            if let Some(w) = &input.warm_pool_config {
                if let Some(e) = w.enabled {
                    params.push(param("WarmPoolEnabled", e.to_string()));
                }
                if let Some(m) = w.min_size {
                    params.push(param("WarmPoolMinSize", m.to_string()));
                }
                if let Some(m) = w.max_group_prepared_capacity {
                    params.push(param("WarmPoolMaxGroupPreparedCapacity", m.to_string()));
                }
                if let Some(s) = &w.pool_state {
                    params.push(param("WarmPoolState", s.clone()));
                }
                if let Some(r) = w.reuse_on_scale_in {
                    params.push(param("WarmPoolReuseOnScaleIn", r.to_string()));
                }
                ng.warm_pool_config = Some(w.clone());
            }
            if params.is_empty() {
                return Err(errors::invalid_parameter(
                    "No changes needed. Specify at least one configuration to update.",
                )
                .with_field("nodegroupName", text(&name)));
            }
            ng.status = Some("UPDATING".into());
            ng.modified_at = Some(ctx.received_at);
            let update =
                crate::updates::push(rec, ctx.received_at, "ConfigUpdate", params, Some(Target::Nodegroup(&name)));
            (update, resize)
        };
        if resize {
            self.reconcile_instances(ctx, &cluster, &name).await;
        }
        Ok(types::UpdateNodegroupConfigResponse { update: Some(update) })
    }

    pub(crate) async fn update_nodegroup_version(
        &self,
        ctx: &RequestContext,
        input: types::UpdateNodegroupVersionRequest,
    ) -> Result<types::UpdateNodegroupVersionResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.nodegroup_name.clone();
        let cluster_version = {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            let n = rec.nodegroups.get(&name).ok_or_else(|| not_found(&cluster, &name))?;
            util::authorize(
                ctx,
                "UpdateNodegroupVersion",
                n.nodegroup.nodegroup_arn.as_deref().unwrap_or_default(),
                n.nodegroup.tags.as_ref(),
                None,
                ConditionContext::new(),
            )?;
            if n.nodegroup.status.as_deref() != Some("ACTIVE") && n.nodegroup.status.as_deref() != Some("DEGRADED") {
                return Err(errors::resource_in_use(format!(
                    "Nodegroup {name} is in {} state and cannot be updated.",
                    n.nodegroup.status.as_deref().unwrap_or_default()
                ))
                .with_field("nodegroupName", text(&name)));
            }
            rec.cluster.version.clone().unwrap_or_default()
        };
        let target = input.version.clone().unwrap_or_else(|| cluster_version.clone());
        let kube = catalog::version(&target)
            .ok_or_else(|| errors::invalid_parameter(format!("Requested Nodegroup version {target} is invalid.")))?;
        if kube.minor() > catalog::minor(&cluster_version).unwrap_or_default() {
            return Err(errors::invalid_parameter(format!(
                "Requested Nodegroup version {target} is invalid. Nodegroup version must be no greater than the cluster version {cluster_version}."
            )));
        }
        let (ami_type, current_version, current_release, uses_template) = {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            let n = rec.nodegroups.get(&name).ok_or_else(|| not_found(&cluster, &name))?;
            (
                n.nodegroup.ami_type.clone().unwrap_or_default(),
                n.nodegroup.version.clone().unwrap_or_default(),
                n.nodegroup.release_version.clone().unwrap_or_default(),
                n.nodegroup.launch_template.is_some(),
            )
        };
        if input.launch_template.is_some() && !uses_template {
            return Err(errors::invalid_parameter(
                "A launch template can't be specified for a node group that was not created with one.",
            ));
        }
        if ami_type.starts_with("AL2_") && kube.minor() > 32 {
            return Err(errors::invalid_parameter(format!(
                "AMI Type {ami_type} is only supported for kubernetes versions 1.32 or earlier"
            )));
        }
        if catalog::minor(&current_version).is_some_and(|m| m > kube.minor()) {
            return Err(errors::invalid_parameter(format!(
                "Requested Nodegroup version {target} is lower than the current version {current_version}."
            )));
        }
        let release = input.release_version.clone().unwrap_or_else(|| catalog::release_version(kube, &ami_type));
        if target == current_version && release == current_release && input.launch_template.is_none() {
            return Err(errors::invalid_parameter(format!(
                "Nodegroup {name} is already at version {target} and release version {release}."
            ))
            .with_field("nodegroupName", text(&name)));
        }
        let image = match self.infra() {
            Some(infra) => infra.node_image(&util::scope(ctx), kube.version, &ami_type).await,
            None => None,
        };
        let (update, old) = {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            let n = rec.nodegroups.get_mut(&name).ok_or_else(|| not_found(&cluster, &name))?;
            n.nodegroup.version = Some(kube.version.into());
            n.nodegroup.release_version = Some(release.clone());
            if let Some(lt) = &input.launch_template {
                n.nodegroup.launch_template = Some(lt.clone());
            }
            n.nodegroup.status = Some("UPDATING".into());
            n.nodegroup.modified_at = Some(ctx.received_at);
            if image.is_some() {
                n.image_id = image;
            }
            // A version update replaces every node.
            let old = std::mem::take(&mut n.instances);
            let mut params = vec![param("Version", kube.version), param("ReleaseVersion", release)];
            if let Some(lt) = &input.launch_template {
                if let Some(n) = &lt.name {
                    params.push(param("LaunchTemplateName", n.clone()));
                }
                if let Some(v) = &lt.version {
                    params.push(param("LaunchTemplateVersion", v.clone()));
                }
            }
            let update =
                crate::updates::push(rec, ctx.received_at, "VersionUpdate", params, Some(Target::Nodegroup(&name)));
            (update, old)
        };
        self.reconcile_instances(ctx, &cluster, &name).await;
        if let Some(infra) = self.infra() {
            if !old.is_empty() {
                infra.terminate(&util::scope(ctx), &old).await;
            }
        }
        Ok(types::UpdateNodegroupVersionResponse { update: Some(update) })
    }

    pub(crate) async fn delete_nodegroup(
        &self,
        ctx: &RequestContext,
        input: types::DeleteNodegroupRequest,
    ) -> Result<types::DeleteNodegroupResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.nodegroup_name.clone();
        let (response, instances, profile, remote_sg, role) = {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            let n = rec.nodegroups.get_mut(&name).ok_or_else(|| not_found(&cluster, &name))?;
            util::authorize(
                ctx,
                "DeleteNodegroup",
                n.nodegroup.nodegroup_arn.as_deref().unwrap_or_default(),
                n.nodegroup.tags.as_ref(),
                None,
                ConditionContext::new(),
            )?;
            if n.nodegroup.status.as_deref() == Some("DELETING") {
                return Err(errors::resource_in_use(format!("Nodegroup {name} is already being deleted."))
                    .with_field("nodegroupName", text(&name)));
            }
            n.nodegroup.status = Some("DELETING".into());
            n.nodegroup.modified_at = Some(ctx.received_at);
            let remote = n
                .owns_remote_access_group
                .then(|| n.nodegroup.resources.as_ref().and_then(|r| r.remote_access_security_group.clone()))
                .flatten();
            (
                n.nodegroup.clone(),
                std::mem::take(&mut n.instances),
                n.instance_profile.take(),
                remote,
                n.nodegroup.node_role.clone().unwrap_or_default(),
            )
        };
        if let Some(infra) = self.infra() {
            let scope = util::scope(ctx);
            if !instances.is_empty() {
                infra.terminate(&scope, &instances).await;
            }
            if let Some(p) = profile {
                infra.delete_instance_profile(&scope, util::arn_name(&p), &role).await;
            }
            if let Some(sg) = remote_sg {
                if let Err(e) = infra.delete_security_group(&scope, &sg).await {
                    tracing::warn!(nodegroup = %name, "EKS could not delete the remote access security group: {e}");
                }
            }
        }
        Ok(types::DeleteNodegroupResponse { nodegroup: Some(response) })
    }
}

fn taints_json(taints: &[types::Taint]) -> String {
    serde_json::to_string(
        &taints
            .iter()
            .map(|t| serde_json::json!({"key": t.key, "value": t.value, "effect": t.effect}))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default()
}
