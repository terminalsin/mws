//! What EKS creates in the account, done the way EKS's service-linked roles
//! do it: EC2 security groups and launch templates, Auto Scaling groups for
//! managed node groups, IAM instance profiles.

use std::collections::BTreeMap;
use std::sync::Arc;

use mws_core::{Caller, CallerKind, RequestContext, Service, ServiceError};
use mws_eks::{
    GroupState, Infrastructure, InfrastructureError, InstanceFacts, NodeGroupSpec, NodeGroupTemplate, Scope,
    SubnetFacts,
};
use serde_json::{json, Value};

pub(crate) struct EksInfrastructure {
    pub ec2: mws_ec2::Ec2,
    pub iam: mws_iam::Iam,
    pub autoscaling: mws_autoscaling::AutoScaling,
}

const CLUSTER_ROLE: &str = "AWSServiceRoleForAmazonEKS";
const NODEGROUP_ROLE: &str = "AWSServiceRoleForAmazonEKSNodegroup";

/// A request context for EKS acting through its service-linked role.
fn service_ctx(scope: &Scope<'_>, role: &str) -> RequestContext {
    RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        region: scope.region.to_string(),
        partition: scope.partition.to_string(),
        received_at: scope.now,
        caller: Caller {
            account_id: scope.account.to_string(),
            arn: format!("arn:{}:sts::{}:assumed-role/{role}/EKS", scope.partition, scope.account),
            user_id: format!("AROA{}:EKS", uuid::Uuid::new_v4().simple().to_string()[..17].to_uppercase()),
            access_key_id: String::new(),
            kind: CallerKind::AssumedRole { role_name: role.to_string(), session_name: "EKS".to_string() },
            session: None,
        },
        source_ip: None,
        secure_transport: true,
        authorizer: Arc::new(mws_core::AllowAll),
        endpoint: None,
    }
}

fn error(service: &str, e: ServiceError) -> InfrastructureError {
    InfrastructureError { service: service.to_string(), status: e.status, code: e.code.to_string(), message: e.message }
}

fn tag_spec(resource_type: &str, tags: &BTreeMap<String, String>) -> Value {
    json!([{
        "ResourceType": resource_type,
        "Tags": tags.iter().map(|(k, v)| json!({"Key": k, "Value": v})).collect::<Vec<_>>(),
    }])
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

impl EksInfrastructure {
    async fn ec2(&self, scope: &Scope<'_>, role: &str, op: &str, input: Value) -> Result<Value, InfrastructureError> {
        self.ec2.invoke(service_ctx(scope, role), op, input).await.map_err(|e| error("AmazonEC2", e))
    }

    async fn autoscaling(&self, scope: &Scope<'_>, op: &str, input: Value) -> Result<Value, InfrastructureError> {
        self.autoscaling
            .invoke(service_ctx(scope, NODEGROUP_ROLE), op, input)
            .await
            .map_err(|e| error("AmazonAutoScaling", e))
    }

    /// The EKS-managed launch template's data: the source template's (when
    /// the node group has one) with what EKS adds, as EKS merges them.
    async fn template_data(&self, scope: &Scope<'_>, spec: &NodeGroupSpec) -> Result<Value, InfrastructureError> {
        let mut data = json!({});
        if let Some(src) = &spec.source_template {
            let mut req = json!({"Versions": [src.version.clone().unwrap_or_else(|| "$Default".into())]});
            if let Some(id) = &src.id {
                req["LaunchTemplateId"] = json!(id);
            } else if let Some(name) = &src.name {
                req["LaunchTemplateName"] = json!(name);
            }
            let out = self.ec2(scope, NODEGROUP_ROLE, "DescribeLaunchTemplateVersions", req).await?;
            data = out
                .pointer("/LaunchTemplateVersions/0/LaunchTemplateData")
                .cloned()
                .map(strip_nulls)
                .unwrap_or_else(|| json!({}));
        }
        let obj = data.as_object_mut().expect("object");
        if let Some(image) = &spec.image_id {
            obj.insert("ImageId".into(), json!(image));
        }
        if !obj.contains_key("SecurityGroupIds") && !obj.contains_key("NetworkInterfaces") {
            obj.insert("SecurityGroupIds".into(), json!(spec.security_group_ids));
        }
        if let Some(p) = &spec.instance_profile_arn {
            obj.insert("IamInstanceProfile".into(), json!({"Arn": p}));
        }
        if let Some(k) = &spec.key_name {
            obj.insert("KeyName".into(), json!(k));
        }
        if let Some(size) = spec.disk_size_gib {
            obj.entry("BlockDeviceMappings").or_insert_with(|| {
                json!([{
                    "DeviceName": "/dev/xvda",
                    "Ebs": {"VolumeSize": size, "VolumeType": "gp3", "DeleteOnTermination": true},
                }])
            });
        }
        obj.entry("MetadataOptions").or_insert_with(|| json!({"HttpPutResponseHopLimit": 2, "HttpTokens": "required"}));
        let mut tag_specs = obj.remove("TagSpecifications").and_then(|v| v.as_array().cloned()).unwrap_or_default();
        if !tag_specs.iter().any(|t| str_at(t, "ResourceType") == "instance") {
            let name =
                BTreeMap::from([("Name".to_string(), format!("{}-{}-Node", spec.cluster_name, spec.nodegroup_name))]);
            tag_specs.extend(tag_spec("instance", &name).as_array().cloned().unwrap_or_default());
        }
        obj.insert("TagSpecifications".into(), json!(tag_specs));
        Ok(data)
    }

    async fn iam(&self, scope: &Scope<'_>, op: &str, input: Value) -> Result<Value, InfrastructureError> {
        self.iam
            .invoke(service_ctx(scope, NODEGROUP_ROLE), op, input)
            .await
            .map_err(|e| error("AmazonIdentityManagement", e))
    }
}

#[async_trait::async_trait]
impl Infrastructure for EksInfrastructure {
    async fn subnets(&self, scope: &Scope<'_>, ids: &[String]) -> Result<Vec<SubnetFacts>, InfrastructureError> {
        let out = self.ec2(scope, CLUSTER_ROLE, "DescribeSubnets", json!({"SubnetIds": ids})).await?;
        let subnets = out.get("Subnets").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut vpc_ids: Vec<String> = subnets.iter().map(|s| str_at(s, "VpcId").to_string()).collect();
        vpc_ids.sort();
        vpc_ids.dedup();
        let vpcs = self.ec2(scope, CLUSTER_ROLE, "DescribeVpcs", json!({"VpcIds": vpc_ids})).await?;
        let cidr_of = |vpc: &str| {
            vpcs.get("Vpcs")
                .and_then(Value::as_array)
                .and_then(|v| v.iter().find(|x| str_at(x, "VpcId") == vpc))
                .map(|x| str_at(x, "CidrBlock").to_string())
        };
        let mut facts = Vec::new();
        for id in ids {
            let s = subnets.iter().find(|s| str_at(s, "SubnetId") == id).ok_or_else(|| InfrastructureError {
                service: "AmazonEC2".into(),
                status: 400,
                code: "InvalidSubnetID.NotFound".into(),
                message: format!("The subnet ID '{id}' does not exist"),
            })?;
            let vpc = str_at(s, "VpcId").to_string();
            facts.push(SubnetFacts {
                subnet_id: id.clone(),
                availability_zone: str_at(s, "AvailabilityZone").to_string(),
                vpc_cidr: cidr_of(&vpc),
                vpc_id: vpc,
            });
        }
        Ok(facts)
    }

    async fn security_groups_exist(&self, scope: &Scope<'_>, ids: &[String]) -> Result<(), InfrastructureError> {
        self.ec2(scope, CLUSTER_ROLE, "DescribeSecurityGroups", json!({"GroupIds": ids})).await.map(|_| ())
    }

    async fn create_security_group(
        &self,
        scope: &Scope<'_>,
        vpc_id: &str,
        name: &str,
        description: &str,
        tags: &BTreeMap<String, String>,
        self_ingress: bool,
        ssh_from_anywhere: bool,
    ) -> Result<String, InfrastructureError> {
        let out = self
            .ec2(
                scope,
                CLUSTER_ROLE,
                "CreateSecurityGroup",
                json!({
                    "GroupName": name,
                    "Description": description,
                    "VpcId": vpc_id,
                    "TagSpecifications": tag_spec("security-group", tags),
                }),
            )
            .await?;
        let id = str_at(&out, "GroupId").to_string();
        let mut permissions = Vec::new();
        if self_ingress {
            permissions.push(json!({"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": id}]}));
        }
        if ssh_from_anywhere {
            permissions.push(
                json!({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}),
            );
        }
        if !permissions.is_empty() {
            self.ec2(
                scope,
                CLUSTER_ROLE,
                "AuthorizeSecurityGroupIngress",
                json!({"GroupId": id, "IpPermissions": permissions}),
            )
            .await?;
        }
        Ok(id)
    }

    async fn delete_security_group(&self, scope: &Scope<'_>, group_id: &str) -> Result<(), InfrastructureError> {
        self.ec2(scope, CLUSTER_ROLE, "DeleteSecurityGroup", json!({"GroupId": group_id})).await.map(|_| ())
    }

    async fn node_image(&self, scope: &Scope<'_>, version: &str, ami_type: &str) -> Option<String> {
        let arch = if ami_type.contains("ARM_64") { "arm64" } else { "x86_64" };
        let mut patterns = Vec::new();
        if ami_type.starts_with("AL2023") {
            patterns.push(format!("amazon-eks-node-al2023-{arch}-standard-{version}-v*"));
        } else if ami_type.starts_with("AL2_") {
            patterns.push(if arch == "arm64" {
                format!("amazon-eks-arm64-node-{version}-v*")
            } else {
                format!("amazon-eks-node-{version}-v*")
            });
        }
        // Bottlerocket, Windows and accelerated AMIs run on the closest
        // image MWS has.
        patterns.push(format!("amazon-eks-node-al2023-{arch}-standard-{version}-v*"));
        patterns.push(format!("al2023-ami-2023.*-{arch}"));
        for pattern in patterns {
            let out = self
                .ec2(
                    scope,
                    NODEGROUP_ROLE,
                    "DescribeImages",
                    json!({"Owners": ["amazon"], "Filters": [{"Name": "name", "Values": [pattern]}]}),
                )
                .await
                .ok()?;
            let images = out.get("Images").and_then(Value::as_array).cloned().unwrap_or_default();
            if let Some(id) = images.iter().find_map(|i| i.get("ImageId").and_then(Value::as_str)) {
                return Some(id.to_string());
            }
        }
        None
    }

    async fn create_instance_profile(
        &self,
        scope: &Scope<'_>,
        name: &str,
        role_arn: &str,
    ) -> Result<String, InfrastructureError> {
        let out = self.iam(scope, "CreateInstanceProfile", json!({"InstanceProfileName": name, "Path": "/"})).await?;
        let role = role_arn.rsplit('/').next().unwrap_or(role_arn);
        self.iam(scope, "AddRoleToInstanceProfile", json!({"InstanceProfileName": name, "RoleName": role})).await?;
        Ok(out.get("InstanceProfile").map(|p| str_at(p, "Arn").to_string()).unwrap_or_default())
    }

    async fn delete_instance_profile(&self, scope: &Scope<'_>, name: &str, role_arn: &str) {
        let role = role_arn.rsplit('/').next().unwrap_or(role_arn);
        let _ = self
            .iam(scope, "RemoveRoleFromInstanceProfile", json!({"InstanceProfileName": name, "RoleName": role}))
            .await;
        if let Err(e) = self.iam(scope, "DeleteInstanceProfile", json!({"InstanceProfileName": name})).await {
            tracing::warn!(profile = name, "EKS could not delete a node group instance profile: {}", e.message);
        }
    }

    async fn create_node_group(
        &self,
        scope: &Scope<'_>,
        spec: &NodeGroupSpec,
    ) -> Result<NodeGroupTemplate, InfrastructureError> {
        let data = self.template_data(scope, spec).await?;
        let tags = BTreeMap::from([
            ("eks:cluster-name".to_string(), spec.cluster_name.clone()),
            ("eks:nodegroup-name".to_string(), spec.nodegroup_name.clone()),
        ]);
        let out = self
            .ec2(
                scope,
                NODEGROUP_ROLE,
                "CreateLaunchTemplate",
                json!({
                    "LaunchTemplateName": spec.template_name,
                    "LaunchTemplateData": data,
                    "TagSpecifications": tag_spec("launch-template", &tags),
                }),
            )
            .await?;
        let id =
            out.pointer("/LaunchTemplate/LaunchTemplateId").and_then(Value::as_str).unwrap_or_default().to_string();
        let version =
            out.pointer("/LaunchTemplate/LatestVersionNumber").and_then(Value::as_i64).unwrap_or(1).to_string();
        let mut input = json!({
            "AutoScalingGroupName": spec.group_name,
            "MixedInstancesPolicy": mixed_instances(spec, &id, &version),
            "MinSize": spec.min_size,
            "MaxSize": spec.max_size,
            "DesiredCapacity": spec.desired_size,
            "VPCZoneIdentifier": spec.subnets.join(","),
            "CapacityRebalance": spec.capacity_type == "SPOT",
            "Tags": spec.tags.iter().map(|(k, v)| json!({
                "ResourceId": spec.group_name,
                "ResourceType": "auto-scaling-group",
                "Key": k,
                "Value": v,
                "PropagateAtLaunch": true,
            })).collect::<Vec<_>>(),
        });
        if spec.subnets.is_empty() {
            input.as_object_mut().expect("object").remove("VPCZoneIdentifier");
        }
        if let Err(e) = self.autoscaling(scope, "CreateAutoScalingGroup", input).await {
            let _ = self.ec2(scope, NODEGROUP_ROLE, "DeleteLaunchTemplate", json!({"LaunchTemplateId": id})).await;
            return Err(e);
        }
        self.autoscaling.tick().await;
        Ok(NodeGroupTemplate { id, version })
    }

    async fn scale_node_group(
        &self,
        scope: &Scope<'_>,
        group: &str,
        min: i32,
        max: i32,
        desired: i32,
    ) -> Result<(), InfrastructureError> {
        self.autoscaling(
            scope,
            "UpdateAutoScalingGroup",
            json!({"AutoScalingGroupName": group, "MinSize": min, "MaxSize": max, "DesiredCapacity": desired}),
        )
        .await?;
        self.autoscaling.tick().await;
        Ok(())
    }

    async fn roll_node_group(
        &self,
        scope: &Scope<'_>,
        spec: &NodeGroupSpec,
        template_id: &str,
    ) -> Result<String, InfrastructureError> {
        let data = self.template_data(scope, spec).await?;
        let out = self
            .ec2(
                scope,
                NODEGROUP_ROLE,
                "CreateLaunchTemplateVersion",
                json!({"LaunchTemplateId": template_id, "LaunchTemplateData": data}),
            )
            .await?;
        let version =
            out.pointer("/LaunchTemplateVersion/VersionNumber").and_then(Value::as_i64).unwrap_or_default().to_string();
        let group = spec.group_name.as_str();
        let old = self.node_group_state(scope, group).await.map(|s| s.instance_ids).unwrap_or_default();
        // EKS keeps the group from rebalancing while it replaces nodes.
        let processes = json!({"AutoScalingGroupName": group, "ScalingProcesses": ["AZRebalance"]});
        self.autoscaling(scope, "SuspendProcesses", processes.clone()).await?;
        let result = async {
            self.autoscaling(
                scope,
                "UpdateAutoScalingGroup",
                json!({
                    "AutoScalingGroupName": group,
                    "MixedInstancesPolicy": mixed_instances(spec, template_id, &version),
                }),
            )
            .await?;
            for id in &old {
                self.autoscaling(
                    scope,
                    "TerminateInstanceInAutoScalingGroup",
                    json!({"InstanceId": id, "ShouldDecrementDesiredCapacity": false}),
                )
                .await?;
            }
            self.autoscaling.tick().await;
            Ok::<_, InfrastructureError>(())
        }
        .await;
        self.autoscaling(scope, "ResumeProcesses", processes).await?;
        result.map(|()| version)
    }

    async fn node_group_state(&self, scope: &Scope<'_>, group: &str) -> Option<GroupState> {
        let out = self
            .autoscaling(scope, "DescribeAutoScalingGroups", json!({"AutoScalingGroupNames": [group]}))
            .await
            .ok()?;
        let g = out.pointer("/AutoScalingGroups/0")?;
        let int = |k: &str| g.get(k).and_then(Value::as_i64).unwrap_or_default() as i32;
        let list = |k: &str| g.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
        Some(GroupState {
            min_size: int("MinSize"),
            max_size: int("MaxSize"),
            desired_capacity: int("DesiredCapacity"),
            instance_ids: list("Instances")
                .iter()
                .filter(|i| {
                    let s = str_at(i, "LifecycleState");
                    !s.starts_with("Terminat") && !s.starts_with("Detach") && s != "Standby"
                })
                .map(|i| str_at(i, "InstanceId").to_string())
                .collect(),
            suspended_processes: list("SuspendedProcesses")
                .iter()
                .map(|p| str_at(p, "ProcessName").to_string())
                .collect(),
        })
    }

    async fn instances(&self, scope: &Scope<'_>, ids: &[String]) -> Vec<InstanceFacts> {
        if ids.is_empty() {
            return Vec::new();
        }
        let input = json!({
            "InstanceIds": ids,
            "Filters": [{"Name": "instance-state-name", "Values": ["pending", "running"]}],
        });
        let Ok(out) = self.ec2(scope, NODEGROUP_ROLE, "DescribeInstances", input).await else {
            return Vec::new();
        };
        let reservations = out.get("Reservations").and_then(Value::as_array).cloned().unwrap_or_default();
        reservations
            .iter()
            .flat_map(|r| r.get("Instances").and_then(Value::as_array).cloned().unwrap_or_default())
            .map(|i| InstanceFacts {
                instance_id: str_at(&i, "InstanceId").to_string(),
                private_ip: str_at(&i, "PrivateIpAddress").to_string(),
                private_dns_name: str_at(&i, "PrivateDnsName").to_string(),
                availability_zone: i
                    .get("Placement")
                    .map(|p| str_at(p, "AvailabilityZone").to_string())
                    .unwrap_or_default(),
                instance_type: str_at(&i, "InstanceType").to_string(),
                image_id: str_at(&i, "ImageId").to_string(),
            })
            .collect()
    }

    async fn delete_node_group(&self, scope: &Scope<'_>, group: &str, template_id: Option<&str>) {
        if let Err(e) = self
            .autoscaling(scope, "DeleteAutoScalingGroup", json!({"AutoScalingGroupName": group, "ForceDelete": true}))
            .await
        {
            tracing::warn!(group, "EKS could not delete a node group's Auto Scaling group: {e}");
        }
        self.autoscaling.tick().await;
        if let Some(id) = template_id {
            if let Err(e) =
                self.ec2(scope, NODEGROUP_ROLE, "DeleteLaunchTemplate", json!({"LaunchTemplateId": id})).await
            {
                tracing::warn!(template = id, "EKS could not delete a node group's launch template: {e}");
            }
        }
    }
}

/// The group's mixed instances policy: EKS's launch template, one override
/// per instance type, and the capacity type as the instances distribution.
fn mixed_instances(spec: &NodeGroupSpec, template_id: &str, version: &str) -> Value {
    let distribution = if spec.capacity_type == "SPOT" {
        json!({
            "OnDemandBaseCapacity": 0,
            "OnDemandPercentageAboveBaseCapacity": 0,
            "SpotAllocationStrategy": "capacity-optimized",
        })
    } else {
        json!({
            "OnDemandAllocationStrategy": "prioritized",
            "OnDemandBaseCapacity": 0,
            "OnDemandPercentageAboveBaseCapacity": 100,
        })
    };
    let mut lt = json!({"LaunchTemplateSpecification": {"LaunchTemplateId": template_id, "Version": version}});
    if !spec.instance_types.is_empty() {
        lt["Overrides"] = json!(spec.instance_types.iter().map(|t| json!({"InstanceType": t})).collect::<Vec<_>>());
    }
    json!({"LaunchTemplate": lt, "InstancesDistribution": distribution})
}

fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, strip_nulls(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        v => v,
    }
}
