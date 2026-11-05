//! What EKS creates in the account, done the way EKS's service-linked roles
//! do it: EC2 security groups and instances, IAM instance profiles.

use std::collections::BTreeMap;
use std::sync::Arc;

use mws_core::{Caller, CallerKind, RequestContext, Service, ServiceError};
use mws_eks::{Infrastructure, InfrastructureError, NodeLaunch, Scope, SubnetFacts};
use serde_json::{json, Value};

pub(crate) struct EksInfrastructure {
    pub ec2: mws_ec2::Ec2,
    pub iam: mws_iam::Iam,
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

    async fn launch(&self, scope: &Scope<'_>, launch: &NodeLaunch) -> Result<Vec<String>, InfrastructureError> {
        let mut tags = launch.tags.clone();
        tags.insert("Name".into(), format!("{}-{}-Node", launch.cluster_name, launch.nodegroup_name));
        let subnets = if launch.subnets.is_empty() { vec![String::new()] } else { launch.subnets.clone() };
        let mut ids = Vec::new();
        // Spread the instances over the subnets, as the Auto Scaling group
        // balances its Availability Zones.
        for (i, subnet) in subnets.iter().enumerate() {
            let count = launch.count / subnets.len() + usize::from(i < launch.count % subnets.len());
            if count == 0 {
                continue;
            }
            let mut input = json!({
                "ImageId": launch.image_id,
                "InstanceType": launch.instance_type,
                "MinCount": count,
                "MaxCount": count,
                "SecurityGroupIds": launch.security_group_ids,
                "TagSpecifications": tag_spec("instance", &tags),
            });
            if !subnet.is_empty() {
                input["SubnetId"] = json!(subnet);
            }
            if let Some(p) = &launch.instance_profile_arn {
                input["IamInstanceProfile"] = json!({"Arn": p});
            }
            if let Some(k) = &launch.key_name {
                input["KeyName"] = json!(k);
            }
            if let Some(size) = launch.disk_size_gib {
                input["BlockDeviceMappings"] = json!([{
                    "DeviceName": "/dev/xvda",
                    "Ebs": {"VolumeSize": size, "VolumeType": "gp3", "DeleteOnTermination": true},
                }]);
            }
            let out = match self.ec2(scope, NODEGROUP_ROLE, "RunInstances", input).await {
                Ok(out) => out,
                Err(e) => {
                    if !ids.is_empty() {
                        self.terminate(scope, &ids).await;
                    }
                    return Err(e);
                }
            };
            for i in out.get("Instances").and_then(Value::as_array).into_iter().flatten() {
                ids.push(str_at(i, "InstanceId").to_string());
            }
        }
        Ok(ids)
    }

    async fn terminate(&self, scope: &Scope<'_>, instance_ids: &[String]) {
        if let Err(e) =
            self.ec2(scope, NODEGROUP_ROLE, "TerminateInstances", json!({"InstanceIds": instance_ids})).await
        {
            tracing::warn!("EKS could not terminate node instances: {e}");
        }
    }
}
