//! Amazon EKS through the official Rust SDK: clusters in a real MWS VPC,
//! managed node groups running EC2 instances, and every other EKS API.

use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_ec2::types::Filter;
use aws_sdk_eks::client::Waiters;
use aws_sdk_eks::error::ProvideErrorMetadata;
use aws_sdk_eks::types::{
    AccessScope, AccessScopeType, AddonPodIdentityAssociations, AmiTypes, ArgoCdAwsIdcConfigRequest,
    ArgoCdConfigRequest, AuthenticationMode, CapabilityConfigurationRequest, CapabilityDeletePropagationPolicy,
    CapabilityType, ConnectorConfigProvider, ConnectorConfigRequest, CreateAccessConfigRequest,
    EksAnywhereSubscriptionTerm, EksAnywhereSubscriptionTermUnit, EncryptionConfig, FargateProfileSelector,
    IdentityProviderConfig, LogSetup, LogType, Logging, NodegroupScalingConfig, OidcIdentityProviderConfigRequest,
    Provider, ResolveConflicts, Taint, TaintEffect, UpdateLabelsPayload, UpdateStatus, UpdateTaintsPayload, UpdateType,
    VpcConfigRequest,
};
use aws_sdk_eks::Client;
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

fn trust(service: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":["sts:AssumeRole","sts:TagSession"]}}]}}"#
    )
}

/// Roles, a VPC with subnets in two zones, and clients.
struct Env {
    eks: Client,
    ec2: aws_sdk_ec2::Client,
    iam: aws_sdk_iam::Client,
    cluster_role: String,
    node_role: String,
    pod_role: String,
    subnets: Vec<String>,
    vpc: String,
}

async fn env(mws: &Mws) -> Env {
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let mut roles = HashMap::new();
    for (name, service) in [
        ("eks-cluster", "eks.amazonaws.com"),
        ("eks-node", "ec2.amazonaws.com"),
        ("eks-pod", "pods.eks.amazonaws.com"),
        ("eks-fargate", "eks-fargate-pods.amazonaws.com"),
        ("eks-capability", "capabilities.eks.amazonaws.com"),
        ("eks-connector", "ssm.amazonaws.com"),
    ] {
        let r = iam.create_role().role_name(name).assume_role_policy_document(trust(service)).send().await.unwrap();
        roles.insert(name, r.role().unwrap().arn().to_string());
    }
    let vpc = ec2.create_vpc().cidr_block("10.20.0.0/16").send().await.unwrap();
    let vpc = vpc.vpc().unwrap().vpc_id().unwrap().to_string();
    let mut subnets = Vec::new();
    for (i, zone) in ["us-east-1a", "us-east-1b"].iter().enumerate() {
        let s = ec2
            .create_subnet()
            .vpc_id(&vpc)
            .cidr_block(format!("10.20.{i}.0/24"))
            .availability_zone(*zone)
            .send()
            .await
            .unwrap();
        subnets.push(s.subnet().unwrap().subnet_id().unwrap().to_string());
    }
    Env {
        eks: Client::new(&cfg),
        ec2,
        iam,
        cluster_role: roles["eks-cluster"].clone(),
        node_role: roles["eks-node"].clone(),
        pod_role: roles["eks-pod"].clone(),
        subnets,
        vpc,
    }
}

impl Env {
    async fn cluster(&self, name: &str, mode: AuthenticationMode) -> aws_sdk_eks::types::Cluster {
        let c = self
            .eks
            .create_cluster()
            .name(name)
            .role_arn(&self.cluster_role)
            .resources_vpc_config(VpcConfigRequest::builder().set_subnet_ids(Some(self.subnets.clone())).build())
            .access_config(CreateAccessConfigRequest::builder().authentication_mode(mode).build())
            .tags("team", "platform")
            .send()
            .await
            .unwrap();
        self.eks.wait_until_cluster_active().name(name).wait(Duration::from_secs(60)).await.unwrap();
        c.cluster().unwrap().clone()
    }

    async fn instances(&self, nodegroup: &str) -> Vec<aws_sdk_ec2::types::Instance> {
        let out = self
            .ec2
            .describe_instances()
            .filters(Filter::builder().name("tag:eks:nodegroup-name").values(nodegroup).build())
            .filters(Filter::builder().name("instance-state-name").values("pending").values("running").build())
            .send()
            .await
            .unwrap();
        out.reservations().iter().flat_map(|r| r.instances().to_vec()).collect()
    }
}

#[tokio::test]
async fn clusters_live_in_the_vpc_and_settle() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    let created = e
        .eks
        .create_cluster()
        .name("prod")
        .role_arn(&e.cluster_role)
        .resources_vpc_config(VpcConfigRequest::builder().set_subnet_ids(Some(e.subnets.clone())).build())
        .logging(
            Logging::builder()
                .cluster_logging(LogSetup::builder().types(LogType::Api).types(LogType::Audit).enabled(true).build())
                .build(),
        )
        .tags("team", "platform")
        .send()
        .await
        .unwrap();
    let c = created.cluster().unwrap();
    assert_eq!(c.status().unwrap().as_str(), "CREATING");
    assert_eq!(c.arn(), Some(format!("arn:aws:eks:us-east-1:{ACCOUNT}:cluster/prod").as_str()));
    assert_eq!(c.version(), Some("1.34"));
    let vpc = c.resources_vpc_config().unwrap();
    assert_eq!(vpc.vpc_id(), Some(e.vpc.as_str()));
    assert!(vpc.endpoint_public_access() && !vpc.endpoint_private_access());
    assert_eq!(vpc.public_access_cidrs(), ["0.0.0.0/0"]);
    // The VPC is in 10.0.0.0/8, so the service CIDR avoids it.
    assert_eq!(c.kubernetes_network_config().unwrap().service_ipv4_cidr(), Some("172.20.0.0/16"));
    let logging = c.logging().unwrap().cluster_logging();
    assert_eq!(logging[0].types(), [LogType::Api, LogType::Audit]);
    assert_eq!(logging[0].enabled(), Some(true));
    assert_eq!(c.access_config().unwrap().authentication_mode(), Some(&AuthenticationMode::ConfigMap));
    assert_eq!(c.upgrade_policy().unwrap().support_type().unwrap().as_str(), "EXTENDED");
    let issuer = c.identity().unwrap().oidc().unwrap().issuer().unwrap();
    assert!(issuer.starts_with("https://oidc.eks.us-east-1.amazonaws.com/id/"), "{issuer}");
    let id = issuer.rsplit('/').next().unwrap();
    assert_eq!(c.endpoint(), Some(format!("https://{id}.gr7.us-east-1.eks.amazonaws.com").as_str()));
    let pem =
        base64::engine::general_purpose::STANDARD.decode(c.certificate_authority().unwrap().data().unwrap()).unwrap();
    let pem = String::from_utf8(pem).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");

    // The cluster security group is real, in the cluster's VPC.
    let sg = vpc.cluster_security_group_id().unwrap();
    let groups = e.ec2.describe_security_groups().group_ids(sg).send().await.unwrap();
    let group = &groups.security_groups()[0];
    assert_eq!(group.vpc_id(), Some(e.vpc.as_str()));
    assert!(group.group_name().unwrap().starts_with("eks-cluster-sg-prod-"));
    assert!(group.tags().iter().any(|t| t.key() == Some("kubernetes.io/cluster/prod") && t.value() == Some("owned")));

    e.eks.wait_until_cluster_active().name("prod").wait(Duration::from_secs(60)).await.unwrap();
    let d = e.eks.describe_cluster().name("prod").send().await.unwrap();
    assert_eq!(d.cluster().unwrap().status().unwrap().as_str(), "ACTIVE");
    assert_eq!(d.cluster().unwrap().tags().unwrap()["team"], "platform");

    let err = e
        .eks
        .create_cluster()
        .name("prod")
        .role_arn(&e.cluster_role)
        .resources_vpc_config(VpcConfigRequest::builder().set_subnet_ids(Some(e.subnets.clone())).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(err.as_service_error().unwrap()), "ResourceInUseException");
    assert_eq!(message(err.as_service_error().unwrap()), "Cluster already exists with name: prod");

    let list = e.eks.list_clusters().send().await.unwrap();
    assert_eq!(list.clusters(), ["prod"]);

    e.eks.delete_cluster().name("prod").send().await.unwrap();
    e.eks.wait_until_cluster_deleted().name("prod").wait(Duration::from_secs(60)).await.unwrap();
    let err = e.eks.describe_cluster().name("prod").send().await.unwrap_err();
    let se = err.into_service_error();
    assert!(se.is_resource_not_found_exception());
    assert_eq!(message(&se), "No cluster found for name: prod.");
    let gone = e.ec2.describe_security_groups().group_ids(sg).send().await.unwrap_err();
    assert_eq!(code(gone.as_service_error().unwrap()), "InvalidGroup.NotFound");
}

#[tokio::test]
async fn cluster_validation_matches_eks() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    let create = |subnets: Vec<String>, role: &str| {
        e.eks
            .create_cluster()
            .name("bad")
            .role_arn(role)
            .resources_vpc_config(VpcConfigRequest::builder().set_subnet_ids(Some(subnets)).build())
    };
    let err = create(vec![e.subnets[0].clone()], &e.cluster_role).send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Subnets specified must be in at least two different AZs");
    let err = create(vec!["subnet-0123456789abcdef0".into(), e.subnets[0].clone()], &e.cluster_role)
        .send()
        .await
        .unwrap_err();
    let se = err.into_service_error();
    assert!(se.is_invalid_parameter_exception());
    assert!(message(&se).starts_with("The subnet ID 'subnet-0123456789abcdef0' does not exist (Service: AmazonEC2;"));
    let err = create(e.subnets.clone(), &e.node_role).send().await.unwrap_err();
    assert!(message(err.as_service_error().unwrap()).contains("cannot be assumed by Amazon EKS"));
    let missing = format!("arn:aws:iam::{ACCOUNT}:role/nope");
    let err = create(e.subnets.clone(), &missing).send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), format!("Role with arn: {missing}, does not exist."));
    let err = create(e.subnets.clone(), &e.cluster_role).version("1.20").send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "unsupported Kubernetes version 1.20");
    let err = create(e.subnets.clone(), &e.cluster_role)
        .access_config(CreateAccessConfigRequest::builder().bootstrap_cluster_creator_admin_permissions(false).build())
        .send()
        .await
        .unwrap_err();
    assert!(
        message(err.as_service_error().unwrap()).starts_with("bootstrapClusterCreatorAdminPermissions must be true")
    );

    // A caller without eks:CreateCluster, or without iam:PassRole.
    let (_, cfg) = user_with_policy(
        &mws,
        "dev",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"eks:*","Resource":"*"}]}"#),
    )
    .await;
    let dev = Client::new(&cfg);
    let err = dev
        .create_cluster()
        .name("x")
        .role_arn(&e.cluster_role)
        .resources_vpc_config(VpcConfigRequest::builder().set_subnet_ids(Some(e.subnets.clone())).build())
        .send()
        .await
        .unwrap_err();
    let se = err.into_service_error();
    assert_eq!(code(&se), "AccessDeniedException", "{se:?}");
    assert!(message(&se).contains("iam:PassRole"));
    let (_, cfg) = user_with_policy(&mws, "nobody", None).await;
    let err = Client::new(&cfg).list_clusters().send().await.unwrap_err();
    let se = err.into_service_error();
    assert!(message(&se).contains("eks:ListClusters"), "{se:?}");
}

#[tokio::test]
async fn managed_node_groups_run_ec2_instances() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    let cluster = e.cluster("apps", AuthenticationMode::ApiAndConfigMap).await;
    let cluster_sg = cluster.resources_vpc_config().unwrap().cluster_security_group_id().unwrap().to_string();

    let ng = e
        .eks
        .create_nodegroup()
        .cluster_name("apps")
        .nodegroup_name("workers")
        .node_role(&e.node_role)
        .set_subnets(Some(e.subnets.clone()))
        .scaling_config(NodegroupScalingConfig::builder().min_size(1).max_size(4).desired_size(2).build())
        .labels("tier", "app")
        .taints(Taint::builder().key("dedicated").value("app").effect(TaintEffect::NoSchedule).build())
        .tags("cost", "apps")
        .send()
        .await
        .unwrap();
    let ng = ng.nodegroup().unwrap();
    assert_eq!(ng.status().unwrap().as_str(), "CREATING");
    assert_eq!(ng.ami_type(), Some(&AmiTypes::Al2023X8664Standard));
    assert_eq!(ng.instance_types(), ["t3.medium"]);
    assert_eq!(ng.disk_size(), Some(20));
    assert_eq!(ng.version(), Some("1.34"));
    assert_eq!(ng.release_version(), Some("1.34.2-20250101"));
    assert_eq!(ng.capacity_type().unwrap().as_str(), "ON_DEMAND");
    assert_eq!(ng.update_config().unwrap().max_unavailable(), Some(1));
    let asg = ng.resources().unwrap().auto_scaling_groups()[0].name().unwrap().to_string();
    assert!(asg.starts_with("eks-workers-"), "{asg}");
    assert!(ng
        .nodegroup_arn()
        .unwrap()
        .starts_with(&format!("arn:aws:eks:us-east-1:{ACCOUNT}:nodegroup/apps/workers/")));

    e.eks
        .wait_until_nodegroup_active()
        .cluster_name("apps")
        .nodegroup_name("workers")
        .wait(Duration::from_secs(60))
        .await
        .unwrap();

    // Two instances, spread over the subnets, from the EKS-optimized AMI,
    // in the cluster security group, with an instance profile for the node
    // role.
    let nodes = e.instances("workers").await;
    assert_eq!(nodes.len(), 2);
    let mut subnets: Vec<_> = nodes.iter().map(|i| i.subnet_id().unwrap().to_string()).collect();
    subnets.sort();
    let mut want = e.subnets.clone();
    want.sort();
    assert_eq!(subnets, want);
    let node = &nodes[0];
    assert_eq!(node.instance_type().unwrap().as_str(), "t3.medium");
    assert!(node.security_groups().iter().any(|g| g.group_id() == Some(cluster_sg.as_str())));
    assert!(node.tags().iter().any(|t| t.key() == Some("eks:cluster-name") && t.value() == Some("apps")));
    let image = e.ec2.describe_images().image_ids(node.image_id().unwrap()).send().await.unwrap();
    assert_eq!(image.images()[0].name(), Some("amazon-eks-node-al2023-x86_64-standard-1.34-v20250101"));
    let profile_arn = node.iam_instance_profile().unwrap().arn().unwrap().to_string();
    let profile_name = profile_arn.rsplit('/').next().unwrap();
    let profile = e.iam.get_instance_profile().instance_profile_name(profile_name).send().await.unwrap();
    assert_eq!(profile.instance_profile().unwrap().roles()[0].arn(), e.node_role.as_str());
    // The AMI is the one Parameter Store recommends.
    let ssm = aws_sdk_ssm::Client::new(&mws.root_sdk_config().await);
    let p = ssm
        .get_parameter()
        .name("/aws/service/eks/optimized-ami/1.34/amazon-linux-2023/x86_64/standard/recommended/image_id")
        .send()
        .await
        .unwrap();
    assert_eq!(p.parameter().unwrap().value(), node.image_id());

    // The node role got an EC2_LINUX access entry.
    let entry = e.eks.describe_access_entry().cluster_name("apps").principal_arn(&e.node_role).send().await.unwrap();
    let entry = entry.access_entry().unwrap();
    assert_eq!(entry.r#type(), Some("EC2_LINUX"));
    assert_eq!(entry.username(), Some("system:node:{{EC2PrivateDNSName}}"));

    // Scaling out starts instances; the update succeeds.
    let up = e
        .eks
        .update_nodegroup_config()
        .cluster_name("apps")
        .nodegroup_name("workers")
        .scaling_config(NodegroupScalingConfig::builder().desired_size(3).build())
        .labels(UpdateLabelsPayload::builder().add_or_update_labels("zone", "a").remove_labels("tier").build())
        .taints(
            UpdateTaintsPayload::builder()
                .remove_taints(Taint::builder().key("dedicated").effect(TaintEffect::NoSchedule).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let up = up.update().unwrap();
    assert_eq!(up.r#type(), Some(&UpdateType::ConfigUpdate));
    assert_eq!(up.status(), Some(&UpdateStatus::InProgress));
    assert_eq!(e.instances("workers").await.len(), 3);
    let d = e
        .eks
        .describe_update()
        .name("apps")
        .update_id(up.id().unwrap())
        .nodegroup_name("workers")
        .send()
        .await
        .unwrap();
    assert_eq!(d.update().unwrap().status(), Some(&UpdateStatus::Successful));
    let ng = e.eks.describe_nodegroup().cluster_name("apps").nodegroup_name("workers").send().await.unwrap();
    let ng = ng.nodegroup().unwrap();
    assert_eq!(ng.scaling_config().unwrap().desired_size(), Some(3));
    assert_eq!(ng.labels().unwrap().get("zone").map(String::as_str), Some("a"));
    assert!(ng.labels().unwrap().get("tier").is_none());
    assert!(ng.taints().is_empty());
    let updates = e.eks.list_updates().name("apps").nodegroup_name("workers").send().await.unwrap();
    assert_eq!(updates.update_ids(), [up.id().unwrap()]);
    assert!(e.eks.list_updates().name("apps").send().await.unwrap().update_ids().is_empty());

    let err = e
        .eks
        .update_nodegroup_config()
        .cluster_name("apps")
        .nodegroup_name("workers")
        .scaling_config(NodegroupScalingConfig::builder().desired_size(9).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Desired capacity 9 can't be greater than max size 4");

    // A cluster upgrade, then the node group follows and its nodes are
    // replaced from the new AMI.
    let err = e.eks.update_cluster_version().name("apps").version("1.33").send().await.unwrap_err();
    assert_eq!(
        message(err.as_service_error().unwrap()),
        "Unsupported Kubernetes minor version update from 1.34 to 1.33"
    );
    let v = e.eks.update_cluster_version().name("apps").version("1.35").send().await.unwrap();
    assert_eq!(v.update().unwrap().r#type(), Some(&UpdateType::VersionUpdate));
    e.eks.wait_until_cluster_active().name("apps").wait(Duration::from_secs(60)).await.unwrap();
    let before: Vec<_> = e.instances("workers").await.iter().map(|i| i.instance_id().unwrap().to_string()).collect();
    let nv = e.eks.update_nodegroup_version().cluster_name("apps").nodegroup_name("workers").send().await.unwrap();
    assert_eq!(
        nv.update().unwrap().params().iter().find(|p| p.r#type().unwrap().as_str() == "Version").unwrap().value(),
        Some("1.35")
    );
    let after = e.instances("workers").await;
    assert_eq!(after.len(), 3);
    assert!(after.iter().all(|i| !before.contains(&i.instance_id().unwrap().to_string())));
    let image = e.ec2.describe_images().image_ids(after[0].image_id().unwrap()).send().await.unwrap();
    assert_eq!(image.images()[0].name(), Some("amazon-eks-node-al2023-x86_64-standard-1.35-v20250101"));

    // Graviton instances need an ARM AMI type; AL2 stops at 1.32.
    let err = e
        .eks
        .create_nodegroup()
        .cluster_name("apps")
        .nodegroup_name("arm")
        .node_role(&e.node_role)
        .set_subnets(Some(e.subnets.clone()))
        .ami_type(AmiTypes::Al2023X8664Standard)
        .instance_types("t4g.medium")
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(err.as_service_error().unwrap()),
        "[t4g.medium] is not a valid instance type for requested amiType AL2023_x86_64_STANDARD"
    );
    let err = e
        .eks
        .create_nodegroup()
        .cluster_name("apps")
        .nodegroup_name("old")
        .node_role(&e.node_role)
        .set_subnets(Some(e.subnets.clone()))
        .ami_type(AmiTypes::Al2X8664)
        .send()
        .await
        .unwrap_err();
    assert!(message(err.as_service_error().unwrap()).contains("only supported for kubernetes versions 1.32 or earlier"));
    let err = e
        .eks
        .create_nodegroup()
        .cluster_name("apps")
        .nodegroup_name("x")
        .node_role(&e.cluster_role)
        .set_subnets(Some(e.subnets.clone()))
        .send()
        .await
        .unwrap_err();
    assert!(message(err.as_service_error().unwrap())
        .starts_with("Following required service principals [ec2.amazonaws.com] were not found"));
    let arm = e
        .eks
        .create_nodegroup()
        .cluster_name("apps")
        .nodegroup_name("arm")
        .node_role(&e.node_role)
        .set_subnets(Some(e.subnets.clone()))
        .instance_types("t4g.medium")
        .scaling_config(NodegroupScalingConfig::builder().min_size(0).max_size(1).desired_size(0).build())
        .send()
        .await
        .unwrap();
    assert_eq!(arm.nodegroup().unwrap().ami_type(), Some(&AmiTypes::Al2023Arm64Standard));
    let mut names = e.eks.list_nodegroups().cluster_name("apps").send().await.unwrap().nodegroups().to_vec();
    names.sort();
    assert_eq!(names, ["arm", "workers"]);

    // A cluster with node groups can't be deleted.
    let err = e.eks.delete_cluster().name("apps").send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Cluster has nodegroups attached");

    // Deleting the node group terminates its instances and its profile.
    let del = e.eks.delete_nodegroup().cluster_name("apps").nodegroup_name("workers").send().await.unwrap();
    assert_eq!(del.nodegroup().unwrap().status().unwrap().as_str(), "DELETING");
    assert!(e.instances("workers").await.is_empty());
    e.eks
        .wait_until_nodegroup_deleted()
        .cluster_name("apps")
        .nodegroup_name("workers")
        .wait(Duration::from_secs(60))
        .await
        .unwrap();
    let err = e.eks.describe_nodegroup().cluster_name("apps").nodegroup_name("workers").send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "No node group found for name: workers.");
    assert!(e.iam.get_instance_profile().instance_profile_name(profile_name).send().await.is_err());
}

#[tokio::test]
async fn cluster_config_updates_and_encryption() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    e.cluster("cfg", AuthenticationMode::ConfigMap).await;

    let u = e
        .eks
        .update_cluster_config()
        .name("cfg")
        .resources_vpc_config(
            VpcConfigRequest::builder().endpoint_private_access(true).public_access_cidrs("203.0.113.0/24").build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(u.update().unwrap().r#type(), Some(&UpdateType::EndpointAccessUpdate));
    let err = e
        .eks
        .update_cluster_config()
        .name("cfg")
        .resources_vpc_config(VpcConfigRequest::builder().endpoint_private_access(false).build())
        .logging(Logging::builder().build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Only one type of update can be allowed.");
    let u = e
        .eks
        .update_cluster_config()
        .name("cfg")
        .logging(
            Logging::builder()
                .cluster_logging(LogSetup::builder().types(LogType::Scheduler).enabled(true).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(u.update().unwrap().r#type(), Some(&UpdateType::LoggingUpdate));
    let u = e
        .eks
        .update_cluster_config()
        .name("cfg")
        .access_config(
            aws_sdk_eks::types::UpdateAccessConfigRequest::builder()
                .authentication_mode(AuthenticationMode::Api)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(u.update().unwrap().r#type(), Some(&UpdateType::AccessConfigUpdate));
    let err = e
        .eks
        .update_cluster_config()
        .name("cfg")
        .access_config(
            aws_sdk_eks::types::UpdateAccessConfigRequest::builder()
                .authentication_mode(AuthenticationMode::ConfigMap)
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(err.as_service_error().unwrap()),
        "Unsupported authentication mode update from API to CONFIG_MAP"
    );
    let u = e.eks.update_cluster_config().name("cfg").deletion_protection(true).send().await.unwrap();
    let id = u.update().unwrap().id().unwrap().to_string();
    let c = e.eks.describe_cluster().name("cfg").send().await.unwrap();
    let c = c.cluster().unwrap();
    assert_eq!(c.deletion_protection(), Some(true));
    let vpc = c.resources_vpc_config().unwrap();
    assert!(vpc.endpoint_private_access());
    assert_eq!(vpc.public_access_cidrs(), ["203.0.113.0/24"]);
    let setups = c.logging().unwrap().cluster_logging();
    assert_eq!(setups[0].types(), [LogType::Scheduler]);
    assert_eq!(c.access_config().unwrap().authentication_mode(), Some(&AuthenticationMode::Api));
    let err = e.eks.delete_cluster().name("cfg").send().await.unwrap_err();
    assert!(err.into_service_error().is_invalid_request_exception());

    // Updates that finished can't be cancelled.
    let err = e.eks.cancel_update().name("cfg").update_id(&id).send().await.unwrap_err();
    assert!(err.into_service_error().is_invalid_state_exception());
    assert_eq!(e.eks.list_updates().name("cfg").send().await.unwrap().update_ids().len(), 4);

    let key = format!("arn:aws:kms:us-east-1:{ACCOUNT}:key/1234abcd-12ab-34cd-56ef-1234567890ab");
    #[allow(deprecated)]
    let enc =
        || EncryptionConfig::builder().resources("secrets").provider(Provider::builder().key_arn(&key).build()).build();
    let u = e.eks.associate_encryption_config().cluster_name("cfg").encryption_config(enc()).send().await.unwrap();
    assert_eq!(u.update().unwrap().r#type(), Some(&UpdateType::AssociateEncryptionConfig));
    let err =
        e.eks.associate_encryption_config().cluster_name("cfg").encryption_config(enc()).send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Encryption is already enabled on the cluster");

    let versions = e.eks.describe_cluster_versions().send().await.unwrap();
    let names: Vec<_> = versions.cluster_versions().iter().filter_map(|v| v.cluster_version()).collect();
    assert!(names.contains(&"1.34") && names.contains(&"1.35"));
    let default = e.eks.describe_cluster_versions().default_only(true).send().await.unwrap();
    assert_eq!(default.cluster_versions()[0].cluster_version(), Some("1.34"));
    assert!(default.cluster_versions()[0].default_version());
}

#[tokio::test]
async fn access_entries_and_policies() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    e.cluster("acc", AuthenticationMode::Api).await;
    // The creator is a cluster admin.
    let root = format!("arn:aws:iam::{ACCOUNT}:root");
    let entries = e.eks.list_access_entries().cluster_name("acc").send().await.unwrap();
    assert_eq!(entries.access_entries(), [root.as_str()]);
    let pols = e.eks.list_associated_access_policies().cluster_name("acc").principal_arn(&root).send().await.unwrap();
    assert_eq!(
        pols.associated_access_policies()[0].policy_arn(),
        Some("arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy")
    );

    let dev = e
        .iam
        .create_role()
        .role_name("dev")
        .assume_role_policy_document(trust("ec2.amazonaws.com"))
        .send()
        .await
        .unwrap();
    let dev = dev.role().unwrap().arn().to_string();
    let entry = e
        .eks
        .create_access_entry()
        .cluster_name("acc")
        .principal_arn(&dev)
        .kubernetes_groups("developers")
        .tags("k", "v")
        .send()
        .await
        .unwrap();
    let entry = entry.access_entry().unwrap();
    assert_eq!(entry.username(), Some(format!("arn:aws:sts::{ACCOUNT}:assumed-role/dev/{{{{SessionName}}}}").as_str()));
    assert_eq!(entry.r#type(), Some("STANDARD"));
    assert!(entry
        .access_entry_arn()
        .unwrap()
        .starts_with(&format!("arn:aws:eks:us-east-1:{ACCOUNT}:access-entry/acc/role/{ACCOUNT}/dev/")));
    let err = e.eks.create_access_entry().cluster_name("acc").principal_arn(&dev).send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_in_use_exception());
    let err = e
        .eks
        .create_access_entry()
        .cluster_name("acc")
        .principal_arn(format!("arn:aws:iam::{ACCOUNT}:role/other"))
        .username("system:admin")
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_invalid_parameter_exception());

    let updated =
        e.eks.update_access_entry().cluster_name("acc").principal_arn(&dev).username("dev-user").send().await.unwrap();
    assert_eq!(updated.access_entry().unwrap().username(), Some("dev-user"));

    let view = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy";
    let assoc = e
        .eks
        .associate_access_policy()
        .cluster_name("acc")
        .principal_arn(&dev)
        .policy_arn(view)
        .access_scope(AccessScope::builder().r#type(AccessScopeType::Namespace).namespaces("team-a").build())
        .send()
        .await
        .unwrap();
    assert_eq!(assoc.associated_access_policy().unwrap().access_scope().unwrap().namespaces(), ["team-a"]);
    let err = e
        .eks
        .associate_access_policy()
        .cluster_name("acc")
        .principal_arn(&dev)
        .policy_arn(view)
        .access_scope(AccessScope::builder().r#type(AccessScopeType::Namespace).build())
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_invalid_parameter_exception());
    let filtered = e.eks.list_access_entries().cluster_name("acc").associated_policy_arn(view).send().await.unwrap();
    assert_eq!(filtered.access_entries(), [dev.as_str()]);
    e.eks.disassociate_access_policy().cluster_name("acc").principal_arn(&dev).policy_arn(view).send().await.unwrap();
    let pols = e.eks.list_associated_access_policies().cluster_name("acc").principal_arn(&dev).send().await.unwrap();
    assert!(pols.associated_access_policies().is_empty());
    e.eks.delete_access_entry().cluster_name("acc").principal_arn(&dev).send().await.unwrap();
    let err = e.eks.describe_access_entry().cluster_name("acc").principal_arn(&dev).send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_not_found_exception());

    let policies = e.eks.list_access_policies().max_results(5).send().await.unwrap();
    assert_eq!(policies.access_policies().len(), 5);
    let rest = e.eks.list_access_policies().next_token(policies.next_token().unwrap()).send().await.unwrap();
    assert!(rest.access_policies().iter().any(|p| p.name() == Some("AmazonEKSViewPolicy")));

    // A CONFIG_MAP cluster has no access entries.
    e.cluster("legacy", AuthenticationMode::ConfigMap).await;
    let err = e.eks.create_access_entry().cluster_name("legacy").principal_arn(&root).send().await.unwrap_err();
    assert!(
        message(err.as_service_error().unwrap()).starts_with("The cluster's authentication mode must be set to one of")
    );
}

#[tokio::test]
async fn addons_and_pod_identity() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    e.cluster("ad", AuthenticationMode::Api).await;

    let versions =
        e.eks.describe_addon_versions().kubernetes_version("1.34").addon_name("kube-proxy").send().await.unwrap();
    let info = &versions.addons()[0];
    assert_eq!(info.addon_versions()[0].addon_version(), Some("v1.34.1-eksbuild.2"));
    assert!(info.addon_versions()[0].compatibilities()[0].default_version());
    let all = e.eks.describe_addon_versions().send().await.unwrap();
    assert!(all.addons().iter().any(|a| a.addon_name() == Some("aws-ebs-csi-driver")));
    let cfg = e
        .eks
        .describe_addon_configuration()
        .addon_name("vpc-cni")
        .addon_version("v1.20.4-eksbuild.2")
        .send()
        .await
        .unwrap();
    let schema: serde_json::Value = serde_json::from_str(cfg.configuration_schema().unwrap()).unwrap();
    assert!(schema["definitions"].is_object());
    assert_eq!(cfg.pod_identity_configuration()[0].service_account(), Some("aws-node"));

    let addon = e
        .eks
        .create_addon()
        .cluster_name("ad")
        .addon_name("vpc-cni")
        .configuration_values(r#"{"env":{"ENABLE_PREFIX_DELEGATION":"true"}}"#)
        .pod_identity_associations(
            AddonPodIdentityAssociations::builder().service_account("aws-node").role_arn(&e.pod_role).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let addon = addon.addon().unwrap();
    assert_eq!(addon.status().unwrap().as_str(), "CREATING");
    assert_eq!(addon.addon_version(), Some("v1.20.4-eksbuild.2"));
    assert_eq!(addon.pod_identity_associations().len(), 1);
    e.eks
        .wait_until_addon_active()
        .cluster_name("ad")
        .addon_name("vpc-cni")
        .wait(Duration::from_secs(60))
        .await
        .unwrap();
    let err =
        e.eks.create_addon().cluster_name("ad").addon_name("coredns").addon_version("v0.0.1").send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Addon version specified is not supported");
    let err = e.eks.create_addon().cluster_name("ad").addon_name("vpc-cni").send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_in_use_exception());
    let up = e
        .eks
        .update_addon()
        .cluster_name("ad")
        .addon_name("vpc-cni")
        .addon_version("v1.19.6-eksbuild.7")
        .resolve_conflicts(ResolveConflicts::Overwrite)
        .send()
        .await
        .unwrap();
    assert_eq!(up.update().unwrap().r#type(), Some(&UpdateType::AddonUpdate));
    let d = e.eks.describe_addon().cluster_name("ad").addon_name("vpc-cni").send().await.unwrap();
    assert_eq!(d.addon().unwrap().addon_version(), Some("v1.19.6-eksbuild.7"));
    assert_eq!(d.addon().unwrap().status().unwrap().as_str(), "ACTIVE");
    assert_eq!(e.eks.list_addons().cluster_name("ad").send().await.unwrap().addons(), ["vpc-cni"]);
    let addon_updates = e.eks.list_updates().name("ad").addon_name("vpc-cni").send().await.unwrap();
    assert_eq!(addon_updates.update_ids().len(), 1);

    // The add-on owns its association.
    let owned = e.eks.list_pod_identity_associations().cluster_name("ad").send().await.unwrap();
    let owned = &owned.associations()[0];
    assert_eq!(owned.owner_arn(), addon.addon_arn());
    let err = e
        .eks
        .delete_pod_identity_association()
        .cluster_name("ad")
        .association_id(owned.association_id().unwrap())
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_invalid_request_exception());

    let assoc = e
        .eks
        .create_pod_identity_association()
        .cluster_name("ad")
        .namespace("default")
        .service_account("app")
        .role_arn(&e.pod_role)
        .tags("app", "web")
        .send()
        .await
        .unwrap();
    let assoc = assoc.association().unwrap();
    let id = assoc.association_id().unwrap().to_string();
    assert!(id.starts_with("a-") && id.len() == 19, "{id}");
    assert_eq!(
        assoc.association_arn(),
        Some(format!("arn:aws:eks:us-east-1:{ACCOUNT}:podidentityassociation/ad/{id}").as_str())
    );
    let err = e
        .eks
        .create_pod_identity_association()
        .cluster_name("ad")
        .namespace("default")
        .service_account("app")
        .role_arn(&e.pod_role)
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_resource_in_use_exception());
    let err = e
        .eks
        .create_pod_identity_association()
        .cluster_name("ad")
        .namespace("default")
        .service_account("other")
        .role_arn(&e.node_role)
        .send()
        .await
        .unwrap_err();
    assert!(message(err.as_service_error().unwrap()).contains("must trust pods.eks.amazonaws.com"));
    let target = format!("arn:aws:iam::{ACCOUNT}:role/target");
    let up = e
        .eks
        .update_pod_identity_association()
        .cluster_name("ad")
        .association_id(&id)
        .target_role_arn(&target)
        .disable_session_tags(true)
        .send()
        .await
        .unwrap();
    let up = up.association().unwrap();
    assert_eq!(up.target_role_arn(), Some(target.as_str()));
    assert!(up.external_id().is_some());
    assert_eq!(up.disable_session_tags(), Some(true));
    let d = e.eks.describe_pod_identity_association().cluster_name("ad").association_id(&id).send().await.unwrap();
    assert_eq!(d.association().unwrap().service_account(), Some("app"));
    let filtered = e.eks.list_pod_identity_associations().cluster_name("ad").namespace("default").send().await.unwrap();
    assert_eq!(filtered.associations().len(), 1);
    e.eks.delete_pod_identity_association().cluster_name("ad").association_id(&id).send().await.unwrap();

    let del = e.eks.delete_addon().cluster_name("ad").addon_name("vpc-cni").send().await.unwrap();
    assert_eq!(del.addon().unwrap().status().unwrap().as_str(), "DELETING");
    e.eks
        .wait_until_addon_deleted()
        .cluster_name("ad")
        .addon_name("vpc-cni")
        .wait(Duration::from_secs(60))
        .await
        .unwrap();
    assert!(e.eks.list_pod_identity_associations().cluster_name("ad").send().await.unwrap().associations().is_empty());
    let err = e.eks.describe_addon().cluster_name("ad").addon_name("vpc-cni").send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "No addon: vpc-cni found in cluster: ad");
}

#[tokio::test]
async fn fargate_identity_providers_and_capabilities() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    e.cluster("fg", AuthenticationMode::Api).await;
    let fargate_role = format!("arn:aws:iam::{ACCOUNT}:role/eks-fargate");

    let err = e
        .eks
        .create_fargate_profile()
        .cluster_name("fg")
        .fargate_profile_name("none")
        .pod_execution_role_arn(&fargate_role)
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Fargate Profile must have at least one selector.");
    let fp = e
        .eks
        .create_fargate_profile()
        .cluster_name("fg")
        .fargate_profile_name("serverless")
        .pod_execution_role_arn(&fargate_role)
        .selectors(FargateProfileSelector::builder().namespace("batch").labels("run", "fargate").build())
        .send()
        .await
        .unwrap();
    let fp = fp.fargate_profile().unwrap();
    assert_eq!(fp.status().unwrap().as_str(), "CREATING");
    assert_eq!(fp.subnets().len(), 2);
    e.eks
        .wait_until_fargate_profile_active()
        .cluster_name("fg")
        .fargate_profile_name("serverless")
        .wait(Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        e.eks.list_fargate_profiles().cluster_name("fg").send().await.unwrap().fargate_profile_names(),
        ["serverless"]
    );
    let entry = e.eks.describe_access_entry().cluster_name("fg").principal_arn(&fargate_role).send().await.unwrap();
    assert_eq!(entry.access_entry().unwrap().r#type(), Some("FARGATE_LINUX"));
    let err = e.eks.delete_cluster().name("fg").send().await.unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "Cluster has fargate profiles attached");
    e.eks.delete_fargate_profile().cluster_name("fg").fargate_profile_name("serverless").send().await.unwrap();
    let err = e
        .eks
        .describe_fargate_profile()
        .cluster_name("fg")
        .fargate_profile_name("serverless")
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(err.as_service_error().unwrap()), "No Fargate Profile found with name: serverless.");

    // OIDC identity provider.
    let idp = e
        .eks
        .associate_identity_provider_config()
        .cluster_name("fg")
        .oidc(
            OidcIdentityProviderConfigRequest::builder()
                .identity_provider_config_name("okta")
                .issuer_url("https://example.okta.com")
                .client_id("kubernetes")
                .username_claim("email")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(idp.update().unwrap().r#type(), Some(&UpdateType::AssociateIdentityProviderConfig));
    let which = IdentityProviderConfig::builder().r#type("oidc").name("okta").build().unwrap();
    let d = e
        .eks
        .describe_identity_provider_config()
        .cluster_name("fg")
        .identity_provider_config(which.clone())
        .send()
        .await
        .unwrap();
    let oidc = d.identity_provider_config().unwrap().oidc().unwrap();
    assert_eq!(oidc.status().unwrap().as_str(), "ACTIVE");
    assert_eq!(oidc.username_claim(), Some("email"));
    let list = e.eks.list_identity_provider_configs().cluster_name("fg").send().await.unwrap();
    assert_eq!(list.identity_provider_configs()[0].name(), "okta");
    e.eks
        .disassociate_identity_provider_config()
        .cluster_name("fg")
        .identity_provider_config(which.clone())
        .send()
        .await
        .unwrap();
    let err = e
        .eks
        .describe_identity_provider_config()
        .cluster_name("fg")
        .identity_provider_config(which)
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_resource_not_found_exception());

    // Capabilities.
    let role = format!("arn:aws:iam::{ACCOUNT}:role/eks-capability");
    let argo = e
        .eks
        .create_capability()
        .cluster_name("fg")
        .capability_name("argo")
        .r#type(CapabilityType::Argocd)
        .role_arn(&role)
        .delete_propagation_policy(CapabilityDeletePropagationPolicy::Retain)
        .configuration(
            CapabilityConfigurationRequest::builder()
                .argo_cd(
                    ArgoCdConfigRequest::builder()
                        .aws_idc(
                            ArgoCdAwsIdcConfigRequest::builder()
                                .idc_instance_arn("arn:aws:sso:::instance/ssoins-1234567890abcdef")
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let argo = argo.capability().unwrap();
    assert_eq!(argo.status().unwrap().as_str(), "CREATING");
    let server = argo.configuration().unwrap().argo_cd().unwrap().server_url().unwrap();
    assert!(server.ends_with(".eks-capabilities.us-east-1.amazonaws.com"), "{server}");
    let err = e
        .eks
        .create_capability()
        .cluster_name("fg")
        .capability_name("ack")
        .r#type(CapabilityType::Ack)
        .role_arn(&e.node_role)
        .delete_propagation_policy(CapabilityDeletePropagationPolicy::Retain)
        .send()
        .await
        .unwrap_err();
    assert!(message(err.as_service_error().unwrap()).contains("capabilities.eks.amazonaws.com"));
    let caps = e.eks.list_capabilities().cluster_name("fg").send().await.unwrap();
    assert_eq!(caps.capabilities()[0].status().unwrap().as_str(), "ACTIVE");
    let up = e.eks.update_capability().cluster_name("fg").capability_name("argo").role_arn(&role).send().await.unwrap();
    assert_eq!(up.update().unwrap().r#type(), Some(&UpdateType::CapabilityUpdate));
    let ups = e.eks.list_updates().name("fg").capability_name("argo").send().await.unwrap();
    assert_eq!(ups.update_ids().len(), 1);
    let d = e.eks.describe_capability().cluster_name("fg").capability_name("argo").send().await.unwrap();
    assert_eq!(d.capability().unwrap().r#type(), Some(&CapabilityType::Argocd));
    e.eks.delete_capability().cluster_name("fg").capability_name("argo").send().await.unwrap();
    let err = e.eks.describe_capability().cluster_name("fg").capability_name("argo").send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_not_found_exception());
}

#[tokio::test]
async fn certificate_authorities_rotate() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    e.cluster("ca", AuthenticationMode::Api).await;
    let list = e.eks.list_certificate_authorities().cluster_name("ca").send().await.unwrap();
    let original = list.certificate_authorities()[0].id().unwrap().to_string();
    assert_eq!(list.certificate_authorities()[0].signing_status().unwrap().as_str(), "IN_USE");

    let created = e.eks.create_certificate_authority().cluster_name("ca").send().await.unwrap();
    let new = created.certificate_authority().unwrap().id().unwrap().to_string();
    assert_eq!(created.certificate_authority().unwrap().distribution_status().unwrap().as_str(), "IN_PROGRESS");
    let err = e.eks.create_certificate_authority().cluster_name("ca").send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_limit_exceeded_exception());
    let d =
        e.eks.describe_certificate_authority().cluster_name("ca").certificate_authority_id(&new).send().await.unwrap();
    let ca = d.certificate_authority().unwrap();
    assert_eq!(ca.distribution_status().unwrap().as_str(), "COMPLETE");
    assert!(ca.validity().unwrap().not_after().is_some());

    e.eks.activate_certificate_authority().cluster_name("ca").certificate_authority_id(&new).send().await.unwrap();
    let c = e.eks.describe_cluster().name("ca").send().await.unwrap();
    assert_eq!(c.cluster().unwrap().certificate_authority().unwrap().active().unwrap().id(), Some(new.as_str()));
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(c.cluster().unwrap().certificate_authority().unwrap().data().unwrap())
        .unwrap();
    assert_eq!(String::from_utf8(bundle).unwrap().matches("BEGIN CERTIFICATE").count(), 2);

    let err = e
        .eks
        .delete_certificate_authority()
        .cluster_name("ca")
        .certificate_authority_id(&new)
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_resource_in_use_exception());
    e.eks.delete_certificate_authority().cluster_name("ca").certificate_authority_id(&original).send().await.unwrap();
    let list = e.eks.list_certificate_authorities().cluster_name("ca").send().await.unwrap();
    assert_eq!(list.certificate_authorities().len(), 1);
}

#[tokio::test]
async fn insights_subscriptions_registered_clusters_and_tags() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    let cluster = e.cluster("ins", AuthenticationMode::Api).await;

    let insights = e.eks.list_insights().cluster_name("ins").send().await.unwrap();
    let names: Vec<_> = insights.insights().iter().filter_map(|i| i.name()).collect();
    assert!(names.contains(&"Kubelet version skew"), "{names:?}");
    assert!(names.contains(&"Deprecated APIs removed in Kubernetes v1.35"));
    let first = insights.insights()[0].id().unwrap();
    let d = e.eks.describe_insight().cluster_name("ins").id(first).send().await.unwrap();
    assert_eq!(d.insight().unwrap().insight_status().unwrap().status().unwrap().as_str(), "PASSING");
    let r = e.eks.start_insights_refresh().cluster_name("ins").send().await.unwrap();
    assert_eq!(r.status().unwrap().as_str(), "IN_PROGRESS");
    let r = e.eks.describe_insights_refresh().cluster_name("ins").send().await.unwrap();
    assert_eq!(r.status().unwrap().as_str(), "COMPLETED");

    // Tags on clusters and their children.
    let arn = cluster.arn().unwrap();
    e.eks.tag_resource().resource_arn(arn).tags("env", "test").send().await.unwrap();
    let tags = e.eks.list_tags_for_resource().resource_arn(arn).send().await.unwrap();
    assert_eq!(tags.tags().unwrap()["env"], "test");
    assert_eq!(tags.tags().unwrap()["team"], "platform");
    e.eks.untag_resource().resource_arn(arn).tag_keys("team").send().await.unwrap();
    let tags = e.eks.list_tags_for_resource().resource_arn(arn).send().await.unwrap();
    assert!(!tags.tags().unwrap().contains_key("team"));
    let err = e.eks.tag_resource().resource_arn(arn).tags("aws:x", "y").send().await.unwrap_err();
    assert!(err.into_service_error().is_bad_request_exception());
    let err = e
        .eks
        .list_tags_for_resource()
        .resource_arn(format!("arn:aws:eks:us-east-1:{ACCOUNT}:cluster/missing"))
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_not_found_exception());

    // EKS Anywhere.
    let sub = e
        .eks
        .create_eks_anywhere_subscription()
        .name("onprem")
        .term(EksAnywhereSubscriptionTerm::builder().duration(12).unit(EksAnywhereSubscriptionTermUnit::Months).build())
        .license_quantity(2)
        .send()
        .await
        .unwrap();
    let sub = sub.subscription().unwrap();
    let id = sub.id().unwrap().to_string();
    assert_eq!(sub.licenses().len(), 2);
    assert_eq!(sub.status(), Some("CREATING"));
    let d = e.eks.describe_eks_anywhere_subscription().id(&id).send().await.unwrap();
    assert_eq!(d.subscription().unwrap().status(), Some("ACTIVE"));
    let u = e.eks.update_eks_anywhere_subscription().id(&id).auto_renew(true).send().await.unwrap();
    assert!(u.subscription().unwrap().auto_renew());
    e.eks.tag_resource().resource_arn(sub.arn().unwrap()).tags("k", "v").send().await.unwrap();
    let subs = e.eks.list_eks_anywhere_subscriptions().send().await.unwrap();
    assert_eq!(subs.subscriptions().len(), 1);
    let err = e
        .eks
        .create_eks_anywhere_subscription()
        .name("bad")
        .term(EksAnywhereSubscriptionTerm::builder().duration(7).unit(EksAnywhereSubscriptionTermUnit::Months).build())
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_invalid_parameter_exception());
    e.eks.delete_eks_anywhere_subscription().id(&id).send().await.unwrap();
    let err = e.eks.describe_eks_anywhere_subscription().id(&id).send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_not_found_exception());

    // EKS Connector.
    let reg = e
        .eks
        .register_cluster()
        .name("onprem-k8s")
        .connector_config(
            ConnectorConfigRequest::builder()
                .role_arn(format!("arn:aws:iam::{ACCOUNT}:role/eks-connector"))
                .provider(ConnectorConfigProvider::Other)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let reg = reg.cluster().unwrap();
    assert_eq!(reg.status().unwrap().as_str(), "PENDING");
    assert!(reg.connector_config().unwrap().activation_code().is_some());
    assert_eq!(e.eks.list_clusters().send().await.unwrap().clusters(), ["ins"]);
    let mut all = e.eks.list_clusters().include("all").send().await.unwrap().clusters().to_vec();
    all.sort();
    assert_eq!(all, ["ins", "onprem-k8s"]);
    let err = e.eks.delete_cluster().name("onprem-k8s").send().await.unwrap_err();
    assert!(err.into_service_error().is_invalid_request_exception());
    let dereg = e.eks.deregister_cluster().name("onprem-k8s").send().await.unwrap();
    assert_eq!(dereg.cluster().unwrap().status().unwrap().as_str(), "DELETING");
    let err = e.eks.describe_cluster().name("onprem-k8s").send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_not_found_exception());
}

#[tokio::test]
async fn eks_state_survives_export_and_import() {
    let mws = Mws::start().await;
    let e = env(&mws).await;
    e.cluster("saved", AuthenticationMode::Api).await;
    let (status, snapshot) = mws.control("GET", "/_mws/state", None).await;
    assert_eq!(status, 200);
    let (status, _) = mws.control("POST", "/_mws/reset", None).await;
    assert_eq!(status, 200);
    assert!(e.eks.describe_cluster().name("saved").send().await.is_err());
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&snapshot.to_string())).await;
    assert_eq!(status, 200);
    let c = e.eks.describe_cluster().name("saved").send().await.unwrap();
    assert_eq!(c.cluster().unwrap().status().unwrap().as_str(), "ACTIVE");
}
