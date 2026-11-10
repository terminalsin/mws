//! CloudFormation stacks with EKS, Auto Scaling, GuardDuty and Security
//! Hub resources (metadata backends): clusters and node groups that wait
//! for `ACTIVE`, groups that wait for their capacity, in-place updates and
//! deletes, checked through each service's own SDK client.

use std::time::Duration;

use aws_sdk_cloudformation::types::{Capability, Output, Parameter, StackStatus};
use aws_sdk_cloudformation::Client;
use aws_sdk_ec2::types::Filter;
use mws_e2e::Mws;

const TEMPLATE: &str = r#"
Parameters:
  Ami: {Type: String}
  Desired: {Type: Number, Default: 2}
  Nodes: {Type: Number, Default: 1}
  Frequency: {Type: String, Default: FIFTEEN_MINUTES}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: {CidrBlock: 10.50.0.0/16}
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties: {VpcId: !Ref Vpc, CidrBlock: 10.50.1.0/24, AvailabilityZone: us-east-1a}
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties: {VpcId: !Ref Vpc, CidrBlock: 10.50.2.0/24, AvailabilityZone: us-east-1b}
  ClusterRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [{Effect: Allow, Principal: {Service: eks.amazonaws.com}, Action: ["sts:AssumeRole", "sts:TagSession"]}]
  NodeRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [{Effect: Allow, Principal: {Service: ec2.amazonaws.com}, Action: sts:AssumeRole}]
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [{Effect: Allow, Principal: {AWS: !Ref AWS::AccountId}, Action: sts:AssumeRole}]
  Cluster:
    Type: AWS::EKS::Cluster
    Properties:
      RoleArn: !GetAtt ClusterRole.Arn
      ResourcesVpcConfig:
        SubnetIds: [!Ref SubnetA, !Ref SubnetB]
        EndpointPublicAccess: true
      AccessConfig: {AuthenticationMode: API_AND_CONFIG_MAP}
      Logging:
        ClusterLogging:
          EnabledTypes: [{Type: api}, {Type: audit}]
      Tags: [{Key: team, Value: platform}]
  Nodes:
    Type: AWS::EKS::Nodegroup
    Properties:
      ClusterName: !Ref Cluster
      NodeRole: !GetAtt NodeRole.Arn
      Subnets: [!Ref SubnetA, !Ref SubnetB]
      ScalingConfig: {MinSize: 1, MaxSize: 3, DesiredSize: !Ref Nodes}
      Labels: {workload: general}
  Admin:
    Type: AWS::EKS::AccessEntry
    Properties:
      ClusterName: !Ref Cluster
      PrincipalArn: !GetAtt AdminRole.Arn
      AccessPolicies:
        - PolicyArn: arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy
          AccessScope: {Type: cluster}
  WebConfig:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      ImageId: !Ref Ami
      InstanceType: t3.micro
      InstanceMonitoring: "false"
  Web:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      LaunchConfigurationName: !Ref WebConfig
      MinSize: "1"
      MaxSize: "3"
      DesiredCapacity: !Ref Desired
      VPCZoneIdentifier: [!Ref SubnetA, !Ref SubnetB]
      Tags: [{Key: app, Value: web, PropagateAtLaunch: "true"}]
  ScaleOut:
    Type: AWS::AutoScaling::ScalingPolicy
    Properties:
      AutoScalingGroupName: !Ref Web
      PolicyType: SimpleScaling
      AdjustmentType: ChangeInCapacity
      ScalingAdjustment: "1"
      Cooldown: "60"
  Launching:
    Type: AWS::AutoScaling::LifecycleHook
    Properties:
      AutoScalingGroupName: !Ref Web
      LifecycleTransition: autoscaling:EC2_INSTANCE_LAUNCHING
      HeartbeatTimeout: "300"
      DefaultResult: CONTINUE
  Nightly:
    Type: AWS::AutoScaling::ScheduledAction
    Properties:
      AutoScalingGroupName: !Ref Web
      Recurrence: "0 2 * * *"
      DesiredCapacity: "1"
  Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: !Ref Frequency
  ArchiveLow:
    Type: AWS::GuardDuty::Filter
    Properties:
      DetectorId: !Ref Detector
      Name: archive-low
      Action: ARCHIVE
      Rank: 1
      FindingCriteria:
        Criterion:
          severity: {LessThan: 4}
  Hub:
    Type: AWS::SecurityHub::Hub
    Properties:
      EnableDefaultStandards: false
      Tags: {owner: security}
  Critical:
    Type: AWS::SecurityHub::Insight
    DependsOn: Hub
    Properties:
      Name: critical findings
      GroupByAttribute: ResourceId
      Filters:
        SeverityLabel: [{Value: CRITICAL, Comparison: EQUALS}]
Outputs:
  ClusterName: {Value: !Ref Cluster}
  ClusterArn: {Value: !GetAtt Cluster.Arn}
  ClusterEndpoint: {Value: !GetAtt Cluster.Endpoint}
  ClusterCa: {Value: !GetAtt Cluster.CertificateAuthorityData}
  ClusterOidc: {Value: !GetAtt Cluster.OpenIdConnectIssuerUrl}
  ClusterSg: {Value: !GetAtt Cluster.ClusterSecurityGroupId}
  NodesName: {Value: !GetAtt Nodes.NodegroupName}
  NodesArn: {Value: !GetAtt Nodes.Arn}
  AdminArn: {Value: !GetAtt Admin.AccessEntryArn}
  GroupName: {Value: !Ref Web}
  PolicyArn: {Value: !Ref ScaleOut}
  PolicyName: {Value: !GetAtt ScaleOut.PolicyName}
  DetectorId: {Value: !GetAtt Detector.Id}
  HubArn: {Value: !GetAtt Hub.ARN}
  InsightArn: {Value: !GetAtt Critical.InsightArn}
"#;

fn param(k: &str, v: &str) -> Parameter {
    Parameter::builder().parameter_key(k).parameter_value(v).build()
}

fn output(outputs: &[Output], key: &str) -> String {
    outputs
        .iter()
        .find(|o| o.output_key() == Some(key))
        .and_then(|o| o.output_value())
        .unwrap_or_else(|| panic!("no output {key}"))
        .to_string()
}

async fn settle(cfn: &Client, stack: &str) -> aws_sdk_cloudformation::types::Stack {
    for _ in 0..1200 {
        let out = cfn.describe_stacks().stack_name(stack).send().await.unwrap();
        let s = out.stacks()[0].clone();
        if !s.stack_status().unwrap().as_str().ends_with("_IN_PROGRESS") {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("stack {stack} did not settle");
}

async fn failures(cfn: &Client, stack: &str) -> Vec<String> {
    let events = cfn.describe_stack_events().stack_name(stack).send().await.unwrap();
    events
        .stack_events()
        .iter()
        .filter(|e| e.resource_status().is_some_and(|s| s.as_str().ends_with("FAILED")))
        .map(|e| {
            format!(
                "{}: {}",
                e.logical_resource_id().unwrap_or_default(),
                e.resource_status_reason().unwrap_or_default()
            )
        })
        .collect()
}

fn in_service(g: &aws_sdk_autoscaling::types::AutoScalingGroup) -> usize {
    g.instances().iter().filter(|i| i.lifecycle_state().map(|s| s.as_str()) == Some("InService")).count()
}

#[tokio::test]
async fn clusters_groups_and_security_services_deploy_update_and_delete() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let cfn = Client::new(&config);
    let ec2 = aws_sdk_ec2::Client::new(&config);
    let eks = aws_sdk_eks::Client::new(&config);
    let asg = aws_sdk_autoscaling::Client::new(&config);
    let gd = aws_sdk_guardduty::Client::new(&config);
    let sh = aws_sdk_securityhub::Client::new(&config);

    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();

    cfn.create_stack()
        .stack_name("compute")
        .template_body(TEMPLATE)
        .parameters(param("Ami", &ami))
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    let stack = settle(&cfn, "compute").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", failures(&cfn, "compute").await);
    let outs = stack.outputs().to_vec();

    // EKS: the cluster is ACTIVE and the attributes are what EKS reports.
    let name = output(&outs, "ClusterName");
    assert!(name.starts_with("compute-Cluster-"), "{name}");
    let c = eks.describe_cluster().name(&name).send().await.unwrap();
    let cluster = c.cluster().unwrap();
    assert_eq!(cluster.status().map(|s| s.as_str()), Some("ACTIVE"));
    assert_eq!(cluster.arn(), Some(output(&outs, "ClusterArn").as_str()));
    assert_eq!(cluster.endpoint(), Some(output(&outs, "ClusterEndpoint").as_str()));
    assert_eq!(cluster.certificate_authority().unwrap().data(), Some(output(&outs, "ClusterCa").as_str()));
    assert_eq!(cluster.identity().unwrap().oidc().unwrap().issuer(), Some(output(&outs, "ClusterOidc").as_str()));
    let sg = output(&outs, "ClusterSg");
    assert!(sg.starts_with("sg-"), "{sg}");
    assert_eq!(cluster.resources_vpc_config().unwrap().cluster_security_group_id(), Some(sg.as_str()));
    assert_eq!(cluster.tags().unwrap().get("team").map(String::as_str), Some("platform"));
    let logging = cluster.logging().unwrap().cluster_logging();
    let enabled: Vec<&str> = logging
        .iter()
        .filter(|l| l.enabled() == Some(true))
        .flat_map(|l| l.types().iter().map(|t| t.as_str()))
        .collect();
    assert_eq!(enabled, ["api", "audit"]);
    let ng_name = output(&outs, "NodesName");
    let ng = eks.describe_nodegroup().cluster_name(&name).nodegroup_name(&ng_name).send().await.unwrap();
    let ng = ng.nodegroup().unwrap();
    assert_eq!(ng.status().map(|s| s.as_str()), Some("ACTIVE"));
    assert_eq!(ng.nodegroup_arn(), Some(output(&outs, "NodesArn").as_str()));
    assert_eq!(ng.scaling_config().unwrap().desired_size(), Some(1));
    assert_eq!(ng.labels().unwrap().get("workload").map(String::as_str), Some("general"));
    assert!(output(&outs, "AdminArn").starts_with("arn:aws:eks:us-east-1:"));
    let entries = eks.list_access_entries().cluster_name(&name).send().await.unwrap();
    let admin = entries.access_entries().iter().find(|a| a.contains(":role/compute-AdminRole-")).unwrap().clone();
    let policies =
        eks.list_associated_access_policies().cluster_name(&name).principal_arn(&admin).send().await.unwrap();
    assert_eq!(
        policies.associated_access_policies()[0].policy_arn(),
        Some("arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy")
    );

    // Auto Scaling: the group reached its desired capacity before the
    // stack completed.
    let group = output(&outs, "GroupName");
    let g = asg.describe_auto_scaling_groups().auto_scaling_group_names(&group).send().await.unwrap();
    let g = &g.auto_scaling_groups()[0];
    assert_eq!(g.desired_capacity(), Some(2));
    assert_eq!(in_service(g), 2);
    assert!(g.launch_configuration_name().unwrap().starts_with("compute-WebConfig-"));
    assert!(g.tags().iter().any(|t| t.key() == Some("app") && t.propagate_at_launch() == Some(true)));
    let p = asg.describe_policies().auto_scaling_group_name(&group).send().await.unwrap();
    let policy = &p.scaling_policies()[0];
    assert_eq!(policy.policy_arn(), Some(output(&outs, "PolicyArn").as_str()));
    assert_eq!(policy.policy_name(), Some(output(&outs, "PolicyName").as_str()));
    assert_eq!(policy.scaling_adjustment(), Some(1));
    assert_eq!(policy.cooldown(), Some(60));
    let hooks = asg.describe_lifecycle_hooks().auto_scaling_group_name(&group).send().await.unwrap();
    assert_eq!(hooks.lifecycle_hooks()[0].heartbeat_timeout(), Some(300));
    let actions = asg.describe_scheduled_actions().auto_scaling_group_name(&group).send().await.unwrap();
    assert_eq!(actions.scheduled_update_group_actions()[0].recurrence(), Some("0 2 * * *"));

    // GuardDuty and Security Hub.
    let detector = output(&outs, "DetectorId");
    let d = gd.get_detector().detector_id(&detector).send().await.unwrap();
    assert_eq!(d.finding_publishing_frequency().map(|f| f.as_str()), Some("FIFTEEN_MINUTES"));
    let f = gd.get_filter().detector_id(&detector).filter_name("archive-low").send().await.unwrap();
    assert_eq!(f.action().map(|a| a.as_str()), Some("ARCHIVE"));
    assert_eq!(f.finding_criteria().unwrap().criterion().unwrap()["severity"].less_than(), Some(4));
    let hub = sh.describe_hub().send().await.unwrap();
    assert_eq!(hub.hub_arn(), Some(output(&outs, "HubArn").as_str()));
    let enabled = sh.get_enabled_standards().send().await.unwrap();
    assert!(enabled.standards_subscriptions().is_empty(), "EnableDefaultStandards: false");
    let insights = sh.get_insights().insight_arns(output(&outs, "InsightArn")).send().await.unwrap();
    assert_eq!(insights.insights()[0].name(), Some("critical findings"));

    // Update in place.
    cfn.update_stack()
        .stack_name("compute")
        .use_previous_template(true)
        .parameters(param("Ami", &ami))
        .parameters(param("Desired", "1"))
        .parameters(param("Nodes", "2"))
        .parameters(param("Frequency", "ONE_HOUR"))
        .capabilities(Capability::CapabilityIam)
        .send()
        .await
        .unwrap();
    let stack = settle(&cfn, "compute").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::UpdateComplete), "{:?}", failures(&cfn, "compute").await);
    assert_eq!(output(stack.outputs(), "ClusterName"), name);
    assert_eq!(output(stack.outputs(), "GroupName"), group);
    let g = asg.describe_auto_scaling_groups().auto_scaling_group_names(&group).send().await.unwrap();
    assert_eq!(g.auto_scaling_groups()[0].desired_capacity(), Some(1));
    let ng = eks.describe_nodegroup().cluster_name(&name).nodegroup_name(&ng_name).send().await.unwrap();
    assert_eq!(ng.nodegroup().unwrap().scaling_config().unwrap().desired_size(), Some(2));
    let d = gd.get_detector().detector_id(&detector).send().await.unwrap();
    assert_eq!(d.finding_publishing_frequency().map(|f| f.as_str()), Some("ONE_HOUR"));

    // Delete: everything is gone.
    cfn.delete_stack().stack_name("compute").send().await.unwrap();
    let stack = settle(&cfn, "compute").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::DeleteComplete), "{:?}", failures(&cfn, "compute").await);
    let e = eks.describe_cluster().name(&name).send().await.unwrap_err();
    assert_eq!(e.into_service_error().meta().code(), Some("ResourceNotFoundException"));
    let g = asg.describe_auto_scaling_groups().auto_scaling_group_names(&group).send().await.unwrap();
    assert!(g.auto_scaling_groups().is_empty());
    let lcs = asg.describe_launch_configurations().send().await.unwrap();
    assert!(lcs.launch_configurations().is_empty());
    let detectors = gd.list_detectors().send().await.unwrap();
    assert!(detectors.detector_ids().is_empty());
    assert!(sh.describe_hub().send().await.is_err());
}
