//! CloudFormation stacks of container-platform resources through the
//! official Rust SDK: an ECR repository, an EFS file system with a mount
//! target and access point, an Application Load Balancer with a target
//! group, listener and rule, a Classic Load Balancer, and an ECS cluster,
//! task definition and Fargate service behind the ALB (metadata backend,
//! no Docker). Each resource is checked through its own service's SDK,
//! updated in place and removed with the stack.

use std::time::Duration;

use aws_sdk_cloudformation::types::{Parameter, StackStatus};
use aws_sdk_cloudformation::Client;
use mws_e2e::Mws;

fn param(k: &str, v: &str) -> Parameter {
    Parameter::builder().parameter_key(k).parameter_value(v).build()
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

fn output(s: &aws_sdk_cloudformation::types::Stack, key: &str) -> String {
    s.outputs()
        .iter()
        .find(|o| o.output_key() == Some(key))
        .and_then(|o| o.output_value())
        .unwrap_or_else(|| panic!("no output {key}"))
        .to_string()
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

async fn physical_id(cfn: &Client, stack: &str, logical: &str) -> String {
    let r = cfn.describe_stack_resource().stack_name(stack).logical_resource_id(logical).send().await.unwrap();
    r.stack_resource_detail().unwrap().physical_resource_id().unwrap().to_string()
}

const TEMPLATE: &str = r#"
Parameters:
  VpcId: {Type: "AWS::EC2::VPC::Id"}
  SubnetA: {Type: String}
  SubnetB: {Type: String}
  SecurityGroup: {Type: String}
  DesiredCount: {Type: Number, Default: 1}
  HealthPath: {Type: String, Default: /health}
  IdleTimeout: {Type: Number, Default: 120}
  Mutability: {Type: String, Default: IMMUTABLE}
Resources:
  Repo:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: cfn-web
      ImageTagMutability: !Ref Mutability
      ImageScanningConfiguration: {ScanOnPush: "true"}
      LifecyclePolicy:
        LifecyclePolicyText: '{"rules":[{"rulePriority":1,"selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":14},"action":{"type":"expire"}}]}'
      EmptyOnDelete: true
      Tags: [{Key: team, Value: web}]
  FileSystem:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
      PerformanceMode: generalPurpose
      LifecyclePolicies: [{TransitionToIA: AFTER_30_DAYS}]
      BackupPolicy: {Status: ENABLED}
      FileSystemTags: [{Key: Name, Value: shared}]
  MountTarget:
    Type: AWS::EFS::MountTarget
    Properties:
      FileSystemId: !Ref FileSystem
      SubnetId: !Ref SubnetA
      SecurityGroups: [!Ref SecurityGroup]
  AccessPoint:
    Type: AWS::EFS::AccessPoint
    Properties:
      FileSystemId: !Ref FileSystem
      PosixUser: {Uid: "1000", Gid: "1000"}
      RootDirectory:
        Path: /app
        CreationInfo: {OwnerUid: "1000", OwnerGid: "1000", Permissions: "0755"}
      AccessPointTags: [{Key: Name, Value: app}]
  Alb:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Subnets: [!Ref SubnetA, !Ref SubnetB]
      SecurityGroups: [!Ref SecurityGroup]
      LoadBalancerAttributes:
        - {Key: idle_timeout.timeout_seconds, Value: !Ref IdleTimeout}
      Tags: [{Key: tier, Value: edge}]
  Targets:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Port: 80
      Protocol: HTTP
      VpcId: !Ref VpcId
      TargetType: ip
      HealthCheckPath: !Ref HealthPath
      HealthCheckIntervalSeconds: "15"
      Matcher: {HttpCode: 200}
      TargetGroupAttributes:
        - {Key: deregistration_delay.timeout_seconds, Value: 0}
  Http:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref Alb
      Port: 80
      Protocol: HTTP
      DefaultActions: [{Type: forward, TargetGroupArn: !Ref Targets}]
  Api:
    Type: AWS::ElasticLoadBalancingV2::ListenerRule
    Properties:
      ListenerArn: !Ref Http
      Priority: 10
      Conditions: [{Field: path-pattern, Values: [/api/*]}]
      Actions:
        - Type: fixed-response
          FixedResponseConfig: {StatusCode: 200, ContentType: text/plain, MessageBody: ok}
  Classic:
    Type: AWS::ElasticLoadBalancing::LoadBalancer
    Properties:
      Subnets: [!Ref SubnetA]
      SecurityGroups: [!Ref SecurityGroup]
      Listeners: [{LoadBalancerPort: "80", InstancePort: "8080", Protocol: HTTP}]
      HealthCheck: {Target: "HTTP:8080/", Interval: "30", Timeout: "5", HealthyThreshold: "3", UnhealthyThreshold: "5"}
      ConnectionDrainingPolicy: {Enabled: true, Timeout: 60}
  Cluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterSettings: [{Name: containerInsights, Value: enabled}]
      Tags: [{Key: team, Value: web}]
  Providers:
    Type: AWS::ECS::ClusterCapacityProviderAssociations
    Properties:
      Cluster: !Ref Cluster
      CapacityProviders: [FARGATE, FARGATE_SPOT]
      DefaultCapacityProviderStrategy: [{CapacityProvider: FARGATE, Weight: 1}]
  TaskDef:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: cfn-web
      Cpu: 256
      Memory: 512
      NetworkMode: awsvpc
      RequiresCompatibilities: [FARGATE]
      ContainerDefinitions:
        - Name: web
          Image: !Sub "${Repo.RepositoryUri}:latest"
          Essential: true
          PortMappings: [{ContainerPort: 80}]
          DockerLabels: {com.example.Team: web}
          MountPoints: [{SourceVolume: data, ContainerPath: /data}]
      Volumes:
        - Name: data
          EFSVolumeConfiguration:
            FilesystemId: !Ref FileSystem
            TransitEncryption: ENABLED
            AuthorizationConfig: {AccessPointId: !Ref AccessPoint}
  Service:
    Type: AWS::ECS::Service
    DependsOn: [Http, MountTarget]
    Properties:
      Cluster: !Ref Cluster
      TaskDefinition: !Ref TaskDef
      DesiredCount: !Ref DesiredCount
      LaunchType: FARGATE
      HealthCheckGracePeriodSeconds: 600
      DeploymentConfiguration: {MinimumHealthyPercent: 0, MaximumPercent: 200}
      NetworkConfiguration:
        AwsvpcConfiguration:
          Subnets: [!Ref SubnetA]
          SecurityGroups: [!Ref SecurityGroup]
          AssignPublicIp: ENABLED
      LoadBalancers: [{TargetGroupArn: !Ref Targets, ContainerName: web, ContainerPort: 80}]
      Tags: [{Key: app, Value: web}]
Outputs:
  RepoUri: {Value: !GetAtt Repo.RepositoryUri}
  RepoArn: {Value: !GetAtt Repo.Arn}
  FsId: {Value: !GetAtt FileSystem.FileSystemId}
  FsArn: {Value: !GetAtt FileSystem.Arn}
  MountIp: {Value: !GetAtt MountTarget.IpAddress}
  ApArn: {Value: !GetAtt AccessPoint.Arn}
  ApId: {Value: !GetAtt AccessPoint.AccessPointId}
  AlbDns: {Value: !GetAtt Alb.DNSName}
  AlbZone: {Value: !GetAtt Alb.CanonicalHostedZoneID}
  AlbFullName: {Value: !GetAtt Alb.LoadBalancerFullName}
  AlbName: {Value: !GetAtt Alb.LoadBalancerName}
  TgFullName: {Value: !GetAtt Targets.TargetGroupFullName}
  TgLbs: {Value: !Join [",", !GetAtt Targets.LoadBalancerArns]}
  RuleArn: {Value: !GetAtt Api.RuleArn}
  ClassicDns: {Value: !GetAtt Classic.DNSName}
  ClassicSg: {Value: !GetAtt Classic.SourceSecurityGroup.GroupName}
  ClusterArn: {Value: !GetAtt Cluster.Arn}
  TaskDefArn: {Value: !GetAtt TaskDef.TaskDefinitionArn}
  ServiceArn: {Value: !Ref Service}
  ServiceName: {Value: !GetAtt Service.Name}
"#;

struct Clients {
    cfn: Client,
    ec2: aws_sdk_ec2::Client,
    ecr: aws_sdk_ecr::Client,
    ecs: aws_sdk_ecs::Client,
    efs: aws_sdk_efs::Client,
    elb: aws_sdk_elasticloadbalancingv2::Client,
    classic: aws_sdk_elasticloadbalancing::Client,
}

async fn clients(mws: &Mws) -> Clients {
    let c = mws.root_sdk_config().await;
    Clients {
        cfn: Client::new(&c),
        ec2: aws_sdk_ec2::Client::new(&c),
        ecr: aws_sdk_ecr::Client::new(&c),
        ecs: aws_sdk_ecs::Client::new(&c),
        efs: aws_sdk_efs::Client::new(&c),
        elb: aws_sdk_elasticloadbalancingv2::Client::new(&c),
        classic: aws_sdk_elasticloadbalancing::Client::new(&c),
    }
}

/// The default VPC, two of its subnets in different zones and its default
/// security group.
async fn network(ec2: &aws_sdk_ec2::Client) -> (String, String, String, String) {
    let s = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let subnets = s.subnets();
    let a = &subnets[0];
    let b = subnets.iter().find(|x| x.availability_zone() != a.availability_zone()).unwrap();
    let vpc = a.vpc_id().unwrap().to_string();
    let sg = ec2
        .describe_security_groups()
        .filters(aws_sdk_ec2::types::Filter::builder().name("vpc-id").values(&vpc).build())
        .filters(aws_sdk_ec2::types::Filter::builder().name("group-name").values("default").build())
        .send()
        .await
        .unwrap();
    let sg = sg.security_groups()[0].group_id().unwrap().to_string();
    (vpc, a.subnet_id().unwrap().to_string(), b.subnet_id().unwrap().to_string(), sg)
}

#[tokio::test]
async fn ecs_service_behind_an_alb_with_ecr_and_efs_deploys_updates_and_deletes() {
    let mws = Mws::start().await;
    let c = clients(&mws).await;
    let (vpc, a, b, sg) = network(&c.ec2).await;
    let net = vec![param("VpcId", &vpc), param("SubnetA", &a), param("SubnetB", &b), param("SecurityGroup", &sg)];

    c.cfn
        .create_stack()
        .stack_name("web")
        .template_body(TEMPLATE)
        .set_parameters(Some(net.clone()))
        .send()
        .await
        .unwrap();
    let stack = settle(&c.cfn, "web").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", failures(&c.cfn, "web").await);

    // ECR: the repository with its settings and lifecycle policy.
    let repos = c.ecr.describe_repositories().repository_names("cfn-web").send().await.unwrap();
    let repo = &repos.repositories()[0];
    assert_eq!(output(&stack, "RepoUri"), repo.repository_uri().unwrap());
    assert_eq!(output(&stack, "RepoArn"), repo.repository_arn().unwrap());
    assert_eq!(repo.image_tag_mutability().unwrap().as_str(), "IMMUTABLE");
    assert!(repo.image_scanning_configuration().unwrap().scan_on_push());
    c.ecr.get_lifecycle_policy().repository_name("cfn-web").send().await.unwrap();
    assert_eq!(physical_id(&c.cfn, "web", "Repo").await, "cfn-web");

    // EFS: the file system, mount target and access point.
    let fs_id = output(&stack, "FsId");
    assert!(fs_id.starts_with("fs-"), "{fs_id}");
    let fss = c.efs.describe_file_systems().file_system_id(&fs_id).send().await.unwrap();
    let fs = &fss.file_systems()[0];
    assert_eq!(output(&stack, "FsArn"), fs.file_system_arn().unwrap());
    assert!(fs.encrypted().unwrap());
    assert_eq!(fs.name(), Some("shared"));
    let backup = c.efs.describe_backup_policy().file_system_id(&fs_id).send().await.unwrap();
    assert_eq!(backup.backup_policy().unwrap().status().as_str(), "ENABLED");
    let mts = c.efs.describe_mount_targets().file_system_id(&fs_id).send().await.unwrap();
    assert_eq!(mts.mount_targets().len(), 1);
    assert_eq!(mts.mount_targets()[0].life_cycle_state().as_str(), "available");
    assert_eq!(output(&stack, "MountIp"), mts.mount_targets()[0].ip_address().unwrap());
    let aps = c.efs.describe_access_points().access_point_id(output(&stack, "ApId")).send().await.unwrap();
    let ap = &aps.access_points()[0];
    assert_eq!(output(&stack, "ApArn"), ap.access_point_arn().unwrap());
    assert_eq!(ap.posix_user().unwrap().uid(), 1000);
    assert_eq!(ap.root_directory().unwrap().path(), Some("/app"));

    // ELBv2: the load balancer, target group, listener and rule.
    let alb_arn = physical_id(&c.cfn, "web", "Alb").await;
    let lbs = c.elb.describe_load_balancers().load_balancer_arns(&alb_arn).send().await.unwrap();
    let lb = &lbs.load_balancers()[0];
    assert_eq!(output(&stack, "AlbDns"), lb.dns_name().unwrap());
    assert_eq!(output(&stack, "AlbZone"), lb.canonical_hosted_zone_id().unwrap());
    assert_eq!(output(&stack, "AlbName"), lb.load_balancer_name().unwrap());
    assert!(output(&stack, "AlbName").starts_with("web-Alb-"), "{}", output(&stack, "AlbName"));
    assert_eq!(output(&stack, "AlbFullName"), alb_arn.split_once(":loadbalancer/").unwrap().1);
    assert!(output(&stack, "AlbFullName").starts_with("app/"));
    let idle = |attrs: &aws_sdk_elasticloadbalancingv2::operation::describe_load_balancer_attributes::DescribeLoadBalancerAttributesOutput| {
        attrs.attributes().iter().find(|a| a.key() == Some("idle_timeout.timeout_seconds")).and_then(|a| a.value()).unwrap().to_string()
    };
    let attrs = c.elb.describe_load_balancer_attributes().load_balancer_arn(&alb_arn).send().await.unwrap();
    assert_eq!(idle(&attrs), "120");
    let tg_arn = physical_id(&c.cfn, "web", "Targets").await;
    let tgs = c.elb.describe_target_groups().target_group_arns(&tg_arn).send().await.unwrap();
    let tg = &tgs.target_groups()[0];
    assert_eq!(tg.health_check_path(), Some("/health"));
    assert_eq!(tg.health_check_interval_seconds(), Some(15));
    assert_eq!(tg.matcher().unwrap().http_code(), Some("200"));
    assert_eq!(output(&stack, "TgFullName"), tg_arn.rsplit(':').next().unwrap());
    let tga = c.elb.describe_target_group_attributes().target_group_arn(&tg_arn).send().await.unwrap();
    assert!(tga
        .attributes()
        .iter()
        .any(|a| a.key() == Some("deregistration_delay.timeout_seconds") && a.value() == Some("0")));
    let listeners = c.elb.describe_listeners().load_balancer_arn(&alb_arn).send().await.unwrap();
    assert_eq!(listeners.listeners().len(), 1);
    assert_eq!(listeners.listeners()[0].port(), Some(80));
    assert_eq!(listeners.listeners()[0].default_actions()[0].target_group_arn(), Some(tg_arn.as_str()));
    let rules = c.elb.describe_rules().rule_arns(output(&stack, "RuleArn")).send().await.unwrap();
    let rule = &rules.rules()[0];
    assert_eq!(rule.priority(), Some("10"));
    assert_eq!(rule.actions()[0].fixed_response_config().unwrap().status_code(), Some("200"));

    // Classic Load Balancer.
    let classic_name = physical_id(&c.cfn, "web", "Classic").await;
    let d = c.classic.describe_load_balancers().load_balancer_names(&classic_name).send().await.unwrap();
    let clb = &d.load_balancer_descriptions()[0];
    assert_eq!(output(&stack, "ClassicDns"), clb.dns_name().unwrap());
    assert_eq!(output(&stack, "ClassicSg"), clb.source_security_group().unwrap().group_name().unwrap());
    assert_eq!(clb.health_check().unwrap().target(), "HTTP:8080/");
    assert_eq!(clb.listener_descriptions()[0].listener().unwrap().instance_port(), 8080);
    let ca = c.classic.describe_load_balancer_attributes().load_balancer_name(&classic_name).send().await.unwrap();
    let drain = ca.load_balancer_attributes().unwrap().connection_draining().unwrap();
    assert!(drain.enabled());
    assert_eq!(drain.timeout(), Some(60));

    // ECS: the cluster, its capacity providers, the task definition and the
    // service, steady with its task running and registered in the group.
    let cluster = physical_id(&c.cfn, "web", "Cluster").await;
    let clusters = c
        .ecs
        .describe_clusters()
        .clusters(&cluster)
        .include(aws_sdk_ecs::types::ClusterField::Settings)
        .send()
        .await
        .unwrap();
    let cl = &clusters.clusters()[0];
    assert_eq!(output(&stack, "ClusterArn"), cl.cluster_arn().unwrap());
    assert_eq!(cl.capacity_providers(), ["FARGATE", "FARGATE_SPOT"]);
    assert_eq!(cl.settings()[0].value(), Some("enabled"));
    let td_arn = output(&stack, "TaskDefArn");
    assert_eq!(physical_id(&c.cfn, "web", "TaskDef").await, td_arn);
    assert!(td_arn.ends_with(":task-definition/cfn-web:1"), "{td_arn}");
    let td = c.ecs.describe_task_definition().task_definition(&td_arn).send().await.unwrap();
    let td = td.task_definition().unwrap();
    assert_eq!(td.cpu(), Some("256"));
    let cd = &td.container_definitions()[0];
    assert_eq!(cd.image(), Some(format!("{}:latest", output(&stack, "RepoUri")).as_str()));
    assert_eq!(cd.docker_labels().unwrap().get("com.example.Team").map(String::as_str), Some("web"));
    let efs_vol = td.volumes()[0].efs_volume_configuration().unwrap();
    assert_eq!(efs_vol.file_system_id(), fs_id);
    assert_eq!(efs_vol.authorization_config().unwrap().access_point_id(), Some(output(&stack, "ApId").as_str()));

    let service_arn = output(&stack, "ServiceArn");
    assert!(service_arn.contains(":service/"), "{service_arn}");
    let svcs = c.ecs.describe_services().cluster(&cluster).services(&service_arn).send().await.unwrap();
    let svc = &svcs.services()[0];
    assert_eq!(svc.service_name(), Some(output(&stack, "ServiceName").as_str()));
    assert_eq!(svc.running_count(), 1, "CloudFormation waits for the service to be steady");
    assert_eq!(svc.load_balancers()[0].target_group_arn(), Some(tg_arn.as_str()));
    assert_eq!(svc.health_check_grace_period_seconds(), Some(600));
    let tags = c.ecs.list_tags_for_resource().resource_arn(&service_arn).send().await.unwrap();
    assert!(tags.tags().iter().any(|t| t.key() == Some("app") && t.value() == Some("web")));

    // Update in place: count, health check path, idle timeout and tag
    // mutability change without replacing anything.
    let mut update = net.clone();
    update.extend([
        param("DesiredCount", "2"),
        param("HealthPath", "/ready"),
        param("IdleTimeout", "90"),
        param("Mutability", "MUTABLE"),
    ]);
    c.cfn.update_stack().stack_name("web").template_body(TEMPLATE).set_parameters(Some(update)).send().await.unwrap();
    let stack = settle(&c.cfn, "web").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::UpdateComplete), "{:?}", failures(&c.cfn, "web").await);
    assert_eq!(output(&stack, "ServiceArn"), service_arn);
    assert_eq!(physical_id(&c.cfn, "web", "Alb").await, alb_arn);
    assert_eq!(physical_id(&c.cfn, "web", "Targets").await, tg_arn);
    let svcs = c.ecs.describe_services().cluster(&cluster).services(&service_arn).send().await.unwrap();
    assert_eq!(svcs.services()[0].desired_count(), 2);
    assert_eq!(svcs.services()[0].running_count(), 2);
    let tgs = c.elb.describe_target_groups().target_group_arns(&tg_arn).send().await.unwrap();
    assert_eq!(tgs.target_groups()[0].health_check_path(), Some("/ready"));
    // The refreshed target group now reports the load balancer in front.
    assert_eq!(output(&stack, "TgLbs"), alb_arn);
    let attrs = c.elb.describe_load_balancer_attributes().load_balancer_arn(&alb_arn).send().await.unwrap();
    assert_eq!(idle(&attrs), "90");
    let repos = c.ecr.describe_repositories().repository_names("cfn-web").send().await.unwrap();
    assert_eq!(repos.repositories()[0].image_tag_mutability().unwrap().as_str(), "MUTABLE");

    // Delete removes everything.
    c.cfn.delete_stack().stack_name("web").send().await.unwrap();
    for _ in 0..1200 {
        let out = c.cfn.describe_stacks().stack_name("web").send().await;
        match out {
            Err(_) => break,
            Ok(o) if o.stacks()[0].stack_status() == Some(&StackStatus::DeleteComplete) => break,
            Ok(o) if o.stacks()[0].stack_status() == Some(&StackStatus::DeleteFailed) => {
                panic!("delete failed: {:?}", failures(&c.cfn, "web").await)
            }
            Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let svcs = c.ecs.describe_services().cluster(&cluster).services(&service_arn).send().await;
    if let Ok(svcs) = svcs {
        assert!(svcs.services().iter().all(|s| s.status() == Some("INACTIVE")));
    }
    let clusters = c.ecs.describe_clusters().clusters(&cluster).send().await.unwrap();
    assert!(clusters.clusters().iter().all(|c| c.status() == Some("INACTIVE")));
    let td = c.ecs.describe_task_definition().task_definition(&td_arn).send().await.unwrap();
    assert_eq!(td.task_definition().unwrap().status().unwrap().as_str(), "INACTIVE");
    assert!(c.elb.describe_load_balancers().load_balancer_arns(&alb_arn).send().await.is_err());
    assert!(c.elb.describe_target_groups().target_group_arns(&tg_arn).send().await.is_err());
    assert!(c.classic.describe_load_balancers().load_balancer_names(&classic_name).send().await.is_err());
    assert!(c.ecr.describe_repositories().repository_names("cfn-web").send().await.is_err());
    assert!(c.efs.describe_file_systems().file_system_id(&fs_id).send().await.is_err());
    mws.stop().await;
}

#[tokio::test]
async fn ecr_registry_resources_and_unknown_attributes() {
    let mws = Mws::start().await;
    let c = clients(&mws).await;
    let template = r#"
Resources:
  Policy:
    Type: AWS::ECR::RegistryPolicy
    Properties:
      PolicyText:
        Version: "2012-10-17"
        Statement:
          - Sid: Replicate
            Effect: Allow
            Principal: {AWS: "arn:aws:iam::210987654321:root"}
            Action: ["ecr:CreateRepository", "ecr:ReplicateImage"]
            Resource: !Sub "arn:aws:ecr:${AWS::Region}:${AWS::AccountId}:repository/*"
  Template:
    Type: AWS::ECR::RepositoryCreationTemplate
    Properties:
      Prefix: cache
      Description: pulled images
      AppliedFor: [PULL_THROUGH_CACHE]
      ImageTagMutability: MUTABLE
      ResourceTags: [{Key: source, Value: cache}]
Outputs:
  RegistryId: {Value: !GetAtt Policy.RegistryId}
  TemplatePrefix: {Value: !Ref Template}
"#;
    c.cfn.create_stack().stack_name("registry").template_body(template).send().await.unwrap();
    let stack = settle(&c.cfn, "registry").await;
    assert_eq!(stack.stack_status(), Some(&StackStatus::CreateComplete), "{:?}", failures(&c.cfn, "registry").await);
    assert_eq!(output(&stack, "RegistryId"), "123456789012");
    assert_eq!(output(&stack, "TemplatePrefix"), "cache");
    let p = c.ecr.get_registry_policy().send().await.unwrap();
    assert!(p.policy_text().unwrap().contains("ecr:ReplicateImage"));
    let t = c.ecr.describe_repository_creation_templates().prefixes("cache").send().await.unwrap();
    assert_eq!(t.repository_creation_templates()[0].description(), Some("pulled images"));

    // Fn::GetAtt of an attribute the type doesn't have fails validation.
    let bad = r#"
Resources:
  Repo: {Type: AWS::ECR::Repository}
Outputs:
  X: {Value: !GetAtt Repo.Nope}
"#;
    let e = c.cfn.create_stack().stack_name("bad").template_body(bad).send().await.unwrap_err();
    let msg = aws_sdk_cloudformation::error::ProvideErrorMetadata::message(&e).unwrap_or_default().to_string();
    assert!(msg.contains("does not support attribute type Nope"), "{msg}");

    c.cfn.delete_stack().stack_name("registry").send().await.unwrap();
    for _ in 0..600 {
        if c.ecr.get_registry_policy().send().await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(c.ecr.get_registry_policy().send().await.is_err());
    mws.stop().await;
}
