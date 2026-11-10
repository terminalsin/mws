//! ECS working with the services AWS couples it to, through the official
//! Rust SDKs: service tasks in Elastic Load Balancing target groups, Auto
//! Scaling group capacity providers whose instances join the cluster and
//! scale with managed scaling, and Express services behind a real
//! Application Load Balancer.

use std::time::Duration;

use aws_sdk_ecs::types::{
    AutoScalingGroupProvider, AwsVpcConfiguration, CapacityProviderStrategyItem, Compatibility, ContainerDefinition,
    ExpressGatewayContainer, LaunchType, LoadBalancer, ManagedScaling, ManagedScalingStatus, NetworkConfiguration,
    NetworkMode, PortMapping,
};
use aws_sdk_elasticloadbalancingv2::types::{ProtocolEnum, TargetTypeEnum};
use mws_e2e::Mws;

struct Clients {
    ecs: aws_sdk_ecs::Client,
    ec2: aws_sdk_ec2::Client,
    elb: aws_sdk_elasticloadbalancingv2::Client,
    asg: aws_sdk_autoscaling::Client,
    iam: aws_sdk_iam::Client,
}

async fn clients(mws: &Mws) -> Clients {
    let cfg = mws.root_sdk_config().await;
    Clients {
        ecs: aws_sdk_ecs::Client::new(&cfg),
        ec2: aws_sdk_ec2::Client::new(&cfg),
        elb: aws_sdk_elasticloadbalancingv2::Client::new(&cfg),
        asg: aws_sdk_autoscaling::Client::new(&cfg),
        iam: aws_sdk_iam::Client::new(&cfg),
    }
}

async fn default_vpc(ec2: &aws_sdk_ec2::Client) -> (String, String) {
    let s = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let subnet = &s.subnets()[0];
    (subnet.vpc_id().unwrap().to_string(), subnet.subnet_id().unwrap().to_string())
}

/// The target group's targets and their states.
async fn targets(elb: &aws_sdk_elasticloadbalancingv2::Client, tg: &str) -> Vec<(String, String)> {
    let h = elb.describe_target_health().target_group_arn(tg).send().await.unwrap();
    h.target_health_descriptions()
        .iter()
        .map(|d| {
            (
                d.target().and_then(|t| t.id()).unwrap_or_default().to_string(),
                d.target_health().and_then(|t| t.state()).map(|s| s.as_str().to_string()).unwrap_or_default(),
            )
        })
        .collect()
}

async fn eventually<T>(what: &str, mut f: impl AsyncFnMut() -> Option<T>) -> T {
    for _ in 0..240 {
        if let Some(v) = f().await {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("never happened: {what}");
}

#[tokio::test]
async fn service_tasks_join_target_groups() {
    let mws = Mws::start().await;
    let c = clients(&mws).await;
    let (vpc, subnet) = default_vpc(&c.ec2).await;
    let tg = c
        .elb
        .create_target_group()
        .name("web")
        .protocol(ProtocolEnum::Http)
        .port(80)
        .vpc_id(&vpc)
        .target_type(TargetTypeEnum::Ip)
        .send()
        .await
        .unwrap();
    let tg_arn = tg.target_groups()[0].target_group_arn().unwrap().to_string();
    // ECS only takes target groups that a load balancer forwards to.
    let zones = c
        .ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let lb_subnets: Vec<String> =
        zones.subnets().iter().take(2).filter_map(|s| s.subnet_id().map(String::from)).collect();
    let lb = c.elb.create_load_balancer().name("web").set_subnets(Some(lb_subnets)).send().await.unwrap();
    c.elb
        .create_listener()
        .load_balancer_arn(lb.load_balancers()[0].load_balancer_arn().unwrap())
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(
            aws_sdk_elasticloadbalancingv2::types::Action::builder()
                .r#type(aws_sdk_elasticloadbalancingv2::types::ActionTypeEnum::Forward)
                .target_group_arn(&tg_arn)
                .build(),
        )
        .send()
        .await
        .unwrap();

    c.ecs.create_cluster().send().await.unwrap();
    c.ecs
        .register_task_definition()
        .family("web")
        .network_mode(NetworkMode::Awsvpc)
        .requires_compatibilities(Compatibility::Fargate)
        .cpu("256")
        .memory("512")
        .container_definitions(
            ContainerDefinition::builder()
                .name("web")
                .image("nginx")
                .port_mappings(PortMapping::builder().container_port(80).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    c.ecs
        .create_service()
        .service_name("web")
        .task_definition("web")
        .desired_count(2)
        .launch_type(LaunchType::Fargate)
        .network_configuration(
            NetworkConfiguration::builder()
                .awsvpc_configuration(AwsVpcConfiguration::builder().subnets(&subnet).build().unwrap())
                .build(),
        )
        .load_balancers(
            LoadBalancer::builder().target_group_arn(&tg_arn).container_name("web").container_port(80).build(),
        )
        .send()
        .await
        .unwrap();

    // Each running task is registered by its private IP.
    let registered = eventually("both tasks registered", async || {
        let t = targets(&c.elb, &tg_arn).await;
        (t.len() == 2).then_some(t)
    })
    .await;
    let tasks = c.ecs.list_tasks().service_name("web").send().await.unwrap();
    let d = c.ecs.describe_tasks().set_tasks(Some(tasks.task_arns().to_vec())).send().await.unwrap();
    let mut ips: Vec<String> = d
        .tasks()
        .iter()
        .map(|t| t.containers()[0].network_interfaces()[0].private_ipv4_address().unwrap().to_string())
        .collect();
    let mut ids: Vec<String> = registered.iter().map(|(id, _)| id.clone()).collect();
    ips.sort();
    ids.sort();
    assert_eq!(ids, ips);

    // Scaling in deregisters the stopped tasks (they drain).
    c.ecs.update_service().service("web").desired_count(0).send().await.unwrap();
    eventually("targets deregistered", async || {
        let t = targets(&c.elb, &tg_arn).await;
        t.iter().all(|(_, state)| state == "draining").then_some(())
    })
    .await;
    mws.stop().await;
}

#[tokio::test]
async fn capacity_provider_instances_join_the_cluster_and_scale() {
    let mws = Mws::start().await;
    let c = clients(&mws).await;
    let images = c
        .ec2
        .describe_images()
        .owners("amazon")
        .filters(aws_sdk_ec2::types::Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let lt = c
        .ec2
        .create_launch_template()
        .launch_template_name("ecs-hosts")
        .launch_template_data(
            aws_sdk_ec2::types::RequestLaunchTemplateData::builder()
                .image_id(&ami)
                .instance_type(aws_sdk_ec2::types::InstanceType::T3Micro)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let lt_id = lt.launch_template().unwrap().launch_template_id().unwrap().to_string();
    c.asg
        .create_auto_scaling_group()
        .auto_scaling_group_name("ecs-hosts")
        .min_size(0)
        .max_size(4)
        .desired_capacity(1)
        .launch_template(
            aws_sdk_autoscaling::types::LaunchTemplateSpecification::builder()
                .launch_template_id(&lt_id)
                .version("$Latest")
                .build(),
        )
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap();
    let group = c.asg.describe_auto_scaling_groups().auto_scaling_group_names("ecs-hosts").send().await.unwrap();
    let asg_arn = group.auto_scaling_groups()[0].auto_scaling_group_arn().unwrap().to_string();

    c.ecs
        .create_capacity_provider()
        .name("hosts")
        .auto_scaling_group_provider(
            AutoScalingGroupProvider::builder()
                .auto_scaling_group_arn(&asg_arn)
                .managed_scaling(
                    ManagedScaling::builder().status(ManagedScalingStatus::Enabled).target_capacity(100).build(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    c.ecs
        .create_cluster()
        .cluster_name("ec2")
        .capacity_providers("hosts")
        .default_capacity_provider_strategy(
            CapacityProviderStrategyItem::builder().capacity_provider("hosts").weight(1).build().unwrap(),
        )
        .send()
        .await
        .unwrap();

    // The group's instance registers itself, sized by its instance type
    // (t3.micro: 2 vCPUs, 1 GiB).
    let ci = eventually("the instance joins the cluster", async || {
        let l = c.ecs.list_container_instances().cluster("ec2").send().await.unwrap();
        let arn = l.container_instance_arns().first()?.clone();
        let d = c.ecs.describe_container_instances().cluster("ec2").container_instances(arn).send().await.unwrap();
        d.container_instances().first().cloned()
    })
    .await;
    assert_eq!(ci.capacity_provider_name(), Some("hosts"));
    let cpu = ci.registered_resources().iter().find(|r| r.name() == Some("CPU")).unwrap().integer_value();
    assert_eq!(cpu, 2048);

    // Three tasks that each need most of an instance's memory: managed
    // scaling grows the group until they all run.
    c.ecs
        .register_task_definition()
        .family("big")
        .requires_compatibilities(Compatibility::Ec2)
        .container_definitions(ContainerDefinition::builder().name("app").image("busybox").cpu(512).memory(600).build())
        .send()
        .await
        .unwrap();
    c.ecs
        .create_service()
        .cluster("ec2")
        .service_name("big")
        .task_definition("big")
        .desired_count(3)
        .send()
        .await
        .unwrap();
    eventually("three tasks run on three instances", async || {
        let d = c.ecs.describe_services().cluster("ec2").services("big").send().await.unwrap();
        (d.services()[0].running_count() == 3).then_some(())
    })
    .await;
    let g = c.asg.describe_auto_scaling_groups().auto_scaling_group_names("ecs-hosts").send().await.unwrap();
    assert_eq!(g.auto_scaling_groups()[0].desired_capacity(), Some(3));
    let l = c.ecs.list_container_instances().cluster("ec2").send().await.unwrap();
    assert_eq!(l.container_instance_arns().len(), 3);
    mws.stop().await;
}

#[tokio::test]
async fn express_services_get_a_load_balancer() {
    let mws = Mws::start().await;
    let c = clients(&mws).await;
    let trust = |service: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
        )
    };
    let infra = c
        .iam
        .create_role()
        .role_name("infra")
        .assume_role_policy_document(trust("ecs.amazonaws.com"))
        .send()
        .await
        .unwrap();
    let exec = c
        .iam
        .create_role()
        .role_name("exec")
        .assume_role_policy_document(trust("ecs-tasks.amazonaws.com"))
        .send()
        .await
        .unwrap();

    let created = c
        .ecs
        .create_express_gateway_service()
        .service_name("shop")
        .infrastructure_role_arn(infra.role().unwrap().arn())
        .execution_role_arn(exec.role().unwrap().arn())
        .primary_container(ExpressGatewayContainer::builder().image("nginx").container_port(8080).build().unwrap())
        .health_check_path("/health")
        .send()
        .await
        .unwrap();
    let arn = created.service().unwrap().service_arn().unwrap().to_string();

    let lbs = c.elb.describe_load_balancers().names("ecs-express-shop").send().await.unwrap();
    let lb = &lbs.load_balancers()[0];
    assert_eq!(lb.r#type().map(|t| t.as_str()), Some("application"));
    let tgs = c.elb.describe_target_groups().load_balancer_arn(lb.load_balancer_arn().unwrap()).send().await.unwrap();
    let tg = &tgs.target_groups()[0];
    assert_eq!(tg.port(), Some(8080));
    assert_eq!(tg.health_check_path(), Some("/health"));
    let tg_arn = tg.target_group_arn().unwrap().to_string();

    // The service's task is registered in the target group.
    eventually("the task is registered", async || (targets(&c.elb, &tg_arn).await.len() == 1).then_some(())).await;
    let svc = c.ecs.describe_services().services("shop").send().await.unwrap();
    assert_eq!(svc.services()[0].load_balancers()[0].target_group_arn(), Some(tg_arn.as_str()));

    // Service revisions report what ECS manages.
    let deps = c.ecs.list_service_deployments().service("shop").send().await.unwrap();
    let dep = deps.service_deployments()[0].service_deployment_arn().unwrap().to_string();
    let d = c.ecs.describe_service_deployments().service_deployment_arns(&dep).send().await.unwrap();
    let rev = d.service_deployments()[0].target_service_revision().unwrap().arn().unwrap().to_string();
    let revs = c.ecs.describe_service_revisions().service_revision_arns(&rev).send().await.unwrap();
    let managed = revs.service_revisions()[0].ecs_managed_resources().unwrap();
    assert_eq!(managed.ingress_paths()[0].load_balancer().unwrap().arn(), lb.load_balancer_arn());

    c.ecs.delete_express_gateway_service().service_arn(&arn).send().await.unwrap();
    let gone = c.elb.describe_load_balancers().names("ecs-express-shop").send().await.unwrap_err();
    assert_eq!(gone.into_service_error().meta().code(), Some("LoadBalancerNotFound"));
    mws.stop().await;
}
