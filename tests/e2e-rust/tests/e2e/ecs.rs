//! Amazon ECS through the official Rust SDK, with the metadata backend (no
//! containers run): clusters, task definitions, the task lifecycle with
//! real EC2 network interfaces, services kept at their desired count with
//! rolling deployments, container instances and placement, task sets,
//! attributes, settings, tags, daemons, gateways, Express services and IAM.

use std::time::Duration;

use aws_sdk_ecs::types::{
    Attribute, AwsVpcConfiguration, CapacityProviderStrategyItem, Compatibility, ContainerDefinition,
    DaemonContainerDefinition, DeploymentController, DeploymentControllerType, DesiredStatus, ExpressGatewayContainer,
    GatewayConfiguration, HostSharedAlbConfiguration, KeyValuePair, LaunchType, NetworkConfiguration, NetworkMode,
    PortMapping, Resource, Scale, ScaleUnit, SettingName, Tag, TargetType,
};
use aws_sdk_ecs::Client;
use mws_e2e::Mws;

async fn clients(mws: &Mws) -> (Client, aws_sdk_ec2::Client, aws_sdk_iam::Client) {
    let cfg = mws.root_sdk_config().await;
    (Client::new(&cfg), aws_sdk_ec2::Client::new(&cfg), aws_sdk_iam::Client::new(&cfg))
}

async fn default_subnet(ec2: &aws_sdk_ec2::Client) -> String {
    let s = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    s.subnets()[0].subnet_id().unwrap().to_string()
}

fn awsvpc(subnet: &str) -> NetworkConfiguration {
    NetworkConfiguration::builder()
        .awsvpc_configuration(AwsVpcConfiguration::builder().subnets(subnet).build().unwrap())
        .build()
}

async fn role(iam: &aws_sdk_iam::Client, name: &str, service: &str) -> String {
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    let r = iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    r.role().unwrap().arn().to_string()
}

async fn web_task_definition(ecs: &Client, family: &str, image: &str) -> String {
    let out = ecs
        .register_task_definition()
        .family(family)
        .network_mode(NetworkMode::Awsvpc)
        .requires_compatibilities(Compatibility::Fargate)
        .cpu("256")
        .memory("512")
        .container_definitions(
            ContainerDefinition::builder()
                .name("web")
                .image(image)
                .port_mappings(PortMapping::builder().container_port(80).build())
                .environment(KeyValuePair::builder().name("MODE").value("test").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    out.task_definition().unwrap().task_definition_arn().unwrap().to_string()
}

async fn wait_task(ecs: &Client, cluster: &str, arn: &str, want: &str) -> aws_sdk_ecs::types::Task {
    for _ in 0..200 {
        let d = ecs.describe_tasks().cluster(cluster).tasks(arn).send().await.unwrap();
        if let Some(t) = d.tasks().first() {
            if t.last_status() == Some(want) {
                return t.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("task {arn} never reached {want}");
}

async fn wait_service(
    ecs: &Client,
    cluster: &str,
    name: &str,
    check: impl Fn(&aws_sdk_ecs::types::Service) -> bool,
) -> aws_sdk_ecs::types::Service {
    for _ in 0..300 {
        let d = ecs.describe_services().cluster(cluster).services(name).send().await.unwrap();
        if let Some(s) = d.services().first() {
            if check(s) {
                return s.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let d = ecs.describe_services().cluster(cluster).services(name).send().await.unwrap();
    panic!("service {name} never settled: {:#?}", d.services().first());
}

#[tokio::test]
async fn clusters_and_task_definitions() {
    let mws = Mws::start().await;
    let (ecs, _, _) = clients(&mws).await;

    let c = ecs
        .create_cluster()
        .cluster_name("prod")
        .tags(Tag::builder().key("team").value("core").build())
        .send()
        .await
        .unwrap();
    let cluster = c.cluster().unwrap();
    assert_eq!(cluster.status(), Some("ACTIVE"));
    let cluster_arn = cluster.cluster_arn().unwrap().to_string();
    assert!(cluster_arn.ends_with(":cluster/prod"), "{cluster_arn}");

    let listed = ecs.list_clusters().send().await.unwrap();
    assert!(listed.cluster_arns().contains(&cluster_arn));

    let d = ecs
        .describe_clusters()
        .clusters("prod")
        .clusters("nope")
        .include(aws_sdk_ecs::types::ClusterField::Tags)
        .send()
        .await
        .unwrap();
    assert_eq!(d.clusters().len(), 1);
    assert_eq!(d.clusters()[0].tags().len(), 1);
    assert_eq!(d.failures()[0].reason(), Some("MISSING"));

    ecs.update_cluster_settings()
        .cluster("prod")
        .settings(
            aws_sdk_ecs::types::ClusterSetting::builder()
                .name(aws_sdk_ecs::types::ClusterSettingName::ContainerInsights)
                .value("enabled")
                .build(),
        )
        .send()
        .await
        .unwrap();
    ecs.update_cluster()
        .cluster("prod")
        .service_connect_defaults(
            aws_sdk_ecs::types::ClusterServiceConnectDefaultsRequest::builder()
                .namespace("prod.local")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let pcp = ecs
        .put_cluster_capacity_providers()
        .cluster("prod")
        .capacity_providers("FARGATE")
        .capacity_providers("FARGATE_SPOT")
        .default_capacity_provider_strategy(
            CapacityProviderStrategyItem::builder().capacity_provider("FARGATE").weight(1).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(pcp.cluster().unwrap().capacity_providers().len(), 2);

    // Task definitions: revisions, families, deregistration and deletion.
    let first = web_task_definition(&ecs, "web", "nginx:1").await;
    let second = web_task_definition(&ecs, "web", "nginx:2").await;
    assert!(first.ends_with(":task-definition/web:1"), "{first}");
    assert!(second.ends_with(":task-definition/web:2"), "{second}");
    let latest = ecs.describe_task_definition().task_definition("web").send().await.unwrap();
    let td = latest.task_definition().unwrap();
    assert_eq!(td.revision(), 2);
    assert_eq!(td.container_definitions()[0].essential(), Some(true));
    assert_eq!(td.container_definitions()[0].port_mappings()[0].host_port(), Some(80));
    assert!(td.compatibilities().contains(&Compatibility::Fargate));

    let bad = ecs
        .register_task_definition()
        .family("bad")
        .requires_compatibilities(Compatibility::Fargate)
        .network_mode(NetworkMode::Awsvpc)
        .cpu("256")
        .memory("4096")
        .container_definitions(ContainerDefinition::builder().name("a").image("busybox").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(bad.into_service_error().meta().code(), Some("ClientException"));

    let fams = ecs.list_task_definition_families().send().await.unwrap();
    assert_eq!(fams.families(), ["web"]);
    let defs = ecs.list_task_definitions().family_prefix("web").send().await.unwrap();
    assert_eq!(defs.task_definition_arns().len(), 2);

    ecs.deregister_task_definition().task_definition("web:1").send().await.unwrap();
    let active = ecs.list_task_definitions().family_prefix("web").send().await.unwrap();
    assert_eq!(active.task_definition_arns(), std::slice::from_ref(&second));
    let del = ecs.delete_task_definitions().task_definitions("web:1").task_definitions("web:2").send().await.unwrap();
    assert_eq!(del.task_definitions().len(), 1);
    assert_eq!(del.task_definitions()[0].status(), Some(&aws_sdk_ecs::types::TaskDefinitionStatus::DeleteInProgress));
    assert_eq!(del.failures().len(), 1, "an ACTIVE revision cannot be deleted");

    let gone = ecs.delete_cluster().cluster("prod").send().await.unwrap();
    assert_eq!(gone.cluster().unwrap().status(), Some("INACTIVE"));
    let err = ecs.describe_clusters().clusters("prod").send().await.unwrap();
    assert_eq!(err.clusters()[0].status(), Some("INACTIVE"));
    let missing = ecs.list_services().cluster("prod").send().await.unwrap_err();
    assert_eq!(missing.into_service_error().meta().code(), Some("ClusterNotFoundException"));
    mws.stop().await;
}

#[tokio::test]
async fn fargate_tasks_get_network_interfaces() {
    let mws = Mws::start().await;
    let (ecs, ec2, _) = clients(&mws).await;
    let subnet = default_subnet(&ec2).await;
    ecs.create_cluster().send().await.unwrap();
    let td = web_task_definition(&ecs, "api", "nginx").await;

    let missing = ecs.run_task().task_definition(&td).launch_type(LaunchType::Fargate).send().await.unwrap_err();
    assert_eq!(missing.into_service_error().meta().code(), Some("InvalidParameterException"));

    let run = ecs
        .run_task()
        .task_definition(&td)
        .launch_type(LaunchType::Fargate)
        .network_configuration(awsvpc(&subnet))
        .count(2)
        .started_by("e2e")
        .tags(Tag::builder().key("k").value("v").build())
        .send()
        .await
        .unwrap();
    assert_eq!(run.tasks().len(), 2);
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    assert!(arn.contains(":task/default/"), "{arn}");
    assert_eq!(run.tasks()[0].last_status(), Some("PROVISIONING"));

    let t = wait_task(&ecs, "default", &arn, "RUNNING").await;
    assert_eq!(t.desired_status(), Some("RUNNING"));
    assert_eq!(t.containers()[0].last_status(), Some("RUNNING"));
    let att = &t.attachments()[0];
    assert_eq!(att.r#type(), Some("ElasticNetworkInterface"));
    assert_eq!(att.status(), Some("ATTACHED"));
    let detail = |k: &str| {
        att.details().iter().find(|d| d.name() == Some(k)).and_then(|d| d.value()).unwrap_or_default().to_string()
    };
    let eni = detail("networkInterfaceId");
    assert_eq!(detail("subnetId"), subnet);
    let enis = ec2.describe_network_interfaces().network_interface_ids(&eni).send().await.unwrap();
    let ni = &enis.network_interfaces()[0];
    assert_eq!(ni.requester_managed(), Some(true));
    assert_eq!(ni.private_ip_address(), Some(detail("privateIPv4Address").as_str()));
    assert_eq!(t.containers()[0].network_interfaces()[0].private_ipv4_address(), ni.private_ip_address());

    // The task metadata endpoint (v4) containers find in
    // ECS_CONTAINER_METADATA_URI_V4.
    let task_id = arn.rsplit('/').next().unwrap();
    let (status, _, body) = mws.raw("GET", &format!("/_aws/ecs/metadata/{task_id}/web/task"), &[], b"").await;
    assert_eq!(status, 200);
    let meta: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(meta["TaskARN"], arn.as_str());
    assert_eq!(meta["Containers"][0]["Name"], "web");
    assert_eq!(meta["Containers"][0]["Networks"][0]["IPv4Addresses"][0], ni.private_ip_address().unwrap());
    let (status, _, _) = mws.raw("GET", "/_aws/ecs/metadata/nope/web", &[], b"").await;
    assert_eq!(status, 404);

    let listed = ecs.list_tasks().started_by("e2e").send().await.unwrap();
    assert_eq!(listed.task_arns().len(), 2);
    let tags = ecs.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), Some("k"));

    ecs.stop_task().task(&arn).reason("done here").send().await.unwrap();
    let stopped = wait_task(&ecs, "default", &arn, "STOPPED").await;
    assert_eq!(stopped.stopped_reason(), Some("done here"));
    assert_eq!(stopped.stop_code(), Some(&aws_sdk_ecs::types::TaskStopCode::UserInitiated));
    let after = eni_gone(&ec2, &eni).await;
    assert!(after, "the task's interface is deleted when it stops");
    let stopped_list = ecs.list_tasks().desired_status(DesiredStatus::Stopped).send().await.unwrap();
    assert_eq!(stopped_list.task_arns(), std::slice::from_ref(&arn));

    // The task-state APIs the agent calls.
    ecs.submit_task_state_change().task(&arn).status("STOPPED").send().await.unwrap();
    ecs.submit_container_state_change().task(&arn).container_name("web").status("STOPPED").send().await.unwrap();
    ecs.submit_attachment_state_changes()
        .attachments(
            aws_sdk_ecs::types::AttachmentStateChange::builder()
                .attachment_arn("arn:aws:ecs:us-east-1:000000000000:attachment/x")
                .status("DETACHED")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    mws.stop().await;
}

async fn eni_gone(ec2: &aws_sdk_ec2::Client, eni: &str) -> bool {
    for _ in 0..50 {
        if ec2.describe_network_interfaces().network_interface_ids(eni).send().await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn services_roll_out_new_revisions() {
    let mws = Mws::start().await;
    let (ecs, ec2, _) = clients(&mws).await;
    let subnet = default_subnet(&ec2).await;
    ecs.create_cluster().cluster_name("apps").send().await.unwrap();
    let v1 = web_task_definition(&ecs, "shop", "shop:1").await;
    let v2 = web_task_definition(&ecs, "shop", "shop:2").await;

    let created = ecs
        .create_service()
        .cluster("apps")
        .service_name("shop")
        .task_definition(&v1)
        .desired_count(2)
        .launch_type(LaunchType::Fargate)
        .network_configuration(awsvpc(&subnet))
        .send()
        .await
        .unwrap();
    let svc = created.service().unwrap();
    assert_eq!(svc.status(), Some("ACTIVE"));
    assert_eq!(svc.deployments().len(), 1);
    assert_eq!(svc.deployments()[0].status(), Some("PRIMARY"));
    let steady = wait_service(&ecs, "apps", "shop", |s| {
        s.running_count() == 2 && s.events().iter().any(|e| e.message().unwrap_or_default().contains("steady state"))
    })
    .await;
    assert_eq!(steady.deployments()[0].rollout_state(), Some(&aws_sdk_ecs::types::DeploymentRolloutState::Completed));
    let tasks = ecs.list_tasks().cluster("apps").service_name("shop").send().await.unwrap();
    assert_eq!(tasks.task_arns().len(), 2);
    let listed = ecs.list_services().cluster("apps").send().await.unwrap();
    assert_eq!(listed.service_arns().len(), 1);

    // A new task definition rolls out; the old tasks go away.
    ecs.update_service().cluster("apps").service("shop").task_definition(&v2).desired_count(3).send().await.unwrap();
    let rolled = wait_service(&ecs, "apps", "shop", |s| {
        s.deployments().len() == 1 && s.running_count() == 3 && s.task_definition() == Some(v2.as_str())
    })
    .await;
    assert_eq!(rolled.deployments()[0].task_definition(), Some(v2.as_str()));
    let running = ecs.list_tasks().cluster("apps").service_name("shop").send().await.unwrap();
    let d = ecs.describe_tasks().cluster("apps").set_tasks(Some(running.task_arns().to_vec())).send().await.unwrap();
    assert!(d.tasks().iter().all(|t| t.task_definition_arn() == Some(v2.as_str())));

    // Service deployments and revisions record both rollouts.
    let deps = ecs.list_service_deployments().cluster("apps").service("shop").send().await.unwrap();
    assert_eq!(deps.service_deployments().len(), 2);
    let arns: Vec<String> =
        deps.service_deployments().iter().filter_map(|d| d.service_deployment_arn().map(String::from)).collect();
    let described = ecs.describe_service_deployments().set_service_deployment_arns(Some(arns)).send().await.unwrap();
    let latest = described
        .service_deployments()
        .iter()
        .find(|d| d.status() == Some(&aws_sdk_ecs::types::ServiceDeploymentStatus::Successful))
        .expect("a successful deployment");
    let rev = latest.target_service_revision().unwrap().arn().unwrap().to_string();
    let revs = ecs.describe_service_revisions().service_revision_arns(&rev).send().await.unwrap();
    assert_eq!(revs.service_revisions()[0].task_definition(), Some(v2.as_str()));
    let not_running = ecs
        .continue_service_deployment()
        .service_deployment_arn(latest.service_deployment_arn().unwrap())
        .send()
        .await
        .unwrap_err();
    assert!(not_running.into_service_error().meta().code().is_some());
    let stop_done = ecs
        .stop_service_deployment()
        .service_deployment_arn(latest.service_deployment_arn().unwrap())
        .send()
        .await
        .unwrap_err();
    assert!(stop_done.into_service_error().meta().code().is_some());

    let ns = ecs.list_services_by_namespace().namespace("nothing.local").send().await.unwrap();
    assert!(ns.service_arns().is_empty());

    // Deleting needs force (or zero desired) and drains the tasks.
    let refused = ecs.delete_service().cluster("apps").service("shop").send().await.unwrap_err();
    assert_eq!(refused.into_service_error().meta().code(), Some("InvalidParameterException"));
    let del = ecs.delete_service().cluster("apps").service("shop").force(true).send().await.unwrap();
    assert_eq!(del.service().unwrap().status(), Some("DRAINING"));
    for _ in 0..100 {
        let t = ecs.list_tasks().cluster("apps").send().await.unwrap();
        if t.task_arns().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ecs.list_tasks().cluster("apps").send().await.unwrap().task_arns().is_empty());
    mws.stop().await;
}

#[tokio::test]
async fn container_instances_place_tasks() {
    let mws = Mws::start().await;
    let (ecs, _, _) = clients(&mws).await;
    ecs.create_cluster().cluster_name("ec2").send().await.unwrap();
    ecs.register_task_definition()
        .family("worker")
        .requires_compatibilities(Compatibility::Ec2)
        .container_definitions(
            ContainerDefinition::builder()
                .name("w")
                .image("busybox")
                .cpu(1024)
                .memory(1024)
                .port_mappings(PortMapping::builder().container_port(8080).host_port(8080).build())
                .build(),
        )
        .send()
        .await
        .unwrap();

    let none = ecs.run_task().cluster("ec2").task_definition("worker").send().await.unwrap_err();
    assert_eq!(none.into_service_error().meta().message(), Some("No Container Instances were found in your cluster."));

    let reg = ecs
        .register_container_instance()
        .cluster("ec2")
        .attributes(Attribute::builder().name("stack").value("blue").build().unwrap())
        .send()
        .await
        .unwrap();
    let ci = reg.container_instance().unwrap();
    let ci_arn = ci.container_instance_arn().unwrap().to_string();
    assert_eq!(ci.status(), Some("ACTIVE"));
    assert!(ci.registered_resources().iter().any(|r: &Resource| r.name() == Some("CPU")));
    let poll = ecs.discover_poll_endpoint().cluster("ec2").container_instance(&ci_arn).send().await.unwrap();
    assert!(poll.endpoint().is_some());

    let run = ecs.run_task().cluster("ec2").task_definition("worker").send().await.unwrap();
    assert_eq!(run.tasks().len(), 1);
    assert_eq!(run.tasks()[0].container_instance_arn(), Some(ci_arn.as_str()));
    // The host port is taken now.
    let second = ecs.run_task().cluster("ec2").task_definition("worker").send().await.unwrap();
    assert_eq!(second.failures()[0].reason(), Some("RESOURCE:PORTS"));
    let d = ecs.describe_container_instances().cluster("ec2").container_instances(&ci_arn).send().await.unwrap();
    assert_eq!(d.container_instances()[0].running_tasks_count() + d.container_instances()[0].pending_tasks_count(), 1);

    let started =
        ecs.start_task().cluster("ec2").task_definition("worker").container_instances(&ci_arn).send().await.unwrap();
    assert_eq!(started.failures()[0].reason(), Some("RESOURCE:PORTS"));

    // Attributes and constraints.
    ecs.put_attributes()
        .cluster("ec2")
        .attributes(
            Attribute::builder()
                .name("zone")
                .value("a")
                .target_type(TargetType::ContainerInstance)
                .target_id(&ci_arn)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let attrs = ecs
        .list_attributes()
        .cluster("ec2")
        .target_type(TargetType::ContainerInstance)
        .attribute_name("zone")
        .send()
        .await
        .unwrap();
    assert_eq!(attrs.attributes()[0].value(), Some("a"));
    let filtered =
        ecs.list_container_instances().cluster("ec2").filter("attribute:stack == blue").send().await.unwrap();
    assert_eq!(filtered.container_instance_arns(), std::slice::from_ref(&ci_arn));
    ecs.delete_attributes()
        .cluster("ec2")
        .attributes(Attribute::builder().name("zone").target_id(&ci_arn).build().unwrap())
        .send()
        .await
        .unwrap();

    let agent = ecs.update_container_agent().cluster("ec2").container_instance(&ci_arn).send().await.unwrap_err();
    assert_eq!(agent.into_service_error().meta().code(), Some("NoUpdateAvailableException"));
    let drain = ecs
        .update_container_instances_state()
        .cluster("ec2")
        .container_instances(&ci_arn)
        .status(aws_sdk_ecs::types::ContainerInstanceStatus::Draining)
        .send()
        .await
        .unwrap();
    assert_eq!(drain.container_instances()[0].status(), Some("DRAINING"));

    let busy = ecs.deregister_container_instance().cluster("ec2").container_instance(&ci_arn).send().await.unwrap_err();
    assert_eq!(busy.into_service_error().meta().code(), Some("InvalidParameterException"));
    let gone = ecs
        .deregister_container_instance()
        .cluster("ec2")
        .container_instance(&ci_arn)
        .force(true)
        .send()
        .await
        .unwrap();
    assert_eq!(gone.container_instance().unwrap().status(), Some("INACTIVE"));
    mws.stop().await;
}

#[tokio::test]
async fn task_sets_protection_and_exec() {
    let mws = Mws::start().await;
    let (ecs, ec2, _) = clients(&mws).await;
    let subnet = default_subnet(&ec2).await;
    ecs.create_cluster().send().await.unwrap();
    let td = web_task_definition(&ecs, "blue", "app:1").await;

    // EXTERNAL deployments: the caller manages task sets.
    ecs.create_service()
        .service_name("ext")
        .desired_count(2)
        .deployment_controller(
            DeploymentController::builder().r#type(DeploymentControllerType::External).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let ts = ecs
        .create_task_set()
        .cluster("default")
        .service("ext")
        .task_definition(&td)
        .launch_type(LaunchType::Fargate)
        .network_configuration(awsvpc(&subnet))
        .scale(Scale::builder().value(100.0).unit(ScaleUnit::Percent).build())
        .send()
        .await
        .unwrap();
    let ts_arn = ts.task_set().unwrap().task_set_arn().unwrap().to_string();
    ecs.update_service_primary_task_set()
        .cluster("default")
        .service("ext")
        .primary_task_set(&ts_arn)
        .send()
        .await
        .unwrap();
    ecs.update_task_set()
        .cluster("default")
        .service("ext")
        .task_set(&ts_arn)
        .scale(Scale::builder().value(50.0).unit(ScaleUnit::Percent).build())
        .send()
        .await
        .unwrap();
    let mut running = 0;
    for _ in 0..100 {
        let d = ecs.describe_task_sets().cluster("default").service("ext").task_sets(&ts_arn).send().await.unwrap();
        running = d.task_sets()[0].running_count();
        if running == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(running, 1, "50% of 2 desired");

    // Task protection is for service tasks.
    let tasks = ecs.list_tasks().service_name("ext").send().await.unwrap();
    let task = tasks.task_arns()[0].clone();
    let p = ecs
        .update_task_protection()
        .cluster("default")
        .tasks(&task)
        .protection_enabled(true)
        .expires_in_minutes(60)
        .send()
        .await
        .unwrap();
    assert!(p.protected_tasks()[0].protection_enabled());
    let got = ecs.get_task_protection().cluster("default").tasks(&task).send().await.unwrap();
    assert!(got.protected_tasks()[0].protection_enabled());

    // ExecuteCommand needs the task to have it enabled.
    let no_exec =
        ecs.execute_command().cluster("default").task(&task).command("ls").interactive(true).send().await.unwrap_err();
    assert_eq!(no_exec.into_service_error().meta().code(), Some("InvalidParameterException"));

    ecs.delete_task_set().cluster("default").service("ext").task_set(&ts_arn).force(true).send().await.unwrap();
    let after = ecs.describe_task_sets().cluster("default").service("ext").task_sets(&ts_arn).send().await.unwrap();
    assert_eq!(after.task_sets().first().and_then(|t| t.status()), Some("DRAINING"));
    mws.stop().await;
}

#[tokio::test]
async fn settings_capacity_providers_and_tags() {
    let mws = Mws::start().await;
    let (ecs, _, _) = clients(&mws).await;

    let s = ecs.put_account_setting().name(SettingName::ContainerInsights).value("enhanced").send().await.unwrap();
    assert_eq!(s.setting().unwrap().value(), Some("enhanced"));
    ecs.put_account_setting_default().name(SettingName::TagResourceAuthorization).value("on").send().await.unwrap();
    let listed =
        ecs.list_account_settings().name(SettingName::ContainerInsights).effective_settings(true).send().await.unwrap();
    assert_eq!(listed.settings()[0].value(), Some("enhanced"));
    ecs.delete_account_setting().name(SettingName::ContainerInsights).send().await.unwrap();
    let bad = ecs.put_account_setting().name(SettingName::AwsvpcTrunking).value("maybe").send().await.unwrap_err();
    assert_eq!(bad.into_service_error().meta().code(), Some("InvalidParameterException"));

    let asg = "arn:aws:autoscaling:us-east-1:000000000000:autoScalingGroup:1a2b:autoScalingGroupName/workers";
    let cp = ecs
        .create_capacity_provider()
        .name("workers")
        .auto_scaling_group_provider(
            aws_sdk_ecs::types::AutoScalingGroupProvider::builder().auto_scaling_group_arn(asg).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let cp_arn = cp.capacity_provider().unwrap().capacity_provider_arn().unwrap().to_string();
    let d = ecs
        .describe_capacity_providers()
        .capacity_providers("workers")
        .capacity_providers("FARGATE")
        .send()
        .await
        .unwrap();
    assert_eq!(d.capacity_providers().len(), 2);
    ecs.update_capacity_provider()
        .name("workers")
        .auto_scaling_group_provider(
            aws_sdk_ecs::types::AutoScalingGroupProviderUpdate::builder()
                .managed_termination_protection(aws_sdk_ecs::types::ManagedTerminationProtection::Disabled)
                .build(),
        )
        .send()
        .await
        .unwrap();

    ecs.tag_resource().resource_arn(&cp_arn).tags(Tag::builder().key("a").value("1").build()).send().await.unwrap();
    ecs.tag_resource().resource_arn(&cp_arn).tags(Tag::builder().key("b").value("2").build()).send().await.unwrap();
    ecs.untag_resource().resource_arn(&cp_arn).tag_keys("a").send().await.unwrap();
    let tags = ecs.list_tags_for_resource().resource_arn(&cp_arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].key(), Some("b"));
    let del = ecs.delete_capacity_provider().capacity_provider("workers").send().await.unwrap();
    assert_eq!(del.capacity_provider().unwrap().status(), Some(&aws_sdk_ecs::types::CapacityProviderStatus::Inactive));
    mws.stop().await;
}

#[tokio::test]
async fn daemons_and_gateways() {
    let mws = Mws::start().await;
    let (ecs, ec2, iam) = clients(&mws).await;
    let subnet = default_subnet(&ec2).await;
    let infra = role(&iam, "ecsInfra", "ecs.amazonaws.com").await;
    let cluster = ecs.create_cluster().cluster_name("edge").send().await.unwrap();
    let cluster_arn = cluster.cluster().unwrap().cluster_arn().unwrap().to_string();

    // Daemon task definitions and daemons.
    let dtd = ecs
        .register_daemon_task_definition()
        .family("agent")
        .container_definitions(
            DaemonContainerDefinition::builder().name("agent").image("datadog/agent").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let dtd_arn = dtd.daemon_task_definition_arn().unwrap().to_string();
    let got = ecs.describe_daemon_task_definition().daemon_task_definition("agent").send().await.unwrap();
    assert_eq!(got.daemon_task_definition().unwrap().revision(), 1);
    let listed = ecs.list_daemon_task_definitions().send().await.unwrap();
    assert_eq!(listed.daemon_task_definitions().len(), 1);

    let asg = "arn:aws:autoscaling:us-east-1:000000000000:autoScalingGroup:1a2b:autoScalingGroupName/edge";
    let cp = ecs
        .create_capacity_provider()
        .name("edge-hosts")
        .auto_scaling_group_provider(
            aws_sdk_ecs::types::AutoScalingGroupProvider::builder().auto_scaling_group_arn(asg).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let cp_arn = cp.capacity_provider().unwrap().capacity_provider_arn().unwrap().to_string();
    let daemon = ecs
        .create_daemon()
        .daemon_name("agent")
        .cluster_arn(&cluster_arn)
        .daemon_task_definition_arn(&dtd_arn)
        .capacity_provider_arns(&cp_arn)
        .send()
        .await
        .unwrap();
    let daemon_arn = daemon.daemon_arn().unwrap().to_string();
    let desc = ecs.describe_daemon().daemon_arn(&daemon_arn).send().await.unwrap();
    assert_eq!(desc.daemon().unwrap().status(), Some(&aws_sdk_ecs::types::DaemonStatus::Active));
    let rev = desc.daemon().unwrap().current_revisions()[0].arn().unwrap().to_string();
    let revs = ecs.describe_daemon_revisions().daemon_revision_arns(&rev).send().await.unwrap();
    assert_eq!(revs.daemon_revisions()[0].daemon_task_definition_arn(), Some(dtd_arn.as_str()));
    assert_eq!(ecs.list_daemons().cluster_arn(&cluster_arn).send().await.unwrap().daemon_summaries_list().len(), 1);
    ecs.update_daemon()
        .daemon_arn(&daemon_arn)
        .daemon_task_definition_arn(&dtd_arn)
        .capacity_provider_arns(&cp_arn)
        .send()
        .await
        .unwrap();
    let deps = ecs.list_daemon_deployments().daemon_arn(&daemon_arn).send().await.unwrap();
    assert_eq!(deps.daemon_deployments().len(), 2);
    let dep = deps.daemon_deployments()[0].daemon_deployment_arn().unwrap().to_string();
    let dd = ecs.describe_daemon_deployments().daemon_deployment_arns(&dep).send().await.unwrap();
    assert_eq!(dd.daemon_deployments()[0].status(), Some(&aws_sdk_ecs::types::DaemonDeploymentStatus::Successful));
    let in_use = ecs.delete_daemon_task_definition().daemon_task_definition(&dtd_arn).send().await.unwrap_err();
    assert_eq!(in_use.into_service_error().meta().code(), Some("ClientException"));
    ecs.delete_daemon().daemon_arn(&daemon_arn).send().await.unwrap();
    ecs.delete_daemon_task_definition().daemon_task_definition(&dtd_arn).send().await.unwrap();

    // Gateways: a shared ALB that clusters associate with; services with
    // gateway connectors get routes.
    let gw = ecs
        .create_gateway()
        .name("public")
        .infrastructure_role_arn(&infra)
        .configuration(GatewayConfiguration::HostSharedAlb(HostSharedAlbConfiguration::builder().build()))
        .send()
        .await
        .unwrap();
    let gw_arn = gw.gateway_arn().unwrap().to_string();
    ecs.associate_gateway_with_cluster().gateway(&gw_arn).cluster("edge").send().await.unwrap();
    let assoc = ecs.list_gateway_cluster_associations().gateway(&gw_arn).send().await.unwrap();
    assert_eq!(assoc.gateway_cluster_associations()[0].cluster_arn(), Some(cluster_arn.as_str()));
    let td = web_task_definition(&ecs, "front", "front:1").await;
    ecs.create_service()
        .cluster("edge")
        .service_name("front")
        .task_definition(&td)
        .desired_count(1)
        .launch_type(LaunchType::Fargate)
        .network_configuration(awsvpc(&subnet))
        .gateway_connectors(aws_sdk_ecs::types::GatewayConnector::builder().port_name("web").build().unwrap())
        .send()
        .await
        .unwrap();
    let routes = ecs.list_gateway_routes().gateway(&gw_arn).send().await.unwrap();
    assert_eq!(routes.gateway_routes().len(), 1);
    let route_arn = routes.gateway_routes()[0].gateway_route_arn().unwrap().to_string();
    let route = ecs.describe_gateway_route().gateway_route_arn(&route_arn).send().await.unwrap();
    assert!(route.gateway_route().unwrap().service_url().unwrap().starts_with("https://front-web."));
    let res = ecs.describe_gateway_resources().gateway(&gw_arn).send().await.unwrap();
    assert_eq!(res.gateway_resources().unwrap().gateway_arn(), Some(gw_arn.as_str()));
    ecs.update_gateway().gateway(&gw_arn).deletion_protection(true).send().await.unwrap();
    let d = ecs.describe_gateway().gateway("public").send().await.unwrap();
    assert_eq!(d.gateway().unwrap().deletion_protection(), Some(true));
    assert_eq!(ecs.list_gateways().send().await.unwrap().gateways().len(), 1);
    let busy = ecs.delete_gateway().gateway(&gw_arn).send().await.unwrap_err();
    assert!(busy.into_service_error().meta().code().is_some());
    ecs.update_gateway().gateway(&gw_arn).deletion_protection(false).send().await.unwrap();
    ecs.disassociate_gateway_from_cluster().gateway(&gw_arn).cluster("edge").send().await.unwrap();
    ecs.delete_gateway().gateway(&gw_arn).send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn express_services_run_like_services() {
    let mws = Mws::start().await;
    let (ecs, _, iam) = clients(&mws).await;
    let infra = role(&iam, "ecsInfrastructureRoleForExpressServices", "ecs.amazonaws.com").await;
    let exec = role(&iam, "ecsTaskExecutionRole", "ecs-tasks.amazonaws.com").await;

    let created = ecs
        .create_express_gateway_service()
        .service_name("hello")
        .infrastructure_role_arn(&infra)
        .execution_role_arn(&exec)
        .primary_container(
            ExpressGatewayContainer::builder()
                .image("public.ecr.aws/nginx/nginx:latest")
                .container_port(80)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let svc = created.service().unwrap();
    let arn = svc.service_arn().unwrap().to_string();
    assert!(arn.ends_with(":service/default/hello"), "{arn}");
    let cfg = &svc.active_configurations()[0];
    assert_eq!(cfg.cpu(), Some("1024"));
    assert!(cfg.ingress_paths()[0].endpoint().starts_with("https://hello."));

    // It is a real service in the default cluster, running Fargate tasks.
    let running = wait_service(&ecs, "default", "hello", |s| s.running_count() == 1).await;
    assert_eq!(running.launch_type(), Some(&LaunchType::Fargate));
    let described = ecs.describe_express_gateway_service().service_arn(&arn).send().await.unwrap();
    assert_eq!(
        described.service().unwrap().status().unwrap().status_code(),
        Some(&aws_sdk_ecs::types::ExpressGatewayServiceStatusCode::Active)
    );

    let updated =
        ecs.update_express_gateway_service().service_arn(&arn).cpu("2048").memory("4096").send().await.unwrap();
    let target = updated.service().unwrap().target_configuration().unwrap();
    assert_eq!(target.cpu(), Some("2048"));
    assert!(target.task_definition_arn().unwrap().ends_with(":2"));

    let deleted = ecs.delete_express_gateway_service().service_arn(&arn).send().await.unwrap();
    assert_eq!(
        deleted.service().unwrap().status().unwrap().status_code(),
        Some(&aws_sdk_ecs::types::ExpressGatewayServiceStatusCode::Draining)
    );
    mws.stop().await;
}

#[tokio::test]
async fn iam_policies_apply() {
    let mws = Mws::start().await;
    let (ecs, _, _) = clients(&mws).await;
    ecs.create_cluster().cluster_name("locked").send().await.unwrap();
    ecs.create_cluster().cluster_name("open").send().await.unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"ecs:ListServices","Resource":"*","Condition":{"ArnLike":{"ecs:cluster":"arn:aws:ecs:*:*:cluster/open"}}},
        {"Effect":"Allow","Action":"ecs:RegisterTaskDefinition","Resource":"*"}]}"#;
    let (_, cfg) = mws_e2e::user_with_policy(&mws, "dev", Some(policy)).await;
    let dev = Client::new(&cfg);
    dev.list_services().cluster("open").send().await.unwrap();
    let denied = dev.list_services().cluster("locked").send().await.unwrap_err();
    let e = denied.into_service_error();
    assert_eq!(e.meta().code(), Some("AccessDeniedException"));
    assert!(e.meta().message().unwrap().contains("ecs:ListServices"), "{:?}", e.meta().message());

    // Running a task with a role needs iam:PassRole.
    let td = dev
        .register_task_definition()
        .family("r")
        .task_role_arn("arn:aws:iam::000000000000:role/app")
        .container_definitions(ContainerDefinition::builder().name("a").image("busybox").memory(64).build())
        .send()
        .await
        .unwrap();
    assert!(td.task_definition().is_some());
    let user_run = dev.run_task().cluster("open").task_definition("r").send().await.unwrap_err();
    assert_eq!(user_run.into_service_error().meta().code(), Some("AccessDeniedException"));
    mws.stop().await;
}

/// Each `lastStatus`/`desiredStatus` change of a task is an
/// `ECS Task State Change` event on the default bus, with the task as the
/// detail.
#[tokio::test]
async fn task_state_changes_reach_eventbridge() {
    let mws = Mws::start().await;
    let (ecs, ec2, _) = clients(&mws).await;
    let cfg = mws.root_sdk_config().await;
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let url = sqs.create_queue().queue_name("ecs-tasks").send().await.unwrap().queue_url.unwrap();
    let queue_arn = "arn:aws:sqs:us-east-1:123456789012:ecs-tasks";
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},
        "Action":"sqs:SendMessage","Resource":queue_arn}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    eb.put_rule()
        .name("task-stopped")
        .event_pattern(
            r#"{"source":["aws.ecs"],"detail-type":["ECS Task State Change"],"detail":{"lastStatus":["STOPPED"]}}"#,
        )
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("task-stopped")
        .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(queue_arn).build().unwrap())
        .send()
        .await
        .unwrap();

    let subnet = default_subnet(&ec2).await;
    ecs.create_cluster().send().await.unwrap();
    let td = web_task_definition(&ecs, "evented", "nginx").await;
    let run = ecs
        .run_task()
        .task_definition(&td)
        .launch_type(LaunchType::Fargate)
        .network_configuration(awsvpc(&subnet))
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    wait_task(&ecs, "default", &arn, "RUNNING").await;
    ecs.stop_task().task(&arn).reason("done").send().await.unwrap();
    wait_task(&ecs, "default", &arn, "STOPPED").await;

    let mut event = None;
    for _ in 0..100 {
        let r = sqs.receive_message().queue_url(&url).send().await.unwrap();
        if let Some(m) = r.messages().first() {
            event = Some(serde_json::from_str::<serde_json::Value>(m.body().unwrap()).unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let event = event.expect("an ECS Task State Change event");
    assert_eq!(event["source"], "aws.ecs");
    assert_eq!(event["detail-type"], "ECS Task State Change");
    assert_eq!(event["resources"][0], arn.as_str());
    assert_eq!(event["detail"]["taskArn"], arn.as_str());
    assert_eq!(event["detail"]["lastStatus"], "STOPPED");
    assert_eq!(event["detail"]["desiredStatus"], "STOPPED");
    assert_eq!(event["detail"]["stoppedReason"], "done");
}
