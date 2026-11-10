//! ECS acting with the roles a task definition names, and checking what a
//! service points at, through the official Rust SDKs (metadata backend):
//! ECR images pulled as the execution role under identity and repository
//! policy, `iam:PassRole` for services, load balancer checks, task role
//! credentials served (and refreshed) by the credentials endpoint, and
//! `ExecuteCommand` needing `ssmmessages:*` on the task role.

use std::time::Duration;

use aws_sdk_ecs::error::ProvideErrorMetadata;
use aws_sdk_ecs::types::{
    AwsVpcConfiguration, Compatibility, ContainerDefinition, LaunchType, LoadBalancer, NetworkConfiguration,
    NetworkMode, PortMapping,
};
use aws_sdk_elasticloadbalancingv2::types::{Action, ActionTypeEnum, ProtocolEnum, TargetTypeEnum};
use mws_e2e::Mws;

use crate::ecr::push;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

async fn task_role(iam: &aws_sdk_iam::Client, name: &str, policy: Option<&str>) -> String {
    let r = iam.create_role().role_name(name).assume_role_policy_document(TRUST).send().await.unwrap();
    if let Some(p) = policy {
        iam.put_role_policy().role_name(name).policy_name("p").policy_document(p).send().await.unwrap();
    }
    r.role().unwrap().arn().to_string()
}

async fn subnets(ec2: &aws_sdk_ec2::Client) -> (String, Vec<String>) {
    let s = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let vpc = s.subnets()[0].vpc_id().unwrap().to_string();
    (vpc, s.subnets().iter().filter_map(|s| s.subnet_id().map(String::from)).collect())
}

fn awsvpc(subnet: &str) -> NetworkConfiguration {
    NetworkConfiguration::builder()
        .awsvpc_configuration(AwsVpcConfiguration::builder().subnets(subnet).build().unwrap())
        .build()
}

async fn register(ecs: &aws_sdk_ecs::Client, family: &str, image: &str, exec: Option<&str>, task: Option<&str>) {
    ecs.register_task_definition()
        .family(family)
        .network_mode(NetworkMode::Awsvpc)
        .requires_compatibilities(Compatibility::Fargate)
        .cpu("256")
        .memory("512")
        .set_execution_role_arn(exec.map(String::from))
        .set_task_role_arn(task.map(String::from))
        .container_definitions(
            ContainerDefinition::builder()
                .name("web")
                .image(image)
                .port_mappings(PortMapping::builder().container_port(80).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
}

/// Run a task and wait until it is RUNNING or STOPPED.
async fn run(ecs: &aws_sdk_ecs::Client, family: &str, subnet: &str) -> aws_sdk_ecs::types::Task {
    let out = ecs
        .run_task()
        .task_definition(family)
        .launch_type(LaunchType::Fargate)
        .network_configuration(awsvpc(subnet))
        .enable_execute_command(true)
        .send()
        .await
        .unwrap();
    let arn = out.tasks()[0].task_arn().unwrap().to_string();
    for _ in 0..200 {
        let d = ecs.describe_tasks().tasks(&arn).send().await.unwrap();
        let t = d.tasks()[0].clone();
        if matches!(t.last_status(), Some("RUNNING" | "STOPPED")) {
            return t;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("task {arn} never settled");
}

#[tokio::test]
async fn ecr_images_are_pulled_as_the_execution_role() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ecs = aws_sdk_ecs::Client::new(&cfg);
    let ecr = aws_sdk_ecr::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let (_, subnets) = subnets(&aws_sdk_ec2::Client::new(&cfg)).await;
    let subnet = &subnets[0];
    ecs.create_cluster().send().await.unwrap();

    let repo = ecr.create_repository().repository_name("app").send().await.unwrap();
    let uri = repo.repository().unwrap().repository_uri().unwrap().to_string();
    let digest = push(&ecr, "app", "v1", "one").await;
    let image = format!("{uri}:v1");

    // Fargate needs an execution role to pull from ECR.
    let err = ecs
        .register_task_definition()
        .family("noexec")
        .network_mode(NetworkMode::Awsvpc)
        .requires_compatibilities(Compatibility::Fargate)
        .cpu("256")
        .memory("512")
        .container_definitions(ContainerDefinition::builder().name("web").image(&image).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ClientException"));
    assert_eq!(
        err.message(),
        Some("Fargate requires task definition to have execution role ARN to support ECR images.")
    );

    // A role that may not log in to the registry.
    let exec = task_role(&iam, "exec", None).await;
    register(&ecs, "app", &image, Some(&exec), None).await;
    let t = run(&ecs, "app", subnet).await;
    assert_eq!(t.last_status(), Some("STOPPED"));
    let reason = t.stopped_reason().unwrap_or_default();
    assert!(
        reason.starts_with("ResourceInitializationError: unable to pull secrets or registry auth: execution resource retrieval failed: unable to retrieve ecr registry auth"),
        "{reason}"
    );
    assert!(reason.contains("ecr:GetAuthorizationToken"), "{reason}");

    // Logging in is not pulling.
    iam.put_role_policy()
        .role_name("exec")
        .policy_name("p")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let t = run(&ecs, "app", subnet).await;
    let reason = t.stopped_reason().unwrap_or_default().to_string();
    assert!(reason.starts_with("CannotPullContainerError: "), "{reason}");
    assert!(
        reason.contains(&format!("failed to resolve ref {image}")) && reason.ends_with("403 Forbidden"),
        "{reason}"
    );

    // With pull permissions the image comes from MWS's registry.
    iam.put_role_policy()
        .role_name("exec")
        .policy_name("p")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr:GetAuthorizationToken","ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    let t = run(&ecs, "app", subnet).await;
    assert_eq!(t.last_status(), Some("RUNNING"), "{:?}", t.stopped_reason());
    assert_eq!(t.containers()[0].image_digest(), Some(digest.as_str()));

    // A repository policy can deny the role.
    let deny = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"{exec}"}},"Action":"ecr:BatchGetImage"}}]}}"#
    );
    ecr.set_repository_policy().repository_name("app").policy_text(deny).send().await.unwrap();
    let t = run(&ecs, "app", subnet).await;
    assert!(t.stopped_reason().unwrap_or_default().ends_with("403 Forbidden"), "{:?}", t.stopped_reason());
    ecr.delete_repository_policy().repository_name("app").send().await.unwrap();

    // Images that are not in the repository stop the task.
    register(&ecs, "gone", &format!("{uri}:nope"), Some(&exec), None).await;
    let t = run(&ecs, "gone", subnet).await;
    assert_eq!(
        t.stopped_reason(),
        Some(
            format!(
                "CannotPullContainerError: pull image manifest has been retried 1 time(s): failed to resolve ref {uri}:nope: {uri}:nope: not found"
            )
            .as_str()
        )
    );
    assert_eq!(t.stop_code(), Some(&aws_sdk_ecs::types::TaskStopCode::TaskFailedToStart));
    mws.stop().await;
}

#[tokio::test]
async fn task_role_credentials_come_from_the_credentials_endpoint() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ecs = aws_sdk_ecs::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let (_, subnets) = subnets(&aws_sdk_ec2::Client::new(&cfg)).await;
    ecs.create_cluster().send().await.unwrap();
    let app = task_role(&iam, "app", None).await;
    register(&ecs, "app", "nginx", None, Some(&app)).await;
    let t = run(&ecs, "app", &subnets[0]).await;
    let arn = t.task_arn().unwrap().to_string();
    let task_id = arn.rsplit('/').next().unwrap().to_string();

    let fetch = async || {
        let (status, _, body) = mws.raw("GET", &format!("/_aws/ecs/metadata/{task_id}/credentials"), &[], b"").await;
        assert_eq!(status, 200);
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()
    };
    let first = fetch().await;
    assert_eq!(first["RoleArn"], app.as_str());
    let creds = aws_sdk_sts::types::Credentials::builder()
        .access_key_id(first["AccessKeyId"].as_str().unwrap())
        .secret_access_key(first["SecretAccessKey"].as_str().unwrap())
        .session_token(first["Token"].as_str().unwrap())
        .expiration(aws_sdk_sts::primitives::DateTime::from_secs(0))
        .build()
        .unwrap();
    let as_task = aws_sdk_sts::Client::new(&mws_e2e::sts_config(&mws, &creds).await);
    let who = as_task.get_caller_identity().send().await.unwrap();
    assert_eq!(who.arn(), Some(format!("arn:aws:sts::123456789012:assumed-role/app/{task_id}").as_str()));

    // Close to expiry, the endpoint hands out a new session.
    assert_eq!(fetch().await["AccessKeyId"], first["AccessKeyId"]);
    let body = serde_json::json!({"advanceSeconds": 6 * 3600 - 600}).to_string();
    assert_eq!(mws.control("POST", "/_mws/clock", Some(&body)).await.0, 200);
    ecs.describe_tasks().tasks(&arn).send().await.unwrap();
    let second = fetch().await;
    assert_ne!(second["AccessKeyId"], first["AccessKeyId"]);
    assert!(second["Expiration"].as_str().unwrap() > first["Expiration"].as_str().unwrap());
    mws.stop().await;
}

#[tokio::test]
async fn execute_command_needs_session_manager_permissions_on_the_task_role() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ecs = aws_sdk_ecs::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let (_, subnets) = subnets(&aws_sdk_ec2::Client::new(&cfg)).await;
    ecs.create_cluster().send().await.unwrap();
    let bare = task_role(&iam, "bare", None).await;
    let ssm = task_role(
        &iam,
        "ssm",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssmmessages:CreateControlChannel","ssmmessages:CreateDataChannel","ssmmessages:OpenControlChannel","ssmmessages:OpenDataChannel"],"Resource":"*"}]}"#,
        ),
    )
    .await;
    register(&ecs, "bare", "nginx", None, Some(&bare)).await;
    register(&ecs, "ssm", "nginx", None, Some(&ssm)).await;
    let exec = async |family: &str| {
        let t = run(&ecs, family, &subnets[0]).await;
        ecs.execute_command().task(t.task_arn().unwrap()).command("ls").interactive(true).send().await
    };
    let err = exec("bare").await.unwrap_err();
    assert_eq!(err.code(), Some("TargetNotConnectedException"));
    assert_eq!(err.message(), Some("The execute command failed due to an internal error. Try again later."));
    let ok = exec("ssm").await.unwrap();
    assert!(ok.session().unwrap().session_id().is_some());
    mws.stop().await;
}

#[tokio::test]
async fn services_check_roles_and_load_balancers() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ecs = aws_sdk_ecs::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&cfg);
    let (vpc, subnets) = subnets(&aws_sdk_ec2::Client::new(&cfg)).await;
    ecs.create_cluster().send().await.unwrap();
    let app = task_role(&iam, "app", None).await;
    register(&ecs, "web", "nginx", None, Some(&app)).await;

    // Services pass the task role to their tasks.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecs:*","Resource":"*"}]}"#;
    let (_, dev_cfg) = mws_e2e::user_with_policy(&mws, "dev", Some(policy)).await;
    let dev = aws_sdk_ecs::Client::new(&dev_cfg);
    let create = |c: &aws_sdk_ecs::Client, name: &str| {
        c.create_service()
            .service_name(name)
            .task_definition("web")
            .desired_count(1)
            .launch_type(LaunchType::Fargate)
            .network_configuration(awsvpc(&subnets[0]))
    };
    let err = create(&dev, "svc").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    assert!(err.message().unwrap().contains("iam:PassRole"), "{:?}", err.message());

    // Target groups must be usable by the service's tasks.
    let tg = |name: &str, ty: TargetTypeEnum| {
        elb.create_target_group().name(name).protocol(ProtocolEnum::Http).port(80).vpc_id(&vpc).target_type(ty).send()
    };
    let ip = tg("ip", TargetTypeEnum::Ip).await.unwrap().target_groups()[0].target_group_arn().unwrap().to_string();
    let inst =
        tg("inst", TargetTypeEnum::Instance).await.unwrap().target_groups()[0].target_group_arn().unwrap().to_string();
    let lb = |arn: &str, name: &str, port: i32| {
        LoadBalancer::builder().target_group_arn(arn).container_name(name).container_port(port).build()
    };
    let reject = async |l: LoadBalancer| {
        let e = create(&ecs, "svc").load_balancers(l).send().await.unwrap_err();
        assert_eq!(e.code(), Some("InvalidParameterException"));
        e.message().unwrap_or_default().to_string()
    };
    assert_eq!(
        reject(lb(&ip, "web", 80)).await,
        format!("The target group with targetGroupArn {ip} does not have an associated load balancer.")
    );
    let alb = elb.create_load_balancer().name("front").set_subnets(Some(subnets[..2].to_vec())).send().await.unwrap();
    let alb_arn = alb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    for (port, group) in [(80, &ip), (81, &inst)] {
        elb.create_listener()
            .load_balancer_arn(&alb_arn)
            .protocol(ProtocolEnum::Http)
            .port(port)
            .default_actions(Action::builder().r#type(ActionTypeEnum::Forward).target_group_arn(group).build())
            .send()
            .await
            .unwrap();
    }
    assert_eq!(
        reject(lb(&inst, "web", 80)).await,
        format!("The provided target group {inst} has target type instance, which is incompatible with the awsvpc network mode specified in the task definition.")
    );
    assert_eq!(reject(lb(&ip, "api", 80)).await, "The container api does not exist in the task definition.");
    assert_eq!(reject(lb(&ip, "web", 8080)).await, "The container web did not have a container port 8080 defined.");
    let missing = ip.replace("/ip/", "/missing/");
    assert!(reject(lb(&missing, "web", 80)).await.contains("validate the specified targetGroupArn"));

    // The caller passes the role: the service starts and its task registers.
    create(&ecs, "svc").load_balancers(lb(&ip, "web", 80)).send().await.unwrap();
    let err = ecs.update_service().service("svc").load_balancers(lb(&ip, "web", 8080)).send().await.unwrap_err();
    assert_eq!(err.message(), Some("The container web did not have a container port 8080 defined."));
    for _ in 0..200 {
        let h = elb.describe_target_health().target_group_arn(&ip).send().await.unwrap();
        if !h.target_health_descriptions().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let h = elb.describe_target_health().target_group_arn(&ip).send().await.unwrap();
    assert_eq!(h.target_health_descriptions().len(), 1);
    mws.stop().await;
}
