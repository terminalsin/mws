//! ECS tasks that really run: the Docker backend, through the official
//! Rust SDK. An awsvpc task gets its role credentials, a Secrets Manager
//! secret and the task metadata endpoint, and its output lands in
//! CloudWatch Logs. Skipped when no Docker daemon answers.

use std::process::Command;
use std::time::Duration;

use aws_sdk_ecs::types::{
    AwsVpcConfiguration, Compatibility, ContainerDefinition, LaunchType, LogConfiguration, LogDriver,
    NetworkConfiguration, NetworkMode, Secret,
};
use mws_e2e::Mws;

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn containers_named(prefix: &str) -> Vec<String> {
    let out = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}", "--filter", &format!("name={prefix}")])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect()
}

#[tokio::test]
async fn tasks_run_as_containers() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { ecs_backend: mws_ecs::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let cfg = mws.root_sdk_config().await;
    let ecs = aws_sdk_ecs::Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sm = aws_sdk_secretsmanager::Client::new(&cfg);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);

    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let exec = iam.create_role().role_name("exec").assume_role_policy_document(trust).send().await.unwrap();
    let exec_arn = exec.role().unwrap().arn().to_string();
    iam.put_role_policy()
        .role_name("exec")
        .policy_name("pull-and-log")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:*","secretsmanager:GetSecretValue"],"Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let app = iam.create_role().role_name("app").assume_role_policy_document(trust).send().await.unwrap();
    let app_arn = app.role().unwrap().arn().to_string();
    let secret = sm.create_secret().name("db-pass").secret_string("hunter2").send().await.unwrap();

    let subnets = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let subnet = subnets.subnets()[0].subnet_id().unwrap().to_string();

    let script = r#"echo "secret=$DB_PASS"; echo "key=$AWS_ACCESS_KEY_ID"; echo "creds=$(wget -qO- "$AWS_CONTAINER_CREDENTIALS_FULL_URI")"; echo "meta=$(wget -qO- "$ECS_CONTAINER_METADATA_URI_V4/task")"; echo done"#;
    ecs.create_cluster().send().await.unwrap();
    ecs.register_task_definition()
        .family("job")
        .network_mode(NetworkMode::Awsvpc)
        .requires_compatibilities(Compatibility::Fargate)
        .cpu("256")
        .memory("512")
        .execution_role_arn(&exec_arn)
        .task_role_arn(&app_arn)
        .container_definitions(
            ContainerDefinition::builder()
                .name("main")
                .image("alpine:3.20")
                .command("sh")
                .command("-c")
                .command(script)
                .secrets(Secret::builder().name("DB_PASS").value_from(secret.arn().unwrap()).build().unwrap())
                .log_configuration(
                    LogConfiguration::builder()
                        .log_driver(LogDriver::Awslogs)
                        .options("awslogs-group", "/ecs/job")
                        .options("awslogs-region", "us-east-1")
                        .options("awslogs-stream-prefix", "job")
                        .options("awslogs-create-group", "true")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let run = ecs
        .run_task()
        .task_definition("job")
        .launch_type(LaunchType::Fargate)
        .network_configuration(
            NetworkConfiguration::builder()
                .awsvpc_configuration(AwsVpcConfiguration::builder().subnets(&subnet).build().unwrap())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let task_id = arn.rsplit('/').next().unwrap().to_string();

    let mut task = None;
    for _ in 0..600 {
        let d = ecs.describe_tasks().tasks(&arn).send().await.unwrap();
        if d.tasks()[0].last_status() == Some("STOPPED") {
            task = Some(d.tasks()[0].clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let task = task.expect("the task stops when its essential container exits");
    assert_eq!(
        task.stop_code(),
        Some(&aws_sdk_ecs::types::TaskStopCode::EssentialContainerExited),
        "{:?}",
        task.stopped_reason()
    );
    assert_eq!(task.containers()[0].exit_code(), Some(0), "{:?}", task.containers()[0].reason());

    let stream = format!("job/main/{task_id}");
    let mut text = String::new();
    for _ in 0..40 {
        if let Ok(ev) = logs.get_log_events().log_group_name("/ecs/job").log_stream_name(&stream).send().await {
            text = ev.events().iter().filter_map(|e| e.message()).collect::<Vec<_>>().join("\n");
            if text.contains("done") {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(text.contains("secret=hunter2"), "logs: {text}");
    // The task role's session comes from the credentials endpoint, not
    // the environment.
    assert!(text.lines().any(|l| l == "key="), "no static keys: {text}");
    assert!(text.contains(r#""AccessKeyId":"ASIA"#), "the task role's session: {text}");
    assert!(text.contains(&format!("\"TaskARN\":\"{arn}\"")), "task metadata: {text}");

    for _ in 0..40 {
        if containers_named(&format!("mws-ecs-{task_id}")).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(containers_named(&format!("mws-ecs-{task_id}")).is_empty(), "the task's containers are removed");
    mws.stop().await;
}
