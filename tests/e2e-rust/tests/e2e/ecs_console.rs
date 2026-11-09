//! The console's terminal and file browser for ECS task containers
//! (`/_aws/ecs/tasks/<cluster>/<task>/<container>/...`): signed, needs
//! `ecs:ExecuteCommand` and a task run with execute command enabled.

use std::process::Command;
use std::time::Duration;

use aws_sdk_ecs::types::{
    AwsVpcConfiguration, Compatibility, ContainerDefinition, LaunchType, NetworkConfiguration, NetworkMode,
};
use mws_e2e::Mws;
use serde_json::{json, Value};

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run a long-lived alpine task; returns its id once it is RUNNING (or
/// whatever status it settles in).
async fn run_task(mws: &Mws, exec: bool) -> String {
    let cfg = mws.root_sdk_config().await;
    let ecs = aws_sdk_ecs::Client::new(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let subnets = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    let subnet = subnets.subnets()[0].subnet_id().unwrap().to_string();
    ecs.create_cluster().send().await.unwrap();
    ecs.register_task_definition()
        .family("shell")
        .network_mode(NetworkMode::Awsvpc)
        .requires_compatibilities(Compatibility::Fargate)
        .cpu("256")
        .memory("512")
        .container_definitions(
            ContainerDefinition::builder().name("main").image("alpine:3.20").command("sleep").command("600").build(),
        )
        .send()
        .await
        .unwrap();
    let run = ecs
        .run_task()
        .task_definition("shell")
        .launch_type(LaunchType::Fargate)
        .enable_execute_command(exec)
        .network_configuration(
            NetworkConfiguration::builder()
                .awsvpc_configuration(AwsVpcConfiguration::builder().subnets(&subnet).build().unwrap())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    for _ in 0..600 {
        let d = ecs.describe_tasks().tasks(&arn).send().await.unwrap();
        if d.tasks()[0].last_status() == Some("RUNNING") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    arn.rsplit('/').next().unwrap().to_string()
}

fn json(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(body)))
}

#[tokio::test]
async fn console_needs_execute_command() {
    let mws = Mws::start().await;
    let task = run_task(&mws, false).await;
    let cmd = json!({"command": "id"}).to_string();
    let (status, _, out) =
        mws.signed("ecs", "POST", &format!("/_aws/ecs/tasks/default/{task}/main/exec"), cmd.as_bytes()).await;
    assert_eq!(status, 409, "{}", String::from_utf8_lossy(&out));
    assert!(json(&out)["message"].as_str().unwrap().contains("execute command was not enabled"));
    let (status, _, _) =
        mws.signed("ecs", "POST", "/_aws/ecs/tasks/default/0123456789abcdef/main/exec", cmd.as_bytes()).await;
    assert_eq!(status, 404);
    mws.stop().await;
}

#[tokio::test]
async fn console_docker_shell_in_a_task() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { ecs_backend: mws_ecs::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let task = run_task(&mws, true).await;
    let base = format!("/_aws/ecs/tasks/default/{task}/main");
    let (status, _, out) = mws
        .signed(
            "ecs",
            "POST",
            &format!("{base}/exec"),
            json!({"command": "cat /etc/alpine-release >/dev/null && echo alpine"}).to_string().as_bytes(),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    assert_eq!(json(&out)["stdout"], "alpine\n");
    let (status, _, _) = mws.signed("ecs", "PUT", &format!("{base}/file?path=%2Ftmp%2Fhello.txt"), b"hello").await;
    assert_eq!(status, 200);
    let (_, _, out) = mws.signed("ecs", "GET", &format!("{base}/files?path=%2Ftmp"), b"").await;
    assert!(json(&out)["entries"].as_array().unwrap().iter().any(|e| e["name"] == "hello.txt" && e["size"] == 5));
    let (_, _, body) = mws.signed("ecs", "GET", &format!("{base}/file?path=%2Ftmp%2Fhello.txt"), b"").await;
    assert_eq!(body, b"hello");
    let ecs = aws_sdk_ecs::Client::new(&mws.root_sdk_config().await);
    ecs.stop_task().task(&task).send().await.unwrap();
    mws.stop().await;
}
