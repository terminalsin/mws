//! EC2 instances that really run: the Docker backend, through the official
//! Rust SDK. Skipped when no Docker daemon answers.

use std::process::Command;
use std::time::Duration;

use aws_sdk_ec2::types::{Filter, InstanceStateName};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `docker inspect` of an instance's container: its state, or `None` once
/// it is gone.
fn container_state(instance_id: &str) -> Option<String> {
    let out = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Status}}", &format!("mws-ec2-{instance_id}")])
        .output()
        .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn wait_for_state(ec2: &Client, id: &str, want: InstanceStateName) {
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
        let state = d.reservations()[0].instances()[0].state().unwrap().name().cloned();
        if state.as_ref() == Some(&want) {
            return;
        }
        if want != InstanceStateName::Terminated && state == Some(InstanceStateName::Terminated) {
            panic!("instance {id} terminated: {:?}", d.reservations()[0].instances()[0].state_reason());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("instance {id} never reached {want:?}");
}

#[tokio::test]
async fn instances_run_as_containers() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    // Listen on every interface so instances reach MWS through the Docker
    // host gateway.
    let config = mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let ec2 = Client::new(&mws.root_sdk_config().await);

    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    use base64::Engine;
    // User data runs once at first boot; it reads instance metadata the
    // way software on an instance would.
    let script = "#!/bin/sh\necho \"user data ran on $(hostname)\"\necho \"imds says $(wget -qO- \"$AWS_EC2_METADATA_SERVICE_ENDPOINT/latest/meta-data/instance-id\")\"\n";
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(aws_sdk_ec2::types::InstanceType::T3Nano)
        .user_data(base64::engine::general_purpose::STANDARD.encode(script))
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    let ip = run.instances()[0].private_ip_address().unwrap().to_string();
    wait_for_state(&ec2, &id, InstanceStateName::Running).await;
    assert_eq!(container_state(&id).as_deref(), Some("running"));
    let inspect = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            &format!("mws-ec2-{id}"),
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&inspect.stdout).trim(), ip, "the container has the instance's private IP");

    let mut console = String::new();
    for _ in 0..120 {
        let out = ec2.get_console_output().instance_id(&id).send().await.unwrap();
        if let Some(text) = out.output() {
            console = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(text).unwrap()).unwrap();
            if console.contains("Cloud-init finished") {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(console.contains("user data ran on ip-"), "console: {console}");
    assert!(console.contains(&format!("imds says {id}")), "console: {console}");

    ec2.stop_instances().instance_ids(&id).send().await.unwrap();
    wait_for_state(&ec2, &id, InstanceStateName::Stopped).await;
    assert_eq!(container_state(&id).as_deref(), Some("exited"));
    ec2.start_instances().instance_ids(&id).send().await.unwrap();
    wait_for_state(&ec2, &id, InstanceStateName::Running).await;
    assert_eq!(container_state(&id).as_deref(), Some("running"));

    ec2.terminate_instances().instance_ids(&id).send().await.unwrap();
    wait_for_state(&ec2, &id, InstanceStateName::Terminated).await;
    assert_eq!(container_state(&id), None);

    mws.stop().await;
}
