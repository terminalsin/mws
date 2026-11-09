//! The console's terminal and file browser for EC2 instances
//! (`/_aws/ec2/instances/<id>/...`): signed requests that need
//! `ssm:StartSession`, running in the instance's container.

use std::process::Command;
use std::time::Duration;

use aws_sdk_ec2::types::{Filter, InstanceStateName, InstanceType};
use aws_sdk_ec2::Client;
use mws_e2e::{user_with_policy, Mws};
use serde_json::{json, Value};

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

async fn launch(ec2: &Client) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values("mws-alpine-*").build())
        .send()
        .await
        .unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let run = ec2
        .run_instances()
        .image_id(ami)
        .instance_type(InstanceType::T3Nano)
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().unwrap().name() == Some(&InstanceStateName::Running) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("instance {id} never ran");
}

fn json(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(body)))
}

#[tokio::test]
async fn console_needs_permission_and_a_machine() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let id = launch(&ec2).await;
    let exec = format!("/_aws/ec2/instances/{id}/exec");
    let body = json!({"command": "echo hi"}).to_string();

    // The metadata backend runs nothing to connect to.
    let (status, _, out) = mws.signed("ec2", "POST", &exec, body.as_bytes()).await;
    assert_eq!(status, 409);
    assert!(json(&out)["message"].as_str().unwrap().contains("MWS_EC2_BACKEND=docker"));
    let (status, _, _) =
        mws.signed("ec2", "POST", "/_aws/ec2/instances/i-0123456789abcdef0/exec", body.as_bytes()).await;
    assert_eq!(status, 404);

    // Session Manager's permission is required.
    user_with_policy(&mws, "viewer", None).await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let key = iam.create_access_key().user_name("viewer").send().await.unwrap();
    let key = key.access_key().unwrap();
    let (status, _, out) =
        mws.signed_as(key.access_key_id(), key.secret_access_key(), "ec2", "POST", &exec, body.as_bytes()).await;
    assert_eq!(status, 403);
    assert!(json(&out)["message"].as_str().unwrap().contains("ssm:StartSession"), "{}", json(&out));

    // Unsigned requests never reach it.
    let (status, _, _) = mws.raw("POST", &exec, &[], body.as_bytes()).await;
    assert!(status == 403 || status == 401, "unsigned: {status}");
    mws.stop().await;
}

#[tokio::test]
async fn console_docker_terminal_and_files() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let id = launch(&ec2).await;
    let base = format!("/_aws/ec2/instances/{id}");

    // Terminal: output, exit codes, and the working directory carries over.
    let (status, _, out) = mws
        .signed("ec2", "POST", &format!("{base}/exec"), json!({"command": "echo hi; cd /tmp"}).to_string().as_bytes())
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    let v = json(&out);
    assert_eq!(v["stdout"], "hi\n");
    assert_eq!(v["exitCode"], 0);
    assert_eq!(v["cwd"], "/tmp");
    let (_, _, out) = mws
        .signed(
            "ec2",
            "POST",
            &format!("{base}/exec"),
            json!({"command": "pwd; exit 3", "cwd": "/tmp"}).to_string().as_bytes(),
        )
        .await;
    let v = json(&out);
    assert_eq!(v["stdout"], "/tmp\n");
    assert_eq!(v["exitCode"], 3);

    // Files: upload (binary-safe), list, download, delete.
    let data: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    let (status, _, out) = mws.signed("ec2", "PUT", &format!("{base}/file?path=%2Fsrv%2Fapp%2Fdata.bin"), &data).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    let (status, _, out) = mws.signed("ec2", "GET", &format!("{base}/files?path=%2Fsrv%2Fapp"), b"").await;
    assert_eq!(status, 200);
    let v = json(&out);
    assert_eq!(v["entries"][0]["name"], "data.bin");
    assert_eq!(v["entries"][0]["type"], "file");
    assert_eq!(v["entries"][0]["size"], 70_000);
    let (_, _, out) = mws.signed("ec2", "GET", &format!("{base}/files?path=%2Fsrv"), b"").await;
    assert_eq!(json(&out)["entries"][0]["type"], "dir");
    let (status, headers, body) =
        mws.signed("ec2", "GET", &format!("{base}/file?path=%2Fsrv%2Fapp%2Fdata.bin"), b"").await;
    assert_eq!(status, 200);
    assert_eq!(body, data);
    assert!(headers.iter().any(|(k, v)| k == "x-mws-truncated" && v == "false"));
    let (status, _, _) = mws.signed("ec2", "DELETE", &format!("{base}/file?path=%2Fsrv%2Fapp"), b"").await;
    assert_eq!(status, 200);
    let (status, _, _) = mws.signed("ec2", "GET", &format!("{base}/files?path=%2Fsrv%2Fapp"), b"").await;
    assert_eq!(status, 404);

    ec2.terminate_instances().instance_ids(&id).send().await.unwrap();
    mws.stop().await;
}
