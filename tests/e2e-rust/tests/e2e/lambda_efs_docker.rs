//! Lambda functions with `FileSystemConfigs`: the EFS access point is
//! mounted into the function's execution environment when the function's
//! subnets reach a mount target, through the official Rust SDK. The mount
//! itself needs Docker; the failure paths do not.

use std::time::Duration;

use aws_sdk_ec2::types::{Filter, IpPermission, UserIdGroupPair};
use aws_sdk_efs::types::{CreationInfo, PosixUser, RootDirectory};
use aws_sdk_lambda::error::ProvideErrorMetadata;
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::{FileSystemConfig, FunctionCode, Runtime, VpcConfig};
use mws_e2e::Mws;

use crate::ecr::docker_available;
use crate::lambda::zip;

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const HANDLER: &str = r#"
import os

def handler(event, context):
    path = "/mnt/data/visits.txt"
    if event.get("write"):
        with open(path, "a") as f:
            f.write(event["write"] + "\n")
    st = os.stat("/mnt/data")
    with open(path) as f:
        return {"lines": f.read().splitlines(), "uid": st.st_uid, "mode": oct(st.st_mode & 0o777)}
"#;

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

/// Everything a function needs to mount `fs` through an access point:
/// returns `(subnets by zone, function security group, access point arn)`.
/// The mount target is created only in the first zone's subnet.
async fn file_system(mws: &Mws, token: &str) -> (Vec<String>, String, String) {
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let efs = aws_sdk_efs::Client::new(&cfg);
    let vpc = ec2.describe_vpcs().filters(filter("isDefault", "true")).send().await.unwrap().vpcs()[0]
        .vpc_id()
        .unwrap()
        .to_string();
    let s = ec2.describe_subnets().filters(filter("default-for-az", "true")).send().await.unwrap();
    let mut subnets: Vec<(String, String)> = s
        .subnets()
        .iter()
        .map(|s| (s.availability_zone().unwrap().to_string(), s.subnet_id().unwrap().to_string()))
        .collect();
    subnets.sort();
    let subnets: Vec<String> = subnets.into_iter().map(|(_, id)| id).collect();

    let group = |name: String| {
        let ec2 = ec2.clone();
        let vpc = vpc.clone();
        async move {
            ec2.create_security_group()
                .group_name(&name)
                .description(&name)
                .vpc_id(vpc)
                .send()
                .await
                .unwrap()
                .group_id()
                .unwrap()
                .to_string()
        }
    };
    let fn_sg = group(format!("{token}-fn")).await;
    let mt_sg = group(format!("{token}-mt")).await;
    ec2.authorize_security_group_ingress()
        .group_id(&mt_sg)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(2049)
                .to_port(2049)
                .user_id_group_pairs(UserIdGroupPair::builder().group_id(&fn_sg).build())
                .build(),
        )
        .send()
        .await
        .unwrap();

    let fs = efs.create_file_system().creation_token(token).send().await.unwrap();
    let fs_id = fs.file_system_id().to_string();
    crate::efs::wait_file_system(&efs, &fs_id).await;
    let mt = efs
        .create_mount_target()
        .file_system_id(&fs_id)
        .subnet_id(&subnets[0])
        .security_groups(&mt_sg)
        .send()
        .await
        .unwrap();
    let ap = efs
        .create_access_point()
        .file_system_id(&fs_id)
        .posix_user(PosixUser::builder().uid(1000).gid(1000).build().unwrap())
        .root_directory(
            RootDirectory::builder()
                .path("/lambda")
                .creation_info(
                    CreationInfo::builder().owner_uid(1000).owner_gid(1000).permissions("755").build().unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let ap_arn = ap.access_point_arn().unwrap().to_string();

    // Wait for the file system, mount target and access point.
    for _ in 0..100 {
        let t = efs.describe_mount_targets().mount_target_id(mt.mount_target_id()).send().await.unwrap();
        let a = efs.describe_access_points().access_point_id(ap.access_point_id().unwrap()).send().await.unwrap();
        let f = efs.describe_file_systems().file_system_id(&fs_id).send().await.unwrap();
        if t.mount_targets()[0].life_cycle_state().as_str() == "available"
            && a.access_points()[0].life_cycle_state().map(|s| s.as_str()) == Some("available")
            && f.file_systems()[0].life_cycle_state().as_str() == "available"
        {
            return (subnets, fn_sg, ap_arn);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("EFS resources never became available");
}

async fn function(
    lambda: &aws_sdk_lambda::Client,
    role_arn: &str,
    name: &str,
    subnet: &str,
    sg: &str,
    ap_arn: &str,
) -> String {
    let mut last = None;
    // A just-created role can take a moment to be assumable.
    for _ in 0..20 {
        match lambda
            .create_function()
            .function_name(name)
            .runtime(Runtime::Python313)
            .role(role_arn)
            .handler("index.handler")
            .timeout(30)
            .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("index.py", HANDLER)]))).build())
            .vpc_config(VpcConfig::builder().subnet_ids(subnet).security_group_ids(sg).build())
            .file_system_configs(FileSystemConfig::builder().arn(ap_arn).local_mount_path("/mnt/data").build().unwrap())
            .send()
            .await
        {
            Ok(f) => return f.function_arn().unwrap().to_string(),
            Err(e) => last = Some(format!("{:?}", e.into_service_error())),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("create_function failed: {last:?}");
}

async fn invoke_error(lambda: &aws_sdk_lambda::Client, name: &str) -> (String, String) {
    let e = lambda.invoke().function_name(name).payload(Blob::new("{}")).send().await.unwrap_err().into_service_error();
    (e.code().unwrap_or_default().to_string(), e.message().unwrap_or_default().to_string())
}

#[tokio::test]
async fn efs_mounts_need_a_container_and_a_network_path() {
    let config = mws::Config { lambda_runtime_executor: mws::LambdaRuntimeExecutor::Local, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role_arn = iam
        .create_role()
        .role_name("efs-fn")
        .assume_role_policy_document(TRUST)
        .send()
        .await
        .unwrap()
        .role()
        .unwrap()
        .arn()
        .to_string();
    let (subnets, sg, ap_arn) = file_system(&mws, "local").await;

    // No mount target in the second zone: no network path.
    function(&lambda, &role_arn, "efs-elsewhere", &subnets[1], &sg, &ap_arn).await;
    let (code, message) = invoke_error(&lambda, "efs-elsewhere").await;
    assert_eq!(code, "EFSMountConnectivityException", "{message}");

    // Without the function's security group the mount target refuses NFS.
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let other = ec2
        .create_security_group()
        .group_name("efs-other")
        .description("other")
        .vpc_id(
            ec2.describe_vpcs().filters(filter("isDefault", "true")).send().await.unwrap().vpcs()[0].vpc_id().unwrap(),
        )
        .send()
        .await
        .unwrap()
        .group_id()
        .unwrap()
        .to_string();
    function(&lambda, &role_arn, "efs-blocked", &subnets[0], &other, &ap_arn).await;
    let (code, message) = invoke_error(&lambda, "efs-blocked").await;
    assert_eq!(code, "EFSMountConnectivityException", "{message}");
    assert!(message.contains("2049"), "{message}");

    // Reachable, but local processes can't mount: MWS says so.
    function(&lambda, &role_arn, "efs-local", &subnets[0], &sg, &ap_arn).await;
    let (code, message) = invoke_error(&lambda, "efs-local").await;
    assert_eq!(code, "EFSMountFailureException", "{message}");
}

#[tokio::test]
async fn efs_access_point_is_mounted_into_the_function_docker() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { lambda_runtime_executor: mws::LambdaRuntimeExecutor::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role_arn = iam
        .create_role()
        .role_name("efs-fn")
        .assume_role_policy_document(TRUST)
        .send()
        .await
        .unwrap()
        .role()
        .unwrap()
        .arn()
        .to_string();
    let (subnets, sg, ap_arn) = file_system(&mws, "docker").await;
    function(&lambda, &role_arn, "efs-writer", &subnets[0], &sg, &ap_arn).await;
    function(&lambda, &role_arn, "efs-reader", &subnets[0], &sg, &ap_arn).await;

    let call = |name: &'static str, payload: &'static str| {
        let lambda = lambda.clone();
        async move {
            let out = lambda.invoke().function_name(name).payload(Blob::new(payload)).send().await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(out.payload().unwrap().as_ref()).unwrap();
            assert_eq!(out.function_error(), None, "{body}");
            body
        }
    };
    let first = call("efs-writer", r#"{"write":"one"}"#).await;
    assert_eq!(first["lines"], serde_json::json!(["one"]));
    // The access point's root directory was created from its creation info.
    assert_eq!(first["uid"], 1000);
    assert_eq!(first["mode"], "0o755");
    call("efs-writer", r#"{"write":"two"}"#).await;
    // Another function mounting the same access point sees the same files.
    let read = call("efs-reader", "{}").await;
    assert_eq!(read["lines"], serde_json::json!(["one", "two"]));
}
