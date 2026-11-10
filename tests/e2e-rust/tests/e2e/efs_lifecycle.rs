//! EFS lifecycle states and throughput change limits, through the official
//! Rust SDK: file systems are `creating` and mount targets `creating`
//! before they are `available`, deleted file systems are `deleting`, and
//! throughput changes wait 24 hours.

use aws_sdk_efs::error::ProvideErrorMetadata;
use aws_sdk_efs::types::ThroughputMode;
use aws_sdk_efs::Client;
use mws_e2e::Mws;

use crate::efs::{wait_file_system, wait_file_system_deleted};

async fn advance(mws: &Mws, seconds: i64) {
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&format!("{{\"advanceSeconds\": {seconds}}}"))).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn file_systems_and_mount_targets_take_time() {
    let mws = Mws::start().await;
    let conf = mws.root_sdk_config().await;
    let efs = Client::new(&conf);
    let ec2 = aws_sdk_ec2::Client::new(&conf);
    let subnet = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap()
        .subnets()[0]
        .subnet_id()
        .unwrap()
        .to_string();

    let fs = efs.create_file_system().creation_token("life").send().await.unwrap();
    let id = fs.file_system_id().to_string();
    assert_eq!(fs.life_cycle_state().as_str(), "creating");
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.file_systems()[0].life_cycle_state().as_str(), "creating");

    // No mount target until the file system is available.
    let e = efs.create_mount_target().file_system_id(&id).subnet_id(&subnet).send().await.unwrap_err();
    assert_eq!(e.raw_response().unwrap().status().as_u16(), 409);
    let e = e.into_service_error();
    assert_eq!(e.code(), Some("IncorrectFileSystemLifeCycleState"));
    assert_eq!(e.message(), Some(format!("File system '{id}' is in the 'creating' state.").as_str()));

    wait_file_system(&efs, &id).await;
    let mt = efs.create_mount_target().file_system_id(&id).subnet_id(&subnet).send().await.unwrap();
    assert_eq!(mt.life_cycle_state().as_str(), "creating");
    let d = efs.describe_mount_targets().mount_target_id(mt.mount_target_id()).send().await.unwrap();
    assert_eq!(d.mount_targets()[0].life_cycle_state().as_str(), "creating");
    let e = efs
        .describe_mount_target_security_groups()
        .mount_target_id(mt.mount_target_id())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(e.code(), Some("IncorrectMountTargetState"));

    // The emulated clock finishes it.
    advance(&mws, 120).await;
    let d = efs.describe_mount_targets().mount_target_id(mt.mount_target_id()).send().await.unwrap();
    assert_eq!(d.mount_targets()[0].life_cycle_state().as_str(), "available");

    // Deleting: `deleting`, then gone. The file system is in use until
    // its mount target is gone.
    efs.delete_mount_target().mount_target_id(mt.mount_target_id()).send().await.unwrap();
    let d = efs.describe_mount_targets().mount_target_id(mt.mount_target_id()).send().await.unwrap();
    assert_eq!(d.mount_targets()[0].life_cycle_state().as_str(), "deleting");
    let e = efs.delete_file_system().file_system_id(&id).send().await.unwrap_err().into_service_error();
    assert_eq!(e.code(), Some("FileSystemInUse"));
    advance(&mws, 120).await;
    efs.delete_file_system().file_system_id(&id).send().await.unwrap();
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.file_systems()[0].life_cycle_state().as_str(), "deleting");
    let e = efs.create_mount_target().file_system_id(&id).subnet_id(&subnet).send().await.unwrap_err();
    assert_eq!(e.into_service_error().code(), Some("IncorrectFileSystemLifeCycleState"));
    wait_file_system_deleted(&efs, &id).await;
}

#[tokio::test]
async fn throughput_changes_wait_a_day() {
    let mws = Mws::start().await;
    let efs = Client::new(&mws.root_sdk_config().await);
    let fs = efs.create_file_system().creation_token("tput").send().await.unwrap();
    let id = fs.file_system_id().to_string();
    wait_file_system(&efs, &id).await;

    let update = |mode: Option<ThroughputMode>, mibps: Option<f64>| {
        efs.update_file_system()
            .file_system_id(&id)
            .set_throughput_mode(mode)
            .set_provisioned_throughput_in_mibps(mibps)
    };
    // Switching to provisioned throughput, then increasing it, are allowed.
    update(Some(ThroughputMode::Provisioned), Some(100.0)).send().await.unwrap();
    update(None, Some(200.0)).send().await.unwrap();

    // Decreasing it or changing the mode must wait 24 hours.
    let too_soon = |e: aws_sdk_efs::error::SdkError<
        aws_sdk_efs::operation::update_file_system::UpdateFileSystemError,
    >| {
        assert_eq!(e.raw_response().unwrap().status().as_u16(), 429);
        let e = e.into_service_error();
        let aws_sdk_efs::operation::update_file_system::UpdateFileSystemError::TooManyRequests(t) = &e else {
            panic!("{e:?}")
        };
        assert_eq!(t.error_code(), "TooManyRequests");
        assert!(
            t.message().unwrap().starts_with(
                "You have reached the maximum number of throughput mode changes or provisioned throughput value decreases."
            ),
            "{t:?}"
        );
    };
    too_soon(update(None, Some(50.0)).send().await.unwrap_err());
    too_soon(update(Some(ThroughputMode::Bursting), None).send().await.unwrap_err());
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.file_systems()[0].provisioned_throughput_in_mibps(), Some(200.0));

    // A decrease starts the wait again; increases never wait.
    advance(&mws, 24 * 3600 + 60).await;
    update(None, Some(50.0)).send().await.unwrap();
    update(None, Some(60.0)).send().await.unwrap();
    too_soon(update(None, Some(40.0)).send().await.unwrap_err());
    too_soon(update(Some(ThroughputMode::Bursting), None).send().await.unwrap_err());
    advance(&mws, 24 * 3600 + 60).await;
    update(Some(ThroughputMode::Bursting), None).send().await.unwrap();
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.file_systems()[0].throughput_mode(), Some(&ThroughputMode::Bursting));
}
