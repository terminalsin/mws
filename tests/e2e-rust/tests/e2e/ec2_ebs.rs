//! EBS through the official Rust SDK: volume modifications, status and
//! attributes, volume copies, multi-volume snapshots, snapshot sharing,
//! archive tiers, locks, fast snapshot restores, the account's EBS settings,
//! root volume replacement and the (empty) Recycle Bin.

use aws_sdk_ec2::error::ProvideErrorMetadata;
use aws_sdk_ec2::types::{
    AttributeBooleanValue, CreateVolumePermission, CreateVolumePermissionModifications, Filter, InstanceSpecification,
    LockMode, ResourceType, SnapshotAttributeName, SnapshotBlockPublicAccessState, Tag, TagSpecification,
    VolumeAttributeName, VolumeType,
};
use aws_sdk_ec2::Client;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

async fn alpine_ami(ec2: &Client) -> String {
    let images = ec2.describe_images().owners("amazon").filters(filter("name", "mws-alpine-*")).send().await.unwrap();
    images.images()[0].image_id().unwrap().to_string()
}

async fn volume(ec2: &Client, size: i32) -> String {
    ec2.create_volume()
        .availability_zone("us-east-1a")
        .size(size)
        .volume_type(VolumeType::Gp3)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Volume)
                .tags(Tag::builder().key("team").value("data").build())
                .build(),
        )
        .send()
        .await
        .unwrap()
        .volume_id()
        .unwrap()
        .to_string()
}

fn root_volume(d: &aws_sdk_ec2::operation::describe_instances::DescribeInstancesOutput) -> String {
    let i = &d.reservations()[0].instances()[0];
    let m = i.block_device_mappings().iter().find(|m| m.device_name() == i.root_device_name()).unwrap();
    m.ebs().unwrap().volume_id().unwrap().to_string()
}

async fn snapshot(ec2: &Client, volume_id: &str) -> String {
    ec2.create_snapshot().volume_id(volume_id).send().await.unwrap().snapshot_id().unwrap().to_string()
}

#[tokio::test]
async fn volumes_modify_copy_and_report_status() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let vol = volume(&ec2, 10).await;

    // Modifications: the response shows the change starting, describe shows
    // it done, and a second change within six hours is refused.
    let m = ec2.modify_volume().volume_id(&vol).size(20).iops(4000).send().await.unwrap();
    let m = m.volume_modification().unwrap();
    assert_eq!(m.modification_state().map(|s| s.as_str()), Some("modifying"));
    assert_eq!(m.original_size(), Some(10));
    assert_eq!(m.target_size(), Some(20));
    assert_eq!(m.target_iops(), Some(4000));
    let v = ec2.describe_volumes().volume_ids(&vol).send().await.unwrap();
    assert_eq!(v.volumes()[0].size(), Some(20));
    assert_eq!(v.volumes()[0].iops(), Some(4000));
    let mods = ec2.describe_volumes_modifications().volume_ids(&vol).send().await.unwrap();
    let done = &mods.volumes_modifications()[0];
    assert_eq!(done.modification_state().map(|s| s.as_str()), Some("completed"));
    assert_eq!(done.progress(), Some(100));
    let e = ec2.modify_volume().volume_id(&vol).size(30).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "VolumeModificationRateExceeded");
    let other = volume(&ec2, 10).await;
    let e = ec2.modify_volume().volume_id(&other).size(5).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "InvalidParameterValue");
    assert_eq!(
        message(&e),
        "New size cannot be smaller than existing size. Existing size: 10GiB, requested size: 5GiB."
    );
    let e = ec2.modify_volume().volume_id(&other).size(10).send().await.unwrap_err().into_service_error();
    assert!(message(&e).starts_with("New size, IOPS, throughput, type, or Multi-Attach setting must be different"));
    let e = ec2.describe_volumes_modifications().volume_ids(&other).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "InvalidVolumeModification.NotFound");
    // A move to io2 can turn on Multi-Attach; gp3 can't have it.
    let e =
        ec2.modify_volume().volume_id(&other).multi_attach_enabled(true).send().await.unwrap_err().into_service_error();
    assert_eq!(message(&e), "The parameter multiAttachEnabled is only supported for io1 and io2 volumes.");
    ec2.modify_volume()
        .volume_id(&other)
        .volume_type(VolumeType::Io2)
        .iops(3000)
        .multi_attach_enabled(true)
        .send()
        .await
        .unwrap();
    let v = ec2.describe_volumes().volume_ids(&other).send().await.unwrap();
    assert_eq!(v.volumes()[0].volume_type(), Some(&VolumeType::Io2));
    assert_eq!(v.volumes()[0].multi_attach_enabled(), Some(true));

    // Status and attributes.
    let st = ec2.describe_volume_status().volume_ids(&vol).send().await.unwrap();
    let item = &st.volume_statuses()[0];
    assert_eq!(item.volume_id(), Some(vol.as_str()));
    assert_eq!(item.volume_status().unwrap().status().map(|s| s.as_str()), Some("ok"));
    let st = ec2.describe_volume_status().filters(filter("volume-status.status", "impaired")).send().await.unwrap();
    assert!(st.volume_statuses().is_empty());
    let attr = ec2
        .describe_volume_attribute()
        .volume_id(&vol)
        .attribute(VolumeAttributeName::AutoEnableIo)
        .send()
        .await
        .unwrap();
    assert_eq!(attr.auto_enable_io().unwrap().value(), Some(false));
    ec2.modify_volume_attribute()
        .volume_id(&vol)
        .auto_enable_io(AttributeBooleanValue::builder().value(true).build())
        .send()
        .await
        .unwrap();
    let attr = ec2
        .describe_volume_attribute()
        .volume_id(&vol)
        .attribute(VolumeAttributeName::AutoEnableIo)
        .send()
        .await
        .unwrap();
    assert_eq!(attr.auto_enable_io().unwrap().value(), Some(true));
    ec2.enable_volume_io().volume_id(&vol).send().await.unwrap();
    let e = ec2.enable_volume_io().volume_id("vol-0123456789abcdef0").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "InvalidVolume.NotFound");

    // CopyVolumes: a new volume from the source's data, in its zone.
    let copied = ec2
        .copy_volumes()
        .source_volume_id(&vol)
        .size(40)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Volume)
                .tags(Tag::builder().key("copy").value("yes").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let copy = &copied.volumes()[0];
    let copy_id = copy.volume_id().unwrap().to_string();
    assert_ne!(copy_id, vol);
    assert_eq!(copy.size(), Some(40));
    assert_eq!(copy.availability_zone(), Some("us-east-1a"));
    assert_eq!(copy.volume_type(), Some(&VolumeType::Gp3));
    let d = ec2.describe_volumes().volume_ids(&copy_id).send().await.unwrap();
    assert_eq!(d.volumes()[0].state().map(|s| s.as_str()), Some("available"));
    assert_eq!(d.volumes()[0].tags()[0].key(), Some("copy"));
    let e = ec2.copy_volumes().source_volume_id(&vol).size(5).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "InvalidParameterValue");

    // Deleted volumes don't go to the Recycle Bin without retention rules.
    ec2.delete_volume().volume_id(&copy_id).send().await.unwrap();
    let bin = ec2.list_volumes_in_recycle_bin().send().await.unwrap();
    assert!(bin.volumes().is_empty());
    let e = ec2.restore_volume_from_recycle_bin().volume_id(&copy_id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "InvalidVolume.NotFound");
}

#[tokio::test]
async fn snapshots_share_archive_lock_and_restore_fast() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);
    let vol = volume(&ec2, 8).await;
    let snap = snapshot(&ec2, &vol).await;

    // CopySnapshot within and across regions.
    let copy = ec2
        .copy_snapshot()
        .source_region("us-east-1")
        .source_snapshot_id(&snap)
        .description("copy")
        .send()
        .await
        .unwrap();
    let copy_id = copy.snapshot_id().unwrap().to_string();
    assert_ne!(copy_id, snap);
    let d = ec2.describe_snapshots().snapshot_ids(&copy_id).send().await.unwrap();
    assert_eq!(d.snapshots()[0].description(), Some("copy"));
    assert_eq!(d.snapshots()[0].volume_size(), Some(8));
    let west = Client::from_conf(
        aws_sdk_ec2::config::Builder::from(&mws.root_sdk_config().await)
            .region(aws_sdk_ec2::config::Region::new("eu-west-1"))
            .build(),
    );
    let far = west.copy_snapshot().source_region("us-east-1").source_snapshot_id(&snap).send().await.unwrap();
    let far_id = far.snapshot_id().unwrap().to_string();
    assert_eq!(west.describe_snapshots().snapshot_ids(&far_id).send().await.unwrap().snapshots().len(), 1);
    let e = west
        .copy_snapshot()
        .source_region("us-east-1")
        .source_snapshot_id("snap-0123456789abcdef0")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidSnapshot.NotFound");

    // Sharing: createVolumePermission for an account, then public, which
    // block public access refuses.
    let attr = ec2
        .describe_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .send()
        .await
        .unwrap();
    assert!(attr.create_volume_permissions().is_empty());
    ec2.modify_snapshot_attribute()
        .snapshot_id(&snap)
        .create_volume_permission(
            CreateVolumePermissionModifications::builder()
                .add(CreateVolumePermission::builder().user_id("210987654321").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let attr = ec2
        .describe_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .send()
        .await
        .unwrap();
    assert_eq!(attr.create_volume_permissions()[0].user_id(), Some("210987654321"));
    let e = ec2
        .modify_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .operation_type(aws_sdk_ec2::types::OperationType::Add)
        .user_ids("not-an-account")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(message(&e), "Value (not-an-account) for parameter userId is invalid.");
    let state = ec2.get_snapshot_block_public_access_state().send().await.unwrap();
    assert_eq!(state.state(), Some(&SnapshotBlockPublicAccessState::Unblocked));
    let on = ec2
        .enable_snapshot_block_public_access()
        .state(SnapshotBlockPublicAccessState::BlockNewSharing)
        .send()
        .await
        .unwrap();
    assert_eq!(on.state(), Some(&SnapshotBlockPublicAccessState::BlockNewSharing));
    let e = ec2
        .modify_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .operation_type(aws_sdk_ec2::types::OperationType::Add)
        .group_names("all")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "OperationNotPermitted");
    let off = ec2.disable_snapshot_block_public_access().send().await.unwrap();
    assert_eq!(off.state(), Some(&SnapshotBlockPublicAccessState::Unblocked));
    ec2.modify_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .operation_type(aws_sdk_ec2::types::OperationType::Add)
        .group_names("all")
        .send()
        .await
        .unwrap();
    let attr = ec2
        .describe_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .send()
        .await
        .unwrap();
    assert_eq!(attr.create_volume_permissions().len(), 2);
    ec2.reset_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .send()
        .await
        .unwrap();
    let attr = ec2
        .describe_snapshot_attribute()
        .snapshot_id(&snap)
        .attribute(SnapshotAttributeName::CreateVolumePermission)
        .send()
        .await
        .unwrap();
    assert!(attr.create_volume_permissions().is_empty());

    // Archive tier and restores.
    let e = ec2.restore_snapshot_tier().snapshot_id(&copy_id).permanent_restore(true).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectState");
    let tiered = ec2.modify_snapshot_tier().snapshot_id(&copy_id).send().await.unwrap();
    assert!(tiered.tiering_start_time().is_some());
    let d = ec2.describe_snapshots().snapshot_ids(&copy_id).send().await.unwrap();
    assert_eq!(d.snapshots()[0].storage_tier().map(|s| s.as_str()), Some("archive"));
    let e = ec2.modify_snapshot_tier().snapshot_id(&copy_id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "IncorrectState");
    let st = ec2.describe_snapshot_tier_status().filters(filter("snapshot-id", &copy_id)).send().await.unwrap();
    assert_eq!(
        st.snapshot_tier_statuses()[0].last_tiering_operation_status().map(|s| s.as_str()),
        Some("archival-completed")
    );
    let e = ec2
        .restore_snapshot_tier()
        .snapshot_id(&copy_id)
        .permanent_restore(true)
        .temporary_restore_days(3)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidParameterCombination");
    let restored = ec2.restore_snapshot_tier().snapshot_id(&copy_id).temporary_restore_days(3).send().await.unwrap();
    assert_eq!(restored.restore_duration(), Some(3));
    assert_eq!(restored.is_permanent_restore(), Some(false));
    let d = ec2.describe_snapshots().snapshot_ids(&copy_id).send().await.unwrap();
    assert_eq!(d.snapshots()[0].storage_tier().map(|s| s.as_str()), Some("standard"));
    assert!(d.snapshots()[0].restore_expiry_time().is_some());

    // Locks: governance can be lifted, a locked snapshot can't be deleted,
    // compliance mode holds after its cooling-off period.
    let lock =
        ec2.lock_snapshot().snapshot_id(&snap).lock_mode(LockMode::Governance).lock_duration(1).send().await.unwrap();
    assert_eq!(lock.lock_state().map(|s| s.as_str()), Some("governance"));
    let e = ec2.delete_snapshot().snapshot_id(&snap).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "SnapshotLocked");
    let locked = ec2.describe_locked_snapshots().send().await.unwrap();
    assert_eq!(locked.snapshots().len(), 1);
    assert_eq!(locked.snapshots()[0].snapshot_id(), Some(snap.as_str()));
    ec2.unlock_snapshot().snapshot_id(&snap).send().await.unwrap();
    let e = ec2.unlock_snapshot().snapshot_id(&snap).send().await.unwrap_err().into_service_error();
    assert_eq!(message(&e), format!("The snapshot {snap} is not locked."));
    let e = ec2
        .lock_snapshot()
        .snapshot_id(&snap)
        .lock_mode(LockMode::Governance)
        .lock_duration(1)
        .cool_off_period(1)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidParameterCombination");
    let lock = ec2
        .lock_snapshot()
        .snapshot_id(&copy_id)
        .lock_mode(LockMode::Compliance)
        .lock_duration(1)
        .cool_off_period(1)
        .send()
        .await
        .unwrap();
    assert_eq!(lock.lock_state().map(|s| s.as_str()), Some("compliance-cooloff"));
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 7200}"#)).await;
    assert_eq!(status, 200);
    let locked = ec2.describe_locked_snapshots().filters(filter("lock-state", "compliance")).send().await.unwrap();
    assert_eq!(locked.snapshots()[0].snapshot_id(), Some(copy_id.as_str()));
    let e = ec2.unlock_snapshot().snapshot_id(&copy_id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "IncorrectState");

    // Fast snapshot restores, per zone.
    let fsr = ec2
        .enable_fast_snapshot_restores()
        .source_snapshot_ids(&snap)
        .source_snapshot_ids("snap-0123456789abcdef0")
        .availability_zones("us-east-1a")
        .availability_zones("us-east-1b")
        .send()
        .await
        .unwrap();
    assert_eq!(fsr.successful().len(), 2);
    assert_eq!(fsr.successful()[0].state().map(|s| s.as_str()), Some("enabling"));
    assert_eq!(fsr.unsuccessful().len(), 1);
    let err = &fsr.unsuccessful()[0].fast_snapshot_restore_state_errors()[0];
    assert_eq!(err.error().unwrap().code(), Some("InvalidSnapshot.NotFound"));
    let d = ec2.describe_fast_snapshot_restores().filters(filter("snapshot-id", &snap)).send().await.unwrap();
    assert_eq!(d.fast_snapshot_restores().len(), 2);
    assert!(d.fast_snapshot_restores().iter().all(|f| f.state().map(|s| s.as_str()) == Some("enabled")));
    let off = ec2
        .disable_fast_snapshot_restores()
        .source_snapshot_ids(&snap)
        .availability_zones("us-east-1a")
        .availability_zones("us-east-1c")
        .send()
        .await
        .unwrap();
    assert_eq!(off.successful().len(), 1);
    assert_eq!(off.successful()[0].state().map(|s| s.as_str()), Some("disabling"));
    assert_eq!(
        off.unsuccessful()[0].fast_snapshot_restore_state_errors()[0].error().unwrap().code(),
        Some("InvalidFastSnapshotRestoreState")
    );
    let e = ec2
        .enable_fast_snapshot_restores()
        .source_snapshot_ids(&snap)
        .availability_zones("us-east-1z")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidParameterValue");
    let d = ec2.describe_fast_snapshot_restores().send().await.unwrap();
    assert_eq!(d.fast_snapshot_restores().len(), 1);

    // The Recycle Bin is empty without retention rules.
    let e = ec2.delete_snapshot().snapshot_id(&copy_id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "SnapshotLocked");
    ec2.delete_snapshot().snapshot_id(&far_id).send().await.unwrap_err();
    west.delete_snapshot().snapshot_id(&far_id).send().await.unwrap();
    let bin = ec2.list_snapshots_in_recycle_bin().send().await.unwrap();
    assert!(bin.snapshots().is_empty());
    let e = ec2
        .restore_snapshot_from_recycle_bin()
        .snapshot_id("snap-0123456789abcdef0")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidSnapshot.NotFound");
}

#[tokio::test]
async fn account_settings_instance_snapshots_and_root_replacement() {
    let mws = Mws::start().await;
    let ec2 = Client::new(&mws.root_sdk_config().await);

    // Encryption by default and its key.
    assert_eq!(ec2.get_ebs_encryption_by_default().send().await.unwrap().ebs_encryption_by_default(), Some(false));
    assert_eq!(ec2.get_ebs_default_kms_key_id().send().await.unwrap().kms_key_id(), Some("alias/aws/ebs"));
    let key = ec2.modify_ebs_default_kms_key_id().kms_key_id("alias/ebs-default").send().await.unwrap();
    assert_eq!(key.kms_key_id(), Some(format!("arn:aws:kms:us-east-1:{ACCOUNT}:alias/ebs-default").as_str()));
    let e = ec2.modify_ebs_default_kms_key_id().kms_key_id("nonsense").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let on = ec2.enable_ebs_encryption_by_default().send().await.unwrap();
    assert_eq!(on.ebs_encryption_by_default(), Some(true));
    let encrypted = ec2.create_volume().availability_zone("us-east-1a").size(4).send().await.unwrap();
    assert_eq!(encrypted.encrypted(), Some(true));
    assert_eq!(encrypted.kms_key_id(), Some(format!("arn:aws:kms:us-east-1:{ACCOUNT}:alias/ebs-default").as_str()));
    let off = ec2.disable_ebs_encryption_by_default().send().await.unwrap();
    assert_eq!(off.ebs_encryption_by_default(), Some(false));
    let reset = ec2.reset_ebs_default_kms_key_id().send().await.unwrap();
    assert_eq!(reset.kms_key_id(), Some("alias/aws/ebs"));
    let plain = ec2.create_volume().availability_zone("us-east-1a").size(4).send().await.unwrap();
    assert_eq!(plain.encrypted(), Some(false));

    // CreateSnapshots: one snapshot per attached volume of an instance.
    let ami = alpine_ami(&ec2).await;
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .min_count(1)
        .max_count(1)
        .placement(aws_sdk_ec2::types::Placement::builder().availability_zone("us-east-1a").build())
        .send()
        .await
        .unwrap();
    let instance = run.instances()[0].instance_id().unwrap().to_string();
    crate::ec2::wait_state(&ec2, &instance, aws_sdk_ec2::types::InstanceStateName::Running).await;
    let data = volume(&ec2, 5).await;
    ec2.attach_volume().volume_id(&data).instance_id(&instance).device("/dev/sdf").send().await.unwrap();
    let snaps = ec2
        .create_snapshots()
        .instance_specification(InstanceSpecification::builder().instance_id(&instance).build())
        .description("whole instance")
        .copy_tags_from_source(aws_sdk_ec2::types::CopyTagsFromSource::Volume)
        .send()
        .await
        .unwrap();
    assert_eq!(snaps.snapshots().len(), 2);
    let tagged = snaps.snapshots().iter().find(|s| s.volume_id() == Some(data.as_str())).unwrap();
    assert_eq!(tagged.tags()[0].key(), Some("team"));
    let boot_only = ec2
        .create_snapshots()
        .instance_specification(
            InstanceSpecification::builder().instance_id(&instance).exclude_data_volume_ids(&data).build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(boot_only.snapshots().len(), 1);
    let e = ec2
        .create_snapshots()
        .instance_specification(
            InstanceSpecification::builder()
                .instance_id(&instance)
                .exclude_data_volume_ids(plain.volume_id().unwrap())
                .build(),
        )
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidParameterValue");

    // Replace the root volume with a fresh one from the AMI's snapshot.
    let before = ec2.describe_instances().instance_ids(&instance).send().await.unwrap();
    let old_root = root_volume(&before);
    let e = ec2
        .create_replace_root_volume_task()
        .instance_id(&instance)
        .image_id(&ami)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "MissingParameter");
    let task = ec2
        .create_replace_root_volume_task()
        .instance_id(&instance)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::ReplaceRootVolumeTask)
                .tags(Tag::builder().key("why").value("patch").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let task = task.replace_root_volume_task().unwrap();
    assert_eq!(task.task_state().map(|s| s.as_str()), Some("pending"));
    let task_id = task.replace_root_volume_task_id().unwrap().to_string();
    let tasks = ec2.describe_replace_root_volume_tasks().replace_root_volume_task_ids(&task_id).send().await.unwrap();
    assert_eq!(tasks.replace_root_volume_tasks()[0].task_state().map(|s| s.as_str()), Some("succeeded"));
    let tasks =
        ec2.describe_replace_root_volume_tasks().filters(filter("instance-id", &instance)).send().await.unwrap();
    assert_eq!(tasks.replace_root_volume_tasks().len(), 1);
    let after = ec2.describe_instances().instance_ids(&instance).send().await.unwrap();
    let new_root = root_volume(&after);
    assert_ne!(new_root, old_root);
    // The replaced volume is kept (detached) unless asked otherwise.
    let old = ec2.describe_volumes().volume_ids(&old_root).send().await.unwrap();
    assert_eq!(old.volumes()[0].state().map(|s| s.as_str()), Some("available"));
    let e = ec2
        .describe_replace_root_volume_tasks()
        .replace_root_volume_task_ids("replacevol-0123456789abcdef0")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidReplaceRootVolumeTaskId.NotFound");
}
