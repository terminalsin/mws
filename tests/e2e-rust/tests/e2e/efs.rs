//! Amazon EFS through the official Rust SDK: file systems, mount targets in
//! EC2 subnets, access points, policies, replication and tags; mounts as
//! the EFS mount helper asks for them; and (with Docker) a real instance
//! mounting a file system and writing to it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use aws_sdk_ec2::types::{Filter, InstanceStateName, IpPermission, UserIdGroupPair};
use aws_sdk_efs::error::ProvideErrorMetadata;
use aws_sdk_efs::types::{
    BackupPolicy, CreationInfo, DestinationToCreate, LifecyclePolicy, PerformanceMode, PosixUser,
    ReplicationOverwriteProtection, ResourceIdType, RootDirectory, Status, Tag, ThroughputMode, TransitionToIaRules,
};
use aws_sdk_efs::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

async fn clients(mws: &Mws) -> (Client, aws_sdk_ec2::Client) {
    let conf = mws.root_sdk_config().await;
    (Client::new(&conf), aws_sdk_ec2::Client::new(&conf))
}

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

fn tag(k: &str, v: &str) -> Tag {
    Tag::builder().key(k).value(v).build().unwrap()
}

/// Where MWS keeps a file system's data (the default `MWS_EFS_DIR`).
fn data_dir(rel: &str) -> PathBuf {
    std::env::temp_dir().join("mws-efs").join(rel)
}

/// Poll DescribeFileSystems until the file system is `available`, as code
/// must on AWS (the SDKs have no EFS waiters).
pub(crate) async fn wait_file_system(efs: &Client, id: &str) {
    for _ in 0..100 {
        let d = efs.describe_file_systems().file_system_id(id).send().await.unwrap();
        if d.file_systems()[0].life_cycle_state().as_str() == "available" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("file system {id} never became available");
}

/// Poll DescribeMountTargets until every mount target of the file system is
/// `available`.
pub(crate) async fn wait_mount_targets(efs: &Client, fs_id: &str) {
    for _ in 0..100 {
        let d = efs.describe_mount_targets().file_system_id(fs_id).send().await.unwrap();
        if d.mount_targets().iter().all(|m| m.life_cycle_state().as_str() == "available") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the mount targets of {fs_id} never became available");
}

/// Poll DescribeFileSystems until the file system is gone.
pub(crate) async fn wait_file_system_deleted(efs: &Client, id: &str) {
    for _ in 0..100 {
        if efs.describe_file_systems().file_system_id(id).send().await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("file system {id} was never deleted");
}

/// `(subnet id, zone)` of the default subnets, ordered by zone.
async fn default_subnets(ec2: &aws_sdk_ec2::Client) -> Vec<(String, String)> {
    let s = ec2.describe_subnets().filters(filter("default-for-az", "true")).send().await.unwrap();
    let mut out: Vec<(String, String)> = s
        .subnets()
        .iter()
        .map(|s| (s.subnet_id().unwrap().to_string(), s.availability_zone().unwrap().to_string()))
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

#[tokio::test]
#[allow(deprecated)] // CreateTags, DeleteTags and DescribeTags are still part of the API.
async fn file_systems_and_their_settings() {
    let mws = Mws::start().await;
    let (efs, _) = clients(&mws).await;

    let created = efs
        .create_file_system()
        .creation_token("tok-1")
        .tags(tag("Name", "shared"))
        .tags(tag("team", "infra"))
        .send()
        .await
        .unwrap();
    let id = created.file_system_id().to_string();
    assert!(id.starts_with("fs-") && id.len() == 20, "{id}");
    assert_eq!(created.life_cycle_state().as_str(), "creating");
    assert_eq!(created.owner_id(), ACCOUNT);
    assert_eq!(created.name(), Some("shared"));
    assert_eq!(created.performance_mode(), &PerformanceMode::GeneralPurpose);
    assert_eq!(created.throughput_mode(), Some(&ThroughputMode::Bursting));
    assert_eq!(created.encrypted(), Some(false));
    assert_eq!(
        created.file_system_arn(),
        Some(format!("arn:aws:elasticfilesystem:us-east-1:{ACCOUNT}:file-system/{id}").as_str())
    );
    assert_eq!(
        created.file_system_protection().unwrap().replication_overwrite_protection(),
        Some(&ReplicationOverwriteProtection::Enabled)
    );

    // The creation token makes creation idempotent: a second call names the
    // file system that already exists.
    let e = efs.create_file_system().creation_token("tok-1").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "FileSystemAlreadyExists");
    let aws_sdk_efs::operation::create_file_system::CreateFileSystemError::FileSystemAlreadyExists(exists) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(exists.file_system_id(), id);
    assert_eq!(exists.error_code(), "FileSystemAlreadyExists");

    wait_file_system(&efs, &id).await;
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    let fs = &d.file_systems()[0];
    assert_eq!(fs.life_cycle_state().as_str(), "available");
    assert_eq!(fs.size_in_bytes().unwrap().value(), 6144);
    assert_eq!(fs.number_of_mount_targets(), 0);
    let by_token = efs.describe_file_systems().creation_token("tok-1").send().await.unwrap();
    assert_eq!(by_token.file_systems()[0].file_system_id(), id);

    // Data written to the file system shows up in its metered size.
    std::fs::write(data_dir(&id).join("hello.txt"), vec![b'x'; 10_000]).unwrap();
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.file_systems()[0].size_in_bytes().unwrap().value(), 6144 + 12288);

    // Paging through file systems with markers.
    for i in 0..3 {
        efs.create_file_system().creation_token(format!("page-{i}")).send().await.unwrap();
    }
    let p1 = efs.describe_file_systems().max_items(2).send().await.unwrap();
    assert_eq!(p1.file_systems().len(), 2);
    let p2 = efs.describe_file_systems().max_items(2).marker(p1.next_marker().unwrap()).send().await.unwrap();
    assert_eq!(p2.file_systems().len(), 2);
    assert!(p2.next_marker().is_none());

    // Throughput.
    let e = efs
        .update_file_system()
        .file_system_id(&id)
        .throughput_mode(ThroughputMode::Provisioned)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "BadRequest");
    let u = efs
        .update_file_system()
        .file_system_id(&id)
        .throughput_mode(ThroughputMode::Provisioned)
        .provisioned_throughput_in_mibps(128.0)
        .send()
        .await
        .unwrap();
    assert_eq!(u.life_cycle_state().as_str(), "updating");
    assert_eq!(u.provisioned_throughput_in_mibps(), Some(128.0));

    // Backup, lifecycle and protection settings.
    let b = efs.describe_backup_policy().file_system_id(&id).send().await.unwrap();
    assert_eq!(b.backup_policy().unwrap().status(), &Status::Disabled);
    efs.put_backup_policy()
        .file_system_id(&id)
        .backup_policy(BackupPolicy::builder().status(Status::Enabled).build().unwrap())
        .send()
        .await
        .unwrap();
    let b = efs.describe_backup_policy().file_system_id(&id).send().await.unwrap();
    assert_eq!(b.backup_policy().unwrap().status(), &Status::Enabled);
    let l = efs.describe_lifecycle_configuration().file_system_id(&id).send().await.unwrap();
    assert!(l.lifecycle_policies().is_empty());
    efs.put_lifecycle_configuration()
        .file_system_id(&id)
        .lifecycle_policies(LifecyclePolicy::builder().transition_to_ia(TransitionToIaRules::After30Days).build())
        .send()
        .await
        .unwrap();
    let l = efs.describe_lifecycle_configuration().file_system_id(&id).send().await.unwrap();
    assert_eq!(l.lifecycle_policies()[0].transition_to_ia(), Some(&TransitionToIaRules::After30Days));
    let e = efs
        .put_lifecycle_configuration()
        .file_system_id(&id)
        .lifecycle_policies(
            LifecyclePolicy::builder()
                .transition_to_ia(TransitionToIaRules::After7Days)
                .transition_to_primary_storage_class(
                    aws_sdk_efs::types::TransitionToPrimaryStorageClassRules::After1Access,
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "BadRequest");
    let p = efs
        .update_file_system_protection()
        .file_system_id(&id)
        .replication_overwrite_protection(ReplicationOverwriteProtection::Disabled)
        .send()
        .await
        .unwrap();
    assert_eq!(p.replication_overwrite_protection(), Some(&ReplicationOverwriteProtection::Disabled));

    // File system policies.
    let e = efs.describe_file_system_policy().file_system_id(&id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "PolicyNotFound");
    let e = efs
        .put_file_system_policy()
        .file_system_id(&id)
        .policy("{not json")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidPolicyException");
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"*"}},"Action":"elasticfilesystem:ClientMount","Resource":"arn:aws:elasticfilesystem:us-east-1:{ACCOUNT}:file-system/{id}"}}]}}"#
    );
    let put = efs.put_file_system_policy().file_system_id(&id).policy(&policy).send().await.unwrap();
    assert_eq!(put.policy(), Some(policy.as_str()));
    let got = efs.describe_file_system_policy().file_system_id(&id).send().await.unwrap();
    assert_eq!(got.policy(), Some(policy.as_str()));
    // A policy that would lock the caller out is refused unless bypassed.
    let lockout = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"*"}},"Action":"elasticfilesystem:*","Resource":"arn:aws:elasticfilesystem:us-east-1:{ACCOUNT}:file-system/{id}"}}]}}"#
    );
    let e = efs
        .put_file_system_policy()
        .file_system_id(&id)
        .policy(&lockout)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "InvalidPolicyException");
    efs.delete_file_system_policy().file_system_id(&id).send().await.unwrap();

    // Tags, the legacy way and the new way.
    efs.create_tags().file_system_id(&id).tags(tag("env", "dev")).send().await.unwrap();
    efs.delete_tags().file_system_id(&id).tag_keys("team").send().await.unwrap();
    let t = efs.describe_tags().file_system_id(&id).send().await.unwrap();
    let keys: Vec<_> = t.tags().iter().map(|t| t.key()).collect();
    assert_eq!(keys, ["Name", "env"]);
    efs.tag_resource().resource_id(&id).tags(tag("Name", "renamed")).send().await.unwrap();
    efs.untag_resource().resource_id(&id).tag_keys("env").send().await.unwrap();
    let t = efs.list_tags_for_resource().resource_id(&id).send().await.unwrap();
    assert_eq!(t.tags().len(), 1);
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.file_systems()[0].name(), Some("renamed"));
    let e = efs.tag_resource().resource_id(&id).tags(tag("aws:x", "y")).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "BadRequest");

    // Encryption with the AWS managed key, or a key of the caller's.
    let enc = efs.create_file_system().creation_token("enc").encrypted(true).send().await.unwrap();
    let kms = aws_sdk_kms::Client::new(&mws.root_sdk_config().await);
    let managed = kms.describe_key().key_id("alias/aws/elasticfilesystem").send().await.unwrap();
    assert_eq!(enc.kms_key_id(), managed.key_metadata().unwrap().arn());
    let key = kms.create_key().send().await.unwrap().key_metadata().unwrap().key_id().to_string();
    let own = efs.create_file_system().creation_token("own-key").encrypted(true).kms_key_id(&key).send().await.unwrap();
    assert!(own.kms_key_id().unwrap().ends_with(&format!("key/{key}")));
    let e = efs
        .create_file_system()
        .creation_token("bad-key")
        .encrypted(true)
        .kms_key_id("11111111-2222-3333-4444-555555555555")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "BadRequest");

    // One Zone file systems.
    let oz = efs.create_file_system().creation_token("oz").availability_zone_name("us-east-1b").send().await.unwrap();
    assert_eq!(oz.availability_zone_id(), Some("use1-az2"));
    let b = efs.describe_backup_policy().file_system_id(oz.file_system_id()).send().await.unwrap();
    assert_eq!(b.backup_policy().unwrap().status(), &Status::Enabled);

    // Short ids on request.
    let prefs = efs.describe_account_preferences().send().await.unwrap();
    assert_eq!(prefs.resource_id_preference().unwrap().resource_id_type(), Some(&ResourceIdType::LongId));
    efs.put_account_preferences().resource_id_type(ResourceIdType::ShortId).send().await.unwrap();
    let short = efs.create_file_system().creation_token("short").send().await.unwrap();
    assert_eq!(short.file_system_id().len(), 11, "{}", short.file_system_id());

    // Deleting: `deleting` for a moment, then gone.
    efs.delete_file_system().file_system_id(&id).send().await.unwrap();
    let d = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.file_systems()[0].life_cycle_state().as_str(), "deleting");
    wait_file_system_deleted(&efs, &id).await;
    assert!(!data_dir(&id).exists());
    let e = efs.describe_file_systems().file_system_id(&id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "FileSystemNotFound");
    assert_eq!(e.meta().message(), Some(format!("File system '{id}' does not exist.").as_str()));
}

#[tokio::test]
async fn mount_targets_and_access_points() {
    let mws = Mws::start().await;
    let (efs, ec2) = clients(&mws).await;
    let subnets = default_subnets(&ec2).await;
    let fs = efs.create_file_system().creation_token("mt").send().await.unwrap();
    let id = fs.file_system_id().to_string();
    wait_file_system(&efs, &id).await;

    let sg = ec2
        .create_security_group()
        .group_name("efs")
        .description("efs")
        .vpc_id(
            ec2.describe_vpcs().filters(filter("isDefault", "true")).send().await.unwrap().vpcs()[0].vpc_id().unwrap(),
        )
        .send()
        .await
        .unwrap()
        .group_id()
        .unwrap()
        .to_string();
    let mt = efs
        .create_mount_target()
        .file_system_id(&id)
        .subnet_id(&subnets[0].0)
        .security_groups(&sg)
        .send()
        .await
        .unwrap();
    assert_eq!(mt.life_cycle_state().as_str(), "creating");
    assert_eq!(mt.availability_zone_name(), Some(subnets[0].1.as_str()));
    assert_eq!(mt.availability_zone_id(), Some("use1-az1"));
    let mt_id = mt.mount_target_id().to_string();
    let eni = mt.network_interface_id().unwrap().to_string();
    let ip = mt.ip_address().unwrap().to_string();

    // The mount target is an EFS-managed interface in the subnet.
    let n = ec2.describe_network_interfaces().network_interface_ids(&eni).send().await.unwrap();
    let n = &n.network_interfaces()[0];
    assert_eq!(n.private_ip_address(), Some(ip.as_str()));
    assert_eq!(n.requester_managed(), Some(true));
    assert_eq!(n.description(), Some(format!("EFS mount target for {id} ({mt_id})").as_str()));
    assert_eq!(n.groups()[0].group_id(), Some(sg.as_str()));
    assert!(ec2.delete_network_interface().network_interface_id(&eni).send().await.is_err());
    assert!(ec2.delete_security_group().group_id(&sg).send().await.is_err());

    // One mount target per Availability Zone, all in one VPC.
    let e = efs
        .create_mount_target()
        .file_system_id(&id)
        .subnet_id(&subnets[0].0)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "MountTargetConflict");
    let vpc =
        ec2.create_vpc().cidr_block("10.9.0.0/16").send().await.unwrap().vpc().unwrap().vpc_id().unwrap().to_string();
    let other = ec2
        .create_subnet()
        .vpc_id(&vpc)
        .cidr_block("10.9.1.0/24")
        .availability_zone("us-east-1c")
        .send()
        .await
        .unwrap()
        .subnet()
        .unwrap()
        .subnet_id()
        .unwrap()
        .to_string();
    let e =
        efs.create_mount_target().file_system_id(&id).subnet_id(&other).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "MountTargetConflict");
    let e = efs
        .create_mount_target()
        .file_system_id(&id)
        .subnet_id("subnet-0123456789abcdef0")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "SubnetNotFound");
    let e = efs
        .create_mount_target()
        .file_system_id(&id)
        .subnet_id(&subnets[1].0)
        .security_groups("sg-0123456789abcdef0")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "SecurityGroupNotFound");
    let other_fs = efs.create_file_system().creation_token("mt-other").send().await.unwrap();
    wait_file_system(&efs, other_fs.file_system_id()).await;
    let e = efs
        .create_mount_target()
        .file_system_id(other_fs.file_system_id())
        .subnet_id(&subnets[0].0)
        .ip_address(&ip)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "IpAddressInUse");
    // Without groups, the VPC's default group.
    let mt2 = efs.create_mount_target().file_system_id(&id).subnet_id(&subnets[1].0).send().await.unwrap();

    let e = efs.describe_mount_targets().send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "BadRequest");
    wait_mount_targets(&efs, &id).await;
    let d = efs.describe_mount_targets().file_system_id(&id).send().await.unwrap();
    assert_eq!(d.mount_targets().len(), 2);
    assert!(d.mount_targets().iter().all(|m| m.life_cycle_state().as_str() == "available"));
    let d = efs.describe_mount_targets().mount_target_id(&mt_id).send().await.unwrap();
    assert_eq!(d.mount_targets().len(), 1);
    let fsd = efs.describe_file_systems().file_system_id(&id).send().await.unwrap();
    assert_eq!(fsd.file_systems()[0].number_of_mount_targets(), 2);

    let groups =
        efs.describe_mount_target_security_groups().mount_target_id(mt2.mount_target_id()).send().await.unwrap();
    assert!(groups.security_groups()[0].starts_with("sg-"));
    efs.modify_mount_target_security_groups()
        .mount_target_id(mt2.mount_target_id())
        .security_groups(&sg)
        .send()
        .await
        .unwrap();
    let groups =
        efs.describe_mount_target_security_groups().mount_target_id(mt2.mount_target_id()).send().await.unwrap();
    assert_eq!(groups.security_groups(), std::slice::from_ref(&sg));

    // Access points.
    let ap = efs
        .create_access_point()
        .file_system_id(&id)
        .client_token("ap-1")
        .posix_user(PosixUser::builder().uid(1000).gid(1000).build().unwrap())
        .root_directory(
            RootDirectory::builder()
                .path("/apps/one")
                .creation_info(
                    CreationInfo::builder().owner_uid(1000).owner_gid(1000).permissions("750").build().unwrap(),
                )
                .build(),
        )
        .tags(tag("Name", "one"))
        .send()
        .await
        .unwrap();
    let ap_id = ap.access_point_id().unwrap().to_string();
    assert!(ap_id.starts_with("fsap-"));
    assert_eq!(ap.life_cycle_state().map(|s| s.as_str()), Some("creating"));
    assert_eq!(ap.name(), Some("one"));
    let e = efs
        .create_access_point()
        .file_system_id(&id)
        .client_token("ap-1")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "AccessPointAlreadyExists");
    let aws_sdk_efs::operation::create_access_point::CreateAccessPointError::AccessPointAlreadyExists(exists) = &e
    else {
        panic!("{e:?}")
    };
    assert_eq!(exists.access_point_id(), ap_id);
    efs.create_access_point().file_system_id(&id).client_token("ap-2").send().await.unwrap();
    let aps = efs.describe_access_points().file_system_id(&id).send().await.unwrap();
    assert_eq!(aps.access_points().len(), 2);
    let one = efs.describe_access_points().access_point_id(&ap_id).send().await.unwrap();
    assert_eq!(one.access_points()[0].root_directory().unwrap().path(), Some("/apps/one"));
    let by_ap = efs.describe_mount_targets().access_point_id(&ap_id).send().await.unwrap();
    assert_eq!(by_ap.mount_targets().len(), 2);
    let t = efs.list_tags_for_resource().resource_id(&ap_id).send().await.unwrap();
    assert_eq!(t.tags()[0].value(), "one");
    efs.delete_access_point().access_point_id(&ap_id).send().await.unwrap();
    let e = efs.describe_access_points().access_point_id(&ap_id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "AccessPointNotFound");

    // A file system with mount targets cannot be deleted.
    let e = efs.delete_file_system().file_system_id(&id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "FileSystemInUse");
    efs.delete_mount_target().mount_target_id(&mt_id).send().await.unwrap();
    efs.delete_mount_target().mount_target_id(mt2.mount_target_id()).send().await.unwrap();
    let n = ec2.describe_network_interfaces().filters(filter("network-interface-id", &eni)).send().await.unwrap();
    assert!(n.network_interfaces().is_empty());
    let e = efs.describe_mount_targets().mount_target_id(&mt_id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "MountTargetNotFound");
    efs.delete_file_system().file_system_id(&id).send().await.unwrap();
}

/// Ask MWS for a mount the way the mount helper on an instance does.
async fn mount(mws: &Mws, instance: &str, fs_type: &str, source: &str, options: &str) -> BTreeMap<String, String> {
    let q: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("instance", instance)
        .append_pair("type", fs_type)
        .append_pair("source", source)
        .append_pair("options", options)
        .finish();
    let (status, _, body) = mws.raw("GET", &format!("/_aws/efs/mount?{q}"), &[], b"").await;
    assert_eq!(status, 200);
    String::from_utf8(body)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

async fn running_instance(ec2: &aws_sdk_ec2::Client, subnet: &str, sg: &str) -> String {
    let images = ec2.describe_images().owners("amazon").filters(filter("name", "mws-alpine-*")).send().await.unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let run = ec2
        .run_instances()
        .image_id(ami)
        .instance_type(aws_sdk_ec2::types::InstanceType::T3Nano)
        .subnet_id(subnet)
        .security_group_ids(sg)
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let id = run.instances()[0].instance_id().unwrap().to_string();
    wait_running(ec2, &id).await;
    id
}

async fn wait_running(ec2: &aws_sdk_ec2::Client, id: &str) {
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().unwrap().name() == Some(&InstanceStateName::Running) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("instance {id} never ran");
}

#[tokio::test]
async fn mounts_follow_the_network_and_the_file_system_policy() {
    let mws = Mws::start().await;
    let (efs, ec2) = clients(&mws).await;
    let subnets = default_subnets(&ec2).await;
    let vpc = ec2.describe_vpcs().filters(filter("isDefault", "true")).send().await.unwrap().vpcs()[0]
        .vpc_id()
        .unwrap()
        .to_string();
    let group = |name: &'static str| {
        let ec2 = ec2.clone();
        let vpc = vpc.clone();
        async move {
            ec2.create_security_group()
                .group_name(name)
                .description(name)
                .vpc_id(vpc)
                .send()
                .await
                .unwrap()
                .group_id()
                .unwrap()
                .to_string()
        }
    };
    let client_sg = group("client").await;
    let nfs_sg = group("nfs").await;
    let instance = running_instance(&ec2, &subnets[0].0, &client_sg).await;

    let fs = efs.create_file_system().creation_token("mounts").send().await.unwrap();
    let id = fs.file_system_id().to_string();
    wait_file_system(&efs, &id).await;
    let dns = format!("{id}.efs.us-east-1.amazonaws.com");

    // No mount target yet: the name does not resolve.
    let r = mount(&mws, &instance, "nfs4", &format!("{dns}:/"), "nfsvers=4.1").await;
    assert!(r["error"].contains("Failed to resolve server"), "{r:?}");
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "tls").await;
    assert!(r["error"].contains("Failed to resolve"), "{r:?}");

    // A mount target in another zone: the zonal DNS name still does not
    // resolve here, but the mount helper falls back to it. Its group lets
    // nothing in yet, so the connection times out.
    let mt = efs
        .create_mount_target()
        .file_system_id(&id)
        .subnet_id(&subnets[1].0)
        .security_groups(&nfs_sg)
        .send()
        .await
        .unwrap();
    // Until the mount target is available, nothing resolves.
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "tls").await;
    assert!(r["error"].contains("Failed to resolve"), "{r:?}");
    wait_mount_targets(&efs, &id).await;
    let r = mount(&mws, &instance, "nfs4", &format!("{dns}:/"), "").await;
    assert!(r["error"].contains("Failed to resolve server"), "{r:?}");
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "tls").await;
    assert_eq!(r["error"], "mount.nfs4: Connection timed out");

    // Allow NFS from the client's security group.
    ec2.authorize_security_group_ingress()
        .group_id(&nfs_sg)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(2049)
                .to_port(2049)
                .user_id_group_pairs(UserIdGroupPair::builder().group_id(&client_sg).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "tls").await;
    assert_eq!(r.get("error"), None, "{r:?}");
    assert_eq!(r["dir"], id);
    assert_eq!(r["readonly"], "0");
    assert_eq!(r["mount_target"], mt.mount_target_id());
    // By the mount target's address, too.
    let r = mount(&mws, &instance, "nfs4", &format!("{}:/", mt.ip_address().unwrap()), "").await;
    assert_eq!(r["dir"], id);
    // A path that is not there.
    let r = mount(&mws, &instance, "efs", &format!("{id}:/missing"), "tls").await;
    assert!(r["error"].contains("No such file or directory"), "{r:?}");
    std::fs::create_dir_all(data_dir(&id).join("exports/a")).unwrap();
    let r = mount(&mws, &instance, "efs", &format!("{id}:/exports/a"), "").await;
    assert_eq!(r["dir"], format!("{id}/exports/a"));

    // Access points create their root directory on first mount, and need
    // TLS with the mount helper.
    let ap = efs
        .create_access_point()
        .file_system_id(&id)
        .client_token("app")
        .root_directory(
            RootDirectory::builder()
                .path("/app")
                .creation_info(
                    CreationInfo::builder().owner_uid(1001).owner_gid(1002).permissions("0750").build().unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let ap_id = ap.access_point_id().unwrap();
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), &format!("accesspoint={ap_id}")).await;
    assert_eq!(r["error"], "The 'accesspoint' option requires the 'tls' option.");
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), &format!("tls,accesspoint={ap_id}")).await;
    assert_eq!(r["dir"], format!("{id}/app"));
    assert_eq!(r["chown"], "1001:1002");
    assert!(data_dir(&id).join("app").is_dir());

    // A file system policy that only grants ClientMount to the instance
    // role makes anonymous mounts fail and IAM mounts read-only.
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("efs-client").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    iam.create_instance_profile().instance_profile_name("efs-client").send().await.unwrap();
    iam.add_role_to_instance_profile()
        .instance_profile_name("efs-client")
        .role_name("efs-client")
        .send()
        .await
        .unwrap();
    ec2.associate_iam_instance_profile()
        .instance_id(&instance)
        .iam_instance_profile(aws_sdk_ec2::types::IamInstanceProfileSpecification::builder().name("efs-client").build())
        .send()
        .await
        .unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{role_arn}"}},"Action":"elasticfilesystem:ClientMount","Resource":"*","Condition":{{"Bool":{{"aws:SecureTransport":"true"}}}}}}]}}"#
    );
    efs.put_file_system_policy().file_system_id(&id).policy(policy).send().await.unwrap();
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "tls").await;
    assert!(r["error"].contains("access denied by server"), "{r:?}");
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "tls,iam").await;
    assert_eq!(r.get("error"), None, "{r:?}");
    assert_eq!(r["readonly"], "1");
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "iam").await;
    assert_eq!(r["error"], "The 'iam' option requires the 'tls' option.");

    // Stopped instances mount nothing.
    ec2.stop_instances().instance_ids(&instance).send().await.unwrap();
    for _ in 0..40 {
        let d = ec2.describe_instances().instance_ids(&instance).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().unwrap().name() == Some(&InstanceStateName::Stopped) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let r = mount(&mws, &instance, "efs", &format!("{id}:/"), "tls,iam").await;
    assert_eq!(r["error"], "mount.nfs4: Connection timed out");
}

#[tokio::test]
async fn replication_copies_data_to_a_read_only_destination() {
    let mws = Mws::start().await;
    let (efs, _) = clients(&mws).await;
    let fs = efs.create_file_system().creation_token("repl-src").send().await.unwrap();
    let id = fs.file_system_id().to_string();
    wait_file_system(&efs, &id).await;
    std::fs::create_dir_all(data_dir(&id).join("data")).unwrap();
    std::fs::write(data_dir(&id).join("data/one.txt"), "one").unwrap();

    let c = efs
        .create_replication_configuration()
        .source_file_system_id(&id)
        .destinations(DestinationToCreate::builder().region("us-west-2").build())
        .send()
        .await
        .unwrap();
    assert_eq!(c.source_file_system_id(), id);
    assert_eq!(c.source_file_system_region(), "us-east-1");
    let dest = c.destinations()[0].file_system_id().to_string();
    assert_eq!(c.destinations()[0].region(), "us-west-2");
    assert_eq!(std::fs::read_to_string(data_dir(&dest).join("data/one.txt")).unwrap(), "one");
    let e = efs
        .create_replication_configuration()
        .source_file_system_id(&id)
        .destinations(DestinationToCreate::builder().region("eu-west-1").build())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "ReplicationAlreadyExists");

    // The destination lives in its Region, protected while it replicates.
    let west = Client::from_conf(
        aws_sdk_efs::config::Builder::from(&mws.root_sdk_config().await)
            .region(aws_sdk_efs::config::Region::new("us-west-2"))
            .build(),
    );
    let d = west.describe_file_systems().file_system_id(&dest).send().await.unwrap();
    assert_eq!(
        d.file_systems()[0].file_system_protection().unwrap().replication_overwrite_protection(),
        Some(&ReplicationOverwriteProtection::Replicating)
    );

    // Describing brings the destination up to date.
    std::fs::write(data_dir(&id).join("data/two.txt"), "two").unwrap();
    let r = efs.describe_replication_configurations().file_system_id(&id).send().await.unwrap();
    assert_eq!(r.replications()[0].destinations()[0].status().as_str(), "ENABLED");
    assert!(r.replications()[0].destinations()[0].last_replicated_timestamp().is_some());
    assert_eq!(std::fs::read_to_string(data_dir(&dest).join("data/two.txt")).unwrap(), "two");
    let r = west.describe_replication_configurations().send().await.unwrap();
    assert_eq!(r.replications().len(), 1);

    let e = efs.delete_file_system().file_system_id(&id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "FileSystemInUse");
    efs.delete_replication_configuration().source_file_system_id(&id).send().await.unwrap();
    let e =
        efs.describe_replication_configurations().file_system_id(&id).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "ReplicationNotFound");
    let d = west.describe_file_systems().file_system_id(&dest).send().await.unwrap();
    assert_eq!(
        d.file_systems()[0].file_system_protection().unwrap().replication_overwrite_protection(),
        Some(&ReplicationOverwriteProtection::Enabled)
    );
    efs.delete_file_system().file_system_id(&id).send().await.unwrap();
    west.delete_file_system().file_system_id(&dest).send().await.unwrap();
}

#[tokio::test]
async fn calls_are_authorized_with_tags() {
    let mws = Mws::start().await;
    let (efs, _) = clients(&mws).await;
    let a = efs.create_file_system().creation_token("a").tags(tag("team", "a")).send().await.unwrap();
    let b = efs.create_file_system().creation_token("b").tags(tag("team", "b")).send().await.unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"elasticfilesystem:DescribeFileSystems","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"a"}}},
        {"Effect":"Allow","Action":"elasticfilesystem:CreateFileSystem","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"a"}}},
        {"Effect":"Allow","Action":"elasticfilesystem:TagResource","Resource":"*","Condition":{"StringEquals":{"elasticfilesystem:CreateAction":"CreateFileSystem"}}}
    ]}"#;
    let (_, conf) = user_with_policy(&mws, "efs-user", Some(policy)).await;
    let user = Client::new(&conf);
    user.describe_file_systems().file_system_id(a.file_system_id()).send().await.unwrap();
    let e =
        user.describe_file_systems().file_system_id(b.file_system_id()).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "AccessDeniedException");
    let e = user.create_file_system().creation_token("c").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "AccessDeniedException");
    user.create_file_system().creation_token("c").tags(tag("team", "a")).send().await.unwrap();
    let e = user.delete_file_system().file_system_id(a.file_system_id()).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "AccessDeniedException");
}

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[tokio::test]
async fn instances_mount_and_share_a_file_system() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_on_all_interfaces(config).await;
    let (efs, ec2) = clients(&mws).await;
    let subnets = default_subnets(&ec2).await;
    let vpc = ec2.describe_vpcs().filters(filter("isDefault", "true")).send().await.unwrap().vpcs()[0]
        .vpc_id()
        .unwrap()
        .to_string();
    let sg = ec2.create_security_group().group_name("nfs").description("nfs").vpc_id(&vpc).send().await.unwrap();
    let sg = sg.group_id().unwrap().to_string();
    ec2.authorize_security_group_ingress()
        .group_id(&sg)
        .ip_protocol("tcp")
        .from_port(2049)
        .to_port(2049)
        .cidr_ip("172.31.0.0/16")
        .send()
        .await
        .unwrap();
    let fs = efs.create_file_system().creation_token("docker").send().await.unwrap();
    let id = fs.file_system_id().to_string();
    wait_file_system(&efs, &id).await;
    efs.create_mount_target().file_system_id(&id).subnet_id(&subnets[0].0).security_groups(&sg).send().await.unwrap();
    wait_mount_targets(&efs, &id).await;

    use base64::Engine;
    // The usual user data: mount with the NFS client and write a file.
    // An access point for the app's own directory, mounted from /etc/fstab.
    let ap = efs
        .create_access_point()
        .file_system_id(&id)
        .client_token("app")
        .root_directory(
            RootDirectory::builder()
                .path("/app")
                .creation_info(
                    CreationInfo::builder().owner_uid(1000).owner_gid(1000).permissions("755").build().unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let ap_id = ap.access_point_id().unwrap().to_string();
    // The usual user data: mount with the NFS client and write a file, and
    // an fstab entry through the EFS mount helper with `mount -a`.
    let script = format!(
        "#!/bin/sh\nmkdir -p /mnt/efs /mnt/app\nmount -t nfs4 -o nfsvers=4.1,rsize=1048576,hard,timeo=600 {id}.efs.us-east-1.amazonaws.com:/ /mnt/efs && echo \"hello from $(hostname)\" > /mnt/efs/hello.txt\necho '{id}:/ /mnt/app efs _netdev,tls,accesspoint={ap_id} 0 0' >> /etc/fstab\nmount -a && echo app > /mnt/app/app.txt\n"
    );
    let images = ec2.describe_images().owners("amazon").filters(filter("name", "mws-alpine-*")).send().await.unwrap();
    let ami = images.images()[0].image_id().unwrap().to_string();
    let run = ec2
        .run_instances()
        .image_id(&ami)
        .instance_type(aws_sdk_ec2::types::InstanceType::T3Nano)
        .subnet_id(&subnets[0].0)
        .user_data(base64::engine::general_purpose::STANDARD.encode(script))
        .min_count(1)
        .max_count(1)
        .send()
        .await
        .unwrap();
    let instance = run.instances()[0].instance_id().unwrap().to_string();
    wait_running(&ec2, &instance).await;
    let hello = data_dir(&id).join("hello.txt");
    let mut console = String::new();
    for _ in 0..120 {
        if hello.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let out = ec2.get_console_output().instance_id(&instance).send().await.unwrap();
        console = out
            .output()
            .map(|o| {
                String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(o).unwrap()).into_owned()
            })
            .unwrap_or_default();
    }
    let content = std::fs::read_to_string(&hello).unwrap_or_else(|_| panic!("no file written; console: {console}"));
    assert!(content.starts_with("hello from "), "{content}");
    let app = data_dir(&id).join("app/app.txt");
    for _ in 0..40 {
        if app.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(std::fs::read_to_string(&app).unwrap_or_else(|_| panic!("no app file; console: {console}")), "app\n");
    ec2.terminate_instances().instance_ids(&instance).send().await.unwrap();
}
