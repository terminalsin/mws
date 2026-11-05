//! RDS and Aurora through the official Rust SDK, with the metadata-only
//! backend (see `rds_docker` for databases that really run).

use std::time::Duration;

use aws_sdk_rds::error::ProvideErrorMetadata;
use aws_sdk_rds::types::{
    ApplyMethod, CloudwatchLogsExportConfiguration, Filter, Parameter, ServerlessV2ScalingConfiguration, Tag,
};
use aws_sdk_rds::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

/// Run a test body with room on the stack: the SDK's (debug-built) RDS
/// deserializers need more than a test thread's 2 MiB.
pub(crate) fn run<F: std::future::Future<Output = ()> + Send + 'static>(body: F) {
    let thread = std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 << 20)
                .build()
                .unwrap()
                .block_on(body)
        })
        .unwrap();
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

fn tag(k: &str, v: &str) -> Tag {
    Tag::builder().key(k).value(v).build()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
}

/// The default VPC's subnets, as EC2 reports them.
async fn default_subnets(mws: &Mws) -> Vec<(String, String)> {
    let ec2 = aws_sdk_ec2::Client::new(&mws.root_sdk_config().await);
    let out = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    out.subnets()
        .iter()
        .map(|s| (s.subnet_id().unwrap().to_string(), s.availability_zone().unwrap().to_string()))
        .collect()
}

async fn create_postgres(rds: &Client, id: &str) -> aws_sdk_rds::types::DbInstance {
    rds.create_db_instance()
        .db_instance_identifier(id)
        .engine("postgres")
        .engine_version("16")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("correct-horse-battery")
        .db_name("registry")
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap()
}

async fn eventually<T, F, Fut>(secs: u64, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(std::time::Instant::now() < deadline, "timed out waiting");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[test]
fn postgres_instance_lifecycle() {
    run(postgres_instance_lifecycle_body());
}

async fn postgres_instance_lifecycle_body() {
    let mws = Mws::start().await;
    let rds = client(&mws).await;

    let created = rds
        .create_db_instance()
        .db_instance_identifier("Harbor-DB")
        .engine("postgres")
        .engine_version("16")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("correct-horse-battery")
        .db_name("registry")
        .tags(tag("app", "harbor"))
        .copy_tags_to_snapshot(true)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    // Identifiers are stored in lower case.
    assert_eq!(created.db_instance_identifier(), Some("harbor-db"));
    assert_eq!(created.db_instance_status(), Some("creating"));
    assert_eq!(created.engine_version(), Some("16.8"));
    assert_eq!(created.db_instance_arn(), Some(format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:harbor-db").as_str()));
    assert!(created.dbi_resource_id().unwrap().starts_with("db-"));
    assert_eq!(created.db_parameter_groups()[0].db_parameter_group_name(), Some("default.postgres16"));
    assert_eq!(created.option_group_memberships()[0].option_group_name(), Some("default:postgres-16"));
    assert_eq!(created.storage_type(), Some("gp3"));
    assert_eq!(created.ca_certificate_identifier(), Some("rds-ca-rsa2048-g1"));
    let subnets = default_subnets(&mws).await;
    assert!(created.db_subnet_group().unwrap().vpc_id().unwrap().starts_with("vpc-"));
    assert_eq!(created.db_subnet_group().unwrap().subnets().len(), subnets.len());

    let d = rds.describe_db_instances().db_instance_identifier("harbor-db").send().await.unwrap();
    let db = &d.db_instances()[0];
    assert_eq!(db.db_instance_status(), Some("available"));
    let endpoint = db.endpoint().unwrap();
    assert_eq!(endpoint.port(), Some(5432));
    assert!(endpoint.address().unwrap().starts_with("harbor-db."));
    assert!(endpoint.address().unwrap().ends_with(".us-east-1.rds.amazonaws.com"));
    assert_eq!(db.tag_list()[0].key(), Some("app"));
    // An automated snapshot is taken when the instance becomes available.
    let auto = rds
        .describe_db_snapshots()
        .db_instance_identifier("harbor-db")
        .snapshot_type("automated")
        .send()
        .await
        .unwrap();
    assert_eq!(auto.db_snapshots().len(), 1);
    assert!(auto.db_snapshots()[0].db_snapshot_identifier().unwrap().starts_with("rds:harbor-db-"));

    let dup = rds
        .create_db_instance()
        .db_instance_identifier("harbor-db")
        .engine("postgres")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "DBInstanceAlreadyExists");
    let short = rds
        .create_db_instance()
        .db_instance_identifier("short-pw")
        .engine("postgres")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("short")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&short), "InvalidParameterValue");
    assert!(message(&short).contains("shorter than 8 characters"));
    let version = rds
        .create_db_instance()
        .db_instance_identifier("old")
        .engine("postgres")
        .engine_version("9.6")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&version), "InvalidParameterCombination");
    assert_eq!(message(&version), "Cannot find version 9.6 for postgres");
    let serverless = rds
        .create_db_instance()
        .db_instance_identifier("sv2")
        .engine("postgres")
        .db_instance_class("db.serverless")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&serverless), "InvalidParameterCombination");
    let missing = rds.describe_db_instances().db_instance_identifier("nope").send().await.unwrap_err();
    assert_eq!(code(&missing), "DBInstanceNotFound");
    assert_eq!(message(&missing), "DBInstance nope not found.");

    // Modify: pending until applied, or at once with ApplyImmediately.
    let m = rds
        .modify_db_instance()
        .db_instance_identifier("harbor-db")
        .db_instance_class("db.t3.small")
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(m.db_instance_class(), Some("db.t3.micro"));
    assert_eq!(m.pending_modified_values().unwrap().db_instance_class(), Some("db.t3.small"));
    let m = rds
        .modify_db_instance()
        .db_instance_identifier("harbor-db")
        .allocated_storage(50)
        .backup_retention_period(7)
        .deletion_protection(true)
        .cloudwatch_logs_export_configuration(
            CloudwatchLogsExportConfiguration::builder().enable_log_types("postgresql").build(),
        )
        .apply_immediately(true)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(m.allocated_storage(), Some(50));
    assert_eq!(m.backup_retention_period(), Some(7));
    assert_eq!(m.enabled_cloudwatch_logs_exports(), ["postgresql"]);
    let shrink =
        rds.modify_db_instance().db_instance_identifier("harbor-db").allocated_storage(30).send().await.unwrap_err();
    assert_eq!(code(&shrink), "InvalidParameterValue");
    let protected = rds
        .delete_db_instance()
        .db_instance_identifier("harbor-db")
        .skip_final_snapshot(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&protected), "InvalidParameterCombination");
    let valid =
        rds.describe_valid_db_instance_modifications().db_instance_identifier("harbor-db").send().await.unwrap();
    let storage = valid.valid_db_instance_modifications_message().unwrap().storage();
    assert!(storage.iter().any(|s| s.storage_type() == Some("io2")));
    assert_eq!(storage[0].storage_size()[0].from(), Some(50));

    // Reboot, stop and start.
    let r = rds.reboot_db_instance().db_instance_identifier("harbor-db").send().await.unwrap();
    assert_eq!(r.db_instance().unwrap().db_instance_status(), Some("rebooting"));
    let failover =
        rds.reboot_db_instance().db_instance_identifier("harbor-db").force_failover(true).send().await.unwrap_err();
    assert_eq!(code(&failover), "InvalidParameterCombination");
    let s = rds.stop_db_instance().db_instance_identifier("harbor-db").send().await.unwrap();
    assert_eq!(s.db_instance().unwrap().db_instance_status(), Some("stopping"));
    let d = rds.describe_db_instances().db_instance_identifier("harbor-db").send().await.unwrap();
    assert_eq!(d.db_instances()[0].db_instance_status(), Some("stopped"));
    assert!(d.db_instances()[0].automatic_restart_time().is_some());
    let stopped = rds.reboot_db_instance().db_instance_identifier("harbor-db").send().await.unwrap_err();
    assert_eq!(code(&stopped), "InvalidDBInstanceState");
    rds.start_db_instance().db_instance_identifier("harbor-db").send().await.unwrap();
    let again = rds.start_db_instance().db_instance_identifier("harbor-db").send().await.unwrap_err();
    assert_eq!(code(&again), "InvalidDBInstanceState");

    // Manual snapshots copy the instance's tags.
    let snap = rds
        .create_db_snapshot()
        .db_instance_identifier("harbor-db")
        .db_snapshot_identifier("before-upgrade")
        .send()
        .await
        .unwrap()
        .db_snapshot
        .unwrap();
    assert_eq!(snap.snapshot_type(), Some("manual"));
    assert_eq!(snap.tag_list()[0].value(), Some("harbor"));
    assert_eq!(
        snap.db_snapshot_arn(),
        Some(format!("arn:aws:rds:us-east-1:{ACCOUNT}:snapshot:before-upgrade").as_str())
    );
    let taken = rds
        .create_db_snapshot()
        .db_instance_identifier("harbor-db")
        .db_snapshot_identifier("before-upgrade")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&taken), "DBSnapshotAlreadyExists");
    let copy = rds
        .copy_db_snapshot()
        .source_db_snapshot_identifier("before-upgrade")
        .target_db_snapshot_identifier("copy-1")
        .copy_tags(true)
        .send()
        .await
        .unwrap()
        .db_snapshot
        .unwrap();
    assert_eq!(copy.source_db_snapshot_identifier(), snap.db_snapshot_arn());
    let listed = rds.describe_db_snapshots().snapshot_type("manual").send().await.unwrap();
    assert_eq!(listed.db_snapshots().len(), 2);
    let filtered = rds.describe_db_snapshots().filters(filter("db-snapshot-id", "copy-1")).send().await.unwrap();
    assert_eq!(filtered.db_snapshots().len(), 1);
    let modified =
        rds.modify_db_snapshot().db_snapshot_identifier("copy-1").engine_version("16.8").send().await.unwrap();
    assert_eq!(modified.db_snapshot().unwrap().engine_version(), Some("16.8"));
    let shared = rds
        .modify_db_snapshot_attribute()
        .db_snapshot_identifier("copy-1")
        .attribute_name("restore")
        .values_to_add("210987654321")
        .send()
        .await
        .unwrap();
    let attrs = shared.db_snapshot_attributes_result().unwrap().db_snapshot_attributes();
    assert_eq!(attrs[0].attribute_values(), ["210987654321"]);
    let attrs = rds.describe_db_snapshot_attributes().db_snapshot_identifier("copy-1").send().await.unwrap();
    assert_eq!(
        attrs.db_snapshot_attributes_result().unwrap().db_snapshot_attributes()[0].attribute_name(),
        Some("restore")
    );
    let bad = rds
        .modify_db_snapshot_attribute()
        .db_snapshot_identifier("copy-1")
        .attribute_name("restore")
        .values_to_add("abc")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad), "InvalidParameterValue");
    let auto_share = rds
        .modify_db_snapshot_attribute()
        .db_snapshot_identifier(auto.db_snapshots()[0].db_snapshot_identifier().unwrap())
        .attribute_name("restore")
        .values_to_add("all")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&auto_share), "InvalidDBSnapshotState");

    // Restores.
    let restored = rds
        .restore_db_instance_from_db_snapshot()
        .db_instance_identifier("harbor-restored")
        .db_snapshot_identifier("before-upgrade")
        .db_instance_class("db.t3.medium")
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(restored.db_name(), Some("registry"));
    assert_eq!(restored.master_username(), Some("harbor"));
    assert_eq!(restored.allocated_storage(), Some(50));
    let pitr = rds
        .restore_db_instance_to_point_in_time()
        .source_db_instance_identifier("harbor-db")
        .target_db_instance_identifier("harbor-pitr")
        .use_latest_restorable_time(true)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(pitr.engine(), Some("postgres"));
    let both = rds
        .restore_db_instance_to_point_in_time()
        .source_db_instance_identifier("harbor-db")
        .target_db_instance_identifier("harbor-pitr2")
        .use_latest_restorable_time(true)
        .restore_time(aws_sdk_rds::primitives::DateTime::from_secs(1))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&both), "InvalidParameterCombination");
    let early = rds
        .restore_db_instance_to_point_in_time()
        .source_db_instance_identifier("harbor-db")
        .target_db_instance_identifier("harbor-pitr2")
        .restore_time(aws_sdk_rds::primitives::DateTime::from_secs(1))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&early), "PointInTimeRestoreNotEnabled");

    // Read replicas, then promotion.
    let replica = rds
        .create_db_instance_read_replica()
        .db_instance_identifier("harbor-replica")
        .source_db_instance_identifier("harbor-db")
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(replica.read_replica_source_db_instance_identifier(), Some("harbor-db"));
    assert_eq!(replica.status_infos()[0].status(), Some("replicating"));
    let source = rds.describe_db_instances().db_instance_identifier("harbor-db").send().await.unwrap();
    assert_eq!(source.db_instances()[0].read_replica_db_instance_identifiers(), ["harbor-replica"]);
    let has_replica = rds.stop_db_instance().db_instance_identifier("harbor-db").send().await.unwrap_err();
    assert_eq!(code(&has_replica), "InvalidDBInstanceState");
    let promoted = rds.promote_read_replica().db_instance_identifier("harbor-replica").send().await.unwrap();
    assert!(promoted.db_instance().unwrap().read_replica_source_db_instance_identifier().is_none());
    let not_replica = rds.promote_read_replica().db_instance_identifier("harbor-replica").send().await.unwrap_err();
    assert_eq!(code(&not_replica), "InvalidDBInstanceState");

    // IAM roles for features such as S3 import.
    let role = format!("arn:aws:iam::{ACCOUNT}:role/rds-s3");
    rds.add_role_to_db_instance()
        .db_instance_identifier("harbor-db")
        .role_arn(&role)
        .feature_name("s3Import")
        .send()
        .await
        .unwrap();
    let dup = rds
        .add_role_to_db_instance()
        .db_instance_identifier("harbor-db")
        .role_arn(&role)
        .feature_name("s3Import")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "DBInstanceRoleAlreadyExists");
    let d = rds.describe_db_instances().db_instance_identifier("harbor-db").send().await.unwrap();
    assert_eq!(d.db_instances()[0].associated_roles()[0].status(), Some("ACTIVE"));
    rds.remove_role_from_db_instance()
        .db_instance_identifier("harbor-db")
        .role_arn(&role)
        .feature_name("s3Import")
        .send()
        .await
        .unwrap();
    let gone = rds
        .remove_role_from_db_instance()
        .db_instance_identifier("harbor-db")
        .role_arn(&role)
        .feature_name("s3Import")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&gone), "DBInstanceRoleNotFound");

    // Log files (empty without a running database).
    let logs = rds.describe_db_log_files().db_instance_identifier("harbor-db").send().await.unwrap();
    assert_eq!(logs.describe_db_log_files()[0].log_file_name(), Some("error/postgresql.log"));
    let portion = rds
        .download_db_log_file_portion()
        .db_instance_identifier("harbor-db")
        .log_file_name("error/postgresql.log")
        .send()
        .await
        .unwrap();
    assert_eq!(portion.additional_data_pending(), Some(false));
    let no_file = rds
        .download_db_log_file_portion()
        .db_instance_identifier("harbor-db")
        .log_file_name("error/other.log")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&no_file), "DBLogFileNotFoundFault");

    // Rename with ApplyImmediately.
    let renamed = rds
        .modify_db_instance()
        .db_instance_identifier("harbor-restored")
        .new_db_instance_identifier("harbor-two")
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    assert_eq!(renamed.db_instance().unwrap().db_instance_identifier(), Some("harbor-two"));
    assert!(rds.describe_db_instances().db_instance_identifier("harbor-restored").send().await.is_err());

    // Delete: a final snapshot is required unless skipped; automated
    // backups can be kept.
    let needs = rds.delete_db_instance().db_instance_identifier("harbor-two").send().await.unwrap_err();
    assert_eq!(code(&needs), "InvalidParameterCombination");
    let deleted = rds
        .delete_db_instance()
        .db_instance_identifier("harbor-two")
        .final_db_snapshot_identifier("harbor-two-final")
        .delete_automated_backups(false)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.db_instance().unwrap().db_instance_status(), Some("deleting"));
    let final_snap = rds.describe_db_snapshots().db_snapshot_identifier("harbor-two-final").send().await.unwrap();
    assert_eq!(final_snap.db_snapshots()[0].status(), Some("available"));
    let backups = rds.describe_db_instance_automated_backups().send().await.unwrap();
    let retained: Vec<_> =
        backups.db_instance_automated_backups().iter().filter(|b| b.status() == Some("retained")).collect();
    assert_eq!(retained.len(), 1);
    let resource = retained[0].dbi_resource_id().unwrap().to_string();
    let live = backups.db_instance_automated_backups().iter().find(|b| b.status() == Some("active")).unwrap();
    let in_use = rds
        .delete_db_instance_automated_backup()
        .dbi_resource_id(live.dbi_resource_id().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&in_use), "InvalidDBInstanceAutomatedBackupState");
    let removed = rds.delete_db_instance_automated_backup().dbi_resource_id(&resource).send().await.unwrap();
    assert_eq!(removed.db_instance_automated_backup().unwrap().status(), Some("deleting"));
    rds.delete_db_snapshot().db_snapshot_identifier("copy-1").send().await.unwrap();
    let auto_delete = rds
        .delete_db_snapshot()
        .db_snapshot_identifier(auto.db_snapshots()[0].db_snapshot_identifier().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&auto_delete), "InvalidDBSnapshotState");
    rds.delete_db_instance().db_instance_identifier("harbor-pitr").skip_final_snapshot(true).send().await.unwrap();
    let left = rds.describe_db_instances().send().await.unwrap();
    let mut ids: Vec<_> = left.db_instances().iter().filter_map(|d| d.db_instance_identifier()).collect();
    ids.sort();
    assert_eq!(ids, ["harbor-db", "harbor-replica"]);
}

#[test]
fn managed_master_passwords_and_encryption() {
    run(managed_master_passwords_and_encryption_body());
}

async fn managed_master_passwords_and_encryption_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = Client::new(&config);
    let sm = aws_sdk_secretsmanager::Client::new(&config);
    let kms = aws_sdk_kms::Client::new(&config);

    let key = kms.create_key().description("langfuse").send().await.unwrap();
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();
    let db = rds
        .create_db_instance()
        .db_instance_identifier("langfuse")
        .engine("postgres")
        .db_instance_class("db.t4g.medium")
        .allocated_storage(20)
        .master_username("langfuse")
        .manage_master_user_password(true)
        .storage_encrypted(true)
        .kms_key_id(&key_arn)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(db.storage_encrypted(), Some(true));
    assert_eq!(db.kms_key_id(), Some(key_arn.as_str()));
    let secret = db.master_user_secret().unwrap();
    assert_eq!(secret.secret_status(), Some("active"));
    let secret_arn = secret.secret_arn().unwrap().to_string();
    assert!(secret_arn.contains(":secret:rds!db-"));
    // The secret holds the credentials, owned by RDS.
    let value = sm.get_secret_value().secret_id(&secret_arn).send().await.unwrap();
    let creds: serde_json::Value = serde_json::from_str(value.secret_string().unwrap()).unwrap();
    assert_eq!(creds["username"], "langfuse");
    let first = creds["password"].as_str().unwrap().to_string();
    assert!(first.len() >= 20);
    let described = sm.describe_secret().secret_id(&secret_arn).send().await.unwrap();
    assert_eq!(described.owning_service(), Some("rds"));
    assert_eq!(described.rotation_enabled(), Some(true));
    assert_eq!(described.rotation_rules().unwrap().automatically_after_days(), Some(7));
    assert!(described
        .tags()
        .iter()
        .any(|t| t.key() == Some("aws:rds:primaryDBInstanceArn") && t.value() == db.db_instance_arn()));

    // Rotation from RDS, and from Secrets Manager, both set a new password.
    let pw_and = rds
        .modify_db_instance()
        .db_instance_identifier("langfuse")
        .master_user_password("another-password")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&pw_and), "InvalidParameterCombination");
    rds.modify_db_instance()
        .db_instance_identifier("langfuse")
        .rotate_master_user_password(true)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let value = sm.get_secret_value().secret_id(&secret_arn).send().await.unwrap();
    let creds: serde_json::Value = serde_json::from_str(value.secret_string().unwrap()).unwrap();
    let second = creds["password"].as_str().unwrap().to_string();
    assert_ne!(first, second);
    sm.rotate_secret().secret_id(&secret_arn).send().await.unwrap();
    let value = sm.get_secret_value().secret_id(&secret_arn).send().await.unwrap();
    let creds: serde_json::Value = serde_json::from_str(value.secret_string().unwrap()).unwrap();
    assert_ne!(creds["password"].as_str().unwrap(), second);

    // Turning management off needs a password; the secret is removed.
    let needs = rds
        .modify_db_instance()
        .db_instance_identifier("langfuse")
        .manage_master_user_password(false)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&needs), "InvalidParameterCombination");
    let off = rds
        .modify_db_instance()
        .db_instance_identifier("langfuse")
        .manage_master_user_password(false)
        .master_user_password("now-my-own-password")
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    assert!(off.db_instance().unwrap().master_user_secret().is_none());
    assert!(sm.describe_secret().secret_id(&secret_arn).send().await.is_err());

    // Default encryption uses the aws/rds key; a disabled key is refused.
    let default_key = rds
        .create_db_instance()
        .db_instance_identifier("encrypted-default")
        .engine("mysql")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("admin")
        .master_user_password("correct-horse-battery")
        .storage_encrypted(true)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    let aliases = kms.list_aliases().send().await.unwrap();
    let aws_rds = aliases.aliases().iter().find(|a| a.alias_name() == Some("alias/aws/rds")).unwrap();
    assert!(default_key.kms_key_id().unwrap().ends_with(aws_rds.target_key_id().unwrap()));
    assert_eq!(default_key.engine_version(), Some("8.4.4"));
    assert!(default_key.endpoint().is_none());
    kms.disable_key().key_id(&key_arn).send().await.unwrap();
    let disabled = rds
        .create_db_instance()
        .db_instance_identifier("disabled-key")
        .engine("postgres")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .storage_encrypted(true)
        .kms_key_id(&key_arn)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&disabled), "KMSKeyNotAccessibleFault");
    let key_without = rds
        .create_db_instance()
        .db_instance_identifier("key-without")
        .engine("postgres")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .kms_key_id(&key_arn)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&key_without), "InvalidParameterCombination");

    // Encrypted snapshots carry the key and can't be made public.
    rds.create_db_snapshot()
        .db_instance_identifier("encrypted-default")
        .db_snapshot_identifier("enc")
        .send()
        .await
        .unwrap();
    let public = rds
        .modify_db_snapshot_attribute()
        .db_snapshot_identifier("enc")
        .attribute_name("restore")
        .values_to_add("all")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&public), "InvalidParameterValue");
}

#[test]
fn aurora_postgres_clusters() {
    run(aurora_postgres_clusters_body());
}

async fn aurora_postgres_clusters_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = Client::new(&config);
    let sm = aws_sdk_secretsmanager::Client::new(&config);

    let orphan = rds
        .create_db_instance()
        .db_instance_identifier("orphan")
        .engine("aurora-postgresql")
        .db_instance_class("db.r6g.large")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&orphan), "InvalidParameterValue");
    let cluster = rds
        .create_db_cluster()
        .db_cluster_identifier("langfuse")
        .engine("aurora-postgresql")
        .engine_version("16.8")
        .master_username("langfuse")
        .manage_master_user_password(true)
        .database_name("langfuse")
        .storage_encrypted(true)
        .serverless_v2_scaling_configuration(
            ServerlessV2ScalingConfiguration::builder().min_capacity(0.5).max_capacity(8.0).build(),
        )
        .tags(tag("app", "langfuse"))
        .send()
        .await
        .unwrap()
        .db_cluster
        .unwrap();
    assert_eq!(cluster.status(), Some("creating"));
    assert_eq!(cluster.engine_version(), Some("16.8"));
    assert_eq!(cluster.port(), Some(5432));
    assert_eq!(cluster.db_cluster_parameter_group(), Some("default.aurora-postgresql16"));
    assert_eq!(cluster.storage_type(), Some("aurora"));
    assert!(cluster.endpoint().unwrap().starts_with("langfuse.cluster-"));
    assert!(cluster.reader_endpoint().unwrap().starts_with("langfuse.cluster-ro-"));
    assert_eq!(cluster.availability_zones().len(), 3);
    let secret = cluster.master_user_secret().unwrap().secret_arn().unwrap().to_string();
    assert!(secret.contains(":secret:rds!cluster-"));
    let value = sm.get_secret_value().secret_id(&secret).send().await.unwrap();
    assert!(value.secret_string().unwrap().contains("\"username\":\"langfuse\""));

    // Instances join the cluster; the first is the writer.
    let member_pw = rds
        .create_db_instance()
        .db_instance_identifier("langfuse-1")
        .db_cluster_identifier("langfuse")
        .engine("aurora-postgresql")
        .db_instance_class("db.serverless")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&member_pw), "InvalidParameterCombination");
    assert_eq!(
        message(&member_pw),
        "The requested DB Instance will be a member of a DB Cluster. Set master user password for the DB Cluster."
    );
    for (id, class) in [("langfuse-1", "db.serverless"), ("langfuse-2", "db.r6g.large")] {
        let i = rds
            .create_db_instance()
            .db_instance_identifier(id)
            .db_cluster_identifier("langfuse")
            .engine("aurora-postgresql")
            .db_instance_class(class)
            .send()
            .await
            .unwrap()
            .db_instance
            .unwrap();
        assert_eq!(i.db_cluster_identifier(), Some("langfuse"));
        assert_eq!(i.storage_encrypted(), Some(true));
    }
    let micro = rds
        .create_db_instance()
        .db_instance_identifier("langfuse-3")
        .db_cluster_identifier("langfuse")
        .engine("aurora-postgresql")
        .db_instance_class("db.t3.micro")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&micro), "InvalidParameterCombination");
    let d = rds.describe_db_clusters().db_cluster_identifier("langfuse").send().await.unwrap();
    let c = &d.db_clusters()[0];
    assert_eq!(c.status(), Some("available"));
    let members = c.db_cluster_members();
    assert_eq!(members.len(), 2);
    assert_eq!(
        members.iter().find(|m| m.is_cluster_writer() == Some(true)).unwrap().db_instance_identifier(),
        Some("langfuse-1")
    );
    assert_eq!(c.serverless_v2_scaling_configuration().unwrap().max_capacity(), Some(8.0));
    let i = rds.describe_db_instances().filters(filter("db-cluster-id", "langfuse")).send().await.unwrap();
    assert_eq!(i.db_instances().len(), 2);
    assert!(i.db_instances().iter().all(|d| d.db_instance_status() == Some("available")));
    let snapshot_member = rds
        .create_db_snapshot()
        .db_instance_identifier("langfuse-1")
        .db_snapshot_identifier("member")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&snapshot_member), "InvalidDBInstanceState");

    // Failover moves the writer.
    let f = rds.failover_db_cluster().db_cluster_identifier("langfuse").send().await.unwrap();
    let writer = f
        .db_cluster()
        .unwrap()
        .db_cluster_members()
        .iter()
        .find(|m| m.is_cluster_writer() == Some(true))
        .cloned()
        .unwrap();
    assert_eq!(writer.db_instance_identifier(), Some("langfuse-2"));
    rds.failover_db_cluster()
        .db_cluster_identifier("langfuse")
        .target_db_instance_identifier("langfuse-1")
        .send()
        .await
        .unwrap();

    // Custom endpoints.
    let e = rds
        .create_db_cluster_endpoint()
        .db_cluster_identifier("langfuse")
        .db_cluster_endpoint_identifier("analytics")
        .endpoint_type("READER")
        .static_members("langfuse-2")
        .send()
        .await
        .unwrap();
    assert_eq!(e.custom_endpoint_type(), Some("READER"));
    assert!(e.endpoint().unwrap().starts_with("analytics.cluster-custom-"));
    let not_member = rds
        .create_db_cluster_endpoint()
        .db_cluster_identifier("langfuse")
        .db_cluster_endpoint_identifier("bad")
        .endpoint_type("ANY")
        .static_members("someone-else")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&not_member), "InvalidParameterValue");
    rds.modify_db_cluster_endpoint()
        .db_cluster_endpoint_identifier("analytics")
        .endpoint_type("ANY")
        .send()
        .await
        .unwrap();
    let all = rds.describe_db_cluster_endpoints().db_cluster_identifier("langfuse").send().await.unwrap();
    let kinds: Vec<_> = all.db_cluster_endpoints().iter().filter_map(|e| e.endpoint_type()).collect();
    assert_eq!(kinds, ["WRITER", "READER", "CUSTOM"]);
    let d = rds.describe_db_clusters().db_cluster_identifier("langfuse").send().await.unwrap();
    assert_eq!(d.db_clusters()[0].custom_endpoints().len(), 1);
    rds.delete_db_cluster_endpoint().db_cluster_endpoint_identifier("analytics").send().await.unwrap();
    let gone =
        rds.describe_db_cluster_endpoints().db_cluster_endpoint_identifier("analytics").send().await.unwrap_err();
    assert_eq!(code(&gone), "DBClusterEndpointNotFoundFault");

    // Modify, roles, the Data API endpoint.
    let m = rds
        .modify_db_cluster()
        .db_cluster_identifier("langfuse")
        .backup_retention_period(14)
        .deletion_protection(true)
        .serverless_v2_scaling_configuration(
            ServerlessV2ScalingConfiguration::builder().min_capacity(0.0).max_capacity(16.0).build(),
        )
        .apply_immediately(true)
        .send()
        .await
        .unwrap()
        .db_cluster
        .unwrap();
    assert_eq!(m.backup_retention_period(), Some(14));
    assert_eq!(m.serverless_v2_scaling_configuration().unwrap().seconds_until_auto_pause(), Some(300));
    let bad_capacity = rds
        .modify_db_cluster()
        .db_cluster_identifier("langfuse")
        .serverless_v2_scaling_configuration(
            ServerlessV2ScalingConfiguration::builder().min_capacity(4.0).max_capacity(2.0).build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_capacity), "InvalidParameterValue");
    let role = format!("arn:aws:iam::{ACCOUNT}:role/aurora-s3");
    rds.add_role_to_db_cluster()
        .db_cluster_identifier("langfuse")
        .role_arn(&role)
        .feature_name("s3Export")
        .send()
        .await
        .unwrap();
    let dup = rds.add_role_to_db_cluster().db_cluster_identifier("langfuse").role_arn(&role).send().await.unwrap_err();
    assert_eq!(code(&dup), "DBClusterRoleAlreadyExists");
    rds.remove_role_from_db_cluster().db_cluster_identifier("langfuse").role_arn(&role).send().await.unwrap();
    let cluster_arn = c.db_cluster_arn().unwrap().to_string();
    let on = rds.enable_http_endpoint().resource_arn(&cluster_arn).send().await.unwrap();
    assert_eq!(on.http_endpoint_enabled(), Some(true));
    let off = rds.disable_http_endpoint().resource_arn(&cluster_arn).send().await.unwrap();
    assert_eq!(off.http_endpoint_enabled(), Some(false));

    // Cluster snapshots, copies, sharing and restores.
    let s = rds
        .create_db_cluster_snapshot()
        .db_cluster_identifier("langfuse")
        .db_cluster_snapshot_identifier("langfuse-snap")
        .send()
        .await
        .unwrap()
        .db_cluster_snapshot
        .unwrap();
    assert_eq!(s.status(), Some("available"));
    assert_eq!(s.storage_encrypted(), Some(true));
    rds.copy_db_cluster_snapshot()
        .source_db_cluster_snapshot_identifier("langfuse-snap")
        .target_db_cluster_snapshot_identifier("langfuse-copy")
        .send()
        .await
        .unwrap();
    let listed = rds
        .describe_db_cluster_snapshots()
        .db_cluster_identifier("langfuse")
        .snapshot_type("manual")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.db_cluster_snapshots().len(), 2);
    // The cluster's first automated backup is listed too.
    let all = rds.describe_db_cluster_snapshots().db_cluster_identifier("langfuse").send().await.unwrap();
    assert_eq!(all.db_cluster_snapshots().len(), 3);
    rds.modify_db_cluster_snapshot_attribute()
        .db_cluster_snapshot_identifier("langfuse-copy")
        .attribute_name("restore")
        .values_to_add("210987654321")
        .send()
        .await
        .unwrap();
    let attrs = rds
        .describe_db_cluster_snapshot_attributes()
        .db_cluster_snapshot_identifier("langfuse-copy")
        .send()
        .await
        .unwrap();
    assert_eq!(
        attrs.db_cluster_snapshot_attributes_result().unwrap().db_cluster_snapshot_attributes()[0].attribute_values(),
        ["210987654321"]
    );
    let restored = rds
        .restore_db_cluster_from_snapshot()
        .db_cluster_identifier("langfuse-restored")
        .snapshot_identifier("langfuse-snap")
        .engine("aurora-postgresql")
        .send()
        .await
        .unwrap()
        .db_cluster
        .unwrap();
    assert_eq!(restored.database_name(), Some("langfuse"));
    assert_eq!(restored.master_username(), Some("langfuse"));
    let clone = rds
        .restore_db_cluster_to_point_in_time()
        .db_cluster_identifier("langfuse-clone")
        .source_db_cluster_identifier("langfuse")
        .restore_type("copy-on-write")
        .use_latest_restorable_time(true)
        .send()
        .await
        .unwrap()
        .db_cluster
        .unwrap();
    let source = rds.describe_db_clusters().db_cluster_identifier("langfuse").send().await.unwrap();
    assert_eq!(clone.clone_group_id(), source.db_clusters()[0].clone_group_id());
    rds.delete_db_cluster_snapshot().db_cluster_snapshot_identifier("langfuse-copy").send().await.unwrap();

    // Stop, start, reboot.
    rds.stop_db_cluster().db_cluster_identifier("langfuse").send().await.unwrap();
    let d = rds.describe_db_clusters().db_cluster_identifier("langfuse").send().await.unwrap();
    assert_eq!(d.db_clusters()[0].status(), Some("stopped"));
    let i = rds.describe_db_instances().db_instance_identifier("langfuse-1").send().await.unwrap();
    assert_eq!(i.db_instances()[0].db_instance_status(), Some("stopped"));
    let member_stop = rds.start_db_instance().db_instance_identifier("langfuse-1").send().await.unwrap_err();
    assert_eq!(code(&member_stop), "InvalidParameterCombination");
    rds.start_db_cluster().db_cluster_identifier("langfuse").send().await.unwrap();
    rds.reboot_db_cluster().db_cluster_identifier("langfuse").send().await.unwrap();
    let d = rds.describe_db_clusters().db_cluster_identifier("langfuse").send().await.unwrap();
    assert_eq!(d.db_clusters()[0].status(), Some("available"));

    // Deleting: protection, then members, then the cluster.
    let protected =
        rds.delete_db_cluster().db_cluster_identifier("langfuse").skip_final_snapshot(true).send().await.unwrap_err();
    assert_eq!(code(&protected), "InvalidParameterValue");
    rds.modify_db_cluster().db_cluster_identifier("langfuse").deletion_protection(false).send().await.unwrap();
    let busy =
        rds.delete_db_cluster().db_cluster_identifier("langfuse").skip_final_snapshot(true).send().await.unwrap_err();
    assert_eq!(code(&busy), "InvalidDBClusterStateFault");
    for id in ["langfuse-1", "langfuse-2"] {
        rds.delete_db_instance().db_instance_identifier(id).send().await.unwrap();
    }
    rds.delete_db_cluster()
        .db_cluster_identifier("langfuse")
        .final_db_snapshot_identifier("langfuse-final")
        .delete_automated_backups(false)
        .send()
        .await
        .unwrap();
    let gone = rds.describe_db_clusters().db_cluster_identifier("langfuse").send().await.unwrap_err();
    assert_eq!(code(&gone), "DBClusterNotFoundFault");
    assert!(sm.describe_secret().secret_id(&secret).send().await.is_err());
    let final_snap =
        rds.describe_db_cluster_snapshots().db_cluster_snapshot_identifier("langfuse-final").send().await.unwrap();
    assert_eq!(final_snap.db_cluster_snapshots().len(), 1);
    let backups = rds.describe_db_cluster_automated_backups().send().await.unwrap();
    assert_eq!(backups.db_cluster_automated_backups()[0].status(), Some("retained"));
    let resource = backups.db_cluster_automated_backups()[0].db_cluster_resource_id().unwrap();
    rds.delete_db_cluster_automated_backup().db_cluster_resource_id(resource).send().await.unwrap();
    assert!(rds
        .describe_db_cluster_automated_backups()
        .send()
        .await
        .unwrap()
        .db_cluster_automated_backups()
        .is_empty());

    // Multi-AZ DB clusters (non-Aurora) come with three instances.
    let maz = rds
        .create_db_cluster()
        .db_cluster_identifier("maz")
        .engine("postgres")
        .db_cluster_instance_class("db.m6g.large")
        .storage_type("io1")
        .allocated_storage(100)
        .iops(1000)
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap()
        .db_cluster
        .unwrap();
    assert_eq!(maz.db_cluster_members().len(), 3);
    assert_eq!(maz.multi_az(), Some(true));
    let no_class = rds
        .create_db_cluster()
        .db_cluster_identifier("maz2")
        .engine("postgres")
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&no_class), "InvalidParameterValue");
}

#[test]
fn aurora_global_databases() {
    run(aurora_global_databases_body());
}

async fn aurora_global_databases_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let east = Client::new(&config);
    let west = Client::from_conf(
        aws_sdk_rds::config::Builder::from(&config).region(aws_sdk_rds::config::Region::new("us-west-2")).build(),
    );

    east.create_db_cluster()
        .db_cluster_identifier("primary")
        .engine("aurora-postgresql")
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap();
    let g = east
        .create_global_cluster()
        .global_cluster_identifier("shop")
        .source_db_cluster_identifier("primary")
        .send()
        .await
        .unwrap()
        .global_cluster
        .unwrap();
    assert_eq!(g.engine(), Some("aurora-postgresql"));
    assert_eq!(g.global_cluster_arn(), Some(format!("arn:aws:rds::{ACCOUNT}:global-cluster:shop").as_str()));
    assert_eq!(g.global_cluster_members()[0].is_writer(), Some(true));
    let dup = east
        .create_global_cluster()
        .global_cluster_identifier("shop")
        .engine("aurora-postgresql")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "GlobalClusterAlreadyExistsFault");

    // A secondary in another Region inherits the credentials.
    let secondary = west
        .create_db_cluster()
        .db_cluster_identifier("secondary")
        .engine("aurora-postgresql")
        .global_cluster_identifier("shop")
        .send()
        .await
        .unwrap()
        .db_cluster
        .unwrap();
    assert_eq!(secondary.master_username(), Some("app"));
    let secondary_arn = secondary.db_cluster_arn().unwrap().to_string();
    let d = east.describe_global_clusters().global_cluster_identifier("shop").send().await.unwrap();
    let members = d.global_clusters()[0].global_cluster_members();
    assert_eq!(members.len(), 2);
    let writer = members.iter().find(|m| m.is_writer() == Some(true)).unwrap();
    assert_eq!(writer.readers(), [secondary_arn.as_str()]);
    let w = west.describe_db_clusters().db_cluster_identifier("secondary").send().await.unwrap();
    assert!(w.db_clusters()[0].replication_source_identifier().unwrap().ends_with(":cluster:primary"));

    let switched = east
        .switchover_global_cluster()
        .global_cluster_identifier("shop")
        .target_db_cluster_identifier(&secondary_arn)
        .send()
        .await
        .unwrap()
        .global_cluster
        .unwrap();
    assert_eq!(switched.failover_state().unwrap().to_db_cluster_arn(), Some(secondary_arn.as_str()));
    let d = east.describe_global_clusters().send().await.unwrap();
    let writer = d.global_clusters()[0].global_cluster_members().iter().find(|m| m.is_writer() == Some(true)).unwrap();
    assert_eq!(writer.db_cluster_arn(), Some(secondary_arn.as_str()));
    let primary_arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:cluster:primary");
    east.failover_global_cluster()
        .global_cluster_identifier("shop")
        .target_db_cluster_identifier(&primary_arn)
        .allow_data_loss(true)
        .send()
        .await
        .unwrap();
    east.modify_global_cluster().global_cluster_identifier("shop").deletion_protection(true).send().await.unwrap();

    let in_global =
        west.delete_db_cluster().db_cluster_identifier("secondary").skip_final_snapshot(true).send().await.unwrap_err();
    assert_eq!(code(&in_global), "InvalidDBClusterStateFault");
    let writer_first = east
        .remove_from_global_cluster()
        .global_cluster_identifier("shop")
        .db_cluster_identifier(&primary_arn)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&writer_first), "InvalidGlobalClusterStateFault");
    east.remove_from_global_cluster()
        .global_cluster_identifier("shop")
        .db_cluster_identifier(&secondary_arn)
        .send()
        .await
        .unwrap();
    east.remove_from_global_cluster()
        .global_cluster_identifier("shop")
        .db_cluster_identifier(&primary_arn)
        .send()
        .await
        .unwrap();
    let protected = east.delete_global_cluster().global_cluster_identifier("shop").send().await.unwrap_err();
    assert_eq!(code(&protected), "InvalidGlobalClusterStateFault");
    east.modify_global_cluster()
        .global_cluster_identifier("shop")
        .deletion_protection(false)
        .new_global_cluster_identifier("shop2")
        .send()
        .await
        .unwrap();
    east.delete_global_cluster().global_cluster_identifier("shop2").send().await.unwrap();
    let gone = east.describe_global_clusters().global_cluster_identifier("shop2").send().await.unwrap_err();
    assert_eq!(code(&gone), "GlobalClusterNotFoundFault");
}

#[test]
fn subnet_parameter_and_option_groups() {
    run(subnet_parameter_and_option_groups_body());
}

async fn subnet_parameter_and_option_groups_body() {
    let mws = Mws::start().await;
    let rds = client(&mws).await;
    let subnets = default_subnets(&mws).await;

    let g = rds
        .create_db_subnet_group()
        .db_subnet_group_name("Private")
        .db_subnet_group_description("private subnets")
        .subnet_ids(&subnets[0].0)
        .subnet_ids(&subnets[1].0)
        .tags(tag("tier", "data"))
        .send()
        .await
        .unwrap()
        .db_subnet_group
        .unwrap();
    assert_eq!(g.db_subnet_group_name(), Some("private"));
    assert_eq!(g.subnet_group_status(), Some("Complete"));
    assert_eq!(g.subnets().len(), 2);
    let one_az = rds
        .create_db_subnet_group()
        .db_subnet_group_name("one")
        .db_subnet_group_description("one")
        .subnet_ids(&subnets[0].0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&one_az), "DBSubnetGroupDoesNotCoverEnoughAZs");
    let bogus = rds
        .create_db_subnet_group()
        .db_subnet_group_name("bogus")
        .db_subnet_group_description("bogus")
        .subnet_ids("subnet-0123456789abcdef0")
        .subnet_ids(&subnets[0].0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bogus), "InvalidSubnet");
    rds.modify_db_subnet_group()
        .db_subnet_group_name("private")
        .subnet_ids(&subnets[0].0)
        .subnet_ids(&subnets[1].0)
        .subnet_ids(&subnets[2].0)
        .send()
        .await
        .unwrap();
    let d = rds.describe_db_subnet_groups().db_subnet_group_name("private").send().await.unwrap();
    assert_eq!(d.db_subnet_groups()[0].subnets().len(), 3);

    // Parameter groups: custom values, static parameters wait for a reboot.
    let pg = rds
        .create_db_parameter_group()
        .db_parameter_group_name("harbor-pg16")
        .db_parameter_group_family("postgres16")
        .description("harbor")
        .send()
        .await
        .unwrap()
        .db_parameter_group
        .unwrap();
    assert_eq!(pg.db_parameter_group_arn(), Some(format!("arn:aws:rds:us-east-1:{ACCOUNT}:pg:harbor-pg16").as_str()));
    let family = rds
        .create_db_parameter_group()
        .db_parameter_group_name("bad")
        .db_parameter_group_family("postgres99")
        .description("bad")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&family), "InvalidParameterValue");
    rds.modify_db_parameter_group()
        .db_parameter_group_name("harbor-pg16")
        .parameters(
            Parameter::builder()
                .parameter_name("work_mem")
                .parameter_value("8192")
                .apply_method(ApplyMethod::Immediate)
                .build(),
        )
        .parameters(
            Parameter::builder()
                .parameter_name("max_connections")
                .parameter_value("200")
                .apply_method(ApplyMethod::PendingReboot)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let static_now = rds
        .modify_db_parameter_group()
        .db_parameter_group_name("harbor-pg16")
        .parameters(
            Parameter::builder()
                .parameter_name("max_connections")
                .parameter_value("300")
                .apply_method(ApplyMethod::Immediate)
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&static_now), "InvalidParameterCombination");
    let user = rds.describe_db_parameters().db_parameter_group_name("harbor-pg16").source("user").send().await.unwrap();
    let mut names: Vec<_> = user.parameters().iter().filter_map(|p| p.parameter_name()).collect();
    names.sort();
    assert_eq!(names, ["max_connections", "work_mem"]);
    rds.reset_db_parameter_group()
        .db_parameter_group_name("harbor-pg16")
        .parameters(Parameter::builder().parameter_name("work_mem").apply_method(ApplyMethod::Immediate).build())
        .send()
        .await
        .unwrap();
    let user = rds.describe_db_parameters().db_parameter_group_name("harbor-pg16").source("user").send().await.unwrap();
    assert_eq!(user.parameters().len(), 1);
    rds.copy_db_parameter_group()
        .source_db_parameter_group_identifier("harbor-pg16")
        .target_db_parameter_group_identifier("harbor-copy")
        .target_db_parameter_group_description("copy")
        .send()
        .await
        .unwrap();
    let groups = rds.describe_db_parameter_groups().send().await.unwrap();
    assert!(groups.db_parameter_groups().iter().any(|g| g.db_parameter_group_name() == Some("harbor-copy")));
    let defaults =
        rds.describe_engine_default_parameters().db_parameter_group_family("postgres16").send().await.unwrap();
    assert!(defaults
        .engine_defaults()
        .unwrap()
        .parameters()
        .iter()
        .any(|p| p.parameter_name() == Some("shared_buffers")));
    let default_change = rds
        .modify_db_parameter_group()
        .db_parameter_group_name("default.postgres16")
        .parameters(
            Parameter::builder()
                .parameter_name("work_mem")
                .parameter_value("1")
                .apply_method(ApplyMethod::Immediate)
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&default_change), "InvalidParameterValue");

    // An instance using the group, in the subnet group.
    let db = rds
        .create_db_instance()
        .db_instance_identifier("tuned")
        .engine("postgres")
        .engine_version("16.8")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .db_parameter_group_name("harbor-pg16")
        .db_subnet_group_name("private")
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(db.db_subnet_group().unwrap().db_subnet_group_name(), Some("private"));
    let wrong_family = rds
        .modify_db_instance()
        .db_instance_identifier("tuned")
        .db_parameter_group_name("default.postgres15")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&wrong_family), "InvalidParameterCombination");
    let in_use = rds.delete_db_parameter_group().db_parameter_group_name("harbor-pg16").send().await.unwrap_err();
    assert_eq!(code(&in_use), "InvalidDBParameterGroupState");
    let subnet_in_use = rds.delete_db_subnet_group().db_subnet_group_name("private").send().await.unwrap_err();
    assert_eq!(code(&subnet_in_use), "InvalidDBSubnetGroupStateFault");
    rds.delete_db_parameter_group().db_parameter_group_name("harbor-copy").send().await.unwrap();

    // Cluster parameter groups.
    rds.create_db_cluster_parameter_group()
        .db_cluster_parameter_group_name("aurora-pg16")
        .db_parameter_group_family("aurora-postgresql16")
        .description("aurora")
        .send()
        .await
        .unwrap();
    rds.modify_db_cluster_parameter_group()
        .db_cluster_parameter_group_name("aurora-pg16")
        .parameters(
            Parameter::builder()
                .parameter_name("rds.force_ssl")
                .parameter_value("1")
                .apply_method(ApplyMethod::PendingReboot)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let p = rds
        .describe_db_cluster_parameters()
        .db_cluster_parameter_group_name("aurora-pg16")
        .source("user")
        .send()
        .await
        .unwrap();
    assert_eq!(p.parameters()[0].parameter_value(), Some("1"));
    rds.reset_db_cluster_parameter_group()
        .db_cluster_parameter_group_name("aurora-pg16")
        .reset_all_parameters(true)
        .send()
        .await
        .unwrap();
    rds.copy_db_cluster_parameter_group()
        .source_db_cluster_parameter_group_identifier("aurora-pg16")
        .target_db_cluster_parameter_group_identifier("aurora-copy")
        .target_db_cluster_parameter_group_description("copy")
        .send()
        .await
        .unwrap();
    let groups =
        rds.describe_db_cluster_parameter_groups().db_cluster_parameter_group_name("aurora-copy").send().await.unwrap();
    assert_eq!(groups.db_cluster_parameter_groups()[0].db_parameter_group_family(), Some("aurora-postgresql16"));
    let defaults = rds
        .describe_engine_default_cluster_parameters()
        .db_parameter_group_family("aurora-postgresql16")
        .send()
        .await
        .unwrap();
    assert!(!defaults.engine_defaults().unwrap().parameters().is_empty());
    rds.delete_db_cluster_parameter_group().db_cluster_parameter_group_name("aurora-copy").send().await.unwrap();

    // Option groups.
    let og = rds
        .create_option_group()
        .option_group_name("mysql-audit")
        .engine_name("mysql")
        .major_engine_version("8.0")
        .option_group_description("audit")
        .send()
        .await
        .unwrap()
        .option_group
        .unwrap();
    assert_eq!(og.engine_name(), Some("mysql"));
    rds.copy_option_group()
        .source_option_group_identifier("mysql-audit")
        .target_option_group_identifier("mysql-audit-copy")
        .target_option_group_description("copy")
        .send()
        .await
        .unwrap();
    let not_there = rds
        .modify_option_group()
        .option_group_name("mysql-audit")
        .options_to_remove("MARIADB_AUDIT_PLUGIN")
        .apply_immediately(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&not_there), "InvalidParameterValue");
    let ogs = rds.describe_option_groups().engine_name("mysql").send().await.unwrap();
    assert!(ogs.option_groups_list().len() >= 2);
    let opts =
        rds.describe_option_group_options().engine_name("mysql").major_engine_version("8.0").send().await.unwrap();
    let _ = opts.option_group_options();
    rds.delete_option_group().option_group_name("mysql-audit-copy").send().await.unwrap();
    let default_og = rds.delete_option_group().option_group_name("default:postgres-16").send().await.unwrap_err();
    assert_eq!(code(&default_og), "InvalidOptionGroupStateFault");

    // Tags on groups, by ARN.
    let arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:subgrp:private");
    rds.add_tags_to_resource().resource_name(&arn).tags(tag("owner", "platform")).send().await.unwrap();
    let t = rds.list_tags_for_resource().resource_name(&arn).send().await.unwrap();
    assert_eq!(t.tag_list().len(), 2);
    rds.remove_tags_from_resource().resource_name(&arn).tag_keys("tier").send().await.unwrap();
    let t = rds.list_tags_for_resource().resource_name(&arn).send().await.unwrap();
    assert_eq!(t.tag_list()[0].key(), Some("owner"));
    let reserved = rds.add_tags_to_resource().resource_name(&arn).tags(tag("aws:x", "y")).send().await.unwrap_err();
    assert_eq!(code(&reserved), "InvalidParameterValue");
    let missing = rds
        .list_tags_for_resource()
        .resource_name(format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:nope"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&missing), "DBInstanceNotFound");
}

#[test]
fn events_subscriptions_and_catalog() {
    run(events_subscriptions_and_catalog_body());
}

async fn events_subscriptions_and_catalog_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = Client::new(&config);
    let sns = aws_sdk_sns::Client::new(&config);
    let logs = aws_sdk_cloudwatchlogs::Client::new(&config);
    let eb = aws_sdk_eventbridge::Client::new(&config);

    // RDS events reach EventBridge rules.
    logs.create_log_group().log_group_name("/rds/events").send().await.unwrap();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": format!("arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/rds/events:*"),
        }],
    });
    logs.put_resource_policy().policy_name("events").policy_document(policy.to_string()).send().await.unwrap();
    eb.put_rule()
        .name("rds")
        .event_pattern(r#"{"source":["aws.rds"],"detail-type":["RDS DB Instance Event"]}"#)
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("rds")
        .targets(
            aws_sdk_eventbridge::types::Target::builder()
                .id("log")
                .arn(format!("arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/rds/events"))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    // Event subscriptions publish to SNS as events.rds.amazonaws.com, which
    // the topic policy must allow.
    let topic = sns.create_topic().name("rds-events").send().await.unwrap().topic_arn.unwrap();
    let topic_policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.rds.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": topic,
            "Condition": {
                "ArnLike": {"aws:SourceArn": format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:*")},
                "StringEquals": {"aws:SourceAccount": ACCOUNT},
            },
        }],
    });
    sns.set_topic_attributes()
        .topic_arn(&topic)
        .attribute_name("Policy")
        .attribute_value(topic_policy.to_string())
        .send()
        .await
        .unwrap();
    let sqs = aws_sdk_sqs::Client::new(&config);
    let queue = sqs.create_queue().queue_name("rds-notifications").send().await.unwrap().queue_url.unwrap();
    let queue_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:rds-notifications");
    let queue_policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
        }],
    });
    sqs.set_queue_attributes()
        .queue_url(&queue)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, queue_policy.to_string())
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&queue_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();
    let denied = rds
        .create_event_subscription()
        .subscription_name("ops")
        .sns_topic_arn(format!("arn:aws:sns:us-east-1:{ACCOUNT}:nope"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "SNSTopicArnNotFound");
    let sub = rds
        .create_event_subscription()
        .subscription_name("ops")
        .sns_topic_arn(&topic)
        .source_type("db-instance")
        .event_categories("creation")
        .event_categories("deletion")
        .send()
        .await
        .unwrap()
        .event_subscription
        .unwrap();
    assert_eq!(sub.status(), Some("active"));
    assert_eq!(sub.customer_aws_id(), Some(ACCOUNT));
    let bad_category = rds
        .create_event_subscription()
        .subscription_name("bad")
        .sns_topic_arn(&topic)
        .source_type("db-instance")
        .event_categories("nonsense")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_category), "SubscriptionCategoryNotFound");
    create_postgres(&rds, "evented").await;
    let note = eventually(15, || async {
        let r = sqs.receive_message().queue_url(&queue).send().await.ok()?;
        r.messages().first().and_then(|m| m.body()).map(str::to_string)
    })
    .await;
    let note: serde_json::Value = serde_json::from_str(&note).unwrap();
    assert_eq!(note["Source ID"], "evented");
    assert_eq!(note["Event Message"], "DB instance created");
    rds.add_source_identifier_to_subscription()
        .subscription_name("ops")
        .source_identifier("evented")
        .send()
        .await
        .unwrap();
    let d = rds.describe_event_subscriptions().subscription_name("ops").send().await.unwrap();
    assert_eq!(d.event_subscriptions_list()[0].source_ids_list(), ["evented"]);
    rds.modify_event_subscription().subscription_name("ops").enabled(false).send().await.unwrap();
    rds.modify_event_subscription().subscription_name("ops").enabled(true).send().await.unwrap();
    rds.remove_source_identifier_from_subscription()
        .subscription_name("ops")
        .source_identifier("evented")
        .send()
        .await
        .unwrap();

    let events = rds
        .describe_events()
        .source_identifier("evented")
        .source_type(aws_sdk_rds::types::SourceType::DbInstance)
        .send()
        .await
        .unwrap();
    assert!(events.events().iter().any(|e| e.message() == Some("DB instance created")));
    let categories = rds.describe_event_categories().source_type("db-instance").send().await.unwrap();
    assert!(categories.event_categories_map_list()[0].event_categories().iter().any(|c| c == "backup"));
    let logged = eventually(15, || async {
        let out = logs.filter_log_events().log_group_name("/rds/events").send().await.ok()?;
        let m: Vec<serde_json::Value> =
            out.events().iter().filter_map(|e| serde_json::from_str(e.message().unwrap_or_default()).ok()).collect();
        m.into_iter().find(|e| e["detail"]["EventID"] == "RDS-EVENT-0005")
    })
    .await;
    assert_eq!(logged["source"], "aws.rds");
    assert_eq!(logged["detail"]["SourceIdentifier"], "evented");
    assert_eq!(logged["detail"]["SourceType"], "DB_INSTANCE");
    rds.delete_event_subscription().subscription_name("ops").send().await.unwrap();
    let gone = rds.describe_event_subscriptions().subscription_name("ops").send().await.unwrap_err();
    assert_eq!(code(&gone), "SubscriptionNotFound");

    // The catalog.
    let versions = rds.describe_db_engine_versions().engine("postgres").send().await.unwrap();
    assert!(versions.db_engine_versions().iter().any(|v| v.engine_version() == Some("16.8")));
    let default =
        rds.describe_db_engine_versions().engine("aurora-postgresql").default_only(true).send().await.unwrap();
    assert_eq!(default.db_engine_versions().len(), 1);
    let family = rds.describe_db_engine_versions().db_parameter_group_family("mysql8.0").send().await.unwrap();
    assert!(family.db_engine_versions().iter().all(|v| v.engine() == Some("mysql")));
    let majors = rds.describe_db_major_engine_versions().engine("postgres").send().await.unwrap();
    assert!(majors.db_major_engine_versions().iter().any(|m| m.major_engine_version() == Some("16")));
    let orderable = rds
        .describe_orderable_db_instance_options()
        .engine("aurora-postgresql")
        .db_instance_class("db.serverless")
        .send()
        .await
        .unwrap();
    assert!(!orderable.orderable_db_instance_options().is_empty());
    let certs = rds.describe_certificates().send().await.unwrap();
    assert_eq!(certs.default_certificate_for_new_launches(), Some("rds-ca-rsa2048-g1"));
    assert_eq!(certs.certificates().len(), 3);
    let quotas = rds.describe_account_attributes().send().await.unwrap();
    let instances = quotas.account_quotas().iter().find(|q| q.account_quota_name() == Some("DBInstances")).unwrap();
    assert_eq!(instances.used(), Some(1));
    assert_eq!(instances.max(), Some(40));
    let regions = rds.describe_source_regions().send().await.unwrap();
    assert!(regions.source_regions().iter().any(|r| r.region_name() == Some("us-west-2")));
    let pending = rds.describe_pending_maintenance_actions().send().await.unwrap();
    assert!(pending.pending_maintenance_actions().is_empty());
    let arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:evented");
    let none = rds
        .apply_pending_maintenance_action()
        .resource_identifier(&arn)
        .apply_action("system-update")
        .opt_in_type("immediate")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&none), "InvalidParameterValue");
    let unknown = rds
        .apply_pending_maintenance_action()
        .resource_identifier(format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:nope"))
        .apply_action("system-update")
        .opt_in_type("immediate")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&unknown), "ResourceNotFoundFault");
}

#[test]
fn iam_controls_rds() {
    run(iam_controls_rds_body());
}

async fn iam_controls_rds_body() {
    let mws = Mws::start().await;
    let rds = client(&mws).await;
    create_postgres(&rds, "prod-db").await;
    rds.add_tags_to_resource()
        .resource_name(format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:prod-db"))
        .tags(tag("env", "prod"))
        .send()
        .await
        .unwrap();
    create_postgres(&rds, "dev-db").await;
    rds.add_tags_to_resource()
        .resource_name(format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:dev-db"))
        .tags(tag("env", "dev"))
        .send()
        .await
        .unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":["rds:Describe*","rds:RebootDBInstance"],"Resource":"*"},
        {"Effect":"Deny","Action":"rds:RebootDBInstance","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}},
        {"Effect":"Allow","Action":"rds:CreateDBInstance","Resource":"*","Condition":{"StringEquals":{"rds:DatabaseEngine":"postgres"}}}
    ]}"#;
    let (_, cfg) = user_with_policy(&mws, "dba", Some(policy)).await;
    let dba = Client::new(&cfg);
    assert_eq!(dba.describe_db_instances().send().await.unwrap().db_instances().len(), 2);
    dba.reboot_db_instance().db_instance_identifier("dev-db").send().await.unwrap();
    let denied = dba.reboot_db_instance().db_instance_identifier("prod-db").send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDenied");
    let mysql = dba
        .create_db_instance()
        .db_instance_identifier("mysql")
        .engine("mysql")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("admin")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&mysql), "AccessDenied");
    create_postgres(&dba, "allowed").await;
    let delete =
        dba.delete_db_instance().db_instance_identifier("allowed").skip_final_snapshot(true).send().await.unwrap_err();
    assert_eq!(code(&delete), "AccessDenied");
}
