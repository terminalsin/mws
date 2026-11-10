//! Secrets Manager work that AWS finishes asynchronously (forced deletion,
//! replication) and secrets that another service manages.

use aws_sdk_secretsmanager::error::ProvideErrorMetadata;
use aws_sdk_secretsmanager::types::ReplicaRegionType;
use aws_sdk_secretsmanager::Client;
use mws_e2e::Mws;

use super::secretsmanager::{wait_deleted, wait_in_sync};

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

#[tokio::test]
async fn forced_deletion_keeps_the_name_until_it_settles() {
    let mws = Mws::start().await;
    let sm = Client::new(&mws.root_sdk_config().await);
    sm.create_secret().name("app").secret_string("v1").send().await.unwrap();
    let deleted = sm.delete_secret().secret_id("app").force_delete_without_recovery(true).send().await.unwrap();
    assert!(deleted.deletion_date().is_some());

    let taken = sm.create_secret().name("app").secret_string("v2").send().await.unwrap_err();
    assert_eq!(code(&taken), "InvalidRequestException");
    assert_eq!(
        taken.message(),
        Some("You can't create this secret because a secret with this name is already scheduled for deletion.")
    );
    let read = sm.get_secret_value().secret_id("app").send().await.unwrap_err();
    assert_eq!(code(&read), "InvalidRequestException");
    assert_eq!(
        read.message(),
        Some("You can't perform this operation on the secret because it was marked for deletion.")
    );
    let described = sm.describe_secret().secret_id("app").send().await.unwrap();
    assert!(described.deleted_date().is_some());
    let restore = sm.restore_secret().secret_id("app").send().await.unwrap_err();
    assert_eq!(code(&restore), "InvalidRequestException");
    // Deleting it again is accepted.
    sm.delete_secret().secret_id("app").force_delete_without_recovery(true).send().await.unwrap();

    wait_deleted(&sm, "app").await;
    let again = sm.create_secret().name("app").secret_string("v2").send().await.unwrap();
    assert!(again.version_id().is_some());
    mws.stop().await;
}

#[tokio::test]
async fn replicas_are_in_progress_before_in_sync() {
    let mws = Mws::start().await;
    let sm = Client::new(&mws.root_sdk_config().await);
    sm.create_secret().name("shared").secret_string("v1").send().await.unwrap();
    let out = sm
        .replicate_secret_to_regions()
        .secret_id("shared")
        .add_replica_regions(ReplicaRegionType::builder().region("us-west-2").build())
        .send()
        .await
        .unwrap();
    assert_eq!(out.replication_status()[0].status().map(|s| s.as_str()), Some("InProgress"));
    let d = sm.describe_secret().secret_id("shared").send().await.unwrap();
    assert_eq!(d.replication_status()[0].status().map(|s| s.as_str()), Some("InProgress"));
    wait_in_sync(&sm, "shared").await;
    let d = sm.describe_secret().secret_id("shared").send().await.unwrap();
    assert_eq!(d.replication_status()[0].status_message(), Some("Replication succeeded"));
    mws.stop().await;
}

#[tokio::test]
async fn secrets_managed_by_another_service_change_only_through_it() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = aws_sdk_rds::Client::new(&config);
    let sm = Client::new(&config);
    let db = rds
        .create_db_instance()
        .db_instance_identifier("managed")
        .engine("postgres")
        .db_instance_class("db.t4g.micro")
        .allocated_storage(20)
        .master_username("app")
        .manage_master_user_password(true)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    let arn = db.master_user_secret().unwrap().secret_arn().unwrap().to_string();
    let modify = format!("You can't modify secret {arn} because it's managed by rds.");

    let put = sm.put_secret_value().secret_id(&arn).secret_string("{}").send().await.unwrap_err();
    assert_eq!(code(&put), "InvalidRequestException");
    assert_eq!(put.message(), Some(modify.as_str()));
    let update = sm.update_secret().secret_id(&arn).description("mine now").send().await.unwrap_err();
    assert_eq!(code(&update), "InvalidRequestException");
    assert_eq!(update.message(), Some(modify.as_str()));
    let current = sm.get_secret_value().secret_id(&arn).send().await.unwrap().version_id().unwrap().to_string();
    let stage = sm
        .update_secret_version_stage()
        .secret_id(&arn)
        .version_stage("MINE")
        .move_to_version_id(&current)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&stage), "InvalidRequestException");
    let delete = sm.delete_secret().secret_id(&arn).force_delete_without_recovery(true).send().await.unwrap_err();
    assert_eq!(code(&delete), "InvalidRequestException");
    assert_eq!(delete.message(), Some(format!("You can't delete secret {arn} because it's managed by rds.").as_str()));

    // The owner still changes it, and Secrets Manager rotation goes through RDS.
    rds.modify_db_instance()
        .db_instance_identifier("managed")
        .rotate_master_user_password(true)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let rotated = sm.get_secret_value().secret_id(&arn).send().await.unwrap();
    assert_ne!(rotated.version_id(), Some(current.as_str()));
    sm.rotate_secret().secret_id(&arn).send().await.unwrap();
    mws.stop().await;
}
