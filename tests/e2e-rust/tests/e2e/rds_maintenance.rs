//! RDS deferred modifications, maintenance windows and pending
//! maintenance actions on the emulated clock, storage change rules, and
//! Enhanced Monitoring roles (metadata backend).

use aws_sdk_rds::error::ProvideErrorMetadata;
use aws_sdk_rds::types::SourceType;
use aws_sdk_rds::Client;
use mws_e2e::{user_with_policy, Mws};

use super::rds::run;

const ACCOUNT: &str = "123456789012";

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message(e: &impl ProvideErrorMetadata) -> String {
    e.message().unwrap_or_default().to_string()
}

async fn advance(mws: &Mws, seconds: u64) {
    let body = format!(r#"{{"advanceSeconds": {seconds}}}"#);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

async fn create_postgres(rds: &Client, id: &str) {
    rds.create_db_instance()
        .db_instance_identifier(id)
        .engine("postgres")
        .engine_version("16.8")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap();
}

async fn instance(rds: &Client, id: &str) -> aws_sdk_rds::types::DbInstance {
    rds.describe_db_instances().db_instance_identifier(id).send().await.unwrap().db_instances()[0].clone()
}

async fn messages(rds: &Client, id: &str) -> Vec<String> {
    rds.describe_events()
        .source_identifier(id)
        .source_type(SourceType::DbInstance)
        .duration(20160)
        .send()
        .await
        .unwrap()
        .events()
        .iter()
        .filter_map(|e| e.message().map(str::to_string))
        .collect()
}

const CLASS_EVENT: &str = "Finished applying modification to DB instance class";

#[test]
fn rds_deferred_modifications_apply_in_the_maintenance_window() {
    run(deferred_body());
}

async fn deferred_body() {
    let mws = Mws::start().await;
    let rds = Client::new(&mws.root_sdk_config().await);
    create_postgres(&rds, "maint-db").await;
    let arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:maint-db");

    // A change that is not to the class sends no class event.
    rds.modify_db_instance().db_instance_identifier("maint-db").backup_retention_period(3).send().await.unwrap();
    assert!(!messages(&rds, "maint-db").await.iter().any(|m| m == CLASS_EVENT));

    // Without ApplyImmediately everything waits in PendingModifiedValues.
    let m = rds
        .modify_db_instance()
        .db_instance_identifier("maint-db")
        .db_instance_class("db.t3.small")
        .allocated_storage(30)
        .multi_az(true)
        .engine_version("17.4")
        .allow_major_version_upgrade(true)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(m.db_instance_status(), Some("available"));
    let p = m.pending_modified_values().unwrap();
    assert_eq!(p.db_instance_class(), Some("db.t3.small"));
    assert_eq!(p.allocated_storage(), Some(30));
    assert_eq!(p.multi_az(), Some(true));
    assert_eq!(p.engine_version(), Some("17.4"));
    let db = instance(&rds, "maint-db").await;
    assert_eq!(db.db_instance_class(), Some("db.t3.micro"));
    assert_eq!(db.allocated_storage(), Some(20));
    assert_eq!(db.engine_version(), Some("16.8"));
    assert!(!messages(&rds, "maint-db").await.iter().any(|m| m == CLASS_EVENT));

    // The pending engine upgrade is a db-upgrade maintenance action.
    let pending = rds.describe_pending_maintenance_actions().send().await.unwrap();
    let actions = pending.pending_maintenance_actions();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].resource_identifier(), Some(arn.as_str()));
    let action = &actions[0].pending_maintenance_action_details()[0];
    assert_eq!(action.action(), Some("db-upgrade"));
    assert!(action.current_apply_date().is_some());
    assert!(action.opt_in_status().is_none());
    let filtered = rds
        .describe_pending_maintenance_actions()
        .filters(aws_sdk_rds::types::Filter::builder().name("db-instance-id").values("other").build())
        .send()
        .await
        .unwrap();
    assert!(filtered.pending_maintenance_actions().is_empty());

    let opted = rds
        .apply_pending_maintenance_action()
        .resource_identifier(&arn)
        .apply_action("db-upgrade")
        .opt_in_type("next-maintenance")
        .send()
        .await
        .unwrap();
    let details = opted.resource_pending_maintenance_actions().unwrap().pending_maintenance_action_details();
    assert_eq!(details[0].opt_in_status(), Some("next-maintenance"));
    let listed = rds.describe_pending_maintenance_actions().resource_identifier(&arn).send().await.unwrap();
    assert_eq!(
        listed.pending_maintenance_actions()[0].pending_maintenance_action_details()[0].opt_in_status(),
        Some("next-maintenance")
    );
    let undone = rds
        .apply_pending_maintenance_action()
        .resource_identifier(&arn)
        .apply_action("db-upgrade")
        .opt_in_type("undo-opt-in")
        .send()
        .await
        .unwrap();
    let details = undone.resource_pending_maintenance_actions().unwrap().pending_maintenance_action_details();
    assert!(details[0].opt_in_status().is_none());
    let bad = rds
        .apply_pending_maintenance_action()
        .resource_identifier(&arn)
        .apply_action("db-upgrade")
        .opt_in_type("sometime")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad), "InvalidParameterValue");
    let none = rds
        .apply_pending_maintenance_action()
        .resource_identifier(&arn)
        .apply_action("system-update")
        .opt_in_type("immediate")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&none), "InvalidParameterValue");

    // A week and a day later the maintenance window has come.
    advance(&mws, 8 * 86400).await;
    let db = instance(&rds, "maint-db").await;
    assert_eq!(db.db_instance_class(), Some("db.t3.small"));
    assert_eq!(db.allocated_storage(), Some(30));
    assert_eq!(db.multi_az(), Some(true));
    assert!(db.secondary_availability_zone().is_some());
    assert_eq!(db.engine_version(), Some("17.4"));
    let p = db.pending_modified_values().unwrap();
    assert!(p.db_instance_class().is_none() && p.allocated_storage().is_none() && p.engine_version().is_none());
    assert_eq!(db.db_instance_status(), Some("storage-optimization"));
    assert!(rds.describe_pending_maintenance_actions().send().await.unwrap().pending_maintenance_actions().is_empty());
    assert!(messages(&rds, "maint-db").await.iter().any(|m| m == CLASS_EVENT));

    // Storage can't change again while the last change is optimized
    // (six hours), and increases must be at least 10%.
    let busy = rds
        .modify_db_instance()
        .db_instance_identifier("maint-db")
        .allocated_storage(40)
        .apply_immediately(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&busy), "InvalidParameterCombination");
    assert_eq!(
        message(&busy),
        "You can't currently modify the storage of this DB instance because the previous storage change is being optimized."
    );
    // Other changes are fine meanwhile.
    rds.modify_db_instance().db_instance_identifier("maint-db").deletion_protection(false).send().await.unwrap();
    advance(&mws, 7 * 3600).await;
    assert_eq!(instance(&rds, "maint-db").await.db_instance_status(), Some("available"));
    let small = rds
        .modify_db_instance()
        .db_instance_identifier("maint-db")
        .allocated_storage(32)
        .apply_immediately(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&small), "InvalidParameterCombination");
    assert_eq!(message(&small), "Invalid storage size for engine name postgres and storage type gp3: 32");

    // With ApplyImmediately the response keeps the old values, the new
    // ones pending, while the instance is modifying.
    let m = rds
        .modify_db_instance()
        .db_instance_identifier("maint-db")
        .db_instance_class("db.t3.medium")
        .allocated_storage(33)
        .apply_immediately(true)
        .send()
        .await
        .unwrap()
        .db_instance
        .unwrap();
    assert_eq!(m.db_instance_status(), Some("modifying"));
    assert_eq!(m.db_instance_class(), Some("db.t3.small"));
    assert_eq!(m.pending_modified_values().unwrap().db_instance_class(), Some("db.t3.medium"));
    let db = instance(&rds, "maint-db").await;
    assert_eq!(db.db_instance_class(), Some("db.t3.medium"));
    assert_eq!(db.allocated_storage(), Some(33));
    assert_eq!(db.db_instance_status(), Some("storage-optimization"));
}

#[test]
fn rds_apply_pending_maintenance_action_immediately() {
    run(apply_now_body());
}

async fn apply_now_body() {
    let mws = Mws::start().await;
    let rds = Client::new(&mws.root_sdk_config().await);
    create_postgres(&rds, "upgrade-now").await;
    let arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:upgrade-now");
    rds.modify_db_instance()
        .db_instance_identifier("upgrade-now")
        .engine_version("17.4")
        .allow_major_version_upgrade(true)
        .db_instance_class("db.t3.small")
        .send()
        .await
        .unwrap();
    let applied = rds
        .apply_pending_maintenance_action()
        .resource_identifier(&arn)
        .apply_action("db-upgrade")
        .opt_in_type("immediate")
        .send()
        .await
        .unwrap();
    let details = applied.resource_pending_maintenance_actions().unwrap().pending_maintenance_action_details();
    assert_eq!(details[0].opt_in_status(), Some("immediate"));
    let db = instance(&rds, "upgrade-now").await;
    assert_eq!(db.engine_version(), Some("17.4"));
    assert_eq!(db.db_instance_status(), Some("available"));
    // Only the upgrade was applied; the class change still waits.
    assert_eq!(db.db_instance_class(), Some("db.t3.micro"));
    assert_eq!(db.pending_modified_values().unwrap().db_instance_class(), Some("db.t3.small"));
    assert!(rds.describe_pending_maintenance_actions().send().await.unwrap().pending_maintenance_actions().is_empty());

    // Aurora: a deferred cluster upgrade is listed on the cluster and
    // applied in its maintenance window.
    rds.create_db_cluster()
        .db_cluster_identifier("aurora")
        .engine("aurora-postgresql")
        .engine_version("16.8")
        .master_username("aurora")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap();
    let cluster_arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:cluster:aurora");
    let m = rds
        .modify_db_cluster()
        .db_cluster_identifier("aurora")
        .engine_version("17.4")
        .allow_major_version_upgrade(true)
        .send()
        .await
        .unwrap()
        .db_cluster
        .unwrap();
    assert_eq!(m.engine_version(), Some("16.8"));
    assert_eq!(m.pending_modified_values().unwrap().engine_version(), Some("17.4"));
    let pending = rds
        .describe_pending_maintenance_actions()
        .filters(aws_sdk_rds::types::Filter::builder().name("db-cluster-id").values("aurora").build())
        .send()
        .await
        .unwrap();
    assert_eq!(pending.pending_maintenance_actions()[0].resource_identifier(), Some(cluster_arn.as_str()));
    advance(&mws, 8 * 86400).await;
    let c = rds.describe_db_clusters().db_cluster_identifier("aurora").send().await.unwrap().db_clusters()[0].clone();
    assert_eq!(c.engine_version(), Some("17.4"));
    assert_eq!(c.status(), Some("available"));
    assert!(c.pending_modified_values().unwrap().engine_version().is_none());
    // The class change on the instance was applied in its window too.
    assert_eq!(instance(&rds, "upgrade-now").await.db_instance_class(), Some("db.t3.small"));
}

#[test]
fn rds_enhanced_monitoring_roles() {
    run(monitoring_body());
}

async fn monitoring_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = Client::new(&config);
    let iam = aws_sdk_iam::Client::new(&config);
    let create = |role: Option<String>| {
        rds.create_db_instance()
            .db_instance_identifier("monitored")
            .engine("postgres")
            .db_instance_class("db.t3.micro")
            .allocated_storage(20)
            .master_username("harbor")
            .master_user_password("correct-horse-battery")
            .monitoring_interval(60)
            .set_monitoring_role_arn(role)
    };
    let no_role = create(None).send().await.unwrap_err();
    assert_eq!(code(&no_role), "InvalidParameterCombination");
    assert_eq!(
        message(&no_role),
        "A MonitoringRoleARN value is required if you specify a MonitoringInterval value other than 0."
    );
    let invalid = "IAM role ARN value is invalid or does not include the required permissions for: ENHANCED_MONITORING";
    let missing = create(Some(format!("arn:aws:iam::{ACCOUNT}:role/nope"))).send().await.unwrap_err();
    assert_eq!(code(&missing), "InvalidParameterValue");
    assert_eq!(message(&missing), invalid);
    let trust = |service: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
        )
    };
    let ec2_role = iam
        .create_role()
        .role_name("ec2-only")
        .assume_role_policy_document(trust("ec2.amazonaws.com"))
        .send()
        .await
        .unwrap()
        .role
        .unwrap()
        .arn;
    let untrusted = create(Some(ec2_role)).send().await.unwrap_err();
    assert_eq!(code(&untrusted), "InvalidParameterValue");
    assert_eq!(message(&untrusted), invalid);
    let role = iam
        .create_role()
        .role_name("rds-monitoring-role")
        .assume_role_policy_document(trust("monitoring.rds.amazonaws.com"))
        .send()
        .await
        .unwrap()
        .role
        .unwrap()
        .arn;
    let db = create(Some(role.clone())).send().await.unwrap().db_instance.unwrap();
    assert_eq!(db.monitoring_interval(), Some(60));
    assert_eq!(db.monitoring_role_arn(), Some(role.as_str()));

    // Modify checks the same way; turning monitoring off needs no role.
    rds.modify_db_instance().db_instance_identifier("monitored").monitoring_interval(0).send().await.unwrap();
    let modify_none = rds
        .modify_db_instance()
        .db_instance_identifier("monitored")
        .monitoring_interval(30)
        .monitoring_role_arn("")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&modify_none), "InvalidParameterCombination");

    // Passing the role needs iam:PassRole.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds:*","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "dba", Some(policy)).await;
    let dba = Client::new(&cfg);
    let denied = dba
        .modify_db_instance()
        .db_instance_identifier("monitored")
        .monitoring_interval(30)
        .monitoring_role_arn(&role)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "AccessDenied");
}
