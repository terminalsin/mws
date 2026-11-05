//! RDS Proxy, Blue/Green deployments, reserved instances, exports to S3,
//! backtracking, Limitless shard groups, zero-ETL integrations, capacity
//! reservations and the rest of the RDS API, through the official Rust SDK
//! with the metadata-only backend (`rds_docker` has the ones that move real
//! data).

use std::time::Duration;

use aws_sdk_rds::error::ProvideErrorMetadata;
use aws_sdk_rds::types::{Filter, Tag, UserAuthConfig};
use aws_sdk_rds::Client;
use mws_e2e::Mws;

use crate::rds::run;

const ACCOUNT: &str = "123456789012";

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn filter(name: &str, value: &str) -> Filter {
    Filter::builder().name(name).values(value).build()
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

async fn create_postgres(rds: &Client, id: &str) {
    rds.create_db_instance()
        .db_instance_identifier(id)
        .engine("postgres")
        .engine_version("16")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .master_user_password("correct-horse-battery")
        .backup_retention_period(1)
        .send()
        .await
        .unwrap();
    wait_instance(rds, id).await;
}

async fn wait_instance(rds: &Client, id: &str) {
    eventually(30, || async {
        let out = rds.describe_db_instances().db_instance_identifier(id).send().await.ok()?;
        (out.db_instances()[0].db_instance_status() == Some("available")).then_some(())
    })
    .await;
}

async fn wait_cluster(rds: &Client, id: &str) {
    eventually(30, || async {
        let out = rds.describe_db_clusters().db_cluster_identifier(id).send().await.ok()?;
        (out.db_clusters()[0].status() == Some("available")).then_some(())
    })
    .await;
}

/// A role `service` may assume, allowed everything.
async fn service_role(mws: &Mws, name: &str, service: &str) -> String {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    let role = iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    iam.put_role_policy()
        .role_name(name)
        .policy_name("all")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","kms:*","secretsmanager:*"],"Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    role.role.unwrap().arn
}

async fn subnets(mws: &Mws) -> Vec<String> {
    let ec2 = aws_sdk_ec2::Client::new(&mws.root_sdk_config().await);
    let out = ec2
        .describe_subnets()
        .filters(aws_sdk_ec2::types::Filter::builder().name("default-for-az").values("true").build())
        .send()
        .await
        .unwrap();
    out.subnets().iter().filter_map(|s| s.subnet_id().map(str::to_string)).collect()
}

#[test]
fn proxies_and_blue_green() {
    run(proxies_and_blue_green_body());
}

async fn proxies_and_blue_green_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = Client::new(&config);
    let sm = aws_sdk_secretsmanager::Client::new(&config);
    create_postgres(&rds, "harbor").await;
    let secret = sm
        .create_secret()
        .name("harbor-db")
        .secret_string(r#"{"username":"harbor","password":"correct-horse-battery"}"#)
        .send()
        .await
        .unwrap()
        .arn
        .unwrap();
    let role = service_role(&mws, "proxy-role", "rds.amazonaws.com").await;
    let subnet_ids = subnets(&mws).await;

    // ---- RDS Proxy ----
    let missing = rds
        .create_db_proxy()
        .db_proxy_name("harbor-proxy")
        .engine_family(aws_sdk_rds::types::EngineFamily::Postgresql)
        .role_arn(&role)
        .set_vpc_subnet_ids(Some(subnet_ids.clone()))
        .auth(UserAuthConfig::builder().secret_arn(format!("{secret}-gone")).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&missing), "InvalidParameterValue");
    let wrong_auth = rds
        .create_db_proxy()
        .db_proxy_name("harbor-proxy")
        .engine_family(aws_sdk_rds::types::EngineFamily::Postgresql)
        .role_arn(&role)
        .set_vpc_subnet_ids(Some(subnet_ids.clone()))
        .auth(
            UserAuthConfig::builder()
                .secret_arn(&secret)
                .client_password_auth_type(aws_sdk_rds::types::ClientPasswordAuthType::MysqlNativePassword)
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&wrong_auth), "InvalidParameterValue");
    let proxy = rds
        .create_db_proxy()
        .db_proxy_name("harbor-proxy")
        .engine_family(aws_sdk_rds::types::EngineFamily::Postgresql)
        .role_arn(&role)
        .set_vpc_subnet_ids(Some(subnet_ids.clone()))
        .auth(UserAuthConfig::builder().secret_arn(&secret).build())
        .require_tls(true)
        .tags(Tag::builder().key("app").value("harbor").build())
        .send()
        .await
        .unwrap()
        .db_proxy
        .unwrap();
    assert!(proxy.db_proxy_arn().unwrap().contains(":db-proxy:prx-"));
    assert_eq!(proxy.engine_family(), Some("POSTGRESQL"));
    assert_eq!(proxy.require_tls(), Some(true));
    let dup = rds
        .create_db_proxy()
        .db_proxy_name("harbor-proxy")
        .engine_family(aws_sdk_rds::types::EngineFamily::Postgresql)
        .role_arn(&role)
        .set_vpc_subnet_ids(Some(subnet_ids.clone()))
        .auth(UserAuthConfig::builder().secret_arn(&secret).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "DBProxyAlreadyExistsFault");
    let proxy = eventually(30, || async {
        let p = rds.describe_db_proxies().db_proxy_name("harbor-proxy").send().await.ok()?.db_proxies()[0].clone();
        (p.status().map(|s| s.as_str()) == Some("available")).then_some(p)
    })
    .await;
    assert!(
        proxy.endpoint().unwrap().starts_with("harbor-proxy.proxy-")
            || proxy.endpoint().unwrap().contains(':')
            || proxy.endpoint().unwrap().starts_with("127.")
    );
    let groups = rds.describe_db_proxy_target_groups().db_proxy_name("harbor-proxy").send().await.unwrap();
    assert_eq!(groups.target_groups()[0].target_group_name(), Some("default"));
    assert_eq!(groups.target_groups()[0].connection_pool_config().unwrap().max_connections_percent(), Some(100));
    rds.modify_db_proxy_target_group()
        .db_proxy_name("harbor-proxy")
        .target_group_name("default")
        .connection_pool_config(
            aws_sdk_rds::types::ConnectionPoolConfiguration::builder().max_connections_percent(60).build(),
        )
        .send()
        .await
        .unwrap();
    let targets = rds
        .register_db_proxy_targets()
        .db_proxy_name("harbor-proxy")
        .db_instance_identifiers("harbor")
        .send()
        .await
        .unwrap();
    assert_eq!(targets.db_proxy_targets()[0].rds_resource_id(), Some("harbor"));
    let described = rds.describe_db_proxy_targets().db_proxy_name("harbor-proxy").send().await.unwrap();
    assert_eq!(described.targets().len(), 1);
    let endpoint = rds
        .create_db_proxy_endpoint()
        .db_proxy_name("harbor-proxy")
        .db_proxy_endpoint_name("harbor-ro")
        .set_vpc_subnet_ids(Some(subnet_ids.clone()))
        .target_role(aws_sdk_rds::types::DbProxyEndpointTargetRole::ReadOnly)
        .send()
        .await
        .unwrap()
        .db_proxy_endpoint
        .unwrap();
    assert_eq!(endpoint.db_proxy_endpoint_name(), Some("harbor-ro"));
    let endpoints = rds.describe_db_proxy_endpoints().db_proxy_name("harbor-proxy").send().await.unwrap();
    assert_eq!(endpoints.db_proxy_endpoints().len(), 2, "default and custom endpoints");
    rds.modify_db_proxy_endpoint()
        .db_proxy_endpoint_name("harbor-ro")
        .new_db_proxy_endpoint_name("harbor-reader")
        .send()
        .await
        .unwrap();
    rds.delete_db_proxy_endpoint().db_proxy_endpoint_name("harbor-reader").send().await.unwrap();
    rds.modify_db_proxy()
        .db_proxy_name("harbor-proxy")
        .idle_client_timeout(900)
        .debug_logging(true)
        .send()
        .await
        .unwrap();
    let tags = rds.list_tags_for_resource().resource_name(proxy.db_proxy_arn().unwrap()).send().await.unwrap();
    assert_eq!(tags.tag_list()[0].key(), Some("app"));
    rds.deregister_db_proxy_targets()
        .db_proxy_name("harbor-proxy")
        .db_instance_identifiers("harbor")
        .send()
        .await
        .unwrap();
    rds.delete_db_proxy().db_proxy_name("harbor-proxy").send().await.unwrap();
    let gone = rds.describe_db_proxies().db_proxy_name("harbor-proxy").send().await;
    if let Err(e) = gone {
        assert_eq!(code(&e.into_service_error()), "DBProxyNotFoundFault");
    }

    // ---- Blue/Green ----
    let source = format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:harbor");
    let bg = rds
        .create_blue_green_deployment()
        .blue_green_deployment_name("harbor-upgrade")
        .source(&source)
        .target_engine_version("17")
        .send()
        .await
        .unwrap()
        .blue_green_deployment
        .unwrap();
    let id = bg.blue_green_deployment_identifier().unwrap().to_string();
    assert!(id.starts_with("bgd-"));
    assert_eq!(bg.status(), Some("PROVISIONING"));
    let again = rds
        .create_blue_green_deployment()
        .blue_green_deployment_name("again")
        .source(&source)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&again), "BlueGreenDeploymentAlreadyExistsFault");
    let bg = eventually(30, || async {
        let out = rds.describe_blue_green_deployments().blue_green_deployment_identifier(&id).send().await.ok()?;
        let b = out.blue_green_deployments()[0].clone();
        (b.status() == Some("AVAILABLE")).then_some(b)
    })
    .await;
    let green = bg.target().unwrap().to_string();
    assert!(green.contains(":db:harbor-green-"), "{green}");
    let early = rds
        .switchover_blue_green_deployment()
        .blue_green_deployment_identifier(&id)
        .switchover_timeout(10)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&early), "InvalidParameterValue");
    let switched = rds
        .switchover_blue_green_deployment()
        .blue_green_deployment_identifier(&id)
        .send()
        .await
        .unwrap()
        .blue_green_deployment
        .unwrap();
    assert!(matches!(switched.status(), Some("SWITCHOVER_IN_PROGRESS") | Some("SWITCHOVER_COMPLETED")));
    eventually(30, || async {
        let out = rds.describe_blue_green_deployments().blue_green_deployment_identifier(&id).send().await.ok()?;
        (out.blue_green_deployments()[0].status() == Some("SWITCHOVER_COMPLETED")).then_some(())
    })
    .await;
    let new_blue = rds.describe_db_instances().db_instance_identifier("harbor").send().await.unwrap();
    assert_eq!(new_blue.db_instances()[0].engine_version().map(|v| v.starts_with("17")), Some(true));
    let old = rds.describe_db_instances().db_instance_identifier("harbor-old1").send().await.unwrap();
    assert!(old.db_instances()[0].engine_version().unwrap().starts_with("16"));
    let filtered = rds
        .describe_blue_green_deployments()
        .filters(filter("blue-green-deployment-name", "harbor-upgrade"))
        .send()
        .await
        .unwrap();
    assert_eq!(filtered.blue_green_deployments().len(), 1);
    let bad = rds
        .delete_blue_green_deployment()
        .blue_green_deployment_identifier(&id)
        .delete_target(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad), "InvalidParameterCombination");
    rds.delete_blue_green_deployment().blue_green_deployment_identifier(&id).send().await.unwrap();
    let gone = rds.describe_blue_green_deployments().blue_green_deployment_identifier(&id).send().await;
    if let Err(e) = gone {
        assert_eq!(code(&e.into_service_error()), "BlueGreenDeploymentNotFoundFault");
    }
}

#[test]
fn reserved_instances_exports_and_backtrack() {
    run(reserved_instances_exports_and_backtrack_body());
}

async fn reserved_instances_exports_and_backtrack_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = Client::new(&config);

    // ---- reserved instances ----
    let offerings = rds
        .describe_reserved_db_instances_offerings()
        .db_instance_class("db.r6g.large")
        .product_description("postgresql")
        .duration("1")
        .offering_type("No Upfront")
        .multi_az(false)
        .send()
        .await
        .unwrap();
    assert_eq!(offerings.reserved_db_instances_offerings().len(), 1);
    let offering = offerings.reserved_db_instances_offerings()[0].clone();
    assert_eq!(offering.duration(), Some(31_536_000));
    assert_eq!(offering.currency_code(), Some("USD"));
    assert_eq!(offering.recurring_charges()[0].recurring_charge_frequency(), Some("Hourly"));
    let bad_duration = rds.describe_reserved_db_instances_offerings().duration("2").send().await.unwrap_err();
    assert_eq!(code(&bad_duration), "InvalidParameterValue");
    let none = rds
        .purchase_reserved_db_instances_offering()
        .reserved_db_instances_offering_id("00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&none), "ReservedDBInstancesOfferingNotFound");
    let ri = rds
        .purchase_reserved_db_instances_offering()
        .reserved_db_instances_offering_id(offering.reserved_db_instances_offering_id().unwrap())
        .reserved_db_instance_id("langfuse-ri")
        .db_instance_count(2)
        .send()
        .await
        .unwrap()
        .reserved_db_instance
        .unwrap();
    assert_eq!(ri.state(), Some("payment-pending"));
    assert_eq!(ri.db_instance_count(), Some(2));
    let dup = rds
        .purchase_reserved_db_instances_offering()
        .reserved_db_instances_offering_id(offering.reserved_db_instances_offering_id().unwrap())
        .reserved_db_instance_id("langfuse-ri")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "ReservedDBInstanceAlreadyExists");
    let bought = rds.describe_reserved_db_instances().reserved_db_instance_id("langfuse-ri").send().await.unwrap();
    assert_eq!(bought.reserved_db_instances()[0].state(), Some("active"));
    // A year later on the emulated clock, the reservation has retired.
    mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 31622400}"#)).await;
    let retired = rds.describe_reserved_db_instances().reserved_db_instance_id("langfuse-ri").send().await.unwrap();
    assert_eq!(retired.reserved_db_instances()[0].state(), Some("retired"));
    mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;

    // ---- exports to S3 ----
    create_postgres(&rds, "registry").await;
    rds.create_db_snapshot()
        .db_instance_identifier("registry")
        .db_snapshot_identifier("registry-snap")
        .send()
        .await
        .unwrap();
    eventually(30, || async {
        let s = rds.describe_db_snapshots().db_snapshot_identifier("registry-snap").send().await.ok()?;
        (s.db_snapshots()[0].status() == Some("available")).then_some(())
    })
    .await;
    let s3 = Mws::s3(&config);
    s3.create_bucket().bucket("rds-exports").send().await.unwrap();
    let kms = aws_sdk_kms::Client::new(&config);
    let key = kms.create_key().send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    let role = service_role(&mws, "export-role", "export.rds.amazonaws.com").await;
    let snap_arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:snapshot:registry-snap");
    let bad_bucket = rds
        .start_export_task()
        .export_task_identifier("bad")
        .source_arn(&snap_arn)
        .s3_bucket_name("Not_A_Bucket")
        .iam_role_arn(&role)
        .kms_key_id(&key)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_bucket), "InvalidS3BucketFault");
    let wrong_role = service_role(&mws, "lambda-role", "lambda.amazonaws.com").await;
    let unassumable = rds
        .start_export_task()
        .export_task_identifier("bad")
        .source_arn(&snap_arn)
        .s3_bucket_name("rds-exports")
        .iam_role_arn(&wrong_role)
        .kms_key_id(&key)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&unassumable), "IamRoleNotFound");
    let bad_key = rds
        .start_export_task()
        .export_task_identifier("bad")
        .source_arn(&snap_arn)
        .s3_bucket_name("rds-exports")
        .iam_role_arn(&role)
        .kms_key_id("arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_key), "KMSKeyNotAccessibleFault");
    let task = rds
        .start_export_task()
        .export_task_identifier("registry-export")
        .source_arn(&snap_arn)
        .s3_bucket_name("rds-exports")
        .s3_prefix("nightly")
        .iam_role_arn(&role)
        .kms_key_id(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(task.source_type().map(|s| s.as_str()), Some("SNAPSHOT"));
    let done = eventually(30, || async {
        let t = rds.describe_export_tasks().export_task_identifier("registry-export").send().await.ok()?;
        let t = t.export_tasks()[0].clone();
        (t.status() == Some("COMPLETE")).then_some(t)
    })
    .await;
    assert_eq!(done.percent_progress(), Some(100));
    let objects = s3.list_objects_v2().bucket("rds-exports").prefix("nightly/registry-export/").send().await.unwrap();
    let keys: Vec<&str> = objects.contents().iter().filter_map(|o| o.key()).collect();
    assert!(keys.contains(&"nightly/registry-export/export_info_registry-export.json"), "{keys:?}");
    let info = s3
        .get_object()
        .bucket("rds-exports")
        .key("nightly/registry-export/export_info_registry-export.json")
        .send()
        .await
        .unwrap();
    assert_eq!(info.server_side_encryption().map(|s| s.as_str()), Some("aws:kms"));
    let info: serde_json::Value = serde_json::from_slice(&info.body.collect().await.unwrap().into_bytes()).unwrap();
    assert_eq!(info["status"], "COMPLETE");
    assert_eq!(info["sourceArn"], snap_arn.as_str());
    let finished = rds.cancel_export_task().export_task_identifier("registry-export").send().await.unwrap_err();
    assert_eq!(code(&finished), "InvalidExportTaskStateFault");
    let dup = rds
        .start_export_task()
        .export_task_identifier("registry-export")
        .source_arn(&snap_arn)
        .s3_bucket_name("rds-exports")
        .iam_role_arn(&role)
        .kms_key_id(&key)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "ExportTaskAlreadyExists");
    let listed = rds.describe_export_tasks().filters(filter("status", "complete")).send().await.unwrap();
    assert_eq!(listed.export_tasks().len(), 1);
    let missing = rds.describe_export_tasks().export_task_identifier("nope").send().await.unwrap_err();
    assert_eq!(code(&missing), "ExportTaskNotFound");

    // ---- backtrack ----
    let pg_backtrack = rds
        .create_db_cluster()
        .db_cluster_identifier("pg")
        .engine("aurora-postgresql")
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .backtrack_window(3600)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&pg_backtrack), "InvalidParameterCombination");
    rds.create_db_cluster()
        .db_cluster_identifier("orders")
        .engine("aurora-mysql")
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .backtrack_window(7200)
        .send()
        .await
        .unwrap();
    wait_cluster(&rds, "orders").await;
    let c = rds.describe_db_clusters().db_cluster_identifier("orders").send().await.unwrap();
    assert_eq!(c.db_clusters()[0].backtrack_window(), Some(7200));
    assert!(c.db_clusters()[0].earliest_backtrack_time().is_some());
    let future = rds
        .backtrack_db_cluster()
        .db_cluster_identifier("orders")
        .backtrack_to(aws_smithy_types::DateTime::from_secs(chrono::Utc::now().timestamp() + 3600))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&future), "InvalidParameterValue");
    let back = rds
        .backtrack_db_cluster()
        .db_cluster_identifier("orders")
        .backtrack_to(aws_smithy_types::DateTime::from_secs(chrono::Utc::now().timestamp() - 10))
        .use_earliest_time_on_point_in_time_unavailable(true)
        .send()
        .await
        .unwrap();
    let bid = back.backtrack_identifier().unwrap().to_string();
    let listed = rds.describe_db_cluster_backtracks().db_cluster_identifier("orders").send().await.unwrap();
    assert_eq!(listed.db_cluster_backtracks()[0].backtrack_identifier(), Some(bid.as_str()));
    eventually(30, || async {
        let b = rds
            .describe_db_cluster_backtracks()
            .db_cluster_identifier("orders")
            .backtrack_identifier(&bid)
            .send()
            .await
            .ok()?;
        (b.db_cluster_backtracks()[0].status() == Some("completed")).then_some(())
    })
    .await;
    let unknown = rds
        .describe_db_cluster_backtracks()
        .db_cluster_identifier("orders")
        .backtrack_identifier("nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&unknown), "DBClusterBacktrackNotFoundFault");
}

#[test]
fn limitless_integrations_and_the_rest() {
    run(limitless_integrations_and_the_rest_body());
}

async fn limitless_integrations_and_the_rest_body() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let rds = Client::new(&config);

    // ---- Limitless shard groups ----
    rds.create_db_cluster()
        .db_cluster_identifier("standard")
        .engine("aurora-postgresql")
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap();
    rds.create_db_cluster()
        .db_cluster_identifier("limitless")
        .engine("aurora-postgresql")
        .master_username("app")
        .master_user_password("correct-horse-battery")
        .cluster_scalability_type(aws_sdk_rds::types::ClusterScalabilityType::Limitless)
        .send()
        .await
        .unwrap();
    wait_cluster(&rds, "standard").await;
    wait_cluster(&rds, "limitless").await;
    let not_limitless = rds
        .create_db_shard_group()
        .db_shard_group_identifier("shards")
        .db_cluster_identifier("standard")
        .max_acu(768.0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&not_limitless), "InvalidDBClusterStateFault");
    let group = rds
        .create_db_shard_group()
        .db_shard_group_identifier("shards")
        .db_cluster_identifier("limitless")
        .max_acu(768.0)
        .compute_redundancy(1)
        .send()
        .await
        .unwrap();
    assert!(group.db_shard_group_resource_id().unwrap().starts_with("shardgrp-"));
    let second = rds
        .create_db_shard_group()
        .db_shard_group_identifier("more")
        .db_cluster_identifier("limitless")
        .max_acu(768.0)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&second), "MaxDBShardGroupLimitReached");
    eventually(30, || async {
        let g = rds.describe_db_shard_groups().db_shard_group_identifier("shards").send().await.ok()?;
        (g.db_shard_groups()[0].status() == Some("available")).then_some(())
    })
    .await;
    let blocked =
        rds.delete_db_cluster().db_cluster_identifier("limitless").skip_final_snapshot(true).send().await.unwrap_err();
    assert_eq!(code(&blocked), "InvalidDBClusterStateFault");
    let modified =
        rds.modify_db_shard_group().db_shard_group_identifier("shards").max_acu(1024.0).send().await.unwrap();
    assert_eq!(modified.max_acu(), Some(1024.0));
    eventually(30, || async {
        let g = rds.describe_db_shard_groups().db_shard_group_identifier("shards").send().await.ok()?;
        (g.db_shard_groups()[0].status() == Some("available")).then_some(())
    })
    .await;
    rds.reboot_db_shard_group().db_shard_group_identifier("shards").send().await.unwrap();
    eventually(30, || async {
        let g = rds.describe_db_shard_groups().db_shard_group_identifier("shards").send().await.ok()?;
        (g.db_shard_groups()[0].status() == Some("available")).then_some(())
    })
    .await;
    let by_cluster = rds.describe_db_shard_groups().filters(filter("db-cluster-id", "limitless")).send().await.unwrap();
    assert_eq!(by_cluster.db_shard_groups().len(), 1);
    rds.delete_db_shard_group().db_shard_group_identifier("shards").send().await.unwrap();
    eventually(30, || async {
        let g = rds.describe_db_shard_groups().db_shard_group_identifier("shards").send().await;
        g.is_err().then_some(())
    })
    .await;

    // ---- zero-ETL integrations ----
    let source = format!("arn:aws:rds:us-east-1:{ACCOUNT}:cluster:standard");
    let target =
        format!("arn:aws:redshift-serverless:us-east-1:{ACCOUNT}:namespace/7f3e0f2a-0000-4000-8000-000000000000");
    let bad_target = rds
        .create_integration()
        .integration_name("to-s3")
        .source_arn(&source)
        .target_arn("arn:aws:s3:::bucket")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_target), "InvalidParameterValue");
    let integration = rds
        .create_integration()
        .integration_name("analytics")
        .source_arn(&source)
        .target_arn(&target)
        .data_filter("include: app.*")
        .send()
        .await
        .unwrap();
    assert!(integration.integration_arn().unwrap().contains(":integration:"));
    let dup = rds
        .create_integration()
        .integration_name("analytics")
        .source_arn(&source)
        .target_arn(&target)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "IntegrationAlreadyExistsFault");
    eventually(30, || async {
        let i = rds.describe_integrations().integration_identifier("analytics").send().await.ok()?;
        (i.integrations()[0].status().map(|s| s.as_str()) == Some("active")).then_some(())
    })
    .await;
    rds.modify_integration().integration_identifier("analytics").description("BI").send().await.unwrap();
    let by_source = rds.describe_integrations().filters(filter("source-arn", &source)).send().await.unwrap();
    assert_eq!(by_source.integrations()[0].description(), Some("BI"));
    rds.delete_integration().integration_identifier(integration.integration_arn().unwrap()).send().await.unwrap();

    // ---- capacity reservations ----
    let reservation = rds
        .create_db_capacity_reservation()
        .db_capacity_reservation_name("peak")
        .db_instance_class("db.r6g.large")
        .engine("postgres")
        .capacity_per_availability_zone(2)
        .availability_zones("us-east-1a")
        .send()
        .await
        .unwrap()
        .db_capacity_reservation
        .unwrap();
    let rid = reservation.db_capacity_reservation_identifier().unwrap().to_string();
    assert_eq!(reservation.state().map(|s| s.as_str()), Some("active"));
    assert_eq!(reservation.available_capacity_per_availability_zone_list()[0].available_capacity(), Some(2));
    let bad_az = rds
        .create_db_capacity_reservation()
        .db_capacity_reservation_name("elsewhere")
        .db_instance_class("db.r6g.large")
        .engine("postgres")
        .capacity_per_availability_zone(1)
        .availability_zones("eu-west-1a")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_az), "InvalidParameterValue");
    rds.modify_db_capacity_reservation()
        .db_capacity_reservation_identifier(&rid)
        .capacity_per_availability_zone(3)
        .send()
        .await
        .unwrap();
    let cancelled = rds.cancel_db_capacity_reservation().db_capacity_reservation_identifier(&rid).send().await.unwrap();
    assert_eq!(cancelled.db_capacity_reservation().unwrap().state().map(|s| s.as_str()), Some("cancelled"));
    let again = rds.cancel_db_capacity_reservation().db_capacity_reservation_identifier(&rid).send().await.unwrap_err();
    assert_eq!(code(&again), "InvalidDBCapacityReservationState");
    let listed = rds.describe_db_capacity_reservations().send().await.unwrap();
    assert_eq!(listed.db_capacity_reservations().len(), 1);

    // ---- activity streams ----
    let kms = aws_sdk_kms::Client::new(&config);
    let key = kms.create_key().send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    let started = rds
        .start_activity_stream()
        .resource_arn(&source)
        .mode(aws_sdk_rds::types::ActivityStreamMode::Async)
        .kms_key_id(&key)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let stream = started.kinesis_stream_name().unwrap().to_string();
    assert!(stream.starts_with("aws-rds-das-cluster-"), "{stream}");
    eventually(30, || async {
        let c = rds.describe_db_clusters().db_cluster_identifier("standard").send().await.ok()?;
        (c.db_clusters()[0].activity_stream_status().map(|s| s.as_str()) == Some("started")).then_some(())
    })
    .await;
    let stopped = rds.stop_activity_stream().resource_arn(&source).send().await.unwrap();
    assert_eq!(stopped.kinesis_stream_name(), Some(stream.as_str()));
    let unlocked = rds
        .modify_activity_stream()
        .resource_arn(&source)
        .audit_policy_state(aws_sdk_rds::types::AuditPolicyState::UnlockedPolicy)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&unlocked), "ResourceNotFoundFault");

    // ---- custom engine versions ----
    let unsupported =
        rds.create_custom_db_engine_version().engine("postgres").engine_version("16.custom").send().await.unwrap_err();
    assert_eq!(code(&unsupported), "InvalidParameterValue");
    let cev = rds
        .create_custom_db_engine_version()
        .engine("custom-sqlserver-ee")
        .engine_version("15.00.4249.2.my-cev")
        .image_id("ami-0123456789abcdef0")
        .send()
        .await
        .unwrap();
    assert_eq!(cev.status(), Some("creating"));
    let versions = rds.describe_db_engine_versions().engine("custom-sqlserver-ee").send().await.unwrap();
    assert_eq!(versions.db_engine_versions().len(), 1);
    rds.modify_custom_db_engine_version()
        .engine("custom-sqlserver-ee")
        .engine_version("15.00.4249.2.my-cev")
        .status(aws_sdk_rds::types::CustomEngineVersionStatus::Inactive)
        .send()
        .await
        .unwrap();
    rds.delete_custom_db_engine_version()
        .engine("custom-sqlserver-ee")
        .engine_version("15.00.4249.2.my-cev")
        .send()
        .await
        .unwrap();
    let gone = rds
        .delete_custom_db_engine_version()
        .engine("custom-sqlserver-ee")
        .engine_version("15.00.4249.2.my-cev")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&gone), "CustomDBEngineVersionNotFoundFault");

    // ---- catalogs, certificates, recommendations ----
    let platforms = rds
        .describe_serverless_v2_platform_versions()
        .engine("aurora-postgresql")
        .default_only(true)
        .send()
        .await
        .unwrap();
    assert_eq!(platforms.serverless_v2_platform_versions().len(), 1);
    let certs = rds.describe_certificates().send().await.unwrap();
    let other = certs
        .certificates()
        .iter()
        .find(|c| Some(c.certificate_identifier().unwrap()) != certs.default_certificate_for_new_launches())
        .unwrap()
        .certificate_identifier()
        .unwrap()
        .to_string();
    let modified = rds.modify_certificates().certificate_identifier(&other).send().await.unwrap();
    assert_eq!(modified.certificate().unwrap().customer_override(), Some(true));
    let certs = rds.describe_certificates().send().await.unwrap();
    assert_eq!(certs.default_certificate_for_new_launches(), Some(other.as_str()));
    rds.modify_certificates().remove_customer_override(true).send().await.unwrap();
    let recs = rds.describe_db_recommendations().send().await.unwrap();
    assert!(recs.db_recommendations().is_empty());

    // ---- what MWS's engines don't have ----
    let classic = rds
        .create_db_security_group()
        .db_security_group_name("classic")
        .db_security_group_description("EC2-Classic")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&classic), "DBSecurityGroupNotSupported");
    assert!(rds.describe_db_security_groups().send().await.unwrap().db_security_groups().is_empty());
    create_postgres(&rds, "app").await;
    let tenant = rds
        .create_tenant_database()
        .db_instance_identifier("app")
        .tenant_db_name("pdb1")
        .master_username("admin")
        .master_user_password("correct-horse-battery")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&tenant), "InvalidDBInstanceState");
    assert!(rds.describe_tenant_databases().send().await.unwrap().tenant_databases().is_empty());
    let not_replica = rds.switchover_read_replica().db_instance_identifier("app").send().await.unwrap_err();
    assert_eq!(code(&not_replica), "InvalidDBInstanceState");
    let not_cluster_replica =
        rds.promote_read_replica_db_cluster().db_cluster_identifier("standard").send().await.unwrap_err();
    assert_eq!(code(&not_cluster_replica), "InvalidDBClusterStateFault");
    let not_v1 = rds
        .modify_current_db_cluster_capacity()
        .db_cluster_identifier("standard")
        .capacity(8)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&not_v1), "InvalidDBClusterStateFault");

    // ---- cross-Region automated backup replication ----
    let west = Client::new(
        &aws_config::SdkConfig::builder()
            .region(aws_config::Region::new("us-west-2"))
            .credentials_provider(config.credentials_provider().unwrap())
            .endpoint_url(config.endpoint_url().unwrap())
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build(),
    );
    let app_arn = format!("arn:aws:rds:us-east-1:{ACCOUNT}:db:app");
    let replicated = west
        .start_db_instance_automated_backups_replication()
        .source_db_instance_arn(&app_arn)
        .backup_retention_period(7)
        .send()
        .await
        .unwrap()
        .db_instance_automated_backup
        .unwrap();
    assert_eq!(replicated.status(), Some("replicating"));
    assert_eq!(replicated.region(), Some("us-west-2"));
    let source = rds.describe_db_instances().db_instance_identifier("app").send().await.unwrap();
    assert_eq!(source.db_instances()[0].db_instance_automated_backups_replications().len(), 1);
    let in_west = west.describe_db_instance_automated_backups().send().await.unwrap();
    assert_eq!(in_west.db_instance_automated_backups().len(), 1);
    let stopped =
        west.stop_db_instance_automated_backups_replication().source_db_instance_arn(&app_arn).send().await.unwrap();
    assert_eq!(stopped.db_instance_automated_backup().unwrap().status(), Some("retained"));
    let source = rds.describe_db_instances().db_instance_identifier("app").send().await.unwrap();
    assert!(source.db_instances()[0].db_instance_automated_backups_replications().is_empty());
}
