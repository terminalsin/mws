//! ElastiCache through the official Rust SDK, with the metadata backend
//! (resources become available at once; see `elasticache_docker` for
//! nodes that really run).

use aws_sdk_elasticache::error::ProvideErrorMetadata;
use aws_sdk_elasticache::types::{
    AuthenticationMode, CacheUsageLimits, CustomerNodeEndpoint, DataStorage, DataStorageUnit, EcpuPerSecond,
    InputAuthenticationType, ParameterNameValue, ReshardingConfiguration, SourceType, Tag,
};
use aws_sdk_elasticache::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

async fn client_in(mws: &Mws, region: &str) -> Client {
    let cfg = mws.root_sdk_config().await;
    let conf = aws_sdk_elasticache::config::Builder::from(&cfg)
        .region(aws_sdk_elasticache::config::Region::new(region.to_string()))
        .build();
    Client::from_conf(conf)
}

fn code(e: &impl ProvideErrorMetadata) -> String {
    e.code().unwrap_or_default().to_string()
}

fn tag(k: &str, v: &str) -> Tag {
    Tag::builder().key(k).value(v).build()
}

#[tokio::test]
async fn cache_clusters() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;

    let c = ec
        .create_cache_cluster()
        .cache_cluster_id("Memcache-1")
        .engine("memcached")
        .cache_node_type("cache.t3.micro")
        .num_cache_nodes(2)
        .tags(tag("team", "web"))
        .send()
        .await
        .unwrap();
    let c = c.cache_cluster().unwrap();
    // Identifiers are stored in lowercase.
    assert_eq!(c.cache_cluster_id(), Some("memcache-1"));
    assert_eq!(c.engine(), Some("memcached"));
    assert_eq!(c.engine_version(), Some("1.6.22"));
    let arn = c.arn().unwrap().to_string();
    assert_eq!(arn, format!("arn:aws:elasticache:us-east-1:{ACCOUNT}:cluster:memcache-1"));

    let d =
        ec.describe_cache_clusters().cache_cluster_id("memcache-1").show_cache_node_info(true).send().await.unwrap();
    let c = &d.cache_clusters()[0];
    assert_eq!(c.cache_cluster_status(), Some("available"));
    assert_eq!(c.cache_nodes().len(), 2);
    assert_eq!(c.cache_nodes()[0].cache_node_id(), Some("0001"));
    assert_eq!(c.configuration_endpoint().and_then(|e| e.port()), Some(11211));
    assert_eq!(c.cache_parameter_group().and_then(|p| p.cache_parameter_group_name()), Some("default.memcached1.6"));

    let e = ec
        .create_cache_cluster()
        .cache_cluster_id("memcache-1")
        .engine("memcached")
        .cache_node_type("cache.t3.micro")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheClusterAlreadyExists");
    let e = ec
        .create_cache_cluster()
        .cache_cluster_id("bad")
        .engine("redis")
        .cache_node_type("cache.nope")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let e = ec.describe_cache_clusters().cache_cluster_id("missing").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheClusterNotFound");

    let m = ec
        .modify_cache_cluster()
        .cache_cluster_id("memcache-1")
        .num_cache_nodes(3)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    assert!(m.cache_cluster().is_some());
    let d =
        ec.describe_cache_clusters().cache_cluster_id("memcache-1").show_cache_node_info(true).send().await.unwrap();
    assert_eq!(d.cache_clusters()[0].cache_nodes().len(), 3);

    let r =
        ec.reboot_cache_cluster().cache_cluster_id("memcache-1").cache_node_ids_to_reboot("0001").send().await.unwrap();
    assert!(r.cache_cluster().is_some());

    // A standalone Redis OSS node.
    let r = ec
        .create_cache_cluster()
        .cache_cluster_id("redis-1")
        .engine("redis")
        .cache_node_type("cache.r6g.large")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.cache_cluster().unwrap().engine_version(), Some("7.1.0"));
    let e = ec
        .create_cache_cluster()
        .cache_cluster_id("redis-2")
        .engine("redis")
        .cache_node_type("cache.r6g.large")
        .num_cache_nodes(2)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let allowed = ec.list_allowed_node_type_modifications().cache_cluster_id("redis-1").send().await.unwrap();
    assert!(allowed.scale_up_modifications().iter().any(|t| t == "cache.r6g.xlarge"));
    assert!(
        allowed.scale_down_modifications().iter().any(|t| t == "cache.r6g.large")
            || !allowed.scale_down_modifications().is_empty()
    );

    let all = ec.describe_cache_clusters().send().await.unwrap();
    assert_eq!(all.cache_clusters().len(), 2);

    let del = ec.delete_cache_cluster().cache_cluster_id("memcache-1").send().await.unwrap();
    assert_eq!(del.cache_cluster().unwrap().cache_cluster_status(), Some("deleting"));
    ec.delete_cache_cluster().cache_cluster_id("redis-1").send().await.unwrap();
    let all = ec.describe_cache_clusters().send().await.unwrap();
    assert!(all.cache_clusters().is_empty());
}

#[tokio::test]
async fn replication_groups() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;

    let g = ec
        .create_replication_group()
        .replication_group_id("sessions")
        .replication_group_description("session store")
        .engine("valkey")
        .cache_node_type("cache.r7g.large")
        .num_cache_clusters(2)
        .automatic_failover_enabled(true)
        .multi_az_enabled(true)
        .transit_encryption_enabled(true)
        .auth_token("a-very-long-auth-token-1234")
        .send()
        .await
        .unwrap();
    let g = g.replication_group().unwrap();
    assert_eq!(g.replication_group_id(), Some("sessions"));

    let d = ec.describe_replication_groups().replication_group_id("sessions").send().await.unwrap();
    let g = &d.replication_groups()[0];
    assert_eq!(g.status(), Some("available"));
    assert_eq!(g.member_clusters().len(), 2);
    assert_eq!(g.auth_token_enabled(), Some(true));
    let ng = &g.node_groups()[0];
    assert!(ng.primary_endpoint().is_some());
    assert!(ng.reader_endpoint().is_some());
    assert_eq!(ng.node_group_members().len(), 2);
    let primary = ng
        .node_group_members()
        .iter()
        .find(|m| m.current_role() == Some("primary"))
        .and_then(|m| m.cache_cluster_id())
        .unwrap()
        .to_string();
    assert_eq!(primary, "sessions-001");

    let m = ec
        .modify_replication_group()
        .replication_group_id("sessions")
        .replication_group_description("sessions v2")
        .snapshot_retention_limit(3)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    assert_eq!(m.replication_group().unwrap().description(), Some("sessions v2"));

    ec.increase_replica_count()
        .replication_group_id("sessions")
        .new_replica_count(2)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let d = ec.describe_replication_groups().replication_group_id("sessions").send().await.unwrap();
    assert_eq!(d.replication_groups()[0].member_clusters().len(), 3);
    ec.decrease_replica_count()
        .replication_group_id("sessions")
        .new_replica_count(1)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let d = ec.describe_replication_groups().replication_group_id("sessions").send().await.unwrap();
    assert_eq!(d.replication_groups()[0].member_clusters().len(), 2);

    let f = ec.test_failover().replication_group_id("sessions").node_group_id("0001").send().await.unwrap();
    assert!(f.replication_group().is_some());
    let d = ec.describe_replication_groups().replication_group_id("sessions").send().await.unwrap();
    let new_primary = d.replication_groups()[0].node_groups()[0]
        .node_group_members()
        .iter()
        .find(|m| m.current_role() == Some("primary"))
        .and_then(|m| m.cache_cluster_id())
        .unwrap()
        .to_string();
    assert_ne!(new_primary, primary);

    // Cluster mode: shards with slot ranges, resharded online.
    let c = ec
        .create_replication_group()
        .replication_group_id("shards")
        .replication_group_description("sharded")
        .engine("redis")
        .cache_node_type("cache.r7g.large")
        .num_node_groups(2)
        .replicas_per_node_group(1)
        .automatic_failover_enabled(true)
        .send()
        .await
        .unwrap();
    assert_eq!(c.replication_group().unwrap().cluster_enabled(), Some(true));
    let d = ec.describe_replication_groups().replication_group_id("shards").send().await.unwrap();
    let g = &d.replication_groups()[0];
    assert!(g.configuration_endpoint().is_some());
    let slots: Vec<_> = g.node_groups().iter().filter_map(|n| n.slots()).collect();
    assert_eq!(slots, vec!["0-8191", "8192-16383"]);
    ec.modify_replication_group_shard_configuration()
        .replication_group_id("shards")
        .node_group_count(3)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let d = ec.describe_replication_groups().replication_group_id("shards").send().await.unwrap();
    assert_eq!(d.replication_groups()[0].node_groups().len(), 3);

    let e = ec.delete_replication_group().replication_group_id("missing").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ReplicationGroupNotFoundFault");
    ec.delete_replication_group().replication_group_id("shards").send().await.unwrap();
    ec.delete_replication_group().replication_group_id("sessions").send().await.unwrap();
    assert!(ec.describe_replication_groups().send().await.unwrap().replication_groups().is_empty());
    assert!(ec.describe_cache_clusters().send().await.unwrap().cache_clusters().is_empty());
}

#[tokio::test]
async fn parameter_groups() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;

    let p = ec
        .create_cache_parameter_group()
        .cache_parameter_group_name("tuned")
        .cache_parameter_group_family("redis7")
        .description("tuned redis")
        .send()
        .await
        .unwrap();
    assert_eq!(p.cache_parameter_group().unwrap().cache_parameter_group_family(), Some("redis7"));

    let groups = ec.describe_cache_parameter_groups().send().await.unwrap();
    assert!(groups.cache_parameter_groups().iter().any(|g| g.cache_parameter_group_name() == Some("default.redis7")));
    assert!(groups.cache_parameter_groups().iter().any(|g| g.cache_parameter_group_name() == Some("tuned")));

    ec.modify_cache_parameter_group()
        .cache_parameter_group_name("tuned")
        .parameter_name_values(
            ParameterNameValue::builder().parameter_name("maxmemory-policy").parameter_value("allkeys-lru").build(),
        )
        .send()
        .await
        .unwrap();
    let params =
        ec.describe_cache_parameters().cache_parameter_group_name("tuned").source("user").send().await.unwrap();
    let p = &params.parameters()[0];
    assert_eq!(p.parameter_name(), Some("maxmemory-policy"));
    assert_eq!(p.parameter_value(), Some("allkeys-lru"));

    let e = ec
        .modify_cache_parameter_group()
        .cache_parameter_group_name("tuned")
        .parameter_name_values(
            ParameterNameValue::builder().parameter_name("maxmemory-policy").parameter_value("sometimes").build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let e = ec
        .modify_cache_parameter_group()
        .cache_parameter_group_name("default.redis7")
        .parameter_name_values(
            ParameterNameValue::builder().parameter_name("maxmemory-policy").parameter_value("allkeys-lru").build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidCacheParameterGroupState");

    ec.reset_cache_parameter_group()
        .cache_parameter_group_name("tuned")
        .reset_all_parameters(true)
        .send()
        .await
        .unwrap();
    let params =
        ec.describe_cache_parameters().cache_parameter_group_name("tuned").source("user").send().await.unwrap();
    assert!(params.parameters().is_empty());

    let defaults =
        ec.describe_engine_default_parameters().cache_parameter_group_family("memcached1.6").send().await.unwrap();
    let defaults = defaults.engine_defaults().unwrap();
    assert_eq!(defaults.cache_parameter_group_family(), Some("memcached1.6"));
    assert!(defaults.parameters().iter().any(|p| p.parameter_name() == Some("max_item_size")));

    ec.delete_cache_parameter_group().cache_parameter_group_name("tuned").send().await.unwrap();
    let e = ec.delete_cache_parameter_group().cache_parameter_group_name("tuned").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheParameterGroupNotFound");
}

#[tokio::test]
async fn subnet_and_security_groups() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;
    let ec2 = aws_sdk_ec2::Client::new(&mws.root_sdk_config().await);
    let subnets = ec2.describe_subnets().send().await.unwrap();
    let ids: Vec<String> = subnets.subnets().iter().filter_map(|s| s.subnet_id().map(str::to_string)).collect();
    assert!(ids.len() >= 2);

    let g = ec
        .create_cache_subnet_group()
        .cache_subnet_group_name("app")
        .cache_subnet_group_description("app subnets")
        .subnet_ids(&ids[0])
        .send()
        .await
        .unwrap();
    let g = g.cache_subnet_group().unwrap();
    assert!(g.vpc_id().unwrap().starts_with("vpc-"));
    assert_eq!(g.subnets().len(), 1);
    assert!(g.subnets()[0].subnet_availability_zone().and_then(|z| z.name()).is_some());

    let e = ec
        .create_cache_subnet_group()
        .cache_subnet_group_name("bad")
        .cache_subnet_group_description("bad")
        .subnet_ids("subnet-00000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidSubnet");

    let m = ec
        .modify_cache_subnet_group()
        .cache_subnet_group_name("app")
        .subnet_ids(&ids[0])
        .subnet_ids(&ids[1])
        .send()
        .await
        .unwrap();
    assert_eq!(m.cache_subnet_group().unwrap().subnets().len(), 2);
    let d = ec.describe_cache_subnet_groups().cache_subnet_group_name("app").send().await.unwrap();
    assert_eq!(d.cache_subnet_groups()[0].cache_subnet_group_description(), Some("app subnets"));

    // A cluster in the group; the group can't be deleted while used.
    ec.create_cache_cluster()
        .cache_cluster_id("in-vpc")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(1)
        .cache_subnet_group_name("app")
        .send()
        .await
        .unwrap();
    let e = ec.delete_cache_subnet_group().cache_subnet_group_name("app").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheSubnetGroupInUse");
    ec.delete_cache_cluster().cache_cluster_id("in-vpc").send().await.unwrap();
    ec.delete_cache_subnet_group().cache_subnet_group_name("app").send().await.unwrap();

    // Cache security groups belong to EC2-Classic, which accounts no longer
    // have.
    let e =
        ec.create_cache_security_group().cache_security_group_name("old").description("old").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let d = ec.describe_cache_security_groups().send().await.unwrap();
    assert!(d.cache_security_groups().is_empty());
    let e = ec.delete_cache_security_group().cache_security_group_name("old").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheSecurityGroupNotFound");
    let e = ec
        .authorize_cache_security_group_ingress()
        .cache_security_group_name("old")
        .ec2_security_group_name("web")
        .ec2_security_group_owner_id(ACCOUNT)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheSecurityGroupNotFound");
    let e = ec
        .revoke_cache_security_group_ingress()
        .cache_security_group_name("old")
        .ec2_security_group_name("web")
        .ec2_security_group_owner_id(ACCOUNT)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheSecurityGroupNotFound");
}

#[tokio::test]
async fn users_and_user_groups() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;

    let users = ec.describe_users().send().await.unwrap();
    assert!(users.users().iter().any(|u| u.user_id() == Some("default")));

    let u = ec
        .create_user()
        .user_id("app-user")
        .user_name("app")
        .engine("redis")
        .access_string("on ~app:* +@read +@write")
        .passwords("a-password-of-sixteen-plus")
        .send()
        .await
        .unwrap();
    assert_eq!(u.authentication().and_then(|a| a.password_count()), Some(1));
    assert_eq!(u.status(), Some("active"));

    let e = ec
        .create_user()
        .user_id("bad")
        .user_name("bad")
        .engine("redis")
        .access_string("on")
        .passwords("short")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");

    let m = ec
        .modify_user()
        .user_id("app-user")
        .authentication_mode(
            AuthenticationMode::builder()
                .r#type(InputAuthenticationType::Password)
                .passwords("another-password-of-16")
                .passwords("third-password-of-sixteen")
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(m.authentication().and_then(|a| a.password_count()), Some(2));

    let nopass = ec
        .create_user()
        .user_id("default-off")
        .user_name("default")
        .engine("redis")
        .access_string("off")
        .no_password_required(true)
        .send()
        .await
        .unwrap();
    assert_eq!(nopass.authentication().and_then(|a| a.r#type()).map(|t| t.as_str()), Some("no-password"));

    let g = ec
        .create_user_group()
        .user_group_id("app-users")
        .engine("redis")
        .user_ids("default-off")
        .user_ids("app-user")
        .send()
        .await
        .unwrap();
    assert_eq!(g.user_ids().len(), 2);

    // A group needs a user named `default`.
    let e = ec
        .create_user_group()
        .user_group_id("no-default")
        .engine("redis")
        .user_ids("app-user")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "DefaultUserRequired");

    let m = ec.modify_user_group().user_group_id("app-users").user_ids_to_remove("app-user").send().await.unwrap();
    assert!(m.pending_changes().is_some() || m.user_ids().len() == 1);
    let d = ec.describe_user_groups().user_group_id("app-users").send().await.unwrap();
    assert_eq!(d.user_groups()[0].user_ids(), ["default-off"]);

    let g = ec
        .create_replication_group()
        .replication_group_id("rbac")
        .replication_group_description("rbac")
        .engine("redis")
        .cache_node_type("cache.t4g.small")
        .num_cache_clusters(1)
        .transit_encryption_enabled(true)
        .user_group_ids("app-users")
        .send()
        .await
        .unwrap();
    assert_eq!(g.replication_group().unwrap().user_group_ids(), ["app-users"]);
    let e = ec.delete_user_group().user_group_id("app-users").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidUserGroupState");
    ec.delete_replication_group().replication_group_id("rbac").send().await.unwrap();

    ec.delete_user_group().user_group_id("app-users").send().await.unwrap();
    ec.delete_user().user_id("app-user").send().await.unwrap();
    let e = ec.delete_user().user_id("default").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidUserState");
    let e = ec.describe_users().user_id("app-user").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "UserNotFound");
}

#[tokio::test]
async fn snapshots_copy_restore_and_export() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;
    let s3 = Mws::s3(&mws.root_sdk_config().await);

    ec.create_cache_cluster()
        .cache_cluster_id("source")
        .engine("redis")
        .cache_node_type("cache.m7g.large")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap();
    let s = ec.create_snapshot().cache_cluster_id("source").snapshot_name("nightly").send().await.unwrap();
    assert_eq!(s.snapshot().unwrap().snapshot_source(), Some("manual"));
    let d = ec.describe_snapshots().snapshot_name("nightly").send().await.unwrap();
    assert_eq!(d.snapshots()[0].snapshot_status(), Some("available"));
    assert_eq!(d.snapshots()[0].cache_cluster_id(), Some("source"));

    let c =
        ec.copy_snapshot().source_snapshot_name("nightly").target_snapshot_name("nightly-copy").send().await.unwrap();
    assert_eq!(c.snapshot().unwrap().snapshot_name(), Some("nightly-copy"));

    // Export to S3 needs the bucket to let ElastiCache write.
    s3.create_bucket().bucket("cache-exports").send().await.unwrap();
    let e = ec
        .copy_snapshot()
        .source_snapshot_name("nightly")
        .target_snapshot_name("export")
        .target_bucket("cache-exports")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidParameterValue");
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "elasticache.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::cache-exports/*"
        }]
    });
    s3.put_bucket_policy().bucket("cache-exports").policy(policy.to_string()).send().await.unwrap();
    ec.copy_snapshot()
        .source_snapshot_name("nightly")
        .target_snapshot_name("export")
        .target_bucket("cache-exports")
        .send()
        .await
        .unwrap();
    let obj = s3.get_object().bucket("cache-exports").key("export-0001.rdb").send().await.unwrap();
    let body = obj.body.collect().await.unwrap().into_bytes();
    assert!(body.starts_with(b"REDIS"));

    // Restore into a new replication group.
    let r = ec
        .create_replication_group()
        .replication_group_id("restored")
        .replication_group_description("from snapshot")
        .snapshot_name("nightly")
        .cache_node_type("cache.m7g.large")
        .num_cache_clusters(1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.replication_group().unwrap().replication_group_id(), Some("restored"));

    ec.delete_snapshot().snapshot_name("nightly-copy").send().await.unwrap();
    let e = ec.delete_snapshot().snapshot_name("nightly-copy").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "SnapshotNotFoundFault");

    // A final snapshot on delete.
    ec.delete_cache_cluster()
        .cache_cluster_id("source")
        .final_snapshot_identifier("source-final")
        .send()
        .await
        .unwrap();
    let d = ec.describe_snapshots().snapshot_name("source-final").send().await.unwrap();
    assert_eq!(d.snapshots().len(), 1);
}

#[tokio::test]
async fn serverless_caches() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;
    let s3 = Mws::s3(&mws.root_sdk_config().await);

    let c = ec
        .create_serverless_cache()
        .serverless_cache_name("Sessions")
        .engine("valkey")
        .cache_usage_limits(
            CacheUsageLimits::builder()
                .data_storage(DataStorage::builder().maximum(10).unit(DataStorageUnit::Gb).build())
                .ecpu_per_second(EcpuPerSecond::builder().maximum(5000).build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let c = c.serverless_cache().unwrap();
    assert_eq!(c.serverless_cache_name(), Some("sessions"));
    assert_eq!(c.status(), Some("creating"));
    assert_eq!(c.major_engine_version(), Some("8"));
    assert!(c.endpoint().is_some());
    assert!(c.reader_endpoint().is_some());

    let d = ec.describe_serverless_caches().serverless_cache_name("sessions").send().await.unwrap();
    assert_eq!(d.serverless_caches()[0].status(), Some("available"));

    let e = ec.create_serverless_cache().serverless_cache_name("sessions").engine("valkey").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ServerlessCacheAlreadyExistsFault");

    let m = ec
        .modify_serverless_cache()
        .serverless_cache_name("sessions")
        .description("user sessions")
        .snapshot_retention_limit(5)
        .send()
        .await
        .unwrap();
    assert_eq!(m.serverless_cache().unwrap().description(), Some("user sessions"));

    let s = ec
        .create_serverless_cache_snapshot()
        .serverless_cache_name("sessions")
        .serverless_cache_snapshot_name("snap-1")
        .send()
        .await
        .unwrap();
    assert_eq!(s.serverless_cache_snapshot().unwrap().snapshot_type(), Some("manual"));
    let d = ec.describe_serverless_cache_snapshots().serverless_cache_name("sessions").send().await.unwrap();
    assert_eq!(d.serverless_cache_snapshots()[0].status(), Some("available"));
    ec.copy_serverless_cache_snapshot()
        .source_serverless_cache_snapshot_name("snap-1")
        .target_serverless_cache_snapshot_name("snap-2")
        .send()
        .await
        .unwrap();
    assert_eq!(ec.describe_serverless_cache_snapshots().send().await.unwrap().serverless_cache_snapshots().len(), 2);

    s3.create_bucket().bucket("serverless-exports").send().await.unwrap();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "elasticache.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::serverless-exports/*"
        }]
    });
    s3.put_bucket_policy().bucket("serverless-exports").policy(policy.to_string()).send().await.unwrap();
    ec.export_serverless_cache_snapshot()
        .serverless_cache_snapshot_name("snap-1")
        .s3_bucket_name("serverless-exports")
        .send()
        .await
        .unwrap();
    s3.head_object().bucket("serverless-exports").key("snap-1-0001.rdb").send().await.unwrap();

    // Restore a new cache from a snapshot.
    ec.create_serverless_cache()
        .serverless_cache_name("restored")
        .engine("valkey")
        .snapshot_arns_to_restore("snap-2")
        .send()
        .await
        .unwrap();

    // Migration into a serverless cache.
    let p = ec
        .prepare_migration()
        .serverless_cache_name("restored")
        .customer_node_endpoint_list(CustomerNodeEndpoint::builder().address("10.0.0.5").port(6379).build())
        .send()
        .await
        .unwrap();
    assert_eq!(p.serverless_cache().and_then(|c| c.migration()).and_then(|m| m.status()), Some("ready"));
    ec.stop_migration().serverless_cache_name("restored").send().await.unwrap();
    let e = ec.stop_migration().serverless_cache_name("restored").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ServerlessCacheNotUnderMigrationFault");

    ec.delete_serverless_cache_snapshot().serverless_cache_snapshot_name("snap-2").send().await.unwrap();
    let del = ec.delete_serverless_cache().serverless_cache_name("sessions").send().await.unwrap();
    assert_eq!(del.serverless_cache().unwrap().status(), Some("deleting"));
    let e = ec.describe_serverless_caches().serverless_cache_name("sessions").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ServerlessCacheNotFoundFault");
}

#[tokio::test]
async fn global_datastores() {
    let mws = Mws::start().await;
    let east = client(&mws).await;
    let west = client_in(&mws, "us-west-2").await;

    east.create_replication_group()
        .replication_group_id("primary")
        .replication_group_description("primary")
        .engine("redis")
        .cache_node_type("cache.r7g.large")
        .num_node_groups(2)
        .replicas_per_node_group(1)
        .automatic_failover_enabled(true)
        .send()
        .await
        .unwrap();
    let g = east
        .create_global_replication_group()
        .global_replication_group_id_suffix("app")
        .primary_replication_group_id("primary")
        .global_replication_group_description("everywhere")
        .send()
        .await
        .unwrap();
    let id = g.global_replication_group().unwrap().global_replication_group_id().unwrap().to_string();
    assert_eq!(id, "ldgnf-app");

    // A secondary in another Region takes its settings from the primary.
    let s = west
        .create_replication_group()
        .replication_group_id("secondary")
        .replication_group_description("secondary")
        .global_replication_group_id(&id)
        .send()
        .await
        .unwrap();
    let s = s.replication_group().unwrap();
    assert_eq!(
        s.global_replication_group_info().and_then(|i| i.global_replication_group_member_role()),
        Some("SECONDARY")
    );
    assert_eq!(s.cluster_enabled(), Some(true));

    let d = east
        .describe_global_replication_groups()
        .global_replication_group_id(&id)
        .show_member_info(true)
        .send()
        .await
        .unwrap();
    let g = &d.global_replication_groups()[0];
    assert_eq!(g.members().len(), 2);
    assert_eq!(g.global_node_groups().len(), 2);
    assert_eq!(g.status(), Some("available"));

    east.modify_global_replication_group()
        .global_replication_group_id(&id)
        .global_replication_group_description("both coasts")
        .apply_immediately(true)
        .send()
        .await
        .unwrap();

    east.increase_node_groups_in_global_replication_group()
        .global_replication_group_id(&id)
        .node_group_count(3)
        .regional_configurations(
            aws_sdk_elasticache::types::RegionalConfiguration::builder()
                .replication_group_id("secondary")
                .replication_group_region("us-west-2")
                .resharding_configuration(
                    ReshardingConfiguration::builder().preferred_availability_zones("us-west-2a").build(),
                )
                .build(),
        )
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let d = east.describe_global_replication_groups().global_replication_group_id(&id).send().await.unwrap();
    assert_eq!(d.global_replication_groups()[0].global_node_groups().len(), 3);
    east.decrease_node_groups_in_global_replication_group()
        .global_replication_group_id(&id)
        .node_group_count(2)
        .global_node_groups_to_retain(format!("{id}-0001"))
        .global_node_groups_to_retain(format!("{id}-0002"))
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    east.rebalance_slots_in_global_replication_group()
        .global_replication_group_id(&id)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();

    let f = east
        .failover_global_replication_group()
        .global_replication_group_id(&id)
        .primary_region("us-west-2")
        .primary_replication_group_id("secondary")
        .send()
        .await
        .unwrap();
    let members = f.global_replication_group().unwrap().members();
    assert!(members.iter().any(|m| m.replication_group_id() == Some("secondary") && m.role() == Some("PRIMARY")));

    // Secondaries leave before the global datastore is deleted.
    let e = east
        .delete_global_replication_group()
        .global_replication_group_id(&id)
        .retain_primary_replication_group(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidGlobalReplicationGroupState");
    east.disassociate_global_replication_group()
        .global_replication_group_id(&id)
        .replication_group_id("primary")
        .replication_group_region("us-east-1")
        .send()
        .await
        .unwrap();
    east.delete_global_replication_group()
        .global_replication_group_id(&id)
        .retain_primary_replication_group(true)
        .send()
        .await
        .unwrap();
    let e = east.describe_global_replication_groups().global_replication_group_id(&id).send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "GlobalReplicationGroupNotFoundFault");
    let d = west.describe_replication_groups().replication_group_id("secondary").send().await.unwrap();
    assert!(d.replication_groups()[0].global_replication_group_info().is_none());
}

#[tokio::test]
async fn online_migration() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;
    ec.create_replication_group()
        .replication_group_id("target")
        .replication_group_description("migration target")
        .engine("redis")
        .cache_node_type("cache.r7g.large")
        .num_cache_clusters(1)
        .send()
        .await
        .unwrap();
    let endpoint = CustomerNodeEndpoint::builder().address("10.0.0.5").port(6379).build();
    ec.test_migration()
        .replication_group_id("target")
        .customer_node_endpoint_list(endpoint.clone())
        .send()
        .await
        .unwrap();
    let s = ec
        .start_migration()
        .replication_group_id("target")
        .customer_node_endpoint_list(endpoint.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(s.replication_group().unwrap().status(), Some("modifying"));
    let e = ec
        .start_migration()
        .replication_group_id("target")
        .customer_node_endpoint_list(endpoint)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ReplicationGroupAlreadyUnderMigrationFault");
    let c = ec.complete_migration().replication_group_id("target").send().await.unwrap();
    assert_eq!(c.replication_group().unwrap().status(), Some("available"));
    let e = ec.complete_migration().replication_group_id("target").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ReplicationGroupNotUnderMigrationFault");
}

#[tokio::test]
async fn tags_events_versions_reservations_and_updates() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;

    let c = ec
        .create_cache_cluster()
        .cache_cluster_id("old-redis")
        .engine("redis")
        .engine_version("7.0")
        .cache_node_type("cache.t4g.small")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap();
    let arn = c.cache_cluster().unwrap().arn().unwrap().to_string();

    ec.add_tags_to_resource()
        .resource_name(&arn)
        .tags(tag("env", "test"))
        .tags(tag("team", "core"))
        .send()
        .await
        .unwrap();
    let t = ec.list_tags_for_resource().resource_name(&arn).send().await.unwrap();
    assert_eq!(t.tag_list().len(), 2);
    let t = ec.remove_tags_from_resource().resource_name(&arn).tag_keys("team").send().await.unwrap();
    assert_eq!(t.tag_list().len(), 1);
    let e = ec.list_tags_for_resource().resource_name("not-an-arn").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "InvalidARN");
    let e = ec
        .list_tags_for_resource()
        .resource_name(format!("arn:aws:elasticache:us-east-1:{ACCOUNT}:cluster:missing"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "CacheClusterNotFound");

    let ev =
        ec.describe_events().source_type(SourceType::CacheCluster).source_identifier("old-redis").send().await.unwrap();
    assert!(ev.events().iter().any(|e| e.message().is_some_and(|m| m.contains("created"))));

    let v = ec.describe_cache_engine_versions().engine("valkey").send().await.unwrap();
    assert!(v.cache_engine_versions().iter().any(|v| v.engine_version() == Some("8.0.1")));
    let v = ec.describe_cache_engine_versions().engine("redis").default_only(true).send().await.unwrap();
    assert_eq!(v.cache_engine_versions().len(), 1);

    let o = ec
        .describe_reserved_cache_nodes_offerings()
        .cache_node_type("cache.r7g.large")
        .duration("1")
        .offering_type("No Upfront")
        .product_description("redis")
        .send()
        .await
        .unwrap();
    assert_eq!(o.reserved_cache_nodes_offerings().len(), 1);
    let offering = o.reserved_cache_nodes_offerings()[0].reserved_cache_nodes_offering_id().unwrap().to_string();
    let p = ec
        .purchase_reserved_cache_nodes_offering()
        .reserved_cache_nodes_offering_id(&offering)
        .reserved_cache_node_id("my-reservation")
        .cache_node_count(2)
        .send()
        .await
        .unwrap();
    assert_eq!(p.reserved_cache_node().unwrap().cache_node_count(), Some(2));
    let r = ec.describe_reserved_cache_nodes().reserved_cache_node_id("my-reservation").send().await.unwrap();
    assert_eq!(r.reserved_cache_nodes()[0].state(), Some("active"));
    let e = ec
        .purchase_reserved_cache_nodes_offering()
        .reserved_cache_nodes_offering_id(&offering)
        .reserved_cache_node_id("my-reservation")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "ReservedCacheNodeAlreadyExists");

    let u = ec.describe_service_updates().send().await.unwrap();
    let update = u
        .service_updates()
        .iter()
        .find(|u| u.engine() == Some("redis"))
        .and_then(|u| u.service_update_name())
        .unwrap()
        .to_string();
    // The update applies to the Redis OSS 7.0 cluster.
    let a =
        ec.describe_update_actions().service_update_name(&update).cache_cluster_ids("old-redis").send().await.unwrap();
    assert_eq!(a.update_actions()[0].update_action_status().map(|s| s.as_str()), Some("not-applied"));
    let stop =
        ec.batch_stop_update_action().service_update_name(&update).cache_cluster_ids("old-redis").send().await.unwrap();
    assert_eq!(stop.unprocessed_update_actions().len(), 1);
    let applied = ec
        .batch_apply_update_action()
        .service_update_name(&update)
        .cache_cluster_ids("old-redis")
        .send()
        .await
        .unwrap();
    assert_eq!(applied.processed_update_actions().len(), 1);
    let a = ec
        .describe_update_actions()
        .service_update_name(&update)
        .cache_cluster_ids("old-redis")
        .show_node_level_update_status(true)
        .send()
        .await
        .unwrap();
    assert_eq!(a.update_actions()[0].update_action_status().map(|s| s.as_str()), Some("complete"));
}

#[tokio::test]
async fn iam_controls_access() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;
    ec.create_cache_cluster()
        .cache_cluster_id("prod-cache")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(1)
        .tags(tag("env", "prod"))
        .send()
        .await
        .unwrap();

    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "elasticache:Describe*", "Resource": "*"},
            {"Effect": "Allow", "Action": "elasticache:CreateCacheCluster", "Resource": "*",
             "Condition": {"StringEquals": {"elasticache:CacheNodeType": "cache.t4g.micro"}}},
            {"Effect": "Allow", "Action": "elasticache:DeleteCacheCluster", "Resource": "*",
             "Condition": {"StringNotEquals": {"aws:ResourceTag/env": "prod"}}}
        ]
    });
    let (_, cfg) = user_with_policy(&mws, "dev", Some(&policy.to_string())).await;
    let dev = Client::new(&cfg);
    dev.describe_cache_clusters().send().await.unwrap();
    let e = dev.delete_cache_cluster().cache_cluster_id("prod-cache").send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDenied");
    let e = dev
        .create_cache_cluster()
        .cache_cluster_id("big")
        .engine("valkey")
        .cache_node_type("cache.r7g.xlarge")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDenied");
    dev.create_cache_cluster()
        .cache_cluster_id("small")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap();
    dev.delete_cache_cluster().cache_cluster_id("small").send().await.unwrap();
}

#[tokio::test]
async fn cloudwatch_metrics() {
    let mws = Mws::start().await;
    let ec = client(&mws).await;
    ec.create_cache_cluster()
        .cache_cluster_id("metered")
        .engine("valkey")
        .cache_node_type("cache.r7g.large")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap();
    ec.create_cache_cluster()
        .cache_cluster_id("metered-mc")
        .engine("memcached")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(2)
        .send()
        .await
        .unwrap();
    // Minutes close on the emulated clock, which ElastiCache reads from
    // requests.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":180}"#)).await;
    assert_eq!(status, 200);
    ec.describe_cache_clusters().send().await.unwrap();

    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    let listed = cw.list_metrics().namespace("AWS/ElastiCache").send().await.unwrap();
    let names: Vec<_> = listed.metrics().iter().filter_map(|m| m.metric_name()).collect();
    for want in ["CPUUtilization", "CurrConnections", "CacheHits", "FreeableMemory", "IsMaster", "GetHits", "CmdGet"] {
        assert!(names.contains(&want), "{want} missing from {names:?}");
    }
    let now = aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() + 3600);
    let start = aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() - 3600);
    let out = cw
        .get_metric_statistics()
        .namespace("AWS/ElastiCache")
        .metric_name("FreeableMemory")
        .dimensions(aws_sdk_cloudwatch::types::Dimension::builder().name("CacheClusterId").value("metered").build())
        .dimensions(aws_sdk_cloudwatch::types::Dimension::builder().name("CacheNodeId").value("0001").build())
        .start_time(start)
        .end_time(now)
        .period(7200)
        .statistics(aws_sdk_cloudwatch::types::Statistic::Maximum)
        .send()
        .await
        .unwrap();
    // An idle cache.r7g.large has its 13.07 GiB free.
    assert!(out.datapoints()[0].maximum().unwrap() > 13.0 * 1024.0 * 1024.0 * 1024.0, "{:?}", out.datapoints());
    let mc = cw
        .list_metrics()
        .namespace("AWS/ElastiCache")
        .metric_name("CurrItems")
        .dimensions(
            aws_sdk_cloudwatch::types::DimensionFilter::builder().name("CacheClusterId").value("metered-mc").build(),
        )
        .send()
        .await
        .unwrap();
    // One series per node.
    assert_eq!(mc.metrics().len(), 2);
}
