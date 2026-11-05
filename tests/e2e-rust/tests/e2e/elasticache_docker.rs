//! ElastiCache nodes that really run (Redis OSS, Valkey and Memcached in
//! Docker containers), driven through the official Rust SDK and spoken to
//! over RESP the way applications do. Skipped when no Docker daemon
//! answers.

use std::process::Command;
use std::time::Duration;

use aws_sdk_elasticache::Client;
use mws_e2e::Mws;
use mws_elasticache::resp::{Auth, Client as Redis};

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

async fn start() -> Option<(Mws, Client)> {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return None;
    }
    let config = mws::Config { elasticache_backend: mws_elasticache::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let ec = Client::new(&mws.root_sdk_config().await);
    Some((mws, ec))
}

/// Wait until the containers of deleted nodes are gone.
async fn wait_containers_gone(prefix: &str) {
    for _ in 0..100 {
        let out = Command::new("docker")
            .args(["ps", "-aq", "--filter", &format!("name=mws-elasticache-{prefix}")])
            .output()
            .unwrap();
        if out.stdout.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("containers mws-elasticache-{prefix}* were not removed");
}

async fn wait_group(ec: &Client, id: &str) -> aws_sdk_elasticache::types::ReplicationGroup {
    for _ in 0..600 {
        let d = ec.describe_replication_groups().replication_group_id(id).send().await.unwrap();
        let g = d.replication_groups()[0].clone();
        match g.status() {
            Some("available") => return g,
            Some("create-failed") => panic!("replication group {id} failed: {g:?}"),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    panic!("replication group {id} never became available");
}

async fn wait_snapshot(ec: &Client, name: &str) {
    for _ in 0..600 {
        let d = ec.describe_snapshots().snapshot_name(name).send().await.unwrap();
        match d.snapshots()[0].snapshot_status() {
            Some("available") => return,
            Some("failed") => panic!("snapshot {name} failed"),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    panic!("snapshot {name} never became available");
}

type Tls = Option<std::sync::Arc<rustls::ClientConfig>>;

/// A TLS client trusting the CA of MWS's node certificates.
async fn ca_client(mws: &Mws) -> Tls {
    let (status, _, ca) = mws.raw("GET", "/_aws/elasticache/ca.pem", &[], b"").await;
    assert_eq!(status, 200);
    Some(mws_elasticache::tls::client_config(std::str::from_utf8(&ca).unwrap()).unwrap())
}

fn endpoint(e: Option<&aws_sdk_elasticache::types::Endpoint>) -> (String, u16) {
    let e = e.expect("endpoint");
    (e.address().unwrap().to_string(), e.port().unwrap() as u16)
}

async fn text(c: &mut Redis, args: &[&str]) -> Option<String> {
    c.cmd(args).await.unwrap().as_text()
}

/// Wait until `GET key` on a connection answers `want` (replication is
/// asynchronous).
async fn eventually_get(host: &str, port: u16, tls: &Tls, auth: &Auth, key: &str, want: &str) {
    for _ in 0..100 {
        if let Ok(mut c) = Redis::connect_with(host, port, tls.clone(), auth).await {
            if c.cmd(&["GET", key]).await.ok().and_then(|r| r.as_text()).as_deref() == Some(want) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("{key} never read {want} on {host}:{port}");
}

#[tokio::test]
async fn replication_group_with_auth_and_failover() {
    let Some((mws, ec)) = start().await else { return };
    // AUTH needs encryption in transit, so the nodes speak TLS.
    let tls = ca_client(&mws).await;
    let token = "an-auth-token-of-sixteen-plus";
    ec.create_replication_group()
        .replication_group_id("docker-sessions")
        .replication_group_description("sessions")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_clusters(2)
        .automatic_failover_enabled(true)
        .transit_encryption_enabled(true)
        .auth_token(token)
        .send()
        .await
        .unwrap();
    let g = wait_group(&ec, "docker-sessions").await;
    let ng = &g.node_groups()[0];
    let (host, port) = endpoint(ng.primary_endpoint());
    let (rhost, rport) = endpoint(ng.reader_endpoint());

    // Without the token the node refuses commands.
    let mut anon = Redis::connect_with(&host, port, tls.clone(), &Auth::None).await.unwrap();
    let r = anon.cmd(&["GET", "x"]).await.unwrap();
    assert!(format!("{r:?}").contains("NOAUTH"), "{r:?}");

    let auth = Auth::Password(token.into());
    let mut c = Redis::connect_with(&host, port, tls.clone(), &auth).await.unwrap();
    assert_eq!(text(&mut c, &["SET", "user:1", "alice"]).await.as_deref(), Some("OK"));
    let role = c.cmd(&["ROLE"]).await.unwrap();
    assert_eq!(role.items()[0].as_text().as_deref(), Some("master"));
    // The reader endpoint reaches the replica, which has the data.
    eventually_get(&rhost, rport, &tls, &auth, "user:1", "alice").await;
    let mut r = Redis::connect_with(&rhost, rport, tls.clone(), &auth).await.unwrap();
    assert_eq!(r.cmd(&["ROLE"]).await.unwrap().items()[0].as_text().as_deref(), Some("slave"));

    // Failover promotes the replica; the primary endpoint follows it.
    ec.test_failover().replication_group_id("docker-sessions").node_group_id("0001").send().await.unwrap();
    wait_group(&ec, "docker-sessions").await;
    let mut promoted = None;
    for _ in 0..100 {
        if let Ok(mut c) = Redis::connect_with(&host, port, tls.clone(), &auth).await {
            if c.cmd(&["SET", "user:2", "bob"]).await.ok().and_then(|r| r.as_text()).as_deref() == Some("OK") {
                promoted = Some(c);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut c = promoted.expect("primary endpoint accepts writes after failover");
    assert_eq!(text(&mut c, &["GET", "user:1"]).await.as_deref(), Some("alice"));

    // AUTH token rotation keeps the old token valid until it is set.
    let new_token = "a-rotated-token-of-sixteen-plus";
    ec.modify_replication_group()
        .replication_group_id("docker-sessions")
        .auth_token(new_token)
        .auth_token_update_strategy(aws_sdk_elasticache::types::AuthTokenUpdateStrategyType::Rotate)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    wait_group(&ec, "docker-sessions").await;
    let new_auth = Auth::Password(new_token.into());
    eventually_get(&host, port, &tls, &new_auth, "user:2", "bob").await;
    eventually_get(&host, port, &tls, &auth, "user:2", "bob").await;

    ec.delete_replication_group().replication_group_id("docker-sessions").send().await.unwrap();
    wait_containers_gone("docker-sessions").await;
    mws.stop().await;
}

#[tokio::test]
async fn cluster_mode_snapshot_and_restore() {
    let Some((mws, ec)) = start().await else { return };
    ec.create_replication_group()
        .replication_group_id("docker-shards")
        .replication_group_description("sharded")
        .engine("redis")
        .cache_node_type("cache.t4g.micro")
        .num_node_groups(2)
        .replicas_per_node_group(0)
        .send()
        .await
        .unwrap();
    let g = wait_group(&ec, "docker-shards").await;
    let (host, port) = endpoint(g.configuration_endpoint());

    let mut c = Redis::connect(&host, port).await.unwrap();
    let info = text(&mut c, &["CLUSTER", "INFO"]).await.unwrap();
    assert!(info.contains("cluster_state:ok"), "{info}");
    let slots = c.cmd(&["CLUSTER", "SLOTS"]).await.unwrap();
    assert_eq!(slots.items().len(), 2);

    // Write keys to both shards, following MOVED redirects.
    for key in ["alpha", "bravo", "charlie", "delta"] {
        let mut answer = c.cmd(&["SET", key, &format!("v-{key}")]).await.unwrap();
        if let Some(moved) = format!("{answer:?}").split("MOVED ").nth(1) {
            let target = moved.split_whitespace().nth(1).unwrap().trim_matches(|ch: char| ch == '"' || ch == ')');
            let (h, p) = target.rsplit_once(':').unwrap();
            let mut other = Redis::connect(h, p.parse().unwrap()).await.unwrap();
            answer = other.cmd(&["SET", key, &format!("v-{key}")]).await.unwrap();
        }
        assert_eq!(answer.as_text().as_deref(), Some("OK"), "{key}: {answer:?}");
    }

    ec.create_snapshot().replication_group_id("docker-shards").snapshot_name("shards-snap").send().await.unwrap();
    wait_snapshot(&ec, "shards-snap").await;

    // Restore into a non-clustered group: every key lands on its primary.
    ec.create_replication_group()
        .replication_group_id("docker-restored")
        .replication_group_description("restored")
        .snapshot_name("shards-snap")
        .engine("redis")
        .cache_node_type("cache.t4g.micro")
        .num_cache_clusters(1)
        .cache_parameter_group_name("default.redis7")
        .send()
        .await
        .unwrap();
    let g = wait_group(&ec, "docker-restored").await;
    let (rh, rp) = endpoint(g.node_groups()[0].primary_endpoint());
    let mut r = Redis::connect(&rh, rp).await.unwrap();
    for key in ["alpha", "bravo", "charlie", "delta"] {
        assert_eq!(text(&mut r, &["GET", key]).await, Some(format!("v-{key}")));
    }

    ec.delete_replication_group().replication_group_id("docker-restored").send().await.unwrap();
    ec.delete_replication_group().replication_group_id("docker-shards").send().await.unwrap();
    wait_containers_gone("docker-shards").await;
    wait_containers_gone("docker-restored").await;
    mws.stop().await;
}

#[tokio::test]
async fn memcached_and_parameter_groups() {
    let Some((mws, ec)) = start().await else { return };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    ec.create_cache_cluster()
        .cache_cluster_id("docker-memcached")
        .engine("memcached")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap();
    let mut node = None;
    for _ in 0..600 {
        let d = ec
            .describe_cache_clusters()
            .cache_cluster_id("docker-memcached")
            .show_cache_node_info(true)
            .send()
            .await
            .unwrap();
        let c = &d.cache_clusters()[0];
        if c.cache_cluster_status() == Some("available") {
            node = Some(endpoint(c.cache_nodes()[0].endpoint()));
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (host, port) = node.expect("memcached cluster becomes available");
    let mut s = tokio::net::TcpStream::connect((host.as_str(), port)).await.unwrap();
    s.write_all(b"set greeting 0 0 5\r\nhello\r\nget greeting\r\n").await.unwrap();
    let mut buf = vec![0u8; 256];
    let mut got = String::new();
    for _ in 0..20 {
        let n = s.read(&mut buf).await.unwrap();
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
        if got.contains("END") {
            break;
        }
    }
    assert!(got.contains("STORED") && got.contains("hello"), "{got}");
    ec.delete_cache_cluster().cache_cluster_id("docker-memcached").send().await.unwrap();

    // Parameter group changes reach running Valkey nodes (CONFIG SET).
    ec.create_cache_parameter_group()
        .cache_parameter_group_name("lru")
        .cache_parameter_group_family("valkey8")
        .description("lru")
        .send()
        .await
        .unwrap();
    ec.create_cache_cluster()
        .cache_cluster_id("docker-valkey")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(1)
        .cache_parameter_group_name("lru")
        .send()
        .await
        .unwrap();
    let mut node = None;
    for _ in 0..600 {
        let d = ec
            .describe_cache_clusters()
            .cache_cluster_id("docker-valkey")
            .show_cache_node_info(true)
            .send()
            .await
            .unwrap();
        let c = &d.cache_clusters()[0];
        if c.cache_cluster_status() == Some("available") {
            node = Some(endpoint(c.cache_nodes()[0].endpoint()));
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (host, port) = node.expect("valkey cluster becomes available");
    ec.modify_cache_parameter_group()
        .cache_parameter_group_name("lru")
        .parameter_name_values(
            aws_sdk_elasticache::types::ParameterNameValue::builder()
                .parameter_name("maxmemory-policy")
                .parameter_value("allkeys-lru")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let mut policy = String::new();
    for _ in 0..50 {
        let mut c = Redis::connect(&host, port).await.unwrap();
        let r = c.cmd(&["CONFIG", "GET", "maxmemory-policy"]).await.unwrap();
        policy = r.items().get(1).and_then(|v| v.as_text()).unwrap_or_default();
        if policy == "allkeys-lru" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(policy, "allkeys-lru");

    // CloudWatch metrics come from the node's own counters.
    let mut c = Redis::connect(&host, port).await.unwrap();
    text(&mut c, &["SET", "a", "1"]).await;
    for _ in 0..3 {
        assert_eq!(text(&mut c, &["GET", "a"]).await.as_deref(), Some("1"));
    }
    assert_eq!(c.cmd(&["GET", "missing"]).await.unwrap(), mws_elasticache::resp::Resp::Bulk(None));
    // Let the sampler read the node, then close the minute.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":120}"#)).await;
    assert_eq!(status, 200);
    ec.describe_cache_clusters().send().await.unwrap();
    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    // Counters are summed; gauges such as IsMaster read their Maximum,
    // since the window can span more than one closed minute.
    let stat = |name: &'static str, statistic: aws_sdk_cloudwatch::types::Statistic| {
        let cw = cw.clone();
        async move {
            let now = aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() + 3600);
            let start = aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() - 3600);
            let out = cw
                .get_metric_statistics()
                .namespace("AWS/ElastiCache")
                .metric_name(name)
                .dimensions(
                    aws_sdk_cloudwatch::types::Dimension::builder()
                        .name("CacheClusterId")
                        .value("docker-valkey")
                        .build(),
                )
                .dimensions(aws_sdk_cloudwatch::types::Dimension::builder().name("CacheNodeId").value("0001").build())
                .start_time(start)
                .end_time(now)
                .period(7200)
                .statistics(statistic.clone())
                .send()
                .await
                .unwrap();
            let d = out.datapoints().first();
            match statistic {
                aws_sdk_cloudwatch::types::Statistic::Maximum => d.and_then(|d| d.maximum()),
                _ => d.and_then(|d| d.sum()),
            }
            .unwrap_or(-1.0)
        }
    };
    let sum = |name| stat(name, aws_sdk_cloudwatch::types::Statistic::Sum);
    let max = |name| stat(name, aws_sdk_cloudwatch::types::Statistic::Maximum);
    assert_eq!(sum("CacheHits").await, 3.0);
    assert_eq!(sum("CacheMisses").await, 1.0);
    assert!(sum("GetTypeCmds").await >= 4.0);
    assert!(sum("SetTypeCmds").await >= 1.0);
    assert_eq!(max("IsMaster").await, 1.0);
    assert!(max("BytesUsedForCache").await > 0.0);
    ec.delete_cache_cluster().cache_cluster_id("docker-valkey").send().await.unwrap();
    wait_containers_gone("docker-valkey").await;
    wait_containers_gone("docker-memcached").await;
    mws.stop().await;
}

#[tokio::test]
async fn encryption_in_transit() {
    let Some((mws, ec)) = start().await else { return };
    // Clients trust the CA MWS signs node certificates with.
    let (status, _, ca) = mws.raw("GET", "/_aws/elasticache/ca.pem", &[], b"").await;
    assert_eq!(status, 200);
    let ca = String::from_utf8(ca).unwrap();
    assert!(ca.starts_with("-----BEGIN CERTIFICATE-----"), "{ca}");
    let tls = mws_elasticache::tls::client_config(&ca).unwrap();
    assert!(ca_client(&mws).await.is_some());

    let token = "a-tls-auth-token-of-sixteen";
    ec.create_replication_group()
        .replication_group_id("docker-tls")
        .replication_group_description("tls")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_clusters(2)
        .transit_encryption_enabled(true)
        .auth_token(token)
        .send()
        .await
        .unwrap();
    let g = wait_group(&ec, "docker-tls").await;
    assert_eq!(g.transit_encryption_enabled(), Some(true));
    let ng = &g.node_groups()[0];
    let (host, port) = endpoint(ng.primary_endpoint());
    let (rhost, rport) = endpoint(ng.reader_endpoint());
    let auth = Auth::Password(token.into());

    // Plain RESP gets nowhere: the port speaks TLS.
    if let Ok(mut plain) = Redis::connect(&host, port).await {
        assert!(plain.cmd(&["PING"]).await.is_err());
    }
    let mut c = Redis::connect_with(&host, port, Some(tls.clone()), &auth).await.unwrap();
    assert_eq!(text(&mut c, &["SET", "secret", "sauce"]).await.as_deref(), Some("OK"));
    // Replication runs over TLS too.
    let mut found = false;
    for _ in 0..100 {
        if let Ok(mut r) = Redis::connect_with(&rhost, rport, Some(tls.clone()), &auth).await {
            if r.cmd(&["GET", "secret"]).await.ok().and_then(|v| v.as_text()).as_deref() == Some("sauce") {
                found = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(found, "replica never received the key over TLS");
    ec.delete_replication_group().replication_group_id("docker-tls").send().await.unwrap();

    // Encryption in transit turned on for a running group.
    ec.create_replication_group()
        .replication_group_id("docker-upgrade")
        .replication_group_description("upgrade")
        .engine("redis")
        .cache_node_type("cache.t4g.micro")
        .num_cache_clusters(1)
        .send()
        .await
        .unwrap();
    let g = wait_group(&ec, "docker-upgrade").await;
    let (host, port) = endpoint(g.node_groups()[0].primary_endpoint());
    let mut c = Redis::connect(&host, port).await.unwrap();
    assert_eq!(text(&mut c, &["SET", "k", "v"]).await.as_deref(), Some("OK"));
    ec.modify_replication_group()
        .replication_group_id("docker-upgrade")
        .transit_encryption_enabled(true)
        .transit_encryption_mode(aws_sdk_elasticache::types::TransitEncryptionMode::Required)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let mut upgraded = false;
    for _ in 0..100 {
        if let Ok(mut c) = Redis::connect_with(&host, port, Some(tls.clone()), &Auth::None).await {
            if c.cmd(&["GET", "k"]).await.ok().and_then(|v| v.as_text()).as_deref() == Some("v") {
                upgraded = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(upgraded, "the group never served TLS");
    ec.delete_replication_group().replication_group_id("docker-upgrade").send().await.unwrap();
    wait_containers_gone("docker-tls").await;
    wait_containers_gone("docker-upgrade").await;
    mws.stop().await;
}
