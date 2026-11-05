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
            Some("create-failed") => {
                let events = ec
                    .describe_events()
                    .source_identifier(id)
                    .source_type(aws_sdk_elasticache::types::SourceType::ReplicationGroup)
                    .send()
                    .await
                    .unwrap();
                let why: Vec<&str> = events.events().iter().filter_map(|e| e.message()).collect();
                panic!("replication group {id} failed: {why:?}")
            }
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
            node = Some((endpoint(c.cache_nodes()[0].endpoint()), endpoint(c.configuration_endpoint())));
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let ((host, port), (cfg_host, cfg_port)) = node.expect("memcached cluster becomes available");
    async fn exchange(s: &mut tokio::net::TcpStream, send: &[u8], until: &str) -> String {
        s.write_all(send).await.unwrap();
        let mut buf = vec![0u8; 512];
        let mut got = String::new();
        for _ in 0..20 {
            let n = s.read(&mut buf).await.unwrap();
            got.push_str(&String::from_utf8_lossy(&buf[..n]));
            if got.contains(until) {
                break;
            }
        }
        got
    }
    let mut s = tokio::net::TcpStream::connect((host.as_str(), port)).await.unwrap();
    let got = exchange(&mut s, b"set greeting 0 0 5\r\nhello\r\nget greeting\r\n", "END").await;
    assert!(got.contains("STORED") && got.contains("hello"), "{got}");

    // Auto discovery: the configuration endpoint lists the nodes, and
    // passes other commands through to them.
    assert_ne!(cfg_port, port);
    let mut cfg = tokio::net::TcpStream::connect((cfg_host.as_str(), cfg_port)).await.unwrap();
    let got = exchange(&mut cfg, b"config get cluster\r\n", "END").await;
    let lines: Vec<&str> = got.split("\r\n").collect();
    assert!(lines[0].starts_with("CONFIG cluster 0 "), "{got}");
    let body = lines[1];
    let (version, nodes) = body.split_once('\n').unwrap();
    assert_eq!(version, "1", "{got}");
    assert_eq!(nodes.trim_end(), format!("{host}|{host}|{port}"));
    let got = exchange(&mut cfg, b"get greeting\r\n", "END").await;
    assert!(got.contains("hello"), "{got}");
    ec.modify_cache_cluster()
        .cache_cluster_id("docker-memcached")
        .num_cache_nodes(2)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let mut listed = String::new();
    for _ in 0..300 {
        listed = exchange(&mut cfg, b"config get cluster\r\n", "END").await;
        if listed.matches('|').count() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(listed.contains("\r\n2\n"), "{listed}");
    assert_eq!(listed.matches('|').count(), 4, "{listed}");
    for _ in 0..300 {
        let d = ec.describe_cache_clusters().cache_cluster_id("docker-memcached").send().await.unwrap();
        if d.cache_clusters()[0].cache_cluster_status() == Some("available") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
    // CONFIG is one of the commands ElastiCache restricts; INFO shows the
    // policy.
    let mut c = Redis::connect(&host, port).await.unwrap();
    match c.cmd(&["CONFIG", "GET", "maxmemory-policy"]).await.unwrap() {
        mws_elasticache::resp::Resp::Error(e) => assert!(e.starts_with("ERR unknown command 'CONFIG'"), "{e}"),
        other => panic!("CONFIG ran: {other:?}"),
    }
    for cmd in [&["SHUTDOWN"][..], &["REPLICAOF", "NO", "ONE"], &["DEBUG", "SLEEP", "0"], &["BGSAVE"]] {
        let r = c.cmd(cmd).await.unwrap();
        assert!(matches!(&r, mws_elasticache::resp::Resp::Error(e) if e.starts_with("ERR unknown command")), "{r:?}");
    }
    let mut policy = String::new();
    for _ in 0..50 {
        let info = text(&mut c, &["INFO", "memory"]).await.unwrap_or_default();
        policy = info.lines().find_map(|l| l.strip_prefix("maxmemory_policy:")).unwrap_or_default().trim().to_string();
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

#[tokio::test]
async fn upgrades_restricted_commands_and_vpc_access() {
    let Some((mws, ec)) = start().await else { return };
    // A Valkey 8.0 group moves to 8.1 in place: the nodes are replaced and
    // keep their data.
    ec.create_replication_group()
        .replication_group_id("docker-ver")
        .replication_group_description("upgrade")
        .engine("valkey")
        .engine_version("8.0")
        .cache_node_type("cache.t4g.micro")
        .num_cache_clusters(2)
        .send()
        .await
        .unwrap();
    let g = wait_group(&ec, "docker-ver").await;
    let (host, port) = endpoint(g.node_groups()[0].primary_endpoint());
    let mut c = Redis::connect(&host, port).await.unwrap();
    assert_eq!(text(&mut c, &["SET", "kept", "yes"]).await.as_deref(), Some("OK"));
    let info = text(&mut c, &["INFO", "server"]).await.unwrap();
    assert!(info.contains("valkey_version:8.0"), "{info}");
    drop(c);
    let out = ec
        .modify_replication_group()
        .replication_group_id("docker-ver")
        .engine_version("8.1")
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    assert_eq!(out.replication_group().unwrap().status(), Some("modifying"));
    let g = wait_group(&ec, "docker-ver").await;
    let (host, port) = endpoint(g.node_groups()[0].primary_endpoint());
    let mut c = Redis::connect(&host, port).await.unwrap();
    let info = text(&mut c, &["INFO", "server"]).await.unwrap();
    assert!(info.contains("valkey_version:8.1"), "{info}");
    assert_eq!(text(&mut c, &["GET", "kept"]).await.as_deref(), Some("yes"));
    let (rhost, rport) = endpoint(g.node_groups()[0].reader_endpoint());
    eventually_get(&rhost, rport, &None, &Auth::None, "kept", "yes").await;
    let events = ec
        .describe_events()
        .source_identifier("docker-ver")
        .source_type(aws_sdk_elasticache::types::SourceType::ReplicationGroup)
        .send()
        .await
        .unwrap();
    assert!(
        events.events().iter().any(|e| e.message() == Some("Engine version upgraded to 8.1.0")),
        "{:?}",
        events.events()
    );
    // MIGRATE and the other restricted commands answer like unknown ones.
    let r = c.cmd(&["MIGRATE", "127.0.0.1", "1", "kept", "0", "1000"]).await.unwrap();
    assert!(
        matches!(&r, mws_elasticache::resp::Resp::Error(e) if e.starts_with("ERR unknown command 'MIGRATE'")),
        "{r:?}"
    );
    ec.delete_replication_group().replication_group_id("docker-ver").send().await.unwrap();

    // Nodes join their VPC's Docker network, where EC2 instances run, and
    // answer there under `<cluster>-<node>`.
    let vpc = ec
        .describe_cache_subnet_groups()
        .send()
        .await
        .unwrap()
        .cache_subnet_groups()
        .iter()
        .find_map(|g| g.vpc_id().map(str::to_string));
    let vpc = match vpc {
        Some(v) => v,
        None => {
            // The default subnet group appears with the first cluster.
            ec.create_cache_cluster()
                .cache_cluster_id("docker-vpc-probe")
                .engine("memcached")
                .cache_node_type("cache.t4g.micro")
                .num_cache_nodes(1)
                .send()
                .await
                .unwrap();
            let d = ec.describe_cache_subnet_groups().cache_subnet_group_name("default").send().await.unwrap();
            ec.delete_cache_cluster().cache_cluster_id("docker-vpc-probe").send().await.ok();
            d.cache_subnet_groups()[0].vpc_id().unwrap().to_string()
        }
    };
    let network = format!("mws-{vpc}");
    let created = Command::new("docker").args(["network", "create", &network]).output().unwrap().status.success();
    ec.create_cache_cluster()
        .cache_cluster_id("docker-vpc")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(1)
        .send()
        .await
        .unwrap();
    let mut port = 0;
    for _ in 0..600 {
        let d = ec
            .describe_cache_clusters()
            .cache_cluster_id("docker-vpc")
            .show_cache_node_info(true)
            .send()
            .await
            .unwrap();
        let cl = &d.cache_clusters()[0];
        if cl.cache_cluster_status() == Some("available") {
            port = cl.cache_nodes()[0].endpoint().unwrap().port().unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(port > 0, "docker-vpc became available");
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            &network,
            "--entrypoint",
            "valkey-cli",
            "valkey/valkey:8.1-alpine",
            "-h",
            "docker-vpc-0001",
            "-p",
            &port.to_string(),
            "PING",
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "PONG", "{}", String::from_utf8_lossy(&out.stderr));
    ec.delete_cache_cluster().cache_cluster_id("docker-vpc").send().await.unwrap();
    wait_containers_gone("docker-vpc").await;
    wait_containers_gone("docker-ver").await;
    if created {
        let _ = Command::new("docker").args(["network", "rm", &network]).output();
    }
    mws.stop().await;
}

#[tokio::test]
async fn log_delivery() {
    use aws_sdk_elasticache::types::{
        CloudWatchLogsDestinationDetails, DestinationDetails, DestinationType, KinesisFirehoseDestinationDetails,
        LogDeliveryConfigurationRequest, LogFormat, LogType,
    };
    let Some((mws, ec)) = start().await else { return };
    let config = mws.root_sdk_config().await;
    let logs = aws_sdk_cloudwatchlogs::Client::new(&config);
    for g in ["/ec/slow", "/ec/engine"] {
        logs.create_log_group().log_group_name(g).send().await.unwrap();
    }
    let firehose = aws_sdk_firehose::Client::new(&config);
    let role = aws_sdk_iam::Client::new(&config)
        .create_role()
        .role_name("firehose-delivery")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#,
        )
        .send()
        .await
        .unwrap();
    firehose
        .create_delivery_stream()
        .delivery_stream_name("untagged")
        .extended_s3_destination_configuration(
            aws_sdk_firehose::types::ExtendedS3DestinationConfiguration::builder()
                .role_arn(role.role().unwrap().arn())
                .bucket_arn("arn:aws:s3:::cache-logs")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    ec.create_cache_parameter_group()
        .cache_parameter_group_name("slow-all")
        .cache_parameter_group_family("valkey8")
        .description("log every command")
        .send()
        .await
        .unwrap();
    ec.modify_cache_parameter_group()
        .cache_parameter_group_name("slow-all")
        .parameter_name_values(
            aws_sdk_elasticache::types::ParameterNameValue::builder()
                .parameter_name("slowlog-log-slower-than")
                .parameter_value("0")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let to_logs = |kind: LogType, format: LogFormat, group: &str| {
        LogDeliveryConfigurationRequest::builder()
            .log_type(kind)
            .log_format(format)
            .destination_type(DestinationType::CloudWatchLogs)
            .destination_details(
                DestinationDetails::builder()
                    .cloud_watch_logs_details(CloudWatchLogsDestinationDetails::builder().log_group(group).build())
                    .build(),
            )
            .enabled(true)
            .build()
    };
    ec.create_cache_cluster()
        .cache_cluster_id("docker-logs")
        .engine("valkey")
        .cache_node_type("cache.t4g.micro")
        .num_cache_nodes(1)
        .cache_parameter_group_name("slow-all")
        .log_delivery_configurations(to_logs(LogType::SlowLog, LogFormat::Json, "/ec/slow"))
        .log_delivery_configurations(to_logs(LogType::EngineLog, LogFormat::Text, "/ec/engine"))
        .send()
        .await
        .unwrap();
    let mut node = None;
    for _ in 0..600 {
        let d = ec
            .describe_cache_clusters()
            .cache_cluster_id("docker-logs")
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
    let (host, port) = node.expect("docker-logs becomes available");
    let mut c = Redis::connect(&host, port).await.unwrap();
    assert_eq!(text(&mut c, &["SET", "logged", "1"]).await.as_deref(), Some("OK"));

    // Slow log entries arrive as JSON, engine log lines as text, in streams
    // named after the node.
    let events = |group: &'static str| {
        let logs = logs.clone();
        async move {
            let out = logs.filter_log_events().log_group_name(group).send().await.unwrap();
            out.events()
                .iter()
                .map(|e| {
                    (e.log_stream_name().unwrap_or_default().to_string(), e.message().unwrap_or_default().to_string())
                })
                .collect::<Vec<_>>()
        }
    };
    let mut slow = Vec::new();
    for _ in 0..100 {
        slow = events("/ec/slow").await;
        if slow.iter().any(|(_, m)| m.contains("SET ... (2 more arguments)")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let (stream, message) =
        slow.iter().find(|(_, m)| m.contains("SET ... (2 more arguments)")).expect("SET in the slow log").clone();
    assert_eq!(stream, "docker-logs-0001-slow-log");
    let entry: serde_json::Value = serde_json::from_str(&message).unwrap();
    assert_eq!(entry["CacheClusterId"], "docker-logs");
    assert_eq!(entry["CacheNodeId"], "0001");
    assert!(entry["Duration (us)"].is_number(), "{entry}");
    // MWS's own commands stay out of it.
    assert!(slow.iter().all(|(_, m)| !m.contains("\"INFO") && !m.contains("SLOWLOG")), "{slow:?}");
    let engine = events("/ec/engine").await;
    assert!(
        engine.iter().any(|(s, m)| s == "docker-logs-0001-engine-log" && m.starts_with("docker-logs-0001 ")),
        "{engine:?}"
    );
    // ElastiCache let the log delivery service write to the groups.
    let policies = logs.describe_resource_policies().send().await.unwrap();
    assert!(policies.resource_policies().iter().any(|p| p.policy_name() == Some("AWSLogDeliveryWrite20150319")));
    let d = ec.describe_cache_clusters().cache_cluster_id("docker-logs").send().await.unwrap();
    for l in d.cache_clusters()[0].log_delivery_configurations() {
        assert_eq!(l.status(), Some(&aws_sdk_elasticache::types::LogDeliveryConfigurationStatus::Active), "{l:?}");
    }

    // A Firehose stream must be tagged LogDeliveryEnabled=true: without
    // the tag the configuration reports an error.
    ec.modify_cache_cluster()
        .cache_cluster_id("docker-logs")
        .apply_immediately(true)
        .log_delivery_configurations(
            LogDeliveryConfigurationRequest::builder()
                .log_type(LogType::SlowLog)
                .log_format(LogFormat::Text)
                .destination_type(DestinationType::KinesisFirehose)
                .destination_details(
                    DestinationDetails::builder()
                        .kinesis_firehose_details(
                            KinesisFirehoseDestinationDetails::builder().delivery_stream("untagged").build(),
                        )
                        .build(),
                )
                .enabled(true)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(text(&mut c, &["SET", "again", "1"]).await.as_deref(), Some("OK"));
    let mut status = None;
    for _ in 0..100 {
        let d = ec.describe_cache_clusters().cache_cluster_id("docker-logs").send().await.unwrap();
        let slow_cfg = d.cache_clusters()[0]
            .log_delivery_configurations()
            .iter()
            .find(|l| l.log_type() == Some(&LogType::SlowLog))
            .cloned();
        status = slow_cfg.clone();
        if slow_cfg.and_then(|l| l.status().cloned())
            == Some(aws_sdk_elasticache::types::LogDeliveryConfigurationStatus::Error)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let status = status.unwrap();
    assert_eq!(status.status(), Some(&aws_sdk_elasticache::types::LogDeliveryConfigurationStatus::Error));
    assert!(status.message().unwrap_or_default().contains("LogDeliveryEnabled"), "{status:?}");
    ec.delete_cache_cluster().cache_cluster_id("docker-logs").send().await.unwrap();
    wait_containers_gone("docker-logs").await;
    mws.stop().await;
}
