//! RDS databases that really run: the Docker backend starts PostgreSQL in a
//! container per instance (or per Aurora cluster), and a real PostgreSQL
//! client connects to the endpoint RDS reports. Skipped when no Docker
//! daemon answers.

use std::process::Command;
use std::time::Duration;

use aws_sdk_rds::Client;
use mws_e2e::Mws;

use super::rds::run;

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Containers MWS runs for RDS.
fn rds_containers() -> Vec<String> {
    let out = Command::new("docker")
        .args(["ps", "-a", "--filter", "name=mws-rds-", "--format", "{{.Names}}"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect()
}

async fn wait_available(rds: &Client, id: &str) -> aws_sdk_rds::types::DbInstance {
    for _ in 0..600 {
        let d = rds.describe_db_instances().db_instance_identifier(id).send().await.unwrap();
        let db = d.db_instances()[0].clone();
        match db.db_instance_status() {
            Some("available") => return db,
            Some("failed") => panic!("instance {id} failed"),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    panic!("instance {id} never became available");
}

async fn wait_cluster_available(rds: &Client, id: &str) -> aws_sdk_rds::types::DbCluster {
    for _ in 0..600 {
        let d = rds.describe_db_clusters().db_cluster_identifier(id).send().await.unwrap();
        let c = d.db_clusters()[0].clone();
        if c.status() == Some("available") {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("cluster {id} never became available");
}

async fn connect(
    host: &str,
    port: i32,
    user: &str,
    password: &str,
    db: &str,
) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
    let conn = format!("host={host} port={port} user={user} password={password} dbname={db} connect_timeout=10");
    let (client, connection) = tokio_postgres::connect(&conn, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn secret_password(sm: &aws_sdk_secretsmanager::Client, arn: &str) -> String {
    let v = sm.get_secret_value().secret_id(arn).send().await.unwrap();
    let creds: serde_json::Value = serde_json::from_str(v.secret_string().unwrap()).unwrap();
    creds["password"].as_str().unwrap().to_string()
}

async fn connect_with_retry(host: &str, port: i32, user: &str, password: &str, db: &str) -> tokio_postgres::Client {
    let mut last = None;
    for _ in 0..60 {
        match connect(host, port, user, password, db).await {
            Ok(c) => return c,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("could not connect: {last:?}");
}

#[test]
fn postgres_runs_in_docker() {
    run(postgres_runs_in_docker_body());
}

async fn postgres_runs_in_docker_body() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { rds_backend: mws_rds::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let sdk = mws.root_sdk_config().await;
    let rds = Client::new(&sdk);
    let sm = aws_sdk_secretsmanager::Client::new(&sdk);

    rds.create_db_instance()
        .db_instance_identifier("harbor")
        .engine("postgres")
        .engine_version("16")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("harbor")
        .manage_master_user_password(true)
        .db_name("registry")
        .backup_retention_period(0)
        .send()
        .await
        .unwrap();
    let db = wait_available(&rds, "harbor").await;
    let endpoint = db.endpoint().unwrap();
    let (host, port) = (endpoint.address().unwrap().to_string(), endpoint.port().unwrap());
    assert_eq!(host, "127.0.0.1");
    assert_ne!(port, 5432);
    let secret = db.master_user_secret().unwrap().secret_arn().unwrap().to_string();

    // The credentials in Secrets Manager open the database.
    let pw = secret_password(&sm, &secret).await;
    let pg = connect_with_retry(&host, port, "harbor", &pw, "registry").await;
    pg.batch_execute("CREATE TABLE artifacts (name text); INSERT INTO artifacts VALUES ('nginx:1.27')").await.unwrap();
    let row = pg.query_one("SELECT version()", &[]).await.unwrap();
    assert!(row.get::<_, String>(0).starts_with("PostgreSQL 16"));
    drop(pg);

    // Rotating the secret changes the password in the database.
    rds.modify_db_instance()
        .db_instance_identifier("harbor")
        .rotate_master_user_password(true)
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let new_pw = secret_password(&sm, &secret).await;
    assert_ne!(new_pw, pw);
    let pg = connect_with_retry(&host, port, "harbor", &new_pw, "registry").await;
    let rows = pg.query("SELECT name FROM artifacts", &[]).await.unwrap();
    assert_eq!(rows.len(), 1);
    drop(pg);
    let mut old_rejected = false;
    for _ in 0..40 {
        if connect(&host, port, "harbor", &pw, "registry").await.is_err() {
            old_rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(old_rejected, "the old password still works");

    // A snapshot holds the data; a restore brings it back in a new
    // instance.
    rds.create_db_snapshot()
        .db_instance_identifier("harbor")
        .db_snapshot_identifier("harbor-snap")
        .send()
        .await
        .unwrap();
    let pg = connect_with_retry(&host, port, "harbor", &new_pw, "registry").await;
    pg.batch_execute("INSERT INTO artifacts VALUES ('after-snapshot')").await.unwrap();
    drop(pg);
    rds.restore_db_instance_from_db_snapshot()
        .db_instance_identifier("harbor-restored")
        .db_snapshot_identifier("harbor-snap")
        .send()
        .await
        .unwrap();
    let restored = wait_available(&rds, "harbor-restored").await;
    let e = restored.endpoint().unwrap();
    let pg = connect_with_retry(e.address().unwrap(), e.port().unwrap(), "harbor", &new_pw, "registry").await;
    let rows = pg.query("SELECT name FROM artifacts", &[]).await.unwrap();
    assert_eq!(rows.len(), 1, "the restore has the data as of the snapshot");
    drop(pg);

    // Stop and start keep the data and the endpoint's address.
    rds.stop_db_instance().db_instance_identifier("harbor").send().await.unwrap();
    for _ in 0..120 {
        let d = rds.describe_db_instances().db_instance_identifier("harbor").send().await.unwrap();
        if d.db_instances()[0].db_instance_status() == Some("stopped") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(connect(&host, port, "harbor", &new_pw, "registry").await.is_err());
    rds.start_db_instance().db_instance_identifier("harbor").send().await.unwrap();
    let db = wait_available(&rds, "harbor").await;
    let e = db.endpoint().unwrap();
    let pg = connect_with_retry(e.address().unwrap(), e.port().unwrap(), "harbor", &new_pw, "registry").await;
    assert_eq!(pg.query("SELECT name FROM artifacts", &[]).await.unwrap().len(), 2);
    drop(pg);

    for id in ["harbor", "harbor-restored"] {
        rds.delete_db_instance().db_instance_identifier(id).skip_final_snapshot(true).send().await.unwrap();
    }
    rds.delete_db_snapshot().db_snapshot_identifier("harbor-snap").send().await.unwrap();
    for _ in 0..120 {
        if rds.describe_db_instances().send().await.unwrap().db_instances().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(rds.describe_db_instances().send().await.unwrap().db_instances().is_empty());
}

#[test]
fn aurora_postgres_runs_in_docker() {
    run(aurora_postgres_runs_in_docker_body());
}

async fn aurora_postgres_runs_in_docker_body() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { rds_backend: mws_rds::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let rds = Client::new(&mws.root_sdk_config().await);

    rds.create_db_cluster()
        .db_cluster_identifier("langfuse")
        .engine("aurora-postgresql")
        .engine_version("16")
        .master_username("langfuse")
        .master_user_password("correct-horse-battery")
        .database_name("langfuse")
        .send()
        .await
        .unwrap();
    rds.create_db_instance()
        .db_instance_identifier("langfuse-1")
        .db_cluster_identifier("langfuse")
        .engine("aurora-postgresql")
        .db_instance_class("db.r6g.large")
        .send()
        .await
        .unwrap();
    let cluster = wait_cluster_available(&rds, "langfuse").await;
    let member = wait_available(&rds, "langfuse-1").await;
    let port = cluster.port().unwrap();
    // The writer, reader and instance endpoints all reach the cluster's
    // database.
    assert_eq!(cluster.endpoint(), Some("127.0.0.1"));
    assert_eq!(member.endpoint().unwrap().port(), Some(port));
    let pg = connect_with_retry("127.0.0.1", port, "langfuse", "correct-horse-battery", "langfuse").await;
    pg.batch_execute("CREATE TABLE traces (id int)").await.unwrap();
    drop(pg);

    // The master password changes through ModifyDBCluster.
    rds.modify_db_cluster()
        .db_cluster_identifier("langfuse")
        .master_user_password("battery-staple-horse")
        .apply_immediately(true)
        .send()
        .await
        .unwrap();
    let pg = connect_with_retry("127.0.0.1", port, "langfuse", "battery-staple-horse", "langfuse").await;
    pg.batch_execute("INSERT INTO traces VALUES (1)").await.unwrap();
    drop(pg);

    let resource = rds.describe_db_clusters().db_cluster_identifier("langfuse").send().await.unwrap().db_clusters()[0]
        .db_cluster_resource_id()
        .unwrap()
        .to_ascii_lowercase();
    rds.delete_db_instance().db_instance_identifier("langfuse-1").send().await.unwrap();
    rds.delete_db_cluster().db_cluster_identifier("langfuse").skip_final_snapshot(true).send().await.unwrap();
    for _ in 0..120 {
        if rds.describe_db_clusters().send().await.unwrap().db_clusters().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // (Other tests' databases may be running.)
    let left = rds_containers();
    assert!(!left.contains(&format!("mws-rds-{resource}")), "containers left: {left:?}");
}

async fn wait_automated_snapshot(rds: &Client, id: &str) {
    for _ in 0..240 {
        let d = rds.describe_db_snapshots().db_instance_identifier(id).snapshot_type("automated").send().await.unwrap();
        if d.db_snapshots().iter().any(|s| s.status() == Some("available")) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no automated snapshot of {id}");
}

fn smithy_time(t: chrono::DateTime<chrono::Utc>) -> aws_sdk_rds::primitives::DateTime {
    aws_sdk_rds::primitives::DateTime::from_millis(t.timestamp_millis())
}

/// The rows of `SELECT name FROM ledger` in a PostgreSQL database.
async fn pg_rows(db: &aws_sdk_rds::types::DbInstance, password: &str) -> Vec<String> {
    let e = db.endpoint().unwrap();
    let pg = connect_with_retry(e.address().unwrap(), e.port().unwrap(), "app", password, "app").await;
    let rows = pg.query("SELECT name FROM ledger ORDER BY name", &[]).await.unwrap();
    rows.iter().map(|r| r.get::<_, String>(0)).collect()
}

#[test]
fn postgres_point_in_time_restore() {
    run(postgres_point_in_time_restore_body());
}

async fn postgres_point_in_time_restore_body() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { rds_backend: mws_rds::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let rds = Client::new(&mws.root_sdk_config().await);
    let pw = "ledger-password-1";
    rds.create_db_instance()
        .db_instance_identifier("ledger")
        .engine("postgres")
        .engine_version("16")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("app")
        .master_user_password(pw)
        .db_name("app")
        .backup_retention_period(1)
        .send()
        .await
        .unwrap();
    let db = wait_available(&rds, "ledger").await;
    let resource = db.dbi_resource_id().unwrap().to_string();
    wait_automated_snapshot(&rds, "ledger").await;

    // Rows written after the automated backup, on both sides of the
    // restore time.
    let e = db.endpoint().unwrap();
    let pg = connect_with_retry(e.address().unwrap(), e.port().unwrap(), "app", pw, "app").await;
    pg.batch_execute("CREATE TABLE ledger (name text); INSERT INTO ledger VALUES ('before')").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let restore_time = chrono::Utc::now();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    pg.batch_execute("INSERT INTO ledger VALUES ('after')").await.unwrap();
    drop(pg);

    let d = rds.describe_db_instances().db_instance_identifier("ledger").send().await.unwrap();
    let latest = d.db_instances()[0].latest_restorable_time().unwrap().to_millis().unwrap();
    assert!(latest >= restore_time.timestamp_millis());

    rds.restore_db_instance_to_point_in_time()
        .source_db_instance_identifier("ledger")
        .target_db_instance_identifier("ledger-then")
        .restore_time(smithy_time(restore_time))
        .send()
        .await
        .unwrap();
    rds.restore_db_instance_to_point_in_time()
        .source_db_instance_identifier("ledger")
        .target_db_instance_identifier("ledger-now")
        .use_latest_restorable_time(true)
        .send()
        .await
        .unwrap();
    let then = wait_available(&rds, "ledger-then").await;
    assert_eq!(pg_rows(&then, pw).await, ["before"], "the restore holds the data as of the restore time");
    let now = wait_available(&rds, "ledger-now").await;
    assert_eq!(pg_rows(&now, pw).await, ["after", "before"]);

    // A deleted instance's retained backup restores to a point in time
    // too.
    rds.delete_db_instance()
        .db_instance_identifier("ledger")
        .skip_final_snapshot(true)
        .delete_automated_backups(false)
        .send()
        .await
        .unwrap();
    for _ in 0..120 {
        let b = rds.describe_db_instance_automated_backups().dbi_resource_id(&resource).send().await.unwrap();
        if b.db_instance_automated_backups().first().and_then(|b| b.status()) == Some("retained") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    rds.restore_db_instance_to_point_in_time()
        .source_dbi_resource_id(&resource)
        .target_db_instance_identifier("ledger-retained")
        .restore_time(smithy_time(restore_time))
        .send()
        .await
        .unwrap();
    let retained = wait_available(&rds, "ledger-retained").await;
    assert_eq!(pg_rows(&retained, pw).await, ["before"]);

    for id in ["ledger-then", "ledger-now", "ledger-retained"] {
        rds.delete_db_instance().db_instance_identifier(id).skip_final_snapshot(true).send().await.unwrap();
    }
    rds.delete_db_instance_automated_backup().dbi_resource_id(&resource).send().await.unwrap();
    for _ in 0..120 {
        if rds.describe_db_instances().send().await.unwrap().db_instances().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Run SQL with the `mysql` client inside an instance's container.
fn mysql_exec(id: &str, password: &str, sql: &str) -> String {
    // A backup pauses the container for a moment, and a restore replaces
    // it: look it up again and retry.
    let mut last = String::new();
    for _ in 0..20 {
        let out = Command::new("docker")
            .args(["ps", "-q", "--filter", &format!("label=mws.rds.identifier={id}")])
            .output()
            .unwrap();
        let container = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or_default().to_string();
        if container.is_empty() {
            last = format!("no container for {id}");
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        let out = Command::new("docker")
            .args([
                "exec",
                &container,
                "mysql",
                "-h",
                "127.0.0.1",
                "-u",
                "app",
                &format!("-p{password}"),
                "-N",
                "-e",
                sql,
            ])
            .output()
            .unwrap();
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
        last = format!("{}{}", String::from_utf8_lossy(&out.stderr), String::from_utf8_lossy(&out.stdout));
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("mysql failed: {last}");
}

#[test]
fn mysql_point_in_time_restore() {
    run(mysql_point_in_time_restore_body());
}

async fn mysql_point_in_time_restore_body() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { rds_backend: mws_rds::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let rds = Client::new(&mws.root_sdk_config().await);
    let pw = "orders-password-1";
    rds.create_db_instance()
        .db_instance_identifier("orders")
        .engine("mysql")
        .engine_version("8.0")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("app")
        .master_user_password(pw)
        .db_name("app")
        .backup_retention_period(1)
        .send()
        .await
        .unwrap();
    wait_available(&rds, "orders").await;
    wait_automated_snapshot(&rds, "orders").await;

    mysql_exec("orders", pw, "CREATE TABLE app.ledger (name varchar(20)); INSERT INTO app.ledger VALUES ('before')");
    // The binary log has one-second timestamps.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let restore_time = chrono::Utc::now();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    mysql_exec("orders", pw, "INSERT INTO app.ledger VALUES ('after')");

    rds.restore_db_instance_to_point_in_time()
        .source_db_instance_identifier("orders")
        .target_db_instance_identifier("orders-then")
        .restore_time(smithy_time(restore_time))
        .send()
        .await
        .unwrap();
    wait_available(&rds, "orders-then").await;
    // (Its first automated backup pauses the container briefly.)
    wait_automated_snapshot(&rds, "orders-then").await;
    assert_eq!(mysql_exec("orders-then", pw, "SELECT name FROM app.ledger ORDER BY name"), "before");
    assert_eq!(mysql_exec("orders", pw, "SELECT count(*) FROM app.ledger"), "2");

    for id in ["orders", "orders-then"] {
        rds.delete_db_instance().db_instance_identifier(id).skip_final_snapshot(true).send().await.unwrap();
    }
    for _ in 0..120 {
        if rds.describe_db_instances().send().await.unwrap().db_instances().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A role `service` may assume, allowed everything it needs.
async fn service_role(mws: &Mws, name: &str, service: &str) -> String {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    let role = iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    iam.put_role_policy()
        .role_name(name)
        .policy_name("all")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","kms:*","secretsmanager:*"],"Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    role.role.unwrap().arn
}

#[test]
fn proxy_export_and_blue_green_in_docker() {
    run(proxy_export_and_blue_green_in_docker_body());
}

async fn proxy_export_and_blue_green_in_docker_body() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { rds_backend: mws_rds::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let sdk = mws.root_sdk_config().await;
    let rds = Client::new(&sdk);
    let pw = "harbor-password-1";
    rds.create_db_instance()
        .db_instance_identifier("harbor")
        .engine("postgres")
        .engine_version("16")
        .db_instance_class("db.t3.micro")
        .allocated_storage(20)
        .master_username("app")
        .master_user_password(pw)
        .db_name("app")
        .backup_retention_period(1)
        .send()
        .await
        .unwrap();
    wait_available(&rds, "harbor").await;
    // (Its first automated backup pauses the container briefly.)
    wait_automated_snapshot(&rds, "harbor").await;
    let db = wait_available(&rds, "harbor").await;
    let e = db.endpoint().unwrap();
    let pg = connect_with_retry(e.address().unwrap(), e.port().unwrap(), "app", pw, "app").await;
    pg.batch_execute(
        "CREATE TABLE artifacts (id bigint, name text, size double precision, signed boolean);
         INSERT INTO artifacts VALUES (1, 'nginx:1.27', 187.5, true), (2, 'redis:7', 41.25, false)",
    )
    .await
    .unwrap();
    drop(pg);

    // ---- a proxy endpoint forwards to the instance ----
    let sm = aws_sdk_secretsmanager::Client::new(&sdk);
    let secret = sm
        .create_secret()
        .name("harbor-db")
        .secret_string(format!(r#"{{"username":"app","password":"{pw}"}}"#))
        .send()
        .await
        .unwrap()
        .arn
        .unwrap();
    let role = service_role(&mws, "proxy-role", "rds.amazonaws.com").await;
    let ec2 = aws_sdk_ec2::Client::new(&sdk);
    let subnets: Vec<String> = ec2
        .describe_subnets()
        .send()
        .await
        .unwrap()
        .subnets()
        .iter()
        .filter(|s| s.default_for_az() == Some(true))
        .filter_map(|s| s.subnet_id().map(str::to_string))
        .collect();
    let proxy = rds
        .create_db_proxy()
        .db_proxy_name("harbor-proxy")
        .engine_family(aws_sdk_rds::types::EngineFamily::Postgresql)
        .role_arn(&role)
        .set_vpc_subnet_ids(Some(subnets))
        .auth(aws_sdk_rds::types::UserAuthConfig::builder().secret_arn(&secret).build())
        .send()
        .await
        .unwrap()
        .db_proxy
        .unwrap();
    let proxy_arn = proxy.db_proxy_arn().unwrap().to_string();
    rds.register_db_proxy_targets()
        .db_proxy_name("harbor-proxy")
        .db_instance_identifiers("harbor")
        .send()
        .await
        .unwrap();
    let (host, port) = {
        let mut found = None;
        for _ in 0..60 {
            let (status, body) = mws.control("GET", "/_aws/rds/proxy-endpoints", None).await;
            assert_eq!(status, 200);
            if let Some(l) = body.as_array().unwrap().iter().find(|l| l["arn"] == proxy_arn.as_str()) {
                found = Some((l["host"].as_str().unwrap().to_string(), l["port"].as_i64().unwrap() as i32));
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        found.expect("the proxy listens")
    };
    let through = connect_with_retry(&host, port, "app", pw, "app").await;
    let n: i64 = through.query_one("SELECT count(*) FROM artifacts", &[]).await.unwrap().get(0);
    assert_eq!(n, 2);
    drop(through);
    rds.deregister_db_proxy_targets()
        .db_proxy_name("harbor-proxy")
        .db_instance_identifiers("harbor")
        .send()
        .await
        .unwrap();
    rds.delete_db_proxy().db_proxy_name("harbor-proxy").send().await.unwrap();

    // ---- a snapshot export writes the table as Parquet ----
    rds.create_db_snapshot()
        .db_instance_identifier("harbor")
        .db_snapshot_identifier("harbor-snap")
        .send()
        .await
        .unwrap();
    for _ in 0..240 {
        let s = rds.describe_db_snapshots().db_snapshot_identifier("harbor-snap").send().await.unwrap();
        if s.db_snapshots()[0].status() == Some("available") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let s3 = Mws::s3(&sdk);
    s3.create_bucket().bucket("exports").send().await.unwrap();
    let kms = aws_sdk_kms::Client::new(&sdk);
    let key = kms.create_key().send().await.unwrap().key_metadata.unwrap().arn.unwrap();
    let export_role = service_role(&mws, "export-role", "export.rds.amazonaws.com").await;
    rds.start_export_task()
        .export_task_identifier("harbor-export")
        .source_arn("arn:aws:rds:us-east-1:123456789012:snapshot:harbor-snap")
        .s3_bucket_name("exports")
        .iam_role_arn(&export_role)
        .kms_key_id(&key)
        .export_only("app.public.artifacts")
        .send()
        .await
        .unwrap();
    let mut status = String::new();
    for _ in 0..600 {
        let t = rds.describe_export_tasks().export_task_identifier("harbor-export").send().await.unwrap();
        let t = t.export_tasks()[0].clone();
        status = t.status().unwrap_or_default().to_string();
        if status == "COMPLETE" || status == "FAILED" {
            assert_eq!(status, "COMPLETE", "{:?}", t.failure_cause());
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(status, "COMPLETE");
    let objects =
        s3.list_objects_v2().bucket("exports").prefix("harbor-export/app/public.artifacts/1/").send().await.unwrap();
    let key = objects.contents()[0].key().unwrap().to_string();
    assert!(key.ends_with(".parquet"), "{key}");
    let body =
        s3.get_object().bucket("exports").key(&key).send().await.unwrap().body.collect().await.unwrap().into_bytes();
    assert!(body.starts_with(b"PAR1") && body.ends_with(b"PAR1"));
    let has = |needle: &[u8]| body.windows(needle.len()).any(|w| w == needle);
    assert!(has(b"nginx:1.27") && has(b"redis:7") && has(b"signed"));
    let tables = s3
        .get_object()
        .bucket("exports")
        .key("harbor-export/export_tables_info_harbor-export_from_1_to_1.json")
        .send()
        .await
        .unwrap()
        .body
        .collect()
        .await
        .unwrap()
        .into_bytes();
    let tables: serde_json::Value = serde_json::from_slice(&tables).unwrap();
    assert_eq!(tables["perTableStatus"][0]["target"], "app.public.artifacts");

    // ---- Blue/Green: green takes over with blue's latest data ----
    let bg = rds
        .create_blue_green_deployment()
        .blue_green_deployment_name("harbor-17")
        .source("arn:aws:rds:us-east-1:123456789012:db:harbor")
        .target_engine_version("17")
        .send()
        .await
        .unwrap()
        .blue_green_deployment
        .unwrap();
    let id = bg.blue_green_deployment_identifier().unwrap().to_string();
    for _ in 0..600 {
        let b = rds.describe_blue_green_deployments().blue_green_deployment_identifier(&id).send().await.unwrap();
        if b.blue_green_deployments()[0].status() == Some("AVAILABLE") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let blue = wait_available(&rds, "harbor").await;
    let e = blue.endpoint().unwrap();
    let pg = connect_with_retry(e.address().unwrap(), e.port().unwrap(), "app", pw, "app").await;
    pg.batch_execute("INSERT INTO artifacts VALUES (3, 'langfuse:3', 512.0, true)").await.unwrap();
    drop(pg);
    rds.switchover_blue_green_deployment().blue_green_deployment_identifier(&id).send().await.unwrap();
    for _ in 0..600 {
        let b = rds.describe_blue_green_deployments().blue_green_deployment_identifier(&id).send().await.unwrap();
        if b.blue_green_deployments()[0].status() == Some("SWITCHOVER_COMPLETED") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let new_blue = wait_available(&rds, "harbor").await;
    let e = new_blue.endpoint().unwrap();
    let pg = connect_with_retry(e.address().unwrap(), e.port().unwrap(), "app", pw, "app").await;
    let version: String = pg.query_one("SHOW server_version", &[]).await.unwrap().get(0);
    assert!(version.starts_with("17"), "{version}");
    let n: i64 = pg.query_one("SELECT count(*) FROM artifacts", &[]).await.unwrap().get(0);
    assert_eq!(n, 3, "green has blue's writes from before the switchover");
    drop(pg);
    rds.delete_blue_green_deployment().blue_green_deployment_identifier(&id).send().await.unwrap();

    for id in ["harbor", "harbor-old1"] {
        rds.delete_db_instance().db_instance_identifier(id).skip_final_snapshot(true).send().await.unwrap();
    }
    for _ in 0..120 {
        if rds.describe_db_instances().send().await.unwrap().db_instances().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[test]
fn aurora_mysql_backtrack_in_docker() {
    run(aurora_mysql_backtrack_in_docker_body());
}

async fn aurora_mysql_backtrack_in_docker_body() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let config = mws::Config { rds_backend: mws_rds::BackendChoice::Docker, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let rds = Client::new(&mws.root_sdk_config().await);
    let pw = "orders-password-1";
    rds.create_db_cluster()
        .db_cluster_identifier("journal")
        .engine("aurora-mysql")
        .master_username("app")
        .master_user_password(pw)
        .database_name("app")
        .backtrack_window(3600)
        .send()
        .await
        .unwrap();
    wait_cluster_available(&rds, "journal").await;
    for _ in 0..240 {
        let s = rds
            .describe_db_cluster_snapshots()
            .db_cluster_identifier("journal")
            .snapshot_type("automated")
            .send()
            .await
            .unwrap();
        if s.db_cluster_snapshots().iter().any(|s| s.status() == Some("available")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    mysql_exec("journal", pw, "CREATE TABLE app.entries (name varchar(20)); INSERT INTO app.entries VALUES ('kept')");
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let to = chrono::Utc::now();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    mysql_exec("journal", pw, "INSERT INTO app.entries VALUES ('mistake')");

    let b =
        rds.backtrack_db_cluster().db_cluster_identifier("journal").backtrack_to(smithy_time(to)).send().await.unwrap();
    let bid = b.backtrack_identifier().unwrap().to_string();
    let mut status = String::new();
    for _ in 0..600 {
        let d = rds
            .describe_db_cluster_backtracks()
            .db_cluster_identifier("journal")
            .backtrack_identifier(&bid)
            .send()
            .await
            .unwrap();
        status = d.db_cluster_backtracks()[0].status().unwrap_or_default().to_string();
        if status != "applying" && status != "pending" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(status, "completed");
    wait_cluster_available(&rds, "journal").await;
    assert_eq!(mysql_exec("journal", pw, "SELECT name FROM app.entries ORDER BY name"), "kept");

    rds.delete_db_cluster().db_cluster_identifier("journal").skip_final_snapshot(true).send().await.unwrap();
    for _ in 0..120 {
        if rds.describe_db_clusters().send().await.unwrap().db_clusters().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
