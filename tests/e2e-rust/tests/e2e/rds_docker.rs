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

    rds.delete_db_instance().db_instance_identifier("langfuse-1").send().await.unwrap();
    rds.delete_db_cluster().db_cluster_identifier("langfuse").skip_final_snapshot(true).send().await.unwrap();
    for _ in 0..120 {
        if rds.describe_db_clusters().send().await.unwrap().db_clusters().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let left = rds_containers();
    assert!(left.is_empty() || !left.iter().any(|c| c.contains("cluster-")), "containers left: {left:?}");
}
