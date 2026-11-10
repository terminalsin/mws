//! Elastic Load Balancing access logs and connection logs, delivered to S3
//! through the official Rust SDKs: bucket permission checks when logging is
//! turned on, then the files ELB writes at the end of each interval on the
//! emulated clock.

use std::io::Read as _;
use std::time::Duration;

use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, Certificate, FixedResponseActionConfig, LoadBalancerAttribute, LoadBalancerTypeEnum,
    PathPatternConditionConfig, ProtocolEnum, RuleCondition, TargetDescription, TargetHealthStateEnum,
};
use mws_e2e::Mws;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::elbv2::{
    client, code, default_network, forward, get, https_request, imported_certificate, ip_target_group,
    listener_address, message, tls_connect, wait_for_health, Backend,
};

const ACCOUNT: &str = "123456789012";

fn attr(key: &str, value: &str) -> LoadBalancerAttribute {
    LoadBalancerAttribute::builder().key(key).value(value).build()
}

/// A bucket whose policy lets `principal` write ELB logs under `prefix`.
async fn log_bucket(s3: &aws_sdk_s3::Client, bucket: &str, principal: serde_json::Value, prefix: &str) {
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    let resource = if prefix.is_empty() {
        format!("arn:aws:s3:::{bucket}/AWSLogs/{ACCOUNT}/*")
    } else {
        format!("arn:aws:s3:::{bucket}/{prefix}/AWSLogs/{ACCOUNT}/*")
    };
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:PutObject", "Resource": resource}]
    });
    s3.put_bucket_policy().bucket(bucket).policy(policy.to_string()).send().await.unwrap();
}

/// Move the emulated clock past the end of the current 5-minute interval
/// (and tell ELB, which reads the clock from requests).
async fn next_interval(mws: &Mws, minutes: i64) {
    let body = format!(r#"{{"advanceSeconds": {}}}"#, minutes * 60 + 1);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
    client(mws).await.describe_load_balancers().send().await.unwrap();
}

/// The log objects under `prefix`, waiting for at least one: `(key, text)`.
async fn log_files(s3: &aws_sdk_s3::Client, bucket: &str, prefix: &str, suffix: &str) -> Vec<(String, String)> {
    for _ in 0..80 {
        let list = s3.list_objects_v2().bucket(bucket).prefix(prefix).send().await.unwrap();
        let keys: Vec<String> = list
            .contents()
            .iter()
            .filter_map(|o| o.key().map(str::to_string))
            .filter(|k| k.ends_with(suffix))
            .collect();
        if !keys.is_empty() {
            let mut out = Vec::new();
            for key in keys {
                let obj = s3.get_object().bucket(bucket).key(&key).send().await.unwrap();
                let bytes = obj.body.collect().await.unwrap().into_bytes().to_vec();
                let text = if suffix.ends_with(".gz") {
                    let mut s = String::new();
                    flate2::read::GzDecoder::new(bytes.as_slice()).read_to_string(&mut s).unwrap();
                    s
                } else {
                    String::from_utf8(bytes).unwrap()
                };
                out.push((key, text));
            }
            return out;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("no {suffix} log files under s3://{bucket}/{prefix}");
}

/// Split a log line into fields, keeping quoted fields whole.
fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

#[tokio::test]
async fn application_load_balancer_access_and_connection_logs() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let elb = client(&mws).await;
    let s3 = Mws::s3(&cfg);
    let (vpc, subnets) = default_network(&mws).await;
    let backend = Backend::start("logged").await;

    let lb = elb.create_load_balancer().name("logs").set_subnets(Some(subnets)).send().await.unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let lb_id = lb_arn.rsplit('/').next().unwrap().to_string();
    let tg = ip_target_group(&elb, "logs", &vpc, ProtocolEnum::Http).await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(backend.port()).build())
        .send()
        .await
        .unwrap();
    let http = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    let http_arn = http.listeners()[0].listener_arn().unwrap().to_string();
    elb.create_rule()
        .listener_arn(&http_arn)
        .priority(5)
        .conditions(
            RuleCondition::builder()
                .field("path-pattern")
                .path_pattern_config(PathPatternConditionConfig::builder().values("/teapot").build())
                .build(),
        )
        .actions(
            Action::builder()
                .r#type(ActionTypeEnum::FixedResponse)
                .fixed_response_config(FixedResponseActionConfig::builder().status_code("418").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let (cert, _) = imported_certificate(&mws, "logs.example.com").await;
    let https = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Https)
        .port(443)
        .certificates(Certificate::builder().certificate_arn(&cert).build())
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    let https_arn = https.listeners()[0].listener_arn().unwrap().to_string();
    wait_for_health(&elb, &tg, &[(backend.port(), TargetHealthStateEnum::Healthy)]).await;

    // A bucket ELB may not write to is refused, and nothing changes.
    s3.create_bucket().bucket("closed-logs").send().await.unwrap();
    let err = elb
        .modify_load_balancer_attributes()
        .load_balancer_arn(&lb_arn)
        .attributes(attr("access_logs.s3.enabled", "true"))
        .attributes(attr("access_logs.s3.bucket", "closed-logs"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidConfigurationRequest");
    assert_eq!(message(&err), "Access Denied for bucket: closed-logs. Please check S3bucket permission");
    let attrs = elb.describe_load_balancer_attributes().load_balancer_arn(&lb_arn).send().await.unwrap();
    let enabled = attrs.attributes().iter().find(|a| a.key() == Some("access_logs.s3.enabled")).unwrap();
    assert_eq!(enabled.value(), Some("false"));

    // The service principal, granted by bucket policy.
    let principal = serde_json::json!({"Service": "logdelivery.elasticloadbalancing.amazonaws.com"});
    log_bucket(&s3, "alb-logs", principal, "web").await;
    elb.modify_load_balancer_attributes()
        .load_balancer_arn(&lb_arn)
        .attributes(attr("access_logs.s3.enabled", "true"))
        .attributes(attr("access_logs.s3.bucket", "alb-logs"))
        .attributes(attr("access_logs.s3.prefix", "web"))
        .attributes(attr("connection_logs.s3.enabled", "true"))
        .attributes(attr("connection_logs.s3.bucket", "alb-logs"))
        .attributes(attr("connection_logs.s3.prefix", "web"))
        .attributes(attr("health_check_logs.s3.enabled", "true"))
        .attributes(attr("health_check_logs.s3.bucket", "alb-logs"))
        .attributes(attr("health_check_logs.s3.prefix", "web"))
        .send()
        .await
        .unwrap();
    // ELB proves it can write with a test file.
    s3.head_object()
        .bucket("alb-logs")
        .key(format!("web/AWSLogs/{ACCOUNT}/ELBAccessLogTestFile"))
        .send()
        .await
        .unwrap();

    let addr = listener_address(&mws, &http_arn).await;
    let ok = get(&addr, "shop.example.com", "/hello?q=1", &[("User-Agent", "log-test/1.0")]).await;
    assert_eq!(ok.status, 200);
    let teapot = get(&addr, "shop.example.com", "/teapot", &[]).await;
    assert_eq!(teapot.status, 418);
    let tls_addr = listener_address(&mws, &https_arn).await;
    let secure = https_request(&tls_addr, "logs.example.com", "/secure", &[]).await;
    assert_eq!(secure.status, 200);
    // At least one health check (every 5 seconds) while health check logs
    // are on.
    tokio::time::sleep(Duration::from_secs(6)).await;

    next_interval(&mws, 5).await;
    let region = "us-east-1";
    let dir = format!("web/AWSLogs/{ACCOUNT}/elasticloadbalancing/{region}/");
    let files = log_files(&s3, "alb-logs", &dir, ".log.gz").await;
    let access: Vec<&(String, String)> =
        files.iter().filter(|(k, _)| !k.contains("/conn_log.") && !k.contains("/health_log.")).collect();
    assert_eq!(access.len(), 1, "{files:?}");
    let (key, text) = access[0];
    let name = key.rsplit('/').next().unwrap();
    let pattern = regex::Regex::new(&format!(
        r"^{ACCOUNT}_elasticloadbalancing_{region}_app\.logs\.{lb_id}_\d{{8}}T\d{{4}}Z_[0-9a-f.:]+_[0-9a-z]+\.log\.gz$"
    ))
    .unwrap();
    assert!(pattern.is_match(name), "{name}");
    assert!(regex::Regex::new(r"/\d{4}/\d{2}/\d{2}/[^/]+$").unwrap().is_match(key), "{key}");

    let lines: Vec<Vec<String>> = text.lines().map(fields).collect();
    assert_eq!(lines.len(), 3, "{text}");
    let hello = lines.iter().find(|l| l[12].contains("/hello")).unwrap_or_else(|| panic!("{text}"));
    assert_eq!(hello[0], "http");
    assert_eq!(hello[2], format!("app/logs/{lb_id}"));
    assert_eq!(hello[4], format!("127.0.0.1:{}", backend.port()));
    assert_eq!(hello[8], "200");
    assert_eq!(hello[9], "200");
    assert_eq!(hello[12], "GET http://shop.example.com:80/hello?q=1 HTTP/1.1");
    assert_eq!(hello[13], "log-test/1.0");
    assert_eq!(hello[14], "-");
    assert_eq!(hello[16], tg);
    assert!(hello[17].starts_with("Root=1-"), "{:?}", hello);
    assert_eq!(hello[20], "0", "default rule priority");
    assert_eq!(hello[22], "forward");
    assert_eq!(hello[26], "200");
    assert!(hello.last().unwrap().starts_with("TID_"), "{hello:?}");

    let tea = lines.iter().find(|l| l[12].contains("/teapot")).unwrap();
    assert_eq!(tea[4], "-");
    assert_eq!(tea[5..8], ["-1", "-1", "-1"]);
    assert_eq!(tea[8], "418");
    assert_eq!(tea[9], "-");
    assert_eq!(tea[20], "5");
    assert_eq!(tea[22], "fixed-response");

    let https_line = lines.iter().find(|l| l[12].contains("/secure")).unwrap();
    assert_eq!(https_line[0], "https");
    assert!(https_line[15].starts_with("TLSv1."), "{https_line:?}");
    assert_eq!(https_line[18], "logs.example.com");
    assert_eq!(https_line[19], cert);

    // One connection log entry for the HTTPS handshake, tied to the request
    // by its connection trace id.
    let conn: Vec<&(String, String)> = files.iter().filter(|(k, _)| k.contains("/conn_log.")).collect();
    assert_eq!(conn.len(), 1, "{files:?}");
    let entry = fields(conn[0].1.lines().next().unwrap());
    assert_eq!(entry[1], "127.0.0.1");
    assert_eq!(entry[3], "443");
    assert!(entry[4].starts_with("TLSv1."), "{entry:?}");
    assert_eq!(entry[10], "Success");
    assert_eq!(entry[11], *https_line.last().unwrap());

    // Health check log entries: one per check of the target.
    let mut health = Vec::new();
    for _ in 0..40 {
        health = log_files(&s3, "alb-logs", &dir, ".log.gz").await;
        health.retain(|(k, _)| k.contains("/health_log."));
        if !health.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(health.len(), 1, "{health:?}");
    let check = fields(health[0].1.lines().next().unwrap());
    assert_eq!(check[0], "http");
    assert_eq!(check[3], format!("127.0.0.1:{}", backend.port()));
    assert_eq!(check[4], tg.rsplit_once(':').unwrap().1);
    assert_eq!(check[5..8], ["PASS", "200", "-"]);
    backend.stop();
}

#[tokio::test]
async fn network_load_balancer_tls_logs_and_regional_account_policies() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let elb = client(&mws).await;
    let s3 = Mws::s3(&cfg);
    let (vpc, subnets) = default_network(&mws).await;
    let backend = Backend::start("tls").await;

    let lb = elb
        .create_load_balancer()
        .name("tls-logs")
        .r#type(LoadBalancerTypeEnum::Network)
        .set_subnets(Some(subnets[..1].to_vec()))
        .send()
        .await
        .unwrap();
    let lb_arn = lb.load_balancers()[0].load_balancer_arn().unwrap().to_string();
    let lb_id = lb_arn.rsplit('/').next().unwrap().to_string();
    let tg = ip_target_group(&elb, "tls-logs", &vpc, ProtocolEnum::Tcp).await;
    elb.register_targets()
        .target_group_arn(&tg)
        .targets(TargetDescription::builder().id("127.0.0.1").port(backend.port()).build())
        .send()
        .await
        .unwrap();
    let (cert, _) = imported_certificate(&mws, "tls.example.com").await;
    let listener = elb
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Tls)
        .port(443)
        .certificates(Certificate::builder().certificate_arn(&cert).build())
        .default_actions(forward(&tg))
        .send()
        .await
        .unwrap();
    let listener_arn = listener.listeners()[0].listener_arn().unwrap().to_string();
    wait_for_health(&elb, &tg, &[(backend.port(), TargetHealthStateEnum::Healthy)]).await;

    // Older bucket policies name the Region's ELB account (us-east-1's).
    let principal = serde_json::json!({"AWS": "arn:aws:iam::127311923021:root"});
    log_bucket(&s3, "nlb-logs", principal, "").await;
    elb.modify_load_balancer_attributes()
        .load_balancer_arn(&lb_arn)
        .attributes(attr("access_logs.s3.enabled", "true"))
        .attributes(attr("access_logs.s3.bucket", "nlb-logs"))
        .send()
        .await
        .unwrap();

    let addr = listener_address(&mws, &listener_arn).await;
    // The backend keeps the connection open, so read one response and
    // hang up, which ends the TLS connection the log records.
    let (mut tls, _) = tls_connect(&addr, "tls.example.com", None).await.unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: tls.example.com\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 8192];
    let n = tls.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"), "{:?}", &buf[..n]);
    tls.shutdown().await.unwrap();
    drop(tls);

    next_interval(&mws, 5).await;
    let dir = format!("AWSLogs/{ACCOUNT}/elasticloadbalancing/us-east-1/");
    let files = log_files(&s3, "nlb-logs", &dir, ".log.gz").await;
    assert_eq!(files.len(), 1);
    let (key, text) = &files[0];
    assert!(key.contains(&format!("_elasticloadbalancing_us-east-1_net.tls-logs.{lb_id}_")), "{key}");
    let line = fields(text.lines().next().unwrap());
    assert_eq!(line[0..2], ["tls", "2.0"]);
    assert_eq!(line[3], format!("net/tls-logs/{lb_id}"));
    assert_eq!(line[4], listener_arn.rsplit('/').next().unwrap());
    assert!(line[5].starts_with("127.0.0.1:"), "{line:?}");
    assert!(line[9].parse::<u64>().unwrap() > 0 && line[10].parse::<u64>().unwrap() > 0, "{line:?}");
    assert_eq!(line[12], cert);
    assert!(line[15] == "tlsv12" || line[15] == "tlsv13", "{line:?}");
    assert_eq!(line[17], "tls.example.com");
    backend.stop();
}

#[tokio::test]
async fn classic_load_balancer_access_logs() {
    use aws_sdk_elasticloadbalancing::types::{AccessLog, Listener, LoadBalancerAttributes};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let classic = aws_sdk_elasticloadbalancing::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    default_network(&mws).await;
    let zones = ec2.describe_availability_zones().send().await.unwrap();
    let zone = zones.availability_zones()[0].zone_name().unwrap().to_string();
    let http = Listener::builder().protocol("HTTP").load_balancer_port(80).instance_port(8080).build().unwrap();
    classic
        .create_load_balancer()
        .load_balancer_name("old")
        .listeners(http)
        .availability_zones(zone)
        .send()
        .await
        .unwrap();

    let logs = |bucket: &str| {
        LoadBalancerAttributes::builder()
            .access_log(
                AccessLog::builder()
                    .enabled(true)
                    .s3_bucket_name(bucket)
                    .s3_bucket_prefix("classic")
                    .emit_interval(5)
                    .build(),
            )
            .build()
    };
    s3.create_bucket().bucket("classic-closed").send().await.unwrap();
    let err = classic
        .modify_load_balancer_attributes()
        .load_balancer_name("old")
        .load_balancer_attributes(logs("classic-closed"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.meta().code(), Some("InvalidConfigurationRequest"));
    assert_eq!(
        err.meta().message(),
        Some("Access Denied for bucket: classic-closed. Please check S3bucket permission")
    );

    let principal = serde_json::json!({"AWS": "arn:aws:iam::127311923021:root"});
    log_bucket(&s3, "classic-logs", principal, "classic").await;
    classic
        .modify_load_balancer_attributes()
        .load_balancer_name("old")
        .load_balancer_attributes(logs("classic-logs"))
        .send()
        .await
        .unwrap();

    // No instances are registered, so ELB answers 503 itself, and logs it.
    let (status, list) = mws.control("GET", "/_aws/elb/listeners", None).await;
    assert_eq!(status, 200);
    let addr = list
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["listener"].as_str().unwrap().ends_with("loadbalancer/old:80"))
        .unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();
    let r = get(&addr, "old.example.com", "/legacy", &[("User-Agent", "classic-test")]).await;
    assert_eq!(r.status, 503);

    next_interval(&mws, 5).await;
    classic.describe_load_balancers().send().await.unwrap();
    let files =
        log_files(&s3, "classic-logs", &format!("classic/AWSLogs/{ACCOUNT}/elasticloadbalancing/us-east-1/"), ".log")
            .await;
    assert_eq!(files.len(), 1);
    let (key, text) = &files[0];
    assert!(key.contains(&format!("/{ACCOUNT}_elasticloadbalancing_us-east-1_old_")), "{key}");
    let line = fields(text.lines().next().unwrap());
    assert_eq!(line[1], "old");
    assert_eq!(line[3], "-");
    assert_eq!(line[4..7], ["-1", "-1", "-1"]);
    assert_eq!(line[7], "503");
    assert_eq!(line[11], "GET http://old.example.com:80/legacy HTTP/1.1");
    assert_eq!(line[12], "classic-test");
}
