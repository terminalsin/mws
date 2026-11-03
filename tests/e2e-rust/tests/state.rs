//! Persistence, scenarios, reset and snapshots, observed through the
//! official Rust SDK.

use std::path::PathBuf;

use aws_sdk_acmpca::types::CertificateAuthorityStatus;
use mws_e2e::{sts_config, user_with_policy, Mws};
use serde_json::json;

fn example_scenario() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/scenario.json")
}

/// A fresh database path under the target directory.
fn temp_db(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mws-e2e-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("state.db")
}

async fn user_names(iam: &aws_sdk_iam::Client) -> Vec<String> {
    iam.list_users().send().await.unwrap().users().iter().map(|u| u.user_name().to_string()).collect()
}

#[tokio::test]
async fn startup_scenario_seeds_what_the_sdk_sees() {
    let mws = Mws::start_with(mws::Config { scenario: Some(example_scenario()), ..Default::default() }).await;
    let cfg = mws.root_sdk_config().await;

    let iam = aws_sdk_iam::Client::new(&cfg);
    assert_eq!(user_names(&iam).await, ["deployer"]);
    let user = iam.get_user().user_name("deployer").send().await.unwrap();
    assert_eq!(user.user().unwrap().tags()[0].value(), "platform");
    let attached = iam.list_attached_role_policies().role_name("app").send().await.unwrap();
    assert_eq!(attached.attached_policies()[0].policy_name(), Some("ReadOnlyAccess"));

    let r53 = aws_sdk_route53::Client::new(&cfg);
    let zones = r53.list_hosted_zones_by_name().dns_name("example.internal").send().await.unwrap();
    let zone = &zones.hosted_zones()[0];
    assert_eq!(zone.name(), "example.internal.");
    let records = r53.list_resource_record_sets().hosted_zone_id(zone.id()).send().await.unwrap();
    let api = records.resource_record_sets().iter().find(|r| r.name() == "api.example.internal.").unwrap();
    assert_eq!(api.resource_records()[0].value(), "10.0.0.10");

    let pca = aws_sdk_acmpca::Client::new(&cfg);
    let cas = pca.list_certificate_authorities().send().await.unwrap();
    assert_eq!(cas.certificate_authorities()[0].status(), Some(&CertificateAuthorityStatus::Active));
}

#[tokio::test]
async fn scenario_outputs_feed_sdk_clients_and_policies_apply() {
    let mws = Mws::start().await;
    let scenario = json!({
        "steps": [
            { "service": "iam", "action": "CreateUser", "input": { "UserName": "dns-admin" } },
            { "service": "iam", "action": "PutUserPolicy", "input": {
                "UserName": "dns-admin", "PolicyName": "dns",
                "PolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"route53:ListHostedZones\",\"Resource\":\"*\"}]}"
            } },
            { "id": "key", "service": "iam", "action": "CreateAccessKey", "input": { "UserName": "dns-admin" } },
            { "service": "iam", "action": "GetUser", "accessKeyId": "${key.AccessKey.AccessKeyId}" , "input": {} }
        ]
    });
    // The last step runs as dns-admin, who may not call iam:GetUser.
    let (status, body) = mws.control("POST", "/_mws/scenario", Some(&scenario.to_string())).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["step"], 4);
    assert_eq!(body["code"], "AccessDenied");
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    assert!(user_names(&root).await.is_empty(), "a failed scenario is rolled back");

    let mut ok = scenario.clone();
    ok["steps"].as_array_mut().unwrap().pop();
    let (status, body) = mws.control("POST", "/_mws/scenario", Some(&ok.to_string())).await;
    assert_eq!(status, 200, "{body}");
    let key = &body["outputs"]["key"]["AccessKey"];
    let cfg =
        mws.sdk_config(key["AccessKeyId"].as_str().unwrap(), key["SecretAccessKey"].as_str().unwrap(), None).await;
    aws_sdk_route53::Client::new(&cfg).list_hosted_zones().send().await.unwrap();
    let denied = aws_sdk_iam::Client::new(&cfg).list_users().send().await.unwrap_err();
    assert_eq!(denied.into_service_error().meta().code(), Some("AccessDenied"));
}

#[tokio::test]
async fn scenario_input_is_validated_like_a_request() {
    let mws = Mws::start().await;
    let scenario = json!({ "steps": [
        { "service": "iam", "action": "CreateUser", "input": { "UserName": "ok" } },
        { "service": "iam", "action": "CreateUser", "input": { "UserName": "not valid!" } }
    ]});
    let (status, body) = mws.control("POST", "/_mws/scenario", Some(&scenario.to_string())).await;
    assert_eq!(status, 400);
    assert_eq!(body["step"], 2);
    assert_eq!(body["code"], "ValidationError");
    assert!(body["error"].as_str().unwrap().contains("failed to satisfy constraint"), "{body}");

    let (status, body) = mws
        .control("POST", "/_mws/scenario", Some(r#"{"steps":[{"service":"dynamodb","action":"ListTables"}]}"#))
        .await;
    assert_eq!(status, 400);
    assert!(body["error"].as_str().unwrap().contains("unknown service \"dynamodb\""), "{body}");
}

#[tokio::test]
async fn s3_buckets_and_objects_from_scenarios_survive_export_and_import() {
    let mws = Mws::start().await;
    let scenario = json!({ "steps": [
        { "service": "s3", "action": "CreateBucket", "input": { "Bucket": "seeded" } },
        { "service": "s3", "action": "PutBucketTagging", "input": { "Bucket": "seeded",
            "Tagging": { "TagSet": [{ "Key": "env", "Value": "test" }] } } }
    ]});
    let (status, body) = mws.control("POST", "/_mws/scenario", Some(&scenario.to_string())).await;
    assert_eq!(status, 200, "{body}");
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    s3.put_object()
        .bucket("seeded")
        .key("blob")
        .body(aws_sdk_s3::primitives::ByteStream::from(vec![0u8, 159, 255]))
        .send()
        .await
        .unwrap();

    let (_, state) = mws.control("GET", "/_mws/state", None).await;
    mws.control("POST", "/_mws/reset?to=empty", None).await;
    assert!(s3.list_buckets().send().await.unwrap().buckets().is_empty());
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&state.to_string())).await;
    assert_eq!(status, 200);
    let got = s3.get_object().bucket("seeded").key("blob").send().await.unwrap();
    assert_eq!(got.body.collect().await.unwrap().into_bytes().as_ref(), [0u8, 159, 255]);
    let tags = s3.get_bucket_tagging().bucket("seeded").send().await.unwrap();
    assert_eq!(tags.tag_set()[0].value(), "test");
}

#[tokio::test]
async fn reset_snapshots_and_import() {
    let mws = Mws::start_with(mws::Config { scenario: Some(example_scenario()), ..Default::default() }).await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_user().user_name("extra").send().await.unwrap();

    let (status, _) = mws.control("PUT", "/_mws/snapshots/with-extra", None).await;
    assert_eq!(status, 200);
    let (_, exported) = mws.control("GET", "/_mws/state", None).await;

    // Reset returns to the scenario's baseline.
    mws.control("POST", "/_mws/reset", None).await;
    assert_eq!(user_names(&iam).await, ["deployer"]);

    mws.control("POST", "/_mws/snapshots/with-extra/restore", None).await;
    assert_eq!(user_names(&iam).await, ["deployer", "extra"]);

    mws.control("POST", "/_mws/reset?to=empty", None).await;
    assert!(user_names(&iam).await.is_empty());
    let r53 = aws_sdk_route53::Client::new(&mws.root_sdk_config().await);
    assert!(r53.list_hosted_zones().send().await.unwrap().hosted_zones().is_empty());

    let (status, body) = mws.control("PUT", "/_mws/state", Some(&exported.to_string())).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(user_names(&iam).await, ["deployer", "extra"]);
    assert_eq!(r53.list_hosted_zones().send().await.unwrap().hosted_zones().len(), 1);

    let (_, list) = mws.control("GET", "/_mws/snapshots", None).await;
    assert_eq!(list["snapshots"][0]["name"], "with-extra");
    assert_eq!(mws.control("DELETE", "/_mws/snapshots/with-extra", None).await.0, 200);
    assert_eq!(mws.control("POST", "/_mws/snapshots/with-extra/restore", None).await.0, 404);
    assert_eq!(mws.control("PUT", "/_mws/state", Some(r#"{"services":{}}"#)).await.0, 400);
}

#[tokio::test]
async fn state_survives_a_restart() {
    let db = temp_db("restart");
    let config = mws::Config { db: Some(db.clone()), ..Default::default() };

    let mws = Mws::start_with(config.clone()).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    iam.create_user().user_name("kept").send().await.unwrap();
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("worker").assume_role_policy_document(trust).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();
    let assume =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}"#;
    let (_, runner) = user_with_policy(&mws, "runner", Some(assume)).await;
    let creds = aws_sdk_sts::Client::new(&runner)
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name("before-restart")
        .send()
        .await
        .unwrap()
        .credentials()
        .unwrap()
        .clone();
    let zone = aws_sdk_route53::Client::new(&cfg)
        .create_hosted_zone()
        .name("kept.example")
        .caller_reference("restart-test")
        .send()
        .await
        .unwrap();
    let zone_id = zone.hosted_zone().unwrap().id().to_string();

    // Changes reach the database shortly after they happen, not only at
    // shutdown.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let saved = mws_server::Store::open(&db).unwrap().service_states().unwrap();
    assert!(saved["iam"].contains("\"kept\""), "IAM state was written in the background");
    assert!(saved["route53"].contains("kept.example."));
    mws.stop().await;

    let mws = Mws::start_with(config).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    assert_eq!(user_names(&iam).await, ["kept", "runner"]);
    assert_eq!(iam.get_role().role_name("worker").send().await.unwrap().role().unwrap().arn(), role_arn);
    let r53 = aws_sdk_route53::Client::new(&cfg);
    assert_eq!(r53.get_hosted_zone().id(&zone_id).send().await.unwrap().hosted_zone().unwrap().name(), "kept.example.");

    // Temporary credentials issued before the restart still work.
    let sts = aws_sdk_sts::Client::new(&sts_config(&mws, &creds).await);
    let me = sts.get_caller_identity().send().await.unwrap();
    assert_eq!(me.arn(), Some("arn:aws:sts::123456789012:assumed-role/worker/before-restart"));
    mws.stop().await;
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

#[tokio::test]
async fn changing_the_scenario_replaces_saved_state_but_keeps_a_snapshot() {
    let db = temp_db("scenario-change");
    let mws = Mws::start_with(mws::Config { db: Some(db.clone()), ..Default::default() }).await;
    aws_sdk_iam::Client::new(&mws.root_sdk_config().await).create_user().user_name("old").send().await.unwrap();
    mws.stop().await;

    let mws =
        Mws::start_with(mws::Config { db: Some(db.clone()), scenario: Some(example_scenario()), ..Default::default() })
            .await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    assert_eq!(user_names(&iam).await, ["deployer"]);
    let (_, list) = mws.control("GET", "/_mws/snapshots", None).await;
    let name = list["snapshots"][0]["name"].as_str().unwrap().to_string();
    assert!(name.starts_with("before-scenario-change-"), "{name}");
    mws.control("POST", &format!("/_mws/snapshots/{name}/restore"), None).await;
    assert_eq!(user_names(&iam).await, ["old"]);
    mws.stop().await;
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}
