//! GuardDuty threat detection through the official Rust SDKs: enabling a
//! detector creates its service-linked role (and needs
//! `iam:CreateServiceLinkedRole`), suspicious management API calls that
//! CloudTrail records become findings, threat lists are read from S3
//! (`ACTIVATING`, then `ACTIVE` or `ERROR`) and matched against callers'
//! source addresses, and findings reach EventBridge five minutes after
//! they are first seen and their updates on the detector's publishing
//! frequency, on the emulated clock.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use aws_sdk_guardduty::error::ProvideErrorMetadata;
use aws_sdk_guardduty::types::{FindingPublishingFrequency, IpSetFormat, ThreatIntelSetFormat};
use aws_sdk_guardduty::Client;
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::{user_with_policy, Mws};
use serde_json::{json, Value};

const ACCOUNT: &str = "123456789012";
const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn advance(mws: &Mws, seconds: i64) {
    let (status, body) =
        mws.control("POST", "/_mws/clock", Some(&json!({ "advanceSeconds": seconds }).to_string())).await;
    assert_eq!(status, 200, "{body}");
}

/// `aws.guardduty` events from the default bus, delivered to SQS.
struct Inbox {
    sqs: aws_sdk_sqs::Client,
    url: String,
}

impl Inbox {
    async fn new(cfg: &aws_config::SdkConfig, name: &str) -> Self {
        let eb = aws_sdk_eventbridge::Client::new(cfg);
        let sqs = aws_sdk_sqs::Client::new(cfg);
        let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url.unwrap();
        let attrs = sqs
            .get_queue_attributes()
            .queue_url(&url)
            .attribute_names(QueueAttributeName::QueueArn)
            .send()
            .await
            .unwrap();
        let arn = attrs.attributes().unwrap()[&QueueAttributeName::QueueArn].clone();
        let policy = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":arn}]});
        sqs.set_queue_attributes()
            .queue_url(&url)
            .attributes(QueueAttributeName::Policy, policy.to_string())
            .send()
            .await
            .unwrap();
        eb.put_rule().name(name).event_pattern(r#"{"source":["aws.guardduty"]}"#).send().await.unwrap();
        eb.put_targets()
            .rule(name)
            .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&arn).build().unwrap())
            .send()
            .await
            .unwrap();
        Inbox { sqs, url }
    }

    /// Every event that arrives within `wait`.
    async fn drain(&self, wait: Duration) -> Vec<Value> {
        let deadline = Instant::now() + wait;
        let mut out = Vec::new();
        while Instant::now() < deadline {
            let r = self.sqs.receive_message().queue_url(&self.url).max_number_of_messages(10).send().await.unwrap();
            if r.messages().is_empty() {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            for m in r.messages() {
                self.sqs
                    .delete_message()
                    .queue_url(&self.url)
                    .receipt_handle(m.receipt_handle().unwrap())
                    .send()
                    .await
                    .unwrap();
                out.push(serde_json::from_str(m.body().unwrap()).unwrap());
            }
        }
        out
    }
}

/// The detector's findings by type.
async fn findings(gd: &Client, detector: &str) -> BTreeMap<String, aws_sdk_guardduty::types::Finding> {
    let ids = gd.list_findings().detector_id(detector).max_results(50).send().await.unwrap().finding_ids().to_vec();
    if ids.is_empty() {
        return BTreeMap::new();
    }
    let got = gd.get_findings().detector_id(detector).set_finding_ids(Some(ids)).send().await.unwrap();
    got.findings().iter().map(|f| (f.r#type().unwrap().to_string(), f.clone())).collect()
}

#[tokio::test]
async fn enabling_creates_the_service_linked_role() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&root);
    let only_gd = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"guardduty:*","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "gd-only", Some(only_gd)).await;
    let denied = Client::new(&cfg).create_detector().enable(true).send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    assert!(denied.message().unwrap_or_default().contains("iam:CreateServiceLinkedRole"), "{denied:?}");
    let roles = iam.list_roles().path_prefix("/aws-service-role/").send().await.unwrap();
    assert!(roles.roles().iter().all(|r| r.role_name() != "AWSServiceRoleForAmazonGuardDuty"));

    let gd = Client::new(&root);
    let id = gd.create_detector().enable(true).send().await.unwrap().detector_id().unwrap().to_string();
    let roles = iam.list_roles().path_prefix("/aws-service-role/").send().await.unwrap();
    let role = roles.roles().iter().find(|r| r.role_name() == "AWSServiceRoleForAmazonGuardDuty").unwrap();
    assert_eq!(role.path(), "/aws-service-role/guardduty.amazonaws.com/");
    let detector = gd.get_detector().detector_id(&id).send().await.unwrap();
    assert_eq!(detector.service_role(), Some(role.arn()));

    // Lists need iam:PutRolePolicy (and iam:DeleteRolePolicy) on that role.
    let list = Client::new(&cfg)
        .create_ip_set()
        .detector_id(&id)
        .name("office")
        .format(IpSetFormat::Txt)
        .location("s3://lists/office.txt")
        .activate(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&list), "AccessDeniedException");
    assert!(list.message().unwrap_or_default().contains("iam:PutRolePolicy"), "{list:?}");
    let with_role = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"guardduty:*","Resource":"*"},
        {"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":role.arn()}]});
    let (_, cfg) = user_with_policy(&mws, "gd-lists", Some(&with_role.to_string())).await;
    let lists = Client::new(&cfg);
    let ip = lists
        .create_ip_set()
        .detector_id(&id)
        .name("office")
        .format(IpSetFormat::Txt)
        .location("s3://lists/office.txt")
        .activate(true)
        .send()
        .await
        .unwrap()
        .ip_set_id()
        .unwrap()
        .to_string();
    let delete = lists.delete_ip_set().detector_id(&id).ip_set_id(&ip).send().await.unwrap_err();
    assert_eq!(code(&delete), "AccessDeniedException");
    gd.delete_ip_set().detector_id(&id).ip_set_id(&ip).send().await.unwrap();
}

#[tokio::test]
async fn suspicious_api_calls_become_findings() {
    use aws_sdk_s3::types::{BucketLoggingStatus, PublicAccessBlockConfiguration};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let gd = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let control = aws_sdk_s3control::Client::new(&cfg);
    // Set up before GuardDuty is on: nothing here raises findings.
    let inbox = Inbox::new(&cfg, "gd-detect").await;
    s3.create_bucket().bucket("gd-trail").send().await.unwrap();
    let trail_policy = json!({"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl",
         "Resource":"arn:aws:s3:::gd-trail"},
        {"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject",
         "Resource":format!("arn:aws:s3:::gd-trail/AWSLogs/{ACCOUNT}/*"),
         "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}]});
    s3.put_bucket_policy().bucket("gd-trail").policy(trail_policy.to_string()).send().await.unwrap();
    ct.create_trail().name("audit").s3_bucket_name("gd-trail").send().await.unwrap();
    ct.start_logging().name("audit").send().await.unwrap();
    iam.update_account_password_policy().minimum_password_length(14).require_symbols(true).send().await.unwrap();

    let id = gd
        .create_detector()
        .enable(true)
        .finding_publishing_frequency(FindingPublishingFrequency::FifteenMinutes)
        .send()
        .await
        .unwrap()
        .detector_id()
        .unwrap()
        .to_string();
    assert!(findings(&gd, &id).await.is_empty(), "GuardDuty's own calls raise no findings");

    // Suspicious calls, all with root credentials.
    s3.create_bucket().bucket("gd-open").send().await.unwrap();
    let off = PublicAccessBlockConfiguration::builder()
        .block_public_acls(false)
        .ignore_public_acls(false)
        .block_public_policy(false)
        .restrict_public_buckets(false)
        .build();
    s3.put_public_access_block().bucket("gd-open").public_access_block_configuration(off).send().await.unwrap();
    control
        .put_public_access_block()
        .account_id(ACCOUNT)
        .public_access_block_configuration(
            aws_sdk_s3control::types::PublicAccessBlockConfiguration::builder()
                .block_public_acls(false)
                .ignore_public_acls(false)
                .block_public_policy(false)
                .restrict_public_buckets(false)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let public = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
        "Action":"s3:GetObject","Resource":"arn:aws:s3:::gd-open/*"}]});
    s3.put_bucket_policy().bucket("gd-open").policy(public.to_string()).send().await.unwrap();
    s3.put_bucket_logging()
        .bucket("gd-open")
        .bucket_logging_status(BucketLoggingStatus::builder().build())
        .send()
        .await
        .unwrap();
    ct.stop_logging().name("audit").send().await.unwrap();
    iam.update_account_password_policy().minimum_password_length(8).send().await.unwrap();

    let found = findings(&gd, &id).await;
    let mut types: Vec<&str> = found.keys().map(String::as_str).collect();
    types.sort();
    assert_eq!(
        types,
        [
            "Policy:IAMUser/RootCredentialUsage",
            "Policy:S3/AccountBlockPublicAccessDisabled",
            "Policy:S3/BucketAnonymousAccessGranted",
            "Policy:S3/BucketBlockPublicAccessDisabled",
            "Stealth:IAMUser/CloudTrailLoggingDisabled",
            "Stealth:IAMUser/PasswordPolicyChange",
            "Stealth:S3/ServerAccessLoggingDisabled",
        ]
    );
    let root = &found["Policy:IAMUser/RootCredentialUsage"];
    let key = root.resource().unwrap().access_key_details().unwrap();
    assert_eq!((key.user_type(), key.user_name(), key.principal_id()), (Some("Root"), Some("Root"), Some(ACCOUNT)));
    assert_eq!(root.resource().unwrap().resource_type(), Some("AccessKey"));
    assert_eq!(root.severity(), Some(2.0));
    let svc = root.service().unwrap();
    assert!(svc.count().unwrap() >= 7, "{svc:?}");
    assert_eq!(svc.feature_name(), Some("CloudTrail"));
    let call = svc.action().unwrap().aws_api_call_action().unwrap();
    assert_eq!(svc.action().unwrap().action_type(), Some("AWS_API_CALL"));
    assert_eq!(call.caller_type(), Some("Remote IP"));
    assert_eq!(call.remote_ip_details().unwrap().ip_address_v4(), Some("127.0.0.1"));
    assert_eq!(root.title(), Some(format!("API {} was invoked using root credentials.", call.api().unwrap()).as_str()));
    assert!(svc.event_first_seen().unwrap() <= svc.event_last_seen().unwrap());

    let trail = &found["Stealth:IAMUser/CloudTrailLoggingDisabled"];
    let call = trail.service().unwrap().action().unwrap().aws_api_call_action().unwrap();
    assert_eq!((call.api(), call.service_name()), (Some("StopLogging"), Some("cloudtrail.amazonaws.com")));
    assert_eq!(
        call.affected_resources().unwrap()["AWS::CloudTrail::Trail"],
        format!("arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/audit")
    );
    let open = &found["Policy:S3/BucketAnonymousAccessGranted"];
    assert_eq!(open.severity(), Some(8.0));
    assert_eq!(open.resource().unwrap().resource_type(), Some("S3Bucket"));
    let bucket = &open.resource().unwrap().s3_bucket_details()[0];
    assert_eq!((bucket.name(), bucket.arn()), (Some("gd-open"), Some("arn:aws:s3:::gd-open")));
    assert_eq!(bucket.public_access().unwrap().effective_permission(), Some("PUBLIC"));
    let bpa = &found["Policy:S3/BucketBlockPublicAccessDisabled"];
    assert_eq!(bpa.title(), Some("Amazon S3 Block Public Access was disabled for S3 bucket gd-open."));

    // New findings reach EventBridge within five minutes, not at once.
    assert!(inbox.drain(Duration::from_secs(2)).await.is_empty());
    advance(&mws, 301).await;
    let mut events = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while events.len() < 7 && Instant::now() < deadline {
        events.extend(inbox.drain(Duration::from_secs(1)).await);
    }
    let mut sent: Vec<String> = events.iter().map(|e| e["detail"]["type"].as_str().unwrap().to_string()).collect();
    sent.sort();
    assert_eq!(sent, types, "{events:?}");
    assert!(events.iter().all(|e| e["detail-type"] == "GuardDuty Finding" && e["source"] == "aws.guardduty"));

    // A repeat updates the finding at once, and the update is published on
    // the detector's frequency (fifteen minutes here).
    let before = findings(&gd, &id).await["Stealth:IAMUser/CloudTrailLoggingDisabled"].service().unwrap().count();
    ct.start_logging().name("audit").send().await.unwrap();
    ct.stop_logging().name("audit").send().await.unwrap();
    let after = findings(&gd, &id).await;
    let trail = &after["Stealth:IAMUser/CloudTrailLoggingDisabled"];
    assert_eq!(trail.service().unwrap().count(), before.map(|c| c + 1));
    assert!(inbox.drain(Duration::from_secs(2)).await.is_empty());
    advance(&mws, 15 * 60).await;
    let mut updates = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while updates.len() < 2 && Instant::now() < deadline {
        updates.extend(inbox.drain(Duration::from_secs(1)).await);
    }
    let update = updates
        .iter()
        .find(|e| e["detail"]["type"] == "Stealth:IAMUser/CloudTrailLoggingDisabled")
        .unwrap_or_else(|| panic!("{updates:?}"));
    assert_eq!(update["detail"]["service"]["count"], json!(before.unwrap() + 1));
    assert!(updates.iter().any(|e| e["detail"]["type"] == "Policy:IAMUser/RootCredentialUsage"));
}

#[tokio::test]
async fn threat_lists_are_read_from_s3_and_matched() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let gd = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("gd-lists").send().await.unwrap();
    for (key, body) in [("bad.txt", "# known bad\n127.0.0.0/8\n"), ("junk.txt", "this is not an address\n")] {
        s3.put_object().bucket("gd-lists").key(key).body(body.as_bytes().to_vec().into()).send().await.unwrap();
    }
    let (_, user_cfg) = user_with_policy(&mws, "ops", Some(ADMIN)).await;
    let user_s3 = Mws::s3(&user_cfg);
    let id = gd.create_detector().enable(true).send().await.unwrap().detector_id().unwrap().to_string();

    let create = |name: &'static str, location: &'static str| {
        let gd = gd.clone();
        let id = id.clone();
        async move {
            gd.create_threat_intel_set()
                .detector_id(id)
                .name(name)
                .format(ThreatIntelSetFormat::Txt)
                .location(location)
                .activate(true)
                .send()
                .await
                .unwrap()
                .threat_intel_set_id()
                .unwrap()
                .to_string()
        }
    };
    let bad = create("known-bad", "s3://gd-lists/bad.txt").await;
    let missing = create("missing", "https://gd-lists.s3.amazonaws.com/nope.txt").await;
    let junk = create("junk", "s3://gd-lists/junk.txt").await;
    let status = |list: String| {
        let gd = gd.clone();
        let id = id.clone();
        async move {
            let got = gd.get_threat_intel_set().detector_id(id).threat_intel_set_id(list).send().await.unwrap();
            got.status().unwrap().as_str().to_string()
        }
    };
    assert_eq!(status(bad.clone()).await, "ACTIVATING");
    // Calls from a listed address before the list is active are not matched.
    user_s3.list_buckets().send().await.unwrap();
    assert!(findings(&gd, &id).await.is_empty());

    advance(&mws, 10).await;
    assert_eq!(status(bad.clone()).await, "ACTIVE");
    assert_eq!(status(missing.clone()).await, "ERROR");
    assert_eq!(status(junk.clone()).await, "ERROR");

    // The SDK calls from 127.0.0.1, which is on the list.
    user_s3.list_buckets().send().await.unwrap();
    user_s3.create_bucket().bucket("from-bad-ip").send().await.unwrap();
    let found = findings(&gd, &id).await;
    let mut types: Vec<&str> = found.keys().map(String::as_str).collect();
    types.sort();
    assert_eq!(
        types,
        ["Recon:IAMUser/MaliciousIPCaller.Custom", "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"]
    );
    let recon = &found["Recon:IAMUser/MaliciousIPCaller.Custom"];
    let key = recon.resource().unwrap().access_key_details().unwrap();
    assert_eq!((key.user_type(), key.user_name()), (Some("IAMUser"), Some("ops")));
    assert_eq!(recon.severity(), Some(5.0));
    let svc = recon.service().unwrap();
    let call = svc.action().unwrap().aws_api_call_action().unwrap();
    assert_eq!((call.api(), call.service_name()), (Some("ListBuckets"), Some("s3.amazonaws.com")));
    let intel = &svc.evidence().unwrap().threat_intelligence_details()[0];
    assert_eq!(intel.threat_list_name(), Some("known-bad"));
    let info: Value = serde_json::from_str(svc.additional_info().unwrap().value().unwrap()).unwrap();
    assert_eq!(info["threatListName"], "known-bad");
    let write = &found["UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"];
    assert_eq!(write.service().unwrap().action().unwrap().aws_api_call_action().unwrap().api(), Some("CreateBucket"));

    // Fixing the file and updating the list reads it again.
    s3.put_object().bucket("gd-lists").key("nope.txt").body(b"203.0.113.0/24\n".to_vec().into()).send().await.unwrap();
    gd.update_threat_intel_set().detector_id(&id).threat_intel_set_id(&missing).activate(true).send().await.unwrap();
    assert_eq!(status(missing.clone()).await, "ACTIVATING");
    advance(&mws, 10).await;
    assert_eq!(status(missing.clone()).await, "ACTIVE");

    // Addresses on a trusted IP list raise no findings.
    s3.put_object().bucket("gd-lists").key("trusted.txt").body(b"127.0.0.1\n".to_vec().into()).send().await.unwrap();
    gd.create_ip_set()
        .detector_id(&id)
        .name("office")
        .format(IpSetFormat::Txt)
        .location("s3://gd-lists/trusted.txt")
        .activate(true)
        .send()
        .await
        .unwrap();
    advance(&mws, 10).await;
    let before = findings(&gd, &id).await["Recon:IAMUser/MaliciousIPCaller.Custom"].service().unwrap().count();
    user_s3.list_buckets().send().await.unwrap();
    let after = findings(&gd, &id).await;
    assert_eq!(after["Recon:IAMUser/MaliciousIPCaller.Custom"].service().unwrap().count(), before);
    assert_eq!(after.len(), 2);
}
