//! Amazon SES (v1 and v2) through the official Rust SDKs: verification,
//! the sandbox, the outbox, templates, event destinations, receipt rules
//! fed over SMTP, and SMTP submission with SES SMTP credentials.

use std::time::Duration;

use aws_sdk_route53::types::{Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType};
use aws_sdk_ses::types as t1;
use aws_sdk_sesv2::types as t2;
use aws_sdk_sqs::types::QueueAttributeName;
use mws_e2e::Mws;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const ACCOUNT: &str = "123456789012";

fn code<E: aws_sdk_ses::error::ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn auto_verifying() -> Mws {
    Mws::start_with(mws::Config { ses_auto_verify: true, ..mws::Config::default() }).await
}

fn simple(subject: &str, text: &str) -> t1::Message {
    t1::Message::builder()
        .subject(t1::Content::builder().data(subject).build().unwrap())
        .body(t1::Body::builder().text(t1::Content::builder().data(text).build().unwrap()).build())
        .build()
}

fn to(addresses: &[&str]) -> t1::Destination {
    t1::Destination::builder().set_to_addresses(Some(addresses.iter().map(|a| a.to_string()).collect())).build()
}

fn v2_simple(subject: &str, text: &str) -> t2::EmailContent {
    t2::EmailContent::builder()
        .simple(
            t2::Message::builder()
                .subject(t2::Content::builder().data(subject).build().unwrap())
                .body(t2::Body::builder().text(t2::Content::builder().data(text).build().unwrap()).build())
                .build(),
        )
        .build()
}

async fn outbox(mws: &Mws, query: &str) -> Vec<serde_json::Value> {
    let (status, body) = mws.control("GET", &format!("/_aws/ses{query}"), None).await;
    assert_eq!(status, 200);
    body["messages"].as_array().cloned().unwrap_or_default()
}

/// An SQS queue that SNS (and S3) may send to, subscribed raw to `topic`.
async fn queue_for(cfg: &aws_config::SdkConfig, name: &str, topic: &str) -> String {
    let sqs = aws_sdk_sqs::Client::new(cfg);
    let sns = aws_sdk_sns::Client::new(cfg);
    let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url().unwrap().to_string();
    let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:{name}");
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": arn}]
    });
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(topic)
        .protocol("sqs")
        .endpoint(&arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();
    url
}

/// Messages from `url` until `want` have arrived (or a few seconds pass).
async fn drain(cfg: &aws_config::SdkConfig, url: &str, want: usize) -> Vec<serde_json::Value> {
    let sqs = aws_sdk_sqs::Client::new(cfg);
    let mut out = Vec::new();
    for _ in 0..40 {
        let got = sqs.receive_message().queue_url(url).max_number_of_messages(10).send().await.unwrap();
        for m in got.messages() {
            out.push(serde_json::from_str(m.body().unwrap()).unwrap());
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
        if out.len() >= want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    out
}

/// A tiny SMTP client: send `lines` one at a time, return each reply.
struct Smtp {
    read: BufReader<tokio::net::tcp::OwnedReadHalf>,
    write: tokio::net::tcp::OwnedWriteHalf,
}

impl Smtp {
    async fn connect(addr: std::net::SocketAddr) -> (Self, String) {
        let (read, write) = tokio::net::TcpStream::connect(addr).await.unwrap().into_split();
        let mut s = Smtp { read: BufReader::new(read), write };
        let greeting = s.reply().await;
        (s, greeting)
    }

    async fn reply(&mut self) -> String {
        let mut all = String::new();
        loop {
            let mut line = String::new();
            self.read.read_line(&mut line).await.unwrap();
            all.push_str(&line);
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return all.trim_end().to_string();
            }
        }
    }

    async fn cmd(&mut self, line: &str) -> String {
        self.write.write_all(format!("{line}\r\n").as_bytes()).await.unwrap();
        self.reply().await
    }

    async fn data(&mut self, message: &str) -> String {
        assert!(self.cmd("DATA").await.starts_with("354"));
        let body = message.replace("\n.", "\n..");
        self.write.write_all(format!("{body}\r\n.\r\n").as_bytes()).await.unwrap();
        self.reply().await
    }
}

#[tokio::test]
async fn v1_email_verification_sandbox_and_outbox() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_ses::Client::new(&cfg);

    ses.verify_email_identity().email_address("sender@example.com").send().await.unwrap();
    let attrs = ses.get_identity_verification_attributes().identities("sender@example.com").send().await.unwrap();
    assert_eq!(attrs.verification_attributes()["sender@example.com"].verification_status().as_str(), "Pending");

    // The verification mail sits in the outbox; following its link verifies.
    let mails = outbox(&mws, "?to=sender@example.com").await;
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert_eq!(mails[0]["Kind"], "VerificationEmail");
    let link = mails[0]["VerificationLink"].as_str().unwrap().to_string();
    let (status, _, _) = mws.raw("GET", &link, &[], b"").await;
    assert_eq!(status, 200);
    let attrs = ses.get_identity_verification_attributes().identities("sender@example.com").send().await.unwrap();
    assert_eq!(attrs.verification_attributes()["sender@example.com"].verification_status().as_str(), "Success");

    // Sandbox: unverified recipients are refused, the simulator is not.
    let err = ses
        .send_email()
        .source("sender@example.com")
        .destination(to(&["someone@elsewhere.com"]))
        .message(simple("hi", "hello"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "MessageRejected");
    assert!(err.to_string().contains("Email address is not verified"), "{err}");
    let err = ses
        .send_email()
        .source("nobody@example.com")
        .destination(to(&["success@simulator.amazonses.com"]))
        .message(simple("hi", "hello"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "MessageRejected");

    let sent = ses
        .send_email()
        .source("Sender <sender@example.com>")
        .destination(to(&["success@simulator.amazonses.com"]))
        .message(simple("Quarterly report", "All good."))
        .tags(t1::MessageTag::builder().name("campaign").value("q3").build().unwrap())
        .send()
        .await
        .unwrap();
    let mails = outbox(&mws, &format!("?id={}", sent.message_id())).await;
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0]["Subject"], "Quarterly report");
    assert_eq!(mails[0]["Body"]["text_part"], "All good.");
    assert_eq!(mails[0]["Destination"]["ToAddresses"][0], "success@simulator.amazonses.com");
    assert!(mails[0]["RawData"].as_str().unwrap().contains("Subject: Quarterly report"));

    let raw = "From: sender@example.com\r\nTo: success@simulator.amazonses.com\r\nSubject: Raw one\r\n\r\nraw body\r\n";
    ses.send_raw_email()
        .raw_message(t1::RawMessage::builder().data(aws_sdk_ses::primitives::Blob::new(raw)).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(outbox(&mws, "?email=sender@example.com").await.len(), 2);

    let quota = ses.get_send_quota().send().await.unwrap();
    assert_eq!(quota.max24_hour_send(), 200.0);
    assert_eq!(quota.max_send_rate(), 1.0);
    assert_eq!(quota.sent_last24_hours(), 2.0);
    let stats = ses.get_send_statistics().send().await.unwrap();
    assert_eq!(stats.send_data_points().iter().map(|p| p.delivery_attempts()).sum::<i64>(), 2);

    let ids = ses.list_identities().send().await.unwrap();
    assert_eq!(ids.identities(), ["sender@example.com"]);
    ses.delete_identity().identity("sender@example.com").send().await.unwrap();
    assert!(ses.list_identities().send().await.unwrap().identities().is_empty());

    // The outbox can be cleared.
    let (status, _) = mws.control("DELETE", "/_aws/ses", None).await;
    assert_eq!(status, 204);
    assert!(outbox(&mws, "").await.is_empty());
}

#[tokio::test]
async fn v2_domain_verifies_through_route53_dkim_records_and_templates_render() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);
    let r53 = aws_sdk_route53::Client::new(&cfg);

    let created = ses.create_email_identity().email_identity("example.org").send().await.unwrap();
    assert_eq!(created.identity_type().unwrap().as_str(), "DOMAIN");
    assert!(!created.verified_for_sending_status());
    let tokens: Vec<String> = created.dkim_attributes().unwrap().tokens().to_vec();
    assert_eq!(tokens.len(), 3);

    let err = ses
        .send_email()
        .from_email_address("noreply@example.org")
        .destination(t2::Destination::builder().to_addresses("success@simulator.amazonses.com").build())
        .content(v2_simple("x", "y"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::code(&err), Some("MessageRejected"));

    // Publish the DKIM CNAMEs in a public hosted zone: SES sees them.
    let zone = r53.create_hosted_zone().name("example.org").caller_reference("ses").send().await.unwrap();
    let zone_id = zone.hosted_zone().unwrap().id().to_string();
    let mut batch = ChangeBatch::builder();
    for t in &tokens {
        batch = batch.changes(
            Change::builder()
                .action(ChangeAction::Upsert)
                .resource_record_set(
                    ResourceRecordSet::builder()
                        .name(format!("{t}._domainkey.example.org"))
                        .r#type(RrType::Cname)
                        .ttl(300)
                        .resource_records(
                            ResourceRecord::builder().value(format!("{t}.dkim.amazonses.com")).build().unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        );
    }
    r53.change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(batch.build().unwrap())
        .send()
        .await
        .unwrap();
    let got = ses.get_email_identity().email_identity("example.org").send().await.unwrap();
    assert!(got.verified_for_sending_status());
    assert_eq!(got.dkim_attributes().unwrap().status().unwrap().as_str(), "SUCCESS");

    // v1 sees the same identity.
    let v1 = aws_sdk_ses::Client::new(&cfg);
    let dkim = v1.get_identity_dkim_attributes().identities("example.org").send().await.unwrap();
    assert_eq!(dkim.dkim_attributes()["example.org"].dkim_verification_status().as_str(), "Success");

    ses.create_email_template()
        .template_name("welcome")
        .template_content(
            t2::EmailTemplateContent::builder()
                .subject("Welcome, {{name}}!")
                .text("Hi {{name}},{{#if vip}} you are a VIP.{{/if}}")
                .html("<p>Hi {{name}}</p>")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let rendered = ses
        .test_render_email_template()
        .template_name("welcome")
        .template_data(r#"{"name":"Ada","vip":true}"#)
        .send()
        .await
        .unwrap();
    assert!(rendered.rendered_template().contains("Subject: Welcome, Ada!"), "{}", rendered.rendered_template());

    let sent = ses
        .send_email()
        .from_email_address("noreply@example.org")
        .destination(t2::Destination::builder().to_addresses("success@simulator.amazonses.com").build())
        .content(
            t2::EmailContent::builder()
                .template(
                    t2::Template::builder()
                        .template_name("welcome")
                        .template_data(r#"{"name":"Grace","vip":false}"#)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let mails = outbox(&mws, &format!("?id={}", sent.message_id().unwrap())).await;
    assert_eq!(mails[0]["Subject"], "Welcome, Grace!");
    assert_eq!(mails[0]["Body"]["text_part"], "Hi Grace,");

    // A missing attribute is a rendering failure, refused up front.
    let err = ses
        .test_render_email_template()
        .template_name("welcome")
        .template_data("{}")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::code(&err), Some("BadRequestException"));

    let err = ses.get_email_identity().email_identity("missing.org").send().await.unwrap_err().into_service_error();
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::code(&err), Some("NotFoundException"));
}

#[tokio::test]
async fn configuration_set_events_reach_sns_and_the_mailbox_simulator_bounces() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);
    let topic = sns.create_topic().name("ses-events").send().await.unwrap().topic_arn().unwrap().to_string();
    let queue = queue_for(&cfg, "ses-events", &topic).await;

    ses.create_email_identity().email_identity("app.test").send().await.unwrap();
    ses.create_configuration_set().configuration_set_name("tracked").send().await.unwrap();
    ses.create_configuration_set_event_destination()
        .configuration_set_name("tracked")
        .event_destination_name("to-sns")
        .event_destination(
            t2::EventDestinationDefinition::builder()
                .enabled(true)
                .matching_event_types(t2::EventType::Send)
                .matching_event_types(t2::EventType::Delivery)
                .matching_event_types(t2::EventType::Bounce)
                .sns_destination(t2::SnsDestination::builder().topic_arn(&topic).build().unwrap())
                .build(),
        )
        .send()
        .await
        .unwrap();

    let send = |rcpt: &'static str| {
        ses.send_email()
            .from_email_address("alerts@app.test")
            .destination(t2::Destination::builder().to_addresses(rcpt).build())
            .content(v2_simple("event test", "body"))
            .configuration_set_name("tracked")
            .email_tags(t2::MessageTag::builder().name("flow").value("signup").build().unwrap())
            .send()
    };
    let ok = send("success@simulator.amazonses.com").await.unwrap();
    let bounced = send("bounce@simulator.amazonses.com").await.unwrap();

    let events = drain(&cfg, &queue, 4).await;
    let mut kinds: Vec<(String, String)> = events
        .iter()
        .map(|e| (e["eventType"].as_str().unwrap().to_string(), e["mail"]["messageId"].as_str().unwrap().to_string()))
        .collect();
    kinds.sort();
    let ok_id = ok.message_id().unwrap().to_string();
    let bounce_id = bounced.message_id().unwrap().to_string();
    let mut want = vec![
        ("Bounce".to_string(), bounce_id.clone()),
        ("Delivery".to_string(), ok_id.clone()),
        ("Send".to_string(), bounce_id.clone()),
        ("Send".to_string(), ok_id.clone()),
    ];
    want.sort();
    assert_eq!(kinds, want, "{events:#?}");
    let bounce = events.iter().find(|e| e["eventType"] == "Bounce").unwrap();
    assert_eq!(bounce["bounce"]["bounceType"], "Permanent");
    assert_eq!(bounce["bounce"]["bouncedRecipients"][0]["emailAddress"], "bounce@simulator.amazonses.com");
    assert_eq!(bounce["mail"]["tags"]["flow"][0], "signup");
    assert_eq!(bounce["mail"]["tags"]["ses:configuration-set"][0], "tracked");

    // As in SES, simulator bounces do not reach the suppression list.
    let err = ses
        .get_suppressed_destination()
        .email_address("bounce@simulator.amazonses.com")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::code(&err), Some("NotFoundException"));

    let cs = ses.get_configuration_set().configuration_set_name("tracked").send().await.unwrap();
    assert_eq!(cs.configuration_set_name(), Some("tracked"));
    let dests = ses.get_configuration_set_event_destinations().configuration_set_name("tracked").send().await.unwrap();
    assert_eq!(dests.event_destinations().len(), 1);
}

#[tokio::test]
async fn receipt_rules_deliver_smtp_mail_to_s3_and_sns() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_ses::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);

    s3.create_bucket().bucket("inbound-mail").send().await.unwrap();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::inbound-mail/*",
            "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}}
        }]
    });
    let topic = sns.create_topic().name("inbound").send().await.unwrap().topic_arn().unwrap().to_string();
    let queue = queue_for(&cfg, "inbound", &topic).await;
    ses.verify_domain_identity().domain("inbound.test").send().await.unwrap();
    ses.create_receipt_rule_set().rule_set_name("main").send().await.unwrap();

    let s3_action = |bucket: &str| {
        t1::ReceiptAction::builder()
            .s3_action(t1::S3Action::builder().bucket_name(bucket).object_key_prefix("mail/").build().unwrap())
            .build()
    };
    let rule = t1::ReceiptRule::builder()
        .name("store")
        .enabled(true)
        .recipients("inbound.test")
        .actions(
            t1::ReceiptAction::builder()
                .add_header_action(
                    t1::AddHeaderAction::builder().header_name("X-Routed").header_value("yes").build().unwrap(),
                )
                .build(),
        )
        .actions(s3_action("inbound-mail"))
        .actions(
            t1::ReceiptAction::builder()
                .sns_action(
                    t1::SnsAction::builder().topic_arn(&topic).encoding(t1::SnsActionEncoding::Utf8).build().unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap();
    // Without the bucket policy SES may not write there.
    let err = ses
        .create_receipt_rule()
        .rule_set_name("main")
        .rule(rule.clone())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidS3Configuration");
    s3.put_bucket_policy().bucket("inbound-mail").policy(policy.to_string()).send().await.unwrap();
    ses.create_receipt_rule().rule_set_name("main").rule(rule).send().await.unwrap();
    let err = ses.create_receipt_rule_set().rule_set_name("main").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "AlreadyExists");
    let err = ses
        .describe_receipt_rule()
        .rule_set_name("main")
        .rule_name("nope")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "RuleDoesNotExist");

    let smtp = mws.start_smtp().await;
    // No active rule set yet: nobody is hosted here.
    let (mut c, greeting) = Smtp::connect(smtp).await;
    assert!(greeting.starts_with("220 "), "{greeting}");
    assert!(c.cmd("EHLO client.test").await.contains("AUTH PLAIN LOGIN"));
    assert!(c.cmd("MAIL FROM:<alice@sender.test>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@inbound.test>").await.starts_with("550"));
    c.cmd("QUIT").await;

    ses.set_active_receipt_rule_set().rule_set_name("main").send().await.unwrap();
    let active = ses.describe_active_receipt_rule_set().send().await.unwrap();
    assert_eq!(active.metadata().unwrap().name(), Some("main"));
    assert_eq!(active.rules()[0].name(), "store");
    let err = ses.delete_receipt_rule_set().rule_set_name("main").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "CannotDelete");

    let (mut c, _) = Smtp::connect(smtp).await;
    c.cmd("EHLO client.test").await;
    assert!(c.cmd("MAIL FROM:<alice@sender.test>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@inbound.test>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<carol@elsewhere.test>").await.starts_with("550"));
    let reply = c
        .data("From: Alice <alice@sender.test>\r\nTo: bob@inbound.test\r\nSubject: Invoice 42\r\n\r\nPlease pay.\r\n.dot line\r\n")
        .await;
    assert!(reply.starts_with("250 Ok "), "{reply}");
    let message_id = reply.trim_start_matches("250 Ok ").to_string();
    c.cmd("QUIT").await;

    let stored = s3.get_object().bucket("inbound-mail").key(format!("mail/{message_id}")).send().await.unwrap();
    let body = String::from_utf8(stored.body.collect().await.unwrap().to_vec()).unwrap();
    assert!(body.contains("X-Routed: yes"), "{body}");
    assert!(body.contains("Subject: Invoice 42"));
    assert!(body.contains("\r\n.dot line\r\n"), "dot-stuffing undone: {body}");

    let notes = drain(&cfg, &queue, 1).await;
    assert_eq!(notes.len(), 1);
    let n = &notes[0];
    assert_eq!(n["notificationType"], "Received");
    assert_eq!(n["mail"]["messageId"], message_id.as_str());
    assert_eq!(n["mail"]["source"], "alice@sender.test");
    assert_eq!(n["mail"]["commonHeaders"]["subject"], "Invoice 42");
    assert_eq!(n["receipt"]["recipients"][0], "bob@inbound.test");
    assert_eq!(n["receipt"]["action"]["type"], "SNS");
    assert!(n["content"].as_str().unwrap().contains("Please pay."));

    let (status, received) = mws.control("GET", "/_aws/ses/inbound", None).await;
    assert_eq!(status, 200);
    assert_eq!(received["messages"][0]["MatchedRules"][0], "store");

    // An IP filter blocking the sender refuses the message.
    ses.create_receipt_filter()
        .filter(
            t1::ReceiptFilter::builder()
                .name("block-local")
                .ip_filter(
                    t1::ReceiptIpFilter::builder()
                        .policy(t1::ReceiptFilterPolicy::Block)
                        .cidr("127.0.0.0/8")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(ses.list_receipt_filters().send().await.unwrap().filters().len(), 1);
    let (status, refused) =
        mws.control("POST", "/_aws/ses/inbound?from=a@b.test&to=bob@inbound.test", Some("Subject: x\r\n\r\ny")).await;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["smtpCode"], 554);
    ses.delete_receipt_filter().filter_name("block-local").send().await.unwrap();

    // Mail sent through SES to a hosted address is received too.
    let sent = ses
        .send_email()
        .source("noreply@inbound.test")
        .destination(to(&["bob@inbound.test"]))
        .message(simple("Loopback", "via SES"))
        .send()
        .await
        .unwrap();
    let notes = drain(&cfg, &queue, 1).await;
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0]["mail"]["commonHeaders"]["subject"], "Loopback");
    assert_ne!(notes[0]["mail"]["messageId"], sent.message_id());
}

#[tokio::test]
async fn smtp_submission_uses_ses_smtp_credentials_and_iam() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_ses::Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    ses.verify_email_identity().email_address("app@mailer.test").send().await.unwrap();

    let mut keys = Vec::new();
    for (user, policy) in [
        (
            "smtp-ok",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendRawEmail","Resource":"*"}]}"#,
        ),
        (
            "smtp-denied",
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ses:SendEmail","Resource":"*"}]}"#,
        ),
    ] {
        iam.create_user().user_name(user).send().await.unwrap();
        iam.put_user_policy().user_name(user).policy_name("ses").policy_document(policy).send().await.unwrap();
        let key = iam.create_access_key().user_name(user).send().await.unwrap();
        let key = key.access_key().unwrap();
        keys.push((key.access_key_id().to_string(), key.secret_access_key().to_string()));
    }
    let smtp = mws.start_smtp().await;
    let login = |akid: &str, secret: &str| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .encode(format!("\0{akid}\0{}", mws_ses::smtp_password(secret, "us-east-1")))
    };

    // A wrong password (derived for another key) is refused.
    let (mut c, _) = Smtp::connect(smtp).await;
    c.cmd("EHLO me").await;
    let bad = login(&keys[0].0, &keys[1].1);
    assert!(c.cmd(&format!("AUTH PLAIN {bad}")).await.starts_with("535"));

    let ok = login(&keys[0].0, &keys[0].1);
    assert!(c.cmd(&format!("AUTH PLAIN {ok}")).await.starts_with("235"));
    c.cmd("MAIL FROM:<app@mailer.test>").await;
    assert!(c.cmd("RCPT TO:<success@simulator.amazonses.com>").await.starts_with("250"));
    let reply = c
        .data("From: app@mailer.test\r\nTo: success@simulator.amazonses.com\r\nSubject: Over SMTP\r\nX-SES-CONFIGURATION-SET: none\r\n\r\nhello\r\n")
        .await;
    // The named configuration set does not exist.
    assert!(reply.starts_with("554"), "{reply}");
    c.cmd("MAIL FROM:<app@mailer.test>").await;
    c.cmd("RCPT TO:<success@simulator.amazonses.com>").await;
    let reply = c
        .data("From: app@mailer.test\r\nTo: success@simulator.amazonses.com\r\nSubject: Over SMTP\r\n\r\nhello\r\n")
        .await;
    assert!(reply.starts_with("250 Ok "), "{reply}");
    let id = reply.trim_start_matches("250 Ok ");
    let mails = outbox(&mws, &format!("?id={id}")).await;
    assert_eq!(mails[0]["Subject"], "Over SMTP");
    c.cmd("QUIT").await;

    // IAM still decides: this user may not SendRawEmail.
    let (mut c, _) = Smtp::connect(smtp).await;
    c.cmd("EHLO me").await;
    assert!(c.cmd(&format!("AUTH PLAIN {}", login(&keys[1].0, &keys[1].1))).await.starts_with("235"));
    c.cmd("MAIL FROM:<app@mailer.test>").await;
    c.cmd("RCPT TO:<success@simulator.amazonses.com>").await;
    let reply =
        c.data("From: app@mailer.test\r\nTo: success@simulator.amazonses.com\r\nSubject: no\r\n\r\nno\r\n").await;
    assert!(reply.starts_with("554") && reply.contains("not authorized"), "{reply}");
}
