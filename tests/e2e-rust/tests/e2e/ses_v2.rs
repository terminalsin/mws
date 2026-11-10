//! Every SES v2 operation through the official Rust SDK: identities and
//! their attributes, templates, configuration set options, the account and
//! suppression list, contacts and list management, import and export jobs
//! through S3, dedicated IPs, the deliverability dashboard, multi-Region
//! endpoints, tenants, reputation entities and tags.

use aws_sdk_sesv2::error::ProvideErrorMetadata;
use aws_sdk_sesv2::primitives::DateTime;
use aws_sdk_sesv2::types as t2;
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

async fn auto_verifying() -> Mws {
    Mws::start_with(mws::Config { ses_auto_verify: true, ..mws::Config::default() }).await
}

fn simple(subject: &str) -> t2::EmailContent {
    t2::EmailContent::builder()
        .simple(
            t2::Message::builder()
                .subject(t2::Content::builder().data(subject).build().unwrap())
                .body(t2::Body::builder().text(t2::Content::builder().data("body").build().unwrap()).build())
                .build(),
        )
        .build()
}

fn dest(a: &str) -> t2::Destination {
    t2::Destination::builder().to_addresses(a).build()
}

fn arn(resource: &str) -> String {
    format!("arn:aws:ses:us-east-1:{ACCOUNT}:{resource}")
}

/// Decide the account's production access review now (MWS control API).
async fn grant_production_access(mws: &Mws) {
    let (status, body) = mws.control("POST", "/_aws/ses/production-access?status=GRANTED", None).await;
    assert_eq!(status, 200, "{body}");
}

async fn outbox(mws: &Mws, query: &str) -> Vec<serde_json::Value> {
    let (_, body) = mws.control("GET", &format!("/_aws/ses{query}"), None).await;
    body["messages"].as_array().cloned().unwrap_or_default()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::test]
async fn identities_attributes_policies_and_certificates() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);

    let created = ses.create_email_identity().email_identity("dev@team.test").send().await.unwrap();
    assert_eq!(created.identity_type().unwrap().as_str(), "EMAIL_ADDRESS");
    ses.create_email_identity().email_identity("team.test").send().await.unwrap();
    let err = ses.create_email_identity().email_identity("team.test").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("AlreadyExistsException"));
    let names: Vec<String> = ses
        .list_email_identities()
        .send()
        .await
        .unwrap()
        .email_identities()
        .iter()
        .map(|i| i.identity_name().unwrap().to_string())
        .collect();
    assert_eq!(names, ["dev@team.test", "team.test"]);

    let policy = |action: &str| {
        serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": format!("arn:aws:iam::{ACCOUNT}:root")}, "Action": action, "Resource": arn("identity/team.test")}]
        })
        .to_string()
    };
    ses.create_email_identity_policy()
        .email_identity("team.test")
        .policy_name("p")
        .policy(policy("ses:SendEmail"))
        .send()
        .await
        .unwrap();
    ses.update_email_identity_policy()
        .email_identity("team.test")
        .policy_name("p")
        .policy(policy("ses:SendRawEmail"))
        .send()
        .await
        .unwrap();
    let got = ses.get_email_identity_policies().email_identity("team.test").send().await.unwrap();
    assert!(got.policies().unwrap()["p"].contains("ses:SendRawEmail"));
    ses.delete_email_identity_policy().email_identity("team.test").policy_name("p").send().await.unwrap();
    assert!(ses
        .get_email_identity_policies()
        .email_identity("team.test")
        .send()
        .await
        .unwrap()
        .policies()
        .unwrap()
        .is_empty());

    ses.create_configuration_set().configuration_set_name("default-set").send().await.unwrap();
    ses.put_email_identity_configuration_set_attributes()
        .email_identity("team.test")
        .configuration_set_name("default-set")
        .send()
        .await
        .unwrap();
    ses.put_email_identity_dkim_attributes().email_identity("team.test").signing_enabled(false).send().await.unwrap();
    let rotated = ses
        .put_email_identity_dkim_signing_attributes()
        .email_identity("team.test")
        .signing_attributes_origin(t2::DkimSigningAttributesOrigin::AwsSes)
        .signing_attributes(
            t2::DkimSigningAttributes::builder().next_signing_key_length(t2::DkimSigningKeyLength::Rsa2048Bit).build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(rotated.dkim_tokens().len(), 3);
    ses.put_email_identity_feedback_attributes()
        .email_identity("team.test")
        .email_forwarding_enabled(true)
        .send()
        .await
        .unwrap();
    ses.put_email_identity_mail_from_attributes()
        .email_identity("team.test")
        .mail_from_domain("mail.team.test")
        .behavior_on_mx_failure(t2::BehaviorOnMxFailure::UseDefaultValue)
        .send()
        .await
        .unwrap();
    let got = ses.get_email_identity().email_identity("team.test").send().await.unwrap();
    assert_eq!(got.configuration_set_name(), Some("default-set"));
    assert!(!got.dkim_attributes().unwrap().signing_enabled());
    assert!(got.feedback_forwarding_status());
    assert_eq!(got.mail_from_attributes().unwrap().mail_from_domain(), "mail.team.test");
    assert_eq!(got.mail_from_attributes().unwrap().mail_from_domain_status().as_str(), "PENDING");

    let cert = "arn:aws:acm:us-east-1:123456789012:certificate/0a1b2c3d";
    ses.associate_email_identity_certificate()
        .email_identity("team.test")
        .from_address("signed@team.test")
        .certificate_arn(cert)
        .send()
        .await
        .unwrap();
    let certs = ses.list_email_identity_certificates().email_identity("team.test").send().await.unwrap();
    assert_eq!(certs.certificates().len(), 1);
    ses.disassociate_email_identity_certificate()
        .email_identity("team.test")
        .from_address("signed@team.test")
        .send()
        .await
        .unwrap();
    assert!(ses
        .list_email_identity_certificates()
        .email_identity("team.test")
        .send()
        .await
        .unwrap()
        .certificates()
        .is_empty());

    ses.delete_email_identity().email_identity("dev@team.test").send().await.unwrap();
    let err =
        ses.delete_email_identity().email_identity("dev@team.test").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn templates_custom_verification_and_bulk_sending() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);
    ses.create_email_identity().email_identity("brand.test").send().await.unwrap();

    let content = |subject: &str| t2::EmailTemplateContent::builder().subject(subject).text("Hi {{name}}").build();
    ses.create_email_template()
        .template_name("promo")
        .template_content(content("Deal for {{name}}"))
        .send()
        .await
        .unwrap();
    ses.update_email_template()
        .template_name("promo")
        .template_content(content("Offer for {{name}}"))
        .send()
        .await
        .unwrap();
    let got = ses.get_email_template().template_name("promo").send().await.unwrap();
    assert_eq!(got.template_content().unwrap().subject(), Some("Offer for {{name}}"));
    let listed = ses.list_email_templates().send().await.unwrap();
    assert_eq!(listed.templates_metadata()[0].template_name(), Some("promo"));

    // Two entries at once exceed the sandbox's one message a second.
    grant_production_access(&mws).await;
    let bulk = ses
        .send_bulk_email()
        .from_email_address("deals@brand.test")
        .default_content(
            t2::BulkEmailContent::builder()
                .template(t2::Template::builder().template_name("promo").template_data(r#"{"name":"there"}"#).build())
                .build(),
        )
        .bulk_email_entries(
            t2::BulkEmailEntry::builder()
                .destination(dest("success@simulator.amazonses.com"))
                .replacement_email_content(
                    t2::ReplacementEmailContent::builder()
                        .replacement_template(
                            t2::ReplacementTemplate::builder().replacement_template_data(r#"{"name":"Kim"}"#).build(),
                        )
                        .build(),
                )
                .build(),
        )
        .bulk_email_entries(t2::BulkEmailEntry::builder().destination(dest("success@simulator.amazonses.com")).build())
        .send()
        .await
        .unwrap();
    let results = bulk.bulk_email_entry_results();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.status().map(|s| s.as_str()) == Some("SUCCESS")));
    let subjects: Vec<String> = outbox(&mws, "?email=deals@brand.test")
        .await
        .iter()
        .map(|m| m["Subject"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(subjects, ["Offer for Kim", "Offer for there"]);
    ses.delete_email_template().template_name("promo").send().await.unwrap();
    let err = ses.get_email_template().template_name("promo").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));

    let custom = |subject: &str| {
        ses.update_custom_verification_email_template()
            .template_name("join")
            .from_email_address("hello@brand.test")
            .template_subject(subject)
            .template_content("<p>Welcome aboard</p>")
            .success_redirection_url("https://brand.test/yes")
            .failure_redirection_url("https://brand.test/no")
    };
    ses.create_custom_verification_email_template()
        .template_name("join")
        .from_email_address("hello@brand.test")
        .template_subject("Join us")
        .template_content("<p>Welcome</p>")
        .success_redirection_url("https://brand.test/yes")
        .failure_redirection_url("https://brand.test/no")
        .send()
        .await
        .unwrap();
    custom("Join us today").send().await.unwrap();
    let got = ses.get_custom_verification_email_template().template_name("join").send().await.unwrap();
    assert_eq!(got.template_subject(), Some("Join us today"));
    assert_eq!(
        ses.list_custom_verification_email_templates()
            .send()
            .await
            .unwrap()
            .custom_verification_email_templates()
            .len(),
        1
    );
    let sent =
        ses.send_custom_verification_email().email_address("fan@else.test").template_name("join").send().await.unwrap();
    let mail = outbox(&mws, &format!("?id={}", sent.message_id().unwrap())).await;
    assert_eq!(mail[0]["Kind"], "CustomVerificationEmail");
    ses.delete_custom_verification_email_template().template_name("join").send().await.unwrap();
    let err = custom("gone").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn configuration_set_options() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);
    let topic = sns.create_topic().name("cs-events").send().await.unwrap().topic_arn().unwrap().to_string();
    let cs = "marketing";

    ses.create_configuration_set().configuration_set_name(cs).send().await.unwrap();
    let err = ses.create_configuration_set().configuration_set_name(cs).send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("AlreadyExistsException"));
    assert_eq!(ses.list_configuration_sets().send().await.unwrap().configuration_sets(), [cs]);

    ses.put_configuration_set_archiving_options()
        .configuration_set_name(cs)
        .archive_arn(format!("arn:aws:ses:us-east-1:{ACCOUNT}:mailmanager-archive/a-0123456789abcdefghijklmn"))
        .send()
        .await
        .unwrap();
    ses.put_configuration_set_delivery_options()
        .configuration_set_name(cs)
        .tls_policy(t2::TlsPolicy::Require)
        .send()
        .await
        .unwrap();
    ses.put_configuration_set_reputation_options()
        .configuration_set_name(cs)
        .reputation_metrics_enabled(true)
        .send()
        .await
        .unwrap();
    ses.put_configuration_set_sending_options().configuration_set_name(cs).sending_enabled(true).send().await.unwrap();
    ses.put_configuration_set_suppression_options()
        .configuration_set_name(cs)
        .suppressed_reasons(t2::SuppressionListReason::Complaint)
        .send()
        .await
        .unwrap();
    ses.put_configuration_set_tracking_options()
        .configuration_set_name(cs)
        .custom_redirect_domain("track.marketing.test")
        .send()
        .await
        .unwrap();
    ses.put_configuration_set_vdm_options()
        .configuration_set_name(cs)
        .vdm_options(
            t2::VdmOptions::builder()
                .dashboard_options(
                    t2::DashboardOptions::builder().engagement_metrics(t2::FeatureStatus::Enabled).build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    ses.update_configuration_set()
        .configuration_set_name(cs)
        .message_security_options(t2::MessageSecurityOptions::builder().build())
        .send()
        .await
        .unwrap();
    let got = ses.get_configuration_set().configuration_set_name(cs).send().await.unwrap();
    assert_eq!(got.delivery_options().unwrap().tls_policy().unwrap().as_str(), "REQUIRE");
    assert!(got.reputation_options().unwrap().reputation_metrics_enabled());
    assert!(got.sending_options().unwrap().sending_enabled());
    assert_eq!(got.suppression_options().unwrap().suppressed_reasons()[0].as_str(), "COMPLAINT");
    assert_eq!(got.tracking_options().unwrap().custom_redirect_domain(), "track.marketing.test");
    assert!(got.archiving_options().unwrap().archive_arn().unwrap().ends_with("a-0123456789abcdefghijklmn"));

    let def = |enabled: bool| {
        t2::EventDestinationDefinition::builder()
            .enabled(enabled)
            .matching_event_types(t2::EventType::Send)
            .sns_destination(t2::SnsDestination::builder().topic_arn(&topic).build().unwrap())
            .build()
    };
    ses.create_configuration_set_event_destination()
        .configuration_set_name(cs)
        .event_destination_name("d")
        .event_destination(def(true))
        .send()
        .await
        .unwrap();
    ses.update_configuration_set_event_destination()
        .configuration_set_name(cs)
        .event_destination_name("d")
        .event_destination(def(false))
        .send()
        .await
        .unwrap();
    let d = ses.get_configuration_set_event_destinations().configuration_set_name(cs).send().await.unwrap();
    assert!(!d.event_destinations()[0].enabled());
    ses.delete_configuration_set_event_destination()
        .configuration_set_name(cs)
        .event_destination_name("d")
        .send()
        .await
        .unwrap();
    assert!(ses
        .get_configuration_set_event_destinations()
        .configuration_set_name(cs)
        .send()
        .await
        .unwrap()
        .event_destinations()
        .is_empty());

    ses.put_configuration_set_sending_options().configuration_set_name(cs).sending_enabled(false).send().await.unwrap();
    ses.create_email_identity().email_identity("marketing.test").send().await.unwrap();
    let err = ses
        .send_email()
        .from_email_address("hi@marketing.test")
        .destination(dest("success@simulator.amazonses.com"))
        .content(simple("paused"))
        .configuration_set_name(cs)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("SendingPausedException"));
    ses.delete_configuration_set().configuration_set_name(cs).send().await.unwrap();
    let err = ses.get_configuration_set().configuration_set_name(cs).send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn account_suppression_list_and_insights() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);

    let account = ses.get_account().send().await.unwrap();
    assert!(!account.production_access_enabled());
    assert_eq!(account.send_quota().unwrap().max24_hour_send(), 200.0);
    ses.put_account_details()
        .mail_type(t2::MailType::Transactional)
        .website_url("https://shop.test")
        .use_case_description("Order receipts")
        .production_access_enabled(true)
        .send()
        .await
        .unwrap();
    // The request opens a review; the account stays in the sandbox.
    let account = ses.get_account().send().await.unwrap();
    assert!(!account.production_access_enabled());
    let review = account.details().unwrap().review_details().unwrap();
    assert_eq!(review.status().map(|s| s.as_str()), Some("PENDING"));
    assert!(review.case_id().is_some());
    grant_production_access(&mws).await;
    let account = ses.get_account().send().await.unwrap();
    assert!(account.production_access_enabled());
    assert_eq!(account.details().unwrap().review_details().unwrap().status().map(|s| s.as_str()), Some("GRANTED"));
    assert_eq!(account.send_quota().unwrap().max24_hour_send(), 50000.0);
    assert_eq!(account.details().unwrap().website_url(), Some("https://shop.test"));
    let err = ses
        .put_account_details()
        .mail_type(t2::MailType::Transactional)
        .website_url("https://shop.test")
        .production_access_enabled(true)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("ConflictException"));

    ses.put_account_dedicated_ip_warmup_attributes().auto_warmup_enabled(false).send().await.unwrap();
    ses.put_account_pricing_attributes().plan(t2::PricingPlan::Essentials).send().await.unwrap();
    ses.put_account_sending_attributes().sending_enabled(true).send().await.unwrap();
    ses.put_account_suppression_attributes()
        .suppressed_reasons(t2::SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();
    ses.put_account_vdm_attributes()
        .vdm_attributes(t2::VdmAttributes::builder().vdm_enabled(t2::FeatureStatus::Enabled).build().unwrap())
        .send()
        .await
        .unwrap();
    let account = ses.get_account().send().await.unwrap();
    assert!(!account.dedicated_ip_auto_warmup_enabled());
    assert_eq!(account.suppression_attributes().unwrap().suppressed_reasons()[0].as_str(), "BOUNCE");
    assert_eq!(account.vdm_attributes().unwrap().vdm_enabled().as_str(), "ENABLED");

    ses.put_suppressed_destination()
        .email_address("gone@old.test")
        .reason(t2::SuppressionListReason::Complaint)
        .send()
        .await
        .unwrap();
    let s = ses.get_suppressed_destination().email_address("gone@old.test").send().await.unwrap();
    assert_eq!(s.suppressed_destination().unwrap().reason().as_str(), "COMPLAINT");
    let listed = ses.list_suppressed_destinations().send().await.unwrap();
    assert_eq!(listed.suppressed_destination_summaries().len(), 1);
    ses.delete_suppressed_destination().email_address("gone@old.test").send().await.unwrap();
    let err =
        ses.get_suppressed_destination().email_address("gone@old.test").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));

    ses.create_email_identity().email_identity("shop.test").send().await.unwrap();
    let sent = ses
        .send_email()
        .from_email_address("orders@shop.test")
        .destination(dest("success@simulator.amazonses.com"))
        .content(simple("Receipt"))
        .send()
        .await
        .unwrap();
    let id = sent.message_id().unwrap();
    let insights = ses.get_message_insights().message_id(id).send().await.unwrap();
    assert_eq!(insights.subject(), Some("Receipt"));
    assert_eq!(insights.insights()[0].destination(), Some("success@simulator.amazonses.com"));
    let metrics = ses
        .batch_get_metric_data()
        .queries(
            t2::BatchGetMetricDataQuery::builder()
                .id("sends")
                .namespace(t2::MetricNamespace::Vdm)
                .metric(t2::Metric::Send)
                .start_date(DateTime::from_secs(now() - 86400))
                .end_date(DateTime::from_secs(now() + 60))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.results()[0].values(), [1]);
    let addr = ses.get_email_address_insights().email_address("success@simulator.amazonses.com").send().await.unwrap();
    assert!(addr.mailbox_validation().is_some());
}

#[tokio::test]
async fn contact_lists_and_list_management() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);
    let topic = |name: &str, status: t2::SubscriptionStatus| {
        t2::Topic::builder().topic_name(name).display_name(name).default_subscription_status(status).build().unwrap()
    };
    ses.create_contact_list()
        .contact_list_name("newsletter")
        .topics(topic("weekly", t2::SubscriptionStatus::OptIn))
        .send()
        .await
        .unwrap();
    let err = ses.create_contact_list().contact_list_name("second").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("LimitExceededException"));
    ses.update_contact_list()
        .contact_list_name("newsletter")
        .topics(topic("weekly", t2::SubscriptionStatus::OptIn))
        .topics(topic("offers", t2::SubscriptionStatus::OptOut))
        .description("Our news")
        .send()
        .await
        .unwrap();
    let list = ses.get_contact_list().contact_list_name("newsletter").send().await.unwrap();
    assert_eq!(list.topics().len(), 2);
    assert_eq!(ses.list_contact_lists().send().await.unwrap().contact_lists().len(), 1);

    ses.create_contact().contact_list_name("newsletter").email_address("reader@else.test").send().await.unwrap();
    ses.create_contact().contact_list_name("newsletter").email_address("other@else.test").send().await.unwrap();
    ses.update_contact()
        .contact_list_name("newsletter")
        .email_address("other@else.test")
        .topic_preferences(
            t2::TopicPreference::builder()
                .topic_name("offers")
                .subscription_status(t2::SubscriptionStatus::OptIn)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let c = ses.get_contact().contact_list_name("newsletter").email_address("other@else.test").send().await.unwrap();
    assert_eq!(c.topic_preferences()[0].subscription_status().as_str(), "OPT_IN");
    let all = ses.list_contacts().contact_list_name("newsletter").send().await.unwrap();
    assert_eq!(all.contacts().len(), 2);

    // A list-managed send carries a working one-click unsubscribe link.
    ses.put_account_details()
        .mail_type(t2::MailType::Marketing)
        .website_url("https://else.test")
        .production_access_enabled(true)
        .send()
        .await
        .unwrap();
    grant_production_access(&mws).await;
    ses.create_email_identity().email_identity("news.test").send().await.unwrap();
    let sent = ses
        .send_email()
        .from_email_address("editor@news.test")
        .destination(dest("reader@else.test"))
        .content(simple("Issue 1"))
        .list_management_options(
            t2::ListManagementOptions::builder().contact_list_name("newsletter").topic_name("weekly").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let mail = outbox(&mws, &format!("?id={}", sent.message_id().unwrap())).await;
    let raw = mail[0]["RawData"].as_str().unwrap();
    let link =
        raw.lines().find_map(|l| l.strip_prefix("List-Unsubscribe: <")).unwrap().trim_end_matches('>').to_string();
    let (status, _, _) = mws.raw("POST", &link, &[], b"List-Unsubscribe=One-Click").await;
    assert_eq!(status, 200);
    let c = ses.get_contact().contact_list_name("newsletter").email_address("reader@else.test").send().await.unwrap();
    assert!(c
        .topic_preferences()
        .iter()
        .any(|p| p.topic_name() == "weekly" && p.subscription_status().as_str() == "OPT_OUT"));

    ses.delete_contact().contact_list_name("newsletter").email_address("other@else.test").send().await.unwrap();
    ses.delete_contact_list().contact_list_name("newsletter").send().await.unwrap();
    let err = ses.get_contact_list().contact_list_name("newsletter").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn import_export_jobs_dedicated_ips_and_deliverability() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("ses-data").send().await.unwrap();
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::ses-data/*"
        }]
    });
    s3.put_bucket_policy().bucket("ses-data").policy(policy.to_string()).send().await.unwrap();
    s3.put_object()
        .bucket("ses-data")
        .key("suppress.csv")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            b"emailAddress,reason\na@x.test,BOUNCE\nb@x.test,COMPLAINT\n",
        ))
        .send()
        .await
        .unwrap();

    let job = ses
        .create_import_job()
        .import_destination(
            t2::ImportDestination::builder()
                .suppression_list_destination(
                    t2::SuppressionListDestination::builder()
                        .suppression_list_import_action(t2::SuppressionListImportAction::Put)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .import_data_source(
            t2::ImportDataSource::builder()
                .s3_url("s3://ses-data/suppress.csv")
                .data_format(t2::DataFormat::Csv)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let got = ses.get_import_job().job_id(job.job_id().unwrap()).send().await.unwrap();
    assert_eq!(got.job_status().unwrap().as_str(), "COMPLETED");
    assert_eq!(got.processed_records_count(), Some(2));
    assert_eq!(ses.list_import_jobs().send().await.unwrap().import_jobs().len(), 1);
    assert_eq!(ses.list_suppressed_destinations().send().await.unwrap().suppressed_destination_summaries().len(), 2);

    ses.create_email_identity().email_identity("data.test").send().await.unwrap();
    ses.send_email()
        .from_email_address("x@data.test")
        .destination(dest("success@simulator.amazonses.com"))
        .content(simple("exported"))
        .send()
        .await
        .unwrap();
    let export = ses
        .create_export_job()
        .export_data_source(
            t2::ExportDataSource::builder()
                .message_insights_data_source(
                    t2::MessageInsightsDataSource::builder()
                        .start_date(DateTime::from_secs(now() - 3600))
                        .end_date(DateTime::from_secs(now() + 60))
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .export_destination(
            t2::ExportDestination::builder()
                .data_format(t2::DataFormat::Json)
                .s3_url("s3://ses-data/exports/")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let export_id = export.job_id().unwrap().to_string();
    let got = ses.get_export_job().job_id(&export_id).send().await.unwrap();
    assert_eq!(got.job_status().unwrap().as_str(), "COMPLETED");
    assert_eq!(got.statistics().unwrap().exported_records_count(), Some(1));
    let object = s3.get_object().bucket("ses-data").key(format!("exports/{export_id}.json")).send().await.unwrap();
    let body = String::from_utf8(object.body.collect().await.unwrap().to_vec()).unwrap();
    assert!(body.contains("\"SUBJECT\":\"exported\""), "{body}");
    assert_eq!(ses.list_export_jobs().send().await.unwrap().export_jobs().len(), 1);
    let err = ses.cancel_export_job().job_id(&export_id).send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("ConflictException"));

    ses.create_dedicated_ip_pool().pool_name("bulk").scaling_mode(t2::ScalingMode::Standard).send().await.unwrap();
    assert_eq!(ses.list_dedicated_ip_pools().send().await.unwrap().dedicated_ip_pools(), ["bulk"]);
    ses.put_dedicated_ip_pool_scaling_attributes()
        .pool_name("bulk")
        .scaling_mode(t2::ScalingMode::Managed)
        .send()
        .await
        .unwrap();
    let pool = ses.get_dedicated_ip_pool().pool_name("bulk").send().await.unwrap();
    assert_eq!(pool.dedicated_ip_pool().unwrap().scaling_mode().as_str(), "MANAGED");
    assert!(ses.get_dedicated_ips().pool_name("bulk").send().await.unwrap().dedicated_ips().is_empty());
    let err = ses.get_dedicated_ip().ip("192.0.2.10").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
    let err = ses
        .put_dedicated_ip_in_pool()
        .ip("192.0.2.10")
        .destination_pool_name("bulk")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
    let err = ses
        .put_dedicated_ip_warmup_attributes()
        .ip("192.0.2.10")
        .warmup_percentage(50)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
    ses.delete_dedicated_ip_pool().pool_name("bulk").send().await.unwrap();

    let err =
        ses.get_blacklist_reports().blacklist_item_names("192.0.2.10").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
    ses.put_deliverability_dashboard_option()
        .dashboard_enabled(true)
        .subscribed_domains(t2::DomainDeliverabilityTrackingOption::builder().domain("data.test").build())
        .send()
        .await
        .unwrap();
    let options = ses.get_deliverability_dashboard_options().send().await.unwrap();
    assert!(options.dashboard_enabled());
    assert_eq!(options.active_subscribed_domains().len(), 1);
    let reports = ses.get_blacklist_reports().blacklist_item_names("192.0.2.10").send().await.unwrap();
    assert!(reports.blacklist_report()["192.0.2.10"].is_empty());
    let stats = ses
        .get_domain_statistics_report()
        .domain("data.test")
        .start_date(DateTime::from_secs(now() - 86400))
        .end_date(DateTime::from_secs(now() + 60))
        .send()
        .await
        .unwrap();
    assert_eq!(stats.overall_volume().unwrap().volume_statistics().unwrap().inbox_raw_count(), Some(1));
    let campaigns = ses
        .list_domain_deliverability_campaigns()
        .subscribed_domain("data.test")
        .start_date(DateTime::from_secs(now() - 86400))
        .end_date(DateTime::from_secs(now() + 60))
        .send()
        .await
        .unwrap();
    assert!(campaigns.domain_deliverability_campaigns().is_empty());
    let err =
        ses.get_domain_deliverability_campaign().campaign_id("c-1").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
    let report = ses
        .create_deliverability_test_report()
        .report_name("placement")
        .from_email_address("x@data.test")
        .content(simple("Placement test"))
        .send()
        .await
        .unwrap();
    let got = ses.get_deliverability_test_report().report_id(report.report_id()).send().await.unwrap();
    assert_eq!(got.deliverability_test_report().unwrap().subject(), Some("Placement test"));
    assert_eq!(ses.list_deliverability_test_reports().send().await.unwrap().deliverability_test_reports().len(), 1);
}

#[tokio::test]
async fn endpoints_tenants_reputation_and_tags() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_sesv2::Client::new(&cfg);
    let tag = |k: &str, v: &str| t2::Tag::builder().key(k).value(v).build().unwrap();

    let ep = ses
        .create_multi_region_endpoint()
        .endpoint_name("global")
        .details(
            t2::Details::builder()
                .routes_details(t2::RouteDetails::builder().region("us-west-2").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(ep.status().unwrap().as_str(), "READY");
    let got = ses.get_multi_region_endpoint().endpoint_name("global").send().await.unwrap();
    assert_eq!(got.routes().len(), 2);
    assert_eq!(ses.list_multi_region_endpoints().send().await.unwrap().multi_region_endpoints().len(), 1);
    ses.delete_multi_region_endpoint().endpoint_name("global").send().await.unwrap();

    ses.create_email_identity().email_identity("saas.test").send().await.unwrap();
    let tenant = ses.create_tenant().tenant_name("acme").tags(tag("tier", "gold")).send().await.unwrap();
    assert_eq!(tenant.sending_status().unwrap().as_str(), "ENABLED");
    ses.put_tenant_suppression_attributes()
        .tenant_name("acme")
        .suppressed_reasons(t2::SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();
    let identity_arn = arn("identity/saas.test");
    ses.create_tenant_resource_association().tenant_name("acme").resource_arn(&identity_arn).send().await.unwrap();
    let resources = ses.list_tenant_resources().tenant_name("acme").send().await.unwrap();
    assert_eq!(resources.tenant_resources()[0].resource_arn(), Some(identity_arn.as_str()));
    let tenants = ses.list_resource_tenants().resource_arn(&identity_arn).send().await.unwrap();
    assert_eq!(tenants.resource_tenants()[0].tenant_name(), Some("acme"));
    let sent = ses
        .send_email()
        .from_email_address("bot@saas.test")
        .destination(dest("success@simulator.amazonses.com"))
        .content(simple("from a tenant"))
        .tenant_name("acme")
        .send()
        .await
        .unwrap();
    assert!(sent.message_id().is_some());
    let got = ses.get_tenant().tenant_name("acme").send().await.unwrap();
    assert_eq!(got.tenant().unwrap().tenant_name(), Some("acme"));
    assert_eq!(ses.list_tenants().send().await.unwrap().tenants().len(), 1);
    ses.delete_tenant_resource_association().tenant_name("acme").resource_arn(&identity_arn).send().await.unwrap();
    ses.delete_tenant().tenant_name("acme").send().await.unwrap();
    let err = ses.get_tenant().tenant_name("acme").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));

    let entity = ses
        .get_reputation_entity()
        .reputation_entity_type(t2::ReputationEntityType::Resource)
        .reputation_entity_reference(&identity_arn)
        .send()
        .await
        .unwrap();
    assert_eq!(entity.reputation_entity().unwrap().sending_status_aggregate().unwrap().as_str(), "ENABLED");
    ses.update_reputation_entity_customer_managed_status()
        .reputation_entity_type(t2::ReputationEntityType::Resource)
        .reputation_entity_reference(&identity_arn)
        .sending_status(t2::SendingStatus::Disabled)
        .send()
        .await
        .unwrap();
    ses.update_reputation_entity_policy()
        .reputation_entity_type(t2::ReputationEntityType::Resource)
        .reputation_entity_reference(&identity_arn)
        .reputation_entity_policy("arn:aws:ses:us-east-1:aws:reputation-policy/strict")
        .send()
        .await
        .unwrap();
    let listed = ses.list_reputation_entities().send().await.unwrap();
    let e = listed
        .reputation_entities()
        .iter()
        .find(|e| e.reputation_entity_reference() == Some(identity_arn.as_str()))
        .unwrap();
    assert_eq!(e.sending_status_aggregate().unwrap().as_str(), "DISABLED");
    assert!(e.reputation_management_policy().unwrap().ends_with("strict"));

    // With VDM on, a domain without DKIM set up gets a recommendation.
    ses.put_account_vdm_attributes()
        .vdm_attributes(t2::VdmAttributes::builder().vdm_enabled(t2::FeatureStatus::Enabled).build().unwrap())
        .send()
        .await
        .unwrap();
    let recs = ses.list_recommendations().send().await.unwrap();
    assert!(recs.recommendations().is_empty(), "auto-verified domains have DKIM");

    ses.tag_resource()
        .resource_arn(&identity_arn)
        .tags(tag("team", "growth"))
        .tags(tag("env", "dev"))
        .send()
        .await
        .unwrap();
    ses.untag_resource().resource_arn(&identity_arn).tag_keys("env").send().await.unwrap();
    let tags = ses.list_tags_for_resource().resource_arn(&identity_arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].key(), "team");
    let err = ses
        .list_tags_for_resource()
        .resource_arn(arn("identity/missing.test"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("NotFoundException"));
}
