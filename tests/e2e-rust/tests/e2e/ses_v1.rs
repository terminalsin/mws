//! Every SES v1 operation through the official Rust SDK: identity
//! attributes and policies, templates, custom verification emails,
//! configuration sets, account sending, receipt rule management and
//! `SendBounce`.

use aws_sdk_ses::error::ProvideErrorMetadata;
use aws_sdk_ses::types as t1;
use mws_e2e::Mws;

async fn auto_verifying() -> Mws {
    Mws::start_with(mws::Config { ses_auto_verify: true, ..mws::Config::default() }).await
}

fn to(addresses: &[&str]) -> t1::Destination {
    t1::Destination::builder().set_to_addresses(Some(addresses.iter().map(|a| a.to_string()).collect())).build()
}

fn simple(subject: &str) -> t1::Message {
    t1::Message::builder()
        .subject(t1::Content::builder().data(subject).build().unwrap())
        .body(t1::Body::builder().text(t1::Content::builder().data("body").build().unwrap()).build())
        .build()
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

#[tokio::test]
async fn identity_attributes_policies_and_legacy_addresses() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_ses::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);

    ses.verify_email_address().email_address("old@legacy.test").send().await.unwrap();
    let listed = ses.list_verified_email_addresses().send().await.unwrap();
    assert_eq!(listed.verified_email_addresses(), ["old@legacy.test"]);
    ses.delete_verified_email_address().email_address("old@legacy.test").send().await.unwrap();
    assert!(ses.list_verified_email_addresses().send().await.unwrap().verified_email_addresses().is_empty());

    let token = ses.verify_domain_identity().domain("corp.test").send().await.unwrap();
    assert!(!token.verification_token().is_empty());
    let dkim = ses.verify_domain_dkim().domain("corp.test").send().await.unwrap();
    assert_eq!(dkim.dkim_tokens().len(), 3);
    ses.set_identity_dkim_enabled().identity("corp.test").dkim_enabled(false).send().await.unwrap();
    let attrs = ses.get_identity_dkim_attributes().identities("corp.test").send().await.unwrap();
    assert!(!attrs.dkim_attributes()["corp.test"].dkim_enabled());

    ses.set_identity_mail_from_domain()
        .identity("corp.test")
        .mail_from_domain("bounce.corp.test")
        .behavior_on_mx_failure(t1::BehaviorOnMxFailure::RejectMessage)
        .send()
        .await
        .unwrap();
    let mf = ses.get_identity_mail_from_domain_attributes().identities("corp.test").send().await.unwrap();
    let mf = &mf.mail_from_domain_attributes()["corp.test"];
    assert_eq!(mf.mail_from_domain(), "bounce.corp.test");
    assert_eq!(mf.behavior_on_mx_failure().as_str(), "RejectMessage");
    let err = ses
        .set_identity_mail_from_domain()
        .identity("corp.test")
        .mail_from_domain("elsewhere.test")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("InvalidParameterValue"));

    let topic = sns.create_topic().name("feedback").send().await.unwrap().topic_arn().unwrap().to_string();
    for kind in [t1::NotificationType::Bounce, t1::NotificationType::Complaint] {
        ses.set_identity_notification_topic()
            .identity("corp.test")
            .notification_type(kind)
            .sns_topic(&topic)
            .send()
            .await
            .unwrap();
    }
    ses.set_identity_headers_in_notifications_enabled()
        .identity("corp.test")
        .notification_type(t1::NotificationType::Bounce)
        .enabled(true)
        .send()
        .await
        .unwrap();
    ses.set_identity_feedback_forwarding_enabled()
        .identity("corp.test")
        .forwarding_enabled(false)
        .send()
        .await
        .unwrap();
    let n = ses.get_identity_notification_attributes().identities("corp.test").send().await.unwrap();
    let n = &n.notification_attributes()["corp.test"];
    assert_eq!(n.bounce_topic(), topic);
    assert_eq!(n.complaint_topic(), topic);
    assert!(n.headers_in_bounce_notifications_enabled());
    assert!(!n.forwarding_enabled());

    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": ["ses:SendEmail", "ses:SendRawEmail"],
            "Resource": "arn:aws:ses:us-east-1:123456789012:identity/corp.test"
        }]
    });
    ses.put_identity_policy()
        .identity("corp.test")
        .policy_name("delegate")
        .policy(policy.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(ses.list_identity_policies().identity("corp.test").send().await.unwrap().policy_names(), ["delegate"]);
    let got = ses.get_identity_policies().identity("corp.test").policy_names("delegate").send().await.unwrap();
    assert!(got.policies()["delegate"].contains("ses:SendRawEmail"));
    let err = ses
        .put_identity_policy()
        .identity("corp.test")
        .policy_name("bad")
        .policy("{}")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("InvalidPolicy"));
    ses.delete_identity_policy().identity("corp.test").policy_name("delegate").send().await.unwrap();
    assert!(ses.list_identity_policies().identity("corp.test").send().await.unwrap().policy_names().is_empty());
}

#[tokio::test]
async fn templates_and_custom_verification_emails() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_ses::Client::new(&cfg);
    ses.verify_email_identity().email_address("news@corp.test").send().await.unwrap();

    let template = |subject: &str| {
        t1::Template::builder()
            .template_name("digest")
            .subject_part(subject)
            .text_part("Hello {{name}}, {{count}} new items.")
            .html_part("<p>Hello {{name}}</p>")
            .build()
            .unwrap()
    };
    ses.create_template().template(template("Digest for {{name}}")).send().await.unwrap();
    let err = ses.create_template().template(template("dup")).send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("AlreadyExists"));
    ses.update_template().template(template("Your digest, {{name}}")).send().await.unwrap();
    let got = ses.get_template().template_name("digest").send().await.unwrap();
    assert_eq!(got.template().unwrap().subject_part(), Some("Your digest, {{name}}"));
    let listed = ses.list_templates().send().await.unwrap();
    assert_eq!(listed.templates_metadata()[0].name(), Some("digest"));
    let rendered = ses
        .test_render_template()
        .template_name("digest")
        .template_data(r#"{"name":"Ada","count":3}"#)
        .send()
        .await
        .unwrap();
    assert!(rendered.rendered_template().unwrap().contains("Subject: Your digest, Ada"));
    let err = ses
        .test_render_template()
        .template_name("digest")
        .template_data(r#"{"count":3}"#)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("MissingRenderingAttribute"));

    let sent = ses
        .send_templated_email()
        .source("news@corp.test")
        .destination(to(&["success@simulator.amazonses.com"]))
        .template("digest")
        .template_data(r#"{"name":"Grace","count":1}"#)
        .send()
        .await
        .unwrap();
    let mail = outbox(&mws, &format!("?id={}", sent.message_id())).await;
    assert_eq!(mail[0]["Subject"], "Your digest, Grace");
    assert_eq!(mail[0]["Template"], "digest");

    // Two destinations at once exceed the sandbox's one message a second.
    grant_production_access(&mws).await;
    let bulk = ses
        .send_bulk_templated_email()
        .source("news@corp.test")
        .template("digest")
        .default_template_data(r#"{"name":"friend","count":0}"#)
        .destinations(
            t1::BulkEmailDestination::builder()
                .destination(to(&["success@simulator.amazonses.com"]))
                .replacement_template_data(r#"{"name":"Lin"}"#)
                .build(),
        )
        .destinations(t1::BulkEmailDestination::builder().destination(to(&["success@simulator.amazonses.com"])).build())
        .send()
        .await
        .unwrap();
    assert_eq!(bulk.status().len(), 2);
    assert!(bulk.status().iter().all(|s| s.status().map(|s| s.as_str()) == Some("Success")));
    let subjects: Vec<String> = outbox(&mws, "?email=news@corp.test")
        .await
        .iter()
        .map(|m| m["Subject"].as_str().unwrap().to_string())
        .collect();
    assert!(
        subjects.contains(&"Your digest, Lin".to_string()) && subjects.contains(&"Your digest, friend".to_string())
    );
    ses.delete_template().template_name("digest").send().await.unwrap();
    let err = ses.get_template().template_name("digest").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("TemplateDoesNotExist"));

    ses.create_custom_verification_email_template()
        .template_name("onboard")
        .from_email_address("news@corp.test")
        .template_subject("Confirm your address")
        .template_content("<html><body>Please confirm.</body></html>")
        .success_redirection_url("https://corp.test/ok")
        .failure_redirection_url("https://corp.test/fail")
        .send()
        .await
        .unwrap();
    ses.update_custom_verification_email_template()
        .template_name("onboard")
        .template_subject("Confirm your email")
        .send()
        .await
        .unwrap();
    let got = ses.get_custom_verification_email_template().template_name("onboard").send().await.unwrap();
    assert_eq!(got.template_subject(), Some("Confirm your email"));
    let listed = ses.list_custom_verification_email_templates().send().await.unwrap();
    assert_eq!(listed.custom_verification_email_templates().len(), 1);
    ses.send_custom_verification_email()
        .email_address("new.user@corp.test")
        .template_name("onboard")
        .send()
        .await
        .unwrap();
    let mail = outbox(&mws, "?to=new.user@corp.test").await;
    assert_eq!(mail[0]["Kind"], "CustomVerificationEmail");
    assert_eq!(mail[0]["Subject"], "Confirm your email");
    ses.delete_custom_verification_email_template().template_name("onboard").send().await.unwrap();
    let err = ses
        .get_custom_verification_email_template()
        .template_name("onboard")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("CustomVerificationEmailTemplateDoesNotExist"));
}

#[tokio::test]
async fn configuration_sets_and_account_sending() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_ses::Client::new(&cfg);
    let sns = aws_sdk_sns::Client::new(&cfg);
    let topic = sns.create_topic().name("cs").send().await.unwrap().topic_arn().unwrap().to_string();
    ses.verify_email_identity().email_address("ops@corp.test").send().await.unwrap();

    ses.create_configuration_set()
        .configuration_set(t1::ConfigurationSet::builder().name("ops").build().unwrap())
        .send()
        .await
        .unwrap();
    let names: Vec<String> = ses
        .list_configuration_sets()
        .send()
        .await
        .unwrap()
        .configuration_sets()
        .iter()
        .map(|c| c.name().to_string())
        .collect();
    assert_eq!(names, ["ops"]);
    let dest = |enabled: bool| {
        t1::EventDestination::builder()
            .name("sns")
            .enabled(enabled)
            .matching_event_types(t1::EventType::Send)
            .sns_destination(t1::SnsDestination::builder().topic_arn(&topic).build().unwrap())
            .build()
            .unwrap()
    };
    ses.create_configuration_set_event_destination()
        .configuration_set_name("ops")
        .event_destination(dest(true))
        .send()
        .await
        .unwrap();
    ses.update_configuration_set_event_destination()
        .configuration_set_name("ops")
        .event_destination(dest(false))
        .send()
        .await
        .unwrap();
    ses.create_configuration_set_tracking_options()
        .configuration_set_name("ops")
        .tracking_options(t1::TrackingOptions::builder().custom_redirect_domain("click.corp.test").build())
        .send()
        .await
        .unwrap();
    ses.update_configuration_set_tracking_options()
        .configuration_set_name("ops")
        .tracking_options(t1::TrackingOptions::builder().custom_redirect_domain("go.corp.test").build())
        .send()
        .await
        .unwrap();
    ses.put_configuration_set_delivery_options()
        .configuration_set_name("ops")
        .delivery_options(t1::DeliveryOptions::builder().tls_policy(t1::TlsPolicy::Require).build())
        .send()
        .await
        .unwrap();
    ses.update_configuration_set_reputation_metrics_enabled()
        .configuration_set_name("ops")
        .enabled(true)
        .send()
        .await
        .unwrap();
    let d = ses
        .describe_configuration_set()
        .configuration_set_name("ops")
        .configuration_set_attribute_names(t1::ConfigurationSetAttribute::EventDestinations)
        .configuration_set_attribute_names(t1::ConfigurationSetAttribute::TrackingOptions)
        .configuration_set_attribute_names(t1::ConfigurationSetAttribute::DeliveryOptions)
        .configuration_set_attribute_names(t1::ConfigurationSetAttribute::ReputationOptions)
        .send()
        .await
        .unwrap();
    assert!(!d.event_destinations()[0].enabled());
    assert_eq!(d.tracking_options().unwrap().custom_redirect_domain(), Some("go.corp.test"));
    assert_eq!(d.delivery_options().unwrap().tls_policy().map(|p| p.as_str()), Some("Require"));
    assert!(d.reputation_options().unwrap().reputation_metrics_enabled());

    let send = || {
        ses.send_email()
            .source("ops@corp.test")
            .destination(to(&["success@simulator.amazonses.com"]))
            .message(simple("cs"))
            .configuration_set_name("ops")
            .send()
    };
    send().await.unwrap();
    ses.update_configuration_set_sending_enabled().configuration_set_name("ops").enabled(false).send().await.unwrap();
    let err = send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("ConfigurationSetSendingPausedException"));
    ses.update_configuration_set_sending_enabled().configuration_set_name("ops").enabled(true).send().await.unwrap();

    assert!(ses.get_account_sending_enabled().send().await.unwrap().enabled());
    ses.update_account_sending_enabled().enabled(false).send().await.unwrap();
    let err = send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("AccountSendingPausedException"));
    ses.update_account_sending_enabled().enabled(true).send().await.unwrap();

    ses.delete_configuration_set_tracking_options().configuration_set_name("ops").send().await.unwrap();
    let err = ses
        .delete_configuration_set_tracking_options()
        .configuration_set_name("ops")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("TrackingOptionsDoesNotExistException"));
    ses.delete_configuration_set_event_destination()
        .configuration_set_name("ops")
        .event_destination_name("sns")
        .send()
        .await
        .unwrap();
    ses.delete_configuration_set().configuration_set_name("ops").send().await.unwrap();
    let err = send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("ConfigurationSetDoesNotExist"));
}

#[tokio::test]
async fn receipt_rule_management_and_send_bounce() {
    let mws = auto_verifying().await;
    let cfg = mws.root_sdk_config().await;
    let ses = aws_sdk_ses::Client::new(&cfg);
    ses.verify_domain_identity().domain("corp.test").send().await.unwrap();

    ses.create_receipt_rule_set().rule_set_name("a").send().await.unwrap();
    let rule =
        |name: &str| t1::ReceiptRule::builder().name(name).enabled(true).recipients("corp.test").build().unwrap();
    ses.create_receipt_rule().rule_set_name("a").rule(rule("r1")).send().await.unwrap();
    ses.create_receipt_rule().rule_set_name("a").after("r1").rule(rule("r2")).send().await.unwrap();
    let order = |set: &'static str| {
        let ses = ses.clone();
        async move {
            ses.describe_receipt_rule_set()
                .rule_set_name(set)
                .send()
                .await
                .unwrap()
                .rules()
                .iter()
                .map(|r| r.name().to_string())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(order("a").await, ["r1", "r2"]);
    ses.set_receipt_rule_position().rule_set_name("a").rule_name("r2").send().await.unwrap();
    assert_eq!(order("a").await, ["r2", "r1"]);
    ses.reorder_receipt_rule_set().rule_set_name("a").rule_names("r1").rule_names("r2").send().await.unwrap();
    assert_eq!(order("a").await, ["r1", "r2"]);
    let err = ses
        .reorder_receipt_rule_set()
        .rule_set_name("a")
        .rule_names("r1")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.code(), Some("InvalidParameterValue"));

    let mut disabled = rule("r2");
    disabled.enabled = false;
    ses.update_receipt_rule().rule_set_name("a").rule(disabled).send().await.unwrap();
    let r2 = ses.describe_receipt_rule().rule_set_name("a").rule_name("r2").send().await.unwrap();
    assert!(!r2.rule().unwrap().enabled());

    ses.clone_receipt_rule_set().rule_set_name("b").original_rule_set_name("a").send().await.unwrap();
    assert_eq!(order("b").await, ["r1", "r2"]);
    let sets = ses.list_receipt_rule_sets().send().await.unwrap();
    assert_eq!(sets.rule_sets().len(), 2);
    ses.delete_receipt_rule().rule_set_name("b").rule_name("r1").send().await.unwrap();
    assert_eq!(order("b").await, ["r2"]);
    ses.delete_receipt_rule_set().rule_set_name("b").send().await.unwrap();
    let err = ses.describe_receipt_rule_set().rule_set_name("b").send().await.unwrap_err().into_service_error();
    assert_eq!(err.code(), Some("RuleSetDoesNotExist"));

    // SendBounce answers mail this account received.
    ses.set_active_receipt_rule_set().rule_set_name("a").send().await.unwrap();
    let (status, received) = mws
        .control(
            "POST",
            "/_aws/ses/inbound?from=sender@remote.test&to=bob@corp.test",
            Some("Subject: hi\r\n\r\nhello\r\n"),
        )
        .await;
    assert_eq!(status, 200, "{received}");
    let original = received["messageId"].as_str().unwrap().to_string();
    let bounce = ses
        .send_bounce()
        .original_message_id(&original)
        .bounce_sender("mailer-daemon@corp.test")
        .bounced_recipient_info_list(
            t1::BouncedRecipientInfo::builder()
                .recipient("bob@corp.test")
                .bounce_type(t1::BounceType::DoesNotExist)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let mail = outbox(&mws, &format!("?id={}", bounce.message_id().unwrap())).await;
    assert_eq!(mail[0]["Kind"], "Bounce");
    assert_eq!(mail[0]["Destination"]["ToAddresses"][0], "sender@remote.test");
    assert!(mail[0]["RawData"].as_str().unwrap().contains("Status: 5.1.1"));
    ses.set_active_receipt_rule_set().send().await.unwrap();
    assert!(ses.describe_active_receipt_rule_set().send().await.unwrap().metadata().is_none());
}
