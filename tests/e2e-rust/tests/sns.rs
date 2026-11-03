//! SNS through the official Rust SDK: topics, subscriptions, filter
//! policies, FIFO, platform applications, SMS, and real deliveries to
//! Lambda functions and HTTP endpoints with verifiable signatures.

use std::io::Write;
use std::time::Duration;

use aws_sdk_sns::error::ProvideErrorMetadata;
use aws_sdk_sns::types::{LanguageCodeString, MessageAttributeValue, PublishBatchRequestEntry, Tag};
use aws_sdk_sns::Client;
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn message<E: ProvideErrorMetadata>(e: &E) -> String {
    e.message().unwrap_or_default().to_string()
}

fn attr(t: &str, v: &str) -> MessageAttributeValue {
    MessageAttributeValue::builder().data_type(t).string_value(v).build().unwrap()
}

async fn get_json(mws: &Mws, path: &str) -> serde_json::Value {
    let (status, _, body) = mws.raw("GET", path, &[], b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn topic_lifecycle_attributes_and_tags() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let created = sns
        .create_topic()
        .name("orders")
        .attributes("DisplayName", "Orders")
        .tags(Tag::builder().key("team").value("checkout").build().unwrap())
        .send()
        .await
        .unwrap();
    let arn = created.topic_arn().unwrap().to_string();
    assert_eq!(arn, "arn:aws:sns:us-east-1:123456789012:orders");
    // Idempotent for the same settings, an error for different ones.
    let again = sns.create_topic().name("orders").attributes("DisplayName", "Orders").send().await.unwrap();
    assert_eq!(again.topic_arn(), Some(arn.as_str()));
    let err = sns.create_topic().name("orders").attributes("DisplayName", "Other").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");
    let err = sns.create_topic().name("bad name!").send().await.unwrap_err();
    let err = err.into_service_error();
    assert_eq!(message(&err), "Invalid parameter: Topic Name");

    let attrs = sns.get_topic_attributes().topic_arn(&arn).send().await.unwrap();
    let attrs = attrs.attributes().unwrap();
    assert_eq!(attrs["DisplayName"], "Orders");
    assert_eq!(attrs["Owner"], "123456789012");
    assert_eq!(attrs["SubscriptionsConfirmed"], "0");
    let policy: serde_json::Value = serde_json::from_str(&attrs["Policy"]).unwrap();
    assert_eq!(policy["Id"], "__default_policy_ID");
    assert!(attrs["EffectiveDeliveryPolicy"].contains("defaultHealthyRetryPolicy"));

    sns.set_topic_attributes()
        .topic_arn(&arn)
        .attribute_name("DisplayName")
        .attribute_value("Renamed")
        .send()
        .await
        .unwrap();
    let err = sns
        .set_topic_attributes()
        .topic_arn(&arn)
        .attribute_name("FifoTopic")
        .attribute_value("true")
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err.into_service_error()), "Invalid parameter: AttributeName");
    let attrs = sns.get_topic_attributes().topic_arn(&arn).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["DisplayName"], "Renamed");

    let listed = sns.list_topics().send().await.unwrap();
    assert_eq!(listed.topics().len(), 1);
    assert_eq!(listed.topics()[0].topic_arn(), Some(arn.as_str()));

    sns.tag_resource()
        .resource_arn(&arn)
        .tags(Tag::builder().key("env").value("dev").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = sns.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 2);
    sns.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = sns.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().iter().map(|t| t.key()).collect::<Vec<_>>(), vec!["env"]);
    let err = sns
        .list_tags_for_resource()
        .resource_arn("arn:aws:sns:us-east-1:123456789012:missing")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ResourceNotFound");

    sns.delete_topic().topic_arn(&arn).send().await.unwrap();
    // DeleteTopic is idempotent.
    sns.delete_topic().topic_arn(&arn).send().await.unwrap();
    let err = sns.get_topic_attributes().topic_arn(&arn).send().await.unwrap_err();
    let err = err.into_service_error();
    assert_eq!(code(&err), "NotFound");
    assert_eq!(message(&err), "Topic does not exist");
}

#[tokio::test]
async fn permissions_and_data_protection_policies() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let arn = sns.create_topic().name("shared").send().await.unwrap().topic_arn().unwrap().to_string();
    sns.add_permission()
        .topic_arn(&arn)
        .label("partner")
        .aws_account_id("111122223333")
        .action_name("Publish")
        .action_name("Subscribe")
        .send()
        .await
        .unwrap();
    let attrs = sns.get_topic_attributes().topic_arn(&arn).send().await.unwrap();
    let policy: serde_json::Value = serde_json::from_str(&attrs.attributes().unwrap()["Policy"]).unwrap();
    let st = policy["Statement"].as_array().unwrap().iter().find(|s| s["Sid"] == "partner").unwrap().clone();
    assert_eq!(st["Principal"]["AWS"], "arn:aws:iam::111122223333:root");
    assert_eq!(st["Action"], serde_json::json!(["SNS:Publish", "SNS:Subscribe"]));
    let err = sns
        .add_permission()
        .topic_arn(&arn)
        .label("partner")
        .aws_account_id("111122223333")
        .action_name("Publish")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");
    sns.remove_permission().topic_arn(&arn).label("partner").send().await.unwrap();
    let attrs = sns.get_topic_attributes().topic_arn(&arn).send().await.unwrap();
    assert!(!attrs.attributes().unwrap()["Policy"].contains("partner"));

    let doc = serde_json::json!({
        "Name": "basic", "Description": "", "Version": "2021-06-01",
        "Statement": [{
            "Sid": "audit", "DataDirection": "Inbound", "Principal": ["*"],
            "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
            "Operation": { "Audit": { "SampleRate": "99", "FindingsDestination": {} } }
        }]
    })
    .to_string();
    sns.put_data_protection_policy().resource_arn(&arn).data_protection_policy(&doc).send().await.unwrap();
    let got = sns.get_data_protection_policy().resource_arn(&arn).send().await.unwrap();
    assert_eq!(got.data_protection_policy(), Some(doc.as_str()));
    let err =
        sns.put_data_protection_policy().resource_arn(&arn).data_protection_policy("{}").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");
}

#[tokio::test]
async fn publish_needs_permission_and_topic_policies_grant_it() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let arn = sns.create_topic().name("guarded").send().await.unwrap().topic_arn().unwrap().to_string();
    let (_, cfg) = user_with_policy(&mws, "nobody", None).await;
    let user = Client::new(&cfg);
    let err = user.publish().topic_arn(&arn).message("hi").send().await.unwrap_err();
    let err = err.into_service_error();
    assert_eq!(code(&err), "AuthorizationError");
    assert!(message(&err).contains("is not authorized to perform: sns:Publish"), "{}", message(&err));

    // A topic policy naming the user grants it without an identity policy.
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::123456789012:user/nobody" },
            "Action": "SNS:Publish",
            "Resource": arn
        }]
    });
    sns.set_topic_attributes()
        .topic_arn(&arn)
        .attribute_name("Policy")
        .attribute_value(policy.to_string())
        .send()
        .await
        .unwrap();
    user.publish().topic_arn(&arn).message("hi").send().await.unwrap();
    let err = user.get_topic_attributes().topic_arn(&arn).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "AuthorizationError");
}

#[tokio::test]
async fn subscriptions_confirmations_and_attributes() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let arn = sns.create_topic().name("alerts").send().await.unwrap().topic_arn().unwrap().to_string();

    // Email needs confirmation: the outbox has the confirmation mail.
    let pending = sns.subscribe().topic_arn(&arn).protocol("email").endpoint("ops@example.com").send().await.unwrap();
    assert_eq!(pending.subscription_arn(), Some("pending confirmation"));
    let mails = get_json(&mws, "/_aws/sns/email-messages?email=ops@example.com").await;
    let mail = &mails["emailMessages"][0];
    assert!(mail["subject"].as_str().unwrap().ends_with("Subscription Confirmation"));
    let listed = sns.list_subscriptions_by_topic().topic_arn(&arn).send().await.unwrap();
    assert_eq!(listed.subscriptions()[0].subscription_arn(), Some("PendingConfirmation"));

    // ReturnSubscriptionArn gives the real ARN of a pending subscription.
    let sub = sns
        .subscribe()
        .topic_arn(&arn)
        .protocol("email-json")
        .endpoint("bot@example.com")
        .return_subscription_arn(true)
        .send()
        .await
        .unwrap();
    let sub_arn = sub.subscription_arn().unwrap().to_string();
    assert!(sub_arn.starts_with(&format!("{arn}:")));
    let attrs = sns.get_subscription_attributes().subscription_arn(&sub_arn).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["PendingConfirmation"], "true");
    let token = get_json(&mws, &format!("/_aws/sns/subscription-tokens/{sub_arn}")).await;
    let token = token["subscriptionToken"].as_str().unwrap().to_string();
    let err = sns.confirm_subscription().topic_arn(&arn).token("nope").send().await.unwrap_err();
    assert_eq!(message(&err.into_service_error()), "Invalid parameter: Token");
    let confirmed = sns
        .confirm_subscription()
        .topic_arn(&arn)
        .token(&token)
        .authenticate_on_unsubscribe("true")
        .send()
        .await
        .unwrap();
    assert_eq!(confirmed.subscription_arn(), Some(sub_arn.as_str()));
    let attrs = sns.get_subscription_attributes().subscription_arn(&sub_arn).send().await.unwrap();
    let a = attrs.attributes().unwrap();
    assert_eq!(a["PendingConfirmation"], "false");
    assert_eq!(a["ConfirmationWasAuthenticated"], "true");
    assert_eq!(a["Protocol"], "email-json");

    // Attributes: filter policies are validated, raw delivery only for
    // some protocols.
    sns.set_subscription_attributes()
        .subscription_arn(&sub_arn)
        .attribute_name("FilterPolicy")
        .attribute_value(r#"{"level":["error"]}"#)
        .send()
        .await
        .unwrap();
    let err = sns
        .set_subscription_attributes()
        .subscription_arn(&sub_arn)
        .attribute_name("FilterPolicy")
        .attribute_value(r#"{"level":"error"}"#)
        .send()
        .await
        .unwrap_err();
    assert!(message(&err.into_service_error()).starts_with("Invalid parameter: FilterPolicy"));
    let err = sns
        .set_subscription_attributes()
        .subscription_arn(&sub_arn)
        .attribute_name("RawMessageDelivery")
        .attribute_value("true")
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(&err.into_service_error()),
        "Invalid parameter: Delivery protocol [email-json] does not support raw message delivery."
    );
    let attrs = sns.get_subscription_attributes().subscription_arn(&sub_arn).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["FilterPolicyScope"], "MessageAttributes");

    // Messages that pass the filter reach the mailbox.
    sns.publish()
        .topic_arn(&arn)
        .message("disk full")
        .subject("Alarm")
        .message_attributes("level", attr("String", "error"))
        .send()
        .await
        .unwrap();
    sns.publish()
        .topic_arn(&arn)
        .message("all good")
        .message_attributes("level", attr("String", "info"))
        .send()
        .await
        .unwrap();
    let mails = get_json(&mws, "/_aws/sns/email-messages?email=bot@example.com").await;
    let mails = mails["emailMessages"].as_array().unwrap();
    assert_eq!(mails.len(), 2, "confirmation + one notification: {mails:?}");
    let body: serde_json::Value = serde_json::from_str(mails[1]["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["Type"], "Notification");
    assert_eq!(body["Message"], "disk full");
    assert_eq!(body["Subject"], "Alarm");
    assert_eq!(body["MessageAttributes"]["level"]["Value"], "error");

    let all = sns.list_subscriptions().send().await.unwrap();
    assert_eq!(all.subscriptions().len(), 2);
    sns.unsubscribe().subscription_arn(&sub_arn).send().await.unwrap();
    let err = sns.unsubscribe().subscription_arn(&sub_arn).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "NotFound");
    let attrs = sns.get_topic_attributes().topic_arn(&arn).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["SubscriptionsDeleted"], "1");
    assert_eq!(attrs.attributes().unwrap()["SubscriptionsPending"], "1");
}

#[tokio::test]
async fn subscribe_validates_protocols_and_endpoints() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let arn = sns.create_topic().name("v").send().await.unwrap().topic_arn().unwrap().to_string();
    let err = sns.subscribe().topic_arn(&arn).protocol("pigeon").endpoint("x").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");
    let err = sns.subscribe().topic_arn(&arn).protocol("sqs").endpoint("not-an-arn").send().await.unwrap_err();
    assert_eq!(message(&err.into_service_error()), "Invalid parameter: SQS endpoint ARN");
    let err =
        sns.subscribe().topic_arn(&arn).protocol("http").endpoint("https://example.com").send().await.unwrap_err();
    assert_eq!(message(&err.into_service_error()), "Invalid parameter: Endpoint must match the specified protocol");
    let err = sns
        .subscribe()
        .topic_arn("arn:aws:sns:us-east-1:123456789012:nope")
        .protocol("email")
        .endpoint("a@example.com")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "NotFound");
}

#[tokio::test]
async fn publish_validation_batches_and_fifo() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let arn = sns.create_topic().name("std").send().await.unwrap().topic_arn().unwrap().to_string();
    let out = sns.publish().topic_arn(&arn).message("hello").send().await.unwrap();
    assert_eq!(out.message_id().unwrap().len(), 36);
    let err = sns.publish().topic_arn(&arn).message("{}").message_structure("json").send().await.unwrap_err();
    assert_eq!(
        message(&err.into_service_error()),
        "Invalid parameter: Message Structure - No default entry in JSON message body"
    );
    let err = sns.publish().topic_arn(&arn).message("x".repeat(262_145)).send().await.unwrap_err();
    assert_eq!(message(&err.into_service_error()), "Invalid parameter: Message too long");
    let err = sns
        .publish()
        .topic_arn(&arn)
        .message("x")
        .message_attributes("n", attr("Number", "abc"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ParameterValueInvalid");
    let err = sns.publish().topic_arn(&arn).message("x").message_deduplication_id("d").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");

    let entry = |id: &str, msg: &str| PublishBatchRequestEntry::builder().id(id).message(msg).build().unwrap();
    let batch = sns
        .publish_batch()
        .topic_arn(&arn)
        .publish_batch_request_entries(entry("a", "one"))
        .publish_batch_request_entries(entry("b", ""))
        .send()
        .await
        .unwrap();
    assert_eq!(batch.successful().len(), 1);
    assert_eq!(batch.failed()[0].id(), "b");
    assert_eq!(batch.failed()[0].code(), "InvalidParameter");
    assert!(batch.failed()[0].sender_fault());
    let err = sns
        .publish_batch()
        .topic_arn(&arn)
        .publish_batch_request_entries(entry("a", "one"))
        .publish_batch_request_entries(entry("a", "two"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "BatchEntryIdsNotDistinct");

    // FIFO topics need group ids and deduplicate.
    let fifo = sns
        .create_topic()
        .name("events.fifo")
        .attributes("FifoTopic", "true")
        .attributes("ContentBasedDeduplication", "true")
        .send()
        .await
        .unwrap()
        .topic_arn()
        .unwrap()
        .to_string();
    let err = sns.create_topic().name("nofifo").attributes("FifoTopic", "true").send().await.unwrap_err();
    assert_eq!(message(&err.into_service_error()), "Invalid parameter: Topic Name");
    let err = sns.publish().topic_arn(&fifo).message("m").send().await.unwrap_err();
    assert_eq!(
        message(&err.into_service_error()),
        "Invalid parameter: The MessageGroupId parameter is required for FIFO topics"
    );
    let first = sns.publish().topic_arn(&fifo).message("m").message_group_id("g").send().await.unwrap();
    let dup = sns.publish().topic_arn(&fifo).message("m").message_group_id("g").send().await.unwrap();
    assert_eq!(first.message_id(), dup.message_id());
    let next = sns.publish().topic_arn(&fifo).message("n").message_group_id("g").send().await.unwrap();
    let a: u128 = first.sequence_number().unwrap().parse().unwrap();
    let b: u128 = next.sequence_number().unwrap().parse().unwrap();
    assert!(b > a);
    let attrs = sns.get_topic_attributes().topic_arn(&fifo).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["FifoTopic"], "true");
    let err = sns.subscribe().topic_arn(&fifo).protocol("email").endpoint("a@example.com").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");
}

#[tokio::test]
async fn platform_applications_and_endpoints() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let app = sns
        .create_platform_application()
        .name("mobile")
        .platform("GCM")
        .attributes("PlatformCredential", "server-key")
        .send()
        .await
        .unwrap();
    let app_arn = app.platform_application_arn().unwrap().to_string();
    assert_eq!(app_arn, "arn:aws:sns:us-east-1:123456789012:app/GCM/mobile");
    let err = sns
        .create_platform_application()
        .name("x")
        .platform("PIGEON")
        .attributes("PlatformCredential", "k")
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(&err.into_service_error()), "Invalid parameter: Platform");
    let attrs = sns.get_platform_application_attributes().platform_application_arn(&app_arn).send().await.unwrap();
    let attrs = attrs.attributes().unwrap();
    assert_eq!(attrs["Enabled"], "true");
    assert!(!attrs.contains_key("PlatformCredential"));
    sns.set_platform_application_attributes()
        .platform_application_arn(&app_arn)
        .attributes("SuccessFeedbackSampleRate", "50")
        .send()
        .await
        .unwrap();
    let apps = sns.list_platform_applications().send().await.unwrap();
    assert_eq!(apps.platform_applications()[0].attributes().unwrap()["SuccessFeedbackSampleRate"], "50");

    let ep = sns
        .create_platform_endpoint()
        .platform_application_arn(&app_arn)
        .token("device-token-1")
        .custom_user_data("user-1")
        .send()
        .await
        .unwrap();
    let ep_arn = ep.endpoint_arn().unwrap().to_string();
    assert!(ep_arn.starts_with("arn:aws:sns:us-east-1:123456789012:endpoint/GCM/mobile/"));
    // Same token and attributes: same endpoint. Different data: an error.
    let again = sns
        .create_platform_endpoint()
        .platform_application_arn(&app_arn)
        .token("device-token-1")
        .custom_user_data("user-1")
        .send()
        .await
        .unwrap();
    assert_eq!(again.endpoint_arn(), Some(ep_arn.as_str()));
    let err = sns
        .create_platform_endpoint()
        .platform_application_arn(&app_arn)
        .token("device-token-1")
        .custom_user_data("other")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");

    let out = sns
        .publish()
        .target_arn(&ep_arn)
        .message_structure("json")
        .message(r#"{"default":"plain","GCM":"{\"notification\":{\"title\":\"hi\"}}"}"#)
        .send()
        .await
        .unwrap();
    let pushed = get_json(&mws, &format!("/_aws/sns/platform-endpoint-messages?endpointArn={ep_arn}")).await;
    let pushed = &pushed["platformEndpointMessages"][0];
    assert_eq!(pushed["messageId"], out.message_id().unwrap());
    assert_eq!(pushed["message"], r#"{"notification":{"title":"hi"}}"#);
    assert_eq!(pushed["token"], "device-token-1");

    sns.set_endpoint_attributes().endpoint_arn(&ep_arn).attributes("Enabled", "false").send().await.unwrap();
    let attrs = sns.get_endpoint_attributes().endpoint_arn(&ep_arn).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["Enabled"], "false");
    assert_eq!(attrs.attributes().unwrap()["CustomUserData"], "user-1");
    let err = sns.publish().target_arn(&ep_arn).message("x").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "EndpointDisabled");

    let eps = sns.list_endpoints_by_platform_application().platform_application_arn(&app_arn).send().await.unwrap();
    assert_eq!(eps.endpoints().len(), 1);
    sns.delete_endpoint().endpoint_arn(&ep_arn).send().await.unwrap();
    let err = sns.get_endpoint_attributes().endpoint_arn(&ep_arn).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "NotFound");
    sns.delete_platform_application().platform_application_arn(&app_arn).send().await.unwrap();
    let err = sns.get_platform_application_attributes().platform_application_arn(&app_arn).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "NotFound");
}

#[tokio::test]
async fn sms_settings_opt_outs_and_sandbox() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    sns.set_sms_attributes()
        .attributes("DefaultSMSType", "Transactional")
        .attributes("DefaultSenderID", "MWS")
        .send()
        .await
        .unwrap();
    let got = sns.get_sms_attributes().attributes("DefaultSMSType").send().await.unwrap();
    assert_eq!(got.attributes().unwrap().len(), 1);
    assert_eq!(got.attributes().unwrap()["DefaultSMSType"], "Transactional");
    let err = sns.set_sms_attributes().attributes("DefaultSMSType", "Spam").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");

    sns.publish().phone_number("+15555550100").message("your code is 1").send().await.unwrap();
    let sms = get_json(&mws, "/_aws/sns/sms-messages?phoneNumber=%2B15555550100").await;
    assert_eq!(sms["smsMessages"][0]["message"], "your code is 1");
    assert_eq!(sms["smsMessages"][0]["senderId"], "MWS");
    let err = sns.publish().phone_number("555").message("x").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "InvalidParameter");

    let out = sns.check_if_phone_number_is_opted_out().phone_number("+15555550101").send().await.unwrap();
    assert!(!out.is_opted_out());
    let (status, _, _) = mws.raw("POST", "/_aws/sns/sms-opt-out?phoneNumber=%2B15555550101", &[], b"").await;
    assert_eq!(status, 200);
    let out = sns.check_if_phone_number_is_opted_out().phone_number("+15555550101").send().await.unwrap();
    assert!(out.is_opted_out());
    let listed = sns.list_phone_numbers_opted_out().send().await.unwrap();
    assert_eq!(listed.phone_numbers(), ["+15555550101"]);
    sns.opt_in_phone_number().phone_number("+15555550101").send().await.unwrap();
    let listed = sns.list_phone_numbers_opted_out().send().await.unwrap();
    assert!(listed.phone_numbers().is_empty());

    let status = sns.get_sms_sandbox_account_status().send().await.unwrap();
    assert!(!status.is_in_sandbox());
    sns.create_sms_sandbox_phone_number()
        .phone_number("+15555550102")
        .language_code(LanguageCodeString::EnUs)
        .send()
        .await
        .unwrap();
    let listed = sns.list_sms_sandbox_phone_numbers().send().await.unwrap();
    assert_eq!(listed.phone_numbers()[0].status().map(|s| s.as_str()), Some("Pending"));
    let sms = get_json(&mws, "/_aws/sns/sms-messages?phoneNumber=%2B15555550102").await;
    let text = sms["smsMessages"][0]["message"].as_str().unwrap().to_string();
    let otp = text.rsplit(' ').next().unwrap();
    let wrong = if otp == "000000" { "111111" } else { "000000" };
    let err = sns
        .verify_sms_sandbox_phone_number()
        .phone_number("+15555550102")
        .one_time_password(wrong)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "VerificationException");
    sns.verify_sms_sandbox_phone_number().phone_number("+15555550102").one_time_password(otp).send().await.unwrap();
    let listed = sns.list_sms_sandbox_phone_numbers().send().await.unwrap();
    assert_eq!(listed.phone_numbers()[0].status().map(|s| s.as_str()), Some("Verified"));
    sns.delete_sms_sandbox_phone_number().phone_number("+15555550102").send().await.unwrap();
    let err = sns.delete_sms_sandbox_phone_number().phone_number("+15555550102").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ResourceNotFound");

    let numbers = sns.list_origination_numbers().send().await.unwrap();
    assert!(numbers.phone_numbers().is_empty());
}

// ---- deliveries ------------------------------------------------------------

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

const RECORDER: &str = r#"
import json, os

def handler(event, context):
    with open(os.environ["OUT"], "a") as f:
        f.write(json.dumps(event) + "\n")
    return {}
"#;

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        for (name, body) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

async fn wait_for_lines(path: &std::path::Path, n: usize) -> Vec<serde_json::Value> {
    for _ in 0..200 {
        if let Ok(text) = std::fs::read_to_string(path) {
            let lines: Vec<serde_json::Value> =
                text.lines().filter(|l| !l.is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect();
            if lines.len() >= n {
                return lines;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{} never got {n} lines", path.display());
}

#[tokio::test]
async fn lambda_subscriptions_get_the_sns_event_when_the_function_policy_allows() {
    use aws_sdk_lambda::primitives::Blob;
    use aws_sdk_lambda::types::{Environment, FunctionCode, Runtime};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam.create_role().role_name("sns-fn").assume_role_policy_document(TRUST).send().await.unwrap();
    let out = std::env::temp_dir().join(format!("mws-sns-{}.jsonl", uuid_like()));
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let f = lambda
        .create_function()
        .function_name("recorder")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .environment(Environment::builder().variables("OUT", out.to_string_lossy()).build())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", RECORDER)]))).build())
        .send()
        .await
        .unwrap();
    let fn_arn = f.function_arn().unwrap().to_string();
    let sns = Client::new(&cfg);
    let topic = sns.create_topic().name("to-lambda").send().await.unwrap().topic_arn().unwrap().to_string();
    let sub = sns.subscribe().topic_arn(&topic).protocol("lambda").endpoint(&fn_arn).send().await.unwrap();
    let sub_arn = sub.subscription_arn().unwrap().to_string();
    assert!(sub_arn.starts_with(&topic));

    // Without a function policy SNS may not invoke the function.
    sns.publish().topic_arn(&topic).message("dropped").send().await.unwrap();
    lambda
        .add_permission()
        .function_name("recorder")
        .statement_id("sns")
        .action("lambda:InvokeFunction")
        .principal("sns.amazonaws.com")
        .source_arn(&topic)
        .send()
        .await
        .unwrap();
    sns.publish()
        .topic_arn(&topic)
        .message("delivered")
        .subject("Hello")
        .message_attributes("kind", attr("String", "greeting"))
        .send()
        .await
        .unwrap();
    let events = wait_for_lines(&out, 1).await;
    let _ = std::fs::remove_file(&out);
    assert_eq!(events.len(), 1, "{events:?}");
    let record = &events[0]["Records"][0];
    assert_eq!(record["EventSource"], "aws:sns");
    assert_eq!(record["EventSubscriptionArn"], sub_arn);
    let msg = &record["Sns"];
    assert_eq!(msg["Type"], "Notification");
    assert_eq!(msg["Message"], "delivered");
    assert_eq!(msg["Subject"], "Hello");
    assert_eq!(msg["TopicArn"], topic);
    assert_eq!(msg["MessageAttributes"]["kind"]["Type"], "String");
    assert_eq!(msg["MessageAttributes"]["kind"]["Value"], "greeting");
    assert!(msg["SigningCertUrl"].as_str().unwrap().starts_with(&mws.endpoint));
}

fn uuid_like() -> String {
    format!("{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap())
}

/// A local HTTP endpoint that records the requests it gets.
async fn http_endpoint() -> (String, tokio::sync::mpsc::UnboundedReceiver<(Vec<(String, String)>, String)>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}/hook", listener.local_addr().unwrap().port());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&raw[..split]).to_string();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if raw.len() >= split + 4 + len {
                            let headers = head
                                .lines()
                                .skip(1)
                                .filter_map(|l| l.split_once(':'))
                                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                                .collect();
                            let body = String::from_utf8_lossy(&raw[split + 4..split + 4 + len]).to_string();
                            let _ = tx.send((headers, body));
                            let _ =
                                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                            break;
                        }
                    }
                }
            });
        }
    });
    (url, rx)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or("")
}

/// Check an SNS message signature with the certificate SNS serves.
async fn verify_signature(mws: &Mws, msg: &serde_json::Value, fields: &[&str]) {
    use x509_parser::prelude::*;
    let cert_url = msg["SigningCertURL"].as_str().unwrap();
    let (status, _, pem) = mws.raw("GET", cert_url, &[], b"").await;
    assert_eq!(status, 200);
    let (_, pem) = parse_x509_pem(&pem).unwrap();
    let cert = pem.parse_x509().unwrap();
    let key = cert.public_key().subject_public_key.data.to_vec();
    let mut text = String::new();
    for f in fields {
        if let Some(v) = msg[*f].as_str() {
            text.push_str(&format!("{f}\n{v}\n"));
        }
    }
    let sig = base64::engine::general_purpose::STANDARD.decode(msg["Signature"].as_str().unwrap()).unwrap();
    let alg: &dyn aws_lc_rs::signature::VerificationAlgorithm = if msg["SignatureVersion"] == "2" {
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256
    } else {
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY
    };
    aws_lc_rs::signature::UnparsedPublicKey::new(alg, key).verify(text.as_bytes(), &sig).expect("signature verifies");
}

#[tokio::test]
async fn http_subscriptions_confirm_through_the_subscribe_url_and_get_signed_notifications() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let (url, mut rx) = http_endpoint().await;
    let topic = sns
        .create_topic()
        .name("webhooks")
        .attributes("SignatureVersion", "2")
        .send()
        .await
        .unwrap()
        .topic_arn()
        .unwrap()
        .to_string();
    sns.subscribe().topic_arn(&topic).protocol("http").endpoint(&url).send().await.unwrap();
    let (headers, body) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.unwrap().unwrap();
    assert_eq!(header(&headers, "x-amz-sns-message-type"), "SubscriptionConfirmation");
    assert_eq!(header(&headers, "x-amz-sns-topic-arn"), topic);
    let confirmation: serde_json::Value = serde_json::from_str(&body).unwrap();
    verify_signature(
        &mws,
        &confirmation,
        &["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"],
    )
    .await;
    // Visiting the SubscribeURL (unsigned, as a browser would) confirms.
    let (status, _, body) = mws.raw("GET", confirmation["SubscribeURL"].as_str().unwrap(), &[], b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8_lossy(&body).contains("<ConfirmSubscriptionResult>"));

    sns.publish().topic_arn(&topic).message("ping").subject("S").send().await.unwrap();
    let (headers, body) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.unwrap().unwrap();
    assert_eq!(header(&headers, "x-amz-sns-message-type"), "Notification");
    assert_eq!(header(&headers, "user-agent"), "Amazon Simple Notification Service Agent");
    let note: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(note["Message"], "ping");
    assert_eq!(note["SignatureVersion"], "2");
    verify_signature(&mws, &note, &["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]).await;

    // Raw delivery posts the message itself.
    let sub_arn = header(&headers, "x-amz-sns-subscription-arn").to_string();
    sns.set_subscription_attributes()
        .subscription_arn(&sub_arn)
        .attribute_name("RawMessageDelivery")
        .attribute_value("true")
        .send()
        .await
        .unwrap();
    sns.publish().topic_arn(&topic).message("raw body").send().await.unwrap();
    let (headers, body) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.unwrap().unwrap();
    assert_eq!(body, "raw body");
    assert_eq!(header(&headers, "x-amz-sns-rawdelivery"), "true");

    // The UnsubscribeURL works unsigned too.
    let (status, _, _) = mws
        .raw("GET", &format!("/?Action=Unsubscribe&SubscriptionArn={}", urlencoding::encode(&sub_arn)), &[], b"")
        .await;
    assert_eq!(status, 200);
    let subs = sns.list_subscriptions_by_topic().topic_arn(&topic).send().await.unwrap();
    assert!(subs.subscriptions().is_empty());
}

#[tokio::test]
async fn sns_state_survives_export_and_import() {
    let mws = Mws::start().await;
    let sns = client(&mws).await;
    let arn = sns.create_topic().name("kept").send().await.unwrap().topic_arn().unwrap().to_string();
    sns.subscribe().topic_arn(&arn).protocol("sms").endpoint("+15555550199").send().await.unwrap();
    let (status, state) = mws.control("GET", "/_mws/state", None).await;
    assert_eq!(status, 200);
    let (status, _) = mws.control("POST", "/_mws/reset", None).await;
    assert_eq!(status, 200);
    assert!(sns.list_topics().send().await.unwrap().topics().is_empty());
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&state.to_string())).await;
    assert_eq!(status, 200, "{state}");
    assert_eq!(sns.list_topics().send().await.unwrap().topics().len(), 1);
    assert_eq!(sns.list_subscriptions().send().await.unwrap().subscriptions().len(), 1);
}

#[tokio::test]
async fn s3_event_notifications_publish_to_topics_the_topic_policy_opens() {
    use aws_sdk_s3::types::{
        Event, FilterRule, FilterRuleName, NotificationConfiguration, NotificationConfigurationFilter, S3KeyFilter,
        TopicConfiguration,
    };
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("uploads").send().await.unwrap();
    let topic = sns.create_topic().name("s3-events").send().await.unwrap().topic_arn().unwrap().to_string();
    sns.subscribe().topic_arn(&topic).protocol("sms").endpoint("+15555550150").send().await.unwrap();
    let config = |events: Event| {
        NotificationConfiguration::builder()
            .topic_configurations(
                TopicConfiguration::builder()
                    .id("images")
                    .topic_arn(&topic)
                    .events(events)
                    .filter(
                        NotificationConfigurationFilter::builder()
                            .key(
                                S3KeyFilter::builder()
                                    .filter_rules(
                                        FilterRule::builder().name(FilterRuleName::Prefix).value("img/").build(),
                                    )
                                    .filter_rules(
                                        FilterRule::builder().name(FilterRuleName::Suffix).value(".png").build(),
                                    )
                                    .build(),
                            )
                            .build(),
                    )
                    .build()
                    .unwrap(),
            )
            .build()
    };
    // The default topic policy does not let S3 publish.
    let err = s3
        .put_bucket_notification_configuration()
        .bucket("uploads")
        .notification_configuration(config(Event::S3ObjectCreated))
        .send()
        .await
        .unwrap_err();
    let err = err.into_service_error();
    assert_eq!(err.meta().code(), Some("InvalidArgument"));
    assert_eq!(err.meta().message(), Some("Unable to validate the following destination configurations"));

    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": "s3.amazonaws.com" },
            "Action": "SNS:Publish",
            "Resource": topic,
            "Condition": { "ArnLike": { "aws:SourceArn": "arn:aws:s3:::uploads" } }
        }]
    });
    sns.set_topic_attributes()
        .topic_arn(&topic)
        .attribute_name("Policy")
        .attribute_value(policy.to_string())
        .send()
        .await
        .unwrap();
    s3.put_bucket_notification_configuration()
        .bucket("uploads")
        .notification_configuration(config(Event::S3ObjectCreated))
        .send()
        .await
        .unwrap();
    let got = s3.get_bucket_notification_configuration().bucket("uploads").send().await.unwrap();
    assert_eq!(got.topic_configurations()[0].id(), Some("images"));

    s3.put_object().bucket("uploads").key("img/cat.png").body(b"meow".to_vec().into()).send().await.unwrap();
    s3.put_object().bucket("uploads").key("docs/readme.txt").body(b"skip".to_vec().into()).send().await.unwrap();
    let sms = get_json(&mws, "/_aws/sns/sms-messages?phoneNumber=%2B15555550150").await;
    let sms = sms["smsMessages"].as_array().unwrap();
    assert_eq!(sms.len(), 2, "test event + one object event: {sms:?}");
    let test: serde_json::Value = serde_json::from_str(sms[0]["message"].as_str().unwrap()).unwrap();
    assert_eq!(test["Event"], "s3:TestEvent");
    assert_eq!(test["Bucket"], "uploads");
    let event: serde_json::Value = serde_json::from_str(sms[1]["message"].as_str().unwrap()).unwrap();
    let record = &event["Records"][0];
    assert_eq!(record["eventSource"], "aws:s3");
    assert_eq!(record["eventName"], "ObjectCreated:Put");
    assert_eq!(record["s3"]["configurationId"], "images");
    assert_eq!(record["s3"]["bucket"]["arn"], "arn:aws:s3:::uploads");
    assert_eq!(record["s3"]["object"]["key"], "img/cat.png");
    assert_eq!(record["s3"]["object"]["size"], 4);

    // Overlapping rules are refused.
    let overlapping = NotificationConfiguration::builder()
        .topic_configurations(
            TopicConfiguration::builder().topic_arn(&topic).events(Event::S3ObjectCreated).build().unwrap(),
        )
        .topic_configurations(
            TopicConfiguration::builder().topic_arn(&topic).events(Event::S3ObjectCreatedPut).build().unwrap(),
        )
        .build();
    let err = s3
        .put_bucket_notification_configuration()
        .bucket("uploads")
        .notification_configuration(overlapping)
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        err.into_service_error().meta().message(),
        Some("Configurations overlap. Configurations on the same bucket cannot share a common event type.")
    );
}

#[tokio::test]
async fn s3_event_notifications_invoke_functions() {
    use aws_sdk_lambda::primitives::Blob;
    use aws_sdk_lambda::types::{Environment, FunctionCode, Runtime};
    use aws_sdk_s3::types::{Event, LambdaFunctionConfiguration, NotificationConfiguration};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let role = iam.create_role().role_name("s3-fn").assume_role_policy_document(TRUST).send().await.unwrap();
    let out = std::env::temp_dir().join(format!("mws-s3-{}.jsonl", uuid_like()));
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let f = lambda
        .create_function()
        .function_name("on-upload")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .environment(Environment::builder().variables("OUT", out.to_string_lossy()).build())
        .code(FunctionCode::builder().zip_file(Blob::new(zip(&[("app.py", RECORDER)]))).build())
        .send()
        .await
        .unwrap();
    let fn_arn = f.function_arn().unwrap().to_string();
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("inbox").send().await.unwrap();
    let config = NotificationConfiguration::builder()
        .lambda_function_configurations(
            LambdaFunctionConfiguration::builder()
                .lambda_function_arn(&fn_arn)
                .events(Event::S3ObjectRemoved)
                .build()
                .unwrap(),
        )
        .build();
    let err = s3
        .put_bucket_notification_configuration()
        .bucket("inbox")
        .notification_configuration(config.clone())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("InvalidArgument"));
    lambda
        .add_permission()
        .function_name("on-upload")
        .statement_id("s3")
        .action("lambda:InvokeFunction")
        .principal("s3.amazonaws.com")
        .source_arn("arn:aws:s3:::inbox")
        .send()
        .await
        .unwrap();
    s3.put_bucket_notification_configuration().bucket("inbox").notification_configuration(config).send().await.unwrap();
    s3.put_object().bucket("inbox").key("a b.txt").body(b"x".to_vec().into()).send().await.unwrap();
    s3.delete_object().bucket("inbox").key("a b.txt").send().await.unwrap();
    let events = wait_for_lines(&out, 1).await;
    let _ = std::fs::remove_file(&out);
    assert_eq!(events.len(), 1, "{events:?}");
    let record = &events[0]["Records"][0];
    assert_eq!(record["eventName"], "ObjectRemoved:Delete");
    assert_eq!(record["s3"]["object"]["key"], "a+b.txt");
}

#[tokio::test]
async fn sqs_subscriptions_get_envelopes_or_raw_messages_and_s3_events_reach_queues() {
    use aws_sdk_s3::types::{Event, NotificationConfiguration, QueueConfiguration};
    use aws_sdk_sqs::types::QueueAttributeName;
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    let topic = sns.create_topic().name("fanout").send().await.unwrap().topic_arn().unwrap().to_string();
    let mut queues = Vec::new();
    for name in ["enveloped", "raw"] {
        let url = sqs.create_queue().queue_name(name).send().await.unwrap().queue_url().unwrap().to_string();
        let arn = format!("arn:aws:sqs:us-east-1:123456789012:{name}");
        let policy = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": ["sns.amazonaws.com", "s3.amazonaws.com"]},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}
            }]
        });
        sqs.set_queue_attributes()
            .queue_url(&url)
            .attributes(QueueAttributeName::Policy, policy.to_string())
            .send()
            .await
            .unwrap();
        queues.push((url, arn));
    }
    let sub = |arn: &str, raw: bool| {
        let s = sns.subscribe().topic_arn(&topic).protocol("sqs").endpoint(arn);
        if raw {
            s.attributes("RawMessageDelivery", "true")
        } else {
            s
        }
    };
    let enveloped = sub(&queues[0].1, false).send().await.unwrap();
    assert!(enveloped.subscription_arn().unwrap().starts_with(&topic));
    sub(&queues[1].1, true).send().await.unwrap();

    sns.publish()
        .topic_arn(&topic)
        .subject("hello")
        .message("payload")
        .message_attributes("kind", attr("String", "greeting"))
        .send()
        .await
        .unwrap();

    let receive = |url: &str| sqs.receive_message().queue_url(url).message_attribute_names("All").wait_time_seconds(2);
    let got = receive(&queues[0].0).send().await.unwrap();
    let m = &got.messages()[0];
    let envelope: serde_json::Value = serde_json::from_str(m.body().unwrap()).unwrap();
    assert_eq!(envelope["Type"], "Notification");
    assert_eq!(envelope["TopicArn"], topic.as_str());
    assert_eq!(envelope["Subject"], "hello");
    assert_eq!(envelope["Message"], "payload");
    assert_eq!(envelope["MessageAttributes"]["kind"]["Value"], "greeting");
    verify_signature(&mws, &envelope, &["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]).await;

    let got = receive(&queues[1].0).send().await.unwrap();
    let m = &got.messages()[0];
    assert_eq!(m.body(), Some("payload"));
    assert_eq!(m.message_attributes().unwrap()["kind"].string_value(), Some("greeting"));

    // S3 sends its events straight to a queue whose policy lets it.
    s3.create_bucket().bucket("drops").send().await.unwrap();
    let missing = "arn:aws:sqs:us-east-1:123456789012:missing";
    for arn in [missing, queues[1].1.as_str()] {
        let put = s3
            .put_bucket_notification_configuration()
            .bucket("drops")
            .notification_configuration(
                NotificationConfiguration::builder()
                    .queue_configurations(
                        QueueConfiguration::builder().queue_arn(arn).events(Event::S3ObjectCreated).build().unwrap(),
                    )
                    .build(),
            )
            .send()
            .await;
        if arn == missing {
            assert_eq!(put.unwrap_err().into_service_error().meta().code(), Some("InvalidArgument"));
        } else {
            put.unwrap();
        }
    }
    // The configuration's test event comes first.
    let got = receive(&queues[1].0).send().await.unwrap();
    let test: serde_json::Value = serde_json::from_str(got.messages()[0].body().unwrap()).unwrap();
    assert_eq!(test["Event"], "s3:TestEvent");
    assert_eq!(test["Bucket"], "drops");
    sqs.delete_message()
        .queue_url(&queues[1].0)
        .receipt_handle(got.messages()[0].receipt_handle().unwrap())
        .send()
        .await
        .unwrap();

    s3.put_object().bucket("drops").key("a b.txt").body(b"x".to_vec().into()).send().await.unwrap();
    let got = receive(&queues[1].0).send().await.unwrap();
    let event: serde_json::Value = serde_json::from_str(got.messages()[0].body().unwrap()).unwrap();
    let record = &event["Records"][0];
    assert_eq!(record["eventName"], "ObjectCreated:Put");
    assert_eq!(record["s3"]["bucket"]["name"], "drops");
    assert_eq!(record["s3"]["object"]["key"], "a+b.txt");
}
