//! SES sending limits through the official Rust SDKs: the maximum send
//! rate (sandbox one message a second, production 14) and the production
//! access review that `PutAccountDetails` opens (pending for 24 hours on
//! the emulated clock, then granted; or denied through the MWS control
//! API).

use aws_sdk_ses::types as t1;
use aws_sdk_sesv2::types as t2;
use aws_smithy_types::retry::RetryConfig;
use mws_e2e::Mws;

async fn auto_verifying() -> Mws {
    Mws::start_with(mws::Config { ses_auto_verify: true, ..mws::Config::default() }).await
}

async fn clock(mws: &Mws, body: &str) {
    let (status, out) = mws.control("POST", "/_mws/clock", Some(body)).await;
    assert_eq!(status, 200, "{out}");
}

/// SES clients that report throttling instead of retrying it.
async fn clients(mws: &Mws) -> (aws_sdk_ses::Client, aws_sdk_sesv2::Client) {
    let cfg = mws.root_sdk_config().await;
    let v1 = aws_sdk_ses::Client::from_conf(
        aws_sdk_ses::config::Builder::from(&cfg).retry_config(RetryConfig::disabled()).build(),
    );
    let v2 = aws_sdk_sesv2::Client::from_conf(
        aws_sdk_sesv2::config::Builder::from(&cfg).retry_config(RetryConfig::disabled()).build(),
    );
    (v1, v2)
}

fn v1_message() -> t1::Message {
    t1::Message::builder()
        .subject(t1::Content::builder().data("rate").build().unwrap())
        .body(t1::Body::builder().text(t1::Content::builder().data("body").build().unwrap()).build())
        .build()
}

fn v2_content() -> t2::EmailContent {
    t2::EmailContent::builder()
        .simple(
            t2::Message::builder()
                .subject(t2::Content::builder().data("rate").build().unwrap())
                .body(t2::Body::builder().text(t2::Content::builder().data("body").build().unwrap()).build())
                .build(),
        )
        .build()
}

fn simulator(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("success+{i}@simulator.amazonses.com")).collect()
}

#[tokio::test]
async fn maximum_send_rate_is_enforced() {
    let mws = auto_verifying().await;
    let (v1, v2) = clients(&mws).await;
    v1.verify_email_identity().email_address("sender@rate.test").send().await.unwrap();

    let send_v1 = |to: Vec<String>| {
        v1.send_email()
            .source("sender@rate.test")
            .destination(t1::Destination::builder().set_to_addresses(Some(to)).build())
            .message(v1_message())
            .send()
    };
    let send_v2 = |to: Vec<String>| {
        v2.send_email()
            .from_email_address("sender@rate.test")
            .destination(t2::Destination::builder().set_to_addresses(Some(to)).build())
            .content(v2_content())
            .send()
    };

    // The sandbox sends one message a second.
    let quota = v1.get_send_quota().send().await.unwrap();
    assert_eq!(quota.max_send_rate(), 1.0);
    send_v1(simulator(1)).await.unwrap();
    let err = send_v1(simulator(1)).await.unwrap_err().into_service_error();
    assert_eq!(aws_sdk_ses::error::ProvideErrorMetadata::code(&err), Some("Throttling"));
    assert_eq!(aws_sdk_ses::error::ProvideErrorMetadata::message(&err), Some("Maximum sending rate exceeded."));
    let err = send_v2(simulator(1)).await.unwrap_err().into_service_error();
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::code(&err), Some("TooManyRequestsException"));
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::message(&err), Some("Maximum sending rate exceeded."));

    // A second later there is room again; a bulk send beyond the rate gets
    // ACCOUNT_THROTTLED for the entries that do not fit.
    clock(&mws, r#"{"advanceSeconds": 1}"#).await;
    v2.create_email_template()
        .template_name("t")
        .template_content(t2::EmailTemplateContent::builder().subject("hi").text("hello").build())
        .send()
        .await
        .unwrap();
    let bulk = v2
        .send_bulk_email()
        .from_email_address("sender@rate.test")
        .default_content(
            t2::BulkEmailContent::builder()
                .template(t2::Template::builder().template_name("t").template_data("{}").build())
                .build(),
        )
        .bulk_email_entries(
            t2::BulkEmailEntry::builder()
                .destination(t2::Destination::builder().to_addresses("success@simulator.amazonses.com").build())
                .build(),
        )
        .bulk_email_entries(
            t2::BulkEmailEntry::builder()
                .destination(t2::Destination::builder().to_addresses("success+b@simulator.amazonses.com").build())
                .build(),
        )
        .send()
        .await
        .unwrap();
    let statuses: Vec<&str> =
        bulk.bulk_email_entry_results().iter().map(|r| r.status().map(|s| s.as_str()).unwrap_or_default()).collect();
    assert_eq!(statuses, ["SUCCESS", "ACCOUNT_THROTTLED"]);

    // Production access: 14 recipients a second.
    let (status, _) = mws.control("POST", "/_aws/ses/production-access", None).await;
    assert_eq!(status, 200);
    clock(&mws, r#"{"advanceSeconds": 1}"#).await;
    let quota = v1.get_send_quota().send().await.unwrap();
    assert_eq!(quota.max_send_rate(), 14.0);
    send_v1(simulator(10)).await.unwrap();
    let err = send_v2(simulator(5)).await.unwrap_err().into_service_error();
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::code(&err), Some("TooManyRequestsException"));
    send_v2(simulator(4)).await.unwrap();
    clock(&mws, r#"{"offsetSeconds": 0}"#).await;
}

#[tokio::test]
async fn production_access_review_is_pending_then_granted() {
    let mws = auto_verifying().await;
    let (_, v2) = clients(&mws).await;

    v2.put_account_details()
        .mail_type(t2::MailType::Transactional)
        .website_url("https://shop.test")
        .use_case_description("Order receipts for customers who bought something.")
        .production_access_enabled(true)
        .send()
        .await
        .unwrap();
    let account = v2.get_account().send().await.unwrap();
    assert!(!account.production_access_enabled(), "the account stays in the sandbox while reviewed");
    let review = account.details().unwrap().review_details().unwrap();
    assert_eq!(review.status(), Some(&t2::ReviewStatus::Pending));
    let case_id = review.case_id().unwrap().to_string();
    assert_eq!(account.send_quota().unwrap().max24_hour_send(), 200.0);
    assert_eq!(account.send_quota().unwrap().max_send_rate(), 1.0);

    // Asking again while the case is open is a conflict.
    let err = v2
        .put_account_details()
        .mail_type(t2::MailType::Transactional)
        .website_url("https://shop.test")
        .production_access_enabled(true)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(aws_sdk_sesv2::error::ProvideErrorMetadata::code(&err), Some("ConflictException"));

    // Still pending after 23 hours; granted after 24.
    clock(&mws, r#"{"advanceSeconds": 82800}"#).await;
    let account = v2.get_account().send().await.unwrap();
    assert_eq!(account.details().unwrap().review_details().unwrap().status(), Some(&t2::ReviewStatus::Pending));
    clock(&mws, r#"{"advanceSeconds": 3600}"#).await;
    let account = v2.get_account().send().await.unwrap();
    assert!(account.production_access_enabled());
    let review = account.details().unwrap().review_details().unwrap();
    assert_eq!(review.status(), Some(&t2::ReviewStatus::Granted));
    assert_eq!(review.case_id(), Some(case_id.as_str()));
    assert_eq!(account.send_quota().unwrap().max24_hour_send(), 50000.0);
    assert_eq!(account.send_quota().unwrap().max_send_rate(), 14.0);
    clock(&mws, r#"{"offsetSeconds": 0}"#).await;
}

#[tokio::test]
async fn production_access_can_be_denied() {
    let mws = auto_verifying().await;
    let (_, v2) = clients(&mws).await;
    v2.put_account_details()
        .mail_type(t2::MailType::Marketing)
        .website_url("https://promo.test")
        .production_access_enabled(true)
        .send()
        .await
        .unwrap();
    let (status, body) = mws.control("POST", "/_aws/ses/production-access?status=DENIED", None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "DENIED");
    let account = v2.get_account().send().await.unwrap();
    assert!(!account.production_access_enabled());
    assert_eq!(account.details().unwrap().review_details().unwrap().status(), Some(&t2::ReviewStatus::Denied));

    // A denied account may ask again: a new review opens.
    v2.put_account_details()
        .mail_type(t2::MailType::Marketing)
        .website_url("https://promo.test")
        .production_access_enabled(true)
        .send()
        .await
        .unwrap();
    let account = v2.get_account().send().await.unwrap();
    assert_eq!(account.details().unwrap().review_details().unwrap().status(), Some(&t2::ReviewStatus::Pending));
}
