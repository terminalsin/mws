//! AWS Marketplace Metering and Entitlement Service through the official
//! Rust SDKs, against a catalog seeded through `/_aws/marketplace/`: SaaS
//! registration (ResolveCustomer), entitlements, BatchMeterUsage, and
//! MeterUsage/RegisterUsage from a buyer's own account.

use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PSS_2048_8192_SHA256};
use aws_sdk_marketplaceentitlement::types::GetEntitlementFilterName;
use aws_sdk_marketplaceentitlement::Client as Entitlements;
use aws_sdk_marketplacemetering::error::ProvideErrorMetadata;
use aws_sdk_marketplacemetering::primitives::DateTime;
use aws_sdk_marketplacemetering::types::{Tag, UsageAllocation, UsageRecord, UsageRecordResultStatus};
use aws_sdk_marketplacemetering::Client as Metering;
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};
use serde_json::{json, Value};

const SELLER: &str = "123456789012";
const BUYER: &str = "111122223333";

fn err_code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn post(mws: &Mws, path: &str, body: Value) -> Value {
    let (status, out) = mws.control("POST", path, Some(&body.to_string())).await;
    assert_eq!(status, 200, "{path}: {out}");
    out
}

async fn product(mws: &Mws, product_type: &str, dims: &[&str]) -> String {
    let dims: Vec<Value> = dims.iter().map(|d| json!({ "name": d })).collect();
    let out = post(
        mws,
        "/_aws/marketplace/products",
        json!({ "sellerAccountId": SELLER, "productType": product_type, "dimensions": dims }),
    )
    .await;
    let code = out["productCode"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 25);
    code
}

fn now() -> DateTime {
    DateTime::from_secs(chrono::Utc::now().timestamp())
}

fn hours_ago(h: i64) -> DateTime {
    DateTime::from_secs(chrono::Utc::now().timestamp() - h * 3600)
}

fn record(customer: &str, dimension: &str, quantity: i32, at: DateTime) -> UsageRecord {
    UsageRecord::builder()
        .customer_identifier(customer)
        .dimension(dimension)
        .quantity(quantity)
        .timestamp(at)
        .build()
        .unwrap()
}

#[tokio::test]
async fn saas_registration_entitlements_and_batch_metering() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let metering = Metering::new(&cfg);
    let entitlements = Entitlements::new(&cfg);
    let code = product(&mws, "SaaS", &["users", "requests", "tier"]).await;

    let sub = post(
        &mws,
        "/_aws/marketplace/subscriptions",
        json!({
            "productCode": code,
            "customerAWSAccountId": BUYER,
            "entitlements": [
                { "dimension": "users", "value": { "integerValue": 25 }, "expirationDate": "2099-01-01T00:00:00Z" },
                { "dimension": "tier", "value": { "stringValue": "gold" } },
                { "dimension": "requests", "value": { "booleanValue": true }, "expirationDate": "2001-01-01T00:00:00Z" }
            ]
        }),
    )
    .await;
    let customer = sub["customerIdentifier"].as_str().unwrap().to_string();
    let license = sub["licenseArn"].as_str().unwrap().to_string();
    assert!(license.starts_with("arn:aws:license-manager::294406891311:license:l-"), "{license}");
    let token = sub["registrationToken"].as_str().unwrap().to_string();

    // The SaaS landing page resolves the buyer.
    let resolved = metering.resolve_customer().registration_token(&token).send().await.unwrap();
    assert_eq!(resolved.customer_identifier(), Some(customer.as_str()));
    assert_eq!(resolved.product_code(), Some(code.as_str()));
    assert_eq!(resolved.customer_aws_account_id(), Some(BUYER));
    assert_eq!(resolved.license_arn(), Some(license.as_str()));
    assert!(resolved.metadata().unwrap().agreement_id().unwrap().starts_with("agmt-"));
    let e = metering.resolve_customer().registration_token("bogus").send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidTokenException");
    let expired = post(
        &mws,
        "/_aws/marketplace/registration-tokens",
        json!({ "customerIdentifier": customer, "expiresInSeconds": -1 }),
    )
    .await;
    let e = metering
        .resolve_customer()
        .registration_token(expired["registrationToken"].as_str().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "ExpiredTokenException");

    // Entitlements: expired ones are gone; filters and pages work.
    let got = entitlements.get_entitlements().product_code(&code).send().await.unwrap();
    let mut dims: Vec<_> = got.entitlements().iter().map(|e| e.dimension().unwrap().to_string()).collect();
    dims.sort();
    assert_eq!(dims, ["tier", "users"]);
    let users = entitlements
        .get_entitlements()
        .product_code(&code)
        .filter(GetEntitlementFilterName::Dimension, vec!["users".into()])
        .filter(GetEntitlementFilterName::CustomerIdentifier, vec![customer.clone()])
        .send()
        .await
        .unwrap();
    let users = &users.entitlements()[0];
    assert_eq!(users.value().unwrap().integer_value(), Some(25));
    assert_eq!(users.customer_aws_account_id(), Some(BUYER));
    assert_eq!(users.license_arn(), Some(license.as_str()));
    assert_eq!(users.expiration_date().unwrap().secs(), 4070908800);
    let page = entitlements.get_entitlements().product_code(&code).max_results(1).send().await.unwrap();
    assert_eq!(page.entitlements().len(), 1);
    let rest = entitlements
        .get_entitlements()
        .product_code(&code)
        .next_token(page.next_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(rest.entitlements().len(), 1);
    assert!(rest.next_token().is_none());
    let e = entitlements
        .get_entitlements()
        .product_code(&code)
        .filter(GetEntitlementFilterName::CustomerIdentifier, vec![customer.clone()])
        .filter(GetEntitlementFilterName::CustomerAwsAccountId, vec![BUYER.into()])
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.into_service_error().meta().code(), Some("InvalidParameterException"));
    let e = entitlements.get_entitlements().product_code("nope").send().await.unwrap_err();
    assert_eq!(e.into_service_error().meta().code(), Some("InvalidParameterException"));

    // BatchMeterUsage: new records succeed, resending is idempotent, and a
    // second value for the same hour is a duplicate.
    let at = hours_ago(2);
    let out = metering
        .batch_meter_usage()
        .product_code(&code)
        .usage_records(record(&customer, "users", 7, at))
        .send()
        .await
        .unwrap();
    let first = &out.results()[0];
    assert_eq!(first.status(), Some(&UsageRecordResultStatus::Success));
    let id = first.metering_record_id().unwrap().to_string();
    assert!(out.unprocessed_records().is_empty());
    let again = metering
        .batch_meter_usage()
        .product_code(&code)
        .usage_records(record(&customer, "users", 7, at))
        .usage_records(record(&customer, "users", 9, at))
        .send()
        .await
        .unwrap();
    assert_eq!(again.results()[0].status(), Some(&UsageRecordResultStatus::Success));
    assert_eq!(again.results()[0].metering_record_id(), Some(id.as_str()));
    assert_eq!(again.results()[1].status(), Some(&UsageRecordResultStatus::DuplicateRecord));

    // Concurrent Agreements style: account and license, no product code.
    let allocated = UsageRecord::builder()
        .customer_aws_account_id(BUYER)
        .license_arn(&license)
        .dimension("requests")
        .quantity(10)
        .timestamp(now())
        .usage_allocations(
            UsageAllocation::builder()
                .allocated_usage_quantity(4)
                .tags(Tag::builder().key("team").value("a").build().unwrap())
                .build()
                .unwrap(),
        )
        .usage_allocations(UsageAllocation::builder().allocated_usage_quantity(6).build().unwrap())
        .build()
        .unwrap();
    let out = metering.batch_meter_usage().usage_records(allocated.clone()).send().await.unwrap();
    assert_eq!(out.results()[0].status(), Some(&UsageRecordResultStatus::Success));

    // Whole-batch failures.
    let bad = |r: UsageRecord| metering.batch_meter_usage().product_code(&code).usage_records(r).send();
    let e = bad(record("nobody", "users", 1, now())).await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidCustomerIdentifierException");
    let e = bad(record(&customer, "gigabytes", 1, now())).await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidUsageDimensionException");
    let e = bad(record(&customer, "users", 1, hours_ago(25))).await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "TimestampOutOfBoundsException");
    let mut uneven = allocated.clone();
    uneven.quantity = Some(11);
    let e = metering.batch_meter_usage().usage_records(uneven).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidUsageAllocationsException");
    let e = metering
        .batch_meter_usage()
        .product_code("someoneelsesproduct")
        .usage_records(record(&customer, "users", 1, now()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidProductCodeException");

    // The buyer cancels.
    let (status, _) = mws.control("DELETE", &format!("/_aws/marketplace/subscriptions/{customer}"), None).await;
    assert_eq!(status, 200);
    let out = metering
        .batch_meter_usage()
        .product_code(&code)
        .usage_records(record(&customer, "tier", 1, now()))
        .send()
        .await
        .unwrap();
    assert_eq!(out.results()[0].status(), Some(&UsageRecordResultStatus::CustomerNotSubscribed));
    assert!(out.results()[0].metering_record_id().is_none());
    let got = entitlements.get_entitlements().product_code(&code).send().await.unwrap();
    assert!(got.entitlements().is_empty());

    let (status, records) =
        mws.control("GET", &format!("/_aws/marketplace-metering/records?productCode={code}"), None).await;
    assert_eq!(status, 200);
    let records = records["records"].as_array().unwrap();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0]["meteringRecordId"], json!(id));
    assert_eq!(records[1]["usageAllocations"][0]["tags"], json!([["team", "a"]]));

    // The catalog and the records are part of saved state.
    let (_, state) = mws.control("GET", "/_mws/state", None).await;
    mws.control("POST", "/_mws/reset?to=empty", None).await;
    let e = entitlements.get_entitlements().product_code(&code).send().await.unwrap_err();
    assert_eq!(e.into_service_error().meta().code(), Some("InvalidParameterException"));
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&state.to_string())).await;
    assert_eq!(status, 200);
    entitlements.get_entitlements().product_code(&code).send().await.unwrap();
    let (_, records) = mws.control("GET", "/_aws/marketplace-metering/records", None).await;
    assert_eq!(records["records"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn sellers_need_permission_and_their_own_products() {
    let mws = Mws::start().await;
    let code = product(&mws, "SaaS", &["users"]).await;
    let sub =
        post(&mws, "/_aws/marketplace/subscriptions", json!({ "productCode": code, "customerAWSAccountId": BUYER }))
            .await;
    let token = sub["registrationToken"].as_str().unwrap();

    let (_, cfg) = user_with_policy(&mws, "nobody", None).await;
    let e = Metering::new(&cfg).resolve_customer().registration_token(token).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "AccessDeniedException");
    let e = Entitlements::new(&cfg).get_entitlements().product_code(&code).send().await.unwrap_err();
    assert_eq!(e.into_service_error().meta().code(), Some("AccessDeniedException"));

    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["aws-marketplace:ResolveCustomer","aws-marketplace:GetEntitlements"],"Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "fulfillment", Some(policy)).await;
    let resolved = Metering::new(&cfg).resolve_customer().registration_token(token).send().await.unwrap();
    assert_eq!(resolved.customer_aws_account_id(), Some(BUYER));
    Entitlements::new(&cfg).get_entitlements().product_code(&code).send().await.unwrap();

    // Another seller's product is invalid to this one.
    let other = post(
        &mws,
        "/_aws/marketplace/products",
        json!({ "sellerAccountId": "444455556666", "dimensions": [{ "name": "users" }] }),
    )
    .await;
    let other_code = other["productCode"].as_str().unwrap();
    let other_sub = post(
        &mws,
        "/_aws/marketplace/subscriptions",
        json!({ "productCode": other_code, "customerAWSAccountId": BUYER }),
    )
    .await;
    let e = Metering::new(&cfg)
        .resolve_customer()
        .registration_token(other_sub["registrationToken"].as_str().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidTokenException");
    let e = Entitlements::new(&cfg).get_entitlements().product_code(other_code).send().await.unwrap_err();
    assert_eq!(e.into_service_error().meta().code(), Some("InvalidParameterException"));
}

/// Credentials in a new member account, as the buyer's instance role.
async fn buyer_metering(mws: &Mws) -> (String, Metering) {
    let orgs = aws_sdk_organizations::Client::new(&mws.root_sdk_config().await);
    orgs.create_organization().send().await.unwrap();
    let created = orgs.create_account().email("buyer@example.com").account_name("buyer").send().await.unwrap();
    let request_id = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let account = status.create_account_status().unwrap().account_id().unwrap().to_string();
    let admin = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    let (_, admin_cfg) = user_with_policy(mws, "admin", Some(admin)).await;
    let creds = aws_sdk_sts::Client::new(&admin_cfg)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
        .role_session_name("i-0123456789abcdef0")
        .send()
        .await
        .unwrap();
    let cfg = mws_e2e::sts_config(mws, creds.credentials().unwrap()).await;
    (account, Metering::new(&cfg))
}

#[tokio::test]
async fn meter_usage_and_register_usage_from_the_buyer_account() {
    let mws = Mws::start().await;
    let (account, buyer) = buyer_metering(&mws).await;
    let ami = product(&mws, "AMI", &["vcpu_hours"]).await;
    let container = product(&mws, "Container", &["pods"]).await;

    let meter = |qty: i32, at: DateTime| {
        buyer.meter_usage().product_code(&ami).usage_dimension("vcpu_hours").usage_quantity(qty).timestamp(at)
    };
    let e = meter(1, now()).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "CustomerNotEntitledException");
    let e = buyer.register_usage().product_code(&container).public_key_version(1).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "CustomerNotEntitledException");

    for p in [&ami, &container] {
        post(&mws, "/_aws/marketplace/subscriptions", json!({ "productCode": p, "customerAWSAccountId": account }))
            .await;
    }

    // Once per instance, dimension and hour; repeating it is idempotent.
    let at = now();
    let id = meter(4, at).send().await.unwrap().metering_record_id().unwrap().to_string();
    let again = meter(4, at).send().await.unwrap();
    assert_eq!(again.metering_record_id(), Some(id.as_str()));
    let e = meter(5, at).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "DuplicateRequestException");
    let e = meter(1, hours_ago(7)).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "TimestampOutOfBoundsException");
    let e =
        buyer.meter_usage().product_code(&ami).usage_dimension("gpu_hours").timestamp(now()).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidUsageDimensionException");
    let e = buyer.meter_usage().product_code("unknown").usage_dimension("x").timestamp(now()).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidProductCodeException");
    let e = meter(2, hours_ago(1)).dry_run(true).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "DryRunOperation");

    // A ClientToken names one request.
    let earlier = hours_ago(1);
    let first = meter(2, earlier).client_token("tok-1").send().await.unwrap();
    let retry = meter(2, earlier).client_token("tok-1").send().await.unwrap();
    assert_eq!(first.metering_record_id(), retry.metering_record_id());
    let e = meter(3, hours_ago(2)).client_token("tok-1").send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "IdempotencyConflictException");

    let (_, records) =
        mws.control("GET", &format!("/_aws/marketplace-metering/records?customerAWSAccountId={account}"), None).await;
    let records = records["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["quantity"], json!(4));
    assert!(records[0]["reportedBy"].as_str().unwrap().ends_with("/i-0123456789abcdef0"));

    // RegisterUsage answers a JWT MWS's Marketplace key signed.
    let e = buyer.register_usage().product_code(&container).public_key_version(2).send().await.unwrap_err();
    assert_eq!(err_code(&e.into_service_error()), "InvalidPublicKeyVersionException");
    let reg = buyer.register_usage().product_code(&container).public_key_version(1).nonce("n-1").send().await.unwrap();
    let jwt = reg.signature().unwrap();
    let (signed, sig) = jwt.rsplit_once('.').unwrap();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let claims: Value = serde_json::from_slice(&b64.decode(signed.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert_eq!(claims["productCode"], json!(container));
    assert_eq!(claims["nonce"], json!("n-1"));
    assert_eq!(claims["publicKeyVersion"], json!(1));
    let (status, _, pem) = mws.raw("GET", "/_aws/marketplace-metering/public-key", &[], b"").await;
    assert_eq!(status, 200);
    let pem = String::from_utf8(pem).unwrap();
    let der: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(der).unwrap();
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, der)
        .verify(signed.as_bytes(), &b64.decode(sig).unwrap())
        .expect("RegisterUsage signature verifies");

    // Unsubscribing stops new registrations, not the running task's.
    let (_, subs) = mws.control("GET", &format!("/_aws/marketplace/subscriptions?productCode={container}"), None).await;
    let id = subs["subscriptions"][0]["customerIdentifier"].as_str().unwrap().to_string();
    mws.control("DELETE", &format!("/_aws/marketplace/subscriptions/{id}"), None).await;
    buyer.register_usage().product_code(&container).public_key_version(1).send().await.unwrap();
}
