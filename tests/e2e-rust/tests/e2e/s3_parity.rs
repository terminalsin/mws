//! S3 behaviours found by the parity audit: listing edge cases, tag limits, anonymous ListBuckets, Requester Pays and the static
//! website endpoint.

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    Condition, ErrorDocument, IndexDocument, Payer, Redirect, RequestPayer, RequestPaymentConfiguration, RoutingRule,
    Tag, Tagging, WebsiteConfiguration,
};
use mws_e2e::{user_with_policy, Mws};

async fn root(mws: &Mws) -> aws_sdk_s3::Client {
    Mws::s3(&mws.root_sdk_config().await)
}

#[tokio::test]
async fn listing_tags_and_anonymous_list_buckets() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("edge").send().await.unwrap();
    s3.put_object().bucket("edge").key("a").body(ByteStream::from_static(b"x")).send().await.unwrap();

    // max-keys=0 is an empty page that is not truncated.
    let page = s3.list_objects_v2().bucket("edge").max_keys(0).send().await.unwrap();
    assert_eq!(page.is_truncated(), Some(false));
    assert_eq!(page.key_count(), Some(0));
    assert!(page.contents().is_empty());

    let tags: Vec<Tag> = (0..11).map(|i| Tag::builder().key(format!("k{i}")).value("v").build().unwrap()).collect();
    let err = s3
        .put_object_tagging()
        .bucket("edge")
        .key("a")
        .tagging(Tagging::builder().set_tag_set(Some(tags)).build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("BadRequest"));
    assert_eq!(err.message(), Some("Object tags cannot be greater than 10"));

    // Anonymous ListBuckets is refused in S3's own words.
    let (status, _, body) = mws.raw("GET", "/", &[], b"").await;
    assert_eq!(status, 403);
    assert!(String::from_utf8_lossy(&body).contains("<Code>AccessDenied</Code>"));
}

#[tokio::test]
async fn requester_pays_buckets_charge_other_accounts() {
    let mws = Mws::start().await;
    let orgs = aws_sdk_organizations::Client::new(&mws.root_sdk_config().await);
    orgs.create_organization().send().await.unwrap();
    let created = orgs.create_account().email("payer@example.com").account_name("payer").send().await.unwrap();
    let request_id = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let member = status.create_account_status().unwrap().account_id().unwrap().to_string();
    let admin_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    let (_, admin_cfg) = user_with_policy(&mws, "admin", Some(admin_policy)).await;
    let creds = aws_sdk_sts::Client::new(&admin_cfg)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{member}:role/OrganizationAccountAccessRole"))
        .role_session_name("s3")
        .send()
        .await
        .unwrap();
    let member_s3 = Mws::s3(&mws_e2e::sts_config(&mws, creds.credentials().unwrap()).await);

    let owner = root(&mws).await;
    owner.create_bucket().bucket("datasets").send().await.unwrap();
    owner.put_object().bucket("datasets").key("d.csv").body(ByteStream::from_static(b"1,2")).send().await.unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{member}:root"}},
        "Action":"s3:GetObject","Resource":"arn:aws:s3:::datasets/*"}}]}}"#
    );
    owner.put_bucket_policy().bucket("datasets").policy(policy).send().await.unwrap();
    owner
        .put_bucket_request_payment()
        .bucket("datasets")
        .request_payment_configuration(RequestPaymentConfiguration::builder().payer(Payer::Requester).build().unwrap())
        .send()
        .await
        .unwrap();

    // The owner pays for its own requests.
    let got = owner.get_object().bucket("datasets").key("d.csv").send().await.unwrap();
    assert_eq!(got.request_charged(), None);
    // Others must accept the charges.
    let err = member_s3.get_object().bucket("datasets").key("d.csv").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let got = member_s3
        .get_object()
        .bucket("datasets")
        .key("d.csv")
        .request_payer(RequestPayer::Requester)
        .send()
        .await
        .unwrap();
    assert_eq!(got.request_charged().map(|c| c.as_str()), Some("requester"));
    // Anonymous requests never reach a Requester Pays bucket.
    owner.delete_public_access_block().bucket("datasets").send().await.unwrap();
    let public = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
        "Action":"s3:GetObject","Resource":"arn:aws:s3:::datasets/*"}]}"#;
    owner.put_bucket_policy().bucket("datasets").policy(public).send().await.unwrap();
    let (status, _, _) = mws.raw("GET", "/datasets/d.csv", &[("x-amz-request-payer", "requester")], b"").await;
    assert_eq!(status, 403);
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn website_endpoint_serves_index_error_documents_and_redirects() {
    let mws = Mws::start().await;
    let s3 = root(&mws).await;
    s3.create_bucket().bucket("www").send().await.unwrap();
    s3.delete_public_access_block().bucket("www").send().await.unwrap();
    let public = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::www/*"},
        {"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::www"}]}"#;
    s3.put_bucket_policy().bucket("www").policy(public).send().await.unwrap();
    for (key, body) in [("index.html", "home"), ("docs/index.html", "docs"), ("404.html", "gone")] {
        s3.put_object()
            .bucket("www")
            .key(key)
            .content_type("text/html")
            .body(ByteStream::from(body.as_bytes().to_vec()))
            .send()
            .await
            .unwrap();
    }
    s3.put_object()
        .bucket("www")
        .key("old.html")
        .website_redirect_location("/index.html")
        .body(ByteStream::from_static(b""))
        .send()
        .await
        .unwrap();

    let (status, _, body) = mws.raw("GET", "/_aws/s3-website/www/", &[], b"").await;
    assert_eq!(status, 404);
    assert!(String::from_utf8_lossy(&body).contains("NoSuchWebsiteConfiguration"));

    let rule = RoutingRule::builder()
        .condition(Condition::builder().key_prefix_equals("blog/").build())
        .redirect(Redirect::builder().replace_key_prefix_with("docs/").http_redirect_code("302").build())
        .build();
    s3.put_bucket_website()
        .bucket("www")
        .website_configuration(
            WebsiteConfiguration::builder()
                .index_document(IndexDocument::builder().suffix("index.html").build().unwrap())
                .error_document(ErrorDocument::builder().key("404.html").build().unwrap())
                .routing_rules(rule)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let (status, headers, body) = mws.raw("GET", "/_aws/s3-website/www/", &[], b"").await;
    assert_eq!((status, body.as_slice()), (200, b"home".as_slice()));
    assert_eq!(header(&headers, "content-type"), Some("text/html"));
    // Through the website host name, as on AWS.
    let host = [("Host", "www.s3-website-us-east-1.amazonaws.com")];
    let (status, _, body) = mws.raw("GET", "/docs/", &host, b"").await;
    assert_eq!((status, body.as_slice()), (200, b"docs".as_slice()));
    let (status, headers, _) = mws.raw("GET", "/docs", &host, b"").await;
    assert_eq!((status, header(&headers, "location")), (302, Some("/docs/")));
    let (status, _, body) = mws.raw("GET", "/missing", &host, b"").await;
    assert_eq!((status, body.as_slice()), (404, b"gone".as_slice()));
    let (status, headers, _) = mws.raw("GET", "/old.html", &host, b"").await;
    assert_eq!((status, header(&headers, "location")), (301, Some("/index.html")));
    let (status, headers, _) = mws.raw("GET", "/blog/post", &host, b"").await;
    assert_eq!(status, 302);
    assert!(header(&headers, "location").unwrap().ends_with("/docs/post"));
    let (status, _, body) = mws.raw("PUT", "/x", &host, b"x").await;
    assert_eq!(status, 405);
    assert!(String::from_utf8_lossy(&body).contains("<li>Code: MethodNotAllowed</li>"));
}
