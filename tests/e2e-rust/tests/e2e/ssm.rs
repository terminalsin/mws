//! SSM Parameter Store through the official Rust SDK.

use aws_sdk_ssm::error::ProvideErrorMetadata;
use aws_sdk_ssm::types::{
    ParameterStringFilter, ParameterTier, ParameterType, ParametersFilter, ParametersFilterKey, ResourceTypeForTagging,
    Tag,
};
use aws_sdk_ssm::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn put(ssm: &Client, name: &str, value: &str) -> i64 {
    ssm.put_parameter().name(name).value(value).r#type(ParameterType::String).send().await.unwrap().version()
}

#[tokio::test]
async fn parameters_versions_labels_and_history() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    let out = ssm
        .put_parameter()
        .name("/app/db/host")
        .value("db1")
        .r#type(ParameterType::String)
        .description("database host")
        .send()
        .await
        .unwrap();
    assert_eq!(out.version(), 1);
    assert_eq!(out.tier(), Some(&ParameterTier::Standard));

    let got = ssm.get_parameter().name("/app/db/host").send().await.unwrap();
    let p = got.parameter().unwrap();
    assert_eq!(p.name(), Some("/app/db/host"));
    assert_eq!(p.value(), Some("db1"));
    assert_eq!(p.version(), 1);
    assert_eq!(p.r#type(), Some(&ParameterType::String));
    assert_eq!(p.data_type(), Some("text"));
    assert_eq!(p.arn(), Some(format!("arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/db/host").as_str()));

    let dup = ssm.put_parameter().name("/app/db/host").value("x").send().await.unwrap_err();
    assert_eq!(code(dup.into_service_error()), "ParameterAlreadyExists");
    let v2 = ssm.put_parameter().name("/app/db/host").value("db2").overwrite(true).send().await.unwrap();
    assert_eq!(v2.version(), 2);
    assert_eq!(
        ssm.get_parameter().name("/app/db/host").send().await.unwrap().parameter().unwrap().value(),
        Some("db2")
    );
    let first = ssm.get_parameter().name("/app/db/host:1").send().await.unwrap();
    assert_eq!(first.parameter().unwrap().value(), Some("db1"));
    assert_eq!(first.parameter().unwrap().selector(), Some(":1"));
    let err = ssm.get_parameter().name("/app/db/host:9").send().await.unwrap_err();
    assert_eq!(code(err.into_service_error()), "ParameterVersionNotFound");
    // By ARN, the response names the parameter by its ARN too.
    let arn = format!("arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/db/host");
    let by_arn = ssm.get_parameter().name(&arn).send().await.unwrap();
    assert_eq!(by_arn.parameter().unwrap().name(), Some(arn.as_str()));

    // Labels: valid ones attach (and move between versions), invalid ones
    // come back.
    let labelled = ssm
        .label_parameter_version()
        .name("/app/db/host")
        .parameter_version(1)
        .labels("prod")
        .labels("1bad")
        .labels("awsx")
        .send()
        .await
        .unwrap();
    assert_eq!(labelled.parameter_version(), 1);
    assert_eq!(labelled.invalid_labels(), ["1bad", "awsx"]);
    let prod = ssm.get_parameter().name("/app/db/host:prod").send().await.unwrap();
    assert_eq!(prod.parameter().unwrap().value(), Some("db1"));
    assert_eq!(prod.parameter().unwrap().selector(), Some(":prod"));
    let moved = ssm.label_parameter_version().name("/app/db/host").labels("prod").send().await.unwrap();
    assert_eq!(moved.parameter_version(), 2);
    let history = ssm.get_parameter_history().name("/app/db/host").send().await.unwrap();
    let versions: Vec<_> = history.parameters().iter().map(|h| (h.version(), h.labels().to_vec())).collect();
    assert_eq!(versions, [(1, vec![]), (2, vec!["prod".to_string()])]);
    assert_eq!(history.parameters()[0].description(), Some("database host"));
    assert_eq!(history.parameters()[1].description(), Some("database host"), "kept on overwrite");
    assert!(history.parameters()[0].last_modified_user().unwrap().ends_with(":root"));
    let paged = ssm.get_parameter_history().name("/app/db/host").max_results(1).send().await.unwrap();
    assert_eq!(paged.parameters().len(), 1);
    let rest =
        ssm.get_parameter_history().name("/app/db/host").next_token(paged.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.parameters()[0].version(), 2);

    let unlabelled = ssm
        .unlabel_parameter_version()
        .name("/app/db/host")
        .parameter_version(2)
        .labels("prod")
        .labels("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(unlabelled.removed_labels(), ["prod"]);
    assert_eq!(unlabelled.invalid_labels(), ["nope"]);
    let err = ssm.get_parameter().name("/app/db/host:prod").send().await.unwrap_err();
    assert_eq!(code(err.into_service_error()), "ParameterNotFound");

    // Top-level names: the leading slash is optional.
    put(&ssm, "/plain", "p").await;
    assert_eq!(ssm.get_parameter().name("plain").send().await.unwrap().parameter().unwrap().value(), Some("p"));

    let many = ssm.get_parameters().names("/app/db/host").names("plain").names("/missing").send().await.unwrap();
    assert_eq!(many.parameters().len(), 2);
    assert_eq!(many.invalid_parameters(), ["/missing"]);

    ssm.delete_parameter().name("plain").send().await.unwrap();
    let err = ssm.delete_parameter().name("plain").send().await.unwrap_err();
    assert_eq!(code(err.into_service_error()), "ParameterNotFound");
    put(&ssm, "/a1", "x").await;
    let deleted = ssm.delete_parameters().names("/a1").names("/zzz").send().await.unwrap();
    assert_eq!(deleted.deleted_parameters(), ["/a1"]);
    assert_eq!(deleted.invalid_parameters(), ["/zzz"]);
    let err = ssm.get_parameter().name("/missing").send().await.unwrap_err();
    assert_eq!(code(err.into_service_error()), "ParameterNotFound");
}

#[tokio::test]
async fn names_values_and_patterns_are_validated() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    let put_code = |name: &'static str, value: &'static str| {
        let ssm = ssm.clone();
        async move {
            let e = ssm.put_parameter().name(name).value(value).r#type(ParameterType::String).send().await.unwrap_err();
            code(e.into_service_error())
        }
    };
    assert_eq!(put_code("awsthing", "x").await, "ValidationException");
    assert_eq!(put_code("/ssm/thing", "x").await, "ValidationException");
    assert_eq!(put_code("/aws/thing", "x").await, "AccessDeniedException");
    assert_eq!(put_code("a/b", "x").await, "ValidationException");
    assert_eq!(put_code("/bad name/x", "x").await, "ValidationException");
    assert_eq!(put_code("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p", "x").await, "HierarchyLevelLimitExceededException");
    assert_eq!(put_code("/nested", "{{ssm:other}}").await, "ValidationException");

    let e = ssm.put_parameter().name("/untyped").value("x").send().await.unwrap_err();
    assert_eq!(e.into_service_error().message(), Some("A parameter type is required when you create a parameter."));
    let e = ssm
        .put_parameter()
        .name("/t")
        .value("x")
        .r#type(ParameterType::String)
        .overwrite(true)
        .tags(Tag::builder().key("k").value("v").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");

    ssm.put_parameter()
        .name("/port")
        .value("8080")
        .r#type(ParameterType::String)
        .allowed_pattern(r"^\d+$")
        .send()
        .await
        .unwrap();
    let e = ssm.put_parameter().name("/port").value("http").overwrite(true).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ParameterPatternMismatchException");
    let e = ssm
        .put_parameter()
        .name("/re")
        .value("x")
        .r#type(ParameterType::String)
        .allowed_pattern("(")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidAllowedPatternException");

    let list = ssm.put_parameter().name("/list").value("a,b,c").r#type(ParameterType::StringList).send().await.unwrap();
    assert_eq!(list.version(), 1);
    let e = ssm
        .put_parameter()
        .name("/img")
        .value("ami-1234")
        .r#type(ParameterType::String)
        .data_type("aws:ec2:thing")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    ssm.put_parameter()
        .name("/img")
        .value("ami-0123456789abcdef0")
        .r#type(ParameterType::String)
        .data_type("aws:ec2:image")
        .send()
        .await
        .unwrap();
    let img = ssm.get_parameter().name("/img").send().await.unwrap();
    assert_eq!(img.parameter().unwrap().data_type(), Some("aws:ec2:image"));

    // A parameter keeps at most 100 versions; the oldest goes unless labelled.
    put(&ssm, "/counter", "0").await;
    ssm.label_parameter_version().name("/counter").labels("first").send().await.unwrap();
    for i in 1..100 {
        ssm.put_parameter().name("/counter").value(i.to_string()).overwrite(true).send().await.unwrap();
    }
    let e = ssm.put_parameter().name("/counter").value("100").overwrite(true).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ParameterMaxVersionLimitExceeded");
    ssm.unlabel_parameter_version().name("/counter").parameter_version(1).labels("first").send().await.unwrap();
    let v = ssm.put_parameter().name("/counter").value("100").overwrite(true).send().await.unwrap();
    assert_eq!(v.version(), 101);
    let e = ssm.get_parameter().name("/counter:1").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ParameterVersionNotFound");
}

#[tokio::test]
async fn secure_strings_are_encrypted_with_kms() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    let kms = aws_sdk_kms::Client::new(&mws.root_sdk_config().await);
    ssm.put_parameter()
        .name("/app/password")
        .value("hunter2")
        .r#type(ParameterType::SecureString)
        .send()
        .await
        .unwrap();
    let raw = ssm.get_parameter().name("/app/password").send().await.unwrap();
    let raw_default = raw.parameter().unwrap().value().unwrap().to_string();
    assert_ne!(raw_default, "hunter2");
    let plain = ssm.get_parameter().name("/app/password").with_decryption(true).send().await.unwrap();
    assert_eq!(plain.parameter().unwrap().value(), Some("hunter2"));
    let aliases = kms.list_aliases().send().await.unwrap();
    assert!(aliases.aliases().iter().any(|a| a.alias_name() == Some("alias/aws/ssm")));
    let meta = ssm.describe_parameters().send().await.unwrap();
    assert_eq!(meta.parameters()[0].key_id(), Some("alias/aws/ssm"));

    // A customer managed key: the stored value is a real KMS ciphertext,
    // bound to the parameter ARN. (alias/aws/ssm only allows use through
    // Parameter Store, so that one can't be decrypted directly.)
    let key = kms.create_key().send().await.unwrap();
    let key_id = key.key_metadata().unwrap().key_id().to_string();
    ssm.put_parameter()
        .name("/app/cmk")
        .value("direct")
        .r#type(ParameterType::SecureString)
        .key_id(&key_id)
        .send()
        .await
        .unwrap();
    let raw = ssm.get_parameter().name("/app/cmk").send().await.unwrap();
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.decode(raw.parameter().unwrap().value().unwrap()).unwrap();
    let arn = format!("arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/cmk");
    let dec = kms
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(blob.clone()))
        .encryption_context("PARAMETER_ARN", &arn)
        .send()
        .await
        .unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"direct");
    let e = kms.decrypt().ciphertext_blob(aws_sdk_kms::primitives::Blob::new(blob)).send().await.unwrap_err();
    assert_eq!(e.into_service_error().code(), Some("InvalidCiphertextException"));
    let e = kms
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(
            base64::engine::general_purpose::STANDARD.decode(&raw_default).unwrap(),
        ))
        .encryption_context("PARAMETER_ARN", format!("arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/app/password"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.into_service_error().code(), Some("AccessDeniedException"));

    // An advanced value uses envelope encryption.
    ssm.put_parameter()
        .name("/app/token")
        .value("t0k3n")
        .r#type(ParameterType::SecureString)
        .key_id(&key_id)
        .tier(ParameterTier::Advanced)
        .send()
        .await
        .unwrap();
    let got = ssm.get_parameter().name("/app/token").with_decryption(true).send().await.unwrap();
    assert_eq!(got.parameter().unwrap().value(), Some("t0k3n"));
    let many = ssm.get_parameters().names("/app/token").names("/app/password").with_decryption(true).send().await;
    let values: Vec<_> = many.unwrap().parameters().iter().filter_map(|p| p.value().map(str::to_string)).collect();
    assert_eq!(values, ["t0k3n", "hunter2"]);
    let history = ssm.get_parameter_history().name("/app/token").with_decryption(true).send().await.unwrap();
    assert_eq!(history.parameters()[0].value(), Some("t0k3n"));
    assert_eq!(history.parameters()[0].key_id(), Some(key_id.as_str()));

    let e = ssm
        .put_parameter()
        .name("/bad-key")
        .value("x")
        .r#type(ParameterType::SecureString)
        .key_id("alias/does-not-exist")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidKeyId");
    let e = ssm
        .put_parameter()
        .name("/plain-key")
        .value("x")
        .r#type(ParameterType::String)
        .key_id(&key_id)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");

    // Reading may be allowed while decrypting isn't: the customer managed
    // key's policy only trusts the account, and the user has no kms grant.
    let policy =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParameter","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "reader", Some(policy)).await;
    let reader = Client::new(&cfg);
    reader.get_parameter().name("/app/token").send().await.unwrap();
    let e = reader.get_parameter().name("/app/token").with_decryption(true).send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));
    assert!(e.message().unwrap().contains("kms:Decrypt"));
    // alias/aws/ssm lets anyone in the account decrypt through Parameter Store.
    let ok = reader.get_parameter().name("/app/password").with_decryption(true).send().await.unwrap();
    assert_eq!(ok.parameter().unwrap().value(), Some("hunter2"));

    kms.disable_key().key_id(&key_id).send().await.unwrap();
    let e = ssm.get_parameter().name("/app/token").with_decryption(true).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidKeyId");
}

#[tokio::test]
async fn paths_and_filters() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    for (name, value) in
        [("/svc/a", "1"), ("/svc/b", "2"), ("/svc/deep/c", "3"), ("/svc/deep/er/d", "4"), ("/other/x", "5")]
    {
        put(&ssm, name, value).await;
    }
    ssm.put_parameter().name("/svc/secret").value("s").r#type(ParameterType::SecureString).send().await.unwrap();
    let names = |ps: &[aws_sdk_ssm::types::Parameter]| {
        ps.iter().filter_map(|p| p.name().map(str::to_string)).collect::<Vec<_>>()
    };

    let one = ssm.get_parameters_by_path().path("/svc").send().await.unwrap();
    assert_eq!(names(one.parameters()), ["/svc/a", "/svc/b", "/svc/secret"]);
    let all = ssm.get_parameters_by_path().path("/svc/").recursive(true).with_decryption(true).send().await.unwrap();
    assert_eq!(names(all.parameters()), ["/svc/a", "/svc/b", "/svc/deep/c", "/svc/deep/er/d", "/svc/secret"]);
    assert_eq!(all.parameters()[4].value(), Some("s"));
    let page = ssm.get_parameters_by_path().path("/svc").recursive(true).max_results(2).send().await.unwrap();
    assert_eq!(page.parameters().len(), 2);
    let next = ssm
        .get_parameters_by_path()
        .path("/svc")
        .recursive(true)
        .max_results(2)
        .next_token(page.next_token().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(names(next.parameters()), ["/svc/deep/c", "/svc/deep/er/d"]);
    let typed = ssm
        .get_parameters_by_path()
        .path("/svc")
        .recursive(true)
        .parameter_filters(ParameterStringFilter::builder().key("Type").values("SecureString").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(names(typed.parameters()), ["/svc/secret"]);
    let e = ssm
        .get_parameters_by_path()
        .path("/svc")
        .parameter_filters(ParameterStringFilter::builder().key("Name").values("/svc/a").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidFilterKey");
    let e = ssm.get_parameters_by_path().path("svc").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    let e = ssm.get_parameters_by_path().path("/svc").next_token("garbage").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidNextToken");

    let described = ssm
        .describe_parameters()
        .parameter_filters(
            ParameterStringFilter::builder().key("Path").option("Recursive").values("/svc/deep").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let got: Vec<_> = described.parameters().iter().filter_map(|p| p.name()).collect();
    assert_eq!(got, ["/svc/deep/c", "/svc/deep/er/d"]);
    let begins = ssm
        .describe_parameters()
        .parameter_filters(
            ParameterStringFilter::builder().key("Name").option("BeginsWith").values("/svc/d").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(begins.parameters().len(), 2);
    let legacy = ssm
        .describe_parameters()
        .filters(ParametersFilter::builder().key(ParametersFilterKey::Name).values("/other").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.parameters()[0].name(), Some("/other/x"));
    let e = ssm
        .describe_parameters()
        .filters(ParametersFilter::builder().key(ParametersFilterKey::Name).values("/other").build().unwrap())
        .parameter_filters(ParameterStringFilter::builder().key("Type").values("String").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    let e = ssm
        .describe_parameters()
        .parameter_filters(ParameterStringFilter::builder().key("Label").values("x").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidFilterKey");
    let e = ssm
        .describe_parameters()
        .parameter_filters(ParameterStringFilter::builder().key("Type").option("Contains").values("S").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidFilterOption");
    let paged = ssm.describe_parameters().max_results(4).send().await.unwrap();
    assert_eq!(paged.parameters().len(), 4);
    let rest = ssm.describe_parameters().next_token(paged.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.parameters().len(), 2);
}

#[tokio::test]
async fn tiers_policies_and_service_settings() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    let big = "x".repeat(5000);
    let e = ssm.put_parameter().name("/big").value(&big).r#type(ParameterType::String).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    let out = ssm
        .put_parameter()
        .name("/big")
        .value(&big)
        .r#type(ParameterType::String)
        .tier(ParameterTier::IntelligentTiering)
        .send()
        .await
        .unwrap();
    assert_eq!(out.tier(), Some(&ParameterTier::Advanced));
    let e = ssm
        .put_parameter()
        .name("/big")
        .value("small")
        .overwrite(true)
        .tier(ParameterTier::Standard)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    let kept = ssm.put_parameter().name("/big").value("small").overwrite(true).send().await.unwrap();
    assert_eq!(kept.tier(), Some(&ParameterTier::Advanced));

    let in_a_minute = (chrono::Utc::now() + chrono::Duration::minutes(1)).to_rfc3339();
    let policies = format!(
        r#"[{{"Type":"Expiration","Version":"1.0","Attributes":{{"Timestamp":"{in_a_minute}"}}}},
            {{"Type":"ExpirationNotification","Version":"1.0","Attributes":{{"Before":"1","Unit":"Hours"}}}}]"#
    );
    let e = ssm
        .put_parameter()
        .name("/temp")
        .value("v")
        .r#type(ParameterType::String)
        .policies(&policies)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException", "standard parameters take no policies");
    ssm.put_parameter()
        .name("/temp")
        .value("v")
        .r#type(ParameterType::String)
        .tier(ParameterTier::Advanced)
        .policies(&policies)
        .send()
        .await
        .unwrap();
    let meta = ssm
        .describe_parameters()
        .parameter_filters(ParameterStringFilter::builder().key("Name").values("/temp").build().unwrap())
        .send()
        .await
        .unwrap();
    let pol = meta.parameters()[0].policies();
    assert_eq!(pol.len(), 2);
    assert_eq!(pol[0].policy_type(), Some("Expiration"));
    assert_eq!(pol[0].policy_status(), Some("Pending"));
    let bad = r#"[{"Type":"Retention","Version":"1.0","Attributes":{}}]"#;
    let e = ssm.put_parameter().name("/temp").value("v").overwrite(true).policies(bad).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidPolicyTypeException");
    // Expiration deletes the parameter once the (emulated) clock passes it.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":120}"#)).await;
    assert_eq!(status, 200);
    let e = ssm.get_parameter().name("/temp").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ParameterNotFound");

    let tier = "/ssm/parameter-store/default-parameter-tier";
    let s = ssm.get_service_setting().setting_id(tier).send().await.unwrap();
    let s = s.service_setting().unwrap();
    assert_eq!(s.setting_value(), Some("Standard"));
    assert_eq!(s.status(), Some("Default"));
    assert_eq!(s.arn(), Some(format!("arn:aws:ssm:us-east-1:{ACCOUNT}:servicesetting{tier}").as_str()));
    ssm.update_service_setting().setting_id(tier).setting_value("Advanced").send().await.unwrap();
    let s = ssm.get_service_setting().setting_id(tier).send().await.unwrap();
    assert_eq!(s.service_setting().unwrap().status(), Some("Customized"));
    let out = put_with_tier(&ssm, "/defaulted").await;
    assert_eq!(out, ParameterTier::Advanced);
    let e = ssm.update_service_setting().setting_id(tier).setting_value("Gold").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ValidationException");
    let reset = ssm.reset_service_setting().setting_id(tier).send().await.unwrap();
    assert_eq!(reset.service_setting().unwrap().setting_value(), Some("Standard"));
    assert_eq!(put_with_tier(&ssm, "/defaulted2").await, ParameterTier::Standard);
    let e = ssm.get_service_setting().setting_id("/ssm/nope").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ServiceSettingNotFound");
    let ht = ssm.get_service_setting().setting_id("/ssm/parameter-store/high-throughput-enabled").send().await.unwrap();
    assert_eq!(ht.service_setting().unwrap().setting_value(), Some("false"));
}

async fn put_with_tier(ssm: &Client, name: &str) -> ParameterTier {
    let out = ssm.put_parameter().name(name).value("v").r#type(ParameterType::String).send().await.unwrap();
    out.tier().unwrap().clone()
}

#[tokio::test]
async fn tags_and_iam() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    ssm.put_parameter()
        .name("/team/a")
        .value("a")
        .r#type(ParameterType::String)
        .tags(Tag::builder().key("team").value("blue").build().unwrap())
        .send()
        .await
        .unwrap();
    put(&ssm, "/team/b", "b").await;
    ssm.add_tags_to_resource()
        .resource_type(ResourceTypeForTagging::Parameter)
        .resource_id("/team/b")
        .tags(Tag::builder().key("team").value("red").build().unwrap())
        .tags(Tag::builder().key("env").value("dev").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = ssm
        .list_tags_for_resource()
        .resource_type(ResourceTypeForTagging::Parameter)
        .resource_id("/team/b")
        .send()
        .await
        .unwrap();
    let pairs: Vec<_> = tags.tag_list().iter().map(|t| (t.key(), t.value())).collect();
    assert_eq!(pairs, [("env", "dev"), ("team", "red")]);
    ssm.remove_tags_from_resource()
        .resource_type(ResourceTypeForTagging::Parameter)
        .resource_id("/team/b")
        .tag_keys("env")
        .send()
        .await
        .unwrap();
    let tags = ssm
        .list_tags_for_resource()
        .resource_type(ResourceTypeForTagging::Parameter)
        .resource_id("/team/b")
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tag_list().len(), 1);
    let e = ssm
        .list_tags_for_resource()
        .resource_type(ResourceTypeForTagging::Parameter)
        .resource_id("/nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidResourceId");
    let tagged = ssm
        .describe_parameters()
        .parameter_filters(ParameterStringFilter::builder().key("tag:team").values("blue").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(tagged.parameters()[0].name(), Some("/team/a"));

    // Identity policies scope access by path and by tag.
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[
            {{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters"],"Resource":"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/team/*",
              "Condition":{{"StringEquals":{{"aws:ResourceTag/team":"blue"}}}}}},
            {{"Effect":"Allow","Action":"ssm:GetParametersByPath","Resource":"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/team"}}]}}"#
    );
    let (_, cfg) = user_with_policy(&mws, "blue", Some(&policy)).await;
    let blue = Client::new(&cfg);
    blue.get_parameter().name("/team/a").send().await.unwrap();
    let e = blue.get_parameter().name("/team/b").send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(e.code(), Some("AccessDeniedException"));
    assert!(e.message().unwrap().contains("ssm:GetParameter"));
    let e = blue.get_parameters().names("/team/a").names("/team/b").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "AccessDeniedException");
    let by_path = blue.get_parameters_by_path().path("/team").send().await.unwrap();
    assert_eq!(by_path.parameters().len(), 2);
    let e = blue.put_parameter().name("/team/c").value("c").r#type(ParameterType::String).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "AccessDeniedException");
    let e = blue.describe_parameters().send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "AccessDeniedException");
}

#[tokio::test]
async fn advanced_parameters_are_shared_through_resource_policies() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    let orgs = aws_sdk_organizations::Client::new(&mws.root_sdk_config().await);
    orgs.create_organization().send().await.unwrap();
    let created = orgs.create_account().email("ssm@example.com").account_name("ssm").send().await.unwrap();
    let request_id = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let member = status.create_account_status().unwrap().account_id().unwrap().to_string();
    let admin_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    let (_, admin_cfg) = user_with_policy(&mws, "admin", Some(admin_policy)).await;
    let creds = aws_sdk_sts::Client::new(&admin_cfg)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{member}:role/OrganizationAccountAccessRole"))
        .role_session_name("ssm")
        .send()
        .await
        .unwrap();
    let other = Client::new(&mws_e2e::sts_config(&mws, creds.credentials().unwrap()).await);

    put(&ssm, "/shared/std", "s").await;
    ssm.put_parameter()
        .name("/shared/cfg")
        .value("v")
        .r#type(ParameterType::String)
        .tier(ParameterTier::Advanced)
        .send()
        .await
        .unwrap();
    let arn = format!("arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/shared/cfg");
    let e = other.get_parameter().name(&arn).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "AccessDeniedException");

    let doc = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{member}:root"}},
            "Action":["ssm:GetParameter","ssm:DescribeParameters"],"Resource":"{arn}"}}]}}"#
    );
    let std_arn = format!("arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/shared/std");
    let e = ssm.put_resource_policy().resource_arn(&std_arn).policy(&doc).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ResourcePolicyInvalidParameterException");
    let put = ssm.put_resource_policy().resource_arn(&arn).policy(&doc).send().await.unwrap();
    let (id, hash) = (put.policy_id().unwrap().to_string(), put.policy_hash().unwrap().to_string());
    let listed = ssm.get_resource_policies().resource_arn(&arn).send().await.unwrap();
    assert_eq!(listed.policies()[0].policy_id(), Some(id.as_str()));

    let got = other.get_parameter().name(&arn).send().await.unwrap();
    assert_eq!(got.parameter().unwrap().value(), Some("v"));
    assert_eq!(got.parameter().unwrap().name(), Some(arn.as_str()));
    let shared = other.describe_parameters().shared(true).send().await.unwrap();
    assert_eq!(shared.parameters().len(), 1);
    assert_eq!(shared.parameters()[0].arn(), Some(arn.as_str()));
    assert!(other.describe_parameters().send().await.unwrap().parameters().is_empty());

    let e =
        ssm.delete_resource_policy().resource_arn(&arn).policy_id(&id).policy_hash("stale").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ResourcePolicyConflictException");
    ssm.delete_resource_policy().resource_arn(&arn).policy_id(&id).policy_hash(&hash).send().await.unwrap();
    let e = other.get_parameter().name(&arn).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "AccessDeniedException");
}

#[tokio::test]
async fn secrets_manager_references_and_other_operations() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    let e = ssm.get_parameter().name("/aws/reference/secretsmanager/db").send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(e.code(), Some("ValidationException"));
    assert_eq!(e.message(), Some("WithDecryption flag must be True for retrieving a Secret Manager secret."));
    let e =
        ssm.get_parameter().name("/aws/reference/secretsmanager/db").with_decryption(true).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ParameterNotFound");
    // Outside Parameter Store, SSM operations aren't emulated yet.
    let e = ssm.describe_instance_information().send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "NotImplemented");
}

#[tokio::test]
async fn parameters_survive_export_and_import() {
    let mws = Mws::start().await;
    let ssm = client(&mws).await;
    put(&ssm, "/keep/me", "1").await;
    ssm.put_parameter().name("/keep/secret").value("s3cr3t").r#type(ParameterType::SecureString).send().await.unwrap();
    let (_, state) = mws.control("GET", "/_mws/state", None).await;
    mws.control("POST", "/_mws/reset?to=empty", None).await;
    let e = ssm.get_parameter().name("/keep/me").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ParameterNotFound");
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&state.to_string())).await;
    assert_eq!(status, 200);
    assert_eq!(ssm.get_parameter().name("/keep/me").send().await.unwrap().parameter().unwrap().value(), Some("1"));
    let secret = ssm.get_parameter().name("/keep/secret").with_decryption(true).send().await.unwrap();
    assert_eq!(secret.parameter().unwrap().value(), Some("s3cr3t"));
}
