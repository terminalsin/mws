//! IAM and STS behaviours found missing by the IAM/STS parity audit: trust
//! policy validation, deleted principals, tag key case, model patterns that
//! need look-ahead, AWS managed policies, resource-policy grants under
//! boundaries and session policies, and OIDC session tags.

use aws_sdk_iam::error::ProvideErrorMetadata;
use mws_e2e::{jwt, sts_config, user_with_policy, Mws};

const A: &str = "123456789012";

fn trust(principal: &str, action: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{principal},"Action":"{action}"}}]}}"#
    )
}

async fn create_role_err(iam: &aws_sdk_iam::Client, name: &str, doc: &str) -> (String, String) {
    let err = iam.create_role().role_name(name).assume_role_policy_document(doc).send().await.unwrap_err();
    (err.code().unwrap_or_default().to_string(), err.message().unwrap_or_default().to_string())
}

#[tokio::test]
async fn trust_policies_are_validated_like_iam() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);

    let ghost = format!(r#"{{"AWS":"arn:aws:iam::{A}:user/ghost"}}"#);
    assert_eq!(
        create_role_err(&iam, "r", &trust(&ghost, "sts:AssumeRole")).await,
        (
            "MalformedPolicyDocument".into(),
            format!(r#"Invalid principal in policy: "AWS":"arn:aws:iam::{A}:user/ghost""#)
        )
    );
    let wildcard = format!(r#"{{"AWS":"arn:aws:iam::{A}:role/*"}}"#);
    assert_eq!(
        create_role_err(&iam, "r", &trust(&wildcard, "sts:AssumeRole")).await,
        ("MalformedPolicyDocument".into(), format!(r#"Invalid principal in policy: "AWS":"arn:aws:iam::{A}:role/*""#))
    );
    let ec2 = r#"{"Service":"ec2.amazonaws.com"}"#;
    assert_eq!(
        create_role_err(&iam, "r", &trust(ec2, "s3:GetObject")).await,
        ("MalformedPolicyDocument".into(), "AssumeRole policy may only specify STS AssumeRole actions.".into())
    );
    let services: Vec<String> = (0..100).map(|i| format!(r#""svc{i:03}.amazonaws.com""#)).collect();
    let big = trust(&format!(r#"{{"Service":[{}]}}"#, services.join(",")), "sts:AssumeRole");
    assert_eq!(
        create_role_err(&iam, "r", &big).await,
        ("LimitExceeded".into(), "Cannot exceed quota for ACLSizePerRole: 2048".into())
    );

    // Existing principals, other accounts, and services are fine.
    iam.create_user().user_name("alice").send().await.unwrap();
    let ok = format!(r#"{{"AWS":["arn:aws:iam::{A}:user/alice","111122223333"],"Service":"ec2.amazonaws.com"}}"#);
    iam.create_role().role_name("r").assume_role_policy_document(trust(&ok, "sts:AssumeRole")).send().await.unwrap();
    let err = iam
        .update_assume_role_policy()
        .role_name("r")
        .policy_document(trust(&ghost, "sts:AssumeRole"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("MalformedPolicyDocument"));
}

#[tokio::test]
async fn deleted_principals_turn_into_unique_ids() {
    let mws = Mws::start().await;
    let (_, temp) = user_with_policy(&mws, "temp", None).await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let user_id = iam.get_user().user_name("temp").send().await.unwrap().user().unwrap().user_id().to_string();
    let principal = format!(r#"{{"AWS":"arn:aws:iam::{A}:user/temp"}}"#);
    iam.create_role()
        .role_name("trusts-temp")
        .assume_role_policy_document(trust(&principal, "sts:AssumeRole"))
        .send()
        .await
        .unwrap();
    let assume = |cfg: aws_config::SdkConfig| async move {
        aws_sdk_sts::Client::new(&cfg)
            .assume_role()
            .role_arn(format!("arn:aws:iam::{A}:role/trusts-temp"))
            .role_session_name("s1")
            .send()
            .await
    };
    assume(temp).await.unwrap();

    let key = iam.list_access_keys().user_name("temp").send().await.unwrap();
    for k in key.access_key_metadata() {
        iam.delete_access_key().user_name("temp").access_key_id(k.access_key_id().unwrap()).send().await.unwrap();
    }
    iam.delete_user().user_name("temp").send().await.unwrap();
    let doc = iam.get_role().role_name("trusts-temp").send().await.unwrap();
    let doc = urlencoding::decode(doc.role().unwrap().assume_role_policy_document().unwrap()).unwrap().into_owned();
    let doc: serde_json::Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(doc["Statement"][0]["Principal"]["AWS"], serde_json::Value::String(user_id));

    // A new user with the same name does not inherit the old grant.
    let (_, again) = user_with_policy(&mws, "temp", None).await;
    let err = assume(again).await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}

#[tokio::test]
async fn tags_aliases_and_aws_managed_policies() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_user().user_name("u").send().await.unwrap();
    let tag = |k: &str| aws_sdk_iam::types::Tag::builder().key(k).value("v").build().unwrap();
    let err = iam.tag_user().user_name("u").tags(tag("team")).tags(tag("Team")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidInput"));
    assert_eq!(err.message(), Some("Duplicate tag keys found. Please note that Tag keys are case insensitive."));

    // The alias pattern uses a look-ahead, which the model states.
    let err = iam.create_account_alias().account_alias("bad--alias").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationError"));
    assert_eq!(
        err.message(),
        Some("1 validation error detected: Value 'bad--alias' at 'accountAlias' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$")
    );
    iam.create_account_alias().account_alias("good-alias").send().await.unwrap();

    let managed = "arn:aws:iam::aws:policy/ReadOnlyAccess";
    let err = iam.set_default_policy_version().policy_arn(managed).version_id("v1").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let err = iam.delete_policy_version().policy_arn(managed).version_id("v1").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}

#[tokio::test]
async fn resource_policy_grants_to_a_role_respect_its_boundary() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&root);
    let s3 = Mws::s3(&root);
    s3.create_bucket().bucket("shared").send().await.unwrap();

    // The role's boundary only allows IAM reads; it has no identity policy.
    let boundary = iam
        .create_policy()
        .policy_name("iam-only")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:Get*","Resource":"*"}}"#,
        )
        .send()
        .await
        .unwrap();
    let account = format!(r#"{{"AWS":"arn:aws:iam::{A}:root"}}"#);
    iam.create_role()
        .role_name("bounded")
        .assume_role_policy_document(trust(&account, "sts:AssumeRole"))
        .permissions_boundary(boundary.policy().unwrap().arn().unwrap())
        .send()
        .await
        .unwrap();
    let assume_any =
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}"#;
    let (_, user) = user_with_policy(&mws, "u", Some(assume_any)).await;
    let creds = aws_sdk_sts::Client::new(&user)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{A}:role/bounded"))
        .role_session_name("s1")
        .send()
        .await
        .unwrap();
    let session = Mws::s3(&sts_config(&mws, creds.credentials().unwrap()).await);
    let policy = |principal: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":{{"Effect":"Allow","Principal":{{"AWS":"{principal}"}},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::shared"}}}}"#
        )
    };

    // Granted to the role: the boundary still limits it.
    s3.put_bucket_policy()
        .bucket("shared")
        .policy(policy(&format!("arn:aws:iam::{A}:role/bounded")))
        .send()
        .await
        .unwrap();
    let err = session.list_objects_v2().bucket("shared").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // Granted to the session itself: the boundary does not apply.
    s3.put_bucket_policy()
        .bucket("shared")
        .policy(policy(&format!("arn:aws:sts::{A}:assumed-role/bounded/s1")))
        .send()
        .await
        .unwrap();
    session.list_objects_v2().bucket("shared").send().await.unwrap();
}

#[tokio::test]
async fn mfa_age_and_session_token_size() {
    use crate::iam_advanced::{base32_decode, totp};
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}}"#;
    let (iam, cfg) = user_with_policy(&mws, "mfa", Some(policy)).await;
    // Without MFA the key is absent, so the condition fails.
    assert_eq!(iam.list_roles().send().await.unwrap_err().code(), Some("AccessDenied"));

    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let device = root.create_virtual_mfa_device().virtual_mfa_device_name("dev").send().await.unwrap();
    let device = device.virtual_mfa_device().unwrap();
    let serial = device.serial_number().to_string();
    let seed = base32_decode(std::str::from_utf8(device.base32_string_seed().unwrap().as_ref()).unwrap());
    root.enable_mfa_device()
        .user_name("mfa")
        .serial_number(&serial)
        .authentication_code1(totp(&seed, -2))
        .authentication_code2(totp(&seed, -1))
        .send()
        .await
        .unwrap();
    let sts = aws_sdk_sts::Client::new(&cfg);
    let out = sts.get_session_token().serial_number(&serial).token_code(totp(&seed, 0)).send().await.unwrap();
    let token_len = out.credentials().unwrap().session_token().len() as i32;
    assert_eq!(out.session_token_size(), Some(token_len));
    assert!(out.session_token_utilization().is_some_and(|u| u > 0 && u <= 100));
    let mfa_iam = aws_sdk_iam::Client::new(&sts_config(&mws, out.credentials().unwrap()).await);
    mfa_iam.list_roles().send().await.unwrap();
}

#[tokio::test]
async fn web_identity_tokens_carry_session_tags() {
    let config = mws::Config { skip_federation_signature_verification: true, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let provider = root
        .create_open_id_connect_provider()
        .url("https://idp.example.com")
        .client_id_list("sts.amazonaws.com")
        .thumbprint_list("6938fd4d98bab03faadb97b34396831e3780aea1")
        .send()
        .await
        .unwrap();
    let provider_arn = provider.open_id_connect_provider_arn().unwrap();
    let federated = format!(r#"{{"Federated":"{provider_arn}"}}"#);
    let without_tag_session = trust(&federated, "sts:AssumeRoleWithWebIdentity");
    root.create_role().role_name("web").assume_role_policy_document(&without_tag_session).send().await.unwrap();
    root.put_role_policy()
        .role_name("web")
        .policy_name("p")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"blue"}}}}"#,
        )
        .send()
        .await
        .unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let token = jwt(serde_json::json!({
        "iss": "https://idp.example.com", "sub": "dev", "aud": "sts.amazonaws.com", "exp": now + 600,
        "https://aws.amazon.com/tags": {"principal_tags": {"team": ["blue"]}, "transitive_tag_keys": ["team"]}
    }));
    let sts = aws_sdk_sts::Client::new(&mws.root_sdk_config().await);
    let assume = || {
        sts.assume_role_with_web_identity()
            .role_arn(format!("arn:aws:iam::{A}:role/web"))
            .role_session_name("dev")
            .web_identity_token(token.clone())
            .send()
    };
    // Passing tags needs sts:TagSession in the trust policy.
    let err = assume().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    let with_tag_session = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{federated},"Action":["sts:AssumeRoleWithWebIdentity","sts:TagSession"]}}]}}"#
    );
    root.update_assume_role_policy().role_name("web").policy_document(with_tag_session).send().await.unwrap();
    let out = assume().await.unwrap();
    let iam = aws_sdk_iam::Client::new(&sts_config(&mws, out.credentials().unwrap()).await);
    iam.list_roles().send().await.unwrap();
}
