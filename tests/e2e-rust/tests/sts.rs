//! STS through the official SDK, with policies enforced end to end.
#![allow(deprecated)]

use aws_sdk_sts::error::ProvideErrorMetadata;
use mws_e2e::{jwt, sts_config, user_with_policy, Mws};

const ACCOUNT_TRUST: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}"#;
const IAM_READ: &str =
    r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["iam:Get*","iam:List*"],"Resource":"*"}}"#;
const ASSUME_ANY: &str =
    r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}"#;

async fn make_role(mws: &Mws, name: &str, trust: &str, policy: &str) {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    iam.put_role_policy().role_name(name).policy_name("p").policy_document(policy).send().await.unwrap();
}

#[tokio::test]
async fn caller_identity_for_root_and_users() {
    let mws = Mws::start().await;
    let sts = aws_sdk_sts::Client::new(&mws.root_sdk_config().await);
    let me = sts.get_caller_identity().send().await.unwrap();
    assert_eq!(me.arn(), Some("arn:aws:iam::123456789012:root"));
    assert_eq!(me.account(), Some("123456789012"));

    let (_, cfg) = user_with_policy(&mws, "ivan", None).await;
    let me = aws_sdk_sts::Client::new(&cfg).get_caller_identity().send().await.unwrap();
    assert_eq!(me.arn(), Some("arn:aws:iam::123456789012:user/ivan"));
    assert!(me.user_id().unwrap().starts_with("AIDA"));
}

#[tokio::test]
async fn assume_role_needs_trust_and_identity_permission() {
    let mws = Mws::start().await;
    make_role(&mws, "reader", ACCOUNT_TRUST, IAM_READ).await;
    let role_arn = "arn:aws:iam::123456789012:role/reader";

    // Trust delegates to the account, so the user also needs sts:AssumeRole.
    let (_, cfg) = user_with_policy(&mws, "jane", None).await;
    let err = aws_sdk_sts::Client::new(&cfg)
        .assume_role()
        .role_arn(role_arn)
        .role_session_name("s1")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(
        err.message(),
        Some("User: arn:aws:iam::123456789012:user/jane is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::123456789012:role/reader")
    );

    let (_, cfg) = user_with_policy(&mws, "kate", Some(ASSUME_ANY)).await;
    let out = aws_sdk_sts::Client::new(&cfg)
        .assume_role()
        .role_arn(role_arn)
        .role_session_name("kate-session")
        .send()
        .await
        .unwrap();
    let user = out.assumed_role_user().unwrap();
    assert_eq!(user.arn(), "arn:aws:sts::123456789012:assumed-role/reader/kate-session");
    assert!(user.assumed_role_id().starts_with("AROA") && user.assumed_role_id().ends_with(":kate-session"));
    let creds = out.credentials().unwrap();
    assert!(creds.access_key_id().starts_with("ASIA"));

    // The session has the role's permissions, not kate's.
    let session = sts_config(&mws, creds).await;
    let me = aws_sdk_sts::Client::new(&session).get_caller_identity().send().await.unwrap();
    assert_eq!(me.arn(), Some(user.arn()));
    let iam = aws_sdk_iam::Client::new(&session);
    iam.list_users().send().await.unwrap();
    let err = iam.create_user().user_name("x").send().await.unwrap_err();
    assert_eq!(
        err.message(),
        Some("User: arn:aws:sts::123456789012:assumed-role/reader/kate-session is not authorized to perform: iam:CreateUser on resource: arn:aws:iam::123456789012:user/x because no identity-based policy allows the iam:CreateUser action")
    );

    // The role records its last use.
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let role = root.get_role().role_name("reader").send().await.unwrap();
    assert!(role.role().unwrap().role_last_used().unwrap().last_used_date().is_some());
}

#[tokio::test]
async fn trust_naming_a_user_directly_needs_no_identity_policy() {
    let mws = Mws::start().await;
    let trust = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/leo"},"Action":"sts:AssumeRole"}}"#;
    make_role(&mws, "direct", trust, IAM_READ).await;
    let (_, leo) = user_with_policy(&mws, "leo", None).await;
    aws_sdk_sts::Client::new(&leo)
        .assume_role()
        .role_arn("arn:aws:iam::123456789012:role/direct")
        .role_session_name("s1")
        .send()
        .await
        .unwrap();
    let (_, mia) = user_with_policy(&mws, "mia", Some(ASSUME_ANY)).await;
    let err = aws_sdk_sts::Client::new(&mia)
        .assume_role()
        .role_arn("arn:aws:iam::123456789012:role/direct")
        .role_session_name("s1")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}

#[tokio::test]
async fn session_policies_external_id_and_durations() {
    let mws = Mws::start().await;
    let trust = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret-123"}}}}"#;
    make_role(
        &mws,
        "partner",
        trust,
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}"#,
    )
    .await;
    let arn = "arn:aws:iam::123456789012:role/partner";
    let (_, cfg) = user_with_policy(&mws, "nora", Some(ASSUME_ANY)).await;
    let sts = aws_sdk_sts::Client::new(&cfg);

    let err = sts.assume_role().role_arn(arn).role_session_name("s1").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    let err = sts
        .assume_role()
        .role_arn(arn)
        .role_session_name("s1")
        .external_id("secret-123")
        .duration_seconds(7200)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.message(), Some("The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));

    let out = sts
        .assume_role()
        .role_arn(arn)
        .role_session_name("scoped")
        .external_id("secret-123")
        .policy(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:List*","Resource":"*"}}"#)
        .send()
        .await
        .unwrap();
    assert!(out.packed_policy_size().unwrap() > 0);
    let session = sts_config(&mws, out.credentials().unwrap()).await;
    let iam = aws_sdk_iam::Client::new(&session);
    iam.list_roles().send().await.unwrap();
    let err = iam.get_role().role_name("partner").send().await.unwrap_err();
    assert!(err.message().unwrap().ends_with("because no session policy allows the iam:GetRole action"), "{err:?}");

    // Role chaining is limited to one hour.
    make_role(&mws, "second", trust.replace("secret-123", "x").as_str(), IAM_READ).await;
    let chained = aws_sdk_sts::Client::new(&session);
    let err = chained
        .assume_role()
        .role_arn("arn:aws:iam::123456789012:role/second")
        .role_session_name("c1")
        .external_id("x")
        .duration_seconds(3601)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationError"));
}

#[tokio::test]
async fn root_cannot_assume_roles() {
    let mws = Mws::start().await;
    make_role(&mws, "r", ACCOUNT_TRUST, IAM_READ).await;
    let sts = aws_sdk_sts::Client::new(&mws.root_sdk_config().await);
    let err = sts
        .assume_role()
        .role_arn("arn:aws:iam::123456789012:role/r")
        .role_session_name("s1")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.message(), Some("Roles may not be assumed by root accounts."));
}

#[tokio::test]
async fn session_tokens_cannot_call_iam_without_mfa() {
    let mws = Mws::start().await;
    let (_, cfg) = user_with_policy(
        &mws,
        "olga",
        Some(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#),
    )
    .await;
    let out = aws_sdk_sts::Client::new(&cfg).get_session_token().send().await.unwrap();
    let session = sts_config(&mws, out.credentials().unwrap()).await;
    let me = aws_sdk_sts::Client::new(&session).get_caller_identity().send().await.unwrap();
    assert_eq!(me.arn(), Some("arn:aws:iam::123456789012:user/olga"));
    let err = aws_sdk_iam::Client::new(&session).list_users().send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidClientTokenId"));
}

#[tokio::test]
async fn federation_tokens_are_scoped_by_their_policy() {
    let mws = Mws::start().await;
    let admin = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;
    let (_, cfg) = user_with_policy(&mws, "pat", Some(admin)).await;
    let sts = aws_sdk_sts::Client::new(&cfg);
    let out = sts.get_federation_token().name("contractor").policy(IAM_READ).send().await.unwrap();
    assert_eq!(out.federated_user().unwrap().arn(), "arn:aws:sts::123456789012:federated-user/contractor");
    let iam = aws_sdk_iam::Client::new(&sts_config(&mws, out.credentials().unwrap()).await);
    iam.list_users().send().await.unwrap();
    assert!(iam.create_user().user_name("x").send().await.is_err());

    // Without a session policy a federated user has no permissions at all.
    let out = sts.get_federation_token().name("nobody").send().await.unwrap();
    let iam = aws_sdk_iam::Client::new(&sts_config(&mws, out.credentials().unwrap()).await);
    let err = iam.list_users().send().await.unwrap_err();
    assert!(err.message().unwrap().ends_with("because no session policy allows the iam:ListUsers action"), "{err:?}");
}

#[tokio::test]
async fn web_identity_federation() {
    let mws = Mws::start().await;
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let provider = root
        .create_open_id_connect_provider()
        .url("https://token.actions.githubusercontent.com")
        .client_id_list("sts.amazonaws.com")
        .thumbprint_list("6938fd4d98bab03faadb97b34396831e3780aea1")
        .send()
        .await
        .unwrap();
    let provider_arn = provider.open_id_connect_provider_arn().unwrap().to_string();
    assert_eq!(provider_arn, "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com");
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":{{"Effect":"Allow","Principal":{{"Federated":"{provider_arn}"}},"Action":"sts:AssumeRoleWithWebIdentity",
        "Condition":{{"StringEquals":{{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}},"StringLike":{{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}}}}}}"#
    );
    make_role(&mws, "ci", &trust, IAM_READ).await;
    let exp = chrono_now() + 600;
    let token = |sub: &str, aud: &str| {
        jwt(serde_json::json!({"iss":"https://token.actions.githubusercontent.com","sub":sub,"aud":aud,"exp":exp}))
    };

    // The SDK sends this call unsigned; anonymous credentials are fine.
    let sts = aws_sdk_sts::Client::new(&mws.root_sdk_config().await);
    let out = sts
        .assume_role_with_web_identity()
        .role_arn("arn:aws:iam::123456789012:role/ci")
        .role_session_name("gha")
        .web_identity_token(token("repo:acme/app:ref:refs/heads/main", "sts.amazonaws.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(out.subject_from_web_identity_token(), Some("repo:acme/app:ref:refs/heads/main"));
    assert_eq!(out.assumed_role_user().unwrap().arn(), "arn:aws:sts::123456789012:assumed-role/ci/gha");
    let iam = aws_sdk_iam::Client::new(&sts_config(&mws, out.credentials().unwrap()).await);
    iam.list_roles().send().await.unwrap();

    let err = sts
        .assume_role_with_web_identity()
        .role_arn("arn:aws:iam::123456789012:role/ci")
        .role_session_name("gha")
        .web_identity_token(token("repo:evil/app", "sts.amazonaws.com"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let err = sts
        .assume_role_with_web_identity()
        .role_arn("arn:aws:iam::123456789012:role/ci")
        .role_session_name("gha")
        .web_identity_token(token("repo:acme/app", "someone-else"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidIdentityToken"));
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}
