//! IAM policy enforcement, observed through the official SDK.

use aws_sdk_iam::error::ProvideErrorMetadata;
use aws_sdk_iam::types::{ContextEntry, ContextKeyTypeEnum, PolicyEvaluationDecisionType, Tag};
use mws_e2e::{user_with_policy, Mws};

const READ_ONLY: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:Get*","iam:List*"],"Resource":"*"}]}"#;

#[tokio::test]
async fn a_user_without_policies_is_denied_with_aws_wording() {
    let mws = Mws::start().await;
    let (bob, _) = user_with_policy(&mws, "bob", None).await;
    let err = bob.list_users().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(
        err.message(),
        Some("User: arn:aws:iam::123456789012:user/bob is not authorized to perform: iam:ListUsers on resource: arn:aws:iam::123456789012:user/ because no identity-based policy allows the iam:ListUsers action")
    );
    assert_eq!(err.raw_response().unwrap().status().as_u16(), 403);
}

#[tokio::test]
async fn inline_allow_and_explicit_deny() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"iam:*","Resource":"*"},
        {"Effect":"Deny","Action":"iam:DeleteUser","Resource":"arn:aws:iam::*:user/protected-*"}]}"#;
    let (admin, _) = user_with_policy(&mws, "admin", Some(policy)).await;
    admin.create_user().user_name("protected-1").send().await.unwrap();
    admin.create_user().user_name("scratch").send().await.unwrap();
    admin.delete_user().user_name("scratch").send().await.unwrap();
    let err = admin.delete_user().user_name("protected-1").send().await.unwrap_err();
    assert_eq!(
        err.message(),
        Some("User: arn:aws:iam::123456789012:user/admin is not authorized to perform: iam:DeleteUser on resource: arn:aws:iam::123456789012:user/protected-1 with an explicit deny in an identity-based policy")
    );
}

#[tokio::test]
async fn group_and_managed_policies_apply() {
    let mws = Mws::start().await;
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let (carol, _) = user_with_policy(&mws, "carol", None).await;
    root.create_group().group_name("readers").send().await.unwrap();
    root.attach_group_policy()
        .group_name("readers")
        .policy_arn("arn:aws:iam::aws:policy/IAMReadOnlyAccess")
        .send()
        .await
        .unwrap();
    assert!(carol.list_users().send().await.is_err());
    root.add_user_to_group().group_name("readers").user_name("carol").send().await.unwrap();
    carol.list_users().send().await.unwrap();
    let err = carol.create_user().user_name("x").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    let groups = root.list_groups_for_user().user_name("carol").send().await.unwrap();
    assert_eq!(groups.groups()[0].group_name(), "readers");
    let err = root.delete_group().group_name("readers").send().await.unwrap_err();
    assert_eq!(err.message(), Some("Cannot delete entity, must remove users from group first."));
}

#[tokio::test]
async fn permissions_boundary_caps_effective_permissions() {
    let mws = Mws::start().await;
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let (dave, _) = user_with_policy(
        &mws,
        "dave",
        Some(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}"#),
    )
    .await;
    dave.create_user().user_name("u1").send().await.unwrap();
    let boundary =
        root.create_policy().policy_name("read-only-boundary").policy_document(READ_ONLY).send().await.unwrap();
    let boundary_arn = boundary.policy().unwrap().arn().unwrap().to_string();
    root.put_user_permissions_boundary().user_name("dave").permissions_boundary(&boundary_arn).send().await.unwrap();
    dave.list_users().send().await.unwrap();
    let err = dave.create_user().user_name("u2").send().await.unwrap_err();
    assert!(
        err.message().unwrap().ends_with("because no permissions boundary allows the iam:CreateUser action"),
        "{err:?}"
    );

    let user = root.get_user().user_name("dave").send().await.unwrap();
    assert_eq!(
        user.user().unwrap().permissions_boundary().unwrap().permissions_boundary_arn(),
        Some(boundary_arn.as_str())
    );
    let err = root.delete_policy().policy_arn(&boundary_arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("DeleteConflict"));
}

#[tokio::test]
async fn policy_variables_scope_users_to_themselves() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["iam:*AccessKey*","iam:GetUser"],"Resource":"arn:aws:iam::*:user/${aws:username}"}}"#;
    let (erin, _) = user_with_policy(&mws, "erin", Some(policy)).await;
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    root.create_user().user_name("frank").send().await.unwrap();
    erin.list_access_keys().send().await.unwrap();
    erin.get_user().send().await.unwrap();
    let err = erin.list_access_keys().user_name("frank").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}

#[tokio::test]
async fn request_tag_conditions() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["iam:CreateUser","iam:TagUser"],"Resource":"*",
        "Condition":{"StringEquals":{"aws:RequestTag/team":"platform"}}}}"#;
    let (gina, _) = user_with_policy(&mws, "gina", Some(policy)).await;
    let tag = |v: &str| Tag::builder().key("team").value(v).build().unwrap();
    gina.create_user().user_name("ok").tags(tag("platform")).send().await.unwrap();
    let err = gina.create_user().user_name("nope").tags(tag("web")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let err = gina.create_user().user_name("untagged").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}

#[tokio::test]
async fn managed_policy_versions() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let p = iam.create_policy().policy_name("p").path("/team/").policy_document(READ_ONLY).send().await.unwrap();
    let arn = p.policy().unwrap().arn().unwrap().to_string();
    assert_eq!(arn, "arn:aws:iam::123456789012:policy/team/p");
    for _ in 0..4 {
        iam.create_policy_version()
            .policy_arn(&arn)
            .policy_document(READ_ONLY)
            .set_as_default(true)
            .send()
            .await
            .unwrap();
    }
    let err = iam.create_policy_version().policy_arn(&arn).policy_document(READ_ONLY).send().await.unwrap_err();
    assert_eq!(err.code(), Some("LimitExceeded"));
    let versions = iam.list_policy_versions().policy_arn(&arn).send().await.unwrap();
    let ids: Vec<_> = versions.versions().iter().map(|v| v.version_id().unwrap().to_string()).collect();
    assert_eq!(ids, ["v5", "v4", "v3", "v2", "v1"]);
    assert_eq!(
        iam.get_policy().policy_arn(&arn).send().await.unwrap().policy().unwrap().default_version_id(),
        Some("v5")
    );

    // Documents come back URL-encoded, exactly as from AWS.
    let v1 = iam.get_policy_version().policy_arn(&arn).version_id("v1").send().await.unwrap();
    let encoded = v1.policy_version().unwrap().document().unwrap();
    assert!(encoded.starts_with("%7B"));
    assert_eq!(urlencoding::decode(encoded).unwrap(), READ_ONLY);

    let err = iam.delete_policy_version().policy_arn(&arn).version_id("v5").send().await.unwrap_err();
    assert_eq!(err.message(), Some("Cannot delete the default version of a policy."));
    let err = iam.delete_policy().policy_arn(&arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("DeleteConflict"));
}

#[tokio::test]
async fn malformed_documents_are_rejected() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let err = iam.create_policy().policy_name("bad").policy_document("{not json").send().await.unwrap_err();
    assert!(err.as_service_error().unwrap().is_malformed_policy_document_exception());
    assert_eq!(err.message(), Some("Syntax errors in policy."));
    let err = iam
        .create_role()
        .role_name("r")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole"}}"#,
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.message(), Some("Missing required field Principal"));
}

#[tokio::test]
async fn simulator_uses_the_real_engine() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"iam:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}},
        {"Effect":"Deny","Action":"iam:DeleteRole","Resource":"*"}]}"#;
    let (_, _) = user_with_policy(&mws, "henry", Some(policy)).await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let out = iam
        .simulate_principal_policy()
        .policy_source_arn("arn:aws:iam::123456789012:user/henry")
        .action_names("iam:CreateRole")
        .action_names("iam:DeleteRole")
        .action_names("s3:GetObject")
        .context_entries(
            ContextEntry::builder()
                .context_key_name("aws:SourceIp")
                .context_key_type(ContextKeyTypeEnum::Ip)
                .context_key_values("10.1.2.3")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let decisions: Vec<_> = out.evaluation_results().iter().map(|r| r.eval_decision().clone()).collect();
    assert_eq!(
        decisions,
        [
            PolicyEvaluationDecisionType::Allowed,
            PolicyEvaluationDecisionType::ExplicitDeny,
            PolicyEvaluationDecisionType::ImplicitDeny
        ]
    );
}

#[tokio::test]
async fn roles_and_instance_profiles() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}"#;
    let role =
        iam.create_role().role_name("web").path("/app/").assume_role_policy_document(trust).send().await.unwrap();
    assert_eq!(role.role().unwrap().arn(), "arn:aws:iam::123456789012:role/app/web");
    iam.put_role_policy().role_name("web").policy_name("logs").policy_document(READ_ONLY).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name("web-profile").send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name("web-profile").role_name("web").send().await.unwrap();
    let ip = iam.get_instance_profile().instance_profile_name("web-profile").send().await.unwrap();
    assert_eq!(ip.instance_profile().unwrap().roles()[0].role_name(), "web");
    let err = iam.delete_role().role_name("web").send().await.unwrap_err();
    assert_eq!(err.message(), Some("Cannot delete entity, must remove roles from instance profile first."));
    let got = iam.get_role().role_name("web").send().await.unwrap();
    assert_eq!(urlencoding::decode(got.role().unwrap().assume_role_policy_document().unwrap()).unwrap(), trust);
    let policies = iam.list_role_policies().role_name("web").send().await.unwrap();
    assert_eq!(policies.policy_names(), ["logs"]);
}
