//! AWS managed policies: every one exists in every account with its real
//! path, id and document, attaches anywhere, and grants exactly what its
//! document says, through the official Rust SDK.

use aws_sdk_iam::error::ProvideErrorMetadata;
use aws_sdk_iam::types::{EntityType, PolicyScopeType};
use mws_e2e::{sts_config, user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn aws_policy(path_and_name: &str) -> String {
    format!("arn:aws:iam::aws:policy/{path_and_name}")
}

/// Create a role the account trusts, attach `policies`, and return an SDK
/// config for a session of it (assumed by a user allowed to assume roles).
async fn session_with(mws: &Mws, role: &str, policies: &[&str]) -> aws_config::SdkConfig {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    iam.create_role().role_name(role).assume_role_policy_document(trust).send().await.unwrap();
    for p in policies {
        iam.attach_role_policy().role_name(role).policy_arn(aws_policy(p)).send().await.unwrap();
    }
    let assume = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}"#;
    let (_, user) = user_with_policy(mws, &format!("{role}-user"), Some(assume)).await;
    let creds = aws_sdk_sts::Client::new(&user)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{ACCOUNT}:role/{role}"))
        .role_session_name("session")
        .send()
        .await
        .unwrap();
    sts_config(mws, creds.credentials().unwrap()).await
}

#[tokio::test]
async fn real_managed_policies_exist_with_their_documents() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);

    // A service-role/ policy: the real id, path, version and document.
    let arn = aws_policy("service-role/AWSLambdaBasicExecutionRole");
    let p = iam.get_policy().policy_arn(&arn).send().await.unwrap();
    let p = p.policy().unwrap();
    assert_eq!(p.policy_name(), Some("AWSLambdaBasicExecutionRole"));
    assert_eq!(p.policy_id(), Some("ANPAJNCQGXC42545SKXIK"));
    assert_eq!(p.path(), Some("/service-role/"));
    assert_eq!(p.description(), Some("Provides write permissions to CloudWatch Logs."));
    assert_eq!(p.attachment_count(), Some(0));
    assert!(p.is_attachable());
    let version = p.default_version_id().unwrap().to_string();
    let v = iam.get_policy_version().policy_arn(&arn).version_id(&version).send().await.unwrap();
    let v = v.policy_version().unwrap();
    assert!(v.is_default_version());
    let doc = urlencoding::decode(v.document().unwrap()).unwrap().into_owned();
    let doc: serde_json::Value = serde_json::from_str(&doc).unwrap();
    let actions = &doc["Statement"][0]["Action"];
    assert!(actions.as_array().unwrap().iter().any(|a| a == "logs:PutLogEvents"), "{doc}");

    // The big ones are the real documents too.
    for (name, needle) in [
        ("ReadOnlyAccess", "sqs:List*"),
        ("AmazonSSMManagedInstanceCore", "ssmmessages:CreateControlChannel"),
        ("service-role/AmazonECSTaskExecutionRolePolicy", "ecr:GetAuthorizationToken"),
        ("aws-service-role/AWSSSOServiceRolePolicy", "iam:AttachRolePolicy"),
        ("aws-service-role/AWSResourceAccessManagerServiceRolePolicy", "organizations:DescribeOrganization"),
        ("job-function/ViewOnlyAccess", "s3:ListAllMyBuckets"),
    ] {
        let arn = aws_policy(name);
        let p = iam.get_policy().policy_arn(&arn).send().await.unwrap();
        let version = p.policy().unwrap().default_version_id().unwrap().to_string();
        let v = iam.get_policy_version().policy_arn(&arn).version_id(version).send().await.unwrap();
        let doc = urlencoding::decode(v.policy_version().unwrap().document().unwrap()).unwrap().into_owned();
        assert!(doc.contains(needle), "{name} lacks {needle}");
    }

    // AWS managed policies cannot be changed or tagged.
    let err = iam
        .create_policy_version()
        .policy_arn(aws_policy("ReadOnlyAccess"))
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let err = iam.delete_policy().policy_arn(aws_policy("ReadOnlyAccess")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // A wrong path is a different (missing) policy; a deprecated policy
    // exists but cannot be attached.
    let err = iam.get_policy().policy_arn(aws_policy("AWSLambdaBasicExecutionRole")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchEntity"));
    let config_role = aws_policy("service-role/AWSConfigRole");
    let p = iam.get_policy().policy_arn(&config_role).send().await.unwrap();
    assert!(!p.policy().unwrap().is_attachable());
    iam.create_user().user_name("u").send().await.unwrap();
    let err = iam.attach_user_policy().user_name("u").policy_arn(&config_role).send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchEntity"));
    assert_eq!(err.message(), Some(format!("Policy {config_role} does not exist or is not attachable.").as_str()));
}

#[tokio::test]
async fn list_policies_pages_through_every_aws_managed_policy() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_policy()
        .policy_name("mine")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();

    let mut names = vec![];
    let mut marker = None;
    let mut pages = 0;
    loop {
        let out = iam
            .list_policies()
            .scope(PolicyScopeType::Aws)
            .max_items(1000)
            .set_marker(marker.clone())
            .send()
            .await
            .unwrap();
        pages += 1;
        for p in out.policies() {
            assert!(p.arn().unwrap().starts_with("arn:aws:iam::aws:policy/"), "{:?}", p.arn());
            names.push(p.policy_name().unwrap().to_string());
        }
        if !out.is_truncated() {
            break;
        }
        marker = out.marker().map(str::to_string);
    }
    assert!(pages >= 2);
    assert!(names.len() > 1300, "{} AWS managed policies", names.len());
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "pages overlap");
    for n in ["AdministratorAccess", "AmazonS3ReadOnlyAccess", "AWSLambdaBasicExecutionRole", "AWSSSOServiceRolePolicy"]
    {
        assert!(names.iter().any(|x| x == n), "{n} missing");
    }
    assert!(!names.iter().any(|x| x == "mine"));

    // The paginator sees the same set.
    let all: Vec<_> = iam
        .list_policies()
        .scope(PolicyScopeType::Aws)
        .into_paginator()
        .items()
        .send()
        .collect::<Result<Vec<_>, _>>()
        .await
        .unwrap();
    assert_eq!(all.len(), names.len());

    // PathPrefix and Scope=Local.
    let service_role = iam
        .list_policies()
        .scope(PolicyScopeType::Aws)
        .path_prefix("/service-role/")
        .max_items(1000)
        .send()
        .await
        .unwrap();
    assert!(service_role.policies().len() > 100);
    assert!(service_role.policies().iter().all(|p| p.path() == Some("/service-role/")));
    let local = iam.list_policies().scope(PolicyScopeType::Local).send().await.unwrap();
    assert_eq!(local.policies().len(), 1);
    assert_eq!(local.policies()[0].policy_name(), Some("mine"));

    // OnlyAttached, and GetAccountAuthorizationDetails, list only what is
    // attached in this account.
    let attached = iam.list_policies().scope(PolicyScopeType::Aws).only_attached(true).send().await.unwrap();
    assert!(attached.policies().is_empty());
    iam.create_user().user_name("u").send().await.unwrap();
    iam.attach_user_policy().user_name("u").policy_arn(aws_policy("ReadOnlyAccess")).send().await.unwrap();
    let attached = iam.list_policies().scope(PolicyScopeType::Aws).only_attached(true).send().await.unwrap();
    assert_eq!(attached.policies().len(), 1);
    assert_eq!(attached.policies()[0].attachment_count(), Some(1));
    let details = iam.get_account_authorization_details().filter(EntityType::AwsManagedPolicy).send().await.unwrap();
    let arns: Vec<_> = details.policies().iter().map(|p| p.arn().unwrap()).collect();
    assert_eq!(arns, [aws_policy("ReadOnlyAccess")]);
}

#[tokio::test]
async fn managed_policies_grant_what_their_documents_say() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    Mws::s3(&root).create_bucket().bucket("existing").send().await.unwrap();
    aws_sdk_sqs::Client::new(&root).create_queue().queue_name("existing").send().await.unwrap();

    // ReadOnlyAccess covers every service's reads, and nothing else.
    let reader = session_with(&mws, "reader", &["ReadOnlyAccess"]).await;
    let s3 = Mws::s3(&reader);
    let buckets = s3.list_buckets().send().await.unwrap();
    assert!(buckets.buckets().iter().any(|b| b.name() == Some("existing")));
    let sqs = aws_sdk_sqs::Client::new(&reader);
    sqs.list_queues().send().await.unwrap();
    aws_sdk_iam::Client::new(&reader).list_roles().send().await.unwrap();
    let err = s3.create_bucket().bucket("new-bucket").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let err = sqs.create_queue().queue_name("new").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // AmazonS3ReadOnlyAccess: S3 reads only.
    let s3_reader = session_with(&mws, "s3-reader", &["AmazonS3ReadOnlyAccess"]).await;
    Mws::s3(&s3_reader).list_buckets().send().await.unwrap();
    Mws::s3(&s3_reader).list_objects_v2().bucket("existing").send().await.unwrap();
    let err = Mws::s3(&s3_reader).put_object().bucket("existing").key("k").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let err = aws_sdk_sqs::Client::new(&s3_reader).list_queues().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // Policies under service-role/ and job-function/ attach too; together
    // they grant the union.
    let worker = session_with(
        &mws,
        "worker",
        &[
            "service-role/AWSLambdaBasicExecutionRole",
            "service-role/AmazonECSTaskExecutionRolePolicy",
            "AmazonSSMManagedInstanceCore",
            "AmazonSQSFullAccess",
        ],
    )
    .await;
    let sqs = aws_sdk_sqs::Client::new(&worker);
    sqs.create_queue().queue_name("worker-queue").send().await.unwrap();
    let logs = aws_sdk_cloudwatchlogs::Client::new(&worker);
    logs.create_log_group().log_group_name("/worker").send().await.unwrap();
    let err = logs.describe_log_groups().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    let err = Mws::s3(&worker).list_buckets().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let iam = aws_sdk_iam::Client::new(&root);
    let listed =
        iam.list_attached_role_policies().role_name("worker").path_prefix("/service-role/").send().await.unwrap();
    let mut names: Vec<_> = listed.attached_policies().iter().map(|p| p.policy_name().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["AWSLambdaBasicExecutionRole", "AmazonECSTaskExecutionRolePolicy"]);
}

#[tokio::test]
async fn service_linked_roles_get_their_real_policies() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    aws_sdk_organizations::Client::new(&root).create_organization().send().await.unwrap();
    aws_sdk_ram::Client::new(&root).enable_sharing_with_aws_organization().send().await.unwrap();

    let iam = aws_sdk_iam::Client::new(&root);
    for (service, policy) in [
        ("organizations.amazonaws.com", "AWSOrganizationsServiceTrustPolicy"),
        ("ram.amazonaws.com", "AWSResourceAccessManagerServiceRolePolicy"),
    ] {
        let roles = iam.list_roles().path_prefix(format!("/aws-service-role/{service}/")).send().await.unwrap();
        assert_eq!(roles.roles().len(), 1, "{service}");
        let role = roles.roles()[0].role_name();
        let attached = iam.list_attached_role_policies().role_name(role).send().await.unwrap();
        let attached = attached.attached_policies();
        assert_eq!(attached.len(), 1, "{role}");
        assert_eq!(attached[0].policy_name(), Some(policy));
        assert_eq!(attached[0].policy_arn(), Some(aws_policy(&format!("aws-service-role/{policy}")).as_str()));
    }
}
