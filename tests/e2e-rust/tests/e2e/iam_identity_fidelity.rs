//! IAM identity fidelity: tags on create need `iam:Tag*`, account and
//! membership quotas, service-linked role names and asynchronous deletion,
//! and clock-driven expiry (delegation requests, credential reports), through
//! the official Rust SDK.

use aws_sdk_iam::error::ProvideErrorMetadata;
use aws_sdk_iam::types::{DelegationPermission, Tag};
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";
const EC2_TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

fn tag(k: &str, v: &str) -> Tag {
    Tag::builder().key(k).value(v).build().unwrap()
}

async fn advance_clock(mws: &Mws, seconds: i64) {
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&format!(r#"{{"advanceSeconds": {seconds}}}"#))).await;
    assert_eq!(status, 200);
}

async fn restore_clock(mws: &Mws) {
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"offsetSeconds": 0}"#)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn tags_on_create_need_tag_permission() {
    let mws = Mws::start().await;
    let (iam, _) = user_with_policy(
        &mws,
        "creator",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateRole","iam:CreateUser","iam:CreatePolicy","iam:CreateInstanceProfile"],"Resource":"*"}]}"#,
        ),
    )
    .await;

    // Without tags, the create permission is enough.
    iam.create_role().role_name("plain").assume_role_policy_document(EC2_TRUST).send().await.unwrap();
    iam.create_user().user_name("plain-user").send().await.unwrap();

    // With tags, AWS also needs iam:Tag<Entity> on the new resource.
    let err = iam
        .create_role()
        .role_name("tagged")
        .assume_role_policy_document(EC2_TRUST)
        .tags(tag("team", "a"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().contains("iam:TagRole"), "{:?}", err.message());
    let err = iam.create_user().user_name("tagged-user").tags(tag("team", "a")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().contains("iam:TagUser"));
    let err = iam
        .create_policy()
        .policy_name("tagged-policy")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#,
        )
        .tags(tag("team", "a"))
        .send()
        .await
        .unwrap_err();
    assert!(err.message().unwrap().contains("iam:TagPolicy"));
    let err = iam
        .create_instance_profile()
        .instance_profile_name("tagged-ip")
        .tags(tag("team", "a"))
        .send()
        .await
        .unwrap_err();
    assert!(err.message().unwrap().contains("iam:TagInstanceProfile"));

    // Nothing was created by the denied calls.
    let root = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    assert_eq!(root.get_role().role_name("tagged").send().await.unwrap_err().code(), Some("NoSuchEntity"));

    // With iam:TagRole (scoped by aws:TagKeys) the tagged create succeeds.
    let (iam, _) = user_with_policy(
        &mws,
        "tagger",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:CreateRole","Resource":"*"},{"Effect":"Allow","Action":"iam:TagRole","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}}]}"#,
        ),
    )
    .await;
    let role = iam
        .create_role()
        .role_name("tagged")
        .assume_role_policy_document(EC2_TRUST)
        .tags(tag("team", "a"))
        .send()
        .await
        .unwrap();
    assert_eq!(role.role().unwrap().tags().len(), 1);
    let err = iam
        .create_role()
        .role_name("tagged-other")
        .assume_role_policy_document(EC2_TRUST)
        .tags(tag("owner", "b"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
}

#[tokio::test]
async fn groups_per_user_quota() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_user().user_name("joiner").send().await.unwrap();
    for i in 0..11 {
        iam.create_group().group_name(format!("g{i}")).send().await.unwrap();
    }
    for i in 0..10 {
        iam.add_user_to_group().user_name("joiner").group_name(format!("g{i}")).send().await.unwrap();
    }
    // Adding to a group the user is already in is not a new membership.
    iam.add_user_to_group().user_name("joiner").group_name("g0").send().await.unwrap();
    let err = iam.add_user_to_group().user_name("joiner").group_name("g10").send().await.unwrap_err();
    assert_eq!(err.code(), Some("LimitExceeded"));
    assert_eq!(err.message(), Some("Cannot exceed quota for GroupsPerUser: 10"));
    let groups = iam.list_groups_for_user().user_name("joiner").send().await.unwrap();
    assert_eq!(groups.groups().len(), 10);

    let summary = iam.get_account_summary().send().await.unwrap();
    let map = summary.summary_map().unwrap();
    let get = |k: &str| map.iter().find(|(key, _)| key.as_str() == k).map(|(_, v)| *v);
    assert_eq!(get("GroupsPerUserQuota"), Some(10));
    assert_eq!(get("UsersQuota"), Some(5000));
    assert_eq!(get("Groups"), Some(11));
}

#[tokio::test]
async fn service_linked_role_names_and_deletion() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);

    for (service, name) in [
        ("sso.amazonaws.com", "AWSServiceRoleForSSO"),
        ("ram.amazonaws.com", "AWSServiceRoleForResourceAccessManager"),
        ("spot.amazonaws.com", "AWSServiceRoleForEC2Spot"),
        ("ecs.application-autoscaling.amazonaws.com", "AWSServiceRoleForApplicationAutoScaling_ECSService"),
        ("elasticloadbalancing.amazonaws.com", "AWSServiceRoleForElasticLoadBalancing"),
    ] {
        let out = iam.create_service_linked_role().aws_service_name(service).send().await.unwrap();
        let role = out.role().unwrap();
        assert_eq!(role.role_name(), name);
        assert_eq!(role.path(), format!("/aws-service-role/{service}/"));
        assert_eq!(role.arn(), format!("arn:aws:iam::{ACCOUNT}:role/aws-service-role/{service}/{name}"));
    }

    // Unknown services and unsupported suffixes are refused.
    let err = iam.create_service_linked_role().aws_service_name("nope.amazonaws.com").send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidInput"));
    let err = iam
        .create_service_linked_role()
        .aws_service_name("ecs.amazonaws.com")
        .custom_suffix("blue")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidInput"));
    assert!(err.message().unwrap().contains("Custom suffix is not allowed"));
    let out = iam
        .create_service_linked_role()
        .aws_service_name("autoscaling.amazonaws.com")
        .custom_suffix("blue")
        .send()
        .await
        .unwrap();
    assert_eq!(out.role().unwrap().role_name(), "AWSServiceRoleForAutoScaling_blue");

    // Deletion is asynchronous: IN_PROGRESS, then SUCCEEDED.
    let task = iam.delete_service_linked_role().role_name("AWSServiceRoleForEC2Spot").send().await.unwrap();
    let status = |id: String| {
        let iam = iam.clone();
        async move { iam.get_service_linked_role_deletion_status().deletion_task_id(id).send().await.unwrap() }
    };
    let id = task.deletion_task_id().to_string();
    assert!(id.starts_with("task/aws-service-role/spot.amazonaws.com/AWSServiceRoleForEC2Spot/"));
    assert_eq!(status(id.clone()).await.status().as_str(), "IN_PROGRESS");
    iam.get_role().role_name("AWSServiceRoleForEC2Spot").send().await.unwrap();

    // A role still in use fails to delete and says what uses it.
    iam.create_instance_profile().instance_profile_name("uses-ram").send().await.unwrap();
    iam.add_role_to_instance_profile()
        .instance_profile_name("uses-ram")
        .role_name("AWSServiceRoleForResourceAccessManager")
        .send()
        .await
        .unwrap();
    let busy =
        iam.delete_service_linked_role().role_name("AWSServiceRoleForResourceAccessManager").send().await.unwrap();
    let busy = busy.deletion_task_id().to_string();

    advance_clock(&mws, 10).await;
    assert_eq!(status(id).await.status().as_str(), "SUCCEEDED");
    let err = iam.get_role().role_name("AWSServiceRoleForEC2Spot").send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchEntity"));

    let failed = status(busy).await;
    assert_eq!(failed.status().as_str(), "FAILED");
    let reason = failed.reason().unwrap();
    let usage = reason.role_usage_list();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].resources(), [format!("arn:aws:iam::{ACCOUNT}:instance-profile/uses-ram")]);
    iam.get_role().role_name("AWSServiceRoleForResourceAccessManager").send().await.unwrap();
    restore_clock(&mws).await;
}

#[tokio::test]
async fn delegation_requests_and_credential_reports_follow_the_clock() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let created = iam
        .create_delegation_request()
        .description("Partner needs to read IAM")
        .permissions(
            DelegationPermission::builder().policy_template_arn("arn:aws:iam::aws:policy/IAMReadOnlyAccess").build(),
        )
        .requestor_workflow_id("workflow-expiry")
        .notification_channel("arn:aws:sns:us-east-1:111122223333:partner")
        .session_duration(3600)
        .send()
        .await
        .unwrap();
    let id = created.delegation_request_id().unwrap().to_string();
    let state = |id: String| {
        let iam = iam.clone();
        async move {
            let got = iam.get_delegation_request().delegation_request_id(id).send().await.unwrap();
            got.delegation_request().unwrap().state().unwrap().as_str().to_string()
        }
    };
    assert_eq!(state(id.clone()).await, "UNASSIGNED");

    iam.generate_credential_report().send().await.unwrap();
    iam.get_credential_report().send().await.unwrap();

    // Five hours on: the credential report (4 h) has expired.
    advance_clock(&mws, 5 * 3600).await;
    let err = iam.get_credential_report().send().await.unwrap_err();
    assert_eq!(err.code(), Some("ReportExpired"));
    assert_eq!(state(id.clone()).await, "UNASSIGNED");

    // Seven days after creation the request has expired.
    advance_clock(&mws, 7 * 24 * 3600).await;
    assert_eq!(state(id.clone()).await, "EXPIRED");
    let err = iam.associate_delegation_request().delegation_request_id(&id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidInput"));
    restore_clock(&mws).await;
}
