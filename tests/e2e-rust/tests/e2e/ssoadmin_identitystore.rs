//! IAM Identity Center authorization through the official SDKs: the
//! delegated administrator manages the organization instance's identity
//! store, and sso actions are evaluated on every resource AWS lists for them
//! (instance, permission set, account) with their tags.

use aws_sdk_identitystore::error::ProvideErrorMetadata;
use aws_sdk_identitystore::types::MemberId;
use aws_sdk_identitystore::Client as IdentityStore;
use aws_sdk_organizations::Client as Orgs;
use aws_sdk_ssoadmin::types::{PrincipalType, Tag, TargetType};
use aws_sdk_ssoadmin::Client as SsoAdmin;
use mws_e2e::user_with_policy;
use serde_json::json;

use crate::identity_center::center;

const MANAGEMENT: &str = "123456789012";

#[tokio::test]
async fn delegated_administrator_writes_the_organization_identity_store() {
    let c = center().await;
    let member = IdentityStore::new(&c.member_config().await);
    let create =
        |name: &str| member.create_user().identity_store_id(&c.store).user_name(name).display_name(name).send();
    let err = create("early").await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));

    let orgs = Orgs::new(&c.mws.root_sdk_config().await);
    let _ = orgs.enable_aws_service_access().service_principal("sso.amazonaws.com").send().await;
    orgs.register_delegated_administrator()
        .account_id(&c.member)
        .service_principal("sso.amazonaws.com")
        .send()
        .await
        .unwrap();

    let user = create("dana").await.unwrap().user_id().to_string();
    let group = member.create_group().identity_store_id(&c.store).display_name("ops").send().await.unwrap();
    let group = group.group_id().to_string();
    let membership = member
        .create_group_membership()
        .identity_store_id(&c.store)
        .group_id(&group)
        .member_id(MemberId::UserId(user.clone()))
        .send()
        .await
        .unwrap();
    member
        .update_user()
        .identity_store_id(&c.store)
        .user_id(&user)
        .operations(
            aws_sdk_identitystore::types::AttributeOperation::builder()
                .attribute_path("displayName")
                .attribute_value(aws_smithy_types::Document::String("Dana".into()))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    // The management account sees what the delegated administrator wrote.
    let seen = c.ids.describe_user().identity_store_id(&c.store).user_id(&user).send().await.unwrap();
    assert_eq!(seen.display_name(), Some("Dana"));
    member
        .delete_group_membership()
        .identity_store_id(&c.store)
        .membership_id(membership.membership_id())
        .send()
        .await
        .unwrap();
    member.delete_group().identity_store_id(&c.store).group_id(&group).send().await.unwrap();
    member.delete_user().identity_store_id(&c.store).user_id(&user).send().await.unwrap();
}

#[tokio::test]
async fn sso_actions_are_scoped_by_account_and_tags() {
    let c = center().await;
    let bob = c.user("bob", "Engineer").await;
    let ps = c.permission_set("Eng").await;
    c.admin
        .tag_resource()
        .instance_arn(&c.instance_arn)
        .resource_arn(&ps)
        .tags(Tag::builder().key("team").value("blue").build().unwrap())
        .send()
        .await
        .unwrap();
    let other = c.permission_set("Other").await;

    // A delegate who may assign only into the member account, describe only
    // blue permission sets and create only blue ones.
    let policy = json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sso:CreateAccountAssignment",
         "Resource": [c.instance_arn, "arn:aws:sso:::permissionSet/*", format!("arn:aws:sso:::account/{}", c.member)]},
        {"Effect": "Allow", "Action": "sso:DescribePermissionSet", "Resource": c.instance_arn},
        {"Effect": "Allow", "Action": "sso:DescribePermissionSet", "Resource": "arn:aws:sso:::permissionSet/*",
         "Condition": {"StringEquals": {"aws:ResourceTag/team": "blue"}}},
        {"Effect": "Allow", "Action": "sso:CreatePermissionSet", "Resource": "*",
         "Condition": {"StringEquals": {"aws:RequestTag/team": "blue"}, "ForAllValues:StringEquals": {"aws:TagKeys": ["team"]}}}
    ]});
    let (_, cfg) = user_with_policy(&c.mws, "delegate", Some(&policy.to_string())).await;
    let delegate = SsoAdmin::new(&cfg);
    let assign = |account: &str| {
        delegate
            .create_account_assignment()
            .instance_arn(&c.instance_arn)
            .target_id(account)
            .target_type(TargetType::AwsAccount)
            .permission_set_arn(&ps)
            .principal_type(PrincipalType::User)
            .principal_id(&bob)
            .send()
    };
    assign(&c.member).await.unwrap();
    let err = assign(MANAGEMENT).await.unwrap_err();
    assert_eq!(aws_sdk_ssoadmin::error::ProvideErrorMetadata::code(&err), Some("AccessDeniedException"));
    let message = aws_sdk_ssoadmin::error::ProvideErrorMetadata::message(&err).unwrap().to_string();
    assert!(message.contains(&format!("arn:aws:sso:::account/{MANAGEMENT}")), "{message}");

    let describe =
        |arn: &str| delegate.describe_permission_set().instance_arn(&c.instance_arn).permission_set_arn(arn).send();
    describe(&ps).await.unwrap();
    describe(&other).await.unwrap_err();

    let create = |tag: Option<(&str, &str)>| {
        let mut req = delegate.create_permission_set().instance_arn(&c.instance_arn).name("Delegated");
        if let Some((k, v)) = tag {
            req = req.tags(Tag::builder().key(k).value(v).build().unwrap());
        }
        req.send()
    };
    create(None).await.unwrap_err();
    create(Some(("team", "red"))).await.unwrap_err();
    create(Some(("team", "blue"))).await.unwrap();
}
