//! AWS Identity Store through the official SDK: users, groups and
//! memberships of an IAM Identity Center instance's directory.

use aws_sdk_identitystore::error::ProvideErrorMetadata;
use aws_sdk_identitystore::types::{
    AlternateIdentifier, AttributeOperation, Email, Filter, MemberId, NetworkConfiguration, UniqueAttribute,
};
use aws_smithy_types::Document;

use crate::identity_center::center;

fn unique(path: &str, value: &str) -> AlternateIdentifier {
    AlternateIdentifier::UniqueAttribute(
        UniqueAttribute::builder()
            .attribute_path(path)
            .attribute_value(Document::String(value.into()))
            .build()
            .unwrap(),
    )
}

fn set(path: &str, value: Document) -> AttributeOperation {
    AttributeOperation::builder().attribute_path(path).attribute_value(value).build().unwrap()
}

#[tokio::test]
async fn users_groups_and_memberships() {
    let c = center().await;
    let ids = &c.ids;
    let store = c.store.as_str();

    let stores = ids.list_identity_stores().send().await.unwrap();
    assert_eq!(stores.identity_stores()[0].identity_store_id(), store);
    let described = ids.describe_identity_store().identity_store_id(store).send().await.unwrap();
    assert_eq!(described.identity_store_id(), store);
    let arn = described.identity_store_arn().to_string();
    assert_eq!(arn, format!("arn:aws:identitystore::123456789012:identitystore/{store}"));
    ids.update_identity_store()
        .identity_store_id(store)
        .network_configuration(NetworkConfiguration::builder().vpce_access_required(false).build().unwrap())
        .send()
        .await
        .unwrap();

    let alice = c.user("alice", "Engineer").await;
    let err =
        ids.create_user().identity_store_id(store).user_name("ALICE").display_name("Alice 2").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));

    let described = ids.describe_user().identity_store_id(store).user_id(&alice).send().await.unwrap();
    assert_eq!(described.user_name(), Some("alice"));
    assert_eq!(described.title(), Some("Engineer"));
    assert_eq!(described.emails()[0].value(), Some("alice@example.com"));

    let found =
        ids.get_user_id().identity_store_id(store).alternate_identifier(unique("emails.value", "alice@example.com"));
    assert_eq!(found.send().await.unwrap().user_id(), alice);
    let found = ids.get_user_id().identity_store_id(store).alternate_identifier(unique("userName", "alice"));
    assert_eq!(found.send().await.unwrap().user_id(), alice);
    let err = ids
        .get_user_id()
        .identity_store_id(store)
        .alternate_identifier(unique("userName", "nobody"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    ids.update_user()
        .identity_store_id(store)
        .user_id(&alice)
        .operations(set("displayName", Document::String("Alice Doe".into())))
        .operations(set("name.givenName", Document::String("Alicia".into())))
        .operations(set(
            "emails",
            Document::Array(vec![Document::Object(
                [
                    ("value".to_string(), Document::String("alicia@example.com".into())),
                    ("primary".to_string(), Document::Bool(true)),
                ]
                .into(),
            )]),
        ))
        .send()
        .await
        .unwrap();
    let described = ids.describe_user().identity_store_id(store).user_id(&alice).send().await.unwrap();
    assert_eq!(described.display_name(), Some("Alice Doe"));
    assert_eq!(described.name().unwrap().given_name(), Some("Alicia"));
    assert_eq!(described.emails()[0].value(), Some("alicia@example.com"));
    let err = ids
        .update_user()
        .identity_store_id(store)
        .user_id(&alice)
        .operations(set("nope", Document::String("x".into())))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));

    let bob = ids
        .create_user()
        .identity_store_id(store)
        .user_name("bob")
        .display_name("Bob")
        .emails(Email::builder().value("bob@example.com").primary(true).build())
        .send()
        .await
        .unwrap()
        .user_id()
        .to_string();
    let all = ids.list_users().identity_store_id(store).max_results(1).send().await.unwrap();
    assert_eq!(all.users().len(), 1);
    let rest = ids.list_users().identity_store_id(store).next_token(all.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.users().len(), 1);
    #[allow(deprecated)]
    let filtered = ids
        .list_users()
        .identity_store_id(store)
        .filters(Filter::builder().attribute_path("UserName").attribute_value("bob").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(filtered.users()[0].user_id(), bob);

    let group = ids
        .create_group()
        .identity_store_id(store)
        .display_name("Engineers")
        .description("Builds things")
        .send()
        .await
        .unwrap()
        .group_id()
        .to_string();
    let other = ids.create_group().identity_store_id(store).display_name("Ops").send().await.unwrap();
    let other = other.group_id().to_string();
    let err = ids.create_group().identity_store_id(store).display_name("engineers").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    let found = ids.get_group_id().identity_store_id(store).alternate_identifier(unique("displayName", "Engineers"));
    assert_eq!(found.send().await.unwrap().group_id(), group);
    ids.update_group()
        .identity_store_id(store)
        .group_id(&group)
        .operations(set("description", Document::String("Ships things".into())))
        .send()
        .await
        .unwrap();
    let described = ids.describe_group().identity_store_id(store).group_id(&group).send().await.unwrap();
    assert_eq!(described.description(), Some("Ships things"));
    #[allow(deprecated)]
    let groups = ids
        .list_groups()
        .identity_store_id(store)
        .filters(Filter::builder().attribute_path("DisplayName").attribute_value("Ops").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(groups.groups()[0].group_id(), other);
    assert_eq!(ids.list_groups().identity_store_id(store).send().await.unwrap().groups().len(), 2);

    let membership = ids
        .create_group_membership()
        .identity_store_id(store)
        .group_id(&group)
        .member_id(MemberId::UserId(alice.clone()))
        .send()
        .await
        .unwrap()
        .membership_id()
        .to_string();
    let err = ids
        .create_group_membership()
        .identity_store_id(store)
        .group_id(&group)
        .member_id(MemberId::UserId(alice.clone()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    let found = ids
        .get_group_membership_id()
        .identity_store_id(store)
        .group_id(&group)
        .member_id(MemberId::UserId(alice.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(found.membership_id(), membership);
    let described = ids.describe_group_membership().identity_store_id(store).membership_id(&membership).send().await;
    assert_eq!(described.unwrap().group_id(), group);
    let members = ids.list_group_memberships().identity_store_id(store).group_id(&group).send().await.unwrap();
    assert_eq!(members.group_memberships().len(), 1);
    let of = ids
        .list_group_memberships_for_member()
        .identity_store_id(store)
        .member_id(MemberId::UserId(alice.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(of.group_memberships()[0].group_id(), Some(group.as_str()));
    let check = ids
        .is_member_in_groups()
        .identity_store_id(store)
        .member_id(MemberId::UserId(alice.clone()))
        .group_ids(&group)
        .group_ids(&other)
        .send()
        .await
        .unwrap();
    let exists: Vec<bool> = check.results().iter().map(|r| r.membership_exists()).collect();
    assert_eq!(exists, [true, false]);

    ids.delete_group_membership().identity_store_id(store).membership_id(&membership).send().await.unwrap();
    let err = ids.describe_group_membership().identity_store_id(store).membership_id(&membership).send().await;
    assert_eq!(err.unwrap_err().code(), Some("ResourceNotFoundException"));
    ids.delete_group().identity_store_id(store).group_id(&other).send().await.unwrap();
    ids.delete_user().identity_store_id(store).user_id(&bob).send().await.unwrap();
    let err = ids.describe_user().identity_store_id(store).user_id(&bob).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    // Only principals the store's account allows may use it.
    let (_, nobody) = mws_e2e::user_with_policy(&c.mws, "nobody", None).await;
    let denied = aws_sdk_identitystore::Client::new(&nobody);
    let err = denied.list_users().identity_store_id(store).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
}
