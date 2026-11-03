//! IAM through the official Rust SDK, unmodified apart from the endpoint.

use aws_sdk_iam::error::ProvideErrorMetadata;
use aws_sdk_iam::types::{StatusType, Tag};
use mws_e2e::Mws;

#[tokio::test]
async fn root_get_user_returns_root_arn() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let out = iam.get_user().send().await.unwrap();
    let user = out.user().unwrap();
    assert_eq!(user.arn(), "arn:aws:iam::123456789012:root");
    assert_eq!(user.user_id(), "123456789012");
}

#[tokio::test]
async fn user_lifecycle_and_their_own_credentials() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);

    let created = iam
        .create_user()
        .user_name("alice")
        .path("/engineering/")
        .tags(Tag::builder().key("team").value("platform").build().unwrap())
        .send()
        .await
        .unwrap();
    let alice = created.user().unwrap();
    assert_eq!(alice.arn(), "arn:aws:iam::123456789012:user/engineering/alice");
    assert!(alice.user_id().starts_with("AIDA"));
    assert_eq!(alice.tags()[0].value(), "platform");

    iam.attach_user_policy()
        .user_name("alice")
        .policy_arn("arn:aws:iam::aws:policy/IAMReadOnlyAccess")
        .send()
        .await
        .unwrap();
    let key = iam.create_access_key().user_name("alice").send().await.unwrap();
    let key = key.access_key().unwrap();
    assert_eq!(key.status(), &StatusType::Active);

    // Alice's own keys authenticate as Alice.
    let as_alice = aws_sdk_iam::Client::new(&mws.sdk_config(key.access_key_id(), key.secret_access_key(), None).await);
    let me = as_alice.get_user().send().await.unwrap();
    assert_eq!(me.user().unwrap().user_name(), "alice");

    // A deactivated key stops working.
    iam.update_access_key()
        .user_name("alice")
        .access_key_id(key.access_key_id())
        .status(StatusType::Inactive)
        .send()
        .await
        .unwrap();
    let err = as_alice.get_user().send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidClientTokenId"));

    // Keys must go before the user can.
    let err = iam.delete_user().user_name("alice").send().await.unwrap_err();
    assert_eq!(err.code(), Some("DeleteConflict"));
    assert!(err.as_service_error().unwrap().is_delete_conflict_exception());
    iam.delete_access_key().user_name("alice").access_key_id(key.access_key_id()).send().await.unwrap();
    let err = iam.delete_user().user_name("alice").send().await.unwrap_err();
    assert_eq!(err.message(), Some("Cannot delete entity, must detach all policies first."));
    iam.detach_user_policy()
        .user_name("alice")
        .policy_arn("arn:aws:iam::aws:policy/IAMReadOnlyAccess")
        .send()
        .await
        .unwrap();
    iam.delete_user().user_name("alice").send().await.unwrap();

    let err = iam.get_user().user_name("alice").send().await.unwrap_err();
    assert!(err.as_service_error().unwrap().is_no_such_entity_exception());
    assert_eq!(err.message(), Some("The user with name alice cannot be found."));
}

#[tokio::test]
async fn duplicate_names_are_case_insensitive() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_user().user_name("Bob").send().await.unwrap();
    let err = iam.create_user().user_name("bob").send().await.unwrap_err();
    assert!(err.as_service_error().unwrap().is_entity_already_exists_exception());
}

#[tokio::test]
async fn model_constraints_are_enforced() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let err = iam.create_user().user_name("not valid!").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationError"));
    assert_eq!(
        err.message(),
        Some("1 validation error detected: Value 'not valid!' at 'userName' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[\\w+=,.@-]+$")
    );
    let long = "x".repeat(65);
    let err = iam.create_user().user_name(&long).send().await.unwrap_err();
    assert!(err.message().unwrap().contains("Member must have length less than or equal to 64"));
}

#[tokio::test]
async fn list_users_paginates_with_the_sdk_paginator() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    for i in 0..7 {
        iam.create_user().user_name(format!("user{i}")).send().await.unwrap();
    }
    let pages: Vec<_> = iam.list_users().max_items(3).into_paginator().send().collect::<Vec<_>>().await;
    assert_eq!(pages.len(), 3);
    let names: Vec<String> = pages
        .into_iter()
        .flat_map(|p| p.unwrap().users().iter().map(|u| u.user_name().to_string()).collect::<Vec<_>>())
        .collect();
    assert_eq!(names, (0..7).map(|i| format!("user{i}")).collect::<Vec<_>>());
}

#[tokio::test]
async fn bad_credentials_are_rejected_like_aws() {
    let mws = Mws::start().await;
    let root = &mws.config.iam;

    let wrong_secret = aws_sdk_iam::Client::new(&mws.sdk_config(&root.root_access_key_id, "wrong", None).await);
    let err = wrong_secret.get_user().send().await.unwrap_err();
    assert_eq!(err.code(), Some("SignatureDoesNotMatch"));

    let unknown = aws_sdk_iam::Client::new(&mws.sdk_config("AKIAUNKNOWN000000000", "x", None).await);
    let err = unknown.get_user().send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidClientTokenId"));
}

#[tokio::test]
async fn unimplemented_operations_say_so() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let err = iam.list_server_certificates().send().await.unwrap_err();
    assert_eq!(err.code(), Some("NotImplemented"));
}
