//! KMS work that AWS finishes asynchronously (replica creation, primary
//! Region updates) and the permissions that key creation depends on.

use aws_sdk_kms::error::ProvideErrorMetadata;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeyState, Tag};
use aws_sdk_kms::Client;
use mws_e2e::{user_with_policy, Mws};

use super::kms::wait_key_state;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn tag(k: &str, v: &str) -> Tag {
    Tag::builder().tag_key(k).tag_value(v).build().unwrap()
}

fn in_region(cfg: &aws_config::SdkConfig, region: &'static str) -> Client {
    Client::new(&cfg.to_builder().region(aws_config::Region::new(region)).build())
}

#[tokio::test]
async fn create_key_with_tags_needs_tag_resource() {
    let mws = Mws::start().await;
    let only_create =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "creator", Some(only_create)).await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let c = Client::new(&cfg);

    c.create_key().send().await.unwrap();
    let denied = c.create_key().tags(tag("team", "a")).send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    assert!(denied.message().unwrap().contains("kms:TagResource"), "{:?}", denied.message());

    iam.put_user_policy()
        .user_name("creator")
        .policy_name("tag")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:TagResource","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"a"}}}]}"#,
        )
        .send()
        .await
        .unwrap();
    let created = c.create_key().tags(tag("team", "a")).send().await.unwrap();
    assert_eq!(created.key_metadata().unwrap().key_state(), Some(&KeyState::Enabled));
    let other = c.create_key().tags(tag("team", "b")).send().await.unwrap_err();
    assert_eq!(code(&other), "AccessDeniedException");
}

#[tokio::test]
async fn replica_keys_are_creating_until_ready() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let c = Client::new(&root);
    let west = in_region(&root, "us-west-2");
    let key_id = c.create_key().multi_region(true).send().await.unwrap().key_metadata().unwrap().key_id().to_string();

    let out = c.replicate_key().key_id(&key_id).replica_region("us-west-2").send().await.unwrap();
    assert_eq!(out.replica_key_metadata().unwrap().key_state(), Some(&KeyState::Creating));
    assert!(!out.replica_key_metadata().unwrap().enabled());
    let described = west.describe_key().key_id(&key_id).send().await.unwrap();
    assert_eq!(described.key_metadata().unwrap().key_state(), Some(&KeyState::Creating));
    let busy = west.encrypt().key_id(&key_id).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&busy), "KMSInvalidStateException");
    assert!(busy.message().unwrap().ends_with(" is creating."), "{:?}", busy.message());

    wait_key_state(&west, &key_id, KeyState::Enabled).await;
    let enc = west.encrypt().key_id(&key_id).plaintext(Blob::new("x")).send().await.unwrap();
    let dec = c.decrypt().ciphertext_blob(enc.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"x");
}

#[tokio::test]
async fn replicate_key_needs_create_key_in_the_replica_region() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let c = Client::new(&root);
    let key_id = c.create_key().multi_region(true).send().await.unwrap().key_metadata().unwrap().key_id().to_string();

    // ReplicateKey on the primary, and CreateKey only in the primary Region.
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":["kms:ReplicateKey","kms:DescribeKey"],"Resource":"*"},
        {"Effect":"Allow","Action":"kms:CreateKey","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "replicator", Some(policy)).await;
    let iam = aws_sdk_iam::Client::new(&root);
    let u = Client::new(&cfg);
    let denied = u.replicate_key().key_id(&key_id).replica_region("us-west-2").send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    assert!(denied.message().unwrap().contains("kms:CreateKey"), "{:?}", denied.message());

    iam.put_user_policy()
        .user_name("replicator")
        .policy_name("west")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-west-2"}}}]}"#,
        )
        .send()
        .await
        .unwrap();
    // Tags on the replica also take kms:TagResource there.
    let untagged =
        u.replicate_key().key_id(&key_id).replica_region("us-west-2").tags(tag("team", "a")).send().await.unwrap_err();
    assert_eq!(code(&untagged), "AccessDeniedException");
    assert!(untagged.message().unwrap().contains("kms:TagResource"), "{:?}", untagged.message());
    u.replicate_key().key_id(&key_id).replica_region("us-west-2").send().await.unwrap();

    iam.put_user_policy()
        .user_name("replicator")
        .policy_name("tag")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:TagResource","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}"#,
        )
        .send()
        .await
        .unwrap();
    iam.put_user_policy()
        .user_name("replicator")
        .policy_name("west")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:CreateKey","Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let tagged =
        u.replicate_key().key_id(&key_id).replica_region("eu-west-1").tags(tag("team", "a")).send().await.unwrap();
    assert_eq!(tagged.replica_tags().len(), 1);
}

#[tokio::test]
async fn update_primary_region_puts_both_keys_in_updating() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let c = Client::new(&root);
    let eu = in_region(&root, "eu-west-1");
    let key_id = c.create_key().multi_region(true).send().await.unwrap().key_metadata().unwrap().key_id().to_string();
    c.replicate_key().key_id(&key_id).replica_region("eu-west-1").send().await.unwrap();

    // The replica cannot become the primary while it is still Creating.
    let early = c.update_primary_region().key_id(&key_id).primary_region("eu-west-1").send().await.unwrap_err();
    assert_eq!(code(&early), "KMSInvalidStateException");
    wait_key_state(&eu, &key_id, KeyState::Enabled).await;

    c.update_primary_region().key_id(&key_id).primary_region("eu-west-1").send().await.unwrap();
    for client in [&c, &eu] {
        let md = client.describe_key().key_id(&key_id).send().await.unwrap();
        assert_eq!(md.key_metadata().unwrap().key_state(), Some(&KeyState::Updating));
    }
    // Updating keys stay usable, but their state cannot change.
    c.encrypt().key_id(&key_id).plaintext(Blob::new("x")).send().await.unwrap();
    let busy = c.disable_key().key_id(&key_id).send().await.unwrap_err();
    assert_eq!(code(&busy), "KMSInvalidStateException");
    assert!(busy.message().unwrap().ends_with(" is updating."), "{:?}", busy.message());
    let again = c.update_primary_region().key_id(&key_id).primary_region("eu-west-1").send().await.unwrap_err();
    assert_eq!(code(&again), "KMSInvalidStateException");

    wait_key_state(&c, &key_id, KeyState::Enabled).await;
    wait_key_state(&eu, &key_id, KeyState::Enabled).await;
    let md = eu.describe_key().key_id(&key_id).send().await.unwrap();
    let mrc = md.key_metadata().unwrap().multi_region_configuration().unwrap();
    assert_eq!(mrc.multi_region_key_type().map(|t| t.as_str()), Some("PRIMARY"));
    assert_eq!(mrc.primary_key().unwrap().region(), Some("eu-west-1"));
}

#[tokio::test]
async fn update_primary_region_to_its_own_region_leaves_the_key_usable() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let c = in_region(&cfg, "us-east-1");
    let key = c.create_key().multi_region(true).send().await.unwrap();
    let id = key.key_metadata().unwrap().key_id().to_string();
    wait_key_state(&c, &id, KeyState::Enabled).await;
    c.update_primary_region().key_id(&id).primary_region("us-east-1").send().await.unwrap();
    let md = c.describe_key().key_id(&id).send().await.unwrap();
    assert_eq!(md.key_metadata().unwrap().key_state(), Some(&KeyState::Enabled));
    c.encrypt().key_id(&id).plaintext(Blob::new(b"x".to_vec())).send().await.unwrap();
}
