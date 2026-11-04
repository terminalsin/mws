//! S3 Control resources beyond access points through the official Rust SDK:
//! Access Grants (which vend scoped credentials), Multi-Region Access
//! Points, Storage Lens, and access points for directory buckets.

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3control::error::ProvideErrorMetadata;
use aws_sdk_s3control::types::{
    AccessGrantsLocationConfiguration, CreateMultiRegionAccessPointInput, DeleteMultiRegionAccessPointInput, Grantee,
    GranteeType, MultiRegionAccessPointRoute, Permission, PutMultiRegionAccessPointPolicyInput, Region, Scope,
    ScopePermission, StorageLensConfiguration, StorageLensGroup, StorageLensGroupFilter, StorageLensTag, Tag,
};
use mws_e2e::{sts_config, user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn control(cfg: &aws_config::SdkConfig) -> aws_sdk_s3control::Client {
    aws_sdk_s3control::Client::new(cfg)
}

#[tokio::test]
async fn access_grants_vend_credentials_scoped_to_the_grant() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let control = control(&cfg);
    s3.create_bucket().bucket("data").send().await.unwrap();
    for k in ["team/a.txt", "other/b.txt"] {
        s3.put_object().bucket("data").key(k).body(ByteStream::from_static(b"x")).send().await.unwrap();
    }
    let iam = aws_sdk_iam::Client::new(&cfg);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"Service":"access-grants.s3.amazonaws.com"},"Action":["sts:AssumeRole","sts:SetSourceIdentity"]}]}"#;
    let role = iam.create_role().role_name("grants").assume_role_policy_document(trust).send().await.unwrap();
    let role = role.role().unwrap().arn().to_string();
    iam.put_role_policy()
        .role_name("grants")
        .policy_name("s3")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();

    // Nothing works before the instance exists.
    let e = control.list_access_grants().account_id(ACCOUNT).send().await.unwrap_err();
    assert_eq!(e.code(), Some("AccessGrantsInstanceNotExistsError"));
    let instance = control
        .create_access_grants_instance()
        .account_id(ACCOUNT)
        .tags(Tag::builder().key("env").value("test").build().unwrap())
        .send()
        .await
        .unwrap();
    let instance_arn = instance.access_grants_instance_arn().unwrap().to_string();
    assert!(instance_arn.ends_with(":access-grants/default"), "{instance_arn}");
    let e = control.create_access_grants_instance().account_id(ACCOUNT).send().await.unwrap_err();
    assert_eq!(e.code(), Some("AccessGrantsInstanceAlreadyExists"));

    let location = control
        .create_access_grants_location()
        .account_id(ACCOUNT)
        .location_scope("s3://")
        .iam_role_arn(&role)
        .send()
        .await
        .unwrap();
    let location_id = location.access_grants_location_id().unwrap().to_string();

    let (_, alice) = user_with_policy(
        &mws,
        "alice",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetDataAccess","s3:ListCallerAccessGrants"],"Resource":"*"}]}"#),
    )
    .await;
    let alice_arn = format!("arn:aws:iam::{ACCOUNT}:user/alice");
    let grant = control
        .create_access_grant()
        .account_id(ACCOUNT)
        .access_grants_location_id(&location_id)
        .access_grants_location_configuration(
            AccessGrantsLocationConfiguration::builder().s3_sub_prefix("data/team/*").build(),
        )
        .grantee(Grantee::builder().grantee_type(GranteeType::Iam).grantee_identifier(&alice_arn).build())
        .permission(Permission::Read)
        .send()
        .await
        .unwrap();
    assert_eq!(grant.grant_scope(), Some("s3://data/team/*"));
    let e = control
        .delete_access_grants_location()
        .account_id(ACCOUNT)
        .access_grants_location_id(&location_id)
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("AccessGrantsLocationNotEmptyError"));

    let prefix = control
        .get_access_grants_instance_for_prefix()
        .account_id(ACCOUNT)
        .s3_prefix("s3://data/team")
        .send()
        .await
        .unwrap();
    assert_eq!(prefix.access_grants_instance_arn(), Some(instance_arn.as_str()));

    // Alice's credentials can read what the grant covers and nothing else.
    let alice_control = aws_sdk_s3control::Client::new(&alice);
    let access = alice_control
        .get_data_access()
        .account_id(ACCOUNT)
        .target("s3://data/team/*")
        .permission(Permission::Read)
        .send()
        .await
        .unwrap();
    assert_eq!(access.matched_grant_target(), Some("s3://data/team/*"));
    let c = access.credentials().unwrap();
    let creds = aws_sdk_sts::types::Credentials::builder()
        .access_key_id(c.access_key_id().unwrap())
        .secret_access_key(c.secret_access_key().unwrap())
        .session_token(c.session_token().unwrap())
        .expiration(aws_sdk_sts::primitives::DateTime::from_secs(0))
        .build()
        .unwrap();
    let scoped = Mws::s3(&sts_config(&mws, &creds).await);
    scoped.get_object().bucket("data").key("team/a.txt").send().await.unwrap();
    let e = scoped.get_object().bucket("data").key("other/b.txt").send().await.unwrap_err();
    assert_eq!(aws_sdk_s3::error::ProvideErrorMetadata::code(&e), Some("AccessDenied"));
    let e = scoped
        .put_object()
        .bucket("data")
        .key("team/new.txt")
        .body(ByteStream::from_static(b"x"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_s3::error::ProvideErrorMetadata::code(&e), Some("AccessDenied"));
    let e = alice_control
        .get_data_access()
        .account_id(ACCOUNT)
        .target("s3://data/other/*")
        .permission(Permission::Read)
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("AccessDenied"));
    let e = alice_control
        .get_data_access()
        .account_id(ACCOUNT)
        .target("s3://data/team/*")
        .permission(Permission::Write)
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("AccessDenied"));

    // Grants take tags; the instance can't go while it has locations.
    let grant_arn = grant.access_grant_arn().unwrap();
    control
        .tag_resource()
        .account_id(ACCOUNT)
        .resource_arn(grant_arn)
        .tags(Tag::builder().key("team").value("a").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = control.list_tags_for_resource().account_id(ACCOUNT).resource_arn(grant_arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 1);
    let listed = control.list_access_grants().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(listed.access_grants_list().len(), 1);
    let caller = alice_control.list_caller_access_grants().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(caller.caller_access_grants_list()[0].grant_scope(), Some("s3://data/team/*"));
    let e = control.delete_access_grants_instance().account_id(ACCOUNT).send().await.unwrap_err();
    assert_eq!(e.code(), Some("AccessGrantsInstanceNotEmptyError"));
    control
        .delete_access_grant()
        .account_id(ACCOUNT)
        .access_grant_id(grant.access_grant_id().unwrap())
        .send()
        .await
        .unwrap();
    control
        .delete_access_grants_location()
        .account_id(ACCOUNT)
        .access_grants_location_id(&location_id)
        .send()
        .await
        .unwrap();
    control.delete_access_grants_instance().account_id(ACCOUNT).send().await.unwrap();
    let e = control.get_access_grants_instance().account_id(ACCOUNT).send().await.unwrap_err();
    assert_eq!(e.code(), Some("AccessGrantsInstanceNotExistsError"));
}

#[tokio::test]
async fn multi_region_access_points_complete_their_requests() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let control = control(&cfg);
    s3.create_bucket().bucket("east").send().await.unwrap();
    let west_cfg = cfg.to_builder().region(aws_config::Region::new("us-west-2")).build();
    Mws::s3(&west_cfg)
        .create_bucket()
        .bucket("west")
        .create_bucket_configuration(
            aws_sdk_s3::types::CreateBucketConfiguration::builder()
                .location_constraint(aws_sdk_s3::types::BucketLocationConstraint::UsWest2)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let details = CreateMultiRegionAccessPointInput::builder()
        .name("global")
        .regions(Region::builder().bucket("east").build().unwrap())
        .regions(Region::builder().bucket("west").build().unwrap())
        .build()
        .unwrap();
    let created = control
        .create_multi_region_access_point()
        .account_id(ACCOUNT)
        .client_token("t1")
        .details(details)
        .send()
        .await
        .unwrap();
    let token = created.request_token_arn().unwrap();
    let op = control
        .describe_multi_region_access_point_operation()
        .account_id(ACCOUNT)
        .request_token_arn(token)
        .send()
        .await
        .unwrap();
    let op = op.async_operation().unwrap();
    assert_eq!(op.request_status(), Some("SUCCEEDED"));

    let got = control.get_multi_region_access_point().account_id(ACCOUNT).name("global").send().await.unwrap();
    let report = got.access_point().unwrap();
    assert!(report.alias().unwrap().ends_with(".mrap"));
    let mut regions: Vec<_> = report.regions().iter().filter_map(|r| r.region()).collect();
    regions.sort();
    assert_eq!(regions, ["us-east-1", "us-west-2"]);
    let listed = control.list_multi_region_access_points().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(listed.access_points().len(), 1);

    // A public policy is refused while Block Public Access is on (the
    // default): the request fails asynchronously.
    let public = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}"#;
    let put = control
        .put_multi_region_access_point_policy()
        .account_id(ACCOUNT)
        .client_token("t2")
        .details(PutMultiRegionAccessPointPolicyInput::builder().name("global").policy(public).build().unwrap())
        .send()
        .await
        .unwrap();
    let op = control
        .describe_multi_region_access_point_operation()
        .account_id(ACCOUNT)
        .request_token_arn(put.request_token_arn().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(op.async_operation().unwrap().request_status(), Some("FAILED"));
    let private = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":"s3:GetObject","Resource":"*"}}]}}"#
    );
    control
        .put_multi_region_access_point_policy()
        .account_id(ACCOUNT)
        .client_token("t3")
        .details(PutMultiRegionAccessPointPolicyInput::builder().name("global").policy(&private).build().unwrap())
        .send()
        .await
        .unwrap();
    let policy =
        control.get_multi_region_access_point_policy().account_id(ACCOUNT).name("global").send().await.unwrap();
    assert_eq!(policy.policy().unwrap().established().unwrap().policy(), Some(private.as_str()));
    let status =
        control.get_multi_region_access_point_policy_status().account_id(ACCOUNT).name("global").send().await.unwrap();
    assert!(!status.established().unwrap().is_public());

    // Routes: turn the west bucket's traffic off.
    let mrap_arn = format!("arn:aws:s3::{ACCOUNT}:accesspoint/{}", report.alias().unwrap());
    control
        .submit_multi_region_access_point_routes()
        .account_id(ACCOUNT)
        .mrap(&mrap_arn)
        .route_updates(
            MultiRegionAccessPointRoute::builder().bucket("west").traffic_dial_percentage(0).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let routes =
        control.get_multi_region_access_point_routes().account_id(ACCOUNT).mrap(&mrap_arn).send().await.unwrap();
    let west = routes.routes().iter().find(|r| r.bucket() == Some("west")).unwrap();
    assert_eq!(west.traffic_dial_percentage(), 0);

    control
        .delete_multi_region_access_point()
        .account_id(ACCOUNT)
        .client_token("t4")
        .details(DeleteMultiRegionAccessPointInput::builder().name("global").build().unwrap())
        .send()
        .await
        .unwrap();
    let e = control.get_multi_region_access_point().account_id(ACCOUNT).name("global").send().await.unwrap_err();
    assert_eq!(e.code(), Some("NoSuchMultiRegionAccessPoint"));
}

#[tokio::test]
async fn storage_lens_dashboards_and_groups() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let control = control(&cfg);

    // Every account has the default dashboard, which can't be deleted.
    let listed = control.list_storage_lens_configurations().account_id(ACCOUNT).send().await.unwrap();
    let ids: Vec<_> = listed.storage_lens_configuration_list().iter().map(|c| c.id()).collect();
    assert_eq!(ids, ["default-account-dashboard"]);
    let e = control
        .delete_storage_lens_configuration()
        .account_id(ACCOUNT)
        .config_id("default-account-dashboard")
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("InvalidRequest"));

    let config = StorageLensConfiguration::builder()
        .id("mine")
        .is_enabled(true)
        .account_level(
            aws_sdk_s3control::types::AccountLevel::builder()
                .bucket_level(aws_sdk_s3control::types::BucketLevel::builder().build())
                .build(),
        )
        .build()
        .unwrap();
    control
        .put_storage_lens_configuration()
        .account_id(ACCOUNT)
        .config_id("mine")
        .storage_lens_configuration(config)
        .tags(StorageLensTag::builder().key("k").value("v").build().unwrap())
        .send()
        .await
        .unwrap();
    let got = control.get_storage_lens_configuration().account_id(ACCOUNT).config_id("mine").send().await.unwrap();
    let got = got.storage_lens_configuration().unwrap();
    assert_eq!(got.storage_lens_arn(), Some(format!("arn:aws:s3:us-east-1:{ACCOUNT}:storage-lens/mine").as_str()));
    let tags =
        control.get_storage_lens_configuration_tagging().account_id(ACCOUNT).config_id("mine").send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "k");
    control.delete_storage_lens_configuration_tagging().account_id(ACCOUNT).config_id("mine").send().await.unwrap();
    control.delete_storage_lens_configuration().account_id(ACCOUNT).config_id("mine").send().await.unwrap();
    let e = control.get_storage_lens_configuration().account_id(ACCOUNT).config_id("mine").send().await.unwrap_err();
    assert_eq!(e.code(), Some("NoSuchConfiguration"));

    let group = StorageLensGroup::builder()
        .name("logs")
        .filter(StorageLensGroupFilter::builder().match_any_prefix("logs/").build())
        .build()
        .unwrap();
    control
        .create_storage_lens_group()
        .account_id(ACCOUNT)
        .storage_lens_group(group)
        .tags(Tag::builder().key("team").value("ops").build().unwrap())
        .send()
        .await
        .unwrap();
    let got = control.get_storage_lens_group().account_id(ACCOUNT).name("logs").send().await.unwrap();
    let arn = got.storage_lens_group().unwrap().storage_lens_group_arn().unwrap().to_string();
    assert!(arn.ends_with(":storage-lens-group/logs"), "{arn}");
    let tags = control.list_tags_for_resource().account_id(ACCOUNT).resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags()[0].value(), "ops");
    let listed = control.list_storage_lens_groups().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(listed.storage_lens_group_list().len(), 1);
    control.delete_storage_lens_group().account_id(ACCOUNT).name("logs").send().await.unwrap();
    let e = control.get_storage_lens_group().account_id(ACCOUNT).name("logs").send().await.unwrap_err();
    assert_eq!(e.code(), Some("NoSuchStorageLensGroup"));
}

#[tokio::test]
async fn directory_bucket_access_points_take_scopes() {
    use aws_sdk_s3::types::{
        BucketInfo, BucketType, CreateBucketConfiguration, DataRedundancy, LocationInfo, LocationType,
    };
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let s3 = Mws::s3(&cfg);
    let control = control(&cfg);
    let bucket = "fast--use1-az4--x-s3";
    let config = CreateBucketConfiguration::builder()
        .location(LocationInfo::builder().r#type(LocationType::AvailabilityZone).name("use1-az4").build())
        .bucket(
            BucketInfo::builder()
                .r#type(BucketType::Directory)
                .data_redundancy(DataRedundancy::SingleAvailabilityZone)
                .build(),
        )
        .build();
    s3.create_bucket().bucket(bucket).create_bucket_configuration(config).send().await.unwrap();

    let e = control.create_access_point().account_id(ACCOUNT).name("ap").bucket(bucket).send().await.unwrap_err();
    assert_eq!(e.code(), Some("InvalidRequest"));
    let name = "ap--use1-az4--xa-s3";
    let scope = Scope::builder().prefixes("data/*").permissions(ScopePermission::GetObject).build();
    control.create_access_point().account_id(ACCOUNT).name(name).bucket(bucket).scope(scope).send().await.unwrap();
    let got = control.get_access_point_scope().account_id(ACCOUNT).name(name).send().await.unwrap();
    assert_eq!(got.scope().unwrap().prefixes(), ["data/*"]);
    let bad = Scope::builder().permissions(ScopePermission::from("Everything")).build();
    let e = control.put_access_point_scope().account_id(ACCOUNT).name(name).scope(bad).send().await.unwrap_err();
    assert_eq!(e.code(), Some("InvalidRequest"));
    control.delete_access_point_scope().account_id(ACCOUNT).name(name).send().await.unwrap();
    let got = control.get_access_point_scope().account_id(ACCOUNT).name(name).send().await.unwrap();
    assert!(got.scope().unwrap().prefixes().is_empty());

    let listed = control
        .list_access_points_for_directory_buckets()
        .account_id(ACCOUNT)
        .directory_bucket(bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.access_point_list()[0].name(), name);
    let general = control.list_access_points().account_id(ACCOUNT).send().await.unwrap();
    assert!(general.access_point_list().is_empty());

    // Scopes belong to directory bucket access points only.
    s3.create_bucket().bucket("plain").send().await.unwrap();
    let scope = Scope::builder().prefixes("x/*").build();
    let e = control
        .create_access_point()
        .account_id(ACCOUNT)
        .name("plain-ap")
        .bucket("plain")
        .scope(scope)
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("InvalidRequest"));
}

#[tokio::test]
async fn access_grants_locations_policies_and_identity_center() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let control = control(&cfg);
    let instance = control.create_access_grants_instance().account_id(ACCOUNT).send().await.unwrap();
    let listed = control.list_access_grants_instances().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(listed.access_grants_instances_list().len(), 1);

    let role = format!("arn:aws:iam::{ACCOUNT}:role/grants");
    let location = control
        .create_access_grants_location()
        .account_id(ACCOUNT)
        .location_scope("s3://data/")
        .iam_role_arn(&role)
        .send()
        .await
        .unwrap();
    let id = location.access_grants_location_id().unwrap();
    let other_role = format!("arn:aws:iam::{ACCOUNT}:role/other");
    control
        .update_access_grants_location()
        .account_id(ACCOUNT)
        .access_grants_location_id(id)
        .iam_role_arn(&other_role)
        .send()
        .await
        .unwrap();
    let got =
        control.get_access_grants_location().account_id(ACCOUNT).access_grants_location_id(id).send().await.unwrap();
    assert_eq!(got.iam_role_arn(), Some(other_role.as_str()));
    assert_eq!(got.location_scope(), Some("s3://data/"));
    let locations = control.list_access_grants_locations().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(locations.access_grants_locations_list().len(), 1);
    let e = control
        .get_access_grants_location()
        .account_id(ACCOUNT)
        .access_grants_location_id("nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("AccessGrantsLocationNotExistsError"));

    let grant = control
        .create_access_grant()
        .account_id(ACCOUNT)
        .access_grants_location_id(id)
        .grantee(
            Grantee::builder()
                .grantee_type(GranteeType::Iam)
                .grantee_identifier(format!("arn:aws:iam::{ACCOUNT}:user/bob"))
                .build(),
        )
        .permission(Permission::Readwrite)
        .send()
        .await
        .unwrap();
    let got = control
        .get_access_grant()
        .account_id(ACCOUNT)
        .access_grant_id(grant.access_grant_id().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(got.grant_scope(), Some("s3://data/*"));
    assert_eq!(got.permission(), Some(&Permission::Readwrite));

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::210987654321:root"}},"Action":"s3:GetDataAccess","Resource":"{}"}}]}}"#,
        instance.access_grants_instance_arn().unwrap()
    );
    control.put_access_grants_instance_resource_policy().account_id(ACCOUNT).policy(&policy).send().await.unwrap();
    let got = control.get_access_grants_instance_resource_policy().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(got.policy(), Some(policy.as_str()));
    control.delete_access_grants_instance_resource_policy().account_id(ACCOUNT).send().await.unwrap();
    let e =
        control.put_access_grants_instance_resource_policy().account_id(ACCOUNT).policy("{").send().await.unwrap_err();
    assert_eq!(e.code(), Some("MalformedPolicy"));

    let idc = "arn:aws:sso:::instance/ssoins-1234567890abcdef";
    control
        .associate_access_grants_identity_center()
        .account_id(ACCOUNT)
        .identity_center_arn(idc)
        .send()
        .await
        .unwrap();
    let got = control.get_access_grants_instance().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(got.identity_center_instance_arn(), Some(idc));
    control.dissociate_access_grants_identity_center().account_id(ACCOUNT).send().await.unwrap();
    let got = control.get_access_grants_instance().account_id(ACCOUNT).send().await.unwrap();
    assert_eq!(got.identity_center_instance_arn(), None);
}

#[tokio::test]
async fn storage_lens_tags_and_group_updates() {
    let mws = Mws::start().await;
    let control = control(&mws.root_sdk_config().await);
    let config = StorageLensConfiguration::builder()
        .id("dash")
        .is_enabled(false)
        .account_level(
            aws_sdk_s3control::types::AccountLevel::builder()
                .bucket_level(aws_sdk_s3control::types::BucketLevel::builder().build())
                .build(),
        )
        .build()
        .unwrap();
    control
        .put_storage_lens_configuration()
        .account_id(ACCOUNT)
        .config_id("dash")
        .storage_lens_configuration(config)
        .send()
        .await
        .unwrap();
    control
        .put_storage_lens_configuration_tagging()
        .account_id(ACCOUNT)
        .config_id("dash")
        .tags(StorageLensTag::builder().key("a").value("1").build().unwrap())
        .tags(StorageLensTag::builder().key("b").value("2").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags =
        control.get_storage_lens_configuration_tagging().account_id(ACCOUNT).config_id("dash").send().await.unwrap();
    assert_eq!(tags.tags().len(), 2);

    let group = |prefix: &str| {
        StorageLensGroup::builder()
            .name("g")
            .filter(StorageLensGroupFilter::builder().match_any_prefix(prefix).build())
            .build()
            .unwrap()
    };
    control.create_storage_lens_group().account_id(ACCOUNT).storage_lens_group(group("a/")).send().await.unwrap();
    control
        .update_storage_lens_group()
        .account_id(ACCOUNT)
        .name("g")
        .storage_lens_group(group("b/"))
        .send()
        .await
        .unwrap();
    let got = control.get_storage_lens_group().account_id(ACCOUNT).name("g").send().await.unwrap();
    assert_eq!(got.storage_lens_group().unwrap().filter().unwrap().match_any_prefix(), ["b/"]);
    let e = control
        .update_storage_lens_group()
        .account_id(ACCOUNT)
        .name("missing")
        .storage_lens_group(group("c/"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("InvalidRequest"));
}
