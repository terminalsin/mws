//! Amazon ECR through the official Rust SDK, and its registry endpoint
//! through the Docker registry HTTP API v2 (raw HTTP, and the real Docker
//! CLI when a daemon answers).

use std::process::Command;

use aws_sdk_ecr::error::ProvideErrorMetadata;
use aws_sdk_ecr::primitives::Blob;
use aws_sdk_ecr::types::{
    EncryptionConfiguration, EncryptionType, ImageIdentifier, ImageTagMutability, LifecyclePolicyPreviewFilter,
    ListImagesFilter, RctAppliedFor, RegistryScanningRule, ReplicationConfiguration, ReplicationDestination,
    ReplicationRule, RepositoryFilter, RepositoryFilterType, ScanFrequency, ScanType, ScanningRepositoryFilter,
    ScanningRepositoryFilterType, SigningConfiguration, SigningRule, SubjectIdentifier, Tag, TargetStorageClass,
    UpstreamRegistry,
};
use aws_sdk_ecr::Client;
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};
use sha2_010::{Digest, Sha256};

const ACCOUNT: &str = "123456789012";

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

pub(crate) fn digest(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

async fn client_in(mws: &Mws, region: &str) -> Client {
    let conf = aws_sdk_ecr::config::Builder::from(&mws.root_sdk_config().await)
        .region(aws_sdk_ecr::config::Region::new(region.to_string()))
        .build();
    Client::from_conf(conf)
}

/// Upload a blob through the layer-upload API; returns its digest.
async fn upload(ecr: &Client, repo: &str, data: &[u8]) -> String {
    let up = ecr.initiate_layer_upload().repository_name(repo).send().await.unwrap();
    let id = up.upload_id().unwrap().to_string();
    let part = ecr
        .upload_layer_part()
        .repository_name(repo)
        .upload_id(&id)
        .part_first_byte(0)
        .part_last_byte(data.len() as i64 - 1)
        .layer_part_blob(Blob::new(data))
        .send()
        .await
        .unwrap();
    assert_eq!(part.last_byte_received(), Some(data.len() as i64 - 1));
    let d = digest(data);
    let done = ecr.complete_layer_upload().repository_name(repo).upload_id(&id).layer_digests(&d).send().await.unwrap();
    assert_eq!(done.layer_digest(), Some(d.as_str()));
    d
}

/// A Docker image manifest for one layer, with its config and layer
/// uploaded.
async fn image(ecr: &Client, repo: &str, content: &str) -> String {
    let config = format!(
        r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}},"config":{{"Env":["X={content}"]}}}}"#
    );
    let config_digest = upload(ecr, repo, config.as_bytes()).await;
    let layer = format!("layer {content}").into_bytes();
    let layer_digest = upload(ecr, repo, &layer).await;
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": config.len(), "digest": config_digest},
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": layer.len(), "digest": layer_digest}],
    })
    .to_string()
}

pub(crate) async fn push(ecr: &Client, repo: &str, tag: &str, content: &str) -> String {
    let manifest = image(ecr, repo, content).await;
    let out = ecr.put_image().repository_name(repo).image_tag(tag).image_manifest(&manifest).send().await.unwrap();
    out.image().unwrap().image_id().unwrap().image_digest().unwrap().to_string()
}

fn by_tag(tag: &str) -> ImageIdentifier {
    ImageIdentifier::builder().image_tag(tag).build()
}

fn by_digest(d: &str) -> ImageIdentifier {
    ImageIdentifier::builder().image_digest(d).build()
}

#[tokio::test]
async fn repositories_policies_tags_and_lifecycle_policies() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    let created = ecr
        .create_repository()
        .repository_name("team/app")
        .image_tag_mutability(ImageTagMutability::Immutable)
        .image_scanning_configuration(
            aws_sdk_ecr::types::ImageScanningConfiguration::builder().scan_on_push(true).build(),
        )
        .encryption_configuration(
            EncryptionConfiguration::builder().encryption_type(EncryptionType::Aes256).build().unwrap(),
        )
        .tags(Tag::builder().key("team").value("web").build().unwrap())
        .send()
        .await
        .unwrap();
    let repo = created.repository().unwrap();
    let arn = repo.repository_arn().unwrap().to_string();
    assert_eq!(arn, format!("arn:aws:ecr:us-east-1:{ACCOUNT}:repository/team/app"));
    assert_eq!(repo.repository_uri(), Some(format!("{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/team/app").as_str()));
    assert_eq!(repo.image_tag_mutability(), Some(&ImageTagMutability::Immutable));
    let e = ecr.create_repository().repository_name("team/app").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryAlreadyExistsException");
    let e = ecr.create_repository().repository_name("Upper").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "InvalidParameterException");

    let d = ecr.describe_repositories().repository_names("team/app").send().await.unwrap();
    assert_eq!(d.repositories()[0].repository_name(), Some("team/app"));
    let e = ecr.describe_repositories().repository_names("missing").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryNotFoundException");

    let m = ecr
        .put_image_tag_mutability()
        .repository_name("team/app")
        .image_tag_mutability(ImageTagMutability::Mutable)
        .send()
        .await
        .unwrap();
    assert_eq!(m.image_tag_mutability(), Some(&ImageTagMutability::Mutable));
    ecr.put_image_scanning_configuration()
        .repository_name("team/app")
        .image_scanning_configuration(
            aws_sdk_ecr::types::ImageScanningConfiguration::builder().scan_on_push(false).build(),
        )
        .send()
        .await
        .unwrap();
    let s = ecr.batch_get_repository_scanning_configuration().repository_names("team/app").send().await.unwrap();
    let conf = &s.scanning_configurations()[0];
    assert!(!conf.scan_on_push());
    assert_eq!(conf.scan_frequency(), Some(&ScanFrequency::Manual));

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"pull","Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":["ecr:BatchGetImage"]}}]}}"#
    );
    ecr.set_repository_policy().repository_name("team/app").policy_text(&policy).send().await.unwrap();
    let got = ecr.get_repository_policy().repository_name("team/app").send().await.unwrap();
    assert_eq!(got.policy_text(), Some(policy.as_str()));
    ecr.delete_repository_policy().repository_name("team/app").send().await.unwrap();
    let e = ecr.get_repository_policy().repository_name("team/app").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryPolicyNotFoundException");

    ecr.tag_resource()
        .resource_arn(&arn)
        .tags(Tag::builder().key("env").value("dev").build().unwrap())
        .send()
        .await
        .unwrap();
    ecr.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = ecr.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    let tags: Vec<_> = tags.tags().iter().map(|t| (t.key(), t.value())).collect();
    assert_eq!(tags, vec![("env", "dev")]);

    let lifecycle = r#"{"rules":[{"rulePriority":1,"description":"keep 1","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}}]}"#;
    ecr.put_lifecycle_policy().repository_name("team/app").lifecycle_policy_text(lifecycle).send().await.unwrap();
    let got = ecr.get_lifecycle_policy().repository_name("team/app").send().await.unwrap();
    assert_eq!(got.lifecycle_policy_text(), Some(lifecycle));
    ecr.delete_lifecycle_policy().repository_name("team/app").send().await.unwrap();
    let e = ecr.get_lifecycle_policy().repository_name("team/app").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "LifecyclePolicyNotFoundException");
    let e =
        ecr.put_lifecycle_policy().repository_name("team/app").lifecycle_policy_text("{}").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "InvalidParameterException");

    push(&ecr, "team/app", "v1", "a").await;
    let e = ecr.delete_repository().repository_name("team/app").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryNotEmptyException");
    ecr.delete_repository().repository_name("team/app").force(true).send().await.unwrap();
    assert!(ecr.describe_repositories().send().await.unwrap().repositories().is_empty());
}

#[tokio::test]
async fn layers_images_scans_and_storage_classes() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    ecr.create_repository().repository_name("app").send().await.unwrap();

    let manifest = image(&ecr, "app", "one").await;
    let put = ecr.put_image().repository_name("app").image_tag("v1").image_manifest(&manifest).send().await.unwrap();
    let d1 = put.image().unwrap().image_id().unwrap().image_digest().unwrap().to_string();
    assert_eq!(d1, digest(manifest.as_bytes()));
    let e = ecr.put_image().repository_name("app").image_tag("v1").image_manifest(&manifest).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ImageAlreadyExistsException");
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let layer = parsed["layers"][0]["digest"].as_str().unwrap().to_string();
    let missing = manifest.replace(&layer, &format!("sha256:{}", "1".repeat(64)));
    let e = ecr.put_image().repository_name("app").image_tag("bad").image_manifest(missing).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "LayersNotFoundException");
    let d2 = push(&ecr, "app", "v2", "two").await;

    // Layers: availability and download links.
    let check = ecr
        .batch_check_layer_availability()
        .repository_name("app")
        .layer_digests(&layer)
        .layer_digests(format!("sha256:{}", "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(check.layers()[0].layer_size(), Some(9));
    assert_eq!(check.failures()[0].failure_code().map(|c| c.as_str()), Some("MissingLayerDigest"));
    let url = ecr.get_download_url_for_layer().repository_name("app").layer_digest(&layer).send().await.unwrap();
    let (status, _, body) = mws.raw("GET", url.download_url().unwrap(), &[], b"").await;
    assert_eq!((status, body.as_slice()), (200, b"layer one".as_slice()));

    // Images.
    let got = ecr
        .batch_get_image()
        .repository_name("app")
        .image_ids(by_tag("v1"))
        .image_ids(by_tag("nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(got.images()[0].image_manifest(), Some(manifest.as_str()));
    assert_eq!(got.failures()[0].failure_code().map(|c| c.as_str()), Some("ImageNotFound"));
    let list = ecr.list_images().repository_name("app").send().await.unwrap();
    assert_eq!(list.image_ids().len(), 2);
    let tagged = ecr
        .list_images()
        .repository_name("app")
        .filter(ListImagesFilter::builder().tag_status(aws_sdk_ecr::types::TagStatus::Untagged).build())
        .send()
        .await
        .unwrap();
    assert!(tagged.image_ids().is_empty());
    let described = ecr.describe_images().repository_name("app").image_ids(by_tag("v1")).send().await.unwrap();
    let detail = &described.image_details()[0];
    assert_eq!(detail.image_digest(), Some(d1.as_str()));
    assert_eq!(detail.image_tags(), ["v1"]);
    assert!(detail.last_recorded_pull_time().is_some(), "BatchGetImage records the pull");

    // An artifact that refers to v1.
    let empty = upload(&ecr, "app", b"{}").await;
    let sbom = upload(&ecr, "app", b"sbom").await;
    let referrer = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/spdx+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "size": 2, "digest": empty},
        "layers": [{"mediaType": "application/spdx+json", "size": 4, "digest": sbom}],
        "subject": {"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "size": manifest.len(), "digest": d1},
    })
    .to_string();
    ecr.put_image().repository_name("app").image_manifest(&referrer).send().await.unwrap();
    let refs = ecr
        .list_image_referrers()
        .repository_name("app")
        .subject_id(SubjectIdentifier::builder().image_digest(&d1).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(refs.referrers()[0].artifact_type(), Some("application/spdx+json"));
    assert_eq!(refs.referrers()[0].digest(), digest(referrer.as_bytes()));

    // Scans finish on the emulated clock; one manual scan a day.
    let scan = ecr.start_image_scan().repository_name("app").image_id(by_tag("v1")).send().await.unwrap();
    assert_eq!(scan.image_scan_status().unwrap().status().map(|s| s.as_str()), Some("IN_PROGRESS"));
    let findings =
        ecr.describe_image_scan_findings().repository_name("app").image_id(by_tag("v1")).send().await.unwrap();
    assert_eq!(findings.image_scan_status().unwrap().status().map(|s| s.as_str()), Some("COMPLETE"));
    assert!(findings.image_scan_findings().unwrap().findings().is_empty());
    let e = ecr.start_image_scan().repository_name("app").image_id(by_tag("v1")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "LimitExceededException");
    let e = ecr.describe_image_scan_findings().repository_name("app").image_id(by_tag("v2")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ScanNotFoundException");

    let signing =
        ecr.describe_image_signing_status().repository_name("app").image_id(by_tag("v1")).send().await.unwrap();
    assert!(signing.signing_statuses().is_empty());
    let repl =
        ecr.describe_image_replication_status().repository_name("app").image_id(by_tag("v1")).send().await.unwrap();
    assert!(repl.replication_statuses().is_empty());

    // Archive v2, then restore it (20 minutes on the emulated clock).
    let archived = ecr
        .update_image_storage_class()
        .repository_name("app")
        .image_id(by_digest(&d2))
        .target_storage_class(TargetStorageClass::Archive)
        .send()
        .await
        .unwrap();
    assert_eq!(archived.image_status().map(|s| s.as_str()), Some("ARCHIVED"));
    let got = ecr.batch_get_image().repository_name("app").image_ids(by_tag("v2")).send().await.unwrap();
    assert!(got.images().is_empty(), "archived images can't be pulled");
    ecr.update_image_storage_class()
        .repository_name("app")
        .image_id(by_digest(&d2))
        .target_storage_class(TargetStorageClass::Standard)
        .send()
        .await
        .unwrap();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":1300}"#)).await;
    assert_eq!(status, 200);
    let got = ecr.batch_get_image().repository_name("app").image_ids(by_tag("v2")).send().await.unwrap();
    assert_eq!(got.images().len(), 1);

    // Lifecycle preview: keep the newest image.
    let policy = r#"{"rules":[{"rulePriority":1,"selection":{"tagStatus":"tagged","tagPrefixList":["v"],"countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}}]}"#;
    ecr.start_lifecycle_policy_preview().repository_name("app").lifecycle_policy_text(policy).send().await.unwrap();
    let preview = ecr
        .get_lifecycle_policy_preview()
        .repository_name("app")
        .filter(LifecyclePolicyPreviewFilter::builder().tag_status(aws_sdk_ecr::types::TagStatus::Tagged).build())
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status().map(|s| s.as_str()), Some("COMPLETE"));
    let expiring: Vec<_> = preview.preview_results().iter().filter_map(|r| r.image_digest()).collect();
    assert_eq!(expiring, vec![d1.as_str()]);

    // Deleting a tag of a multi-tag image only untags it.
    ecr.put_image().repository_name("app").image_tag("latest").image_manifest(&manifest).send().await.unwrap();
    let del = ecr.batch_delete_image().repository_name("app").image_ids(by_tag("latest")).send().await.unwrap();
    assert_eq!(del.image_ids()[0].image_tag(), Some("latest"));
    let del = ecr
        .batch_delete_image()
        .repository_name("app")
        .image_ids(by_digest(&d2))
        .image_ids(by_tag("gone"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.image_ids()[0].image_digest(), Some(d2.as_str()));
    assert_eq!(del.failures()[0].failure_code().map(|c| c.as_str()), Some("ImageNotFound"));

    let token = ecr.get_authorization_token().send().await.unwrap();
    let data = &token.authorization_data()[0];
    let decoded = base64::engine::general_purpose::STANDARD.decode(data.authorization_token().unwrap()).unwrap();
    assert!(String::from_utf8(decoded).unwrap().starts_with("AWS:"));
    assert_eq!(data.proxy_endpoint(), Some(format!("https://{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com").as_str()));
}

#[tokio::test]
async fn registry_settings_replication_and_templates() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"rep","Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":["ecr:CreateRepository","ecr:ReplicateImage"],"Resource":"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/*"}}]}}"#
    );
    ecr.put_registry_policy().policy_text(&policy).send().await.unwrap();
    assert_eq!(ecr.get_registry_policy().send().await.unwrap().policy_text(), Some(policy.as_str()));
    ecr.delete_registry_policy().send().await.unwrap();
    let e = ecr.get_registry_policy().send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RegistryPolicyNotFoundException");

    // Replication to another region of the same account.
    let dest = ReplicationDestination::builder().region("us-west-2").registry_id(ACCOUNT).build().unwrap();
    let rule = ReplicationRule::builder()
        .destinations(dest.clone())
        .repository_filters(
            RepositoryFilter::builder().filter("prod").filter_type(RepositoryFilterType::PrefixMatch).build().unwrap(),
        )
        .build()
        .unwrap();
    ecr.create_repository().repository_name("prod/api").send().await.unwrap();
    let d = push(&ecr, "prod/api", "v1", "before").await;
    ecr.put_replication_configuration()
        .replication_configuration(ReplicationConfiguration::builder().rules(rule).build().unwrap())
        .send()
        .await
        .unwrap();
    let reg = ecr.describe_registry().send().await.unwrap();
    assert_eq!(reg.registry_id(), Some(ACCOUNT));
    assert_eq!(reg.replication_configuration().unwrap().rules().len(), 1);
    let d2 = push(&ecr, "prod/api", "v2", "after").await;
    let west = client_in(&mws, "us-west-2").await;
    let got = west.batch_get_image().repository_name("prod/api").image_ids(by_tag("v2")).send().await.unwrap();
    assert_eq!(got.images()[0].image_id().unwrap().image_digest(), Some(d2.as_str()));
    let status = ecr
        .describe_image_replication_status()
        .repository_name("prod/api")
        .image_id(by_tag("v2"))
        .send()
        .await
        .unwrap();
    assert_eq!(status.replication_statuses()[0].status().map(|s| s.as_str()), Some("COMPLETE"));
    // v1 predates the rule: a backfill copies it.
    assert!(west
        .batch_get_image()
        .repository_name("prod/api")
        .image_ids(by_tag("v1"))
        .send()
        .await
        .unwrap()
        .images()
        .is_empty());
    let backfill = ecr.start_replication_backfill().destination(dest.clone()).send().await.unwrap();
    let id = backfill.replication_backfill_id().unwrap().to_string();
    let listed = ecr.list_replication_backfills().send().await.unwrap();
    assert_eq!(listed.backfills()[0].replication_backfill_id(), id);
    let results = ecr.describe_replication_backfill_results().replication_backfill_id(&id).send().await.unwrap();
    assert!(results.results().iter().any(|r| r.image_id().and_then(|i| i.image_digest()) == Some(d.as_str())));
    let got = west.batch_get_image().repository_name("prod/api").image_ids(by_tag("v1")).send().await.unwrap();
    assert_eq!(got.images().len(), 1);
    let e = ecr.stop_replication_backfill().replication_backfill_id(&id).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ReplicationBackfillInvalidStatusException");

    // Registry scanning and account settings.
    ecr.put_registry_scanning_configuration()
        .scan_type(ScanType::Basic)
        .rules(
            RegistryScanningRule::builder()
                .scan_frequency(ScanFrequency::ScanOnPush)
                .repository_filters(
                    ScanningRepositoryFilter::builder()
                        .filter("*")
                        .filter_type(ScanningRepositoryFilterType::Wildcard)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let scanning = ecr.get_registry_scanning_configuration().send().await.unwrap();
    assert_eq!(scanning.scanning_configuration().unwrap().rules().len(), 1);
    let setting = ecr.get_account_setting().name("BASIC_SCAN_TYPE_VERSION").send().await.unwrap();
    assert_eq!(setting.value(), Some("AWS_NATIVE"));
    ecr.put_account_setting().name("BASIC_SCAN_TYPE_VERSION").value("CLAIR").send().await.unwrap();
    let setting = ecr.get_account_setting().name("BASIC_SCAN_TYPE_VERSION").send().await.unwrap();
    assert_eq!(setting.value(), Some("CLAIR"));

    // Signing configuration.
    let profile = format!("arn:aws:signer:us-east-1:{ACCOUNT}:/signing-profiles/ecr");
    ecr.put_signing_configuration()
        .signing_configuration(
            SigningConfiguration::builder()
                .rules(SigningRule::builder().signing_profile_arn(&profile).build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let got = ecr.get_signing_configuration().send().await.unwrap();
    assert_eq!(got.signing_configuration().unwrap().rules()[0].signing_profile_arn(), profile);
    ecr.delete_signing_configuration().send().await.unwrap();
    let e = ecr.get_signing_configuration().send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "SigningConfigurationNotFoundException");

    // Pull-time update exclusions.
    let role = format!("arn:aws:iam::{ACCOUNT}:role/scanner");
    ecr.register_pull_time_update_exclusion().principal_arn(&role).send().await.unwrap();
    let listed = ecr.list_pull_time_update_exclusions().send().await.unwrap();
    assert_eq!(listed.pull_time_update_exclusions(), std::slice::from_ref(&role));
    ecr.deregister_pull_time_update_exclusion().principal_arn(&role).send().await.unwrap();
    assert!(ecr.list_pull_time_update_exclusions().send().await.unwrap().pull_time_update_exclusions().is_empty());

    // Pull-through cache rules.
    ecr.create_pull_through_cache_rule()
        .ecr_repository_prefix("quay")
        .upstream_registry_url("quay.io")
        .upstream_registry(UpstreamRegistry::Quay)
        .send()
        .await
        .unwrap();
    let rules = ecr.describe_pull_through_cache_rules().send().await.unwrap();
    assert_eq!(rules.pull_through_cache_rules()[0].upstream_registry_url(), Some("quay.io"));
    let e = ecr
        .create_pull_through_cache_rule()
        .ecr_repository_prefix("quay")
        .upstream_registry_url("quay.io")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "PullThroughCacheRuleAlreadyExistsException");
    let valid = ecr.validate_pull_through_cache_rule().ecr_repository_prefix("quay").send().await.unwrap();
    assert!(valid.is_valid());
    let e = ecr
        .update_pull_through_cache_rule()
        .ecr_repository_prefix("quay")
        .credential_arn(format!("arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:ecr-pullthroughcache/quay"))
        .send()
        .await;
    assert!(e.is_ok() || code(e.unwrap_err().as_service_error().unwrap()).ends_with("Exception"));
    ecr.delete_pull_through_cache_rule().ecr_repository_prefix("quay").send().await.unwrap();
    let e = ecr.delete_pull_through_cache_rule().ecr_repository_prefix("quay").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "PullThroughCacheRuleNotFoundException");

    // Creation templates: repositories created on push take their settings.
    ecr.create_repository_creation_template()
        .prefix("auto")
        .applied_for(RctAppliedFor::CreateOnPush)
        .image_tag_mutability(ImageTagMutability::Immutable)
        .resource_tags(Tag::builder().key("made").value("on-push").build().unwrap())
        .send()
        .await
        .unwrap();
    ecr.update_repository_creation_template().prefix("auto").description("pushed repos").send().await.unwrap();
    let templates = ecr.describe_repository_creation_templates().prefixes("auto").send().await.unwrap();
    assert_eq!(templates.repository_creation_templates()[0].description(), Some("pushed repos"));
    let token = ecr.get_authorization_token().send().await.unwrap();
    let auth = format!("Basic {}", token.authorization_data()[0].authorization_token().unwrap());
    let config = b"{}";
    let (status, _, _) = mws
        .raw(
            "POST",
            &format!("/v2/auto/svc/blobs/uploads/?digest={}", digest(config)),
            &[("Authorization", &auth)],
            config,
        )
        .await;
    assert_eq!(status, 201);
    let created = ecr.describe_repositories().repository_names("auto/svc").send().await.unwrap();
    assert_eq!(created.repositories()[0].image_tag_mutability(), Some(&ImageTagMutability::Immutable));
    ecr.delete_repository_creation_template().prefix("auto").send().await.unwrap();
    let e = ecr.delete_repository_creation_template().prefix("auto").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "TemplateNotFoundException");
}

#[tokio::test]
async fn iam_and_repository_policies_govern_access() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    ecr.create_repository().repository_name("shared").send().await.unwrap();
    push(&ecr, "shared", "v1", "x").await;
    let (_, cfg) = user_with_policy(
        &mws,
        "dev",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"}]}"#),
    )
    .await;
    let dev = Client::new(&cfg);
    let e = dev.batch_get_image().repository_name("shared").image_ids(by_tag("v1")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");

    // The registry endpoint applies the same rules to dev's password.
    let token = dev.get_authorization_token().send().await.unwrap();
    let auth = format!("Basic {}", token.authorization_data()[0].authorization_token().unwrap());
    let accept = "application/vnd.docker.distribution.manifest.v2+json";
    let (status, _, body) =
        mws.raw("GET", "/v2/shared/manifests/v1", &[("Authorization", &auth), ("Accept", accept)], b"").await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&body));

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:user/dev"}},"Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"]}}]}}"#
    );
    ecr.set_repository_policy().repository_name("shared").policy_text(policy).send().await.unwrap();
    assert_eq!(
        dev.batch_get_image().repository_name("shared").image_ids(by_tag("v1")).send().await.unwrap().images().len(),
        1
    );
    let (status, headers, _) =
        mws.raw("GET", "/v2/shared/manifests/v1", &[("Authorization", &auth), ("Accept", accept)], b"").await;
    assert_eq!(status, 200);
    assert!(headers.iter().any(|(k, v)| k == "docker-content-digest" && v.starts_with("sha256:")));
}

#[tokio::test]
async fn registry_api_challenges_and_token_exchange() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    ecr.create_repository().repository_name("web").send().await.unwrap();
    let d = push(&ecr, "web", "v1", "w").await;

    let (status, headers, _) = mws.raw("GET", "/v2/", &[], b"").await;
    assert_eq!(status, 401);
    let challenge = headers.iter().find(|(k, _)| k == "www-authenticate").map(|(_, v)| v.clone()).unwrap();
    assert!(challenge.starts_with("Bearer realm=\"http://"), "{challenge}");
    assert!(headers.iter().any(|(k, v)| k == "docker-distribution-api-version" && v == "registry/2.0"));

    let token = ecr.get_authorization_token().send().await.unwrap();
    let basic = token.authorization_data()[0].authorization_token().unwrap().to_string();
    let (status, _, body) = mws
        .raw("GET", "/_registry/token?service=ecr.amazonaws.com", &[("Authorization", &format!("Basic {basic}"))], b"")
        .await;
    assert_eq!(status, 200);
    let bearer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let bearer = format!("Bearer {}", bearer["token"].as_str().unwrap());
    let (status, _, _) = mws.raw("GET", "/v2/", &[("Authorization", &bearer)], b"").await;
    assert_eq!(status, 200);

    let (status, headers, _) = mws
        .raw(
            "HEAD",
            "/v2/web/manifests/v1",
            &[("Authorization", &bearer), ("Accept", "application/vnd.docker.distribution.manifest.v2+json")],
            b"",
        )
        .await;
    assert_eq!(status, 200);
    assert!(headers.iter().any(|(k, v)| k == "docker-content-digest" && *v == d));
    let (status, _, body) = mws.raw("GET", "/v2/web/tags/list", &[("Authorization", &bearer)], b"").await;
    assert_eq!(status, 200);
    let tags: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(tags, serde_json::json!({"name": "web", "tags": ["v1"]}));
    let (status, _, body) = mws.raw("GET", "/v2/web/manifests/nope", &[("Authorization", &bearer)], b"").await;
    assert_eq!(status, 404);
    assert!(String::from_utf8_lossy(&body).contains("MANIFEST_UNKNOWN"));
}

/// Run `docker` with a config directory of `host`'s own, so that tests
/// running at once don't share (and race on) stored credentials.
pub(crate) fn docker(host: &str, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    use std::io::Write;
    let config = std::env::temp_dir().join(format!("mws-docker-{}", host.replace([':', '.'], "-")));
    let mut child = Command::new("docker")
        .env("DOCKER_CONFIG", config)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

pub(crate) fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build a tiny image `tag` from scratch.
pub(crate) fn build_image(host: &str, tag: &str, content: &str) {
    let dir = std::env::temp_dir().join(format!("mws-ecr-{}", uuid_like()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hello.txt"), content).unwrap();
    std::fs::write(dir.join("Dockerfile"), "FROM scratch\nCOPY hello.txt /hello.txt\n").unwrap();
    let out = docker(host, &["build", "-q", "-t", tag, dir.to_str().unwrap()], None);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "docker build: {}", String::from_utf8_lossy(&out.stderr));
}

fn uuid_like() -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    format!("{}-{nanos}", std::process::id())
}

pub(crate) fn run_docker(host: &str, args: &[&str], stdin: Option<&str>) {
    let out = docker(host, args, stdin);
    assert!(
        out.status.success(),
        "docker {}: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// Docker runs blocking, so the server needs a thread of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn docker_push_and_pull_with_authorization_token() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    let host = mws.endpoint.trim_start_matches("http://").to_string();
    ecr.create_repository().repository_name("e2e/hello").send().await.unwrap();
    let token = ecr.get_authorization_token().send().await.unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.authorization_data()[0].authorization_token().unwrap())
        .unwrap();
    let password = String::from_utf8(decoded).unwrap()["AWS:".len()..].to_string();
    let image = format!("{host}/e2e/hello:v1");
    build_image(&host, &image, "hello from ecr");
    run_docker(&host, &["login", "-u", "AWS", "--password-stdin", &host], Some(&password));
    run_docker(&host, &["push", &image], None);
    let described = ecr.describe_images().repository_name("e2e/hello").image_ids(by_tag("v1")).send().await.unwrap();
    assert_eq!(described.image_details()[0].image_tags(), ["v1"]);
    run_docker(&host, &["rmi", &image], None);
    run_docker(&host, &["pull", &image], None);
    run_docker(&host, &["rmi", &image], None);
    run_docker(&host, &["logout", &host], None);
}
