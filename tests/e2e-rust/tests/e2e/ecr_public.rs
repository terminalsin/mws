//! Amazon ECR Public through the official Rust SDK, and its public
//! registry endpoint (anonymous pulls, authenticated pushes).

use aws_sdk_ecrpublic::error::ProvideErrorMetadata;
use aws_sdk_ecrpublic::primitives::Blob;
use aws_sdk_ecrpublic::types::{ImageIdentifier, RepositoryCatalogDataInput, Tag};
use aws_sdk_ecrpublic::Client;
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};
use sha2_010::{Digest, Sha256};

use crate::ecr::{build_image, docker_available, run_docker};

const ACCOUNT: &str = "123456789012";
/// A 1x1 PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89,
];

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn digest(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

async fn upload(ecr: &Client, repo: &str, data: &[u8]) -> String {
    let up = ecr.initiate_layer_upload().repository_name(repo).send().await.unwrap();
    let id = up.upload_id().unwrap().to_string();
    ecr.upload_layer_part()
        .repository_name(repo)
        .upload_id(&id)
        .part_first_byte(0)
        .part_last_byte(data.len() as i64 - 1)
        .layer_part_blob(Blob::new(data))
        .send()
        .await
        .unwrap();
    let d = digest(data);
    ecr.complete_layer_upload().repository_name(repo).upload_id(&id).layer_digests(&d).send().await.unwrap();
    d
}

async fn push(ecr: &Client, repo: &str, tag: &str, content: &str) -> (String, String) {
    let config = format!(r#"{{"architecture":"arm64","os":"linux","config":{{"Env":["X={content}"]}}}}"#);
    let config_digest = upload(ecr, repo, config.as_bytes()).await;
    let layer = format!("public {content}").into_bytes();
    let layer_digest = upload(ecr, repo, &layer).await;
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": config.len(), "digest": config_digest},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": layer.len(), "digest": layer_digest}],
    })
    .to_string();
    let out = ecr.put_image().repository_name(repo).image_tag(tag).image_manifest(&manifest).send().await.unwrap();
    (out.image().unwrap().image_id().unwrap().image_digest().unwrap().to_string(), manifest)
}

#[tokio::test]
async fn registries_repositories_and_catalog_data() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;

    let regs = ecr.describe_registries().send().await.unwrap();
    let reg = &regs.registries()[0];
    assert_eq!(reg.registry_id(), ACCOUNT);
    let alias = reg.aliases()[0].name().to_string();
    assert!(reg.aliases()[0].default_registry_alias());
    assert_eq!(reg.registry_uri(), format!("public.ecr.aws/{alias}"));

    ecr.put_registry_catalog_data().display_name("MWS Labs").send().await.unwrap();
    let cat = ecr.get_registry_catalog_data().send().await.unwrap();
    assert_eq!(cat.registry_catalog_data().unwrap().display_name(), Some("MWS Labs"));

    let created = ecr
        .create_repository()
        .repository_name("tools/cli")
        .catalog_data(
            RepositoryCatalogDataInput::builder()
                .description("A CLI")
                .architectures("ARM 64")
                .operating_systems("Linux")
                .about_text("# About")
                .logo_image_blob(Blob::new(PNG))
                .build(),
        )
        .tags(Tag::builder().key("team").value("cli").build())
        .send()
        .await
        .unwrap();
    let repo = created.repository().unwrap();
    let arn = repo.repository_arn().unwrap().to_string();
    assert_eq!(arn, format!("arn:aws:ecr-public::{ACCOUNT}:repository/tools/cli"));
    assert_eq!(repo.repository_uri(), Some(format!("public.ecr.aws/{alias}/tools/cli").as_str()));
    let logo = created.catalog_data().unwrap().logo_url().unwrap().to_string();
    let (status, _, body) = mws.raw("GET", &logo, &[], b"").await;
    assert_eq!((status, body.as_slice()), (200, PNG));
    let e = ecr.create_repository().repository_name("tools/cli").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryAlreadyExistsException");
    let e = ecr
        .create_repository()
        .repository_name("bad-arch")
        .catalog_data(RepositoryCatalogDataInput::builder().architectures("sparc").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "InvalidParameterException");

    let d = ecr.describe_repositories().send().await.unwrap();
    assert_eq!(d.repositories().len(), 1);
    let e = ecr.describe_repositories().repository_names("nope").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryNotFoundException");

    ecr.put_repository_catalog_data()
        .repository_name("tools/cli")
        .catalog_data(RepositoryCatalogDataInput::builder().description("The CLI").usage_text("docker run it").build())
        .send()
        .await
        .unwrap();
    let got = ecr.get_repository_catalog_data().repository_name("tools/cli").send().await.unwrap();
    let c = got.catalog_data().unwrap();
    assert_eq!(c.description(), Some("The CLI"));
    assert_eq!(c.usage_text(), Some("docker run it"));
    assert!(c.logo_url().is_some(), "the logo stays when not replaced");

    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":["ecr-public:PutImage"]}}]}}"#
    );
    ecr.set_repository_policy().repository_name("tools/cli").policy_text(&policy).send().await.unwrap();
    let got = ecr.get_repository_policy().repository_name("tools/cli").send().await.unwrap();
    assert_eq!(got.policy_text(), Some(policy.as_str()));
    ecr.delete_repository_policy().repository_name("tools/cli").send().await.unwrap();
    let e = ecr.get_repository_policy().repository_name("tools/cli").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryPolicyNotFoundException");

    ecr.tag_resource().resource_arn(&arn).tags(Tag::builder().key("env").value("prod").build()).send().await.unwrap();
    ecr.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = ecr.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    let tags: Vec<_> = tags.tags().iter().map(|t| (t.key(), t.value())).collect();
    assert_eq!(tags, vec![(Some("env"), Some("prod"))]);

    push(&ecr, "tools/cli", "v1", "x").await;
    let e = ecr.delete_repository().repository_name("tools/cli").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "RepositoryNotEmptyException");
    ecr.delete_repository().repository_name("tools/cli").force(true).send().await.unwrap();
    assert!(ecr.describe_repositories().send().await.unwrap().repositories().is_empty());
}

#[tokio::test]
async fn images_and_anonymous_registry_pulls() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    ecr.create_repository().repository_name("base").send().await.unwrap();
    let (d1, manifest) = push(&ecr, "base", "v1", "one").await;
    let e = ecr.put_image().repository_name("base").image_tag("v1").image_manifest(&manifest).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ImageAlreadyExistsException");
    let (d2, _) = push(&ecr, "base", "v2", "two").await;
    ecr.put_image().repository_name("base").image_tag("latest").image_manifest(&manifest).send().await.unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let layer = parsed["layers"][0]["digest"].as_str().unwrap().to_string();
    let check = ecr
        .batch_check_layer_availability()
        .repository_name("base")
        .layer_digests(&layer)
        .layer_digests(format!("sha256:{}", "0".repeat(64)))
        .send()
        .await
        .unwrap();
    assert_eq!(check.layers()[0].layer_availability().map(|a| a.as_str()), Some("AVAILABLE"));
    assert_eq!(check.failures()[0].failure_code().map(|c| c.as_str()), Some("MissingLayerDigest"));

    let images = ecr.describe_images().repository_name("base").send().await.unwrap();
    assert_eq!(images.image_details().len(), 2);
    let tags = ecr.describe_image_tags().repository_name("base").send().await.unwrap();
    let mut names: Vec<_> = tags.image_tag_details().iter().filter_map(|t| t.image_tag()).collect();
    names.sort();
    assert_eq!(names, ["latest", "v1", "v2"]);

    // Anonymous pulls through the registry API.
    let alias = ecr.describe_registries().send().await.unwrap().registries()[0].aliases()[0].name().to_string();
    let accept = "application/vnd.oci.image.manifest.v1+json";
    let (status, headers, body) =
        mws.raw("GET", &format!("/v2/public.ecr.aws/{alias}/base/manifests/v1"), &[("Accept", accept)], b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, manifest.as_bytes());
    assert!(headers.iter().any(|(k, v)| k == "docker-content-digest" && *v == d1));
    let (status, _, body) = mws.raw("GET", &format!("/v2/public.ecr.aws/{alias}/base/blobs/{layer}"), &[], b"").await;
    assert_eq!((status, body.as_slice()), (200, b"public one".as_slice()));
    // Pushing needs credentials.
    let (status, headers, _) =
        mws.raw("POST", &format!("/v2/public.ecr.aws/{alias}/base/blobs/uploads/"), &[], b"").await;
    assert_eq!(status, 401);
    assert!(headers.iter().any(|(k, _)| k == "www-authenticate"));
    let token = ecr.get_authorization_token().send().await.unwrap();
    let basic = token.authorization_data().unwrap().authorization_token().unwrap().to_string();
    let (status, _, _) = mws
        .raw(
            "POST",
            &format!("/v2/public.ecr.aws/{alias}/base/blobs/uploads/"),
            &[("Authorization", &format!("Basic {basic}"))],
            b"",
        )
        .await;
    assert_eq!(status, 202);

    let del = ecr
        .batch_delete_image()
        .repository_name("base")
        .image_ids(ImageIdentifier::builder().image_tag("latest").build())
        .image_ids(ImageIdentifier::builder().image_digest(&d2).build())
        .image_ids(ImageIdentifier::builder().image_tag("gone").build())
        .send()
        .await
        .unwrap();
    assert_eq!(del.image_ids().len(), 2);
    assert_eq!(del.failures()[0].failure_code().map(|c| c.as_str()), Some("ImageNotFound"));
    let images = ecr.describe_images().repository_name("base").send().await.unwrap();
    assert_eq!(images.image_details()[0].image_tags(), ["v1"]);

    let decoded = base64::engine::general_purpose::STANDARD.decode(&basic).unwrap();
    assert!(String::from_utf8(decoded).unwrap().starts_with("AWS:"));
}

#[tokio::test]
async fn iam_governs_public_api_and_pushes() {
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    ecr.create_repository().repository_name("locked").send().await.unwrap();
    let (_, cfg) = user_with_policy(
        &mws,
        "pusher",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecr-public:GetAuthorizationToken","sts:GetServiceBearerToken"],"Resource":"*"}]}"#),
    )
    .await;
    let dev = Client::new(&cfg);
    let e = dev.describe_repositories().send().await;
    assert!(e.unwrap().repositories().is_empty(), "unauthorized repositories are left out");
    let e = dev.put_registry_catalog_data().display_name("x").send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");
    let token = dev.get_authorization_token().send().await.unwrap();
    let basic = token.authorization_data().unwrap().authorization_token().unwrap().to_string();
    let alias = ecr.describe_registries().send().await.unwrap().registries()[0].aliases()[0].name().to_string();
    let (status, _, _) = mws
        .raw(
            "POST",
            &format!("/v2/public.ecr.aws/{alias}/locked/blobs/uploads/"),
            &[("Authorization", &format!("Basic {basic}"))],
            b"",
        )
        .await;
    assert_eq!(status, 403);
}

// Docker runs blocking, so the server needs a thread of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn docker_push_then_anonymous_pull() {
    if !docker_available() {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let mws = Mws::start().await;
    let ecr = client(&mws).await;
    let host = mws.endpoint.trim_start_matches("http://").to_string();
    ecr.create_repository().repository_name("hello").send().await.unwrap();
    let alias = ecr.describe_registries().send().await.unwrap().registries()[0].aliases()[0].name().to_string();
    let token = ecr.get_authorization_token().send().await.unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.authorization_data().unwrap().authorization_token().unwrap())
        .unwrap();
    let password = String::from_utf8(decoded).unwrap()["AWS:".len()..].to_string();
    let image = format!("{host}/public.ecr.aws/{alias}/hello:v1");
    build_image(&host, &image, "hello from ecr public");
    run_docker(&host, &["login", "-u", "AWS", "--password-stdin", &host], Some(&password));
    run_docker(&host, &["push", &image], None);
    run_docker(&host, &["logout", &host], None);
    run_docker(&host, &["rmi", &image], None);
    run_docker(&host, &["pull", &image], None);
    run_docker(&host, &["rmi", &image], None);
    let tags = ecr.describe_image_tags().repository_name("hello").send().await.unwrap();
    assert_eq!(tags.image_tag_details()[0].image_tag(), Some("v1"));
}
