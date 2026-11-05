//! CodeArtifact through the official Rust SDK, and its repository
//! endpoints through the npm, PyPI and Maven protocols (raw HTTP, and the
//! real `npm`, `pip`/`twine` and Gradle clients when they are installed).

use aws_sdk_codeartifact::error::ProvideErrorMetadata;
use aws_sdk_codeartifact::primitives::ByteStream;
use aws_sdk_codeartifact::types::{
    AllowPublish, AllowUpstream, PackageFormat, PackageGroupAllowedRepository, PackageGroupOriginRestrictionMode,
    PackageGroupOriginRestrictionType, PackageOriginRestrictions, PackageVersionStatus, Tag, UpstreamRepository,
};
use aws_sdk_codeartifact::Client;
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};
use sha2_010::Digest;

const ACCOUNT: &str = "123456789012";

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn upstream(name: &str) -> UpstreamRepository {
    UpstreamRepository::builder().repository_name(name).build().unwrap()
}

async fn token(ca: &Client, domain: &str) -> String {
    ca.get_authorization_token().domain(domain).send().await.unwrap().authorization_token().unwrap().to_string()
}

async fn endpoint(ca: &Client, domain: &str, repo: &str, format: PackageFormat) -> String {
    ca.get_repository_endpoint()
        .domain(domain)
        .repository(repo)
        .format(format)
        .send()
        .await
        .unwrap()
        .repository_endpoint()
        .unwrap()
        .to_string()
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn basic(token: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("aws:{token}")))
}

#[tokio::test]
async fn domains_repositories_policies_and_tags() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    let d = ca
        .create_domain()
        .domain("acme")
        .tags(Tag::builder().key("team").value("infra").build().unwrap())
        .send()
        .await
        .unwrap();
    let d = d.domain().unwrap();
    assert_eq!(d.name(), Some("acme"));
    assert_eq!(d.owner(), Some(ACCOUNT));
    assert_eq!(d.arn(), Some(format!("arn:aws:codeartifact:us-east-1:{ACCOUNT}:domain/acme").as_str()));
    assert_eq!(d.status().map(|s| s.as_str()), Some("Active"));
    assert!(d.encryption_key().unwrap().starts_with(&format!("arn:aws:kms:us-east-1:{ACCOUNT}:key/")));
    let dup = ca.create_domain().domain("acme").send().await.unwrap_err();
    assert_eq!(code(dup.into_service_error()), "ConflictException");
    let missing = ca.describe_domain().domain("nope").send().await.unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");

    ca.create_repository().domain("acme").repository("upstream").description("shared").send().await.unwrap();
    let r =
        ca.create_repository().domain("acme").repository("app").upstreams(upstream("upstream")).send().await.unwrap();
    let r = r.repository().unwrap();
    assert_eq!(r.upstreams()[0].repository_name(), Some("upstream"));
    assert_eq!(r.administrator_account(), Some(ACCOUNT));
    let bad = ca.create_repository().domain("acme").repository("xx").upstreams(upstream("ghost")).send().await;
    assert_eq!(code(bad.unwrap_err().into_service_error()), "ResourceNotFoundException");

    let described = ca.describe_domain().domain("acme").send().await.unwrap();
    assert_eq!(described.domain().unwrap().repository_count(), 2);
    assert_eq!(ca.list_domains().send().await.unwrap().domains().len(), 1);
    let in_domain = ca.list_repositories_in_domain().domain("acme").repository_prefix("ap").send().await.unwrap();
    assert_eq!(in_domain.repositories().len(), 1);
    assert_eq!(ca.list_repositories().send().await.unwrap().repositories().len(), 2);

    let updated = ca.update_repository().domain("acme").repository("app").description("the app").send().await.unwrap();
    assert_eq!(updated.repository().unwrap().description(), Some("the app"));
    assert_eq!(updated.repository().unwrap().upstreams().len(), 1);
    let described = ca.describe_repository().domain("acme").repository("app").send().await.unwrap();
    let described = described.repository().unwrap();
    assert_eq!(described.description(), Some("the app"));
    assert_eq!(described.arn(), Some(format!("arn:aws:codeartifact:us-east-1:{ACCOUNT}:repository/acme/app").as_str()));
    let missing = ca.describe_repository().domain("acme").repository("ghost").send().await.unwrap_err();
    assert_eq!(code(missing.into_service_error()), "ResourceNotFoundException");

    let ext = ca
        .associate_external_connection()
        .domain("acme")
        .repository("upstream")
        .external_connection("public:npmjs")
        .send()
        .await
        .unwrap();
    let conn = &ext.repository().unwrap().external_connections()[0];
    assert_eq!(conn.external_connection_name(), Some("public:npmjs"));
    assert_eq!(conn.package_format().map(|f| f.as_str()), Some("npm"));
    let bad = ca
        .associate_external_connection()
        .domain("acme")
        .repository("upstream")
        .external_connection("public:nope")
        .send()
        .await;
    assert_eq!(code(bad.unwrap_err().into_service_error()), "ValidationException");
    ca.disassociate_external_connection()
        .domain("acme")
        .repository("upstream")
        .external_connection("public:npmjs")
        .send()
        .await
        .unwrap();

    let url = endpoint(&ca, "acme", "app", PackageFormat::Npm).await;
    assert_eq!(url, format!("{}/_aws/codeartifact/us-east-1/acme-{ACCOUNT}/npm/app/", mws.endpoint));

    // Permissions policies, with revisions.
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":"codeartifact:*","Resource":"*"}}]}}"#
    );
    let put = ca.put_domain_permissions_policy().domain("acme").policy_document(&policy).send().await.unwrap();
    let revision = put.policy().unwrap().revision().unwrap().to_string();
    let stale = ca
        .put_domain_permissions_policy()
        .domain("acme")
        .policy_document(&policy)
        .policy_revision("stale")
        .send()
        .await;
    assert_eq!(code(stale.unwrap_err().into_service_error()), "ConflictException");
    let got = ca.get_domain_permissions_policy().domain("acme").send().await.unwrap();
    assert_eq!(got.policy().unwrap().document(), Some(policy.as_str()));
    ca.delete_domain_permissions_policy().domain("acme").policy_revision(revision).send().await.unwrap();
    let gone = ca.get_domain_permissions_policy().domain("acme").send().await.unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
    ca.put_repository_permissions_policy()
        .domain("acme")
        .repository("app")
        .policy_document(&policy)
        .send()
        .await
        .unwrap();
    let got = ca.get_repository_permissions_policy().domain("acme").repository("app").send().await.unwrap();
    assert!(got.policy().unwrap().resource_arn().unwrap().ends_with(":repository/acme/app"));
    ca.delete_repository_permissions_policy().domain("acme").repository("app").send().await.unwrap();
    let bad = ca.put_repository_permissions_policy().domain("acme").repository("app").policy_document("{").send().await;
    assert_eq!(code(bad.unwrap_err().into_service_error()), "ValidationException");

    // Tags.
    let arn = format!("arn:aws:codeartifact:us-east-1:{ACCOUNT}:domain/acme");
    let tags = ca.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "team");
    ca.tag_resource()
        .resource_arn(&arn)
        .tags(Tag::builder().key("env").value("dev").build().unwrap())
        .send()
        .await
        .unwrap();
    ca.untag_resource().resource_arn(&arn).tag_keys("team").send().await.unwrap();
    let tags = ca.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().iter().map(|t| t.key()).collect::<Vec<_>>(), vec!["env"]);

    // Deletion order is enforced.
    let busy = ca.delete_repository().domain("acme").repository("upstream").send().await.unwrap_err();
    assert_eq!(code(busy.into_service_error()), "ConflictException");
    let busy = ca.delete_domain().domain("acme").send().await.unwrap_err();
    assert_eq!(code(busy.into_service_error()), "ConflictException");
    ca.delete_repository().domain("acme").repository("app").send().await.unwrap();
    ca.delete_repository().domain("acme").repository("upstream").send().await.unwrap();
    let deleted = ca.delete_domain().domain("acme").send().await.unwrap();
    assert_eq!(deleted.domain().unwrap().name(), Some("acme"));
}

#[tokio::test]
async fn generic_packages_versions_and_statuses() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("gen").send().await.unwrap();
    ca.create_repository().domain("gen").repository("repo-a").send().await.unwrap();
    ca.create_repository().domain("gen").repository("repo-b").send().await.unwrap();

    let content = b"hello artifact".to_vec();
    let sha = hex::encode(sha2_010::Sha256::digest(&content));
    let publish = |version: &'static str, name: &'static str, unfinished: bool| {
        ca.publish_package_version()
            .domain("gen")
            .repository("repo-a")
            .format(PackageFormat::Generic)
            .namespace("tools")
            .package("cli")
            .package_version(version)
            .asset_name(name)
            .asset_sha256(&sha)
            .asset_content(ByteStream::from(content.clone()))
            .unfinished(unfinished)
            .send()
    };
    let first = publish("1.0.0", "cli-linux", true).await.unwrap();
    assert_eq!(first.status().map(|s| s.as_str()), Some("Unfinished"));
    let done = publish("1.0.0", "cli-mac", false).await.unwrap();
    assert_eq!(done.status().map(|s| s.as_str()), Some("Published"));
    assert_eq!(done.asset().unwrap().hashes().unwrap()[&aws_sdk_codeartifact::types::HashAlgorithm::Sha256], sha);
    let again = publish("1.0.0", "cli-win", false).await.unwrap_err();
    assert_eq!(code(again.into_service_error()), "ConflictException");
    publish("1.1.0", "cli-linux", false).await.unwrap();

    let packages = ca.list_packages().domain("gen").repository("repo-a").send().await.unwrap();
    let p = &packages.packages()[0];
    assert_eq!((p.namespace(), p.package()), (Some("tools"), Some("cli")));
    let origin = p.origin_configuration().unwrap().restrictions().unwrap();
    assert_eq!((origin.publish().as_str(), origin.upstream().as_str()), ("ALLOW", "BLOCK"));

    let versions = ca
        .list_package_versions()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .send()
        .await
        .unwrap();
    assert_eq!(versions.versions().iter().map(|v| v.version()).collect::<Vec<_>>(), vec!["1.1.0", "1.0.0"]);
    assert_eq!(versions.default_display_version(), Some("1.1.0"));

    let described = ca
        .describe_package_version()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .package_version("1.0.0")
        .send()
        .await
        .unwrap();
    let v = described.package_version().unwrap();
    assert_eq!(v.status(), Some(&PackageVersionStatus::Published));
    assert_eq!(v.origin().unwrap().origin_type().map(|o| o.as_str()), Some("INTERNAL"));
    assert_eq!(v.origin().unwrap().domain_entry_point().unwrap().repository_name(), Some("repo-a"));
    let revision = v.revision().unwrap().to_string();

    let assets = ca
        .list_package_version_assets()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .package_version("1.0.0")
        .send()
        .await
        .unwrap();
    assert_eq!(assets.assets().len(), 2);
    let asset = ca
        .get_package_version_asset()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .package_version("1.0.0")
        .asset("cli-mac")
        .send()
        .await
        .unwrap();
    assert_eq!(asset.package_version_revision(), Some(revision.as_str()));
    assert_eq!(asset.asset.collect().await.unwrap().into_bytes().as_ref(), content.as_slice());

    // Statuses: a wrong expected status fails that version only.
    let out = ca
        .update_package_versions_status()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .versions("1.0.0")
        .versions("9.9.9")
        .target_status(PackageVersionStatus::Archived)
        .send()
        .await
        .unwrap();
    assert_eq!(out.successful_versions().unwrap()["1.0.0"].status(), Some(&PackageVersionStatus::Archived));
    assert_eq!(out.failed_versions().unwrap()["9.9.9"].error_code().map(|c| c.as_str()), Some("NOT_FOUND"));
    let out = ca
        .update_package_versions_status()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .versions("1.1.0")
        .expected_status(PackageVersionStatus::Unlisted)
        .target_status(PackageVersionStatus::Archived)
        .send()
        .await
        .unwrap();
    assert_eq!(out.failed_versions().unwrap()["1.1.0"].error_code().map(|c| c.as_str()), Some("MISMATCHED_STATUS"));
    let archived = ca
        .get_package_version_asset()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .package_version("1.0.0")
        .asset("cli-mac")
        .send()
        .await;
    assert!(archived.is_err());

    // Copy, dispose, delete.
    let copied = ca
        .copy_package_versions()
        .domain("gen")
        .source_repository("repo-a")
        .destination_repository("repo-b")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .versions("1.1.0")
        .send()
        .await
        .unwrap();
    assert!(copied.successful_versions().unwrap().contains_key("1.1.0"));
    let again = ca
        .copy_package_versions()
        .domain("gen")
        .source_repository("repo-a")
        .destination_repository("repo-b")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .versions("1.1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(again.failed_versions().unwrap()["1.1.0"].error_code().map(|c| c.as_str()), Some("ALREADY_EXISTS"));
    let disposed = ca
        .dispose_package_versions()
        .domain("gen")
        .repository("repo-b")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .versions("1.1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(disposed.successful_versions().unwrap()["1.1.0"].status(), Some(&PackageVersionStatus::Disposed));
    let deleted = ca
        .delete_package_versions()
        .domain("gen")
        .repository("repo-b")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .versions("1.1.0")
        .send()
        .await
        .unwrap();
    assert!(deleted.successful_versions().unwrap().contains_key("1.1.0"));

    let readme = ca
        .get_package_version_readme()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .package_version("1.1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(readme.version(), Some("1.1.0"));
    let deps = ca
        .list_package_version_dependencies()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .package_version("1.1.0")
        .send()
        .await
        .unwrap();
    assert!(deps.dependencies().is_empty());

    let origin = ca
        .put_package_origin_configuration()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .restrictions(
            PackageOriginRestrictions::builder()
                .publish(AllowPublish::Block)
                .upstream(AllowUpstream::Allow)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(origin.origin_configuration().unwrap().restrictions().unwrap().publish(), &AllowPublish::Block);
    let blocked = publish("2.0.0", "cli-linux", false).await.unwrap_err();
    assert_eq!(code(blocked.into_service_error()), "AccessDeniedException");
    let described = ca
        .describe_package()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .send()
        .await
        .unwrap();
    assert_eq!(described.package().unwrap().name(), Some("cli"));
    ca.delete_package()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .send()
        .await
        .unwrap();
    let gone = ca
        .describe_package()
        .domain("gen")
        .repository("repo-a")
        .format(PackageFormat::Generic)
        .namespace("tools")
        .package("cli")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(gone.into_service_error()), "ResourceNotFoundException");
}

#[tokio::test]
async fn package_groups_and_origin_controls() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("grp").send().await.unwrap();
    ca.create_repository().domain("grp").repository("internal").send().await.unwrap();
    ca.create_repository().domain("grp").repository("other").send().await.unwrap();

    let root = ca.describe_package_group().domain("grp").package_group("/*").send().await.unwrap();
    let root = root.package_group().unwrap();
    assert!(root.parent().is_none());
    let publish =
        &root.origin_configuration().unwrap().restrictions().unwrap()[&PackageGroupOriginRestrictionType::Publish];
    assert_eq!(publish.mode(), Some(&PackageGroupOriginRestrictionMode::Allow));

    ca.create_package_group().domain("grp").package_group("/generic/*").send().await.unwrap();
    let child = ca
        .create_package_group()
        .domain("grp")
        .package_group("/generic/acme/*")
        .contact_info("team@example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(child.package_group().unwrap().parent().unwrap().pattern(), Some("/generic/*"));
    let bad = ca.create_package_group().domain("grp").package_group("/pypi/ns/x$").send().await;
    assert_eq!(code(bad.unwrap_err().into_service_error()), "ValidationException");
    let dup = ca.create_package_group().domain("grp").package_group("/generic/*").send().await;
    assert_eq!(code(dup.unwrap_err().into_service_error()), "ConflictException");

    let all = ca.list_package_groups().domain("grp").send().await.unwrap();
    assert_eq!(all.package_groups().len(), 3);
    let subs = ca.list_sub_package_groups().domain("grp").package_group("/generic/*").send().await.unwrap();
    assert_eq!(subs.package_groups()[0].pattern(), Some("/generic/acme/*"));
    let updated = ca
        .update_package_group()
        .domain("grp")
        .package_group("/generic/acme/*")
        .description("acme packages")
        .send()
        .await
        .unwrap();
    assert_eq!(updated.package_group().unwrap().description(), Some("acme packages"));

    // Only `internal` may publish acme packages.
    let out = ca
        .update_package_group_origin_configuration()
        .domain("grp")
        .package_group("/generic/acme/*")
        .restrictions(
            PackageGroupOriginRestrictionType::Publish,
            PackageGroupOriginRestrictionMode::AllowSpecificRepositories,
        )
        .add_allowed_repositories(
            PackageGroupAllowedRepository::builder()
                .repository_name("internal")
                .origin_restriction_type(PackageGroupOriginRestrictionType::Publish)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let updates = out.allowed_repository_updates().unwrap();
    assert_eq!(updates[&PackageGroupOriginRestrictionType::Publish][&"ADDED".into()], vec!["internal".to_string()]);
    let allowed = ca
        .list_allowed_repositories_for_group()
        .domain("grp")
        .package_group("/generic/acme/*")
        .origin_restriction_type(PackageGroupOriginRestrictionType::Publish)
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.allowed_repositories(), &["internal".to_string()]);

    let content = b"x".to_vec();
    let sha = hex::encode(sha2_010::Sha256::digest(&content));
    let publish_to = |repo: &'static str| {
        ca.publish_package_version()
            .domain("grp")
            .repository(repo)
            .format(PackageFormat::Generic)
            .namespace("acme")
            .package("lib")
            .package_version("1.0")
            .asset_name("lib.tar")
            .asset_sha256(&sha)
            .asset_content(ByteStream::from(content.clone()))
            .send()
    };
    let denied = publish_to("other").await.unwrap_err();
    assert_eq!(code(denied.into_service_error()), "AccessDeniedException");
    publish_to("internal").await.unwrap();

    let assoc = ca
        .get_associated_package_group()
        .domain("grp")
        .format(PackageFormat::Generic)
        .namespace("acme")
        .package("lib")
        .send()
        .await
        .unwrap();
    assert_eq!(assoc.package_group().unwrap().pattern(), Some("/generic/acme/*"));
    assert_eq!(assoc.association_type().map(|a| a.as_str()), Some("STRONG"));
    let listed = ca.list_associated_packages().domain("grp").package_group("/generic/acme/*").send().await.unwrap();
    assert_eq!(listed.packages()[0].package(), Some("lib"));

    let busy = ca.delete_package_group().domain("grp").package_group("/generic/*").send().await.unwrap_err();
    assert_eq!(code(busy.into_service_error()), "ConflictException");
    ca.delete_package_group().domain("grp").package_group("/generic/acme/*").send().await.unwrap();
    ca.delete_package_group().domain("grp").package_group("/generic/*").send().await.unwrap();
}

#[tokio::test]
async fn tokens_need_service_bearer_permission_and_authorize_reads() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("auth").send().await.unwrap();
    ca.create_repository().domain("auth").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "auth", "repo", PackageFormat::Npm).await;

    let (_, cfg) = user_with_policy(
        &mws,
        "no-bearer",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"codeartifact:*","Resource":"*"}]}"#),
    )
    .await;
    let denied = Client::new(&cfg).get_authorization_token().domain("auth").send().await.unwrap_err();
    assert_eq!(code(denied.into_service_error()), "AccessDeniedException");

    let (_, cfg) = user_with_policy(
        &mws,
        "token-only",
        Some(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["codeartifact:GetAuthorizationToken","sts:GetServiceBearerToken"],"Resource":"*"}]}"#,
        ),
    )
    .await;
    let limited = token(&Client::new(&cfg), "auth").await;
    let (status, _, _) = mws.raw("GET", &format!("{url}left-pad"), &[], b"").await;
    assert_eq!(status, 401);
    let (status, _, _) = mws.raw("GET", &format!("{url}left-pad"), &[("Authorization", "Bearer nope")], b"").await;
    assert_eq!(status, 401);
    let (status, _, _) = mws.raw("GET", &format!("{url}left-pad"), &[("Authorization", &bearer(&limited))], b"").await;
    assert_eq!(status, 403, "the token acts as a user without codeartifact:ReadFromRepository");
    let root = token(&ca, "auth").await;
    let (status, _, _) = mws.raw("GET", &format!("{url}left-pad"), &[("Authorization", &bearer(&root))], b"").await;
    assert_eq!(status, 404);

    let short = ca.get_authorization_token().domain("auth").duration_seconds(60).send().await.unwrap_err();
    assert_eq!(code(short.into_service_error()), "ValidationException");
}

fn npm_publish_body(name: &str, version: &str, tarball: &[u8], deps: serde_json::Value) -> Vec<u8> {
    let base = name.rsplit('/').next().unwrap();
    serde_json::json!({
        "_id": name,
        "name": name,
        "description": "a test package",
        "dist-tags": { "latest": version },
        "versions": { version: {
            "name": name, "version": version, "description": "a test package",
            "license": "MIT", "dependencies": deps,
            "dist": { "tarball": "ignored" }
        }},
        "readme": "# hello",
        "_attachments": { format!("{base}-{version}.tgz"): {
            "content_type": "application/octet-stream",
            "data": base64::engine::general_purpose::STANDARD.encode(tarball),
            "length": tarball.len()
        }}
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn npm_publish_install_and_upstream_retention() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("js").send().await.unwrap();
    ca.create_repository().domain("js").repository("shared").send().await.unwrap();
    ca.create_repository().domain("js").repository("app").upstreams(upstream("shared")).send().await.unwrap();
    let shared = endpoint(&ca, "js", "shared", PackageFormat::Npm).await;
    let app = endpoint(&ca, "js", "app", PackageFormat::Npm).await;
    let auth = bearer(&token(&ca, "js").await);
    let json = [("Authorization", auth.as_str()), ("Content-Type", "application/json")];

    let tarball = b"fake tarball bytes".to_vec();
    let body = npm_publish_body("@acme/util", "1.0.0", &tarball, serde_json::json!({ "left-pad": "^1.3.0" }));
    let (status, _, out) = mws.raw("PUT", &format!("{shared}@acme%2futil"), &json, &body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    let (status, _, _) = mws.raw("PUT", &format!("{shared}@acme%2futil"), &json, &body).await;
    assert_eq!(status, 409, "versions are immutable");

    // Through the downstream repository, the packument comes from upstream.
    let (status, _, out) = mws.raw("GET", &format!("{app}@acme%2futil"), &json, b"").await;
    assert_eq!(status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    let dist = &doc["versions"]["1.0.0"]["dist"];
    let tarball_url = dist["tarball"].as_str().unwrap().to_string();
    assert_eq!(tarball_url, format!("{app}@acme/util/-/util-1.0.0.tgz"));
    assert_eq!(dist["shasum"], hex::encode(sha1::Sha1::digest(&tarball)));
    assert_eq!(doc["versions"]["1.0.0"]["dependencies"]["left-pad"], "^1.3.0");

    let (status, _, got) = mws.raw("GET", &tarball_url, &json, b"").await;
    assert_eq!(status, 200);
    assert_eq!(got, tarball);

    // The download kept the version in `app`, published there from `shared`.
    let versions = ca
        .list_package_versions()
        .domain("js")
        .repository("app")
        .format(PackageFormat::Npm)
        .namespace("acme")
        .package("util")
        .send()
        .await
        .unwrap();
    let v = &versions.versions()[0];
    assert_eq!(v.version(), "1.0.0");
    assert_eq!(v.origin().unwrap().domain_entry_point().unwrap().repository_name(), Some("shared"));
    let pkg = ca
        .describe_package()
        .domain("js")
        .repository("app")
        .format(PackageFormat::Npm)
        .namespace("acme")
        .package("util")
        .send()
        .await
        .unwrap();
    let r = pkg.package().unwrap().origin_configuration().unwrap().restrictions().unwrap();
    assert_eq!((r.publish(), r.upstream()), (&AllowPublish::Block, &AllowUpstream::Allow));
    // ...so publishing it into `app` directly is blocked.
    let body = npm_publish_body("@acme/util", "2.0.0", &tarball, serde_json::json!({}));
    let (status, _, _) = mws.raw("PUT", &format!("{app}@acme%2futil"), &json, &body).await;
    assert_eq!(status, 403);

    let deps = ca
        .list_package_version_dependencies()
        .domain("js")
        .repository("shared")
        .format(PackageFormat::Npm)
        .namespace("acme")
        .package("util")
        .package_version("1.0.0")
        .send()
        .await
        .unwrap();
    assert_eq!(deps.dependencies()[0].package(), Some("left-pad"));
    assert_eq!(deps.dependencies()[0].dependency_type(), Some("regular"));
    let readme = ca
        .get_package_version_readme()
        .domain("js")
        .repository("shared")
        .format(PackageFormat::Npm)
        .namespace("acme")
        .package("util")
        .package_version("1.0.0")
        .send()
        .await
        .unwrap();
    assert_eq!(readme.readme(), Some("# hello"));

    // dist-tags.
    let (status, _, _) =
        mws.raw("PUT", &format!("{shared}-/package/@acme%2futil/dist-tags/beta"), &json, b"\"1.0.0\"").await;
    assert_eq!(status, 200);
    let (_, _, tags) = mws.raw("GET", &format!("{shared}-/package/@acme%2futil/dist-tags"), &json, b"").await;
    let tags: serde_json::Value = serde_json::from_slice(&tags).unwrap();
    assert_eq!(tags["beta"], "1.0.0");
}

#[tokio::test]
async fn pypi_upload_simple_index_and_download() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("py").send().await.unwrap();
    ca.create_repository().domain("py").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "py", "repo", PackageFormat::Pypi).await;
    let auth = basic(&token(&ca, "py").await);

    let wheel = b"PK fake wheel".to_vec();
    let mut body = Vec::new();
    let field = |body: &mut Vec<u8>, name: &str, value: &str| {
        body.extend_from_slice(
            format!("--BOUNDARY\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
        );
    };
    field(&mut body, ":action", "file_upload");
    field(&mut body, "name", "My_Pkg");
    field(&mut body, "version", "0.1.0");
    field(&mut body, "summary", "demo");
    field(&mut body, "requires_dist", "requests>=2");
    field(&mut body, "sha256_digest", &hex::encode(sha2_010::Sha256::digest(&wheel)));
    body.extend_from_slice(b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"content\"; filename=\"my_pkg-0.1.0-py3-none-any.whl\"\r\nContent-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(&wheel);
    body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");
    let headers = [("Authorization", auth.as_str()), ("Content-Type", "multipart/form-data; boundary=BOUNDARY")];
    let (status, _, out) = mws.raw("POST", &url, &headers, &body).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    let (status, _, _) = mws.raw("POST", &url, &headers, &body).await;
    assert_eq!(status, 409);

    let (status, h, _) = mws.raw("GET", &format!("{url}simple/my-pkg/"), &[], b"").await;
    assert_eq!(status, 401);
    assert!(h.iter().any(|(k, v)| k == "www-authenticate" && v.starts_with("Basic")));
    let (status, _, html) = mws.raw("GET", &format!("{url}simple/my-pkg/"), &[("Authorization", &auth)], b"").await;
    assert_eq!(status, 200);
    let html = String::from_utf8(html).unwrap();
    let href = html.split("href=\"").nth(1).unwrap().split('#').next().unwrap().to_string();
    assert!(html.contains(&format!("#sha256={}", hex::encode(sha2_010::Sha256::digest(&wheel)))));
    let (status, _, got) = mws.raw("GET", &href, &[("Authorization", &auth)], b"").await;
    assert_eq!(status, 200);
    assert_eq!(got, wheel);

    let v = ca
        .describe_package_version()
        .domain("py")
        .repository("repo")
        .format(PackageFormat::Pypi)
        .package("My_Pkg")
        .package_version("0.1.0")
        .send()
        .await
        .unwrap();
    let v = v.package_version().unwrap();
    assert_eq!(v.package_name(), Some("my-pkg"), "PyPI names are normalized");
    assert_eq!(v.summary(), Some("demo"));
    let deps = ca
        .list_package_version_dependencies()
        .domain("py")
        .repository("repo")
        .format(PackageFormat::Pypi)
        .package("my-pkg")
        .package_version("0.1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(deps.dependencies()[0].version_requirement(), Some(">=2"));
}

#[tokio::test]
async fn maven_deploy_publishes_on_metadata_and_resolves() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("jvm").send().await.unwrap();
    ca.create_repository().domain("jvm").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "jvm", "repo", PackageFormat::Maven).await;
    let auth = basic(&token(&ca, "jvm").await);
    let h = [("Authorization", auth.as_str())];

    let jar = b"jar bytes".to_vec();
    let pom = br#"<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>com.acme</groupId><artifactId>lib</artifactId><version>1.0</version><description>Acme lib</description><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency></dependencies></project>"#;
    for (file, data) in [("lib-1.0.jar", jar.as_slice()), ("lib-1.0.pom", pom.as_slice())] {
        let (status, _, _) = mws.raw("PUT", &format!("{url}com/acme/lib/1.0/{file}"), &h, data).await;
        assert_eq!(status, 201);
        let sha1 = hex::encode(sha1::Sha1::digest(data));
        let (status, _, _) = mws.raw("PUT", &format!("{url}com/acme/lib/1.0/{file}.sha1"), &h, sha1.as_bytes()).await;
        assert_eq!(status, 201);
    }
    let describe = || {
        ca.describe_package_version()
            .domain("jvm")
            .repository("repo")
            .format(PackageFormat::Maven)
            .namespace("com.acme")
            .package("lib")
            .package_version("1.0")
            .send()
    };
    assert_eq!(describe().await.unwrap().package_version().unwrap().status(), Some(&PackageVersionStatus::Unfinished));
    let metadata = b"<metadata><groupId>com.acme</groupId><artifactId>lib</artifactId><versioning><versions><version>1.0</version></versions></versioning></metadata>";
    let (status, _, _) = mws.raw("PUT", &format!("{url}com/acme/lib/maven-metadata.xml"), &h, metadata).await;
    assert_eq!(status, 201);
    let v = describe().await.unwrap();
    let v = v.package_version().unwrap();
    assert_eq!(v.status(), Some(&PackageVersionStatus::Published));
    assert_eq!(v.summary(), Some("Acme lib"));

    let (status, _, got) = mws.raw("GET", &format!("{url}com/acme/lib/1.0/lib-1.0.jar"), &h, b"").await;
    assert_eq!((status, got), (200, jar.clone()));
    let (_, _, sha1) = mws.raw("GET", &format!("{url}com/acme/lib/1.0/lib-1.0.jar.sha1"), &h, b"").await;
    assert_eq!(String::from_utf8(sha1).unwrap(), hex::encode(sha1::Sha1::digest(&jar)));
    let (status, _, xml) = mws.raw("GET", &format!("{url}com/acme/lib/maven-metadata.xml"), &h, b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8(xml).unwrap().contains("<release>1.0</release>"));
    let (status, _, _) = mws.raw("PUT", &format!("{url}com/acme/lib/1.0/lib-1.0.jar"), &h, b"other").await;
    assert_eq!(status, 409, "published releases are immutable");
    let deps = ca
        .list_package_version_dependencies()
        .domain("jvm")
        .repository("repo")
        .format(PackageFormat::Maven)
        .namespace("com.acme")
        .package("lib")
        .package_version("1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(deps.dependencies()[0].namespace(), Some("org.slf4j"));
}

/// A stand-in for registry.npmjs.org: one package, one version.
async fn fake_npm_registry() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let packument = serde_json::json!({
        "name": "left-pad",
        "dist-tags": { "latest": "1.3.0" },
        "versions": { "1.3.0": {
            "name": "left-pad", "version": "1.3.0", "license": "WTFPL",
            "dist": { "tarball": format!("{base}/left-pad/-/left-pad-1.3.0.tgz") }
        }}
    })
    .to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let packument = packument.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split(' ').nth(1).unwrap_or("").to_string();
                let (status, body) = match path.as_str() {
                    "/left-pad" => ("200 OK", packument.into_bytes()),
                    "/left-pad/-/left-pad-1.3.0.tgz" => ("200 OK", b"left-pad tarball".to_vec()),
                    _ => ("404 Not Found", b"{}".to_vec()),
                };
                let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    base
}

#[tokio::test]
async fn external_connections_ingest_from_the_public_registry() {
    let mws = Mws::start().await;
    mws.codeartifact.set_registry_url("public:npmjs", &fake_npm_registry().await);
    let ca = client(&mws).await;
    ca.create_domain().domain("ext").send().await.unwrap();
    ca.create_repository().domain("ext").repository("npm-store").send().await.unwrap();
    ca.associate_external_connection()
        .domain("ext")
        .repository("npm-store")
        .external_connection("public:npmjs")
        .send()
        .await
        .unwrap();
    ca.create_repository().domain("ext").repository("app").upstreams(upstream("npm-store")).send().await.unwrap();
    let app = endpoint(&ca, "ext", "app", PackageFormat::Npm).await;
    let auth = bearer(&token(&ca, "ext").await);
    let h = [("Authorization", auth.as_str())];

    let (status, _, out) = mws.raw("GET", &format!("{app}left-pad"), &h, b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let tarball = doc["versions"]["1.3.0"]["dist"]["tarball"].as_str().unwrap().to_string();
    assert!(tarball.starts_with(&app), "tarballs are served by the repository: {tarball}");
    let (status, _, got) = mws.raw("GET", &tarball, &h, b"").await;
    assert_eq!((status, got.as_slice()), (200, b"left-pad tarball".as_slice()));

    for repo in ["npm-store", "app"] {
        let v = ca
            .describe_package_version()
            .domain("ext")
            .repository(repo)
            .format(PackageFormat::Npm)
            .package("left-pad")
            .package_version("1.3.0")
            .send()
            .await
            .unwrap();
        let origin = v.package_version().unwrap().origin().unwrap();
        assert_eq!(origin.origin_type().map(|o| o.as_str()), Some("EXTERNAL"));
        assert_eq!(origin.domain_entry_point().unwrap().external_connection_name(), Some("public:npmjs"));
    }

    // Blocking upstreams for the package hides the public versions.
    ca.put_package_origin_configuration()
        .domain("ext")
        .repository("app")
        .format(PackageFormat::Npm)
        .package("other")
        .restrictions(
            PackageOriginRestrictions::builder()
                .publish(AllowPublish::Allow)
                .upstream(AllowUpstream::Block)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let (status, _, _) = mws.raw("GET", &format!("{app}other"), &h, b"").await;
    assert_eq!(status, 404);
}

/// Run a command; `None` when the program is not installed.
fn run(program: &str, args: &[&str], dir: &std::path::Path, env: &[(&str, &str)]) -> Option<std::process::Output> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).current_dir(dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().ok()
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("mws-codeartifact-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn real_npm_publishes_and_installs() {
    if run("npm", &["--version"], &std::env::temp_dir(), &[]).is_none() {
        eprintln!("npm is not installed; skipping");
        return;
    }
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("npmreal").send().await.unwrap();
    ca.create_repository().domain("npmreal").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "npmreal", "repo", PackageFormat::Npm).await;
    let token = token(&ca, "npmreal").await;
    let host_path = url.trim_start_matches("http:");
    let npmrc =
        format!("registry={url}\n{host_path}:_authToken={token}\naudit=false\nfund=false\nupdate-notifier=false\n");

    let lib = temp_dir("npm-lib");
    std::fs::write(lib.join(".npmrc"), &npmrc).unwrap();
    std::fs::write(
        lib.join("package.json"),
        r#"{"name":"@mws/greet","version":"1.2.3","description":"says hi","main":"index.js","license":"MIT"}"#,
    )
    .unwrap();
    std::fs::write(lib.join("index.js"), "module.exports = () => 'hi from codeartifact';\n").unwrap();
    let cache = temp_dir("npm-cache");
    let env = [("npm_config_cache", cache.to_str().unwrap()), ("npm_config_userconfig", "/dev/null")];
    let out = tokio::task::spawn_blocking({
        let lib = lib.clone();
        let env: Vec<(String, String)> = env.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        move || {
            let env: Vec<(&str, &str)> = env.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            run("npm", &["publish"], &lib, &env).unwrap()
        }
    })
    .await
    .unwrap();
    assert!(out.status.success(), "npm publish: {}", String::from_utf8_lossy(&out.stderr));

    let app = temp_dir("npm-app");
    std::fs::write(app.join(".npmrc"), &npmrc).unwrap();
    std::fs::write(app.join("package.json"), r#"{"name":"app","version":"1.0.0","private":true}"#).unwrap();
    let out = tokio::task::spawn_blocking({
        let app = app.clone();
        let cache = cache.clone();
        move || {
            run("npm", &["install", "@mws/greet@^1.2.0"], &app, &[("npm_config_cache", cache.to_str().unwrap())])
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(out.status.success(), "npm install: {}", String::from_utf8_lossy(&out.stderr));
    let installed = std::fs::read_to_string(app.join("node_modules/@mws/greet/index.js")).unwrap();
    assert!(installed.contains("hi from codeartifact"));

    let v = ca
        .describe_package_version()
        .domain("npmreal")
        .repository("repo")
        .format(PackageFormat::Npm)
        .namespace("mws")
        .package("greet")
        .package_version("1.2.3")
        .send()
        .await
        .unwrap();
    assert_eq!(v.package_version().unwrap().summary(), Some("says hi"));
    let _ = std::fs::remove_dir_all(lib);
    let _ = std::fs::remove_dir_all(app);
    let _ = std::fs::remove_dir_all(cache);
}

#[tokio::test]
async fn real_pip_and_twine() {
    let python = std::env::var("MWS_LAMBDA_PYTHON").unwrap_or_else(|_| "python3".into());
    let has_twine =
        run(&python, &["-m", "twine", "--version"], &std::env::temp_dir(), &[]).is_some_and(|o| o.status.success());
    let has_pip =
        run(&python, &["-m", "pip", "--version"], &std::env::temp_dir(), &[]).is_some_and(|o| o.status.success());
    if !has_pip {
        eprintln!("pip is not installed; skipping");
        return;
    }
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("pyreal").send().await.unwrap();
    ca.create_repository().domain("pyreal").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "pyreal", "repo", PackageFormat::Pypi).await;
    let token = token(&ca, "pyreal").await;

    // A minimal (pure, empty) wheel: a zip with METADATA, WHEEL and RECORD.
    let dir = temp_dir("pypi");
    let wheel_name = "mws_hello-0.3.0-py3-none-any.whl";
    {
        let file = std::fs::File::create(dir.join(wheel_name)).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        let files = [
            ("mws_hello/__init__.py", "GREETING = 'hello'\n".to_string()),
            (
                "mws_hello-0.3.0.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: mws-hello\nVersion: 0.3.0\nSummary: hello\n".to_string(),
            ),
            (
                "mws_hello-0.3.0.dist-info/WHEEL",
                "Wheel-Version: 1.0\nGenerator: mws\nRoot-Is-Purelib: true\nTag: py3-none-any\n".to_string(),
            ),
            ("mws_hello-0.3.0.dist-info/RECORD", "".to_string()),
        ];
        for (name, content) in files {
            use std::io::Write;
            zip.start_file(name, opts).unwrap();
            zip.write_all(content.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }
    if has_twine {
        let out = tokio::task::spawn_blocking({
            let (python, dir, url, token) = (python.clone(), dir.clone(), url.clone(), token.clone());
            move || {
                run(
                    &python,
                    &[
                        "-m",
                        "twine",
                        "upload",
                        "--non-interactive",
                        "--disable-progress-bar",
                        "--repository-url",
                        &url,
                        "-u",
                        "aws",
                        "-p",
                        &token,
                        wheel_name,
                    ],
                    &dir,
                    &[],
                )
                .unwrap()
            }
        })
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "twine: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        eprintln!("twine is not installed; publishing with the SDK-free raw upload instead");
        let wheel = std::fs::read(dir.join(wheel_name)).unwrap();
        let mut body = Vec::new();
        for (k, v) in [(":action", "file_upload"), ("name", "mws-hello"), ("version", "0.3.0")] {
            body.extend_from_slice(
                format!("--B\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").as_bytes(),
            );
        }
        body.extend_from_slice(
            format!("--B\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{wheel_name}\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(&wheel);
        body.extend_from_slice(b"\r\n--B--\r\n");
        let auth = basic(&token);
        let (status, _, _) = mws
            .raw("POST", &url, &[("Authorization", &auth), ("Content-Type", "multipart/form-data; boundary=B")], &body)
            .await;
        assert_eq!(status, 200);
    }

    let index = url.replacen("http://", &format!("http://aws:{token}@"), 1) + "simple/";
    let out_dir = dir.join("downloaded");
    let out = tokio::task::spawn_blocking({
        let (python, dir, out_dir) = (python.clone(), dir.clone(), out_dir.clone());
        move || {
            run(
                &python,
                &[
                    "-m",
                    "pip",
                    "download",
                    "--no-deps",
                    "--no-cache-dir",
                    "--disable-pip-version-check",
                    "--index-url",
                    &index,
                    "-d",
                    out_dir.to_str().unwrap(),
                    "mws-hello==0.3.0",
                ],
                &dir,
                &[("PIP_CONFIG_FILE", "/dev/null")],
            )
            .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "pip: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out_dir.join(wheel_name).exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn real_gradle_publishes_and_resolves() {
    if run("gradle", &["--version"], &std::env::temp_dir(), &[]).is_none_or(|o| !o.status.success()) {
        eprintln!("gradle is not installed; skipping");
        return;
    }
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("gradlereal").send().await.unwrap();
    ca.create_repository().domain("gradlereal").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "gradlereal", "repo", PackageFormat::Maven).await;
    let token = token(&ca, "gradlereal").await;

    let dir = temp_dir("gradle");
    let repo_block = format!(
        "maven {{\n    url = uri(\"{url}\")\n    isAllowInsecureProtocol = true\n    credentials {{ username = \"aws\"; password = System.getenv(\"CODEARTIFACT_AUTH_TOKEN\") }}\n}}"
    );
    std::fs::create_dir_all(dir.join("lib")).unwrap();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(dir.join("settings.gradle.kts"), "rootProject.name = \"mws\"\ninclude(\"lib\", \"app\")\n").unwrap();
    std::fs::write(
        dir.join("lib/build.gradle.kts"),
        format!(
            "plugins {{ `java-library`; `maven-publish` }}\ngroup = \"com.mws\"\nversion = \"0.9.0\"\npublishing {{\n  publications {{ create<MavenPublication>(\"lib\") {{ from(components[\"java\"]) }} }}\n  repositories {{ {repo_block} }}\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("app/build.gradle.kts"),
        format!(
            "plugins {{ base }}\nrepositories {{ {repo_block} }}\nval deps by configurations.creating\ndependencies {{ deps(\"com.mws:lib:0.9.0\") }}\ntasks.register(\"fetch\") {{ doLast {{ deps.resolve().forEach {{ println(\"RESOLVED \" + it.name) }} }} }}\n"
        ),
    )
    .unwrap();
    let gradle = |args: Vec<&'static str>| {
        let (dir, token) = (dir.clone(), token.clone());
        tokio::task::spawn_blocking(move || {
            let mut a = vec!["--no-daemon", "-q"];
            a.extend(args);
            run("gradle", &a, &dir, &[("CODEARTIFACT_AUTH_TOKEN", &token)]).unwrap()
        })
    };
    let out = gradle(vec![":lib:publish"]).await.unwrap();
    assert!(
        out.status.success(),
        "gradle publish: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v = ca
        .describe_package_version()
        .domain("gradlereal")
        .repository("repo")
        .format(PackageFormat::Maven)
        .namespace("com.mws")
        .package("lib")
        .package_version("0.9.0")
        .send()
        .await
        .unwrap();
    assert_eq!(v.package_version().unwrap().status(), Some(&PackageVersionStatus::Published));
    let out = gradle(vec![":app:fetch"]).await.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "gradle resolve: {stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("RESOLVED lib-0.9.0.jar"), "{stdout}");
    let _ = std::fs::remove_dir_all(dir);
}

fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut out = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut out);
    for (name, content) in files {
        zip.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(content.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
    out.into_inner()
}

fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, data) in parts {
        let filename = filename.map(|f| format!("; filename=\"{f}\"")).unwrap_or_default();
        body.extend_from_slice(
            format!("--BOUNDARY\r\nContent-Disposition: form-data; name=\"{name}\"{filename}\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--BOUNDARY--\r\n");
    body
}

#[tokio::test]
async fn nuget_push_registration_and_download() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("nu").send().await.unwrap();
    ca.create_repository().domain("nu").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "nu", "repo", PackageFormat::Nuget).await;
    let auth = basic(&token(&ca, "nu").await);
    let h = [("Authorization", auth.as_str())];

    let (status, _, index) = mws.raw("GET", &format!("{url}v3/index.json"), &h, b"").await;
    assert_eq!(status, 200);
    let index: serde_json::Value = serde_json::from_slice(&index).unwrap();
    let resource = |t: &str| {
        index["resources"].as_array().unwrap().iter().find(|r| r["@type"] == t).unwrap()["@id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let base = resource("PackageBaseAddress/3.0.0");
    let publish = resource("PackagePublish/2.0.0");

    let nuspec = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Acme.Greeter</id>
    <version>1.2.0</version>
    <authors>Acme</authors>
    <description>Says hello</description>
    <license type="expression">MIT</license>
    <projectUrl>https://example.com/greeter</projectUrl>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="13.0.1" />
      </group>
    </dependencies>
  </metadata>
</package>"#;
    let nupkg = zip_of(&[("Acme.Greeter.nuspec", nuspec), ("lib/net8.0/Acme.Greeter.dll", "MZ")]);
    let body = multipart(&[("package", Some("package.nupkg"), &nupkg)]);
    let push_headers = [("Authorization", auth.as_str()), ("Content-Type", "multipart/form-data; boundary=BOUNDARY")];
    let (status, _, out) = mws.raw("PUT", &publish, &push_headers, &body).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&out));
    let (status, _, _) = mws.raw("PUT", &publish, &push_headers, &body).await;
    assert_eq!(status, 409, "versions are immutable");

    let (status, _, versions) = mws.raw("GET", &format!("{base}acme.greeter/index.json"), &h, b"").await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&versions).unwrap()["versions"],
        serde_json::json!(["1.2.0"])
    );
    let (status, _, got) = mws.raw("GET", &format!("{base}acme.greeter/1.2.0/acme.greeter.1.2.0.nupkg"), &h, b"").await;
    assert_eq!(status, 200);
    assert_eq!(got, nupkg);
    let (status, _, got) = mws.raw("GET", &format!("{base}acme.greeter/1.2.0/acme.greeter.nuspec"), &h, b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8(got).unwrap().contains("<id>Acme.Greeter</id>"));

    let registration = resource("RegistrationsBaseUrl/3.6.0");
    let (status, _, reg) = mws.raw("GET", &format!("{registration}acme.greeter/index.json"), &h, b"").await;
    assert_eq!(status, 200);
    let reg: serde_json::Value = serde_json::from_slice(&reg).unwrap();
    let entry = &reg["items"][0]["items"][0]["catalogEntry"];
    assert_eq!(entry["id"], "Acme.Greeter");
    assert_eq!(entry["dependencyGroups"][0]["dependencies"][0]["id"], "Newtonsoft.Json");
    let (status, _, search) =
        mws.raw("GET", &format!("{}?q=greeter", resource("SearchQueryService/3.5.0")), &h, b"").await;
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&search).unwrap()["data"][0]["id"], "Acme.Greeter");

    let v = ca
        .describe_package_version()
        .domain("nu")
        .repository("repo")
        .format(PackageFormat::Nuget)
        .package("Acme.Greeter")
        .package_version("1.2.0")
        .send()
        .await
        .unwrap();
    let v = v.package_version().unwrap();
    assert_eq!(v.package_name(), Some("acme.greeter"), "NuGet names are lower-cased");
    assert_eq!(v.summary(), Some("Says hello"));
    assert_eq!(v.home_page(), Some("https://example.com/greeter"));

    // `dotnet nuget delete` unlists.
    let (status, _, _) = mws.raw("DELETE", &format!("{publish}Acme.Greeter/1.2.0"), &h, b"").await;
    assert_eq!(status, 204);
    let v = ca
        .describe_package_version()
        .domain("nu")
        .repository("repo")
        .format(PackageFormat::Nuget)
        .package("acme.greeter")
        .package_version("1.2.0")
        .send()
        .await
        .unwrap();
    assert_eq!(v.package_version().unwrap().status().map(|s| s.as_str()), Some("Unlisted"));
}

#[tokio::test]
async fn swift_registry_publish_and_resolve() {
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("sw").send().await.unwrap();
    ca.create_repository().domain("sw").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "sw", "repo", PackageFormat::Swift).await;
    let auth = basic(&token(&ca, "sw").await);
    let h = [("Authorization", auth.as_str()), ("Accept", "application/vnd.swift.registry.v1+json")];

    let manifest = "// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: \"Greeter\")\n";
    let archive = zip_of(&[
        ("Greeter/Package.swift", manifest),
        ("Greeter/Package@swift-5.8.swift", "// swift-tools-version:5.8\n"),
        ("Greeter/Sources/Greeter/Greeter.swift", "public func hi() -> String { \"hi\" }\n"),
    ]);
    let metadata = br#"{"description":"Says hi","repositoryURLs":["https://github.com/acme/Greeter.git"]}"#;
    let body = multipart(&[("source-archive", Some("Greeter.zip"), &archive), ("metadata", None, metadata)]);
    let put = [
        ("Authorization", auth.as_str()),
        ("Content-Type", "multipart/form-data; boundary=BOUNDARY"),
        ("Accept", "application/vnd.swift.registry.v1+json"),
    ];
    let (status, headers, out) = mws.raw("PUT", &format!("{url}acme/Greeter/1.0.0"), &put, &body).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&out));
    assert!(headers.iter().any(|(k, v)| k == "content-version" && v == "1"));
    let (status, headers, out) = mws.raw("PUT", &format!("{url}acme/Greeter/1.0.0"), &put, &body).await;
    assert_eq!(status, 409);
    assert!(headers.iter().any(|(k, v)| k == "content-type" && v == "application/problem+json"));
    assert!(serde_json::from_slice::<serde_json::Value>(&out).unwrap()["detail"].is_string());

    let (status, _, releases) = mws.raw("GET", &format!("{url}acme/greeter"), &h, b"").await;
    assert_eq!(status, 200);
    let releases: serde_json::Value = serde_json::from_slice(&releases).unwrap();
    assert!(releases["releases"]["1.0.0"]["url"].as_str().unwrap().ends_with("acme/greeter/1.0.0"));

    let (status, _, release) = mws.raw("GET", &format!("{url}acme/greeter/1.0.0"), &h, b"").await;
    assert_eq!(status, 200);
    let release: serde_json::Value = serde_json::from_slice(&release).unwrap();
    assert_eq!(release["id"], "acme.greeter");
    assert_eq!(release["resources"][0]["checksum"], hex::encode(sha2_010::Sha256::digest(&archive)));
    assert_eq!(release["metadata"]["description"], "Says hi");

    let (status, headers, got) = mws.raw("GET", &format!("{url}acme/greeter/1.0.0/Package.swift"), &h, b"").await;
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8(got).unwrap(), manifest);
    assert!(headers.iter().any(|(k, v)| k == "link" && v.contains("swift-version=5.8")));
    let (status, headers, got) = mws.raw("GET", &format!("{url}acme/greeter/1.0.0.zip"), &h, b"").await;
    assert_eq!(status, 200);
    assert_eq!(got, archive);
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2_010::Sha256::digest(&archive));
    assert!(headers.iter().any(|(k, v)| k == "digest" && *v == format!("sha-256={digest}")));

    let (status, _, ids) =
        mws.raw("GET", &format!("{url}identifiers?url=https://github.com/acme/greeter"), &h, b"").await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&ids).unwrap()["identifiers"],
        serde_json::json!(["acme.greeter"])
    );
    let (status, _, _) = mws.raw("GET", &format!("{url}acme/missing"), &h, b"").await;
    assert_eq!(status, 404);

    let v = ca
        .describe_package_version()
        .domain("sw")
        .repository("repo")
        .format(PackageFormat::Swift)
        .namespace("acme")
        .package("greeter")
        .package_version("1.0.0")
        .send()
        .await
        .unwrap();
    let v = v.package_version().unwrap();
    assert_eq!(v.summary(), Some("Says hi"));
    assert_eq!(v.source_code_repository(), Some("https://github.com/acme/Greeter.git"));
}

/// Run a command off the async runtime, with `env` and a private `HOME`.
async fn run_blocking(
    program: &str,
    args: &[&str],
    dir: &std::path::Path,
    env: &[(&str, &str)],
) -> std::process::Output {
    let program = program.to_string();
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let dir = dir.to_path_buf();
    let env: Vec<(String, String)> = env.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let env: Vec<(&str, &str)> = env.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        run(&program, &args, &dir, &env).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn real_cargo_publishes_and_fetches() {
    if run("cargo", &["--version"], &std::env::temp_dir(), &[]).is_none() {
        eprintln!("cargo is not installed; skipping");
        return;
    }
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("crates").send().await.unwrap();
    ca.create_repository().domain("crates").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "crates", "repo", PackageFormat::Cargo).await;
    let token = token(&ca, "crates").await;

    let (status, _, _) = mws.raw("GET", &format!("{url}config.json"), &[], b"").await;
    assert_eq!(status, 401, "the index needs a token");
    let (status, _, config) =
        mws.raw("GET", &format!("{url}config.json"), &[("Authorization", &bearer(&token))], b"").await;
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&config).unwrap()["auth-required"], true);

    let home = temp_dir("cargo-home");
    let index = format!("sparse+{url}");
    let auth = bearer(&token);
    let target = home.join("target").to_str().unwrap().to_string();
    let env = [
        ("CARGO_HOME", home.to_str().unwrap()),
        ("CARGO_REGISTRIES_CA_INDEX", index.as_str()),
        ("CARGO_REGISTRIES_CA_TOKEN", auth.as_str()),
        ("CARGO_REGISTRIES_CA_CREDENTIAL_PROVIDER", "cargo:token"),
        ("CARGO_TARGET_DIR", target.as_str()),
    ];
    let lib = temp_dir("cargo-lib");
    std::fs::create_dir_all(lib.join("src")).unwrap();
    std::fs::write(
        lib.join("Cargo.toml"),
        "[package]\nname = \"mws-greet\"\nversion = \"0.1.0\"\nedition = \"2021\"\ndescription = \"Says hi\"\nlicense = \"MIT\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(lib.join("src/lib.rs"), "pub fn hi() -> &'static str { \"hi from codeartifact\" }\n").unwrap();
    let out = run_blocking("cargo", &["publish", "--registry", "ca", "--allow-dirty", "--no-verify"], &lib, &env).await;
    assert!(out.status.success(), "cargo publish: {}", String::from_utf8_lossy(&out.stderr));

    let app = temp_dir("cargo-app");
    std::fs::create_dir_all(app.join("src")).unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nmws-greet = { version = \"0.1\", registry = \"ca\" }\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(app.join("src/main.rs"), "fn main() { println!(\"{}\", mws_greet::hi()); }\n").unwrap();
    let out = run_blocking("cargo", &["fetch"], &app, &env).await;
    assert!(out.status.success(), "cargo fetch: {}", String::from_utf8_lossy(&out.stderr));
    let lock = std::fs::read_to_string(app.join("Cargo.lock")).unwrap();
    assert!(lock.contains("name = \"mws-greet\""));

    let out = run_blocking("cargo", &["yank", "--registry", "ca", "mws-greet@0.1.0"], &lib, &env).await;
    assert!(out.status.success(), "cargo yank: {}", String::from_utf8_lossy(&out.stderr));
    let v = ca
        .describe_package_version()
        .domain("crates")
        .repository("repo")
        .format(PackageFormat::Cargo)
        .package("mws-greet")
        .package_version("0.1.0")
        .send()
        .await
        .unwrap();
    let v = v.package_version().unwrap();
    assert_eq!(v.summary(), Some("Says hi"));
    assert_eq!(v.status().map(|s| s.as_str()), Some("Unlisted"));
    for d in [home, lib, app] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[tokio::test]
async fn real_gem_pushes_and_bundler_installs() {
    if run("gem", &["--version"], &std::env::temp_dir(), &[]).is_none()
        || run("bundle", &["--version"], &std::env::temp_dir(), &[]).is_none()
    {
        eprintln!("gem or bundler is not installed; skipping");
        return;
    }
    let mws = Mws::start().await;
    let ca = client(&mws).await;
    ca.create_domain().domain("gems").send().await.unwrap();
    ca.create_repository().domain("gems").repository("repo").send().await.unwrap();
    let url = endpoint(&ca, "gems", "repo", PackageFormat::Ruby).await;
    let token = token(&ca, "gems").await;

    let home = temp_dir("gem-home");
    let lib = temp_dir("gem-lib");
    std::fs::create_dir_all(lib.join("lib")).unwrap();
    std::fs::write(lib.join("lib/mws_greet.rb"), "module MwsGreet\n  def self.hi = 'hi from codeartifact'\nend\n")
        .unwrap();
    std::fs::write(
        lib.join("mws_greet.gemspec"),
        "Gem::Specification.new do |s|\n  s.name = 'mws_greet'\n  s.version = '0.2.0'\n  s.summary = 'Says hi'\n  s.authors = ['MWS']\n  s.license = 'MIT'\n  s.homepage = 'https://example.com/greet'\n  s.files = ['lib/mws_greet.rb']\n  s.required_ruby_version = '>= 2.7'\nend\n",
    )
    .unwrap();
    let gem_home = home.join("gems").to_str().unwrap().to_string();
    let env = [("HOME", home.to_str().unwrap()), ("GEM_HOME", gem_home.as_str())];
    let out = run_blocking("gem", &["build", "mws_greet.gemspec"], &lib, &env).await;
    assert!(out.status.success(), "gem build: {}", String::from_utf8_lossy(&out.stderr));
    let key = basic(&token);
    let push_env = [env[0], env[1], ("GEM_HOST_API_KEY", key.as_str())];
    let host = url.trim_end_matches('/');
    let out = run_blocking("gem", &["push", "--host", host, "mws_greet-0.2.0.gem"], &lib, &push_env).await;
    assert!(
        out.status.success(),
        "gem push: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Successfully registered gem: mws_greet (0.2.0)"));

    let app = temp_dir("gem-app");
    let source = url.replacen("http://", &format!("http://aws:{token}@"), 1);
    std::fs::write(app.join("Gemfile"), format!("source \"{source}\"\ngem \"mws_greet\", \"~> 0.2\"\n")).unwrap();
    let (vendor, config) = (app.join("vendor"), app.join(".bundle"));
    let bundle_env =
        [env[0], env[1], ("BUNDLE_PATH", vendor.to_str().unwrap()), ("BUNDLE_APP_CONFIG", config.to_str().unwrap())];
    let out = run_blocking("bundle", &["install"], &app, &bundle_env).await;
    assert!(
        out.status.success(),
        "bundle install: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let out =
        run_blocking("bundle", &["exec", "ruby", "-e", "require 'mws_greet'; print MwsGreet.hi"], &app, &bundle_env)
            .await;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hi from codeartifact",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v = ca
        .describe_package_version()
        .domain("gems")
        .repository("repo")
        .format(PackageFormat::Ruby)
        .package("mws_greet")
        .package_version("0.2.0")
        .send()
        .await
        .unwrap();
    let v = v.package_version().unwrap();
    assert_eq!(v.summary(), Some("Says hi"));
    assert_eq!(v.home_page(), Some("https://example.com/greet"));
    for d in [home, lib, app] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A registry serving fixed files; `{base}` in a body becomes its URL.
async fn fake_registry(files: Vec<(&'static str, Vec<u8>)>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let files: std::sync::Arc<Vec<(String, Vec<u8>)>> = std::sync::Arc::new(
        files
            .into_iter()
            .map(|(p, b)| {
                let b = match String::from_utf8(b.clone()) {
                    Ok(s) => s.replace("{base}", &base).into_bytes(),
                    Err(_) => b,
                };
                (p.to_string(), b)
            })
            .collect(),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let files = files.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split(' ').nth(1).unwrap_or("").to_string();
                let (status, body) = match files.iter().find(|(p, _)| *p == path) {
                    Some((_, b)) => ("200 OK", b.clone()),
                    None => ("404 Not Found", b"{}".to_vec()),
                };
                let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    base
}

#[tokio::test]
async fn cargo_nuget_and_rubygems_external_connections() {
    let mws = Mws::start().await;
    let crates = fake_registry(vec![
        ("/config.json", br#"{"dl":"{base}/dl"}"#.to_vec()),
        (
            "/de/mo/demo",
            br#"{"name":"demo","vers":"1.0.0","deps":[],"cksum":"x","features":{},"yanked":false}"#.to_vec(),
        ),
        ("/dl/demo/1.0.0/download", b"demo crate".to_vec()),
    ])
    .await;
    let nupkg = zip_of(&[(
        "Acme.Lib.nuspec",
        "<package><metadata><id>Acme.Lib</id><version>2.0.0</version><description>lib</description></metadata></package>",
    )]);
    let nuget = fake_registry(vec![
        (
            "/v3/index.json",
            br#"{"version":"3.0.0","resources":[{"@id":"{base}/flat/","@type":"PackageBaseAddress/3.0.0"}]}"#.to_vec(),
        ),
        ("/flat/acme.lib/index.json", br#"{"versions":["2.0.0"]}"#.to_vec()),
        ("/flat/acme.lib/2.0.0/acme.lib.2.0.0.nupkg", nupkg.clone()),
    ])
    .await;
    let gems = fake_registry(vec![
        ("/info/rack", b"---\n3.0.0 |checksum:abc,ruby:>= 2.4\n".to_vec()),
        ("/gems/rack-3.0.0.gem", b"rack gem".to_vec()),
    ])
    .await;
    mws.codeartifact.set_registry_url("public:crates-io", &crates);
    mws.codeartifact.set_registry_url("public:nuget-org", &format!("{nuget}/v3/index.json"));
    mws.codeartifact.set_registry_url("public:ruby-gems-org", &gems);
    let ca = client(&mws).await;
    ca.create_domain().domain("ext2").send().await.unwrap();
    let auth = basic(&token(&ca, "ext2").await);
    let h = [("Authorization", auth.as_str())];
    for (repo, conn) in
        [("crates", "public:crates-io"), ("nuget", "public:nuget-org"), ("gems", "public:ruby-gems-org")]
    {
        ca.create_repository().domain("ext2").repository(repo).send().await.unwrap();
        ca.associate_external_connection()
            .domain("ext2")
            .repository(repo)
            .external_connection(conn)
            .send()
            .await
            .unwrap();
    }

    let url = endpoint(&ca, "ext2", "crates", PackageFormat::Cargo).await;
    let (status, _, index) = mws.raw("GET", &format!("{url}de/mo/demo"), &h, b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8(index).unwrap().contains(r#""vers":"1.0.0""#));
    let (status, _, got) = mws.raw("GET", &format!("{url}api/v1/crates/demo/1.0.0/download"), &h, b"").await;
    assert_eq!((status, got.as_slice()), (200, b"demo crate".as_slice()));

    let url = endpoint(&ca, "ext2", "nuget", PackageFormat::Nuget).await;
    let (status, _, versions) = mws.raw("GET", &format!("{url}v3/package/acme.lib/index.json"), &h, b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8(versions).unwrap().contains("2.0.0"));
    let (status, _, got) =
        mws.raw("GET", &format!("{url}v3/package/acme.lib/2.0.0/acme.lib.2.0.0.nupkg"), &h, b"").await;
    assert_eq!((status, got), (200, nupkg));

    let url = endpoint(&ca, "ext2", "gems", PackageFormat::Ruby).await;
    let (status, _, info) = mws.raw("GET", &format!("{url}info/rack"), &h, b"").await;
    assert_eq!(status, 200);
    assert!(String::from_utf8(info).unwrap().contains("3.0.0 |checksum:abc"));
    let (status, _, got) = mws.raw("GET", &format!("{url}gems/rack-3.0.0.gem"), &h, b"").await;
    assert_eq!((status, got.as_slice()), (200, b"rack gem".as_slice()));

    for (repo, format, package, version) in [
        ("crates", PackageFormat::Cargo, "demo", "1.0.0"),
        ("nuget", PackageFormat::Nuget, "acme.lib", "2.0.0"),
        ("gems", PackageFormat::Ruby, "rack", "3.0.0"),
    ] {
        let v = ca
            .describe_package_version()
            .domain("ext2")
            .repository(repo)
            .format(format)
            .package(package)
            .package_version(version)
            .send()
            .await
            .unwrap();
        assert_eq!(v.package_version().unwrap().origin().unwrap().origin_type().map(|o| o.as_str()), Some("EXTERNAL"));
    }
}
