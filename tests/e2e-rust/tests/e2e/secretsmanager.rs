//! Secrets Manager through the official Rust SDK: versions and staging
//! labels, KMS encryption, IAM and resource policies, rotation that runs a
//! real Lambda function, and replication.

use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

use aws_sdk_lambda::primitives::Blob as LambdaBlob;
use aws_sdk_lambda::types::{FunctionCode, Runtime};
use aws_sdk_secretsmanager::error::ProvideErrorMetadata;
use aws_sdk_secretsmanager::primitives::Blob;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType, ReplicaRegionType, RotationRulesType, Tag};
use aws_sdk_secretsmanager::Client;
use mws_e2e::{user_with_policy, Mws};

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

async fn client_in(mws: &Mws, region: &str) -> Client {
    let cfg = mws.root_sdk_config().await;
    let conf = aws_sdk_secretsmanager::config::Builder::from(&cfg)
        .region(aws_sdk_secretsmanager::config::Region::new(region.to_string()))
        .build();
    Client::from_conf(conf)
}

fn stages(map: Option<&HashMap<String, Vec<String>>>, id: &str) -> Vec<String> {
    map.and_then(|m| m.get(id)).cloned().unwrap_or_default()
}

#[tokio::test]
async fn versions_and_staging_labels() {
    let mws = Mws::start().await;
    let sm = client(&mws).await;

    let created = sm
        .create_secret()
        .name("prod/db")
        .description("Database credentials")
        .secret_string(r#"{"username":"app","password":"one"}"#)
        .tags(Tag::builder().key("team").value("payments").build())
        .send()
        .await
        .unwrap();
    let arn = created.arn().unwrap().to_string();
    assert!(arn.starts_with("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-"), "{arn}");
    assert_eq!(arn.len(), "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-".len() + 6);
    let v1 = created.version_id().unwrap().to_string();

    let dup = sm.create_secret().name("prod/db").secret_string("x").send().await.unwrap_err();
    assert_eq!(code(&dup), "ResourceExistsException");
    let bad = sm.create_secret().name("bad name!").secret_string("x").send().await.unwrap_err();
    assert_eq!(code(&bad), "InvalidParameterException");

    // Name, full ARN and partial ARN (without the suffix) all work.
    let partial = arn[..arn.len() - 7].to_string();
    for id in ["prod/db", arn.as_str(), partial.as_str()] {
        let got = sm.get_secret_value().secret_id(id).send().await.unwrap();
        assert_eq!(got.secret_string(), Some(r#"{"username":"app","password":"one"}"#));
        assert_eq!(got.version_id(), Some(v1.as_str()));
        assert_eq!(got.version_stages(), ["AWSCURRENT"]);
    }

    let d = sm.describe_secret().secret_id("prod/db").send().await.unwrap();
    assert_eq!(d.name(), Some("prod/db"));
    assert_eq!(d.description(), Some("Database credentials"));
    assert_eq!(d.kms_key_id(), None, "aws/secretsmanager is not reported");
    assert_eq!(d.rotation_enabled(), None);
    assert_eq!(d.tags().len(), 1);
    assert!(d.last_accessed_date().is_some());
    assert_eq!(stages(d.version_ids_to_stages(), &v1), ["AWSCURRENT"]);

    // A new value moves AWSCURRENT, and AWSPREVIOUS follows.
    let put = sm
        .put_secret_value()
        .secret_id("prod/db")
        .secret_string(r#"{"username":"app","password":"two"}"#)
        .send()
        .await
        .unwrap();
    let v2 = put.version_id().unwrap().to_string();
    assert_eq!(put.version_stages(), ["AWSCURRENT"]);
    let prev = sm.get_secret_value().secret_id("prod/db").version_stage("AWSPREVIOUS").send().await.unwrap();
    assert_eq!(prev.version_id(), Some(v1.as_str()));

    // Same token and value: nothing happens. Different value: refused.
    let again = sm
        .put_secret_value()
        .secret_id("prod/db")
        .client_request_token(&v2)
        .secret_string(r#"{"username":"app","password":"two"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(again.version_id(), Some(v2.as_str()));
    let changed = sm
        .put_secret_value()
        .secret_id("prod/db")
        .client_request_token(&v2)
        .secret_string("different")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&changed), "ResourceExistsException");

    // A custom label on a version of its own.
    let staged = sm
        .put_secret_value()
        .secret_id("prod/db")
        .secret_string("three")
        .version_stages("canary")
        .send()
        .await
        .unwrap();
    let v3 = staged.version_id().unwrap().to_string();
    assert_eq!(sm.get_secret_value().secret_id("prod/db").send().await.unwrap().version_id(), Some(v2.as_str()));
    let canary = sm.get_secret_value().secret_id("prod/db").version_stage("canary").send().await.unwrap();
    assert_eq!(canary.secret_string(), Some("three"));
    let mismatch =
        sm.get_secret_value().secret_id("prod/db").version_id(&v1).version_stage("canary").send().await.unwrap_err();
    assert_eq!(code(&mismatch), "InvalidRequestException");
    let missing = sm.get_secret_value().secret_id("prod/db").version_stage("nope").send().await.unwrap_err();
    assert_eq!(code(&missing), "ResourceNotFoundException");

    // Moving AWSCURRENT needs the version it leaves.
    let refused = sm
        .update_secret_version_stage()
        .secret_id("prod/db")
        .version_stage("AWSCURRENT")
        .move_to_version_id(&v3)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&refused), "InvalidParameterException");
    assert!(refused.message().unwrap().contains("RemoveFromVersionId"));
    sm.update_secret_version_stage()
        .secret_id("prod/db")
        .version_stage("AWSCURRENT")
        .move_to_version_id(&v3)
        .remove_from_version_id(&v2)
        .send()
        .await
        .unwrap();
    let d = sm.describe_secret().secret_id("prod/db").send().await.unwrap();
    let map = d.version_ids_to_stages();
    assert_eq!(stages(map, &v3), ["canary", "AWSCURRENT"]);
    assert_eq!(stages(map, &v2), ["AWSPREVIOUS"]);
    assert!(stages(map, &v1).is_empty(), "v1 is deprecated");
    sm.update_secret_version_stage()
        .secret_id("prod/db")
        .version_stage("canary")
        .remove_from_version_id(&v3)
        .send()
        .await
        .unwrap();

    let listed = sm.list_secret_version_ids().secret_id("prod/db").send().await.unwrap();
    assert_eq!(listed.versions().len(), 2);
    assert_eq!(listed.versions()[0].kms_key_ids(), ["DefaultEncryptionKey"]);
    let all = sm.list_secret_version_ids().secret_id("prod/db").include_deprecated(true).send().await.unwrap();
    assert_eq!(all.versions().len(), 3);

    // UpdateSecret: metadata and a new current value.
    let updated = sm
        .update_secret()
        .secret_id("prod/db")
        .description("rotated by hand")
        .secret_string("four")
        .send()
        .await
        .unwrap();
    let v4 = updated.version_id().unwrap().to_string();
    let got = sm.get_secret_value().secret_id("prod/db").send().await.unwrap();
    assert_eq!((got.secret_string(), got.version_id()), (Some("four"), Some(v4.as_str())));
    let reuse = sm
        .update_secret()
        .secret_id("prod/db")
        .client_request_token(&v4)
        .secret_string("four")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&reuse), "ResourceExistsException");

    // Binary secrets.
    sm.create_secret().name("blob").secret_binary(Blob::new(vec![0, 1, 2, 255])).send().await.unwrap();
    let b = sm.get_secret_value().secret_id("blob").send().await.unwrap();
    assert_eq!(b.secret_binary().unwrap().as_ref(), &[0, 1, 2, 255]);
    assert_eq!(b.secret_string(), None);
    // A secret without a value has no AWSCURRENT yet.
    sm.create_secret().name("empty").send().await.unwrap();
    let none = sm.get_secret_value().secret_id("empty").send().await.unwrap_err();
    assert_eq!(code(&none), "ResourceNotFoundException");

    // Tags.
    sm.tag_resource().secret_id("prod/db").tags(Tag::builder().key("env").value("prod").build()).send().await.unwrap();
    sm.untag_resource().secret_id("prod/db").tag_keys("team").send().await.unwrap();
    let d = sm.describe_secret().secret_id("prod/db").send().await.unwrap();
    assert_eq!(d.tags().iter().map(|t| t.key().unwrap()).collect::<Vec<_>>(), ["env"]);

    // Listing with filters, sorting and pages.
    let by_tag = sm
        .list_secrets()
        .filters(Filter::builder().key(FilterNameStringType::TagKey).values("env").build())
        .send()
        .await
        .unwrap();
    assert_eq!(by_tag.secret_list().iter().map(|s| s.name().unwrap()).collect::<Vec<_>>(), ["prod/db"]);
    let not_prod = sm
        .list_secrets()
        .filters(Filter::builder().key(FilterNameStringType::Name).values("!prod").build())
        .sort_by(aws_sdk_secretsmanager::types::SortByType::Name)
        .send()
        .await
        .unwrap();
    assert_eq!(not_prod.secret_list().iter().map(|s| s.name().unwrap()).collect::<Vec<_>>(), ["blob", "empty"]);
    let described = sm
        .list_secrets()
        .filters(Filter::builder().key(FilterNameStringType::Description).values("ROTATED").build())
        .send()
        .await
        .unwrap();
    assert_eq!(described.secret_list().len(), 1);
    let page = sm.list_secrets().max_results(2).send().await.unwrap();
    assert_eq!(page.secret_list().len(), 2);
    let rest = sm.list_secrets().max_results(2).next_token(page.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.secret_list().len(), 1);
    assert!(rest.next_token().is_none());

    // BatchGetSecretValue, by id (with errors) and by filter.
    let batch = sm
        .batch_get_secret_value()
        .secret_id_list("prod/db")
        .secret_id_list("blob")
        .secret_id_list("ghost")
        .send()
        .await
        .unwrap();
    assert_eq!(batch.secret_values().len(), 2);
    assert_eq!(batch.errors().len(), 1);
    assert_eq!(batch.errors()[0].secret_id(), Some("ghost"));
    assert_eq!(batch.errors()[0].error_code(), Some("ResourceNotFoundException"));
    let filtered = sm
        .batch_get_secret_value()
        .filters(Filter::builder().key(FilterNameStringType::Name).values("prod").build())
        .send()
        .await
        .unwrap();
    assert_eq!(filtered.secret_values().iter().map(|v| v.secret_string().unwrap()).collect::<Vec<_>>(), ["four"]);
    let both = sm
        .batch_get_secret_value()
        .secret_id_list("blob")
        .filters(Filter::builder().key(FilterNameStringType::Name).values("prod").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&both), "InvalidParameterException");

    // Deletion with a recovery window, restore, and forced deletion.
    let clash = sm.delete_secret().secret_id("blob").recovery_window_in_days(7).force_delete_without_recovery(true);
    assert_eq!(code(&clash.send().await.unwrap_err()), "InvalidParameterException");
    let short = sm.delete_secret().secret_id("blob").recovery_window_in_days(3).send().await.unwrap_err();
    assert_eq!(code(&short), "InvalidParameterException");
    let deleted = sm.delete_secret().secret_id("blob").recovery_window_in_days(7).send().await.unwrap();
    let when = deleted.deletion_date().unwrap().secs() - chrono::Utc::now().timestamp();
    assert!((7 * 86400 - 60..=7 * 86400 + 60).contains(&when), "{when}");
    let gone = sm.get_secret_value().secret_id("blob").send().await.unwrap_err();
    assert_eq!(code(&gone), "InvalidRequestException");
    assert!(sm.describe_secret().secret_id("blob").send().await.unwrap().deleted_date().is_some());
    assert_eq!(sm.list_secrets().send().await.unwrap().secret_list().len(), 2);
    assert_eq!(sm.list_secrets().include_planned_deletion(true).send().await.unwrap().secret_list().len(), 3);
    let taken = sm.create_secret().name("blob").secret_string("x").send().await.unwrap_err();
    assert_eq!(code(&taken), "InvalidRequestException");
    sm.restore_secret().secret_id("blob").send().await.unwrap();
    assert!(sm.get_secret_value().secret_id("blob").send().await.is_ok());
    sm.delete_secret().secret_id("blob").force_delete_without_recovery(true).send().await.unwrap();
    let gone = sm.describe_secret().secret_id("blob").send().await.unwrap_err();
    assert_eq!(code(&gone), "ResourceNotFoundException");
    sm.create_secret().name("blob").secret_string("reborn").send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn recovery_window_ends_on_the_emulated_clock() {
    let mws = Mws::start().await;
    let sm = client(&mws).await;
    sm.create_secret().name("old").secret_string("x").send().await.unwrap();
    sm.delete_secret().secret_id("old").recovery_window_in_days(7).send().await.unwrap();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":691200}"#)).await;
    assert_eq!(status, 200);
    let gone = sm.describe_secret().secret_id("old").send().await.unwrap_err();
    assert_eq!(code(&gone), "ResourceNotFoundException");
    sm.create_secret().name("old").secret_string("new").send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn random_passwords() {
    let mws = Mws::start().await;
    let sm = client(&mws).await;
    let p = sm.get_random_password().send().await.unwrap();
    assert_eq!(p.random_password().unwrap().len(), 32);
    let p = sm
        .get_random_password()
        .password_length(50)
        .exclude_punctuation(true)
        .exclude_characters("aeiou")
        .send()
        .await
        .unwrap();
    let p = p.random_password().unwrap();
    assert_eq!(p.len(), 50);
    assert!(p.chars().all(|c| c.is_ascii_alphanumeric() && !"aeiou".contains(c)), "{p}");
    let none = sm
        .get_random_password()
        .exclude_lowercase(true)
        .exclude_uppercase(true)
        .exclude_numbers(true)
        .exclude_punctuation(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&none), "InvalidParameterException");
    mws.stop().await;
}

#[tokio::test]
async fn kms_keys_iam_and_resource_policies() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sm = Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let key = kms.create_key().send().await.unwrap();
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();
    kms.create_alias().alias_name("alias/secrets").target_key_id(&key_arn).send().await.unwrap();

    sm.create_secret().name("cmk").kms_key_id("alias/secrets").secret_string("guarded").send().await.unwrap();
    let d = sm.describe_secret().secret_id("cmk").send().await.unwrap();
    assert_eq!(d.kms_key_id(), Some("arn:aws:kms:us-east-1:123456789012:alias/secrets"));
    let versions = sm.list_secret_version_ids().secret_id("cmk").send().await.unwrap();
    assert_eq!(versions.versions()[0].kms_key_ids(), [key_arn.as_str()]);
    sm.create_secret().name("managed").secret_string("open").send().await.unwrap();

    // A disabled key cannot encrypt or decrypt.
    kms.disable_key().key_id(&key_arn).send().await.unwrap();
    let e = sm.get_secret_value().secret_id("cmk").send().await.unwrap_err();
    assert_eq!(code(&e), "DecryptionFailure");
    let e = sm.put_secret_value().secret_id("cmk").secret_string("more").send().await.unwrap_err();
    assert_eq!(code(&e), "EncryptionFailure");
    kms.enable_key().key_id(&key_arn).send().await.unwrap();

    // Reading needs secretsmanager:GetSecretValue and, for a customer
    // managed key, kms:Decrypt; aws/secretsmanager allows the account
    // through Secrets Manager.
    let read_only = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}"#;
    let (_, reader_cfg) = user_with_policy(&mws, "reader", Some(read_only)).await;
    let reader = Client::new(&reader_cfg);
    assert_eq!(reader.get_secret_value().secret_id("managed").send().await.unwrap().secret_string(), Some("open"));
    let e = reader.get_secret_value().secret_id("cmk").send().await.unwrap_err();
    assert_eq!(code(&e), "AccessDeniedException");
    assert_eq!(e.message(), Some("Access to KMS is not allowed"));
    let e = reader.describe_secret().secret_id("cmk").send().await.unwrap_err();
    assert_eq!(code(&e), "AccessDeniedException");
    let with_kms = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue","kms:Decrypt"],"Resource":"*"}]}"#;
    let (_, decrypter_cfg) = user_with_policy(&mws, "decrypter", Some(with_kms)).await;
    let decrypter = Client::new(&decrypter_cfg);
    assert_eq!(decrypter.get_secret_value().secret_id("cmk").send().await.unwrap().secret_string(), Some("guarded"));

    // Changing the key re-encrypts the current version.
    sm.update_secret().secret_id("cmk").kms_key_id("").send().await.unwrap();
    assert_eq!(reader.get_secret_value().secret_id("cmk").send().await.unwrap().secret_string(), Some("guarded"));

    // Resource policies grant on their own within the account.
    let (_, outsider_cfg) = user_with_policy(&mws, "outsider", None).await;
    let outsider = Client::new(&outsider_cfg);
    assert_eq!(
        code(&outsider.get_secret_value().secret_id("managed").send().await.unwrap_err()),
        "AccessDeniedException"
    );
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/outsider"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}"#;
    let v = sm.validate_resource_policy().secret_id("managed").resource_policy(policy).send().await.unwrap();
    assert!(v.policy_validation_passed());
    sm.put_resource_policy().secret_id("managed").resource_policy(policy).send().await.unwrap();
    let got = sm.get_resource_policy().secret_id("managed").send().await.unwrap();
    assert_eq!(got.resource_policy(), Some(policy));
    let managed_arn = got.arn().unwrap().to_string();
    assert_eq!(outsider.get_secret_value().secret_id(&managed_arn).send().await.unwrap().secret_string(), Some("open"));

    let public = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}"#;
    let v = sm.validate_resource_policy().resource_policy(public).send().await.unwrap();
    assert!(!v.policy_validation_passed());
    assert_eq!(v.validation_errors().len(), 1);
    let e = sm
        .put_resource_policy()
        .secret_id("managed")
        .resource_policy(public)
        .block_public_policy(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "PublicPolicyException");
    let e = sm.put_resource_policy().secret_id("managed").resource_policy("{nope").send().await.unwrap_err();
    assert_eq!(code(&e), "MalformedPolicyDocumentException");
    sm.delete_resource_policy().secret_id("managed").send().await.unwrap();
    assert_eq!(sm.get_resource_policy().secret_id("managed").send().await.unwrap().resource_policy(), None);
    assert_eq!(
        code(&outsider.get_secret_value().secret_id(&managed_arn).send().await.unwrap_err()),
        "AccessDeniedException"
    );

    // Tag conditions.
    let by_tag = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:DescribeSecret","Resource":"*","Condition":{"StringEquals":{"secretsmanager:ResourceTag/team":"blue"}}}]}"#;
    let (_, blue_cfg) = user_with_policy(&mws, "blue", Some(by_tag)).await;
    let blue = Client::new(&blue_cfg);
    sm.tag_resource().secret_id("managed").tags(Tag::builder().key("team").value("blue").build()).send().await.unwrap();
    assert!(blue.describe_secret().secret_id("managed").send().await.is_ok());
    assert_eq!(code(&blue.describe_secret().secret_id("cmk").send().await.unwrap_err()), "AccessDeniedException");
    mws.stop().await;
}

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        for (name, body) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
const ROTATOR_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:DescribeSecret","secretsmanager:GetSecretValue","secretsmanager:PutSecretValue","secretsmanager:UpdateSecretVersionStage","secretsmanager:GetRandomPassword"],"Resource":"*"}]}"#;

/// The shape of AWS's rotation function templates.
pub const ROTATOR: &str = r#"
import json, boto3

def handler(event, context):
    arn, token, step = event["SecretId"], event["ClientRequestToken"], event["Step"]
    sm = boto3.client("secretsmanager")
    meta = sm.describe_secret(SecretId=arn)
    if not meta["RotationEnabled"]:
        raise ValueError("rotation is not enabled")
    versions = meta["VersionIdsToStages"]
    if token not in versions:
        raise ValueError("no such version")
    if "AWSCURRENT" in versions[token]:
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError("version is not pending")
    if step == "createSecret":
        current = json.loads(sm.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"])
        try:
            sm.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except sm.exceptions.ResourceNotFoundException:
            current["password"] = sm.get_random_password(ExcludePunctuation=True)["RandomPassword"]
            current["generation"] = current.get("generation", 0) + 1
            sm.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current), VersionStages=["AWSPENDING"])
    elif step == "finishSecret":
        old = next(v for v, s in versions.items() if "AWSCURRENT" in s)
        sm.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=old)
"#;

async fn rotated(
    sm: &Client,
    id: &str,
    token: &str,
) -> aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretOutput {
    for _ in 0..300 {
        let d = sm.describe_secret().secret_id(id).send().await.unwrap();
        if stages(d.version_ids_to_stages(), token) == ["AWSCURRENT"] {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("rotation to {token} did not finish");
}

#[tokio::test]
async fn rotation_runs_the_lambda_function() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sm = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let role = iam.create_role().role_name("rotator").assume_role_policy_document(TRUST).send().await.unwrap();
    iam.put_role_policy()
        .role_name("rotator")
        .policy_name("secrets")
        .policy_document(ROTATOR_POLICY)
        .send()
        .await
        .unwrap();
    let function = lambda
        .create_function()
        .function_name("rotator")
        .runtime(Runtime::Python312)
        .role(role.role().unwrap().arn())
        .handler("app.handler")
        .timeout(30)
        .code(FunctionCode::builder().zip_file(LambdaBlob::new(zip(&[("app.py", ROTATOR)]))).build())
        .send()
        .await
        .unwrap();
    mws_e2e::function_active(&lambda, "rotator").await;
    let function_arn = function.function_arn().unwrap().to_string();
    let created =
        sm.create_secret().name("db").secret_string(r#"{"username":"app","password":"initial"}"#).send().await.unwrap();
    let first = created.version_id().unwrap().to_string();

    let no_function = sm.rotate_secret().secret_id("db").send().await.unwrap_err();
    assert_eq!(code(&no_function), "InvalidRequestException");
    // The function policy must let Secrets Manager invoke it.
    let denied = sm
        .rotate_secret()
        .secret_id("db")
        .rotation_lambda_arn(&function_arn)
        .rotation_rules(RotationRulesType::builder().automatically_after_days(1).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    assert!(denied.message().unwrap().contains("secretsmanager.amazonaws.com"));
    lambda
        .add_permission()
        .function_name("rotator")
        .statement_id("secrets")
        .action("lambda:InvokeFunction")
        .principal("secretsmanager.amazonaws.com")
        .send()
        .await
        .unwrap();

    let bad_rules = sm
        .rotate_secret()
        .secret_id("db")
        .rotation_lambda_arn(&function_arn)
        .rotation_rules(
            RotationRulesType::builder().automatically_after_days(1).schedule_expression("rate(2 days)").build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_rules), "InvalidParameterException");

    let rotation = sm
        .rotate_secret()
        .secret_id("db")
        .rotation_lambda_arn(&function_arn)
        .rotation_rules(RotationRulesType::builder().automatically_after_days(1).build())
        .send()
        .await
        .unwrap();
    let token = rotation.version_id().unwrap().to_string();
    let d = rotated(&sm, "db", &token).await;
    assert_eq!(d.rotation_enabled(), Some(true));
    assert_eq!(d.rotation_lambda_arn(), Some(function_arn.as_str()));
    assert_eq!(d.rotation_rules().unwrap().automatically_after_days(), Some(1));
    assert!(d.last_rotated_date().is_some());
    let next = d.next_rotation_date().unwrap().secs();
    let tomorrow_end = (chrono::Utc::now().date_naive() + chrono::Days::new(1)).and_hms_opt(23, 59, 59).unwrap();
    assert_eq!(next, tomorrow_end.and_utc().timestamp());
    assert_eq!(stages(d.version_ids_to_stages(), &first), ["AWSPREVIOUS"]);
    let value: serde_json::Value =
        serde_json::from_str(sm.get_secret_value().secret_id("db").send().await.unwrap().secret_string().unwrap())
            .unwrap();
    assert_eq!(value["username"], "app");
    assert_eq!(value["generation"], 1);
    assert_ne!(value["password"], "initial");
    assert_eq!(value["password"].as_str().unwrap().len(), 32);

    // The window opens at midnight the next day: move the clock past it
    // and the next request starts the scheduled rotation.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":172800}"#)).await;
    assert_eq!(status, 200);
    sm.list_secrets().send().await.unwrap();
    let mut scheduled = None;
    for _ in 0..300 {
        let d = sm.describe_secret().secret_id("db").send().await.unwrap();
        let current = d
            .version_ids_to_stages()
            .unwrap()
            .iter()
            .find(|(_, s)| s.as_slice() == ["AWSCURRENT"])
            .map(|(v, _)| v.clone());
        if let Some(c) = current.filter(|c| *c != token) {
            scheduled = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(scheduled.is_some(), "scheduled rotation did not run");
    let value: serde_json::Value =
        serde_json::from_str(sm.get_secret_value().secret_id("db").send().await.unwrap().secret_string().unwrap())
            .unwrap();
    assert_eq!(value["generation"], 2);

    // A failing function leaves AWSPENDING behind, and the next rotation
    // is refused until it is cleaned up.
    sm.put_secret_value().secret_id("db").secret_string("not json").send().await.unwrap();
    let failing = sm.rotate_secret().secret_id("db").send().await.unwrap();
    let failing_token = failing.version_id().unwrap().to_string();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let d = sm.describe_secret().secret_id("db").send().await.unwrap();
    assert_eq!(stages(d.version_ids_to_stages(), &failing_token), ["AWSPENDING"]);
    let busy = sm.rotate_secret().secret_id("db").send().await.unwrap_err();
    assert_eq!(code(&busy), "InvalidRequestException");

    // CancelRotateSecret turns rotation off and names the stuck version.
    let cancelled = sm.cancel_rotate_secret().secret_id("db").send().await.unwrap();
    assert_eq!(cancelled.version_id(), Some(failing_token.as_str()));
    let d = sm.describe_secret().secret_id("db").send().await.unwrap();
    assert_eq!(d.rotation_enabled(), Some(false));
    assert!(d.next_rotation_date().is_none());
    assert_eq!(d.rotation_lambda_arn(), Some(function_arn.as_str()));
    mws.stop().await;
}

#[tokio::test]
async fn replicas_follow_their_primary() {
    let mws = Mws::start().await;
    let sm = client(&mws).await;
    let west = client_in(&mws, "us-west-2").await;
    let eu = client_in(&mws, "eu-west-1").await;
    let created = sm
        .create_secret()
        .name("shared")
        .secret_string("v1")
        .add_replica_regions(ReplicaRegionType::builder().region("us-west-2").build())
        .send()
        .await
        .unwrap();
    let arn = created.arn().unwrap().to_string();
    let status = created.replication_status();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].status().map(|s| s.as_str()), Some("InSync"));

    let replica = west.describe_secret().secret_id("shared").send().await.unwrap();
    assert_eq!(replica.arn(), Some(arn.replace("us-east-1", "us-west-2").as_str()));
    assert_eq!(replica.primary_region(), Some("us-east-1"));
    assert_eq!(west.get_secret_value().secret_id("shared").send().await.unwrap().secret_string(), Some("v1"));
    let primary = sm.describe_secret().secret_id("shared").send().await.unwrap();
    assert_eq!(primary.primary_region(), Some("us-east-1"));
    assert_eq!(primary.replication_status()[0].region(), Some("us-west-2"));

    sm.put_secret_value().secret_id("shared").secret_string("v2").send().await.unwrap();
    assert_eq!(west.get_secret_value().secret_id("shared").send().await.unwrap().secret_string(), Some("v2"));
    let prev = west.get_secret_value().secret_id("shared").version_stage("AWSPREVIOUS").send().await.unwrap();
    assert_eq!(prev.secret_string(), Some("v1"));
    let read_only = west.put_secret_value().secret_id("shared").secret_string("nope").send().await.unwrap_err();
    assert_eq!(code(&read_only), "InvalidRequestException");

    let added = sm
        .replicate_secret_to_regions()
        .secret_id("shared")
        .add_replica_regions(ReplicaRegionType::builder().region("eu-west-1").build())
        .send()
        .await
        .unwrap();
    assert_eq!(added.replication_status().len(), 2);
    assert_eq!(eu.get_secret_value().secret_id("shared").send().await.unwrap().secret_string(), Some("v2"));

    let blocked = sm.delete_secret().secret_id("shared").send().await.unwrap_err();
    assert_eq!(code(&blocked), "InvalidRequestException");
    let removed = sm
        .remove_regions_from_replication()
        .secret_id("shared")
        .remove_replica_regions("eu-west-1")
        .send()
        .await
        .unwrap();
    assert_eq!(removed.replication_status().len(), 1);
    assert_eq!(code(&eu.describe_secret().secret_id("shared").send().await.unwrap_err()), "ResourceNotFoundException");

    // Promote the us-west-2 replica to a standalone secret.
    west.stop_replication_to_replica().secret_id("shared").send().await.unwrap();
    let promoted = west.describe_secret().secret_id("shared").send().await.unwrap();
    assert_eq!(promoted.primary_region(), None);
    west.put_secret_value().secret_id("shared").secret_string("west").send().await.unwrap();
    assert_eq!(sm.get_secret_value().secret_id("shared").send().await.unwrap().secret_string(), Some("v2"));
    assert!(sm.describe_secret().secret_id("shared").send().await.unwrap().replication_status().is_empty());
    sm.delete_secret().secret_id("shared").force_delete_without_recovery(true).send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn state_survives_export_and_import() {
    let mws = Mws::start().await;
    let sm = client(&mws).await;
    sm.create_secret().name("kept").secret_string("value").send().await.unwrap();
    let (status, snapshot) = mws.control("GET", "/_mws/state", None).await;
    assert_eq!(status, 200);
    let (status, _) = mws.control("POST", "/_mws/reset", None).await;
    assert_eq!(status, 200);
    assert_eq!(code(&sm.describe_secret().secret_id("kept").send().await.unwrap_err()), "ResourceNotFoundException");
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&snapshot.to_string())).await;
    assert_eq!(status, 200);
    assert_eq!(sm.get_secret_value().secret_id("kept").send().await.unwrap().secret_string(), Some("value"));
    mws.stop().await;
}

#[tokio::test]
async fn parameter_store_references_read_secrets_as_the_caller() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sm = Client::new(&cfg);
    let ssm = aws_sdk_ssm::Client::new(&cfg);
    let created = sm.create_secret().name("db").secret_string("first").send().await.unwrap();
    let first = created.version_id().unwrap().to_string();
    sm.put_secret_value().secret_id("db").secret_string("second").send().await.unwrap();

    let p = ssm.get_parameter().name("/aws/reference/secretsmanager/db").with_decryption(true).send().await.unwrap();
    let p = p.parameter().unwrap();
    assert_eq!(p.value(), Some("second"));
    assert_eq!(p.r#type(), Some(&aws_sdk_ssm::types::ParameterType::SecureString));
    assert_eq!(p.arn(), created.arn());
    let source: serde_json::Value = serde_json::from_str(p.source_result().unwrap()).unwrap();
    assert_eq!(source["Name"], "db");
    for selector in ["AWSPREVIOUS", first.as_str()] {
        let name = format!("/aws/reference/secretsmanager/db:{selector}");
        let p = ssm.get_parameter().name(&name).with_decryption(true).send().await.unwrap();
        assert_eq!(p.parameter().unwrap().value(), Some("first"));
    }

    // The caller needs secretsmanager:GetSecretValue, not just SSM.
    let ssm_only =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParameter","Resource":"*"}]}"#;
    let (_, user_cfg) = user_with_policy(&mws, "ssm-only", Some(ssm_only)).await;
    let as_user = aws_sdk_ssm::Client::new(&user_cfg);
    let e = as_user
        .get_parameter()
        .name("/aws/reference/secretsmanager/db")
        .with_decryption(true)
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.into_service_error().meta().code(), Some("AccessDeniedException"));
    mws.stop().await;
}

#[tokio::test]
async fn errors_idempotency_and_quotas_match_aws() {
    let mws = Mws::start().await;
    let sm = client(&mws).await;

    // Model constraints answer ValidationException, as Secrets Manager does.
    let e = sm.create_secret().name("short").client_request_token("too-short").secret_string("x").send().await;
    assert_eq!(code(&e.unwrap_err()), "ValidationException");
    let e = sm.list_secrets().max_results(101).send().await.unwrap_err();
    assert_eq!(code(&e), "ValidationException");

    // IAM is asked before the lookup: an unauthorized caller is denied
    // rather than told the secret doesn't exist.
    let (_, nobody_cfg) = user_with_policy(&mws, "nobody", None).await;
    let nobody = Client::new(&nobody_cfg);
    let e = nobody.get_secret_value().secret_id("missing").send().await.unwrap_err();
    assert_eq!(code(&e), "AccessDeniedException");
    let e = sm.get_secret_value().secret_id("missing").send().await.unwrap_err();
    assert_eq!(code(&e), "ResourceNotFoundException");

    // A retried CreateSecret (same token, same value) is ignored.
    let token = "11111111-2222-3333-4444-555555555555";
    let first = sm.create_secret().name("retried").client_request_token(token).secret_string("v").send().await.unwrap();
    let again = sm.create_secret().name("retried").client_request_token(token).secret_string("v").send().await.unwrap();
    assert_eq!(first.arn(), again.arn());
    assert_eq!(again.version_id(), Some(token));
    let e = sm.create_secret().name("retried").client_request_token(token).secret_string("w").send().await;
    assert_eq!(code(&e.unwrap_err()), "ResourceExistsException");
    let e = sm.create_secret().name("retried").secret_string("v").send().await.unwrap_err();
    assert_eq!(code(&e), "ResourceExistsException");

    // Secrets are Regional: another Region's ARN finds nothing.
    let west = client_in(&mws, "us-west-2").await;
    let e = west.get_secret_value().secret_id(first.arn().unwrap()).send().await.unwrap_err();
    assert_eq!(code(&e), "ResourceNotFoundException");

    // Forcibly deleting a secret that doesn't exist succeeds.
    let gone = sm.delete_secret().secret_id("never-was").force_delete_without_recovery(true).send().await.unwrap();
    assert_eq!(gone.name(), Some("never-was"));
    assert!(gone.deletion_date().is_some());
    let e = sm.delete_secret().secret_id("never-was").send().await.unwrap_err();
    assert_eq!(code(&e), "ResourceNotFoundException");

    // The first value of an empty secret becomes AWSCURRENT.
    sm.create_secret().name("empty").send().await.unwrap();
    let put = sm.put_secret_value().secret_id("empty").secret_string("first").version_stages("mine").send().await;
    let mut labels = put.unwrap().version_stages().to_vec();
    labels.sort();
    assert_eq!(labels, ["AWSCURRENT", "mine"]);
    assert_eq!(sm.get_secret_value().secret_id("empty").send().await.unwrap().secret_string(), Some("first"));

    // At most 20 staging labels across a secret's versions.
    let many: Vec<String> = (0..19).map(|i| format!("label-{i}")).collect();
    sm.put_secret_value().secret_id("retried").secret_string("l").set_version_stages(Some(many)).send().await.unwrap();
    let e = sm.put_secret_value().secret_id("retried").secret_string("m").version_stages("one-more").send().await;
    assert_eq!(code(&e.unwrap_err()), "LimitExceededException");

    // At most 100 versions; unlabelled ones older than a day make room.
    sm.create_secret().name("busy").secret_string("0").send().await.unwrap();
    for i in 1..100 {
        sm.put_secret_value().secret_id("busy").secret_string(i.to_string()).send().await.unwrap();
    }
    let e = sm.put_secret_value().secret_id("busy").secret_string("100").send().await.unwrap_err();
    assert_eq!(code(&e), "LimitExceededException");
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":90000}"#)).await;
    assert_eq!(status, 200);
    sm.put_secret_value().secret_id("busy").secret_string("100").send().await.unwrap();
    let all = sm.list_secret_version_ids().secret_id("busy").include_deprecated(true).send().await.unwrap();
    assert_eq!(all.versions().len(), 100);

    // Name and tag filters are case-sensitive prefixes; descriptions match
    // word by word; the free-text search splits words like the console.
    sm.create_secret()
        .name("DatabaseSecret")
        .description("Primary database credentials")
        .tags(Tag::builder().key("Env").value("Prod892").build())
        .send()
        .await
        .unwrap();
    sm.create_secret().name("databaseSecret").send().await.unwrap();
    let names = |out: aws_sdk_secretsmanager::operation::list_secrets::ListSecretsOutput| {
        let mut n: Vec<String> = out.secret_list().iter().filter_map(|s| s.name().map(str::to_string)).collect();
        n.sort();
        n
    };
    let by = |key: FilterNameStringType, value: &str| Filter::builder().key(key).values(value).build();
    let out = sm.list_secrets().filters(by(FilterNameStringType::Name, "Data")).send().await.unwrap();
    assert_eq!(names(out), ["DatabaseSecret"]);
    let out = sm.list_secrets().filters(by(FilterNameStringType::Description, "CRED")).send().await.unwrap();
    assert_eq!(names(out), ["DatabaseSecret"]);
    let out = sm.list_secrets().filters(by(FilterNameStringType::All, "secretProd892")).send().await.unwrap();
    assert_eq!(names(out), ["DatabaseSecret"]);
    let out = sm.list_secrets().filters(by(FilterNameStringType::TagValue, "prod")).send().await.unwrap();
    assert!(names(out).is_empty());
    mws.stop().await;
}
