//! KMS through the official Rust SDK: real cryptography, key policies,
//! grants, aliases, rotation, imported material and multi-Region keys.

use aws_lc_rs::agreement;
use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey, OAEP_SHA256_MGF1SHA256};
use aws_lc_rs::signature::{self, KeyPair, UnparsedPublicKey};
use aws_sdk_kms::error::ProvideErrorMetadata;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{
    AlgorithmSpec, DataKeyPairSpec, DataKeySpec, EncryptionAlgorithmSpec, GrantConstraints, GrantOperation,
    KeyAgreementAlgorithmSpec, KeySpec, KeyState, KeyUsageType, MacAlgorithmSpec, MessageType, OriginType,
    SigningAlgorithmSpec, Tag, WrappingKeySpec,
};
use aws_sdk_kms::Client;
use mws_e2e::{user_with_policy, Mws};

async fn kms(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn new_key(c: &Client) -> String {
    c.create_key().send().await.unwrap().key_metadata().unwrap().key_id().to_string()
}

async fn new_key_with(c: &Client, spec: KeySpec, usage: KeyUsageType) -> String {
    let out = c.create_key().key_spec(spec).key_usage(usage).send().await.unwrap();
    out.key_metadata().unwrap().arn().unwrap().to_string()
}

#[tokio::test]
async fn symmetric_encryption_binds_the_encryption_context() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let created = c.create_key().description("app data").send().await.unwrap();
    let md = created.key_metadata().unwrap();
    assert_eq!(md.key_state(), Some(&KeyState::Enabled));
    assert_eq!(md.key_spec(), Some(&KeySpec::SymmetricDefault));
    assert_eq!(md.encryption_algorithms(), &[EncryptionAlgorithmSpec::SymmetricDefault]);
    assert_eq!(md.aws_account_id(), Some("123456789012"));
    assert!(md.arn().unwrap().starts_with("arn:aws:kms:us-east-1:123456789012:key/"));
    let key_id = md.key_id().to_string();

    let enc = c
        .encrypt()
        .key_id(&key_id)
        .plaintext(Blob::new("secret"))
        .encryption_context("tenant", "a")
        .send()
        .await
        .unwrap();
    let blob = enc.ciphertext_blob().unwrap().clone();
    assert_eq!(enc.key_id(), md.arn());

    // No KeyId needed: the ciphertext names its key.
    let dec = c.decrypt().ciphertext_blob(blob.clone()).encryption_context("tenant", "a").send().await.unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"secret");
    assert_eq!(dec.key_id(), md.arn());
    assert_eq!(dec.encryption_algorithm(), Some(&EncryptionAlgorithmSpec::SymmetricDefault));

    let wrong = c.decrypt().ciphertext_blob(blob.clone()).encryption_context("tenant", "b").send().await.unwrap_err();
    assert_eq!(code(&wrong), "InvalidCiphertextException");
    let missing = c.decrypt().ciphertext_blob(blob.clone()).send().await.unwrap_err();
    assert_eq!(code(&missing), "InvalidCiphertextException");
    let garbage = c.decrypt().ciphertext_blob(Blob::new(vec![7u8; 64])).send().await.unwrap_err();
    assert_eq!(code(&garbage), "InvalidCiphertextException");

    let other = new_key(&c).await;
    let incorrect = c
        .decrypt()
        .key_id(&other)
        .ciphertext_blob(blob.clone())
        .encryption_context("tenant", "a")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&incorrect), "IncorrectKeyException");

    let re = c
        .re_encrypt()
        .ciphertext_blob(blob)
        .source_encryption_context("tenant", "a")
        .destination_key_id(&other)
        .send()
        .await
        .unwrap();
    assert!(re.source_key_id().unwrap().ends_with(&key_id));
    let dec = c.decrypt().ciphertext_blob(re.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"secret");
    assert!(dec.key_id().unwrap().ends_with(&other));
}

#[tokio::test]
async fn data_keys_and_random_bytes() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    let dk = c.generate_data_key().key_id(&key).key_spec(DataKeySpec::Aes256).send().await.unwrap();
    assert_eq!(dk.plaintext().unwrap().as_ref().len(), 32);
    let back = c.decrypt().ciphertext_blob(dk.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(back.plaintext(), dk.plaintext());

    let n = c.generate_data_key().key_id(&key).number_of_bytes(64).send().await.unwrap();
    assert_eq!(n.plaintext().unwrap().as_ref().len(), 64);
    let both =
        c.generate_data_key().key_id(&key).number_of_bytes(16).key_spec(DataKeySpec::Aes128).send().await.unwrap_err();
    assert_eq!(code(&both), "ValidationException");

    let np = c.generate_data_key_without_plaintext().key_id(&key).key_spec(DataKeySpec::Aes128).send().await.unwrap();
    let back = c.decrypt().ciphertext_blob(np.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(back.plaintext().unwrap().as_ref().len(), 16);

    // A data key pair: the encrypted private key decrypts to the PKCS#8
    // that matches the public key.
    let pair =
        c.generate_data_key_pair().key_id(&key).key_pair_spec(DataKeyPairSpec::EccNistP256).send().await.unwrap();
    let private =
        c.decrypt().ciphertext_blob(pair.private_key_ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(private.plaintext(), pair.private_key_plaintext());
    let kp = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pair.private_key_plaintext().unwrap().as_ref(),
    )
    .unwrap();
    assert_eq!(kp.public_key().as_der().unwrap().as_ref(), pair.public_key().unwrap().as_ref());

    let rnd = c.generate_random().number_of_bytes(48).send().await.unwrap();
    assert_eq!(rnd.plaintext().unwrap().as_ref().len(), 48);

    let sign_key = new_key_with(&c, KeySpec::EccNistP256, KeyUsageType::SignVerify).await;
    let wrong = c.generate_data_key().key_id(&sign_key).key_spec(DataKeySpec::Aes256).send().await.unwrap_err();
    assert_eq!(code(&wrong), "InvalidKeyUsageException");
}

#[tokio::test]
async fn key_lifecycle_states_and_errors() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;

    c.disable_key().key_id(&key).send().await.unwrap();
    let off = c.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&off), "DisabledException");
    c.enable_key().key_id(&key).send().await.unwrap();

    let short = c.schedule_key_deletion().key_id(&key).pending_window_in_days(3).send().await.unwrap_err();
    assert_eq!(code(&short), "ValidationException");
    let sched = c.schedule_key_deletion().key_id(&key).pending_window_in_days(7).send().await.unwrap();
    assert_eq!(sched.key_state(), Some(&KeyState::PendingDeletion));
    assert_eq!(sched.pending_window_in_days(), Some(7));
    assert!(sched.deletion_date().is_some());
    let pending = c.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&pending), "KMSInvalidStateException");
    let md = c.describe_key().key_id(&key).send().await.unwrap();
    assert_eq!(md.key_metadata().unwrap().key_state(), Some(&KeyState::PendingDeletion));
    c.cancel_key_deletion().key_id(&key).send().await.unwrap();
    let md = c.describe_key().key_id(&key).send().await.unwrap();
    assert_eq!(md.key_metadata().unwrap().key_state(), Some(&KeyState::Disabled));
    let again = c.cancel_key_deletion().key_id(&key).send().await.unwrap_err();
    assert_eq!(code(&again), "KMSInvalidStateException");

    c.update_key_description().key_id(&key).description("renamed").send().await.unwrap();
    let md = c.describe_key().key_id(&key).send().await.unwrap();
    assert_eq!(md.key_metadata().unwrap().description(), Some("renamed"));

    let missing = c.describe_key().key_id("11111111-2222-3333-4444-555555555555").send().await.unwrap_err();
    assert_eq!(code(&missing), "NotFoundException");
    assert_eq!(
        missing.message(),
        Some("Key 'arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555' does not exist")
    );

    for _ in 0..2 {
        new_key(&c).await;
    }
    let page1 = c.list_keys().limit(2).send().await.unwrap();
    assert_eq!(page1.keys().len(), 2);
    assert!(page1.truncated());
    let page2 = c.list_keys().limit(2).marker(page1.next_marker().unwrap()).send().await.unwrap();
    assert_eq!(page2.keys().len(), 1);
    assert!(!page2.truncated());

    c.tag_resource()
        .key_id(&key)
        .tags(Tag::builder().tag_key("team").tag_value("core").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = c.list_resource_tags().key_id(&key).send().await.unwrap();
    assert_eq!(tags.tags()[0].tag_value(), "core");
    let reserved = c
        .tag_resource()
        .key_id(&key)
        .tags(Tag::builder().tag_key("aws:x").tag_value("y").build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&reserved), "TagException");
    c.untag_resource().key_id(&key).tag_keys("team").send().await.unwrap();
    assert!(c.list_resource_tags().key_id(&key).send().await.unwrap().tags().is_empty());
}

#[tokio::test]
async fn aliases_name_keys() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let a = new_key(&c).await;
    let b = new_key(&c).await;
    c.create_alias().alias_name("alias/app").target_key_id(&a).send().await.unwrap();
    let dup = c.create_alias().alias_name("alias/app").target_key_id(&b).send().await.unwrap_err();
    assert_eq!(code(&dup), "AlreadyExistsException");
    let reserved = c.create_alias().alias_name("alias/aws/mine").target_key_id(&a).send().await.unwrap_err();
    assert_eq!(code(&reserved), "InvalidAliasNameException");

    let enc = c.encrypt().key_id("alias/app").plaintext(Blob::new("hi")).send().await.unwrap();
    assert!(enc.key_id().unwrap().ends_with(&a));
    let by_arn = c.describe_key().key_id("arn:aws:kms:us-east-1:123456789012:alias/app").send().await.unwrap();
    assert_eq!(by_arn.key_metadata().unwrap().key_id(), a);

    c.update_alias().alias_name("alias/app").target_key_id(&b).send().await.unwrap();
    let enc = c.encrypt().key_id("alias/app").plaintext(Blob::new("hi")).send().await.unwrap();
    assert!(enc.key_id().unwrap().ends_with(&b));
    let listed = c.list_aliases().key_id(&b).send().await.unwrap();
    assert_eq!(listed.aliases()[0].alias_name(), Some("alias/app"));
    assert_eq!(listed.aliases()[0].alias_arn(), Some("arn:aws:kms:us-east-1:123456789012:alias/app"));

    c.delete_alias().alias_name("alias/app").send().await.unwrap();
    let gone = c.describe_key().key_id("alias/app").send().await.unwrap_err();
    assert_eq!(code(&gone), "NotFoundException");
    assert_eq!(gone.message(), Some("Alias arn:aws:kms:us-east-1:123456789012:alias/app is not found."));
}

#[tokio::test]
async fn signatures_verify_outside_kms() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;

    let rsa = new_key_with(&c, KeySpec::Rsa2048, KeyUsageType::SignVerify).await;
    let public = c.get_public_key().key_id(&rsa).send().await.unwrap();
    assert_eq!(public.signing_algorithms().len(), 6);
    let spki = public.public_key().unwrap().as_ref().to_vec();
    let rsa_public = PublicEncryptingKey::from_der(&spki).unwrap();
    let _ = rsa_public;
    for (alg, params) in [
        (SigningAlgorithmSpec::RsassaPssSha256, &signature::RSA_PSS_2048_8192_SHA256),
        (SigningAlgorithmSpec::RsassaPkcs1V15Sha256, &signature::RSA_PKCS1_2048_8192_SHA256),
    ] {
        let sig =
            c.sign().key_id(&rsa).message(Blob::new("payload")).signing_algorithm(alg.clone()).send().await.unwrap();
        let sig = sig.signature().unwrap().as_ref().to_vec();
        let raw = rsa_spki_to_pkcs1(&spki);
        UnparsedPublicKey::new(params, &raw).verify(b"payload", &sig).unwrap();
        let ok = c
            .verify()
            .key_id(&rsa)
            .message(Blob::new("payload"))
            .signature(Blob::new(sig.clone()))
            .signing_algorithm(alg.clone())
            .send()
            .await
            .unwrap();
        assert!(ok.signature_valid());
        let bad = c
            .verify()
            .key_id(&rsa)
            .message(Blob::new("tampered"))
            .signature(Blob::new(sig))
            .signing_algorithm(alg)
            .send()
            .await
            .unwrap_err();
        assert_eq!(code(&bad), "KMSInvalidSignatureException");
    }

    // ECDSA over a precomputed digest verifies against the raw message.
    let ec = new_key_with(&c, KeySpec::EccNistP256, KeyUsageType::SignVerify).await;
    let point = ec_point(c.get_public_key().key_id(&ec).send().await.unwrap().public_key().unwrap().as_ref());
    let d = digest(&SHA256, b"message");
    let sig = c
        .sign()
        .key_id(&ec)
        .message(Blob::new(d.as_ref()))
        .message_type(MessageType::Digest)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
        .send()
        .await
        .unwrap();
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point)
        .verify(b"message", sig.signature().unwrap().as_ref())
        .unwrap();
    let wrong_alg = c
        .sign()
        .key_id(&ec)
        .message(Blob::new("m"))
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha384)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&wrong_alg), "InvalidKeyUsageException");

    let sym = new_key(&c).await;
    let no_public = c.get_public_key().key_id(&sym).send().await.unwrap_err();
    assert_eq!(code(&no_public), "UnsupportedOperationException");
}

/// The RSAPublicKey inside an RSA SubjectPublicKeyInfo (skip the fixed
/// AlgorithmIdentifier and the BIT STRING header).
fn rsa_spki_to_pkcs1(spki: &[u8]) -> Vec<u8> {
    let pos = spki.windows(2).position(|w| w == [0x03, 0x82]).unwrap();
    spki[pos + 5..].to_vec()
}

/// The uncompressed point at the end of an EC SubjectPublicKeyInfo.
fn ec_point(spki: &[u8]) -> Vec<u8> {
    spki[spki.len() - 65..].to_vec()
}

#[tokio::test]
async fn rsa_encryption_hmac_and_key_agreement() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;

    let rsa = new_key_with(&c, KeySpec::Rsa3072, KeyUsageType::EncryptDecrypt).await;
    let spki = c.get_public_key().key_id(&rsa).send().await.unwrap().public_key().unwrap().as_ref().to_vec();
    let public = OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(&spki).unwrap()).unwrap();
    let mut ct = vec![0u8; public.ciphertext_size()];
    let ct = public.encrypt(&OAEP_SHA256_MGF1SHA256, b"offline", &mut ct, None).unwrap().to_vec();
    let dec = c
        .decrypt()
        .key_id(&rsa)
        .ciphertext_blob(Blob::new(ct))
        .encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256)
        .send()
        .await
        .unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"offline");

    let hmac = new_key_with(&c, KeySpec::Hmac256, KeyUsageType::GenerateVerifyMac).await;
    let mac = c
        .generate_mac()
        .key_id(&hmac)
        .message(Blob::new("m"))
        .mac_algorithm(MacAlgorithmSpec::HmacSha256)
        .send()
        .await
        .unwrap();
    assert_eq!(mac.mac().unwrap().as_ref().len(), 32);
    let ok = c
        .verify_mac()
        .key_id(&hmac)
        .message(Blob::new("m"))
        .mac(mac.mac().unwrap().clone())
        .mac_algorithm(MacAlgorithmSpec::HmacSha256)
        .send()
        .await
        .unwrap();
    assert!(ok.mac_valid());
    let bad = c
        .verify_mac()
        .key_id(&hmac)
        .message(Blob::new("other"))
        .mac(mac.mac().unwrap().clone())
        .mac_algorithm(MacAlgorithmSpec::HmacSha256)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad), "KMSInvalidMacException");
    let bad_combo = c.create_key().key_spec(KeySpec::Hmac256).send().await.unwrap_err();
    assert_eq!(code(&bad_combo), "ValidationException");

    // ECDH: both sides derive the same secret.
    let ecdh = new_key_with(&c, KeySpec::EccNistP256, KeyUsageType::KeyAgreement).await;
    let kms_spki = c.get_public_key().key_id(&ecdh).send().await.unwrap().public_key().unwrap().as_ref().to_vec();
    let mine = agreement::PrivateKey::generate(&agreement::ECDH_P256).unwrap();
    let my_spki = mine.compute_public_key().unwrap().as_der().unwrap().as_ref().to_vec();
    let derived = c
        .derive_shared_secret()
        .key_id(&ecdh)
        .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
        .public_key(Blob::new(my_spki))
        .send()
        .await
        .unwrap();
    let local = agreement::agree(
        &mine,
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, ec_point(&kms_spki)),
        (),
        |s| Ok(s.to_vec()),
    )
    .unwrap();
    assert_eq!(derived.shared_secret().unwrap().as_ref(), local.as_slice());
}

#[tokio::test]
async fn key_policies_gate_iam_users() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    let (_, cfg) = user_with_policy(&mws, "dev", None).await;
    let dev = Client::new(&cfg);

    // The default key policy delegates to IAM, and dev has no IAM policy.
    let denied = dev.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDeniedException");
    assert!(denied.message().unwrap().contains("kms:Encrypt"), "{:?}", denied.message());

    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.put_user_policy()
        .user_name("dev")
        .policy_name("kms")
        .policy_document(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}"#)
        .send()
        .await
        .unwrap();
    dev.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap();

    // A key policy that does not delegate to IAM: IAM permissions no longer
    // matter, only the users the policy names.
    let restricted = r#"{"Version":"2012-10-17","Statement":[
        {"Sid":"Admin","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:PutKeyPolicy","Resource":"*"},
        {"Sid":"Ops","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/ops"},"Action":["kms:Encrypt","kms:Decrypt"],"Resource":"*"}]}"#;
    let (_, ops_cfg) = user_with_policy(&mws, "ops", None).await;
    let ops = Client::new(&ops_cfg);
    c.put_key_policy().key_id(&key).policy(restricted).send().await.unwrap();
    ops.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap();
    let dev_denied = dev.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&dev_denied), "AccessDeniedException");
    let root_denied = c.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&root_denied), "AccessDeniedException");
    let got = c.get_key_policy().key_id(&key).send().await.unwrap_err();
    assert_eq!(code(&got), "AccessDeniedException");

    // The lockout safety check refuses a policy the caller could not change.
    let other = new_key(&c).await;
    let lockout = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/ops"},"Action":"kms:*","Resource":"*"}]}"#;
    let refused = c.put_key_policy().key_id(&other).policy(lockout).send().await.unwrap_err();
    assert_eq!(code(&refused), "MalformedPolicyDocumentException");
    c.put_key_policy().key_id(&other).policy(lockout).bypass_policy_lockout_safety_check(true).send().await.unwrap();
    let malformed = c.create_key().policy("{not json").send().await.unwrap_err();
    assert_eq!(code(&malformed), "MalformedPolicyDocumentException");

    let fresh = new_key(&c).await;
    let policy = c.get_key_policy().key_id(&fresh).send().await.unwrap();
    let doc: serde_json::Value = serde_json::from_str(policy.policy().unwrap()).unwrap();
    assert_eq!(doc["Statement"][0]["Principal"]["AWS"], "arn:aws:iam::123456789012:root");
    assert_eq!(policy.policy_name(), Some("default"));
}

#[tokio::test]
async fn grants_allow_their_grantee() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    let (_, cfg) = user_with_policy(&mws, "app", None).await;
    let app = Client::new(&cfg);
    assert!(app.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.is_err());

    let grant = c
        .create_grant()
        .key_id(&key)
        .grantee_principal("arn:aws:iam::123456789012:user/app")
        .retiring_principal("arn:aws:iam::123456789012:user/app")
        .operations(GrantOperation::Encrypt)
        .operations(GrantOperation::Decrypt)
        .constraints(GrantConstraints::builder().encryption_context_equals("purpose", "test").build())
        .name("app-grant")
        .send()
        .await
        .unwrap();
    let grant_id = grant.grant_id().unwrap().to_string();
    assert_eq!(grant_id.len(), 64);

    let enc = app
        .encrypt()
        .key_id(&key)
        .plaintext(Blob::new("x"))
        .encryption_context("purpose", "test")
        .send()
        .await
        .unwrap();
    let outside = app.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&outside), "AccessDeniedException");
    app.decrypt()
        .ciphertext_blob(enc.ciphertext_blob().unwrap().clone())
        .encryption_context("purpose", "test")
        .send()
        .await
        .unwrap();

    let grants = c.list_grants().key_id(&key).send().await.unwrap();
    assert_eq!(grants.grants().len(), 1);
    assert_eq!(grants.grants()[0].name(), Some("app-grant"));
    let retirable =
        c.list_retirable_grants().retiring_principal("arn:aws:iam::123456789012:user/app").send().await.unwrap();
    assert_eq!(retirable.grants().len(), 1);

    let bad_op = c
        .create_grant()
        .key_id(&key)
        .grantee_principal("arn:aws:iam::123456789012:user/app")
        .operations(GrantOperation::Sign)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_op), "ValidationException");

    app.retire_grant().grant_token(grant.grant_token().unwrap()).send().await.unwrap();
    assert!(c.list_grants().key_id(&key).send().await.unwrap().grants().is_empty());
    let after = app
        .encrypt()
        .key_id(&key)
        .plaintext(Blob::new("x"))
        .encryption_context("purpose", "test")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&after), "AccessDeniedException");

    let g2 = c
        .create_grant()
        .key_id(&key)
        .grantee_principal("arn:aws:iam::123456789012:user/app")
        .operations(GrantOperation::DescribeKey)
        .send()
        .await
        .unwrap();
    app.describe_key().key_id(&key).send().await.unwrap();
    c.revoke_grant().key_id(&key).grant_id(g2.grant_id().unwrap()).send().await.unwrap();
    assert!(app.describe_key().key_id(&key).send().await.is_err());
}

#[tokio::test]
async fn rotation_keeps_old_ciphertexts_readable() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    let before = c.encrypt().key_id(&key).plaintext(Blob::new("old")).send().await.unwrap();

    c.enable_key_rotation().key_id(&key).rotation_period_in_days(90).send().await.unwrap();
    let status = c.get_key_rotation_status().key_id(&key).send().await.unwrap();
    assert!(status.key_rotation_enabled());
    assert_eq!(status.rotation_period_in_days(), Some(90));
    assert!(status.next_rotation_date().is_some());

    let first = c
        .describe_key()
        .key_id(&key)
        .send()
        .await
        .unwrap()
        .key_metadata()
        .unwrap()
        .current_key_material_id()
        .map(str::to_string);
    c.rotate_key_on_demand().key_id(&key).send().await.unwrap();
    let rotations = c.list_key_rotations().key_id(&key).send().await.unwrap();
    assert_eq!(rotations.rotations().len(), 1);
    assert_eq!(rotations.rotations()[0].rotation_type().map(|r| r.as_str()), Some("ON_DEMAND"));
    let current = c
        .describe_key()
        .key_id(&key)
        .send()
        .await
        .unwrap()
        .key_metadata()
        .unwrap()
        .current_key_material_id()
        .map(str::to_string);
    assert_ne!(first, current);

    let old = c.decrypt().ciphertext_blob(before.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(old.plaintext().unwrap().as_ref(), b"old");
    assert_eq!(old.key_material_id().map(str::to_string), first);
    let after = c.encrypt().key_id(&key).plaintext(Blob::new("new")).send().await.unwrap();
    let new = c.decrypt().ciphertext_blob(after.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(new.key_material_id().map(str::to_string), current);

    c.disable_key_rotation().key_id(&key).send().await.unwrap();
    assert!(!c.get_key_rotation_status().key_id(&key).send().await.unwrap().key_rotation_enabled());
    let asym = new_key_with(&c, KeySpec::EccNistP256, KeyUsageType::SignVerify).await;
    let unsupported = c.enable_key_rotation().key_id(&asym).send().await.unwrap_err();
    assert_eq!(code(&unsupported), "UnsupportedOperationException");
}

/// Wrap key material as the AWS docs describe for RSA_AES_KEY_WRAP_SHA_256:
/// RSA-OAEP(SHA-256) of a fresh AES key, then AES key wrap with padding.
fn wrap_material(spki: &[u8], material: &[u8]) -> Vec<u8> {
    use aws_lc_rs::key_wrap::{AesKek, KeyWrapPadded, AES_256};
    let mut aes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut aes).unwrap();
    let public = OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(spki).unwrap()).unwrap();
    let mut wrapped_key = vec![0u8; public.ciphertext_size()];
    let wrapped_key = public.encrypt(&OAEP_SHA256_MGF1SHA256, &aes, &mut wrapped_key, None).unwrap().to_vec();
    let kek = AesKek::new(&AES_256, &aes).unwrap();
    let mut out = vec![0u8; material.len() + 16];
    let wrapped = kek.wrap_with_padding(material, &mut out).unwrap().to_vec();
    [wrapped_key, wrapped].concat()
}

#[tokio::test]
async fn imported_key_material() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let created = c.create_key().origin(OriginType::External).send().await.unwrap();
    let key = created.key_metadata().unwrap().key_id().to_string();
    assert_eq!(created.key_metadata().unwrap().key_state(), Some(&KeyState::PendingImport));
    let early = c.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&early), "KMSInvalidStateException");

    let material = [42u8; 32];
    let import = |material: Vec<u8>| {
        let c = c.clone();
        let key = key.clone();
        async move {
            let params = c
                .get_parameters_for_import()
                .key_id(&key)
                .wrapping_algorithm(AlgorithmSpec::RsaAesKeyWrapSha256)
                .wrapping_key_spec(WrappingKeySpec::Rsa4096)
                .send()
                .await
                .unwrap();
            let wrapped = wrap_material(params.public_key().unwrap().as_ref(), &material);
            c.import_key_material()
                .key_id(&key)
                .import_token(params.import_token().unwrap().clone())
                .encrypted_key_material(Blob::new(wrapped))
                .send()
                .await
        }
    };
    import(material.to_vec()).await.unwrap();
    let md = c.describe_key().key_id(&key).send().await.unwrap();
    assert_eq!(md.key_metadata().unwrap().key_state(), Some(&KeyState::Enabled));
    let enc = c.encrypt().key_id(&key).plaintext(Blob::new("imported")).send().await.unwrap();

    c.delete_imported_key_material().key_id(&key).send().await.unwrap();
    let md = c.describe_key().key_id(&key).send().await.unwrap();
    assert_eq!(md.key_metadata().unwrap().key_state(), Some(&KeyState::PendingImport));
    let different = import(vec![7u8; 32]).await.unwrap_err();
    assert_eq!(code(&different), "IncorrectKeyMaterialException");
    import(material.to_vec()).await.unwrap();
    let dec = c.decrypt().ciphertext_blob(enc.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"imported");

    let native = new_key(&c).await;
    let not_external = c
        .get_parameters_for_import()
        .key_id(&native)
        .wrapping_algorithm(AlgorithmSpec::RsaesOaepSha256)
        .wrapping_key_spec(WrappingKeySpec::Rsa2048)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&not_external), "UnsupportedOperationException");
}

#[tokio::test]
async fn multi_region_replicas_share_material() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let created = c.create_key().multi_region(true).send().await.unwrap();
    let md = created.key_metadata().unwrap();
    let key_id = md.key_id().to_string();
    assert!(key_id.starts_with("mrk-"));
    let enc = c.encrypt().key_id(&key_id).plaintext(Blob::new("everywhere")).send().await.unwrap();

    let replica = c.replicate_key().key_id(&key_id).replica_region("us-west-2").send().await.unwrap();
    let rmd = replica.replica_key_metadata().unwrap();
    assert_eq!(rmd.arn(), Some(format!("arn:aws:kms:us-west-2:123456789012:key/{key_id}").as_str()));
    let dup = c.replicate_key().key_id(&key_id).replica_region("us-west-2").send().await.unwrap_err();
    assert_eq!(code(&dup), "AlreadyExistsException");

    let west_cfg = aws_config::SdkConfig::builder()
        .region(aws_config::Region::new("us-west-2"))
        .endpoint_url(&mws.endpoint)
        .credentials_provider(mws.root_sdk_config().await.credentials_provider().unwrap())
        .behavior_version(aws_config::BehaviorVersion::latest())
        .build();
    let west = Client::new(&west_cfg);
    let dec = west.decrypt().ciphertext_blob(enc.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"everywhere");
    let described = west.describe_key().key_id(&key_id).send().await.unwrap();
    let mrc = described.key_metadata().unwrap().multi_region_configuration().unwrap();
    assert_eq!(mrc.multi_region_key_type().map(|t| t.as_str()), Some("REPLICA"));
    assert_eq!(mrc.primary_key().unwrap().region(), Some("us-east-1"));

    // The primary cannot be deleted while it has replicas.
    let sched = c.schedule_key_deletion().key_id(&key_id).pending_window_in_days(7).send().await.unwrap();
    assert_eq!(sched.key_state(), Some(&KeyState::PendingReplicaDeletion));
}

#[tokio::test]
async fn kms_state_survives_export_and_import() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    c.create_alias().alias_name("alias/kept").target_key_id(&key).send().await.unwrap();
    let enc = c.encrypt().key_id("alias/kept").plaintext(Blob::new("durable")).send().await.unwrap();

    let (_, exported) = mws.control("GET", "/_mws/state", None).await;
    mws.control("POST", "/_mws/reset", None).await;
    assert!(c.list_keys().send().await.unwrap().keys().is_empty());
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&exported.to_string())).await;
    assert_eq!(status, 200);
    let dec = c.decrypt().ciphertext_blob(enc.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(dec.plaintext().unwrap().as_ref(), b"durable");
    c.describe_key().key_id("alias/kept").send().await.unwrap();
}

#[tokio::test]
async fn ml_kem_keys_encapsulate_shared_secrets() {
    use aws_sdk_kms::types::EncapsulationAlgorithmSpec;
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key_with(&c, KeySpec::MlKem768, KeyUsageType::EncapsulateDecapsulate).await;
    let enc =
        c.encapsulate().key_id(&key).encapsulation_algorithm(EncapsulationAlgorithmSpec::MlKem).send().await.unwrap();
    let secret = enc.shared_secret().unwrap().as_ref().to_vec();
    assert_eq!(secret.len(), 32);
    let ct = enc.shared_secret_ciphertext_blob().unwrap().clone();
    let dec = c
        .decapsulate()
        .key_id(&key)
        .encapsulation_algorithm(EncapsulationAlgorithmSpec::MlKem)
        .shared_secret_ciphertext_blob(ct.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(dec.shared_secret().unwrap().as_ref(), secret.as_slice());

    // Another ML-KEM key derives a different secret from the same ciphertext.
    let other = new_key_with(&c, KeySpec::MlKem768, KeyUsageType::EncapsulateDecapsulate).await;
    let wrong = c
        .decapsulate()
        .key_id(&other)
        .encapsulation_algorithm(EncapsulationAlgorithmSpec::MlKem)
        .shared_secret_ciphertext_blob(ct)
        .send()
        .await;
    if let Ok(w) = wrong {
        assert_ne!(w.shared_secret().unwrap().as_ref(), secret.as_slice());
    }

    // Encapsulation needs an ENCAPSULATE_DECAPSULATE key.
    let symmetric = new_key(&c).await;
    let err = c
        .encapsulate()
        .key_id(&symmetric)
        .encapsulation_algorithm(EncapsulationAlgorithmSpec::MlKem)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err), "InvalidKeyUsageException");
}

#[tokio::test]
async fn data_key_pairs_without_plaintext_decrypt_later() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    let out = c
        .generate_data_key_pair_without_plaintext()
        .key_id(&key)
        .key_pair_spec(DataKeyPairSpec::EccNistP256)
        .encryption_context("purpose", "signing")
        .send()
        .await
        .unwrap();
    assert_eq!(out.key_pair_spec(), Some(&DataKeyPairSpec::EccNistP256));
    let public = out.public_key().unwrap().as_ref().to_vec();
    let private = c
        .decrypt()
        .ciphertext_blob(out.private_key_ciphertext_blob().unwrap().clone())
        .encryption_context("purpose", "signing")
        .send()
        .await
        .unwrap();
    // The decrypted private key signs messages the public key verifies.
    let pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        private.plaintext().unwrap().as_ref(),
    )
    .unwrap();
    let spki = pair.public_key().as_der().unwrap();
    assert_eq!(spki.as_ref(), public.as_slice());
    let sig = pair.sign(&aws_lc_rs::rand::SystemRandom::new(), b"hello").unwrap();
    let raw_point = &public[public.len() - 65..];
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, raw_point).verify(b"hello", sig.as_ref()).unwrap();

    let missing_context =
        c.decrypt().ciphertext_blob(out.private_key_ciphertext_blob().unwrap().clone()).send().await.unwrap_err();
    assert_eq!(code(&missing_context), "InvalidCiphertextException");
}

#[tokio::test]
async fn key_last_usage_and_policy_names() {
    use aws_sdk_kms::operation::RequestId;
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    let fresh = c.get_key_last_usage().key_id(&key).send().await.unwrap();
    assert!(fresh.key_last_usage().is_none());
    assert!(fresh.key_creation_date().is_some());
    assert!(fresh.tracking_start_date().is_some());

    let enc = c.encrypt().key_id(&key).plaintext(Blob::new("x")).send().await.unwrap();
    let used = c.get_key_last_usage().key_id(&key).send().await.unwrap();
    let last = used.key_last_usage().unwrap();
    assert_eq!(last.operation().map(|o| o.as_str()), Some("Encrypt"));
    assert_eq!(last.kms_request_id(), enc.request_id());
    assert!(used.key_id().unwrap().starts_with("arn:aws:kms:us-east-1:123456789012:key/"));

    // DescribeKey is not a cryptographic operation and does not count.
    c.describe_key().key_id(&key).send().await.unwrap();
    let still = c.get_key_last_usage().key_id(&key).send().await.unwrap();
    assert_eq!(still.key_last_usage().unwrap().operation().map(|o| o.as_str()), Some("Encrypt"));

    let policies = c.list_key_policies().key_id(&key).send().await.unwrap();
    assert_eq!(policies.policy_names(), ["default"]);
    assert!(!policies.truncated());
    let missing = c.list_key_policies().key_id("1234abcd-12ab-34cd-56ef-1234567890ab").send().await.unwrap_err();
    assert_eq!(code(&missing), "NotFoundException");
}

#[tokio::test]
async fn update_primary_region_swaps_primary_and_replica() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key_id = c.create_key().multi_region(true).send().await.unwrap().key_metadata().unwrap().key_id().to_string();
    c.replicate_key().key_id(&key_id).replica_region("eu-west-1").send().await.unwrap();

    let missing = c.update_primary_region().key_id(&key_id).primary_region("ap-south-1").send().await.unwrap_err();
    assert_eq!(code(&missing), "NotFoundException");

    c.update_primary_region().key_id(&key_id).primary_region("eu-west-1").send().await.unwrap();
    let md = c.describe_key().key_id(&key_id).send().await.unwrap();
    let mrc = md.key_metadata().unwrap().multi_region_configuration().unwrap();
    assert_eq!(mrc.multi_region_key_type().map(|t| t.as_str()), Some("REPLICA"));
    assert_eq!(mrc.primary_key().unwrap().region(), Some("eu-west-1"));

    // The old primary is now a replica and cannot change the primary.
    let again = c.update_primary_region().key_id(&key_id).primary_region("us-east-1").send().await.unwrap_err();
    assert_eq!(code(&again), "UnsupportedOperationException");

    let single = new_key(&c).await;
    let not_mrk = c.update_primary_region().key_id(&single).primary_region("eu-west-1").send().await.unwrap_err();
    assert_eq!(code(&not_mrk), "UnsupportedOperationException");
}

#[tokio::test]
async fn external_key_stores_lifecycle() {
    use aws_sdk_kms::types::{
        ConnectionErrorCodeType, ConnectionStateType, CustomKeyStoreType, XksProxyAuthenticationCredentialType,
        XksProxyConnectivityType,
    };
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let cred = XksProxyAuthenticationCredentialType::builder()
        .access_key_id("ABCDE22345673EXAMPLE")
        .raw_secret_access_key("DXjSUawnel2fr6SKC7G25CNxTyWKE5PF9XX6H/u9pSo=")
        .build()
        .unwrap();
    let create = |name: &str, path: &str| {
        c.create_custom_key_store()
            .custom_key_store_name(name)
            .custom_key_store_type(CustomKeyStoreType::ExternalKeyStore)
            .xks_proxy_uri_endpoint("https://xks.example.com")
            .xks_proxy_uri_path(path)
            .xks_proxy_connectivity(XksProxyConnectivityType::PublicEndpoint)
            .xks_proxy_authentication_credential(cred.clone())
            .send()
    };
    let id = create("store-a", "/kms/xks/v1").await.unwrap().custom_key_store_id().unwrap().to_string();
    assert!(id.starts_with("cks-"));
    let dup_name = create("store-a", "/other/kms/xks/v1").await.unwrap_err();
    assert_eq!(code(&dup_name), "CustomKeyStoreNameInUseException");
    let dup_uri = create("store-b", "/kms/xks/v1").await.unwrap_err();
    assert_eq!(code(&dup_uri), "XksProxyUriInUseException");
    let hsm = c
        .create_custom_key_store()
        .custom_key_store_name("hsm")
        .cloud_hsm_cluster_id("cluster-abc234defgh")
        .key_store_password("password1234")
        .trust_anchor_certificate("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&hsm), "CloudHsmClusterNotFoundException");

    let described = c.describe_custom_key_stores().custom_key_store_id(&id).send().await.unwrap();
    let store = &described.custom_key_stores()[0];
    assert_eq!(store.custom_key_store_name(), Some("store-a"));
    assert_eq!(store.connection_state(), Some(&ConnectionStateType::Disconnected));
    assert_eq!(store.custom_key_store_type(), Some(&CustomKeyStoreType::ExternalKeyStore));
    let xks = store.xks_proxy_configuration().unwrap();
    assert_eq!(xks.access_key_id(), Some("ABCDE22345673EXAMPLE"));
    assert_eq!(xks.uri_path(), Some("/kms/xks/v1"));

    // MWS cannot reach the proxy, so connecting fails as an unreachable proxy does.
    c.connect_custom_key_store().custom_key_store_id(&id).send().await.unwrap();
    let failed = c.describe_custom_key_stores().custom_key_store_name("store-a").send().await.unwrap();
    let store = &failed.custom_key_stores()[0];
    assert_eq!(store.connection_state(), Some(&ConnectionStateType::Failed));
    assert_eq!(store.connection_error_code(), Some(&ConnectionErrorCodeType::XksProxyNotReachable));
    let busy = c.update_custom_key_store().custom_key_store_id(&id).new_custom_key_store_name("x").send().await;
    assert_eq!(code(&busy.unwrap_err()), "CustomKeyStoreInvalidStateException");

    c.disconnect_custom_key_store().custom_key_store_id(&id).send().await.unwrap();
    c.update_custom_key_store()
        .custom_key_store_id(&id)
        .new_custom_key_store_name("store-renamed")
        .xks_proxy_uri_path("/v2/kms/xks/v1")
        .send()
        .await
        .unwrap();
    let renamed = c.describe_custom_key_stores().send().await.unwrap();
    assert_eq!(renamed.custom_key_stores().len(), 1);
    let store = &renamed.custom_key_stores()[0];
    assert_eq!(store.custom_key_store_name(), Some("store-renamed"));
    assert_eq!(store.xks_proxy_configuration().unwrap().uri_path(), Some("/v2/kms/xks/v1"));

    c.delete_custom_key_store().custom_key_store_id(&id).send().await.unwrap();
    let gone = c.describe_custom_key_stores().custom_key_store_id(&id).send().await.unwrap_err();
    assert_eq!(code(&gone), "CustomKeyStoreNotFoundException");
    let gone = c.connect_custom_key_store().custom_key_store_id(&id).send().await.unwrap_err();
    assert_eq!(code(&gone), "CustomKeyStoreNotFoundException");
}

async fn advance_days(mws: &Mws, days: i64) {
    let body = format!(r#"{{"advanceSeconds": {}}}"#, days * 86400);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn deletion_and_rotation_follow_the_emulated_clock() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let doomed = new_key(&c).await;
    let rotating = new_key(&c).await;
    c.enable_key_rotation().key_id(&rotating).rotation_period_in_days(90).send().await.unwrap();
    let blob = c.encrypt().key_id(&rotating).plaintext(Blob::new("old")).send().await.unwrap();

    // Rotation reads as off while a key is pending deletion.
    c.enable_key_rotation().key_id(&doomed).send().await.unwrap();
    c.schedule_key_deletion().key_id(&doomed).pending_window_in_days(7).send().await.unwrap();
    let status = c.get_key_rotation_status().key_id(&doomed).send().await.unwrap();
    assert!(!status.key_rotation_enabled());

    advance_days(&mws, 6).await;
    let md = c.describe_key().key_id(&doomed).send().await.unwrap();
    assert_eq!(md.key_metadata().unwrap().key_state(), Some(&KeyState::PendingDeletion));
    advance_days(&mws, 2).await;
    let gone = c.describe_key().key_id(&doomed).send().await.unwrap_err();
    assert_eq!(code(&gone), "NotFoundException");

    // 8 days in: not yet rotated. 200 days in: two rotations, each dated
    // when it was due.
    assert!(c.list_key_rotations().key_id(&rotating).send().await.unwrap().rotations().is_empty());
    advance_days(&mws, 192).await;
    let rotations = c.list_key_rotations().key_id(&rotating).send().await.unwrap();
    assert_eq!(rotations.rotations().len(), 2);
    let dates: Vec<_> = rotations.rotations().iter().map(|r| r.rotation_date().unwrap().secs()).collect();
    assert_eq!(dates[1] - dates[0], 90 * 86400);
    let decrypted = c.decrypt().ciphertext_blob(blob.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(decrypted.plaintext().unwrap().as_ref(), b"old");
}

#[tokio::test]
async fn describe_key_creates_predefined_aws_managed_keys() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let md = c.describe_key().key_id("alias/aws/ebs").send().await.unwrap();
    let md = md.key_metadata().unwrap();
    assert_eq!(md.key_manager(), Some(&aws_sdk_kms::types::KeyManagerType::Aws));
    let again = c.describe_key().key_id("arn:aws:kms:us-east-1:123456789012:alias/aws/ebs").send().await.unwrap();
    assert_eq!(again.key_metadata().unwrap().key_id(), md.key_id());
    let aliases = c.list_aliases().key_id(md.key_id()).send().await.unwrap();
    assert_eq!(aliases.aliases()[0].alias_name(), Some("alias/aws/ebs"));

    let unknown = c.describe_key().key_id("alias/aws/not-a-service").send().await.unwrap_err();
    assert_eq!(code(&unknown), "NotFoundException");
}

#[tokio::test]
async fn malformed_key_ids_and_sensitive_values() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let bad = c.describe_key().key_id("garbage").send().await.unwrap_err();
    assert_eq!(code(&bad), "NotFoundException");
    assert_eq!(bad.message(), Some("Invalid keyId 'garbage'"));
    let missing = c.describe_key().key_id("1234abcd-12ab-34cd-56ef-1234567890ab").send().await.unwrap_err();
    assert_eq!(
        missing.message(),
        Some("Key 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab' does not exist")
    );

    // Plaintext is @sensitive, so AWS leaves it out of the message.
    let key = new_key(&c).await;
    let long = c.encrypt().key_id(&key).plaintext(Blob::new(vec![b'a'; 4097])).send().await.unwrap_err();
    assert_eq!(
        long.message(),
        Some("1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length less than or equal to 4096")
    );
}

#[tokio::test]
async fn grants_hand_on_only_what_they_hold() {
    let mws = Mws::start().await;
    let c = kms(&mws).await;
    let key = new_key(&c).await;
    let (_, cfg) = user_with_policy(&mws, "lead", None).await;
    let lead = Client::new(&cfg);
    user_with_policy(&mws, "worker", None).await;
    let worker = "arn:aws:iam::123456789012:user/worker";
    c.create_grant()
        .key_id(&key)
        .grantee_principal("arn:aws:iam::123456789012:user/lead")
        .operations(GrantOperation::Encrypt)
        .operations(GrantOperation::CreateGrant)
        .operations(GrantOperation::DescribeKey)
        .constraints(GrantConstraints::builder().encryption_context_subset("team", "a").build())
        .send()
        .await
        .unwrap();

    // Constraints don't apply to DescribeKey.
    lead.describe_key().key_id(&key).send().await.unwrap();

    // A subset of the operations under constraints at least as strict.
    lead.create_grant()
        .key_id(&key)
        .grantee_principal(worker)
        .operations(GrantOperation::Encrypt)
        .constraints(
            GrantConstraints::builder()
                .encryption_context_equals("team", "a")
                .encryption_context_equals("env", "prod")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let more_ops = lead
        .create_grant()
        .key_id(&key)
        .grantee_principal(worker)
        .operations(GrantOperation::Decrypt)
        .constraints(GrantConstraints::builder().encryption_context_subset("team", "a").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&more_ops), "AccessDeniedException");
    let looser = lead
        .create_grant()
        .key_id(&key)
        .grantee_principal(worker)
        .operations(GrantOperation::Encrypt)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&looser), "AccessDeniedException");
}
