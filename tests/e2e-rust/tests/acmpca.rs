//! AWS Private CA through the official Rust SDK, with the issued
//! certificates checked cryptographically.

use aws_sdk_acmpca::primitives::Blob;
use aws_sdk_acmpca::types::{
    Asn1Subject, CertificateAuthorityConfiguration, CertificateAuthorityStatus, CertificateAuthorityType, KeyAlgorithm,
    RevocationReason, SigningAlgorithm, Tag, Validity, ValidityPeriodType,
};
use aws_sdk_acmpca::Client;
use mws_e2e::{user_with_policy, Mws};
use x509_parser::prelude::*;

const ROOT_TEMPLATE: &str = "arn:aws:acm-pca:::template/RootCACertificate/V1";
const SUB_TEMPLATE: &str = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1";

fn der(pem: &str) -> Vec<u8> {
    parse_x509_pem(pem.as_bytes()).unwrap().1.contents
}

fn assert_signed_by(child_pem: &str, issuer_pem: &str) {
    let child_der = der(child_pem);
    let issuer_der = der(issuer_pem);
    let (_, child) = X509Certificate::from_der(&child_der).unwrap();
    let (_, issuer) = X509Certificate::from_der(&issuer_der).unwrap();
    child.verify_signature(Some(issuer.public_key())).expect("signature verifies");
    assert_eq!(child.issuer().as_raw(), issuer.subject().as_raw(), "issuer name matches byte for byte");
}

async fn create_ca(
    pca: &Client,
    ty: CertificateAuthorityType,
    cn: &str,
    key: KeyAlgorithm,
    sig: SigningAlgorithm,
) -> String {
    pca.create_certificate_authority()
        .certificate_authority_type(ty)
        .certificate_authority_configuration(
            CertificateAuthorityConfiguration::builder()
                .key_algorithm(key)
                .signing_algorithm(sig)
                .subject(Asn1Subject::builder().common_name(cn).organization("MWS").country("US").build())
                .build()
                .unwrap(),
        )
        .tags(Tag::builder().key("env").value("test").build().unwrap())
        .send()
        .await
        .unwrap()
        .certificate_authority_arn()
        .unwrap()
        .to_string()
}

async fn issue(pca: &Client, ca: &str, csr: &str, template: Option<&str>, sig: SigningAlgorithm, days: i64) -> String {
    let mut req = pca
        .issue_certificate()
        .certificate_authority_arn(ca)
        .csr(Blob::new(csr.as_bytes()))
        .signing_algorithm(sig)
        .validity(Validity::builder().value(days).r#type(ValidityPeriodType::Days).build().unwrap());
    if let Some(t) = template {
        req = req.template_arn(t);
    }
    req.send().await.unwrap().certificate_arn().unwrap().to_string()
}

/// Create a root CA, self-issue and import its certificate.
async fn active_root(pca: &Client) -> (String, String) {
    let ca = create_ca(
        pca,
        CertificateAuthorityType::Root,
        "MWS Root",
        KeyAlgorithm::Rsa2048,
        SigningAlgorithm::Sha256Withrsa,
    )
    .await;
    let csr = pca.get_certificate_authority_csr().certificate_authority_arn(&ca).send().await.unwrap();
    let cert_arn =
        issue(pca, &ca, csr.csr().unwrap(), Some(ROOT_TEMPLATE), SigningAlgorithm::Sha256Withrsa, 3650).await;
    let cert = pca.get_certificate().certificate_authority_arn(&ca).certificate_arn(&cert_arn).send().await.unwrap();
    let pem = cert.certificate().unwrap().to_string();
    pca.import_certificate_authority_certificate()
        .certificate_authority_arn(&ca)
        .certificate(Blob::new(pem.as_bytes()))
        .send()
        .await
        .unwrap();
    (ca, pem)
}

fn leaf_csr(cn: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![format!("{cn}"), "alt.example.test".into()]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.serialize_request(&key).unwrap().pem().unwrap()
}

#[tokio::test]
async fn root_ca_lifecycle_and_end_entity_issuance() {
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);

    let ca = create_ca(
        &pca,
        CertificateAuthorityType::Root,
        "MWS Root",
        KeyAlgorithm::Rsa2048,
        SigningAlgorithm::Sha256Withrsa,
    )
    .await;
    assert!(ca.starts_with("arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/"));
    let desc = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    assert_eq!(desc.certificate_authority().unwrap().status(), Some(&CertificateAuthorityStatus::PendingCertificate));

    // Not active yet: end-entity issuance is refused.
    let csr = leaf_csr("www.example.test");
    let err = pca
        .issue_certificate()
        .certificate_authority_arn(&ca)
        .csr(Blob::new(csr.as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withrsa)
        .validity(Validity::builder().value(30).r#type(ValidityPeriodType::Days).build().unwrap())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(err.is_invalid_state_exception(), "{err:?}");

    let pca_csr = pca.get_certificate_authority_csr().certificate_authority_arn(&ca).send().await.unwrap();
    let root_arn =
        issue(&pca, &ca, pca_csr.csr().unwrap(), Some(ROOT_TEMPLATE), SigningAlgorithm::Sha256Withrsa, 3650).await;
    let root = pca.get_certificate().certificate_authority_arn(&ca).certificate_arn(&root_arn).send().await.unwrap();
    let root_pem = root.certificate().unwrap().to_string();
    assert_signed_by(&root_pem, &root_pem);
    pca.import_certificate_authority_certificate()
        .certificate_authority_arn(&ca)
        .certificate(Blob::new(root_pem.as_bytes()))
        .send()
        .await
        .unwrap();
    let desc = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    let desc = desc.certificate_authority().unwrap();
    assert_eq!(desc.status(), Some(&CertificateAuthorityStatus::Active));
    assert!(desc.not_after().is_some());

    // Issue an end-entity certificate and check it properly.
    let leaf_arn = issue(&pca, &ca, &csr, None, SigningAlgorithm::Sha256Withrsa, 30).await;
    assert!(leaf_arn.starts_with(&format!("{ca}/certificate/")));
    let leaf = pca.get_certificate().certificate_authority_arn(&ca).certificate_arn(&leaf_arn).send().await.unwrap();
    let leaf_pem = leaf.certificate().unwrap();
    assert_eq!(leaf.certificate_chain().unwrap().trim(), root_pem.trim());
    assert_signed_by(leaf_pem, &root_pem);
    let leaf_der = der(leaf_pem);
    let (_, cert) = X509Certificate::from_der(&leaf_der).unwrap();
    assert_eq!(cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), "www.example.test");
    let sans = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(sans.value.general_names.len(), 2);
    assert!(!cert.basic_constraints().unwrap().unwrap().value.ca);
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && eku.client_auth);
    let days = (cert.validity().not_after.timestamp() - chrono_now()) / 86400;
    assert!((29..=30).contains(&days), "{days}");

    // Revoke by serial, twice.
    let serial = cert.raw_serial().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    pca.revoke_certificate()
        .certificate_authority_arn(&ca)
        .certificate_serial(&serial)
        .revocation_reason(RevocationReason::KeyCompromise)
        .send()
        .await
        .unwrap();
    let err = pca
        .revoke_certificate()
        .certificate_authority_arn(&ca)
        .certificate_serial(&serial)
        .revocation_reason(RevocationReason::KeyCompromise)
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_request_already_processed_exception());

    // Active CAs must be disabled before deletion; deletion is restorable.
    let err = pca.delete_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert!(err.into_service_error().is_invalid_state_exception());
    pca.update_certificate_authority()
        .certificate_authority_arn(&ca)
        .status(CertificateAuthorityStatus::Disabled)
        .send()
        .await
        .unwrap();
    pca.delete_certificate_authority()
        .certificate_authority_arn(&ca)
        .permanent_deletion_time_in_days(7)
        .send()
        .await
        .unwrap();
    let desc = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    assert_eq!(desc.certificate_authority().unwrap().status(), Some(&CertificateAuthorityStatus::Deleted));
    assert!(desc.certificate_authority().unwrap().restorable_until().is_some());
    pca.restore_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    let desc = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    assert_eq!(desc.certificate_authority().unwrap().status(), Some(&CertificateAuthorityStatus::Disabled));
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::test]
async fn subordinate_ca_chain() {
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);
    let (root, root_pem) = active_root(&pca).await;

    let sub = create_ca(
        &pca,
        CertificateAuthorityType::Subordinate,
        "MWS Issuing",
        KeyAlgorithm::EcPrime256v1,
        SigningAlgorithm::Sha256Withecdsa,
    )
    .await;
    let sub_csr = pca.get_certificate_authority_csr().certificate_authority_arn(&sub).send().await.unwrap();
    let sub_cert_arn =
        issue(&pca, &root, sub_csr.csr().unwrap(), Some(SUB_TEMPLATE), SigningAlgorithm::Sha256Withrsa, 365).await;
    let sub_cert =
        pca.get_certificate().certificate_authority_arn(&root).certificate_arn(&sub_cert_arn).send().await.unwrap();
    let sub_pem = sub_cert.certificate().unwrap().to_string();
    assert_signed_by(&sub_pem, &root_pem);

    // Importing without the chain is refused; with it, the CA activates.
    let err = pca
        .import_certificate_authority_certificate()
        .certificate_authority_arn(&sub)
        .certificate(Blob::new(sub_pem.as_bytes()))
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_invalid_request_exception());
    // The root's certificate does not match the subordinate's key.
    let err = pca
        .import_certificate_authority_certificate()
        .certificate_authority_arn(&sub)
        .certificate(Blob::new(root_pem.as_bytes()))
        .certificate_chain(Blob::new(root_pem.as_bytes()))
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_certificate_mismatch_exception());
    pca.import_certificate_authority_certificate()
        .certificate_authority_arn(&sub)
        .certificate(Blob::new(sub_pem.as_bytes()))
        .certificate_chain(Blob::new(root_pem.as_bytes()))
        .send()
        .await
        .unwrap();

    let leaf_arn = issue(&pca, &sub, &leaf_csr("svc.example.test"), None, SigningAlgorithm::Sha256Withecdsa, 7).await;
    let leaf = pca.get_certificate().certificate_authority_arn(&sub).certificate_arn(&leaf_arn).send().await.unwrap();
    assert_signed_by(leaf.certificate().unwrap(), &sub_pem);
    let chain = leaf.certificate_chain().unwrap();
    assert!(chain.contains(sub_pem.trim()) && chain.contains(root_pem.trim()));

    // Validity beyond the issuing CA's own is refused.
    let err = pca
        .issue_certificate()
        .certificate_authority_arn(&sub)
        .csr(Blob::new(leaf_csr("x.example.test").as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
        .validity(Validity::builder().value(5).r#type(ValidityPeriodType::Years).build().unwrap())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.meta().code(), Some("ValidationException"));

    let ca_cert = pca.get_certificate_authority_certificate().certificate_authority_arn(&sub).send().await.unwrap();
    assert_eq!(ca_cert.certificate_chain().unwrap().trim(), root_pem.trim());
    let listed = pca.list_certificate_authorities().send().await.unwrap();
    assert_eq!(listed.certificate_authorities().len(), 2);
}

#[tokio::test]
async fn validation_tags_and_errors() {
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);
    let ca = create_ca(
        &pca,
        CertificateAuthorityType::Root,
        "Tags",
        KeyAlgorithm::EcPrime256v1,
        SigningAlgorithm::Sha256Withecdsa,
    )
    .await;

    pca.tag_certificate_authority()
        .certificate_authority_arn(&ca)
        .tags(Tag::builder().key("team").value("pki").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = pca.list_tags().certificate_authority_arn(&ca).send().await.unwrap();
    assert_eq!(tags.tags().len(), 2);
    pca.untag_certificate_authority()
        .certificate_authority_arn(&ca)
        .tags(Tag::builder().key("env").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(pca.list_tags().certificate_authority_arn(&ca).send().await.unwrap().tags().len(), 1);

    let missing = format!("{}0", &ca[..ca.len() - 1]);
    let err = pca.describe_certificate_authority().certificate_authority_arn(&missing).send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_not_found_exception());
    let err = pca
        .describe_certificate_authority()
        .certificate_authority_arn("arn:aws:acm-pca:us-east-1:123456789012:nope/x")
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_invalid_arn_exception());

    let err = pca
        .issue_certificate()
        .certificate_authority_arn(&ca)
        .csr(Blob::new(b"not a csr".to_vec()))
        .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
        .validity(Validity::builder().value(1).r#type(ValidityPeriodType::Days).build().unwrap())
        .template_arn(ROOT_TEMPLATE)
        .send()
        .await
        .unwrap_err();
    assert!(err.into_service_error().is_malformed_csr_exception());

    // Model constraints: ARN length.
    let err = pca.describe_certificate_authority().certificate_authority_arn("arn:x").send().await.unwrap_err();
    let err = err.into_service_error();
    assert_eq!(err.meta().code(), Some("ValidationException"));
    assert!(
        err.meta()
            .message()
            .unwrap()
            .starts_with("1 validation error detected: Value 'arn:x' at 'certificateAuthorityArn'"),
        "{:?}",
        err.meta().message()
    );

    // A never-activated CA is deleted outright.
    pca.delete_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    let err = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert!(err.into_service_error().is_resource_not_found_exception());
}

#[tokio::test]
async fn iam_and_resource_policies_govern_issuance() {
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);
    let (ca, _) = active_root(&pca).await;

    // The AWS managed AWSPrivateCAUser policy: end-entity certificates only.
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let (_, cfg) = user_with_policy(&mws, "issuer", None).await;
    iam.attach_user_policy()
        .user_name("issuer")
        .policy_arn("arn:aws:iam::aws:policy/AWSPrivateCAUser")
        .send()
        .await
        .unwrap();
    let user = Client::new(&cfg);
    issue(&user, &ca, &leaf_csr("ok.example.test"), None, SigningAlgorithm::Sha256Withrsa, 1).await;
    let err = user
        .issue_certificate()
        .certificate_authority_arn(&ca)
        .csr(Blob::new(leaf_csr("sub.example.test").as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withrsa)
        .template_arn(SUB_TEMPLATE)
        .validity(Validity::builder().value(1).r#type(ValidityPeriodType::Days).build().unwrap())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(err.meta().code(), Some("AccessDeniedException"));
    assert!(err.meta().message().unwrap().contains("acm-pca:IssueCertificate"), "{:?}", err.meta().message());
    let err = user.delete_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert!(err.into_service_error().meta().message().unwrap().contains("not authorized"));

    // A user with no identity policy can be let in by the CA's resource policy.
    let (_, cfg) = user_with_policy(&mws, "outsider", None).await;
    let outsider = Client::new(&cfg);
    assert!(outsider.get_certificate_authority_certificate().certificate_authority_arn(&ca).send().await.is_err());
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:user/outsider"},
            "Action": "acm-pca:GetCertificateAuthorityCertificate",
            "Resource": ca
        }]
    });
    pca.put_policy().resource_arn(&ca).policy(policy.to_string()).send().await.unwrap();
    outsider.get_certificate_authority_certificate().certificate_authority_arn(&ca).send().await.unwrap();
    assert!(pca.get_policy().resource_arn(&ca).send().await.unwrap().policy().unwrap().contains("outsider"));
    let err = pca.put_policy().resource_arn(&ca).policy("{nope").send().await.unwrap_err();
    assert!(err.into_service_error().is_invalid_policy_exception());
}
