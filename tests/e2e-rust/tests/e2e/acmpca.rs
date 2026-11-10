//! AWS Private CA through the official Rust SDK, with the issued
//! certificates checked cryptographically.

use aws_sdk_acmpca::client::Waiters as _;
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

pub(crate) fn assert_signed_by(child_pem: &str, issuer_pem: &str) {
    let child_der = der(child_pem);
    let issuer_der = der(issuer_pem);
    let (_, child) = X509Certificate::from_der(&child_der).unwrap();
    let (_, issuer) = X509Certificate::from_der(&issuer_der).unwrap();
    child.verify_signature(Some(issuer.public_key())).expect("signature verifies");
    assert_eq!(child.issuer().as_raw(), issuer.subject().as_raw(), "issuer name matches byte for byte");
}

/// A new CA's CSR, once Private CA has made it: the CA is `CREATING` and
/// `GetCertificateAuthorityCsr` answers `RequestInProgressException` until
/// then, so real code waits with the SDK waiter.
pub(crate) async fn wait_csr(
    pca: &Client,
    ca: &str,
) -> aws_sdk_acmpca::operation::get_certificate_authority_csr::GetCertificateAuthorityCsrOutput {
    pca.wait_until_certificate_authority_csr_created()
        .certificate_authority_arn(ca)
        .wait(std::time::Duration::from_secs(60))
        .await
        .expect("CSR created")
        .into_result()
        .unwrap()
}

/// An issued certificate, once issuance (which is asynchronous) is done.
pub(crate) async fn wait_cert(
    pca: &Client,
    ca: &str,
    cert_arn: &str,
) -> aws_sdk_acmpca::operation::get_certificate::GetCertificateOutput {
    pca.wait_until_certificate_issued()
        .certificate_authority_arn(ca)
        .certificate_arn(cert_arn)
        .wait(std::time::Duration::from_secs(60))
        .await
        .expect("certificate issued")
        .into_result()
        .unwrap()
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
pub(crate) async fn active_root(pca: &Client) -> (String, String) {
    let ca = create_ca(
        pca,
        CertificateAuthorityType::Root,
        "MWS Root",
        KeyAlgorithm::Rsa2048,
        SigningAlgorithm::Sha256Withrsa,
    )
    .await;
    let csr = wait_csr(&pca, &ca).await;
    let cert_arn =
        issue(pca, &ca, csr.csr().unwrap(), Some(ROOT_TEMPLATE), SigningAlgorithm::Sha256Withrsa, 3650).await;
    let cert = wait_cert(&pca, &ca, &cert_arn).await;
    let pem = cert.certificate().unwrap().to_string();
    pca.import_certificate_authority_certificate()
        .certificate_authority_arn(&ca)
        .certificate(Blob::new(pem.as_bytes()))
        .send()
        .await
        .unwrap();
    (ca, pem)
}

pub(crate) fn leaf_csr(cn: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string(), "alt.example.test".into()]).unwrap();
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
    // The CA is CREATING until Private CA has made its key and CSR.
    let desc = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    assert_eq!(desc.certificate_authority().unwrap().status(), Some(&CertificateAuthorityStatus::Creating));
    let err = pca.get_certificate_authority_csr().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert!(err.into_service_error().is_request_in_progress_exception());
    let pca_csr = wait_csr(&pca, &ca).await;
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

    let root_arn =
        issue(&pca, &ca, pca_csr.csr().unwrap(), Some(ROOT_TEMPLATE), SigningAlgorithm::Sha256Withrsa, 3650).await;
    let root = wait_cert(&pca, &ca, &root_arn).await;
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
    // Issuance is asynchronous: GetCertificate answers
    // RequestInProgressException until it is done (the waiter retries).
    let err = pca
        .get_certificate()
        .certificate_authority_arn(&ca)
        .certificate_arn(&leaf_arn)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(err.is_request_in_progress_exception(), "{err:?}");
    let leaf = wait_cert(&pca, &ca, &leaf_arn).await;
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
    let sub_csr = wait_csr(&pca, &sub).await;
    let sub_cert_arn =
        issue(&pca, &root, sub_csr.csr().unwrap(), Some(SUB_TEMPLATE), SigningAlgorithm::Sha256Withrsa, 365).await;
    let sub_cert = wait_cert(&pca, &root, &sub_cert_arn).await;
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
    let leaf = wait_cert(&pca, &sub, &leaf_arn).await;
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

    // Change the last hex digit so the ARN never matches the real CA.
    let last = if ca.ends_with('0') { '1' } else { '0' };
    let missing = format!("{}{last}", &ca[..ca.len() - 1]);
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

    // A never-activated CA is deleted, restorably, like any other.
    pca.delete_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    let desc = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    assert_eq!(desc.certificate_authority().unwrap().status(), Some(&CertificateAuthorityStatus::Deleted));
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

/// A plain HTTP/1.1 request to MWS, unsigned, as a CRL or OCSP client sends it.
async fn http(endpoint: &str, method: &str, path: &str, content_type: Option<&str>, body: &[u8]) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let host = endpoint.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(host).await.unwrap();
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        out.extend([0x82, (content.len() >> 8) as u8, content.len() as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// An OCSP request (RFC 6960) for `serial` issued by `issuer_pem`, SHA-1 CertID, with a nonce.
fn ocsp_request(issuer_pem: &str, serial: &[u8], nonce: &[u8]) -> Vec<u8> {
    use aws_lc_rs::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
    let issuer_der = der(issuer_pem);
    let (_, issuer) = X509Certificate::from_der(&issuer_der).unwrap();
    let name_hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, issuer.subject().as_raw());
    let key_hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &issuer.public_key().subject_public_key.data);
    let sha1 = tlv(0x30, &[&[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a][..], &[0x05, 0x00]].concat());
    let mut serial_content = serial.to_vec();
    if serial_content[0] & 0x80 != 0 {
        serial_content.insert(0, 0);
    }
    let cert_id = tlv(
        0x30,
        &[sha1, tlv(0x04, name_hash.as_ref()), tlv(0x04, key_hash.as_ref()), tlv(0x02, &serial_content)].concat(),
    );
    let request = tlv(0x30, &cert_id);
    let nonce_ext = tlv(
        0x30,
        &[&[0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02][..], &tlv(0x04, &tlv(0x04, nonce))]
            .concat(),
    );
    let tbs = tlv(0x30, &[tlv(0x30, &request), tlv(0xa2, &tlv(0x30, &nonce_ext))].concat());
    tlv(0x30, &tbs)
}

/// Walk an OCSP response far enough to return (status tag of the first
/// SingleResponse, whether the nonce is echoed), checking the signature
/// with the issuer's key.
fn read_ocsp_response(resp: &[u8], issuer_pem: &str, nonce: &[u8]) -> (u8, bool) {
    use x509_parser::der_parser::der::parse_der;
    let (_, top) = parse_der(resp).unwrap();
    let top = top.as_sequence().unwrap();
    assert_eq!(top[0].as_u32().unwrap(), 0, "successful");
    let bytes = top[1].as_slice().unwrap(); // [0] EXPLICIT content
    let (_, rb) = parse_der(bytes).unwrap();
    let rb = rb.as_sequence().unwrap();
    let basic_der = rb[1].as_slice().unwrap();
    let (_, basic) = parse_der(basic_der).unwrap();
    let basic = basic.as_sequence().unwrap();
    let tbs_raw = {
        // Re-slice the raw tbsResponseData from the BasicOCSPResponse encoding.
        let (rest, _) = x509_parser::der_parser::der::parse_der(basic_der).unwrap();
        assert!(rest.is_empty());
        let inner = &basic_der[if basic_der[1] & 0x80 != 0 { 2 + (basic_der[1] & 0x7f) as usize } else { 2 }..];
        let (after, _) = parse_der(inner).unwrap();
        &inner[..inner.len() - after.len()]
    };
    let sig = basic[2].as_bitstring().unwrap();
    let issuer_der = der(issuer_pem);
    let (_, issuer) = X509Certificate::from_der(&issuer_der).unwrap();
    let key = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
        issuer.public_key().subject_public_key.data.to_vec(),
    );
    key.verify(tbs_raw, sig.data).expect("OCSP response signed by the CA");
    let tbs = basic[0].as_sequence().unwrap();
    let responses = tbs[2].as_sequence().unwrap();
    let single = responses[0].as_sequence().unwrap();
    let status_tag = single[1].header.raw_tag().unwrap()[0];
    let has_nonce = tbs.len() > 3 && basic_der.windows(nonce.len()).any(|w| w == nonce);
    (status_tag, has_nonce)
}

/// A bucket ACM PCA may write to; `public` CRLs need ACLs and public
/// access allowed.
async fn pca_bucket(s3: &aws_sdk_s3::Client, name: &str, public: bool) {
    use aws_sdk_s3::types::ObjectOwnership;
    if s3.head_bucket().bucket(name).send().await.is_err() {
        let mut create = s3.create_bucket().bucket(name);
        if public {
            create = create.object_ownership(ObjectOwnership::BucketOwnerPreferred);
        }
        create.send().await.unwrap();
        if public {
            s3.delete_public_access_block().bucket(name).send().await.unwrap();
        }
    }
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "acm-pca.amazonaws.com"},
            "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketAcl", "s3:GetBucketLocation"],
            "Resource": [format!("arn:aws:s3:::{name}/*"), format!("arn:aws:s3:::{name}")],
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}
        }]
    });
    s3.put_bucket_policy().bucket(name).policy(policy.to_string()).send().await.unwrap();
}

#[tokio::test]
async fn crl_ocsp_and_audit_reports() {
    use aws_sdk_acmpca::types::{
        AuditReportResponseFormat, AuditReportStatus, CrlConfiguration, OcspConfiguration, RevocationConfiguration,
    };
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);
    let (ca, ca_pem) = active_root(&pca).await;
    let ca_id = ca.rsplit('/').next().unwrap().to_string();

    // CRLs need a bucket.
    let err = pca
        .update_certificate_authority()
        .certificate_authority_arn(&ca)
        .revocation_configuration(
            RevocationConfiguration::builder()
                .crl_configuration(CrlConfiguration::builder().enabled(true).build().unwrap())
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("InvalidArgsException"));

    let revocation = RevocationConfiguration::builder()
        .crl_configuration(
            CrlConfiguration::builder()
                .enabled(true)
                .expiration_in_days(5)
                .s3_bucket_name("crl-bucket")
                .build()
                .unwrap(),
        )
        .ocsp_configuration(OcspConfiguration::builder().enabled(true).build().unwrap())
        .build();
    // ACM PCA writes CRLs into S3 as acm-pca.amazonaws.com: the bucket must
    // exist and its policy must allow that.
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    let update = || {
        pca.update_certificate_authority().certificate_authority_arn(&ca).revocation_configuration(revocation.clone())
    };
    let err = update().send().await.unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("InvalidArgsException"));
    pca_bucket(&s3, "crl-bucket", true).await;
    s3.delete_bucket_policy().bucket("crl-bucket").send().await.unwrap();
    let err = update().send().await.unwrap_err().into_service_error();
    assert_eq!(err.meta().code(), Some("InvalidArgsException"));
    assert!(err.meta().message().unwrap().contains("acm-pca.amazonaws.com"), "{:?}", err.meta().message());
    pca_bucket(&s3, "crl-bucket", true).await;
    update().send().await.unwrap();

    // Issued certificates point at the CRL and the OCSP responder.
    let leaf_arn = issue(&pca, &ca, &leaf_csr("leaf.example.test"), None, SigningAlgorithm::Sha256Withrsa, 30).await;
    let leaf = wait_cert(&pca, &ca, &leaf_arn).await;
    let leaf_pem = leaf.certificate().unwrap().to_string();
    let leaf_der = der(&leaf_pem);
    let (_, leaf_cert) = X509Certificate::from_der(&leaf_der).unwrap();
    let mut crl_uri = None;
    let mut ocsp_uri = None;
    for ext in leaf_cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::CRLDistributionPoints(points) => {
                if let Some(DistributionPointName::FullName(names)) = &points.points[0].distribution_point {
                    if let GeneralName::URI(u) = &names[0] {
                        crl_uri = Some(u.to_string());
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                if let GeneralName::URI(u) = &aia.accessdescs[0].access_location {
                    ocsp_uri = Some(u.to_string());
                }
            }
            _ => {}
        }
    }
    assert_eq!(crl_uri.unwrap(), format!("http://crl-bucket.s3.us-east-1.amazonaws.com/crl/{ca_id}.crl"));
    assert_eq!(ocsp_uri.unwrap(), "http://ocsp.acm-pca.us-east-1.amazonaws.com");
    let leaf_serial = leaf_cert.raw_serial().to_vec();

    // OCSP says good, echoing the nonce.
    let nonce = b"mws-nonce-0123456789";
    let (status, body) =
        http(&mws.endpoint, "POST", "/", Some("application/ocsp-request"), &ocsp_request(&ca_pem, &leaf_serial, nonce))
            .await;
    assert_eq!(status, 200);
    assert_eq!(read_ocsp_response(&body, &ca_pem, nonce), (0x80, true), "good");

    // Revoke: the CRL lists it, signed by the CA, and OCSP says revoked.
    let serial_hex = leaf_serial.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    pca.revoke_certificate()
        .certificate_authority_arn(&ca)
        .certificate_serial(&serial_hex)
        .revocation_reason(RevocationReason::KeyCompromise)
        .send()
        .await
        .unwrap();
    let (status, crl_der) = http(&mws.endpoint, "GET", &format!("/crl-bucket/crl/{ca_id}.crl"), None, b"").await;
    assert_eq!(status, 200);
    let (_, crl) = parse_x509_crl(&crl_der).unwrap();
    let ca_der = der(&ca_pem);
    let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();
    crl.verify_signature(ca_cert.public_key()).expect("CRL signed by the CA");
    assert_eq!(crl.issuer().as_raw(), ca_cert.subject().as_raw());
    let revoked: Vec<_> = crl.iter_revoked_certificates().map(|r| r.raw_serial().to_vec()).collect();
    assert_eq!(revoked, vec![leaf_serial.clone()]);
    let next = crl.next_update().unwrap().timestamp() - crl.last_update().timestamp();
    assert_eq!(next, 5 * 86400);

    let (status, body) =
        http(&mws.endpoint, "POST", "/", Some("application/ocsp-request"), &ocsp_request(&ca_pem, &leaf_serial, nonce))
            .await;
    assert_eq!(status, 200);
    assert_eq!(read_ocsp_response(&body, &ca_pem, nonce).0, 0xa1, "revoked");
    // An unknown serial is unknown.
    let (_, body) =
        http(&mws.endpoint, "POST", "/", Some("application/ocsp-request"), &ocsp_request(&ca_pem, &[0x42; 16], nonce))
            .await;
    assert_eq!(read_ocsp_response(&body, &ca_pem, nonce).0, 0x82, "unknown");

    // Audit report, written to S3 with the same kind of bucket policy.
    let err = pca
        .create_certificate_authority_audit_report()
        .certificate_authority_arn(&ca)
        .s3_bucket_name("audit-bucket")
        .audit_report_response_format(AuditReportResponseFormat::Json)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("InvalidArgsException"));
    pca_bucket(&s3, "audit-bucket", false).await;
    let report = pca
        .create_certificate_authority_audit_report()
        .certificate_authority_arn(&ca)
        .s3_bucket_name("audit-bucket")
        .audit_report_response_format(AuditReportResponseFormat::Json)
        .send()
        .await
        .unwrap();
    let id = report.audit_report_id().unwrap();
    let key = report.s3_key().unwrap();
    assert_eq!(key, format!("audit-report/{ca_id}/{id}.json"));
    let described = pca
        .describe_certificate_authority_audit_report()
        .certificate_authority_arn(&ca)
        .audit_report_id(id)
        .send()
        .await
        .unwrap();
    assert_eq!(described.audit_report_status(), Some(&AuditReportStatus::Success));
    assert_eq!(described.s3_bucket_name(), Some("audit-bucket"));
    let object = s3.get_object().bucket("audit-bucket").key(key).send().await.unwrap();
    assert_eq!(object.content_type(), Some("application/json"));
    let body = object.body.collect().await.unwrap().into_bytes();
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    let leaf_row = rows.iter().find(|r| r["certificateArn"] == leaf_arn.as_str()).unwrap();
    assert_eq!(leaf_row["revocationReason"], "KEY_COMPROMISE");
    assert_eq!(leaf_row["serial"], serial_hex);
    assert_eq!(leaf_row["subject"], "CN=leaf.example.test");

    let err = pca
        .describe_certificate_authority_audit_report()
        .certificate_authority_arn(&ca)
        .audit_report_id("00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("ResourceNotFoundException"));
}

#[tokio::test]
async fn ca_tags_authorize_through_resource_tag() {
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);
    let ca = create_ca(
        &pca,
        CertificateAuthorityType::Root,
        "Tagged",
        KeyAlgorithm::Rsa2048,
        SigningAlgorithm::Sha256Withrsa,
    )
    .await;
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "acm-pca:DescribeCertificateAuthority",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:ResourceTag/env": "prod"}}
        }]
    });
    let (_, cfg) = user_with_policy(&mws, "abac", Some(&policy.to_string())).await;
    let user = Client::new(&cfg);
    let err = user.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert_eq!(err.into_service_error().meta().code(), Some("AccessDeniedException"));
    pca.tag_certificate_authority()
        .certificate_authority_arn(&ca)
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .unwrap();
    user.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
}

#[tokio::test]
async fn acm_permissions_on_a_ca() {
    use aws_sdk_acmpca::error::ProvideErrorMetadata;
    use aws_sdk_acmpca::types::ActionType;
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);
    let (ca, _) = active_root(&pca).await;
    let empty = pca.list_permissions().certificate_authority_arn(&ca).send().await.unwrap();
    assert!(empty.permissions().is_empty());

    let grant = || {
        pca.create_permission()
            .certificate_authority_arn(&ca)
            .principal("acm.amazonaws.com")
            .actions(ActionType::IssueCertificate)
            .actions(ActionType::GetCertificate)
            .actions(ActionType::ListPermissions)
            .send()
    };
    grant().await.unwrap();
    let dup = grant().await.unwrap_err();
    assert_eq!(dup.code(), Some("PermissionAlreadyExistsException"));

    let listed = pca.list_permissions().certificate_authority_arn(&ca).send().await.unwrap();
    let p = &listed.permissions()[0];
    assert_eq!(p.principal(), Some("acm.amazonaws.com"));
    assert_eq!(p.source_account(), Some("123456789012"));
    assert_eq!(p.certificate_authority_arn(), Some(ca.as_str()));
    assert_eq!(p.actions().len(), 3);
    assert!(p.created_at().is_some());

    pca.delete_permission().certificate_authority_arn(&ca).principal("acm.amazonaws.com").send().await.unwrap();
    assert!(pca.list_permissions().certificate_authority_arn(&ca).send().await.unwrap().permissions().is_empty());
    let gone = pca.delete_permission().certificate_authority_arn(&ca).principal("acm.amazonaws.com").send().await;
    assert_eq!(gone.unwrap_err().code(), Some("ResourceNotFoundException"));

    // Only the CA owner manages its permissions.
    let (_, cfg) = user_with_policy(&mws, "outsider", None).await;
    let denied = Client::new(&cfg).list_permissions().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert_eq!(denied.code(), Some("AccessDeniedException"));
}

#[tokio::test]
async fn tags_on_create_need_tag_permission() {
    let mws = Mws::start().await;
    let create = |pca: Client, tagged: bool| async move {
        let mut req = pca
            .create_certificate_authority()
            .certificate_authority_type(CertificateAuthorityType::Root)
            .certificate_authority_configuration(
                CertificateAuthorityConfiguration::builder()
                    .key_algorithm(KeyAlgorithm::EcPrime256v1)
                    .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
                    .subject(Asn1Subject::builder().common_name("Tagged").build())
                    .build()
                    .unwrap(),
            );
        if tagged {
            req = req.tags(Tag::builder().key("env").value("test").build().unwrap());
        }
        req.send().await
    };
    let narrow = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":"acm-pca:CreateCertificateAuthority","Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "no-tagging", Some(narrow)).await;
    let err = create(Client::new(&cfg), true).await.unwrap_err().into_service_error();
    assert_eq!(err.meta().code(), Some("AccessDeniedException"));
    assert!(err.meta().message().unwrap().contains("acm-pca:TagCertificateAuthority"), "{:?}", err.meta().message());
    create(Client::new(&cfg), false).await.unwrap();

    let with_tagging = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Action":["acm-pca:CreateCertificateAuthority","acm-pca:TagCertificateAuthority"],"Resource":"*"}]}"#;
    let (_, cfg) = user_with_policy(&mws, "tagging", Some(with_tagging)).await;
    let ca = create(Client::new(&cfg), true).await.unwrap().certificate_authority_arn().unwrap().to_string();
    let root = Client::new(&mws.root_sdk_config().await);
    assert_eq!(root.list_tags().certificate_authority_arn(&ca).send().await.unwrap().tags().len(), 1);
}
