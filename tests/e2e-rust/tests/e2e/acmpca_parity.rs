//! Private CA behaviour that real AWS has and the basic flows don't show:
//! passthrough templates, CSR extensions, time-driven lifecycle, and CAs
//! scoped to their account and region.

use aws_sdk_acmpca::error::ProvideErrorMetadata;
use aws_sdk_acmpca::primitives::Blob;
use aws_sdk_acmpca::types::{
    AccessDescription, AccessMethod, AccessMethodType, ApiPassthrough, Asn1Subject, CertificateAuthorityConfiguration,
    CertificateAuthorityStatus, CertificateAuthorityType, CertificateAuthorityUsageMode, CrlConfiguration,
    CsrExtensions, CustomAttribute, CustomExtension, ExtendedKeyUsage, ExtendedKeyUsageType, Extensions,
    GeneralName as PcaGeneralName, KeyAlgorithm, KeyUsage, PolicyInformation, PolicyQualifierId, PolicyQualifierInfo,
    Qualifier, ResourceOwner, RevocationConfiguration, SigningAlgorithm, Validity, ValidityPeriodType,
};
use aws_sdk_acmpca::Client;
use mws_e2e::{sts_config, user_with_policy, Mws};
use serde_json::json;
use x509_parser::prelude::*;

const ROOT_TEMPLATE: &str = "arn:aws:acm-pca:::template/RootCACertificate/V1";

fn der(pem: &str) -> Vec<u8> {
    parse_x509_pem(pem.as_bytes()).unwrap().1.contents
}

fn config(cn: &str) -> CertificateAuthorityConfiguration {
    CertificateAuthorityConfiguration::builder()
        .key_algorithm(KeyAlgorithm::EcPrime256v1)
        .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
        .subject(Asn1Subject::builder().common_name(cn).organization("MWS").build())
        .build()
        .unwrap()
}

fn days(n: i64) -> Validity {
    Validity::builder().value(n).r#type(ValidityPeriodType::Days).build().unwrap()
}

/// Create a root CA from `config`, self-issue a certificate valid `valid_days`, import it.
async fn root(pca: &Client, config: CertificateAuthorityConfiguration, valid_days: i64) -> (String, String) {
    root_with(pca, config, valid_days, None, None).await
}

async fn root_with(
    pca: &Client,
    config: CertificateAuthorityConfiguration,
    valid_days: i64,
    usage: Option<CertificateAuthorityUsageMode>,
    revocation: Option<RevocationConfiguration>,
) -> (String, String) {
    let ca = pca
        .create_certificate_authority()
        .certificate_authority_type(CertificateAuthorityType::Root)
        .certificate_authority_configuration(config)
        .set_usage_mode(usage)
        .set_revocation_configuration(revocation)
        .send()
        .await
        .unwrap()
        .certificate_authority_arn()
        .unwrap()
        .to_string();
    let csr = pca.get_certificate_authority_csr().certificate_authority_arn(&ca).send().await.unwrap();
    let cert_arn = pca
        .issue_certificate()
        .certificate_authority_arn(&ca)
        .csr(Blob::new(csr.csr().unwrap().as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
        .template_arn(ROOT_TEMPLATE)
        .validity(days(valid_days))
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    let cert = pca.get_certificate().certificate_authority_arn(&ca).certificate_arn(cert_arn).send().await.unwrap();
    let pem = cert.certificate().unwrap().to_string();
    pca.import_certificate_authority_certificate()
        .certificate_authority_arn(&ca)
        .certificate(Blob::new(pem.as_bytes()))
        .send()
        .await
        .unwrap();
    (ca, pem)
}

/// A CSR for `cn` with a SAN and a private extension (1.3.6.1.4.1.99999.1).
fn csr_with_extension(cn: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![0x05, 0x00]));
    params.serialize_request(&key).unwrap().pem().unwrap()
}

async fn issue_pem(
    pca: &Client,
    ca: &str,
    csr: &str,
    template: &str,
    api: Option<ApiPassthrough>,
) -> Result<String, Option<String>> {
    let arn = pca
        .issue_certificate()
        .certificate_authority_arn(ca)
        .csr(Blob::new(csr.as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
        .template_arn(format!("arn:aws:acm-pca:::template/{template}"))
        .set_api_passthrough(api)
        .validity(days(30))
        .send()
        .await
        .map_err(|e| e.code().map(str::to_string))?
        .certificate_arn()
        .unwrap()
        .to_string();
    let cert = pca.get_certificate().certificate_authority_arn(ca).certificate_arn(arn).send().await.unwrap();
    Ok(cert.certificate().unwrap().to_string())
}

fn has_extension(cert: &X509Certificate<'_>, oid: &str) -> bool {
    cert.extensions().iter().any(|e| e.oid.to_id_string() == oid)
}

#[tokio::test]
async fn passthrough_templates_and_csr_extensions() {
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);

    // CsrExtensions end up in the CA's own CSR.
    let mut cfg = config("Passthrough Root");
    cfg.csr_extensions = Some(
        CsrExtensions::builder()
            .key_usage(KeyUsage::builder().key_cert_sign(true).crl_sign(true).digital_signature(true).build())
            .subject_information_access(
                AccessDescription::builder()
                    .access_method(AccessMethod::builder().access_method_type(AccessMethodType::CaRepository).build())
                    .access_location(
                        PcaGeneralName::builder().uniform_resource_identifier("http://repo.example.test/").build(),
                    )
                    .build(),
            )
            .build(),
    );
    let (ca, root_pem) = root(&pca, cfg, 3650).await;
    let csr = pca.get_certificate_authority_csr().certificate_authority_arn(&ca).send().await.unwrap();
    let csr_der = der(csr.csr().unwrap());
    let (_, req) = X509CertificationRequest::from_der(&csr_der).unwrap();
    let requested: Vec<String> = req
        .certification_request_info
        .iter_attributes()
        .filter_map(|a| match a.parsed_attribute() {
            x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(r) => Some(r),
            _ => None,
        })
        .flat_map(|r| r.extensions.iter().map(|e| e.oid.to_id_string()))
        .collect();
    assert!(requested.contains(&"2.5.29.15".to_string()), "{requested:?}");
    assert!(requested.contains(&"1.3.6.1.5.5.7.1.11".to_string()), "{requested:?}");

    // The root certificate carries the template's extensions only.
    let root_der = der(&root_pem);
    let (_, root_cert) = X509Certificate::from_der(&root_der).unwrap();
    let bc = root_cert.basic_constraints().unwrap().unwrap();
    assert!(bc.critical && bc.value.ca && bc.value.path_len_constraint.is_none());
    let ku = root_cert.key_usage().unwrap().unwrap().value;
    assert!(ku.key_cert_sign() && ku.crl_sign() && ku.digital_signature() && !ku.key_encipherment());
    assert!(has_extension(&root_cert, "2.5.29.14"), "root has a subject key identifier");
    assert!(!has_extension(&root_cert, "2.5.29.35"), "self-signed root has no authority key identifier");

    let api = ApiPassthrough::builder()
        .subject(Asn1Subject::builder().common_name("api.example.test").organization("API Org").build())
        .extensions(
            Extensions::builder()
                .subject_alternative_names(PcaGeneralName::builder().dns_name("api.example.test").build())
                .subject_alternative_names(PcaGeneralName::builder().ip_address("10.0.0.7").build())
                .subject_alternative_names(PcaGeneralName::builder().rfc822_name("ops@example.test").build())
                .certificate_policies(
                    PolicyInformation::builder()
                        .cert_policy_id("2.23.140.1.2.1")
                        .policy_qualifiers(
                            PolicyQualifierInfo::builder()
                                .policy_qualifier_id(PolicyQualifierId::Cps)
                                .qualifier(Qualifier::builder().cps_uri("https://cps.example.test").build().unwrap())
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .custom_extensions(
                    CustomExtension::builder()
                        .object_identifier("1.3.6.1.4.1.99999.2")
                        .value("BQA=") // DER NULL
                        .critical(false)
                        .build()
                        .unwrap(),
                )
                // The template sets EKU itself, so this is overridden.
                .extended_key_usage(
                    ExtendedKeyUsage::builder().extended_key_usage_type(ExtendedKeyUsageType::CodeSigning).build(),
                )
                .build(),
        )
        .build();

    // A base template ignores ApiPassthrough and takes no CSR extensions
    // beyond the subject alternative names.
    let csr = csr_with_extension("csr.example.test");
    let base = issue_pem(&pca, &ca, &csr, "EndEntityCertificate/V1", Some(api.clone())).await.unwrap();
    let base_der = der(&base);
    let (_, base_cert) = X509Certificate::from_der(&base_der).unwrap();
    assert_eq!(base_cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), "csr.example.test");
    assert!(!has_extension(&base_cert, "1.3.6.1.4.1.99999.1"));
    assert!(!has_extension(&base_cert, "2.5.29.32"));
    assert!(has_extension(&base_cert, "2.5.29.14"), "end-entity certificates have a subject key identifier");
    let san = base_cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(san.value.general_names, vec![GeneralName::DNSName("csr.example.test")]);

    // The API passthrough variant uses the request's subject and extensions,
    // but the template's own extensions win.
    let passed = issue_pem(&pca, &ca, &csr, "EndEntityCertificate_APIPassthrough/V1", Some(api.clone())).await.unwrap();
    let passed_der = der(&passed);
    let (_, cert) = X509Certificate::from_der(&passed_der).unwrap();
    assert_eq!(cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), "api.example.test");
    assert_eq!(cert.subject().iter_organization().next().unwrap().as_str().unwrap(), "API Org");
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        san.value.general_names,
        vec![
            GeneralName::DNSName("api.example.test"),
            GeneralName::IPAddress(&[10, 0, 0, 7]),
            GeneralName::RFC822Name("ops@example.test"),
        ]
    );
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && eku.client_auth && !eku.code_signing);
    let policies = cert
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::CertificatePolicies(p) => Some(p.clone()),
            _ => None,
        })
        .expect("certificate policies");
    assert_eq!(policies[0].policy_id.to_id_string(), "2.23.140.1.2.1");
    assert!(has_extension(&cert, "1.3.6.1.4.1.99999.2"));
    assert!(!has_extension(&cert, "1.3.6.1.4.1.99999.1"), "no CSR passthrough");

    // CSR passthrough copies the CSR's other extensions.
    let csr_passed = issue_pem(&pca, &ca, &csr, "EndEntityCertificate_CSRPassthrough/V1", None).await.unwrap();
    let csr_passed_der = der(&csr_passed);
    let (_, cert) = X509Certificate::from_der(&csr_passed_der).unwrap();
    assert!(has_extension(&cert, "1.3.6.1.4.1.99999.1"));

    // A blank template takes key usages from the request.
    let blank_api = ApiPassthrough::builder()
        .extensions(
            Extensions::builder()
                .key_usage(KeyUsage::builder().digital_signature(true).non_repudiation(true).build())
                .extended_key_usage(
                    ExtendedKeyUsage::builder().extended_key_usage_type(ExtendedKeyUsageType::EmailProtection).build(),
                )
                .build(),
        )
        .build();
    let blank =
        issue_pem(&pca, &ca, &csr, "BlankEndEntityCertificate_APIPassthrough/V1", Some(blank_api)).await.unwrap();
    let blank_der = der(&blank);
    let (_, cert) = X509Certificate::from_der(&blank_der).unwrap();
    let ku = cert.key_usage().unwrap().unwrap().value;
    assert!(ku.digital_signature() && ku.non_repudiation() && !ku.key_encipherment());
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.email_protection && !eku.server_auth);
    let bc = cert.basic_constraints().unwrap().unwrap();
    assert!(!bc.value.ca && !bc.critical);

    // A blank template needs API passthrough; unknown templates are refused.
    let err = issue_pem(&pca, &ca, &csr, "BlankEndEntityCertificate/V1", None).await.unwrap_err();
    assert_eq!(err.as_deref(), Some("InvalidArgsException"));

    // Custom attributes cannot be mixed with standard ones.
    let mixed = ApiPassthrough::builder()
        .subject(
            Asn1Subject::builder()
                .common_name("x")
                .custom_attributes(CustomAttribute::builder().object_identifier("2.5.4.3").value("y").build().unwrap())
                .build(),
        )
        .build();
    let err = issue_pem(&pca, &ca, &csr, "EndEntityCertificate_APIPassthrough/V1", Some(mixed)).await.unwrap_err();
    assert_eq!(err.as_deref(), Some("InvalidArgsException"));
    let custom_only = ApiPassthrough::builder()
        .subject(
            Asn1Subject::builder()
                .custom_attributes(
                    CustomAttribute::builder()
                        .object_identifier("2.5.4.3")
                        .value("custom.example.test")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .build();
    let pem = issue_pem(&pca, &ca, &csr, "EndEntityCertificate_APIPassthrough/V1", Some(custom_only)).await.unwrap();
    let custom_der = der(&pem);
    let (_, cert) = X509Certificate::from_der(&custom_der).unwrap();
    assert_eq!(cert.subject().iter_common_name().next().unwrap().as_str().unwrap(), "custom.example.test");
}

async fn advance(mws: &Mws, days: i64) {
    let body = json!({"advanceSeconds": days * 86400}).to_string();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

async fn status(pca: &Client, ca: &str) -> CertificateAuthorityStatus {
    let desc = pca.describe_certificate_authority().certificate_authority_arn(ca).send().await.unwrap();
    desc.certificate_authority().unwrap().status().unwrap().clone()
}

#[tokio::test]
async fn ca_lifecycle_follows_the_clock() {
    let mws = Mws::start().await;
    let sdk = mws.root_sdk_config().await;
    let pca = Client::new(&sdk);
    let s3 = Mws::s3(&sdk);

    // A CRL bucket ACM PCA may write to.
    s3.create_bucket().bucket("clock-crls").send().await.unwrap();
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "acm-pca.amazonaws.com"},
            "Action": ["s3:PutObject", "s3:GetBucketAcl", "s3:GetBucketLocation"],
            "Resource": ["arn:aws:s3:::clock-crls", "arn:aws:s3:::clock-crls/*"]
        }]
    });
    s3.put_bucket_policy().bucket("clock-crls").policy(policy.to_string()).send().await.unwrap();
    let revocation = RevocationConfiguration::builder()
        .crl_configuration(
            CrlConfiguration::builder()
                .enabled(true)
                .expiration_in_days(2)
                .s3_bucket_name("clock-crls")
                .s3_object_acl(aws_sdk_acmpca::types::S3ObjectAcl::BucketOwnerFullControl)
                .build()
                .unwrap(),
        )
        .build();
    let (ca, _) = root_with(&pca, config("Clock Root"), 10, None, Some(revocation)).await;
    let key = format!("crl/{}.crl", ca.rsplit('/').next().unwrap());
    let this_update = |body: Vec<u8>| {
        let (_, crl) = CertificateRevocationList::from_der(&body).unwrap();
        crl.last_update().timestamp()
    };
    let crl = s3.get_object().bucket("clock-crls").key(&key).send().await.unwrap();
    let first = this_update(crl.body.collect().await.unwrap().to_vec());

    // Past half the CRL's validity, a fresh CRL is published.
    advance(&mws, 1).await;
    let _ = status(&pca, &ca).await;
    let crl = s3.get_object().bucket("clock-crls").key(&key).send().await.unwrap();
    let second = this_update(crl.body.collect().await.unwrap().to_vec());
    assert!(second >= first + 86_000, "CRL regenerated: {first} -> {second}");

    // Past the CA certificate's notAfter, the CA is EXPIRED and issues nothing.
    advance(&mws, 10).await;
    assert_eq!(status(&pca, &ca).await, CertificateAuthorityStatus::Expired);
    let err = pca
        .issue_certificate()
        .certificate_authority_arn(&ca)
        .csr(Blob::new(csr_with_extension("late.example.test").as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
        .validity(days(1))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidStateException"));

    // Deleted CAs return to their pre-deletion state, until the restoration
    // period ends; then they are gone.
    pca.delete_certificate_authority()
        .certificate_authority_arn(&ca)
        .permanent_deletion_time_in_days(7)
        .send()
        .await
        .unwrap();
    assert_eq!(status(&pca, &ca).await, CertificateAuthorityStatus::Deleted);
    pca.restore_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap();
    assert_eq!(status(&pca, &ca).await, CertificateAuthorityStatus::Expired);
    pca.delete_certificate_authority()
        .certificate_authority_arn(&ca)
        .permanent_deletion_time_in_days(7)
        .send()
        .await
        .unwrap();
    advance(&mws, 8).await;
    let err = pca.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));
    let err = pca.restore_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    // A CA still waiting for its certificate is restorable too, back to
    // PENDING_CERTIFICATE.
    let pending = pca
        .create_certificate_authority()
        .certificate_authority_type(CertificateAuthorityType::Root)
        .certificate_authority_configuration(config("Pending"))
        .send()
        .await
        .unwrap()
        .certificate_authority_arn()
        .unwrap()
        .to_string();
    pca.delete_certificate_authority().certificate_authority_arn(&pending).send().await.unwrap();
    assert_eq!(status(&pca, &pending).await, CertificateAuthorityStatus::Deleted);
    pca.restore_certificate_authority().certificate_authority_arn(&pending).send().await.unwrap();
    assert_eq!(status(&pca, &pending).await, CertificateAuthorityStatus::PendingCertificate);
}

#[tokio::test]
async fn short_lived_certificate_mode_caps_validity() {
    let mws = Mws::start().await;
    let pca = Client::new(&mws.root_sdk_config().await);
    let (ca, _) =
        root_with(&pca, config("Short Lived"), 365, Some(CertificateAuthorityUsageMode::ShortLivedCertificate), None)
            .await;
    let issue = |n: i64| {
        pca.issue_certificate()
            .certificate_authority_arn(&ca)
            .csr(Blob::new(csr_with_extension("short.example.test").as_bytes()))
            .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
            .validity(days(n))
            .send()
    };
    issue(7).await.unwrap();
    let err = issue(8).await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
}

#[tokio::test]
async fn cas_belong_to_their_account_and_region() {
    let mws = Mws::start().await;
    let sdk = mws.root_sdk_config().await;
    let pca = Client::new(&sdk);
    let (ca, _) = root(&pca, config("Scoped Root"), 365).await;

    // Another region's endpoint knows nothing of it.
    let west = Client::from_conf(
        aws_sdk_acmpca::config::Builder::from(&sdk).region(aws_sdk_acmpca::config::Region::new("us-west-2")).build(),
    );
    let listed = west.list_certificate_authorities().send().await.unwrap();
    assert!(listed.certificate_authorities().is_empty());
    let err = west.describe_certificate_authority().certificate_authority_arn(&ca).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    // Another account lists only its own CAs, and sees this one under
    // OTHER_ACCOUNTS once the CA's policy shares it.
    let orgs = aws_sdk_organizations::Client::new(&sdk);
    orgs.create_organization().send().await.unwrap();
    let out = orgs.create_account().email("member@example.com").account_name("member").send().await.unwrap();
    let request_id = out.create_account_status().unwrap().id().unwrap();
    let created = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let member = created.create_account_status().unwrap().account_id().unwrap().to_string();
    let (_, admin) = user_with_policy(
        &mws,
        "admin",
        Some(r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#),
    )
    .await;
    let creds = aws_sdk_sts::Client::new(&admin)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{member}:role/OrganizationAccountAccessRole"))
        .role_session_name("pca")
        .send()
        .await
        .unwrap();
    let other = Client::new(&sts_config(&mws, creds.credentials().unwrap()).await);
    let mine = other.list_certificate_authorities().send().await.unwrap();
    assert!(mine.certificate_authorities().is_empty(), "{mine:?}");
    let shared =
        other.list_certificate_authorities().resource_owner(ResourceOwner::OtherAccounts).send().await.unwrap();
    assert!(shared.certificate_authorities().is_empty());

    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": member},
            "Action": ["acm-pca:DescribeCertificateAuthority", "acm-pca:GetCertificateAuthorityCertificate",
                       "acm-pca:IssueCertificate", "acm-pca:GetCertificate", "acm-pca:ListPermissions",
                       "acm-pca:ListTags"],
            "Resource": ca,
        }]
    });
    pca.put_policy().resource_arn(&ca).policy(policy.to_string()).send().await.unwrap();
    let shared =
        other.list_certificate_authorities().resource_owner(ResourceOwner::OtherAccounts).send().await.unwrap();
    let arns: Vec<&str> = shared.certificate_authorities().iter().filter_map(|c| c.arn()).collect();
    assert_eq!(arns, vec![ca.as_str()]);
    let mine = other.list_certificate_authorities().send().await.unwrap();
    assert!(mine.certificate_authorities().is_empty());
    let own = pca.list_certificate_authorities().send().await.unwrap();
    assert_eq!(own.certificate_authorities().len(), 1);
}
