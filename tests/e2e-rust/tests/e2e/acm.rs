//! AWS Certificate Manager through the official Rust SDK: DNS validation
//! against MWS's Route 53, email approval, private certificates from
//! Private CA, imports and exports, managed renewal on the emulated clock,
//! IAM enforcement, and managed ACME endpoints driven by a real ACME client.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use aws_sdk_acm::error::ProvideErrorMetadata;
use aws_sdk_acm::primitives::Blob;
use aws_sdk_acm::types::{
    AcmCertificateMetadataFilter, AcmeAuthorizationBehavior, AcmeContact, CertificateAuthority, CertificateExport,
    CertificateFilter, CertificateFilterStatement, CertificateKeyPairOrigin, CertificateOptions, CertificateStatus,
    CommonNameFilter, ComparisonOperator, DnsPrevalidationOptions, DomainScope, DomainScopeOption,
    DomainValidationOption, ExpiryEventsConfiguration, Filters, KeyAlgorithm, PrevalidationOptions,
    PublicCertificateAuthority, PublicKeyAlgorithm, RenewalStatus, RevocationReason, SubjectFilter, Tag,
    ValidationChallenge, ValidationMethod, X509AttributeFilter,
};
use aws_sdk_acm::Client;
use aws_sdk_route53::types::{Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType};
use base64::Engine;
use mws_e2e::{user_with_policy, Mws};
use serde_json::{json, Value};
use x509_parser::prelude::*;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn clients(mws: &Mws) -> (Client, aws_sdk_route53::Client) {
    let cfg = mws.root_sdk_config().await;
    (Client::new(&cfg), aws_sdk_route53::Client::new(&cfg))
}

async fn zone(r53: &aws_sdk_route53::Client, name: &str) -> String {
    let out = r53.create_hosted_zone().name(name).caller_reference(name).send().await.unwrap();
    out.hosted_zone().unwrap().id().trim_start_matches("/hostedzone/").to_string()
}

async fn upsert_cname(r53: &aws_sdk_route53::Client, zone: &str, name: &str, value: &str) {
    let set = ResourceRecordSet::builder()
        .name(name)
        .r#type(RrType::Cname)
        .ttl(300)
        .resource_records(ResourceRecord::builder().value(value).build().unwrap())
        .build()
        .unwrap();
    let change = Change::builder().action(ChangeAction::Upsert).resource_record_set(set).build().unwrap();
    r53.change_resource_record_sets()
        .hosted_zone_id(zone)
        .change_batch(ChangeBatch::builder().changes(change).build().unwrap())
        .send()
        .await
        .unwrap();
}

/// Create every DNS validation record a certificate asks for.
async fn publish_validation_records(acm: &Client, r53: &aws_sdk_route53::Client, zone_id: &str, arn: &str) {
    let d = acm.describe_certificate().certificate_arn(arn).send().await.unwrap();
    for dv in d.certificate().unwrap().domain_validation_options() {
        let rr = dv.resource_record().expect("DNS validation record");
        upsert_cname(r53, zone_id, rr.name(), rr.value()).await;
    }
}

fn der(pem: &str) -> Vec<u8> {
    parse_x509_pem(pem.as_bytes()).unwrap().1.contents
}

fn pem_blocks(pem: &str) -> Vec<Vec<u8>> {
    Pem::iter_from_buffer(pem.as_bytes()).map(|p| p.unwrap().contents).collect()
}

fn assert_signed_by(child_der: &[u8], issuer_der: &[u8]) {
    let (_, child) = X509Certificate::from_der(child_der).unwrap();
    let (_, issuer) = X509Certificate::from_der(issuer_der).unwrap();
    child.verify_signature(Some(issuer.public_key())).expect("signature verifies");
}

async fn clock(mws: &Mws, days: i64) {
    let body = json!({"advanceSeconds": days * 86400}).to_string();
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn dns_validated_public_certificate() {
    let mws = Mws::start().await;
    let (acm, r53) = clients(&mws).await;
    let zone_id = zone(&r53, "example.com").await;

    let request = || {
        acm.request_certificate()
            .domain_name("example.com")
            .subject_alternative_names("www.example.com")
            .subject_alternative_names("*.example.com")
            .validation_method(ValidationMethod::Dns)
            .idempotency_token("tok1")
            .tags(Tag::builder().key("team").value("web").build().unwrap())
    };
    let arn = request().send().await.unwrap().certificate_arn().unwrap().to_string();
    assert!(arn.starts_with("arn:aws:acm:us-east-1:123456789012:certificate/"), "{arn}");
    assert_eq!(request().send().await.unwrap().certificate_arn(), Some(arn.as_str()), "idempotent");

    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.status(), Some(&CertificateStatus::PendingValidation));
    assert_eq!(c.r#type().unwrap().as_str(), "AMAZON_ISSUED");
    assert_eq!(c.key_algorithm().unwrap().as_str(), "RSA-2048");
    assert_eq!(c.subject_alternative_names(), ["example.com", "www.example.com", "*.example.com"]);
    let dvs = c.domain_validation_options();
    assert_eq!(dvs.len(), 3);
    let rr = dvs[0].resource_record().unwrap();
    assert!(rr.name().starts_with('_') && rr.name().ends_with(".example.com."));
    assert!(rr.value().ends_with(".acm-validations.aws."));
    // A wildcard shares its base domain's record.
    assert_eq!(dvs[2].resource_record().unwrap().name(), rr.name());

    let err = acm.get_certificate().certificate_arn(&arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "RequestInProgressException");

    let listed = acm.list_certificate_domain_validations().certificate_arn(&arn).send().await.unwrap();
    let summary = &listed.domain_validation_summary_list()[1];
    assert_eq!(summary.domain_name(), "www.example.com");
    let active = summary.active_validation_configuration().unwrap();
    assert!(matches!(active.validation_challenge(), Some(ValidationChallenge::DnsValidationChallenge(_))));

    // Only one of two records published: still pending.
    upsert_cname(&r53, &zone_id, rr.name(), rr.value()).await;
    let c = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(c.certificate().unwrap().status(), Some(&CertificateStatus::PendingValidation));
    publish_validation_records(&acm, &r53, &zone_id, &arn).await;

    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.status(), Some(&CertificateStatus::Issued));
    assert_eq!(c.issuer(), Some("Amazon"));
    assert_eq!(c.subject(), Some("CN=example.com"));
    assert_eq!(c.signature_algorithm(), Some("SHA256WITHRSA"));
    let lifetime = c.not_after().unwrap().secs() - c.not_before().unwrap().secs();
    assert_eq!(lifetime, 198 * 86400);
    assert_eq!(c.renewal_eligibility().unwrap().as_str(), "ELIGIBLE");
    assert_eq!(c.extended_key_usages()[0].name().unwrap().as_str(), "TLS_WEB_SERVER_AUTHENTICATION");

    let got = acm.get_certificate().certificate_arn(&arn).send().await.unwrap();
    let leaf = der(got.certificate().unwrap());
    let chain = pem_blocks(got.certificate_chain().unwrap());
    assert_eq!(chain.len(), 2, "intermediate and root");
    assert_signed_by(&leaf, &chain[0]);
    assert_signed_by(&chain[0], &chain[1]);
    let (_, x) = X509Certificate::from_der(&leaf).unwrap();
    let sans: Vec<String> =
        x.subject_alternative_name().unwrap().unwrap().value.general_names.iter().map(|g| g.to_string()).collect();
    assert!(sans.iter().any(|s| s.contains("*.example.com")), "{sans:?}");

    // Listing defaults to RSA_2048 keys.
    let list = acm.list_certificates().send().await.unwrap();
    assert_eq!(list.certificate_summary_list().len(), 1);
    let s = &list.certificate_summary_list()[0];
    assert_eq!(s.key_algorithm(), Some(&KeyAlgorithm::Rsa2048));
    assert_eq!(s.status(), Some(&CertificateStatus::Issued));
    let none = acm
        .list_certificates()
        .includes(Filters::builder().key_types(KeyAlgorithm::EcPrime256v1).build())
        .send()
        .await
        .unwrap();
    assert!(none.certificate_summary_list().is_empty());
    let pending =
        acm.list_certificates().certificate_statuses(CertificateStatus::PendingValidation).send().await.unwrap();
    assert!(pending.certificate_summary_list().is_empty());

    let search = acm
        .search_certificates()
        .filter_statement(CertificateFilterStatement::And(vec![
            CertificateFilterStatement::Filter(CertificateFilter::X509AttributeFilter(X509AttributeFilter::Subject(
                SubjectFilter::CommonName(
                    CommonNameFilter::builder()
                        .value("example")
                        .comparison_operator(ComparisonOperator::Contains)
                        .build()
                        .unwrap(),
                ),
            ))),
            CertificateFilterStatement::Not(Box::new(CertificateFilterStatement::Filter(
                CertificateFilter::AcmCertificateMetadataFilter(AcmCertificateMetadataFilter::Exported(true)),
            ))),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(search.results().len(), 1);
    let attrs = search.results()[0].x509_attributes().unwrap();
    assert_eq!(attrs.issuer().unwrap().organization(), Some("Amazon"));
    assert_eq!(attrs.subject_alternative_names().len(), 3);

    // Tags.
    acm.add_tags_to_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .tags(Tag::builder().key("flag").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = acm.list_tags_for_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(tags.tags().len(), 3);
    acm.remove_tags_from_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("env").value("not-prod").build().unwrap())
        .tags(Tag::builder().key("flag").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = acm.list_tags_for_certificate().certificate_arn(&arn).send().await.unwrap();
    let keys: Vec<_> = tags.tags().iter().map(|t| t.key()).collect();
    assert_eq!(keys, ["team", "env"], "a value that does not match keeps the tag");
    let err = acm
        .add_tags_to_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("aws:reserved").value("x").build().unwrap())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidTagException");

    // Public certificates are always logged; the opt-out is gone.
    #[allow(deprecated)]
    let opt_out = CertificateOptions::builder()
        .certificate_transparency_logging_preference(
            aws_sdk_acm::types::CertificateTransparencyLoggingPreference::Disabled,
        )
        .build();
    let err = acm
        .update_certificate_options()
        .certificate_arn(&arn)
        .options(opt_out)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationException");

    // Not exportable, and never exported so not revocable.
    let err = acm
        .export_certificate()
        .certificate_arn(&arn)
        .passphrase(Blob::new("secret-pass"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationException");
    let err = acm
        .revoke_certificate()
        .certificate_arn(&arn)
        .revocation_reason(RevocationReason::Superseded)
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationException");
    let err = acm.renew_certificate().certificate_arn(&arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ValidationException");

    acm.delete_certificate().certificate_arn(&arn).send().await.unwrap();
    let err = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "ResourceNotFoundException");
    let err = acm.describe_certificate().certificate_arn("not-an-arn-at-all-xx").send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ValidationException");
}

#[tokio::test]
async fn renewal_and_expiry_follow_the_clock() {
    let mws = Mws::start().await;
    let (acm, r53) = clients(&mws).await;
    let zone_id = zone(&r53, "renew.example.org").await;
    let arn = acm
        .request_certificate()
        .domain_name("renew.example.org")
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    publish_validation_records(&acm, &r53, &zone_id, &arn).await;
    let first = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let first_serial = first.certificate().unwrap().serial().unwrap().to_string();

    // A pending request times out after 72 hours.
    let stale = acm
        .request_certificate()
        .domain_name("never.renew.example.org")
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();

    // 150 days in: inside the 60-day renewal window, and the record is
    // still there, so ACM renews.
    clock(&mws, 150).await;
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.renewal_summary().unwrap().renewal_status(), &RenewalStatus::Success);
    assert_ne!(c.serial().unwrap(), first_serial);
    assert_eq!(c.status(), Some(&CertificateStatus::Issued));
    let d = acm.describe_certificate().certificate_arn(&stale).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().status(), Some(&CertificateStatus::ValidationTimedOut));

    // Without its validation record the next renewal stays pending and the
    // certificate expires.
    let rr = c.domain_validation_options()[0].resource_record().unwrap().clone();
    let set = ResourceRecordSet::builder()
        .name(rr.name())
        .r#type(RrType::Cname)
        .ttl(300)
        .resource_records(ResourceRecord::builder().value(rr.value()).build().unwrap())
        .build()
        .unwrap();
    r53.change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(
            ChangeBatch::builder()
                .changes(Change::builder().action(ChangeAction::Delete).resource_record_set(set).build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    clock(&mws, 150).await;
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(
        d.certificate().unwrap().renewal_summary().unwrap().renewal_status(),
        &RenewalStatus::PendingAutoRenewal
    );
    clock(&mws, 60).await;
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().status(), Some(&CertificateStatus::Expired));
}

#[tokio::test]
async fn email_validation_and_migration_to_dns() {
    let mws = Mws::start().await;
    let (acm, r53) = clients(&mws).await;
    let zone_id = zone(&r53, "example.net").await;
    let arn = acm
        .request_certificate()
        .domain_name("shop.example.net")
        .domain_validation_options(
            DomainValidationOption::builder()
                .domain_name("shop.example.net")
                .validation_domain("example.net")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let dv = &d.certificate().unwrap().domain_validation_options()[0];
    assert_eq!(dv.validation_method(), Some(&ValidationMethod::Email), "EMAIL is the default");
    assert_eq!(dv.validation_domain(), Some("example.net"));
    assert!(dv.validation_emails().contains(&"admin@example.net".to_string()));

    let err = acm
        .resend_validation_email()
        .certificate_arn(&arn)
        .domain("shop.example.net")
        .validation_domain("other.org")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidDomainValidationOptionsException");
    acm.resend_validation_email()
        .certificate_arn(&arn)
        .domain("shop.example.net")
        .validation_domain("shop.example.net")
        .send()
        .await
        .unwrap();

    // The link in the validation email approves the request.
    let link = format!("/_acm/approvals?certificate={}&domain=shop.example.net", urlencoding::encode(&arn));
    let (status, _, body) = mws.raw("GET", &link, &[], b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().status(), Some(&CertificateStatus::Issued));

    // Migrate the issued certificate from email to DNS validation.
    acm.update_certificate_options()
        .certificate_arn(&arn)
        .options(CertificateOptions::builder().validation_method(ValidationMethod::Dns).build())
        .send()
        .await
        .unwrap();
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let update = d.certificate().unwrap().update_summary().unwrap();
    assert_eq!(update.status().unwrap().as_str(), "PENDING_DOMAIN_VALIDATION");
    let listed = acm.list_certificate_domain_validations().certificate_arn(&arn).send().await.unwrap();
    let requested = listed.domain_validation_summary_list()[0].requested_validation_configuration().unwrap();
    let Some(ValidationChallenge::DnsValidationChallenge(dns)) = requested.validation_challenge() else {
        panic!("DNS challenge expected")
    };
    let rr = dns.resource_record().unwrap();
    upsert_cname(&r53, &zone_id, rr.name(), rr.value()).await;
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.update_summary().unwrap().status().unwrap().as_str(), "SUCCESS");
    assert_eq!(c.domain_validation_options()[0].validation_method(), Some(&ValidationMethod::Dns));

    // Domains that cannot have public certificates fail.
    let bad = acm.request_certificate().domain_name("app.internal").send().await.unwrap();
    let d = acm.describe_certificate().certificate_arn(bad.certificate_arn().unwrap()).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().status(), Some(&CertificateStatus::Failed));
    assert_eq!(d.certificate().unwrap().failure_reason().unwrap().as_str(), "INVALID_PUBLIC_DOMAIN");
}

#[tokio::test]
async fn exportable_public_certificate_can_be_revoked() {
    let mws = Mws::start().await;
    let (acm, r53) = clients(&mws).await;
    let zone_id = zone(&r53, "export.example.com").await;
    let arn = acm
        .request_certificate()
        .domain_name("api.export.example.com")
        .validation_method(ValidationMethod::Dns)
        .key_algorithm(KeyAlgorithm::EcPrime256v1)
        .options(CertificateOptions::builder().export(CertificateExport::Enabled).build())
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    publish_validation_records(&acm, &r53, &zone_id, &arn).await;
    let err = acm
        .export_certificate()
        .certificate_arn(&arn)
        .passphrase(Blob::new("pass$word"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "InvalidParameterException");
    let out =
        acm.export_certificate().certificate_arn(&arn).passphrase(Blob::new("correct horse")).send().await.unwrap();
    assert!(out.private_key().unwrap().starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    let leaf = der(out.certificate().unwrap());
    let (_, x) = X509Certificate::from_der(&leaf).unwrap();
    assert_eq!(x.issuer().iter_common_name().next().unwrap().as_str().unwrap(), "Amazon ECDSA 256 M01");

    let listed = acm
        .list_certificates()
        .includes(
            Filters::builder().key_types(KeyAlgorithm::EcPrime256v1).export_option(CertificateExport::Enabled).build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(listed.certificate_summary_list()[0].exported(), Some(true));

    let revoked = acm
        .revoke_certificate()
        .certificate_arn(&arn)
        .revocation_reason(RevocationReason::KeyCompromise)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.certificate_arn(), Some(arn.as_str()));
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.status(), Some(&CertificateStatus::Revoked));
    assert_eq!(c.revocation_reason(), Some(&RevocationReason::KeyCompromise));
}

#[tokio::test]
async fn private_certificates_come_from_private_ca() {
    use aws_sdk_acmpca::types::{
        ActionType, Asn1Subject, CertificateAuthorityConfiguration, CertificateAuthorityType, KeyAlgorithm as PcaKey,
        SigningAlgorithm, Validity, ValidityPeriodType,
    };
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let acm = Client::new(&cfg);
    let pca = aws_sdk_acmpca::Client::new(&cfg);
    let ca = pca
        .create_certificate_authority()
        .certificate_authority_type(CertificateAuthorityType::Root)
        .certificate_authority_configuration(
            CertificateAuthorityConfiguration::builder()
                .key_algorithm(PcaKey::EcPrime256v1)
                .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
                .subject(Asn1Subject::builder().common_name("Corp Root").organization("Corp").build())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .certificate_authority_arn()
        .unwrap()
        .to_string();
    let csr = pca.get_certificate_authority_csr().certificate_authority_arn(&ca).send().await.unwrap();
    let root = pca
        .issue_certificate()
        .certificate_authority_arn(&ca)
        .csr(aws_sdk_acmpca::primitives::Blob::new(csr.csr().unwrap().as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withecdsa)
        .template_arn("arn:aws:acm-pca:::template/RootCACertificate/V1")
        .validity(Validity::builder().value(5).r#type(ValidityPeriodType::Years).build().unwrap())
        .send()
        .await
        .unwrap();
    let root_pem = pca
        .get_certificate()
        .certificate_authority_arn(&ca)
        .certificate_arn(root.certificate_arn().unwrap())
        .send()
        .await
        .unwrap()
        .certificate()
        .unwrap()
        .to_string();
    pca.import_certificate_authority_certificate()
        .certificate_authority_arn(&ca)
        .certificate(aws_sdk_acmpca::primitives::Blob::new(root_pem.as_bytes()))
        .send()
        .await
        .unwrap();

    let arn = acm
        .request_certificate()
        .domain_name("svc.corp.internal")
        .subject_alternative_names("alt.corp.internal")
        .certificate_authority_arn(&ca)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.status(), Some(&CertificateStatus::Issued));
    assert_eq!(c.r#type().unwrap().as_str(), "PRIVATE");
    assert_eq!(c.certificate_authority_arn(), Some(ca.as_str()));
    assert_eq!(c.issuer(), Some("Corp"));
    let serial = c.serial().unwrap().to_string();
    let got = acm.get_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_signed_by(&der(got.certificate().unwrap()), &der(&root_pem));
    assert_eq!(der(got.certificate_chain().unwrap()), der(&root_pem));

    let exported =
        acm.export_certificate().certificate_arn(&arn).passphrase(Blob::new("passphrase")).send().await.unwrap();
    assert!(exported.private_key().unwrap().contains("ENCRYPTED PRIVATE KEY"));

    // ACM renews as acm.amazonaws.com, which needs the CA's permission.
    acm.renew_certificate().certificate_arn(&arn).send().await.unwrap();
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let renewal = d.certificate().unwrap().renewal_summary().unwrap().clone();
    assert_eq!(renewal.renewal_status(), &RenewalStatus::Failed);
    assert_eq!(renewal.renewal_status_reason().unwrap().as_str(), "PCA_ACCESS_DENIED");
    pca.create_permission()
        .certificate_authority_arn(&ca)
        .principal("acm.amazonaws.com")
        .actions(ActionType::IssueCertificate)
        .actions(ActionType::GetCertificate)
        .actions(ActionType::ListPermissions)
        .send()
        .await
        .unwrap();
    acm.renew_certificate().certificate_arn(&arn).send().await.unwrap();
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.renewal_summary().unwrap().renewal_status(), &RenewalStatus::Success);
    assert_ne!(c.serial().unwrap(), serial);

    // A requester without acm-pca:IssueCertificate gets a failed request.
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"acm:*","Resource":"*"}]}"#;
    let (_, user_cfg) = user_with_policy(&mws, "acm-only", Some(policy)).await;
    let user = Client::new(&user_cfg);
    let arn = user
        .request_certificate()
        .domain_name("denied.corp.internal")
        .certificate_authority_arn(&ca)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    let d = user.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().status(), Some(&CertificateStatus::Failed));
    assert_eq!(d.certificate().unwrap().failure_reason().unwrap().as_str(), "PCA_ACCESS_DENIED");
}

fn self_signed(names: &[&str], days: i64) -> (String, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, names[0]);
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "Imported Org");
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::days(1);
    params.not_after = now + ::time::Duration::days(days);
    (params.self_signed(&key).unwrap().pem(), key)
}

#[tokio::test]
async fn import_reimport_and_account_configuration() {
    let mws = Mws::start().await;
    let (acm, _) = clients(&mws).await;
    let (cert, key) = self_signed(&["imported.example.com", "alt.example.com"], 90);
    let arn = acm
        .import_certificate()
        .certificate(Blob::new(cert.as_bytes()))
        .private_key(Blob::new(key.serialize_pem().as_bytes()))
        .certificate_chain(Blob::new(cert.as_bytes()))
        .tags(Tag::builder().key("src").value("import").build().unwrap())
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.r#type().unwrap().as_str(), "IMPORTED");
    assert_eq!(c.domain_name(), Some("imported.example.com"));
    assert_eq!(c.issuer(), Some("Imported Org"));
    assert_eq!(c.key_algorithm().unwrap().as_str(), "EC-prime256v1");
    assert_eq!(c.renewal_eligibility().unwrap().as_str(), "INELIGIBLE");
    assert_eq!(c.certificate_key_pair_origin(), Some(&CertificateKeyPairOrigin::CustomerProvided));
    assert!(c.imported_at().is_some());
    let got = acm.get_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(der(got.certificate().unwrap()), der(&cert));

    // A key that does not match is refused.
    let (_, other_key) = self_signed(&["x.example.com"], 30);
    let err = acm
        .import_certificate()
        .certificate(Blob::new(cert.as_bytes()))
        .private_key(Blob::new(other_key.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationException");

    // Reimport keeps the ARN and tags; tags may not be given.
    let (cert2, key2) = self_signed(&["renewed.example.com"], 120);
    let again = acm
        .import_certificate()
        .certificate_arn(&arn)
        .certificate(Blob::new(cert2.as_bytes()))
        .private_key(Blob::new(key2.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(again.certificate_arn(), Some(arn.as_str()));
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().domain_name(), Some("renewed.example.com"));
    assert_eq!(acm.list_tags_for_certificate().certificate_arn(&arn).send().await.unwrap().tags().len(), 1);
    let err = acm
        .export_certificate()
        .certificate_arn(&arn)
        .passphrase(Blob::new("passphrase"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&err), "ValidationException");

    let cfg = acm.get_account_configuration().send().await.unwrap();
    assert_eq!(cfg.expiry_events().unwrap().days_before_expiry(), Some(45));
    acm.put_account_configuration()
        .idempotency_token("cfg1")
        .expiry_events(ExpiryEventsConfiguration::builder().days_before_expiry(30).build())
        .send()
        .await
        .unwrap();
    let cfg = acm.get_account_configuration().send().await.unwrap();
    assert_eq!(cfg.expiry_events().unwrap().days_before_expiry(), Some(30));
}

#[tokio::test]
async fn iam_policies_and_condition_keys_apply() {
    let mws = Mws::start().await;
    let policy = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"acm:RequestCertificate","Resource":"*",
         "Condition":{"StringEquals":{"acm:ValidationMethod":"DNS"}}},
        {"Effect":"Allow","Action":"acm:DescribeCertificate","Resource":"*",
         "Condition":{"StringEquals":{"aws:ResourceTag/team":"blue"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "dns-only", Some(policy)).await;
    let acm = Client::new(&cfg);
    let err = acm.request_certificate().domain_name("a.example.com").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "AccessDeniedException");
    let blue = acm
        .request_certificate()
        .domain_name("a.example.com")
        .validation_method(ValidationMethod::Dns)
        .tags(Tag::builder().key("team").value("blue").build().unwrap())
        .send()
        .await
        .unwrap();
    let red = acm
        .request_certificate()
        .domain_name("b.example.com")
        .validation_method(ValidationMethod::Dns)
        .tags(Tag::builder().key("team").value("red").build().unwrap())
        .send()
        .await
        .unwrap();
    acm.describe_certificate().certificate_arn(blue.certificate_arn().unwrap()).send().await.unwrap();
    let err = acm.describe_certificate().certificate_arn(red.certificate_arn().unwrap()).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "AccessDeniedException");
    let err = acm.list_certificates().send().await.unwrap_err().into_service_error();
    assert_eq!(code(&err), "AccessDeniedException");
}

// --- ACME ---

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// A small RFC 8555 client: ES256 account key, EAB, POST-as-GET.
struct AcmeClient<'a> {
    mws: &'a Mws,
    directory: Value,
    key: EcdsaKeyPair,
    kid: Option<String>,
}

impl<'a> AcmeClient<'a> {
    async fn new(mws: &'a Mws, directory_url: &str) -> AcmeClient<'a> {
        let (status, _, body) = mws.raw("GET", directory_url, &[], b"").await;
        assert_eq!(status, 200);
        let directory: Value = serde_json::from_slice(&body).unwrap();
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        AcmeClient { mws, directory, key, kid: None }
    }

    fn url(&self, name: &str) -> String {
        self.directory[name].as_str().unwrap().to_string()
    }

    fn jwk(&self) -> Value {
        let point = self.key.public_key().as_ref();
        json!({"crv": "P-256", "kty": "EC", "x": b64(&point[1..33]), "y": b64(&point[33..65])})
    }

    async fn nonce(&self) -> String {
        let (_, headers, _) = self.mws.raw("HEAD", &self.url("newNonce"), &[], b"").await;
        headers.iter().find(|(k, _)| k == "replay-nonce").unwrap().1.clone()
    }

    fn sign(&self, protected: Value, payload: &str) -> Value {
        let protected = b64(protected.to_string().as_bytes());
        let input = format!("{protected}.{payload}");
        let sig = self.key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
        json!({"protected": protected, "payload": payload, "signature": b64(sig.as_ref())})
    }

    /// POST a JWS; `None` payload is POST-as-GET.
    async fn post(&self, url: &str, payload: Option<Value>) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut protected = json!({"alg": "ES256", "nonce": self.nonce().await, "url": url});
        match &self.kid {
            Some(kid) => protected["kid"] = json!(kid),
            None => protected["jwk"] = self.jwk(),
        }
        let payload = payload.map(|p| b64(p.to_string().as_bytes())).unwrap_or_default();
        let body = self.sign(protected, &payload).to_string();
        self.mws.raw("POST", url, &[("Content-Type", "application/jose+json")], body.as_bytes()).await
    }

    async fn register(&mut self, eab_kid: &str, mac_key: &str) -> (u16, Value) {
        let url = self.url("newAccount");
        let eab_protected = b64(json!({"alg": "HS256", "kid": eab_kid, "url": url}).to_string().as_bytes());
        let eab_payload = b64(self.jwk().to_string().as_bytes());
        let mac = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(mac_key).unwrap();
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &mac);
        let tag = aws_lc_rs::hmac::sign(&key, format!("{eab_protected}.{eab_payload}").as_bytes());
        let eab = json!({"protected": eab_protected, "payload": eab_payload, "signature": b64(tag.as_ref())});
        let payload =
            json!({"termsOfServiceAgreed": true, "contact": ["mailto:ops@example.com"], "externalAccountBinding": eab});
        let (status, headers, body) = self.post(&url, Some(payload)).await;
        if status == 201 || status == 200 {
            self.kid = headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v.clone());
        }
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}

async fn acme_role(mws: &Mws) -> String {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"acm.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let role = iam.create_role().role_name("acme-clients").assume_role_policy_document(trust).send().await.unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["acm:RequestCertificate","acm:RevokeCertificate"],"Resource":"*"}]}"#;
    iam.put_role_policy().role_name("acme-clients").policy_name("acme").policy_document(policy).send().await.unwrap();
    role.role().unwrap().arn().to_string()
}

#[tokio::test]
async fn managed_acme_endpoint_issues_to_a_real_acme_client() {
    let mws = Mws::start().await;
    let (acm, r53) = clients(&mws).await;
    let zone_id = zone(&r53, "acme.example.com").await;
    let role_arn = acme_role(&mws).await;

    let endpoint_arn = acm
        .create_acme_endpoint()
        .authorization_behavior(AcmeAuthorizationBehavior::PreApproved)
        .contact(AcmeContact::Required)
        .certificate_authority(CertificateAuthority::PublicCertificateAuthority(
            PublicCertificateAuthority::builder()
                .allowed_key_algorithms(PublicKeyAlgorithm::EcPrime256V1)
                .allowed_key_algorithms(PublicKeyAlgorithm::Rsa2048)
                .build(),
        ))
        .tags(Tag::builder().key("owner").value("platform").build().unwrap())
        .certificate_tags(Tag::builder().key("issued-by").value("acme").build().unwrap())
        .idempotency_token("ep1")
        .send()
        .await
        .unwrap()
        .acme_endpoint_arn()
        .unwrap()
        .to_string();
    let endpoint = acm.describe_acme_endpoint().acme_endpoint_arn(&endpoint_arn).send().await.unwrap();
    let endpoint = endpoint.acme_endpoint().unwrap();
    assert_eq!(endpoint.status().unwrap().as_str(), "ACTIVE");
    let directory_url = endpoint.endpoint_url().unwrap().to_string();
    assert!(directory_url.ends_with("/directory"), "{directory_url}");
    assert_eq!(acm.list_acme_endpoints().send().await.unwrap().acme_endpoints().len(), 1);
    acm.update_acme_endpoint().acme_endpoint_arn(&endpoint_arn).contact(AcmeContact::NotRequired).send().await.unwrap();

    // Tags on ACME resources.
    acm.tag_resource()
        .resource_arn(&endpoint_arn)
        .tags(Tag::builder().key("cost").value("42").build().unwrap())
        .send()
        .await
        .unwrap();
    acm.untag_resource().resource_arn(&endpoint_arn).tag_keys("owner").send().await.unwrap();
    let tags = acm.list_tags_for_resource().resource_arn(&endpoint_arn).send().await.unwrap();
    assert_eq!(tags.tags().iter().map(|t| t.key()).collect::<Vec<_>>(), ["cost"]);

    // ACM writes the prevalidation record into the hosted zone.
    let dv_arn = acm
        .create_acme_domain_validation()
        .acme_endpoint_arn(&endpoint_arn)
        .domain_name("acme.example.com")
        .prevalidation_options(PrevalidationOptions::DnsPrevalidation(
            DnsPrevalidationOptions::builder()
                .hosted_zone_id(&zone_id)
                .domain_scope(
                    DomainScope::builder()
                        .exact_domain(DomainScopeOption::Enabled)
                        .subdomains(DomainScopeOption::Enabled)
                        .build(),
                )
                .build(),
        ))
        .send()
        .await
        .unwrap()
        .acme_domain_validation_arn()
        .to_string();
    let dv = acm.describe_acme_domain_validation().acme_domain_validation_arn(&dv_arn).send().await.unwrap();
    assert_eq!(dv.acme_domain_validation().unwrap().status().unwrap().as_str(), "VALID");
    // A domain outside the zone fails with DOMAIN_MISMATCH.
    let other = acm
        .create_acme_domain_validation()
        .acme_endpoint_arn(&endpoint_arn)
        .domain_name("elsewhere.org")
        .prevalidation_options(PrevalidationOptions::DnsPrevalidation(
            DnsPrevalidationOptions::builder().hosted_zone_id(&zone_id).build(),
        ))
        .send()
        .await
        .unwrap()
        .acme_domain_validation_arn()
        .to_string();
    let d = acm.describe_acme_domain_validation().acme_domain_validation_arn(&other).send().await.unwrap();
    let d = d.acme_domain_validation().unwrap();
    assert_eq!(d.status().unwrap().as_str(), "INVALID");
    assert_eq!(d.failure_details().unwrap().reason().unwrap().as_str(), "DOMAIN_MISMATCH");
    acm.update_acme_domain_validation()
        .acme_domain_validation_arn(&other)
        .prevalidation_options(PrevalidationOptions::DnsPrevalidation(DnsPrevalidationOptions::builder().build()))
        .send()
        .await
        .unwrap();
    let listed = acm.list_acme_domain_validations().acme_endpoint_arn(&endpoint_arn).send().await.unwrap();
    assert_eq!(listed.acme_domain_validations().len(), 2);
    acm.delete_acme_domain_validation().acme_domain_validation_arn(&other).send().await.unwrap();

    let eab = acm
        .create_acme_external_account_binding()
        .acme_endpoint_arn(&endpoint_arn)
        .role_arn(&role_arn)
        .send()
        .await
        .unwrap();
    let eab_arn = eab.external_account_binding().unwrap().acme_external_account_binding_arn().unwrap().to_string();
    let creds = acm
        .get_acme_external_account_binding_credentials()
        .acme_external_account_binding_arn(&eab_arn)
        .send()
        .await
        .unwrap();
    let (eab_kid, mac) = (creds.key_id().unwrap().to_string(), creds.mac_key().unwrap().to_string());
    assert_eq!(
        acm.list_acme_external_account_bindings()
            .acme_endpoint_arn(&endpoint_arn)
            .send()
            .await
            .unwrap()
            .external_account_bindings()
            .len(),
        1
    );

    // Register, order, finalize, download.
    let mut client = AcmeClient::new(&mws, &directory_url).await;
    assert_eq!(client.directory["meta"]["externalAccountRequired"], json!(true));
    let (status, account) = client.register(&eab_kid, &mac).await;
    assert_eq!(status, 201, "{account}");
    assert_eq!(account["status"], "valid");
    let account_url = client.kid.clone().unwrap();
    let used =
        acm.describe_acme_external_account_binding().acme_external_account_binding_arn(&eab_arn).send().await.unwrap();
    assert!(used.external_account_binding().unwrap().last_used_at().is_some());

    let (status, _, body) = client
        .post(&client.url("newOrder"), Some(json!({"identifiers": [{"type": "dns", "value": "outside.org"}]})))
        .await;
    assert_eq!(status, 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["type"],
        "urn:ietf:params:acme:error:rejectedIdentifier"
    );

    let ids = json!({"identifiers": [{"type": "dns", "value": "www.acme.example.com"}, {"type": "dns", "value": "acme.example.com"}]});
    let (status, headers, body) = client.post(&client.url("newOrder"), Some(ids)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let order: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(order["status"], "ready");
    let order_url = headers.iter().find(|(k, _)| k == "location").unwrap().1.clone();
    let authz = order["authorizations"][0].as_str().unwrap().to_string();
    let (status, _, body) = client.post(&authz, None).await;
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["status"], "valid");

    let cert_key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(vec!["www.acme.example.com".to_string(), "acme.example.com".to_string()])
            .unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&cert_key).unwrap();
    let (status, _, body) =
        client.post(order["finalize"].as_str().unwrap(), Some(json!({"csr": b64(csr.der())}))).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (_, _, body) = client.post(&order_url, None).await;
    let order: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(order["status"], "valid");
    let (status, headers, body) = client.post(order["certificate"].as_str().unwrap(), None).await;
    assert_eq!(status, 200);
    assert!(headers.iter().any(|(k, v)| k == "content-type" && v == "application/pem-certificate-chain"));
    let chain = pem_blocks(&String::from_utf8(body).unwrap());
    assert_signed_by(&chain[0], &chain[1]);
    let (_, leaf) = X509Certificate::from_der(&chain[0]).unwrap();
    assert_eq!(leaf.public_key().raw, cert_key.public_key_der().as_slice(), "issued for the client's own key");

    // The certificate shows up in ACM, but only when ACME is asked for.
    assert!(acm
        .list_certificates()
        .includes(Filters::builder().key_types(KeyAlgorithm::EcPrime256v1).build())
        .send()
        .await
        .unwrap()
        .certificate_summary_list()
        .is_empty());
    let listed = acm
        .list_certificates()
        .certificate_key_pair_origins(CertificateKeyPairOrigin::Acme)
        .includes(Filters::builder().key_types(KeyAlgorithm::EcPrime256v1).build())
        .send()
        .await
        .unwrap();
    let cert_arn = listed.certificate_summary_list()[0].certificate_arn().unwrap().to_string();
    let d = acm.describe_certificate().certificate_arn(&cert_arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.acme_endpoint_arn(), Some(endpoint_arn.as_str()));
    let account_id = c.acme_account_id().unwrap().to_string();
    let tags = acm.list_tags_for_certificate().certificate_arn(&cert_arn).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "issued-by");
    let search = acm
        .search_certificates()
        .filter_statement(CertificateFilterStatement::Filter(CertificateFilter::AcmCertificateMetadataFilter(
            AcmCertificateMetadataFilter::AcmeAccountId(account_id),
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(search.results().len(), 1);

    // Revoke through ACME.
    let (status, _, body) =
        client.post(&client.url("revokeCert"), Some(json!({"certificate": b64(&chain[0]), "reason": 4}))).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let d = acm.describe_certificate().certificate_arn(&cert_arn).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().status(), Some(&CertificateStatus::Revoked));

    // ACME certificates are not the account's to delete.
    let err = acm.delete_certificate().certificate_arn(&cert_arn).send().await.unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ValidationException");

    // Accounts.
    let accounts = acm.list_acme_accounts().acme_endpoint_arn(&endpoint_arn).send().await.unwrap();
    assert_eq!(accounts.acme_accounts()[0].account_url(), Some(account_url.as_str()));
    let described =
        acm.describe_acme_account().acme_endpoint_arn(&endpoint_arn).account_url(&account_url).send().await.unwrap();
    assert_eq!(described.acme_account().unwrap().acme_external_account_binding_arn(), Some(eab_arn.as_str()));
    acm.revoke_acme_account().acme_endpoint_arn(&endpoint_arn).account_url(&account_url).send().await.unwrap();
    let (status, _, _) = client
        .post(&client.url("newOrder"), Some(json!({"identifiers": [{"type": "dns", "value": "acme.example.com"}]})))
        .await;
    assert_eq!(status, 403, "a revoked account can no longer order");

    // A revoked binding registers nobody.
    acm.revoke_acme_external_account_binding().acme_external_account_binding_arn(&eab_arn).send().await.unwrap();
    let mut second = AcmeClient::new(&mws, &directory_url).await;
    let (status, problem) = second.register(&eab_kid, &mac).await;
    assert_eq!(status, 403, "{problem}");
    acm.delete_acme_external_account_binding().acme_external_account_binding_arn(&eab_arn).send().await.unwrap();
    let err = acm
        .describe_acme_external_account_binding()
        .acme_external_account_binding_arn(&eab_arn)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&err.into_service_error()), "ResourceNotFoundException");

    acm.delete_acme_endpoint().acme_endpoint_arn(&endpoint_arn).send().await.unwrap();
    let (status, _, _) = mws.raw("GET", &directory_url, &[], b"").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn listing_defaults_to_rsa_certificates_with_a_domain() {
    let mws = Mws::start().await;
    let (acm, _) = clients(&mws).await;
    let (cert, key) = self_signed(&["ec.example.com"], 90);
    acm.import_certificate()
        .certificate(Blob::new(cert.as_bytes()))
        .private_key(Blob::new(key.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap();
    // No subject and no SANs: no domain name at all.
    let nameless_key = rcgen::KeyPair::generate().unwrap();
    let nameless = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&nameless_key).unwrap();
    acm.import_certificate()
        .certificate(Blob::new(nameless.pem().as_bytes()))
        .private_key(Blob::new(nameless_key.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap();

    let list = acm.list_certificates().send().await.unwrap();
    assert!(list.certificate_summary_list().is_empty(), "only RSA_1024 and RSA_2048 by default");
    let ec = acm
        .list_certificates()
        .includes(Filters::builder().key_types(KeyAlgorithm::EcPrime256v1).build())
        .send()
        .await
        .unwrap();
    let names: Vec<_> = ec.certificate_summary_list().iter().map(|s| s.domain_name().unwrap_or_default()).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&"ec.example.com"));
}

#[tokio::test]
async fn email_validated_renewal_waits_for_approval() {
    let mws = Mws::start().await;
    let (acm, _) = clients(&mws).await;
    let arn = acm
        .request_certificate()
        .domain_name("mail.example.net")
        .validation_method(ValidationMethod::Email)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    let link = format!("/_acm/approvals?certificate={}&domain=mail.example.net", urlencoding::encode(&arn));
    let (status, _, _) = mws.raw("GET", &link, &[], b"").await;
    assert_eq!(status, 200);
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let first = d.certificate().unwrap().clone();
    assert_eq!(first.status(), Some(&CertificateStatus::Issued));

    // Inside the renewal window ACM asks the owner again.
    clock(&mws, 140).await;
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.status(), Some(&CertificateStatus::Issued));
    let renewal = c.renewal_summary().unwrap();
    assert_eq!(renewal.renewal_status(), &RenewalStatus::PendingValidation);
    assert_eq!(renewal.domain_validation_options()[0].validation_status().unwrap().as_str(), "PENDING_VALIDATION");
    assert_eq!(c.serial(), first.serial());
    acm.resend_validation_email()
        .certificate_arn(&arn)
        .domain("mail.example.net")
        .validation_domain("example.net")
        .send()
        .await
        .unwrap();

    // Approving the renewal email renews the certificate.
    let (status, _, body) = mws.raw("GET", &link, &[], b"").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let c = d.certificate().unwrap();
    assert_eq!(c.renewal_summary().unwrap().renewal_status(), &RenewalStatus::Success);
    assert_ne!(c.serial(), first.serial());
    assert!(c.not_after().unwrap().secs() > first.not_after().unwrap().secs());
}

/// Every `aws.acm` event on the default bus, delivered to an SQS queue.
async fn acm_event_queue(mws: &Mws) -> (aws_sdk_eventbridge::Client, EventInbox) {
    let cfg = mws.root_sdk_config().await;
    let eb = aws_sdk_eventbridge::Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let url = sqs.create_queue().queue_name("acm-events").send().await.unwrap().queue_url.unwrap();
    let attrs = sqs
        .get_queue_attributes()
        .queue_url(&url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap();
    let queue_arn = attrs.attributes().unwrap()[&aws_sdk_sqs::types::QueueAttributeName::QueueArn].clone();
    let policy = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow",
        "Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":queue_arn}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    eb.put_rule().name("acm").event_pattern(r#"{"source":["aws.acm"]}"#).send().await.unwrap();
    eb.put_targets()
        .rule("acm")
        .targets(aws_sdk_eventbridge::types::Target::builder().id("q").arn(&queue_arn).build().unwrap())
        .send()
        .await
        .unwrap();
    (eb, EventInbox { sqs, url, seen: Vec::new() })
}

/// Events received from an ACM event queue, kept until a test asks for
/// them (they arrive in any order).
struct EventInbox {
    sqs: aws_sdk_sqs::Client,
    url: String,
    seen: Vec<Value>,
}

impl EventInbox {
    /// Wait for an event of `detail_type` about `arn`.
    async fn expect(&mut self, detail_type: &str, arn: &str) -> Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(i) = self.seen.iter().position(|e| e["detail-type"] == detail_type && e["resources"][0] == arn)
            {
                return self.seen.remove(i);
            }
            assert!(std::time::Instant::now() < deadline, "no {detail_type} event for {arn}: {:?}", self.seen);
            let r = self.sqs.receive_message().queue_url(&self.url).max_number_of_messages(10).send().await.unwrap();
            if r.messages().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            for m in r.messages() {
                self.sqs
                    .delete_message()
                    .queue_url(&self.url)
                    .receipt_handle(m.receipt_handle().unwrap())
                    .send()
                    .await
                    .unwrap();
                self.seen.push(serde_json::from_str(m.body().unwrap()).unwrap());
            }
        }
    }
}

#[tokio::test]
async fn certificate_events_and_days_to_expiry_metric() {
    let mws = Mws::start().await;
    let (acm, r53) = clients(&mws).await;
    let (eb, mut inbox) = acm_event_queue(&mws).await;
    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    let zone_id = zone(&r53, "events.example.org").await;
    let issued = acm
        .request_certificate()
        .domain_name("events.example.org")
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    publish_validation_records(&acm, &r53, &zone_id, &issued).await;
    let (cert, key) = self_signed(&["short.example.org"], 20);
    let imported = acm
        .import_certificate()
        .certificate(Blob::new(cert.as_bytes()))
        .private_key(Blob::new(key.serialize_pem().as_bytes()))
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();

    // Issuance happens in the background once the record is in Route 53.
    let e = inbox.expect("ACM Certificate Available", &issued).await;
    assert_eq!(e["source"], "aws.acm");
    assert_eq!(e["detail"]["Action"], "ISSUANCE");
    assert_eq!(e["detail"]["CertificateType"], "AMAZON_ISSUED");
    assert_eq!(e["detail"]["CommonName"], "events.example.org");
    assert_eq!(e["detail"]["DomainValidationMethod"], "DNS");
    assert_eq!(e["detail"]["DaysToExpiry"], 198);
    assert_eq!(e["detail"]["InUse"], false);
    let e = inbox.expect("ACM Certificate Available", &imported).await;
    assert_eq!(e["detail"]["Action"], "IMPORT");
    assert_eq!(e["detail"]["CertificateType"], "IMPORTED");

    // DaysToExpiry in AWS/CertificateManager, per certificate.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let stats = loop {
        let stats = cw
            .get_metric_statistics()
            .namespace("AWS/CertificateManager")
            .metric_name("DaysToExpiry")
            .dimensions(aws_sdk_cloudwatch::types::Dimension::builder().name("CertificateArn").value(&imported).build())
            .start_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono_now() - 3600))
            .end_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono_now() + 3600))
            .period(60)
            .statistics(aws_sdk_cloudwatch::types::Statistic::Minimum)
            .send()
            .await
            .unwrap();
        if !stats.datapoints().is_empty() {
            break stats;
        }
        assert!(std::time::Instant::now() < deadline, "no DaysToExpiry metric");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    assert_eq!(stats.datapoints()[0].minimum(), Some(19.0));
    let metrics = cw.list_metrics().namespace("AWS/CertificateManager").send().await.unwrap();
    assert_eq!(metrics.metrics().len(), 2);

    // Expiry happens on the clock, with nobody calling ACM.
    clock(&mws, 25).await;
    eb.list_rules().send().await.unwrap();
    let e = inbox.expect("ACM Certificate Expired", &imported).await;
    assert_eq!(e["detail"]["CommonName"], "short.example.org");

    // So does managed renewal: the validation record is still there.
    clock(&mws, 120).await;
    eb.list_rules().send().await.unwrap();
    let e = inbox.expect("ACM Certificate Available", &issued).await;
    assert_eq!(e["detail"]["Action"], "RENEWAL");
    let d = acm.describe_certificate().certificate_arn(&imported).send().await.unwrap();
    assert_eq!(d.certificate().unwrap().status(), Some(&CertificateStatus::Expired));
}

#[tokio::test]
async fn renewal_that_needs_the_owner_sends_an_event() {
    let mws = Mws::start().await;
    let (acm, r53) = clients(&mws).await;
    let (eb, mut inbox) = acm_event_queue(&mws).await;
    let zone_id = zone(&r53, "stuck.example.org").await;
    let arn = acm
        .request_certificate()
        .domain_name("stuck.example.org")
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    publish_validation_records(&acm, &r53, &zone_id, &arn).await;
    let d = acm.describe_certificate().certificate_arn(&arn).send().await.unwrap();
    let rr = d.certificate().unwrap().domain_validation_options()[0].resource_record().unwrap().clone();
    let set = ResourceRecordSet::builder()
        .name(rr.name())
        .r#type(RrType::Cname)
        .ttl(300)
        .resource_records(ResourceRecord::builder().value(rr.value()).build().unwrap())
        .build()
        .unwrap();
    r53.change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(
            ChangeBatch::builder()
                .changes(Change::builder().action(ChangeAction::Delete).resource_record_set(set).build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    clock(&mws, 145).await;
    eb.list_rules().send().await.unwrap();
    let e = inbox.expect("ACM Certificate Renewal Action Required", &arn).await;
    assert_eq!(e["detail"]["RenewalStatus"], "PENDING_AUTO_RENEWAL");
    assert_eq!(e["detail"]["DomainValidationMethod"], "DNS");
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}
