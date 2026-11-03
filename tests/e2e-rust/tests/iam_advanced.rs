//! IAM credentials, account settings, SAML, access advisor, service-linked
//! roles, delegation requests and the STS operations that build on them,
//! through the official Rust SDKs.

use aws_sdk_iam::error::ProvideErrorMetadata;
use aws_sdk_iam::primitives::Blob;
use aws_sdk_iam::types::{DelegationPermission, EncodingType, GlobalEndpointTokenVersion, ReportStateType, StatusType};
use base64::Engine;
use mws_e2e::{sts_config, Mws};
use serde_json::{json, Value};

const ACCOUNT: &str = "123456789012";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn base32_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut bits, mut acc, mut out) = (0u32, 0u64, vec![]);
    for c in s.trim_end_matches('=').bytes() {
        acc = (acc << 5) | ALPHABET.iter().position(|a| *a == c).unwrap() as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// RFC 6238 TOTP (SHA-1, 6 digits) at `offset` 30-second steps from now.
fn totp(seed: &[u8], offset: i64) -> String {
    let step = (now_secs() / 30 + offset) as u64;
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let mac = aws_lc_rs::hmac::sign(&key, &step.to_be_bytes());
    let h = mac.as_ref();
    let o = (h[19] & 0xf) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]) % 1_000_000;
    format!("{n:06}")
}

#[tokio::test]
async fn virtual_mfa_gates_session_tokens() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    iam.create_user().user_name("mfa-user").send().await.unwrap();
    iam.put_user_policy()
        .user_name("mfa-user")
        .policy_name("mfa-only")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}"#,
        )
        .send()
        .await
        .unwrap();
    let key = iam.create_access_key().user_name("mfa-user").send().await.unwrap();
    let key = key.access_key().unwrap();

    let device = iam.create_virtual_mfa_device().virtual_mfa_device_name("phone").send().await.unwrap();
    let device = device.virtual_mfa_device().unwrap();
    let serial = device.serial_number().to_string();
    assert_eq!(serial, format!("arn:aws:iam::{ACCOUNT}:mfa/phone"));
    assert!(device.qr_code_png().unwrap().as_ref().starts_with(b"\x89PNG"));
    let seed = base32_decode(std::str::from_utf8(device.base32_string_seed().unwrap().as_ref()).unwrap());

    let err = iam
        .enable_mfa_device()
        .user_name("mfa-user")
        .serial_number(&serial)
        .authentication_code1("000000")
        .authentication_code2("000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidAuthenticationCode"));
    iam.enable_mfa_device()
        .user_name("mfa-user")
        .serial_number(&serial)
        .authentication_code1(totp(&seed, -2))
        .authentication_code2(totp(&seed, -1))
        .send()
        .await
        .unwrap();
    let listed = iam.list_mfa_devices().user_name("mfa-user").send().await.unwrap();
    assert_eq!(listed.mfa_devices()[0].serial_number(), serial);

    let user_sts = aws_sdk_sts::Client::new(&mws.sdk_config(key.access_key_id(), key.secret_access_key(), None).await);
    let err = user_sts.get_session_token().serial_number(&serial).token_code("123456").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    let creds = user_sts.get_session_token().serial_number(&serial).token_code(totp(&seed, 0)).send().await.unwrap();
    // Without MFA the policy condition fails; the MFA session passes it.
    let plain = aws_sdk_iam::Client::new(&mws.sdk_config(key.access_key_id(), key.secret_access_key(), None).await);
    assert_eq!(plain.get_user().send().await.unwrap_err().code(), Some("AccessDenied"));
    let session_iam = aws_sdk_iam::Client::new(&sts_config(&mws, creds.credentials().unwrap()).await);
    assert_eq!(session_iam.get_user().send().await.unwrap().user().unwrap().user_name(), "mfa-user");

    let summary = iam.get_account_summary().send().await.unwrap();
    let map = summary.summary_map().unwrap();
    assert_eq!(map[&aws_sdk_iam::types::SummaryKeyType::MfaDevicesInUse], 1);

    let err = iam.delete_user().user_name("mfa-user").send().await.unwrap_err();
    assert_eq!(err.code(), Some("DeleteConflict"));
    iam.deactivate_mfa_device().user_name("mfa-user").serial_number(&serial).send().await.unwrap();
    iam.delete_virtual_mfa_device().serial_number(&serial).send().await.unwrap();
}

#[tokio::test]
async fn ssh_keys_certificates_and_service_credentials() {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::KeyPair;
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_user().user_name("dev").send().await.unwrap();

    // SSH key uploaded as PEM, returned in either encoding.
    let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let spki: aws_lc_rs::encoding::PublicKeyX509Der = rsa.public_key().as_der().unwrap();
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", B64.encode(spki.as_ref()));
    let up = iam.upload_ssh_public_key().user_name("dev").ssh_public_key_body(&pem).send().await.unwrap();
    let ssh = up.ssh_public_key().unwrap();
    assert!(ssh.ssh_public_key_id().starts_with("APKA"));
    assert_eq!(ssh.fingerprint().matches(':').count(), 15);
    let got = iam
        .get_ssh_public_key()
        .user_name("dev")
        .ssh_public_key_id(ssh.ssh_public_key_id())
        .encoding(EncodingType::Ssh)
        .send()
        .await
        .unwrap();
    assert!(got.ssh_public_key().unwrap().ssh_public_key_body().starts_with("ssh-rsa AAAA"));
    let dup = iam.upload_ssh_public_key().user_name("dev").ssh_public_key_body(&pem).send().await.unwrap_err();
    assert_eq!(dup.code(), Some("DuplicateSSHPublicKey"));
    iam.update_ssh_public_key()
        .user_name("dev")
        .ssh_public_key_id(ssh.ssh_public_key_id())
        .status(StatusType::Inactive)
        .send()
        .await
        .unwrap();

    // Signing certificate and server certificate from one self-signed cert.
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["www.example.test".into()]).unwrap().self_signed(&key).unwrap();
    let signing = iam.upload_signing_certificate().user_name("dev").certificate_body(cert.pem()).send().await.unwrap();
    assert_eq!(signing.certificate().unwrap().status(), &StatusType::Active);
    let err = iam.upload_signing_certificate().user_name("dev").certificate_body("junk").send().await.unwrap_err();
    assert_eq!(err.code(), Some("MalformedCertificate"));

    let other = rcgen::KeyPair::generate().unwrap();
    let err = iam
        .upload_server_certificate()
        .server_certificate_name("web")
        .certificate_body(cert.pem())
        .private_key(other.serialize_pem())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("KeyPairMismatch"));
    let sc = iam
        .upload_server_certificate()
        .server_certificate_name("web")
        .path("/cloudfront/")
        .certificate_body(cert.pem())
        .private_key(key.serialize_pem())
        .send()
        .await
        .unwrap();
    let meta = sc.server_certificate_metadata().unwrap();
    assert_eq!(meta.arn(), format!("arn:aws:iam::{ACCOUNT}:server-certificate/cloudfront/web"));
    assert!(meta.expiration().is_some());
    iam.update_server_certificate()
        .server_certificate_name("web")
        .new_server_certificate_name("web2")
        .send()
        .await
        .unwrap();
    let listed = iam.list_server_certificates().path_prefix("/cloudfront/").send().await.unwrap();
    assert_eq!(listed.server_certificate_metadata_list()[0].server_certificate_name(), "web2");
    iam.delete_server_certificate().server_certificate_name("web2").send().await.unwrap();

    // Service-specific credentials.
    let created = iam
        .create_service_specific_credential()
        .user_name("dev")
        .service_name("codecommit.amazonaws.com")
        .send()
        .await
        .unwrap();
    let c = created.service_specific_credential().unwrap();
    assert_eq!(c.service_user_name(), format!("dev-at-{ACCOUNT}"));
    assert!(!c.service_password().is_empty());
    let reset = iam
        .reset_service_specific_credential()
        .user_name("dev")
        .service_specific_credential_id(c.service_specific_credential_id())
        .send()
        .await
        .unwrap();
    assert_ne!(reset.service_specific_credential().unwrap().service_password(), c.service_password());
    let err = iam
        .create_service_specific_credential()
        .user_name("dev")
        .service_name("ec2.amazonaws.com")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("NotSupportedService"));

    let err = iam.delete_user().user_name("dev").send().await.unwrap_err();
    assert_eq!(err.code(), Some("DeleteConflict"));
}

#[tokio::test]
async fn password_policy_change_password_and_credential_report() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);

    let err = iam.get_account_password_policy().send().await.unwrap_err();
    assert_eq!(err.code(), Some("NoSuchEntity"));
    iam.update_account_password_policy()
        .minimum_password_length(12)
        .require_symbols(true)
        .allow_users_to_change_password(true)
        .password_reuse_prevention(3)
        .max_password_age(90)
        .send()
        .await
        .unwrap();
    let p = iam.get_account_password_policy().send().await.unwrap();
    let p = p.password_policy().unwrap();
    assert_eq!(p.minimum_password_length(), Some(12));
    assert!(p.expire_passwords());

    iam.create_user().user_name("pw").send().await.unwrap();
    let err = iam.create_login_profile().user_name("pw").password("short!").send().await.unwrap_err();
    assert_eq!(err.code(), Some("PasswordPolicyViolation"));
    iam.create_login_profile().user_name("pw").password("long-enough-pw!").send().await.unwrap();

    let key = iam.create_access_key().user_name("pw").send().await.unwrap();
    let key = key.access_key().unwrap();
    let as_user = aws_sdk_iam::Client::new(&mws.sdk_config(key.access_key_id(), key.secret_access_key(), None).await);
    as_user.change_password().old_password("long-enough-pw!").new_password("another-long-pw!").send().await.unwrap();
    let err = as_user
        .change_password()
        .old_password("another-long-pw!")
        .new_password("long-enough-pw!")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("PasswordPolicyViolation"));
    let err = iam.change_password().old_password("a").new_password("b").send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidUserType"));

    let err = iam.get_credential_report().send().await.unwrap_err();
    assert_eq!(err.code(), Some("ReportNotPresent"));
    let started = iam.generate_credential_report().send().await.unwrap();
    assert_eq!(started.state(), Some(&ReportStateType::Started));
    let again = iam.generate_credential_report().send().await.unwrap();
    assert_eq!(again.state(), Some(&ReportStateType::Complete));
    let report = iam.get_credential_report().send().await.unwrap();
    let csv = String::from_utf8(report.content().unwrap().as_ref().to_vec()).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines[0].starts_with("user,arn,user_creation_time,password_enabled"));
    assert!(lines[1].starts_with("<root_account>,"));
    let pw_row: Vec<&str> = lines.iter().find(|l| l.starts_with("pw,")).unwrap().split(',').collect();
    assert_eq!(pw_row[3], "true");
    assert_eq!(pw_row[8], "true");

    iam.set_security_token_service_preferences()
        .global_endpoint_token_version(GlobalEndpointTokenVersion::V2Token)
        .send()
        .await
        .unwrap();
    let summary = iam.get_account_summary().send().await.unwrap();
    assert_eq!(summary.summary_map().unwrap()[&aws_sdk_iam::types::SummaryKeyType::GlobalEndpointTokenVersion], 2);

    iam.delete_account_password_policy().send().await.unwrap();
}

fn saml_metadata(entity: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><!-- {} --><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{entity}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
        "x".repeat(1000)
    )
}

fn saml_response(issuer: &str, role: &str, provider: &str, session: &str) -> String {
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">alice@example.test</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="https://signin.aws.amazon.com/saml" NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://signin.aws.amazon.com/saml</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><saml:AttributeValue>{role},{provider}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml:AttributeValue>{session}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#
    );
    B64.encode(xml)
}

#[tokio::test]
async fn saml_provider_and_assume_role_with_saml() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let issuer = "https://idp.example.test";

    let err = iam.create_saml_provider().name("bad").saml_metadata_document("x".repeat(1000)).send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidInput"));
    let created =
        iam.create_saml_provider().name("corp").saml_metadata_document(saml_metadata(issuer)).send().await.unwrap();
    let provider = created.saml_provider_arn().unwrap().to_string();
    assert_eq!(provider, format!("arn:aws:iam::{ACCOUNT}:saml-provider/corp"));
    let got = iam.get_saml_provider().saml_provider_arn(&provider).send().await.unwrap();
    assert!(got.valid_until().unwrap().secs() > now_secs() + 50 * 365 * 86400);
    assert_eq!(iam.list_saml_providers().send().await.unwrap().saml_provider_list().len(), 1);

    let trust = json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": provider},
        "Action": "sts:AssumeRoleWithSAML", "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}}]});
    let role = iam.create_role().role_name("sso").assume_role_policy_document(trust.to_string()).send().await.unwrap();
    let role_arn = role.role().unwrap().arn().to_string();

    let sts = aws_sdk_sts::Client::new(&cfg);
    let out = sts
        .assume_role_with_saml()
        .role_arn(&role_arn)
        .principal_arn(&provider)
        .saml_assertion(saml_response(issuer, &role_arn, &provider, "alice"))
        .send()
        .await
        .unwrap();
    assert_eq!(out.assumed_role_user().unwrap().arn(), format!("arn:aws:sts::{ACCOUNT}:assumed-role/sso/alice"));
    assert_eq!(out.subject(), Some("alice@example.test"));
    assert_eq!(out.subject_type(), Some("persistent"));
    assert_eq!(out.issuer(), Some(issuer));
    assert!(out.name_qualifier().is_some());
    let me = aws_sdk_sts::Client::new(&sts_config(&mws, out.credentials().unwrap()).await);
    assert!(me.get_caller_identity().send().await.unwrap().arn().unwrap().ends_with("assumed-role/sso/alice"));

    // An assertion from another issuer is refused.
    let err = sts
        .assume_role_with_saml()
        .role_arn(&role_arn)
        .principal_arn(&provider)
        .saml_assertion(saml_response("https://evil.example.test", &role_arn, &provider, "alice"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("InvalidIdentityToken"));
}

#[tokio::test]
async fn service_linked_roles_and_access_advisor() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);

    let slr =
        iam.create_service_linked_role().aws_service_name("elasticloadbalancing.amazonaws.com").send().await.unwrap();
    let role = slr.role().unwrap();
    assert_eq!(role.role_name(), "AWSServiceRoleForElasticLoadBalancing");
    assert_eq!(role.path(), "/aws-service-role/elasticloadbalancing.amazonaws.com/");
    let err = iam.delete_role().role_name(role.role_name()).send().await.unwrap_err();
    assert_eq!(err.code(), Some("UnmodifiableEntity"));
    let task = iam.delete_service_linked_role().role_name(role.role_name()).send().await.unwrap();
    let status =
        iam.get_service_linked_role_deletion_status().deletion_task_id(task.deletion_task_id()).send().await.unwrap();
    assert_eq!(status.status().as_str(), "SUCCEEDED");

    let user = iam.create_user().user_name("advisor").send().await.unwrap();
    let user_arn = user.user().unwrap().arn().to_string();
    iam.put_user_policy()
        .user_name("advisor")
        .policy_name("r53")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"route53:List*","Resource":"*"}]}"#,
        )
        .send()
        .await
        .unwrap();
    iam.attach_user_policy()
        .user_name("advisor")
        .policy_arn("arn:aws:iam::aws:policy/IAMReadOnlyAccess")
        .send()
        .await
        .unwrap();
    let job = iam.generate_service_last_accessed_details().arn(&user_arn).send().await.unwrap();
    let details = iam.get_service_last_accessed_details().job_id(job.job_id().unwrap()).send().await.unwrap();
    assert_eq!(details.job_status().as_str(), "COMPLETED");
    let namespaces: Vec<&str> = details.services_last_accessed().iter().map(|s| s.service_namespace()).collect();
    assert_eq!(namespaces, ["iam", "route53"]);

    let granting = iam
        .list_policies_granting_service_access()
        .arn(&user_arn)
        .service_namespaces("route53")
        .service_namespaces("iam")
        .send()
        .await
        .unwrap();
    let entries = granting.policies_granting_service_access();
    let route53 = entries.iter().find(|e| e.service_namespace() == Some("route53")).unwrap();
    assert_eq!(route53.policies()[0].policy_name(), "r53");
    assert_eq!(route53.policies()[0].policy_type().as_str(), "INLINE");
    let iam_entry = entries.iter().find(|e| e.service_namespace() == Some("iam")).unwrap();
    assert_eq!(iam_entry.policies()[0].policy_arn(), Some("arn:aws:iam::aws:policy/IAMReadOnlyAccess"));

    let err = iam.list_organizations_features().send().await.unwrap_err();
    assert_eq!(err.code(), Some("OrganizationNotFoundException"));
}

#[tokio::test]
async fn outbound_federation_issues_signed_tokens() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sts = aws_sdk_sts::Client::new(&cfg);

    let err = sts
        .get_web_identity_token()
        .audience("https://api.example.test")
        .signing_algorithm("ES384")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("OutboundWebIdentityFederationDisabledException"));
    let enabled = iam.enable_outbound_web_identity_federation().send().await.unwrap();
    let issuer = enabled.issuer_identifier().unwrap().to_string();
    let err = iam.enable_outbound_web_identity_federation().send().await.unwrap_err();
    assert_eq!(err.code(), Some("FeatureEnabled"));

    for alg in ["ES384", "RS256"] {
        let out = sts
            .get_web_identity_token()
            .audience("https://api.example.test")
            .signing_algorithm(alg)
            .duration_seconds(120)
            .send()
            .await
            .unwrap();
        let token = out.web_identity_token().unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header: Value = serde_json::from_slice(&e.decode(parts[0]).unwrap()).unwrap();
        let claims: Value = serde_json::from_slice(&e.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], alg);
        assert_eq!(claims["iss"], issuer);
        assert_eq!(claims["aud"], "https://api.example.test");
        assert_eq!(claims["sub"], format!("arn:aws:iam::{ACCOUNT}:root"));
        assert_eq!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(), 120);
    }

    iam.disable_outbound_web_identity_federation().send().await.unwrap();
    let err = iam.get_outbound_web_identity_federation_info().send().await.unwrap_err();
    assert_eq!(err.code(), Some("FeatureDisabled"));
}

#[tokio::test]
async fn delegation_request_lifecycle() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);

    let created = iam
        .create_delegation_request()
        .description("Partner needs to read Route 53")
        .permissions(
            DelegationPermission::builder().policy_template_arn("arn:aws:iam::aws:policy/IAMReadOnlyAccess").build(),
        )
        .requestor_workflow_id("workflow-1")
        .notification_channel("arn:aws:sns:us-east-1:111122223333:partner")
        .session_duration(3600)
        .send()
        .await
        .unwrap();
    let id = created.delegation_request_id().unwrap().to_string();
    let get = |id: String| {
        let iam = iam.clone();
        async move { iam.get_delegation_request().delegation_request_id(id).send().await.unwrap() }
    };
    assert_eq!(get(id.clone()).await.delegation_request().unwrap().state().unwrap().as_str(), "UNASSIGNED");

    iam.associate_delegation_request().delegation_request_id(&id).send().await.unwrap();
    iam.update_delegation_request().delegation_request_id(&id).notes("looks fine").send().await.unwrap();
    assert_eq!(get(id.clone()).await.delegation_request().unwrap().state().unwrap().as_str(), "PENDING_APPROVAL");
    let err = iam.send_delegation_token().delegation_request_id(&id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("InvalidInput"));
    iam.accept_delegation_request().delegation_request_id(&id).send().await.unwrap();
    iam.send_delegation_token().delegation_request_id(&id).send().await.unwrap();
    let req = get(id.clone()).await;
    assert_eq!(req.delegation_request().unwrap().state().unwrap().as_str(), "FINALIZED");
    let listed = iam.list_delegation_requests().send().await.unwrap();
    assert_eq!(listed.delegation_requests().len(), 1);

    let summary = iam
        .get_human_readable_summary()
        .entity_arn(format!("arn:aws:iam::{ACCOUNT}:delegation-request/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(summary.summary_state().unwrap().as_str(), "AVAILABLE");

    // AWS posts the exchange token to the partner; MWS keeps it in state.
    let (_, state) = mws.control("GET", "/_mws/state", None).await;
    let token = state["services"]["iam"]["delegation_requests"][&id]["token"].as_str().unwrap().to_string();
    let sts = aws_sdk_sts::Client::new(&cfg);
    let out = sts.get_delegated_access_token().trade_in_token(&token).send().await.unwrap();
    assert_eq!(out.assumed_principal(), Some(format!("arn:aws:iam::{ACCOUNT}:root").as_str()));
    let err = sts.get_delegated_access_token().trade_in_token(&token).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ExpiredTradeInTokenException"));

    let err = iam
        .get_role_template_version()
        .template_arn("arn:aws:iam::aws:role-template/Example")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("NoSuchEntity"));
}

#[tokio::test]
async fn new_iam_state_survives_export_and_import() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    iam.create_virtual_mfa_device().virtual_mfa_device_name("kept").send().await.unwrap();
    iam.update_account_password_policy().minimum_password_length(20).send().await.unwrap();
    iam.create_saml_provider()
        .name("kept")
        .saml_metadata_document(saml_metadata("https://kept.test"))
        .send()
        .await
        .unwrap();
    let (_, state) = mws.control("GET", "/_mws/state", None).await;
    mws.control("POST", "/_mws/reset", None).await;
    assert!(iam.get_account_password_policy().send().await.is_err());
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&state.to_string())).await;
    assert_eq!(status, 200);
    let p = iam.get_account_password_policy().send().await.unwrap();
    assert_eq!(p.password_policy().unwrap().minimum_password_length(), Some(20));
    assert_eq!(iam.list_virtual_mfa_devices().send().await.unwrap().virtual_mfa_devices().len(), 1);
    assert_eq!(iam.list_saml_providers().send().await.unwrap().saml_provider_list().len(), 1);
    let _ = Blob::new(vec![]);
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}
