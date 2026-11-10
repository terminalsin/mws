//! STS fidelity through the official SDKs: MFA-protected role trust,
//! resource control policies and global condition keys on federated
//! assumptions, SAML source identity, and tokens stamped on the emulated
//! clock.

use aws_sdk_organizations::types::PolicyType;
use aws_sdk_organizations::Client as Orgs;
use aws_sdk_sts::error::ProvideErrorMetadata;
use base64::Engine;
use mws_e2e::{jwt, sts_config, user_with_policy, Mws};
use serde_json::{json, Value};

use crate::iam_advanced::{base32_decode, totp};

const ACCOUNT: &str = "123456789012";
const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::test]
async fn mfa_protected_assume_role_sees_the_new_mfa() {
    let mws = Mws::start().await;
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    // The caller's own policy also requires MFA: it sees the code too.
    let (_, user_cfg) = user_with_policy(
        &mws,
        "alice",
        Some(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}"#,
        ),
    )
    .await;
    let device = iam.create_virtual_mfa_device().virtual_mfa_device_name("alice-phone").send().await.unwrap();
    let device = device.virtual_mfa_device().unwrap();
    let serial = device.serial_number().to_string();
    let seed = base32_decode(std::str::from_utf8(device.base32_string_seed().unwrap().as_ref()).unwrap());
    iam.enable_mfa_device()
        .user_name("alice")
        .serial_number(&serial)
        .authentication_code1(totp(&seed, -2))
        .authentication_code2(totp(&seed, -1))
        .send()
        .await
        .unwrap();

    // The standard cross-account MFA trust pattern.
    let trust = json!({"Version": "2012-10-17", "Statement": {"Effect": "Allow",
        "Principal": {"AWS": format!("arn:aws:iam::{ACCOUNT}:user/alice")}, "Action": "sts:AssumeRole",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}, "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}}});
    iam.create_role().role_name("break-glass").assume_role_policy_document(trust.to_string()).send().await.unwrap();
    let role_arn = format!("arn:aws:iam::{ACCOUNT}:role/break-glass");

    let sts = aws_sdk_sts::Client::new(&user_cfg);
    let err = sts.assume_role().role_arn(&role_arn).role_session_name("ops").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"), "{err:?}");
    // A wrong code fails the MFA check before any policy is evaluated.
    let err = sts
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name("ops")
        .serial_number(&serial)
        .token_code("000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(
        err.message().unwrap().starts_with("MultiFactorAuthentication failed with invalid MFA one time pass code."),
        "{err:?}"
    );
    let out = sts
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name("ops")
        .serial_number(&serial)
        .token_code(totp(&seed, 0))
        .send()
        .await
        .unwrap();
    // The session is MFA-authenticated.
    let session_iam = aws_sdk_iam::Client::new(&sts_config(&mws, out.credentials().unwrap()).await);
    iam.put_role_policy()
        .role_name("break-glass")
        .policy_name("mfa-reads")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:GetRole","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}"#,
        )
        .send()
        .await
        .unwrap();
    session_iam.get_role().role_name("break-glass").send().await.unwrap();
}

/// An organization with one member account, and admin credentials in it.
async fn org_with_member(mws: &Mws) -> (Orgs, String, String, aws_config::SdkConfig) {
    let orgs = Orgs::new(&mws.root_sdk_config().await);
    orgs.create_organization().send().await.unwrap();
    let root_id = orgs.list_roots().send().await.unwrap().roots()[0].id().unwrap().to_string();
    let out = orgs.create_account().email("data@example.com").account_name("data").send().await.unwrap();
    let request_id = out.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let account = status.create_account_status().unwrap().account_id().unwrap().to_string();
    let (_, admin) = user_with_policy(mws, "admin", Some(ADMIN)).await;
    let creds = aws_sdk_sts::Client::new(&admin)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
        .role_session_name("ops")
        .send()
        .await
        .unwrap();
    let member = sts_config(mws, creds.credentials().unwrap()).await;
    (orgs, root_id, account, member)
}

#[tokio::test]
async fn resource_control_policies_and_global_keys_apply_to_web_identity() {
    let config = mws::Config { skip_federation_signature_verification: true, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let (orgs, root_id, account, member) = org_with_member(&mws).await;
    let member_iam = aws_sdk_iam::Client::new(&member);
    let host = "token.actions.githubusercontent.com";
    let provider = member_iam
        .create_open_id_connect_provider()
        .url(format!("https://{host}"))
        .client_id_list("sts.amazonaws.com")
        .thumbprint_list("6938fd4d98bab03faadb97b34396831e3780aea1")
        .send()
        .await
        .unwrap();
    let provider_arn = provider.open_id_connect_provider_arn().unwrap().to_string();
    // Global request keys are present for the unsigned federated caller.
    let trust = json!({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Principal": {"Federated": provider_arn},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1", "aws:ResourceAccount": account},
            "Bool": {"aws:SecureTransport": "false"}, "DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}}}});
    member_iam.create_role().role_name("ci").assume_role_policy_document(trust.to_string()).send().await.unwrap();
    let role_arn = format!("arn:aws:iam::{account}:role/ci");
    let token = |sub: &str| {
        jwt(json!({"iss": format!("https://{host}"), "sub": sub, "aud": "sts.amazonaws.com", "exp": now_secs() + 600}))
    };
    let sts = aws_sdk_sts::Client::new(&mws.root_sdk_config().await);
    let assume = |token: String| {
        sts.assume_role_with_web_identity()
            .role_arn(&role_arn)
            .role_session_name("gha")
            .web_identity_token(token)
            .send()
    };
    assume(token("repo:acme/app:ref:refs/heads/main")).await.unwrap();
    assume(token("repo:evil/app:ref:refs/heads/main")).await.unwrap();

    // A data-perimeter RCP: only the organization's own repositories.
    orgs.enable_policy_type().root_id(&root_id).policy_type(PolicyType::ResourceControlPolicy).send().await.unwrap();
    let rcp = json!({"Version": "2012-10-17", "Statement": {"Effect": "Deny", "Principal": "*",
        "Action": "sts:AssumeRoleWithWebIdentity", "Resource": "*",
        "Condition": {"StringNotLike": {format!("{host}:sub"): "repo:acme/*"}}}});
    let rcp = orgs
        .create_policy()
        .name("github-perimeter")
        .description("Only acme repositories")
        .r#type(PolicyType::ResourceControlPolicy)
        .content(rcp.to_string())
        .send()
        .await
        .unwrap();
    let rcp_id = rcp.policy().unwrap().policy_summary().unwrap().id().unwrap().to_string();
    orgs.attach_policy().policy_id(&rcp_id).target_id(&account).send().await.unwrap();
    assume(token("repo:acme/app:ref:refs/heads/main")).await.unwrap();
    let err = assume(token("repo:evil/app:ref:refs/heads/main")).await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(err.message(), Some("Not authorized to perform sts:AssumeRoleWithWebIdentity"));
}

fn saml_metadata(entity: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{entity}/sso"/></md:IDPSSODescriptor><!-- {} --></md:EntityDescriptor>"#,
        "x".repeat(1000)
    )
}

/// An unsigned SAML response (MWS runs with signature checks off).
fn saml_response(issuer: &str, role: &str, provider: &str, source_identity: Option<&str>) -> String {
    let source = source_identity
        .map(|s| {
            format!(
                r#"<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SourceIdentity"><saml:AttributeValue>{s}</saml:AttributeValue></saml:Attribute>"#
            )
        })
        .unwrap_or_default();
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">alice</saml:NameID><saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="https://signin.aws.amazon.com/saml" NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://signin.aws.amazon.com/saml</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role"><saml:AttributeValue>{role},{provider}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml:AttributeValue>alice</saml:AttributeValue></saml:Attribute>{source}</saml:AttributeStatement></saml:Assertion></samlp:Response>"#
    );
    B64.encode(xml)
}

#[tokio::test]
async fn saml_source_identity_needs_set_source_identity() {
    let config = mws::Config { skip_federation_signature_verification: true, ..Default::default() };
    let mws = Mws::start_with(config).await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let issuer = "https://idp.example.test";
    let created = iam.create_saml_provider().name("corp").saml_metadata_document(saml_metadata(issuer)).send().await;
    let provider = created.unwrap().saml_provider_arn().unwrap().to_string();
    let trust = |actions: Value| {
        json!({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Principal": {"Federated": provider},
            "Action": actions, "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}}})
        .to_string()
    };
    iam.create_role()
        .role_name("sso")
        .assume_role_policy_document(trust(json!("sts:AssumeRoleWithSAML")))
        .send()
        .await
        .unwrap();
    let role_arn = format!("arn:aws:iam::{ACCOUNT}:role/sso");
    let sts = aws_sdk_sts::Client::new(&cfg);
    let assume = |source: Option<&str>| {
        sts.assume_role_with_saml()
            .role_arn(&role_arn)
            .principal_arn(&provider)
            .saml_assertion(saml_response(issuer, &role_arn, &provider, source))
            .send()
    };
    let out = assume(None).await.unwrap();
    assert_eq!(out.source_identity(), None);
    let err = assume(Some("alice@example.test")).await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert_eq!(err.message(), Some("Not authorized to perform sts:AssumeRoleWithSAML"));

    iam.update_assume_role_policy()
        .role_name("sso")
        .policy_document(trust(json!(["sts:AssumeRoleWithSAML", "sts:SetSourceIdentity"])))
        .send()
        .await
        .unwrap();
    let out = assume(Some("alice@example.test")).await.unwrap();
    assert_eq!(out.source_identity(), Some("alice@example.test"));
}

#[tokio::test]
async fn web_identity_tokens_follow_the_emulated_clock() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let sts = aws_sdk_sts::Client::new(&cfg);
    let issuer = iam.enable_outbound_web_identity_federation().send().await.unwrap();
    let issuer = issuer.issuer_identifier().unwrap().to_string();
    let provider =
        iam.create_open_id_connect_provider().url(&issuer).client_id_list("https://api.example.test").send().await;
    let provider_arn = provider.unwrap().open_id_connect_provider_arn().unwrap().to_string();
    let trust = json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Federated":provider_arn},"Action":"sts:AssumeRoleWithWebIdentity"}});
    iam.create_role().role_name("outbound").assume_role_policy_document(trust.to_string()).send().await.unwrap();

    // Two days ahead: far past any token's lifetime on the wall clock.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds": 172800}"#)).await;
    assert_eq!(status, 200);
    let out = sts
        .get_web_identity_token()
        .audience("https://api.example.test")
        .signing_algorithm("RS256")
        .duration_seconds(300)
        .send()
        .await
        .unwrap();
    let token = out.web_identity_token().unwrap();
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let iat = claims["iat"].as_i64().unwrap();
    assert!(iat >= now_secs() + 172_800 - 60, "iat {iat} is not on the emulated clock");
    assert_eq!(claims["exp"].as_i64().unwrap() - iat, 300);
    assert_eq!(out.expiration().unwrap().secs(), claims["exp"].as_i64().unwrap());
    // MWS accepts its own fresh token.
    sts.assume_role_with_web_identity()
        .role_arn(format!("arn:aws:iam::{ACCOUNT}:role/outbound"))
        .role_session_name("loop")
        .web_identity_token(token)
        .send()
        .await
        .unwrap();
}
