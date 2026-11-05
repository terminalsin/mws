//! IAM Identity Center administration beyond assignments (instance
//! settings, Regions, tags, permission set policies), customer managed
//! applications with trusted token issuers, and the OAuth flows of
//! sso-oidc: authorization code with PKCE, refresh, and `CreateTokenWithIAM`.

use aws_lc_rs::digest;
use aws_sdk_ssoadmin::error::ProvideErrorMetadata;
use aws_sdk_ssoadmin::types::{
    AccessControlAttribute, AccessControlAttributeValue, AuthenticationMethod, AuthenticationMethodType,
    AuthorizationCodeGrant, AuthorizedTokenIssuer, EncryptionConfiguration, Grant, GrantType, IamAuthenticationMethod,
    InstanceAccessControlAttributeConfiguration, JwksRetrievalOption, JwtBearerGrant, KmsKeyType, OidcJwtConfiguration,
    OidcJwtUpdateConfiguration, PermissionsBoundary, PrincipalType, RefreshTokenGrant, Tag, TokenExchangeGrant,
    TrustedTokenIssuerConfiguration, TrustedTokenIssuerType, TrustedTokenIssuerUpdateConfiguration,
    UserBackgroundSessionApplicationStatus,
};
use aws_sdk_ssooidc::Client as Oidc;
use aws_smithy_types::Document;
use base64::Engine;
use mws_e2e::{jwt, user_with_policy, Mws};

use crate::identity_center::{center, center_with};

const REDIRECT: &str = "http://127.0.0.1:8400/callback";

fn abac(key: &str, source: &str) -> InstanceAccessControlAttributeConfiguration {
    InstanceAccessControlAttributeConfiguration::builder()
        .access_control_attributes(
            AccessControlAttribute::builder()
                .key(key)
                .value(AccessControlAttributeValue::builder().source(source).build().unwrap())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

/// Follow the authorization endpoint as a signed-in browser would: the
/// `code` it redirects back with.
async fn authorize(mws: &Mws, query: &[(&str, &str)]) -> (String, String) {
    let q: String = query.iter().map(|(k, v)| format!("{k}={}&", urlencoding::encode(v))).collect();
    let (status, headers, body) = mws.raw("GET", &format!("/authorize?{q}"), &[], b"").await;
    assert_eq!(status, 302, "{}", String::from_utf8_lossy(&body));
    let location = headers.iter().find(|(k, _)| k == "location").unwrap().1.clone();
    assert!(location.starts_with(REDIRECT), "{location}");
    let params: Vec<(String, String)> = location
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap();
            (k.to_string(), urlencoding::decode(v).unwrap().into_owned())
        })
        .collect();
    let get = |k: &str| params.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default();
    (get("code"), get("state"))
}

#[tokio::test]
async fn instance_settings_regions_tags_and_permission_set_policies() {
    let c = center().await;
    let a = &c.admin;
    let inst = c.instance_arn.as_str();

    a.update_instance().instance_arn(inst).name("corp-sso").send().await.unwrap();
    let described = a.describe_instance().instance_arn(inst).send().await.unwrap();
    assert_eq!(described.name(), Some("corp-sso"));
    let err = a.update_instance().instance_arn(inst).permission_sets_enabled(false).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));

    // A customer managed KMS key must let Identity Center use it.
    let kms = aws_sdk_kms::Client::new(&c.admin_config);
    let key = kms.create_key().send().await.unwrap().key_metadata().unwrap().arn().unwrap().to_string();
    let cmk = |key: &str| {
        EncryptionConfiguration::builder().key_type(KmsKeyType::CustomerManagedKey).kms_key_arn(key).build().unwrap()
    };
    let err = a.update_instance().instance_arn(inst).encryption_configuration(cmk(&key)).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    let store_arn = format!("arn:aws:identitystore::123456789012:identitystore/{}", c.store);
    let policy = serde_json::json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"},
        {"Effect": "Allow", "Principal": {"Service": "sso.amazonaws.com"},
         "Action": ["kms:Decrypt", "kms:ReEncryptTo", "kms:ReEncryptFrom", "kms:GenerateDataKeyWithoutPlaintext"],
         "Resource": "*",
         "Condition": {"StringLike": {"kms:EncryptionContext:aws:sso:instance-arn": inst},
                       "StringEquals": {"aws:SourceAccount": "123456789012"}}},
        {"Effect": "Allow", "Principal": {"Service": "identitystore.amazonaws.com"},
         "Action": ["kms:Decrypt", "kms:ReEncryptTo", "kms:ReEncryptFrom", "kms:GenerateDataKeyWithoutPlaintext"],
         "Resource": "*",
         "Condition": {"StringLike": {"kms:EncryptionContext:aws:identitystore:identitystore-arn": store_arn}}},
        {"Effect": "Allow", "Principal": {"Service": ["sso.amazonaws.com", "identitystore.amazonaws.com"]},
         "Action": "kms:DescribeKey", "Resource": "*"}
    ]});
    kms.put_key_policy().key_id(&key).policy(policy.to_string()).send().await.unwrap();
    a.update_instance().instance_arn(inst).encryption_configuration(cmk(&key)).send().await.unwrap();
    let described = a.describe_instance().instance_arn(inst).send().await.unwrap();
    let enc = described.encryption_configuration_details().unwrap();
    assert_eq!(enc.kms_key_arn(), Some(key.as_str()));
    kms.disable_key().key_id(&key).send().await.unwrap();
    let err = a.update_instance().instance_arn(inst).encryption_configuration(cmk(&key)).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    a.update_instance()
        .instance_arn(inst)
        .encryption_configuration(
            EncryptionConfiguration::builder().key_type(KmsKeyType::AwsOwnedKmsKey).build().unwrap(),
        )
        .send()
        .await
        .unwrap();

    // Regions.
    assert_eq!(
        a.add_region().instance_arn(inst).region_name("eu-west-1").send().await.unwrap().status().unwrap().as_str(),
        "ADDING"
    );
    let err = a.add_region().instance_arn(inst).region_name("eu-west-1").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    let region = a.describe_region().instance_arn(inst).region_name("eu-west-1").send().await.unwrap();
    assert_eq!(region.status().unwrap().as_str(), "ACTIVE");
    assert!(!region.is_primary_region());
    let regions = a.list_regions().instance_arn(inst).send().await.unwrap();
    assert_eq!(regions.regions().len(), 2);
    let err = a.remove_region().instance_arn(inst).region_name("us-east-1").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    a.remove_region().instance_arn(inst).region_name("eu-west-1").send().await.unwrap();
    let err = a.describe_region().instance_arn(inst).region_name("eu-west-1").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    // Attributes for access control.
    a.create_instance_access_control_attribute_configuration()
        .instance_arn(inst)
        .instance_access_control_attribute_configuration(abac("Team", "${path:title}"))
        .send()
        .await
        .unwrap();
    let err = a
        .create_instance_access_control_attribute_configuration()
        .instance_arn(inst)
        .instance_access_control_attribute_configuration(abac("Team", "${path:title}"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    a.update_instance_access_control_attribute_configuration()
        .instance_arn(inst)
        .instance_access_control_attribute_configuration(abac("CostCenter", "${path:enterprise.costCenter}"))
        .send()
        .await
        .unwrap();
    let config = a.describe_instance_access_control_attribute_configuration().instance_arn(inst).send().await.unwrap();
    assert_eq!(config.status().unwrap().as_str(), "ENABLED");
    let attrs = config.instance_access_control_attribute_configuration().unwrap().access_control_attributes();
    assert_eq!(attrs[0].key(), "CostCenter");
    a.delete_instance_access_control_attribute_configuration().instance_arn(inst).send().await.unwrap();
    let err = a.describe_instance_access_control_attribute_configuration().instance_arn(inst).send().await;
    assert_eq!(err.unwrap_err().code(), Some("ResourceNotFoundException"));

    // Permission sets.
    let err = a
        .create_permission_set()
        .instance_arn(inst)
        .name("TooLong")
        .session_duration("PT13H")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    let ps = a
        .create_permission_set()
        .instance_arn(inst)
        .name("Dev")
        .description("Developers")
        .relay_state("https://console.aws.amazon.com/")
        .tags(Tag::builder().key("team").value("core").build().unwrap())
        .send()
        .await
        .unwrap();
    let ps = ps.permission_set().unwrap();
    assert_eq!(ps.session_duration(), Some("PT1H"));
    let ps = ps.permission_set_arn().unwrap().to_string();
    assert!(ps.starts_with(&format!("arn:aws:sso:::permissionSet/{}/ps-", inst.rsplit('/').next().unwrap())));
    let err = a.create_permission_set().instance_arn(inst).name("Dev").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    a.update_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .description("All developers")
        .session_duration("PT4H")
        .send()
        .await
        .unwrap();
    let described = a.describe_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await.unwrap();
    let described = described.permission_set().unwrap();
    assert_eq!(described.description(), Some("All developers"));
    assert_eq!(described.session_duration(), Some("PT4H"));
    assert_eq!(
        a.list_permission_sets().instance_arn(inst).send().await.unwrap().permission_sets(),
        std::slice::from_ref(&ps)
    );

    let tags = a.list_tags_for_resource().instance_arn(inst).resource_arn(&ps).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "team");
    a.tag_resource()
        .instance_arn(inst)
        .resource_arn(&ps)
        .tags(Tag::builder().key("env").value("dev").build().unwrap())
        .send()
        .await
        .unwrap();
    a.untag_resource().instance_arn(inst).resource_arn(&ps).tag_keys("team").send().await.unwrap();
    let tags = a.list_tags_for_resource().instance_arn(inst).resource_arn(&ps).send().await.unwrap();
    let keys: Vec<&str> = tags.tags().iter().map(|t| t.key()).collect();
    assert_eq!(keys, ["env"]);

    let readonly = "arn:aws:iam::aws:policy/ReadOnlyAccess";
    a.attach_managed_policy_to_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .managed_policy_arn(readonly)
        .send()
        .await
        .unwrap();
    let err = a
        .attach_managed_policy_to_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .managed_policy_arn(readonly)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    let managed = a.list_managed_policies_in_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await;
    let managed = managed.unwrap();
    assert_eq!(managed.attached_managed_policies()[0].name(), Some("ReadOnlyAccess"));
    a.detach_managed_policy_from_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .managed_policy_arn(readonly)
        .send()
        .await
        .unwrap();

    let err = a
        .put_inline_policy_to_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .inline_policy("{not json")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    a.put_inline_policy_to_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .inline_policy(crate::identity_center::ADMIN)
        .send()
        .await
        .unwrap();
    let inline = a.get_inline_policy_for_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await;
    assert_eq!(inline.unwrap().inline_policy(), Some(crate::identity_center::ADMIN));
    a.delete_inline_policy_from_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await.unwrap();
    let inline = a.get_inline_policy_for_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await;
    assert_eq!(inline.unwrap().inline_policy(), Some(""));

    a.put_permissions_boundary_to_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .permissions_boundary(PermissionsBoundary::builder().managed_policy_arn(readonly).build())
        .send()
        .await
        .unwrap();
    let boundary = a.get_permissions_boundary_for_permission_set().instance_arn(inst).permission_set_arn(&ps).send();
    assert_eq!(boundary.await.unwrap().permissions_boundary().unwrap().managed_policy_arn(), Some(readonly));
    a.delete_permissions_boundary_from_permission_set()
        .instance_arn(inst)
        .permission_set_arn(&ps)
        .send()
        .await
        .unwrap();
    let err = a.get_permissions_boundary_for_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await;
    assert_eq!(err.unwrap_err().code(), Some("ResourceNotFoundException"));

    a.delete_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await.unwrap();
    let err = a.describe_permission_set().instance_arn(inst).permission_set_arn(&ps).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    // An account instance in a member account has no permission sets until
    // they are enabled, and assigns only its own account.
    let member = aws_sdk_ssoadmin::Client::new(&c.member_config().await);
    let account_inst = member.create_instance().name("team").send().await.unwrap();
    let account_inst = account_inst.instance_arn().unwrap().to_string();
    let err = member.create_permission_set().instance_arn(&account_inst).name("X").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    member.update_instance().instance_arn(&account_inst).permission_sets_enabled(true).send().await.unwrap();
    member.create_permission_set().instance_arn(&account_inst).name("X").send().await.unwrap();
    let err = member.create_instance().name("again").send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConflictException"));
    member.delete_instance().instance_arn(&account_inst).send().await.unwrap();
    let err = member.describe_instance().instance_arn(&account_inst).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));
}

#[tokio::test]
async fn authorization_code_with_pkce_and_refresh() {
    let c = center().await;
    let alice = c.user("alice", "Engineer").await;
    let ps = c.permission_set("Dev").await;
    c.assign(&c.member, &ps, PrincipalType::User, &alice).await;

    let oidc = Oidc::new(&c.mws.root_sdk_config().await);
    let client = oidc
        .register_client()
        .client_name("ide")
        .client_type("public")
        .grant_types("authorization_code")
        .grant_types("refresh_token")
        .redirect_uris(REDIRECT)
        .issuer_url(c.start_url())
        .scopes("sso:account:access")
        .send()
        .await
        .unwrap();
    let (id, secret) = (client.client_id().unwrap(), client.client_secret().unwrap());
    assert!(client.client_secret_expires_at() > client.client_id_issued_at());

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-and-some-more";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref());
    let (code, state) = authorize(
        &c.mws,
        &[
            ("response_type", "code"),
            ("client_id", id),
            ("redirect_uri", REDIRECT),
            ("state", "xyz"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scopes", "sso:account:access"),
            ("username", "alice"),
        ],
    )
    .await;
    assert_eq!(state, "xyz");

    let exchange = |verifier: &str| {
        oidc.create_token()
            .client_id(id)
            .client_secret(secret)
            .grant_type("authorization_code")
            .code(&code)
            .redirect_uri(REDIRECT)
            .code_verifier(verifier)
            .send()
    };
    let err = exchange("wrong-verifier").await.unwrap_err();
    assert_eq!(aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err), Some("InvalidGrantException"));
    let (code2, _) = authorize(
        &c.mws,
        &[
            ("response_type", "code"),
            ("client_id", id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("username", "alice"),
        ],
    )
    .await;
    let out = oidc
        .create_token()
        .client_id(id)
        .client_secret(secret)
        .grant_type("authorization_code")
        .code(&code2)
        .redirect_uri(REDIRECT)
        .code_verifier(verifier)
        .send()
        .await
        .unwrap();
    assert_eq!(out.expires_in(), 3600);
    let refresh = out.refresh_token().unwrap();

    let portal = aws_sdk_sso::Client::new(&c.mws.root_sdk_config().await);
    let accounts = portal.list_accounts().access_token(out.access_token().unwrap()).send().await.unwrap();
    assert_eq!(accounts.account_list()[0].account_id(), Some(c.member.as_str()));

    let refreshed = oidc
        .create_token()
        .client_id(id)
        .client_secret(secret)
        .grant_type("refresh_token")
        .refresh_token(refresh)
        .send()
        .await
        .unwrap();
    portal.list_accounts().access_token(refreshed.access_token().unwrap()).send().await.unwrap();
    // A refresh token is good once.
    let err = oidc
        .create_token()
        .client_id(id)
        .client_secret(secret)
        .grant_type("refresh_token")
        .refresh_token(refresh)
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err), Some("InvalidGrantException"));

    // The client didn't register the device code grant.
    let err =
        oidc.start_device_authorization().client_id(id).client_secret(secret).start_url(c.start_url()).send().await;
    assert_eq!(
        aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err.unwrap_err()),
        Some("UnauthorizedClientException")
    );

    // Device codes the user denies stay denied.
    let client = oidc.register_client().client_name("cli").client_type("public").send().await.unwrap();
    let (id, secret) = (client.client_id().unwrap(), client.client_secret().unwrap());
    let auth =
        oidc.start_device_authorization().client_id(id).client_secret(secret).start_url(c.start_url()).send().await;
    let auth = auth.unwrap();
    let form = format!("user_code={}&username=alice&decision=deny", auth.user_code().unwrap());
    let headers = [("Content-Type", "application/x-www-form-urlencoded")];
    let (status, _, _) = c.mws.raw("POST", "/_aws/sso-oidc/device", &headers, form.as_bytes()).await;
    assert_eq!(status, 200);
    let err = oidc
        .create_token()
        .client_id(id)
        .client_secret(secret)
        .grant_type("urn:ietf:params:oauth:grant-type:device_code")
        .device_code(auth.device_code().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err), Some("AccessDeniedException"));
}

#[tokio::test]
async fn applications_and_create_token_with_iam() {
    let config = mws::Config { skip_federation_signature_verification: true, ..Default::default() };
    let c = center_with(Mws::start_with(config).await).await;
    let a = &c.admin;
    let inst = c.instance_arn.as_str();
    let alice = c.user("alice", "Engineer").await;
    let bob = c.user("bob", "Analyst").await;

    let providers = a.list_application_providers().send().await.unwrap();
    let custom = "arn:aws:sso::aws:applicationProvider/custom";
    assert!(providers.application_providers().iter().any(|p| p.application_provider_arn() == custom));
    let provider = a.describe_application_provider().application_provider_arn(custom).send().await.unwrap();
    assert_eq!(provider.federation_protocol().unwrap().as_str(), "OAUTH");

    // A trusted token issuer for the company's own identity provider.
    let tti = a
        .create_trusted_token_issuer()
        .instance_arn(inst)
        .name("corp-idp")
        .trusted_token_issuer_type(TrustedTokenIssuerType::OidcJwt)
        .trusted_token_issuer_configuration(TrustedTokenIssuerConfiguration::OidcJwtConfiguration(
            OidcJwtConfiguration::builder()
                .issuer_url("https://idp.example.com")
                .claim_attribute_path("sub")
                .identity_store_attribute_path("userName")
                .jwks_retrieval_option(JwksRetrievalOption::OpenIdDiscovery)
                .build()
                .unwrap(),
        ))
        .send()
        .await
        .unwrap();
    let tti = tti.trusted_token_issuer_arn().unwrap().to_string();
    a.update_trusted_token_issuer()
        .trusted_token_issuer_arn(&tti)
        .trusted_token_issuer_configuration(TrustedTokenIssuerUpdateConfiguration::OidcJwtConfiguration(
            OidcJwtUpdateConfiguration::builder()
                .claim_attribute_path("email")
                .identity_store_attribute_path("emails.value")
                .build(),
        ))
        .send()
        .await
        .unwrap();
    let described = a.describe_trusted_token_issuer().trusted_token_issuer_arn(&tti).send().await.unwrap();
    assert_eq!(described.name(), Some("corp-idp"));
    let Some(TrustedTokenIssuerConfiguration::OidcJwtConfiguration(cfg)) =
        described.trusted_token_issuer_configuration()
    else {
        panic!("{described:?}")
    };
    assert_eq!(cfg.claim_attribute_path(), "email");
    assert_eq!(
        a.list_trusted_token_issuers().instance_arn(inst).send().await.unwrap().trusted_token_issuers().len(),
        1
    );

    let app = a
        .create_application()
        .instance_arn(inst)
        .application_provider_arn(custom)
        .name("dashboards")
        .description("Analytics")
        .send()
        .await
        .unwrap();
    let app = app.application_arn().unwrap().to_string();
    a.update_application().application_arn(&app).description("Team analytics").send().await.unwrap();
    let described = a.describe_application().application_arn(&app).send().await.unwrap();
    assert_eq!(described.description(), Some("Team analytics"));
    assert_eq!(described.status().unwrap().as_str(), "ENABLED");
    let listed = a.list_applications().instance_arn(inst).send().await.unwrap();
    assert_eq!(listed.applications()[0].application_arn(), Some(app.as_str()));

    // Who may use it, how, and what it may ask for.
    let (_, backend) = user_with_policy(&c.mws, "backend", None).await;
    let actor_policy = Document::Object(
        [
            ("Version".to_string(), Document::String("2012-10-17".into())),
            (
                "Statement".to_string(),
                Document::Array(vec![Document::Object(
                    [
                        ("Effect".to_string(), Document::String("Allow".into())),
                        (
                            "Principal".to_string(),
                            Document::Object(
                                [(
                                    "AWS".to_string(),
                                    Document::String("arn:aws:iam::123456789012:user/backend".into()),
                                )]
                                .into(),
                            ),
                        ),
                        ("Action".to_string(), Document::String("sso-oauth:CreateTokenWithIAM".into())),
                        ("Resource".to_string(), Document::String("*".into())),
                    ]
                    .into(),
                )]),
            ),
        ]
        .into(),
    );
    a.put_application_authentication_method()
        .application_arn(&app)
        .authentication_method_type(AuthenticationMethodType::Iam)
        .authentication_method(AuthenticationMethod::Iam(
            IamAuthenticationMethod::builder().actor_policy(actor_policy).build().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    let method = a
        .get_application_authentication_method()
        .application_arn(&app)
        .authentication_method_type(AuthenticationMethodType::Iam)
        .send()
        .await
        .unwrap();
    assert!(matches!(method.authentication_method(), Some(AuthenticationMethod::Iam(_))));
    let methods = a.list_application_authentication_methods().application_arn(&app).send().await.unwrap();
    assert_eq!(methods.authentication_methods().len(), 1);

    let grants = [
        (
            GrantType::AuthorizationCode,
            Grant::AuthorizationCode(AuthorizationCodeGrant::builder().redirect_uris(REDIRECT).build()),
        ),
        (GrantType::RefreshToken, Grant::RefreshToken(RefreshTokenGrant::builder().build())),
        (GrantType::TokenExchange, Grant::TokenExchange(TokenExchangeGrant::builder().build())),
        (
            GrantType::JwtBearer,
            Grant::JwtBearer(
                JwtBearerGrant::builder()
                    .authorized_token_issuers(
                        AuthorizedTokenIssuer::builder()
                            .trusted_token_issuer_arn(&tti)
                            .authorized_audiences("dashboards")
                            .build(),
                    )
                    .build(),
            ),
        ),
    ];
    for (t, g) in grants {
        a.put_application_grant().application_arn(&app).grant_type(t).grant(g).send().await.unwrap();
    }
    let err = a
        .put_application_grant()
        .application_arn(&app)
        .grant_type(GrantType::RefreshToken)
        .grant(Grant::TokenExchange(TokenExchangeGrant::builder().build()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    let grant = a.get_application_grant().application_arn(&app).grant_type(GrantType::AuthorizationCode).send().await;
    assert!(matches!(grant.unwrap().grant(), Some(Grant::AuthorizationCode(_))));
    assert_eq!(a.list_application_grants().application_arn(&app).send().await.unwrap().grants().len(), 4);

    a.put_application_access_scope().application_arn(&app).scope("openid").send().await.unwrap();
    a.put_application_access_scope().application_arn(&app).scope("redshift:connect").send().await.unwrap();
    let scope = a.get_application_access_scope().application_arn(&app).scope("openid").send().await.unwrap();
    assert_eq!(scope.scope(), "openid");
    assert_eq!(a.list_application_access_scopes().application_arn(&app).send().await.unwrap().scopes().len(), 2);
    a.delete_application_access_scope().application_arn(&app).scope("redshift:connect").send().await.unwrap();

    a.put_application_session_configuration()
        .application_arn(&app)
        .user_background_session_application_status(UserBackgroundSessionApplicationStatus::Enabled)
        .send()
        .await
        .unwrap();
    let session = a.get_application_session_configuration().application_arn(&app).send().await.unwrap();
    assert_eq!(session.user_background_session_application_status().unwrap().as_str(), "ENABLED");

    a.put_application_assignment_configuration().application_arn(&app).assignment_required(true).send().await.unwrap();
    let config = a.get_application_assignment_configuration().application_arn(&app).send().await.unwrap();
    assert!(config.assignment_required());
    a.create_application_assignment()
        .application_arn(&app)
        .principal_id(&alice)
        .principal_type(PrincipalType::User)
        .send()
        .await
        .unwrap();
    let described = a
        .describe_application_assignment()
        .application_arn(&app)
        .principal_id(&alice)
        .principal_type(PrincipalType::User)
        .send()
        .await
        .unwrap();
    assert_eq!(described.principal_id(), Some(alice.as_str()));
    let listed = a.list_application_assignments().application_arn(&app).send().await.unwrap();
    assert_eq!(listed.application_assignments().len(), 1);
    let mine = a
        .list_application_assignments_for_principal()
        .instance_arn(inst)
        .principal_id(&alice)
        .principal_type(PrincipalType::User)
        .send()
        .await
        .unwrap();
    assert_eq!(mine.application_assignments()[0].application_arn(), Some(app.as_str()));

    // The application's backend signs alice in with the authorization code
    // grant and trades the code for tokens.
    let (code, _) = authorize(
        &c.mws,
        &[("response_type", "code"), ("client_id", &app), ("redirect_uri", REDIRECT), ("username", "alice")],
    )
    .await;
    let oidc = Oidc::new(&backend);
    let out = oidc
        .create_token_with_iam()
        .client_id(&app)
        .grant_type("authorization_code")
        .code(&code)
        .redirect_uri(REDIRECT)
        .send()
        .await
        .unwrap();
    assert_eq!(out.token_type(), Some("Bearer"));
    assert!(out.id_token().unwrap().split('.').count() == 3);
    assert!(out.aws_additional_details().unwrap().identity_context().is_some());
    assert_eq!(out.scope(), ["openid"]);

    // An identity-enhanced role session: the identity context becomes
    // `identitystore:*` condition keys through STS `ProvidedContexts`.
    let root_iam = aws_sdk_iam::Client::new(&c.mws.root_sdk_config().await);
    root_iam
        .put_user_policy()
        .user_name("backend")
        .policy_name("assume")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}"#,
        )
        .send()
        .await
        .unwrap();
    let trust = |actions: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::123456789012:user/backend"}},"Action":{actions}}}}}"#
        )
    };
    for (name, actions) in
        [("app-role", r#"["sts:AssumeRole","sts:SetContext"]"#), ("plain-role", r#""sts:AssumeRole""#)]
    {
        root_iam.create_role().role_name(name).assume_role_policy_document(trust(actions)).send().await.unwrap();
        root_iam
            .put_role_policy()
            .role_name(name)
            .policy_name("by-user")
            .policy_document(format!(
                r#"{{"Version":"2012-10-17","Statement":{{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*","Condition":{{"StringEquals":{{"identitystore:UserId":"{alice}"}}}}}}}}"#
            ))
            .send()
            .await
            .unwrap();
    }
    let identity_context = out.aws_additional_details().unwrap().identity_context().unwrap();
    let context = aws_sdk_sts::types::ProvidedContext::builder()
        .provider_arn("arn:aws:iam::aws:contextProvider/IdentityCenter")
        .context_assertion(identity_context)
        .build();
    let sts = aws_sdk_sts::Client::new(&backend);
    let assume = |role: &str, ctx: Option<aws_sdk_sts::types::ProvidedContext>| {
        sts.assume_role()
            .role_arn(format!("arn:aws:iam::123456789012:role/{role}"))
            .role_session_name("app")
            .set_provided_contexts(ctx.map(|c| vec![c]))
            .send()
    };
    let enhanced = assume("app-role", Some(context.clone())).await.unwrap();
    let enhanced = aws_sdk_iam::Client::new(&mws_e2e::sts_config(&c.mws, enhanced.credentials().unwrap()).await);
    enhanced.list_roles().send().await.unwrap();
    let plain = assume("app-role", None).await.unwrap();
    let plain = aws_sdk_iam::Client::new(&mws_e2e::sts_config(&c.mws, plain.credentials().unwrap()).await);
    let err = plain.list_roles().send().await.unwrap_err();
    assert_eq!(aws_sdk_iam::error::ProvideErrorMetadata::code(&err), Some("AccessDenied"));
    // The trust policy must allow sts:SetContext.
    let err = assume("plain-role", Some(context)).await.unwrap_err();
    assert_eq!(aws_sdk_sts::error::ProvideErrorMetadata::code(&err), Some("AccessDenied"));
    let forged = aws_sdk_sts::types::ProvidedContext::builder()
        .provider_arn("arn:aws:iam::aws:contextProvider/IdentityCenter")
        .context_assertion("Zm9yZ2Vk")
        .build();
    let err = assume("app-role", Some(forged)).await.unwrap_err();
    assert_eq!(aws_sdk_sts::error::ProvideErrorMetadata::code(&err), Some("ValidationError"));
    // Application tokens don't open the AWS access portal.
    let portal = aws_sdk_sso::Client::new(&c.mws.root_sdk_config().await);
    let err = portal.list_accounts().access_token(out.access_token().unwrap()).send().await.unwrap_err();
    assert_eq!(aws_sdk_sso::error::ProvideErrorMetadata::code(&err), Some("UnauthorizedException"));

    let refreshed = oidc
        .create_token_with_iam()
        .client_id(&app)
        .grant_type("refresh_token")
        .refresh_token(out.refresh_token().unwrap())
        .send()
        .await
        .unwrap();
    assert!(refreshed.access_token().is_some());

    // Token exchange: alice's AWS access portal token for an application token.
    let portal_token = c.sign_in("alice").await;
    let exchanged = oidc
        .create_token_with_iam()
        .client_id(&app)
        .grant_type("urn:ietf:params:oauth:grant-type:token-exchange")
        .subject_token(&portal_token)
        .subject_token_type("urn:ietf:params:oauth:token-type:access_token")
        .requested_token_type("urn:ietf:params:oauth:token-type:access_token")
        .send()
        .await
        .unwrap();
    assert!(exchanged.access_token().is_some());
    let bob_token = c.sign_in("bob").await;
    let err = oidc
        .create_token_with_iam()
        .client_id(&app)
        .grant_type("urn:ietf:params:oauth:grant-type:token-exchange")
        .subject_token(&bob_token)
        .subject_token_type("urn:ietf:params:oauth:token-type:access_token")
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err), Some("AccessDeniedException"));

    // JWT bearer: a token from the trusted token issuer.
    let exp = chrono::Utc::now().timestamp() + 300;
    let assertion = |aud: &str| {
        jwt(serde_json::json!({"iss": "https://idp.example.com", "aud": aud, "email": "alice@example.com", "exp": exp}))
    };
    let out = oidc
        .create_token_with_iam()
        .client_id(&app)
        .grant_type("urn:ietf:params:oauth:grant-type:jwt-bearer")
        .assertion(assertion("dashboards"))
        .send()
        .await
        .unwrap();
    assert!(out.access_token().is_some());
    let err = oidc
        .create_token_with_iam()
        .client_id(&app)
        .grant_type("urn:ietf:params:oauth:grant-type:jwt-bearer")
        .assertion(assertion("someone-else"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err), Some("InvalidGrantException"));

    // Only principals the actor policy names may ask.
    let (_, stranger) = user_with_policy(&c.mws, "stranger", Some(crate::identity_center::ADMIN)).await;
    let err = Oidc::new(&stranger)
        .create_token_with_iam()
        .client_id(&app)
        .grant_type("urn:ietf:params:oauth:grant-type:token-exchange")
        .subject_token(&portal_token)
        .subject_token_type("urn:ietf:params:oauth:token-type:access_token")
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err), Some("AccessDeniedException"));

    // Clean up through every delete.
    a.delete_application_assignment()
        .application_arn(&app)
        .principal_id(&alice)
        .principal_type(PrincipalType::User)
        .send()
        .await
        .unwrap();
    let _ = bob;
    a.delete_application_grant().application_arn(&app).grant_type(GrantType::JwtBearer).send().await.unwrap();
    a.delete_application_authentication_method()
        .application_arn(&app)
        .authentication_method_type(AuthenticationMethodType::Iam)
        .send()
        .await
        .unwrap();
    a.delete_application().application_arn(&app).send().await.unwrap();
    let err = a.describe_application().application_arn(&app).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));
    a.delete_trusted_token_issuer().trusted_token_issuer_arn(&tti).send().await.unwrap();
    assert!(a.list_trusted_token_issuers().instance_arn(inst).send().await.unwrap().trusted_token_issuers().is_empty());
}
