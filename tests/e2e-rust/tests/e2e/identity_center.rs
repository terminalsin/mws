//! IAM Identity Center through the official SDKs: an organization instance
//! whose permission sets become real `AWSReservedSSO_*` roles in member
//! accounts, and a user who signs in with the device flow (sso-oidc) and
//! gets working credentials for those roles from the AWS access portal
//! (sso).

use aws_sdk_identitystore::types::{Email, MemberId};
use aws_sdk_identitystore::Client as IdentityStore;
use aws_sdk_organizations::Client as Orgs;
use aws_sdk_sso::error::ProvideErrorMetadata;
use aws_sdk_sso::Client as Portal;
use aws_sdk_ssoadmin::types::{
    AccessControlAttribute, AccessControlAttributeValue, CustomerManagedPolicyReference,
    InstanceAccessControlAttributeConfiguration, PrincipalType, ProvisionTargetType, ProvisioningStatus, StatusValues,
    TargetType,
};
use aws_sdk_ssoadmin::Client as SsoAdmin;
use aws_sdk_ssooidc::Client as Oidc;
use mws_e2e::{sts_config, user_with_policy, Mws};

pub const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;
const ENGINEER: &str = r#"{"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Action":["iam:ListRoles","iam:GetRole"],"Resource":"*"},
    {"Effect":"Allow","Action":"iam:ListUsers","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/JobTitle":"Engineer"}}}
]}"#;
const ENGINEER_V2: &str = r#"{"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Action":["iam:ListRoles","iam:GetRole","iam:CreateUser"],"Resource":"*"}
]}"#;

/// An organization with one member account and an Identity Center
/// organization instance in the management account.
pub struct Center {
    pub mws: Mws,
    pub admin: SsoAdmin,
    pub ids: IdentityStore,
    pub instance_arn: String,
    pub store: String,
    pub member: String,
    /// Administrator credentials in the management account.
    pub admin_config: aws_config::SdkConfig,
}

pub async fn center() -> Center {
    center_with(Mws::start().await).await
}

pub async fn center_with(mws: Mws) -> Center {
    let root = mws.root_sdk_config().await;
    let orgs = Orgs::new(&root);
    orgs.create_organization().send().await.unwrap();
    let out = orgs.create_account().email("dev@example.com").account_name("dev").send().await.unwrap();
    let request_id = out.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let member = status.create_account_status().unwrap().account_id().unwrap().to_string();
    let (_, admin_config) = user_with_policy(&mws, "admin", Some(ADMIN)).await;
    let admin = SsoAdmin::new(&admin_config);
    let instance_arn = admin.create_instance().name("corp").send().await.unwrap().instance_arn().unwrap().to_string();
    let described = admin.describe_instance().instance_arn(&instance_arn).send().await.unwrap();
    let store = described.identity_store_id().unwrap().to_string();
    let ids = IdentityStore::new(&admin_config);
    Center { mws, admin, ids, instance_arn, store, member, admin_config }
}

impl Center {
    pub async fn user(&self, name: &str, title: &str) -> String {
        self.ids
            .create_user()
            .identity_store_id(&self.store)
            .user_name(name)
            .display_name(name)
            .title(title)
            .name(aws_sdk_identitystore::types::Name::builder().given_name(name).family_name("Doe").build())
            .emails(Email::builder().value(format!("{name}@example.com")).primary(true).build())
            .send()
            .await
            .unwrap()
            .user_id()
            .to_string()
    }

    pub async fn permission_set(&self, name: &str) -> String {
        self.admin
            .create_permission_set()
            .instance_arn(&self.instance_arn)
            .name(name)
            .session_duration("PT2H")
            .send()
            .await
            .unwrap()
            .permission_set()
            .unwrap()
            .permission_set_arn()
            .unwrap()
            .to_string()
    }

    /// Assign and wait for the (immediate) result: `(status, reason)`.
    pub async fn assign(
        &self,
        account: &str,
        ps: &str,
        kind: PrincipalType,
        principal: &str,
    ) -> (StatusValues, String) {
        let out = self
            .admin
            .create_account_assignment()
            .instance_arn(&self.instance_arn)
            .target_id(account)
            .target_type(TargetType::AwsAccount)
            .permission_set_arn(ps)
            .principal_type(kind)
            .principal_id(principal)
            .send()
            .await
            .unwrap();
        let first = out.account_assignment_creation_status().unwrap();
        assert_eq!(first.status(), Some(&StatusValues::InProgress));
        let s = self
            .admin
            .describe_account_assignment_creation_status()
            .instance_arn(&self.instance_arn)
            .account_assignment_creation_request_id(first.request_id().unwrap())
            .send()
            .await
            .unwrap();
        let s = s.account_assignment_creation_status().unwrap();
        (s.status().unwrap().clone(), s.failure_reason().unwrap_or_default().to_string())
    }

    pub fn start_url(&self) -> String {
        format!("https://{}.awsapps.com/start", self.store)
    }

    /// Sign `username` in with the device authorization grant (what
    /// `aws sso login` does) and return the access token.
    pub async fn sign_in(&self, username: &str) -> String {
        let oidc = Oidc::new(&self.mws.root_sdk_config().await);
        let client = oidc.register_client().client_name("cli").client_type("public").send().await.unwrap();
        let (id, secret) = (client.client_id().unwrap(), client.client_secret().unwrap());
        let auth = oidc
            .start_device_authorization()
            .client_id(id)
            .client_secret(secret)
            .start_url(self.start_url())
            .send()
            .await
            .unwrap();
        let device_code = auth.device_code().unwrap();
        let token = || {
            oidc.create_token()
                .client_id(id)
                .client_secret(secret)
                .grant_type("urn:ietf:params:oauth:grant-type:device_code")
                .device_code(device_code)
                .send()
        };
        let err = token().await.unwrap_err();
        assert_eq!(aws_sdk_ssooidc::error::ProvideErrorMetadata::code(&err), Some("AuthorizationPendingException"));
        let uri = auth.verification_uri_complete().unwrap();
        assert!(uri.contains(auth.user_code().unwrap()), "{uri}");
        let (status, _, page) = self.mws.raw("GET", uri, &[], b"").await;
        assert_eq!(status, 200);
        assert!(String::from_utf8_lossy(&page).contains(auth.user_code().unwrap()));
        let form = format!("user_code={}&username={username}", auth.user_code().unwrap());
        let (status, _, _) = self
            .mws
            .raw(
                "POST",
                "/_aws/sso-oidc/device",
                &[("Content-Type", "application/x-www-form-urlencoded")],
                form.as_bytes(),
            )
            .await;
        assert_eq!(status, 200);
        let out = token().await.unwrap();
        assert_eq!(out.token_type(), Some("Bearer"));
        assert!(out.expires_in() > 0);
        out.access_token().unwrap().to_string()
    }

    /// Credentials in the member account (through
    /// `OrganizationAccountAccessRole`).
    pub async fn member_config(&self) -> aws_config::SdkConfig {
        let sts = aws_sdk_sts::Client::new(&self.admin_config);
        let creds = sts
            .assume_role()
            .role_arn(format!("arn:aws:iam::{}:role/OrganizationAccountAccessRole", self.member))
            .role_session_name("ops")
            .send()
            .await
            .unwrap();
        sts_config(&self.mws, creds.credentials().unwrap()).await
    }

    pub async fn member_iam(&self) -> aws_sdk_iam::Client {
        aws_sdk_iam::Client::new(&self.member_config().await)
    }
}

#[tokio::test]
async fn permission_sets_become_roles_and_portal_credentials_work() {
    let c = center().await;
    let listed = c.admin.list_instances().send().await.unwrap();
    let inst = &listed.instances()[0];
    assert_eq!(inst.instance_arn(), Some(c.instance_arn.as_str()));
    assert_eq!(inst.owner_account_id(), Some("123456789012"));
    assert_eq!(inst.status().map(|s| s.as_str()), Some("ACTIVE"));
    assert!(c.store.starts_with("d-"));

    // Attribute-based access control: the user's title becomes a session tag.
    c.admin
        .create_instance_access_control_attribute_configuration()
        .instance_arn(&c.instance_arn)
        .instance_access_control_attribute_configuration(
            InstanceAccessControlAttributeConfiguration::builder()
                .access_control_attributes(
                    AccessControlAttribute::builder()
                        .key("JobTitle")
                        .value(AccessControlAttributeValue::builder().source("${path:title}").build().unwrap())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let alice = c.user("alice", "Engineer").await;
    let group = c.ids.create_group().identity_store_id(&c.store).display_name("Engineers").send().await.unwrap();
    let group = group.group_id().to_string();
    c.ids
        .create_group_membership()
        .identity_store_id(&c.store)
        .group_id(&group)
        .member_id(MemberId::UserId(alice.clone()))
        .send()
        .await
        .unwrap();

    let engineer = c.permission_set("Engineer").await;
    c.admin
        .put_inline_policy_to_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&engineer)
        .inline_policy(ENGINEER)
        .send()
        .await
        .unwrap();
    let readonly = c.permission_set("ReadOnly").await;
    c.admin
        .attach_managed_policy_to_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&readonly)
        .managed_policy_arn("arn:aws:iam::aws:policy/ReadOnlyAccess")
        .send()
        .await
        .unwrap();

    // Group assignment in the member account, direct one in the management
    // account.
    let (status, reason) = c.assign(&c.member, &engineer, PrincipalType::Group, &group).await;
    assert_eq!(status, StatusValues::Succeeded, "{reason}");
    let (status, reason) = c.assign("123456789012", &readonly, PrincipalType::User, &alice).await;
    assert_eq!(status, StatusValues::Succeeded, "{reason}");

    // The permission set is a real role in the member account.
    let member_iam = c.member_iam().await;
    let roles = member_iam.list_roles().path_prefix("/aws-reserved/").send().await.unwrap();
    let role = roles.roles().iter().find(|r| r.role_name().starts_with("AWSReservedSSO_Engineer_")).unwrap();
    assert_eq!(role.path(), "/aws-reserved/sso.amazonaws.com/");
    assert_eq!(role.max_session_duration(), Some(7200));
    let role_name = role.role_name().to_string();
    let trust = urlencoding::decode(role.assume_role_policy_document().unwrap()).unwrap().into_owned();
    assert!(trust.contains("sts:AssumeRoleWithSAML") && trust.contains("saml-provider/AWSSSO_"), "{trust}");
    let inline = member_iam.get_role_policy().role_name(&role_name).policy_name("AwsSSOInlinePolicy").send().await;
    assert!(inline.unwrap().policy_document().contains("iam%3AListUsers"));
    let providers = member_iam.list_saml_providers().send().await.unwrap();
    assert!(providers.saml_provider_list().iter().any(|p| p.arn().unwrap().contains("_DO_NOT_DELETE")));
    // Only Identity Center may change it.
    let err = member_iam.delete_role().role_name(&role_name).send().await.unwrap_err();
    assert_eq!(aws_sdk_iam::error::ProvideErrorMetadata::code(&err), Some("UnmodifiableEntity"));
    let err = member_iam
        .put_role_policy()
        .role_name(&role_name)
        .policy_name("x")
        .policy_document(ADMIN)
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_iam::error::ProvideErrorMetadata::code(&err), Some("UnmodifiableEntity"));

    let provisioned = c
        .admin
        .list_permission_sets_provisioned_to_account()
        .instance_arn(&c.instance_arn)
        .account_id(&c.member)
        .send()
        .await
        .unwrap();
    assert_eq!(provisioned.permission_sets(), std::slice::from_ref(&engineer));
    let accounts = c
        .admin
        .list_accounts_for_provisioned_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&engineer)
        .send()
        .await
        .unwrap();
    assert_eq!(accounts.account_ids(), std::slice::from_ref(&c.member));
    let assignments = c
        .admin
        .list_account_assignments()
        .instance_arn(&c.instance_arn)
        .account_id(&c.member)
        .permission_set_arn(&engineer)
        .send()
        .await
        .unwrap();
    assert_eq!(assignments.account_assignments()[0].principal_id(), Some(group.as_str()));
    let mine = c
        .admin
        .list_account_assignments_for_principal()
        .instance_arn(&c.instance_arn)
        .principal_id(&alice)
        .principal_type(PrincipalType::User)
        .send()
        .await
        .unwrap();
    assert_eq!(mine.account_assignments().len(), 1);

    // Sign in and use the access portal.
    let token = c.sign_in("alice").await;
    let portal = Portal::new(&c.mws.root_sdk_config().await);
    let accounts = portal.list_accounts().access_token(&token).send().await.unwrap();
    let mut ids: Vec<&str> = accounts.account_list().iter().filter_map(|a| a.account_id()).collect();
    ids.sort();
    let mut want = vec!["123456789012", c.member.as_str()];
    want.sort();
    assert_eq!(ids, want);
    assert!(accounts.account_list().iter().any(|a| a.account_name() == Some("dev")));
    let roles = portal.list_account_roles().access_token(&token).account_id(&c.member).send().await.unwrap();
    assert_eq!(roles.role_list()[0].role_name(), Some("Engineer"));

    let creds = portal
        .get_role_credentials()
        .access_token(&token)
        .account_id(&c.member)
        .role_name("Engineer")
        .send()
        .await
        .unwrap();
    let creds = creds.role_credentials().unwrap();
    let now_ms = chrono::Utc::now().timestamp_millis();
    assert!(creds.expiration() > now_ms + 7_000_000, "two-hour session");
    let cfg = c
        .mws
        .sdk_config(creds.access_key_id().unwrap(), creds.secret_access_key().unwrap(), creds.session_token())
        .await;
    let me = aws_sdk_sts::Client::new(&cfg).get_caller_identity().send().await.unwrap();
    assert_eq!(me.account(), Some(c.member.as_str()));
    assert_eq!(me.arn(), Some(format!("arn:aws:sts::{}:assumed-role/{role_name}/alice", c.member).as_str()));
    let iam = aws_sdk_iam::Client::new(&cfg);
    iam.list_roles().send().await.unwrap();
    // Allowed only through the JobTitle session tag.
    iam.list_users().send().await.unwrap();
    let err = iam.create_user().user_name("bob").send().await.unwrap_err();
    assert_eq!(aws_sdk_iam::error::ProvideErrorMetadata::code(&err), Some("AccessDenied"));

    // A permission set change reaches the role only when provisioned.
    c.admin
        .put_inline_policy_to_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&engineer)
        .inline_policy(ENGINEER_V2)
        .send()
        .await
        .unwrap();
    let stale = c
        .admin
        .list_accounts_for_provisioned_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&engineer)
        .provisioning_status(ProvisioningStatus::LatestPermissionSetNotProvisioned)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.account_ids(), std::slice::from_ref(&c.member));
    iam.create_user().user_name("bob").send().await.unwrap_err();
    let out = c
        .admin
        .provision_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&engineer)
        .target_type(ProvisionTargetType::AllProvisionedAccounts)
        .send()
        .await
        .unwrap();
    let request = out.permission_set_provisioning_status().unwrap().request_id().unwrap();
    let status = c
        .admin
        .describe_permission_set_provisioning_status()
        .instance_arn(&c.instance_arn)
        .provision_permission_set_request_id(request)
        .send()
        .await
        .unwrap();
    assert_eq!(status.permission_set_provisioning_status().unwrap().status(), Some(&StatusValues::Succeeded));
    let listed = c.admin.list_permission_set_provisioning_status().instance_arn(&c.instance_arn).send().await.unwrap();
    assert!(listed.permission_sets_provisioning_status().iter().any(|s| s.request_id() == Some(request)));
    iam.create_user().user_name("bob").send().await.unwrap();

    // The portal refuses roles the user isn't assigned.
    let err = portal
        .get_role_credentials()
        .access_token(&token)
        .account_id(&c.member)
        .role_name("ReadOnly")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ForbiddenException"));
    let readonly_creds = portal
        .get_role_credentials()
        .access_token(&token)
        .account_id("123456789012")
        .role_name("ReadOnly")
        .send()
        .await
        .unwrap();
    let rc = readonly_creds.role_credentials().unwrap();
    let ro = aws_sdk_iam::Client::new(
        &c.mws.sdk_config(rc.access_key_id().unwrap(), rc.secret_access_key().unwrap(), rc.session_token()).await,
    );
    ro.list_roles().send().await.unwrap();
    ro.create_user().user_name("eve").send().await.unwrap_err();

    // Removing the last assignment deletes the role.
    let out = c
        .admin
        .delete_account_assignment()
        .instance_arn(&c.instance_arn)
        .target_id(&c.member)
        .target_type(TargetType::AwsAccount)
        .permission_set_arn(&engineer)
        .principal_type(PrincipalType::Group)
        .principal_id(&group)
        .send()
        .await
        .unwrap();
    let request = out.account_assignment_deletion_status().unwrap().request_id().unwrap();
    let status = c
        .admin
        .describe_account_assignment_deletion_status()
        .instance_arn(&c.instance_arn)
        .account_assignment_deletion_request_id(request)
        .send()
        .await
        .unwrap();
    assert_eq!(status.account_assignment_deletion_status().unwrap().status(), Some(&StatusValues::Succeeded));
    let listed = c.admin.list_account_assignment_deletion_status().instance_arn(&c.instance_arn).send().await.unwrap();
    assert_eq!(listed.account_assignments_deletion_status().len(), 1);
    let listed = c.admin.list_account_assignment_creation_status().instance_arn(&c.instance_arn).send().await.unwrap();
    assert_eq!(listed.account_assignments_creation_status().len(), 2);
    let err = member_iam.get_role().role_name(&role_name).send().await.unwrap_err();
    assert_eq!(aws_sdk_iam::error::ProvideErrorMetadata::code(&err), Some("NoSuchEntity"));
    let err = portal
        .get_role_credentials()
        .access_token(&token)
        .account_id(&c.member)
        .role_name("Engineer")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ForbiddenException"));

    portal.logout().access_token(&token).send().await.unwrap();
    let err = portal.list_accounts().access_token(&token).send().await.unwrap_err();
    assert_eq!(err.code(), Some("UnauthorizedException"));
}

#[tokio::test]
async fn customer_managed_policies_must_exist_in_the_account() {
    let c = center().await;
    let bob = c.user("bob", "Analyst").await;
    let ps = c.permission_set("Analyst").await;
    let reference = CustomerManagedPolicyReference::builder().name("AnalystAccess").path("/team/").build().unwrap();
    c.admin
        .attach_customer_managed_policy_reference_to_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&ps)
        .customer_managed_policy_reference(reference.clone())
        .send()
        .await
        .unwrap();
    let listed = c
        .admin
        .list_customer_managed_policy_references_in_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&ps)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.customer_managed_policy_references(), std::slice::from_ref(&reference));

    let (status, reason) = c.assign(&c.member, &ps, PrincipalType::User, &bob).await;
    assert_eq!(status, StatusValues::Failed);
    assert!(reason.contains("AnalystAccess"), "{reason}");

    let member_iam = c.member_iam().await;
    member_iam
        .create_policy()
        .policy_name("AnalystAccess")
        .path("/team/")
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*"}}"#,
        )
        .send()
        .await
        .unwrap();
    let (status, reason) = c.assign(&c.member, &ps, PrincipalType::User, &bob).await;
    assert_eq!(status, StatusValues::Succeeded, "{reason}");
    let roles = member_iam.list_roles().path_prefix("/aws-reserved/").send().await.unwrap();
    let role = roles.roles().iter().find(|r| r.role_name().starts_with("AWSReservedSSO_Analyst_")).unwrap();
    let attached = member_iam.list_attached_role_policies().role_name(role.role_name()).send().await.unwrap();
    assert_eq!(
        attached.attached_policies()[0].policy_arn(),
        Some(format!("arn:aws:iam::{}:policy/team/AnalystAccess", c.member).as_str())
    );

    // A permission set with assignments can't be deleted.
    let err = c.admin.delete_permission_set().instance_arn(&c.instance_arn).permission_set_arn(&ps).send().await;
    assert_eq!(aws_sdk_ssoadmin::error::ProvideErrorMetadata::code(&err.unwrap_err()), Some("ConflictException"));
    c.admin
        .detach_customer_managed_policy_reference_from_permission_set()
        .instance_arn(&c.instance_arn)
        .permission_set_arn(&ps)
        .customer_managed_policy_reference(reference)
        .send()
        .await
        .unwrap();
}
