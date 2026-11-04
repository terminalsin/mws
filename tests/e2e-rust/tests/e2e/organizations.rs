//! AWS Organizations through the official SDK: the organization tree, real
//! member accounts, and SCPs/RCPs enforced on what principals in those
//! accounts may do.

use aws_sdk_organizations::error::ProvideErrorMetadata;
use aws_sdk_organizations::types::{ChildType, HandshakeParty, HandshakePartyType, PolicyType};
use aws_sdk_organizations::Client as Orgs;
use aws_sdk_sts::types::PolicyDescriptorType;
use mws_e2e::{sts_config, user_with_policy, Mws};

const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;
const DENY_CREATE_USER: &str =
    r#"{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"iam:CreateUser","Resource":"*"}}"#;
const ONLY_IAM_READS: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["iam:Get*","iam:List*","sts:*"],"Resource":"*"}}"#;

struct Org {
    mws: Mws,
    orgs: Orgs,
    org_id: String,
    root_id: String,
    /// An administrator in the management account (the root user cannot
    /// assume roles).
    admin: aws_config::SdkConfig,
}

async fn org() -> Org {
    let mws = Mws::start().await;
    let orgs = Orgs::new(&mws.root_sdk_config().await);
    let created = orgs.create_organization().send().await.unwrap();
    let org_id = created.organization().unwrap().id().unwrap().to_string();
    let root_id = orgs.list_roots().send().await.unwrap().roots()[0].id().unwrap().to_string();
    let (_, admin) = user_with_policy(&mws, "admin", Some(ADMIN)).await;
    Org { mws, orgs, org_id, root_id, admin }
}

impl Org {
    async fn create_account(&self, name: &str) -> String {
        let out =
            self.orgs.create_account().email(format!("{name}@example.com")).account_name(name).send().await.unwrap();
        let request_id = out.create_account_status().unwrap().id().unwrap();
        let status =
            self.orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
        let status = status.create_account_status().unwrap();
        assert_eq!(status.state().unwrap().as_str(), "SUCCEEDED");
        status.account_id().unwrap().to_string()
    }

    /// Credentials for `OrganizationAccountAccessRole` in a member account.
    async fn member_config(&self, account: &str) -> aws_config::SdkConfig {
        let sts = aws_sdk_sts::Client::new(&self.admin);
        let creds = sts
            .assume_role()
            .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
            .role_session_name("ops")
            .send()
            .await
            .unwrap();
        sts_config(&self.mws, creds.credentials().unwrap()).await
    }
}

#[tokio::test]
async fn organization_tree_and_accounts() {
    let o = org().await;
    let described = o.orgs.describe_organization().send().await.unwrap();
    let organization = described.organization().unwrap();
    assert_eq!(organization.master_account_id(), Some("123456789012"));
    assert_eq!(organization.feature_set().unwrap().as_str(), "ALL");
    assert!(organization.arn().unwrap().starts_with("arn:aws:organizations::123456789012:organization/o-"));

    let err = o.orgs.create_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AlreadyInOrganizationException"));

    let eng = o.orgs.create_organizational_unit().parent_id(&o.root_id).name("Engineering").send().await.unwrap();
    let eng = eng.organizational_unit().unwrap().id().unwrap().to_string();
    let prod = o.orgs.create_organizational_unit().parent_id(&eng).name("Prod").send().await.unwrap();
    let prod_ou = prod.organizational_unit().unwrap();
    assert_eq!(prod_ou.path(), Some(format!("{}/{}/{eng}/{}/", o.org_id, o.root_id, prod_ou.id().unwrap()).as_str()));
    let prod = prod_ou.id().unwrap().to_string();
    let err = o.orgs.create_organizational_unit().parent_id(&eng).name("Prod").send().await.unwrap_err();
    assert_eq!(err.code(), Some("DuplicateOrganizationalUnitException"));

    let account = o.create_account("workloads").await;
    let accounts = o.orgs.list_accounts().send().await.unwrap();
    assert_eq!(accounts.accounts().len(), 2);

    o.orgs
        .move_account()
        .account_id(&account)
        .source_parent_id(&o.root_id)
        .destination_parent_id(&prod)
        .send()
        .await
        .unwrap();
    let parents = o.orgs.list_parents().child_id(&account).send().await.unwrap();
    assert_eq!(parents.parents()[0].id(), Some(prod.as_str()));
    let children = o.orgs.list_children().parent_id(&prod).child_type(ChildType::Account).send().await.unwrap();
    assert_eq!(children.children()[0].id(), Some(account.as_str()));
    let described = o.orgs.describe_account().account_id(&account).send().await.unwrap();
    let a = described.account().unwrap();
    assert_eq!(a.name(), Some("workloads"));
    assert_eq!(a.joined_method().unwrap().as_str(), "CREATED");

    let err = o.orgs.delete_organizational_unit().organizational_unit_id(&prod).send().await.unwrap_err();
    assert_eq!(err.code(), Some("OrganizationalUnitNotEmptyException"));
    let err = o.orgs.delete_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("OrganizationNotEmptyException"));

    o.orgs.tag_resource().resource_id(&account).tags(tag("team", "core")).send().await.unwrap();
    let tags = o.orgs.list_tags_for_resource().resource_id(&account).send().await.unwrap();
    assert_eq!(tags.tags()[0].key(), "team");

    // The new account is real: its access role works, and IAM there is
    // empty apart from that role.
    let member = o.member_config(&account).await;
    let me = aws_sdk_sts::Client::new(&member).get_caller_identity().send().await.unwrap();
    assert_eq!(me.account(), Some(account.as_str()));
    let roles = aws_sdk_iam::Client::new(&member).list_roles().send().await.unwrap();
    let names: Vec<_> = roles.roles().iter().map(|r| r.role_name()).collect();
    assert!(names.contains(&"OrganizationAccountAccessRole"), "{names:?}");
    let users = aws_sdk_iam::Client::new(&member).list_users().send().await.unwrap();
    assert!(users.users().is_empty());

    // Members may describe their organization but not manage it.
    let member_orgs = Orgs::new(&member);
    let seen = member_orgs.describe_organization().send().await.unwrap();
    assert_eq!(seen.organization().unwrap().id(), Some(o.org_id.as_str()));
    let err = member_orgs.list_accounts().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
}

fn tag(k: &str, v: &str) -> aws_sdk_organizations::types::Tag {
    aws_sdk_organizations::types::Tag::builder().key(k).value(v).build().unwrap()
}

#[tokio::test]
async fn service_control_policies_limit_member_accounts() {
    let o = org().await;
    let account = o.create_account("sandbox").await;
    let member = o.member_config(&account).await;
    let member_iam = aws_sdk_iam::Client::new(&member);
    member_iam.create_user().user_name("before-scp").send().await.unwrap();

    // An organization with all features starts with SCPs enabled in the
    // root and FullAWSAccess attached everywhere.
    let roots = o.orgs.list_roots().send().await.unwrap();
    let types = roots.roots()[0].policy_types();
    assert_eq!(types.len(), 1);
    assert_eq!(types[0].r#type(), Some(&PolicyType::ServiceControlPolicy));
    assert_eq!(types[0].status().unwrap().as_str(), "ENABLED");
    let scp = o
        .orgs
        .create_policy()
        .name("no-users")
        .description("Deny iam:CreateUser")
        .r#type(PolicyType::ServiceControlPolicy)
        .content(DENY_CREATE_USER)
        .send()
        .await
        .unwrap();
    let scp_id = scp.policy().unwrap().policy_summary().unwrap().id().unwrap().to_string();
    let err = o
        .orgs
        .enable_policy_type()
        .root_id(&o.root_id)
        .policy_type(PolicyType::ServiceControlPolicy)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("PolicyTypeAlreadyEnabledException"));
    let attached = o
        .orgs
        .list_policies_for_target()
        .target_id(&account)
        .filter(PolicyType::ServiceControlPolicy)
        .send()
        .await
        .unwrap();
    assert_eq!(attached.policies()[0].id(), Some("p-FullAWSAccess"));

    o.orgs.attach_policy().policy_id(&scp_id).target_id(&account).send().await.unwrap();
    let err = member_iam.create_user().user_name("after-scp").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(
        err.message().unwrap().ends_with("with an explicit deny in a service control policy"),
        "{:?}",
        err.message()
    );
    member_iam.list_users().send().await.unwrap();

    // The simulator applies the account's SCPs too.
    let sim = member_iam
        .simulate_principal_policy()
        .policy_source_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
        .action_names("iam:CreateUser")
        .action_names("iam:ListUsers")
        .send()
        .await
        .unwrap();
    let results = sim.evaluation_results();
    assert_eq!(results[0].eval_decision().as_str(), "explicitDeny");
    assert_eq!(results[0].organizations_decision_detail().map(|d| d.allowed_by_organizations()), Some(false));
    assert_eq!(results[1].eval_decision().as_str(), "allowed");
    assert_eq!(results[1].organizations_decision_detail().map(|d| d.allowed_by_organizations()), Some(true));

    // The management account is never limited by SCPs.
    o.orgs.attach_policy().policy_id(&scp_id).target_id(&o.root_id).send().await.unwrap();
    aws_sdk_iam::Client::new(&o.admin).create_user().user_name("mgmt-user").send().await.unwrap();

    // An allow-list SCP: with FullAWSAccess detached, only what it allows.
    let reads = o
        .orgs
        .create_policy()
        .name("iam-reads")
        .description("Only IAM reads")
        .r#type(PolicyType::ServiceControlPolicy)
        .content(ONLY_IAM_READS)
        .send()
        .await
        .unwrap();
    let reads_id = reads.policy().unwrap().policy_summary().unwrap().id().unwrap().to_string();
    o.orgs.detach_policy().policy_id(&scp_id).target_id(&account).send().await.unwrap();
    o.orgs.attach_policy().policy_id(&reads_id).target_id(&account).send().await.unwrap();
    o.orgs.detach_policy().policy_id("p-FullAWSAccess").target_id(&account).send().await.unwrap();
    let err = o.orgs.detach_policy().policy_id(&reads_id).target_id(&account).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConstraintViolationException"));
    let err = member_iam.create_role().role_name("r").assume_role_policy_document(TRUST_ANY).send().await.unwrap_err();
    assert!(
        err.message().unwrap().ends_with("because no service control policy allows the iam:CreateRole action"),
        "{:?}",
        err.message()
    );
    member_iam.list_roles().send().await.unwrap();

    let err = o.orgs.delete_policy().policy_id(&reads_id).send().await.unwrap_err();
    assert_eq!(err.code(), Some("PolicyInUseException"));
}

const TRUST_ANY: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}"#;

#[tokio::test]
async fn org_condition_keys_and_resource_control_policies() {
    let o = org().await;
    let account = o.create_account("data").await;
    let member = o.member_config(&account).await;

    // A management-account role anyone in the organization may assume.
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":{{"Effect":"Allow","Principal":{{"AWS":"*"}},"Action":"sts:AssumeRole","Condition":{{"StringEquals":{{"aws:PrincipalOrgID":"{}"}}}}}}}}"#,
        o.org_id
    );
    let root_iam = aws_sdk_iam::Client::new(&o.mws.root_sdk_config().await);
    root_iam.create_role().role_name("shared").assume_role_policy_document(&trust).send().await.unwrap();
    let creds = aws_sdk_sts::Client::new(&member)
        .assume_role()
        .role_arn("arn:aws:iam::123456789012:role/shared")
        .role_session_name("from-member")
        .send()
        .await
        .unwrap();
    assert_eq!(creds.assumed_role_user().unwrap().arn(), "arn:aws:sts::123456789012:assumed-role/shared/from-member");

    // An RCP on the member account stops anyone assuming its roles.
    o.orgs
        .enable_policy_type()
        .root_id(&o.root_id)
        .policy_type(PolicyType::ResourceControlPolicy)
        .send()
        .await
        .unwrap();
    let rcp = o
        .orgs
        .create_policy()
        .name("no-assume")
        .description("No sts:AssumeRole into this account")
        .r#type(PolicyType::ResourceControlPolicy)
        .content(r#"{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Resource":"*"}}"#)
        .send()
        .await
        .unwrap();
    let rcp_id = rcp.policy().unwrap().policy_summary().unwrap().id().unwrap().to_string();
    o.orgs.attach_policy().policy_id(&rcp_id).target_id(&account).send().await.unwrap();
    let err = aws_sdk_sts::Client::new(&o.admin)
        .assume_role()
        .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
        .role_session_name("blocked")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    o.orgs.detach_policy().policy_id(&rcp_id).target_id(&account).send().await.unwrap();
    o.member_config(&account).await;

    // Customer RCPs may only deny.
    let err = o
        .orgs
        .create_policy()
        .name("allow")
        .description("x")
        .r#type(PolicyType::ResourceControlPolicy)
        .content(
            r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}}"#,
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("MalformedPolicyDocumentException"));
}

#[tokio::test]
async fn invitations_and_leaving() {
    let o = org().await;
    let account = o.create_account("wanderer").await;
    let member = o.member_config(&account).await;

    o.orgs.remove_account_from_organization().account_id(&account).send().await.unwrap();
    let err = Orgs::new(&member).describe_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AWSOrganizationsNotInUseException"));

    let invite = o
        .orgs
        .invite_account_to_organization()
        .target(HandshakeParty::builder().r#type(HandshakePartyType::Account).id(&account).build().unwrap())
        .notes("come back")
        .send()
        .await
        .unwrap();
    let handshake_id = invite.handshake().unwrap().id().unwrap().to_string();
    let err = o
        .orgs
        .invite_account_to_organization()
        .target(HandshakeParty::builder().r#type(HandshakePartyType::Account).id(&account).build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("DuplicateHandshakeException"));

    let member_orgs = Orgs::new(&member);
    let pending = member_orgs.list_handshakes_for_account().send().await.unwrap();
    assert_eq!(pending.handshakes()[0].id(), Some(handshake_id.as_str()));
    let accepted = member_orgs.accept_handshake().handshake_id(&handshake_id).send().await.unwrap();
    assert_eq!(accepted.handshake().unwrap().state().unwrap().as_str(), "ACCEPTED");
    let a = o.orgs.describe_account().account_id(&account).send().await.unwrap();
    assert_eq!(a.account().unwrap().joined_method().unwrap().as_str(), "INVITED");

    let err = o.orgs.leave_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("MasterCannotLeaveOrganizationException"));
    member_orgs.leave_organization().send().await.unwrap();
    assert_eq!(o.orgs.list_accounts().send().await.unwrap().accounts().len(), 1);
    o.orgs.delete_organization().send().await.unwrap();
    let err = o.orgs.describe_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AWSOrganizationsNotInUseException"));
}

#[tokio::test]
async fn centralized_root_access() {
    let o = org().await;
    let account = o.create_account("rooted").await;
    let iam = aws_sdk_iam::Client::new(&o.admin);
    let err = iam.list_organizations_features().send().await.unwrap_err();
    assert_eq!(err.code(), Some("ServiceAccessNotEnabledException"));
    o.orgs.enable_aws_service_access().service_principal("iam.amazonaws.com").send().await.unwrap();
    iam.enable_organizations_root_credentials_management().send().await.unwrap();
    let enabled = iam.enable_organizations_root_sessions().send().await.unwrap();
    assert_eq!(enabled.organization_id(), Some(o.org_id.as_str()));
    let features = iam.list_organizations_features().send().await.unwrap();
    assert_eq!(features.enabled_features().len(), 2);

    let sts = aws_sdk_sts::Client::new(&o.admin);
    let out = sts
        .assume_root()
        .target_principal(&account)
        .task_policy_arn(
            PolicyDescriptorType::builder()
                .arn("arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let root = sts_config(&o.mws, out.credentials().unwrap()).await;
    let me = aws_sdk_sts::Client::new(&root).get_caller_identity().send().await.unwrap();
    assert_eq!(me.arn(), Some(format!("arn:aws:iam::{account}:root").as_str()));
    let root_iam = aws_sdk_iam::Client::new(&root);
    root_iam.list_access_keys().send().await.unwrap();
    let err = root_iam.create_user().user_name("x").send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // Not into the management account itself.
    let err = sts
        .assume_root()
        .target_principal("123456789012")
        .task_policy_arn(
            PolicyDescriptorType::builder()
                .arn("arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials")
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));

    // Turning the features off stops root sessions again.
    let disabled = iam.disable_organizations_root_sessions().send().await.unwrap();
    assert_eq!(disabled.enabled_features().len(), 1);
    let err = sts
        .assume_root()
        .target_principal(&account)
        .task_policy_arn(
            PolicyDescriptorType::builder()
                .arn("arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials")
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDenied"));
    assert!(err.message().unwrap().ends_with("because centralized root access is not enabled for the organization"));
    let disabled = iam.disable_organizations_root_credentials_management().send().await.unwrap();
    assert!(disabled.enabled_features().is_empty());
    assert!(iam.list_organizations_features().send().await.unwrap().enabled_features().is_empty());
}

#[tokio::test]
async fn effective_tag_policies_and_delegation() {
    let o = org().await;
    let account = o.create_account("tagged").await;
    o.orgs.enable_policy_type().root_id(&o.root_id).policy_type(PolicyType::TagPolicy).send().await.unwrap();
    let base =
        r#"{"tags":{"costcenter":{"tag_key":{"@@assign":"CostCenter"},"tag_value":{"@@assign":["100","200"]}}}}"#;
    let extra = r#"{"tags":{"costcenter":{"tag_value":{"@@append":["300"]}}}}"#;
    for (name, content, target) in [("base", base, o.root_id.clone()), ("extra", extra, account.clone())] {
        let p = o
            .orgs
            .create_policy()
            .name(name)
            .description(name)
            .r#type(PolicyType::TagPolicy)
            .content(content)
            .send()
            .await
            .unwrap();
        let id = p.policy().unwrap().policy_summary().unwrap().id().unwrap().to_string();
        o.orgs.attach_policy().policy_id(&id).target_id(&target).send().await.unwrap();
    }
    let member = o.member_config(&account).await;
    let effective = Orgs::new(&member)
        .describe_effective_policy()
        .policy_type(aws_sdk_organizations::types::EffectivePolicyType::TagPolicy)
        .send()
        .await
        .unwrap();
    let content: serde_json::Value =
        serde_json::from_str(effective.effective_policy().unwrap().policy_content().unwrap()).unwrap();
    assert_eq!(
        content,
        serde_json::json!({"tags":{"costcenter":{"tag_key":"CostCenter","tag_value":["100","200","300"]}}})
    );

    // A delegated administrator can read the organization.
    let err = Orgs::new(&member).list_roots().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    let err = o
        .orgs
        .register_delegated_administrator()
        .account_id(&account)
        .service_principal("guardduty.amazonaws.com")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ConstraintViolationException"));
    o.orgs.enable_aws_service_access().service_principal("guardduty.amazonaws.com").send().await.unwrap();
    o.orgs
        .register_delegated_administrator()
        .account_id(&account)
        .service_principal("guardduty.amazonaws.com")
        .send()
        .await
        .unwrap();
    Orgs::new(&member).list_roots().send().await.unwrap();
    let admins = o.orgs.list_delegated_administrators().send().await.unwrap();
    assert_eq!(admins.delegated_administrators()[0].id(), Some(account.as_str()));
    let err = o.orgs.remove_account_from_organization().account_id(&account).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ConstraintViolationException"));

    let services = o.orgs.list_delegated_services_for_account().account_id(&account).send().await.unwrap();
    let principals: Vec<_> = services.delegated_services().iter().filter_map(|s| s.service_principal()).collect();
    assert_eq!(principals, ["guardduty.amazonaws.com"]);
    let access = o.orgs.list_aws_service_access_for_organization().send().await.unwrap();
    assert!(access
        .enabled_service_principals()
        .iter()
        .any(|p| p.service_principal() == Some("guardduty.amazonaws.com")));
    o.orgs
        .deregister_delegated_administrator()
        .account_id(&account)
        .service_principal("guardduty.amazonaws.com")
        .send()
        .await
        .unwrap();
    let err = o.orgs.list_delegated_services_for_account().account_id(&account).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccountNotRegisteredException"));
    let err = Orgs::new(&member).list_roots().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    o.orgs.disable_aws_service_access().service_principal("guardduty.amazonaws.com").send().await.unwrap();
    let access = o.orgs.list_aws_service_access_for_organization().send().await.unwrap();
    assert!(access
        .enabled_service_principals()
        .iter()
        .all(|p| p.service_principal() != Some("guardduty.amazonaws.com")));

    // Merging never fails here, so there are no validation errors to list.
    use aws_sdk_organizations::types::EffectivePolicyType;
    let invalid = o
        .orgs
        .list_accounts_with_invalid_effective_policy()
        .policy_type(EffectivePolicyType::TagPolicy)
        .send()
        .await
        .unwrap();
    assert!(invalid.accounts().is_empty());
    let errors = o
        .orgs
        .list_effective_policy_validation_errors()
        .account_id(&account)
        .policy_type(EffectivePolicyType::TagPolicy)
        .send()
        .await
        .unwrap();
    assert_eq!(errors.account_id(), Some(account.as_str()));
    assert!(errors.effective_policy_validation_errors().is_empty());
    let none = o
        .orgs
        .list_effective_policy_validation_errors()
        .account_id(&account)
        .policy_type(EffectivePolicyType::BackupPolicy)
        .send()
        .await
        .unwrap_err();
    assert_eq!(none.code(), Some("EffectivePolicyNotFoundException"));
}

#[tokio::test]
async fn units_accounts_and_closing() {
    let o = org().await;
    let ou = o.orgs.create_organizational_unit().parent_id(&o.root_id).name("Teams").send().await.unwrap();
    let ou_id = ou.organizational_unit().unwrap().id().unwrap().to_string();
    let renamed =
        o.orgs.update_organizational_unit().organizational_unit_id(&ou_id).name("Squads").send().await.unwrap();
    assert_eq!(renamed.organizational_unit().unwrap().name(), Some("Squads"));
    let described = o.orgs.describe_organizational_unit().organizational_unit_id(&ou_id).send().await.unwrap();
    assert_eq!(described.organizational_unit().unwrap().name(), Some("Squads"));
    let children = o.orgs.list_organizational_units_for_parent().parent_id(&o.root_id).send().await.unwrap();
    assert_eq!(children.organizational_units().len(), 1);
    let missing = o.orgs.describe_organizational_unit().organizational_unit_id("ou-abcd-12345678").send().await;
    assert_eq!(missing.unwrap_err().code(), Some("OrganizationalUnitNotFoundException"));

    let a = o.create_account("alpha").await;
    let b = o.create_account("beta").await;
    o.orgs
        .move_account()
        .account_id(&b)
        .source_parent_id(&o.root_id)
        .destination_parent_id(&ou_id)
        .send()
        .await
        .unwrap();
    let in_root = o.orgs.list_accounts_for_parent().parent_id(&o.root_id).send().await.unwrap();
    let ids: Vec<_> = in_root.accounts().iter().filter_map(|x| x.id()).collect();
    assert!(ids.contains(&a.as_str()) && !ids.contains(&b.as_str()));
    let in_ou = o.orgs.list_accounts_for_parent().parent_id(&ou_id).send().await.unwrap();
    assert_eq!(in_ou.accounts()[0].id(), Some(b.as_str()));

    let statuses = o.orgs.list_create_account_status().send().await.unwrap();
    assert_eq!(statuses.create_account_statuses().len(), 2);
    let failed = o
        .orgs
        .list_create_account_status()
        .states(aws_sdk_organizations::types::CreateAccountState::Failed)
        .send()
        .await
        .unwrap();
    assert!(failed.create_account_statuses().is_empty());

    let gov = o.orgs.create_gov_cloud_account().email("gov@example.com").account_name("gov").send().await;
    assert_eq!(gov.unwrap_err().code(), Some("ConstraintViolationException"));

    o.orgs.close_account().account_id(&a).send().await.unwrap();
    let closed = o.orgs.describe_account().account_id(&a).send().await.unwrap();
    let state = closed.account().unwrap().state().map(|s| s.as_str().to_string());
    assert!(matches!(state.as_deref(), Some("PENDING_CLOSURE") | Some("SUSPENDED")), "{state:?}");
    let again = o.orgs.close_account().account_id(&a).send().await.unwrap_err();
    assert_eq!(again.code(), Some("AccountAlreadyClosedException"));
    let mgmt = o.orgs.close_account().account_id("123456789012").send().await.unwrap_err();
    assert_eq!(mgmt.code(), Some("ConstraintViolationException"));
}

#[tokio::test]
async fn policies_targets_and_resource_policy() {
    let o = org().await;
    let account = o.create_account("target").await;
    let created = o
        .orgs
        .create_policy()
        .name("deny-users")
        .description("first")
        .r#type(PolicyType::ServiceControlPolicy)
        .content(DENY_CREATE_USER)
        .send()
        .await
        .unwrap();
    let id = created.policy().unwrap().policy_summary().unwrap().id().unwrap().to_string();
    let updated = o.orgs.update_policy().policy_id(&id).name("no-users").description("second").send().await.unwrap();
    assert_eq!(updated.policy().unwrap().policy_summary().unwrap().name(), Some("no-users"));
    let described = o.orgs.describe_policy().policy_id(&id).send().await.unwrap();
    let policy = described.policy().unwrap();
    assert_eq!(policy.policy_summary().unwrap().description(), Some("second"));
    assert_eq!(policy.content(), Some(DENY_CREATE_USER));

    let listed = o.orgs.list_policies().filter(PolicyType::ServiceControlPolicy).send().await.unwrap();
    let names: Vec<_> = listed.policies().iter().filter_map(|p| p.name()).collect();
    assert!(names.contains(&"FullAWSAccess") && names.contains(&"no-users"), "{names:?}");

    o.orgs.attach_policy().policy_id(&id).target_id(&account).send().await.unwrap();
    let targets = o.orgs.list_targets_for_policy().policy_id(&id).send().await.unwrap();
    assert_eq!(targets.targets()[0].target_id(), Some(account.as_str()));
    assert_eq!(targets.targets()[0].r#type().map(|t| t.as_str()), Some("ACCOUNT"));

    // Disabling the type detaches every policy of that type.
    o.orgs
        .disable_policy_type()
        .root_id(&o.root_id)
        .policy_type(PolicyType::ServiceControlPolicy)
        .send()
        .await
        .unwrap();
    let roots = o.orgs.list_roots().send().await.unwrap();
    assert!(roots.roots()[0].policy_types().iter().all(|t| t.r#type() != Some(&PolicyType::ServiceControlPolicy)));
    let member_iam = aws_sdk_iam::Client::new(&o.member_config(&account).await);
    member_iam.create_user().user_name("allowed-now").send().await.unwrap();

    let doc = r#"{"Version":"2012-10-17","Statement":[{"Sid":"ReadOnly","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"organizations:Describe*","Resource":"*"}]}"#;
    let put = o.orgs.put_resource_policy().content(doc).send().await.unwrap();
    assert!(put.resource_policy().unwrap().resource_policy_summary().unwrap().id().is_some());
    let got = o.orgs.describe_resource_policy().send().await.unwrap();
    assert_eq!(got.resource_policy().unwrap().content(), Some(doc));
    o.orgs.delete_resource_policy().send().await.unwrap();
    let gone = o.orgs.describe_resource_policy().send().await.unwrap_err();
    assert_eq!(gone.code(), Some("ResourcePolicyNotFoundException"));
}

#[tokio::test]
async fn handshakes_cancel_decline_and_all_features() {
    let mws = Mws::start().await;
    let orgs = Orgs::new(&mws.root_sdk_config().await);
    orgs.create_organization()
        .feature_set(aws_sdk_organizations::types::OrganizationFeatureSet::ConsolidatedBilling)
        .send()
        .await
        .unwrap();
    let created = orgs.create_account().email("x@example.com").account_name("x").send().await.unwrap();
    let request = created.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request).send().await.unwrap();
    let account = status.create_account_status().unwrap().account_id().unwrap().to_string();
    orgs.remove_account_from_organization().account_id(&account).send().await.unwrap();

    let invite = |notes: &'static str| {
        orgs.invite_account_to_organization()
            .target(HandshakeParty::builder().r#type(HandshakePartyType::Account).id(&account).build().unwrap())
            .notes(notes)
            .send()
    };
    let first = invite("one").await.unwrap().handshake().unwrap().id().unwrap().to_string();
    let described = orgs.describe_handshake().handshake_id(&first).send().await.unwrap();
    assert_eq!(described.handshake().unwrap().state().unwrap().as_str(), "OPEN");
    let canceled = orgs.cancel_handshake().handshake_id(&first).send().await.unwrap();
    assert_eq!(canceled.handshake().unwrap().state().unwrap().as_str(), "CANCELED");
    let again = orgs.cancel_handshake().handshake_id(&first).send().await.unwrap_err();
    assert_eq!(again.code(), Some("HandshakeAlreadyInStateException"));

    // The invited account declines the next invitation. It signs in as root
    // of its standalone account through a user it creates there.
    let second = invite("two").await.unwrap().handshake().unwrap().id().unwrap().to_string();
    let listed = orgs.list_handshakes_for_organization().send().await.unwrap();
    assert_eq!(listed.handshakes().len(), 2);
    let admin = user_with_policy(&mws, "billing-admin", Some(ADMIN)).await.1;
    let member = {
        let sts = aws_sdk_sts::Client::new(&admin);
        let creds = sts
            .assume_role()
            .role_arn(format!("arn:aws:iam::{account}:role/OrganizationAccountAccessRole"))
            .role_session_name("decline")
            .send()
            .await
            .unwrap();
        sts_config(&mws, creds.credentials().unwrap()).await
    };
    let declined = Orgs::new(&member).decline_handshake().handshake_id(&second).send().await.unwrap();
    assert_eq!(declined.handshake().unwrap().state().unwrap().as_str(), "DECLINED");

    let enable = orgs.enable_all_features().send().await.unwrap();
    let handshake = enable.handshake().unwrap();
    assert_eq!(handshake.action().unwrap().as_str(), "ENABLE_ALL_FEATURES");
    let open = orgs.list_handshakes_for_organization().send().await.unwrap();
    assert!(open.handshakes().iter().any(|h| h.id() == handshake.id()));
}

#[tokio::test]
async fn responsibility_transfers_between_organizations() {
    use aws_sdk_organizations::types::{ResponsibilityTransferType, Tag as OrgTag};
    use chrono::Datelike;
    let o = org().await;
    // A second organization, managed by an account that left the first.
    let other = o.create_account("other-mgmt").await;
    let other_cfg = o.member_config(&other).await;
    o.orgs.remove_account_from_organization().account_id(&other).send().await.unwrap();
    let other_orgs = Orgs::new(&other_cfg);
    other_orgs.create_organization().send().await.unwrap();

    let now = chrono::Utc::now();
    let next_month = chrono::NaiveDate::from_ymd_opt(
        if now.month() == 12 { now.year() + 1 } else { now.year() },
        if now.month() == 12 { 1 } else { now.month() + 1 },
        1,
    )
    .unwrap()
    .and_hms_opt(0, 0, 0)
    .unwrap()
    .and_utc();
    let start = aws_sdk_organizations::primitives::DateTime::from_secs(next_month.timestamp());
    let target = HandshakeParty::builder().r#type(HandshakePartyType::Account).id(&other).build().unwrap();
    let invite = o
        .orgs
        .invite_organization_to_transfer_responsibility()
        .r#type(ResponsibilityTransferType::Billing)
        .target(target.clone())
        .start_timestamp(start)
        .source_name("billing for other")
        .notes("we pay")
        .tags(OrgTag::builder().key("k").value("v").build().unwrap())
        .send()
        .await
        .unwrap();
    let handshake = invite.handshake().unwrap();
    let transfer_id = handshake
        .resources()
        .iter()
        .find(|r| r.r#type().map(|t| t.as_str()) == Some("RESPONSIBILITY_TRANSFER"))
        .and_then(|r| r.value())
        .unwrap()
        .to_string();
    let not_monthly = o
        .orgs
        .invite_organization_to_transfer_responsibility()
        .r#type(ResponsibilityTransferType::Billing)
        .target(target)
        .start_timestamp(aws_sdk_organizations::primitives::DateTime::from_secs(next_month.timestamp() + 3600))
        .source_name("bad")
        .send()
        .await
        .unwrap_err();
    assert_eq!(not_monthly.code(), Some("InvalidInputException"));

    let described = o.orgs.describe_responsibility_transfer().id(&transfer_id).send().await.unwrap();
    let t = described.responsibility_transfer().unwrap();
    assert_eq!(t.status().map(|s| s.as_str()), Some("REQUESTED"));
    assert_eq!(t.name(), Some("billing for other"));
    let renamed = o.orgs.update_responsibility_transfer().id(&transfer_id).name("renamed").send().await.unwrap();
    assert_eq!(renamed.responsibility_transfer().unwrap().name(), Some("renamed"));

    let inbound = o
        .orgs
        .list_inbound_responsibility_transfers()
        .r#type(ResponsibilityTransferType::Billing)
        .send()
        .await
        .unwrap();
    assert_eq!(inbound.responsibility_transfers()[0].id(), Some(transfer_id.as_str()));
    let outbound = other_orgs
        .list_outbound_responsibility_transfers()
        .r#type(ResponsibilityTransferType::Billing)
        .send()
        .await
        .unwrap();
    assert_eq!(outbound.responsibility_transfers()[0].id(), Some(transfer_id.as_str()));
    let seen_by_other = other_orgs.describe_responsibility_transfer().id(&transfer_id).send().await.unwrap();
    assert_eq!(seen_by_other.responsibility_transfer().unwrap().name(), Some("renamed"));

    let withdrawn = o.orgs.terminate_responsibility_transfer().id(&transfer_id).send().await.unwrap();
    assert_eq!(withdrawn.responsibility_transfer().unwrap().status().map(|s| s.as_str()), Some("WITHDRAWN"));
    let twice = o.orgs.terminate_responsibility_transfer().id(&transfer_id).send().await.unwrap_err();
    assert_eq!(twice.code(), Some("InvalidResponsibilityTransferTransitionException"));
    let missing = o.orgs.describe_responsibility_transfer().id("rt-0000000000").send().await.unwrap_err();
    assert_eq!(missing.code(), Some("ResponsibilityTransferNotFoundException"));
}

#[tokio::test]
async fn member_accounts_survive_export_and_import() {
    let o = org().await;
    let account = o.create_account("persisted").await;
    let (_, exported) = o.mws.control("GET", "/_mws/state", None).await;
    o.mws.control("POST", "/_mws/reset?to=empty", None).await;
    let err = o.orgs.describe_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AWSOrganizationsNotInUseException"));
    let (status, _) = o.mws.control("PUT", "/_mws/state", Some(&exported.to_string())).await;
    assert_eq!(status, 200);
    let accounts = o.orgs.list_accounts().send().await.unwrap();
    assert!(accounts.accounts().iter().any(|a| a.id() == Some(account.as_str())));
    // The admin user's keys and the member's role came back too.
    o.member_config(&account).await;
}

#[tokio::test]
async fn organizations_access_report_shows_member_activity() {
    let o = org().await;
    let member = o.create_account("reports").await;
    let member_cfg = o.member_config(&member).await;
    aws_sdk_iam::Client::new(&member_cfg).list_users().send().await.unwrap();

    let iam = aws_sdk_iam::Client::new(&o.mws.root_sdk_config().await);
    let path = format!("{}/{}", o.org_id, o.root_id);
    let job = iam.generate_organizations_access_report().entity_path(&path).send().await.unwrap();
    let report = iam.get_organizations_access_report().job_id(job.job_id().unwrap()).send().await.unwrap();
    assert_eq!(report.job_status().as_str(), "COMPLETED");
    let details = report.access_details();
    let iam_detail = details.iter().find(|d| d.service_namespace() == "iam").unwrap();
    assert!(iam_detail.last_authenticated_time().is_some());
    assert!(iam_detail.entity_path().unwrap().starts_with(&path), "{:?}", iam_detail.entity_path());
    let lambda = details.iter().find(|d| d.service_namespace() == "lambda").unwrap();
    assert!(lambda.last_authenticated_time().is_none());
    assert!(report.number_of_services_not_accessed().unwrap() < report.number_of_services_accessible().unwrap());

    // A report on just the member account sees only its own activity.
    let member_path = format!("{path}/{member}");
    let job = iam.generate_organizations_access_report().entity_path(&member_path).send().await.unwrap();
    let report = iam.get_organizations_access_report().job_id(job.job_id().unwrap()).send().await.unwrap();
    let iam_detail = report.access_details().iter().find(|d| d.service_namespace() == "iam").unwrap();
    assert_eq!(iam_detail.entity_path(), Some(member_path.as_str()));
}

#[tokio::test]
async fn access_key_info_names_member_accounts() {
    let o = org().await;
    let account = o.create_account("keys").await;
    let member = o.member_config(&account).await;
    let member_iam = aws_sdk_iam::Client::new(&member);
    member_iam.create_user().user_name("svc").send().await.unwrap();
    let key = member_iam.create_access_key().user_name("svc").send().await.unwrap();
    let akid = key.access_key().unwrap().access_key_id().to_string();
    let sts = aws_sdk_sts::Client::new(&o.admin);
    let info = sts.get_access_key_info().access_key_id(&akid).send().await.unwrap();
    assert_eq!(info.account(), Some(account.as_str()));
    use aws_credential_types::provider::ProvideCredentials;
    let session_key = member.credentials_provider().unwrap().provide_credentials().await.unwrap();
    let info = sts.get_access_key_info().access_key_id(session_key.access_key_id()).send().await.unwrap();
    assert_eq!(info.account(), Some(account.as_str()));
}

async fn advance_clock(mws: &Mws, days: i64) {
    let body = format!(r#"{{"advanceSeconds": {}}}"#, days * 86400);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn resource_tags_tagging_and_resource_arns_are_authorized() {
    let o = org().await;
    let keep = o.create_account("keep").await;
    let spare = o.create_account("spare").await;
    let security = o.create_account("security").await;
    o.orgs.tag_resource().resource_id(&keep).tags(tag("protected", "true")).send().await.unwrap();
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[
            {{"Effect":"Allow","Action":"organizations:*","Resource":"*"}},
            {{"Effect":"Deny","Action":"organizations:CloseAccount","Resource":"*","Condition":{{"StringEquals":{{"aws:ResourceTag/protected":"true"}}}}}},
            {{"Effect":"Deny","Action":"organizations:TagResource","Resource":"*"}},
            {{"Effect":"Deny","Action":"organizations:RegisterDelegatedAdministrator","Resource":"arn:aws:organizations::123456789012:account/{}/{keep}"}}]}}"#,
        o.org_id
    );
    let (_, cfg) = user_with_policy(&o.mws, "org-operator", Some(&policy)).await;
    let operator = Orgs::new(&cfg);

    // aws:ResourceTag on the account being closed.
    let err = operator.close_account().account_id(&keep).send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    operator.close_account().account_id(&spare).send().await.unwrap();

    // Creating with tags also needs organizations:TagResource.
    let err = operator
        .create_organizational_unit()
        .parent_id(&o.root_id)
        .name("Tagged")
        .tags(tag("team", "core"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    operator.create_organizational_unit().parent_id(&o.root_id).name("Untagged").send().await.unwrap();

    // Delegated administrators are authorized on the account's ARN.
    operator.enable_aws_service_access().service_principal("config.amazonaws.com").send().await.unwrap();
    let err = operator
        .register_delegated_administrator()
        .account_id(&keep)
        .service_principal("config.amazonaws.com")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    operator
        .register_delegated_administrator()
        .account_id(&security)
        .service_principal("config.amazonaws.com")
        .send()
        .await
        .unwrap();

    // Only the management account and delegated administrators may read
    // the organization's resource policy.
    let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"organizations:Describe*","Resource":"*"}]}"#;
    o.orgs.put_resource_policy().content(doc).send().await.unwrap();
    let plain = o.create_account("plain").await;
    let err = Orgs::new(&o.member_config(&plain).await).describe_resource_policy().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));
    let delegated = Orgs::new(&o.member_config(&security).await).describe_resource_policy().send().await.unwrap();
    assert_eq!(delegated.resource_policy().unwrap().content(), Some(doc));
}

#[tokio::test]
async fn creating_an_organization_needs_the_service_linked_role() {
    let mws = Mws::start().await;
    let orgs_only =
        r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"organizations:*","Resource":"*"}}"#;
    let (_, cfg) = user_with_policy(&mws, "orgs-only", Some(orgs_only)).await;
    let err = Orgs::new(&cfg).create_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("AccessDeniedException"));

    let with_slr = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"organizations:*","Resource":"*"},
        {"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*","Condition":{"StringEquals":{"iam:AWSServiceName":"organizations.amazonaws.com"}}}]}"#;
    let (_, cfg) = user_with_policy(&mws, "org-creator", Some(with_slr)).await;
    Orgs::new(&cfg).create_organization().send().await.unwrap();
    let roles = aws_sdk_iam::Client::new(&mws.root_sdk_config().await)
        .list_roles()
        .path_prefix("/aws-service-role/organizations.amazonaws.com/")
        .send()
        .await
        .unwrap();
    assert_eq!(roles.roles()[0].role_name(), "AWSServiceRoleForOrganizations");
}

#[tokio::test]
async fn waiting_periods_and_expiry_follow_the_clock() {
    let o = org().await;
    let created = o.create_account("fresh").await;
    let err = Orgs::new(&o.member_config(&created).await).leave_organization().send().await.unwrap_err();
    let reason = match err.into_service_error() {
        aws_sdk_organizations::operation::leave_organization::LeaveOrganizationError::ConstraintViolationException(
            e,
        ) => e.reason().map(|r| r.as_str().to_string()),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(reason.as_deref(), Some("WAIT_PERIOD_ACTIVE"));

    // Removing is not subject to the wait; the removed account is invited
    // back, and the invitation runs out after 15 days.
    let wanderer = o.create_account("wanderer").await;
    o.orgs.remove_account_from_organization().account_id(&wanderer).send().await.unwrap();
    let invite = o
        .orgs
        .invite_account_to_organization()
        .target(HandshakeParty::builder().r#type(HandshakePartyType::Account).id(&wanderer).build().unwrap())
        .send()
        .await
        .unwrap();
    let handshake = invite.handshake().unwrap();
    let lifetime = handshake.expiration_timestamp().unwrap().secs() - handshake.requested_timestamp().unwrap().secs();
    assert_eq!(lifetime, 15 * 86400);
    let id = handshake.id().unwrap().to_string();

    advance_clock(&o.mws, 16).await;
    let described = o.orgs.describe_handshake().handshake_id(&id).send().await.unwrap();
    assert_eq!(described.handshake().unwrap().state().unwrap().as_str(), "EXPIRED");
    // Four days on, the created account may leave.
    Orgs::new(&o.member_config(&created).await).leave_organization().send().await.unwrap();
}

#[tokio::test]
async fn errors_carry_the_reasons_aws_gives() {
    use aws_sdk_organizations::operation::attach_policy::AttachPolicyError;
    use aws_sdk_organizations::operation::create_policy::CreatePolicyError;
    use aws_sdk_organizations::operation::detach_policy::DetachPolicyError;
    use aws_sdk_organizations::operation::list_accounts::ListAccountsError;
    use aws_sdk_organizations::operation::list_handshakes_for_organization::ListHandshakesForOrganizationError;
    use aws_sdk_organizations::types::{ActionType, HandshakeFilter};
    let o = org().await;

    let err = o.orgs.list_accounts().next_token("not-a-token").send().await.unwrap_err();
    match err.into_service_error() {
        ListAccountsError::InvalidInputException(e) => {
            assert_eq!(e.reason().map(|r| r.as_str()), Some("INVALID_PAGINATION_TOKEN"))
        }
        other => panic!("unexpected {other:?}"),
    }

    let filter = HandshakeFilter::builder()
        .action_type(ActionType::InviteAccountToOrganization)
        .parent_handshake_id("h-abcdefghij")
        .build();
    let err = o.orgs.list_handshakes_for_organization().filter(filter).send().await.unwrap_err();
    match err.into_service_error() {
        ListHandshakesForOrganizationError::InvalidInputException(e) => {
            assert_eq!(e.reason().map(|r| r.as_str()), Some("MAX_FILTER_LIMIT_EXCEEDED"))
        }
        other => panic!("unexpected {other:?}"),
    }

    // Policies are stored as sent, so whitespace counts towards the limit.
    let padded = format!("{}{}", DENY_CREATE_USER, " ".repeat(5120));
    let err = o
        .orgs
        .create_policy()
        .name("padded")
        .description("")
        .r#type(PolicyType::ServiceControlPolicy)
        .content(padded)
        .send()
        .await
        .unwrap_err();
    match err.into_service_error() {
        CreatePolicyError::ConstraintViolationException(e) => {
            assert_eq!(e.reason().map(|r| r.as_str()), Some("POLICY_CONTENT_LIMIT_EXCEEDED"))
        }
        other => panic!("unexpected {other:?}"),
    }

    // RCPFullAWSAccess stays attached while RCPs are enabled.
    o.orgs
        .enable_policy_type()
        .root_id(&o.root_id)
        .policy_type(PolicyType::ResourceControlPolicy)
        .send()
        .await
        .unwrap();
    let err = o.orgs.detach_policy().policy_id("p-RCPFullAWSAccess").target_id(&o.root_id).send().await.unwrap_err();
    match err.into_service_error() {
        DetachPolicyError::InvalidInputException(e) => {
            assert_eq!(e.reason().map(|r| r.as_str()), Some("NON_DETACHABLE_POLICY"))
        }
        other => panic!("unexpected {other:?}"),
    }
    let err = o.orgs.attach_policy().policy_id("p-FullAWSAccess").target_id(&o.root_id).send().await.unwrap_err();
    assert!(matches!(err.into_service_error(), AttachPolicyError::DuplicatePolicyAttachmentException(_)));
}
