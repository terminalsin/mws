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

    // Attaching needs the policy type enabled.
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
    let err = o.orgs.attach_policy().policy_id(&scp_id).target_id(&account).send().await.unwrap_err();
    assert_eq!(err.code(), Some("PolicyTypeNotEnabledException"));
    let root = o
        .orgs
        .enable_policy_type()
        .root_id(&o.root_id)
        .policy_type(PolicyType::ServiceControlPolicy)
        .send()
        .await
        .unwrap();
    assert_eq!(root.root().unwrap().policy_types()[0].status().unwrap().as_str(), "ENABLED");
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
