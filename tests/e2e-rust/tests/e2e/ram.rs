//! AWS RAM through the official SDK: sharing a Private CA really grants
//! (and revokes) cross-account access, through invitations, the
//! organization, and RAM's managed permissions.

use aws_sdk_acmpca::primitives::Blob;
use aws_sdk_acmpca::types::{ResourceOwner as PcaOwner, SigningAlgorithm, Validity, ValidityPeriodType};
use aws_sdk_organizations::Client as Orgs;
use aws_sdk_ram::error::ProvideErrorMetadata;
use aws_sdk_ram::types::{
    PermissionType, PermissionTypeFilter, ResourceOwner, ResourceShareAssociationType, ResourceShareFeatureSet, Tag,
};
use aws_sdk_ram::Client as Ram;
use mws_e2e::{sts_config, user_with_policy, Mws};

use crate::acmpca::{active_root, leaf_csr};

const ADMIN: &str = r#"{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;
const DEFAULT_PERMISSION: &str = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionCertificateAuthority";
const REVOKE_PERMISSION: &str = "arn:aws:ram::aws:permission/AWSRAMRevokeCertificateCertificateAuthority";

struct World {
    mws: Mws,
    orgs: Orgs,
    admin: aws_config::SdkConfig,
    root: aws_config::SdkConfig,
}

async fn world() -> World {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let orgs = Orgs::new(&root);
    orgs.create_organization().send().await.unwrap();
    let (_, admin) = user_with_policy(&mws, "admin", Some(ADMIN)).await;
    World { mws, orgs, admin, root }
}

impl World {
    async fn account(&self, name: &str) -> String {
        let out =
            self.orgs.create_account().email(format!("{name}@example.com")).account_name(name).send().await.unwrap();
        let id = out.create_account_status().unwrap().id().unwrap();
        let st = self.orgs.describe_create_account_status().create_account_request_id(id).send().await.unwrap();
        st.create_account_status().unwrap().account_id().unwrap().to_string()
    }

    async fn member(&self, account: &str) -> aws_config::SdkConfig {
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

/// Issue an end-entity certificate from `ca` with `pca`: `Ok(arn)` or the
/// error code.
async fn try_issue(pca: &aws_sdk_acmpca::Client, ca: &str) -> Result<String, String> {
    pca.issue_certificate()
        .certificate_authority_arn(ca)
        .csr(Blob::new(leaf_csr("member.example.test").as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withrsa)
        .validity(Validity::builder().value(30).r#type(ValidityPeriodType::Days).build().unwrap())
        .send()
        .await
        .map(|o| o.certificate_arn().unwrap().to_string())
        .map_err(|e| aws_sdk_acmpca::error::ProvideErrorMetadata::code(&e).unwrap_or_default().to_string())
}

#[tokio::test]
async fn sharing_a_ca_with_another_account_grants_and_revokes_access() {
    let w = world().await;
    let member = w.account("member").await;
    let member_cfg = w.member(&member).await;
    let owner_pca = aws_sdk_acmpca::Client::new(&w.root);
    let member_pca = aws_sdk_acmpca::Client::new(&member_cfg);
    let ram = Ram::new(&w.root);
    let member_ram = Ram::new(&member_cfg);
    let (ca, _) = active_root(&owner_pca).await;

    // Not shared: the member can't issue from the owner's CA.
    assert_eq!(try_issue(&member_pca, &ca).await.unwrap_err(), "AccessDeniedException");

    let types = ram.list_resource_types().send().await.unwrap();
    assert!(types.resource_types().iter().any(|t| t.resource_type() == Some("acm-pca:CertificateAuthority")));

    // Sharing with an account (organization sharing is off) sends an
    // invitation; nothing is granted until it is accepted.
    let share = ram
        .create_resource_share()
        .name("ca-share")
        .resource_arns(&ca)
        .principals(&member)
        .tags(Tag::builder().key("team").value("pki").build())
        .send()
        .await
        .unwrap();
    let share = share.resource_share().unwrap();
    let share_arn = share.resource_share_arn().unwrap().to_string();
    assert_eq!(share.status().unwrap().as_str(), "ACTIVE");
    assert_eq!(share.feature_set(), Some(&ResourceShareFeatureSet::Standard));
    assert_eq!(try_issue(&member_pca, &ca).await.unwrap_err(), "AccessDeniedException");

    let principal = ram
        .get_resource_share_associations()
        .association_type(ResourceShareAssociationType::Principal)
        .resource_share_arns(&share_arn)
        .send()
        .await
        .unwrap();
    let p = &principal.resource_share_associations()[0];
    assert_eq!(p.associated_entity(), Some(member.as_str()));
    assert_eq!(p.status().unwrap().as_str(), "ASSOCIATING");
    assert_eq!(p.external(), Some(true));

    let invitations = member_ram.get_resource_share_invitations().send().await.unwrap();
    let inv = &invitations.resource_share_invitations()[0];
    assert_eq!(inv.status().unwrap().as_str(), "PENDING");
    assert_eq!(inv.sender_account_id(), Some("123456789012"));
    let inv_arn = inv.resource_share_invitation_arn().unwrap().to_string();
    let pending =
        member_ram.list_pending_invitation_resources().resource_share_invitation_arn(&inv_arn).send().await.unwrap();
    assert_eq!(pending.resources()[0].arn(), Some(ca.as_str()));
    assert_eq!(pending.resources()[0].r#type(), Some("acm-pca:CertificateAuthority"));
    // Only the receiver sees it.
    let err = ram.accept_resource_share_invitation().resource_share_invitation_arn(&inv_arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceShareInvitationArnNotFoundException"));

    let accepted =
        member_ram.accept_resource_share_invitation().resource_share_invitation_arn(&inv_arn).send().await.unwrap();
    assert_eq!(accepted.resource_share_invitation().unwrap().status().unwrap().as_str(), "ACCEPTED");
    let err =
        member_ram.accept_resource_share_invitation().resource_share_invitation_arn(&inv_arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceShareInvitationAlreadyAcceptedException"));

    // Now the member issues from the shared CA, with the default
    // permission's template only.
    let cert = try_issue(&member_pca, &ca).await.expect("the share grants IssueCertificate");
    assert!(cert.starts_with(&ca));
    let got = member_pca.get_certificate().certificate_authority_arn(&ca).certificate_arn(&cert).send().await.unwrap();
    assert!(got.certificate().unwrap().contains("BEGIN CERTIFICATE"));
    let err = member_pca
        .issue_certificate()
        .certificate_authority_arn(&ca)
        .csr(Blob::new(leaf_csr("x.example.test").as_bytes()))
        .signing_algorithm(SigningAlgorithm::Sha256Withrsa)
        .template_arn("arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1")
        .validity(Validity::builder().value(30).r#type(ValidityPeriodType::Days).build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_acmpca::error::ProvideErrorMetadata::code(&err), Some("AccessDeniedException"));
    // Revocation isn't in the default permission.
    let err = member_pca
        .revoke_certificate()
        .certificate_authority_arn(&ca)
        .certificate_serial(cert.rsplit('/').next().unwrap())
        .revocation_reason(aws_sdk_acmpca::types::RevocationReason::Superseded)
        .send()
        .await
        .unwrap_err();
    assert_eq!(aws_sdk_acmpca::error::ProvideErrorMetadata::code(&err), Some("AccessDeniedException"));

    // The member sees the CA as shared with it.
    let listed =
        member_pca.list_certificate_authorities().resource_owner(PcaOwner::OtherAccounts).send().await.unwrap();
    assert_eq!(listed.certificate_authorities()[0].arn(), Some(ca.as_str()));
    let resources = member_ram.list_resources().resource_owner(ResourceOwner::OtherAccounts).send().await.unwrap();
    assert_eq!(resources.resources()[0].arn(), Some(ca.as_str()));
    let shares = member_ram.get_resource_shares().resource_owner(ResourceOwner::OtherAccounts).send().await.unwrap();
    assert_eq!(shares.resource_shares()[0].resource_share_arn(), Some(share_arn.as_str()));
    let principals = member_ram.list_principals().resource_owner(ResourceOwner::OtherAccounts).send().await.unwrap();
    assert_eq!(principals.principals()[0].id(), Some("123456789012"));
    let principals = ram.list_principals().resource_owner(ResourceOwner::SelfValue).send().await.unwrap();
    assert_eq!(principals.principals()[0].id(), Some(member.as_str()));

    // RAM's policy is the CA's resource policy.
    let policies = ram.get_resource_policies().resource_arns(&ca).send().await.unwrap();
    let policy: serde_json::Value = serde_json::from_str(&policies.policies()[0]).unwrap();
    let text = policy.to_string();
    assert!(text.contains(&format!("arn:aws:iam::{member}:root")), "{text}");
    assert!(text.contains("EndEntityCertificate/V1"), "{text}");
    let ca_policy = owner_pca.get_policy().resource_arn(&ca).send().await.unwrap();
    assert!(ca_policy.policy().unwrap().contains(&member));

    // Swap in the revoke permission: issuing stops, revoking works.
    ram.associate_resource_share_permission()
        .resource_share_arn(&share_arn)
        .permission_arn(REVOKE_PERMISSION)
        .replace(true)
        .send()
        .await
        .unwrap();
    let perms = ram.list_resource_share_permissions().resource_share_arn(&share_arn).send().await.unwrap();
    assert_eq!(perms.permissions().len(), 1);
    assert_eq!(perms.permissions()[0].arn(), Some(REVOKE_PERMISSION));
    assert_eq!(try_issue(&member_pca, &ca).await.unwrap_err(), "AccessDeniedException");
    member_pca
        .revoke_certificate()
        .certificate_authority_arn(&ca)
        .certificate_serial(cert.rsplit('/').next().unwrap())
        .revocation_reason(aws_sdk_acmpca::types::RevocationReason::Superseded)
        .send()
        .await
        .unwrap();
    let assoc = ram.list_permission_associations().permission_arn(REVOKE_PERMISSION).send().await.unwrap();
    assert_eq!(assoc.permissions()[0].resource_share_arn(), Some(share_arn.as_str()));
    let work = ram
        .replace_permission_associations()
        .from_permission_arn(REVOKE_PERMISSION)
        .to_permission_arn(DEFAULT_PERMISSION)
        .send()
        .await
        .unwrap();
    let work = work.replace_permission_associations_work().unwrap();
    assert_eq!(work.status().unwrap().as_str(), "COMPLETED");
    let works = ram.list_replace_permission_associations_work().work_ids(work.id().unwrap()).send().await.unwrap();
    assert_eq!(works.replace_permission_associations_works().len(), 1);
    try_issue(&member_pca, &ca).await.expect("default permission is back");

    // Removing the member takes the access away again.
    ram.disassociate_resource_share().resource_share_arn(&share_arn).principals(&member).send().await.unwrap();
    assert_eq!(try_issue(&member_pca, &ca).await.unwrap_err(), "AccessDeniedException");
    assert!(ram.get_resource_policies().resource_arns(&ca).send().await.unwrap().policies().is_empty());

    // Tags, updates, deletion.
    ram.tag_resource()
        .resource_share_arn(&share_arn)
        .tags(Tag::builder().key("env").value("test").build())
        .send()
        .await
        .unwrap();
    ram.untag_resource().resource_share_arn(&share_arn).tag_keys("team").send().await.unwrap();
    let updated = ram
        .update_resource_share()
        .resource_share_arn(&share_arn)
        .name("renamed")
        .allow_external_principals(false)
        .send()
        .await
        .unwrap();
    let updated = updated.resource_share().unwrap();
    assert_eq!(updated.name(), Some("renamed"));
    assert_eq!(updated.tags().iter().map(|t| t.key().unwrap()).collect::<Vec<_>>(), vec!["env"]);
    // External principals are now refused.
    let err =
        ram.associate_resource_share().resource_share_arn(&share_arn).principals(&member).send().await.unwrap_err();
    assert_eq!(err.code(), Some("OperationNotPermittedException"));
    ram.delete_resource_share().resource_share_arn(&share_arn).send().await.unwrap();
    let shares = ram
        .get_resource_shares()
        .resource_owner(ResourceOwner::SelfValue)
        .resource_share_status("DELETED".into())
        .send()
        .await
        .unwrap();
    assert_eq!(shares.resource_shares().len(), 1);
}

#[tokio::test]
async fn organization_sharing_needs_no_invitation_and_rejections_grant_nothing() {
    let w = world().await;
    let a = w.account("alpha").await;
    let b = w.account("beta").await;
    let a_pca = aws_sdk_acmpca::Client::new(&w.member(&a).await);
    let b_cfg = w.member(&b).await;
    let b_pca = aws_sdk_acmpca::Client::new(&b_cfg);
    let ram = Ram::new(&w.admin);
    let pca = aws_sdk_acmpca::Client::new(&w.root);
    let (ca, _) = active_root(&pca).await;

    // A rejected invitation grants nothing.
    let share = ram.create_resource_share().name("invite").resource_arns(&ca).principals(&b).send().await.unwrap();
    let share_arn = share.resource_share().unwrap().resource_share_arn().unwrap().to_string();
    let b_ram = Ram::new(&b_cfg);
    let inv = b_ram.get_resource_share_invitations().resource_share_arns(&share_arn).send().await.unwrap();
    let inv_arn = inv.resource_share_invitations()[0].resource_share_invitation_arn().unwrap().to_string();
    let rejected =
        b_ram.reject_resource_share_invitation().resource_share_invitation_arn(&inv_arn).send().await.unwrap();
    assert_eq!(rejected.resource_share_invitation().unwrap().status().unwrap().as_str(), "REJECTED");
    let err =
        b_ram.accept_resource_share_invitation().resource_share_invitation_arn(&inv_arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceShareInvitationAlreadyRejectedException"));
    assert_eq!(try_issue(&b_pca, &ca).await.unwrap_err(), "AccessDeniedException");

    // Sharing with the organization needs it enabled, by the management account.
    let org = w.orgs.describe_organization().send().await.unwrap();
    let org = org.organization().unwrap();
    let org_arn = org.arn().unwrap().to_string();
    let err = ram.create_resource_share().name("org").resource_arns(&ca).principals(&org_arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("OperationNotPermittedException"));
    let err = Ram::new(&b_cfg).enable_sharing_with_aws_organization().send().await.unwrap_err();
    assert_eq!(err.code(), Some("OperationNotPermittedException"));
    let enabled = ram.enable_sharing_with_aws_organization().send().await.unwrap();
    assert_eq!(enabled.return_value(), Some(true));
    let services = w.orgs.list_aws_service_access_for_organization().send().await.unwrap();
    assert!(services.enabled_service_principals().iter().any(|s| s.service_principal() == Some("ram.amazonaws.com")));

    // An OU covers the accounts in it, at once and without invitations.
    let root_id = w.orgs.list_roots().send().await.unwrap().roots()[0].id().unwrap().to_string();
    let ou = w.orgs.create_organizational_unit().parent_id(&root_id).name("pki").send().await.unwrap();
    let ou = ou.organizational_unit().unwrap();
    w.orgs
        .move_account()
        .account_id(&a)
        .source_parent_id(&root_id)
        .destination_parent_id(ou.id().unwrap())
        .send()
        .await
        .unwrap();
    let ou_share = ram
        .create_resource_share()
        .name("ou")
        .resource_arns(&ca)
        .principals(ou.arn().unwrap())
        .allow_external_principals(false)
        .send()
        .await
        .unwrap();
    let ou_share_arn = ou_share.resource_share().unwrap().resource_share_arn().unwrap().to_string();
    try_issue(&a_pca, &ca).await.expect("alpha is in the OU");
    assert_eq!(try_issue(&b_pca, &ca).await.unwrap_err(), "AccessDeniedException");

    // The whole organization: beta too.
    ram.associate_resource_share().resource_share_arn(&ou_share_arn).principals(&org_arn).send().await.unwrap();
    try_issue(&b_pca, &ca).await.expect("beta is in the organization");
    let assoc = ram
        .get_resource_share_associations()
        .association_type(ResourceShareAssociationType::Principal)
        .resource_share_arns(&ou_share_arn)
        .send()
        .await
        .unwrap();
    assert!(assoc.resource_share_associations().iter().all(|a| a.status().unwrap().as_str() == "ASSOCIATED"));
    // Accounts inside the organization are no longer external either.
    let direct = ram
        .create_resource_share()
        .name("direct")
        .resource_arns(&ca)
        .principals(&b)
        .allow_external_principals(false)
        .send()
        .await
        .unwrap();
    let direct_arn = direct.resource_share().unwrap().resource_share_arn().unwrap().to_string();
    let assoc = ram
        .get_resource_share_associations()
        .association_type(ResourceShareAssociationType::Principal)
        .resource_share_arns(&direct_arn)
        .send()
        .await
        .unwrap();
    assert_eq!(assoc.resource_share_associations()[0].external(), Some(false));
    assert_eq!(assoc.resource_share_associations()[0].status().unwrap().as_str(), "ASSOCIATED");
}

#[tokio::test]
async fn customer_managed_permissions_and_versions() {
    let mws = Mws::start().await;
    let root = mws.root_sdk_config().await;
    let ram = Ram::new(&root);
    let pca = aws_sdk_acmpca::Client::new(&root);
    let (ca, _) = active_root(&pca).await;

    let managed = ram.list_permissions().resource_type("acm-pca:CertificateAuthority").send().await.unwrap();
    assert!(managed
        .permissions()
        .iter()
        .any(|p| p.arn() == Some(DEFAULT_PERMISSION) && p.is_resource_type_default() == Some(true)));
    let got = ram.get_permission().permission_arn(DEFAULT_PERMISSION).send().await.unwrap();
    let got = got.permission().unwrap();
    assert_eq!(got.permission_type(), Some(&PermissionType::AwsManaged));
    assert!(got.permission().unwrap().contains("acm-pca:IssueCertificate"));

    // Templates are validated against the resource type's actions.
    let err = ram
        .create_permission()
        .name("Bad")
        .resource_type("acm-pca:CertificateAuthority")
        .policy_template(r#"{"Effect":"Allow","Action":["s3:GetObject"]}"#)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("MalformedPolicyTemplateException"));
    let created = ram
        .create_permission()
        .name("ReadOnlyCa")
        .resource_type("acm-pca:CertificateAuthority")
        .policy_template(r#"{"Effect":"Allow","Action":["acm-pca:DescribeCertificateAuthority"]}"#)
        .tags(Tag::builder().key("k").value("v").build())
        .send()
        .await
        .unwrap();
    let perm = created.permission().unwrap().arn().unwrap().to_string();
    assert_eq!(perm, "arn:aws:ram:us-east-1:123456789012:permission/ReadOnlyCa");
    let err = ram
        .create_permission()
        .name("ReadOnlyCa")
        .resource_type("acm-pca:CertificateAuthority")
        .policy_template(r#"{"Effect":"Allow","Action":["acm-pca:DescribeCertificateAuthority"]}"#)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("PermissionAlreadyExistsException"));
    let v2 = ram
        .create_permission_version()
        .permission_arn(&perm)
        .policy_template(r#"{"Effect":"Allow","Action":["acm-pca:DescribeCertificateAuthority","acm-pca:ListTags"]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(v2.permission().unwrap().version(), Some("2"));
    assert_eq!(v2.permission().unwrap().default_version(), Some(false));
    let versions = ram.list_permission_versions().permission_arn(&perm).send().await.unwrap();
    assert_eq!(versions.permissions().len(), 2);
    ram.set_default_permission_version().permission_arn(&perm).permission_version(2).send().await.unwrap();
    let err = ram.delete_permission_version().permission_arn(&perm).permission_version(2).send().await.unwrap_err();
    assert_eq!(err.code(), Some("OperationNotPermittedException"));
    ram.delete_permission_version().permission_arn(&perm).permission_version(1).send().await.unwrap();
    let got = ram.get_permission().permission_arn(&perm).send().await.unwrap();
    assert_eq!(got.permission().unwrap().version(), Some("2"));
    assert!(got.permission().unwrap().permission().unwrap().contains("ListTags"));
    let customer = ram.list_permissions().permission_type(PermissionTypeFilter::CustomerManaged).send().await.unwrap();
    assert_eq!(customer.permissions().len(), 1);
    ram.tag_resource().resource_arn(&perm).tags(Tag::builder().key("k2").value("v2").build()).send().await.unwrap();
    ram.untag_resource().resource_arn(&perm).tag_keys("k").send().await.unwrap();

    // A share using it, with a service principal and source account.
    let share = ram
        .create_resource_share()
        .name("perm")
        .resource_arns(&ca)
        .principals("pca-connector-scep.amazonaws.com")
        .sources("123456789012")
        .permission_arns(&perm)
        .send()
        .await
        .unwrap();
    let share_arn = share.resource_share().unwrap().resource_share_arn().unwrap().to_string();
    let sources = ram.list_source_associations().resource_share_arns(&share_arn).send().await.unwrap();
    assert_eq!(sources.source_associations()[0].source_id(), Some("123456789012"));
    assert_eq!(sources.source_associations()[0].source_type(), Some("ACCOUNT"));
    let policy = ram.get_resource_policies().resource_arns(&ca).send().await.unwrap();
    let text = &policy.policies()[0];
    assert!(text.contains("pca-connector-scep.amazonaws.com") && text.contains("aws:SourceAccount"), "{text}");
    let err = ram.delete_permission().permission_arn(&perm).send().await.unwrap_err();
    assert_eq!(err.code(), Some("OperationNotPermittedException"));
    // Resources of the type need a permission, so it can only be replaced.
    let err = ram
        .disassociate_resource_share_permission()
        .resource_share_arn(&share_arn)
        .permission_arn(&perm)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("OperationNotPermittedException"));
    ram.disassociate_resource_share().resource_share_arn(&share_arn).resource_arns(&ca).send().await.unwrap();
    ram.disassociate_resource_share_permission()
        .resource_share_arn(&share_arn)
        .permission_arn(&perm)
        .send()
        .await
        .unwrap();
    let deleted = ram.delete_permission().permission_arn(&perm).send().await.unwrap();
    assert_eq!(deleted.permission_status().unwrap().as_str(), "DELETED");
}

#[tokio::test]
async fn put_policy_shows_up_as_a_share_created_from_policy() {
    let w = world().await;
    let member = w.account("member").await;
    let pca = aws_sdk_acmpca::Client::new(&w.root);
    let ram = Ram::new(&w.root);
    let (ca, _) = active_root(&pca).await;
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Issue",
            "Effect": "Allow",
            "Principal": {"AWS": member},
            "Action": ["acm-pca:IssueCertificate"],
            "Resource": ca,
            "Condition": {"StringEquals": {"acm-pca:TemplateArn": "arn:aws:acm-pca:::template/EndEntityCertificate/V1"}}
        }]
    });
    pca.put_policy().resource_arn(&ca).policy(policy.to_string()).send().await.unwrap();
    let shares = ram.get_resource_shares().resource_owner(ResourceOwner::SelfValue).send().await.unwrap();
    let share = &shares.resource_shares()[0];
    assert_eq!(share.feature_set(), Some(&ResourceShareFeatureSet::CreatedFromPolicy));
    let share_arn = share.resource_share_arn().unwrap().to_string();
    let err = ram
        .associate_resource_share()
        .resource_share_arn(&share_arn)
        .principals("111122223333")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("OperationNotPermittedException"));

    // Promotion needs a standard twin of the policy's permission first.
    let err = ram.promote_resource_share_created_from_policy().resource_share_arn(&share_arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("UnmatchedPolicyPermissionException"));
    let perms = ram.list_resource_share_permissions().resource_share_arn(&share_arn).send().await.unwrap();
    let from_policy = perms.permissions()[0].arn().unwrap().to_string();
    let promoted = ram
        .promote_permission_created_from_policy()
        .permission_arn(&from_policy)
        .name("IssueEndEntity")
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.permission().unwrap().feature_set().unwrap().as_str(), "STANDARD");
    let ok = ram.promote_resource_share_created_from_policy().resource_share_arn(&share_arn).send().await.unwrap();
    assert_eq!(ok.return_value(), Some(true));
    let shares = ram
        .get_resource_shares()
        .resource_owner(ResourceOwner::SelfValue)
        .resource_share_arns(&share_arn)
        .send()
        .await
        .unwrap();
    assert_eq!(shares.resource_shares()[0].feature_set(), Some(&ResourceShareFeatureSet::Standard));
    let principals = ram
        .list_principals()
        .resource_owner(ResourceOwner::SelfValue)
        .resource_share_arns(&share_arn)
        .send()
        .await
        .unwrap();
    assert_eq!(principals.principals()[0].id(), Some(member.as_str()));
    // It is RAM-managed now: the member issues through it.
    let member_pca = aws_sdk_acmpca::Client::new(&w.member(&member).await);
    try_issue(&member_pca, &ca).await.expect("the promoted share grants IssueCertificate");
}
