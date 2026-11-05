//! Provisioning: turning a permission set into an `AWSReservedSSO_*` role in
//! an account, as AWS does.

use mws_iam::ReservedRoleSpec;

use crate::common::*;
use crate::state::PermissionSet;
use crate::SsoAdmin;

/// The audience of the SAML assertions the AWS access portal signs users in
/// with.
pub const SAML_AUDIENCE: &str = "https://signin.aws.amazon.com/saml";

/// The SAML provider IAM Identity Center creates in each account it
/// provisions to.
pub fn provider_name(instance_id: &str) -> String {
    let id = instance_id.trim_start_matches("ssoins-").trim_start_matches("ins-");
    format!("AWSSSO_{id}_DO_NOT_DELETE")
}

/// `/aws-reserved/sso.amazonaws.com/`, with the Region for instances outside
/// us-east-1.
pub fn role_path(region: &str) -> String {
    if region == "us-east-1" {
        "/aws-reserved/sso.amazonaws.com/".into()
    } else {
        format!("/aws-reserved/sso.amazonaws.com/{region}/")
    }
}

fn metadata(entity_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{entity_id}"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    )
}

impl SsoAdmin {
    /// Provision `ps_arn` into `account`: create or update its role. Returns
    /// the role name, or why provisioning failed.
    pub(crate) fn provision_into(
        &self,
        partition: &str,
        instance_arn: &str,
        ps_arn: &str,
        account: &str,
    ) -> Result<String, String> {
        let (instance_id, region, ps, existing) = {
            let st = self.lock();
            let i = st.instances.get(instance_arn).ok_or("The instance no longer exists.")?;
            let ps: PermissionSet =
                i.permission_sets.get(ps_arn).cloned().ok_or("The permission set no longer exists.")?;
            let existing = i.provisioned.get(&(ps_arn.to_string(), account.to_string())).map(|p| p.role_name.clone());
            (i.id.clone(), i.primary_region.clone(), ps, existing)
        };
        if !self.iam.account_exists(account) {
            return Err(format!("Account {account} doesn't exist."));
        }
        let customer = |name: &str, path: &str| {
            self.iam.customer_managed_policy(account, Some(path), name).ok_or_else(|| {
                format!(
                    "Received a 404 status error: Policy arn:{partition}:iam::{account}:policy{path}{name} doesn't exist in account {account}."
                )
            })
        };
        let mut managed = ps.managed.clone();
        for (name, path) in &ps.customer_managed {
            managed.push(customer(name, path)?);
        }
        let boundary = match &ps.boundary {
            Some(b) => match (&b.managed_policy_arn, &b.customer_managed_policy_reference) {
                (Some(arn), _) => Some(arn.clone()),
                (None, Some(r)) => Some(customer(&r.name, r.path.as_deref().unwrap_or("/"))?),
                (None, None) => None,
            },
            None => None,
        };
        let provider = provider_name(&instance_id);
        let entity_id = format!("https://portal.sso.{region}.amazonaws.com/saml/assertion/{instance_id}");
        let provider_arn = self.iam.ensure_saml_provider(account, &provider, &metadata(&entity_id));
        let trust = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Federated":"{provider_arn}"}},"Action":["sts:AssumeRoleWithSAML","sts:TagSession"],"Condition":{{"StringEquals":{{"SAML:aud":"{SAML_AUDIENCE}"}}}}}}]}}"#
        );
        let role_name = existing.unwrap_or_else(|| {
            let mut name: String = format!("AWSReservedSSO_{}_", ps.name);
            name.push_str(&hex(16));
            name
        });
        self.iam.ensure_service_linked_role(account, SERVICE_PRINCIPAL, "AWSSSOServiceRolePolicy");
        self.iam.put_reserved_role(
            account,
            ReservedRoleSpec {
                name: role_name.clone(),
                path: role_path(&region),
                trust_policy: trust,
                description: None,
                max_session_duration: duration_seconds(&ps.session_duration).unwrap_or(3600) as i32,
                managed_policies: managed,
                inline_policies: ps.inline.iter().map(|d| ("AwsSSOInlinePolicy".to_string(), d.clone())).collect(),
                permissions_boundary: boundary,
            },
        );
        let mut st = self.lock();
        if let Some(i) = st.instances.get_mut(instance_arn) {
            i.provisioned.insert(
                (ps_arn.to_string(), account.to_string()),
                crate::state::Provisioned { role_name: role_name.clone(), version: ps.version },
            );
        }
        Ok(role_name)
    }

    /// Remove `ps_arn`'s role from `account`.
    pub(crate) fn deprovision(&self, instance_arn: &str, ps_arn: &str, account: &str) {
        let removed = {
            let mut st = self.lock();
            st.instances
                .get_mut(instance_arn)
                .and_then(|i| i.provisioned.remove(&(ps_arn.to_string(), account.to_string())))
        };
        if let Some(p) = removed {
            self.iam.delete_reserved_role(account, &p.role_name);
        }
    }
}
