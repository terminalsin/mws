//! What the AWS access portal (`mws-ssoportal`) and the OIDC service
//! (`mws-ssooidc`) read: instances, which accounts and roles a user may
//! reach, and applications with their grants.

use std::collections::BTreeMap;

use crate::generated::types;
use crate::provision::{provider_name, SAML_AUDIENCE};
use crate::state::{Instance, InstanceKind};
use crate::SsoAdmin;

/// An instance, as the portal and OIDC service see it.
#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub arn: String,
    pub id: String,
    pub owner: String,
    pub region: String,
    pub identity_store_id: String,
    pub organization: bool,
}

/// A permission set a user may use in an account, through its
/// provisioned role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRole {
    pub account: String,
    /// The permission set's name: what the portal calls the role.
    pub permission_set_name: String,
    pub role_arn: String,
    /// The SAML provider the role trusts.
    pub provider_arn: String,
    pub saml_audience: String,
    /// The permission set's session duration, in seconds.
    pub session_seconds: i64,
}

/// An application and what it allows.
#[derive(Debug, Clone)]
pub struct ApplicationInfo {
    pub arn: String,
    pub account: String,
    pub instance_arn: String,
    pub identity_store_id: String,
    pub enabled: bool,
    pub assignment_required: bool,
    /// (principal type, principal id).
    pub assignments: Vec<(String, String)>,
    pub scopes: Vec<String>,
    /// Grant type → grant.
    pub grants: BTreeMap<String, types::Grant>,
    /// The IAM authentication method's actor policy, if one is set.
    pub actor_policy: Option<String>,
}

/// A trusted token issuer.
#[derive(Debug, Clone)]
pub struct TokenIssuerInfo {
    pub arn: String,
    pub issuer_url: String,
    pub claim_attribute_path: String,
    pub identity_store_attribute_path: String,
}

fn info(i: &Instance) -> InstanceInfo {
    InstanceInfo {
        arn: i.arn.clone(),
        id: i.id.clone(),
        owner: i.owner.clone(),
        region: i.primary_region.clone(),
        identity_store_id: i.identity_store_id.clone(),
        organization: i.kind == InstanceKind::Organization,
    }
}

impl SsoAdmin {
    /// The instance whose identity store is `identity_store_id`.
    pub fn instance_for_identity_store(&self, identity_store_id: &str) -> Option<InstanceInfo> {
        self.lock().instances.values().find(|i| i.identity_store_id == identity_store_id).map(info)
    }

    pub fn instance_info(&self, instance_arn: &str) -> Option<InstanceInfo> {
        self.lock().instances.get(instance_arn).map(info)
    }

    /// Every permission set `user_id` (directly or through its groups) is
    /// assigned in any account, with the role it is provisioned as.
    pub fn account_roles(&self, identity_store_id: &str, user_id: &str) -> Vec<AccountRole> {
        let groups = self.identity.groups_of(identity_store_id, user_id);
        let partition = self.iam.partition().to_string();
        let st = self.lock();
        let Some(i) = st.instances.values().find(|i| i.identity_store_id == identity_store_id) else {
            return Vec::new();
        };
        let mut out: Vec<AccountRole> = Vec::new();
        for a in &i.assignments {
            let mine = match a.principal_type.as_str() {
                "USER" => a.principal_id == user_id,
                "GROUP" => groups.contains(&a.principal_id),
                _ => false,
            };
            if !mine {
                continue;
            }
            let (Some(ps), Some(p)) =
                (i.permission_sets.get(&a.permission_set), i.provisioned.get(&(a.permission_set.clone(), a.account.clone())))
            else {
                continue;
            };
            let role = AccountRole {
                account: a.account.clone(),
                permission_set_name: ps.name.clone(),
                role_arn: format!(
                    "arn:{partition}:iam::{}:role{}{}",
                    a.account,
                    crate::provision::role_path(&i.primary_region),
                    p.role_name
                ),
                provider_arn: format!("arn:{partition}:iam::{}:saml-provider/{}", a.account, provider_name(&i.id)),
                saml_audience: SAML_AUDIENCE.to_string(),
                session_seconds: crate::common::duration_seconds(&ps.session_duration).unwrap_or(3600),
            };
            if !out.contains(&role) {
                out.push(role);
            }
        }
        out
    }

    /// The session tags attribute-based access control gives `user_id`:
    /// each configured key with its `${path:...}` source resolved from the
    /// user's attributes (keys whose source is empty are left out).
    pub fn access_control_tags(&self, identity_store_id: &str, user_id: &str) -> BTreeMap<String, String> {
        let config = {
            let st = self.lock();
            st.instances
                .values()
                .find(|i| i.identity_store_id == identity_store_id)
                .and_then(|i| i.access_control.clone())
        };
        let (Some(config), Some(user)) = (config, self.identity.user(identity_store_id, user_id)) else {
            return BTreeMap::new();
        };
        let mut tags = BTreeMap::new();
        for a in config.access_control_attributes {
            let Some(source) = a.value.source.first() else { continue };
            let value = match source.strip_prefix("${path:").and_then(|s| s.strip_suffix('}')) {
                Some(path) => user.attribute(path).into_iter().next(),
                None => Some(source.clone()),
            };
            if let Some(v) = value.filter(|v| !v.is_empty()) {
                tags.insert(a.key, v);
            }
        }
        tags
    }

    pub fn application_info(&self, application_arn: &str) -> Option<ApplicationInfo> {
        let st = self.lock();
        st.instances.values().find_map(|i| {
            let a = i.applications.get(application_arn)?;
            Some(ApplicationInfo {
                arn: a.arn.clone(),
                account: a.account.clone(),
                instance_arn: i.arn.clone(),
                identity_store_id: i.identity_store_id.clone(),
                enabled: a.status == "ENABLED",
                assignment_required: a.assignment_required,
                assignments: a.assignments.iter().cloned().collect(),
                scopes: a.scopes.keys().cloned().collect(),
                grants: a.grants.clone(),
                actor_policy: a.auth_methods.get("IAM").map(|m| {
                    let types::AuthenticationMethod::Iam(m) = m;
                    m.actor_policy.clone()
                }),
            })
        })
    }

    pub fn token_issuer_info(&self, arn: &str) -> Option<TokenIssuerInfo> {
        let st = self.lock();
        st.instances.values().find_map(|i| {
            let t = i.token_issuers.get(arn)?;
            Some(TokenIssuerInfo {
                arn: t.arn.clone(),
                issuer_url: t.config.issuer_url.clone(),
                claim_attribute_path: t.config.claim_attribute_path.clone(),
                identity_store_attribute_path: t.config.identity_store_attribute_path.clone(),
            })
        })
    }
}
