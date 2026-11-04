//! OIDC providers, account aliases, summaries and authorization details.

use std::collections::BTreeMap;

use chrono::Utc;
use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::OidcProvider;
use crate::{wire, Iam};

fn no_such_provider(arn: &str) -> ServiceError {
    errors::no_such_entity(format!("OpenIDConnect Provider not found for arn {arn}"))
}

impl Iam {
    pub fn create_open_id_connect_provider(
        &self,
        ctx: &RequestContext,
        input: types::CreateOpenIDConnectProviderRequest,
    ) -> Result<types::CreateOpenIDConnectProviderResponse, ServiceError> {
        let url = input.url.trim_start_matches("https://").trim_end_matches('/').to_string();
        if !input.url.starts_with("https://") {
            return Err(validation("Invalid Openid Connect Provider URL. The URL must begin with https://"));
        }
        let arn = self.arn(&format!("oidc-provider/{url}"));
        let tags = tags_from_wire(input.tags)?;
        self.authorize_with(ctx, "CreateOpenIDConnectProvider", &arn, request_tag_context(&tags))?;
        let mut state = self.write();
        if state.oidc_providers.contains_key(&arn) {
            return Err(errors::entity_already_exists(format!("Provider with url {} already exists.", input.url)));
        }
        let out_tags = tags_to_wire(&tags);
        state.oidc_providers.insert(
            arn.clone(),
            OidcProvider {
                arn: arn.clone(),
                url,
                client_ids: input.client_id_list.unwrap_or_default(),
                thumbprints: input.thumbprint_list.unwrap_or_default(),
                created: Utc::now(),
                tags,
            },
        );
        Ok(types::CreateOpenIDConnectProviderResponse { open_id_connect_provider_arn: Some(arn), tags: out_tags })
    }

    pub fn get_open_id_connect_provider(
        &self,
        ctx: &RequestContext,
        input: types::GetOpenIDConnectProviderRequest,
    ) -> Result<types::GetOpenIDConnectProviderResponse, ServiceError> {
        let arn = input.open_id_connect_provider_arn;
        self.authorize(ctx, "GetOpenIDConnectProvider", &arn)?;
        let state = self.read();
        let p = state.oidc_providers.get(&arn).ok_or_else(|| no_such_provider(&arn))?;
        Ok(types::GetOpenIDConnectProviderResponse {
            url: Some(p.url.clone()),
            client_id_list: Some(p.client_ids.clone()),
            thumbprint_list: Some(p.thumbprints.clone()),
            create_date: Some(p.created),
            tags: tags_to_wire(&p.tags),
        })
    }

    pub fn list_open_id_connect_providers(
        &self,
        ctx: &RequestContext,
        _input: types::ListOpenIDConnectProvidersRequest,
    ) -> Result<types::ListOpenIDConnectProvidersResponse, ServiceError> {
        self.authorize(ctx, "ListOpenIDConnectProviders", "*")?;
        let state = self.read();
        Ok(types::ListOpenIDConnectProvidersResponse {
            open_id_connect_provider_list: Some(
                state
                    .oidc_providers
                    .keys()
                    .map(|arn| types::OpenIDConnectProviderListEntry { arn: Some(arn.clone()) })
                    .collect(),
            ),
        })
    }

    pub fn delete_open_id_connect_provider(
        &self,
        ctx: &RequestContext,
        input: types::DeleteOpenIDConnectProviderRequest,
    ) -> Result<(), ServiceError> {
        let arn = input.open_id_connect_provider_arn;
        self.authorize(ctx, "DeleteOpenIDConnectProvider", &arn)?;
        self.write().oidc_providers.remove(&arn).ok_or_else(|| no_such_provider(&arn))?;
        Ok(())
    }

    fn with_provider(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
        f: impl FnOnce(&mut OidcProvider) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, action, arn)?;
        let mut state = self.write();
        let p = state.oidc_providers.get_mut(arn).ok_or_else(|| no_such_provider(arn))?;
        f(p)
    }

    pub fn add_client_id_to_open_id_connect_provider(
        &self,
        ctx: &RequestContext,
        i: types::AddClientIDToOpenIDConnectProviderRequest,
    ) -> Result<(), ServiceError> {
        self.with_provider(ctx, "AddClientIDToOpenIDConnectProvider", &i.open_id_connect_provider_arn, |p| {
            if !p.client_ids.contains(&i.client_id) {
                p.client_ids.push(i.client_id);
            }
            Ok(())
        })
    }

    pub fn remove_client_id_from_open_id_connect_provider(
        &self,
        ctx: &RequestContext,
        i: types::RemoveClientIDFromOpenIDConnectProviderRequest,
    ) -> Result<(), ServiceError> {
        self.with_provider(ctx, "RemoveClientIDFromOpenIDConnectProvider", &i.open_id_connect_provider_arn, |p| {
            p.client_ids.retain(|c| *c != i.client_id);
            Ok(())
        })
    }

    pub fn update_open_id_connect_provider_thumbprint(
        &self,
        ctx: &RequestContext,
        i: types::UpdateOpenIDConnectProviderThumbprintRequest,
    ) -> Result<(), ServiceError> {
        self.with_provider(ctx, "UpdateOpenIDConnectProviderThumbprint", &i.open_id_connect_provider_arn, |p| {
            p.thumbprints = i.thumbprint_list;
            Ok(())
        })
    }

    pub fn tag_open_id_connect_provider(
        &self,
        ctx: &RequestContext,
        i: types::TagOpenIDConnectProviderRequest,
    ) -> Result<(), ServiceError> {
        let tags = tags_from_wire(Some(i.tags))?;
        self.with_provider(ctx, "TagOpenIDConnectProvider", &i.open_id_connect_provider_arn, |p| {
            merge_tags(&mut p.tags, tags, "TagsPerOpenIDConnectProvider")
        })
    }

    pub fn untag_open_id_connect_provider(
        &self,
        ctx: &RequestContext,
        i: types::UntagOpenIDConnectProviderRequest,
    ) -> Result<(), ServiceError> {
        self.with_provider(ctx, "UntagOpenIDConnectProvider", &i.open_id_connect_provider_arn, |p| {
            remove_tags(&mut p.tags, &i.tag_keys);
            Ok(())
        })
    }

    pub fn list_open_id_connect_provider_tags(
        &self,
        ctx: &RequestContext,
        i: types::ListOpenIDConnectProviderTagsRequest,
    ) -> Result<types::ListOpenIDConnectProviderTagsResponse, ServiceError> {
        let arn = i.open_id_connect_provider_arn;
        self.authorize(ctx, "ListOpenIDConnectProviderTags", &arn)?;
        let tags = self.read().oidc_providers.get(&arn).ok_or_else(|| no_such_provider(&arn))?.tags.clone();
        let (page, is_truncated, marker) = paginate(&tags, |(k, _)| k.clone(), i.marker.as_deref(), i.max_items)?;
        Ok(types::ListOpenIDConnectProviderTagsResponse { tags: tags_list(&page), is_truncated, marker })
    }

    // ---- account ------------------------------------------------------------

    pub fn create_account_alias(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccountAliasRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "CreateAccountAlias", "*")?;
        let mut state = self.write();
        if state.account_aliases.contains(&input.account_alias) {
            return Err(errors::entity_already_exists(format!(
                "The account alias {} already exists.",
                input.account_alias
            )));
        }
        state.account_aliases = vec![input.account_alias];
        Ok(())
    }

    pub fn delete_account_alias(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccountAliasRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteAccountAlias", "*")?;
        let mut state = self.write();
        if !state.account_aliases.contains(&input.account_alias) {
            return Err(errors::no_such_entity(format!("The account alias {} does not exist.", input.account_alias)));
        }
        state.account_aliases.clear();
        Ok(())
    }

    pub fn list_account_aliases(
        &self,
        ctx: &RequestContext,
        _input: types::ListAccountAliasesRequest,
    ) -> Result<types::ListAccountAliasesResponse, ServiceError> {
        self.authorize(ctx, "ListAccountAliases", "*")?;
        Ok(types::ListAccountAliasesResponse {
            account_aliases: self.read().account_aliases.clone(),
            is_truncated: false,
            marker: None,
        })
    }

    pub fn get_account_summary(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::GetAccountSummaryResponse, ServiceError> {
        self.authorize(ctx, "GetAccountSummary", "*")?;
        let s = self.read();
        let local_policies = s.policies.values().filter(|p| !p.aws_managed).count();
        let versions: usize = s.policies.values().filter(|p| !p.aws_managed).map(|p| p.versions.len()).sum();
        let mut m = BTreeMap::new();
        let mut put = |k: &str, v: usize| {
            m.insert(k.to_string(), v as i32);
        };
        put("Users", s.users.len());
        put("UsersQuota", 5000);
        put("Groups", s.groups.len());
        put("GroupsQuota", 300);
        put("Roles", s.roles.len());
        put("RolesQuota", 1000);
        put("Policies", local_policies);
        put("PoliciesQuota", 1500);
        put("PolicyVersionsInUse", versions);
        put("PolicyVersionsInUseQuota", 10000);
        put("InstanceProfiles", s.instance_profiles.len());
        put("InstanceProfilesQuota", 1000);
        put("Providers", s.oidc_providers.len() + s.saml_providers.len());
        put("AccountAccessKeysPresent", usize::from(!s.keys_for(None).is_empty()));
        put("AccountMFAEnabled", 0);
        put("AccountPasswordPresent", 0);
        put(
            "AccountSigningCertificatesPresent",
            usize::from(s.signing_certificates.values().any(|c| c.user.is_none())),
        );
        put("SigningCertificatesPerUserQuota", 2);
        put("MFADevices", s.mfa_devices.len());
        put("MFADevicesInUse", s.mfa_devices.values().filter(|d| d.enabled.is_some()).count());
        put("ServerCertificates", s.server_certificates.len());
        put("ServerCertificatesQuota", 20);
        put("AccessKeysPerUserQuota", 2);
        put("AttachedPoliciesPerUserQuota", MAX_MANAGED_POLICIES_PER_ENTITY);
        put("AttachedPoliciesPerGroupQuota", MAX_MANAGED_POLICIES_PER_ENTITY);
        put("AttachedPoliciesPerRoleQuota", MAX_MANAGED_POLICIES_PER_ENTITY);
        put("GroupsPerUserQuota", 10);
        put("PolicySizeQuota", MANAGED_POLICY_MAX_SIZE);
        put("UserPolicySizeQuota", 2048);
        put("GroupPolicySizeQuota", 5120);
        put("VersionsPerPolicyQuota", MAX_POLICY_VERSIONS);
        put(
            "GlobalEndpointTokenVersion",
            if s.global_endpoint_token_version.as_deref() == Some("v2Token") { 2 } else { 1 },
        );
        Ok(types::GetAccountSummaryResponse { summary_map: Some(m) })
    }

    pub fn get_account_authorization_details(
        &self,
        ctx: &RequestContext,
        input: types::GetAccountAuthorizationDetailsRequest,
    ) -> Result<types::GetAccountAuthorizationDetailsResponse, ServiceError> {
        self.authorize(ctx, "GetAccountAuthorizationDetails", "*")?;
        let s = self.read();
        let filter = input.filter.unwrap_or_default();
        let want = |k: &str| filter.is_empty() || filter.iter().any(|f| f == k);
        let details = |inline: &BTreeMap<String, String>| -> Option<Vec<types::PolicyDetail>> {
            Some(
                inline
                    .iter()
                    .map(|(n, d)| types::PolicyDetail {
                        policy_name: Some(n.clone()),
                        policy_document: Some(encode_document(d)),
                    })
                    .collect(),
            )
        };
        // One ordered list across all four kinds, so Marker and MaxItems
        // page through users, then groups, roles and policies, as AWS does.
        let mut entries: Vec<(String, Detail)> = Vec::new();
        if want("User") {
            entries.extend(s.users.iter().map(|(k, u)| {
                let d = types::UserDetail {
                    path: Some(u.path.clone()),
                    user_name: Some(u.name.clone()),
                    user_id: Some(u.id.clone()),
                    arn: Some(u.arn.clone()),
                    create_date: Some(u.created),
                    user_policy_list: details(&u.inline),
                    group_list: Some(s.groups_for_user(&u.name).iter().map(|g| g.name.clone()).collect()),
                    attached_managed_policies: Some(wire::attached(&u.attached, &s)),
                    permissions_boundary: wire::boundary(&u.permissions_boundary),
                    tags: tags_to_wire(&u.tags),
                };
                (format!("0/{k}"), Detail::User(d))
            }));
        }
        if want("Group") {
            entries.extend(s.groups.iter().map(|(k, g)| {
                let d = types::GroupDetail {
                    path: Some(g.path.clone()),
                    group_name: Some(g.name.clone()),
                    group_id: Some(g.id.clone()),
                    arn: Some(g.arn.clone()),
                    create_date: Some(g.created),
                    group_policy_list: details(&g.inline),
                    attached_managed_policies: Some(wire::attached(&g.attached, &s)),
                };
                (format!("1/{k}"), Detail::Group(d))
            }));
        }
        if want("Role") {
            entries.extend(s.roles.iter().map(|(k, r)| {
                let key = r.name.to_lowercase();
                let d = types::RoleDetail {
                    path: Some(r.path.clone()),
                    role_name: Some(r.name.clone()),
                    role_id: Some(r.id.clone()),
                    arn: Some(r.arn.clone()),
                    create_date: Some(r.created),
                    assume_role_policy_document: Some(encode_document(&r.trust_policy)),
                    instance_profile_list: Some(
                        s.instance_profiles
                            .values()
                            .filter(|ip| ip.roles.contains(&key))
                            .map(|ip| wire::instance_profile(ip, &s))
                            .collect(),
                    ),
                    role_policy_list: details(&r.inline),
                    attached_managed_policies: Some(wire::attached(&r.attached, &s)),
                    permissions_boundary: wire::boundary(&r.permissions_boundary),
                    tags: tags_to_wire(&r.tags),
                    role_last_used: wire::role(r).role_last_used,
                };
                (format!("2/{k}"), Detail::Role(Box::new(d)))
            }));
        }
        if want("LocalManagedPolicy") || want("AWSManagedPolicy") {
            entries.extend(
                s.policies
                    .iter()
                    .filter(|(_, p)| {
                        (p.aws_managed && want("AWSManagedPolicy") && s.attachment_count(&p.arn) > 0)
                            || (!p.aws_managed && want("LocalManagedPolicy"))
                    })
                    .map(|(k, p)| {
                        let d = types::ManagedPolicyDetail {
                            policy_name: Some(p.name.clone()),
                            policy_id: Some(p.id.clone()),
                            arn: Some(p.arn.clone()),
                            path: Some(p.path.clone()),
                            default_version_id: Some(p.default_version.clone()),
                            attachment_count: Some(s.attachment_count(&p.arn) as i32),
                            permissions_boundary_usage_count: Some(s.boundary_usage_count(&p.arn) as i32),
                            is_attachable: true,
                            description: p.description.clone(),
                            create_date: Some(p.created),
                            update_date: Some(p.updated),
                            policy_version_list: Some(
                                p.versions.iter().map(|v| wire::policy_version(p, v, true)).collect(),
                            ),
                        };
                        (format!("3/{k}"), Detail::Policy(d))
                    }),
            );
        }
        drop(s);
        let (page, is_truncated, marker) =
            paginate(&entries, |(k, _)| k.clone(), input.marker.as_deref(), input.max_items)?;
        let (mut users, mut groups, mut roles, mut policies) = (vec![], vec![], vec![], vec![]);
        for (_, d) in page {
            match d {
                Detail::User(u) => users.push(u),
                Detail::Group(g) => groups.push(g),
                Detail::Role(r) => roles.push(*r),
                Detail::Policy(p) => policies.push(p),
            }
        }
        Ok(types::GetAccountAuthorizationDetailsResponse {
            user_detail_list: Some(users),
            group_detail_list: Some(groups),
            role_detail_list: Some(roles),
            policies: Some(policies),
            is_truncated,
            marker,
        })
    }
}

#[derive(Clone)]
enum Detail {
    User(types::UserDetail),
    Group(types::GroupDetail),
    Role(Box<types::RoleDetail>),
    Policy(types::ManagedPolicyDetail),
}
