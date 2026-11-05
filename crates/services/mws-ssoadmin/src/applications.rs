//! Applications (customer managed OAuth 2.0 applications and what they may
//! do) and trusted token issuers.

use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{Application, Instance, TokenIssuer};
use crate::SsoAdmin;

pub const CUSTOM_PROVIDER: &str = "applicationProvider/custom";
const CUSTOM_SAML_PROVIDER: &str = "applicationProvider/custom-saml";

pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";
pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

fn providers(partition: &str) -> Vec<types::ApplicationProvider> {
    let p = |suffix: &str, protocol: &str, name: &str, description: &str| types::ApplicationProvider {
        application_provider_arn: format!("arn:{partition}:sso::aws:{suffix}"),
        federation_protocol: Some(protocol.into()),
        display_data: Some(types::DisplayData {
            display_name: Some(name.into()),
            icon_url: None,
            description: Some(description.into()),
        }),
        resource_server_config: None,
    };
    vec![
        p(CUSTOM_PROVIDER, "OAUTH", "Customer managed application", "An OAuth 2.0 application you manage."),
        p(CUSTOM_SAML_PROVIDER, "SAML", "Custom SAML 2.0 application", "A SAML 2.0 application you manage."),
    ]
}

fn app_not_found(arn: &str) -> ServiceError {
    not_found(format!("Application {arn} doesn't exist."))
}

fn app_mut<'a>(i: &'a mut Instance, arn: &str) -> Result<&'a mut Application, ServiceError> {
    i.applications.get_mut(arn).ok_or_else(|| app_not_found(arn))
}

fn describe(a: &Application, instance_arn: &str, store_arn: Option<String>) -> types::DescribeApplicationResponse {
    types::DescribeApplicationResponse {
        application_arn: Some(a.arn.clone()),
        application_provider_arn: Some(a.provider.clone()),
        name: Some(a.name.clone()),
        application_account: Some(a.account.clone()),
        instance_arn: Some(instance_arn.to_string()),
        identity_store_arn: store_arn,
        status: Some(a.status.clone()),
        portal_options: a.portal_options.clone(),
        description: a.description.clone(),
        created_date: Some(a.created),
        created_from: None,
    }
}

fn grant_matches(grant_type: &str, grant: &types::Grant) -> bool {
    matches!(
        (grant_type, grant),
        (GRANT_AUTHORIZATION_CODE, types::Grant::AuthorizationCode(_))
            | (GRANT_REFRESH_TOKEN, types::Grant::RefreshToken(_))
            | (GRANT_JWT_BEARER, types::Grant::JwtBearer(_))
            | (GRANT_TOKEN_EXCHANGE, types::Grant::TokenExchange(_))
    )
}

fn tti_not_found(arn: &str) -> ServiceError {
    not_found(format!("Trusted token issuer {arn} doesn't exist."))
}

impl SsoAdmin {
    /// The instance owning an application or trusted token issuer, checked
    /// and authorized.
    fn owner_of(&self, ctx: &RequestContext, arn: &str, action: &str) -> Result<InstanceRef, ServiceError> {
        let inst = { self.instance_arn_for(&self.lock(), arn) };
        let inst = inst.ok_or_else(|| not_found(format!("Resource {arn} doesn't exist.")))?;
        self.instance(ctx, &inst, action, Some(arn))
    }

    fn application(&self, ctx: &RequestContext, arn: &str, action: &str) -> Result<InstanceRef, ServiceError> {
        let r = self.owner_of(ctx, arn, action)?;
        self.with_instance(&r.arn, |i| app_mut(i, arn).map(|_| ()))?;
        Ok(r)
    }

    fn with_app<T>(
        &self,
        r: &InstanceRef,
        arn: &str,
        f: impl FnOnce(&mut Application) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        self.with_instance(&r.arn, |i| f(app_mut(i, arn)?))
    }

    pub(crate) fn list_application_providers(
        &self,
        ctx: &RequestContext,
        input: types::ListApplicationProvidersRequest,
    ) -> Result<types::ListApplicationProvidersResponse, ServiceError> {
        ctx.authorize("sso:ListApplicationProviders", "*", Default::default())?;
        let (page, next_token) =
            paginate(providers(&ctx.partition), input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListApplicationProvidersResponse { application_providers: Some(page), next_token })
    }

    pub(crate) fn describe_application_provider(
        &self,
        ctx: &RequestContext,
        input: types::DescribeApplicationProviderRequest,
    ) -> Result<types::DescribeApplicationProviderResponse, ServiceError> {
        ctx.authorize("sso:DescribeApplicationProvider", &input.application_provider_arn, Default::default())?;
        let p = providers(&ctx.partition)
            .into_iter()
            .find(|p| p.application_provider_arn == input.application_provider_arn)
            .ok_or_else(|| not_found(format!("Application provider {} doesn't exist.", input.application_provider_arn)))?;
        Ok(types::DescribeApplicationProviderResponse {
            application_provider_arn: p.application_provider_arn,
            federation_protocol: p.federation_protocol,
            display_data: p.display_data,
            resource_server_config: p.resource_server_config,
        })
    }

    pub(crate) fn create_application(
        &self,
        ctx: &RequestContext,
        input: types::CreateApplicationRequest,
    ) -> Result<types::CreateApplicationResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:CreateApplication", None)?;
        let custom = format!("arn:{}:sso::aws:{CUSTOM_PROVIDER}", ctx.partition);
        if input.application_provider_arn != custom {
            if providers(&ctx.partition).iter().any(|p| p.application_provider_arn == input.application_provider_arn) {
                return Err(errors::validation(
                    "This API only creates OAuth 2.0 customer managed applications. Create SAML 2.0 applications in the console.",
                ));
            }
            return Err(not_found(format!("Application provider {} doesn't exist.", input.application_provider_arn)));
        }
        let tags = tags_from(input.tags)?;
        let store_arn = self.identity.store(&r.identity_store_id).map(|s| s.arn);
        self.with_instance(&r.arn, |i| {
            if i.applications.len() >= 3000 {
                return Err(errors::service_quota_exceeded("The instance has reached the maximum number of applications."));
            }
            let id: String = format!("apl-{}", hex(16));
            let arn = format!("arn:{}:sso::{}:application/{}/{id}", ctx.partition, ctx.caller.account_id, i.id);
            let app = Application {
                arn: arn.clone(),
                account: ctx.caller.account_id.clone(),
                provider: input.application_provider_arn,
                name: input.name,
                description: input.description,
                status: input.status.unwrap_or_else(|| "ENABLED".into()),
                portal_options: input.portal_options,
                created: ctx.received_at,
                tags,
                assignment_required: true,
                ..Default::default()
            };
            i.applications.insert(arn.clone(), app);
            Ok(types::CreateApplicationResponse {
                application_arn: Some(arn),
                instance_arn: Some(i.arn.clone()),
                identity_store_arn: store_arn,
            })
        })
    }

    pub(crate) fn describe_application(
        &self,
        ctx: &RequestContext,
        input: types::DescribeApplicationRequest,
    ) -> Result<types::DescribeApplicationResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:DescribeApplication")?;
        let store_arn = self.identity.store(&r.identity_store_id).map(|s| s.arn);
        self.with_app(&r, &input.application_arn, |a| Ok(describe(a, &r.arn, store_arn)))
    }

    pub(crate) fn list_applications(
        &self,
        ctx: &RequestContext,
        input: types::ListApplicationsRequest,
    ) -> Result<types::ListApplicationsResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListApplications", None)?;
        let store_arn = self.identity.store(&r.identity_store_id).map(|s| s.arn);
        let filter = input.filter.unwrap_or_default();
        let all = self.with_instance(&r.arn, |i| {
            Ok(i.applications
                .values()
                .filter(|a| filter.application_account.as_ref().is_none_or(|x| *x == a.account))
                .filter(|a| filter.application_provider.as_ref().is_none_or(|x| *x == a.provider))
                .map(|a| {
                    let d = describe(a, &r.arn, store_arn.clone());
                    types::Application {
                        application_arn: d.application_arn,
                        application_provider_arn: d.application_provider_arn,
                        name: d.name,
                        application_account: d.application_account,
                        instance_arn: d.instance_arn,
                        identity_store_arn: d.identity_store_arn,
                        status: d.status,
                        portal_options: d.portal_options,
                        description: d.description,
                        created_date: d.created_date,
                        created_from: d.created_from,
                    }
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListApplicationsResponse { applications: Some(page), next_token })
    }

    pub(crate) fn update_application(
        &self,
        ctx: &RequestContext,
        input: types::UpdateApplicationRequest,
    ) -> Result<types::UpdateApplicationResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:UpdateApplication")?;
        self.with_app(&r, &input.application_arn, |a| {
            if let Some(n) = input.name {
                a.name = n;
            }
            if let Some(d) = input.description {
                a.description = Some(d);
            }
            if let Some(s) = input.status {
                a.status = s;
            }
            if let Some(p) = input.portal_options {
                let current = a.portal_options.get_or_insert_with(|| types::PortalOptions {
                    sign_in_options: None,
                    visibility: "ENABLED".into(),
                });
                if p.sign_in_options.is_some() {
                    current.sign_in_options = p.sign_in_options;
                }
            }
            Ok(types::UpdateApplicationResponse {})
        })
    }

    pub(crate) fn delete_application(
        &self,
        ctx: &RequestContext,
        input: types::DeleteApplicationRequest,
    ) -> Result<types::DeleteApplicationResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:DeleteApplication")?;
        self.with_instance(&r.arn, |i| {
            i.applications.remove(&input.application_arn).ok_or_else(|| app_not_found(&input.application_arn))?;
            Ok(types::DeleteApplicationResponse {})
        })
    }

    pub(crate) fn put_application_assignment_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutApplicationAssignmentConfigurationRequest,
    ) -> Result<types::PutApplicationAssignmentConfigurationResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:PutApplicationAssignmentConfiguration")?;
        self.with_app(&r, &input.application_arn, |a| {
            a.assignment_required = input.assignment_required;
            Ok(types::PutApplicationAssignmentConfigurationResponse {})
        })
    }

    pub(crate) fn get_application_assignment_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetApplicationAssignmentConfigurationRequest,
    ) -> Result<types::GetApplicationAssignmentConfigurationResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:GetApplicationAssignmentConfiguration")?;
        self.with_app(&r, &input.application_arn, |a| {
            Ok(types::GetApplicationAssignmentConfigurationResponse { assignment_required: a.assignment_required })
        })
    }

    fn check_app_principal(&self, r: &InstanceRef, kind: &str, id: &str) -> Result<(), ServiceError> {
        let exists = match kind {
            "USER" => self.identity.user_exists(&r.identity_store_id, id),
            "GROUP" => self.identity.group_exists(&r.identity_store_id, id),
            _ => false,
        };
        if exists {
            Ok(())
        } else {
            Err(not_found(format!("Principal {id} of type {kind} doesn't exist in identity store {}.", r.identity_store_id)))
        }
    }

    pub(crate) fn create_application_assignment(
        &self,
        ctx: &RequestContext,
        input: types::CreateApplicationAssignmentRequest,
    ) -> Result<types::CreateApplicationAssignmentResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:CreateApplicationAssignment")?;
        self.check_app_principal(&r, &input.principal_type, &input.principal_id)?;
        self.with_app(&r, &input.application_arn, |a| {
            if !a.assignments.insert((input.principal_type, input.principal_id)) {
                return Err(errors::conflict("The principal is already assigned to the application."));
            }
            Ok(types::CreateApplicationAssignmentResponse {})
        })
    }

    pub(crate) fn delete_application_assignment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteApplicationAssignmentRequest,
    ) -> Result<types::DeleteApplicationAssignmentResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:DeleteApplicationAssignment")?;
        self.with_app(&r, &input.application_arn, |a| {
            if !a.assignments.remove(&(input.principal_type, input.principal_id)) {
                return Err(not_found("The application assignment doesn't exist."));
            }
            Ok(types::DeleteApplicationAssignmentResponse {})
        })
    }

    pub(crate) fn describe_application_assignment(
        &self,
        ctx: &RequestContext,
        input: types::DescribeApplicationAssignmentRequest,
    ) -> Result<types::DescribeApplicationAssignmentResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:DescribeApplicationAssignment")?;
        self.with_app(&r, &input.application_arn, |a| {
            if !a.assignments.contains(&(input.principal_type.clone(), input.principal_id.clone())) {
                return Err(not_found("The application assignment doesn't exist."));
            }
            Ok(types::DescribeApplicationAssignmentResponse {
                principal_type: Some(input.principal_type),
                principal_id: Some(input.principal_id),
                application_arn: Some(a.arn.clone()),
            })
        })
    }

    pub(crate) fn list_application_assignments(
        &self,
        ctx: &RequestContext,
        input: types::ListApplicationAssignmentsRequest,
    ) -> Result<types::ListApplicationAssignmentsResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:ListApplicationAssignments")?;
        let all = self.with_app(&r, &input.application_arn, |a| {
            Ok(a.assignments
                .iter()
                .map(|(t, id)| types::ApplicationAssignment {
                    application_arn: a.arn.clone(),
                    principal_id: id.clone(),
                    principal_type: t.clone(),
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListApplicationAssignmentsResponse { application_assignments: Some(page), next_token })
    }

    pub(crate) fn list_application_assignments_for_principal(
        &self,
        ctx: &RequestContext,
        input: types::ListApplicationAssignmentsForPrincipalRequest,
    ) -> Result<types::ListApplicationAssignmentsForPrincipalResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListApplicationAssignmentsForPrincipal", None)?;
        let only = input.filter.and_then(|f| f.application_arn);
        let key = (input.principal_type.clone(), input.principal_id.clone());
        let all = self.with_instance(&r.arn, |i| {
            Ok(i.applications
                .values()
                .filter(|a| only.as_ref().is_none_or(|o| *o == a.arn))
                .filter(|a| a.assignments.contains(&key))
                .map(|a| types::ApplicationAssignmentForPrincipal {
                    application_arn: Some(a.arn.clone()),
                    principal_id: Some(key.1.clone()),
                    principal_type: Some(key.0.clone()),
                })
                .collect::<Vec<_>>())
        })?;
        let max = (input.max_results > 0).then_some(input.max_results);
        let (page, next_token) = paginate(all, max, 100, input.next_token.as_deref())?;
        Ok(types::ListApplicationAssignmentsForPrincipalResponse { application_assignments: Some(page), next_token })
    }

    pub(crate) fn put_application_access_scope(
        &self,
        ctx: &RequestContext,
        input: types::PutApplicationAccessScopeRequest,
    ) -> Result<(), ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:PutApplicationAccessScope")?;
        self.with_app(&r, &input.application_arn, |a| {
            if !a.scopes.contains_key(&input.scope) && a.scopes.len() >= 25 {
                return Err(errors::service_quota_exceeded("The application has reached the maximum number of scopes."));
            }
            a.scopes.insert(input.scope, input.authorized_targets.unwrap_or_default());
            Ok(())
        })
    }

    pub(crate) fn get_application_access_scope(
        &self,
        ctx: &RequestContext,
        input: types::GetApplicationAccessScopeRequest,
    ) -> Result<types::GetApplicationAccessScopeResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:GetApplicationAccessScope")?;
        self.with_app(&r, &input.application_arn, |a| {
            let targets = a
                .scopes
                .get(&input.scope)
                .ok_or_else(|| not_found(format!("Scope {} doesn't exist for the application.", input.scope)))?;
            Ok(types::GetApplicationAccessScopeResponse {
                scope: input.scope.clone(),
                authorized_targets: (!targets.is_empty()).then(|| targets.clone()),
            })
        })
    }

    pub(crate) fn delete_application_access_scope(
        &self,
        ctx: &RequestContext,
        input: types::DeleteApplicationAccessScopeRequest,
    ) -> Result<(), ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:DeleteApplicationAccessScope")?;
        self.with_app(&r, &input.application_arn, |a| {
            a.scopes
                .remove(&input.scope)
                .ok_or_else(|| not_found(format!("Scope {} doesn't exist for the application.", input.scope)))?;
            Ok(())
        })
    }

    pub(crate) fn list_application_access_scopes(
        &self,
        ctx: &RequestContext,
        input: types::ListApplicationAccessScopesRequest,
    ) -> Result<types::ListApplicationAccessScopesResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:ListApplicationAccessScopes")?;
        let all = self.with_app(&r, &input.application_arn, |a| {
            Ok(a.scopes
                .iter()
                .map(|(s, t)| types::ScopeDetails {
                    scope: s.clone(),
                    authorized_targets: (!t.is_empty()).then(|| t.clone()),
                })
                .collect::<Vec<_>>())
        })?;
        let max = (input.max_results > 0).then_some(input.max_results);
        let (scopes, next_token) = paginate(all, max, 10, input.next_token.as_deref())?;
        Ok(types::ListApplicationAccessScopesResponse { scopes, next_token })
    }

    pub(crate) fn put_application_authentication_method(
        &self,
        ctx: &RequestContext,
        input: types::PutApplicationAuthenticationMethodRequest,
    ) -> Result<(), ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:PutApplicationAuthenticationMethod")?;
        let types::AuthenticationMethod::Iam(m) = &input.authentication_method;
        if input.authentication_method_type != "IAM" {
            return Err(errors::validation("The authentication method type must be IAM."));
        }
        if !serde_json::from_str::<serde_json::Value>(&m.actor_policy).is_ok_and(|v| v.is_object()) {
            return Err(errors::validation("ActorPolicy must be a policy document."));
        }
        self.with_app(&r, &input.application_arn, |a| {
            a.auth_methods.insert(input.authentication_method_type, input.authentication_method);
            Ok(())
        })
    }

    pub(crate) fn get_application_authentication_method(
        &self,
        ctx: &RequestContext,
        input: types::GetApplicationAuthenticationMethodRequest,
    ) -> Result<types::GetApplicationAuthenticationMethodResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:GetApplicationAuthenticationMethod")?;
        self.with_app(&r, &input.application_arn, |a| {
            let m = a
                .auth_methods
                .get(&input.authentication_method_type)
                .cloned()
                .ok_or_else(|| not_found("The authentication method doesn't exist for the application."))?;
            Ok(types::GetApplicationAuthenticationMethodResponse { authentication_method: Some(m) })
        })
    }

    pub(crate) fn delete_application_authentication_method(
        &self,
        ctx: &RequestContext,
        input: types::DeleteApplicationAuthenticationMethodRequest,
    ) -> Result<(), ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:DeleteApplicationAuthenticationMethod")?;
        self.with_app(&r, &input.application_arn, |a| {
            a.auth_methods
                .remove(&input.authentication_method_type)
                .ok_or_else(|| not_found("The authentication method doesn't exist for the application."))?;
            Ok(())
        })
    }

    pub(crate) fn list_application_authentication_methods(
        &self,
        ctx: &RequestContext,
        input: types::ListApplicationAuthenticationMethodsRequest,
    ) -> Result<types::ListApplicationAuthenticationMethodsResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:ListApplicationAuthenticationMethods")?;
        let all = self.with_app(&r, &input.application_arn, |a| {
            Ok(a.auth_methods
                .iter()
                .map(|(t, m)| types::AuthenticationMethodItem {
                    authentication_method_type: Some(t.clone()),
                    authentication_method: Some(m.clone()),
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, None, 100, input.next_token.as_deref())?;
        Ok(types::ListApplicationAuthenticationMethodsResponse { authentication_methods: Some(page), next_token })
    }

    pub(crate) fn put_application_grant(
        &self,
        ctx: &RequestContext,
        input: types::PutApplicationGrantRequest,
    ) -> Result<(), ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:PutApplicationGrant")?;
        if !grant_matches(&input.grant_type, &input.grant) {
            return Err(errors::validation(format!("The grant doesn't match the grant type {}.", input.grant_type)));
        }
        if let types::Grant::JwtBearer(j) = &input.grant {
            let known: Vec<String> = self.with_instance(&r.arn, |i| Ok(i.token_issuers.keys().cloned().collect()))?;
            for t in j.authorized_token_issuers.iter().flatten() {
                if let Some(arn) = &t.trusted_token_issuer_arn {
                    if !known.contains(arn) {
                        return Err(tti_not_found(arn));
                    }
                }
            }
        }
        self.with_app(&r, &input.application_arn, |a| {
            a.grants.insert(input.grant_type, input.grant);
            Ok(())
        })
    }

    pub(crate) fn get_application_grant(
        &self,
        ctx: &RequestContext,
        input: types::GetApplicationGrantRequest,
    ) -> Result<types::GetApplicationGrantResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:GetApplicationGrant")?;
        self.with_app(&r, &input.application_arn, |a| {
            let grant = a
                .grants
                .get(&input.grant_type)
                .cloned()
                .ok_or_else(|| not_found(format!("Grant {} doesn't exist for the application.", input.grant_type)))?;
            Ok(types::GetApplicationGrantResponse { grant })
        })
    }

    pub(crate) fn delete_application_grant(
        &self,
        ctx: &RequestContext,
        input: types::DeleteApplicationGrantRequest,
    ) -> Result<(), ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:DeleteApplicationGrant")?;
        self.with_app(&r, &input.application_arn, |a| {
            a.grants
                .remove(&input.grant_type)
                .ok_or_else(|| not_found(format!("Grant {} doesn't exist for the application.", input.grant_type)))?;
            Ok(())
        })
    }

    pub(crate) fn list_application_grants(
        &self,
        ctx: &RequestContext,
        input: types::ListApplicationGrantsRequest,
    ) -> Result<types::ListApplicationGrantsResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:ListApplicationGrants")?;
        let all = self.with_app(&r, &input.application_arn, |a| {
            Ok(a.grants
                .iter()
                .map(|(t, g)| types::GrantItem { grant_type: t.clone(), grant: g.clone() })
                .collect::<Vec<_>>())
        })?;
        let (grants, next_token) = paginate(all, None, 100, input.next_token.as_deref())?;
        Ok(types::ListApplicationGrantsResponse { grants, next_token })
    }

    pub(crate) fn put_application_session_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutApplicationSessionConfigurationRequest,
    ) -> Result<types::PutApplicationSessionConfigurationResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:PutApplicationSessionConfiguration")?;
        self.with_app(&r, &input.application_arn, |a| {
            a.background_sessions = input.user_background_session_application_status;
            Ok(types::PutApplicationSessionConfigurationResponse {})
        })
    }

    pub(crate) fn get_application_session_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetApplicationSessionConfigurationRequest,
    ) -> Result<types::GetApplicationSessionConfigurationResponse, ServiceError> {
        let r = self.application(ctx, &input.application_arn, "sso:GetApplicationSessionConfiguration")?;
        self.with_app(&r, &input.application_arn, |a| {
            Ok(types::GetApplicationSessionConfigurationResponse {
                user_background_session_application_status: Some(
                    a.background_sessions.clone().unwrap_or_else(|| "DISABLED".into()),
                ),
            })
        })
    }

    pub(crate) fn create_trusted_token_issuer(
        &self,
        ctx: &RequestContext,
        input: types::CreateTrustedTokenIssuerRequest,
    ) -> Result<types::CreateTrustedTokenIssuerResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:CreateTrustedTokenIssuer", None)?;
        let types::TrustedTokenIssuerConfiguration::OidcJwtConfiguration(config) =
            input.trusted_token_issuer_configuration;
        if !config.issuer_url.starts_with("https://") {
            return Err(errors::validation("The issuer URL must use HTTPS."));
        }
        let tags = tags_from(input.tags)?;
        self.with_instance(&r.arn, |i| {
            if i.token_issuers.values().any(|t| t.name == input.name) {
                return Err(errors::conflict(format!("A trusted token issuer named {} already exists.", input.name)));
            }
            if i.token_issuers.values().any(|t| t.config.issuer_url == config.issuer_url) {
                return Err(errors::conflict(format!(
                    "A trusted token issuer for {} already exists.",
                    config.issuer_url
                )));
            }
            let arn = format!(
                "arn:{}:sso::{}:trustedTokenIssuer/{}/tti-{}",
                ctx.partition,
                i.owner,
                i.id,
                uuid::Uuid::new_v4()
            );
            i.token_issuers.insert(
                arn.clone(),
                TokenIssuer { arn: arn.clone(), name: input.name, kind: input.trusted_token_issuer_type, config, tags },
            );
            Ok(types::CreateTrustedTokenIssuerResponse { trusted_token_issuer_arn: Some(arn) })
        })
    }

    fn token_issuer(&self, ctx: &RequestContext, arn: &str, action: &str) -> Result<InstanceRef, ServiceError> {
        let r = self.owner_of(ctx, arn, action).map_err(|e| if e.code == "ResourceNotFoundException" { tti_not_found(arn) } else { e })?;
        self.with_instance(&r.arn, |i| i.token_issuers.get(arn).map(|_| ()).ok_or_else(|| tti_not_found(arn)))?;
        Ok(r)
    }

    pub(crate) fn describe_trusted_token_issuer(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTrustedTokenIssuerRequest,
    ) -> Result<types::DescribeTrustedTokenIssuerResponse, ServiceError> {
        let arn = input.trusted_token_issuer_arn;
        let r = self.token_issuer(ctx, &arn, "sso:DescribeTrustedTokenIssuer")?;
        self.with_instance(&r.arn, |i| {
            let t = i.token_issuers.get(&arn).ok_or_else(|| tti_not_found(&arn))?;
            Ok(types::DescribeTrustedTokenIssuerResponse {
                trusted_token_issuer_arn: Some(t.arn.clone()),
                name: Some(t.name.clone()),
                trusted_token_issuer_type: Some(t.kind.clone()),
                trusted_token_issuer_configuration: Some(types::TrustedTokenIssuerConfiguration::OidcJwtConfiguration(
                    t.config.clone(),
                )),
            })
        })
    }

    pub(crate) fn list_trusted_token_issuers(
        &self,
        ctx: &RequestContext,
        input: types::ListTrustedTokenIssuersRequest,
    ) -> Result<types::ListTrustedTokenIssuersResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListTrustedTokenIssuers", None)?;
        let all = self.with_instance(&r.arn, |i| {
            Ok(i.token_issuers
                .values()
                .map(|t| types::TrustedTokenIssuerMetadata {
                    trusted_token_issuer_arn: Some(t.arn.clone()),
                    name: Some(t.name.clone()),
                    trusted_token_issuer_type: Some(t.kind.clone()),
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListTrustedTokenIssuersResponse { trusted_token_issuers: Some(page), next_token })
    }

    pub(crate) fn update_trusted_token_issuer(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTrustedTokenIssuerRequest,
    ) -> Result<types::UpdateTrustedTokenIssuerResponse, ServiceError> {
        let arn = input.trusted_token_issuer_arn;
        let r = self.token_issuer(ctx, &arn, "sso:UpdateTrustedTokenIssuer")?;
        self.with_instance(&r.arn, |i| {
            if let Some(n) = &input.name {
                if i.token_issuers.values().any(|t| t.arn != arn && t.name == *n) {
                    return Err(errors::conflict(format!("A trusted token issuer named {n} already exists.")));
                }
            }
            let t = i.token_issuers.get_mut(&arn).ok_or_else(|| tti_not_found(&arn))?;
            if let Some(n) = input.name {
                t.name = n;
            }
            if let Some(types::TrustedTokenIssuerUpdateConfiguration::OidcJwtConfiguration(c)) =
                input.trusted_token_issuer_configuration
            {
                if let Some(v) = c.claim_attribute_path {
                    t.config.claim_attribute_path = v;
                }
                if let Some(v) = c.identity_store_attribute_path {
                    t.config.identity_store_attribute_path = v;
                }
                if let Some(v) = c.jwks_retrieval_option {
                    t.config.jwks_retrieval_option = v;
                }
            }
            Ok(types::UpdateTrustedTokenIssuerResponse {})
        })
    }

    pub(crate) fn delete_trusted_token_issuer(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTrustedTokenIssuerRequest,
    ) -> Result<types::DeleteTrustedTokenIssuerResponse, ServiceError> {
        let arn = input.trusted_token_issuer_arn;
        let r = self.token_issuer(ctx, &arn, "sso:DeleteTrustedTokenIssuer")?;
        self.with_instance(&r.arn, |i| {
            i.token_issuers.remove(&arn).ok_or_else(|| tti_not_found(&arn))?;
            Ok(types::DeleteTrustedTokenIssuerResponse {})
        })
    }
}
