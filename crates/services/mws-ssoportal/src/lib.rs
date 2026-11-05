//! The AWS access portal API (`sso`) for MWS: what the AWS CLI and SDKs call
//! with an IAM Identity Center access token to list the accounts and roles
//! a user may use and to get credentials for one.
//!
//! The access token comes from `mws-ssooidc`. Accounts and roles are the
//! user's account assignments (directly or through groups) in
//! `mws-ssoadmin`; credentials are real STS sessions for the provisioned
//! `AWSReservedSSO_*` role, issued through the role's trust policy (its
//! Identity Center SAML provider) with the session named after the user and
//! tagged with the instance's attributes for access control.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ssoportal_generated.rs"));
}

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_organizations::Organizations;
use mws_ssoadmin::{AccountRole, SsoAdmin};
use mws_ssooidc::{SsoOidc, TokenOwner};
use mws_sts::{SamlFederation, Sts};

use generated::{errors, types, Handler};

/// The AWS access portal. Keeps no state of its own.
#[derive(Clone)]
pub struct SsoPortal {
    oidc: SsoOidc,
    admin: SsoAdmin,
    sts: Sts,
    organizations: Organizations,
}

impl SsoPortal {
    pub fn new(oidc: SsoOidc, admin: SsoAdmin, sts: Sts, organizations: Organizations) -> Self {
        Self { oidc, admin, sts, organizations }
    }

    fn owner(&self, ctx: &RequestContext, token: &str) -> Result<TokenOwner, ServiceError> {
        self.oidc
            .portal_token_owner(token, ctx.received_at)
            .ok_or_else(|| errors::unauthorized("Session token not found or invalid"))
    }

    fn roles(&self, owner: &TokenOwner) -> Vec<AccountRole> {
        self.admin.account_roles(&owner.identity_store_id, &owner.user_id)
    }
}

fn paginate<T>(items: Vec<T>, max: Option<i32>, token: Option<&str>) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token.filter(|t| !t.is_empty()) {
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| errors::invalid_request("Invalid next token"))?,
        None => 0,
    };
    let max = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(20);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    Ok((page, (start + max < total).then(|| format!("mws-{}", start + max))))
}

fn no_access() -> ServiceError {
    ServiceError::client("ForbiddenException", 403, "No access")
}

#[async_trait::async_trait]
impl Handler for SsoPortal {
    async fn list_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountsRequest,
    ) -> Result<types::ListAccountsResponse, ServiceError> {
        let owner = self.owner(ctx, &input.access_token)?;
        let mut accounts: Vec<String> = self.roles(&owner).into_iter().map(|r| r.account).collect();
        accounts.sort();
        accounts.dedup();
        let list: Vec<types::AccountInfo> = accounts
            .into_iter()
            .map(|id| {
                let s = self.organizations.account_summary(&id);
                types::AccountInfo {
                    account_name: s.as_ref().map(|s| s.name.clone()),
                    email_address: s.map(|s| s.email),
                    account_id: Some(id),
                }
            })
            .collect();
        let (page, next_token) = paginate(list, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAccountsResponse { next_token, account_list: Some(page) })
    }

    async fn list_account_roles(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountRolesRequest,
    ) -> Result<types::ListAccountRolesResponse, ServiceError> {
        let owner = self.owner(ctx, &input.access_token)?;
        let mut names: Vec<String> = self
            .roles(&owner)
            .into_iter()
            .filter(|r| r.account == input.account_id)
            .map(|r| r.permission_set_name)
            .collect();
        names.sort();
        names.dedup();
        let list = names
            .into_iter()
            .map(|n| types::RoleInfo { role_name: Some(n), account_id: Some(input.account_id.clone()) })
            .collect();
        let (page, next_token) = paginate(list, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAccountRolesResponse { next_token, role_list: Some(page) })
    }

    async fn get_role_credentials(
        &self,
        ctx: &RequestContext,
        input: types::GetRoleCredentialsRequest,
    ) -> Result<types::GetRoleCredentialsResponse, ServiceError> {
        let owner = self.owner(ctx, &input.access_token)?;
        let role = self
            .roles(&owner)
            .into_iter()
            .find(|r| r.account == input.account_id && r.permission_set_name == input.role_name)
            .ok_or_else(no_access)?;
        let session_name = self
            .admin
            .user_name(&owner.identity_store_id, &owner.user_id)
            .ok_or_else(|| errors::unauthorized("Session token not found or invalid"))?;
        let tags = self.admin.access_control_tags(&owner.identity_store_id, &owner.user_id);
        let creds = self
            .sts
            .assume_role_with_saml_as_service(&SamlFederation {
                role_arn: &role.role_arn,
                provider_arn: &role.provider_arn,
                audience: &role.saml_audience,
                session_name: &session_name,
                duration_seconds: role.session_seconds as i32,
                tags,
                region: &ctx.region,
                now: ctx.received_at,
            })
            .map_err(|_| no_access())?;
        Ok(types::GetRoleCredentialsResponse {
            role_credentials: Some(types::RoleCredentials {
                access_key_id: Some(creds.access_key_id),
                secret_access_key: Some(creds.secret_access_key),
                session_token: Some(creds.session_token),
                expiration: creds.expiration.timestamp_millis(),
            }),
        })
    }

    async fn logout(&self, ctx: &RequestContext, input: types::LogoutRequest) -> Result<(), ServiceError> {
        self.owner(ctx, &input.access_token)?;
        self.oidc.revoke(&input.access_token);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Service for SsoPortal {
    /// The portal takes bearer tokens, never signatures.
    fn signing_name(&self) -> &'static str {
        "awsssoportal"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        generated::operation_for(request).is_some() && request.headers().contains_key("x-amz-sso_bearer_token")
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        self.recognizes(request)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }
}
