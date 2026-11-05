//! Client registration, device authorization and `CreateToken`.

use chrono::Duration;
use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::state::{Approval, Client, DeviceAuth, Session};
use crate::tokens::*;
use crate::SsoOidc;

/// How long a client registration lasts.
const CLIENT_LIFETIME_DAYS: i64 = 90;
/// How long a device code stays valid.
const DEVICE_CODE_SECONDS: i64 = 600;
/// Access token lifetimes: shorter when a refresh token comes with it.
const TOKEN_SECONDS: i64 = 28800;
const REFRESHABLE_TOKEN_SECONDS: i64 = 3600;

const KNOWN_GRANTS: &[&str] = &[GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN, GRANT_DEVICE_CODE];

impl SsoOidc {
    /// The registered client `id`, authenticated by `secret`.
    pub(crate) fn client(&self, ctx: &RequestContext, id: &str, secret: &str) -> Result<Client, ServiceError> {
        let c = self.lock().clients.get(id).cloned().ok_or_else(|| invalid_client("Invalid client provided"))?;
        if c.secret != secret {
            return Err(invalid_client("Invalid client provided"));
        }
        if c.expires_at <= ctx.received_at {
            return Err(invalid_client("Client is expired"));
        }
        Ok(c)
    }

    fn check_grant(c: &Client, grant: &str) -> Result<(), ServiceError> {
        // Clients registered without grant types may use the device grant
        // (as the AWS CLI's legacy flow does), nothing else.
        let allowed = if c.grant_types.is_empty() {
            grant == GRANT_DEVICE_CODE
        } else {
            c.grant_types.iter().any(|g| g == grant)
        };
        if allowed {
            Ok(())
        } else {
            Err(unauthorized_client(format!("The client is not authorized to use the grant type {grant}")))
        }
    }

    /// The scopes a token gets: the requested ones, which must be among the
    /// client's, or else all of the client's.
    pub(crate) fn scopes_for(c: &Client, requested: Option<Vec<String>>) -> Result<Vec<String>, ServiceError> {
        match requested.filter(|r| !r.is_empty()) {
            Some(r) => {
                if let Some(bad) = r.iter().find(|s| !c.scopes.contains(s)) {
                    return Err(invalid_scope(format!("Invalid scope: {bad}")));
                }
                Ok(r)
            }
            None => Ok(c.scopes.clone()),
        }
    }

    fn token_response(
        &self,
        ctx: &RequestContext,
        c: &Client,
        session: Session,
    ) -> types::CreateTokenResponse {
        let refresh = c.grant_types.iter().any(|g| g == GRANT_REFRESH_TOKEN);
        let seconds = if refresh { REFRESHABLE_TOKEN_SECONDS } else { TOKEN_SECONDS };
        let (access, refresh_token) = self.issue(session, ctx.received_at, seconds, refresh);
        types::CreateTokenResponse {
            access_token: Some(access),
            token_type: Some("Bearer".into()),
            expires_in: seconds as i32,
            refresh_token,
            id_token: None,
        }
    }
}

#[async_trait::async_trait]
impl Handler for SsoOidc {
    async fn register_client(
        &self,
        ctx: &RequestContext,
        input: types::RegisterClientRequest,
    ) -> Result<types::RegisterClientResponse, ServiceError> {
        if input.client_type != "public" {
            return Err(invalid_client_metadata(format!("Invalid client type: {}", input.client_type)));
        }
        let grant_types = input.grant_types.unwrap_or_default();
        if let Some(bad) = grant_types.iter().find(|g| !KNOWN_GRANTS.contains(&g.as_str())) {
            return Err(invalid_client_metadata(format!("Invalid grant type: {bad}")));
        }
        let redirect_uris = input.redirect_uris.unwrap_or_default();
        if grant_types.iter().any(|g| g == GRANT_AUTHORIZATION_CODE) && redirect_uris.is_empty() {
            return Err(invalid_redirect_uri("Redirect URIs are required for the authorization_code grant"));
        }
        if let Some(bad) = redirect_uris.iter().find(|u| !(u.starts_with("http://") || u.starts_with("https://"))) {
            return Err(invalid_redirect_uri(format!("Invalid redirect URI: {bad}")));
        }
        if let Some(url) = &input.issuer_url {
            if self.store_for_start_url(url).is_none() {
                return Err(invalid_request(format!("Invalid issuer URL: {url}")));
            }
        }
        let now = ctx.received_at;
        let client = Client {
            id: random(16),
            secret: random(96),
            name: input.client_name,
            scopes: input.scopes.unwrap_or_default(),
            redirect_uris,
            grant_types,
            issuer_url: input.issuer_url,
            application_arn: input.entitled_application_arn,
            issued_at: now,
            expires_at: now + Duration::days(CLIENT_LIFETIME_DAYS),
        };
        let out = types::RegisterClientResponse {
            client_id: Some(client.id.clone()),
            client_secret: Some(client.secret.clone()),
            client_id_issued_at: now.timestamp(),
            client_secret_expires_at: client.expires_at.timestamp(),
            authorization_endpoint: None,
            token_endpoint: None,
        };
        self.lock().clients.insert(client.id.clone(), client);
        Ok(out)
    }

    async fn start_device_authorization(
        &self,
        ctx: &RequestContext,
        input: types::StartDeviceAuthorizationRequest,
    ) -> Result<types::StartDeviceAuthorizationResponse, ServiceError> {
        let c = self.client(ctx, &input.client_id, &input.client_secret)?;
        Self::check_grant(&c, GRANT_DEVICE_CODE)?;
        let store = self
            .store_for_start_url(&input.start_url)
            .ok_or_else(|| invalid_request(format!("Invalid start URL: {}", input.start_url)))?;
        let device_code = random(60);
        let user_code = user_code();
        let base = ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into());
        let verification_uri = format!("{base}{}", crate::signin::DEVICE_PATH);
        self.lock().devices.insert(
            device_code.clone(),
            DeviceAuth {
                client_id: c.id,
                user_code: user_code.clone(),
                identity_store_id: store,
                expires_at: ctx.received_at + Duration::seconds(DEVICE_CODE_SECONDS),
                approval: Approval::Pending,
            },
        );
        Ok(types::StartDeviceAuthorizationResponse {
            device_code: Some(device_code),
            verification_uri_complete: Some(format!("{verification_uri}?user_code={user_code}")),
            user_code: Some(user_code),
            verification_uri: Some(verification_uri),
            expires_in: DEVICE_CODE_SECONDS as i32,
            interval: 1,
        })
    }

    async fn create_token(
        &self,
        ctx: &RequestContext,
        input: types::CreateTokenRequest,
    ) -> Result<types::CreateTokenResponse, ServiceError> {
        let c = self.client(ctx, &input.client_id, &input.client_secret)?;
        let now = ctx.received_at;
        match input.grant_type.as_str() {
            GRANT_DEVICE_CODE => {
                Self::check_grant(&c, GRANT_DEVICE_CODE)?;
                let code = input.device_code.ok_or_else(|| invalid_request("deviceCode is required"))?;
                let device = {
                    let st = self.lock();
                    st.devices.get(&code).cloned()
                }
                .ok_or_else(|| invalid_grant("Invalid device code provided"))?;
                if device.client_id != c.id {
                    return Err(invalid_grant("Invalid device code provided"));
                }
                if device.expires_at <= now {
                    self.lock().devices.remove(&code);
                    return Err(expired_token("Device code has expired"));
                }
                let user_id = match device.approval {
                    Approval::Pending => return Err(authorization_pending()),
                    Approval::Denied => {
                        self.lock().devices.remove(&code);
                        return Err(access_denied("The user denied the authorization request"));
                    }
                    Approval::Approved { user_id } => user_id,
                };
                self.lock().devices.remove(&code);
                let scopes = Self::scopes_for(&c, input.scope)?;
                let session = Session {
                    client_id: c.id.clone(),
                    identity_store_id: device.identity_store_id,
                    user_id,
                    scopes,
                    application_arn: None,
                };
                Ok(self.token_response(ctx, &c, session))
            }
            GRANT_AUTHORIZATION_CODE => {
                Self::check_grant(&c, GRANT_AUTHORIZATION_CODE)?;
                let code = input.code.ok_or_else(|| invalid_request("code is required"))?;
                let auth = self.lock().codes.remove(&code).ok_or_else(|| invalid_grant("Invalid authorization code provided"))?;
                if auth.client_id != c.id || auth.expires_at <= now {
                    return Err(invalid_grant("Invalid authorization code provided"));
                }
                if input.redirect_uri.as_deref() != Some(auth.redirect_uri.as_str()) {
                    return Err(invalid_grant("The redirect URI doesn't match the authorization request"));
                }
                if let Some(challenge) = &auth.code_challenge {
                    let verifier = input.code_verifier.ok_or_else(|| invalid_grant("codeVerifier is required"))?;
                    if !pkce_matches(&verifier, challenge, auth.code_challenge_method.as_deref()) {
                        return Err(invalid_grant("Invalid code verifier provided"));
                    }
                }
                let session = Session {
                    client_id: c.id.clone(),
                    identity_store_id: auth.identity_store_id,
                    user_id: auth.user_id,
                    scopes: auth.scopes,
                    application_arn: None,
                };
                Ok(self.token_response(ctx, &c, session))
            }
            GRANT_REFRESH_TOKEN => {
                Self::check_grant(&c, GRANT_REFRESH_TOKEN)?;
                let token = input.refresh_token.ok_or_else(|| invalid_request("refreshToken is required"))?;
                let session = self.lock().refresh.remove(&token).ok_or_else(|| invalid_grant("Invalid refresh token provided"))?;
                if session.client_id != c.id {
                    return Err(invalid_grant("Invalid refresh token provided"));
                }
                if !self.identity.user_exists(&session.identity_store_id, &session.user_id) {
                    return Err(invalid_grant("The user no longer exists"));
                }
                let scopes = match input.scope.filter(|s| !s.is_empty()) {
                    Some(r) => {
                        if let Some(bad) = r.iter().find(|s| !session.scopes.contains(s)) {
                            return Err(invalid_scope(format!("Invalid scope: {bad}")));
                        }
                        r
                    }
                    None => session.scopes.clone(),
                };
                Ok(self.token_response(ctx, &c, Session { scopes, ..session }))
            }
            other => Err(unsupported_grant_type(format!("Unsupported grant type: {other}"))),
        }
    }

    async fn create_token_with_iam(
        &self,
        ctx: &RequestContext,
        input: types::CreateTokenWithIAMRequest,
    ) -> Result<types::CreateTokenWithIAMResponse, ServiceError> {
        self.token_with_iam(ctx, input).await
    }
}
