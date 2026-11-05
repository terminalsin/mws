//! `CreateTokenWithIAM`: tokens for customer managed applications, asked for
//! by IAM principals the application's actor policy allows.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_ssoadmin::ApplicationInfo;

use crate::generated::types;
use crate::state::Session;
use crate::tokens::*;
use crate::SsoOidc;

const TOKEN_SECONDS: i64 = 3600;
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const REFRESH_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:refresh_token";

impl SsoOidc {
    fn grant_of<'a>(
        app: &'a ApplicationInfo,
        grant: &str,
    ) -> Result<&'a mws_ssoadmin::generated::types::Grant, ServiceError> {
        app.grants.get(grant).ok_or_else(|| {
            unauthorized_client(format!("The application is not authorized to use the grant type {grant}"))
        })
    }

    /// Whether the user (directly or through a group) is assigned to the
    /// application, when the application requires assignment.
    fn assigned(&self, app: &ApplicationInfo, user_id: &str) -> bool {
        if !app.assignment_required {
            return true;
        }
        let groups = self.identity.groups_of(&app.identity_store_id, user_id);
        app.assignments.iter().any(|(t, id)| match t.as_str() {
            "USER" => id == user_id,
            "GROUP" => groups.contains(id),
            _ => false,
        })
    }

    pub(crate) async fn token_with_iam(
        &self,
        ctx: &RequestContext,
        input: types::CreateTokenWithIAMRequest,
    ) -> Result<types::CreateTokenWithIAMResponse, ServiceError> {
        let app =
            self.admin.application_info(&input.client_id).ok_or_else(|| invalid_client("Invalid client provided"))?;
        let policy = app
            .actor_policy
            .clone()
            .ok_or_else(|| access_denied("The application has no IAM authentication method that allows the caller"))?;
        ctx.authorize_with_required_resource_policy(
            "sso-oauth:CreateTokenWithIAM",
            &app.arn,
            &policy,
            ConditionContext::new(),
        )
        .map_err(|e| access_denied(e.message))?;
        if !app.enabled {
            return Err(invalid_client("The application is disabled"));
        }
        let now = ctx.received_at;
        let (user_id, scopes) = match input.grant_type.as_str() {
            GRANT_AUTHORIZATION_CODE => {
                Self::grant_of(&app, GRANT_AUTHORIZATION_CODE)?;
                let code = input.code.ok_or_else(|| invalid_request("code is required"))?;
                let auth = self
                    .lock()
                    .codes
                    .remove(&code)
                    .ok_or_else(|| invalid_grant("Invalid authorization code provided"))?;
                if auth.client_id != app.arn || auth.expires_at <= now {
                    return Err(invalid_grant("Invalid authorization code provided"));
                }
                if input.redirect_uri.as_deref() != Some(auth.redirect_uri.as_str()) {
                    return Err(invalid_grant("The redirect URI doesn't match the authorization request"));
                }
                if let Some(challenge) = &auth.code_challenge {
                    let verifier =
                        input.code_verifier.clone().ok_or_else(|| invalid_grant("codeVerifier is required"))?;
                    if !pkce_matches(&verifier, challenge, auth.code_challenge_method.as_deref()) {
                        return Err(invalid_grant("Invalid code verifier provided"));
                    }
                }
                (auth.user_id, auth.scopes)
            }
            GRANT_REFRESH_TOKEN => {
                Self::grant_of(&app, GRANT_REFRESH_TOKEN)?;
                let token = input.refresh_token.clone().ok_or_else(|| invalid_request("refreshToken is required"))?;
                let s = self
                    .lock()
                    .refresh
                    .remove(&token)
                    .ok_or_else(|| invalid_grant("Invalid refresh token provided"))?;
                if s.application_arn.as_deref() != Some(app.arn.as_str()) {
                    return Err(invalid_grant("Invalid refresh token provided"));
                }
                (s.user_id, s.scopes)
            }
            GRANT_JWT_BEARER => {
                let mws_ssoadmin::generated::types::Grant::JwtBearer(grant) = Self::grant_of(&app, GRANT_JWT_BEARER)?
                else {
                    return Err(unauthorized_client("The application has no jwt-bearer grant"));
                };
                let assertion = input.assertion.clone().ok_or_else(|| invalid_request("assertion is required"))?;
                let claims = jwt_claims(&assertion).ok_or_else(|| invalid_grant("The assertion is not a JWT"))?;
                let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let auds: Vec<String> = match claims.get("aud") {
                    Some(serde_json::Value::String(s)) => vec![s.clone()],
                    Some(serde_json::Value::Array(a)) => {
                        a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
                    }
                    _ => Vec::new(),
                };
                let issuer = grant
                    .authorized_token_issuers
                    .iter()
                    .flatten()
                    .filter_map(|t| {
                        let info = self.admin.token_issuer_info(t.trusted_token_issuer_arn.as_deref()?)?;
                        (info.issuer_url.trim_end_matches('/') == iss.trim_end_matches('/')).then_some((info, t))
                    })
                    .next()
                    .ok_or_else(|| {
                        invalid_grant("The assertion's issuer is not a trusted token issuer of the application")
                    })?;
                let allowed = issuer.1.authorized_audiences.clone().unwrap_or_default();
                if !auds.iter().any(|a| allowed.contains(a)) {
                    return Err(invalid_grant("The assertion's audience is not authorized"));
                }
                if claims.get("exp").and_then(|v| v.as_i64()).is_some_and(|exp| exp <= now.timestamp()) {
                    return Err(invalid_grant("The assertion has expired"));
                }
                self.sts
                    .verify_identity_provider_token(&assertion, &iss)
                    .await
                    .map_err(|_| invalid_grant("The assertion's signature could not be verified"))?;
                let info = issuer.0;
                let claim = claims.get(&info.claim_attribute_path).and_then(|v| v.as_str()).ok_or_else(|| {
                    invalid_grant(format!("The assertion has no {} claim", info.claim_attribute_path))
                })?;
                let user = self
                    .identity
                    .find_user_by_attribute(&app.identity_store_id, &info.identity_store_attribute_path, claim)
                    .ok_or_else(|| invalid_grant("No user matches the assertion"))?;
                (user.user_id, app.scopes.clone())
            }
            GRANT_TOKEN_EXCHANGE => {
                Self::grant_of(&app, GRANT_TOKEN_EXCHANGE)?;
                let subject = input.subject_token.clone().ok_or_else(|| invalid_request("subjectToken is required"))?;
                if input.subject_token_type.as_deref() != Some(ACCESS_TOKEN_TYPE) {
                    return Err(invalid_request("subjectTokenType must be an access token"));
                }
                let t = self.lock().tokens.get(&subject).cloned().filter(|t| t.expires_at > now);
                let t = t.ok_or_else(|| invalid_grant("Invalid subject token provided"))?;
                if t.session.identity_store_id != app.identity_store_id {
                    return Err(invalid_grant("Invalid subject token provided"));
                }
                (t.session.user_id, app.scopes.clone())
            }
            other => return Err(unsupported_grant_type(format!("Unsupported grant type: {other}"))),
        };
        if !self.assigned(&app, &user_id) {
            return Err(access_denied("The user is not assigned to the application"));
        }
        let scopes = match input.scope.filter(|s| !s.is_empty()) {
            Some(r) => {
                if let Some(bad) = r.iter().find(|s| !app.scopes.contains(s) && !scopes.contains(s)) {
                    return Err(invalid_scope(format!("Invalid scope: {bad}")));
                }
                r
            }
            None => scopes,
        };
        let session = Session {
            client_id: app.arn.clone(),
            identity_store_id: app.identity_store_id.clone(),
            user_id: user_id.clone(),
            scopes: scopes.clone(),
            application_arn: Some(app.arn.clone()),
        };
        let refresh = app.grants.contains_key(GRANT_REFRESH_TOKEN);
        let (access, refresh_token) = self.issue(session, now, TOKEN_SECONDS, refresh);
        let instance_id = app.instance_arn.rsplit('/').next().unwrap_or_default().to_string();
        let identity_context = random(48);
        let id_token = self.sign_jwt(&serde_json::json!({
            "iss": format!("https://identitycenter.amazonaws.com/{instance_id}"),
            "sub": user_id,
            "aud": app.arn,
            "iat": now.timestamp(),
            "exp": now.timestamp() + TOKEN_SECONDS,
            "sts:identity_context": identity_context,
        }));
        Ok(types::CreateTokenWithIAMResponse {
            access_token: Some(access),
            token_type: Some("Bearer".into()),
            expires_in: TOKEN_SECONDS as i32,
            issued_token_type: Some(
                if refresh_token.is_some() { REFRESH_TOKEN_TYPE } else { ACCESS_TOKEN_TYPE }.into(),
            ),
            refresh_token,
            id_token: Some(id_token),
            scope: Some(scopes),
            aws_additional_details: Some(types::AwsAdditionalDetails { identity_context: Some(identity_context) }),
        })
    }
}
