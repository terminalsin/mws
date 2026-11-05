use std::collections::BTreeMap;

use base64::Engine;
use chrono::{DateTime, TimeDelta, Utc};
use mws_core::{Caller, CallerKind, ConditionContext, RequestContext, ServiceError, SessionInfo, SessionKind};
use mws_iam_policy::{Policy, PolicyKind};
use rand::Rng;

use crate::generated::{errors, types, Handler};
use crate::{web_identity, Session, Sts};

pub(crate) const ROLE_DEFAULT_DURATION: i32 = 3600;
const ROLE_CHAINING_MAX: i32 = 3600;
const SESSION_TOKEN_DEFAULT: i32 = 43_200;
const ROOT_SESSION_MAX: i32 = 3600;
const PACKED_POLICY_LIMIT: usize = 2048;

pub(crate) fn access_denied(message: impl Into<String>) -> ServiceError {
    ServiceError::client("AccessDenied", 403, message)
}

pub(crate) fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationError", 400, message)
}

fn random(alphabet: &[u8], len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char).collect()
}

/// A session token. Session policies and tags are packed into the token, so
/// it grows with them, as AWS's does.
fn session_token(packed: usize) -> String {
    let mut bytes = vec![0u8; 256 + packed.min(PACKED_POLICY_LIMIT)];
    rand::thread_rng().fill(&mut bytes[..]);
    format!("IQoJb3JpZ2luX2Vj{}", base64::engine::general_purpose::STANDARD.encode(bytes))
}

pub(crate) struct Issued {
    pub(crate) credentials: types::Credentials,
    /// `SessionTokenSize`: the token's length in bytes.
    pub(crate) token_size: i32,
    /// `SessionTokenUtilization`: the percentage of the largest allowed token.
    pub(crate) token_utilization: i32,
}

/// The longest session token: one carrying the most packed policy and tags.
const MAX_SESSION_TOKEN: usize = 16 + (256 + PACKED_POLICY_LIMIT).div_ceil(3) * 4;

impl Sts {
    fn inner_verifies_signatures(&self) -> bool {
        self.inner.verify_federation_signatures
    }

    /// Check a web identity token's signature: against MWS's own keys when
    /// MWS issued it, else against the provider's published JWKS.
    pub(crate) async fn verify_web_identity_signature(
        &self,
        token: &str,
        issuer: &str,
        thumbprints: &[String],
    ) -> Result<(), ServiceError> {
        use crate::oidc_keys::{self, Key, VerifyError};
        let own = self.iam().outbound_keys_for_issuer(issuer);
        let keys = if !own.is_empty() {
            own.into_iter()
                .filter_map(|(alg, k)| {
                    use aws_lc_rs::signature::KeyPair;
                    let public = match alg.as_str() {
                        "RS256" => aws_lc_rs::rsa::KeyPair::from_pkcs8(&k.pkcs8).ok()?.public_key().as_ref().to_vec(),
                        "ES384" => aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
                            &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                            &k.pkcs8,
                        )
                        .ok()?
                        .public_key()
                        .as_ref()
                        .to_vec(),
                        _ => return None,
                    };
                    Some(Key::Raw { kid: k.key_id, alg, public })
                })
                .collect()
        } else {
            let url = if issuer.starts_with("https://") { issuer.to_string() } else { format!("https://{issuer}") };
            oidc_keys::fetch_jwks(&url, thumbprints).await.map_err(|e| {
                tracing::debug!("fetching OIDC keys for {issuer}: {e:?}");
                errors::idp_communication_error(
                    "Couldn't retrieve verification key from your identity provider,  please reference AssumeRoleWithWebIdentity documentation for requirements",
                )
            })?
        };
        oidc_keys::verify(token, &keys).map_err(|e| {
            tracing::debug!("web identity token for {issuer} rejected: {e:?}");
            match e {
                VerifyError::Communication(_) | VerifyError::Invalid(_) => errors::invalid_identity_token(
                    "The web identity token that was passed could not be validated by AWS. Get a new identity token from the identity provider and then retry the request.",
                ),
            }
        })
    }

    pub(crate) fn issue(&self, mut caller: Caller, duration: i32, session: SessionInfo) -> Issued {
        let akid = mws_core::ids::access_key_id("ASIA", &caller.account_id);
        let secret = random(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 40);
        let packed: usize = session.policies.iter().map(|p| mws_iam_policy::policy_size(p)).sum::<usize>()
            + session.tags.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>();
        let token = session_token(packed);
        let token_size = token.len();
        let expires_at = session.issued_at + TimeDelta::seconds(duration as i64);
        caller.access_key_id = akid.clone();
        caller.session = Some(SessionInfo { expires_at, ..session });
        self.inner.sessions.lock().expect("STS session lock poisoned").insert(
            akid.clone(),
            Session { secret_access_key: secret.clone(), session_token: token.clone(), expires_at, caller },
        );
        // Whole seconds, as AWS reports them.
        let expiration = DateTime::from_timestamp(expires_at.timestamp(), 0).unwrap_or(expires_at);
        Issued {
            credentials: types::Credentials {
                access_key_id: akid,
                secret_access_key: secret,
                session_token: token,
                expiration,
            },
            token_size: token_size as i32,
            token_utilization: (token_size * 100).div_ceil(MAX_SESSION_TOKEN).min(100) as i32,
        }
    }

    /// Session policies from `Policy` and `PolicyArns`, validated.
    pub(crate) fn session_policies(
        &self,
        policy: Option<String>,
        arns: Option<Vec<types::PolicyDescriptorType>>,
    ) -> Result<(Vec<String>, usize), ServiceError> {
        let mut docs = Vec::new();
        let mut packed = 0;
        if let Some(p) = policy {
            Policy::parse(&p, PolicyKind::Identity).map_err(|e| errors::malformed_policy_document(e.0))?;
            packed += mws_iam_policy::policy_size(&p);
            docs.push(p);
        }
        for d in arns.unwrap_or_default() {
            let Some(arn) = d.arn else { continue };
            let doc = self
                .iam()
                .managed_policy_document(&arn)
                .ok_or_else(|| validation(format!("Policy {arn} does not exist or is not attachable.")))?;
            packed += arn.len();
            docs.push(doc);
        }
        Ok((docs, packed))
    }

    pub(crate) fn tags(tags: Option<Vec<types::Tag>>) -> BTreeMap<String, String> {
        tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect()
    }

    pub(crate) fn packed_size(packed: usize, tags: &BTreeMap<String, String>) -> Option<i32> {
        let tag_size: usize = tags.iter().map(|(k, v)| k.len() + v.len()).sum();
        let total = packed + tag_size;
        (total > 0).then(|| ((total * 100).div_ceil(PACKED_POLICY_LIMIT)) as i32)
    }

    pub(crate) fn check_packed(packed: usize, tags: &BTreeMap<String, String>) -> Result<Option<i32>, ServiceError> {
        let size = Self::packed_size(packed, tags);
        if size.is_some_and(|s| s > 100) {
            return Err(errors::packed_policy_too_large(format!(
                "Packed policy consumes {}% of allotted space, please use smaller policy.",
                size.unwrap()
            )));
        }
        Ok(size)
    }

    pub(crate) fn request_tag_context(tags: &BTreeMap<String, String>) -> ConditionContext {
        let mut ctx = ConditionContext::new();
        if tags.is_empty() {
            return ctx;
        }
        for (k, v) in tags {
            ctx.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        }
        ctx.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
        ctx
    }

    pub(crate) fn assumed_role_caller(&self, role: &mws_iam::RoleView, session_name: &str) -> Caller {
        let account = role.account_id.clone();
        Caller {
            arn: format!("arn:{}:sts::{account}:assumed-role/{}/{session_name}", self.iam().partition(), role.name),
            user_id: format!("{}:{session_name}", role.id),
            account_id: account,
            access_key_id: String::new(),
            kind: CallerKind::AssumedRole { role_name: role.name.clone(), session_name: session_name.to_string() },
            session: None,
        }
    }
}

#[async_trait::async_trait]
impl Handler for Sts {
    async fn get_caller_identity(
        &self,
        ctx: &RequestContext,
        _input: types::GetCallerIdentityRequest,
    ) -> Result<types::GetCallerIdentityResponse, ServiceError> {
        let c = &ctx.caller;
        Ok(types::GetCallerIdentityResponse {
            user_id: Some(c.user_id.clone()),
            account: Some(c.account_id.clone()),
            arn: Some(c.arn.clone()),
        })
    }

    async fn get_access_key_info(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessKeyInfoRequest,
    ) -> Result<types::GetAccessKeyInfoResponse, ServiceError> {
        ctx.authorize("sts:GetAccessKeyInfo", "*", ConditionContext::new())?;
        let session_account = self.sessions().get(&input.access_key_id).map(|s| s.caller.account_id.clone());
        let account = session_account
            .or_else(|| self.iam().account_of_access_key(&input.access_key_id))
            .or_else(|| mws_core::ids::account_of_access_key_id(&input.access_key_id))
            .unwrap_or_else(|| ctx.caller.account_id.clone());
        Ok(types::GetAccessKeyInfoResponse { account: Some(account) })
    }

    async fn assume_role(
        &self,
        ctx: &RequestContext,
        input: types::AssumeRoleRequest,
    ) -> Result<types::AssumeRoleResponse, ServiceError> {
        let caller = &ctx.caller;
        match &caller.kind {
            CallerKind::Root => return Err(access_denied("Roles may not be assumed by root accounts.")),
            CallerKind::FederatedUser { .. } => {
                return Err(access_denied("Cannot call AssumeRole with federated user credentials."));
            }
            _ => {}
        }
        let chained = matches!(caller.kind, CallerKind::AssumedRole { .. });
        let not_authorized = || {
            access_denied(format!(
                "User: {} is not authorized to perform: sts:AssumeRole on resource: {}",
                caller.arn, input.role_arn
            ))
        };
        let role = self.iam().role_by_arn(&input.role_arn).ok_or_else(not_authorized)?;

        let duration = input.duration_seconds.unwrap_or(ROLE_DEFAULT_DURATION);
        if chained && duration > ROLE_CHAINING_MAX {
            return Err(validation(
                "The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining.",
            ));
        }
        if duration > role.max_session_duration {
            return Err(validation("The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));
        }

        let (policies, packed) = self.session_policies(input.policy, input.policy_arns)?;
        let request_tags = Self::tags(input.tags);

        // Tags and source identity marked transitive by the calling session
        // carry over to the new one.
        let mut tags = BTreeMap::new();
        let mut transitive = input.transitive_tag_keys.clone().unwrap_or_default();
        let mut source_identity = input.source_identity.clone();
        if let Some(s) = &caller.session {
            for k in &s.transitive_tag_keys {
                if let Some(v) = s.tags.get(k) {
                    tags.insert(k.clone(), v.clone());
                    if !transitive.contains(k) {
                        transitive.push(k.clone());
                    }
                }
            }
            if let Some(si) = &s.source_identity {
                if source_identity.as_ref().is_some_and(|new| new != si) {
                    return Err(access_denied("SourceIdentity cannot be changed once set."));
                }
                source_identity = Some(si.clone());
            }
        }
        for (k, v) in &request_tags {
            if tags.contains_key(k) {
                return Err(validation(format!(
                    "Tag key {k} is already set by a transitive tag from the calling session."
                )));
            }
            tags.insert(k.clone(), v.clone());
        }
        let packed_policy_size = Self::check_packed(packed, &request_tags)?;

        let mut cond = Self::request_tag_context(&request_tags);
        cond.insert("sts:RoleSessionName".into(), vec![input.role_session_name.clone()]);
        if let Some(e) = &input.external_id {
            cond.insert("sts:ExternalId".into(), vec![e.clone()]);
        }
        if let Some(si) = &input.source_identity {
            cond.insert("sts:SourceIdentity".into(), vec![si.clone()]);
        }
        if !transitive.is_empty() {
            cond.insert("sts:TransitiveTagKeys".into(), transitive.clone());
        }
        ctx.authorize_against_trust_policy("sts:AssumeRole", &role.arn, &role.trust_policy, cond.clone())
            .map_err(|_| not_authorized())?;
        if !request_tags.is_empty() {
            ctx.authorize_against_trust_policy("sts:TagSession", &role.arn, &role.trust_policy, cond.clone())?;
        }
        if input.source_identity.is_some() {
            ctx.authorize_against_trust_policy("sts:SetSourceIdentity", &role.arn, &role.trust_policy, cond)?;
        }

        let mfa = self.check_mfa(caller, input.serial_number.as_deref(), input.token_code.as_deref())?;
        let new_caller = self.assumed_role_caller(&role, &input.role_session_name);
        let assumed_role_user =
            types::AssumedRoleUser { assumed_role_id: new_caller.user_id.clone(), arn: new_caller.arn.clone() };
        let issued = self.issue(
            new_caller,
            duration,
            SessionInfo {
                kind: SessionKind::AssumeRole,
                policies,
                tags,
                transitive_tag_keys: transitive,
                source_identity: source_identity.clone(),
                issued_at: ctx.received_at,
                expires_at: ctx.received_at,
                mfa_authenticated: mfa,
            },
        );
        self.iam().note_role_used(&role, &ctx.region);
        Ok(types::AssumeRoleResponse {
            credentials: Some(issued.credentials),
            session_token_utilization: Some(issued.token_utilization),
            session_token_size: Some(issued.token_size),
            assumed_role_user: Some(assumed_role_user),
            packed_policy_size,
            source_identity,
        })
    }

    async fn assume_role_with_web_identity(
        &self,
        ctx: &RequestContext,
        input: types::AssumeRoleWithWebIdentityRequest,
    ) -> Result<types::AssumeRoleWithWebIdentityResponse, ServiceError> {
        let claims = web_identity::decode(&input.web_identity_token).ok_or_else(|| {
            errors::invalid_identity_token(
                "The ID Token provided is not a valid JWT. (You may see this error if you sent an Access Token)",
            )
        })?;
        let role_account = mws_iam::arn_account(&input.role_arn).unwrap_or(self.iam().account_id_str()).to_string();
        let provider = self.iam().oidc_provider_for_issuer(&role_account, &claims.iss).ok_or_else(|| {
            errors::invalid_identity_token(format!(
                "No OpenIDConnect provider found in your account for {}",
                claims.iss
            ))
        })?;
        if self.inner_verifies_signatures() {
            self.verify_web_identity_signature(&input.web_identity_token, &claims.iss, &provider.thumbprints).await?;
        }
        let audience = claims
            .aud
            .iter()
            .find(|a| provider.client_ids.contains(a))
            .cloned()
            .ok_or_else(|| errors::invalid_identity_token("Incorrect token audience"))?;
        if let Some(exp) = claims.exp {
            let now = ctx.received_at;
            if now.timestamp() >= exp {
                let fmt = |t: DateTime<Utc>| t.format("%a %b %d %H:%M:%S UTC %Y").to_string();
                return Err(errors::expired_token(format!(
                    "Token expired: current date/time {} must be before the expiration date/time {}",
                    fmt(now),
                    fmt(DateTime::from_timestamp(exp, 0).unwrap_or(now))
                )));
            }
        }
        let denied = || access_denied("Not authorized to perform sts:AssumeRoleWithWebIdentity");
        let role = self.iam().role_by_arn(&input.role_arn).ok_or_else(denied)?;

        // Only the trust policy decides: there is no calling IAM identity.
        let mut cond = ConditionContext::new();
        cond.insert(format!("{}:aud", provider.url), vec![audience.clone()]);
        cond.insert(format!("{}:sub", provider.url), vec![claims.sub.clone()]);
        if let Some(amr) = claims.raw.get("amr").and_then(|v| v.as_array()) {
            cond.insert(
                format!("{}:amr", provider.url),
                amr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            );
        }
        cond.insert("sts:RoleSessionName".into(), vec![input.role_session_name.clone()]);
        cond.insert("aws:FederatedProvider".into(), vec![provider.arn.clone()]);
        let session_tags = web_identity::session_tags(&claims.raw);
        cond.extend(Self::request_tag_context(&session_tags.tags));
        if !session_tags.transitive.is_empty() {
            cond.insert("sts:TransitiveTagKeys".into(), session_tags.transitive.clone());
        }
        if let Some(si) = &session_tags.source_identity {
            cond.insert("sts:SourceIdentity".into(), vec![si.clone()]);
        }
        let allows =
            |action: &str| crate::extra::trust_allows(&role.trust_policy, action, &role.arn, &provider.arn, &cond);
        if !allows("sts:AssumeRoleWithWebIdentity") {
            return Err(denied());
        }
        // Tags and a source identity in the token need their own permissions.
        if !session_tags.tags.is_empty() && !allows("sts:TagSession") {
            return Err(denied());
        }
        if session_tags.source_identity.is_some() && !allows("sts:SetSourceIdentity") {
            return Err(denied());
        }

        let duration = input.duration_seconds.unwrap_or(ROLE_DEFAULT_DURATION);
        if duration > role.max_session_duration {
            return Err(validation("The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));
        }
        let (policies, packed) = self.session_policies(input.policy, input.policy_arns)?;
        let packed_policy_size = Self::check_packed(packed, &session_tags.tags)?;
        let new_caller = self.assumed_role_caller(&role, &input.role_session_name);
        let assumed_role_user =
            types::AssumedRoleUser { assumed_role_id: new_caller.user_id.clone(), arn: new_caller.arn.clone() };
        let issued = self.issue(
            new_caller,
            duration,
            SessionInfo {
                kind: SessionKind::AssumeRoleWithWebIdentity,
                policies,
                tags: session_tags.tags,
                transitive_tag_keys: session_tags.transitive,
                source_identity: session_tags.source_identity.clone(),
                issued_at: ctx.received_at,
                expires_at: ctx.received_at,
                mfa_authenticated: false,
            },
        );
        self.iam().note_role_used(&role, &ctx.region);
        Ok(types::AssumeRoleWithWebIdentityResponse {
            credentials: Some(issued.credentials),
            session_token_utilization: Some(issued.token_utilization),
            session_token_size: Some(issued.token_size),
            subject_from_web_identity_token: Some(claims.sub),
            assumed_role_user: Some(assumed_role_user),
            packed_policy_size,
            provider: Some(claims.iss),
            audience: Some(audience),
            source_identity: session_tags.source_identity,
        })
    }

    async fn get_session_token(
        &self,
        ctx: &RequestContext,
        input: types::GetSessionTokenRequest,
    ) -> Result<types::GetSessionTokenResponse, ServiceError> {
        let caller = &ctx.caller;
        if caller.session.is_some() {
            return Err(access_denied("Cannot call GetSessionToken with session credentials"));
        }
        let root = matches!(caller.kind, CallerKind::Root);
        if !root && !matches!(caller.kind, CallerKind::User { .. }) {
            return Err(access_denied("Cannot call GetSessionToken with session credentials"));
        }
        // AWS requires no permission for GetSessionToken: it authenticates
        // the caller (optionally with MFA) and cannot be controlled by policy.
        let mfa = self.check_mfa(caller, input.serial_number.as_deref(), input.token_code.as_deref())?;
        let mut duration = input.duration_seconds.unwrap_or(SESSION_TOKEN_DEFAULT);
        if root {
            duration = duration.min(ROOT_SESSION_MAX);
        }
        let issued = self.issue(
            caller.clone(),
            duration,
            SessionInfo {
                kind: SessionKind::GetSessionToken,
                policies: vec![],
                tags: BTreeMap::new(),
                transitive_tag_keys: vec![],
                source_identity: None,
                issued_at: ctx.received_at,
                expires_at: ctx.received_at,
                mfa_authenticated: mfa,
            },
        );
        Ok(types::GetSessionTokenResponse {
            credentials: Some(issued.credentials),
            session_token_utilization: Some(issued.token_utilization),
            session_token_size: Some(issued.token_size),
        })
    }

    async fn get_federation_token(
        &self,
        ctx: &RequestContext,
        input: types::GetFederationTokenRequest,
    ) -> Result<types::GetFederationTokenResponse, ServiceError> {
        let caller = &ctx.caller;
        let parent_user = match (&caller.kind, &caller.session) {
            (CallerKind::User { name }, None) => Some(name.clone()),
            (CallerKind::Root, None) => None,
            _ => return Err(access_denied("Cannot call GetFederationToken with session credentials")),
        };
        let account = caller.account_id.clone();
        let arn = format!("arn:{}:sts::{account}:federated-user/{}", self.iam().partition(), input.name);
        let tags = Self::tags(input.tags);
        ctx.authorize("sts:GetFederationToken", &arn, Self::request_tag_context(&tags))?;
        let (policies, packed) = self.session_policies(input.policy, input.policy_arns)?;
        let packed_policy_size = Self::check_packed(packed, &tags)?;
        let mut duration = input.duration_seconds.unwrap_or(SESSION_TOKEN_DEFAULT);
        if parent_user.is_none() {
            duration = duration.min(ROOT_SESSION_MAX);
        }
        let new_caller = Caller {
            arn: arn.clone(),
            user_id: format!("{account}:{}", input.name),
            account_id: account,
            access_key_id: String::new(),
            kind: CallerKind::FederatedUser { name: input.name.clone(), parent_user },
            session: None,
        };
        let federated_user = types::FederatedUser { federated_user_id: new_caller.user_id.clone(), arn };
        let issued = self.issue(
            new_caller,
            duration,
            SessionInfo {
                kind: SessionKind::GetFederationToken,
                policies,
                tags,
                transitive_tag_keys: vec![],
                source_identity: None,
                issued_at: ctx.received_at,
                expires_at: ctx.received_at,
                mfa_authenticated: false,
            },
        );
        Ok(types::GetFederationTokenResponse {
            credentials: Some(issued.credentials),
            session_token_utilization: Some(issued.token_utilization),
            session_token_size: Some(issued.token_size),
            federated_user: Some(federated_user),
            packed_policy_size,
        })
    }

    async fn assume_role_with_saml(
        &self,
        ctx: &RequestContext,
        input: types::AssumeRoleWithSAMLRequest,
    ) -> Result<types::AssumeRoleWithSAMLResponse, ServiceError> {
        self.assume_role_with_saml_impl(ctx, input).await
    }

    async fn assume_root(
        &self,
        ctx: &RequestContext,
        input: types::AssumeRootRequest,
    ) -> Result<types::AssumeRootResponse, ServiceError> {
        self.assume_root_impl(ctx, input).await
    }

    async fn decode_authorization_message(
        &self,
        ctx: &RequestContext,
        input: types::DecodeAuthorizationMessageRequest,
    ) -> Result<types::DecodeAuthorizationMessageResponse, ServiceError> {
        self.decode_authorization_message_impl(ctx, input).await
    }

    async fn get_delegated_access_token(
        &self,
        ctx: &RequestContext,
        input: types::GetDelegatedAccessTokenRequest,
    ) -> Result<types::GetDelegatedAccessTokenResponse, ServiceError> {
        self.get_delegated_access_token_impl(ctx, input).await
    }

    async fn get_web_identity_token(
        &self,
        ctx: &RequestContext,
        input: types::GetWebIdentityTokenRequest,
    ) -> Result<types::GetWebIdentityTokenResponse, ServiceError> {
        self.get_web_identity_token_impl(ctx, input).await
    }
}
