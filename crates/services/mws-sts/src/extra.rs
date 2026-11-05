//! AssumeRoleWithSAML, AssumeRoot, DecodeAuthorizationMessage,
//! GetDelegatedAccessToken, GetWebIdentityToken, and MFA code checks.

use std::collections::BTreeMap;

use base64::Engine;
use chrono::{TimeDelta, Utc};
use mws_core::{Caller, CallerKind, ConditionContext, RequestContext, ServiceError, SessionInfo, SessionKind};
use mws_iam_policy::{decide, Policy, PolicyKind, PolicySet, PrincipalInfo, Request, SourcedPolicy};

use crate::generated::{errors, types};
use crate::ops::{access_denied, validation, ROLE_DEFAULT_DURATION};
use crate::{saml, Sts};

const SAML_AUDIENCES: &[&str] = &["https://signin.aws.amazon.com/saml", "urn:amazon:webservices"];
const WEB_TOKEN_DEFAULT: i32 = 300;
/// Root task sessions last at most 15 minutes.
const ROOT_TASK_DURATION: i32 = 900;
const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn is_aws_saml_audience(a: &str) -> bool {
    SAML_AUDIENCES.contains(&a)
        || a.strip_prefix("https://").and_then(|r| r.strip_suffix(".signin.aws.amazon.com/saml")).is_some()
}

/// Whether a role's trust policy allows a federated principal.
pub(crate) fn trust_allows(
    trust_policy: &str,
    action: &str,
    role_arn: &str,
    federated: &str,
    cond: &ConditionContext,
) -> bool {
    let Ok(trust) = Policy::parse(trust_policy, PolicyKind::Trust) else { return false };
    let principal = PrincipalInfo { federated: Some(federated.to_string()), ..Default::default() };
    let set = PolicySet {
        resource: Some(SourcedPolicy { source_id: "trust".into(), policy: trust }),
        resource_required: true,
        ..Default::default()
    };
    let mut context = mws_iam_policy::ConditionContext::new();
    for (k, v) in cond {
        context.insert(k, v.clone());
    }
    decide(&set, &Request { action, resource: role_arn, principal: &principal, context: &context }).allowed
}

impl Sts {
    /// Check `SerialNumber`/`TokenCode`. Returns whether the session is
    /// MFA-authenticated.
    pub(crate) fn check_mfa(
        &self,
        caller: &Caller,
        serial: Option<&str>,
        code: Option<&str>,
    ) -> Result<bool, ServiceError> {
        let (serial, code) = match (serial, code) {
            (None, None) => return Ok(false),
            (Some(s), Some(c)) => (s, c),
            _ => {
                return Err(access_denied(
                    "MultiFactorAuthentication failed, must provide both MFA serial number and one time pass code.",
                ))
            }
        };
        let invalid = || access_denied("MultiFactorAuthentication failed with invalid MFA one time pass code. ");
        let owner = self.iam().mfa_device_owner(serial).ok_or_else(invalid)?;
        if let CallerKind::User { name } = &caller.kind {
            if owner != name.to_lowercase() {
                return Err(invalid());
            }
        }
        if !self.iam().verify_mfa_code(serial, code) {
            return Err(invalid());
        }
        Ok(true)
    }

    pub(crate) async fn assume_role_with_saml_impl(
        &self,
        ctx: &RequestContext,
        input: types::AssumeRoleWithSAMLRequest,
    ) -> Result<types::AssumeRoleWithSAMLResponse, ServiceError> {
        let invalid = |m: &str| errors::invalid_identity_token(m.to_string());
        let assertion =
            saml::parse(&input.saml_assertion).ok_or_else(|| invalid("Invalid SAML Response: unable to parse"))?;
        let metadata = self
            .iam()
            .saml_provider_metadata(&input.principal_arn)
            .ok_or_else(|| invalid(&format!("No SAML provider found for ARN {}", input.principal_arn)))?;
        if saml::metadata_entity_id(&metadata).is_some_and(|id| id != assertion.issuer) {
            return Err(invalid("Issuer not present in specified provider"));
        }
        if self.inner.verify_federation_signatures {
            let xml = saml::decode(&input.saml_assertion).unwrap_or_default();
            if !crate::saml_sig::verify(&xml, &crate::saml_sig::signing_certificates(&metadata)) {
                return Err(invalid("Response signature invalid"));
            }
        }
        let now = ctx.received_at;
        if assertion.not_on_or_after.is_some_and(|t| now >= t) {
            return Err(errors::expired_token("Response is expired"));
        }
        if assertion.not_before.is_some_and(|t| now < t - TimeDelta::minutes(5)) {
            return Err(invalid("Response is not yet valid"));
        }
        let audience = assertion
            .recipient
            .clone()
            .filter(|r| is_aws_saml_audience(r))
            .or_else(|| assertion.audiences.iter().find(|a| is_aws_saml_audience(a)).cloned())
            .ok_or_else(|| invalid("Invalid audience in SAML Response"))?;
        let denied = || access_denied("Not authorized to perform sts:AssumeRoleWithSAML");
        let roles = assertion.attribute(saml::ATTR_ROLE).ok_or_else(denied)?;
        let listed = roles.iter().any(|v| {
            let parts: Vec<&str> = v.split(',').map(str::trim).collect();
            parts.len() == 2
                && parts.contains(&input.role_arn.as_str())
                && parts.contains(&input.principal_arn.as_str())
        });
        if !listed {
            return Err(denied());
        }
        let session_name = assertion
            .attribute(saml::ATTR_SESSION_NAME)
            .and_then(|v| v.first())
            .cloned()
            .ok_or_else(|| invalid("RoleSessionName is required in AuthnResponse"))?;
        let role = self.iam().role_by_arn(&input.role_arn).ok_or_else(denied)?;

        let account = role.account_id.clone();
        let provider_name = input.principal_arn.rsplit('/').next().unwrap_or_default().to_string();
        let qualifier = saml::name_qualifier(&assertion.issuer, &account, &provider_name);
        let mut cond = ConditionContext::new();
        cond.insert("SAML:aud".into(), vec![audience.clone()]);
        cond.insert("SAML:iss".into(), vec![assertion.issuer.clone()]);
        cond.insert("SAML:doc".into(), vec![format!("{account}/{provider_name}")]);
        cond.insert("SAML:namequalifier".into(), vec![qualifier.clone()]);
        if let Some(s) = &assertion.subject {
            cond.insert("SAML:sub".into(), vec![s.clone()]);
        }
        if let Some(t) = assertion.subject_type() {
            cond.insert("SAML:sub_type".into(), vec![t]);
        }
        cond.insert("sts:RoleSessionName".into(), vec![session_name.clone()]);
        cond.insert("aws:FederatedProvider".into(), vec![input.principal_arn.clone()]);
        if !trust_allows(&role.trust_policy, "sts:AssumeRoleWithSAML", &role.arn, &input.principal_arn, &cond) {
            return Err(denied());
        }
        let mut tags = BTreeMap::new();
        for (name, values) in &assertion.attributes {
            if let (Some(key), Some(v)) = (name.strip_prefix(saml::ATTR_TAG_PREFIX), values.first()) {
                tags.insert(key.to_string(), v.clone());
            }
        }
        let transitive: Vec<String> =
            assertion.attribute(saml::ATTR_TRANSITIVE).map(<[String]>::to_vec).unwrap_or_default();
        if !tags.is_empty() {
            let mut tag_cond = cond.clone();
            tag_cond.extend(Self::request_tag_context(&tags));
            if !trust_allows(&role.trust_policy, "sts:TagSession", &role.arn, &input.principal_arn, &tag_cond) {
                return Err(denied());
            }
        }
        let source_identity = assertion.attribute(saml::ATTR_SOURCE_IDENTITY).and_then(|v| v.first()).cloned();

        let attr_duration = assertion
            .attribute(saml::ATTR_SESSION_DURATION)
            .and_then(|v| v.first())
            .and_then(|v| v.parse::<i32>().ok());
        let duration = match (input.duration_seconds, attr_duration) {
            (Some(d), Some(a)) => d.min(a),
            (Some(d), None) => d,
            (None, Some(a)) => a,
            (None, None) => ROLE_DEFAULT_DURATION,
        };
        if duration > role.max_session_duration {
            return Err(validation("The requested DurationSeconds exceeds the MaxSessionDuration set for this role."));
        }
        let (policies, packed) = self.session_policies(input.policy, input.policy_arns)?;
        let packed_policy_size = Self::check_packed(packed, &tags)?;
        let new_caller = self.assumed_role_caller(&role, &session_name);
        let assumed_role_user =
            types::AssumedRoleUser { assumed_role_id: new_caller.user_id.clone(), arn: new_caller.arn.clone() };
        let issued = self.issue(
            new_caller,
            duration,
            SessionInfo {
                kind: SessionKind::AssumeRoleWithSAML,
                policies,
                tags,
                transitive_tag_keys: transitive,
                source_identity: source_identity.clone(),
                issued_at: ctx.received_at,
                expires_at: ctx.received_at,
                mfa_authenticated: false,
                provided_context: Default::default(),
            },
        );
        self.iam().note_role_used(&role, &ctx.region);
        Ok(types::AssumeRoleWithSAMLResponse {
            credentials: Some(issued.credentials),
            session_token_utilization: Some(issued.token_utilization),
            session_token_size: Some(issued.token_size),
            assumed_role_user: Some(assumed_role_user),
            packed_policy_size,
            subject: assertion.subject.clone(),
            subject_type: assertion.subject_type(),
            issuer: Some(assertion.issuer.clone()),
            audience: Some(audience),
            name_qualifier: Some(qualifier),
            source_identity,
        })
    }

    pub(crate) async fn assume_root_impl(
        &self,
        ctx: &RequestContext,
        input: types::AssumeRootRequest,
    ) -> Result<types::AssumeRootResponse, ServiceError> {
        let target = format!("arn:{}:iam::{}:root", self.iam().partition(), input.target_principal);
        let mut cond = ConditionContext::new();
        if let Some(arn) = &input.task_policy_arn.arn {
            cond.insert("sts:TaskPolicyArn".into(), vec![arn.clone()]);
        }
        ctx.authorize("sts:AssumeRoot", &target, cond)?;
        let not_enabled = || {
            access_denied(format!(
                "User: {} is not authorized to perform: sts:AssumeRoot on resource: {target} because centralized root access is not enabled for the organization",
                ctx.caller.arn
            ))
        };
        let caller_account = ctx.caller.account_id.clone();
        let org = self.iam().organization_of(&caller_account).ok_or_else(not_enabled)?;
        let iam_admin =
            org.is_management(&caller_account) || org.delegated_admin_for.iter().any(|s| s == "iam.amazonaws.com");
        if !iam_admin
            || !org.trusted_services.iter().any(|s| s == "iam.amazonaws.com")
            || !self.iam().org_root_sessions_enabled(&org.management_account_id)
        {
            return Err(not_enabled());
        }
        let member = self.iam().organization_of(&input.target_principal);
        if member.as_ref().is_none_or(|m| m.organization_id != org.organization_id)
            || org.is_management(&input.target_principal)
        {
            return Err(access_denied(format!(
                "User: {} is not authorized to perform: sts:AssumeRoot on resource: {target} because the target is not a member account of the organization",
                ctx.caller.arn
            )));
        }
        let task_arn = input.task_policy_arn.arn.clone().unwrap_or_default();
        let task_policy = task_arn
            .contains(":policy/root-task/")
            .then(|| self.iam().managed_policy_document(&task_arn))
            .flatten()
            .ok_or_else(|| validation(format!("The task policy {task_arn} is not a valid root task policy.")))?;
        let duration = input.duration_seconds.unwrap_or(ROOT_TASK_DURATION);
        if !(1..=ROOT_TASK_DURATION).contains(&duration) {
            return Err(validation(format!(
                "1 validation error detected: Value '{duration}' at 'durationSeconds' failed to satisfy constraint: Member must have value less than or equal to {ROOT_TASK_DURATION}"
            )));
        }
        let account = input.target_principal.clone();
        let caller = Caller {
            arn: target.clone(),
            user_id: account.clone(),
            account_id: account,
            access_key_id: String::new(),
            kind: CallerKind::Root,
            session: None,
        };
        let issued = self.issue(
            caller,
            duration,
            SessionInfo {
                kind: SessionKind::AssumeRoot,
                policies: vec![task_policy],
                tags: BTreeMap::new(),
                transitive_tag_keys: vec![],
                source_identity: None,
                issued_at: ctx.received_at,
                expires_at: ctx.received_at,
                mfa_authenticated: false,
                provided_context: Default::default(),
            },
        );
        Ok(types::AssumeRootResponse {
            credentials: Some(issued.credentials),
            session_token_utilization: Some(issued.token_utilization),
            session_token_size: Some(issued.token_size),
            ..Default::default()
        })
    }

    pub(crate) async fn decode_authorization_message_impl(
        &self,
        ctx: &RequestContext,
        input: types::DecodeAuthorizationMessageRequest,
    ) -> Result<types::DecodeAuthorizationMessageResponse, ServiceError> {
        ctx.authorize("sts:DecodeAuthorizationMessage", "*", ConditionContext::new())?;
        let invalid = || errors::invalid_authorization_message("The encoded authorization message is invalid.");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(input.encoded_message.trim())
            .or_else(|_| B64URL.decode(input.encoded_message.trim()))
            .map_err(|_| invalid())?;
        let json: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| invalid())?;
        if !json.is_object() {
            return Err(invalid());
        }
        Ok(types::DecodeAuthorizationMessageResponse { decoded_message: Some(json.to_string()) })
    }

    pub(crate) async fn get_delegated_access_token_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetDelegatedAccessTokenRequest,
    ) -> Result<types::GetDelegatedAccessTokenResponse, ServiceError> {
        let expired = || errors::expired_trade_in_token("The trade-in token is invalid or has expired.");
        let grant = self.iam().redeem_delegation_token(&input.trade_in_token).ok_or_else(expired)?;
        let account = mws_iam::arn_account(&grant.approver_arn).ok_or_else(expired)?.to_string();
        let caller = if grant.approver_arn.ends_with(":root") {
            Caller {
                arn: grant.approver_arn.clone(),
                user_id: account.clone(),
                account_id: account,
                access_key_id: String::new(),
                kind: CallerKind::Root,
                session: None,
            }
        } else if let Some(name) = grant.approver_arn.split(":user/").nth(1).and_then(|p| p.rsplit('/').next()) {
            let user = self.iam().user_by_name(&account, name).ok_or_else(expired)?;
            Caller {
                arn: user.arn,
                user_id: user.id,
                account_id: account,
                access_key_id: String::new(),
                kind: CallerKind::User { name: user.name },
                session: None,
            }
        } else {
            return Err(expired());
        };
        let policies: Vec<String> = grant
            .policy_template_arn
            .as_deref()
            .and_then(|a| self.iam().managed_policy_document(a))
            .into_iter()
            .collect();
        let packed: usize = grant.policy_template_arn.as_ref().map(String::len).unwrap_or(0);
        let issued = self.issue(
            caller,
            grant.session_duration,
            SessionInfo {
                kind: SessionKind::GetDelegatedAccessToken,
                policies,
                tags: BTreeMap::new(),
                transitive_tag_keys: vec![],
                source_identity: None,
                issued_at: ctx.received_at,
                expires_at: ctx.received_at,
                mfa_authenticated: false,
                provided_context: Default::default(),
            },
        );
        Ok(types::GetDelegatedAccessTokenResponse {
            credentials: Some(issued.credentials),
            packed_policy_size: Self::packed_size(packed, &BTreeMap::new()),
            assumed_principal: Some(grant.approver_arn),
        })
    }

    pub(crate) async fn get_web_identity_token_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetWebIdentityTokenRequest,
    ) -> Result<types::GetWebIdentityTokenResponse, ServiceError> {
        let alg = input.signing_algorithm.as_str();
        if alg != "RS256" && alg != "ES384" {
            return Err(validation(format!(
                "1 validation error detected: Value '{alg}' at 'signingAlgorithm' failed to satisfy constraint: Member must satisfy enum value set: [RS256, ES384]"
            )));
        }
        let duration = input.duration_seconds.unwrap_or(WEB_TOKEN_DEFAULT);
        if !(60..=3600).contains(&duration) {
            return Err(validation(format!(
                "1 validation error detected: Value '{duration}' at 'durationSeconds' failed to satisfy constraint: Member must have value between 60 and 3600"
            )));
        }
        let tags = Self::tags(input.tags);
        let mut cond = Self::request_tag_context(&tags);
        cond.insert("sts:IdentityTokenAudience".into(), input.audience.clone());
        cond.insert("sts:SigningAlgorithm".into(), vec![alg.to_string()]);
        cond.insert("sts:DurationSeconds".into(), vec![duration.to_string()]);
        ctx.authorize("sts:GetWebIdentityToken", "*", cond)?;
        let key = self.iam().outbound_signing_key(alg).ok_or_else(|| {
            errors::outbound_web_identity_federation_disabled(
                "Outbound web identity federation is not enabled for this account. Call iam:EnableOutboundWebIdentityFederation first.",
            )
        })?;
        let now = Utc::now();
        let exp = now + TimeDelta::seconds(duration as i64);
        let aud = match input.audience.as_slice() {
            [one] => serde_json::Value::from(one.clone()),
            many => serde_json::Value::from(many.to_vec()),
        };
        let header = serde_json::json!({ "kid": key.key_id, "typ": "JWT", "alg": alg });
        let payload = serde_json::json!({
            "aud": aud,
            "sub": ctx.caller.arn,
            "https://sts.amazonaws.com/": {
                "aws_account": ctx.caller.account_id,
                "source_region": ctx.region,
                "principal_id": ctx.caller.arn,
                "request_tags": tags,
            },
            "iss": key.issuer,
            "exp": exp.timestamp(),
            "iat": now.timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        let signing_input = format!("{}.{}", B64URL.encode(header.to_string()), B64URL.encode(payload.to_string()));
        let signature = sign(alg, &key.pkcs8, signing_input.as_bytes())
            .ok_or_else(|| ServiceError::internal("failed to sign web identity token"))?;
        Ok(types::GetWebIdentityTokenResponse {
            web_identity_token: Some(format!("{signing_input}.{}", B64URL.encode(signature))),
            expiration: chrono::DateTime::from_timestamp(exp.timestamp(), 0),
        })
    }
}

fn sign(alg: &str, pkcs8: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, RsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING, RSA_PKCS1_SHA256};
    let rng = SystemRandom::new();
    match alg {
        "RS256" => {
            let key = RsaKeyPair::from_pkcs8(pkcs8).ok()?;
            let mut sig = vec![0; key.public_modulus_len()];
            key.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig).ok()?;
            Some(sig)
        }
        "ES384" => {
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8).ok()?;
            Some(key.sign(&rng, msg).ok()?.as_ref().to_vec())
        }
        _ => None,
    }
}
