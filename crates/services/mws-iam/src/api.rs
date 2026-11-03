//! Read-only views other services (STS) use. AWS couples STS to IAM
//! identities, so this is the one sanctioned cross-service API.

use std::collections::BTreeMap;

use mws_core::ServiceError;
use mws_iam_policy::PolicyKind;

use crate::Iam;

#[derive(Debug, Clone)]
pub struct RoleView {
    pub account_id: String,
    pub name: String,
    pub arn: String,
    pub id: String,
    pub trust_policy: String,
    pub max_session_duration: i32,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct UserView {
    pub name: String,
    pub arn: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct OidcProviderView {
    pub arn: String,
    pub url: String,
    pub client_ids: Vec<String>,
}

/// The account field of an ARN, when it is an account id.
pub fn arn_account(arn: &str) -> Option<&str> {
    let account = arn.split(':').nth(4)?;
    (account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())).then_some(account)
}

impl Iam {
    /// The configured account. Requests work in their caller's account; see
    /// [`Iam::in_account`].
    pub fn account_id_str(&self) -> &str {
        &self.inner.config.account_id
    }

    /// The account that owns a long-term access key.
    pub fn account_of_access_key(&self, access_key_id: &str) -> Option<String> {
        if access_key_id == self.inner.config.root_access_key_id {
            return Some(self.inner.config.account_id.clone());
        }
        let accounts = self.inner.accounts.read().expect("IAM state lock poisoned");
        accounts.iter().find(|(_, s)| s.access_keys.contains_key(access_key_id)).map(|(a, _)| a.clone())
    }

    /// The namespace of the account an ARN names, or the current one.
    pub(crate) fn read_for_arn(&self, arn: &str) -> crate::common::StateRead<'_> {
        match arn_account(arn) {
            Some(a) => self.inner.read_account(a),
            None => self.read(),
        }
    }

    pub(crate) fn write_for_arn(&self, arn: &str) -> crate::common::StateWrite<'_> {
        match arn_account(arn) {
            Some(a) => self.inner.write_account(a),
            None => self.write(),
        }
    }

    pub fn partition(&self) -> &str {
        &self.inner.config.partition
    }

    /// Look up a role by ARN (path included).
    pub fn role_by_arn(&self, arn: &str) -> Option<RoleView> {
        let account = arn_account(arn)?.to_string();
        if !self.account_exists(&account) {
            return None;
        }
        let state = self.inner.read_account(&account);
        state.roles.values().find(|r| r.arn == arn).map(|r| RoleView {
            account_id: account.clone(),
            name: r.name.clone(),
            arn: r.arn.clone(),
            id: r.id.clone(),
            trust_policy: r.trust_policy.clone(),
            max_session_duration: r.max_session_duration,
            tags: r.tags.iter().cloned().collect(),
        })
    }

    /// Look up a user in `account`.
    pub fn user_by_name(&self, account: &str, name: &str) -> Option<UserView> {
        self.inner.read_account(account).user(name).map(|u| UserView {
            name: u.name.clone(),
            arn: u.arn.clone(),
            id: u.id.clone(),
        })
    }

    /// Find the OIDC provider in `account` whose URL (without scheme) is
    /// `issuer`.
    pub fn oidc_provider_for_issuer(&self, account: &str, issuer: &str) -> Option<OidcProviderView> {
        let wanted = issuer.trim_start_matches("https://").trim_end_matches('/');
        self.inner.read_account(account).oidc_providers.values().find(|p| p.url == wanted).map(|p| OidcProviderView {
            arn: p.arn.clone(),
            url: p.url.clone(),
            client_ids: p.client_ids.clone(),
        })
    }

    /// The default version of a managed policy.
    pub fn managed_policy_document(&self, arn: &str) -> Option<String> {
        self.read_for_arn(arn).policies.get(arn).map(|p| p.default_document().to_string())
    }

    /// Validate a session or identity policy document as IAM would.
    pub fn validate_identity_policy(&self, doc: &str) -> Result<(), ServiceError> {
        crate::common::validate_policy(doc, PolicyKind::Identity).map(|_| ())
    }

    /// Record that a role was used (for `RoleLastUsed`).
    pub fn note_role_used(&self, role: &RoleView, region: &str) {
        if let Some(r) = self.inner.write_account(&role.account_id).role_mut(&role.name) {
            r.last_used = Some((chrono::Utc::now(), region.to_string()));
        }
    }
}

/// What a redeemed delegation exchange token grants.
#[derive(Debug, Clone)]
pub struct DelegationGrant {
    /// The identity that accepted the request.
    pub approver_arn: String,
    pub session_duration: i32,
    pub policy_template_arn: Option<String>,
}

/// A signing key for outbound web identity tokens.
pub struct OutboundKey {
    pub issuer: String,
    /// PKCS#8 DER.
    pub pkcs8: Vec<u8>,
    pub key_id: String,
}

impl Iam {
    /// The lower-cased user name an enabled MFA device belongs to.
    pub fn mfa_device_owner(&self, serial: &str) -> Option<String> {
        self.read_for_arn(serial).mfa_devices.get(serial).filter(|d| d.enabled.is_some()).and_then(|d| d.user.clone())
    }

    /// Redeem a delegation exchange token once, for STS
    /// GetDelegatedAccessToken.
    pub fn redeem_delegation_token(&self, token: &str) -> Option<DelegationGrant> {
        let mut accounts = self.inner.accounts.write().expect("IAM state lock poisoned");
        let d = accounts
            .values_mut()
            .flat_map(|s| s.delegation_requests.values_mut())
            .find(|d| d.token.as_deref() == Some(token) && !d.redeemed)?;
        d.redeemed = true;
        Some(DelegationGrant {
            approver_arn: d.request.approver_id.clone()?,
            session_duration: d.request.session_duration.unwrap_or(3600),
            policy_template_arn: d.request.permissions.as_ref().and_then(|p| p.policy_template_arn.clone()),
        })
    }

    /// The issuer and signing key for outbound web identity tokens, or `None`
    /// while outbound federation is disabled. Keys are created on first use
    /// and kept in IAM state.
    pub fn outbound_signing_key(&self, algorithm: &str) -> Option<OutboundKey> {
        use aws_lc_rs::encoding::AsDer;
        let mut state = self.write();
        let issuer = state.outbound_enabled.then(|| state.outbound_issuer.clone()).flatten()?;
        if !state.outbound_keys.contains_key(algorithm) {
            let der = match algorithm {
                "RS256" => {
                    let k = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).ok()?;
                    let der: aws_lc_rs::encoding::Pkcs8V1Der = k.as_der().ok()?;
                    der.as_ref().to_vec()
                }
                "ES384" => {
                    let k = aws_lc_rs::signature::EcdsaKeyPair::generate(
                        &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    )
                    .ok()?;
                    k.to_pkcs8v1().ok()?.as_ref().to_vec()
                }
                _ => return None,
            };
            state.outbound_keys.insert(algorithm.to_string(), der);
        }
        let pkcs8 = state.outbound_keys[algorithm].clone();
        let key_id = {
            use md5::Digest;
            md5::Md5::digest(&pkcs8).iter().map(|b| format!("{b:02x}")).collect()
        };
        Some(OutboundKey { issuer, pkcs8, key_id })
    }
}
