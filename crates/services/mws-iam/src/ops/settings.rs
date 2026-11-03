//! Account-wide settings: password policy and ChangePassword, the credential
//! report, account properties, STS token preferences, outbound web identity
//! federation, and the Organizations root-access features.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use mws_core::{CallerKind, RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{LoginProfile, PasswordPolicy, State};
use crate::Iam;

const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|'";
const REPORT_TTL_HOURS: i64 = 4;

/// The policy AWS applies when the account has none: at least 8 characters
/// and three of the four character classes.
pub(crate) fn check_password(
    policy: Option<&PasswordPolicy>,
    password: &str,
    history: &[String],
) -> Result<(), ServiceError> {
    let violation = |m: &str| errors::password_policy_violation(m.to_string());
    let upper = password.chars().any(|c| c.is_ascii_uppercase());
    let lower = password.chars().any(|c| c.is_ascii_lowercase());
    let number = password.chars().any(|c| c.is_ascii_digit());
    let symbol = password.chars().any(|c| SYMBOLS.contains(c));
    let Some(p) = policy else {
        if password.chars().count() < 8 || [upper, lower, number, symbol].iter().filter(|b| **b).count() < 3 {
            return Err(violation("Password does not conform to the account password policy."));
        }
        return Ok(());
    };
    if (password.chars().count() as i32) < p.minimum_length {
        return Err(violation(&format!("Password should have a minimum length of {}", p.minimum_length)));
    }
    if p.require_uppercase && !upper {
        return Err(violation("Password should have at least one uppercase letter"));
    }
    if p.require_lowercase && !lower {
        return Err(violation("Password should have at least one lowercase letter"));
    }
    if p.require_numbers && !number {
        return Err(violation("Password should have at least one number"));
    }
    if p.require_symbols && !symbol {
        return Err(violation("Password should have at least one symbol"));
    }
    if let Some(n) = p.reuse_prevention {
        if history.iter().rev().take(n as usize).any(|h| h == password) {
            return Err(violation(&format!("Password cannot be one of the last {n} passwords used")));
        }
    }
    Ok(())
}

impl LoginProfile {
    /// Replace the password, keeping the old one for reuse checks.
    pub(crate) fn set_password(&mut self, password: String) {
        let old = std::mem::replace(&mut self.password, password);
        self.history.push(old);
        if self.history.len() > 24 {
            self.history.remove(0);
        }
        self.changed = Some(Utc::now());
    }
}

fn no_policy(account: &str) -> ServiceError {
    errors::no_such_entity(format!("The Password Policy with domain name {account} cannot be found."))
}

fn iso(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true).replace('Z', "+00:00")
}

fn opt_time(t: Option<DateTime<Utc>>, none: &str) -> String {
    t.map(iso).unwrap_or_else(|| none.to_string())
}

fn credential_report(state: &State, account: &str, root_arn: &str) -> String {
    let mut out = String::from(
        "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,\
access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,\
access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,\
cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n",
    );
    let keys = |user: Option<&str>| -> Vec<String> {
        let mut ks = state.keys_for(user);
        ks.sort_by_key(|k| k.created);
        (0..2)
            .flat_map(|i| match ks.get(i) {
                Some(k) => vec![
                    k.active.to_string(),
                    iso(k.created),
                    k.last_used.as_ref().map(|l| iso(l.0)).unwrap_or_else(|| "N/A".into()),
                    k.last_used.as_ref().map(|l| l.1.clone()).unwrap_or_else(|| "N/A".into()),
                    k.last_used.as_ref().map(|l| l.2.clone()).unwrap_or_else(|| "N/A".into()),
                ],
                None => vec!["false".into(), "N/A".into(), "N/A".into(), "N/A".into(), "N/A".into()],
            })
            .collect()
    };
    let certs = |user: Option<String>| -> Vec<String> {
        let mut cs: Vec<_> = state.signing_certificates.values().filter(|c| c.user == user).collect();
        cs.sort_by_key(|c| c.uploaded);
        (0..2)
            .flat_map(|i| match cs.get(i) {
                Some(c) => vec![c.active.to_string(), iso(c.uploaded)],
                None => vec!["false".into(), "N/A".into()],
            })
            .collect()
    };
    let policy = state.password_policy.as_ref();
    let mut rows = vec![];
    let mut root = vec!["<root_account>".to_string(), root_arn.to_string(), "N/A".into()];
    root.extend(["not_supported", "no_information", "not_supported", "not_supported", "false"].map(String::from));
    root.extend(keys(None));
    root.extend(certs(None));
    rows.push(root);
    for u in state.users.values() {
        let key = u.name.to_lowercase();
        let mut row = vec![u.name.clone(), u.arn.clone(), iso(u.created)];
        match &u.login_profile {
            Some(lp) => {
                let changed = lp.changed.unwrap_or(lp.created);
                row.push("true".into());
                row.push(opt_time(u.password_last_used, "no_information"));
                row.push(iso(changed));
                row.push(match policy.and_then(|p| p.max_age) {
                    Some(days) => iso(changed + Duration::days(days as i64)),
                    None => "N/A".into(),
                });
            }
            None => row.extend(["false", "N/A", "N/A", "N/A"].map(String::from)),
        }
        row.push(state.mfa_devices.values().any(|d| d.user.as_deref() == Some(key.as_str())).to_string());
        row.extend(keys(Some(&u.name)));
        row.extend(certs(Some(key)));
        rows.push(row);
    }
    let _ = account;
    for r in rows {
        out.push_str(&r.join(","));
        out.push('\n');
    }
    out
}

fn no_organization() -> ServiceError {
    errors::organization_not_found("The request was rejected because no organization is associated with your account.")
}

impl Iam {
    // --- Password policy ---------------------------------------------------

    pub fn update_account_password_policy(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccountPasswordPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UpdateAccountPasswordPolicy", "*")?;
        self.write().password_policy = Some(PasswordPolicy {
            minimum_length: input.minimum_password_length.unwrap_or(6),
            require_symbols: input.require_symbols,
            require_numbers: input.require_numbers,
            require_uppercase: input.require_uppercase_characters,
            require_lowercase: input.require_lowercase_characters,
            allow_users_to_change: input.allow_users_to_change_password,
            max_age: input.max_password_age.filter(|d| *d > 0),
            reuse_prevention: input.password_reuse_prevention,
            hard_expiry: input.hard_expiry,
        });
        Ok(())
    }

    pub fn get_account_password_policy(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::GetAccountPasswordPolicyResponse, ServiceError> {
        self.authorize(ctx, "GetAccountPasswordPolicy", "*")?;
        let state = self.read();
        let p = state.password_policy.as_ref().ok_or_else(|| no_policy(&self.account_id()))?;
        Ok(types::GetAccountPasswordPolicyResponse {
            password_policy: types::PasswordPolicy {
                minimum_password_length: Some(p.minimum_length),
                require_symbols: p.require_symbols,
                require_numbers: p.require_numbers,
                require_uppercase_characters: p.require_uppercase,
                require_lowercase_characters: p.require_lowercase,
                allow_users_to_change_password: p.allow_users_to_change,
                expire_passwords: p.max_age.is_some(),
                max_password_age: p.max_age,
                password_reuse_prevention: p.reuse_prevention,
                hard_expiry: p.hard_expiry,
            },
        })
    }

    pub fn delete_account_password_policy(&self, ctx: &RequestContext, _input: ()) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteAccountPasswordPolicy", "*")?;
        self.write().password_policy.take().ok_or_else(|| no_policy(&self.account_id()))?;
        Ok(())
    }

    pub fn change_password(
        &self,
        ctx: &RequestContext,
        input: types::ChangePasswordRequest,
    ) -> Result<(), ServiceError> {
        let CallerKind::User { name } = &ctx.caller.kind else {
            return Err(errors::invalid_user_type("Only IAM Users can change their own password."));
        };
        let arn = self.user_arn_or_default(name);
        // `AllowUsersToChangePassword` grants iam:ChangePassword on the
        // user's own ARN without a policy.
        let granted = self.read().password_policy.as_ref().is_some_and(|p| p.allow_users_to_change);
        if !granted {
            self.authorize(ctx, "ChangePassword", &arn)?;
        }
        let mut state = self.write();
        let policy = state.password_policy.clone();
        let user = state.user_mut(name).ok_or_else(|| no_such_user(name))?;
        let lp = user
            .login_profile
            .as_mut()
            .ok_or_else(|| errors::no_such_entity(format!("Login Profile for User {name} cannot be found.")))?;
        if lp.password != input.old_password {
            return Err(errors::invalid_user_type("The old password specified is not correct."));
        }
        let mut history = lp.history.clone();
        history.push(lp.password.clone());
        check_password(policy.as_ref(), &input.new_password, &history)?;
        lp.set_password(input.new_password);
        lp.reset_required = false;
        Ok(())
    }

    // --- Credential report -------------------------------------------------

    pub fn generate_credential_report(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::GenerateCredentialReportResponse, ServiceError> {
        self.authorize(ctx, "GenerateCredentialReport", "*")?;
        let mut state = self.write();
        let now = Utc::now();
        match state.credential_report {
            Some(t) if now - t < Duration::hours(REPORT_TTL_HOURS) => {
                Ok(types::GenerateCredentialReportResponse { state: Some("COMPLETE".into()), description: None })
            }
            _ => {
                state.credential_report = Some(now);
                Ok(types::GenerateCredentialReportResponse {
                    state: Some("STARTED".into()),
                    description: Some("No report exists. Starting a new report generation task".into()),
                })
            }
        }
    }

    pub fn get_credential_report(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::GetCredentialReportResponse, ServiceError> {
        self.authorize(ctx, "GetCredentialReport", "*")?;
        let state = self.read();
        let generated = state.credential_report.ok_or_else(|| {
            errors::credential_report_not_present("Unable to find a credential report for this account. To generate a credential report, use GenerateCredentialReport.")
        })?;
        if Utc::now() - generated >= Duration::hours(REPORT_TTL_HOURS) {
            return Err(errors::credential_report_expired(
                "The credential report has expired. To generate a new credential report, use GenerateCredentialReport.",
            ));
        }
        let root = format!("arn:aws:iam::{}:root", self.account_id());
        Ok(types::GetCredentialReportResponse {
            content: Some(credential_report(&state, &self.account_id(), &root).into_bytes()),
            report_format: Some("text/csv".into()),
            generated_time: Some(generated),
        })
    }

    // --- Account properties and STS preferences ---------------------------

    pub fn get_account_properties(
        &self,
        ctx: &RequestContext,
        _input: types::GetAccountPropertiesRequest,
    ) -> Result<types::GetAccountPropertiesResponse, ServiceError> {
        self.authorize(ctx, "GetAccountProperties", "*")?;
        Ok(types::GetAccountPropertiesResponse { properties: Some(self.read().account_properties.clone()) })
    }

    pub fn put_account_properties(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountPropertiesRequest,
    ) -> Result<types::PutAccountPropertiesResponse, ServiceError> {
        self.authorize(ctx, "PutAccountProperties", "*")?;
        let mut namespaces = input.properties.keys().map(|k| k.split_once('/').map(|(ns, _)| ns));
        let first = namespaces.next().flatten();
        if first.is_none() || namespaces.any(|ns| ns != first) {
            return Err(errors::invalid_input(
                "Properties must be in Namespace/PropertyName format and belong to the same namespace.",
            ));
        }
        let mut state = self.write();
        let props: &mut BTreeMap<String, String> = &mut state.account_properties;
        props.extend(input.properties);
        Ok(types::PutAccountPropertiesResponse {})
    }

    pub fn set_security_token_service_preferences(
        &self,
        ctx: &RequestContext,
        input: types::SetSecurityTokenServicePreferencesRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "SetSecurityTokenServicePreferences", "*")?;
        let v = input.global_endpoint_token_version;
        if v != "v1Token" && v != "v2Token" {
            return Err(validation(format!(
                "1 validation error detected: Value '{v}' at 'globalEndpointTokenVersion' failed to satisfy constraint: Member must satisfy enum value set: [v1Token, v2Token]"
            )));
        }
        self.write().global_endpoint_token_version = Some(v);
        Ok(())
    }

    // --- Outbound web identity federation ----------------------------------

    pub fn enable_outbound_web_identity_federation(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::EnableOutboundWebIdentityFederationResponse, ServiceError> {
        self.authorize(ctx, "EnableOutboundWebIdentityFederation", "*")?;
        let mut state = self.write();
        if state.outbound_enabled {
            return Err(errors::feature_enabled("Outbound identity federation is already enabled for your account."));
        }
        let issuer = state
            .outbound_issuer
            .get_or_insert_with(|| format!("https://{}.tokens.sts.global.api.aws", uuid::Uuid::new_v4()))
            .clone();
        state.outbound_enabled = true;
        Ok(types::EnableOutboundWebIdentityFederationResponse { issuer_identifier: Some(issuer) })
    }

    pub fn disable_outbound_web_identity_federation(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DisableOutboundWebIdentityFederation", "*")?;
        let mut state = self.write();
        if !state.outbound_enabled {
            return Err(errors::feature_disabled("Outbound identity federation is already disabled for your account."));
        }
        state.outbound_enabled = false;
        Ok(())
    }

    pub fn get_outbound_web_identity_federation_info(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::GetOutboundWebIdentityFederationInfoResponse, ServiceError> {
        self.authorize(ctx, "GetOutboundWebIdentityFederationInfo", "*")?;
        let state = self.read();
        if !state.outbound_enabled {
            return Err(errors::feature_disabled("Outbound identity federation is disabled for your account."));
        }
        Ok(types::GetOutboundWebIdentityFederationInfoResponse {
            issuer_identifier: state.outbound_issuer.clone(),
            jwt_vending_enabled: true,
        })
    }

    /// The outbound federation issuer when enabled, for STS GetWebIdentityToken.
    pub fn outbound_issuer(&self) -> Option<String> {
        let state = self.read();
        state.outbound_enabled.then(|| state.outbound_issuer.clone()).flatten()
    }

    // --- Organizations centralized root access ------------------------------

    /// The caller's organization, checked as centralized root access
    /// requires: all features, trusted access for IAM, and a caller that is
    /// the management account (or, unless `management_only`, IAM's delegated
    /// administrator). Returns the organization id and management account.
    fn root_access_org(&self, ctx: &RequestContext, management_only: bool) -> Result<(String, String), ServiceError> {
        let account = &ctx.caller.account_id;
        let org = self.organization_of(account).ok_or_else(no_organization)?;
        if !org.all_features {
            return Err(errors::organization_not_in_all_features_mode(
                "The request was rejected because the organization does not have all features enabled.",
            ));
        }
        let delegated = org.delegated_admin_for.iter().any(|s| s == IAM_PRINCIPAL);
        if !org.is_management(account) {
            if management_only {
                return Err(errors::caller_is_not_management_account(
                    "The request was rejected because the account making the request is not the management account for the organization.",
                ));
            }
            if !delegated {
                return Err(errors::account_not_management_or_delegated_administrator(
                    "The request was rejected because the account making the request is not the management account or delegated administrator account for centralized root access.",
                ));
            }
        }
        if !org.trusted_services.iter().any(|s| s == IAM_PRINCIPAL) {
            return Err(errors::service_access_not_enabled(
                "The request was rejected because trusted access is not enabled for IAM in AWS Organizations. For details, see IAM and AWS Organizations in the AWS Organizations User Guide.",
            ));
        }
        Ok((org.organization_id, org.management_account_id))
    }

    fn root_features(&self, management_account: &str) -> Vec<String> {
        let state = self.inner.read_account(management_account);
        let mut out = vec![];
        if state.org_root_credentials_management {
            out.push("RootCredentialsManagement".to_string());
        }
        if state.org_root_sessions {
            out.push("RootSessions".to_string());
        }
        out
    }

    fn set_root_feature(
        &self,
        ctx: &RequestContext,
        credentials_management: bool,
        enabled: bool,
    ) -> Result<(String, Vec<String>), ServiceError> {
        let (org_id, mgmt) = self.root_access_org(ctx, true)?;
        {
            let mut state = self.inner.write_account(&mgmt);
            if credentials_management {
                state.org_root_credentials_management = enabled;
            } else {
                state.org_root_sessions = enabled;
            }
        }
        Ok((org_id, self.root_features(&mgmt)))
    }

    pub fn list_organizations_features(
        &self,
        ctx: &RequestContext,
        _input: types::ListOrganizationsFeaturesRequest,
    ) -> Result<types::ListOrganizationsFeaturesResponse, ServiceError> {
        self.authorize(ctx, "ListOrganizationsFeatures", "*")?;
        let (org_id, mgmt) = self.root_access_org(ctx, false)?;
        Ok(types::ListOrganizationsFeaturesResponse {
            organization_id: Some(org_id),
            enabled_features: Some(self.root_features(&mgmt)),
        })
    }

    pub fn enable_organizations_root_credentials_management(
        &self,
        ctx: &RequestContext,
        _input: types::EnableOrganizationsRootCredentialsManagementRequest,
    ) -> Result<types::EnableOrganizationsRootCredentialsManagementResponse, ServiceError> {
        self.authorize(ctx, "EnableOrganizationsRootCredentialsManagement", "*")?;
        let (org_id, features) = self.set_root_feature(ctx, true, true)?;
        Ok(types::EnableOrganizationsRootCredentialsManagementResponse {
            organization_id: Some(org_id),
            enabled_features: Some(features),
        })
    }

    pub fn disable_organizations_root_credentials_management(
        &self,
        ctx: &RequestContext,
        _input: types::DisableOrganizationsRootCredentialsManagementRequest,
    ) -> Result<types::DisableOrganizationsRootCredentialsManagementResponse, ServiceError> {
        self.authorize(ctx, "DisableOrganizationsRootCredentialsManagement", "*")?;
        let (org_id, features) = self.set_root_feature(ctx, true, false)?;
        Ok(types::DisableOrganizationsRootCredentialsManagementResponse {
            organization_id: Some(org_id),
            enabled_features: Some(features),
        })
    }

    pub fn enable_organizations_root_sessions(
        &self,
        ctx: &RequestContext,
        _input: types::EnableOrganizationsRootSessionsRequest,
    ) -> Result<types::EnableOrganizationsRootSessionsResponse, ServiceError> {
        self.authorize(ctx, "EnableOrganizationsRootSessions", "*")?;
        let (org_id, features) = self.set_root_feature(ctx, false, true)?;
        Ok(types::EnableOrganizationsRootSessionsResponse {
            organization_id: Some(org_id),
            enabled_features: Some(features),
        })
    }

    pub fn disable_organizations_root_sessions(
        &self,
        ctx: &RequestContext,
        _input: types::DisableOrganizationsRootSessionsRequest,
    ) -> Result<types::DisableOrganizationsRootSessionsResponse, ServiceError> {
        self.authorize(ctx, "DisableOrganizationsRootSessions", "*")?;
        let (org_id, features) = self.set_root_feature(ctx, false, false)?;
        Ok(types::DisableOrganizationsRootSessionsResponse {
            organization_id: Some(org_id),
            enabled_features: Some(features),
        })
    }
}

const IAM_PRINCIPAL: &str = "iam.amazonaws.com";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_needs_three_classes() {
        assert!(check_password(None, "short", &[]).is_err());
        assert!(check_password(None, "alllowercase1", &[]).is_err());
        assert!(check_password(None, "Lower1case", &[]).is_ok());
    }

    #[test]
    fn custom_policy_rules() {
        let p = PasswordPolicy {
            minimum_length: 10,
            require_symbols: true,
            require_numbers: false,
            require_uppercase: false,
            require_lowercase: false,
            allow_users_to_change: true,
            max_age: None,
            reuse_prevention: Some(2),
            hard_expiry: None,
        };
        assert!(check_password(Some(&p), "abc!", &[]).is_err());
        assert!(check_password(Some(&p), "abcdefghij", &[]).is_err());
        assert!(check_password(Some(&p), "abcdefghi!", &["abcdefghi!".into()]).is_err());
        assert!(check_password(Some(&p), "abcdefghi!", &["abcdefghi!".into(), "x".into(), "y".into()]).is_ok());
    }
}
