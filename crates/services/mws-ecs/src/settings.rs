//! Account settings: per principal, with account defaults (kept under the
//! root ARN) and the built-in defaults behind them.

use mws_core::{CallerKind, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::names::{authorize, invalid, paginate, Cond, Scope};
use crate::state::Region;
use crate::Ecs;

/// Every setting and its built-in default.
pub const DEFAULTS: &[(&str, &str)] = &[
    ("awsvpcTrunking", "disabled"),
    ("containerInsights", "disabled"),
    ("containerInstanceLongArnFormat", "enabled"),
    ("defaultLogDriverMode", "non-blocking"),
    ("fargateEventWindows", "disabled"),
    ("fargateFIPSMode", "disabled"),
    ("fargateTaskRetirementWaitPeriod", "7"),
    ("guardDutyActivate", "off"),
    ("serviceLongArnFormat", "enabled"),
    ("tagResourceAuthorization", "on"),
    ("taskLongArnFormat", "enabled"),
];

fn allowed_values(name: &str) -> &'static [&'static str] {
    match name {
        "containerInsights" => &["enabled", "disabled", "enhanced"],
        "fargateTaskRetirementWaitPeriod" => &["0", "7", "14"],
        "guardDutyActivate" | "tagResourceAuthorization" => &["on", "off"],
        "defaultLogDriverMode" => &["blocking", "non-blocking"],
        _ => &["enabled", "disabled"],
    }
}

/// Settings only the account default can carry.
fn account_only(name: &str) -> bool {
    matches!(name, "fargateFIPSMode" | "fargateTaskRetirementWaitPeriod" | "guardDutyActivate" | "fargateEventWindows")
}

/// The principal a request acts for: an IAM user or role ARN (sessions act
/// as their role), or the root ARN for the root user and federated users.
pub fn caller_principal(ctx: &RequestContext, scope: &Scope) -> String {
    match &ctx.caller.kind {
        CallerKind::User { .. } => ctx.caller.arn.clone(),
        CallerKind::AssumedRole { role_name, .. } => {
            format!("arn:{}:iam::{}:role/{role_name}", scope.partition, scope.account)
        }
        _ => scope.iam_root(),
    }
}

/// The effective value of a setting for `principal`.
pub fn effective(r: &Region, scope: &Scope, principal: &str, name: &str) -> (String, String) {
    if let Some(v) = r.account_settings.get(principal).and_then(|s| s.get(name)) {
        return (v.clone(), principal.to_string());
    }
    let root = scope.iam_root();
    if let Some(v) = r.account_settings.get(&root).and_then(|s| s.get(name)) {
        return (v.clone(), root);
    }
    let v = DEFAULTS.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string()).unwrap_or_default();
    (v, root)
}

fn setting(name: &str, value: &str, principal: &str) -> t::Setting {
    t::Setting {
        name: Some(name.into()),
        value: Some(value.into()),
        principal_arn: Some(principal.into()),
        r#type: Some("user".into()),
    }
}

fn check(name: &str, value: &str) -> Result<(), ServiceError> {
    if !allowed_values(name).contains(&value) {
        return Err(invalid(format!(
            "The value '{value}' is not valid for the account setting '{name}'. Valid values are: {}.",
            allowed_values(name).join(", ")
        )));
    }
    Ok(())
}

impl Ecs {
    pub(crate) fn put_account_setting_op(
        &self,
        ctx: &RequestContext,
        input: t::PutAccountSettingRequest,
    ) -> Result<t::PutAccountSettingResponse, ServiceError> {
        authorize(ctx, "PutAccountSetting", "*", Cond::new())?;
        check(&input.name, &input.value)?;
        self.with_region(ctx, |r, scope| {
            let principal = input.principal_arn.clone().unwrap_or_else(|| caller_principal(ctx, scope));
            if principal != scope.iam_root() && account_only(&input.name) {
                return Err(invalid(format!(
                    "The account setting '{}' can only be set as the account default.",
                    input.name
                )));
            }
            r.account_settings.entry(principal.clone()).or_default().insert(input.name.clone(), input.value.clone());
            Ok(t::PutAccountSettingResponse { setting: Some(setting(&input.name, &input.value, &principal)) })
        })
    }

    pub(crate) fn put_account_setting_default_op(
        &self,
        ctx: &RequestContext,
        input: t::PutAccountSettingDefaultRequest,
    ) -> Result<t::PutAccountSettingDefaultResponse, ServiceError> {
        authorize(ctx, "PutAccountSettingDefault", "*", Cond::new())?;
        check(&input.name, &input.value)?;
        self.with_region(ctx, |r, scope| {
            let root = scope.iam_root();
            r.account_settings.entry(root.clone()).or_default().insert(input.name.clone(), input.value.clone());
            Ok(t::PutAccountSettingDefaultResponse { setting: Some(setting(&input.name, &input.value, &root)) })
        })
    }

    pub(crate) fn delete_account_setting_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteAccountSettingRequest,
    ) -> Result<t::DeleteAccountSettingResponse, ServiceError> {
        authorize(ctx, "DeleteAccountSetting", "*", Cond::new())?;
        self.with_region(ctx, |r, scope| {
            let principal = input.principal_arn.clone().unwrap_or_else(|| caller_principal(ctx, scope));
            let removed = r.account_settings.get_mut(&principal).and_then(|s| s.remove(&input.name));
            let Some(value) = removed else {
                return Err(invalid("The specified account setting does not exist for the principal."));
            };
            Ok(t::DeleteAccountSettingResponse { setting: Some(setting(&input.name, &value, &principal)) })
        })
    }

    pub(crate) fn list_account_settings_op(
        &self,
        ctx: &RequestContext,
        input: t::ListAccountSettingsRequest,
    ) -> Result<t::ListAccountSettingsResponse, ServiceError> {
        authorize(ctx, "ListAccountSettings", "*", Cond::new())?;
        self.with_region(ctx, |r, scope| {
            let principal = input.principal_arn.clone().unwrap_or_else(|| caller_principal(ctx, scope));
            let mut out = Vec::new();
            for (name, _) in DEFAULTS {
                if input.name.as_deref().is_some_and(|n| n != *name) {
                    continue;
                }
                let found = if input.effective_settings {
                    Some(effective(r, scope, &principal, name))
                } else {
                    r.account_settings.get(&principal).and_then(|s| s.get(*name)).map(|v| (v.clone(), principal.clone()))
                };
                let Some((value, owner)) = found else { continue };
                if input.value.as_deref().is_some_and(|v| v != value) {
                    continue;
                }
                out.push(setting(name, &value, &owner));
            }
            let max = if input.max_results == 0 { None } else { Some(input.max_results) };
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), max, 10)?;
            Ok(t::ListAccountSettingsResponse { settings: Some(page), next_token })
        })
    }
}
