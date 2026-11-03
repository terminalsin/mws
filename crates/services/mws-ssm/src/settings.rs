//! Service settings (`GetServiceSetting`, `UpdateServiceSetting`,
//! `ResetServiceSetting`). Parameter Store's default tier really applies to
//! `PutParameter`; the other settings are stored as given.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::{Region, Setting};
use crate::Ssm;

pub const DEFAULT_TIER: &str = "/ssm/parameter-store/default-parameter-tier";
pub const HIGH_THROUGHPUT: &str = "/ssm/parameter-store/high-throughput-enabled";

/// Every setting MWS knows, with its default and allowed values (empty when
/// any value goes).
const SETTINGS: &[(&str, &str, &[&str])] = &[
    (DEFAULT_TIER, "Standard", &["Standard", "Advanced", "Intelligent-Tiering"]),
    (HIGH_THROUGHPUT, "false", &["true", "false"]),
    ("/ssm/managed-instance/activation-tier", "standard", &["standard", "advanced"]),
    ("/ssm/managed-instance/default-ec2-instance-management-role", "", &[]),
    ("/ssm/automation/customer-script-log-destination", "", &["CloudWatch"]),
    ("/ssm/automation/customer-script-log-group-name", "", &[]),
    ("/ssm/automation/enable-adaptive-concurrency", "false", &["true", "false"]),
    ("/ssm/documents/console/public-sharing-permission", "Enable", &["Enable", "Disable"]),
    ("/ssm/opsinsights/opscenter", "Disabled", &["Enabled", "Disabled"]),
    ("/ssm/appmanager/appmanager-enabled", "false", &["true", "false"]),
];

/// The default tier `PutParameter` uses in a Region.
pub fn default_tier(region: Option<&Region>) -> String {
    region.and_then(|r| r.settings.get(DEFAULT_TIER)).map(|s| s.value.clone()).unwrap_or_else(|| "Standard".into())
}

fn not_found(id: &str) -> ServiceError {
    errors::service_setting_not_found(format!(
        "The service setting {id} wasn't found. Either the service name or the setting hasn't been provisioned by the AWS service team."
    ))
}

/// The setting id without the ARN prefix a caller may give it.
fn bare(id: &str) -> &str {
    match id.strip_prefix("arn:") {
        Some(rest) => rest.split_once(":servicesetting").map_or(id, |(_, s)| s),
        None => id,
    }
}

/// A setting's id, default and allowed values.
fn resolve(id: &str) -> Result<(&'static str, &'static str, &'static [&'static str]), ServiceError> {
    SETTINGS.iter().find(|(name, _, _)| *name == bare(id)).copied().ok_or_else(|| not_found(id))
}

fn arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ssm:{}:{}:servicesetting{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

impl Ssm {
    fn setting(&self, ctx: &RequestContext, id: &'static str, default: &str) -> types::ServiceSetting {
        let st = self.lock();
        let custom = st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.settings.get(id));
        types::ServiceSetting {
            setting_id: Some(id.to_string()),
            setting_value: Some(custom.map_or_else(|| default.to_string(), |s| s.value.clone())),
            last_modified_date: Some(custom.and_then(|s| s.last_modified_date).unwrap_or(chrono::DateTime::UNIX_EPOCH)),
            last_modified_user: Some(custom.map_or_else(|| "System".to_string(), |s| s.last_modified_user.clone())),
            arn: Some(arn(ctx, id)),
            status: Some(if custom.is_some() { "Customized" } else { "Default" }.to_string()),
        }
    }

    pub(crate) fn get_service_setting(
        &self,
        ctx: &RequestContext,
        input: types::GetServiceSettingRequest,
    ) -> Result<types::GetServiceSettingResult, ServiceError> {
        ctx.authorize("ssm:GetServiceSetting", &arn(ctx, bare(&input.setting_id)), ConditionContext::new())?;
        let (id, default, _) = resolve(&input.setting_id)?;
        Ok(types::GetServiceSettingResult { service_setting: Some(self.setting(ctx, id, default)) })
    }

    pub(crate) fn update_service_setting(
        &self,
        ctx: &RequestContext,
        input: types::UpdateServiceSettingRequest,
    ) -> Result<types::UpdateServiceSettingResult, ServiceError> {
        ctx.authorize("ssm:UpdateServiceSetting", &arn(ctx, bare(&input.setting_id)), ConditionContext::new())?;
        let (id, _, allowed) = resolve(&input.setting_id)?;
        if !allowed.is_empty() && !allowed.contains(&input.setting_value.as_str()) {
            return Err(errors::validation(format!(
                "The value {} isn't valid for the service setting {id}. Valid values: {}.",
                input.setting_value,
                allowed.join(", ")
            )));
        }
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        region.settings.insert(
            id.to_string(),
            Setting {
                value: input.setting_value,
                last_modified_date: Some(ctx.received_at),
                last_modified_user: ctx.caller.arn.clone(),
            },
        );
        Ok(types::UpdateServiceSettingResult::default())
    }

    pub(crate) fn reset_service_setting(
        &self,
        ctx: &RequestContext,
        input: types::ResetServiceSettingRequest,
    ) -> Result<types::ResetServiceSettingResult, ServiceError> {
        ctx.authorize("ssm:ResetServiceSetting", &arn(ctx, bare(&input.setting_id)), ConditionContext::new())?;
        let (id, default, _) = resolve(&input.setting_id)?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).settings.remove(id);
        Ok(types::ResetServiceSettingResult { service_setting: Some(self.setting(ctx, id, default)) })
    }
}
