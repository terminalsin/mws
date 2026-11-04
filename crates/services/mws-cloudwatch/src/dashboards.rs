//! Dashboards: `PutDashboard` (with body validation), `GetDashboard`,
//! `ListDashboards` and `DeleteDashboards`. Dashboards are global to the
//! account, as their ARNs (no Region) say.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::names::{self, dashboard_arn, now, request_tag_conditions};
use crate::state::Dashboard;
use crate::CloudWatch;

/// Dashboards live in this pseudo-Region of each account.
const GLOBAL: &str = "";

const WIDGET_TYPES: &[&str] = &["metric", "text", "log", "alarm", "explorer", "custom"];

fn invalid(message: impl Into<String>) -> ServiceError {
    errors::dashboard_invalid_input_error(message)
}

/// Fatal problems with a body, and non-fatal validation messages.
fn validate_body(body: &str) -> Result<Vec<types::DashboardValidationMessage>, ServiceError> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| invalid("The field DashboardBody must be a valid JSON object"))?;
    let Some(obj) = v.as_object() else { return Err(invalid("The field DashboardBody must be a valid JSON object")) };
    let mut messages = Vec::new();
    let Some(widgets) = obj.get("widgets") else {
        return Err(invalid("The dashboard body is invalid, there are 1 validation errors:\n[\n  {\n    \"dataPath\": \"\",\n    \"message\": \"Should have required property 'widgets'\"\n  }\n]"));
    };
    let Some(widgets) = widgets.as_array() else {
        return Err(invalid("The dashboard body is invalid: /widgets should be array"));
    };
    for (i, w) in widgets.iter().enumerate() {
        let path = format!("/widgets/{i}");
        let Some(w) = w.as_object() else {
            return Err(invalid(format!("The dashboard body is invalid: {path} should be object")));
        };
        let Some(t) = w.get("type").and_then(Value::as_str) else {
            return Err(invalid(format!("The dashboard body is invalid: {path} should have required property 'type'")));
        };
        if !WIDGET_TYPES.contains(&t) {
            return Err(invalid(format!(
                "The dashboard body is invalid: {path}/type should be equal to one of the allowed values"
            )));
        }
        for dim in ["x", "y", "width", "height"] {
            if let Some(n) = w.get(dim) {
                if !n.is_number() {
                    return Err(invalid(format!("The dashboard body is invalid: {path}/{dim} should be integer")));
                }
            }
        }
        if t == "metric" {
            let props = w.get("properties").and_then(Value::as_object);
            let has_metrics = props.is_some_and(|p| p.contains_key("metrics") || p.contains_key("annotations"));
            if !has_metrics {
                messages.push(types::DashboardValidationMessage {
                    data_path: Some(format!("{path}/properties")),
                    message: Some("Should have required property 'metrics'".into()),
                });
            }
            if props.is_some_and(|p| !p.contains_key("region")) {
                messages.push(types::DashboardValidationMessage {
                    data_path: Some(format!("{path}/properties")),
                    message: Some("Should have required property 'region'".into()),
                });
            }
        }
    }
    Ok(messages)
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 255 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl CloudWatch {
    pub(crate) fn put_dashboard(
        &self,
        ctx: &RequestContext,
        input: types::PutDashboardInput,
    ) -> Result<types::PutDashboardOutput, ServiceError> {
        let arn = dashboard_arn(ctx, &input.dashboard_name);
        let tags = input.tags.clone().unwrap_or_default();
        ctx.authorize("cloudwatch:PutDashboard", &arn, request_tag_conditions(&tags))?;
        if !valid_name(&input.dashboard_name) {
            return Err(invalid(format!(
                "The value {} for parameter DashboardName is invalid. Dashboard names can contain only alphanumerics, dash (-) and underscore (_).",
                input.dashboard_name
            )));
        }
        if input.dashboard_body.len() > 1_048_576 {
            return Err(invalid("The dashboard body exceeds the maximum size of 1 MB."));
        }
        let messages = validate_body(&input.dashboard_body)?;
        let now = now(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, GLOBAL);
        let created = !region.dashboards.contains_key(&input.dashboard_name);
        region.dashboards.insert(
            input.dashboard_name.clone(),
            Dashboard { arn: arn.clone(), body: input.dashboard_body, last_modified: now },
        );
        if created && !tags.is_empty() {
            region.tags.insert(arn, tags.into_iter().map(|t| (t.key, t.value)).collect());
        }
        Ok(types::PutDashboardOutput { dashboard_validation_messages: Some(messages) })
    }

    pub(crate) fn get_dashboard(
        &self,
        ctx: &RequestContext,
        input: types::GetDashboardInput,
    ) -> Result<types::GetDashboardOutput, ServiceError> {
        ctx.authorize("cloudwatch:GetDashboard", &dashboard_arn(ctx, &input.dashboard_name), ConditionContext::new())?;
        let st = self.lock();
        let d = st
            .region_ref(&ctx.caller.account_id, GLOBAL)
            .and_then(|r| r.dashboards.get(&input.dashboard_name))
            .ok_or_else(|| {
                errors::dashboard_not_found_error(format!("Dashboard {} does not exist", input.dashboard_name))
            })?;
        Ok(types::GetDashboardOutput {
            dashboard_arn: Some(d.arn.clone()),
            dashboard_body: Some(d.body.clone()),
            dashboard_name: Some(input.dashboard_name),
        })
    }

    pub(crate) fn list_dashboards(
        &self,
        ctx: &RequestContext,
        input: types::ListDashboardsInput,
    ) -> Result<types::ListDashboardsOutput, ServiceError> {
        ctx.authorize("cloudwatch:ListDashboards", &names::any(ctx), ConditionContext::new())?;
        let st = self.lock();
        let entries: Vec<types::DashboardEntry> = st
            .region_ref(&ctx.caller.account_id, GLOBAL)
            .map(|r| {
                r.dashboards
                    .iter()
                    .filter(|(n, _)| input.dashboard_name_prefix.as_ref().is_none_or(|p| n.starts_with(p.as_str())))
                    .map(|(n, d)| types::DashboardEntry {
                        dashboard_name: Some(n.clone()),
                        dashboard_arn: Some(d.arn.clone()),
                        last_modified: Some(d.last_modified),
                        size: Some(d.body.len() as i64),
                    })
                    .collect()
            })
            .unwrap_or_default();
        drop(st);
        let (page, next_token) = names::page(entries, input.next_token.as_deref(), 1000)?;
        Ok(types::ListDashboardsOutput { dashboard_entries: Some(page), next_token })
    }

    pub(crate) fn delete_dashboards(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDashboardsInput,
    ) -> Result<types::DeleteDashboardsOutput, ServiceError> {
        for n in &input.dashboard_names {
            ctx.authorize("cloudwatch:DeleteDashboards", &dashboard_arn(ctx, n), ConditionContext::new())?;
        }
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, GLOBAL);
        // As many as possible are deleted, even when some do not exist.
        let missing = input.dashboard_names.iter().find(|n| !region.dashboards.contains_key(n.as_str())).cloned();
        for n in &input.dashboard_names {
            if let Some(d) = region.dashboards.remove(n) {
                region.tags.remove(&d.arn);
            }
        }
        if let Some(missing) = missing {
            return Err(errors::dashboard_not_found_error(format!("Dashboard {missing} does not exist")));
        }
        Ok(types::DeleteDashboardsOutput {})
    }
}

/// The Region-less account bucket dashboards live in.
pub fn global() -> &'static str {
    GLOBAL
}
