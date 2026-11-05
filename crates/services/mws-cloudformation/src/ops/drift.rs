//! Drift detection: comparing resources' live properties with the ones
//! the stack last applied.

use mws_core::{RequestContext, ServiceError};
use serde_json::{Map, Value};

use super::{find, page, validation};
use crate::generated::types;
use crate::providers::Cx;
use crate::state::{DriftDetection, Resource, ResourceDrift};
use crate::CloudFormation;

/// `(path, expected, actual, difference type)` of what differs.
fn differences(path: &str, expected: &Value, actual: Option<&Value>, out: &mut Vec<(String, String, String, String)>) {
    let show = |v: &Value| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let Some(actual) = actual else {
        out.push((path.to_string(), show(expected), "null".into(), "REMOVE".into()));
        return;
    };
    // Policy documents and other JSON strings compare by content.
    if let (Value::String(a), Value::String(b)) = (expected, actual) {
        if let (Ok(x @ Value::Object(_)), Ok(y @ Value::Object(_))) =
            (serde_json::from_str::<Value>(a), serde_json::from_str::<Value>(b))
        {
            differences(path, &x, Some(&y), out);
            return;
        }
    }
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, v) in e {
                differences(&format!("{path}/{k}"), v, a.get(k), out);
            }
            for (k, v) in a {
                if !e.contains_key(k) && !v.is_null() {
                    out.push((format!("{path}/{k}"), "null".into(), show(v), "ADD".into()));
                }
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            for (i, v) in e.iter().enumerate() {
                differences(&format!("{path}/{i}"), v, a.get(i), out);
            }
            for (i, v) in a.iter().enumerate().skip(e.len()) {
                out.push((format!("{path}/{i}"), "null".into(), show(v), "ADD".into()));
            }
        }
        (e, a) => {
            if scalar(e) != scalar(a) {
                out.push((path.to_string(), show(e), show(a), "NOT_EQUAL".into()));
            }
        }
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl CloudFormation {
    async fn drift_of(
        &self,
        ctx: &RequestContext,
        stack_name: &str,
        stack_id: &str,
        tags: &[(String, String)],
        r: &Resource,
    ) -> ResourceDrift {
        let now = ctx.received_at;
        let mut d = ResourceDrift {
            logical_id: r.logical_id.clone(),
            physical_id: r.physical_id.clone(),
            resource_type: r.resource_type.clone(),
            expected: Some(Value::Object(r.properties.clone()).to_string()),
            status: "NOT_CHECKED".into(),
            timestamp: now,
            ..Default::default()
        };
        let (Some(provider), Some(physical)) =
            (self.provider_in(&ctx.caller.account_id, &ctx.region, &r.resource_type), r.physical_id.as_deref())
        else {
            return d;
        };
        let deploy = match self.deploy_context(ctx, None) {
            Ok(c) => c,
            Err(_) => return d,
        };
        let cx = Cx {
            cfn: self,
            ctx: &deploy,
            stack_name,
            stack_id,
            logical_id: &r.logical_id,
            stack_tags: tags,
            offset: deploy.received_at - chrono::Utc::now(),
        };
        match provider.read(&cx, physical, &r.properties).await {
            None => d,
            Some(Err(e)) if e.not_found => {
                d.status = "DELETED".into();
                d
            }
            Some(Err(_)) => d,
            Some(Ok(actual)) => {
                // Only properties the template set are compared.
                let mut compared = Map::new();
                for k in r.properties.keys() {
                    if let Some(v) = actual.get(k) {
                        compared.insert(k.clone(), v.clone());
                    }
                }
                let mut diffs = Vec::new();
                for (k, v) in &r.properties {
                    differences(&format!("/{k}"), v, compared.get(k).or(actual.get(k)), &mut diffs);
                }
                d.actual = Some(Value::Object(compared).to_string());
                d.status = if diffs.is_empty() { "IN_SYNC".into() } else { "MODIFIED".into() };
                d.differences = diffs;
                d
            }
        }
    }

    pub(crate) async fn detect_stack_drift_op(
        &self,
        ctx: &RequestContext,
        input: types::DetectStackDriftInput,
    ) -> Result<types::DetectStackDriftOutput, ServiceError> {
        let stack = { find(&self.state(), ctx, &input.stack_name)?.clone() };
        ctx.authorize("cloudformation:DetectStackDrift", &stack.id, Default::default())?;
        if stack.in_progress() {
            return Err(validation(format!(
                "Drift detection cannot be performed on stack [{}] while it is in {} status",
                stack.id, stack.status
            )));
        }
        let only = input.logical_resource_ids.unwrap_or_default();
        let tags: Vec<(String, String)> = stack.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect();
        let mut results = Vec::new();
        for r in stack.resources.iter().filter(|r| r.exists()) {
            if !only.is_empty() && !only.contains(&r.logical_id) {
                continue;
            }
            results.push(self.drift_of(ctx, &stack.name, &stack.id, &tags, r).await);
        }
        let drifted = results.iter().filter(|r| r.status == "MODIFIED" || r.status == "DELETED").count() as i32;
        let id = uuid::Uuid::new_v4().to_string();
        let status = if drifted > 0 { "DRIFTED" } else { "IN_SYNC" };
        let mut st = self.state();
        if let Some(s) = st.stacks.get_mut(&stack.id) {
            s.drift_status = Some(status.into());
            s.drift_checked = Some(ctx.received_at);
            for d in &results {
                if let Some(r) = s.resource_mut(&d.logical_id) {
                    r.drift_status = Some(d.status.clone());
                    r.drift_checked = Some(ctx.received_at);
                }
            }
        }
        st.drift_detections.insert(
            id.clone(),
            DriftDetection {
                id: id.clone(),
                stack_id: stack.id.clone(),
                status: "DETECTION_COMPLETE".into(),
                status_reason: None,
                stack_drift_status: Some(status.into()),
                drifted_count: drifted,
                timestamp: ctx.received_at,
                results,
            },
        );
        Ok(types::DetectStackDriftOutput { stack_drift_detection_id: id })
    }

    pub(crate) fn describe_stack_drift_detection_status_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackDriftDetectionStatusInput,
    ) -> Result<types::DescribeStackDriftDetectionStatusOutput, ServiceError> {
        let st = self.state();
        let d = st
            .drift_detections
            .get(&input.stack_drift_detection_id)
            .filter(|d| st.stacks.get(&d.stack_id).is_some_and(|s| s.account == ctx.caller.account_id))
            .ok_or_else(|| {
                validation(format!("Drift detection with id {} does not exist", input.stack_drift_detection_id))
            })?;
        ctx.authorize("cloudformation:DescribeStackDriftDetectionStatus", &d.stack_id, Default::default())?;
        Ok(types::DescribeStackDriftDetectionStatusOutput {
            stack_id: d.stack_id.clone(),
            stack_drift_detection_id: d.id.clone(),
            stack_drift_status: d.stack_drift_status.clone(),
            detection_status: d.status.clone(),
            detection_status_reason: d.status_reason.clone(),
            drifted_stack_resource_count: Some(d.drifted_count),
            timestamp: d.timestamp,
        })
    }

    pub(crate) fn describe_stack_resource_drifts_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackResourceDriftsInput,
    ) -> Result<types::DescribeStackResourceDriftsOutput, ServiceError> {
        let st = self.state();
        let s = find(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:DescribeStackResourceDrifts", &s.id, Default::default())?;
        let latest = st.drift_detections.values().filter(|d| d.stack_id == s.id).max_by_key(|d| d.timestamp);
        let filters = input.stack_resource_drift_status_filters.unwrap_or_default();
        let all: Vec<types::StackResourceDrift> = latest
            .map(|d| {
                d.results
                    .iter()
                    .filter(|r| filters.is_empty() || filters.contains(&r.status))
                    .map(|r| wire(&s.id, r))
                    .collect()
            })
            .unwrap_or_default();
        let size = input.max_results.map(|m| m.max(1) as usize).unwrap_or(100);
        let (items, next) = page(&all, input.next_token.as_deref(), size)?;
        Ok(types::DescribeStackResourceDriftsOutput { stack_resource_drifts: items, next_token: next })
    }

    pub(crate) async fn detect_stack_resource_drift_op(
        &self,
        ctx: &RequestContext,
        input: types::DetectStackResourceDriftInput,
    ) -> Result<types::DetectStackResourceDriftOutput, ServiceError> {
        let stack = { find(&self.state(), ctx, &input.stack_name)?.clone() };
        ctx.authorize("cloudformation:DetectStackResourceDrift", &stack.id, Default::default())?;
        let r = stack.resource(&input.logical_resource_id).filter(|r| r.exists()).ok_or_else(|| {
            validation(format!("Resource {} does not exist for stack {}", input.logical_resource_id, input.stack_name))
        })?;
        let tags: Vec<(String, String)> = stack.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect();
        let d = self.drift_of(ctx, &stack.name, &stack.id, &tags, r).await;
        if let Some(s) = self.state().stacks.get_mut(&stack.id) {
            if let Some(r) = s.resource_mut(&d.logical_id) {
                r.drift_status = Some(d.status.clone());
                r.drift_checked = Some(ctx.received_at);
            }
        }
        Ok(types::DetectStackResourceDriftOutput { stack_resource_drift: wire(&stack.id, &d) })
    }
}

fn wire(stack_id: &str, r: &ResourceDrift) -> types::StackResourceDrift {
    types::StackResourceDrift {
        stack_id: stack_id.to_string(),
        logical_resource_id: r.logical_id.clone(),
        physical_resource_id: r.physical_id.clone(),
        physical_resource_id_context: None,
        resource_type: r.resource_type.clone(),
        expected_properties: r.expected.clone(),
        actual_properties: r.actual.clone(),
        property_differences: Some(
            r.differences
                .iter()
                .map(|(p, e, a, t)| types::PropertyDifference {
                    property_path: p.clone(),
                    expected_value: e.clone(),
                    actual_value: a.clone(),
                    difference_type: t.clone(),
                })
                .collect(),
        ),
        stack_resource_drift_status: r.status.clone(),
        timestamp: r.timestamp,
        module_info: None,
        drift_status_reason: None,
    }
}
