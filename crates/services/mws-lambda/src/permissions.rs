//! Resource-based policies on functions (`AddPermission`) and layer
//! versions (`AddLayerVersionPermission`).

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Value};

use crate::functions::revision_id;
use crate::generated::{errors, types};
use crate::names;
use crate::Lambda;

/// The `Principal` element for a principal as `AddPermission` takes it:
/// an account id, an ARN, a service, or `*`.
fn principal(p: &str, partition: &str) -> Value {
    if p == "*" {
        Value::String("*".into())
    } else if p.len() == 12 && p.bytes().all(|b| b.is_ascii_digit()) {
        json!({ "AWS": format!("arn:{partition}:iam::{p}:root") })
    } else if p.starts_with("arn:") {
        json!({ "AWS": p })
    } else {
        json!({ "Service": p })
    }
}

fn statement_conflict(sid: &str) -> ServiceError {
    errors::resource_conflict(format!(
        "The statement id ({sid}) provided already exists. Please provide a new statement id, or remove the existing statement."
    ))
}

fn no_policy() -> ServiceError {
    errors::resource_not_found("The resource you requested does not exist.")
}

impl Lambda {
    pub async fn add_permission(
        &self,
        ctx: &RequestContext,
        input: types::AddPermissionRequest,
    ) -> Result<types::AddPermissionResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:AddPermission", &f, ConditionContext::new())?;
        let action = input.action.clone();
        if !(action == "lambda:*" || action.starts_with("lambda:")) {
            return Err(errors::invalid_parameter_value(format!(
                "1 validation error detected: Value '{action}' at 'action' failed to satisfy constraint: Member must satisfy regular expression pattern: (lambda:[*]|lambda:[a-zA-Z]+|[*])"
            )));
        }
        let mut statement = json!({
            "Sid": input.statement_id,
            "Effect": "Allow",
            "Principal": principal(&input.principal, &ctx.partition),
            "Action": action,
            "Resource": f.qualified_arn(),
        });
        let mut conditions = serde_json::Map::new();
        let mut equals = serde_json::Map::new();
        if let Some(a) = &input.source_account {
            equals.insert("AWS:SourceAccount".into(), Value::String(a.clone()));
        }
        if let Some(t) = &input.event_source_token {
            equals.insert("lambda:EventSourceToken".into(), Value::String(t.clone()));
        }
        if let Some(t) = &input.function_url_auth_type {
            equals.insert("lambda:FunctionUrlAuthType".into(), Value::String(t.clone()));
        }
        if let Some(o) = &input.principal_org_id {
            equals.insert("aws:PrincipalOrgID".into(), Value::String(o.clone()));
        }
        if !equals.is_empty() {
            conditions.insert("StringEquals".into(), Value::Object(equals));
        }
        if let Some(arn) = &input.source_arn {
            conditions.insert("ArnLike".into(), json!({ "AWS:SourceArn": arn }));
        }
        if input.invoked_via_function_url == Some(true) {
            conditions.insert("Bool".into(), json!({ "lambda:InvokedViaFunctionUrl": "true" }));
        }
        if !conditions.is_empty() {
            statement["Condition"] = Value::Object(conditions);
        }
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        if let Some(q) = &f.qualifier {
            if !func.has_qualifier(q) {
                return Err(f.not_found());
            }
        }
        let key = f.qualifier.clone().unwrap_or_default();
        crate::functions::check_revision(
            func.policy_revisions.get(&key).map(String::as_str),
            input.revision_id.as_deref(),
        )?;
        let statements = func.policies.entry(key.clone()).or_default();
        if statements.iter().any(|s| s["Sid"] == input.statement_id.as_str()) {
            return Err(statement_conflict(&input.statement_id));
        }
        statements.push(statement.clone());
        func.policy_revisions.insert(key, revision_id());
        Ok(types::AddPermissionResponse { statement: Some(statement.to_string()) })
    }

    pub async fn remove_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemovePermissionRequest,
    ) -> Result<(), ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:RemovePermission", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        let key = f.qualifier.clone().unwrap_or_default();
        crate::functions::check_revision(
            func.policy_revisions.get(&key).map(String::as_str),
            input.revision_id.as_deref(),
        )?;
        let Some(statements) = func.policies.get_mut(&key) else { return Err(no_policy()) };
        let before = statements.len();
        statements.retain(|s| s["Sid"] != input.statement_id.as_str());
        if statements.len() == before {
            return Err(errors::resource_not_found(format!(
                "Statement {} is not found in resource policy.",
                input.statement_id
            )));
        }
        func.policy_revisions.insert(key, revision_id());
        Ok(())
    }

    pub async fn get_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetPolicyRequest,
    ) -> Result<types::GetPolicyResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:GetPolicy", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        let policy = Self::policy_document(func, f.qualifier.as_deref()).ok_or_else(no_policy)?;
        Ok(types::GetPolicyResponse {
            policy: Some(policy),
            revision_id: func.policy_revisions.get(f.qualifier.as_deref().unwrap_or("")).cloned(),
        })
    }

    pub async fn add_layer_version_permission(
        &self,
        ctx: &RequestContext,
        input: types::AddLayerVersionPermissionRequest,
    ) -> Result<types::AddLayerVersionPermissionResponse, ServiceError> {
        let (layer_arn, version_arn) = self.layer_arns(ctx, &input.layer_name, input.version_number);
        ctx.authorize("lambda:AddLayerVersionPermission", &version_arn, ConditionContext::new())?;
        if input.action != "lambda:GetLayerVersion" {
            return Err(errors::invalid_parameter_value(format!(
                "1 validation error detected: Value '{}' at 'action' failed to satisfy constraint: Member must satisfy regular expression pattern: lambda:GetLayerVersion",
                input.action
            )));
        }
        let mut statement = json!({
            "Sid": input.statement_id,
            "Effect": "Allow",
            "Principal": if input.principal == "*" { Value::String("*".into()) } else { principal(&input.principal, &ctx.partition) },
            "Action": input.action,
            "Resource": version_arn,
        });
        if let Some(org) = &input.organization_id {
            statement["Condition"] = json!({ "StringEquals": { "aws:PrincipalOrgID": org } });
        }
        let mut st = self.write();
        let v = st
            .layers
            .get_mut(&layer_arn)
            .and_then(|l| l.versions.get_mut(&input.version_number))
            .ok_or_else(Self::layer_not_found)?;
        crate::functions::check_revision(
            Some(&v.policy_revision).filter(|r| !r.is_empty()).map(String::as_str),
            input.revision_id.as_deref(),
        )?;
        if v.policy.iter().any(|s| s["Sid"] == input.statement_id.as_str()) {
            return Err(statement_conflict(&input.statement_id));
        }
        v.policy.push(statement.clone());
        v.policy_revision = revision_id();
        Ok(types::AddLayerVersionPermissionResponse {
            statement: Some(statement.to_string()),
            revision_id: Some(v.policy_revision.clone()),
        })
    }

    pub async fn remove_layer_version_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemoveLayerVersionPermissionRequest,
    ) -> Result<(), ServiceError> {
        let (layer_arn, version_arn) = self.layer_arns(ctx, &input.layer_name, input.version_number);
        ctx.authorize("lambda:RemoveLayerVersionPermission", &version_arn, ConditionContext::new())?;
        let mut st = self.write();
        let v = st
            .layers
            .get_mut(&layer_arn)
            .and_then(|l| l.versions.get_mut(&input.version_number))
            .ok_or_else(Self::layer_not_found)?;
        crate::functions::check_revision(Some(v.policy_revision.as_str()), input.revision_id.as_deref())?;
        let before = v.policy.len();
        v.policy.retain(|s| s["Sid"] != input.statement_id.as_str());
        if v.policy.len() == before {
            return Err(errors::resource_not_found(format!(
                "Statement {} is not found in resource policy.",
                input.statement_id
            )));
        }
        v.policy_revision = revision_id();
        Ok(())
    }

    pub async fn get_layer_version_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetLayerVersionPolicyRequest,
    ) -> Result<types::GetLayerVersionPolicyResponse, ServiceError> {
        let (layer_arn, version_arn) = self.layer_arns(ctx, &input.layer_name, input.version_number);
        ctx.authorize("lambda:GetLayerVersionPolicy", &version_arn, ConditionContext::new())?;
        let st = self.read();
        let v = st
            .layers
            .get(&layer_arn)
            .and_then(|l| l.versions.get(&input.version_number))
            .ok_or_else(Self::layer_not_found)?;
        if v.policy.is_empty() {
            return Err(no_policy());
        }
        Ok(types::GetLayerVersionPolicyResponse {
            policy: Some(json!({"Version": "2012-10-17", "Id": "default", "Statement": v.policy}).to_string()),
            revision_id: Some(v.policy_revision.clone()),
        })
    }
}
