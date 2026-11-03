//! Resource policies on secrets.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::ops::{check_live, check_primary};
use crate::SecretsManager;

/// Condition keys that pin a statement to known principals, so a `*`
/// principal with one of them is not public.
const LIMITING_KEYS: &[&str] = &[
    "aws:principalaccount",
    "aws:principalarn",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceowner",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:userid",
    "aws:sourceip",
    "aws:calledvia",
];

fn grants_everyone(principal: &Value) -> bool {
    match principal {
        Value::String(s) => s == "*",
        Value::Object(m) => m.get("AWS").is_some_and(|v| match v {
            Value::String(s) => s == "*",
            Value::Array(a) => a.iter().any(|x| x.as_str() == Some("*")),
            _ => false,
        }),
        _ => false,
    }
}

fn limited(condition: Option<&Value>) -> bool {
    let Some(Value::Object(ops)) = condition else { return false };
    ops.values().any(|keys| {
        keys.as_object().is_some_and(|k| k.keys().any(|key| LIMITING_KEYS.contains(&key.to_ascii_lowercase().as_str())))
    })
}

/// Whether a (syntactically valid) policy grants access to anyone.
pub fn is_public(document: &str) -> bool {
    let Ok(root) = serde_json::from_str::<Value>(document) else { return false };
    let statements = match root.get("Statement") {
        Some(Value::Array(a)) => a.clone(),
        Some(s @ Value::Object(_)) => vec![s.clone()],
        _ => return false,
    };
    statements.iter().any(|s| {
        s.get("Effect").and_then(Value::as_str) == Some("Allow")
            && s.get("Principal").is_some_and(grants_everyone)
            && !limited(s.get("Condition"))
    })
}

fn parse(document: &str) -> Result<(), ServiceError> {
    Policy::parse(document, PolicyKind::Resource).map(|_| ()).map_err(|e| {
        errors::malformed_policy_document(format!("This resource policy contains a syntax error: {}", e.0))
    })
}

impl SecretsManager {
    pub(crate) fn get_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePolicyRequest,
    ) -> Result<types::GetResourcePolicyResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:GetResourcePolicy", ConditionContext::new())?;
        Ok(types::GetResourcePolicyResponse { arn: Some(s.arn), name: Some(s.name), resource_policy: s.policy })
    }

    pub(crate) fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        let mut c = ConditionContext::new();
        if let Some(b) = input.block_public_policy {
            c.insert("secretsmanager:BlockPublicPolicy".into(), vec![b.to_string()]);
        }
        let s = self.find(ctx, &input.secret_id, "secretsmanager:PutResourcePolicy", c)?;
        check_live(&s)?;
        check_primary(&s)?;
        parse(&input.resource_policy)?;
        if input.block_public_policy.unwrap_or(false) && is_public(&input.resource_policy) {
            return Err(errors::public_policy(
                "This resource policy will grant public access to the secret. Use BlockPublicPolicy=false to override.",
            ));
        }
        let now = ctx.received_at;
        self.update(&s.arn, |st| {
            st.policy = Some(input.resource_policy.clone());
            st.last_changed = now;
            Ok(())
        })?;
        self.sync_replicas(ctx, &s.arn, &[]);
        Ok(types::PutResourcePolicyResponse { arn: Some(s.arn), name: Some(s.name) })
    }

    pub(crate) fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyRequest,
    ) -> Result<types::DeleteResourcePolicyResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:DeleteResourcePolicy", ConditionContext::new())?;
        check_live(&s)?;
        check_primary(&s)?;
        let now = ctx.received_at;
        self.update(&s.arn, |st| {
            st.policy = None;
            st.last_changed = now;
            Ok(())
        })?;
        self.sync_replicas(ctx, &s.arn, &[]);
        Ok(types::DeleteResourcePolicyResponse { arn: Some(s.arn), name: Some(s.name) })
    }

    pub(crate) fn validate_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::ValidateResourcePolicyRequest,
    ) -> Result<types::ValidateResourcePolicyResponse, ServiceError> {
        match &input.secret_id {
            Some(id) => {
                self.find(ctx, id, "secretsmanager:ValidateResourcePolicy", ConditionContext::new())?;
            }
            None => ctx.authorize("secretsmanager:ValidateResourcePolicy", "*", ConditionContext::new())?,
        }
        parse(&input.resource_policy)?;
        let mut validation_errors = Vec::new();
        if is_public(&input.resource_policy) {
            validation_errors.push(types::ValidationErrorsEntry {
                check_name: Some("BROAD_ACCESS_CHECKING".into()),
                error_message: Some(
                    "This resource policy grants access to every principal (\"*\") without a condition that limits it to an account or organization.".into(),
                ),
            });
        }
        Ok(types::ValidateResourcePolicyResponse {
            policy_validation_passed: validation_errors.is_empty(),
            validation_errors: Some(validation_errors),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::is_public;

    #[test]
    fn public_statements() {
        let open = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}"#;
        assert!(is_public(open));
        let pinned = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"secretsmanager:GetSecretValue","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalAccount":"111122223333"}}}]}"#;
        assert!(!is_public(pinned));
        let account = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"*","Resource":"*"}]}"#;
        assert!(!is_public(account));
    }
}
