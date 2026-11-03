//! `/aws/reference/secretsmanager/<secret-id>[:version-id|:staging-label]`:
//! Parameter Store hands out Secrets Manager secrets under parameter names.
//! The composition root plugs Secrets Manager in through
//! [`SecretsManagerReferences`], which reads the secret as the caller (so
//! `secretsmanager:GetSecretValue` and the secret's policy apply).

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{ParamRef, SECRETS_PREFIX};
use crate::Ssm;

/// A secret as Parameter Store returns it.
#[derive(Debug, Clone)]
pub struct ReferencedSecret {
    pub arn: String,
    pub secret_string: String,
    pub last_changed_date: DateTime<Utc>,
    /// The secret's `DescribeSecret` output as JSON, returned as
    /// `SourceResult`.
    pub describe_secret: serde_json::Value,
}

/// Secrets Manager, as Parameter Store reaches it.
pub trait SecretsManagerReferences: Send + Sync {
    /// Read `secret_id` as the caller, at `selector` (a version id or a
    /// staging label; `AWSCURRENT` when `None`). Errors are Secrets
    /// Manager's own (`ResourceNotFoundException`, `AccessDeniedException`).
    fn get_secret(
        &self,
        ctx: &RequestContext,
        secret_id: &str,
        selector: Option<&str>,
    ) -> Result<ReferencedSecret, ServiceError>;
}

impl Ssm {
    pub(crate) fn read_secret_reference(
        &self,
        ctx: &RequestContext,
        action: &str,
        input: &str,
        decrypt: bool,
    ) -> Result<types::Parameter, ServiceError> {
        if !decrypt {
            return Err(errors::validation("WithDecryption flag must be True for retrieving a Secret Manager secret."));
        }
        let rest = &input[SECRETS_PREFIX.len()..];
        let (secret_id, selector) = match rest.split_once(':') {
            Some((id, sel)) => (id, Some(sel)),
            None => (rest, None),
        };
        let name = format!("{SECRETS_PREFIX}{secret_id}");
        ctx.authorize(&format!("ssm:{action}"), &ParamRef::own(ctx, &name).arn(), ConditionContext::new())?;
        let not_found = || {
            errors::parameter_not_found(format!(
                "An error occurred (ParameterNotFound) when referencing Secrets Manager: Secret {name} not found."
            ))
        };
        let resolver = self.secrets.read().expect("SSM secrets lock poisoned").clone();
        let resolver = resolver.ok_or_else(not_found)?;
        let secret = resolver.get_secret(ctx, secret_id, selector).map_err(|e| match &*e.code {
            "ResourceNotFoundException" => not_found(),
            _ => e,
        })?;
        Ok(types::Parameter {
            name: Some(name),
            r#type: Some("SecureString".into()),
            value: Some(secret.secret_string),
            version: 0,
            selector: selector.map(|s| format!(":{s}")),
            source_result: Some(secret.describe_secret.to_string()),
            last_modified_date: Some(secret.last_changed_date),
            arn: Some(secret.arn),
            data_type: Some("text".into()),
        })
    }
}
