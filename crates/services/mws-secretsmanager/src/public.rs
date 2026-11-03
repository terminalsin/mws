//! How other services read secrets for their callers: Parameter Store's
//! `/aws/reference/secretsmanager/` parameters.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Map, Value};

use crate::seal::Plain;
use crate::SecretsManager;

/// A secret value read for another service.
#[derive(Debug, Clone)]
pub struct SecretReference {
    pub arn: String,
    /// The string value; binary values come base64-encoded.
    pub secret_string: String,
    pub last_changed_date: DateTime<Utc>,
    /// `DescribeSecret`'s output as it is on the wire.
    pub describe_secret: Value,
}

fn epoch(t: DateTime<Utc>) -> Value {
    json!(t.timestamp_millis() as f64 / 1000.0)
}

impl SecretsManager {
    /// Read `secret_id` as the caller (`secretsmanager:GetSecretValue`,
    /// the secret's resource policy and its KMS key apply). `selector` is a
    /// version id or a staging label; `AWSCURRENT` when `None`.
    pub fn read_for_reference(
        &self,
        ctx: &RequestContext,
        secret_id: &str,
        selector: Option<&str>,
    ) -> Result<SecretReference, ServiceError> {
        self.tick(ctx);
        let s = self.find(ctx, secret_id, "secretsmanager:GetSecretValue", ConditionContext::new())?;
        let (version_id, stage) = match selector {
            Some(sel) if s.version(sel).is_some() => (Some(sel), None),
            Some(sel) => (None, Some(sel)),
            None => (None, None),
        };
        let (_, plain) = self.read_value(ctx, &s, version_id, stage)?;
        let secret_string = match plain {
            Plain::String(v) => v,
            Plain::Binary(b) => base64::engine::general_purpose::STANDARD.encode(b),
        };
        let d = self.describe(&s);
        let mut m = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                m.insert(k.to_string(), v);
            }
        };
        put("ARN", d.arn.map(Value::from));
        put("Name", d.name.map(Value::from));
        put("Description", d.description.map(Value::from));
        put("KmsKeyId", d.kms_key_id.map(Value::from));
        put("RotationEnabled", d.rotation_enabled.map(Value::from));
        put("RotationLambdaARN", d.rotation_lambda_arn.map(Value::from));
        put("LastRotatedDate", d.last_rotated_date.map(epoch));
        put("LastChangedDate", d.last_changed_date.map(epoch));
        put("LastAccessedDate", d.last_accessed_date.map(epoch));
        put("NextRotationDate", d.next_rotation_date.map(epoch));
        put("CreatedDate", d.created_date.map(epoch));
        put("PrimaryRegion", d.primary_region.map(Value::from));
        put(
            "Tags",
            d.tags.map(|t| t.into_iter().map(|t| json!({"Key": t.key, "Value": t.value})).collect::<Vec<_>>().into()),
        );
        put("VersionIdsToStages", d.version_ids_to_stages.map(|v| json!(v)));
        Ok(SecretReference {
            arn: s.arn,
            secret_string,
            last_changed_date: s.last_changed,
            describe_secret: Value::Object(m),
        })
    }
}
