//! Cross-service glue for AWS service metrics, EC2 alarm actions and the
//! EventBridge targets that run work in other services (ECS tasks, Run
//! Command).

use std::sync::Arc;

use mws_core::metrics::{MetricDatum, MetricPublisher};
use mws_core::{Caller, CallerKind, RequestContext, Service};
use mws_events::{TargetError, TargetInvocation, TargetSink};
use serde_json::{json, Map, Value};

/// Services publishing their `AWS/*` metrics into CloudWatch.
pub(crate) struct CloudWatchMetrics(pub mws_cloudwatch::CloudWatch);

impl MetricPublisher for CloudWatchMetrics {
    fn publish(&self, data: Vec<MetricDatum>) {
        for d in data {
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: d.account,
                region: d.region,
                namespace: d.namespace.to_string(),
                metric_name: d.metric_name.to_string(),
                dimensions: d.dimensions,
                unit: Some(d.unit.to_string()),
                timestamp: d.timestamp,
                values: d.values,
            });
        }
    }
}

/// A context for an AWS service acting in `account` through one of its
/// service-linked roles. The service decides what it may do, so nothing
/// is authorized against IAM.
fn service_ctx(template: &RequestContext, account: &str, region: &str, role: &str, session: &str) -> RequestContext {
    RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        region: region.to_string(),
        caller: Caller {
            account_id: account.to_string(),
            arn: format!("arn:{}:sts::{account}:assumed-role/{role}/{session}", template.partition),
            user_id: format!("AROA{}:{session}", uuid::Uuid::new_v4().simple().to_string()[..17].to_uppercase()),
            access_key_id: String::new(),
            kind: CallerKind::AssumedRole { role_name: role.to_string(), session_name: session.to_string() },
            session: None,
        },
        source_ip: None,
        authorizer: Arc::new(mws_core::AllowAll),
        ..template.clone()
    }
}

/// CloudWatch alarm actions of EC2 (`arn:aws:automate:<region>:ec2:stop`,
/// `terminate`, `reboot` and `recover`), run on the instance the alarm's
/// `InstanceId` dimension names, as CloudWatch's service-linked role.
pub(crate) struct Ec2AlarmActions(pub mws_ec2::Ec2);

impl mws_cloudwatch::AlarmActionTarget for Ec2AlarmActions {
    fn run(&self, ctx: &RequestContext, a: mws_cloudwatch::AlarmAction) -> Result<(), String> {
        if a.state != "ALARM" && a.state != "OK" && a.state != "INSUFFICIENT_DATA" {
            return Ok(());
        }
        let parts: Vec<&str> = a.action_arn.splitn(6, ':').collect();
        let (service, verb) = match parts[..] {
            [_, _, _, _, service, verb] => (service, verb),
            _ => return Err(format!("Invalid EC2 action: {}", a.action_arn)),
        };
        if service != "ec2" {
            return Err(format!("Actions of type automate:{service} are not supported"));
        }
        let Some(instance) = a.dimensions.iter().find(|(k, _)| k == "InstanceId").map(|(_, v)| v.clone()) else {
            return Err("EC2 actions need an alarm on a metric with an InstanceId dimension".into());
        };
        let (operation, input) = match verb {
            "stop" => ("StopInstances", json!({"InstanceIds": [instance]})),
            "terminate" => ("TerminateInstances", json!({"InstanceIds": [instance]})),
            "reboot" => ("RebootInstances", json!({"InstanceIds": [instance]})),
            // A recovered instance moves to healthy hardware: a reboot is
            // what an emulated instance can do.
            "recover" => ("RebootInstances", json!({"InstanceIds": [instance]})),
            other => return Err(format!("Unknown EC2 action {other}")),
        };
        let ctx = service_ctx(ctx, &a.account, &a.region, "AWSServiceRoleForCloudWatchEvents", "CloudWatchAlarm");
        let ec2 = self.0.clone();
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                if let Err(e) = ec2.invoke(ctx, operation, input).await {
                    tracing::warn!(%operation, "CloudWatch EC2 alarm action failed: {}", e.message);
                }
            });
        }
        Ok(())
    }
}

fn target_error(e: mws_core::ServiceError) -> TargetError {
    TargetError { code: e.code.to_string(), message: e.message, retryable: e.status >= 500 }
}

/// `snake_case` keys (as the generated types serialize) to the `camelCase`
/// ECS's wire format uses.
fn camel_keys(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| {
                    let mut out = String::new();
                    let mut upper = false;
                    for c in k.chars() {
                        if c == '_' {
                            upper = true;
                        } else if upper {
                            out.extend(c.to_uppercase());
                            upper = false;
                        } else {
                            out.push(c);
                        }
                    }
                    (out, camel_keys(v))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(camel_keys).collect()),
        other => other,
    }
}

/// EventBridge targets that are ECS clusters: each event runs the target's
/// task definition (`EcsParameters`) with `RunTask`, as the target's role.
/// A JSON input becomes the task's overrides, as in EventBridge.
pub(crate) struct EcsTarget(pub mws_ecs::Ecs);

#[async_trait::async_trait]
impl TargetSink for EcsTarget {
    async fn deliver(&self, inv: TargetInvocation<'_>) -> Result<(), TargetError> {
        let Some(params) = inv.definition.and_then(|d| d.ecs_parameters.as_ref()) else {
            return Err(TargetError::permanent("InvalidParameterException", "EcsParameters are required."));
        };
        let ctx = inv.role_context()?;
        let mut request = match camel_keys(serde_json::to_value(params).unwrap_or_default()) {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let count = request.remove("taskCount").unwrap_or(json!(1));
        request.insert("count".into(), count);
        if let Some(arn) = request.remove("taskDefinitionArn") {
            request.insert("taskDefinition".into(), arn);
        }
        let managed = request.remove("enableEcsManagedTags").unwrap_or(json!(false));
        request.insert("enableECSManagedTags".into(), managed);
        request.insert("cluster".into(), json!(inv.target_arn));
        let rule = inv.source_arn.rsplit('/').next().unwrap_or_default();
        request.insert("startedBy".into(), json!(format!("events-rule/{rule}").chars().take(128).collect::<String>()));
        for empty in ["capacityProviderStrategy", "placementConstraints", "placementStrategy", "tags"] {
            if request.get(empty).and_then(Value::as_array).is_some_and(Vec::is_empty) {
                request.remove(empty);
            }
        }
        if let Ok(Value::Object(input)) = serde_json::from_str::<Value>(inv.payload) {
            let overrides = ["containerOverrides", "taskRoleArn", "executionRoleArn", "cpu", "memory"];
            if input.keys().any(|k| overrides.contains(&k.as_str())) {
                request.insert("overrides".into(), Value::Object(input));
            }
        }
        let out = self.0.invoke(ctx, "RunTask", Value::Object(request)).await.map_err(target_error)?;
        match out.get("failures").and_then(Value::as_array).and_then(|f| f.first()) {
            Some(f) if out.get("tasks").and_then(Value::as_array).is_none_or(Vec::is_empty) => {
                Err(TargetError::permanent(
                    "ECSFailure",
                    f.get("reason").and_then(Value::as_str).unwrap_or("RunTask failed").to_string(),
                ))
            }
            _ => Ok(()),
        }
    }
}

/// EventBridge targets that are Systems Manager documents: Run Command
/// sends the document to the `RunCommandParameters` targets as the target's
/// role, with the event input as the document's parameters.
pub(crate) struct RunCommandTarget(pub mws_ssm::Ssm);

#[async_trait::async_trait]
impl TargetSink for RunCommandTarget {
    async fn deliver(&self, inv: TargetInvocation<'_>) -> Result<(), TargetError> {
        let Some(document) = inv.target_arn.split_once(":document/").map(|(_, d)| d) else {
            return Err(TargetError::permanent(
                "InvalidTarget",
                "Only Systems Manager documents (Run Command) are supported as ssm targets.",
            ));
        };
        let ctx = inv.role_context()?;
        let targets: Vec<Value> = inv
            .definition
            .and_then(|d| d.run_command_parameters.as_ref())
            .map(|p| p.run_command_targets.iter().map(|t| json!({"Key": t.key, "Values": t.values})).collect())
            .unwrap_or_default();
        let mut request = json!({ "DocumentName": document, "Targets": targets });
        if let Ok(Value::Object(params)) = serde_json::from_str::<Value>(inv.payload) {
            let params: Map<String, Value> = params
                .into_iter()
                .map(|(k, v)| match v {
                    Value::Array(_) => (k, v),
                    Value::String(s) => (k, json!([s])),
                    other => (k, json!([other.to_string()])),
                })
                .collect();
            request["Parameters"] = Value::Object(params);
        }
        self.0.invoke(ctx, "SendCommand", request).await.map(|_| ()).map_err(target_error)
    }
}

/// Systems Manager resource data syncs writing into S3 buckets as
/// `ssm.amazonaws.com` (the bucket policy must allow it).
pub(crate) struct SsmDataSync(pub mws_s3::S3);

impl mws_ssm::DataSyncDestination for SsmDataSync {
    fn check(&self, partition: &str, account: &str, bucket: &str, key: &str, source_arn: &str) -> Result<(), String> {
        let put = mws_s3::ServicePutObject {
            bucket,
            key,
            body: Vec::new(),
            content_type: "application/json",
            service_principal: "ssm.amazonaws.com",
            source_account: account,
            source_arn,
            acl: Some("bucket-owner-full-control"),
            partition,
        };
        self.0.check_service_access(&put, &["s3:PutObject", "s3:GetBucketAcl"]).map_err(|e| e.to_string())
    }

    fn put(
        &self,
        partition: &str,
        account: &str,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        source_arn: &str,
        kms_key_arn: Option<&str>,
    ) -> Result<(), String> {
        let put = mws_s3::ServicePutObject {
            bucket,
            key,
            body,
            content_type: "application/json",
            service_principal: "ssm.amazonaws.com",
            source_account: account,
            source_arn,
            acl: Some("bucket-owner-full-control"),
            partition,
        };
        match kms_key_arn.filter(|k| !k.is_empty()) {
            Some(k) => self.0.put_object_as_service_kms(put, k).map(|_| ()),
            None => self.0.put_object_as_service(put).map(|_| ()).map_err(|e| e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::camel_keys;
    use serde_json::json;

    #[test]
    fn camel_case_keys() {
        let v = camel_keys(
            json!({"network_configuration": {"awsvpc_configuration": {"assign_public_ip": "ENABLED", "x": null}}, "type": "a"}),
        );
        assert_eq!(
            v,
            json!({"networkConfiguration": {"awsvpcConfiguration": {"assignPublicIp": "ENABLED"}}, "type": "a"})
        );
    }
}
