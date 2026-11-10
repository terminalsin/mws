//! What Systems Manager reaches in other services: EC2 instances with an
//! instance profile are its managed nodes (Run Command runs in them),
//! maintenance window Lambda tasks invoke functions as the task's role, and
//! window executions report state changes to EventBridge.

use async_trait::async_trait;
use mws_core::RequestContext;
use mws_events::ServiceEvent;
use mws_ssm::{ManagedNode, ShellOutput};

/// SSM's managed nodes: EC2 instances launched with an instance profile.
pub(crate) struct SsmNodes(pub mws_ec2::Ec2);

/// The platform name and version an AMI name suggests.
fn platform(image_name: Option<&str>, windows: bool) -> (String, String, String) {
    let name = image_name.unwrap_or_default().to_ascii_lowercase();
    if windows || name.contains("windows") {
        let version = if name.contains("2022") { "10.0.20348" } else { "10.0.17763" };
        return ("Windows".into(), "Microsoft Windows Server".into(), version.into());
    }
    // The first run of digits and dots after `prefix`, e.g. `24.04`.
    let version = |prefix: &str| {
        let start = name.find(prefix)? + prefix.len();
        let rest = &name[start..];
        let from = rest.find(|c: char| c.is_ascii_digit())?;
        let v: String = rest[from..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        Some(v.trim_end_matches('.').to_string()).filter(|v| !v.is_empty())
    };
    let (n, v) = if name.starts_with("al2023") {
        ("Amazon Linux", "2023".to_string())
    } else if name.starts_with("amzn2") {
        ("Amazon Linux", "2".to_string())
    } else if name.contains("ubuntu") {
        ("Ubuntu", version("ubuntu-").unwrap_or_else(|| "24.04".into()))
    } else if name.contains("debian") {
        ("Debian GNU/Linux", version("debian-").unwrap_or_else(|| "12".into()))
    } else if name.contains("alpine") {
        ("Alpine Linux", version("alpine").unwrap_or_else(|| "3.20".into()))
    } else {
        ("Amazon Linux", "2023".to_string())
    };
    ("Linux".into(), n.into(), v)
}

#[async_trait]
impl mws_ssm::ManagedNodes for SsmNodes {
    fn nodes(&self, account: &str, region: &str) -> Vec<ManagedNode> {
        self.0
            .instances(account, region)
            .into_iter()
            .filter_map(|i| {
                let profile = i.iam_instance_profile_arn.clone()?;
                let ping = match i.state.as_str() {
                    "running" => "Online",
                    "stopping" | "stopped" | "shutting-down" => "ConnectionLost",
                    _ => return None,
                };
                let role = self
                    .0
                    .instance_profile(account, &profile)
                    .and_then(|p| p.role_arn)
                    .and_then(|r| r.rsplit('/').next().map(str::to_string))
                    .unwrap_or_default();
                let windows = i.platform_details.as_deref().is_some_and(|p| p.starts_with("Windows"));
                let (platform_type, platform_name, platform_version) = platform(i.image_name.as_deref(), windows);
                let launched = i.launch_time.unwrap_or_default();
                Some(ManagedNode {
                    instance_id: i.instance_id,
                    ping_status: ping.into(),
                    last_ping: launched,
                    platform_type,
                    platform_name,
                    platform_version,
                    iam_role: role,
                    registration_date: launched,
                    ip_address: i.private_ip,
                    computer_name: i.private_dns_name,
                    tags: i.tags,
                })
            })
            .collect()
    }

    async fn run_shell(
        &self,
        account: &str,
        region: &str,
        instance_id: &str,
        script: &str,
    ) -> Result<Option<ShellOutput>, String> {
        let out = self.0.run_command_on_instance(account, region, instance_id, script).await?;
        Ok(out.map(|o| ShellOutput { exit_code: o.exit_code, stdout: o.stdout, stderr: o.stderr }))
    }
}

/// Maintenance window Lambda tasks, run as the task's service role.
pub(crate) struct SsmTasks {
    pub lambda: mws_lambda::Lambda,
    pub sts: mws_sts::Sts,
}

#[async_trait]
impl mws_ssm::TaskInvoker for SsmTasks {
    async fn invoke_lambda(
        &self,
        ctx: &RequestContext,
        role: Option<&str>,
        window_arn: &str,
        function: &str,
        qualifier: Option<&str>,
        payload: Vec<u8>,
    ) -> Result<String, String> {
        let Some(role) = role else {
            return Err(
                "MWS runs Lambda tasks only with a ServiceRoleArn; the service-linked role is not emulated.".into()
            );
        };
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: role,
                service_principal: "ssm.amazonaws.com",
                session_name: "MaintenanceWindowTask",
                duration_seconds: 3600,
                source_account: Some(&ctx.caller.account_id),
                source_arn: Some(window_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("Systems Manager could not assume {role}: {e:?}"))?;
        let resolved = self
            .sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .map_err(|e| format!("{e:?}"))?
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        let rctx = RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() };
        let request = mws_lambda::generated::types::InvocationRequest {
            function_name: function.to_string(),
            qualifier: qualifier.map(str::to_string),
            payload: Some(payload),
            ..Default::default()
        };
        let out = self.lambda.invoke(&rctx, request).await.map_err(|e| format!("{}: {}", e.code, e.message))?;
        if let Some(err) = out.function_error {
            return Err(format!("The function returned an error: {err}"));
        }
        Ok(rctx.request_id.clone())
    }
}

/// Runs due maintenance windows every second and reports their
/// "Maintenance Window Execution State-change Notification" events.
pub(crate) struct SsmWindowEvents {
    pub ssm: mws_ssm::Ssm,
    pub partition: String,
}

impl mws_events::ClockSource for SsmWindowEvents {
    fn due_events(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<ServiceEvent> {
        let ts = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        self.ssm
            .take_window_events(now)
            .into_iter()
            .map(|e| {
                let arn =
                    format!("arn:{}:ssm:{}:{}:maintenancewindow/{}", self.partition, e.region, e.account, e.window_id);
                ServiceEvent {
                    resources: vec![arn],
                    partition: self.partition.clone(),
                    account: e.account,
                    region: e.region,
                    source: "aws.ssm".into(),
                    detail_type: "Maintenance Window Execution State-change Notification".into(),
                    detail: serde_json::json!({
                        "start-time": ts(e.start),
                        "end-time": e.end.map(ts).unwrap_or_default(),
                        "window-id": e.window_id,
                        "window-execution-id": e.window_execution_id,
                        "status": e.status,
                    }),
                    time: e.time,
                }
            })
            .collect()
    }
}

/// How Automation runbooks reach the rest of MWS: assume roles as
/// `ssm.amazonaws.com` (or chain them through STS), hand scripts
/// credentials, and call any service's API by the name AWS SDKs give it.
pub(crate) struct SsmAutomation {
    pub sts: mws_sts::Sts,
    pub services: std::collections::HashMap<String, std::sync::Arc<dyn mws_core::Service>>,
}

impl SsmAutomation {
    pub fn new(sts: mws_sts::Sts, services: &[std::sync::Arc<dyn mws_core::Service>]) -> Self {
        let mut map = std::collections::HashMap::new();
        for s in services {
            map.entry(s.signing_name().to_string()).or_insert_with(|| s.clone());
            map.insert(s.name().to_string(), s.clone());
        }
        Self { sts, services: map }
    }

    /// The service AWS SDKs call `name`.
    fn service(&self, name: &str) -> Option<std::sync::Arc<dyn mws_core::Service>> {
        let mapped = match name {
            "cloudwatch" => "monitoring",
            "efs" => "elasticfilesystem",
            "service-quotas" => "servicequotas",
            "meteringmarketplace" => "marketplace-metering",
            "sso-admin" => "sso",
            "elasticloadbalancingv2" => "elbv2",
            "elasticloadbalancing" => "elb",
            "ses" | "email" => "ses",
            other => other,
        };
        self.services.get(mapped).cloned()
    }

    fn resolve(&self, ctx: &RequestContext, key: &str, token: &str) -> Result<RequestContext, String> {
        let caller = self
            .sts
            .credential_store()
            .resolve(key, Some(token), ctx.received_at)
            .map_err(|e| format!("{e:?}"))?
            .map(|r| r.caller)
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        Ok(RequestContext { caller, source_ip: None, ..ctx.clone() })
    }
}

#[async_trait]
impl mws_ssm::AutomationRuntime for SsmAutomation {
    fn assume_role(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        source_arn: &str,
    ) -> Result<(RequestContext, mws_ssm::ScriptCredentials), String> {
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "ssm.amazonaws.com",
                session_name: "Automation",
                duration_seconds: 3600,
                source_account: Some(&ctx.caller.account_id),
                source_arn: Some(source_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("Systems Manager could not assume {role_arn}: {e:?}"))?;
        let rctx = self.resolve(ctx, &creds.access_key_id, &creds.session_token)?;
        Ok((
            rctx,
            mws_ssm::ScriptCredentials {
                access_key_id: creds.access_key_id,
                secret_access_key: creds.secret_access_key,
                session_token: Some(creds.session_token),
            },
        ))
    }

    async fn chain_role(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        session_name: &str,
    ) -> Result<RequestContext, String> {
        let sts = self.service("sts").ok_or("STS is not available")?;
        let session: String =
            session_name.chars().filter(|c| c.is_ascii_alphanumeric() || "=,.@-".contains(*c)).take(64).collect();
        let out = sts
            .invoke(ctx.clone(), "AssumeRole", serde_json::json!({ "RoleArn": role_arn, "RoleSessionName": session }))
            .await
            .map_err(|e| format!("{}: {}", e.code, e.message))?;
        let c = &out["Credentials"];
        let key = c["AccessKeyId"].as_str().unwrap_or_default();
        let token = c["SessionToken"].as_str().unwrap_or_default();
        self.resolve(ctx, key, token)
    }

    fn credentials_of(&self, ctx: &RequestContext) -> Option<mws_ssm::ScriptCredentials> {
        if ctx.caller.session.is_some() {
            return None;
        }
        let resolved =
            self.sts.credential_store().resolve(&ctx.caller.access_key_id, None, ctx.received_at).ok().flatten()?;
        Some(mws_ssm::ScriptCredentials {
            access_key_id: ctx.caller.access_key_id.clone(),
            secret_access_key: resolved.secret_access_key,
            session_token: None,
        })
    }

    async fn call(
        &self,
        ctx: &RequestContext,
        service: &str,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, mws_core::ServiceError> {
        let Some(svc) = self.service(service) else {
            return Err(mws_core::ServiceError::client(
                "InvalidRequest",
                400,
                format!("MWS does not emulate the service {service}."),
            ));
        };
        svc.invoke(ctx.clone(), operation, input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_from_ami_names() {
        assert_eq!(platform(Some("al2023-ami-2023.6.20250101.0-kernel-6.1-x86_64"), false).2, "2023");
        assert_eq!(platform(Some("ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server"), false).1, "Ubuntu");
        assert_eq!(platform(Some("debian-12-amd64"), false).2, "12");
        assert_eq!(platform(None, true).0, "Windows");
    }
}
