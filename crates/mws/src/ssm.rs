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
