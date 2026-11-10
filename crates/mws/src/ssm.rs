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

    async fn open_session(
        &self,
        account: &str,
        region: &str,
        instance_id: &str,
        kind: &mws_ssm::SessionKind,
    ) -> Result<Option<mws_ssm::SessionIo>, String> {
        let script = session_script(kind);
        let stream = self.0.stream_on_instance(account, region, instance_id, &script).await?;
        Ok(stream.map(|s| mws_ssm::SessionIo { reader: s.output, writer: s.input }))
    }
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// What the SSM Agent runs for a session: shells and commands as
/// `ssm-user` (created with sudo rights, as the agent does) under a
/// terminal, and port sessions as a relay to the port.
fn session_script(kind: &mws_ssm::SessionKind) -> String {
    match kind {
        mws_ssm::SessionKind::Shell { command } => {
            let run = match command {
                Some(c) => sh_quote(c),
                None => "\"$S -l\"".into(),
            };
            format!(
                r#"S=sh; command -v bash >/dev/null 2>&1 && S=bash
export TERM=xterm-256color
if ! id ssm-user >/dev/null 2>&1; then
  (useradd -m -s /bin/$S ssm-user || adduser -D -s /bin/$S ssm-user) >/dev/null 2>&1
  [ -d /etc/sudoers.d ] && echo 'ssm-user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ssm-agent-users 2>/dev/null
fi
export MWS_SESSION_COMMAND={run}
CMD='eval "$MWS_SESSION_COMMAND"'
if id ssm-user >/dev/null 2>&1 && command -v su >/dev/null 2>&1; then
  CMD="su -s /bin/$S ssm-user -c 'cd ~; eval \"\$MWS_SESSION_COMMAND\"'"
fi
if command -v script >/dev/null 2>&1; then exec script -qfc "$CMD" /dev/null; else exec $S -ic "$CMD"; fi"#
            )
        }
        mws_ssm::SessionKind::Port { host, port } => {
            let host = sh_quote(host.as_deref().unwrap_or("127.0.0.1"));
            format!(
                r#"H={host}; P={port}
if command -v socat >/dev/null 2>&1; then exec socat - "TCP:$H:$P"
elif command -v nc >/dev/null 2>&1; then exec nc "$H" "$P"
elif command -v python3 >/dev/null 2>&1; then exec python3 -c 'import socket,sys,threading
s=socket.create_connection((sys.argv[1],int(sys.argv[2])))
def up():
    while True:
        d=sys.stdin.buffer.read1(65536)
        if not d: break
        s.sendall(d)
    s.shutdown(socket.SHUT_WR)
threading.Thread(target=up,daemon=True).start()
while True:
    d=s.recv(65536)
    if not d: break
    sys.stdout.buffer.write(d); sys.stdout.buffer.flush()' "$H" "$P"
else exec bash -c 'exec 3<>"/dev/tcp/$0/$1"; cat <&3 & cat >&3' "$H" "$P"; fi"#
            )
        }
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

/// Run Command, Automation, State Manager, compliance and change calendar
/// events, drained from SSM every second onto the default bus.
pub(crate) struct SsmEvents(pub mws_ssm::Ssm);

impl mws_events::ClockSource for SsmEvents {
    fn due_events(&self, _now: chrono::DateTime<chrono::Utc>) -> Vec<ServiceEvent> {
        self.0
            .take_events()
            .into_iter()
            .map(|e| ServiceEvent {
                partition: e.partition,
                account: e.account,
                region: e.region,
                source: "aws.ssm".into(),
                detail_type: e.detail_type,
                resources: e.resources,
                detail: e.detail,
                time: e.time,
            })
            .collect()
    }
}

/// Where the SSM Agent writes command output (S3, CloudWatch Logs) as the
/// node's instance profile role, and where Systems Manager publishes
/// command notifications (SNS) as the command's service role.
pub(crate) struct SsmOutputs {
    pub ec2: mws_ec2::Ec2,
    pub sts: mws_sts::Sts,
    pub s3: mws_s3::S3,
    pub logs: mws_logs::Logs,
    pub sns: mws_sns::Sns,
}

impl SsmOutputs {
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

    /// A request context for the node's instance profile role, as the
    /// agent gets it from the instance metadata service.
    fn node_ctx(&self, node: mws_ssm::NodeRef<'_>) -> Result<RequestContext, String> {
        let instance = self
            .ec2
            .instances(node.account, node.region)
            .into_iter()
            .find(|i| i.instance_id == node.instance_id)
            .ok_or_else(|| format!("instance {} not found", node.instance_id))?;
        let profile = instance.iam_instance_profile_arn.ok_or("the instance has no instance profile")?;
        let role = self
            .ec2
            .instance_profile(node.account, &profile)
            .and_then(|p| p.role_arn)
            .ok_or("the instance profile has no role")?;
        let instance_arn =
            format!("arn:{}:ec2:{}:{}:instance/{}", node.ctx.partition, node.region, node.account, node.instance_id);
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: &role,
                service_principal: "ec2.amazonaws.com",
                session_name: node.instance_id,
                duration_seconds: 3600,
                source_account: Some(node.account),
                source_arn: Some(&instance_arn),
                now: node.ctx.received_at,
            })
            .map_err(|e| format!("could not assume {role}: {e:?}"))?;
        let ctx = RequestContext { region: node.region.to_string(), ..node.ctx.clone() };
        self.resolve(&ctx, &creds.access_key_id, &creds.session_token)
    }
}

#[async_trait]
impl mws_ssm::CommandOutputs for SsmOutputs {
    async fn put_object(
        &self,
        node: mws_ssm::NodeRef<'_>,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
    ) -> Result<(), String> {
        let ctx = self.node_ctx(node)?;
        let request = mws_s3::generated::types::PutObjectRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_length: Some(body.len() as i64),
            content_type: Some("text/plain".into()),
            body,
            ..Default::default()
        };
        self.s3.put_object_as_caller(&ctx, request).map(|_| ()).map_err(|e| format!("{}: {}", e.code, e.message))
    }

    async fn get_object(&self, node: mws_ssm::NodeRef<'_>, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        let ctx = self.node_ctx(node)?;
        let request = mws_s3::generated::types::GetObjectRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            ..Default::default()
        };
        self.s3.get_object_as_caller(&ctx, request).map(|o| o.body).map_err(|e| format!("{}: {}", e.code, e.message))
    }

    async fn put_log_events(
        &self,
        node: mws_ssm::NodeRef<'_>,
        group: &str,
        stream: &str,
        events: Vec<(i64, String)>,
    ) -> Result<(), String> {
        let ctx = self.node_ctx(node)?;
        let events =
            events.into_iter().map(|(timestamp, message)| mws_logs::ServiceLogEvent { timestamp, message }).collect();
        self.logs
            .put_log_events_as_caller(&ctx, group, stream, events)
            .map_err(|e| format!("{}: {}", e.code, e.message))
    }

    async fn notify(&self, ctx: &RequestContext, n: mws_ssm::CommandNotification) -> Result<(), String> {
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: &n.role_arn,
                service_principal: "ssm.amazonaws.com",
                session_name: "RunCommandNotification",
                duration_seconds: 3600,
                source_account: Some(&n.account),
                source_arn: Some(&n.source_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("Systems Manager could not assume {}: {e:?}", n.role_arn))?;
        let ctx = RequestContext { region: n.region.clone(), ..ctx.clone() };
        let rctx = self.resolve(&ctx, &creds.access_key_id, &creds.session_token)?;
        mws_core::Service::invoke(
            &self.sns,
            rctx,
            "Publish",
            serde_json::json!({ "TopicArn": n.topic_arn, "Message": n.message }),
        )
        .await
        .map(|_| ())
        .map_err(|e| format!("{}: {}", e.code, e.message))
    }

    fn missing_node_permissions(
        &self,
        ctx: &RequestContext,
        account: &str,
        region: &str,
        instance_id: &str,
        actions: &[&str],
    ) -> Result<Vec<String>, String> {
        let rctx = self.node_ctx(mws_ssm::NodeRef { ctx, account, region, instance_id })?;
        Ok(actions
            .iter()
            .filter(|a| {
                !matches!(
                    rctx.check(a, "*", None, mws_core::ResourcePolicyMode::Optional, mws_core::ConditionContext::new()),
                    mws_core::AuthzDecision::Allow
                )
            })
            .map(|a| a.to_string())
            .collect())
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
