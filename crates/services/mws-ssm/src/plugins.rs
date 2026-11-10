//! What each Run Command plugin does on a node, as the SSM Agent runs it,
//! and what the agent and Systems Manager report around an invocation:
//! output uploads to S3 and CloudWatch Logs, SNS notifications and the
//! "EC2 Command (Invocation) Status-change Notification" events.
//!
//! Plugins the agent does not support on a node's platform are skipped in
//! schema 2.2 documents and fail in older ones, as the agent does. Plugins
//! MWS cannot run fail with an output saying so; none reports success
//! without doing its work.

use std::future::Future;
use std::pin::Pin;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::commands::{shell_script, Step, StepOutcome, AGENT_VERSION};
use crate::generated::types;
use crate::outputs::{CommandNotification, NodeRef};
use crate::Ssm;

/// How deep `aws:runDocument` may nest.
const MAX_DEPTH: usize = 3;

/// Plugins only Windows nodes run.
const WINDOWS_ONLY: &[&str] = &[
    "aws:runPowerShellScript",
    "aws:psModule",
    "aws:applications",
    "aws:domainJoin",
    "aws:cloudWatch",
    "aws:configureContainers",
    "aws:updateAgent",
];

/// Plugins only Linux (and macOS) nodes run.
const LINUX_ONLY: &[&str] = &["aws:runShellScript"];

/// Plugins the agent knows, on some platform.
const KNOWN: &[&str] = &[
    "aws:runShellScript",
    "aws:runPowerShellScript",
    "aws:runDocument",
    "aws:downloadContent",
    "aws:configurePackage",
    "aws:softwareInventory",
    "aws:updateSsmAgent",
    "aws:refreshAssociation",
    "aws:runPatchBaseline",
    "aws:runDockerAction",
    "aws:configureDocker",
    "aws:psModule",
    "aws:applications",
    "aws:domainJoin",
    "aws:cloudWatch",
    "aws:configureContainers",
    "aws:updateAgent",
];

/// Where an invocation runs.
#[derive(Debug, Clone)]
pub(crate) struct PluginContext {
    pub account: String,
    pub region: String,
    pub command_id: String,
    pub instance: String,
    pub platform: String,
    /// `aws:runDocument` nesting.
    pub depth: usize,
}

impl PluginContext {
    /// The agent's orchestration directory for the command on the node.
    fn orchestration_dir(&self) -> String {
        format!("/var/lib/amazon/ssm/{}/document/orchestration/{}", self.instance, self.command_id)
    }
}

fn failed(message: impl Into<String>) -> StepOutcome {
    ("Failed", "Failed", 1, String::new(), message.into())
}

fn success(stdout: impl Into<String>) -> StepOutcome {
    ("Success", "Success", 0, stdout.into(), String::new())
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A JSON object given as an object or as a JSON string.
fn object_input(v: Option<&Value>) -> Result<serde_json::Map<String, Value>, String> {
    match v {
        None | Some(Value::Null) => Ok(Default::default()),
        Some(Value::Object(o)) => Ok(o.clone()),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(Default::default()),
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(o)) => Ok(o),
            _ => Err(format!("Invalid input {s}: expected a JSON object.")),
        },
        Some(other) => Err(format!("Invalid input {other}: expected a JSON object.")),
    }
}

/// `bucket` and `key` of an S3 URL as `aws:downloadContent` takes them.
fn s3_location(url: &str) -> Option<(String, String)> {
    if let Some(rest) = url.strip_prefix("s3://") {
        let (b, k) = rest.split_once('/')?;
        return Some((b.to_string(), k.to_string()));
    }
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/')?;
    if host.starts_with("s3.") || host.starts_with("s3-") {
        let (b, k) = path.split_once('/')?;
        return Some((b.to_string(), k.to_string()));
    }
    let bucket = host.split(".s3").next().filter(|b| *b != host)?;
    Some((bucket.to_string(), path.to_string()))
}

impl Ssm {
    /// Run `script` on the node; `Ok(None)` when the node runs nothing.
    async fn shell(&self, run: &PluginContext, script: &str) -> Result<Option<crate::ShellOutput>, String> {
        match self.managed() {
            Some(m) => m.run_shell(&run.account, &run.region, &run.instance, script).await,
            None => Ok(None),
        }
    }

    /// Write `bytes` to `path` on the node.
    async fn write_node_file(&self, run: &PluginContext, path: &str, bytes: &[u8]) -> Result<(), String> {
        let dir = path.rsplit_once('/').map(|(d, _)| d).filter(|d| !d.is_empty()).unwrap_or("/");
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let script = format!(
            "mkdir -p {d} && printf '%s' {b} | base64 -d > {p}",
            d = sh_quote(dir),
            b = sh_quote(&b64),
            p = sh_quote(path)
        );
        match self.shell(run, &script).await? {
            Some(o) if o.exit_code != 0 => Err(format!("failed to write {path}: {}", o.stderr.trim())),
            _ => Ok(()),
        }
    }

    /// Run one step's plugin on the node.
    pub(crate) fn run_plugin<'a>(
        &'a self,
        run: &'a PluginContext,
        step: &'a Step,
        start: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = StepOutcome> + Send + 'a>> {
        Box::pin(async move {
            let action = step.action.as_str();
            let windows = run.platform == "Windows";
            let unsupported = (windows && LINUX_ONLY.contains(&action)) || (!windows && WINDOWS_ONLY.contains(&action));
            let modern = step.schema.as_str() >= "2.2";
            if !KNOWN.contains(&action) {
                return failed(format!(
                    "Plugin with name {action} is not supported by this version of ssm agent, please update to latest version. Step name: {}",
                    step.name
                ));
            }
            if unsupported {
                if modern {
                    return (
                        "Skipped",
                        "Skipped",
                        0,
                        format!("Step execution skipped due to unsupported plugin: {action}. Step name: {}", step.name),
                        String::new(),
                    );
                }
                return failed(format!(
                    "Plugin with name {action} is not supported in current platform. Step name: {}",
                    step.name
                ));
            }
            if windows {
                return failed(format!(
                    "MWS runs nothing on Windows nodes; the {action} step did not run. Step name: {}",
                    step.name
                ));
            }
            let nodes = self.managed();
            match action {
                "aws:runShellScript" => self.run_shell_step(run, &step.inputs).await,
                "aws:runPatchBaseline" => {
                    self.run_patch_baseline(
                        &nodes,
                        &run.account,
                        &run.region,
                        &run.instance,
                        &run.command_id,
                        &step.inputs,
                        start,
                    )
                    .await
                }
                "aws:softwareInventory" => {
                    self.gather_inventory(&nodes, &run.account, &run.region, &run.instance, &step.inputs, start).await
                }
                "aws:runDocument" => self.run_document(run, &step.inputs, start).await,
                "aws:downloadContent" => self.download_content(run, &step.inputs).await,
                "aws:configurePackage" => self.configure_package(run, &step.inputs),
                "aws:updateSsmAgent" => success(format!(
                    "Updating amazon-ssm-agent from {AGENT_VERSION} to latest\namazon-ssm-agent {AGENT_VERSION} has already been installed, update skipped"
                )),
                "aws:refreshAssociation" => self.refresh_association(run, &step.inputs, start),
                other => failed(format!("The {other} plugin is not supported by MWS; the step did not run.")),
            }
        })
    }

    async fn run_shell_step(&self, run: &PluginContext, inputs: &Value) -> StepOutcome {
        let (mut script, timeout) = shell_script(inputs);
        if inputs.get("workingDirectory").and_then(Value::as_str).is_none_or(str::is_empty) {
            // Scripts find what `aws:downloadContent` fetched by default.
            let downloads = sh_quote(&format!("{}/downloads", run.orchestration_dir()));
            script = format!("[ -d {downloads} ] && cd {downloads}\n{script}");
        }
        match tokio::time::timeout(std::time::Duration::from_secs(timeout), self.shell(run, &script)).await {
            Err(_) => (
                "TimedOut",
                "ExecutionTimedOut",
                -1,
                String::new(),
                "failed to run commands: exit status timeout".to_string(),
            ),
            Ok(Err(e)) => ("Failed", "Undeliverable", -1, String::new(), e),
            Ok(Ok(None)) => success(""),
            Ok(Ok(Some(out))) if out.exit_code == 0 => ("Success", "Success", 0, out.stdout, out.stderr),
            Ok(Ok(Some(out))) => {
                let stderr = format!("{}failed to run commands: exit status {}", out.stderr, out.exit_code);
                ("Failed", "Failed", out.exit_code, out.stdout, stderr)
            }
        }
    }

    /// `aws:runDocument`: run an SSM document (by name or ARN) or a
    /// document file on the node, step by step.
    async fn run_document(&self, run: &PluginContext, inputs: &Value, start: DateTime<Utc>) -> StepOutcome {
        if run.depth >= MAX_DEPTH {
            return failed("aws:runDocument steps nest too deeply.");
        }
        let kind = inputs.get("documentType").and_then(Value::as_str).unwrap_or("SSMDocument");
        let path = inputs.get("documentPath").and_then(Value::as_str).unwrap_or_default();
        if path.is_empty() && kind != "LocalPath" {
            return failed("documentPath is required.");
        }
        let content = match kind {
            "SSMDocument" => {
                let Some(found) = self.find_document_in(&run.account, &run.region, path) else {
                    return failed(format!(
                        "failed to fetch document {path}: InvalidDocument: Document with name {path} does not exist."
                    ));
                };
                if found.doc.document_type != "Command" {
                    return failed(format!("Document {path} is not a Command document."));
                }
                let v = found.doc.default();
                match crate::documents::parse_content(&v.content, &v.format) {
                    Ok(c) => c,
                    Err(e) => return failed(e.message),
                }
            }
            "LocalPath" => {
                let full = if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("{}/downloads/{path}", run.orchestration_dir()).trim_end_matches('/').to_string()
                };
                // A directory holds one downloaded document.
                let script = format!(
                    "p={}; if [ -d \"$p\" ]; then p=$(ls -1 \"$p\"/*.json \"$p\"/*.yml \"$p\"/*.yaml 2>/dev/null | head -n 1); fi; cat \"$p\"",
                    sh_quote(&full)
                );
                match self.shell(run, &script).await {
                    Err(e) => return failed(e),
                    Ok(None) => return success(""),
                    Ok(Some(o)) if o.exit_code != 0 => {
                        return failed(format!("failed to read document {full}: {}", o.stderr.trim()))
                    }
                    Ok(Some(o)) => match serde_json::from_str::<Value>(&o.stdout)
                        .ok()
                        .or_else(|| serde_yaml::from_str::<Value>(&o.stdout).ok())
                    {
                        Some(v) if v.is_object() => v,
                        _ => return failed(format!("{full} is not a valid JSON or YAML document.")),
                    },
                }
            }
            other => return failed(format!("documentType {other} is not valid. Use SSMDocument or LocalPath.")),
        };
        let given = match object_input(inputs.get("documentParameters")) {
            Ok(o) => o
                .into_iter()
                .map(|(k, v)| {
                    let values = match v {
                        Value::Array(a) => a
                            .into_iter()
                            .map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()))
                            .collect(),
                        Value::String(s) => vec![s],
                        other => vec![other.to_string()],
                    };
                    (k, values)
                })
                .collect(),
            Err(e) => return failed(e),
        };
        let (params, lists) = match crate::commands::resolve_parameters(&content, &given) {
            Ok(p) => p,
            Err(e) => return failed(e.message),
        };
        let inner = PluginContext { depth: run.depth + 1, ..run.clone() };
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut worst: StepOutcome = success("");
        for sub in crate::commands::steps(&content, &params, &lists, &run.platform) {
            let (status, details, code, out, err) = match &sub.skip {
                Some(reason) => ("Skipped", "Skipped", 0, reason.clone(), String::new()),
                None => self.run_plugin(&inner, &sub, start).await,
            };
            stdout.push_str(&out);
            stderr.push_str(&err);
            if matches!(status, "Failed" | "TimedOut") && worst.0 == "Success" {
                worst = (status, details, code, String::new(), String::new());
            }
        }
        (worst.0, worst.1, worst.2, stdout, stderr)
    }

    /// `aws:downloadContent`: fetch a document, an S3 object or a file
    /// over HTTP(S), GitHub or Git onto the node.
    async fn download_content(&self, run: &PluginContext, inputs: &Value) -> StepOutcome {
        let source_type = inputs.get("sourceType").and_then(Value::as_str).unwrap_or_default();
        let info = match object_input(inputs.get("sourceInfo")) {
            Ok(i) => i,
            Err(e) => return failed(e),
        };
        let dest = inputs.get("destinationPath").and_then(Value::as_str).unwrap_or_default().trim_end_matches('/');
        let dir = if dest.starts_with('/') {
            dest.to_string()
        } else if dest.is_empty() {
            format!("{}/downloads", run.orchestration_dir())
        } else {
            format!("{}/downloads/{dest}", run.orchestration_dir())
        };
        let s = |k: &str| info.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let fetch_in_node = |url: String, name: String| {
            let file = format!("{dir}/{name}");
            let script = format!(
                "mkdir -p {d} && (curl -fsSL -o {f} {u} || wget -q -O {f} {u})",
                d = sh_quote(&dir),
                f = sh_quote(&file),
                u = sh_quote(&url)
            );
            (script, file, url)
        };
        let (script, file, from) = match source_type {
            "SSMDocument" => {
                let name = s("name");
                let Some(found) = self.find_document_in(&run.account, &run.region, &name) else {
                    return failed(format!(
                        "failed to download document {name}: Document with name {name} does not exist."
                    ));
                };
                let v = found.doc.default();
                let ext = if v.format == "YAML" { "yml" } else { "json" };
                let bare = found.doc.name.clone();
                let file = format!("{dir}/{bare}.{ext}");
                return match self.write_node_file(run, &file, v.content.as_bytes()).await {
                    Ok(()) => success(format!("Content downloaded to {file}")),
                    Err(e) => failed(e),
                };
            }
            "S3" => {
                let path = s("path");
                let Some((bucket, key)) = s3_location(&path) else {
                    return failed(format!("{path} is not a valid S3 URL."));
                };
                if key.is_empty() || key.ends_with('/') {
                    return failed("MWS downloads single S3 objects only, not folders.");
                }
                let Some(outputs) = self.command_outputs() else {
                    return failed("S3 is not available.");
                };
                let Some(template) = self.template() else { return failed("S3 is not available.") };
                let ctx = mws_core::RequestContext { region: run.region.clone(), ..template };
                let node =
                    NodeRef { ctx: &ctx, account: &run.account, region: &run.region, instance_id: &run.instance };
                let body = match outputs.get_object(node, &bucket, &key).await {
                    Ok(b) => b,
                    Err(e) => return failed(format!("failed to download {path}: {e}")),
                };
                let name = key.rsplit('/').next().unwrap_or(&key).to_string();
                let file = format!("{dir}/{name}");
                return match self.write_node_file(run, &file, &body).await {
                    Ok(()) => success(format!("Content downloaded to {file}")),
                    Err(e) => failed(e),
                };
            }
            "HTTP" => {
                let url = s("url");
                if url.is_empty() {
                    return failed("sourceInfo must contain url.");
                }
                let name = url.split(['?', '#']).next().unwrap_or(&url).rsplit('/').next().unwrap_or("download");
                let name = if name.is_empty() { "download".to_string() } else { name.to_string() };
                fetch_in_node(url, name)
            }
            "GitHub" => {
                let (owner, repo, path) = (s("owner"), s("repository"), s("path"));
                if owner.is_empty() || repo.is_empty() {
                    return failed("sourceInfo must contain owner and repository.");
                }
                let options = s("getOptions");
                let reference = options
                    .strip_prefix("branch:")
                    .or_else(|| options.strip_prefix("commitID:"))
                    .filter(|r| !r.is_empty())
                    .unwrap_or("HEAD")
                    .to_string();
                if path.is_empty() || path.ends_with('/') {
                    return failed("MWS downloads single GitHub files only, not directories.");
                }
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                let url = format!(
                    "https://raw.githubusercontent.com/{owner}/{repo}/{reference}/{}",
                    path.trim_start_matches('/')
                );
                fetch_in_node(url, name)
            }
            "Git" => {
                let repo = s("repository");
                if repo.is_empty() {
                    return failed("sourceInfo must contain repository.");
                }
                let script =
                    format!("mkdir -p {d} && git clone --depth 1 {r} {d}", d = sh_quote(&dir), r = sh_quote(&repo));
                (script, dir.clone(), repo)
            }
            other => {
                return failed(format!("sourceType {other} is not valid. Use GitHub, Git, HTTP, S3 or SSMDocument."))
            }
        };
        match self.shell(run, &script).await {
            Err(e) => failed(e),
            Ok(None) => success(format!("Content downloaded to {file}")),
            Ok(Some(o)) if o.exit_code == 0 => success(format!("Content downloaded to {file}")),
            Ok(Some(o)) => ("Failed", "Failed", 1, o.stdout, format!("failed to download {from}: {}", o.stderr.trim())),
        }
    }

    /// `aws:configurePackage` (Distributor): the package is a `Package`
    /// document. MWS finds it but does not install it.
    fn configure_package(&self, run: &PluginContext, inputs: &Value) -> StepOutcome {
        let name = inputs.get("name").and_then(Value::as_str).unwrap_or_default();
        let action = inputs.get("action").and_then(Value::as_str).unwrap_or("Install");
        if name.is_empty() {
            return failed("name is required.");
        }
        match self.find_document_in(&run.account, &run.region, name) {
            Some(f) if f.doc.document_type == "Package" => failed(format!(
                "{action} of package {name} is not supported by MWS: Distributor packages are stored but never installed."
            )),
            _ => (
                "Failed",
                "Failed",
                1,
                String::new(),
                format!(
                    "Failed to retrieve package document {name}: ResourceNotFoundException: No package {name} found\nFailed to {} package; {name} is not available",
                    action.to_ascii_lowercase()
                ),
            ),
        }
    }

    /// `aws:refreshAssociation`: apply the node's associations now (all of
    /// them, or those `associationIds` names).
    fn refresh_association(&self, run: &PluginContext, inputs: &Value, at: DateTime<Utc>) -> StepOutcome {
        let wanted: Vec<String> = match inputs.get("associationIds") {
            Some(Value::Array(a)) => {
                a.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string).collect()
            }
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            _ => Vec::new(),
        };
        let ids: Vec<String> = {
            let st = self.lock();
            st.region_ref(&run.account, &run.region)
                .map(|r| {
                    r.associations
                        .iter()
                        .filter(|(id, _)| wanted.is_empty() || wanted.contains(id))
                        .map(|(id, _)| id.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut applied = Vec::new();
        for id in ids {
            let Some(d) = ({
                let st = self.lock();
                st.region_ref(&run.account, &run.region)
                    .and_then(|r| r.associations.get(&id))
                    .map(|a| a.description.clone())
            }) else {
                continue;
            };
            if self.association_targets(&run.account, &run.region, &d).contains(&run.instance) {
                self.apply_association(&run.account, &run.region, &id, at, Some(vec![run.instance.clone()]));
                applied.push(id);
            }
        }
        success(if applied.is_empty() {
            "No associations to refresh.".to_string()
        } else {
            format!("Refreshing associations: {}", applied.join(", "))
        })
    }

    /// Upload one step's output where the command says: S3 objects
    /// `<prefix>/<command>/<instance>/<plugin>/<step>/stdout|stderr` and
    /// CloudWatch Logs streams `<command>/<instance>/<step>/stdout|stderr`,
    /// as the node's role. The S3 URLs of what was uploaded.
    pub(crate) async fn upload_output(
        &self,
        run: &PluginContext,
        command: &types::Command,
        step: &Step,
        index: usize,
        stdout: &str,
        stderr: &str,
    ) -> Option<(String, String)> {
        let outputs = self.command_outputs()?;
        let template = self.template()?;
        let ctx = mws_core::RequestContext { region: run.region.clone(), ..template };
        let node = NodeRef { ctx: &ctx, account: &run.account, region: &run.region, instance_id: &run.instance };
        let mut urls = None;
        if let Some(bucket) = command.output_s3_bucket_name.as_deref().filter(|b| !b.is_empty()) {
            let prefix = command.output_s3_key_prefix.clone().unwrap_or_default();
            let plugin = step.action.replace(':', "");
            let sub = if step.schema.as_str() < "2.0" { format!("{index}.{plugin}") } else { step.name.clone() };
            let mut base = vec![run.command_id.clone(), run.instance.clone(), plugin, sub];
            if !prefix.trim_matches('/').is_empty() {
                base.insert(0, prefix.trim_matches('/').to_string());
            }
            let base = base.join("/");
            let region = command.output_s3_region.clone().filter(|r| !r.is_empty()).unwrap_or(run.region.clone());
            let mut out_url = String::new();
            let mut err_url = String::new();
            for (stream, body, url) in [("stdout", stdout, &mut out_url), ("stderr", stderr, &mut err_url)] {
                if body.is_empty() {
                    continue;
                }
                let key = format!("{base}/{stream}");
                if outputs.put_object(node, bucket, &key, body.as_bytes().to_vec()).await.is_ok() {
                    *url = format!("https://s3.{region}.amazonaws.com/{bucket}/{key}");
                }
            }
            urls = Some((out_url, err_url));
        }
        if let Some(cw) = command.cloud_watch_output_config.as_ref().filter(|c| c.cloud_watch_output_enabled) {
            let group = cw
                .cloud_watch_log_group_name
                .clone()
                .filter(|g| !g.is_empty())
                .unwrap_or_else(|| format!("/aws/ssm/{}", command.document_name.clone().unwrap_or_default()));
            let now = (Utc::now()
                + chrono::Duration::milliseconds(self.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed)))
            .timestamp_millis();
            for (stream, body) in [("stdout", stdout), ("stderr", stderr)] {
                if body.is_empty() {
                    continue;
                }
                let name = format!("{}/{}/{}/{stream}", run.command_id, run.instance, step.name.replace(':', "-"));
                let _ = outputs.put_log_events(node, &group, &name, vec![(now, body.to_string())]).await;
            }
        }
        urls
    }

    /// Report a command's status when it changed: an "EC2 Command
    /// Status-change Notification" event and, if asked, an SNS
    /// notification.
    pub(crate) fn report_command(&self, account: &str, region: &str, command_id: &str) {
        let (view, instances) = {
            let mut st = self.lock();
            let Some(rec) = st
                .region(account, region)
                .commands
                .iter_mut()
                .find(|c| c.command.command_id.as_deref() == Some(command_id))
            else {
                return;
            };
            let view = crate::commands::command_view(rec);
            let status = view.status.clone().unwrap_or_default();
            if rec.reported == status {
                return;
            }
            rec.reported = status;
            (view, rec.invocations.iter().map(|i| i.instance_id.clone()).collect::<Vec<_>>())
        };
        let partition = self.partition();
        let status = view.status.clone().unwrap_or_default();
        let ts = |t: Option<DateTime<Utc>>| t.map(crate::events::iso).unwrap_or_default();
        self.emit(
            account,
            region,
            "EC2 Command Status-change Notification",
            instances.iter().map(|i| format!("arn:{partition}:ec2:{region}:{account}:instance/{i}")).collect(),
            json!({
                "command-id": command_id,
                "document-name": view.document_name,
                "expire-after": ts(view.expires_after),
                "parameters": view.parameters.clone().unwrap_or_default(),
                "requested-date-time": ts(view.requested_date_time),
                "status": status,
            }),
        );
        let message = json!({
            "commandId": command_id,
            "documentName": view.document_name,
            "instanceIds": instances,
            "requestedDateTime": ts(view.requested_date_time),
            "expiresAfter": ts(view.expires_after),
            "outputS3BucketName": view.output_s3_bucket_name.clone().unwrap_or_default(),
            "outputS3KeyPrefix": view.output_s3_key_prefix.clone().unwrap_or_default(),
            "status": status,
            "eventTime": crate::events::iso(self.clock_now()),
        });
        self.notify(account, region, &view, "Command", &status, message);
    }

    /// Report an invocation's status when it changed: an "EC2 Command
    /// Invocation Status-change Notification" event and, if asked, an SNS
    /// notification.
    pub(crate) fn report_invocation(&self, account: &str, region: &str, command_id: &str, instance: &str) {
        let (view, status) = {
            let mut st = self.lock();
            let Some(rec) = st
                .region(account, region)
                .commands
                .iter_mut()
                .find(|c| c.command.command_id.as_deref() == Some(command_id))
            else {
                return;
            };
            let view = rec.command.clone();
            let Some(inv) = rec.invocations.iter_mut().find(|i| i.instance_id == instance) else { return };
            if inv.reported == inv.status || inv.hidden {
                return;
            }
            inv.reported = inv.status.clone();
            (view, inv.status.clone())
        };
        let partition = self.partition();
        let requested = view.requested_date_time.map(crate::events::iso).unwrap_or_default();
        self.emit(
            account,
            region,
            "EC2 Command Invocation Status-change Notification",
            vec![format!("arn:{partition}:ec2:{region}:{account}:instance/{instance}")],
            json!({
                "command-id": command_id,
                "document-name": view.document_name,
                "instance-id": instance,
                "requested-date-time": requested,
                "status": status,
            }),
        );
        let message = json!({
            "commandId": command_id,
            "documentName": view.document_name,
            "instanceId": instance,
            "requestedDateTime": requested,
            "status": status,
            "eventTime": crate::events::iso(self.clock_now()),
        });
        self.notify(account, region, &view, "Invocation", &status, message);
    }

    /// Publish `message` to the command's notification topic, when its
    /// `NotificationConfig` asks for `kind` notifications on `status`.
    fn notify(&self, account: &str, region: &str, c: &types::Command, kind: &str, status: &str, message: Value) {
        let Some(n) = &c.notification_config else { return };
        let Some(topic) = n.notification_arn.clone().filter(|t| !t.is_empty()) else { return };
        if n.notification_type.as_deref().unwrap_or("Command") != kind {
            return;
        }
        let events = n.notification_events.clone().unwrap_or_default();
        let wanted = events.is_empty() || events.iter().any(|e| e == "All" || e == status);
        if !wanted || status == "Pending" {
            return;
        }
        let Some(role) = c.service_role.clone().filter(|r| !r.is_empty()) else { return };
        let (Some(outputs), Some(template)) = (self.command_outputs(), self.template()) else { return };
        let ctx = mws_core::RequestContext { region: region.to_string(), ..template };
        let partition = ctx.partition.clone();
        let note = CommandNotification {
            account: account.to_string(),
            region: region.to_string(),
            role_arn: role,
            topic_arn: topic,
            source_arn: format!(
                "arn:{partition}:ssm:{region}:{account}:command/{}",
                c.command_id.clone().unwrap_or_default()
            ),
            message: message.to_string(),
        };
        crate::commands::spawn(async move {
            let _ = outputs.notify(&ctx, note).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_urls() {
        assert_eq!(s3_location("https://s3.amazonaws.com/b/k/x.sh"), Some(("b".into(), "k/x.sh".into())));
        assert_eq!(s3_location("https://b.s3.us-west-2.amazonaws.com/x.sh"), Some(("b".into(), "x.sh".into())));
        assert_eq!(s3_location("s3://b/x"), Some(("b".into(), "x".into())));
        assert_eq!(s3_location("https://example.com/x"), None);
    }
}
