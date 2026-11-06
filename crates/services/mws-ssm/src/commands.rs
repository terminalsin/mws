//! Managed nodes and Run Command: `DescribeInstanceInformation`,
//! `SendCommand` and the calls that follow a command. EC2 instances with an
//! instance profile are managed nodes (the composition root reports them
//! through [`ManagedNodes`]); commands really run `aws:runShellScript`
//! steps in the instance, as the SSM Agent would.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::documents::{parse_content, pick_version, sha256};
use crate::generated::{errors, types};
use crate::names::{now, page};
use crate::Ssm;

/// The agent version managed nodes report.
pub const AGENT_VERSION: &str = "3.3.1142.0";
/// What `GetCommandInvocation` returns of each output stream.
const MAX_CONTENT: usize = 24000;
/// What a plugin's `Output` holds in `ListCommandInvocations`.
const MAX_PLUGIN_OUTPUT: usize = 2500;

/// A node SSM manages, as the composition root sees it.
#[derive(Debug, Clone, Default)]
pub struct ManagedNode {
    pub instance_id: String,
    /// `Online` or `ConnectionLost`.
    pub ping_status: String,
    pub last_ping: DateTime<Utc>,
    /// `Linux`, `Windows` or `MacOS`.
    pub platform_type: String,
    pub platform_name: String,
    pub platform_version: String,
    /// The instance profile's role name.
    pub iam_role: String,
    pub registration_date: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub computer_name: Option<String>,
    pub tags: BTreeMap<String, String>,
}

/// What a shell script printed.
#[derive(Debug, Clone, Default)]
pub struct ShellOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// The compute nodes SSM manages (EC2 instances with an instance profile),
/// and a way to run a script on one as the SSM Agent does.
#[async_trait::async_trait]
pub trait ManagedNodes: Send + Sync {
    fn nodes(&self, account: &str, region: &str) -> Vec<ManagedNode>;

    /// Run `script` as root on the node. `Ok(None)` when the node runs
    /// nothing (EC2's metadata backend).
    async fn run_shell(
        &self,
        account: &str,
        region: &str,
        instance_id: &str,
        script: &str,
    ) -> Result<Option<ShellOutput>, String>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginRun {
    pub name: String,
    pub status: String,
    pub status_details: String,
    pub response_code: i32,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Invocation {
    pub instance_id: String,
    pub instance_name: String,
    pub status: String,
    pub status_details: String,
    pub plugins: Vec<PluginRun>,
}

impl Invocation {
    fn done(&self) -> bool {
        !matches!(self.status.as_str(), "Pending" | "InProgress" | "Delayed" | "Cancelling")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandRecord {
    pub command: types::Command,
    pub invocations: Vec<Invocation>,
}

/// Command parameters by name.
type Params = BTreeMap<String, Vec<String>>;

/// One step to run: its plugin name, action and inputs (placeholders
/// filled in).
#[derive(Debug, Clone)]
struct Step {
    name: String,
    action: String,
    inputs: Value,
    skip: Option<String>,
}

fn node_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ec2:{}:{}:instance/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

fn list_arn(ctx: &RequestContext) -> String {
    format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// Fill `{{ name }}` placeholders. A string that is exactly one
/// placeholder of a list parameter becomes the list.
fn substitute(v: &Value, params: &BTreeMap<String, Vec<String>>, lists: &[String]) -> Value {
    match v {
        Value::String(s) => {
            let trimmed = s.trim();
            if let Some(inner) = trimmed.strip_prefix("{{").and_then(|x| x.strip_suffix("}}")) {
                let name = inner.trim();
                if !inner.contains("{{") {
                    if let Some(values) = params.get(name) {
                        if lists.iter().any(|l| l == name) {
                            return Value::Array(values.iter().cloned().map(Value::String).collect());
                        }
                    }
                }
            }
            let mut out = s.clone();
            for (k, values) in params {
                let joined = values.join(if lists.contains(k) { "\n" } else { "," });
                for pat in
                    [format!("{{{{ {k} }}}}"), format!("{{{{{k}}}}}"), format!("{{{{ {k}}}}}"), format!("{{{{{k} }}}}")]
                {
                    out = out.replace(&pat, &joined);
                }
            }
            Value::String(out)
        }
        Value::Array(a) => {
            let mut out = Vec::new();
            for x in a {
                match substitute(x, params, lists) {
                    Value::Array(inner) if x.is_string() => out.extend(inner),
                    other => out.push(other),
                }
            }
            Value::Array(out)
        }
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), substitute(x, params, lists))).collect()),
        other => other.clone(),
    }
}

/// The parameters a command runs with: the caller's, then defaults; an
/// error when a parameter is unknown or a required one is missing.
fn resolve_parameters(
    doc: &Value,
    given: &BTreeMap<String, Vec<String>>,
) -> Result<(Params, Vec<String>), ServiceError> {
    let declared = doc.get("parameters").and_then(Value::as_object).cloned().unwrap_or_default();
    if let Some(unknown) = given.keys().find(|k| !declared.contains_key(*k)) {
        return Err(errors::invalid_parameters(format!("Parameter \"{unknown}\" is not declared in the document.")));
    }
    let mut out = BTreeMap::new();
    let mut lists = Vec::new();
    for (name, spec) in &declared {
        let t = spec.get("type").and_then(Value::as_str).unwrap_or("String");
        if t == "StringList" {
            lists.push(name.clone());
        }
        let values = match given.get(name) {
            Some(v) => v.clone(),
            None => match spec.get("default") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(a)) => {
                    a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect()
                }
                Some(other) => vec![other.to_string()],
                None => {
                    return Err(errors::invalid_parameters(format!(
                        "Parameter \"{name}\" is required by the document but was not provided."
                    )))
                }
            },
        };
        if let Some(allowed) = spec.get("allowedValues").and_then(Value::as_array) {
            if given.contains_key(name) && !values.iter().all(|v| allowed.iter().any(|a| a.as_str() == Some(v))) {
                return Err(errors::invalid_parameters(format!(
                    "Parameter \"{name}\" has a value that isn't one of its allowed values."
                )));
            }
        }
        if let Some(min) = spec.get("minItems").and_then(Value::as_u64) {
            if (values.iter().filter(|v| !v.is_empty()).count() as u64) < min {
                return Err(errors::invalid_parameters(format!("Parameter \"{name}\" needs at least {min} item(s).")));
            }
        }
        out.insert(name.clone(), values);
    }
    Ok((out, lists))
}

/// The steps of a Command document, with parameters filled in.
fn steps(doc: &Value, params: &BTreeMap<String, Vec<String>>, lists: &[String], platform: &str) -> Vec<Step> {
    let mut out = Vec::new();
    if let Some(rc) = doc.get("runtimeConfig").and_then(Value::as_object) {
        for (action, cfg) in rc {
            let props = cfg.get("properties").cloned().unwrap_or(Value::Null);
            let props = match props {
                Value::Array(a) => a,
                Value::Null => Vec::new(),
                other => vec![other],
            };
            for p in props {
                out.push(Step {
                    name: action.clone(),
                    action: action.clone(),
                    inputs: substitute(&p, params, lists),
                    skip: None,
                });
            }
        }
        return out;
    }
    for s in doc.get("mainSteps").and_then(Value::as_array).cloned().unwrap_or_default() {
        let action = s.get("action").and_then(Value::as_str).unwrap_or_default().to_string();
        let name = s.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
        let skip = s.get("precondition").and_then(|p| p.get("StringEquals")).and_then(Value::as_array).and_then(|eq| {
            let (k, v) = (eq.first()?.as_str()?, eq.get(1)?.as_str()?);
            (k == "platformType" && v != platform).then(|| {
                format!("Step execution skipped due to unsatisfied preconditions: '\"StringEquals\": [platformType, {v}]'. Step name: {name}")
            })
        });
        out.push(Step {
            name,
            action,
            inputs: substitute(s.get("inputs").unwrap_or(&Value::Null), params, lists),
            skip,
        });
    }
    out
}

/// The shell script an `aws:runShellScript` step runs, and its timeout.
fn shell_script(inputs: &Value) -> (String, u64) {
    let lines: Vec<String> = match inputs.get("runCommand") {
        Some(Value::Array(a)) => {
            a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect()
        }
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    };
    let mut script = String::new();
    if let Some(dir) = inputs.get("workingDirectory").and_then(Value::as_str).filter(|d| !d.is_empty()) {
        script.push_str(&format!("cd '{}' || exit 1\n", dir.replace('\'', "'\\''")));
    }
    script.push_str(&lines.join("\n"));
    let timeout = match inputs.get("timeoutSeconds") {
        Some(Value::String(s)) => s.parse().unwrap_or(3600),
        Some(Value::Number(n)) => n.as_u64().unwrap_or(3600),
        _ => 3600,
    };
    (script, timeout)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn command_view(r: &CommandRecord) -> types::Command {
    let mut c = r.command.clone();
    let done: Vec<&Invocation> = r.invocations.iter().filter(|i| i.done()).collect();
    c.target_count = r.invocations.len() as i32;
    c.completed_count = done.len() as i32;
    c.error_count = done.iter().filter(|i| matches!(i.status.as_str(), "Failed" | "TimedOut")).count() as i32;
    c.delivery_timed_out_count = done.iter().filter(|i| i.status_details == "DeliveryTimedOut").count() as i32;
    let status = if r.command.status.as_deref() == Some("Cancelled") {
        "Cancelled"
    } else if r.invocations.iter().all(|i| i.status == "Pending") && !r.invocations.is_empty() {
        "Pending"
    } else if done.len() < r.invocations.len() {
        "InProgress"
    } else if done.iter().any(|i| i.status == "TimedOut") {
        "TimedOut"
    } else if done.iter().any(|i| i.status == "Failed") {
        "Failed"
    } else if done.iter().all(|i| i.status == "Cancelled") && !done.is_empty() {
        "Cancelled"
    } else {
        "Success"
    };
    c.status = Some(status.into());
    c.status_details = Some(status.into());
    c
}

fn plugin_view(p: &PluginRun, c: &types::Command, details: bool) -> types::CommandPlugin {
    types::CommandPlugin {
        name: Some(p.name.clone()),
        status: Some(p.status.clone()),
        status_details: Some(p.status_details.clone()),
        response_code: p.response_code,
        response_start_date_time: p.start,
        response_finish_date_time: p.end,
        output: details.then(|| truncate(&format!("{}{}", p.stdout, p.stderr), MAX_PLUGIN_OUTPUT)),
        standard_output_url: Some(String::new()),
        standard_error_url: Some(String::new()),
        output_s3_region: c.output_s3_region.clone(),
        output_s3_bucket_name: c.output_s3_bucket_name.clone().or(Some(String::new())),
        output_s3_key_prefix: c.output_s3_key_prefix.clone().or(Some(String::new())),
    }
}

fn invocation_view(r: &CommandRecord, i: &Invocation, details: bool) -> types::CommandInvocation {
    let c = &r.command;
    types::CommandInvocation {
        command_id: c.command_id.clone(),
        instance_id: Some(i.instance_id.clone()),
        instance_name: Some(i.instance_name.clone()),
        comment: c.comment.clone(),
        document_name: c.document_name.clone(),
        document_version: c.document_version.clone(),
        requested_date_time: c.requested_date_time,
        status: Some(i.status.clone()),
        status_details: Some(i.status_details.clone()),
        trace_output: Some(String::new()),
        standard_output_url: Some(String::new()),
        standard_error_url: Some(String::new()),
        command_plugins: details.then(|| i.plugins.iter().map(|p| plugin_view(p, c, true)).collect()),
        service_role: c.service_role.clone(),
        notification_config: c.notification_config.clone(),
        cloud_watch_output_config: c.cloud_watch_output_config.clone(),
    }
}

/// What a command runs: `SendCommand`'s arguments, or a maintenance
/// window task's.
#[derive(Debug, Clone, Default)]
pub(crate) struct Launch {
    pub document_name: String,
    pub document_version: Option<String>,
    pub document_hash: Option<String>,
    pub parameters: BTreeMap<String, Vec<String>>,
    pub instance_ids: Vec<String>,
    /// Whether the caller named the instances (rather than targets).
    pub explicit: bool,
    pub targets: Vec<types::Target>,
    pub comment: Option<String>,
    pub timeout_seconds: Option<i32>,
    pub output_s3_region: Option<String>,
    pub output_s3_bucket_name: Option<String>,
    pub output_s3_key_prefix: Option<String>,
    pub max_concurrency: Option<String>,
    pub max_errors: Option<String>,
    pub service_role_arn: Option<String>,
    pub notification_config: Option<types::NotificationConfig>,
    pub cloud_watch_output_config: Option<types::CloudWatchOutputConfig>,
    pub alarm_configuration: Option<types::AlarmConfiguration>,
}

/// Run `fut` in the background on the current Tokio runtime, or on a
/// thread of its own outside one.
pub(crate) fn spawn<F: std::future::Future<Output = ()> + Send + 'static>(fut: F) {
    match tokio::runtime::Handle::try_current() {
        Ok(h) => {
            h.spawn(fut);
        }
        Err(_) => {
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    rt.block_on(fut);
                }
            });
        }
    }
}

fn iso(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

impl Ssm {
    fn managed(&self) -> Option<Arc<dyn ManagedNodes>> {
        self.nodes.read().expect("SSM nodes lock poisoned").clone()
    }

    pub(crate) fn nodes_of(&self, account: &str, region: &str) -> Vec<ManagedNode> {
        self.managed().map(|m| m.nodes(account, region)).unwrap_or_default()
    }

    pub(crate) fn describe_instance_information(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceInformationRequest,
    ) -> Result<types::DescribeInstanceInformationResult, ServiceError> {
        ctx.authorize("ssm:DescribeInstanceInformation", &list_arn(ctx), ConditionContext::new())?;
        let mut filters: Vec<(String, Vec<String>)> = Vec::new();
        if input.instance_information_filter_list.is_some() && input.filters.is_some() {
            return Err(errors::invalid_filter("You can't specify both InstanceInformationFilterList and Filters."));
        }
        const KEYS: &[&str] = &[
            "InstanceIds",
            "AgentVersion",
            "PingStatus",
            "PlatformTypes",
            "ActivationIds",
            "IamRole",
            "ResourceType",
            "AssociationStatus",
        ];
        for f in input.instance_information_filter_list.unwrap_or_default() {
            if !KEYS.contains(&f.key.as_str()) {
                return Err(errors::invalid_instance_information_filter_value(format!(
                    "{} is not a valid filter key.",
                    f.key
                )));
            }
            filters.push((f.key, f.value_set));
        }
        for f in input.filters.unwrap_or_default() {
            if !KEYS.contains(&f.key.as_str()) && !f.key.starts_with("tag:") && f.key != "tag-key" {
                return Err(errors::invalid_filter_key("The specified key isn't valid."));
            }
            filters.push((f.key, f.values));
        }
        let nodes: Vec<ManagedNode> = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .into_iter()
            .filter(|n| {
                filters.iter().all(|(k, values)| {
                    let any = |x: &str| values.iter().any(|v| v == x);
                    match k.as_str() {
                        "InstanceIds" => any(&n.instance_id),
                        "AgentVersion" => any(AGENT_VERSION),
                        "PingStatus" => any(&n.ping_status),
                        "PlatformTypes" => any(&n.platform_type),
                        "ActivationIds" => false,
                        "IamRole" => any(&n.iam_role),
                        "ResourceType" => any("EC2Instance"),
                        "AssociationStatus" => false,
                        "tag-key" => values.iter().any(|v| n.tags.contains_key(v)),
                        tag => {
                            let key = tag.trim_start_matches("tag:");
                            n.tags.get(key).is_some_and(|t| values.contains(t))
                        }
                    }
                })
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(5, 50) as usize;
        let (items, next) = page(nodes, input.next_token.as_deref(), limit)?;
        let list = items
            .into_iter()
            .map(|n| types::InstanceInformation {
                instance_id: Some(n.instance_id),
                ping_status: Some(n.ping_status),
                last_ping_date_time: Some(n.last_ping),
                agent_version: Some(AGENT_VERSION.into()),
                is_latest_version: Some(true),
                platform_type: Some(n.platform_type),
                platform_name: Some(n.platform_name),
                platform_version: Some(n.platform_version),
                iam_role: Some(n.iam_role),
                registration_date: None,
                resource_type: Some("EC2Instance".into()),
                ip_address: n.ip_address,
                computer_name: n.computer_name,
                ..Default::default()
            })
            .collect();
        Ok(types::DescribeInstanceInformationResult { instance_information_list: Some(list), next_token: next })
    }

    /// The instances `targets` select (`InstanceIds`, `tag:<key>`,
    /// `tag-key`), among the caller's managed nodes.
    pub(crate) fn resolve_targets(
        &self,
        account: &str,
        region: &str,
        targets: &[types::Target],
    ) -> Result<Vec<String>, ServiceError> {
        let nodes = self.nodes_of(account, region);
        let mut out: Vec<String> = Vec::new();
        for t in targets {
            let key = t.key.clone().unwrap_or_default();
            let values = t.values.clone().unwrap_or_default();
            let matched: Vec<String> = match key.as_str() {
                "InstanceIds" => values.clone(),
                "tag-key" => nodes
                    .iter()
                    .filter(|n| values.iter().any(|v| n.tags.contains_key(v)))
                    .map(|n| n.instance_id.clone())
                    .collect(),
                k if k.starts_with("tag:") => {
                    let tag = &k[4..];
                    nodes
                        .iter()
                        .filter(|n| n.tags.get(tag).is_some_and(|x| values.contains(x)))
                        .map(|n| n.instance_id.clone())
                        .collect()
                }
                _ => {
                    return Err(errors::invalid_target(format!(
                        "Target key {key} is not supported. Use InstanceIds, tag:<key> or tag-key."
                    )))
                }
            };
            for m in matched {
                if !out.contains(&m) {
                    out.push(m);
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn send_command(
        &self,
        ctx: &RequestContext,
        input: types::SendCommandRequest,
    ) -> Result<types::SendCommandResult, ServiceError> {
        let explicit = input.instance_ids.clone().unwrap_or_default();
        let targets = input.targets.clone().unwrap_or_default();
        if explicit.is_empty() == targets.is_empty() {
            return Err(errors::invalid_parameters("Specify either InstanceIds or Targets, but not both."));
        }
        let found = self.find_document(ctx, &input.document_name);
        let doc_arn = match &found {
            Some(f) if f.doc.amazon() => crate::documents::arn(&ctx.partition, &ctx.region, "", &f.doc.name),
            Some(f) => crate::documents::arn(&ctx.partition, &ctx.region, &f.owner_account, &f.doc.name),
            None => crate::documents::arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.document_name),
        };
        let ids = if explicit.is_empty() {
            self.resolve_targets(&ctx.caller.account_id, &ctx.region, &targets)?
        } else {
            explicit.clone()
        };
        ctx.authorize("ssm:SendCommand", &doc_arn, ConditionContext::new())?;
        for id in &ids {
            ctx.authorize("ssm:SendCommand", &node_arn(ctx, id), ConditionContext::new())?;
        }
        let launch = Launch {
            document_name: input.document_name,
            document_version: input.document_version,
            document_hash: input.document_hash,
            parameters: input.parameters.unwrap_or_default(),
            instance_ids: ids,
            explicit: !explicit.is_empty(),
            targets,
            comment: input.comment,
            timeout_seconds: input.timeout_seconds,
            output_s3_region: input.output_s3_region,
            output_s3_bucket_name: input.output_s3_bucket_name,
            output_s3_key_prefix: input.output_s3_key_prefix,
            max_concurrency: input.max_concurrency,
            max_errors: input.max_errors,
            service_role_arn: input.service_role_arn,
            notification_config: input.notification_config,
            cloud_watch_output_config: input.cloud_watch_output_config,
            alarm_configuration: input.alarm_configuration,
        };
        let command = self.launch(&ctx.caller.account_id, &ctx.region, now(ctx), launch)?;
        Ok(types::SendCommandResult { command: Some(command) })
    }

    /// Start a command on `launch.instance_ids` in `account` and `region`
    /// (no authorization: the caller has done it). Instances that are not
    /// online managed nodes are an error when named explicitly, and left
    /// out when a target selected them.
    pub(crate) fn launch(
        &self,
        account: &str,
        region: &str,
        requested: DateTime<Utc>,
        input: Launch,
    ) -> Result<types::Command, ServiceError> {
        let found = self
            .find_document_in(account, region, &input.document_name)
            .ok_or_else(|| crate::documents::not_found(&input.document_name))?;
        let doc = found.doc;
        if doc.document_type != "Command" {
            return Err(errors::invalid_document(format!(
                "Document type {} is not supported. Only documents of type Command can be sent.",
                doc.document_type
            )));
        }
        let version = pick_version(&doc, input.document_version.as_deref(), None)?;
        if let Some(h) = &input.document_hash {
            if *h != sha256(&version.content) {
                return Err(errors::invalid_document("The document hash doesn't match the document's content."));
            }
        }
        let content = parse_content(&version.content, &version.format)?;
        let given = input.parameters.clone();
        let (params, lists) = resolve_parameters(&content, &given)?;
        let nodes = self.nodes_of(account, region);
        let ids = input.instance_ids.clone();
        let bad: Vec<String> = ids
            .iter()
            .filter(|id| !nodes.iter().any(|n| &n.instance_id == *id && n.ping_status == "Online"))
            .cloned()
            .collect();
        if !bad.is_empty() && input.explicit {
            return Err(errors::invalid_instance_id(format!(
                "Instances [[{}]] not in a valid state for account {account}",
                bad.join(", ")
            )));
        }
        let ids: Vec<String> = ids.into_iter().filter(|id| !bad.contains(id)).collect();
        let timeout = input.timeout_seconds.unwrap_or(3600).max(30);
        let command = types::Command {
            command_id: Some(uuid::Uuid::new_v4().to_string()),
            document_name: Some(input.document_name.clone()),
            document_version: Some(input.document_version.clone().unwrap_or_else(|| "$DEFAULT".into())),
            comment: Some(input.comment.clone().unwrap_or_default()),
            expires_after: Some(requested + chrono::Duration::seconds(i64::from(timeout))),
            parameters: Some(given),
            instance_ids: Some(if input.explicit { ids.clone() } else { Vec::new() }),
            targets: Some(input.targets.clone()),
            requested_date_time: Some(requested),
            status: Some("Pending".into()),
            status_details: Some("Pending".into()),
            output_s3_region: Some(input.output_s3_region.clone().unwrap_or_else(|| region.to_string())),
            output_s3_bucket_name: Some(input.output_s3_bucket_name.clone().unwrap_or_default()),
            output_s3_key_prefix: Some(input.output_s3_key_prefix.clone().unwrap_or_default()),
            max_concurrency: Some(input.max_concurrency.clone().unwrap_or_else(|| "50".into())),
            max_errors: Some(input.max_errors.clone().unwrap_or_else(|| "0".into())),
            service_role: Some(input.service_role_arn.clone().unwrap_or_default()),
            notification_config: Some(input.notification_config.clone().unwrap_or(types::NotificationConfig {
                notification_arn: Some(String::new()),
                notification_events: Some(Vec::new()),
                notification_type: Some(String::new()),
            })),
            cloud_watch_output_config: Some(input.cloud_watch_output_config.clone().unwrap_or(
                types::CloudWatchOutputConfig {
                    cloud_watch_log_group_name: Some(String::new()),
                    cloud_watch_output_enabled: false,
                },
            )),
            timeout_seconds: Some(timeout),
            alarm_configuration: input.alarm_configuration.clone(),
            ..Default::default()
        };
        let platform = |id: &str| {
            nodes
                .iter()
                .find(|n| n.instance_id == id)
                .map(|n| n.platform_type.clone())
                .unwrap_or_else(|| "Linux".into())
        };
        let mut runs = Vec::new();
        let invocations: Vec<Invocation> = ids
            .iter()
            .map(|id| {
                let s = steps(&content, &params, &lists, &platform(id));
                let plugins = s
                    .iter()
                    .map(|st| PluginRun {
                        name: st.name.clone(),
                        status: "Pending".into(),
                        status_details: "Pending".into(),
                        response_code: -1,
                        ..Default::default()
                    })
                    .collect();
                runs.push((id.clone(), platform(id), s));
                Invocation {
                    instance_id: id.clone(),
                    instance_name: String::new(),
                    status: "Pending".into(),
                    status_details: "Pending".into(),
                    plugins,
                }
            })
            .collect();
        let record = CommandRecord { command, invocations };
        let view = command_view(&record);
        let command_id = record.command.command_id.clone().unwrap_or_default();
        self.lock().region(account, region).commands.insert(0, record);
        for (id, platform, steps) in runs {
            let ssm = self.clone();
            let (account, region, command_id) = (account.to_string(), region.to_string(), command_id.clone());
            spawn(
                async move { ssm.run_invocation(&account, &region, &command_id, &id, &platform, steps, requested).await },
            );
        }
        Ok(view)
    }

    /// A command's current view, for maintenance window tasks that wait
    /// for it.
    pub(crate) fn command_status(
        &self,
        account: &str,
        region: &str,
        command_id: &str,
    ) -> Option<(types::Command, Vec<Invocation>)> {
        let st = self.lock();
        let r = st
            .region_ref(account, region)?
            .commands
            .iter()
            .find(|c| c.command.command_id.as_deref() == Some(command_id))?;
        Some((command_view(r), r.invocations.clone()))
    }

    /// Change one invocation, unless it was cancelled.
    fn update_invocation(
        &self,
        account: &str,
        region: &str,
        command_id: &str,
        instance: &str,
        f: impl FnOnce(&mut Invocation),
    ) -> bool {
        let mut st = self.lock();
        let r = st.region(account, region);
        let Some(rec) = r.commands.iter_mut().find(|c| c.command.command_id.as_deref() == Some(command_id)) else {
            return false;
        };
        let Some(inv) = rec.invocations.iter_mut().find(|i| i.instance_id == instance) else { return false };
        if inv.status == "Cancelled" {
            return false;
        }
        f(inv);
        true
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_invocation(
        &self,
        account: &str,
        region: &str,
        command_id: &str,
        instance: &str,
        platform: &str,
        steps: Vec<Step>,
        requested: DateTime<Utc>,
    ) {
        let started = std::time::Instant::now();
        let clock = |_: ()| requested + chrono::Duration::from_std(started.elapsed()).unwrap_or_default();
        if !self.update_invocation(account, region, command_id, instance, |i| {
            i.status = "InProgress".into();
            i.status_details = "InProgress".into();
        }) {
            return;
        }
        let nodes = self.managed();
        let mut failed: Option<(&'static str, &'static str)> = None;
        for (n, step) in steps.iter().enumerate() {
            let start = clock(());
            if !self.update_invocation(account, region, command_id, instance, |i| {
                i.plugins[n].status = "InProgress".into();
                i.plugins[n].status_details = "InProgress".into();
                i.plugins[n].start = Some(start);
            }) {
                return;
            }
            let (status, details, code, stdout, stderr) = if failed.is_some() {
                (
                    "Success",
                    "Success",
                    0,
                    "Step execution skipped because a previous step failed.".to_string(),
                    String::new(),
                )
            } else if let Some(reason) = &step.skip {
                ("Success", "Success", 0, reason.clone(), String::new())
            } else {
                match step.action.as_str() {
                    "aws:runShellScript" if platform != "Windows" => {
                        let (script, timeout) = shell_script(&step.inputs);
                        let run = async {
                            match &nodes {
                                Some(m) => m.run_shell(account, region, instance, &script).await,
                                None => Ok(None),
                            }
                        };
                        match tokio::time::timeout(std::time::Duration::from_secs(timeout), run).await {
                            Err(_) => (
                                "TimedOut",
                                "ExecutionTimedOut",
                                -1,
                                String::new(),
                                "failed to run commands: exit status timeout".to_string(),
                            ),
                            Ok(Err(e)) => ("Failed", "Undeliverable", -1, String::new(), e),
                            Ok(Ok(None)) => ("Success", "Success", 0, String::new(), String::new()),
                            Ok(Ok(Some(out))) if out.exit_code == 0 => {
                                ("Success", "Success", 0, out.stdout, out.stderr)
                            }
                            Ok(Ok(Some(out))) => {
                                let stderr =
                                    format!("{}failed to run commands: exit status {}", out.stderr, out.exit_code);
                                ("Failed", "Failed", out.exit_code, out.stdout, stderr)
                            }
                        }
                    }
                    "aws:runShellScript" | "aws:runPowerShellScript" | "aws:psModule" | "aws:applications" => (
                        "Failed",
                        "Failed",
                        1,
                        String::new(),
                        format!("Step {} is not supported on the {platform} platform.", step.action),
                    ),
                    other => (
                        "Success",
                        "Success",
                        0,
                        format!("MWS does not run {other} steps; the step reports success without doing anything."),
                        String::new(),
                    ),
                }
            };
            if failed.is_none() && status != "Success" {
                failed = Some((status, details));
            }
            let end = clock(());
            if !self.update_invocation(account, region, command_id, instance, |i| {
                let p = &mut i.plugins[n];
                p.status = status.into();
                p.status_details = details.into();
                p.response_code = code;
                p.end = Some(end);
                p.stdout = stdout;
                p.stderr = stderr;
            }) {
                return;
            }
        }
        let (status, details) = failed.unwrap_or(("Success", "Success"));
        self.update_invocation(account, region, command_id, instance, |i| {
            i.status = status.into();
            i.status_details = details.into();
        });
    }

    fn command_record(&self, ctx: &RequestContext, id: &str) -> Option<CommandRecord> {
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region)?
            .commands
            .iter()
            .find(|c| c.command.command_id.as_deref() == Some(id))
            .cloned()
    }

    fn all_commands(&self, ctx: &RequestContext) -> Vec<CommandRecord> {
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region).map(|r| r.commands.clone()).unwrap_or_default()
    }

    fn command_filters(filters: &[types::CommandFilter]) -> Result<(), ServiceError> {
        for f in filters {
            match f.key.as_str() {
                "InvokedAfter" | "InvokedBefore" => {
                    DateTime::parse_from_rfc3339(&f.value).map_err(|_| {
                        errors::invalid_filter_value(format!("{} is not a valid value for {}.", f.value, f.key))
                    })?;
                }
                "Status" | "ExecutionStage" | "DocumentName" => {}
                _ => return Err(errors::invalid_filter_key("The specified key isn't valid.")),
            }
        }
        Ok(())
    }

    fn command_matches(r: &CommandRecord, filters: &[types::CommandFilter], invocation_status: Option<&str>) -> bool {
        let view = command_view(r);
        filters.iter().all(|f| match f.key.as_str() {
            "InvokedAfter" => {
                DateTime::parse_from_rfc3339(&f.value).is_ok_and(|t| view.requested_date_time.is_some_and(|r| r >= t))
            }
            "InvokedBefore" => {
                DateTime::parse_from_rfc3339(&f.value).is_ok_and(|t| view.requested_date_time.is_some_and(|r| r <= t))
            }
            "Status" => invocation_status.or(view.status.as_deref()) == Some(f.value.as_str()),
            "ExecutionStage" => {
                let complete = !matches!(view.status.as_deref(), Some("Pending" | "InProgress" | "Cancelling"));
                (f.value == "Complete") == complete
            }
            "DocumentName" => view.document_name.as_deref() == Some(f.value.as_str()),
            _ => true,
        })
    }

    pub(crate) fn list_commands(
        &self,
        ctx: &RequestContext,
        input: types::ListCommandsRequest,
    ) -> Result<types::ListCommandsResult, ServiceError> {
        ctx.authorize("ssm:ListCommands", &list_arn(ctx), ConditionContext::new())?;
        let filters = input.filters.unwrap_or_default();
        Self::command_filters(&filters)?;
        let mut records = self.all_commands(ctx);
        if let Some(id) = &input.command_id {
            records.retain(|c| c.command.command_id.as_deref() == Some(id.as_str()));
            if records.is_empty() {
                return Err(errors::invalid_command_id(""));
            }
        }
        if let Some(i) = &input.instance_id {
            records.retain(|c| c.invocations.iter().any(|x| &x.instance_id == i));
        }
        records.retain(|r| Self::command_matches(r, &filters, None));
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(records, input.next_token.as_deref(), limit)?;
        Ok(types::ListCommandsResult { commands: Some(items.iter().map(command_view).collect()), next_token: next })
    }

    pub(crate) fn list_command_invocations(
        &self,
        ctx: &RequestContext,
        input: types::ListCommandInvocationsRequest,
    ) -> Result<types::ListCommandInvocationsResult, ServiceError> {
        ctx.authorize("ssm:ListCommandInvocations", &list_arn(ctx), ConditionContext::new())?;
        let filters = input.filters.unwrap_or_default();
        Self::command_filters(&filters)?;
        let mut records = self.all_commands(ctx);
        if let Some(id) = &input.command_id {
            records.retain(|c| c.command.command_id.as_deref() == Some(id.as_str()));
            if records.is_empty() {
                return Err(errors::invalid_command_id(""));
            }
        }
        let mut out = Vec::new();
        for r in &records {
            for i in &r.invocations {
                if input.instance_id.as_ref().is_some_and(|x| x != &i.instance_id) {
                    continue;
                }
                if Self::command_matches(r, &filters, Some(&i.status)) {
                    out.push(invocation_view(r, i, input.details));
                }
            }
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(out, input.next_token.as_deref(), limit)?;
        Ok(types::ListCommandInvocationsResult { command_invocations: Some(items), next_token: next })
    }

    pub(crate) fn get_command_invocation(
        &self,
        ctx: &RequestContext,
        input: types::GetCommandInvocationRequest,
    ) -> Result<types::GetCommandInvocationResult, ServiceError> {
        ctx.authorize("ssm:GetCommandInvocation", &list_arn(ctx), ConditionContext::new())?;
        if uuid::Uuid::parse_str(&input.command_id).is_err() {
            return Err(errors::invalid_command_id(""));
        }
        let r = self.command_record(ctx, &input.command_id).ok_or_else(|| errors::invocation_does_not_exist(""))?;
        let i = r
            .invocations
            .iter()
            .find(|i| i.instance_id == input.instance_id)
            .ok_or_else(|| errors::invocation_does_not_exist(""))?;
        let plugin = match &input.plugin_name {
            Some(name) => i.plugins.iter().find(|p| &p.name == name).ok_or_else(|| errors::invalid_plugin_name(""))?,
            None if i.plugins.len() == 1 => &i.plugins[0],
            None if i.plugins.is_empty() => {
                return Ok(types::GetCommandInvocationResult {
                    command_id: r.command.command_id.clone(),
                    instance_id: Some(i.instance_id.clone()),
                    status: Some(i.status.clone()),
                    status_details: Some(i.status_details.clone()),
                    response_code: -1,
                    ..Default::default()
                })
            }
            None => return Err(errors::invalid_plugin_name("")),
        };
        let elapsed = match (plugin.start, plugin.end) {
            (Some(s), Some(e)) => {
                let ms = (e - s).num_milliseconds().max(0);
                format!("PT{}.{:03}S", ms / 1000, ms % 1000)
            }
            _ => String::new(),
        };
        let c = &r.command;
        Ok(types::GetCommandInvocationResult {
            command_id: c.command_id.clone(),
            instance_id: Some(i.instance_id.clone()),
            comment: c.comment.clone(),
            document_name: c.document_name.clone(),
            document_version: c.document_version.clone(),
            plugin_name: Some(plugin.name.clone()),
            response_code: plugin.response_code,
            execution_start_date_time: Some(plugin.start.map(iso).unwrap_or_default()),
            execution_elapsed_time: Some(elapsed),
            execution_end_date_time: Some(plugin.end.map(iso).unwrap_or_default()),
            status: Some(if i.status == "Cancelled" { i.status.clone() } else { plugin.status.clone() }),
            status_details: Some(if i.status == "Cancelled" {
                i.status_details.clone()
            } else {
                plugin.status_details.clone()
            }),
            standard_output_content: Some(truncate(&plugin.stdout, MAX_CONTENT)),
            standard_output_url: Some(String::new()),
            standard_error_content: Some(truncate(&plugin.stderr, MAX_CONTENT)),
            standard_error_url: Some(String::new()),
            cloud_watch_output_config: c.cloud_watch_output_config.clone(),
        })
    }

    pub(crate) fn cancel_command(
        &self,
        ctx: &RequestContext,
        input: types::CancelCommandRequest,
    ) -> Result<types::CancelCommandResult, ServiceError> {
        ctx.authorize("ssm:CancelCommand", &list_arn(ctx), ConditionContext::new())?;
        if uuid::Uuid::parse_str(&input.command_id).is_err() {
            return Err(errors::invalid_command_id(""));
        }
        let only = input.instance_ids.unwrap_or_default();
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let rec = region
            .commands
            .iter_mut()
            .find(|c| c.command.command_id.as_deref() == Some(input.command_id.as_str()))
            .ok_or_else(|| errors::invalid_command_id(""))?;
        if let Some(bad) = only.iter().find(|i| !rec.invocations.iter().any(|x| &x.instance_id == *i)) {
            return Err(errors::invalid_instance_id(format!("Instance {bad} is not a target of the command.")));
        }
        for inv in rec.invocations.iter_mut() {
            if (only.is_empty() || only.contains(&inv.instance_id)) && !inv.done() {
                inv.status = "Cancelled".into();
                inv.status_details = "Cancelled".into();
                for p in inv.plugins.iter_mut().filter(|p| matches!(p.status.as_str(), "Pending" | "InProgress")) {
                    p.status = "Cancelled".into();
                    p.status_details = "Cancelled".into();
                }
            }
        }
        if only.is_empty() && rec.invocations.iter().all(|i| i.status == "Cancelled") {
            rec.command.status = Some("Cancelled".into());
        }
        Ok(types::CancelCommandResult::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_expand_lists() {
        let doc: Value = serde_json::from_str(crate::documents::RUN_SHELL_SCRIPT_FOR_TESTS).unwrap();
        let mut given = BTreeMap::new();
        given.insert("commands".to_string(), vec!["echo a".to_string(), "echo b".to_string()]);
        let (params, lists) = resolve_parameters(&doc, &given).unwrap();
        let s = steps(&doc, &params, &lists, "Linux");
        assert_eq!(s.len(), 1);
        let (script, timeout) = shell_script(&s[0].inputs);
        assert_eq!(script, "echo a\necho b");
        assert_eq!(timeout, 3600);
        assert!(resolve_parameters(&doc, &BTreeMap::new()).is_err());
        let mut unknown = given.clone();
        unknown.insert("nope".into(), vec!["x".into()]);
        assert!(resolve_parameters(&doc, &unknown).is_err());
    }

    #[test]
    fn preconditions_skip_other_platforms() {
        let doc: Value = serde_json::from_str(
            r#"{"schemaVersion":"2.2","mainSteps":[{"action":"aws:runPowerShellScript","name":"win","precondition":{"StringEquals":["platformType","Windows"]},"inputs":{"runCommand":["dir"]}}]}"#,
        )
        .unwrap();
        let s = steps(&doc, &BTreeMap::new(), &[], "Linux");
        assert!(s[0].skip.is_some());
    }
}
