//! The Automation engine: runs a runbook's steps in order (or as
//! `nextStep`, `isEnd`, `onFailure` and `aws:branch` direct), with
//! retries, timeouts and cancellation on the emulated clock, and each
//! action doing what AWS's does through the other services' APIs.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use mws_core::{Caller, RequestContext};
use serde_json::{json, Map, Value};

use crate::automation::{
    execution_arn, rate, resolve_parameters, strings_of, ScriptCredentials, Signal, StartSpec, TERMINAL,
};
use crate::generated::types;
use crate::Ssm;

/// Steps without a timeout of their own give up after a week.
const MAX_WAIT_SECONDS: i64 = 7 * 24 * 3600;

pub(crate) struct Run {
    pub account: String,
    pub region: String,
    pub id: String,
    /// The identity steps run as.
    pub ctx: RequestContext,
    pub creds: Option<ScriptCredentials>,
    pub vars: BTreeMap<String, Value>,
    pub mode: String,
}

#[derive(Debug, Default)]
struct StepResult {
    /// `Success`, `Failed`, `TimedOut` or `Cancelled`.
    status: &'static str,
    outputs: BTreeMap<String, Value>,
    next: Option<String>,
    message: String,
    response: Option<String>,
    failure_type: Option<String>,
}

impl StepResult {
    fn ok(outputs: BTreeMap<String, Value>) -> Self {
        Self { status: "Success", outputs, ..Default::default() }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            status: "Failed",
            message: message.into(),
            failure_type: Some("Verification".into()),
            ..Default::default()
        }
    }
}

/// A fan-out child: its identity, parameters, target value and targets.
type Child = (RequestContext, BTreeMap<String, Vec<String>>, Option<String>, Vec<types::Target>);

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The impact a step would have, for execution previews.
pub(crate) fn impact(step: &Value) -> &'static str {
    let action = step.get("action").and_then(Value::as_str).unwrap_or_default();
    match action {
        "aws:executeAwsApi" => {
            let api = step.get("inputs").and_then(|i| i.get("Api")).and_then(Value::as_str).unwrap_or_default();
            let api = pascal(api);
            if ["Describe", "Get", "List", "Head", "Lookup", "Search", "Query", "Scan", "Select"]
                .iter()
                .any(|p| api.starts_with(p))
            {
                "NonMutating"
            } else {
                "Mutating"
            }
        }
        "aws:waitForAwsResourceProperty"
        | "aws:assertAwsResourceProperty"
        | "aws:sleep"
        | "aws:pause"
        | "aws:approve"
        | "aws:branch"
        | "aws:updateVariable" => "NonMutating",
        "aws:changeInstanceState"
        | "aws:runInstances"
        | "aws:createImage"
        | "aws:deleteImage"
        | "aws:copyImage"
        | "aws:createTags"
        | "aws:createStack"
        | "aws:deleteStack" => "Mutating",
        _ => "Undetermined",
    }
}

/// `describe_instances` or `describeInstances` as `DescribeInstances`.
fn pascal(api: &str) -> String {
    if api.contains('_') {
        return api
            .split('_')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let mut c = p.chars();
                c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
            })
            .collect();
    }
    let mut c = api.chars();
    c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
}

/// Whether `caller` is among `approvers` (user or role ARNs or names; an
/// assumed-role session counts as its role).
pub(crate) fn is_approver(caller: &Caller, approvers: &[String]) -> bool {
    if approvers.is_empty() {
        return true;
    }
    let mut names = vec![caller.arn.clone()];
    if let Some(rest) = caller.arn.split_once(":assumed-role/").map(|(_, r)| r) {
        let role = rest.split('/').next().unwrap_or_default();
        let partition = caller.arn.split(':').nth(1).unwrap_or("aws");
        names.push(format!("arn:{partition}:iam::{}:role/{role}", caller.account_id));
        names.push(role.to_string());
    }
    if let Some(user) = caller.arn.split_once(":user/").map(|(_, u)| u) {
        names.push(user.rsplit('/').next().unwrap_or(user).to_string());
    }
    if caller.arn.ends_with(":root") {
        names.push(caller.account_id.clone());
    }
    approvers.iter().any(|a| names.iter().any(|n| n == a))
}

/// Evaluate a JSONPath selector (`$.A.B[0]`, `$.A[*].B`, `$..B`) on `v`.
pub(crate) fn select(v: &Value, path: &str) -> Option<Value> {
    let path = path.trim();
    let rest = path.strip_prefix('$').unwrap_or(path);
    let mut current = vec![v.clone()];
    let mut wildcard = false;
    let chars: Vec<char> = rest.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '.' if chars.get(i + 1) == Some(&'.') => {
                i += 2;
                let start = i;
                while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
                    i += 1;
                }
                let key: String = chars[start..i].iter().collect();
                let mut found = Vec::new();
                for c in &current {
                    descend(c, &key, &mut found);
                }
                current = found;
                wildcard = true;
            }
            '.' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
                    i += 1;
                }
                let key: String = chars[start..i].iter().collect();
                if key == "*" {
                    current = current
                        .iter()
                        .flat_map(|c| match c {
                            Value::Object(m) => m.values().cloned().collect::<Vec<_>>(),
                            Value::Array(a) => a.clone(),
                            _ => Vec::new(),
                        })
                        .collect();
                    wildcard = true;
                } else {
                    current = current.iter().filter_map(|c| c.get(&key).cloned()).collect();
                }
            }
            '[' => {
                let start = i + 1;
                while i < chars.len() && chars[i] != ']' {
                    i += 1;
                }
                let inner: String = chars[start..i.min(chars.len())].iter().collect();
                i += 1;
                let inner = inner.trim();
                if inner == "*" || inner.is_empty() {
                    current = current.iter().flat_map(|c| c.as_array().cloned().unwrap_or_default()).collect();
                    wildcard = true;
                } else if let Ok(n) = inner.parse::<i64>() {
                    current = current
                        .iter()
                        .filter_map(|c| {
                            let a = c.as_array()?;
                            let idx = if n < 0 { a.len() as i64 + n } else { n };
                            a.get(usize::try_from(idx).ok()?).cloned()
                        })
                        .collect();
                } else {
                    let key = inner.trim_matches(|c| c == '\'' || c == '"');
                    current = current.iter().filter_map(|c| c.get(key).cloned()).collect();
                }
            }
            _ => i += 1,
        }
    }
    if wildcard {
        Some(Value::Array(current))
    } else {
        current.into_iter().next()
    }
}

fn descend(v: &Value, key: &str, out: &mut Vec<Value>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == key {
                    out.push(x.clone());
                }
                descend(x, key, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| descend(x, key, out)),
        _ => {}
    }
}

/// `v` as the output type a runbook declares.
pub(crate) fn coerce(v: Value, kind: &str) -> Value {
    let scalar = |v: &Value| -> Value {
        match v {
            Value::Array(a) if a.len() == 1 => a[0].clone(),
            other => other.clone(),
        }
    };
    match kind {
        "Integer" => match scalar(&v) {
            Value::String(s) => s.trim().parse::<i64>().map(Value::from).unwrap_or(Value::String(s)),
            other => other,
        },
        "Boolean" => match scalar(&v) {
            Value::String(s) => Value::Bool(s.eq_ignore_ascii_case("true")),
            other => other,
        },
        "StringList" => Value::Array(strings_of(&v).into_iter().map(Value::String).collect()),
        "StringMap" | "MapList" => v,
        _ => match scalar(&v) {
            Value::String(s) => Value::String(s),
            Value::Null => Value::String(String::new()),
            other => Value::String(other.to_string()),
        },
    }
}

/// Replace `{{ name }}` placeholders in `v` with values from `vars`. A
/// string that is just one placeholder takes the value's own type.
pub(crate) fn substitute(v: &Value, vars: &BTreeMap<String, Value>) -> Value {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\{\{\s*([^{}\s]+)\s*\}\}").expect("valid regex"));
    match v {
        Value::String(s) => {
            if let Some(c) = re.captures(s) {
                if c.get(0).map(|m| m.as_str().len()) == Some(s.trim().len()) && s.trim() == &c[0] {
                    if let Some(val) = vars.get(&c[1]) {
                        return val.clone();
                    }
                }
            }
            Value::String(
                re.replace_all(s, |c: &regex::Captures| match vars.get(&c[1]) {
                    Some(Value::String(x)) => x.clone(),
                    Some(other) => other.to_string(),
                    None => c[0].to_string(),
                })
                .into_owned(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute(x, vars)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), substitute(x, vars))).collect()),
        other => other.clone(),
    }
}

/// The `{{ssm:name}}` parameter references in `v`.
fn ssm_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            let mut rest = s.as_str();
            while let Some(start) = rest.find("{{") {
                let after = &rest[start + 2..];
                let Some(end) = after.find("}}") else { break };
                let inner = after[..end].trim();
                if let Some(name) = inner.strip_prefix("ssm:") {
                    let key = format!("ssm:{name}");
                    if !out.contains(&key) {
                        out.push(key);
                    }
                }
                rest = &after[end + 2..];
            }
        }
        Value::Array(a) => a.iter().for_each(|x| ssm_refs(x, out)),
        Value::Object(m) => m.values().for_each(|x| ssm_refs(x, out)),
        _ => {}
    }
}

/// An ISO 8601 duration (`PT10M`, `P1DT2H30S`) in seconds.
fn iso_duration(s: &str) -> Option<i64> {
    let s = s.trim().strip_prefix('P')?;
    let (date, time) = s.split_once('T').unwrap_or((s, ""));
    let mut total = 0i64;
    let mut num = String::new();
    for c in date.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: i64 = num.parse().ok()?;
            num.clear();
            total += n * match c {
                'Y' => 365 * 86400,
                'M' => 30 * 86400,
                'W' => 7 * 86400,
                'D' => 86400,
                _ => return None,
            };
        }
    }
    for c in time.chars() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
        } else {
            let n: f64 = num.parse().ok()?;
            num.clear();
            total += (n * match c {
                'H' => 3600.0,
                'M' => 60.0,
                'S' => 1.0,
                _ => return None,
            }) as i64;
        }
    }
    Some(total)
}

fn input_str(inputs: &Value, key: &str) -> Option<String> {
    match inputs.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn input_list(inputs: &Value, key: &str) -> Vec<String> {
    inputs.get(key).map(strings_of).unwrap_or_default()
}

/// A step's inputs without the keys that steer the action, as an API
/// request.
fn api_input(inputs: &Value, skip: &[&str]) -> Value {
    let mut m = inputs.as_object().cloned().unwrap_or_default();
    for k in skip {
        m.remove(*k);
    }
    Value::Object(m)
}

impl Ssm {
    pub(crate) fn clock_now(&self) -> DateTime<Utc> {
        let offset = self.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed);
        Utc::now() + chrono::Duration::milliseconds(offset)
    }

    /// Resolve once the emulated clock reaches `t`.
    async fn until(&self, t: DateTime<Utc>) {
        while self.clock_now() < t {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Resolve once `StopAutomationExecution` cancels the execution.
    async fn until_cancelled(&self, run_account: &str, run_region: &str, id: &str) {
        loop {
            let stop = self.automation(run_account, run_region, id).and_then(|r| r.stop);
            if stop.as_deref() == Some("Cancel") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn take_signal(&self, run: &Run, wanted: &[&str]) -> Option<Signal> {
        self.update_automation(&run.account, &run.region, &run.id, |r| {
            let pos = r.signals.iter().position(|s| wanted.contains(&s.signal_type.as_str()))?;
            Some(r.signals.remove(pos))
        })
        .flatten()
    }

    fn set_status(&self, run: &Run, status: &str) {
        self.update_automation(&run.account, &run.region, &run.id, |r| {
            let current = r.execution.automation_execution_status.clone().unwrap_or_default();
            if current != "Cancelling" || status == "Cancelled" {
                r.execution.automation_execution_status = Some(status.into());
            }
        });
        self.mirror_ops_item_status(run, status);
    }

    /// Finish the execution with `status`.
    fn finish(&self, run: &Run, status: &str, message: Option<String>, outputs: BTreeMap<String, Vec<String>>) {
        let end = self.clock_now();
        self.update_automation(&run.account, &run.region, &run.id, |r| {
            r.execution.automation_execution_status = Some(status.into());
            r.execution.execution_end_time = Some(end);
            r.execution.current_step_name = None;
            r.execution.current_action = None;
            if let Some(m) = message {
                r.execution.failure_message = Some(m);
            }
            if !outputs.is_empty() {
                r.execution.outputs = Some(outputs);
            }
            let vars: BTreeMap<String, Vec<String>> = run
                .vars
                .iter()
                .filter_map(|(k, v)| k.strip_prefix("variable:").map(|n| (n.to_string(), strings_of(v))))
                .collect();
            if !vars.is_empty() {
                r.execution.variables = Some(vars);
            }
            for s in r.execution.step_executions.iter_mut().flatten() {
                if matches!(s.step_status.as_deref(), Some("InProgress" | "Waiting")) {
                    s.step_status = Some("Cancelled".into());
                    s.execution_end_time = Some(end);
                }
            }
        });
        let ops = if status == "Success" { "CompletedWithSuccess" } else { status };
        self.mirror_ops_item_status(run, if status == "Failed" { "CompletedWithFailure" } else { ops });
    }

    fn base_vars(&self, run: &mut Run, document: &str) {
        let now = self.clock_now();
        let v = &mut run.vars;
        v.insert("automation:EXECUTION_ID".into(), Value::String(run.id.clone()));
        v.insert("automation:DOCUMENT_NAME".into(), Value::String(document.into()));
        v.insert("global:ACCOUNT_ID".into(), Value::String(run.account.clone()));
        v.insert("global:REGION".into(), Value::String(run.region.clone()));
        v.insert("global:AWS_PARTITION".into(), Value::String(run.ctx.partition.clone()));
        v.insert("global:DATE".into(), Value::String(now.format("%Y-%m-%d").to_string()));
        v.insert("global:DATE_TIME".into(), Value::String(now.format("%Y-%m-%d_%H.%M.%S").to_string()));
    }

    /// Run a plain execution of `content`.
    pub(crate) async fn run_automation_execution(&self, ctx: RequestContext, id: String, content: Value) {
        let Some(rec) = self.automation(&ctx.caller.account_id, &ctx.region, &id) else { return };
        let mut run = Run {
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            id: id.clone(),
            ctx: ctx.clone(),
            creds: None,
            vars: BTreeMap::new(),
            mode: rec.execution.mode.clone().unwrap_or_else(|| "Auto".into()),
        };
        let document = rec.execution.document_name.clone().unwrap_or_default();
        self.base_vars(&mut run, &document);
        let params = rec.execution.parameters.clone().unwrap_or_default();
        match resolve_parameters(&content, &params, None) {
            Ok((typed, _)) => run.vars.extend(typed),
            Err(e) => return self.finish(&run, "Failed", Some(e.message), BTreeMap::new()),
        }
        for (k, v) in content.get("variables").and_then(Value::as_object).into_iter().flatten() {
            run.vars.insert(format!("variable:{k}"), v.get("default").cloned().unwrap_or(Value::Null));
        }
        let Some(runtime) = self.runtime() else {
            return self.finish(&run, "Failed", Some("Automation is not available.".into()), BTreeMap::new());
        };
        let role = content.get("assumeRole").map(|r| substitute(r, &run.vars)).map(|r| strings_of(&r).join(""));
        match role.filter(|r| !r.trim().is_empty()) {
            Some(role) => {
                let arn = execution_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &id);
                match runtime.assume_role(&ctx, role.trim(), &arn) {
                    Ok((c, creds)) => {
                        run.ctx = c;
                        run.creds = Some(creds);
                    }
                    Err(_) => {
                        return self.finish(
                            &run,
                            "Failed",
                            Some("The defined assume role is unable to be assumed.".into()),
                            BTreeMap::new(),
                        )
                    }
                }
            }
            None => run.creds = runtime.credentials_of(&ctx),
        }
        self.set_status(&run, "InProgress");
        let steps = content.get("mainSteps").and_then(Value::as_array).cloned().unwrap_or_default();
        self.seed_steps(&run, &steps);
        let status = self.run_steps(&mut run, steps).await;
        let mut outputs = BTreeMap::new();
        for o in content.get("outputs").and_then(Value::as_array).into_iter().flatten() {
            if let Some(name) = o.as_str() {
                outputs.insert(name.to_string(), run.vars.get(name).map(strings_of).unwrap_or_default());
            }
        }
        let message = match status {
            "Failed" | "TimedOut" => self.failure_summary(&run),
            _ => None,
        };
        self.finish(&run, status, message, outputs);
    }

    fn failure_summary(&self, run: &Run) -> Option<String> {
        let rec = self.automation(&run.account, &run.region, &run.id)?;
        let step = rec
            .execution
            .step_executions
            .iter()
            .flatten()
            .rev()
            .find(|s| matches!(s.step_status.as_deref(), Some("Failed" | "TimedOut")))?;
        Some(format!(
            "Step fails when it is {}. {}. Please refer to Automation Service Troubleshooting Guide for more diagnosis details.",
            if step.step_status.as_deref() == Some("TimedOut") { "Timed Out" } else { "Executing/Canceling action" },
            step.failure_message.clone().unwrap_or_default()
        ))
    }

    /// List every top-level step as `Pending`.
    fn seed_steps(&self, run: &Run, steps: &[Value]) {
        let list: Vec<types::StepExecution> = steps.iter().map(|s| step_view(s, "Pending")).collect();
        self.update_automation(&run.account, &run.region, &run.id, |r| {
            r.execution.step_executions = Some(list);
            counters(r);
        });
    }

    /// Update (or add) the newest execution of step `name`.
    fn put_step(&self, run: &Run, name: &str, f: impl FnOnce(&mut types::StepExecution)) {
        self.update_automation(&run.account, &run.region, &run.id, |r| {
            let list = r.execution.step_executions.get_or_insert_with(Vec::new);
            let idx = list.iter().rposition(|s| s.step_name.as_deref() == Some(name));
            match idx {
                Some(i) => f(&mut list[i]),
                None => {
                    let mut s = types::StepExecution { step_name: Some(name.into()), ..Default::default() };
                    f(&mut s);
                    list.push(s);
                }
            }
            counters(r);
        });
    }

    fn run_steps<'a>(&'a self, run: &'a mut Run, steps: Vec<Value>) -> BoxFut<'a, &'static str> {
        Box::pin(async move {
            let mut i = 0usize;
            let mut failed = false;
            let names: Vec<String> =
                steps.iter().map(|s| s.get("name").and_then(Value::as_str).unwrap_or_default().to_string()).collect();
            let mut guard = 0usize;
            while i < steps.len() {
                guard += 1;
                if guard > 10_000 {
                    return "Failed";
                }
                if let Some(stop) = self.automation(&run.account, &run.region, &run.id).and_then(|r| r.stop) {
                    return if stop == "Cancel" {
                        "Cancelled"
                    } else if failed {
                        "CompletedWithFailure"
                    } else {
                        "CompletedWithSuccess"
                    };
                }
                if let Some(alarms) = self.triggered_alarms(run).await {
                    self.update_automation(&run.account, &run.region, &run.id, |r| {
                        r.execution.triggered_alarms = Some(alarms)
                    });
                    return "Cancelled";
                }
                let step = &steps[i];
                let name = names[i].clone();
                let action = step.get("action").and_then(Value::as_str).unwrap_or_default().to_string();
                if run.mode == "Interactive" {
                    self.set_status(run, "Waiting");
                    let signal = loop {
                        if let Some(s) = self.take_signal(run, &["StartStep", "StopStep"]) {
                            if s.payload.get("StepName").and_then(|v| v.first()) == Some(&name) {
                                break Some(s);
                            }
                        }
                        let stopped =
                            self.automation(&run.account, &run.region, &run.id).and_then(|r| r.stop).is_some();
                        if stopped {
                            break None;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    };
                    let Some(signal) = signal else { continue };
                    self.set_status(run, "InProgress");
                    if signal.signal_type == "StopStep" {
                        self.put_step(run, &name, |s| s.step_status = Some("Cancelled".into()));
                        i += 1;
                        continue;
                    }
                    if let Some(overrides) = signal.payload.get("ParameterOverrides").cloned() {
                        let _ = overrides;
                    }
                }
                let result = self.run_step(run, step, &name, &action).await;
                let is_end = step.get("isEnd").and_then(Value::as_bool).unwrap_or(false);
                let next_step = step.get("nextStep").and_then(Value::as_str).map(str::to_string);
                let goto = |target: &str| names.iter().position(|n| n == target);
                if result.status == "Success" {
                    for (k, v) in result.outputs {
                        run.vars.insert(format!("{name}.{k}"), v);
                    }
                    if let Some(n) = result.next.or(next_step) {
                        match goto(&n) {
                            Some(j) => i = j,
                            None => return if failed { "Failed" } else { "Success" },
                        }
                        continue;
                    }
                    if is_end {
                        break;
                    }
                    i += 1;
                    continue;
                }
                if result.status == "Cancelled" {
                    return "Cancelled";
                }
                let critical = step.get("isCritical").and_then(Value::as_bool).unwrap_or(true);
                let on_failure = step.get("onFailure").and_then(Value::as_str).unwrap_or("Abort");
                if critical {
                    failed = true;
                }
                match on_failure {
                    "Continue" => {
                        if let Some(j) = next_step.as_deref().and_then(goto) {
                            i = j;
                        } else if is_end {
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    s if s.starts_with("step:") => match goto(&s[5..]) {
                        Some(j) => i = j,
                        None => return result.status,
                    },
                    _ => {
                        return if result.status == "TimedOut" { "TimedOut" } else { "Failed" };
                    }
                }
            }
            if failed {
                "Failed"
            } else {
                "Success"
            }
        })
    }

    /// Check the execution's CloudWatch alarms; the alarms in `ALARM`.
    async fn triggered_alarms(&self, run: &Run) -> Option<Vec<types::AlarmStateInformation>> {
        let config = self.automation(&run.account, &run.region, &run.id)?.execution.alarm_configuration?;
        if config.alarms.is_empty() {
            return None;
        }
        let names: Vec<String> = config.alarms.iter().map(|a| a.name.clone()).collect();
        let out = self.api(run, "cloudwatch", "DescribeAlarms", json!({ "AlarmNames": names })).await;
        let out = match out {
            Ok(v) => v,
            Err(_) if config.ignore_poll_alarm_failure => return None,
            Err(_) => {
                return Some(
                    names
                        .into_iter()
                        .map(|n| types::AlarmStateInformation { name: n, state: "UNKNOWN".into() })
                        .collect(),
                )
            }
        };
        let firing: Vec<types::AlarmStateInformation> = out
            .get("MetricAlarms")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(out.get("CompositeAlarms").and_then(Value::as_array).into_iter().flatten())
            .filter(|a| a.get("StateValue").and_then(Value::as_str) == Some("ALARM"))
            .map(|a| types::AlarmStateInformation {
                name: a.get("AlarmName").and_then(Value::as_str).unwrap_or_default().into(),
                state: "ALARM".into(),
            })
            .collect();
        (!firing.is_empty()).then_some(firing)
    }

    async fn run_step(&self, run: &mut Run, step: &Value, name: &str, action: &str) -> StepResult {
        let max_attempts = step.get("maxAttempts").and_then(Value::as_i64).unwrap_or(1).max(1);
        let timeout = step.get("timeoutSeconds").and_then(Value::as_i64);
        let start = self.clock_now();
        self.update_automation(&run.account, &run.region, &run.id, |r| {
            r.execution.current_step_name = Some(name.into());
            r.execution.current_action = Some(action.into());
        });
        let mut result = StepResult::failed("The step did not run.");
        let mut shown_inputs = BTreeMap::new();
        for attempt in 1..=max_attempts {
            self.base_vars_refresh(run);
            let raw = step.get("inputs").cloned().unwrap_or_else(|| json!({}));
            if let Err(e) = self.resolve_ssm_refs(run, &raw).await {
                result = StepResult::failed(e);
                break;
            }
            let inputs = if action == "aws:loop" {
                let mut m = raw.as_object().cloned().unwrap_or_default();
                let steps = m.remove("Steps");
                let mut resolved = substitute(&Value::Object(m), &run.vars);
                if let (Some(s), Some(o)) = (steps, resolved.as_object_mut()) {
                    o.insert("Steps".into(), s);
                }
                resolved
            } else {
                substitute(&raw, &run.vars)
            };
            shown_inputs = inputs
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter(|(k, _)| *k != "Steps")
                        .map(|(k, v)| (k.clone(), serde_json::to_string(v).unwrap_or_default()))
                        .collect()
                })
                .unwrap_or_default();
            let shown = shown_inputs.clone();
            let step_id = uuid::Uuid::new_v4().to_string();
            let template = step_view(step, "InProgress");
            self.put_step(run, name, |s| {
                *s = types::StepExecution {
                    step_execution_id: Some(step_id),
                    execution_start_time: Some(start),
                    inputs: Some(shown),
                    ..template
                };
            });
            let deadline = timeout
                .map(|t| start + chrono::Duration::seconds(t))
                .unwrap_or_else(|| start + chrono::Duration::seconds(MAX_WAIT_SECONDS));
            let (account, region, id) = (run.account.clone(), run.region.clone(), run.id.clone());
            result = tokio::select! {
                r = self.act(run, step, name, action, &inputs) => r,
                _ = self.until(deadline) => StepResult {
                    status: "TimedOut",
                    message: format!("Step timed out while step is verifying the {action} action."),
                    failure_type: Some("Verification".into()),
                    ..Default::default()
                },
                _ = self.until_cancelled(&account, &region, &id) => StepResult {
                    status: "Cancelled",
                    ..Default::default()
                },
            };
            if result.status == "Success" || result.status == "Cancelled" || attempt == max_attempts {
                break;
            }
        }
        let end = self.clock_now();
        let outputs: BTreeMap<String, Vec<String>> =
            result.outputs.iter().map(|(k, v)| (k.clone(), strings_of(v))).collect();
        let status = result.status;
        let message = result.message.clone();
        let response = result.response.clone();
        let failure_type = result.failure_type.clone();
        self.put_step(run, name, |s| {
            s.step_status = Some(status.into());
            s.execution_end_time = Some(end);
            s.outputs = Some(outputs);
            if s.inputs.is_none() {
                s.inputs = Some(shown_inputs);
            }
            s.response = response.or_else(|| (status == "Success").then(String::new));
            s.response_code = None;
            if status != "Success" && status != "Cancelled" {
                s.failure_message = Some(message.clone());
                s.failure_details = Some(types::FailureDetails {
                    failure_stage: Some(if status == "TimedOut" { "Verification" } else { "Invocation" }.into()),
                    failure_type: failure_type.or_else(|| Some("Verification".into())),
                    details: Some(BTreeMap::from([("ExceptionMessage".to_string(), vec![message])])),
                });
            }
        });
        result
    }

    fn base_vars_refresh(&self, run: &mut Run) {
        let now = self.clock_now();
        run.vars.insert("global:DATE".into(), Value::String(now.format("%Y-%m-%d").to_string()));
        run.vars.insert("global:DATE_TIME".into(), Value::String(now.format("%Y-%m-%d_%H.%M.%S").to_string()));
    }

    /// Fetch the Parameter Store values `{{ssm:name}}` references name.
    async fn resolve_ssm_refs(&self, run: &mut Run, v: &Value) -> Result<(), String> {
        let mut refs = Vec::new();
        ssm_refs(v, &mut refs);
        for r in refs {
            if run.vars.contains_key(&r) {
                continue;
            }
            let name = &r[4..];
            let out = self.api(run, "ssm", "GetParameter", json!({ "Name": name })).await?;
            let p = out.get("Parameter").cloned().unwrap_or_default();
            if p.get("Type").and_then(Value::as_str) == Some("SecureString") {
                return Err(format!("SecureString parameter {name} can't be referenced in Automation."));
            }
            let value = p.get("Value").and_then(Value::as_str).unwrap_or_default().to_string();
            let typed = if p.get("Type").and_then(Value::as_str) == Some("StringList") {
                Value::Array(value.split(',').map(|s| Value::String(s.to_string())).collect())
            } else {
                Value::String(value)
            };
            run.vars.insert(r, typed);
        }
        Ok(())
    }

    /// Call another service's API as the run's identity.
    async fn api(&self, run: &Run, service: &str, operation: &str, input: Value) -> Result<Value, String> {
        let Some(runtime) = self.runtime() else { return Err("Automation is not available.".into()) };
        let op = pascal(operation);
        let mut c = run.ctx.clone();
        c.request_id = uuid::Uuid::new_v4().to_string();
        c.received_at = self.clock_now();
        runtime
            .call(&c, &service.to_ascii_lowercase(), &op, input)
            .await
            .map_err(|e| format!("An error occurred ({}) when calling the {op} operation: {}", e.code, e.message))
    }

    async fn act(&self, run: &mut Run, step: &Value, name: &str, action: &str, inputs: &Value) -> StepResult {
        match action {
            "aws:executeAwsApi" => {
                let (Some(service), Some(api)) = (input_str(inputs, "Service"), input_str(inputs, "Api")) else {
                    return StepResult::failed("Service and Api are required inputs.");
                };
                match self.api(run, &service, &api, api_input(inputs, &["Service", "Api"])).await {
                    Ok(resp) => {
                        let mut outputs = BTreeMap::new();
                        for o in step.get("outputs").and_then(Value::as_array).into_iter().flatten() {
                            let (Some(n), Some(sel)) =
                                (o.get("Name").and_then(Value::as_str), o.get("Selector").and_then(Value::as_str))
                            else {
                                continue;
                            };
                            let kind = o.get("Type").and_then(Value::as_str).unwrap_or("String");
                            if let Some(v) = select(&resp, sel) {
                                outputs.insert(n.to_string(), coerce(v, kind));
                            }
                        }
                        let mut r = StepResult::ok(outputs);
                        r.response = Some(String::new());
                        r
                    }
                    Err(e) => StepResult::failed(e),
                }
            }
            "aws:waitForAwsResourceProperty" | "aws:assertAwsResourceProperty" => {
                let (Some(service), Some(api), Some(selector)) =
                    (input_str(inputs, "Service"), input_str(inputs, "Api"), input_str(inputs, "PropertySelector"))
                else {
                    return StepResult::failed("Service, Api and PropertySelector are required inputs.");
                };
                let desired = input_list(inputs, "DesiredValues");
                let request = api_input(inputs, &["Service", "Api", "PropertySelector", "DesiredValues"]);
                loop {
                    let resp = match self.api(run, &service, &api, request.clone()).await {
                        Ok(r) => r,
                        Err(e) => return StepResult::failed(e),
                    };
                    let actual = select(&resp, &selector).map(|v| strings_of(&v)).unwrap_or_default();
                    let matched = !actual.is_empty() && actual.iter().all(|a| desired.contains(a));
                    if matched {
                        return StepResult::ok(BTreeMap::new());
                    }
                    if action == "aws:assertAwsResourceProperty" {
                        return StepResult::failed(format!(
                            "Asserted value {actual:?} is not in the desired values {desired:?}."
                        ));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            "aws:sleep" => {
                let target = if let Some(d) = input_str(inputs, "Duration") {
                    match iso_duration(&d) {
                        Some(s) => self.clock_now() + chrono::Duration::seconds(s),
                        None => return StepResult::failed(format!("Duration {d} is not an ISO 8601 duration.")),
                    }
                } else if let Some(t) = input_str(inputs, "Timestamp") {
                    match DateTime::parse_from_rfc3339(&t) {
                        Ok(t) => t.with_timezone(&Utc),
                        Err(_) => return StepResult::failed(format!("Timestamp {t} is not an ISO 8601 time.")),
                    }
                } else {
                    return StepResult::failed("Duration or Timestamp is required.");
                };
                self.until(target).await;
                StepResult::ok(BTreeMap::new())
            }
            "aws:pause" => {
                self.waiting(run, name, true);
                loop {
                    if self.take_signal(run, &["Resume"]).is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                self.waiting(run, name, false);
                StepResult::ok(BTreeMap::new())
            }
            "aws:approve" => self.approve(run, name, inputs, false).await,
            "aws:runCommand" => self.run_command_step(run, inputs).await,
            "aws:invokeLambdaFunction" => {
                let Some(function) = input_str(inputs, "FunctionName") else {
                    return StepResult::failed("FunctionName is a required input.");
                };
                let payload = match inputs.get("Payload") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => other.to_string(),
                };
                let mut request = json!({ "FunctionName": function });
                for k in ["Qualifier", "InvocationType", "LogType", "ClientContext"] {
                    if let Some(v) = input_str(inputs, k) {
                        request[k] = Value::String(v);
                    }
                }
                if !payload.is_empty() {
                    request["Payload"] = Value::String(base64::engine::general_purpose::STANDARD.encode(payload));
                }
                match self.api(run, "lambda", "Invoke", request).await {
                    Ok(resp) => {
                        let body = resp
                            .get("Payload")
                            .and_then(Value::as_str)
                            .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok())
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or_default();
                        let mut outputs = BTreeMap::new();
                        outputs.insert("StatusCode".into(), resp.get("StatusCode").cloned().unwrap_or(json!(200)));
                        outputs.insert("Payload".into(), Value::String(body.clone()));
                        if let Some(l) = resp.get("LogResult") {
                            outputs.insert("LogResult".into(), l.clone());
                        }
                        if let Some(err) = resp.get("FunctionError").and_then(Value::as_str) {
                            outputs.insert("FunctionError".into(), Value::String(err.into()));
                            let mut r = StepResult::failed(format!("Lambda function returned error {err}: {body}"));
                            r.outputs = outputs;
                            return r;
                        }
                        StepResult::ok(outputs)
                    }
                    Err(e) => StepResult::failed(e),
                }
            }
            "aws:executeScript" => self.execute_script(run, step, inputs).await,
            "aws:branch" => {
                let choices = inputs.get("Choices").and_then(Value::as_array).cloned().unwrap_or_default();
                for c in &choices {
                    if choice_matches(c) {
                        let next = c.get("NextStep").and_then(Value::as_str).map(str::to_string);
                        return StepResult { status: "Success", next, ..Default::default() };
                    }
                }
                match input_str(inputs, "Default") {
                    Some(d) => StepResult { status: "Success", next: Some(d), ..Default::default() },
                    None => StepResult::failed("None of the choices matched and there is no Default step."),
                }
            }
            "aws:executeAutomation" => self.execute_automation_step(run, inputs).await,
            "aws:changeInstanceState" => {
                let ids = input_list(inputs, "InstanceIds");
                let desired = input_str(inputs, "DesiredState").unwrap_or_default();
                let check_only = inputs.get("CheckStateOnly").and_then(Value::as_bool).unwrap_or(false)
                    || input_str(inputs, "CheckStateOnly").as_deref() == Some("true");
                let force = inputs.get("Force").and_then(Value::as_bool).unwrap_or(false);
                if !check_only {
                    let (op, mut req) = match desired.as_str() {
                        "running" => ("StartInstances", json!({ "InstanceIds": ids })),
                        "stopped" => ("StopInstances", json!({ "InstanceIds": ids })),
                        "terminated" => ("TerminateInstances", json!({ "InstanceIds": ids })),
                        other => return StepResult::failed(format!("DesiredState {other} is not valid.")),
                    };
                    if force && op == "StopInstances" {
                        req["Force"] = Value::Bool(true);
                    }
                    if let Err(e) = self.api(run, "ec2", op, req).await {
                        return StepResult::failed(e);
                    }
                }
                match self.wait_instances(run, &ids, &desired).await {
                    Ok(_) => StepResult::ok(BTreeMap::new()),
                    Err(e) => StepResult::failed(e),
                }
            }
            "aws:runInstances" => {
                let mut req = Map::new();
                let copy = |req: &mut Map<String, Value>, from: &str, to: &str| {
                    if let Some(v) = inputs.get(from).filter(|v| !v.is_null()) {
                        req.insert(to.into(), v.clone());
                    }
                };
                for k in [
                    "ImageId",
                    "InstanceType",
                    "KeyName",
                    "SubnetId",
                    "SecurityGroupIds",
                    "UserData",
                    "TagSpecifications",
                    "BlockDeviceMappings",
                    "AdditionalInfo",
                    "ClientToken",
                    "DisableApiTermination",
                    "EbsOptimized",
                    "InstanceInitiatedShutdownBehavior",
                    "PrivateIpAddress",
                    "KernelId",
                    "RamdiskId",
                    "CreditSpecification",
                    "Placement",
                ] {
                    copy(&mut req, k, k);
                }
                req.insert("MinCount".into(), json!(inputs.get("MinInstanceCount").and_then(as_i64).unwrap_or(1)));
                req.insert("MaxCount".into(), json!(inputs.get("MaxInstanceCount").and_then(as_i64).unwrap_or(1)));
                if let Some(n) = input_str(inputs, "IamInstanceProfileName") {
                    req.insert("IamInstanceProfile".into(), json!({ "Name": n }));
                } else if let Some(a) = input_str(inputs, "IamInstanceProfileArn") {
                    req.insert("IamInstanceProfile".into(), json!({ "Arn": a }));
                }
                if let Some(m) = inputs.get("Monitoring").and_then(Value::as_bool) {
                    req.insert("Monitoring".into(), json!({ "Enabled": m }));
                }
                let resp = match self.api(run, "ec2", "RunInstances", Value::Object(req)).await {
                    Ok(r) => r,
                    Err(e) => return StepResult::failed(e),
                };
                let ids: Vec<String> = resp
                    .get("Instances")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|i| i.get("InstanceId").and_then(Value::as_str).map(str::to_string))
                    .collect();
                match self.wait_instances(run, &ids, "running").await {
                    Ok(states) => StepResult::ok(BTreeMap::from([
                        ("InstanceIds".to_string(), json!(ids)),
                        ("InstanceStates".to_string(), json!(states)),
                    ])),
                    Err(e) => StepResult::failed(e),
                }
            }
            "aws:createImage" | "aws:copyImage" => {
                let resp = if action == "aws:createImage" {
                    let mut req = json!({
                        "InstanceId": input_str(inputs, "InstanceId"),
                        "Name": input_str(inputs, "ImageName"),
                    });
                    if let Some(d) = input_str(inputs, "ImageDescription") {
                        req["Description"] = Value::String(d);
                    }
                    if let Some(n) = inputs.get("NoReboot") {
                        req["NoReboot"] = Value::Bool(n.as_bool().unwrap_or(n.as_str() == Some("true")));
                    }
                    if let Some(b) = inputs.get("BlockDeviceMappings") {
                        req["BlockDeviceMappings"] = b.clone();
                    }
                    self.api(run, "ec2", "CreateImage", req).await
                } else {
                    let mut req = json!({
                        "SourceImageId": input_str(inputs, "SourceImageId"),
                        "SourceRegion": input_str(inputs, "SourceRegion"),
                        "Name": input_str(inputs, "ImageName"),
                    });
                    for (from, to) in
                        [("ImageDescription", "Description"), ("KmsKeyId", "KmsKeyId"), ("ClientToken", "ClientToken")]
                    {
                        if let Some(v) = input_str(inputs, from) {
                            req[to] = Value::String(v);
                        }
                    }
                    if let Some(e) = inputs.get("Encrypted").and_then(Value::as_bool) {
                        req["Encrypted"] = Value::Bool(e);
                    }
                    self.api(run, "ec2", "CopyImage", req).await
                };
                let image = match resp {
                    Ok(r) => r.get("ImageId").and_then(Value::as_str).unwrap_or_default().to_string(),
                    Err(e) => return StepResult::failed(e),
                };
                loop {
                    let d = match self.api(run, "ec2", "DescribeImages", json!({ "ImageIds": [image] })).await {
                        Ok(d) => d,
                        Err(e) => return StepResult::failed(e),
                    };
                    let state = select(&d, "$.Images[0].State").and_then(|v| v.as_str().map(str::to_string));
                    match state.as_deref() {
                        Some("available") => {
                            return StepResult::ok(BTreeMap::from([
                                ("ImageId".to_string(), json!(image)),
                                ("ImageState".to_string(), json!("available")),
                            ]))
                        }
                        Some("failed" | "invalid" | "error" | "deregistered") => {
                            return StepResult::failed(format!("Image {image} is {}.", state.unwrap_or_default()))
                        }
                        _ => tokio::time::sleep(Duration::from_millis(500)).await,
                    }
                }
            }
            "aws:deleteImage" => {
                let Some(image) = input_str(inputs, "ImageId") else {
                    return StepResult::failed("ImageId is a required input.");
                };
                let d = match self.api(run, "ec2", "DescribeImages", json!({ "ImageIds": [image] })).await {
                    Ok(d) => d,
                    Err(e) => return StepResult::failed(e),
                };
                let snapshots = select(&d, "$.Images[0].BlockDeviceMappings[*].Ebs.SnapshotId")
                    .map(|v| strings_of(&v))
                    .unwrap_or_default();
                if let Err(e) = self.api(run, "ec2", "DeregisterImage", json!({ "ImageId": image })).await {
                    return StepResult::failed(e);
                }
                for s in snapshots {
                    if let Err(e) = self.api(run, "ec2", "DeleteSnapshot", json!({ "SnapshotId": s })).await {
                        return StepResult::failed(e);
                    }
                }
                StepResult::ok(BTreeMap::new())
            }
            "aws:createTags" => {
                let ids = input_list(inputs, "ResourceIds");
                let tags = inputs.get("Tags").cloned().unwrap_or_else(|| json!([]));
                let kind = input_str(inputs, "ResourceType").unwrap_or_else(|| "EC2".into());
                let r = if kind == "EC2" {
                    self.api(run, "ec2", "CreateTags", json!({ "Resources": ids, "Tags": tags })).await.map(|_| ())
                } else {
                    let mut res = Ok(());
                    for id in &ids {
                        let req = json!({ "ResourceType": kind, "ResourceId": id, "Tags": tags });
                        if let Err(e) = self.api(run, "ssm", "AddTagsToResource", req).await {
                            res = Err(e);
                            break;
                        }
                    }
                    res
                };
                match r {
                    Ok(()) => StepResult::ok(BTreeMap::new()),
                    Err(e) => StepResult::failed(e),
                }
            }
            "aws:createStack" | "aws:deleteStack" => self.stack_step(run, action, inputs).await,
            "aws:updateVariable" => {
                let Some(var) = input_str(inputs, "Name") else {
                    return StepResult::failed("Name is a required input.");
                };
                let key = if var.starts_with("variable:") { var } else { format!("variable:{var}") };
                let value = inputs.get("Value").cloned().unwrap_or(Value::Null);
                run.vars.insert(key, value);
                StepResult::ok(BTreeMap::new())
            }
            "aws:loop" => {
                let steps = inputs.get("Steps").and_then(Value::as_array).cloned().unwrap_or_default();
                let iterators: Vec<Value> = match inputs.get("Iterators") {
                    Some(Value::Array(a)) => a.clone(),
                    Some(Value::Null) | None => Vec::new(),
                    Some(other) => vec![other.clone()],
                };
                let max = inputs.get("MaxIterations").and_then(as_i64).unwrap_or(100).clamp(1, 1000) as usize;
                let mut count = 0usize;
                for (i, v) in iterators.into_iter().enumerate().take(max) {
                    run.vars.insert(format!("{name}.CurrentIteratorValue"), v.clone());
                    run.vars.insert(format!("{name}.CurrentIteration"), json!(i + 1));
                    let status = self.run_steps(run, steps.clone()).await;
                    count = i + 1;
                    if status == "Cancelled" {
                        return StepResult { status: "Cancelled", ..Default::default() };
                    }
                    if status != "Success" {
                        return StepResult::failed(format!("Iteration {} of the loop failed.", i + 1));
                    }
                }
                StepResult::ok(BTreeMap::from([("CurrentIteration".to_string(), json!(count))]))
            }
            "aws:executeStateMachine" => StepResult::failed("MWS does not emulate AWS Step Functions."),
            other => StepResult::failed(format!("The action {other} is not supported by MWS.")),
        }
    }

    /// Mark the execution and step as waiting on a signal (or no longer).
    fn waiting(&self, run: &Run, name: &str, on: bool) {
        let status = if on { "Waiting" } else { "InProgress" };
        self.put_step(run, name, |s| s.step_status = Some(status.into()));
        let rec = self.automation(&run.account, &run.region, &run.id);
        let change = rec.and_then(|r| r.execution.automation_subtype).as_deref() == Some("ChangeRequest");
        if !change {
            self.set_status(run, status);
        }
    }

    async fn approve(&self, run: &mut Run, name: &str, inputs: &Value, change: bool) -> StepResult {
        let approvers: Vec<String> = match inputs.get("Approvers") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| match x {
                    Value::String(s) => Some(s.clone()),
                    Value::Object(o) => o.get("approver").and_then(Value::as_str).map(str::to_string),
                    _ => None,
                })
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        };
        let min = inputs
            .get("MinRequiredApprovals")
            .and_then(as_i64)
            .or_else(|| {
                inputs
                    .get("Approvers")
                    .and_then(Value::as_array)
                    .and_then(|a| a.iter().filter_map(|x| x.get("minRequiredApprovals").and_then(as_i64)).max())
            })
            .unwrap_or(1)
            .max(1) as usize;
        if let Some(topic) = input_str(inputs, "NotificationArn") {
            let message = format!(
                "Automation execution {} is waiting for approval at step {name}. {}",
                run.id,
                input_str(inputs, "Message").unwrap_or_default()
            );
            let _ = self.api(run, "sns", "Publish", json!({ "TopicArn": topic, "Message": message })).await;
        }
        self.waiting(run, name, true);
        if change {
            self.set_status(run, "PendingApproval");
        }
        let mut approved: Vec<String> = Vec::new();
        let mut decisions = Vec::new();
        loop {
            if let Some(s) = self.take_signal(run, &["Approve", "Reject"]) {
                let comment = s.payload.get("Comment").and_then(|c| c.first()).cloned().unwrap_or_default();
                decisions.push(json!({ "Type": s.signal_type, "Approver": s.sender, "Comment": comment }));
                if s.signal_type == "Reject" {
                    self.waiting(run, name, false);
                    let mut r = StepResult::failed("Step execution was rejected by an approver.");
                    r.outputs.insert("ApprovalStatus".into(), json!("Rejected"));
                    r.outputs.insert("ApproverDecisions".into(), Value::Array(decisions));
                    return r;
                }
                if !approved.contains(&s.sender) {
                    approved.push(s.sender);
                }
                if approved.len() >= min.min(approvers.len().max(1)) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let _ = approvers;
        self.waiting(run, name, false);
        StepResult::ok(BTreeMap::from([
            ("ApprovalStatus".to_string(), json!("Approved")),
            ("ApproverDecisions".to_string(), Value::Array(decisions)),
        ]))
    }

    async fn run_command_step(&self, run: &Run, inputs: &Value) -> StepResult {
        let mut req = api_input(inputs, &[]);
        if let Some(Value::Object(params)) = req.get("Parameters").cloned() {
            let fixed: Map<String, Value> = params
                .into_iter()
                .map(|(k, v)| match v {
                    Value::Array(_) => (k, v),
                    Value::String(s) => (k, json!([s])),
                    other => (k, json!([other.to_string()])),
                })
                .collect();
            req["Parameters"] = Value::Object(fixed);
        }
        let resp = match self.api(run, "ssm", "SendCommand", req).await {
            Ok(r) => r,
            Err(e) => return StepResult::failed(e),
        };
        let command = select(&resp, "$.Command.CommandId").and_then(|v| v.as_str().map(str::to_string));
        let Some(command) = command else { return StepResult::failed("SendCommand returned no command.") };
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let Some((c, invocations)) = self.command_status(&run.ctx.caller.account_id, &run.ctx.region, &command)
            else {
                return StepResult::failed(format!("Command {command} disappeared."));
            };
            let status = c.status.clone().unwrap_or_default();
            if matches!(status.as_str(), "Pending" | "InProgress" | "Cancelling") {
                continue;
            }
            let first = invocations.first();
            let code = first.and_then(|i| i.plugins.first()).map(|p| p.response_code).unwrap_or(0);
            let output =
                first.map(|i| i.plugins.iter().map(|p| p.stdout.as_str()).collect::<String>()).unwrap_or_default();
            let outputs = BTreeMap::from([
                ("CommandId".to_string(), json!(command)),
                ("Status".to_string(), json!(status)),
                ("ResponseCode".to_string(), json!(code)),
                ("Output".to_string(), json!(output)),
            ]);
            if status == "Success" {
                return StepResult::ok(outputs);
            }
            let mut r = StepResult::failed(format!("Command {command} finished with status {status}."));
            r.outputs = outputs;
            return r;
        }
    }

    async fn execute_script(&self, run: &Run, step: &Value, inputs: &Value) -> StepResult {
        let runtime = input_str(inputs, "Runtime").unwrap_or_default();
        let handler = input_str(inputs, "Handler").unwrap_or_default();
        let script = input_str(inputs, "Script").unwrap_or_default();
        let payload = inputs.get("InputPayload").cloned().unwrap_or_else(|| json!({}));
        if script.is_empty() {
            return StepResult::failed("Script is a required input (attachments are not supported by MWS).");
        }
        let mut env: Vec<(String, String)> =
            vec![("AWS_REGION".into(), run.region.clone()), ("AWS_DEFAULT_REGION".into(), run.region.clone())];
        if let Some(endpoint) = &run.ctx.endpoint {
            env.push(("AWS_ENDPOINT_URL".into(), endpoint.clone()));
        }
        if let Some(c) = &run.creds {
            env.push(("AWS_ACCESS_KEY_ID".into(), c.access_key_id.clone()));
            env.push(("AWS_SECRET_ACCESS_KEY".into(), c.secret_access_key.clone()));
            if let Some(t) = &c.session_token {
                env.push(("AWS_SESSION_TOKEN".into(), t.clone()));
            }
        }
        let python = runtime.to_ascii_lowercase().starts_with("python");
        let job = tokio::task::spawn_blocking(move || run_script(python, &handler, &script, &payload, &env));
        let result = match job.await {
            Ok(r) => r,
            Err(e) => Err(format!("The script could not run: {e}")),
        };
        match result {
            Ok(value) => {
                let wrapped = json!({ "Payload": value });
                let mut outputs = BTreeMap::new();
                outputs.insert("OutputPayload".to_string(), Value::String(wrapped.to_string()));
                for o in step.get("outputs").and_then(Value::as_array).into_iter().flatten() {
                    let (Some(n), Some(sel)) =
                        (o.get("Name").and_then(Value::as_str), o.get("Selector").and_then(Value::as_str))
                    else {
                        continue;
                    };
                    let kind = o.get("Type").and_then(Value::as_str).unwrap_or("String");
                    if let Some(v) = select(&wrapped, sel) {
                        outputs.insert(n.to_string(), coerce(v, kind));
                    }
                }
                StepResult::ok(outputs)
            }
            Err(e) => StepResult::failed(e),
        }
    }

    async fn execute_automation_step(&self, run: &Run, inputs: &Value) -> StepResult {
        let Some(document) = input_str(inputs, "DocumentName") else {
            return StepResult::failed("DocumentName is a required input.");
        };
        let parameters: BTreeMap<String, Vec<String>> = inputs
            .get("RuntimeParameters")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), strings_of(v))).collect())
            .unwrap_or_default();
        let targets: Vec<types::Target> =
            inputs.get("Targets").and_then(|t| serde_json::from_value(lower_keys(t)).ok()).unwrap_or_default();
        let target_maps: Vec<BTreeMap<String, Vec<String>>> =
            inputs.get("TargetMaps").and_then(|t| serde_json::from_value(t.clone()).ok()).unwrap_or_default();
        let target_locations: Vec<types::TargetLocation> =
            inputs.get("TargetLocations").and_then(|t| serde_json::from_value(lower_keys(t)).ok()).unwrap_or_default();
        let arn = format!(
            "arn:{}:ssm:{}:{}:automation-definition/{document}",
            run.ctx.partition, run.region, run.ctx.caller.account_id
        );
        if let Err(e) = run.ctx.authorize("ssm:StartAutomationExecution", &arn, Default::default()) {
            return StepResult::failed(format!(
                "An error occurred ({}) when calling the StartAutomationExecution operation: {}",
                e.code, e.message
            ));
        }
        let spec = StartSpec {
            document_name: document,
            document_version: input_str(inputs, "DocumentVersion"),
            parameters,
            target_parameter_name: input_str(inputs, "TargetParameterName"),
            targets,
            target_maps,
            max_concurrency: input_str(inputs, "MaxConcurrency"),
            max_errors: input_str(inputs, "MaxErrors"),
            target_locations,
            parent: Some(run.id.clone()),
            ..Default::default()
        };
        let mut ctx = run.ctx.clone();
        ctx.received_at = self.clock_now();
        let child = match self.start_automation(&ctx, spec) {
            Ok(id) => id,
            Err(e) => return StepResult::failed(format!("{}: {}", e.code, e.message)),
        };
        let (status, outputs) = self.wait_execution(&ctx.caller.account_id, &ctx.region, &child).await;
        let out = BTreeMap::from([
            ("ExecutionId".to_string(), json!(child)),
            ("Status".to_string(), json!(status)),
            ("Output".to_string(), json!(serde_json::to_string(&outputs).unwrap_or_default())),
        ]);
        if status == "Success" {
            StepResult::ok(out)
        } else {
            let mut r =
                StepResult::failed(format!("Child automation execution {child} finished with status {status}."));
            r.outputs = out;
            r
        }
    }

    /// Wait for an execution to end; its status and outputs.
    pub(crate) async fn wait_execution(
        &self,
        account: &str,
        region: &str,
        id: &str,
    ) -> (String, BTreeMap<String, Vec<String>>) {
        loop {
            let Some(r) = self.automation(account, region, id) else { return ("Failed".into(), BTreeMap::new()) };
            let status = r.execution.automation_execution_status.clone().unwrap_or_default();
            if TERMINAL.contains(&status.as_str()) {
                return (status, r.execution.outputs.unwrap_or_default());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Wait until every instance is in `desired`; their states.
    async fn wait_instances(&self, run: &Run, ids: &[String], desired: &str) -> Result<Vec<String>, String> {
        loop {
            let d = self.api(run, "ec2", "DescribeInstances", json!({ "InstanceIds": ids })).await?;
            let states: Vec<String> =
                select(&d, "$.Reservations[*].Instances[*].State.Name").map(|v| strings_of(&v)).unwrap_or_default();
            if states.len() >= ids.len() && states.iter().all(|s| s == desired) {
                return Ok(states);
            }
            if desired != "terminated" && states.iter().any(|s| s == "terminated") {
                return Err("An instance was terminated.".into());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn stack_step(&self, run: &Run, action: &str, inputs: &Value) -> StepResult {
        let Some(stack) = input_str(inputs, "StackName") else {
            return StepResult::failed("StackName is a required input.");
        };
        if action == "aws:createStack" {
            let mut req = api_input(inputs, &["TerminationProtection"]);
            if let Some(t) = inputs.get("TerminationProtection") {
                req["EnableTerminationProtection"] = t.clone();
            }
            if let Err(e) = self.api(run, "cloudformation", "CreateStack", req).await {
                return StepResult::failed(e);
            }
        } else {
            let mut req = json!({ "StackName": stack });
            if let Some(r) = input_str(inputs, "RoleARN") {
                req["RoleARN"] = Value::String(r);
            }
            if let Err(e) = self.api(run, "cloudformation", "DeleteStack", req).await {
                return StepResult::failed(e);
            }
        }
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let d = match self.api(run, "cloudformation", "DescribeStacks", json!({ "StackName": stack })).await {
                Ok(d) => d,
                Err(_) if action == "aws:deleteStack" => return StepResult::ok(BTreeMap::new()),
                Err(e) => return StepResult::failed(e),
            };
            let s = select(&d, "$.Stacks[0]").unwrap_or_default();
            let status = s.get("StackStatus").and_then(Value::as_str).unwrap_or_default().to_string();
            if status.ends_with("_IN_PROGRESS") {
                continue;
            }
            let outputs = BTreeMap::from([
                ("StackId".to_string(), s.get("StackId").cloned().unwrap_or_default()),
                ("StackStatus".to_string(), json!(status)),
                ("StackStatusReason".to_string(), s.get("StackStatusReason").cloned().unwrap_or(json!(""))),
            ]);
            let wanted = if action == "aws:createStack" { "CREATE_COMPLETE" } else { "DELETE_COMPLETE" };
            if status == wanted {
                return StepResult::ok(outputs);
            }
            let mut r = StepResult::failed(format!("Stack {stack} is {status}."));
            r.outputs = outputs;
            return r;
        }
    }

    /// Run a rate-control or multi-location execution: one child per
    /// target value (or target map, or account and Region).
    pub(crate) async fn run_fan_out(&self, ctx: RequestContext, id: String, _content: Value, spec: StartSpec) {
        let run = Run {
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            id: id.clone(),
            ctx: ctx.clone(),
            creds: None,
            vars: BTreeMap::new(),
            mode: "Auto".into(),
        };
        self.set_status(&run, "InProgress");
        let base =
            self.automation(&run.account, &run.region, &id).and_then(|r| r.execution.parameters).unwrap_or_default();
        // (context, parameters, target) per child.
        let mut children: Vec<Child> = Vec::new();
        let mut resolved = Vec::new();
        if !spec.target_locations.is_empty() {
            let Some(runtime) = self.runtime() else {
                return self.finish(&run, "Failed", Some("Automation is not available.".into()), BTreeMap::new());
            };
            let source = execution_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &id);
            let admin_role = format!(
                "arn:{}:iam::{}:role/AWS-SystemsManager-AutomationAdministrationRole",
                ctx.partition, ctx.caller.account_id
            );
            let admin = match runtime.assume_role(&ctx, &admin_role, &source) {
                Ok((c, _)) => c,
                Err(_) => {
                    return self.finish(
                        &run,
                        "Failed",
                        Some(format!("The administration role {admin_role} is unable to be assumed.")),
                        BTreeMap::new(),
                    )
                }
            };
            for loc in &spec.target_locations {
                let role = loc
                    .execution_role_name
                    .clone()
                    .unwrap_or_else(|| "AWS-SystemsManager-AutomationExecutionRole".into());
                for account in loc.accounts.iter().flatten() {
                    for region in loc.regions.clone().unwrap_or_else(|| vec![ctx.region.clone()]) {
                        let role_arn = format!("arn:{}:iam::{account}:role/{role}", ctx.partition);
                        let mut admin_ctx = admin.clone();
                        admin_ctx.received_at = self.clock_now();
                        let child_ctx = match runtime.chain_role(&admin_ctx, &role_arn, &id).await {
                            Ok(c) => c,
                            Err(e) => {
                                resolved.push(format!("{account}:{region}: {e}"));
                                continue;
                            }
                        };
                        let mut c = child_ctx;
                        c.region = region.clone();
                        children.push((c, base.clone(), None, loc.targets.clone().unwrap_or_default()));
                    }
                }
            }
        } else if !spec.target_maps.is_empty() {
            for m in &spec.target_maps {
                let mut p = base.clone();
                p.extend(m.clone());
                children.push((ctx.clone(), p, None, Vec::new()));
            }
        } else {
            let values = self.resolve_automation_targets(&run, &spec.targets).await;
            let param = spec.target_parameter_name.clone().unwrap_or_default();
            for v in &values {
                let mut p = base.clone();
                p.insert(param.clone(), vec![v.clone()]);
                children.push((ctx.clone(), p, Some(v.clone()), Vec::new()));
            }
            resolved = values;
        }
        self.update_automation(&run.account, &run.region, &id, |r| {
            r.execution.resolved_targets =
                Some(types::ResolvedTargets { parameter_values: Some(resolved.clone()), truncated: false });
        });
        let total = children.len();
        let concurrency = rate(spec.max_concurrency.as_deref(), total, 1).max(1);
        let max_errors = rate(spec.max_errors.as_deref(), total, 0);
        let mut running: Vec<(String, String, String)> = Vec::new();
        let mut errors = 0usize;
        let mut queue = children.into_iter();
        let mut exhausted = false;
        loop {
            if self.automation(&run.account, &run.region, &id).and_then(|r| r.stop).as_deref() == Some("Cancel") {
                return self.finish(&run, "Cancelled", None, BTreeMap::new());
            }
            while !exhausted && running.len() < concurrency && errors <= max_errors {
                let Some((c, params, target, targets)) = queue.next() else {
                    exhausted = true;
                    break;
                };
                let child_spec = StartSpec {
                    document_name: if c.caller.account_id == ctx.caller.account_id {
                        spec.document_name.clone()
                    } else {
                        match self.find_document(&ctx, &spec.document_name) {
                            Some(f) if !f.doc.amazon() => format!(
                                "arn:{}:ssm:{}:{}:document/{}",
                                ctx.partition, ctx.region, f.owner_account, f.doc.name
                            ),
                            _ => spec.document_name.clone(),
                        }
                    },
                    document_version: spec.document_version.clone(),
                    parameters: params,
                    target_parameter_name: (!targets.is_empty()).then(|| spec.target_parameter_name.clone()).flatten(),
                    targets,
                    parent: Some(id.clone()),
                    target,
                    automation_type: (c.caller.account_id != ctx.caller.account_id || c.region != ctx.region)
                        .then(|| "CrossAccount".into()),
                    ..Default::default()
                };
                match self.start_automation(&c, child_spec) {
                    Ok(child) => running.push((c.caller.account_id.clone(), c.region.clone(), child)),
                    Err(_) => errors += 1,
                }
            }
            let mut still = Vec::new();
            for (a, r, child) in running.drain(..) {
                let status = self
                    .automation(&a, &r, &child)
                    .and_then(|x| x.execution.automation_execution_status)
                    .unwrap_or_else(|| "Failed".into());
                if TERMINAL.contains(&status.as_str()) {
                    if status != "Success" {
                        errors += 1;
                    }
                } else {
                    still.push((a, r, child));
                }
            }
            running = still;
            if running.is_empty() && (exhausted || errors > max_errors) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let status = if errors > max_errors { "Failed" } else { "Success" };
        let message = (errors > max_errors)
            .then(|| format!("{errors} of {total} child executions failed, more than MaxErrors allows."));
        self.finish(&run, status, message, BTreeMap::new());
    }

    /// Rate-control target values; tag targets select EC2 instances
    /// whether or not they are managed nodes.
    async fn resolve_automation_targets(&self, run: &Run, targets: &[types::Target]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in targets {
            let key = t.key.clone().unwrap_or_default();
            let values = t.values.clone().unwrap_or_default();
            let filter = if let Some(tag) = key.strip_prefix("tag:") {
                Some(json!([{ "Name": format!("tag:{tag}"), "Values": values }]))
            } else if key == "tag-key" {
                Some(json!([{ "Name": "tag-key", "Values": values }]))
            } else if key == "ResourceType" || key == "AWS::EC2::Instance" {
                Some(json!([]))
            } else {
                None
            };
            let matched = match filter {
                Some(mut f) => {
                    if let Some(a) = f.as_array_mut() {
                        a.push(json!({ "Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"] }));
                    }
                    match self.api(run, "ec2", "DescribeInstances", json!({ "Filters": f })).await {
                        Ok(d) => select(&d, "$.Reservations[*].Instances[*].InstanceId")
                            .map(|v| strings_of(&v))
                            .unwrap_or_default(),
                        Err(_) => self.automation_target_values(&run.ctx, std::slice::from_ref(t)),
                    }
                }
                None => self.automation_target_values(&run.ctx, std::slice::from_ref(t)),
            };
            for m in matched {
                if !out.contains(&m) {
                    out.push(m);
                }
            }
        }
        out
    }

    /// Run a Change Manager change request: approvals, the scheduled
    /// time, then the runbooks one after another.
    pub(crate) async fn run_change_request(&self, ctx: RequestContext, id: String, content: Value, spec: StartSpec) {
        let mut run = Run {
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            id: id.clone(),
            ctx: ctx.clone(),
            creds: None,
            vars: BTreeMap::new(),
            mode: "Auto".into(),
        };
        let change = spec.change.clone().unwrap_or_default();
        let document = spec.document_name.clone();
        self.base_vars(&mut run, &document);
        let title = change.name.clone().unwrap_or_else(|| document.clone());
        let ops_item = self.create_change_ops_item(&ctx, &id, &title, &document, &change);
        self.update_automation(&run.account, &run.region, &id, |r| r.execution.ops_item_id = ops_item.clone());
        let approvals: Vec<Value> = content
            .get("mainSteps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|s| s.get("action").and_then(Value::as_str) == Some("aws:approve"))
            .cloned()
            .collect();
        self.seed_steps(&run, &approvals);
        if !change.auto_approve {
            for step in &approvals {
                let name = step.get("name").and_then(Value::as_str).unwrap_or("Approve").to_string();
                let r = self.run_step(&mut run, &with_change_approve(step), &name, "aws:approve").await;
                if r.status == "Cancelled" {
                    return self.finish(&run, "Cancelled", None, BTreeMap::new());
                }
                if r.status != "Success" {
                    self.finish(&run, "Rejected", Some("The change request was rejected.".into()), BTreeMap::new());
                    self.mirror_ops_item_status(&run, "Rejected");
                    return;
                }
            }
        }
        self.set_status(&run, "Approved");
        if let Some(at) = change.scheduled_time.filter(|t| *t > self.clock_now()) {
            self.set_status(&run, "Scheduled");
            loop {
                if self.clock_now() >= at {
                    break;
                }
                if self.take_signal(&run, &["Revoke"]).is_some()
                    || self.automation(&run.account, &run.region, &id).and_then(|r| r.stop).is_some()
                {
                    return self.finish(
                        &run,
                        "Cancelled",
                        Some("The change request was revoked.".into()),
                        BTreeMap::new(),
                    );
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        self.set_status(&run, "RunbookInProgress");
        for rb in &change.runbooks {
            let child_spec = StartSpec {
                document_name: rb.document_name.clone(),
                document_version: rb.document_version.clone(),
                parameters: rb.parameters.clone().unwrap_or_default(),
                target_parameter_name: rb.target_parameter_name.clone(),
                targets: rb.targets.clone().unwrap_or_default(),
                target_maps: rb.target_maps.clone().unwrap_or_default(),
                max_concurrency: rb.max_concurrency.clone(),
                max_errors: rb.max_errors.clone(),
                target_locations: rb.target_locations.clone().unwrap_or_default(),
                parent: Some(id.clone()),
                ..Default::default()
            };
            let mut c = ctx.clone();
            c.received_at = self.clock_now();
            let child = match self.start_automation(&c, child_spec) {
                Ok(child) => child,
                Err(e) => {
                    return self.finish(&run, "Failed", Some(format!("{}: {}", e.code, e.message)), BTreeMap::new())
                }
            };
            let (status, _) = self.wait_execution(&run.account, &run.region, &child).await;
            if status != "Success" {
                return self.finish(
                    &run,
                    "Failed",
                    Some(format!("Runbook {} finished with status {status}.", rb.document_name)),
                    BTreeMap::new(),
                );
            }
        }
        self.finish(&run, "Success", None, BTreeMap::new());
    }

    /// Run a maintenance window `AUTOMATION` task as its service role.
    pub(crate) async fn run_automation_task(
        &self,
        account: &str,
        region: &str,
        task: &types::GetMaintenanceWindowTaskResult,
        params: BTreeMap<String, Vec<String>>,
        window_arn: &str,
    ) -> (&'static str, String, String, String) {
        let ap = task.task_invocation_parameters.as_ref().and_then(|p| p.automation.clone()).unwrap_or_default();
        let shown = serde_json::json!({ "documentVersion": ap.document_version, "parameters": params }).to_string();
        let Some(runtime) = self.runtime() else {
            return ("FAILED", "Automation is not available.".into(), String::new(), shown);
        };
        let Some(mut ctx) = self.template() else {
            return ("FAILED", "Automation is not available.".into(), String::new(), shown);
        };
        ctx.region = region.to_string();
        ctx.caller.account_id = account.to_string();
        ctx.received_at = self.clock_now();
        let Some(role) = task.service_role_arn.clone() else {
            return (
                "FAILED",
                "MWS runs Automation tasks only with a ServiceRoleArn; the service-linked role is not emulated.".into(),
                String::new(),
                shown,
            );
        };
        let ctx = match runtime.assume_role(&ctx, &role, window_arn) {
            Ok((c, _)) => c,
            Err(e) => return ("FAILED", e, String::new(), shown),
        };
        let spec = StartSpec {
            document_name: task.task_arn.clone().unwrap_or_default(),
            document_version: ap.document_version.clone(),
            parameters: params,
            ..Default::default()
        };
        let id = match self.start_automation(&ctx, spec) {
            Ok(id) => id,
            Err(e) => return ("FAILED", format!("{}: {}", e.code, e.message), String::new(), shown),
        };
        let (status, _) = self.wait_execution(account, region, &id).await;
        if status == "Success" {
            ("SUCCESS", String::new(), id, shown)
        } else {
            ("FAILED", format!("Automation execution {id} finished with status {status}."), id, shown)
        }
    }
}

/// A change template's `aws:approve` step with its approvers as the
/// engine's approve action reads them.
fn with_change_approve(step: &Value) -> Value {
    step.clone()
}

fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Smithy-cased JSON (`Key`, `Values`) as the generated types' serde
/// field names (`key`, `values`).
fn lower_keys(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    let snake: String = k
                        .chars()
                        .enumerate()
                        .flat_map(|(i, c)| {
                            if c.is_ascii_uppercase() {
                                let mut s = String::new();
                                if i > 0 {
                                    s.push('_');
                                }
                                s.push(c.to_ascii_lowercase());
                                s.chars().collect::<Vec<_>>()
                            } else {
                                vec![c]
                            }
                        })
                        .collect();
                    (snake, lower_keys(x))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(lower_keys).collect()),
        other => other.clone(),
    }
}

/// A step as its `StepExecution` with `status`.
fn step_view(s: &Value, status: &str) -> types::StepExecution {
    let next = s.get("nextStep").and_then(Value::as_str).map(str::to_string);
    let valid_next: Vec<String> = s
        .get("inputs")
        .and_then(|i| i.get("Choices"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("NextStep").and_then(Value::as_str).map(str::to_string))
        .chain(s.get("inputs").and_then(|i| i.get("Default")).and_then(Value::as_str).map(str::to_string))
        .collect();
    types::StepExecution {
        step_name: s.get("name").and_then(Value::as_str).map(str::to_string),
        action: s.get("action").and_then(Value::as_str).map(str::to_string),
        timeout_seconds: s.get("timeoutSeconds").and_then(Value::as_i64),
        on_failure: Some(s.get("onFailure").and_then(Value::as_str).unwrap_or("Abort").to_string()),
        max_attempts: Some(s.get("maxAttempts").and_then(Value::as_i64).unwrap_or(1) as i32),
        step_status: Some(status.into()),
        is_end: Some(s.get("isEnd").and_then(Value::as_bool).unwrap_or(false)),
        next_step: next,
        is_critical: Some(s.get("isCritical").and_then(Value::as_bool).unwrap_or(true)),
        valid_next_steps: (!valid_next.is_empty()).then_some(valid_next),
        ..Default::default()
    }
}

fn counters(r: &mut crate::automation::AutomationRecord) {
    let steps = r.execution.step_executions.clone().unwrap_or_default();
    let count = |s: &str| steps.iter().filter(|x| x.step_status.as_deref() == Some(s)).count() as i32;
    r.execution.progress_counters = Some(types::ProgressCounters {
        total_steps: steps.len() as i32,
        success_steps: count("Success"),
        failed_steps: count("Failed"),
        cancelled_steps: count("Cancelled"),
        timed_out_steps: count("TimedOut"),
    });
}

/// Whether an `aws:branch` choice (already substituted) matches.
fn choice_matches(c: &Value) -> bool {
    if let Some(all) = c.get("And").and_then(Value::as_array) {
        return all.iter().all(choice_matches);
    }
    if let Some(any) = c.get("Or").and_then(Value::as_array) {
        return any.iter().any(choice_matches);
    }
    if let Some(not) = c.get("Not") {
        let mut inner = not.clone();
        if inner.get("Variable").is_none() {
            if let (Some(o), Some(v)) = (inner.as_object_mut(), c.get("Variable")) {
                o.insert("Variable".into(), v.clone());
            }
        }
        return !choice_matches(&inner);
    }
    let var = c.get("Variable").cloned().unwrap_or(Value::Null);
    let s = match &var {
        Value::String(s) => s.clone(),
        Value::Array(a) if a.len() == 1 => strings_of(&a[0]).join(""),
        other => other.to_string(),
    };
    let num = s.trim().parse::<f64>().ok();
    let cmp_num =
        |key: &str, f: fn(f64, f64) -> bool| c.get(key).and_then(as_f64).zip(num).map(|(want, have)| f(have, want));
    if let Some(v) = c.get("StringEquals").and_then(Value::as_str) {
        return s == v;
    }
    if let Some(v) = c.get("EqualsIgnoreCase").and_then(Value::as_str) {
        return s.eq_ignore_ascii_case(v);
    }
    if let Some(v) = c.get("StartsWith").and_then(Value::as_str) {
        return s.starts_with(v);
    }
    if let Some(v) = c.get("EndsWith").and_then(Value::as_str) {
        return s.ends_with(v);
    }
    if let Some(v) = c.get("Contains").and_then(Value::as_str) {
        return match &var {
            Value::Array(a) => strings_of(&Value::Array(a.clone())).iter().any(|x| x == v),
            _ => s.contains(v),
        };
    }
    if let Some(v) = c.get("BooleanEquals") {
        let want = v.as_bool().unwrap_or(v.as_str() == Some("true"));
        return s.eq_ignore_ascii_case(if want { "true" } else { "false" });
    }
    for (key, f) in [
        ("NumericEquals", (|a, b| (a - b).abs() < f64::EPSILON) as fn(f64, f64) -> bool),
        ("NumericGreater", |a, b| a > b),
        ("NumericLesser", |a, b| a < b),
        ("NumericGreaterOrEquals", |a, b| a >= b),
        ("NumericLesserOrEquals", |a, b| a <= b),
    ] {
        if let Some(r) = cmp_num(key, f) {
            return r;
        }
    }
    false
}

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Run an `aws:executeScript` script locally; its return value.
fn run_script(
    python: bool,
    handler: &str,
    script: &str,
    payload: &Value,
    env: &[(String, String)],
) -> Result<Value, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    const MARKER: &str = "__MWS_SCRIPT_RESULT__";
    let dir = std::env::temp_dir().join(format!("mws-automation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let result = (|| {
        let mut cmd = if python {
            std::fs::write(dir.join("script.py"), script).map_err(|e| e.to_string())?;
            let wrapper = format!(
                "import json, sys, traceback\nns = {{'__name__': 'script'}}\nsrc = open({script:?}).read()\ntry:\n    exec(compile(src, 'script.py', 'exec'), ns)\n    handler = ns[{handler:?}]\n    events = json.loads(sys.stdin.read() or '{{}}')\n    result = handler(events, None)\n    print({MARKER:?} + json.dumps(result, default=str))\nexcept Exception as e:\n    traceback.print_exc()\n    sys.exit(1)\n",
                script = dir.join("script.py").to_string_lossy(),
                handler = handler.rsplit('.').next().unwrap_or(handler),
            );
            std::fs::write(dir.join("wrapper.py"), wrapper).map_err(|e| e.to_string())?;
            let python = ["python3", "python"]
                .into_iter()
                .find(|p| Command::new(p).arg("--version").output().is_ok())
                .ok_or("No Python interpreter is available to run the script.")?;
            let mut c = Command::new(python);
            c.arg(dir.join("wrapper.py"));
            c
        } else {
            let body = format!(
                "$ErrorActionPreference = 'Stop'\n$env:InputPayload = [Console]::In.ReadToEnd()\n$result = & {{\n{script}\n}}\nWrite-Output ('{MARKER}' + (ConvertTo-Json -Depth 20 -Compress -InputObject $result))\n"
            );
            std::fs::write(dir.join("script.ps1"), body).map_err(|e| e.to_string())?;
            let mut c = Command::new("pwsh");
            c.args(["-NoProfile", "-NonInteractive", "-File"]).arg(dir.join("script.ps1"));
            c
        };
        cmd.current_dir(&dir).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|e| format!("The script runtime could not start: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload.to_string().as_bytes());
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = stdout.lines().rev().find_map(|l| l.strip_prefix(MARKER)) {
            return Ok(serde_json::from_str(line).unwrap_or(Value::String(line.to_string())));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let last = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("The script failed.");
        Err(format!("{last}\n{stderr}").trim().to_string())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors() {
        let v = json!({"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}}, {"InstanceId": "i-2"}]}]});
        assert_eq!(select(&v, "$.Reservations[0].Instances[0].InstanceId"), Some(json!("i-1")));
        assert_eq!(select(&v, "$.Reservations[*].Instances[*].InstanceId"), Some(json!(["i-1", "i-2"])));
        assert_eq!(select(&v, "$..InstanceId"), Some(json!(["i-1", "i-2"])));
        assert_eq!(select(&v, "$.Missing"), None);
    }

    #[test]
    fn substitution_keeps_types() {
        let vars = BTreeMap::from([
            ("Ids".to_string(), json!(["i-1", "i-2"])),
            ("Name".to_string(), json!("web")),
            ("Step.Count".to_string(), json!(3)),
        ]);
        assert_eq!(substitute(&json!("{{ Ids }}"), &vars), json!(["i-1", "i-2"]));
        assert_eq!(substitute(&json!("hello {{Name}}-{{ Step.Count }}"), &vars), json!("hello web-3"));
        assert_eq!(substitute(&json!("{{ Unknown }}"), &vars), json!("{{ Unknown }}"));
    }

    #[test]
    fn durations_and_choices() {
        assert_eq!(iso_duration("PT10M"), Some(600));
        assert_eq!(iso_duration("P1DT2H3S"), Some(86400 + 7203));
        assert!(choice_matches(&json!({"Variable": "Linux", "StringEquals": "Linux"})));
        assert!(choice_matches(&json!({"Variable": "5", "NumericGreater": 3})));
        assert!(choice_matches(&json!({"Not": {"Variable": "a", "StringEquals": "b"}})));
        assert!(!choice_matches(
            &json!({"And": [{"Variable": "a", "StringEquals": "a"}, {"Variable": "true", "BooleanEquals": false}]})
        ));
        assert_eq!(pascal("describe_instances"), "DescribeInstances");
        assert_eq!(pascal("DescribeInstances"), "DescribeInstances");
    }
}
