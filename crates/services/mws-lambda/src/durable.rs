//! Durable functions: functions with a `DurableConfig` run as durable
//! executions. Each invocation gets the execution's operations
//! (`DurableExecutionArn`, `CheckpointToken`, `InitialExecutionState`) and
//! answers `SUCCEEDED`, `FAILED` or `PENDING`, as the durable execution SDKs
//! expect. While it runs, the SDK records progress with
//! `CheckpointDurableExecution`; MWS keeps the operations, runs waits and
//! step retries on the emulated clock, completes callbacks
//! (`SendDurableExecutionCallback*`) and chained invokes, and invokes the
//! function again whenever an operation it waits for is ready. Executions
//! keep a history of events (`GetDurableExecutionHistory`).
//!
//! Spec: <https://docs.aws.amazon.com/lambda/latest/dg/durable-functions.html>

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::functions::paginate;
use crate::generated::{errors, types};
use crate::names::{self, FunctionRef};
use crate::Lambda;

/// The default `ExecutionTimeout` (seconds).
const DEFAULT_EXECUTION_TIMEOUT: i32 = 86_400;
/// Invocations that fail before answering are retried this many times.
const INVOCATION_RETRIES: u32 = 2;
/// How long a synchronous invocation waits for the execution to finish.
const SYNC_WAIT: Duration = Duration::from_secs(900);

/// One durable execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Execution {
    pub arn: String,
    pub name: String,
    /// The id: the last segment of the ARN and the EXECUTION operation's id.
    pub id: String,
    /// The unqualified function ARN.
    pub function_arn: String,
    /// The version that runs (`$LATEST` or a number).
    pub version: String,
    pub account_id: String,
    pub region: String,
    pub input: String,
    /// `RUNNING`, `SUCCEEDED`, `FAILED`, `TIMED_OUT` or `STOPPED`.
    pub status: String,
    pub result: Option<String>,
    pub error: Option<types::ErrorObject>,
    pub started: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub durable_config: Option<types::DurableConfig>,
    pub trace_header: Option<String>,
    /// In the order they were created.
    pub operations: Vec<types::Operation>,
    pub events: Vec<types::Event>,
    /// Checkpoint tokens the running invocation may use.
    pub tokens: Vec<String>,
    /// Operations that changed since the last invocation started.
    pub updated: Vec<String>,
    pub invoking: bool,
    /// Failed invocations in a row.
    pub failures: u32,
}

impl Execution {
    fn op(&self, id: &str) -> Option<&types::Operation> {
        self.operations.iter().find(|o| o.id == id)
    }

    fn op_mut(&mut self, id: &str) -> Option<&mut types::Operation> {
        self.operations.iter_mut().find(|o| o.id == id)
    }

    fn running(&self) -> bool {
        self.status == "RUNNING"
    }

    fn summary(&self) -> types::Execution {
        types::Execution {
            durable_execution_arn: self.arn.clone(),
            durable_execution_name: self.name.clone(),
            function_arn: format!("{}:{}", self.function_arn, self.version),
            status: self.status.clone(),
            start_timestamp: self.started,
            end_timestamp: self.ended,
            kms_key_arn: self.durable_config.as_ref().and_then(|c| c.kms_key_arn.clone()),
        }
    }

    fn event(&mut self, kind: &str, op: Option<&types::Operation>, at: DateTime<Utc>) -> &mut types::Event {
        let id = self.events.len() as i32 + 1;
        self.events.push(types::Event {
            event_type: Some(kind.to_string()),
            event_id: id,
            id: op.map(|o| o.id.clone()),
            name: op.and_then(|o| o.name.clone()),
            parent_id: op.and_then(|o| o.parent_id.clone()),
            sub_type: op.and_then(|o| o.sub_type.clone()),
            event_timestamp: Some(at),
            ..Default::default()
        });
        self.events.last_mut().expect("just pushed")
    }

    fn mark_updated(&mut self, id: &str) {
        if !self.updated.iter().any(|u| u == id) {
            self.updated.push(id.to_string());
        }
    }

    fn timeout(&self) -> i64 {
        self.durable_config.as_ref().and_then(|c| c.execution_timeout).unwrap_or(DEFAULT_EXECUTION_TIMEOUT) as i64
    }
}

fn result(payload: &Option<String>) -> types::EventResult {
    types::EventResult { payload: payload.clone(), truncated: Some(false) }
}

fn event_error(e: &Option<types::ErrorObject>) -> types::EventError {
    types::EventError { payload: e.clone(), truncated: Some(false) }
}

fn millis(t: &DateTime<Utc>) -> Value {
    json!(t.timestamp_millis())
}

fn error_json(e: &types::ErrorObject) -> Value {
    let mut v = serde_json::Map::new();
    if let Some(m) = &e.error_message {
        v.insert("ErrorMessage".into(), json!(m));
    }
    if let Some(t) = &e.error_type {
        v.insert("ErrorType".into(), json!(t));
    }
    if let Some(d) = &e.error_data {
        v.insert("ErrorData".into(), json!(d));
    }
    if let Some(s) = &e.stack_trace {
        v.insert("StackTrace".into(), json!(s));
    }
    Value::Object(v)
}

/// An operation as invocation payloads carry it (timestamps in epoch
/// milliseconds).
fn operation_json(o: &types::Operation) -> Value {
    let mut v = json!({
        "Id": o.id,
        "Type": o.r#type,
        "Status": o.status,
        "StartTimestamp": millis(&o.start_timestamp),
    });
    let put = |v: &mut Value, k: &str, x: Option<Value>| {
        if let Some(x) = x {
            v[k] = x;
        }
    };
    put(&mut v, "ParentId", o.parent_id.as_ref().map(|p| json!(p)));
    put(&mut v, "Name", o.name.as_ref().map(|p| json!(p)));
    put(&mut v, "SubType", o.sub_type.as_ref().map(|p| json!(p)));
    put(&mut v, "EndTimestamp", o.end_timestamp.as_ref().map(millis));
    if let Some(d) = &o.execution_details {
        v["ExecutionDetails"] = json!({ "InputPayload": d.input_payload });
    }
    if let Some(d) = &o.context_details {
        let mut c = json!({});
        put(&mut c, "ReplayChildren", d.replay_children.map(|r| json!(r)));
        put(&mut c, "Result", d.result.as_ref().map(|r| json!(r)));
        put(&mut c, "Error", d.error.as_ref().map(error_json));
        v["ContextDetails"] = c;
    }
    if let Some(d) = &o.step_details {
        let mut s = json!({ "Attempt": d.attempt });
        put(&mut s, "NextAttemptTimestamp", d.next_attempt_timestamp.as_ref().map(millis));
        put(&mut s, "Result", d.result.as_ref().map(|r| json!(r)));
        put(&mut s, "Error", d.error.as_ref().map(error_json));
        v["StepDetails"] = s;
    }
    if let Some(d) = &o.wait_details {
        let mut w = json!({});
        put(&mut w, "ScheduledEndTimestamp", d.scheduled_end_timestamp.as_ref().map(millis));
        v["WaitDetails"] = w;
    }
    if let Some(d) = &o.callback_details {
        let mut c = json!({});
        put(&mut c, "CallbackId", d.callback_id.as_ref().map(|r| json!(r)));
        put(&mut c, "Result", d.result.as_ref().map(|r| json!(r)));
        put(&mut c, "Error", d.error.as_ref().map(error_json));
        v["CallbackDetails"] = c;
    }
    if let Some(d) = &o.chained_invoke_details {
        let mut c = json!({});
        put(&mut c, "Result", d.result.as_ref().map(|r| json!(r)));
        put(&mut c, "Error", d.error.as_ref().map(error_json));
        v["ChainedInvokeDetails"] = c;
    }
    v
}

fn not_found(arn: &str) -> ServiceError {
    errors::resource_not_found(format!("Durable execution not found: {arn}"))
}

fn invalid_token() -> ServiceError {
    errors::invalid_parameter_value("Invalid checkpoint token.")
}

/// A callback's deadlines: the overall timeout and the heartbeat timeout.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct CallbackTimers {
    timeout_at: Option<DateTime<Utc>>,
    heartbeat_seconds: Option<i32>,
    heartbeat_at: Option<DateTime<Utc>>,
}

/// Request contexts for executions' background work (not persisted), and
/// callback deadlines.
#[derive(Default)]
pub(crate) struct Runtime {
    contexts: Mutex<HashMap<String, RequestContext>>,
    timers: Mutex<HashMap<String, CallbackTimers>>,
    scheduler: std::sync::OnceLock<()>,
}

impl Lambda {
    fn durable_now(&self, ctx: &RequestContext) -> DateTime<Utc> {
        (Utc::now() + self.clock_skew()).max(ctx.received_at)
    }

    fn durable_context(&self, arn: &str) -> Option<RequestContext> {
        let mut ctx = self.inner.durable.contexts.lock().expect("durable lock").get(arn)?.clone();
        ctx.request_id = uuid::Uuid::new_v4().to_string();
        ctx.received_at = Utc::now() + self.clock_skew();
        Some(ctx)
    }

    /// Whether invocations of this version start durable executions.
    pub(crate) fn is_durable(&self, f: &FunctionRef) -> bool {
        let st = self.read();
        Self::function(&st, f)
            .ok()
            .and_then(|func| func.version_for(f.qualifier.as_deref()))
            .is_some_and(|v| v.config.durable_config.is_some())
    }

    /// Start a durable execution for an invocation (or find the one with
    /// the same name and input). Returns its ARN.
    pub(crate) fn start_durable_execution(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        payload: &[u8],
        name: Option<&str>,
    ) -> Result<String, ServiceError> {
        let input = String::from_utf8_lossy(if payload.is_empty() { b"{}" } else { payload }).into_owned();
        let (version, durable_config) = {
            let st = self.read();
            let func = Self::function(&st, f)?;
            let version = match f.qualifier.as_deref() {
                None | Some("$LATEST") => "$LATEST".to_string(),
                Some(q) if q.bytes().all(|b| b.is_ascii_digit()) => q.to_string(),
                Some(alias) => {
                    func.aliases.get(alias).and_then(|a| a.function_version.clone()).ok_or_else(|| f.not_found())?
                }
            };
            let config = func.version_for(Some(&version)).and_then(|v| v.config.durable_config.clone());
            (version, config)
        };
        if let Some(n) = name {
            let valid = !n.is_empty()
                && n.len() <= 64
                && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !valid {
                return Err(errors::invalid_parameter_value(format!(
                    "1 validation error detected: Value '{n}' at 'durableExecutionName' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9-_]+"
                )));
            }
        }
        let now = self.durable_now(ctx);
        let id = uuid::Uuid::new_v4().to_string();
        let name = name.map(str::to_string).unwrap_or_else(|| id.clone());
        let qualified = format!("{}:{version}", f.arn());
        let arn = format!("{qualified}/durable-execution/{name}/{id}");
        let mut st = self.write();
        if let Some(existing) =
            st.durable_executions.values().find(|e| e.function_arn == f.arn() && e.version == version && e.name == name)
        {
            if existing.input == input {
                return Ok(existing.arn.clone());
            }
            return Err(errors::durable_execution_already_started(format!(
                "A durable execution with name {name} has already been started with a different input."
            )));
        }
        let execution_op = types::Operation {
            id: id.clone(),
            r#type: "EXECUTION".into(),
            status: "STARTED".into(),
            start_timestamp: now,
            execution_details: Some(types::ExecutionDetails { input_payload: Some(input.clone()) }),
            ..Default::default()
        };
        let mut e = Execution {
            arn: arn.clone(),
            name,
            id,
            function_arn: f.arn(),
            version,
            account_id: f.account.clone(),
            region: f.region.clone(),
            input: input.clone(),
            status: "RUNNING".into(),
            started: now,
            durable_config,
            operations: vec![execution_op],
            ..Default::default()
        };
        let timeout = e.timeout() as i32;
        e.event("ExecutionStarted", None, now).execution_started_details = Some(types::ExecutionStartedDetails {
            input: types::EventInput { payload: Some(input), truncated: Some(false) },
            execution_timeout: timeout,
        });
        st.durable_executions.insert(arn.clone(), e);
        drop(st);
        self.inner.durable.contexts.lock().expect("durable lock").insert(arn.clone(), ctx.clone());
        self.start_durable_scheduler();
        self.drive(arn.clone());
        Ok(arn)
    }

    /// Wait for an execution to end; its state then.
    pub(crate) async fn wait_for_execution(&self, arn: &str) -> Option<Execution> {
        let started = std::time::Instant::now();
        while started.elapsed() < SYNC_WAIT {
            if let Some(e) = self.read().durable_executions.get(arn).filter(|e| !e.running()) {
                return Some(e.clone());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    /// Invoke the function for an execution unless an invocation is
    /// already running.
    fn drive(&self, arn: String) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move { me.invocation_loop(&arn).await });
    }

    async fn invocation_loop(&self, arn: &str) {
        loop {
            let Some(ctx) = self.durable_context(arn) else { return };
            let (f, payload, started) = {
                let mut st = self.write();
                let Some(e) = st.durable_executions.get_mut(arn) else { return };
                if !e.running() || e.invoking {
                    return;
                }
                e.invoking = true;
                let token = uuid::Uuid::new_v4().simple().to_string();
                e.tokens = vec![token.clone()];
                let updated = std::mem::take(&mut e.updated);
                let payload = json!({
                    "DurableExecutionArn": e.arn,
                    "CheckpointToken": token,
                    "InitialExecutionState": {
                        "Operations": e.operations.iter().map(operation_json).collect::<Vec<_>>(),
                        "NextMarker": "",
                    },
                    "UpdatedOperationIds": updated,
                });
                let f = FunctionRef {
                    partition: ctx.partition.clone(),
                    account: e.account_id.clone(),
                    region: e.region.clone(),
                    name: e.function_arn.rsplit(':').next().unwrap_or_default().to_string(),
                    qualifier: Some(e.version.clone()),
                };
                (f, payload.to_string().into_bytes(), self.durable_now(&ctx))
            };
            let ran = self.run(&ctx, &f, payload, None).await;
            let ended = self.durable_now(&ctx);
            let again = {
                let mut st = self.write();
                let Some(e) = st.durable_executions.get_mut(arn) else { return };
                e.invoking = false;
                e.tokens.clear();
                let (output, invocation_error) = match &ran {
                    Ok(r) if r.outcome.function_error.is_none() => {
                        (serde_json::from_slice::<Value>(&r.outcome.payload).ok(), None)
                    }
                    Ok(r) => {
                        let v: Value = serde_json::from_slice(&r.outcome.payload).unwrap_or_default();
                        (
                            None,
                            Some(types::ErrorObject {
                                error_type: v["errorType"].as_str().map(str::to_string),
                                error_message: v["errorMessage"].as_str().map(str::to_string),
                                ..Default::default()
                            }),
                        )
                    }
                    Err(err) => (
                        None,
                        Some(types::ErrorObject {
                            error_type: Some(err.code.to_string()),
                            error_message: Some(err.message.clone()),
                            ..Default::default()
                        }),
                    ),
                };
                let request_id = ctx.request_id.clone();
                e.event("InvocationCompleted", None, ended).invocation_completed_details =
                    Some(types::InvocationCompletedDetails {
                        start_timestamp: started,
                        end_timestamp: ended,
                        request_id,
                        error: invocation_error.as_ref().map(|err| event_error(&Some(err.clone()))),
                    });
                if !e.running() {
                    false
                } else if let Some(err) = invocation_error {
                    e.failures += 1;
                    if e.failures > INVOCATION_RETRIES {
                        finish(e, "FAILED", None, Some(err), ended);
                        false
                    } else {
                        true
                    }
                } else {
                    e.failures = 0;
                    let output = output.unwrap_or_default();
                    match output.get("Status").and_then(Value::as_str) {
                        Some("SUCCEEDED") => {
                            let result = output
                                .get("Result")
                                .and_then(Value::as_str)
                                .filter(|r| !r.is_empty())
                                .map(str::to_string)
                                .or_else(|| e.result.clone());
                            finish(e, "SUCCEEDED", result, None, ended);
                            false
                        }
                        Some("FAILED") => {
                            let error = output.get("Error").map(parse_error).or_else(|| e.error.clone());
                            finish(e, "FAILED", None, error, ended);
                            false
                        }
                        Some("PENDING") => !e.updated.is_empty(),
                        _ => {
                            let error = types::ErrorObject {
                                error_type: Some("InvalidDurableExecutionOutput".into()),
                                error_message: Some(
                                    "The function did not return a durable execution output (Status SUCCEEDED, FAILED or PENDING).".into(),
                                ),
                                ..Default::default()
                            };
                            finish(e, "FAILED", None, Some(error), ended);
                            false
                        }
                    }
                }
            };
            if !again {
                if self.read().durable_executions.get(arn).is_some_and(|e| !e.running()) {
                    self.inner.durable.contexts.lock().expect("durable lock").remove(arn);
                }
                return;
            }
            if ran.is_err() || ran.as_ref().is_ok_and(|r| r.outcome.function_error.is_some()) {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    /// Check timers once a quarter second: waits that end, step retries
    /// that are due, callbacks that time out, executions that time out.
    fn start_durable_scheduler(&self) {
        self.inner.durable.scheduler.get_or_init(|| {
            let weak = std::sync::Arc::downgrade(&self.inner);
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        let Some(inner) = weak.upgrade() else { return };
                        Lambda { inner }.durable_tick();
                    }
                });
            }
        });
    }

    fn durable_tick(&self) {
        let now = Utc::now() + self.clock_skew();
        let timers = self.inner.durable.timers.lock().expect("durable lock").clone();
        let mut wake = Vec::new();
        {
            let mut st = self.write();
            for e in st.durable_executions.values_mut().filter(|e| e.running()) {
                if (now - e.started).num_seconds() >= e.timeout() {
                    let error = types::ErrorObject {
                        error_type: Some("ExecutionTimedOut".into()),
                        error_message: Some("The durable execution exceeded its execution timeout.".into()),
                        ..Default::default()
                    };
                    finish(e, "TIMED_OUT", None, Some(error), now);
                    continue;
                }
                let mut changed = Vec::new();
                for o in e.operations.iter_mut() {
                    match (o.r#type.as_str(), o.status.as_str()) {
                        ("WAIT", "STARTED") => {
                            if o.wait_details.as_ref().and_then(|w| w.scheduled_end_timestamp).is_some_and(|t| t <= now)
                            {
                                o.status = "SUCCEEDED".into();
                                o.end_timestamp = Some(now);
                                changed.push((o.clone(), "WaitSucceeded"));
                            }
                        }
                        ("STEP", "PENDING") => {
                            if o.step_details.as_ref().and_then(|s| s.next_attempt_timestamp).is_some_and(|t| t <= now)
                            {
                                o.status = "READY".into();
                                changed.push((o.clone(), ""));
                            }
                        }
                        ("CALLBACK", "STARTED") => {
                            let Some(id) = o.callback_details.as_ref().and_then(|c| c.callback_id.clone()) else {
                                continue;
                            };
                            let Some(t) = timers.get(&id) else { continue };
                            let expired = t.timeout_at.is_some_and(|at| at <= now);
                            let silent = t.heartbeat_at.is_some_and(|at| at <= now);
                            if expired || silent {
                                let kind = if expired { "Callback.Timeout" } else { "Callback.HeartbeatTimeout" };
                                let error = types::ErrorObject {
                                    error_type: Some(kind.into()),
                                    error_message: Some("The callback timed out.".into()),
                                    ..Default::default()
                                };
                                o.status = "TIMED_OUT".into();
                                o.end_timestamp = Some(now);
                                o.callback_details.get_or_insert_with(Default::default).error = Some(error);
                                changed.push((o.clone(), "CallbackTimedOut"));
                            }
                        }
                        _ => {}
                    }
                }
                for (op, kind) in &changed {
                    e.mark_updated(&op.id);
                    match *kind {
                        "WaitSucceeded" => {
                            let duration = op
                                .wait_details
                                .as_ref()
                                .and_then(|w| w.scheduled_end_timestamp)
                                .map(|t| (t - op.start_timestamp).num_seconds() as i32);
                            e.event("WaitSucceeded", Some(op), now).wait_succeeded_details =
                                Some(types::WaitSucceededDetails { duration });
                        }
                        "CallbackTimedOut" => {
                            let error = op.callback_details.as_ref().and_then(|c| c.error.clone());
                            e.event("CallbackTimedOut", Some(op), now).callback_timed_out_details =
                                Some(types::CallbackTimedOutDetails { error: event_error(&error) });
                        }
                        _ => {}
                    }
                }
                if !changed.is_empty() && !e.invoking {
                    wake.push(e.arn.clone());
                }
            }
        }
        for arn in wake {
            self.drive(arn);
        }
    }

    /// Apply a checkpoint's updates; the operations they changed.
    fn apply_updates(
        &self,
        ctx: &RequestContext,
        e: &mut Execution,
        updates: Vec<types::OperationUpdate>,
        now: DateTime<Utc>,
        chained: &mut Vec<(String, types::ChainedInvokeOptions, Option<String>)>,
    ) -> Result<Vec<types::Operation>, ServiceError> {
        let mut touched: Vec<String> = Vec::new();
        for u in updates {
            if u.r#type == "EXECUTION" {
                if u.id != e.id {
                    return Err(errors::invalid_parameter_value(format!("Unknown execution operation {}.", u.id)));
                }
                match u.action.as_str() {
                    "SUCCEED" => {
                        e.result = u.payload.clone();
                        finish(e, "SUCCEEDED", u.payload, None, now);
                    }
                    "FAIL" => {
                        e.error = u.error.clone();
                        finish(e, "FAILED", None, u.error, now);
                    }
                    other => {
                        return Err(errors::invalid_parameter_value(format!(
                            "Action {other} is not valid for an EXECUTION operation."
                        )))
                    }
                }
                touched.push(u.id.clone());
                continue;
            }
            let exists = e.op(&u.id).is_some();
            match (u.action.as_str(), exists) {
                ("START", false) => {
                    let mut op = types::Operation {
                        id: u.id.clone(),
                        parent_id: u.parent_id.clone(),
                        name: u.name.clone(),
                        r#type: u.r#type.clone(),
                        sub_type: u.sub_type.clone(),
                        start_timestamp: now,
                        status: "STARTED".into(),
                        ..Default::default()
                    };
                    let kind = match u.r#type.as_str() {
                        "STEP" => {
                            op.step_details = Some(types::StepDetails { attempt: 1, ..Default::default() });
                            "StepStarted"
                        }
                        "WAIT" => {
                            let seconds = u.wait_options.as_ref().and_then(|w| w.wait_seconds).unwrap_or(0);
                            if !(1..=31_622_400).contains(&seconds) {
                                return Err(errors::invalid_parameter_value(
                                    "WaitSeconds must be between 1 and 31622400.",
                                ));
                            }
                            op.wait_details = Some(types::WaitDetails {
                                scheduled_end_timestamp: Some(now + chrono::Duration::seconds(seconds as i64)),
                            });
                            "WaitStarted"
                        }
                        "CALLBACK" => {
                            let callback_id = callback_id(&e.arn, &u.id);
                            op.callback_details = Some(types::CallbackDetails {
                                callback_id: Some(callback_id.clone()),
                                ..Default::default()
                            });
                            let opts = u.callback_options.clone().unwrap_or_default();
                            self.inner.durable.timers.lock().expect("durable lock").insert(
                                callback_id,
                                CallbackTimers {
                                    timeout_at: Some(opts.timeout_seconds)
                                        .filter(|s| *s > 0)
                                        .map(|s| now + chrono::Duration::seconds(s as i64)),
                                    heartbeat_seconds: Some(opts.heartbeat_timeout_seconds).filter(|s| *s > 0),
                                    heartbeat_at: Some(opts.heartbeat_timeout_seconds)
                                        .filter(|s| *s > 0)
                                        .map(|s| now + chrono::Duration::seconds(s as i64)),
                                },
                            );
                            "CallbackStarted"
                        }
                        "CONTEXT" => {
                            op.context_details = Some(types::ContextDetails {
                                replay_children: u.context_options.as_ref().and_then(|c| c.replay_children),
                                ..Default::default()
                            });
                            "ContextStarted"
                        }
                        "CHAINED_INVOKE" => {
                            let Some(opts) = u.chained_invoke_options.clone() else {
                                return Err(errors::invalid_parameter_value(
                                    "ChainedInvokeOptions are required to start a CHAINED_INVOKE operation.",
                                ));
                            };
                            op.chained_invoke_details = Some(Default::default());
                            chained.push((u.id.clone(), opts, u.payload.clone()));
                            "ChainedInvokeStarted"
                        }
                        other => {
                            return Err(errors::invalid_parameter_value(format!("Unknown operation type {other}.")))
                        }
                    };
                    e.operations.push(op.clone());
                    let ev = e.event(kind, Some(&op), now);
                    match kind {
                        "WaitStarted" => {
                            let seconds = u.wait_options.as_ref().and_then(|w| w.wait_seconds).unwrap_or(0);
                            ev.wait_started_details = Some(types::WaitStartedDetails {
                                duration: seconds,
                                scheduled_end_timestamp: now + chrono::Duration::seconds(seconds as i64),
                            });
                        }
                        "StepStarted" => ev.step_started_details = Some(Default::default()),
                        "ContextStarted" => ev.context_started_details = Some(Default::default()),
                        "CallbackStarted" => {
                            let opts = u.callback_options.clone().unwrap_or_default();
                            ev.callback_started_details = Some(types::CallbackStartedDetails {
                                callback_id: op
                                    .callback_details
                                    .as_ref()
                                    .and_then(|c| c.callback_id.clone())
                                    .unwrap_or_default(),
                                heartbeat_timeout: Some(opts.heartbeat_timeout_seconds).filter(|s| *s > 0),
                                timeout: Some(opts.timeout_seconds).filter(|s| *s > 0),
                            });
                        }
                        "ChainedInvokeStarted" => {
                            let opts = u.chained_invoke_options.clone().unwrap_or_default();
                            ev.chained_invoke_started_details = Some(types::ChainedInvokeStartedDetails {
                                function_name: opts.function_name,
                                tenant_id: opts.tenant_id,
                                input: Some(types::EventInput { payload: u.payload.clone(), truncated: Some(false) }),
                                ..Default::default()
                            });
                        }
                        _ => {}
                    }
                }
                ("START", true) => {
                    // A step that was READY (its retry is due) starts again.
                    let op = e.op_mut(&u.id).expect("exists");
                    if op.r#type == "STEP" && op.status == "READY" {
                        op.status = "STARTED".into();
                        let d = op.step_details.get_or_insert_with(Default::default);
                        d.attempt += 1;
                        d.next_attempt_timestamp = None;
                        let op = op.clone();
                        e.event("StepStarted", Some(&op), now).step_started_details = Some(Default::default());
                    }
                }
                (_, false) => {
                    return Err(errors::invalid_parameter_value(format!(
                        "Operation {} does not exist; it must be started first.",
                        u.id
                    )))
                }
                (action, true) => {
                    let op = e.op_mut(&u.id).expect("exists");
                    let terminal = ["SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "STOPPED"];
                    if terminal.contains(&op.status.as_str()) {
                        return Err(errors::invalid_parameter_value(format!(
                            "Operation {} has already completed.",
                            u.id
                        )));
                    }
                    let kind = match (op.r#type.as_str(), action) {
                        ("STEP", "SUCCEED") => {
                            op.status = "SUCCEEDED".into();
                            op.step_details.get_or_insert_with(Default::default).result = u.payload.clone();
                            "StepSucceeded"
                        }
                        ("STEP", "FAIL") => {
                            op.status = "FAILED".into();
                            op.step_details.get_or_insert_with(Default::default).error = u.error.clone();
                            "StepFailed"
                        }
                        ("STEP", "RETRY") => {
                            let delay = u.step_options.as_ref().and_then(|s| s.next_attempt_delay_seconds).unwrap_or(1);
                            op.status = "PENDING".into();
                            let d = op.step_details.get_or_insert_with(Default::default);
                            d.error = u.error.clone();
                            d.next_attempt_timestamp = Some(now + chrono::Duration::seconds(delay.max(0) as i64));
                            "StepFailed"
                        }
                        ("CONTEXT", "SUCCEED") => {
                            op.status = "SUCCEEDED".into();
                            op.context_details.get_or_insert_with(Default::default).result = u.payload.clone();
                            "ContextSucceeded"
                        }
                        ("CONTEXT", "FAIL") => {
                            op.status = "FAILED".into();
                            op.context_details.get_or_insert_with(Default::default).error = u.error.clone();
                            "ContextFailed"
                        }
                        ("WAIT", "CANCEL") => {
                            op.status = "CANCELLED".into();
                            "WaitCancelled"
                        }
                        (t, a) => {
                            return Err(errors::invalid_parameter_value(format!(
                                "Action {a} is not valid for a {t} operation."
                            )))
                        }
                    };
                    if op.status != "PENDING" {
                        op.end_timestamp = Some(now);
                    }
                    let op = op.clone();
                    let attempt = op.step_details.as_ref().map(|d| d.attempt).unwrap_or(0);
                    let retry = types::RetryDetails {
                        current_attempt: attempt,
                        next_attempt_delay_seconds: u.step_options.as_ref().and_then(|s| s.next_attempt_delay_seconds),
                    };
                    let ev = e.event(kind, Some(&op), now);
                    match kind {
                        "StepSucceeded" => {
                            ev.step_succeeded_details =
                                Some(types::StepSucceededDetails { result: result(&u.payload), retry_details: retry })
                        }
                        "StepFailed" => {
                            ev.step_failed_details =
                                Some(types::StepFailedDetails { error: event_error(&u.error), retry_details: retry })
                        }
                        "ContextSucceeded" => {
                            ev.context_succeeded_details =
                                Some(types::ContextSucceededDetails { result: result(&u.payload) })
                        }
                        "ContextFailed" => {
                            ev.context_failed_details =
                                Some(types::ContextFailedDetails { error: event_error(&u.error) })
                        }
                        "WaitCancelled" => {
                            ev.wait_cancelled_details =
                                Some(types::WaitCancelledDetails { error: Some(event_error(&u.error)) })
                        }
                        _ => {}
                    }
                }
            }
            if !touched.contains(&u.id) {
                touched.push(u.id.clone());
            }
        }
        let _ = ctx;
        Ok(touched.iter().filter_map(|id| e.op(id).cloned()).collect())
    }

    pub async fn checkpoint_durable_execution(
        &self,
        ctx: &RequestContext,
        input: types::CheckpointDurableExecutionRequest,
    ) -> Result<types::CheckpointDurableExecutionResponse, ServiceError> {
        let function = self.execution_function(&input.durable_execution_arn)?;
        ctx.authorize("lambda:CheckpointDurableExecution", &function, ConditionContext::new())?;
        let now = self.durable_now(ctx);
        let mut chained = Vec::new();
        let (operations, token, arn) = {
            let mut st = self.write();
            let e = st
                .durable_executions
                .get_mut(&input.durable_execution_arn)
                .ok_or_else(|| not_found(&input.durable_execution_arn))?;
            if !e.tokens.contains(&input.checkpoint_token) {
                return Err(invalid_token());
            }
            if !e.running() {
                return Err(errors::invalid_parameter_value("The durable execution has already completed."));
            }
            let ops = self.apply_updates(ctx, e, input.updates.unwrap_or_default(), now, &mut chained)?;
            let token = if e.running() {
                let t = uuid::Uuid::new_v4().simple().to_string();
                e.tokens.push(t.clone());
                Some(t)
            } else {
                None
            };
            (ops, token, e.arn.clone())
        };
        for (op_id, opts, payload) in chained {
            self.spawn_chained_invoke(ctx, &arn, op_id, opts, payload);
        }
        Ok(types::CheckpointDurableExecutionResponse {
            checkpoint_token: token,
            new_execution_state: types::CheckpointUpdatedExecutionState {
                operations: Some(operations),
                next_marker: None,
            },
        })
    }

    /// Run a chained invoke: invoke the function (as the durable function's
    /// execution role) and complete the operation with its result.
    fn spawn_chained_invoke(
        &self,
        ctx: &RequestContext,
        arn: &str,
        op_id: String,
        opts: types::ChainedInvokeOptions,
        payload: Option<String>,
    ) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let me = self.clone();
        let ctx = ctx.clone();
        let arn = arn.to_string();
        tokio::spawn(async move {
            let function = me.read().durable_executions.get(&arn).map(|e| format!("{}:{}", e.function_arn, e.version));
            let Some(function) = function else { return };
            let outcome: Result<Option<String>, types::ErrorObject> = async {
                let role_ctx = me.role_context(&ctx, &function).map_err(service_error)?;
                let target = names::parse_function(&role_ctx, &opts.function_name, None).map_err(service_error)?;
                me.authorize_function(&role_ctx, "lambda:InvokeFunction", &target, ConditionContext::new())
                    .map_err(service_error)?;
                let body = payload.clone().unwrap_or_else(|| "{}".into()).into_bytes();
                if me.is_durable(&target) {
                    let child = me.start_durable_execution(&role_ctx, &target, &body, None).map_err(service_error)?;
                    let done = me.wait_for_execution(&child).await.ok_or_else(|| types::ErrorObject {
                        error_type: Some("ChainedInvokeTimedOut".into()),
                        ..Default::default()
                    })?;
                    return match done.status.as_str() {
                        "SUCCEEDED" => Ok(done.result),
                        _ => Err(done.error.unwrap_or_default()),
                    };
                }
                let ran = me.run(&role_ctx, &target, body, None).await.map_err(service_error)?;
                let text = String::from_utf8_lossy(&ran.outcome.payload).into_owned();
                if ran.outcome.function_error.is_some() {
                    let v: Value = serde_json::from_str(&text).unwrap_or_default();
                    return Err(types::ErrorObject {
                        error_type: v["errorType"].as_str().map(str::to_string),
                        error_message: v["errorMessage"].as_str().map(str::to_string),
                        ..Default::default()
                    });
                }
                Ok(Some(text))
            }
            .await;
            let now = me.durable_now(&ctx);
            let wake = {
                let mut st = me.write();
                let Some(e) = st.durable_executions.get_mut(&arn) else { return };
                let Some(op) = e.op_mut(&op_id) else { return };
                if op.status != "STARTED" {
                    return;
                }
                op.end_timestamp = Some(now);
                let (kind, details) = match &outcome {
                    Ok(r) => {
                        op.status = "SUCCEEDED".into();
                        op.chained_invoke_details =
                            Some(types::ChainedInvokeDetails { result: r.clone(), error: None });
                        ("ChainedInvokeSucceeded", outcome.clone())
                    }
                    Err(err) => {
                        op.status = "FAILED".into();
                        op.chained_invoke_details =
                            Some(types::ChainedInvokeDetails { result: None, error: Some(err.clone()) });
                        ("ChainedInvokeFailed", outcome.clone())
                    }
                };
                let op = op.clone();
                let ev = e.event(kind, Some(&op), now);
                match details {
                    Ok(r) => {
                        ev.chained_invoke_succeeded_details =
                            Some(types::ChainedInvokeSucceededDetails { result: result(&r) })
                    }
                    Err(err) => {
                        ev.chained_invoke_failed_details =
                            Some(types::ChainedInvokeFailedDetails { error: event_error(&Some(err)) })
                    }
                }
                e.mark_updated(&op_id);
                e.running() && !e.invoking
            };
            if wake {
                me.drive(arn);
            }
        });
    }

    /// The qualified function ARN of an execution ARN.
    fn execution_function(&self, arn: &str) -> Result<String, ServiceError> {
        let function = arn.split("/durable-execution/").next().unwrap_or_default();
        if function.is_empty() || function == arn {
            return Err(errors::invalid_parameter_value(format!("Invalid durable execution ARN: {arn}")));
        }
        Ok(function.to_string())
    }

    pub async fn get_durable_execution_state(
        &self,
        ctx: &RequestContext,
        input: types::GetDurableExecutionStateRequest,
    ) -> Result<types::GetDurableExecutionStateResponse, ServiceError> {
        let function = self.execution_function(&input.durable_execution_arn)?;
        ctx.authorize("lambda:GetDurableExecutionState", &function, ConditionContext::new())?;
        let st = self.read();
        let e = st
            .durable_executions
            .get(&input.durable_execution_arn)
            .ok_or_else(|| not_found(&input.durable_execution_arn))?;
        if !e.tokens.contains(&input.checkpoint_token) {
            return Err(invalid_token());
        }
        let max = if input.max_items > 0 { Some(input.max_items) } else { None };
        let (page, next) = paginate(&e.operations, input.marker.as_deref().filter(|m| !m.is_empty()), max, 1000);
        Ok(types::GetDurableExecutionStateResponse { operations: page, next_marker: next })
    }

    pub async fn get_durable_execution(
        &self,
        ctx: &RequestContext,
        input: types::GetDurableExecutionRequest,
    ) -> Result<types::GetDurableExecutionResponse, ServiceError> {
        let function = self.execution_function(&input.durable_execution_arn)?;
        ctx.authorize("lambda:GetDurableExecution", &function, ConditionContext::new())?;
        let st = self.read();
        let e = st
            .durable_executions
            .get(&input.durable_execution_arn)
            .ok_or_else(|| not_found(&input.durable_execution_arn))?;
        let data = input.include_execution_data;
        Ok(types::GetDurableExecutionResponse {
            durable_execution_arn: e.arn.clone(),
            durable_execution_name: e.name.clone(),
            function_arn: format!("{}:{}", e.function_arn, e.version),
            input_payload: data.then(|| e.input.clone()),
            result: if data { e.result.clone() } else { None },
            error: e.error.clone(),
            start_timestamp: e.started,
            status: e.status.clone(),
            end_timestamp: e.ended,
            version: Some(e.version.clone()),
            trace_header: e.trace_header.clone().map(|t| types::TraceHeader { x_amzn_trace_id: Some(t) }),
            execution_data_included: Some(data),
            durable_config: e.durable_config.clone(),
        })
    }

    pub async fn get_durable_execution_history(
        &self,
        ctx: &RequestContext,
        input: types::GetDurableExecutionHistoryRequest,
    ) -> Result<types::GetDurableExecutionHistoryResponse, ServiceError> {
        let function = self.execution_function(&input.durable_execution_arn)?;
        ctx.authorize("lambda:GetDurableExecutionHistory", &function, ConditionContext::new())?;
        let st = self.read();
        let e = st
            .durable_executions
            .get(&input.durable_execution_arn)
            .ok_or_else(|| not_found(&input.durable_execution_arn))?;
        let mut events = e.events.clone();
        if input.include_execution_data != Some(true) {
            for ev in &mut events {
                strip_event_data(ev);
            }
        }
        if input.reverse_order == Some(true) {
            events.reverse();
        }
        let max = if input.max_items > 0 { Some(input.max_items) } else { None };
        let (page, next) = paginate(&events, input.marker.as_deref(), max, 100);
        Ok(types::GetDurableExecutionHistoryResponse { events: page, next_marker: next })
    }

    pub async fn list_durable_executions_by_function(
        &self,
        ctx: &RequestContext,
        input: types::ListDurableExecutionsByFunctionRequest,
    ) -> Result<types::ListDurableExecutionsByFunctionResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:ListDurableExecutionsByFunction", &f, ConditionContext::new())?;
        let st = self.read();
        Self::function(&st, &f)?;
        let mut all: Vec<&Execution> = st
            .durable_executions
            .values()
            .filter(|e| e.function_arn == f.arn())
            .filter(|e| f.qualifier.as_deref().is_none_or(|q| q == e.version))
            .filter(|e| input.durable_execution_name.as_deref().is_none_or(|n| n == e.name))
            .filter(|e| input.statuses.as_ref().is_none_or(|s| s.is_empty() || s.contains(&e.status)))
            .filter(|e| input.started_after.is_none_or(|t| e.started > t))
            .filter(|e| input.started_before.is_none_or(|t| e.started < t))
            .collect();
        // Newest first unless reversed.
        all.sort_by_key(|e| std::cmp::Reverse(e.started));
        if input.reverse_order == Some(true) {
            all.reverse();
        }
        let summaries: Vec<types::Execution> = all.into_iter().map(Execution::summary).collect();
        let max = if input.max_items > 0 { Some(input.max_items) } else { None };
        let (page, next) = paginate(&summaries, input.marker.as_deref(), max, 50);
        Ok(types::ListDurableExecutionsByFunctionResponse { durable_executions: Some(page), next_marker: next })
    }

    pub async fn stop_durable_execution(
        &self,
        ctx: &RequestContext,
        input: types::StopDurableExecutionRequest,
    ) -> Result<types::StopDurableExecutionResponse, ServiceError> {
        let function = self.execution_function(&input.durable_execution_arn)?;
        ctx.authorize("lambda:StopDurableExecution", &function, ConditionContext::new())?;
        let now = self.durable_now(ctx);
        let mut st = self.write();
        let e = st
            .durable_executions
            .get_mut(&input.durable_execution_arn)
            .ok_or_else(|| not_found(&input.durable_execution_arn))?;
        if !e.running() {
            return Err(errors::invalid_parameter_value("The durable execution is not running."));
        }
        let error = input.error.or_else(|| {
            Some(types::ErrorObject {
                error_type: Some("Stopped".into()),
                error_message: Some("The durable execution was stopped.".into()),
                ..Default::default()
            })
        });
        finish(e, "STOPPED", None, error, now);
        Ok(types::StopDurableExecutionResponse { stop_timestamp: now })
    }

    /// The execution and operation a callback id names.
    fn callback_target(st: &crate::state::State, callback_id: &str) -> Result<(String, String), ServiceError> {
        for e in st.durable_executions.values() {
            for o in &e.operations {
                if o.callback_details.as_ref().and_then(|c| c.callback_id.as_deref()) == Some(callback_id) {
                    return Ok((e.arn.clone(), o.id.clone()));
                }
            }
        }
        Err(errors::resource_not_found(format!("Callback not found: {callback_id}")))
    }

    fn complete_callback(
        &self,
        ctx: &RequestContext,
        action: &str,
        callback_id: &str,
        outcome: Result<Option<String>, Option<types::ErrorObject>>,
    ) -> Result<(), ServiceError> {
        let now = self.durable_now(ctx);
        let wake = {
            let mut st = self.write();
            let (arn, op_id) = Self::callback_target(&st, callback_id)?;
            let function = self.execution_function(&arn)?;
            ctx.authorize(action, &function, ConditionContext::new())?;
            let e = st.durable_executions.get_mut(&arn).expect("found");
            let op = e.op_mut(&op_id).expect("found");
            if op.status != "STARTED" {
                return Err(errors::callback_timeout(format!("Callback {callback_id} is no longer waiting.")));
            }
            op.end_timestamp = Some(now);
            let details = op.callback_details.get_or_insert_with(Default::default);
            let kind = match &outcome {
                Ok(r) => {
                    op.status = "SUCCEEDED".into();
                    details.result = r.clone();
                    "CallbackSucceeded"
                }
                Err(err) => {
                    op.status = "FAILED".into();
                    details.error = err.clone();
                    "CallbackFailed"
                }
            };
            let op = op.clone();
            let ev = e.event(kind, Some(&op), now);
            match outcome {
                Ok(r) => ev.callback_succeeded_details = Some(types::CallbackSucceededDetails { result: result(&r) }),
                Err(err) => {
                    ev.callback_failed_details = Some(types::CallbackFailedDetails { error: event_error(&err) })
                }
            }
            e.mark_updated(&op_id);
            self.inner.durable.timers.lock().expect("durable lock").remove(callback_id);
            (e.running() && !e.invoking).then(|| arn.clone())
        };
        if let Some(arn) = wake {
            self.drive(arn);
        }
        Ok(())
    }

    pub async fn send_durable_execution_callback_success(
        &self,
        ctx: &RequestContext,
        input: types::SendDurableExecutionCallbackSuccessRequest,
    ) -> Result<types::SendDurableExecutionCallbackSuccessResponse, ServiceError> {
        let result = input.result.map(|b| String::from_utf8_lossy(&b).into_owned());
        self.complete_callback(ctx, "lambda:SendDurableExecutionCallbackSuccess", &input.callback_id, Ok(result))?;
        Ok(Default::default())
    }

    pub async fn send_durable_execution_callback_failure(
        &self,
        ctx: &RequestContext,
        input: types::SendDurableExecutionCallbackFailureRequest,
    ) -> Result<types::SendDurableExecutionCallbackFailureResponse, ServiceError> {
        self.complete_callback(
            ctx,
            "lambda:SendDurableExecutionCallbackFailure",
            &input.callback_id,
            Err(input.error),
        )?;
        Ok(Default::default())
    }

    pub async fn send_durable_execution_callback_heartbeat(
        &self,
        ctx: &RequestContext,
        input: types::SendDurableExecutionCallbackHeartbeatRequest,
    ) -> Result<types::SendDurableExecutionCallbackHeartbeatResponse, ServiceError> {
        let now = self.durable_now(ctx);
        let st = self.read();
        let (arn, op_id) = Self::callback_target(&st, &input.callback_id)?;
        let function = self.execution_function(&arn)?;
        ctx.authorize("lambda:SendDurableExecutionCallbackHeartbeat", &function, ConditionContext::new())?;
        let waiting = st.durable_executions.get(&arn).and_then(|e| e.op(&op_id)).is_some_and(|o| o.status == "STARTED");
        drop(st);
        if !waiting {
            return Err(errors::callback_timeout(format!("Callback {} is no longer waiting.", input.callback_id)));
        }
        let mut timers = self.inner.durable.timers.lock().expect("durable lock");
        if let Some(t) = timers.get_mut(&input.callback_id) {
            if let Some(s) = t.heartbeat_seconds {
                t.heartbeat_at = Some(now + chrono::Duration::seconds(s as i64));
            }
        }
        Ok(Default::default())
    }
}

fn service_error(e: ServiceError) -> types::ErrorObject {
    types::ErrorObject { error_type: Some(e.code.to_string()), error_message: Some(e.message), ..Default::default() }
}

fn parse_error(v: &Value) -> types::ErrorObject {
    types::ErrorObject {
        error_message: v["ErrorMessage"].as_str().map(str::to_string),
        error_type: v["ErrorType"].as_str().map(str::to_string),
        error_data: v["ErrorData"].as_str().map(str::to_string),
        stack_trace: v["StackTrace"]
            .as_array()
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()),
    }
}

/// An opaque callback id: the execution and operation it completes.
fn callback_id(execution_arn: &str, op_id: &str) -> String {
    use base64::Engine;
    let raw = format!("{}#{op_id}#{}", execution_arn, uuid::Uuid::new_v4().simple());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// End an execution, recording the closing event and the EXECUTION
/// operation's outcome.
fn finish(
    e: &mut Execution,
    status: &str,
    result_payload: Option<String>,
    error: Option<types::ErrorObject>,
    now: DateTime<Utc>,
) {
    if !e.running() {
        return;
    }
    e.status = status.to_string();
    e.ended = Some(now);
    e.result = result_payload.clone();
    e.error = error.clone();
    e.tokens.clear();
    let id = e.id.clone();
    if let Some(op) = e.op_mut(&id) {
        op.status = status.to_string();
        op.end_timestamp = Some(now);
    }
    let ev = e.event(
        match status {
            "SUCCEEDED" => "ExecutionSucceeded",
            "FAILED" => "ExecutionFailed",
            "TIMED_OUT" => "ExecutionTimedOut",
            _ => "ExecutionStopped",
        },
        None,
        now,
    );
    match status {
        "SUCCEEDED" => {
            ev.execution_succeeded_details = Some(types::ExecutionSucceededDetails { result: result(&result_payload) })
        }
        "FAILED" => ev.execution_failed_details = Some(types::ExecutionFailedDetails { error: event_error(&error) }),
        "TIMED_OUT" => {
            ev.execution_timed_out_details = Some(types::ExecutionTimedOutDetails { error: Some(event_error(&error)) })
        }
        _ => ev.execution_stopped_details = Some(types::ExecutionStoppedDetails { error: event_error(&error) }),
    }
}

/// Drop payloads from an event (history without execution data).
fn strip_event_data(ev: &mut types::Event) {
    if let Some(d) = &mut ev.execution_started_details {
        d.input.payload = None;
    }
    if let Some(d) = &mut ev.execution_succeeded_details {
        d.result.payload = None;
    }
    if let Some(d) = &mut ev.step_succeeded_details {
        d.result.payload = None;
    }
    if let Some(d) = &mut ev.context_succeeded_details {
        d.result.payload = None;
    }
    if let Some(d) = &mut ev.callback_succeeded_details {
        d.result.payload = None;
    }
    if let Some(d) = &mut ev.chained_invoke_succeeded_details {
        d.result.payload = None;
    }
    if let Some(d) = &mut ev.chained_invoke_started_details {
        d.input = None;
    }
}

/// Invocation of a durable function: start the execution; for
/// `RequestResponse`, wait for it and answer its result.
impl Lambda {
    pub(crate) async fn invoke_durable(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        payload: Vec<u8>,
        kind: &str,
        name: Option<&str>,
    ) -> Result<types::InvocationResponse, ServiceError> {
        let arn = self.start_durable_execution(ctx, f, &payload, name)?;
        let version = self.read().durable_executions.get(&arn).map(|e| e.version.clone());
        if kind == "Event" {
            return Ok(types::InvocationResponse {
                status_code: 202,
                durable_execution_arn: Some(arn),
                ..Default::default()
            });
        }
        let Some(done) = self.wait_for_execution(&arn).await else {
            return Err(errors::service("The durable execution did not finish within 15 minutes."));
        };
        let (payload, function_error) = match done.status.as_str() {
            "SUCCEEDED" => (done.result.clone().unwrap_or_else(|| "null".into()).into_bytes(), None),
            _ => {
                let e = done.error.clone().unwrap_or_default();
                let body = json!({
                    "errorType": e.error_type.unwrap_or_else(|| done.status.clone()),
                    "errorMessage": e.error_message.unwrap_or_default(),
                });
                (body.to_string().into_bytes(), Some("Unhandled".to_string()))
            }
        };
        Ok(types::InvocationResponse {
            status_code: 200,
            function_error,
            payload: Some(payload),
            executed_version: version,
            durable_execution_arn: Some(arn),
            ..Default::default()
        })
    }
}
