//! Maintenance windows: windows, their targets and tasks, and executions
//! that really run on the emulated clock. Run Command tasks send commands
//! to the targeted managed nodes; Lambda tasks invoke the function through
//! a [`TaskInvoker`] the composition root provides. Window executions
//! report "Maintenance Window Execution State-change Notification" events.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_schedule::Schedule;
use serde::{Deserialize, Serialize};

use crate::commands::{spawn, Launch};
use crate::generated::{errors, types};
use crate::names::{now, page, request_tag_conditions, resource_tag_conditions};
use crate::Ssm;

/// Windows an account may have per Region.
const MAX_WINDOWS: usize = 50;
const MAX_TARGETS: usize = 100;
const MAX_TASKS: usize = 20;

/// Runs maintenance window tasks of other services.
#[async_trait::async_trait]
pub trait TaskInvoker: Send + Sync {
    /// Invoke a Lambda function as the task's service role (`role`,
    /// assumed by `ssm.amazonaws.com` for the window `window_arn`) would;
    /// returns the request id. `ctx` is a request context for the window's
    /// account and Region, without a caller.
    async fn invoke_lambda(
        &self,
        ctx: &RequestContext,
        role: Option<&str>,
        window_arn: &str,
        function: &str,
        qualifier: Option<&str>,
        payload: Vec<u8>,
    ) -> Result<String, String>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskInvocationRecord {
    pub invocation_id: String,
    /// The command id or Lambda request id.
    pub execution_id: String,
    pub window_target_id: Option<String>,
    pub owner_information: Option<String>,
    pub parameters: String,
    pub status: String,
    pub status_details: String,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskExecutionRecord {
    pub task_execution_id: String,
    pub window_task_id: String,
    pub task: types::GetMaintenanceWindowTaskResult,
    pub status: String,
    pub status_details: String,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub invocations: Vec<TaskInvocationRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecutionRecord {
    pub window_execution_id: String,
    pub status: String,
    pub status_details: String,
    pub start: DateTime<Utc>,
    pub end: Option<DateTime<Utc>>,
    pub tasks: Vec<TaskExecutionRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Window {
    pub window: types::GetMaintenanceWindowResult,
    pub targets: Vec<types::MaintenanceWindowTarget>,
    pub tasks: Vec<types::GetMaintenanceWindowTaskResult>,
    pub tags: BTreeMap<String, String>,
    /// Firings up to here have been run.
    pub checked_until: Option<DateTime<Utc>>,
    /// Newest first.
    pub executions: Vec<ExecutionRecord>,
    pub client_token: Option<String>,
}

/// A window execution's state change, for EventBridge.
#[derive(Debug, Clone)]
pub struct WindowEvent {
    pub account: String,
    pub region: String,
    pub window_id: String,
    pub window_execution_id: String,
    pub status: String,
    pub start: DateTime<Utc>,
    pub end: Option<DateTime<Utc>>,
    pub time: DateTime<Utc>,
}

fn window_arn(partition: &str, region: &str, account: &str, id: &str) -> String {
    format!("arn:{partition}:ssm:{region}:{account}:maintenancewindow/{id}")
}

fn not_found(id: &str) -> ServiceError {
    errors::does_not_exist(format!("Maintenance window {id} does not exist"))
}

fn new_window_id() -> String {
    let u = uuid::Uuid::new_v4().simple().to_string();
    format!("mw-{}", &u[..17])
}

/// A window schedule: `cron(...)`, `rate(...)` or `at(...)`.
enum WindowSchedule {
    Recurring(Schedule),
    At(chrono::NaiveDateTime),
}

fn parse_schedule(expr: &str) -> Result<WindowSchedule, ServiceError> {
    let bad = || errors::validation(format!("Invalid schedule expression: {expr}"));
    if let Some(at) = expr.strip_prefix("at(").and_then(|s| s.strip_suffix(')')) {
        return chrono::NaiveDateTime::parse_from_str(at, "%Y-%m-%dT%H:%M:%S")
            .map(WindowSchedule::At)
            .map_err(|_| bad());
    }
    Schedule::parse(expr).map(WindowSchedule::Recurring).ok_or_else(bad)
}

fn parse_tz(tz: Option<&str>) -> Result<chrono_tz::Tz, ServiceError> {
    match tz {
        None | Some("") => Ok(chrono_tz::UTC),
        Some(t) => t.parse().map_err(|_| errors::validation(format!("Invalid schedule timezone: {t}"))),
    }
}

fn parse_date(s: &Option<String>) -> Result<Option<DateTime<Utc>>, ServiceError> {
    match s.as_deref() {
        None | Some("") => Ok(None),
        Some(d) => DateTime::parse_from_rfc3339(d)
            .map(|t| Some(t.with_timezone(&Utc)))
            .map_err(|_| errors::validation(format!("Invalid date format: {d}. Use ISO-8601 extended format."))),
    }
}

/// The firings of `w` in `(after, until]`, at most `limit`.
fn firings(
    w: &types::GetMaintenanceWindowResult,
    after: DateTime<Utc>,
    until: DateTime<Utc>,
    limit: usize,
) -> Vec<DateTime<Utc>> {
    let Ok(schedule) = parse_schedule(w.schedule.as_deref().unwrap_or_default()) else { return Vec::new() };
    let Ok(tz) = parse_tz(w.schedule_timezone.as_deref()) else { return Vec::new() };
    let start = parse_date(&w.start_date).ok().flatten();
    let end = parse_date(&w.end_date).ok().flatten();
    let after = match start {
        Some(s) if s > after => s - Duration::milliseconds(1),
        _ => after,
    };
    let until = match end {
        Some(e) if e < until => e,
        _ => until,
    };
    if until <= after {
        return Vec::new();
    }
    let offset = Duration::days(i64::from(w.schedule_offset.unwrap_or(0)));
    match schedule {
        WindowSchedule::At(t) => {
            use chrono::TimeZone;
            let Some(at) = tz.from_local_datetime(&t).earliest().map(|t| t.with_timezone(&Utc)) else {
                return Vec::new();
            };
            if at > after && at <= until {
                vec![at]
            } else {
                Vec::new()
            }
        }
        WindowSchedule::Recurring(s) => {
            let anchor = start.or(w.created_date).unwrap_or(after);
            s.fires_between_in(&tz, anchor, after - offset, until - offset, limit)
                .into_iter()
                .map(|t| t + offset)
                .filter(|t| *t > after && *t <= until)
                .collect()
        }
    }
}

fn next_execution(w: &types::GetMaintenanceWindowResult, now: DateTime<Utc>) -> Option<String> {
    if !w.enabled {
        return None;
    }
    let tz = parse_tz(w.schedule_timezone.as_deref()).ok()?;
    let t = firings(w, now, now + Duration::days(366), 1).into_iter().next()?;
    let local = t.with_timezone(&tz);
    Some(if tz == chrono_tz::UTC {
        local.format("%Y-%m-%dT%H:%MZ").to_string()
    } else {
        local.format("%Y-%m-%dT%H:%M%:z").to_string()
    })
}

fn validate_window(w: &types::GetMaintenanceWindowResult) -> Result<(), ServiceError> {
    parse_schedule(w.schedule.as_deref().unwrap_or_default())?;
    parse_tz(w.schedule_timezone.as_deref())?;
    let duration = w.duration.unwrap_or(0);
    if !(1..=24).contains(&duration) {
        return Err(errors::validation("Duration must be between 1 and 24 hours."));
    }
    if w.cutoff < 0 || w.cutoff >= duration {
        return Err(errors::validation("Cutoff must be less than the duration of the maintenance window."));
    }
    if let Some(o) = w.schedule_offset {
        if !w.schedule.as_deref().unwrap_or_default().starts_with("cron(") {
            return Err(errors::validation("ScheduleOffset can be used only with cron expressions."));
        }
        if !(1..=6).contains(&o) {
            return Err(errors::validation("ScheduleOffset must be between 1 and 6."));
        }
    }
    let (start, end) = (parse_date(&w.start_date)?, parse_date(&w.end_date)?);
    if let (Some(s), Some(e)) = (start, end) {
        if e <= s {
            return Err(errors::validation("The end date must be later than the start date."));
        }
    }
    Ok(())
}

fn identity(w: &Window, now: DateTime<Utc>) -> types::MaintenanceWindowIdentity {
    let x = &w.window;
    types::MaintenanceWindowIdentity {
        window_id: x.window_id.clone(),
        name: x.name.clone(),
        description: x.description.clone(),
        enabled: x.enabled,
        duration: x.duration,
        cutoff: x.cutoff,
        schedule: x.schedule.clone(),
        schedule_timezone: x.schedule_timezone.clone(),
        schedule_offset: x.schedule_offset,
        end_date: x.end_date.clone(),
        start_date: x.start_date.clone(),
        next_execution_time: next_execution(x, now),
    }
}

fn task_summary(t: &types::GetMaintenanceWindowTaskResult) -> types::MaintenanceWindowTask {
    types::MaintenanceWindowTask {
        window_id: t.window_id.clone(),
        window_task_id: t.window_task_id.clone(),
        task_arn: t.task_arn.clone(),
        r#type: t.task_type.clone(),
        targets: t.targets.clone(),
        task_parameters: t.task_parameters.clone(),
        priority: t.priority,
        logging_info: t.logging_info.clone(),
        service_role_arn: t.service_role_arn.clone(),
        max_concurrency: t.max_concurrency.clone(),
        max_errors: t.max_errors.clone(),
        name: t.name.clone(),
        description: t.description.clone(),
        cutoff_behavior: t.cutoff_behavior.clone(),
        alarm_configuration: t.alarm_configuration.clone(),
    }
}

fn filter_values(
    filters: &Option<Vec<types::MaintenanceWindowFilter>>,
    allowed: &[&str],
) -> Result<Vec<(String, Vec<String>)>, ServiceError> {
    let mut out = Vec::new();
    for f in filters.clone().unwrap_or_default() {
        let key = f.key.unwrap_or_default();
        if !allowed.contains(&key.as_str()) {
            return Err(errors::validation(format!(
                "Filter key {key} is not supported. Valid keys: {}",
                allowed.join(", ")
            )));
        }
        out.push((key, f.values.unwrap_or_default()));
    }
    Ok(out)
}

fn validate_targets(resource_type: &str, targets: &[types::Target]) -> Result<(), ServiceError> {
    for t in targets {
        let key = t.key.as_deref().unwrap_or_default();
        let ok = match resource_type {
            "RESOURCE_GROUP" => key == "resource-groups:Name" || key == "resource-groups:ResourceTypeFilters",
            _ => key == "InstanceIds" || key.starts_with("tag:") || key == "tag-key" || key == "resource-groups:Name",
        };
        if !ok {
            return Err(errors::validation(format!(
                "Target key {key} is not valid for resource type {resource_type}."
            )));
        }
    }
    Ok(())
}

fn validate_task_targets(w: &Window, targets: &[types::Target]) -> Result<(), ServiceError> {
    for t in targets {
        match t.key.as_deref() {
            Some("WindowTargetIds") => {
                for id in t.values.clone().unwrap_or_default() {
                    if !w.targets.iter().any(|x| x.window_target_id.as_deref() == Some(id.as_str())) {
                        return Err(errors::does_not_exist(format!("Maintenance window target {id} does not exist")));
                    }
                }
            }
            Some("InstanceIds") if w.window.allow_unassociated_targets => {}
            other => {
                return Err(errors::validation(format!(
                    "Target key {} is not valid. Use WindowTargetIds{}.",
                    other.unwrap_or_default(),
                    if w.window.allow_unassociated_targets { " or InstanceIds" } else { "" }
                )))
            }
        }
    }
    Ok(())
}

fn validate_task(task_type: &str, task_arn: &str) -> Result<(), ServiceError> {
    match task_type {
        "RUN_COMMAND" | "AUTOMATION" => Ok(()),
        "LAMBDA" if task_arn.contains(":lambda:") || !task_arn.starts_with("arn:") => Ok(()),
        "STEP_FUNCTIONS" if task_arn.contains(":states:") => Ok(()),
        "LAMBDA" | "STEP_FUNCTIONS" => {
            Err(errors::validation(format!("TaskArn {task_arn} is not valid for task type {task_type}.")))
        }
        _ => Err(errors::validation(format!("Task type {task_type} is not supported."))),
    }
}

/// Fill the maintenance window pseudo parameters (`{{RESOURCE_ID}}`, ...).
fn pseudo(s: &str, vars: &BTreeMap<&str, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v).replace(&format!("{{{{ {k} }}}}"), v);
    }
    out
}

impl Ssm {
    fn invoker(&self) -> Option<Arc<dyn TaskInvoker>> {
        self.invoker.read().expect("SSM invoker lock poisoned").clone()
    }

    /// Run Lambda tasks through `invoker`.
    pub fn set_task_invoker(&self, invoker: Arc<dyn TaskInvoker>) {
        *self.invoker.write().expect("SSM invoker lock poisoned") = Some(invoker);
    }

    fn window_of(&self, ctx: &RequestContext, action: &str, id: &str) -> Result<Window, ServiceError> {
        let w = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.windows.get(id)).cloned()
        };
        let cond = w.as_ref().map(|w| resource_tag_conditions(&w.tags)).unwrap_or_default();
        ctx.authorize(
            &format!("ssm:{action}"),
            &window_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, id),
            cond,
        )?;
        w.ok_or_else(|| not_found(id))
    }

    fn save_window(&self, ctx: &RequestContext, w: Window) {
        let id = w.window.window_id.clone().unwrap_or_default();
        self.lock().region(&ctx.caller.account_id, &ctx.region).windows.insert(id, w);
    }

    fn list_arn(ctx: &RequestContext) -> String {
        format!("arn:{}:ssm:{}:{}:*", ctx.partition, ctx.region, ctx.caller.account_id)
    }

    pub(crate) fn create_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::CreateMaintenanceWindowRequest,
    ) -> Result<types::CreateMaintenanceWindowResult, ServiceError> {
        let tags: Vec<(String, String)> =
            input.tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
        ctx.authorize(
            "ssm:CreateMaintenanceWindow",
            &window_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, "*"),
            request_tag_conditions(tags.iter().map(|(k, v)| (k, v))),
        )?;
        let at = now(ctx);
        let window = types::GetMaintenanceWindowResult {
            window_id: Some(new_window_id()),
            name: Some(input.name),
            description: input.description,
            start_date: input.start_date,
            end_date: input.end_date,
            schedule: Some(input.schedule),
            schedule_timezone: input.schedule_timezone,
            schedule_offset: input.schedule_offset,
            next_execution_time: None,
            duration: Some(input.duration),
            cutoff: input.cutoff,
            allow_unassociated_targets: input.allow_unassociated_targets,
            enabled: true,
            created_date: Some(at),
            modified_date: Some(at),
        };
        validate_window(&window)?;
        if let Some(end) = parse_date(&window.end_date)? {
            if end <= at {
                return Err(errors::validation("The end date must be in the future."));
            }
        }
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(token) = &input.client_token {
            if let Some(w) = r.windows.values().find(|w| w.client_token.as_deref() == Some(token.as_str())) {
                return Ok(types::CreateMaintenanceWindowResult { window_id: w.window.window_id.clone() });
            }
        }
        if r.windows.len() >= MAX_WINDOWS {
            return Err(errors::resource_limit_exceeded(format!(
                "Maintenance window limit exceeded. You can create up to {MAX_WINDOWS} maintenance windows."
            )));
        }
        let id = window.window_id.clone().unwrap_or_default();
        r.windows.insert(
            id.clone(),
            Window {
                window,
                tags: tags.into_iter().collect(),
                checked_until: Some(at),
                client_token: input.client_token,
                ..Default::default()
            },
        );
        Ok(types::CreateMaintenanceWindowResult { window_id: Some(id) })
    }

    pub(crate) fn get_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::GetMaintenanceWindowRequest,
    ) -> Result<types::GetMaintenanceWindowResult, ServiceError> {
        let w = self.window_of(ctx, "GetMaintenanceWindow", &input.window_id)?;
        let mut out = w.window.clone();
        out.next_execution_time = next_execution(&out, now(ctx));
        Ok(out)
    }

    pub(crate) fn update_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMaintenanceWindowRequest,
    ) -> Result<types::UpdateMaintenanceWindowResult, ServiceError> {
        let mut w = self.window_of(ctx, "UpdateMaintenanceWindow", &input.window_id)?;
        let replace = input.replace.unwrap_or(false);
        let x = &mut w.window;
        if replace
            && (input.name.is_none()
                || input.schedule.is_none()
                || input.duration.is_none()
                || input.cutoff.is_none()
                || input.allow_unassociated_targets.is_none())
        {
            return Err(errors::validation(
                "Name, Schedule, Duration, Cutoff and AllowUnassociatedTargets are required when Replace is true.",
            ));
        }
        macro_rules! set {
            ($field:ident) => {
                if input.$field.is_some() || replace {
                    x.$field = input.$field.clone();
                }
            };
        }
        set!(name);
        set!(description);
        set!(start_date);
        set!(end_date);
        set!(schedule);
        set!(schedule_timezone);
        set!(schedule_offset);
        set!(duration);
        if let Some(c) = input.cutoff {
            x.cutoff = c;
        }
        if let Some(a) = input.allow_unassociated_targets {
            x.allow_unassociated_targets = a;
        }
        if let Some(e) = input.enabled {
            x.enabled = e;
        }
        validate_window(x)?;
        x.modified_date = Some(now(ctx));
        let out = types::UpdateMaintenanceWindowResult {
            window_id: x.window_id.clone(),
            name: x.name.clone(),
            description: x.description.clone(),
            start_date: x.start_date.clone(),
            end_date: x.end_date.clone(),
            schedule: x.schedule.clone(),
            schedule_timezone: x.schedule_timezone.clone(),
            schedule_offset: x.schedule_offset,
            duration: x.duration,
            cutoff: x.cutoff,
            allow_unassociated_targets: x.allow_unassociated_targets,
            enabled: x.enabled,
        };
        // A changed schedule fires from now on.
        w.checked_until = Some(now(ctx));
        self.save_window(ctx, w);
        Ok(out)
    }

    pub(crate) fn delete_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMaintenanceWindowRequest,
    ) -> Result<types::DeleteMaintenanceWindowResult, ServiceError> {
        // Deleting a window that doesn't exist succeeds, as in AWS.
        let arn = window_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.window_id);
        ctx.authorize("ssm:DeleteMaintenanceWindow", &arn, ConditionContext::new())?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).windows.remove(&input.window_id);
        Ok(types::DeleteMaintenanceWindowResult { window_id: Some(input.window_id) })
    }

    pub(crate) fn describe_maintenance_windows(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowsRequest,
    ) -> Result<types::DescribeMaintenanceWindowsResult, ServiceError> {
        ctx.authorize("ssm:DescribeMaintenanceWindows", &Self::list_arn(ctx), ConditionContext::new())?;
        let filters = filter_values(&input.filters, &["Name", "Enabled"])?;
        let at = now(ctx);
        let windows: Vec<types::MaintenanceWindowIdentity> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.windows.values().map(|w| identity(w, at)).collect())
                .unwrap_or_default()
        };
        let windows: Vec<_> = windows
            .into_iter()
            .filter(|w| {
                filters.iter().all(|(k, v)| match k.as_str() {
                    "Name" => v.iter().any(|x| w.name.as_deref() == Some(x.as_str())),
                    _ => v.iter().any(|x| x.eq_ignore_ascii_case(if w.enabled { "true" } else { "false" })),
                })
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(windows, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowsResult { window_identities: Some(items), next_token: next })
    }

    pub(crate) fn register_target_with_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::RegisterTargetWithMaintenanceWindowRequest,
    ) -> Result<types::RegisterTargetWithMaintenanceWindowResult, ServiceError> {
        let mut w = self.window_of(ctx, "RegisterTargetWithMaintenanceWindow", &input.window_id)?;
        validate_targets(&input.resource_type, &input.targets)?;
        if w.targets.len() >= MAX_TARGETS {
            return Err(errors::resource_limit_exceeded("The maintenance window has the maximum number of targets."));
        }
        let id = uuid::Uuid::new_v4().to_string();
        w.targets.push(types::MaintenanceWindowTarget {
            window_id: Some(input.window_id),
            window_target_id: Some(id.clone()),
            resource_type: Some(input.resource_type),
            targets: Some(input.targets),
            owner_information: input.owner_information,
            name: input.name,
            description: input.description,
        });
        self.save_window(ctx, w);
        Ok(types::RegisterTargetWithMaintenanceWindowResult { window_target_id: Some(id) })
    }

    pub(crate) fn update_maintenance_window_target(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMaintenanceWindowTargetRequest,
    ) -> Result<types::UpdateMaintenanceWindowTargetResult, ServiceError> {
        let mut w = self.window_of(ctx, "UpdateMaintenanceWindowTarget", &input.window_id)?;
        let replace = input.replace.unwrap_or(false);
        let t = w
            .targets
            .iter_mut()
            .find(|t| t.window_target_id.as_deref() == Some(input.window_target_id.as_str()))
            .ok_or_else(|| {
            errors::does_not_exist(format!("Maintenance window target {} does not exist", input.window_target_id))
        })?;
        if replace && input.targets.is_none() {
            return Err(errors::validation("Targets is required when Replace is true."));
        }
        if let Some(targets) = &input.targets {
            validate_targets(t.resource_type.as_deref().unwrap_or("INSTANCE"), targets)?;
            t.targets = Some(targets.clone());
        }
        if input.owner_information.is_some() || replace {
            t.owner_information = input.owner_information.clone();
        }
        if input.name.is_some() || replace {
            t.name = input.name.clone();
        }
        if input.description.is_some() || replace {
            t.description = input.description.clone();
        }
        let out = types::UpdateMaintenanceWindowTargetResult {
            window_id: t.window_id.clone(),
            window_target_id: t.window_target_id.clone(),
            targets: t.targets.clone(),
            owner_information: t.owner_information.clone(),
            name: t.name.clone(),
            description: t.description.clone(),
        };
        self.save_window(ctx, w);
        Ok(out)
    }

    pub(crate) fn deregister_target_from_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterTargetFromMaintenanceWindowRequest,
    ) -> Result<types::DeregisterTargetFromMaintenanceWindowResult, ServiceError> {
        let mut w = self.window_of(ctx, "DeregisterTargetFromMaintenanceWindow", &input.window_id)?;
        let id = input.window_target_id.clone();
        if !w.targets.iter().any(|t| t.window_target_id.as_deref() == Some(id.as_str())) {
            return Err(errors::does_not_exist(format!("Maintenance window target {id} does not exist")));
        }
        let used = w.tasks.iter().any(|t| {
            t.targets
                .iter()
                .flatten()
                .any(|x| x.key.as_deref() == Some("WindowTargetIds") && x.values.iter().flatten().any(|v| *v == id))
        });
        if used && input.safe.unwrap_or(false) {
            return Err(errors::target_in_use(format!(
                "Maintenance window target {id} is in use by one or more tasks. Remove it from the tasks or deregister it with Safe set to false."
            )));
        }
        w.targets.retain(|t| t.window_target_id.as_deref() != Some(id.as_str()));
        for t in w.tasks.iter_mut() {
            if let Some(targets) = t.targets.as_mut() {
                for x in targets.iter_mut() {
                    if let Some(v) = x.values.as_mut() {
                        v.retain(|v| *v != id);
                    }
                }
            }
        }
        self.save_window(ctx, w);
        Ok(types::DeregisterTargetFromMaintenanceWindowResult {
            window_id: Some(input.window_id),
            window_target_id: Some(id),
        })
    }

    pub(crate) fn describe_maintenance_window_targets(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowTargetsRequest,
    ) -> Result<types::DescribeMaintenanceWindowTargetsResult, ServiceError> {
        let w = self.window_of(ctx, "DescribeMaintenanceWindowTargets", &input.window_id)?;
        let filters = filter_values(&input.filters, &["Type", "WindowTargetId", "OwnerInformation"])?;
        let items: Vec<_> = w
            .targets
            .into_iter()
            .filter(|t| {
                filters.iter().all(|(k, v)| {
                    let value = match k.as_str() {
                        "Type" => t.resource_type.clone(),
                        "WindowTargetId" => t.window_target_id.clone(),
                        _ => t.owner_information.clone(),
                    };
                    v.iter().any(|x| value.as_deref() == Some(x.as_str()))
                })
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowTargetsResult { targets: Some(items), next_token: next })
    }

    pub(crate) fn register_task_with_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::RegisterTaskWithMaintenanceWindowRequest,
    ) -> Result<types::RegisterTaskWithMaintenanceWindowResult, ServiceError> {
        let mut w = self.window_of(ctx, "RegisterTaskWithMaintenanceWindow", &input.window_id)?;
        validate_task(&input.task_type, &input.task_arn)?;
        let targets = input.targets.clone().unwrap_or_default();
        validate_task_targets(&w, &targets)?;
        if input.task_type == "RUN_COMMAND" && targets.is_empty() {
            return Err(errors::validation("Targets is required for RUN_COMMAND tasks."));
        }
        if w.tasks.len() >= MAX_TASKS {
            return Err(errors::resource_limit_exceeded("The maintenance window has the maximum number of tasks."));
        }
        if input.task_type == "RUN_COMMAND" && self.find_document(ctx, &input.task_arn).is_none() {
            return Err(crate::documents::not_found(&input.task_arn));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let targeted = !targets.is_empty();
        w.tasks.push(types::GetMaintenanceWindowTaskResult {
            window_id: Some(input.window_id),
            window_task_id: Some(id.clone()),
            targets: Some(targets),
            task_arn: Some(input.task_arn),
            service_role_arn: input.service_role_arn,
            task_type: Some(input.task_type),
            task_parameters: input.task_parameters,
            task_invocation_parameters: input.task_invocation_parameters,
            priority: input.priority.unwrap_or(1),
            max_concurrency: input.max_concurrency.or_else(|| targeted.then(|| "1".into())),
            max_errors: input.max_errors.or_else(|| targeted.then(|| "1".into())),
            logging_info: input.logging_info,
            name: input.name,
            description: input.description,
            cutoff_behavior: Some(input.cutoff_behavior.unwrap_or_else(|| "CONTINUE_TASK".into())),
            alarm_configuration: input.alarm_configuration,
        });
        self.save_window(ctx, w);
        Ok(types::RegisterTaskWithMaintenanceWindowResult { window_task_id: Some(id) })
    }

    fn task_mut<'a>(
        w: &'a mut Window,
        id: &str,
    ) -> Result<&'a mut types::GetMaintenanceWindowTaskResult, ServiceError> {
        w.tasks
            .iter_mut()
            .find(|t| t.window_task_id.as_deref() == Some(id))
            .ok_or_else(|| errors::does_not_exist(format!("Maintenance window task {id} does not exist")))
    }

    pub(crate) fn get_maintenance_window_task(
        &self,
        ctx: &RequestContext,
        input: types::GetMaintenanceWindowTaskRequest,
    ) -> Result<types::GetMaintenanceWindowTaskResult, ServiceError> {
        let mut w = self.window_of(ctx, "GetMaintenanceWindowTask", &input.window_id)?;
        Ok(Self::task_mut(&mut w, &input.window_task_id)?.clone())
    }

    pub(crate) fn update_maintenance_window_task(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMaintenanceWindowTaskRequest,
    ) -> Result<types::UpdateMaintenanceWindowTaskResult, ServiceError> {
        let mut w = self.window_of(ctx, "UpdateMaintenanceWindowTask", &input.window_id)?;
        if let Some(targets) = &input.targets {
            validate_task_targets(&w, targets)?;
        }
        let replace = input.replace.unwrap_or(false);
        let t = Self::task_mut(&mut w, &input.window_task_id)?;
        if let Some(arn) = &input.task_arn {
            validate_task(t.task_type.as_deref().unwrap_or_default(), arn)?;
        }
        macro_rules! set {
            ($field:ident) => {
                if input.$field.is_some() || replace {
                    t.$field = input.$field.clone();
                }
            };
        }
        set!(targets);
        if input.task_arn.is_some() {
            t.task_arn = input.task_arn.clone();
        }
        set!(service_role_arn);
        set!(task_parameters);
        set!(task_invocation_parameters);
        if let Some(p) = input.priority {
            t.priority = p;
        }
        set!(max_concurrency);
        set!(max_errors);
        set!(logging_info);
        set!(name);
        set!(description);
        if input.cutoff_behavior.is_some() {
            t.cutoff_behavior = input.cutoff_behavior.clone();
        }
        set!(alarm_configuration);
        let t = t.clone();
        self.save_window(ctx, w);
        Ok(types::UpdateMaintenanceWindowTaskResult {
            window_id: t.window_id,
            window_task_id: t.window_task_id,
            targets: t.targets,
            task_arn: t.task_arn,
            service_role_arn: t.service_role_arn,
            task_parameters: t.task_parameters,
            task_invocation_parameters: t.task_invocation_parameters,
            priority: t.priority,
            max_concurrency: t.max_concurrency,
            max_errors: t.max_errors,
            logging_info: t.logging_info,
            name: t.name,
            description: t.description,
            cutoff_behavior: t.cutoff_behavior,
            alarm_configuration: t.alarm_configuration,
        })
    }

    pub(crate) fn deregister_task_from_maintenance_window(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterTaskFromMaintenanceWindowRequest,
    ) -> Result<types::DeregisterTaskFromMaintenanceWindowResult, ServiceError> {
        let mut w = self.window_of(ctx, "DeregisterTaskFromMaintenanceWindow", &input.window_id)?;
        Self::task_mut(&mut w, &input.window_task_id)?;
        w.tasks.retain(|t| t.window_task_id.as_deref() != Some(input.window_task_id.as_str()));
        self.save_window(ctx, w);
        Ok(types::DeregisterTaskFromMaintenanceWindowResult {
            window_id: Some(input.window_id),
            window_task_id: Some(input.window_task_id),
        })
    }

    pub(crate) fn describe_maintenance_window_tasks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowTasksRequest,
    ) -> Result<types::DescribeMaintenanceWindowTasksResult, ServiceError> {
        let w = self.window_of(ctx, "DescribeMaintenanceWindowTasks", &input.window_id)?;
        let filters = filter_values(&input.filters, &["WindowTaskId", "TaskArn", "Type", "Priority"])?;
        let items: Vec<_> = w
            .tasks
            .iter()
            .filter(|t| {
                filters.iter().all(|(k, v)| {
                    let value = match k.as_str() {
                        "WindowTaskId" => t.window_task_id.clone(),
                        "TaskArn" => t.task_arn.clone(),
                        "Type" => t.task_type.clone(),
                        _ => Some(t.priority.to_string()),
                    };
                    v.iter().any(|x| value.as_deref() == Some(x.as_str()))
                })
            })
            .map(task_summary)
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowTasksResult { tasks: Some(items), next_token: next })
    }

    fn windows_matching(
        &self,
        ctx: &RequestContext,
        targets: &[types::Target],
        resource_type: Option<&str>,
    ) -> Vec<Window> {
        let st = self.lock();
        let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) else { return Vec::new() };
        r.windows
            .values()
            .filter(|w| {
                w.targets.iter().any(|t| {
                    resource_type.is_none_or(|rt| t.resource_type.as_deref() == Some(rt))
                        && targets.iter().all(|want| {
                            t.targets.iter().flatten().any(|have| {
                                have.key == want.key
                                    && want
                                        .values
                                        .iter()
                                        .flatten()
                                        .all(|v| have.values.iter().flatten().any(|h| h == v))
                            })
                        })
                })
            })
            .cloned()
            .collect()
    }

    pub(crate) fn describe_maintenance_windows_for_target(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowsForTargetRequest,
    ) -> Result<types::DescribeMaintenanceWindowsForTargetResult, ServiceError> {
        ctx.authorize("ssm:DescribeMaintenanceWindowsForTarget", &Self::list_arn(ctx), ConditionContext::new())?;
        let items: Vec<_> = self
            .windows_matching(ctx, &input.targets, Some(&input.resource_type))
            .into_iter()
            .map(|w| types::MaintenanceWindowIdentityForTarget { window_id: w.window.window_id, name: w.window.name })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowsForTargetResult { window_identities: Some(items), next_token: next })
    }

    pub(crate) fn describe_maintenance_window_schedule(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowScheduleRequest,
    ) -> Result<types::DescribeMaintenanceWindowScheduleResult, ServiceError> {
        ctx.authorize("ssm:DescribeMaintenanceWindowSchedule", &Self::list_arn(ctx), ConditionContext::new())?;
        let windows = match (&input.window_id, &input.targets) {
            (Some(id), _) => vec![self.window_of(ctx, "DescribeMaintenanceWindowSchedule", id)?],
            (None, Some(targets)) => self.windows_matching(ctx, targets, input.resource_type.as_deref()),
            (None, None) => return Err(errors::validation("Specify a WindowId or Targets.")),
        };
        let at = now(ctx);
        let mut until = at + Duration::days(366);
        for f in input.filters.clone().unwrap_or_default() {
            match f.key.as_deref() {
                Some("ScheduledBefore") => {
                    if let Some(t) = f.values.iter().flatten().next().and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                    {
                        until = until.min(t.with_timezone(&Utc));
                    }
                }
                Some("ScheduledAfter") => {}
                other => {
                    return Err(errors::validation(format!(
                        "Filter key {} is not supported.",
                        other.unwrap_or_default()
                    )))
                }
            }
        }
        let after = input
            .filters
            .iter()
            .flatten()
            .find(|f| f.key.as_deref() == Some("ScheduledAfter"))
            .and_then(|f| f.values.iter().flatten().next().and_then(|v| DateTime::parse_from_rfc3339(v).ok()))
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or(at)
            .max(at);
        let mut items = Vec::new();
        for w in windows.iter().filter(|w| w.window.enabled) {
            let tz = parse_tz(w.window.schedule_timezone.as_deref()).unwrap_or(chrono_tz::UTC);
            for t in firings(&w.window, after, until, 100) {
                let local = t.with_timezone(&tz);
                items.push(types::ScheduledWindowExecution {
                    window_id: w.window.window_id.clone(),
                    name: w.window.name.clone(),
                    execution_time: Some(if tz == chrono_tz::UTC {
                        local.format("%Y-%m-%dT%H:%MZ").to_string()
                    } else {
                        local.format("%Y-%m-%dT%H:%M%:z").to_string()
                    }),
                });
            }
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowScheduleResult {
            scheduled_window_executions: Some(items),
            next_token: next,
        })
    }

    fn find_execution(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
    ) -> Result<(String, ExecutionRecord), ServiceError> {
        let found = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| {
                r.windows.iter().find_map(|(wid, w)| {
                    w.executions.iter().find(|e| e.window_execution_id == id).map(|e| (wid.clone(), e.clone()))
                })
            })
        };
        let wid = found.as_ref().map(|(w, _)| w.clone()).unwrap_or_else(|| "*".into());
        ctx.authorize(
            &format!("ssm:{action}"),
            &window_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &wid),
            ConditionContext::new(),
        )?;
        found.ok_or_else(|| errors::does_not_exist(format!("Maintenance window execution {id} does not exist")))
    }

    pub(crate) fn describe_maintenance_window_executions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowExecutionsRequest,
    ) -> Result<types::DescribeMaintenanceWindowExecutionsResult, ServiceError> {
        let w = self.window_of(ctx, "DescribeMaintenanceWindowExecutions", &input.window_id)?;
        let filters = filter_values(&input.filters, &["ExecutedBefore", "ExecutedAfter"])?;
        let items: Vec<_> = w
            .executions
            .iter()
            .filter(|e| {
                filters.iter().all(|(k, v)| {
                    let Some(t) = v.first().and_then(|v| DateTime::parse_from_rfc3339(v).ok()) else { return false };
                    if k == "ExecutedBefore" {
                        e.start <= t
                    } else {
                        e.start >= t
                    }
                })
            })
            .map(|e| types::MaintenanceWindowExecution {
                window_id: Some(input.window_id.clone()),
                window_execution_id: Some(e.window_execution_id.clone()),
                status: Some(e.status.clone()),
                status_details: (!e.status_details.is_empty()).then(|| e.status_details.clone()),
                start_time: Some(e.start),
                end_time: e.end,
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowExecutionsResult { window_executions: Some(items), next_token: next })
    }

    pub(crate) fn get_maintenance_window_execution(
        &self,
        ctx: &RequestContext,
        input: types::GetMaintenanceWindowExecutionRequest,
    ) -> Result<types::GetMaintenanceWindowExecutionResult, ServiceError> {
        let (_, e) = self.find_execution(ctx, "GetMaintenanceWindowExecution", &input.window_execution_id)?;
        Ok(types::GetMaintenanceWindowExecutionResult {
            window_execution_id: Some(e.window_execution_id.clone()),
            task_ids: Some(e.tasks.iter().map(|t| t.task_execution_id.clone()).collect()),
            status: Some(e.status.clone()),
            status_details: (!e.status_details.is_empty()).then(|| e.status_details.clone()),
            start_time: Some(e.start),
            end_time: e.end,
        })
    }

    fn task_execution(e: &ExecutionRecord, id: &str) -> Result<TaskExecutionRecord, ServiceError> {
        e.tasks
            .iter()
            .find(|t| t.task_execution_id == id)
            .cloned()
            .ok_or_else(|| errors::does_not_exist(format!("Maintenance window task execution {id} does not exist")))
    }

    pub(crate) fn describe_maintenance_window_execution_tasks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowExecutionTasksRequest,
    ) -> Result<types::DescribeMaintenanceWindowExecutionTasksResult, ServiceError> {
        let (_, e) = self.find_execution(ctx, "DescribeMaintenanceWindowExecutionTasks", &input.window_execution_id)?;
        let filters = filter_values(&input.filters, &["Status"])?;
        let items: Vec<_> = e
            .tasks
            .iter()
            .filter(|t| filters.iter().all(|(_, v)| v.contains(&t.status)))
            .map(|t| types::MaintenanceWindowExecutionTaskIdentity {
                window_execution_id: Some(e.window_execution_id.clone()),
                task_execution_id: Some(t.task_execution_id.clone()),
                status: Some(t.status.clone()),
                status_details: (!t.status_details.is_empty()).then(|| t.status_details.clone()),
                start_time: t.start,
                end_time: t.end,
                task_arn: t.task.task_arn.clone(),
                task_type: t.task.task_type.clone(),
                alarm_configuration: t.task.alarm_configuration.clone(),
                triggered_alarms: None,
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowExecutionTasksResult {
            window_execution_task_identities: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn get_maintenance_window_execution_task(
        &self,
        ctx: &RequestContext,
        input: types::GetMaintenanceWindowExecutionTaskRequest,
    ) -> Result<types::GetMaintenanceWindowExecutionTaskResult, ServiceError> {
        let (_, e) = self.find_execution(ctx, "GetMaintenanceWindowExecutionTask", &input.window_execution_id)?;
        let t = Self::task_execution(&e, &input.task_id)?;
        Ok(types::GetMaintenanceWindowExecutionTaskResult {
            window_execution_id: Some(e.window_execution_id.clone()),
            task_execution_id: Some(t.task_execution_id.clone()),
            task_arn: t.task.task_arn.clone(),
            service_role: t.task.service_role_arn.clone(),
            r#type: t.task.task_type.clone(),
            task_parameters: t.task.task_parameters.clone().map(|p| vec![p]),
            priority: t.task.priority,
            max_concurrency: t.task.max_concurrency.clone(),
            max_errors: t.task.max_errors.clone(),
            status: Some(t.status.clone()),
            status_details: (!t.status_details.is_empty()).then(|| t.status_details.clone()),
            start_time: t.start,
            end_time: t.end,
            alarm_configuration: t.task.alarm_configuration.clone(),
            triggered_alarms: None,
        })
    }

    fn invocation_identity(
        e: &ExecutionRecord,
        t: &TaskExecutionRecord,
        i: &TaskInvocationRecord,
    ) -> types::MaintenanceWindowExecutionTaskInvocationIdentity {
        types::MaintenanceWindowExecutionTaskInvocationIdentity {
            window_execution_id: Some(e.window_execution_id.clone()),
            task_execution_id: Some(t.task_execution_id.clone()),
            invocation_id: Some(i.invocation_id.clone()),
            execution_id: (!i.execution_id.is_empty()).then(|| i.execution_id.clone()),
            task_type: t.task.task_type.clone(),
            parameters: Some(i.parameters.clone()),
            status: Some(i.status.clone()),
            status_details: (!i.status_details.is_empty()).then(|| i.status_details.clone()),
            start_time: i.start,
            end_time: i.end,
            owner_information: i.owner_information.clone(),
            window_target_id: i.window_target_id.clone(),
        }
    }

    pub(crate) fn describe_maintenance_window_execution_task_invocations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMaintenanceWindowExecutionTaskInvocationsRequest,
    ) -> Result<types::DescribeMaintenanceWindowExecutionTaskInvocationsResult, ServiceError> {
        let (_, e) =
            self.find_execution(ctx, "DescribeMaintenanceWindowExecutionTaskInvocations", &input.window_execution_id)?;
        let t = Self::task_execution(&e, &input.task_id)?;
        let filters = filter_values(&input.filters, &["Status"])?;
        let items: Vec<_> = t
            .invocations
            .iter()
            .filter(|i| filters.iter().all(|(_, v)| v.contains(&i.status)))
            .map(|i| Self::invocation_identity(&e, &t, i))
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(10, 100) as usize;
        let (items, next) = page(items, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeMaintenanceWindowExecutionTaskInvocationsResult {
            window_execution_task_invocation_identities: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn get_maintenance_window_execution_task_invocation(
        &self,
        ctx: &RequestContext,
        input: types::GetMaintenanceWindowExecutionTaskInvocationRequest,
    ) -> Result<types::GetMaintenanceWindowExecutionTaskInvocationResult, ServiceError> {
        let (_, e) =
            self.find_execution(ctx, "GetMaintenanceWindowExecutionTaskInvocation", &input.window_execution_id)?;
        let t = Self::task_execution(&e, &input.task_id)?;
        let i = t.invocations.iter().find(|i| i.invocation_id == input.invocation_id).ok_or_else(|| {
            errors::does_not_exist(format!("Maintenance window task invocation {} does not exist", input.invocation_id))
        })?;
        let x = Self::invocation_identity(&e, &t, i);
        Ok(types::GetMaintenanceWindowExecutionTaskInvocationResult {
            window_execution_id: x.window_execution_id,
            task_execution_id: x.task_execution_id,
            invocation_id: x.invocation_id,
            execution_id: x.execution_id,
            task_type: x.task_type,
            parameters: x.parameters,
            status: x.status,
            status_details: x.status_details,
            start_time: x.start_time,
            end_time: x.end_time,
            owner_information: x.owner_information,
            window_target_id: x.window_target_id,
        })
    }

    pub(crate) fn cancel_maintenance_window_execution(
        &self,
        ctx: &RequestContext,
        input: types::CancelMaintenanceWindowExecutionRequest,
    ) -> Result<types::CancelMaintenanceWindowExecutionResult, ServiceError> {
        let (wid, _) = self.find_execution(ctx, "CancelMaintenanceWindowExecution", &input.window_execution_id)?;
        let at = now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(e) = r
            .windows
            .get_mut(&wid)
            .and_then(|w| w.executions.iter_mut().find(|e| e.window_execution_id == input.window_execution_id))
        {
            if matches!(e.status.as_str(), "PENDING" | "IN_PROGRESS") {
                e.status = "CANCELLED".into();
                e.end = Some(at);
                for t in e.tasks.iter_mut().filter(|t| matches!(t.status.as_str(), "PENDING" | "IN_PROGRESS")) {
                    t.status = "CANCELLED".into();
                    t.end = Some(at);
                }
                r.window_events.push(WindowEvent {
                    account: ctx.caller.account_id.clone(),
                    region: ctx.region.clone(),
                    window_id: wid.clone(),
                    window_execution_id: input.window_execution_id.clone(),
                    status: "CANCELLED".into(),
                    start: e.start,
                    end: Some(at),
                    time: at,
                });
            }
        }
        Ok(types::CancelMaintenanceWindowExecutionResult { window_execution_id: Some(input.window_execution_id) })
    }

    /// Start the window executions due by `now` (the emulated clock), and
    /// hand out the execution state changes since the last call.
    pub fn take_window_events(&self, now: DateTime<Utc>) -> Vec<WindowEvent> {
        self.run_windows(now, true)
    }

    /// Start the window executions due by `now`; with `drain`, also hand
    /// out the pending state changes.
    pub(crate) fn run_windows(&self, now: DateTime<Utc>, drain: bool) -> Vec<WindowEvent> {
        let mut starts = Vec::new();
        let mut out = Vec::new();
        {
            let mut st = self.lock();
            for (key, region) in st.regions.iter_mut() {
                let Some((account, region_name)) = key.split_once('/') else { continue };
                for (wid, w) in region.windows.iter_mut() {
                    let since = w.checked_until.unwrap_or(now);
                    if since >= now {
                        continue;
                    }
                    w.checked_until = Some(now);
                    if !w.window.enabled {
                        continue;
                    }
                    for at in firings(&w.window, since, now, 5) {
                        let busy = w.executions.iter().any(|e| matches!(e.status.as_str(), "PENDING" | "IN_PROGRESS"));
                        let id = uuid::Uuid::new_v4().to_string();
                        let mut e =
                            ExecutionRecord { window_execution_id: id.clone(), start: at, ..Default::default() };
                        if busy {
                            e.status = "SKIPPED_OVERLAPPING".into();
                            e.status_details =
                                "The previous execution of this maintenance window is still running.".into();
                            e.end = Some(at);
                        } else {
                            e.status = "IN_PROGRESS".into();
                            let mut tasks = w.tasks.clone();
                            tasks.sort_by_key(|t| t.priority);
                            e.tasks = tasks
                                .into_iter()
                                .map(|t| TaskExecutionRecord {
                                    task_execution_id: uuid::Uuid::new_v4().to_string(),
                                    window_task_id: t.window_task_id.clone().unwrap_or_default(),
                                    task: t,
                                    status: "PENDING".into(),
                                    ..Default::default()
                                })
                                .collect();
                            starts.push((account.to_string(), region_name.to_string(), wid.clone(), id.clone(), at));
                        }
                        region.window_events.push(WindowEvent {
                            account: account.to_string(),
                            region: region_name.to_string(),
                            window_id: wid.clone(),
                            window_execution_id: id,
                            status: e.status.clone(),
                            start: at,
                            end: e.end,
                            time: at,
                        });
                        w.executions.insert(0, e);
                    }
                }
                if drain {
                    out.append(&mut region.window_events);
                }
            }
        }
        for (account, region, wid, eid, at) in starts {
            let ssm = self.clone();
            spawn(async move { ssm.run_execution(&account, &region, &wid, &eid, at).await });
        }
        out
    }

    fn with_execution<R>(
        &self,
        account: &str,
        region: &str,
        wid: &str,
        eid: &str,
        f: impl FnOnce(&mut Window, usize) -> R,
    ) -> Option<R> {
        let mut st = self.lock();
        let w = st.region(account, region).windows.get_mut(wid)?;
        let n = w.executions.iter().position(|e| e.window_execution_id == eid)?;
        Some(f(w, n))
    }

    async fn run_execution(&self, account: &str, region: &str, wid: &str, eid: &str, start: DateTime<Utc>) {
        let started = std::time::Instant::now();
        let clock = || start + Duration::from_std(started.elapsed()).unwrap_or_default();
        let Some(count) = self.with_execution(account, region, wid, eid, |w, n| w.executions[n].tasks.len()) else {
            return;
        };
        let mut failed = false;
        for k in 0..count {
            let Some(Some((task, window))) = self.with_execution(account, region, wid, eid, |w, n| {
                let e = &mut w.executions[n];
                if e.status != "IN_PROGRESS" {
                    return None;
                }
                let t = &mut e.tasks[k];
                t.status = "IN_PROGRESS".into();
                t.start = Some(clock());
                Some((t.clone(), w.clone()))
            }) else {
                return;
            };
            let (status, details, invocations) = self.run_task(account, region, &window, eid, &task, &clock).await;
            if status != "SUCCESS" {
                failed = true;
            }
            self.with_execution(account, region, wid, eid, |w, n| {
                let t = &mut w.executions[n].tasks[k];
                if t.status == "IN_PROGRESS" {
                    t.status = status.to_string();
                    t.status_details = details;
                    t.end = Some(clock());
                    t.invocations = invocations;
                }
            });
        }
        let end = clock();
        let event = self.with_execution(account, region, wid, eid, |w, n| {
            let e = &mut w.executions[n];
            if e.status != "IN_PROGRESS" {
                return None;
            }
            e.status = if failed { "FAILED" } else { "SUCCESS" }.into();
            if failed {
                e.status_details = "One or more tasks in the orchestration failed.".into();
            }
            e.end = Some(end);
            let event = WindowEvent {
                account: account.to_string(),
                region: region.to_string(),
                window_id: wid.to_string(),
                window_execution_id: eid.to_string(),
                status: e.status.clone(),
                start: e.start,
                end: Some(end),
                time: end,
            };
            Some(event)
        });
        if let Some(event) = event.flatten() {
            self.lock().region(account, region).window_events.push(event);
        }
    }

    /// The managed nodes a task runs on, with the window target each came
    /// from.
    fn task_nodes(
        &self,
        account: &str,
        region: &str,
        w: &Window,
        task: &types::GetMaintenanceWindowTaskResult,
    ) -> Vec<(String, Option<types::MaintenanceWindowTarget>)> {
        let mut out: Vec<(String, Option<types::MaintenanceWindowTarget>)> = Vec::new();
        for t in task.targets.iter().flatten() {
            let values = t.values.clone().unwrap_or_default();
            match t.key.as_deref() {
                Some("WindowTargetIds") => {
                    for target in
                        w.targets.iter().filter(|x| x.window_target_id.as_ref().is_some_and(|id| values.contains(id)))
                    {
                        let ids = self
                            .resolve_targets(account, region, target.targets.as_deref().unwrap_or_default())
                            .unwrap_or_default();
                        for id in ids {
                            if !out.iter().any(|(x, _)| *x == id) {
                                out.push((id, Some(target.clone())));
                            }
                        }
                    }
                }
                Some("InstanceIds") => out.extend(values.into_iter().map(|v| (v, None))),
                _ => {}
            }
        }
        out
    }

    async fn run_task(
        &self,
        account: &str,
        region: &str,
        w: &Window,
        eid: &str,
        te: &TaskExecutionRecord,
        clock: &(dyn Fn() -> DateTime<Utc> + Sync),
    ) -> (&'static str, String, Vec<TaskInvocationRecord>) {
        let task = &te.task;
        let wid = w.window.window_id.clone().unwrap_or_default();
        let nodes = self.task_nodes(account, region, w, task);
        let targeted = task.targets.as_ref().is_some_and(|t| !t.is_empty());
        if targeted && nodes.is_empty() {
            return ("SUCCESS", "No targets were found for this task.".into(), Vec::new());
        }
        let runs: Vec<(Option<String>, Option<types::MaintenanceWindowTarget>)> =
            if targeted { nodes.into_iter().map(|(id, t)| (Some(id), t)).collect() } else { vec![(None, None)] };
        let mut invocations = Vec::new();
        let mut failed = 0;
        for (resource, target) in runs {
            let invocation_id = uuid::Uuid::new_v4().to_string();
            let mut vars: BTreeMap<&str, String> = BTreeMap::new();
            vars.insert("WINDOW_ID", wid.clone());
            vars.insert("WINDOW_EXECUTION_ID", eid.to_string());
            vars.insert("TASK_EXECUTION_ID", te.task_execution_id.clone());
            vars.insert("INVOCATION_ID", invocation_id.clone());
            vars.insert("RESOURCE_ID", resource.clone().unwrap_or_default());
            vars.insert("TARGET_ID", resource.clone().unwrap_or_default());
            vars.insert(
                "TARGET_TYPE",
                target.as_ref().and_then(|t| t.resource_type.clone()).unwrap_or_else(|| "INSTANCE".into()),
            );
            vars.insert(
                "WINDOW_TARGET_ID",
                target.as_ref().and_then(|t| t.window_target_id.clone()).unwrap_or_default(),
            );
            vars.insert(
                "OWNER_INFORMATION",
                target.as_ref().and_then(|t| t.owner_information.clone()).unwrap_or_default(),
            );
            let mut inv = TaskInvocationRecord {
                invocation_id,
                window_target_id: target.as_ref().and_then(|t| t.window_target_id.clone()),
                owner_information: target.as_ref().and_then(|t| t.owner_information.clone()),
                start: Some(clock()),
                ..Default::default()
            };
            let (status, details, execution_id, parameters) = match task.task_type.as_deref() {
                Some("RUN_COMMAND") => self.run_command_task(account, region, task, resource.as_deref(), &vars).await,
                Some("LAMBDA") => self.run_lambda_task(account, region, task, &vars, clock()).await,
                Some("AUTOMATION") => {
                    let params: BTreeMap<String, Vec<String>> = task
                        .task_invocation_parameters
                        .as_ref()
                        .and_then(|p| p.automation.as_ref())
                        .and_then(|a| a.parameters.clone())
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(k, v)| (k, v.iter().map(|x| pseudo(x, &vars)).collect()))
                        .collect();
                    let partition = self.template().map(|t| t.partition).unwrap_or_else(|| "aws".into());
                    let arn = window_arn(&partition, region, account, &wid);
                    self.run_automation_task(account, region, task, params, &arn).await
                }
                Some(other) => (
                    "FAILED",
                    format!("MWS does not run {other} maintenance window tasks."),
                    String::new(),
                    String::new(),
                ),
                None => ("FAILED", String::new(), String::new(), String::new()),
            };
            if status != "SUCCESS" {
                failed += 1;
            }
            inv.status = status.into();
            inv.status_details = details;
            inv.execution_id = execution_id;
            inv.parameters = parameters;
            inv.end = Some(clock());
            invocations.push(inv);
        }
        let max_errors = task.max_errors.as_deref().and_then(|m| m.parse::<usize>().ok()).unwrap_or(0);
        if failed > max_errors || (failed > 0 && !targeted) {
            ("FAILED", "One or more invocations failed.".into(), invocations)
        } else {
            ("SUCCESS", String::new(), invocations)
        }
    }

    async fn run_command_task(
        &self,
        account: &str,
        region: &str,
        task: &types::GetMaintenanceWindowTaskResult,
        resource: Option<&str>,
        vars: &BTreeMap<&str, String>,
    ) -> (&'static str, String, String, String) {
        let rc = task.task_invocation_parameters.as_ref().and_then(|p| p.run_command.clone()).unwrap_or_default();
        let mut params: BTreeMap<String, Vec<String>> = rc.parameters.clone().unwrap_or_default();
        if params.is_empty() {
            for (k, v) in task.task_parameters.clone().unwrap_or_default() {
                params.insert(k, v.values.unwrap_or_default());
            }
        }
        for values in params.values_mut() {
            for v in values.iter_mut() {
                *v = pseudo(v, vars);
            }
        }
        let parameters = serde_json::json!({
            "documentName": task.task_arn,
            "instanceIds": resource.map(|r| vec![r.to_string()]).unwrap_or_default(),
            "parameters": params,
        })
        .to_string();
        let Some(resource) = resource else {
            return ("FAILED", "Run Command tasks need targets.".into(), String::new(), parameters);
        };
        let launch = Launch {
            document_name: task.task_arn.clone().unwrap_or_default(),
            document_version: rc.document_version.clone(),
            document_hash: rc.document_hash.clone(),
            parameters: params,
            instance_ids: vec![resource.to_string()],
            explicit: true,
            comment: rc.comment.clone().map(|c| pseudo(&c, vars)),
            timeout_seconds: rc.timeout_seconds,
            output_s3_bucket_name: rc.output_s3_bucket_name.clone(),
            output_s3_key_prefix: rc.output_s3_key_prefix.clone(),
            service_role_arn: rc.service_role_arn.clone().or_else(|| task.service_role_arn.clone()),
            notification_config: rc.notification_config.clone(),
            cloud_watch_output_config: rc.cloud_watch_output_config.clone(),
            ..Default::default()
        };
        let started = Utc::now();
        let command = match self.launch(account, region, started, launch) {
            Ok(c) => c,
            Err(e) => return ("FAILED", e.message.clone(), String::new(), parameters),
        };
        let id = command.command_id.clone().unwrap_or_default();
        let timeout =
            std::time::Duration::from_secs(u64::try_from(command.timeout_seconds.unwrap_or(3600)).unwrap_or(3600) + 5);
        let begin = std::time::Instant::now();
        loop {
            let Some((view, _)) = self.command_status(account, region, &id) else {
                return ("FAILED", "The command disappeared.".into(), id, parameters);
            };
            match view.status.as_deref() {
                Some("Success") => return ("SUCCESS", "Success".into(), id, parameters),
                Some("Pending" | "InProgress" | "Cancelling") if begin.elapsed() < timeout => {}
                Some("Pending" | "InProgress" | "Cancelling") => {
                    return ("TIMED_OUT", "The command timed out.".into(), id, parameters)
                }
                Some("Cancelled") => return ("CANCELLED", "Cancelled".into(), id, parameters),
                Some("TimedOut") => return ("TIMED_OUT", "TimedOut".into(), id, parameters),
                _ => return ("FAILED", "Failed".into(), id, parameters),
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn run_lambda_task(
        &self,
        account: &str,
        region: &str,
        task: &types::GetMaintenanceWindowTaskResult,
        vars: &BTreeMap<&str, String>,
        at: DateTime<Utc>,
    ) -> (&'static str, String, String, String) {
        let lp = task.task_invocation_parameters.as_ref().and_then(|p| p.lambda.clone()).unwrap_or_default();
        let payload = lp.payload.clone().map(|p| pseudo(&String::from_utf8_lossy(&p), vars)).unwrap_or_default();
        let parameters = serde_json::json!({"payload": payload, "qualifier": lp.qualifier}).to_string();
        let Some(invoker) = self.invoker() else {
            return ("FAILED", "Lambda is not available.".into(), String::new(), parameters);
        };
        let Some(template) = self.template() else {
            return ("FAILED", "Lambda is not available.".into(), String::new(), parameters);
        };
        let mut ctx = template;
        ctx.region = region.to_string();
        ctx.caller.account_id = account.to_string();
        ctx.received_at = at;
        ctx.request_id = uuid::Uuid::new_v4().to_string();
        let window_arn = window_arn(&ctx.partition, region, account, task.window_id.as_deref().unwrap_or_default());
        let role = task.service_role_arn.clone();
        let function = task.task_arn.clone().unwrap_or_default();
        match invoker
            .invoke_lambda(&ctx, role.as_deref(), &window_arn, &function, lp.qualifier.as_deref(), payload.into_bytes())
            .await
        {
            Ok(request_id) => ("SUCCESS", String::new(), request_id, parameters),
            Err(e) => ("FAILED", e, String::new(), parameters),
        }
    }

    /// The tags of the caller's window `id`, for the tagging calls.
    pub(crate) fn window_tags_mut<'a>(
        region: &'a mut crate::state::Region,
        id: &str,
    ) -> Option<&'a mut BTreeMap<String, String>> {
        region.windows.get_mut(id).map(|w| &mut w.tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(schedule: &str) -> types::GetMaintenanceWindowResult {
        types::GetMaintenanceWindowResult {
            schedule: Some(schedule.into()),
            duration: Some(2),
            cutoff: 1,
            enabled: true,
            created_date: Some(DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z").unwrap().with_timezone(&Utc)),
            ..Default::default()
        }
    }

    #[test]
    fn schedules_fire() {
        let t0 = DateTime::parse_from_rfc3339("2026-11-02T00:00:00Z").unwrap().with_timezone(&Utc);
        let w = window("cron(0 4 ? * SUN *)");
        assert_eq!(next_execution(&w, t0).as_deref(), Some("2026-11-08T04:00Z"));
        let mut w2 = w.clone();
        w2.schedule_offset = Some(2);
        assert_eq!(next_execution(&w2, t0).as_deref(), Some("2026-11-03T04:00Z"));
        let mut w3 = window("cron(0 9 ? * * *)");
        w3.schedule_timezone = Some("America/Los_Angeles".into());
        assert_eq!(next_execution(&w3, t0).as_deref(), Some("2026-11-02T09:00-08:00"));
        let at = window("at(2026-12-01T10:00:00)");
        assert_eq!(firings(&at, t0, t0 + Duration::days(60), 5).len(), 1);
        assert!(validate_window(&window("rate(nope)")).is_err());
        let mut bad = window("rate(1 hour)");
        bad.cutoff = 2;
        assert!(validate_window(&bad).is_err());
    }
}
