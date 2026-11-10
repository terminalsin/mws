//! Rotation. `RotateSecret` stores the configuration, adds an empty
//! `AWSPENDING` version for the rotation's `ClientRequestToken`, and runs
//! the rotation function as `secretsmanager.amazonaws.com` through its four
//! steps in the background, as Secrets Manager does. The function does the
//! work by calling back into Secrets Manager with its execution role
//! (`PutSecretValue` with `AWSPENDING`, then `UpdateSecretVersionStage` to
//! move `AWSCURRENT`). Scheduled rotations start once the emulated clock
//! reaches their window.

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_lambda::{ServiceInvocation, ServiceInvokeError};

use crate::generated::{errors, types};
use crate::names::{self, in_region, SERVICE_PRINCIPAL};
use crate::ops::{check_live, check_primary};
use crate::schedule::{self, Schedule};
use crate::state::{Secret, Version, CURRENT, PENDING};
use crate::SecretsManager;

const STEPS: [&str; 4] = ["createSecret", "setSecret", "testSecret", "finishSecret"];

fn cannot_invoke() -> ServiceError {
    ServiceError::client(
        "AccessDeniedException",
        400,
        "Secrets Manager cannot invoke the specified Lambda function. Ensure that the function policy grants access to the principal secretsmanager.amazonaws.com.",
    )
}

/// The schedule and window length rotation rules describe.
fn parse_rules(rules: &types::RotationRulesType) -> Result<(Schedule, Option<Duration>), ServiceError> {
    // Stored rules for `rate(N days)` carry both: the expression wins.
    let schedule = match (rules.automatically_after_days, &rules.schedule_expression) {
        (_, Some(e)) => schedule::parse(e).map_err(errors::invalid_parameter)?,
        (Some(days), None) => Schedule::Days(days),
        (None, None) => {
            return Err(errors::invalid_parameter(
                "You must specify either AutomaticallyAfterDays or ScheduleExpression in RotationRules.",
            ))
        }
    };
    let duration =
        rules.duration.as_deref().map(schedule::parse_duration).transpose().map_err(errors::invalid_parameter)?;
    Ok((schedule, duration))
}

/// The next window for a secret's rules, counted from `from`.
fn next_window(rules: Option<&types::RotationRulesType>, from: DateTime<Utc>) -> Option<schedule::Window> {
    let (schedule, duration) = parse_rules(rules?).ok()?;
    schedule.next_window(from, duration)
}

impl SecretsManager {
    pub(crate) fn rotate_secret(
        &self,
        ctx: &RequestContext,
        input: types::RotateSecretRequest,
    ) -> Result<types::RotateSecretResponse, ServiceError> {
        let immediately = input.rotate_immediately.unwrap_or(true);
        let mut c = ConditionContext::new();
        if let Some(l) = &input.rotation_lambda_arn {
            c.insert("secretsmanager:RotationLambdaARN".into(), vec![l.clone()]);
        }
        c.insert("secretsmanager:ModifyRotationRules".into(), vec![input.rotation_rules.is_some().to_string()]);
        c.insert("secretsmanager:RotateImmediately".into(), vec![immediately.to_string()]);
        let s = self.find(ctx, &input.secret_id, "secretsmanager:RotateSecret", c)?;
        check_live(&s)?;
        check_primary(&s)?;
        let now = ctx.received_at;
        let rules = match &input.rotation_rules {
            Some(r) => {
                if r.automatically_after_days.is_some() && r.schedule_expression.is_some() {
                    return Err(errors::invalid_parameter(
                        "You cannot specify both rotation frequency and schedule expression together.",
                    ));
                }
                let (schedule, duration) = parse_rules(r)?;
                if let Some(d) = duration {
                    schedule.check_duration(d, now).map_err(errors::invalid_parameter)?;
                }
                let mut r = r.clone();
                if let Schedule::Days(n) = schedule {
                    r.automatically_after_days = Some(n);
                }
                Some(r)
            }
            None => s.rotation.rules.clone(),
        };
        let lambda_arn = input.rotation_lambda_arn.clone().or_else(|| s.rotation.lambda_arn.clone());
        let external = input.external_secret_rotation_role_arn.is_some() || s.rotation.external_role_arn.is_some();
        // Secrets another service manages rotate through that service.
        let managed = match (&s.owning_service, &lambda_arn) {
            (Some(owner), None) => self.managed_rotation(owner),
            _ => None,
        };
        if let Some(rotator) = managed {
            let rules = rules.or_else(|| {
                Some(types::RotationRulesType {
                    automatically_after_days: Some(7),
                    schedule_expression: Some("rate(7 days)".into()),
                    ..Default::default()
                })
            });
            self.update(&s.arn, |st| {
                st.rotation.enabled = true;
                st.rotation.rules = rules.clone();
                Ok(())
            })?;
            let version_id = if immediately {
                Some(rotator.rotate(ctx, &s.arn).map_err(errors::internal_service_error)?)
            } else {
                let window = next_window(rules.as_ref(), s.rotation.last_rotated.unwrap_or(now));
                self.update(&s.arn, |st| {
                    st.rotation.window_start = window.map(|w| w.start);
                    st.rotation.next = window.map(|w| w.next_rotation_date());
                    Ok(())
                })?;
                None
            };
            return Ok(types::RotateSecretResponse { arn: Some(s.arn), name: Some(s.name), version_id });
        }
        if lambda_arn.is_none() && !external {
            return Err(errors::invalid_request("No Lambda rotation function ARN is associated with this secret."));
        }
        // A rotation that failed leaves its AWSPENDING version behind. A
        // retry reattempts that rotation with the same version (and
        // token); any other request is refused while Secrets Manager
        // reattempts it.
        let resume = match s.pending_rotation() {
            Some(p) => {
                let id = p.id.clone();
                let running = s.rotation.token.is_some();
                let same = input.client_request_token.as_deref().is_none_or(|t| t == id);
                if running || !same || !immediately || lambda_arn.is_none() {
                    if !running && lambda_arn.is_some() && s.rotation.lambda_arn.is_some() {
                        self.begin(ctx, &s.arn, &id, false)?;
                    }
                    return Err(errors::invalid_request(
                        "A previous rotation isn't complete. That rotation will be reattempted.",
                    ));
                }
                Some(id)
            }
            None => None,
        };
        if let Some(l) = &lambda_arn {
            ctx.authorize("lambda:InvokeFunction", l, ConditionContext::new())?;
            let lambda = self.lambda().ok_or_else(cannot_invoke)?;
            lambda
                .check_service_invoke(&in_region(ctx, &s.region), &invocation(l, &s, Vec::new()))
                .map_err(|_| cannot_invoke())?;
        }
        let token = match resume {
            Some(id) => id,
            None => {
                let token = input.client_request_token.clone().unwrap_or_else(names::new_token);
                if s.version(&token).is_some() {
                    return Err(errors::resource_exists(
                        "You can't modify an existing version, you can only create a new version.",
                    ));
                }
                crate::ops::check_quotas(&s, Some(&token), &[PENDING.into()], now)?;
                token
            }
        };
        let from = s.rotation.last_rotated.unwrap_or(now);
        let window = next_window(rules.as_ref(), if immediately { now } else { from });
        self.update(&s.arn, |st| {
            st.rotation.enabled = true;
            st.rotation.lambda_arn = lambda_arn.clone();
            st.rotation.rules = rules.clone();
            if input.external_secret_rotation_metadata.is_some() {
                st.rotation.external_metadata = input.external_secret_rotation_metadata.clone();
            }
            if input.external_secret_rotation_role_arn.is_some() {
                st.rotation.external_role_arn = input.external_secret_rotation_role_arn.clone();
            }
            st.rotation.window_start = window.map(|w| w.start);
            st.rotation.next = window.map(|w| w.next_rotation_date());
            st.last_changed = now;
            Ok(())
        })?;
        self.sync_replicas(ctx, &s.arn, &[]);
        let version_id = match (&lambda_arn, immediately) {
            (Some(_), true) => {
                self.begin(ctx, &s.arn, &token, false)?;
                Some(token)
            }
            (Some(_), false) => {
                // Test the configuration: testSecret on a pending version
                // that is removed afterwards.
                self.begin(ctx, &s.arn, &token, true)?;
                None
            }
            (None, _) => None,
        };
        Ok(types::RotateSecretResponse { arn: Some(s.arn), name: Some(s.name), version_id })
    }

    /// Add the pending version (or reuse it, when reattempting a rotation
    /// that did not complete) and start the rotation function.
    fn begin(&self, ctx: &RequestContext, arn: &str, token: &str, test_only: bool) -> Result<(), ServiceError> {
        let now = ctx.received_at;
        let rotation_token = names::new_token();
        self.update(arn, |st| {
            if st.version(token).is_none() {
                st.versions.push(Version {
                    id: token.to_string(),
                    stages: Vec::new(),
                    created: now,
                    last_accessed: None,
                    value: None,
                });
            }
            st.attach(PENDING, token);
            st.rotation.token = Some(rotation_token.clone());
            Ok(())
        })?;
        let this = self.clone();
        let ctx = ctx.clone();
        let (arn, token) = (arn.to_string(), token.to_string());
        tokio::spawn(async move { this.run(ctx, arn, token, rotation_token, test_only).await });
        Ok(())
    }

    async fn run(&self, ctx: RequestContext, arn: String, token: String, rotation_token: String, test_only: bool) {
        let started = std::time::Instant::now();
        let Some(secret) = self.lock().secrets.get(&arn).cloned() else { return };
        let (Some(lambda), Some(function)) = (self.lambda().cloned(), secret.rotation.lambda_arn.clone()) else {
            // Nothing to run: don't leave the rotation marked as running.
            let _ = self.update(&arn, |st| {
                st.rotation.token = None;
                Ok(())
            });
            return;
        };
        let rctx = in_region(&ctx, &secret.region);
        let steps: &[&str] = if test_only { &STEPS[2..3] } else { &STEPS };
        let mut ok = true;
        for step in steps {
            let payload = serde_json::json!({
                "Step": step,
                "SecretId": arn,
                "ClientRequestToken": token,
                "RotationToken": rotation_token,
            });
            let result =
                lambda.invoke_as_service(&rctx, invocation(&function, &secret, payload.to_string().into_bytes())).await;
            let failure = match result {
                Ok(r) => r.function_error.map(|e| format!("{e}: {}", String::from_utf8_lossy(&r.payload))),
                Err(ServiceInvokeError::Failed(m)) => Some(m),
                Err(e) => Some(format!("{e:?}")),
            };
            if let Some(f) = failure {
                tracing::warn!(secret = %arn, %step, "rotation function failed: {f}");
                ok = false;
                break;
            }
        }
        let now = ctx.received_at + Duration::from_std(started.elapsed()).unwrap_or_default();
        let _ = self.update(&arn, |st| {
            st.rotation.token = None;
            if test_only {
                match st.version(&token).map(|v| v.value.is_some()) {
                    Some(false) => st.versions.retain(|v| v.id != token),
                    Some(true) => {
                        if let Some(v) = st.version_mut(&token) {
                            v.stages.retain(|s| s != PENDING);
                        }
                    }
                    None => {}
                }
                return Ok(());
            }
            let current = st.version(&token).is_some_and(|v| v.stages.iter().any(|s| s == CURRENT));
            if ok && current {
                if let Some(v) = st.version_mut(&token) {
                    v.stages.retain(|s| s != PENDING);
                }
                st.rotation.last_rotated = Some(now);
                let window = next_window(st.rotation.rules.as_ref(), now);
                st.rotation.window_start = window.map(|w| w.start);
                st.rotation.next = window.map(|w| w.next_rotation_date());
                st.last_changed = now;
            } else {
                if ok {
                    tracing::warn!(secret = %arn, "rotation finished without moving AWSCURRENT to {token}");
                }
                // The AWSPENDING version stays for the reattempt, which the
                // scheduler starts in the next window (or a RotateSecret
                // retry starts sooner).
                if st.rotation.window_start.is_some_and(|w| w <= now) {
                    let window = next_window(st.rotation.rules.as_ref(), now);
                    st.rotation.window_start = window.map(|w| w.start);
                    st.rotation.next = window.map(|w| w.next_rotation_date());
                }
            }
            Ok(())
        });
        self.sync_replicas(&ctx, &arn, &[]);
    }

    pub(crate) fn cancel_rotate_secret(
        &self,
        ctx: &RequestContext,
        input: types::CancelRotateSecretRequest,
    ) -> Result<types::CancelRotateSecretResponse, ServiceError> {
        let s = self.find(ctx, &input.secret_id, "secretsmanager:CancelRotateSecret", ConditionContext::new())?;
        check_live(&s)?;
        check_primary(&s)?;
        if s.rotation.lambda_arn.is_none() && !s.rotation.enabled {
            return Err(errors::invalid_request(
                "Secrets Manager can't cancel rotation because rotation isn't enabled for this secret.",
            ));
        }
        let pending = s.pending_rotation().map(|v| v.id.clone());
        let now = ctx.received_at;
        self.update(&s.arn, |st| {
            st.rotation.enabled = false;
            st.rotation.window_start = None;
            st.rotation.next = None;
            st.last_changed = now;
            Ok(())
        })?;
        self.sync_replicas(ctx, &s.arn, &[]);
        Ok(types::CancelRotateSecretResponse { arn: Some(s.arn), name: Some(s.name), version_id: pending })
    }

    /// Housekeeping on the emulated clock: finish scheduled deletions and
    /// start rotations whose window has opened.
    pub(crate) fn tick(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let due: Vec<(String, Option<String>)> = {
            let mut st = self.lock();
            st.sweep(now);
            st.secrets
                .values()
                .filter(|s| {
                    s.primary_region.is_none()
                        && s.deletion_date.is_none()
                        && s.rotation.enabled
                        && s.rotation.lambda_arn.is_some()
                        && s.rotation.token.is_none()
                        && s.rotation.window_start.is_some_and(|w| w <= now)
                })
                // An incomplete rotation is reattempted with its pending
                // version; otherwise a new rotation starts.
                .map(|s| (s.arn.clone(), s.pending_rotation().map(|v| v.id.clone())))
                .collect()
        };
        self.tick_managed(ctx);
        if due.is_empty() || self.lambda().is_none() {
            return;
        }
        for (arn, pending) in due {
            let token = pending.unwrap_or_else(names::new_token);
            if let Err(e) = self.begin(ctx, &arn, &token, false) {
                tracing::warn!(secret = %arn, "scheduled rotation did not start: {}", e.message);
            }
        }
    }
}

fn invocation<'a>(function: &'a str, s: &'a Secret, payload: Vec<u8>) -> ServiceInvocation<'a> {
    ServiceInvocation {
        function,
        service_principal: SERVICE_PRINCIPAL,
        source_account: Some(&s.account),
        source_arn: Some(&s.arn),
        payload,
    }
}
