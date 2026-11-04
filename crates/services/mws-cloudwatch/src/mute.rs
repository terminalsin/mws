//! Alarm mute rules: schedules (`cron(...)` or `at(...)` plus a duration)
//! during which the targeted alarms change state but run no actions.

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_events::schedule::Schedule;

use crate::generated::{errors, types};
use crate::names::{self, mute_rule_arn, now, request_tag_conditions};
use crate::state::MuteRule;
use crate::CloudWatch;

/// `PT2H`, `PT30M`, `P1D`, `P1W`, `P1DT12H`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let rest = s.strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };
    let mut total = Duration::zero();
    let mut any = false;
    let mut num = String::new();
    for c in date.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: i64 = num.parse().ok()?;
        num.clear();
        any = true;
        total += match c {
            'D' => Duration::days(n),
            'W' => Duration::weeks(n),
            _ => return None,
        };
    }
    if !num.is_empty() {
        return None;
    }
    for c in time.unwrap_or_default().chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: i64 = num.parse().ok()?;
        num.clear();
        any = true;
        total += match c {
            'H' => Duration::hours(n),
            'M' => Duration::minutes(n),
            'S' => Duration::seconds(n),
            _ => return None,
        };
    }
    (any && num.is_empty() && total > Duration::zero()).then_some(total)
}

fn parse_at(expr: &str) -> Option<DateTime<Utc>> {
    let inner = expr.trim().strip_prefix("at(")?.strip_suffix(')')?;
    NaiveDateTime::parse_from_str(inner, "%Y-%m-%dT%H:%M:%S").ok().map(|t| t.and_utc())
}

fn mute_type(r: &MuteRule) -> &'static str {
    if parse_at(&r.config.rule.schedule.expression).is_some() {
        "ONE_TIME"
    } else {
        "RECURRING"
    }
}

/// `SCHEDULED`, `ACTIVE` or `EXPIRED` at `now`.
pub fn status(r: &MuteRule, now: DateTime<Utc>) -> &'static str {
    let c = &r.config;
    if c.expire_date.is_some_and(|e| e <= now) {
        return "EXPIRED";
    }
    if c.start_date.is_some_and(|s| s > now) {
        return "SCHEDULED";
    }
    let Some(duration) = parse_duration(&c.rule.schedule.duration) else { return "SCHEDULED" };
    if let Some(at) = parse_at(&c.rule.schedule.expression) {
        return if now < at {
            "SCHEDULED"
        } else if now < at + duration {
            "ACTIVE"
        } else {
            "EXPIRED"
        };
    }
    let Some(schedule) = Schedule::parse(&c.rule.schedule.expression) else { return "SCHEDULED" };
    let fired = schedule.fires_between(r.updated, now - duration, now, 1);
    if fired.is_empty() {
        "SCHEDULED"
    } else {
        "ACTIVE"
    }
}

impl CloudWatch {
    pub(crate) fn put_alarm_mute_rule(
        &self,
        ctx: &RequestContext,
        input: types::PutAlarmMuteRuleInput,
    ) -> Result<(), ServiceError> {
        let arn = mute_rule_arn(ctx, &input.name);
        let tags = input.tags.clone().unwrap_or_default();
        ctx.authorize("cloudwatch:PutAlarmMuteRule", &arn, request_tag_conditions(&tags))?;
        self.observe(ctx);
        let sched = &input.rule.schedule;
        if parse_at(&sched.expression).is_none() && Schedule::parse(&sched.expression).is_none() {
            return Err(errors::validation(format!(
                "Invalid schedule expression: {}. Use a cron(...) or at(yyyy-mm-ddThh:mm:ss) expression.",
                sched.expression
            )));
        }
        if parse_duration(&sched.duration).is_none() {
            return Err(errors::validation(format!(
                "Invalid duration: {}. Use an ISO 8601 duration such as PT2H.",
                sched.duration
            )));
        }
        if let (Some(s), Some(e)) = (input.start_date, input.expire_date) {
            if e <= s {
                return Err(errors::validation("ExpireDate must be after StartDate."));
            }
        }
        let now = now(ctx);
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        if !region.mute_rules.contains_key(&input.name) && region.mute_rules.len() >= 1000 {
            return Err(errors::limit_exceeded_fault("The maximum number of alarm mute rules has been reached."));
        }
        let created = !region.mute_rules.contains_key(&input.name);
        let mut config = input;
        config.tags = None;
        region.mute_rules.insert(config.name.clone(), MuteRule { arn: arn.clone(), config, updated: now });
        if created && !tags.is_empty() {
            region.tags.insert(arn, tags.into_iter().map(|t| (t.key, t.value)).collect());
        }
        Ok(())
    }

    pub(crate) fn get_alarm_mute_rule(
        &self,
        ctx: &RequestContext,
        input: types::GetAlarmMuteRuleInput,
    ) -> Result<types::GetAlarmMuteRuleOutput, ServiceError> {
        ctx.authorize(
            "cloudwatch:GetAlarmMuteRule",
            &mute_rule_arn(ctx, &input.alarm_mute_rule_name),
            ConditionContext::new(),
        )?;
        let now = now(ctx);
        let st = self.lock();
        let r = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.mute_rules.get(&input.alarm_mute_rule_name))
            .ok_or_else(|| not_found(&input.alarm_mute_rule_name))?;
        Ok(types::GetAlarmMuteRuleOutput {
            name: Some(r.config.name.clone()),
            alarm_mute_rule_arn: Some(r.arn.clone()),
            description: r.config.description.clone(),
            rule: Some(r.config.rule.clone()),
            mute_targets: r.config.mute_targets.clone(),
            start_date: r.config.start_date,
            expire_date: r.config.expire_date,
            status: Some(status(r, now).into()),
            last_updated_timestamp: Some(r.updated),
            mute_type: Some(mute_type(r).into()),
        })
    }

    pub(crate) fn list_alarm_mute_rules(
        &self,
        ctx: &RequestContext,
        input: types::ListAlarmMuteRulesInput,
    ) -> Result<types::ListAlarmMuteRulesOutput, ServiceError> {
        ctx.authorize("cloudwatch:ListAlarmMuteRules", &mute_rule_arn(ctx, "*"), ConditionContext::new())?;
        let now = now(ctx);
        let st = self.lock();
        let region = st.region_ref(&ctx.caller.account_id, &ctx.region);
        if let Some(a) = &input.alarm_name {
            if region.is_none_or(|r| !r.alarms.contains_key(a)) {
                return Err(errors::resource_not_found_exception(format!("Alarm {a} not found")));
            }
        }
        let all: Vec<types::AlarmMuteRuleSummary> =
            region
                .map(|r| {
                    r.mute_rules
                        .values()
                        .filter(|m| {
                            input.alarm_name.as_ref().is_none_or(|a| {
                                m.config.mute_targets.as_ref().is_some_and(|t| t.alarm_names.contains(a))
                            }) && input.statuses.as_ref().is_none_or(|s| s.iter().any(|x| x == status(m, now)))
                        })
                        .map(|m| types::AlarmMuteRuleSummary {
                            alarm_mute_rule_arn: Some(m.arn.clone()),
                            expire_date: m.config.expire_date,
                            status: Some(status(m, now).into()),
                            mute_type: Some(mute_type(m).into()),
                            last_updated_timestamp: Some(m.updated),
                        })
                        .collect()
                })
                .unwrap_or_default();
        drop(st);
        let size = input.max_records.unwrap_or(100).clamp(1, 100) as usize;
        let (page, next_token) = names::page(all, input.next_token.as_deref(), size)?;
        Ok(types::ListAlarmMuteRulesOutput { alarm_mute_rule_summaries: Some(page), next_token })
    }

    pub(crate) fn delete_alarm_mute_rule(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAlarmMuteRuleInput,
    ) -> Result<(), ServiceError> {
        let arn = mute_rule_arn(ctx, &input.alarm_mute_rule_name);
        ctx.authorize("cloudwatch:DeleteAlarmMuteRule", &arn, ConditionContext::new())?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        region.mute_rules.remove(&input.alarm_mute_rule_name);
        region.tags.remove(&arn);
        Ok(())
    }
}

fn not_found(name: &str) -> ServiceError {
    errors::resource_not_found_exception(format!("Alarm mute rule {name} does not exist."))
        .with_field("ResourceType", mws_core::ErrorValue::String("AlarmMuteRule".into()))
        .with_field("ResourceId", mws_core::ErrorValue::String(name.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("PT2H"), Some(Duration::hours(2)));
        assert_eq!(parse_duration("P1DT30M"), Some(Duration::days(1) + Duration::minutes(30)));
        assert_eq!(parse_duration("P"), None);
        assert_eq!(parse_duration("2H"), None);
    }
}
