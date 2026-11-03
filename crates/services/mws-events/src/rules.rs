//! Rules, their targets, and `TestEventPattern`.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::{errors, types};
use crate::names::{self, not_found, request_tags, validation, BusRef};
use crate::pattern::Pattern;
use crate::schedule::Schedule;
use crate::state::Rule;
use crate::{transform, Events};

pub(crate) const MAX_TARGETS: usize = 5;

pub(crate) fn invalid_pattern(e: impl std::fmt::Display) -> ServiceError {
    errors::invalid_event_pattern(format!("Event pattern is not valid. Reason: {e}"))
}

fn rule_missing(rule: &str, bus: &BusRef) -> ServiceError {
    not_found(format!("Rule {rule} does not exist on EventBus {}.", bus.name))
}

impl Events {
    fn check_pass_role(&self, ctx: &RequestContext, role: &str) -> Result<(), ServiceError> {
        let mut c = ConditionContext::new();
        c.insert("iam:PassedToService".into(), vec!["events.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", role, c)
    }

    /// A rule's stored record, with the bus resolved; the rule must exist.
    fn rule(&self, ctx: &RequestContext, bus: &BusRef, name: &str) -> Result<Rule, ServiceError> {
        self.with_bus(ctx, bus, |b| b.rules.get(name).cloned().ok_or_else(|| rule_missing(name, bus)))
    }

    pub fn put_rule(
        &self,
        ctx: &RequestContext,
        input: types::PutRuleRequest,
    ) -> Result<types::PutRuleResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        let rule_arn = bus.rule_arn(&input.name);
        if input.event_pattern.is_none() && input.schedule_expression.is_none() {
            return Err(validation("Parameter(s) EventPattern or ScheduleExpression must be specified."));
        }
        if let Some(p) = &input.event_pattern {
            Pattern::parse(p).map_err(invalid_pattern)?;
        }
        if let Some(s) = &input.schedule_expression {
            if bus.name != "default" {
                return Err(validation("ScheduleExpression is supported only on the default event bus."));
            }
            Schedule::parse(s).ok_or_else(|| validation("Parameter ScheduleExpression is not valid."))?;
        }
        let state = input.state.clone().unwrap_or_else(|| "ENABLED".into());
        let mut extra = request_tags(input.tags.iter().flatten().map(|t| (&t.key, &t.value)));
        if let Some(p) = &input.event_pattern {
            for (field, key) in [("source", "events:source"), ("detail-type", "events:detail-type")] {
                let values = Pattern::exact_strings(p, field);
                if !values.is_empty() {
                    extra.insert(key.into(), values);
                }
            }
        }
        self.authorize_on_bus(ctx, "events:PutRule", &bus, &rule_arn, extra)?;
        if let Some(role) = &input.role_arn {
            self.check_pass_role(ctx, role)?;
        }
        let now = ctx.received_at;
        let creator = ctx.caller.account_id.clone();
        self.with_bus(ctx, &bus, |b| {
            if let Some(existing) = b.rules.get(&input.name) {
                if let Some(m) = &existing.managed_by {
                    return Err(errors::managed_rule(format!(
                        "Rule {} is managed by {m} and cannot be modified.",
                        input.name
                    )));
                }
                if existing.created_by.as_deref().unwrap_or(&bus.account) != creator {
                    return Err(errors::access_denied("You cannot modify a rule created by another account."));
                }
            }
            let rule = b.rules.entry(input.name.clone()).or_insert_with(|| Rule {
                name: input.name.clone(),
                arn: rule_arn.clone(),
                created_at: now,
                created_by: Some(creator.clone()),
                ..Rule::default()
            });
            if rule.schedule_expression != input.schedule_expression {
                rule.created_at = now;
                rule.schedule_checked = None;
            }
            rule.event_pattern = input.event_pattern.clone();
            rule.schedule_expression = input.schedule_expression.clone();
            rule.state = state;
            rule.description = input.description.clone();
            rule.role_arn = input.role_arn.clone();
            Ok(())
        })?;
        if let Some(tags) = input.tags.filter(|t| !t.is_empty()) {
            let mut st = self.lock();
            let region = st.region_mut(&bus.partition, &bus.account, &bus.region, now);
            let entry = region.tags.entry(rule_arn.clone()).or_default();
            for t in tags {
                entry.insert(t.key, t.value);
            }
        }
        Ok(types::PutRuleResponse { rule_arn: Some(rule_arn) })
    }

    pub fn describe_rule(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRuleRequest,
    ) -> Result<types::DescribeRuleResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        self.authorize_on_bus(ctx, "events:DescribeRule", &bus, &bus.rule_arn(&input.name), ConditionContext::new())?;
        let r = self.rule(ctx, &bus, &input.name)?;
        Ok(types::DescribeRuleResponse {
            name: Some(r.name),
            arn: Some(r.arn),
            event_pattern: r.event_pattern,
            schedule_expression: r.schedule_expression,
            state: Some(r.state),
            description: r.description,
            role_arn: r.role_arn,
            managed_by: r.managed_by,
            event_bus_name: Some(bus.name.clone()),
            created_by: Some(r.created_by.unwrap_or(bus.account)),
        })
    }

    pub fn delete_rule(&self, ctx: &RequestContext, input: types::DeleteRuleRequest) -> Result<(), ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        let arn = bus.rule_arn(&input.name);
        self.authorize_on_bus(ctx, "events:DeleteRule", &bus, &arn, ConditionContext::new())?;
        let now = ctx.received_at;
        self.with_bus(ctx, &bus, |b| {
            let Some(rule) = b.rules.get(&input.name) else { return Ok(()) };
            if let Some(m) = &rule.managed_by {
                if !input.force {
                    return Err(errors::managed_rule(format!(
                        "Rule {} is managed by {m} and cannot be deleted without Force.",
                        input.name
                    )));
                }
            }
            if !rule.targets.is_empty() {
                return Err(validation("Rule can't be deleted since it has targets."));
            }
            b.rules.remove(&input.name);
            Ok(())
        })?;
        let mut st = self.lock();
        st.region_mut(&bus.partition, &bus.account, &bus.region, now).tags.remove(&arn);
        Ok(())
    }

    fn set_rule_state(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
        bus_name: Option<&str>,
        state: &str,
    ) -> Result<(), ServiceError> {
        let bus = BusRef::parse(ctx, bus_name)?;
        self.authorize_on_bus(ctx, action, &bus, &bus.rule_arn(name), ConditionContext::new())?;
        self.with_bus(ctx, &bus, |b| {
            let rule = b.rules.get_mut(name).ok_or_else(|| rule_missing(name, &bus))?;
            if let Some(m) = &rule.managed_by {
                return Err(errors::managed_rule(format!("Rule {name} is managed by {m} and cannot be modified.")));
            }
            rule.state = state.to_string();
            Ok(())
        })
    }

    pub fn enable_rule(&self, ctx: &RequestContext, input: types::EnableRuleRequest) -> Result<(), ServiceError> {
        self.set_rule_state(ctx, "events:EnableRule", &input.name, input.event_bus_name.as_deref(), "ENABLED")
    }

    pub fn disable_rule(&self, ctx: &RequestContext, input: types::DisableRuleRequest) -> Result<(), ServiceError> {
        self.set_rule_state(ctx, "events:DisableRule", &input.name, input.event_bus_name.as_deref(), "DISABLED")
    }

    pub fn list_rules(
        &self,
        ctx: &RequestContext,
        input: types::ListRulesRequest,
    ) -> Result<types::ListRulesResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        self.authorize_on_bus(ctx, "events:ListRules", &bus, &bus.rule_arn("*"), ConditionContext::new())?;
        let rules = self.with_bus(ctx, &bus, |b| {
            Ok(b.rules
                .values()
                .filter(|r| input.name_prefix.as_deref().is_none_or(|p| r.name.starts_with(p)))
                .map(|r| types::Rule {
                    name: Some(r.name.clone()),
                    arn: Some(r.arn.clone()),
                    event_pattern: r.event_pattern.clone(),
                    state: Some(r.state.clone()),
                    description: r.description.clone(),
                    schedule_expression: r.schedule_expression.clone(),
                    role_arn: r.role_arn.clone(),
                    managed_by: r.managed_by.clone(),
                    event_bus_name: Some(b.name.clone()),
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = names::paginate(rules, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListRulesResponse { rules: Some(page), next_token })
    }

    pub fn list_rule_names_by_target(
        &self,
        ctx: &RequestContext,
        input: types::ListRuleNamesByTargetRequest,
    ) -> Result<types::ListRuleNamesByTargetResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        self.authorize_on_bus(ctx, "events:ListRuleNamesByTarget", &bus, &bus.rule_arn("*"), ConditionContext::new())?;
        let names = self.with_bus(ctx, &bus, |b| {
            Ok(b.rules
                .values()
                .filter(|r| r.targets.iter().any(|t| t.arn == input.target_arn))
                .map(|r| r.name.clone())
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = names::paginate(names, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListRuleNamesByTargetResponse { rule_names: Some(page), next_token })
    }

    fn check_target(&self, ctx: &RequestContext, bus: &BusRef, t: &types::Target) -> Result<(), ServiceError> {
        let Some((_, service, region, account, resource)) = names::split_arn(&t.arn) else {
            return Err(validation(format!(
                "Parameter {} is not valid. Reason: Provided Arn is not in correct format.",
                t.arn
            )));
        };
        let inputs = [t.input.is_some(), t.input_path.is_some(), t.input_transformer.is_some()];
        if inputs.iter().filter(|b| **b).count() > 1 {
            return Err(validation("Only one of Input, InputPath, or InputTransformer must be provided."));
        }
        if let Some(i) = &t.input {
            if serde_json::from_str::<Value>(i).is_err() {
                return Err(validation(format!(
                    "Parameter Input is not valid. Reason: Input for target {} is not valid JSON.",
                    t.id
                )));
            }
        }
        if let Some(p) = &t.input_path {
            if transform::parse_path(p).is_none() {
                return Err(validation(format!(
                    "Parameter InputPath is not valid. Reason: {p} is not a valid JSON path."
                )));
            }
        }
        if let Some(tr) = &t.input_transformer {
            transform::validate(tr)
                .map_err(|m| validation(format!("Parameter InputTransformer is not valid. Reason: {m}")))?;
        }
        if service == "events" && resource.starts_with("event-bus/") {
            let same_account = account == bus.account;
            if t.role_arn.is_none() && (same_account || region != bus.region) {
                return Err(validation(format!("Parameter(s) RoleArn must be specified for target: {}.", t.id)));
            }
            if t.arn == bus.arn() {
                return Err(validation("Target must not be the event bus the rule is on."));
            }
        }
        if service == "sqs"
            && resource.ends_with(".fifo")
            && t.sqs_parameters.as_ref().and_then(|p| p.message_group_id.as_ref()).is_none()
        {
            return Err(validation(format!("Parameter(s) SqsParameters must be specified for target: {}.", t.id)));
        }
        if let Some(d) = t.dead_letter_config.as_ref().and_then(|d| d.arn.as_deref()) {
            if names::split_arn(d).map(|p| p.1) != Some("sqs") {
                return Err(validation(format!("Parameter DeadLetterConfig.Arn is not valid for target: {}.", t.id)));
            }
        }
        if let Some(r) = &t.retry_policy {
            if r.maximum_retry_attempts.is_some_and(|n| !(0..=185).contains(&n))
                || r.maximum_event_age_in_seconds.is_some_and(|n| !(60..=86_400).contains(&n))
            {
                return Err(validation("Parameter RetryPolicy is not valid."));
            }
        }
        if let Some(role) = &t.role_arn {
            self.check_pass_role(ctx, role)?;
        }
        Ok(())
    }

    pub fn put_targets(
        &self,
        ctx: &RequestContext,
        input: types::PutTargetsRequest,
    ) -> Result<types::PutTargetsResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        let arn = bus.rule_arn(&input.rule);
        let mut extra = ConditionContext::new();
        extra.insert("events:TargetArn".into(), input.targets.iter().map(|t| t.arn.clone()).collect());
        self.authorize_on_bus(ctx, "events:PutTargets", &bus, &arn, extra)?;
        let rule = self.rule(ctx, &bus, &input.rule)?;
        if let Some(m) = &rule.managed_by {
            return Err(errors::managed_rule(format!("Rule {} is managed by {m} and cannot be modified.", input.rule)));
        }
        for t in &input.targets {
            self.check_target(ctx, &bus, t)?;
        }
        self.with_bus(ctx, &bus, |b| {
            let rule = b.rules.get_mut(&input.rule).ok_or_else(|| rule_missing(&input.rule, &bus))?;
            let mut targets = rule.targets.clone();
            for t in input.targets {
                match targets.iter_mut().find(|x| x.id == t.id) {
                    Some(existing) => *existing = t,
                    None => targets.push(t),
                }
            }
            if targets.len() > MAX_TARGETS {
                return Err(errors::limit_exceeded("The requested resource exceeds the maximum number allowed."));
            }
            rule.targets = targets;
            Ok(())
        })?;
        Ok(types::PutTargetsResponse { failed_entry_count: 0, failed_entries: Some(Vec::new()) })
    }

    pub fn remove_targets(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTargetsRequest,
    ) -> Result<types::RemoveTargetsResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        self.authorize_on_bus(ctx, "events:RemoveTargets", &bus, &bus.rule_arn(&input.rule), ConditionContext::new())?;
        self.with_bus(ctx, &bus, |b| {
            let rule = b.rules.get_mut(&input.rule).ok_or_else(|| rule_missing(&input.rule, &bus))?;
            if let Some(m) = &rule.managed_by {
                if !input.force {
                    return Err(errors::managed_rule(format!(
                        "Rule {} is managed by {m} and cannot be modified.",
                        input.rule
                    )));
                }
            }
            rule.targets.retain(|t| !input.ids.contains(&t.id));
            Ok(())
        })?;
        Ok(types::RemoveTargetsResponse { failed_entry_count: 0, failed_entries: Some(Vec::new()) })
    }

    pub fn list_targets_by_rule(
        &self,
        ctx: &RequestContext,
        input: types::ListTargetsByRuleRequest,
    ) -> Result<types::ListTargetsByRuleResponse, ServiceError> {
        let bus = BusRef::parse(ctx, input.event_bus_name.as_deref())?;
        self.authorize_on_bus(
            ctx,
            "events:ListTargetsByRule",
            &bus,
            &bus.rule_arn(&input.rule),
            ConditionContext::new(),
        )?;
        let rule = self.rule(ctx, &bus, &input.rule)?;
        let (page, next_token) = names::paginate(rule.targets, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListTargetsByRuleResponse { targets: Some(page), next_token })
    }

    pub fn test_event_pattern(
        &self,
        ctx: &RequestContext,
        input: types::TestEventPatternRequest,
    ) -> Result<types::TestEventPatternResponse, ServiceError> {
        ctx.authorize("events:TestEventPattern", "*", ConditionContext::new())?;
        let pattern = Pattern::parse(&input.event_pattern).map_err(invalid_pattern)?;
        let event: Value = serde_json::from_str(&input.event)
            .map_err(|_| validation("Parameter Event is not valid. Reason: Event is not valid JSON."))?;
        if !event.is_object() {
            return Err(validation("Parameter Event is not valid. Reason: Event is not a JSON object."));
        }
        for field in ["id", "account", "source", "time", "region", "detail-type"] {
            if event.get(field).is_none() {
                return Err(validation(format!(
                    "Parameter Event is not valid. Reason: Provided Event must have mandatory field: {field}"
                )));
            }
        }
        if event.get("resources").is_some_and(|r| !r.is_array()) {
            return Err(validation("Parameter Event is not valid. Reason: resources must be an array."));
        }
        Ok(types::TestEventPatternResponse { result: pattern.matches(&event) })
    }
}

/// The Region-level helper for rules other modules create (archives).
pub(crate) fn managed_rule_name(archive: &str) -> String {
    format!("Events-Archive-{archive}")
}
