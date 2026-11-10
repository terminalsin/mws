//! Listener rules: conditions, priorities and transforms.

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, validation};
use crate::state::{RegionState, RuleRecord};
use crate::v2::{errors, types as t};
use crate::{account_of, Elb};

pub(crate) fn rule_not_found() -> ServiceError {
    errors::rule_not_found("One or more rules not found")
}

fn find_rule<'a>(r: &'a RegionState, arn: &str) -> Result<&'a RuleRecord, ServiceError> {
    r.rules.get(arn).ok_or_else(rule_not_found)
}

const FIELDS: &[&str] =
    &["host-header", "path-pattern", "http-header", "http-request-method", "query-string", "source-ip"];

/// Check conditions and return them as ELB describes them: values given
/// the legacy way are also shown in the field's config.
fn normalize_conditions(conditions: &[t::RuleCondition]) -> Result<Vec<t::RuleCondition>, ServiceError> {
    if conditions.is_empty() {
        return Err(validation("A rule must have at least one condition"));
    }
    let mut total = 0usize;
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for c in conditions {
        let field = c.field.clone().ok_or_else(|| validation("A condition field must be specified"))?;
        if !FIELDS.contains(&field.as_str()) {
            return Err(validation(format!("Condition field '{field}' is not valid")));
        }
        if !matches!(field.as_str(), "http-header" | "query-string") {
            if seen.contains(&field) {
                return Err(validation(format!("A rule can only have one '{field}' condition")));
            }
            seen.push(field.clone());
        }
        let mut c = c.clone();
        let legacy = c.values.clone().filter(|v| !v.is_empty());
        if legacy.is_some() && !matches!(field.as_str(), "host-header" | "path-pattern") {
            return Err(validation(format!(
                "Values cannot be specified for '{field}' conditions; use the condition's config"
            )));
        }
        let count = match field.as_str() {
            "host-header" => {
                let cfg = c.host_header_config.get_or_insert_with(Default::default);
                if let (Some(v), None) = (&legacy, &cfg.values) {
                    cfg.values = Some(v.clone());
                }
                let n = cfg.values.iter().flatten().count() + cfg.regex_values.iter().flatten().count();
                for v in cfg.values.iter().flatten() {
                    if v.len() > 128 {
                        return Err(validation("Host header values cannot be longer than 128 characters"));
                    }
                }
                if cfg.values.is_some() && cfg.regex_values.is_none() {
                    c.values = cfg.values.clone();
                }
                n
            }
            "path-pattern" => {
                let cfg = c.path_pattern_config.get_or_insert_with(Default::default);
                if let (Some(v), None) = (&legacy, &cfg.values) {
                    cfg.values = Some(v.clone());
                }
                let n = cfg.values.iter().flatten().count() + cfg.regex_values.iter().flatten().count();
                for v in cfg.values.iter().flatten() {
                    if v.len() > 128 {
                        return Err(validation("Path pattern values cannot be longer than 128 characters"));
                    }
                }
                if cfg.values.is_some() && cfg.regex_values.is_none() {
                    c.values = cfg.values.clone();
                }
                n
            }
            "http-header" => {
                let cfg = c.http_header_config.clone().ok_or_else(|| {
                    validation("An HTTP header config must be specified for 'http-header' conditions")
                })?;
                let name = cfg.http_header_name.clone().unwrap_or_default();
                if name.is_empty() || name.len() > 40 {
                    return Err(validation("The HTTP header name must be 1-40 characters"));
                }
                cfg.values.iter().flatten().count() + cfg.regex_values.iter().flatten().count()
            }
            "http-request-method" => {
                let cfg = c.http_request_method_config.clone().ok_or_else(|| {
                    validation("An HTTP request method config must be specified for 'http-request-method' conditions")
                })?;
                for m in cfg.values.iter().flatten() {
                    if m.is_empty() || !m.bytes().all(|b| b.is_ascii_uppercase() || b == b'_' || b == b'-') {
                        return Err(validation(format!("HTTP request method '{m}' is not valid")));
                    }
                }
                cfg.values.iter().flatten().count()
            }
            "query-string" => {
                let cfg = c.query_string_config.clone().ok_or_else(|| {
                    validation("A query string config must be specified for 'query-string' conditions")
                })?;
                for kv in cfg.values.iter().flatten() {
                    if kv.value.is_none() {
                        return Err(validation("Query string conditions must specify a value"));
                    }
                }
                cfg.values.iter().flatten().count()
            }
            "source-ip" => {
                let cfg = c
                    .source_ip_config
                    .clone()
                    .ok_or_else(|| validation("A source IP config must be specified for 'source-ip' conditions"))?;
                for v in cfg.values.iter().flatten() {
                    let ok = v.split_once('/').is_some_and(|(ip, bits)| {
                        bits.parse::<u8>().is_ok()
                            && (ip.parse::<std::net::Ipv4Addr>().is_ok() || ip.parse::<std::net::Ipv6Addr>().is_ok())
                    });
                    if !ok {
                        return Err(validation(format!("Source IP '{v}' is not a valid CIDR")));
                    }
                }
                cfg.values.iter().flatten().count()
            }
            _ => 0,
        };
        if count == 0 {
            return Err(validation(format!("A '{field}' condition must have at least one value")));
        }
        total += count;
        out.push(c);
    }
    if total > 5 {
        return Err(validation("A rule can only have '5' condition values"));
    }
    Ok(out)
}

fn check_transforms(transforms: &[t::RuleTransform]) -> Result<(), ServiceError> {
    let mut seen = Vec::new();
    for tr in transforms {
        if seen.contains(&tr.r#type) {
            return Err(validation(format!("A rule can only have one '{}' transform", tr.r#type)));
        }
        seen.push(tr.r#type.clone());
        let rewrites = match tr.r#type.as_str() {
            "host-header-rewrite" => tr.host_header_rewrite_config.as_ref().and_then(|c| c.rewrites.clone()),
            "url-rewrite" => tr.url_rewrite_config.as_ref().and_then(|c| c.rewrites.clone()),
            other => return Err(validation(format!("Transform type '{other}' is not valid"))),
        }
        .unwrap_or_default();
        if rewrites.len() != 1 {
            return Err(validation("A transform must have exactly one rewrite"));
        }
        for rw in &rewrites {
            if regex::Regex::new(&rw.regex).is_err() {
                return Err(validation(format!("The regular expression '{}' is not valid", rw.regex)));
            }
        }
    }
    Ok(())
}

/// Rules of a listener in evaluation order (the default rule last).
pub(crate) fn rules_of(r: &RegionState, listener_arn: &str) -> Vec<RuleRecord> {
    let mut v: Vec<RuleRecord> = r.rules.values().filter(|x| x.listener_arn == listener_arn).cloned().collect();
    v.sort_by_key(|x| x.priority());
    v
}

impl Elb {
    pub(crate) fn create_rule_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateRuleInput,
    ) -> Result<t::CreateRuleOutput, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        names::check_tags(&tags)?;
        if !(1..=50_000).contains(&input.priority) {
            return Err(validation("Priority must be between 1 and 50000"));
        }
        let conditions = normalize_conditions(&input.conditions)?;
        check_transforms(input.transforms.as_deref().unwrap_or_default())?;
        let (lb_arn, lb_type, protocol) = self.with_region(ctx, |r| {
            let l = super::listener::find_listener(r, &input.listener_arn)?;
            let ty = r.load_balancers.get(l.lb_arn()).map(|x| x.ty().to_string()).unwrap_or_default();
            Ok::<_, ServiceError>((l.lb_arn().to_string(), ty, l.protocol().to_string()))
        })?;
        if lb_type != "application" {
            return Err(errors::operation_not_permitted(
                "Rules are only supported for Application Load Balancer listeners",
            ));
        }
        let account = account_of(ctx);
        let listener_id = input.listener_arn.rsplit('/').next().unwrap_or_default().to_string();
        let lb_path = names::lb_path_of_listener(&input.listener_arn).unwrap_or_default();
        let arn = names::arn(ctx, &account, &format!("listener-rule/{lb_path}/{listener_id}/{}", names::hex_id(16)));
        self.authorize_create_in(ctx, "CreateRule", &input.listener_arn, &arn, &tags)?;
        let max_rules = self.limit(ctx, "rules-per-application-load-balancer");
        let rule = self.with_region(ctx, |r| {
            let actions = super::actions::normalize(r, &lb_arn, &lb_type, &protocol, &input.actions)?;
            let existing = rules_of(r, &input.listener_arn);
            if existing.iter().any(|x| x.priority() == input.priority as i64) {
                return Err(errors::priority_in_use(format!("Priority '{}' is currently in use", input.priority)));
            }
            let lb_rules = r
                .rules
                .values()
                .filter(|x| !x.is_default() && r.listeners.get(&x.listener_arn).is_some_and(|l| l.lb_arn() == lb_arn));
            if lb_rules.count() >= max_rules {
                return Err(errors::too_many_rules(
                    "You have reached the maximum number of rules for this load balancer",
                ));
            }
            let rule = t::Rule {
                rule_arn: Some(arn.clone()),
                priority: Some(input.priority.to_string()),
                conditions: Some(conditions),
                actions: Some(actions),
                is_default: Some(false),
                transforms: input.transforms.clone().filter(|t| !t.is_empty()),
            };
            r.rules.insert(arn.clone(), RuleRecord { rule: rule.clone(), listener_arn: input.listener_arn.clone() });
            if !tags.is_empty() {
                r.tags.insert(arn.clone(), tags.clone());
            }
            Ok(rule)
        })?;
        let mut rule = rule;
        super::actions::redact(&mut rule.actions);
        Ok(t::CreateRuleOutput { rules: Some(vec![rule]) })
    }

    pub(crate) fn describe_rules_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeRulesInput,
    ) -> Result<t::DescribeRulesOutput, ServiceError> {
        names::authorize(ctx, "DescribeRules", "*", Default::default())?;
        let arns = input.rule_arns.unwrap_or_default();
        if input.listener_arn.is_some() == !arns.is_empty() {
            return Err(validation("You must specify either listener ARN or rule ARNs"));
        }
        let all = self.with_region(ctx, |r| -> Result<Vec<t::Rule>, ServiceError> {
            if let Some(l) = &input.listener_arn {
                super::listener::find_listener(r, l)?;
                return Ok(rules_of(r, l).into_iter().map(|x| x.rule).collect());
            }
            arns.iter().map(|a| find_rule(r, a).map(|x| x.rule.clone())).collect()
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        let mut items = items;
        items.iter_mut().for_each(|x| super::actions::redact(&mut x.actions));
        Ok(t::DescribeRulesOutput { rules: Some(items), next_marker: next })
    }

    pub(crate) fn modify_rule_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyRuleInput,
    ) -> Result<t::ModifyRuleOutput, ServiceError> {
        self.authorize_on(ctx, "ModifyRule", &input.rule_arn)?;
        let conditions = match &input.conditions {
            Some(c) => Some(normalize_conditions(c)?),
            None => None,
        };
        if let Some(tr) = &input.transforms {
            check_transforms(tr)?;
        }
        let rule = self.with_region(ctx, |r| {
            let rec = find_rule(r, &input.rule_arn)?.clone();
            let l = super::listener::find_listener(r, &rec.listener_arn)?.clone();
            let lb_type = r.load_balancers.get(l.lb_arn()).map(|x| x.ty().to_string()).unwrap_or_default();
            if rec.is_default() && (conditions.is_some() || input.transforms.is_some()) {
                return Err(errors::operation_not_permitted(
                    "The conditions and transforms of a default rule cannot be modified",
                ));
            }
            let actions = match &input.actions {
                Some(a) => Some(super::actions::normalize(r, l.lb_arn(), &lb_type, l.protocol(), a)?),
                None => None,
            };
            let entry = r.rules.get_mut(&input.rule_arn).ok_or_else(rule_not_found)?;
            if let Some(c) = conditions {
                entry.rule.conditions = Some(c);
            }
            if let Some(a) = actions.clone() {
                entry.rule.actions = Some(a);
            }
            if input.reset_transforms == Some(true) {
                entry.rule.transforms = None;
            } else if let Some(tr) = &input.transforms {
                entry.rule.transforms = Some(tr.clone()).filter(|t| !t.is_empty());
            }
            let out = entry.rule.clone();
            if rec.is_default() {
                if let (Some(a), Some(listener)) = (actions, r.listeners.get_mut(&rec.listener_arn)) {
                    listener.listener.default_actions = Some(a);
                }
            }
            Ok::<_, ServiceError>(out)
        })?;
        let mut rule = rule;
        super::actions::redact(&mut rule.actions);
        Ok(t::ModifyRuleOutput { rules: Some(vec![rule]) })
    }

    pub(crate) fn delete_rule_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteRuleInput,
    ) -> Result<t::DeleteRuleOutput, ServiceError> {
        self.authorize_on(ctx, "DeleteRule", &input.rule_arn)?;
        self.with_region(ctx, |r| {
            let rec = find_rule(r, &input.rule_arn)?;
            if rec.is_default() {
                return Err(errors::operation_not_permitted(format!(
                    "Default rule '{}' cannot be deleted",
                    input.rule_arn
                )));
            }
            r.rules.remove(&input.rule_arn);
            r.tags.remove(&input.rule_arn);
            Ok(t::DeleteRuleOutput {})
        })
    }

    pub(crate) fn set_rule_priorities_op(
        &self,
        ctx: &RequestContext,
        input: t::SetRulePrioritiesInput,
    ) -> Result<t::SetRulePrioritiesOutput, ServiceError> {
        for p in &input.rule_priorities {
            self.authorize_on(ctx, "SetRulePriorities", p.rule_arn.as_deref().unwrap_or_default())?;
        }
        self.with_region(ctx, |r| {
            let mut listener: Option<String> = None;
            let mut wanted = Vec::new();
            for p in &input.rule_priorities {
                let arn = p.rule_arn.clone().unwrap_or_default();
                let rec = find_rule(r, &arn)?;
                if rec.is_default() {
                    return Err(errors::operation_not_permitted(format!(
                        "The priority of default rule '{arn}' cannot be changed"
                    )));
                }
                match &listener {
                    Some(l) if *l != rec.listener_arn => {
                        return Err(validation("All rules must belong to the same listener"));
                    }
                    _ => listener = Some(rec.listener_arn.clone()),
                }
                let priority = p.priority.ok_or_else(|| validation("A priority must be specified for every rule"))?;
                if !(1..=50_000).contains(&priority) {
                    return Err(validation("Priority must be between 1 and 50000"));
                }
                wanted.push((arn, priority));
            }
            let listener = listener.unwrap_or_default();
            let mut final_priorities: Vec<(String, i64)> = rules_of(r, &listener)
                .into_iter()
                .filter(|x| !x.is_default())
                .map(|x| {
                    let p = wanted.iter().find(|(a, _)| a == x.arn()).map(|(_, p)| *p as i64).unwrap_or(x.priority());
                    (x.arn().to_string(), p)
                })
                .collect();
            final_priorities.sort_by_key(|(_, p)| *p);
            if let Some(w) = final_priorities.windows(2).find(|w| w[0].1 == w[1].1) {
                return Err(errors::priority_in_use(format!("Priority '{}' is currently in use", w[0].1)));
            }
            let mut out = Vec::new();
            for (arn, p) in &wanted {
                if let Some(rec) = r.rules.get_mut(arn) {
                    rec.rule.priority = Some(p.to_string());
                    out.push(rec.rule.clone());
                }
            }
            out.iter_mut().for_each(|x| super::actions::redact(&mut x.actions));
            Ok(t::SetRulePrioritiesOutput { rules: Some(out) })
        })
    }
}
