//! Receipt rule sets, rules and IP filters (SES v1 only; SES v2 has no
//! receiving API).

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, authorize};
use crate::state::RuleSet;
use crate::v1::types as t1;
use crate::{v1, Ses};

const MAX_RULE_SETS: usize = 40;
const MAX_RULES: usize = 200;
const MAX_FILTERS: usize = 100;
const MAX_RECIPIENTS: usize = 100;

fn rule_set_arn(ctx: &RequestContext, set: &str) -> String {
    names::arn(ctx, &format!("receipt-rule-set/{set}"))
}

pub fn rule_arn(partition: &str, region: &str, account: &str, set: &str, rule: &str) -> String {
    names::arn_in(partition, region, account, &format!("receipt-rule-set/{set}:receipt-rule/{rule}"))
}

/// Receiving names: letters, digits, `.`, `_` and `-`, starting and ending
/// with a letter or digit, under 64 characters.
fn check_name(kind: &str, name: &str) -> Result<(), ServiceError> {
    let ok = !name.is_empty()
        && name.len() < 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && name.chars().last().is_some_and(|c| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(names::invalid_parameter(format!(
            "Invalid {kind} name <{name}>: Name must (1) contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-), (2) start and end with a letter or number, and (3) contain less than 64 characters."
        )))
    }
}

fn no_rule_set(name: &str) -> ServiceError {
    v1::errors::rule_set_does_not_exist(format!("Rule set does not exist: {name}"))
}

fn no_rule(name: &str) -> ServiceError {
    v1::errors::rule_does_not_exist(format!("Rule does not exist: {name}"))
}

/// Parse `a.b.c.d` or `a.b.c.d/n` (IPv4) into `(address, prefix)`.
pub fn parse_cidr(cidr: &str) -> Option<(std::net::IpAddr, u8)> {
    let (ip, prefix) = match cidr.split_once('/') {
        Some((ip, p)) => (ip, p.parse::<u8>().ok()?),
        None => (cidr, 255),
    };
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = if prefix == 255 { max } else { prefix };
    (prefix <= max).then_some((ip, prefix))
}

/// Whether `ip` is in `cidr`.
pub fn cidr_contains(cidr: &str, ip: &str) -> bool {
    let (Some((net, prefix)), Ok(ip)) = (parse_cidr(cidr), ip.parse::<std::net::IpAddr>()) else {
        return false;
    };
    match (net, ip) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            u32::from(n) & mask == u32::from(i) & mask
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

impl Ses {
    /// Check a rule the way SES does on create and update: names, TLS
    /// policy, recipients, and that SES may use each action's resources.
    fn check_rule(&self, ctx: &RequestContext, set: &str, rule: &t1::ReceiptRule) -> Result<(), ServiceError> {
        check_name("rule", &rule.name)?;
        if let Some(p) = &rule.tls_policy {
            if p != "Require" && p != "Optional" {
                return Err(names::invalid_parameter(format!("Invalid TLS policy: {p}")));
            }
        }
        let recipients = rule.recipients.as_deref().unwrap_or_default();
        if recipients.len() > MAX_RECIPIENTS {
            return Err(v1::errors::limit_exceeded(format!("A rule can have at most {MAX_RECIPIENTS} recipients.")));
        }
        for r in recipients {
            let bare = r.trim_start_matches('.');
            if bare.is_empty() || bare.contains(' ') || (r.contains('@') && names::check_address(r).is_err()) {
                return Err(names::invalid_parameter(format!("Invalid recipient: {r}")));
            }
        }
        let account = ctx.caller.account_id.clone();
        let source_arn = rule_arn(&ctx.partition, &ctx.region, &account, set, &rule.name);
        let links = self.links();
        let check_topic = |topic: &Option<String>| -> Result<(), ServiceError> {
            if let Some(t) = topic {
                links
                    .check_sns(ctx, t, &account, &source_arn)
                    .map_err(|_| v1::errors::invalid_sns_topic(format!("Could not publish to SNS topic <{t}>.")))?;
            }
            Ok(())
        };
        for a in rule.actions.as_deref().unwrap_or_default() {
            let set_count = [
                a.s3_action.is_some(),
                a.bounce_action.is_some(),
                a.workmail_action.is_some(),
                a.lambda_action.is_some(),
                a.stop_action.is_some(),
                a.add_header_action.is_some(),
                a.sns_action.is_some(),
                a.connect_action.is_some(),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if set_count != 1 {
                return Err(names::invalid_parameter("Each receipt action must specify exactly one action type."));
            }
            if let Some(s3) = &a.s3_action {
                links.check_s3(ctx, &s3.bucket_name, &account, &source_arn).map_err(|_| {
                    v1::errors::invalid_s3_configuration(format!("Could not write to bucket: {}", s3.bucket_name))
                })?;
                check_topic(&s3.topic_arn)?;
            }
            if let Some(sns) = &a.sns_action {
                if let Some(e) = &sns.encoding {
                    if e != "UTF-8" && e != "Base64" {
                        return Err(names::invalid_parameter(format!("Invalid SNS encoding: {e}")));
                    }
                }
                check_topic(&Some(sns.topic_arn.clone()))?;
            }
            if let Some(l) = &a.lambda_action {
                if let Some(t) = &l.invocation_type {
                    if t != "Event" && t != "RequestResponse" {
                        return Err(names::invalid_parameter(format!("Invalid invocation type: {t}")));
                    }
                }
                links.check_lambda(ctx, &l.function_arn, &account, &source_arn).map_err(|_| {
                    v1::errors::invalid_lambda_function(format!("Could not invoke Lambda function: {}", l.function_arn))
                })?;
                check_topic(&l.topic_arn)?;
            }
            if let Some(b) = &a.bounce_action {
                if !b.smtp_reply_code.starts_with('5') || b.smtp_reply_code.len() != 3 {
                    return Err(names::invalid_parameter(format!("Invalid SMTP reply code: {}", b.smtp_reply_code)));
                }
                names::check_address(&b.sender)
                    .map_err(|_| names::invalid_parameter(format!("Invalid sender: {}", b.sender)))?;
                check_topic(&b.topic_arn)?;
            }
            if let Some(s) = &a.stop_action {
                if s.scope != "RuleSet" {
                    return Err(names::invalid_parameter(format!("Invalid stop scope: {}", s.scope)));
                }
                check_topic(&s.topic_arn)?;
            }
            if let Some(h) = &a.add_header_action {
                let valid = !h.header_name.is_empty()
                    && h.header_name.len() <= 50
                    && h.header_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    && !h.header_value.contains(['\r', '\n'])
                    && h.header_value.len() <= 2048;
                if !valid {
                    return Err(names::invalid_parameter(format!("Invalid header: {}", h.header_name)));
                }
            }
            if let Some(w) = &a.workmail_action {
                check_topic(&w.topic_arn)?;
            }
        }
        Ok(())
    }

    fn with_rule_set<T>(
        &self,
        ctx: &RequestContext,
        name: &str,
        f: impl FnOnce(&mut RuleSet) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        self.with_region(ctx, |r| match r.rule_sets.get_mut(name) {
            Some(s) => f(s),
            None => Err(no_rule_set(name)),
        })
    }

    pub(crate) fn create_receipt_rule_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateReceiptRuleSetRequest,
    ) -> Result<t1::CreateReceiptRuleSetResponse, ServiceError> {
        authorize(ctx, "1", "CreateReceiptRuleSet", &rule_set_arn(ctx, &input.rule_set_name))?;
        check_name("rule set", &input.rule_set_name)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if r.rule_sets.contains_key(&input.rule_set_name) {
                return Err(v1::errors::already_exists(format!("Rule set already exists: {}", input.rule_set_name)));
            }
            if r.rule_sets.len() >= MAX_RULE_SETS {
                return Err(v1::errors::limit_exceeded(format!("Maximum rule set count {MAX_RULE_SETS} reached.")));
            }
            r.rule_sets.insert(
                input.rule_set_name.clone(),
                RuleSet { name: input.rule_set_name, created: now, rules: Vec::new() },
            );
            Ok(Default::default())
        })
    }

    pub(crate) fn clone_receipt_rule_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CloneReceiptRuleSetRequest,
    ) -> Result<t1::CloneReceiptRuleSetResponse, ServiceError> {
        authorize(ctx, "1", "CloneReceiptRuleSet", &rule_set_arn(ctx, &input.rule_set_name))?;
        check_name("rule set", &input.rule_set_name)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let original = r
                .rule_sets
                .get(&input.original_rule_set_name)
                .ok_or_else(|| no_rule_set(&input.original_rule_set_name))?;
            let rules = original.rules.clone();
            if r.rule_sets.contains_key(&input.rule_set_name) {
                return Err(v1::errors::already_exists(format!("Rule set already exists: {}", input.rule_set_name)));
            }
            if r.rule_sets.len() >= MAX_RULE_SETS {
                return Err(v1::errors::limit_exceeded(format!("Maximum rule set count {MAX_RULE_SETS} reached.")));
            }
            r.rule_sets.insert(input.rule_set_name.clone(), RuleSet { name: input.rule_set_name, created: now, rules });
            Ok(Default::default())
        })
    }

    pub(crate) fn delete_receipt_rule_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteReceiptRuleSetRequest,
    ) -> Result<t1::DeleteReceiptRuleSetResponse, ServiceError> {
        authorize(ctx, "1", "DeleteReceiptRuleSet", &rule_set_arn(ctx, &input.rule_set_name))?;
        self.with_region(ctx, |r| {
            if r.active_rule_set.as_deref() == Some(input.rule_set_name.as_str()) {
                return Err(v1::errors::cannot_delete(format!(
                    "Cannot delete active rule set: {}",
                    input.rule_set_name
                )));
            }
            r.rule_sets.remove(&input.rule_set_name);
            Ok(Default::default())
        })
    }

    fn describe(s: &RuleSet) -> (t1::ReceiptRuleSetMetadata, Vec<t1::ReceiptRule>) {
        (t1::ReceiptRuleSetMetadata { name: Some(s.name.clone()), created_timestamp: Some(s.created) }, s.rules.clone())
    }

    pub(crate) fn describe_receipt_rule_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DescribeReceiptRuleSetRequest,
    ) -> Result<t1::DescribeReceiptRuleSetResponse, ServiceError> {
        authorize(ctx, "1", "DescribeReceiptRuleSet", &rule_set_arn(ctx, &input.rule_set_name))?;
        let (metadata, rules) = self.with_rule_set(ctx, &input.rule_set_name, |s| Ok(Self::describe(s)))?;
        Ok(t1::DescribeReceiptRuleSetResponse { metadata: Some(metadata), rules: Some(rules) })
    }

    pub(crate) fn describe_active_receipt_rule_set_v1(
        &self,
        ctx: &RequestContext,
        _input: t1::DescribeActiveReceiptRuleSetRequest,
    ) -> Result<t1::DescribeActiveReceiptRuleSetResponse, ServiceError> {
        authorize(ctx, "1", "DescribeActiveReceiptRuleSet", "*")?;
        let active = self.with_region(ctx, |r| {
            let name = r.active_rule_set.clone()?;
            r.rule_sets.get(&name).map(Self::describe)
        });
        Ok(match active {
            Some((metadata, rules)) => {
                t1::DescribeActiveReceiptRuleSetResponse { metadata: Some(metadata), rules: Some(rules) }
            }
            None => Default::default(),
        })
    }

    pub(crate) fn set_active_receipt_rule_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SetActiveReceiptRuleSetRequest,
    ) -> Result<t1::SetActiveReceiptRuleSetResponse, ServiceError> {
        let resource = input.rule_set_name.as_deref().map_or_else(|| "*".to_string(), |n| rule_set_arn(ctx, n));
        authorize(ctx, "1", "SetActiveReceiptRuleSet", &resource)?;
        self.with_region(ctx, |r| {
            if let Some(n) = &input.rule_set_name {
                if !r.rule_sets.contains_key(n) {
                    return Err(no_rule_set(n));
                }
            }
            r.active_rule_set = input.rule_set_name;
            Ok(Default::default())
        })
    }

    pub(crate) fn list_receipt_rule_sets_v1(
        &self,
        ctx: &RequestContext,
        input: t1::ListReceiptRuleSetsRequest,
    ) -> Result<t1::ListReceiptRuleSetsResponse, ServiceError> {
        authorize(ctx, "1", "ListReceiptRuleSets", "*")?;
        let all: Vec<t1::ReceiptRuleSetMetadata> =
            self.with_region(ctx, |r| r.rule_sets.values().map(|s| Self::describe(s).0).collect());
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), None, 100);
        Ok(t1::ListReceiptRuleSetsResponse { rule_sets: Some(page), next_token: next })
    }

    pub(crate) fn reorder_receipt_rule_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::ReorderReceiptRuleSetRequest,
    ) -> Result<t1::ReorderReceiptRuleSetResponse, ServiceError> {
        authorize(ctx, "1", "ReorderReceiptRuleSet", &rule_set_arn(ctx, &input.rule_set_name))?;
        self.with_rule_set(ctx, &input.rule_set_name, |s| {
            let mut reordered = Vec::new();
            for n in &input.rule_names {
                let rule = s.rules.iter().find(|r| &r.name == n).ok_or_else(|| no_rule(n))?;
                if reordered.iter().any(|r: &t1::ReceiptRule| &r.name == n) {
                    return Err(names::invalid_parameter(format!("Duplicate rule name: {n}")));
                }
                reordered.push(rule.clone());
            }
            if reordered.len() != s.rules.len() {
                return Err(names::invalid_parameter("The rule names must include every rule in the rule set."));
            }
            s.rules = reordered;
            Ok(Default::default())
        })
    }

    pub(crate) fn create_receipt_rule_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateReceiptRuleRequest,
    ) -> Result<t1::CreateReceiptRuleResponse, ServiceError> {
        authorize(ctx, "1", "CreateReceiptRule", &rule_set_arn(ctx, &input.rule_set_name))?;
        self.with_rule_set(ctx, &input.rule_set_name, |_| Ok(()))?;
        self.check_rule(ctx, &input.rule_set_name, &input.rule)?;
        self.with_rule_set(ctx, &input.rule_set_name, |s| {
            if s.rules.iter().any(|r| r.name == input.rule.name) {
                return Err(v1::errors::already_exists(format!("Rule already exists: {}", input.rule.name)));
            }
            if s.rules.len() >= MAX_RULES {
                return Err(v1::errors::limit_exceeded(format!("Maximum rule count {MAX_RULES} reached.")));
            }
            let at = match &input.after {
                Some(after) => s.rules.iter().position(|r| &r.name == after).ok_or_else(|| no_rule(after))? + 1,
                None => 0,
            };
            s.rules.insert(at, input.rule);
            Ok(Default::default())
        })
    }

    pub(crate) fn update_receipt_rule_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateReceiptRuleRequest,
    ) -> Result<t1::UpdateReceiptRuleResponse, ServiceError> {
        authorize(ctx, "1", "UpdateReceiptRule", &rule_set_arn(ctx, &input.rule_set_name))?;
        self.with_rule_set(ctx, &input.rule_set_name, |s| {
            s.rules.iter().any(|r| r.name == input.rule.name).then_some(()).ok_or_else(|| no_rule(&input.rule.name))
        })?;
        self.check_rule(ctx, &input.rule_set_name, &input.rule)?;
        self.with_rule_set(ctx, &input.rule_set_name, |s| {
            let rule =
                s.rules.iter_mut().find(|r| r.name == input.rule.name).ok_or_else(|| no_rule(&input.rule.name))?;
            *rule = input.rule;
            Ok(Default::default())
        })
    }

    pub(crate) fn delete_receipt_rule_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteReceiptRuleRequest,
    ) -> Result<t1::DeleteReceiptRuleResponse, ServiceError> {
        authorize(ctx, "1", "DeleteReceiptRule", &rule_set_arn(ctx, &input.rule_set_name))?;
        self.with_rule_set(ctx, &input.rule_set_name, |s| {
            s.rules.retain(|r| r.name != input.rule_name);
            Ok(Default::default())
        })
    }

    pub(crate) fn describe_receipt_rule_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DescribeReceiptRuleRequest,
    ) -> Result<t1::DescribeReceiptRuleResponse, ServiceError> {
        authorize(ctx, "1", "DescribeReceiptRule", &rule_set_arn(ctx, &input.rule_set_name))?;
        let rule = self.with_rule_set(ctx, &input.rule_set_name, |s| {
            s.rules.iter().find(|r| r.name == input.rule_name).cloned().ok_or_else(|| no_rule(&input.rule_name))
        })?;
        Ok(t1::DescribeReceiptRuleResponse { rule: Some(rule) })
    }

    pub(crate) fn set_receipt_rule_position_v1(
        &self,
        ctx: &RequestContext,
        input: t1::SetReceiptRulePositionRequest,
    ) -> Result<t1::SetReceiptRulePositionResponse, ServiceError> {
        authorize(ctx, "1", "SetReceiptRulePosition", &rule_set_arn(ctx, &input.rule_set_name))?;
        self.with_rule_set(ctx, &input.rule_set_name, |s| {
            let from =
                s.rules.iter().position(|r| r.name == input.rule_name).ok_or_else(|| no_rule(&input.rule_name))?;
            if let Some(after) = &input.after {
                if !s.rules.iter().any(|r| &r.name == after) {
                    return Err(no_rule(after));
                }
            }
            let rule = s.rules.remove(from);
            let at = match &input.after {
                Some(after) => s.rules.iter().position(|r| &r.name == after).map_or(s.rules.len(), |i| i + 1),
                None => 0,
            };
            s.rules.insert(at, rule);
            Ok(Default::default())
        })
    }

    pub(crate) fn create_receipt_filter_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateReceiptFilterRequest,
    ) -> Result<t1::CreateReceiptFilterResponse, ServiceError> {
        authorize(ctx, "1", "CreateReceiptFilter", &names::arn(ctx, &format!("receipt-filter/{}", input.filter.name)))?;
        check_name("filter", &input.filter.name)?;
        let ip = &input.filter.ip_filter;
        if ip.policy != "Block" && ip.policy != "Allow" {
            return Err(names::invalid_parameter(format!("Invalid filter policy: {}", ip.policy)));
        }
        if !parse_cidr(&ip.cidr).is_some_and(|(a, _)| a.is_ipv4()) {
            return Err(names::invalid_parameter(format!("Invalid CIDR: {}", ip.cidr)));
        }
        self.with_region(ctx, |r| {
            if r.receipt_filters.iter().any(|f| f.name == input.filter.name) {
                return Err(v1::errors::already_exists(format!("Filter already exists: {}", input.filter.name)));
            }
            if r.receipt_filters.len() >= MAX_FILTERS {
                return Err(v1::errors::limit_exceeded(format!("Maximum filter count {MAX_FILTERS} reached.")));
            }
            r.receipt_filters.push(input.filter);
            Ok(Default::default())
        })
    }

    pub(crate) fn delete_receipt_filter_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteReceiptFilterRequest,
    ) -> Result<t1::DeleteReceiptFilterResponse, ServiceError> {
        authorize(ctx, "1", "DeleteReceiptFilter", &names::arn(ctx, &format!("receipt-filter/{}", input.filter_name)))?;
        self.with_region(ctx, |r| r.receipt_filters.retain(|f| f.name != input.filter_name));
        Ok(Default::default())
    }

    pub(crate) fn list_receipt_filters_v1(
        &self,
        ctx: &RequestContext,
        _input: t1::ListReceiptFiltersRequest,
    ) -> Result<t1::ListReceiptFiltersResponse, ServiceError> {
        authorize(ctx, "1", "ListReceiptFilters", "*")?;
        let filters = self.with_region(ctx, |r| r.receipt_filters.clone());
        Ok(t1::ListReceiptFiltersResponse { filters: Some(filters) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs() {
        assert!(cidr_contains("10.0.0.0/8", "10.1.2.3"));
        assert!(!cidr_contains("10.0.0.0/8", "11.1.2.3"));
        assert!(cidr_contains("127.0.0.1", "127.0.0.1"));
        assert!(cidr_contains("0.0.0.0/0", "8.8.8.8"));
        assert!(parse_cidr("1.2.3.4/33").is_none());
    }
}
