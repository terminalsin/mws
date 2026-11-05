//! Automation rules: V1 rules update ASFF findings as they are imported,
//! in rule order, until a terminal rule matches; V2 rules update the OCSF
//! view of findings (severity, status, comment) the same way.

use mws_core::{RequestContext, ServiceError};
use serde_json::Value;

use crate::common::{self, account, authorize_hub, hub, hub_mut, invalid_input, not_found, paginate};
use crate::filters;
use crate::findings::{FieldUpdates, ImportScope};
use crate::generated::{errors, types};
use crate::state::{FindingRec, HistoryRec, RuleRec, RuleV2Rec, State};
use crate::SecurityHub;

const MAX_RULES: usize = 100;

/// The account whose rules apply to findings of `account`: its
/// administrator, or itself.
fn rules_owner(state: &State, account: &str, region: &str) -> String {
    state.administrator_of(account, region).unwrap_or_else(|| account.to_string())
}

/// Run V1 and V2 automation rules over a finding being imported.
pub fn apply_rules(state: &State, scope: &ImportScope<'_>, rec: &mut FindingRec) {
    let owner = rules_owner(state, scope.account, scope.region);
    let Some(h) = state.hub(&owner, scope.region) else { return };
    let mut rules: Vec<&RuleRec> =
        h.automation_rules.values().filter(|r| r.config.rule_status.as_deref() != Some("DISABLED")).collect();
    rules.sort_by_key(|r| (r.config.rule_order.unwrap_or(1000), r.config.created_at));
    for r in rules {
        let criteria = r.config.criteria.as_ref().map(filters::to_json).unwrap_or(Value::Null);
        if !filters::matches_asff(&rec.finding, &criteria, scope.now) {
            continue;
        }
        let arn = r.config.rule_arn.clone().unwrap_or_default();
        for a in r.config.actions.iter().flatten() {
            let Some(u) = &a.finding_fields_update else { continue };
            let updates = FieldUpdates {
                note: u.note.as_ref().map(|n| (n.text.clone(), n.updated_by.clone())),
                severity: u
                    .severity
                    .as_ref()
                    .and_then(|s| FieldUpdates::severity_from(s.normalized, s.product, s.label.clone())),
                verification_state: u.verification_state.clone(),
                confidence: u.confidence,
                criticality: u.criticality,
                types: u.types.clone(),
                user_defined_fields: u.user_defined_fields.clone(),
                workflow_status: u.workflow.as_ref().and_then(|w| w.status.clone()),
                related_findings: u.related_findings.clone(),
            };
            let changes = updates.apply(rec, &arn, scope.now);
            if !changes.is_empty() {
                rec.history.push(HistoryRec {
                    time: scope.now,
                    created: false,
                    source_type: "BATCH_UPDATE_FINDINGS".into(),
                    identity: arn.clone(),
                    updates: changes,
                });
            }
        }
        if r.config.is_terminal == Some(true) {
            break;
        }
    }

    // V2 rules, when Security Hub V2 is on for the owner.
    let Some(_) = state.hubs_v2.get(&crate::state::key(&owner, scope.region)) else { return };
    let mut rules: Vec<&RuleV2Rec> = h.automation_rules_v2.values().filter(|r| r.status != "DISABLED").collect();
    rules.sort_by(|a, b| a.order.partial_cmp(&b.order).unwrap_or(std::cmp::Ordering::Equal));
    for r in rules {
        let types::Criteria::OcsfFindingCriteria(c) = &r.criteria else { continue };
        let doc = crate::ocsf::to_ocsf(&rec.finding, &rec.v2);
        if !filters::matches_composite(&doc, &filters::to_json(c), scope.now) {
            continue;
        }
        for a in &r.actions {
            if let Some(u) = &a.finding_fields_update {
                if u.severity_id.is_some() {
                    rec.v2.severity_id = u.severity_id;
                }
                if u.status_id.is_some() {
                    rec.v2.status_id = u.status_id;
                }
                if u.comment.is_some() {
                    rec.v2.comment = u.comment.clone();
                }
            }
        }
    }
}

fn check_order(order: i32) -> Result<(), ServiceError> {
    if !(1..=1000).contains(&order) {
        return Err(invalid_input("RuleOrder must be between 1 and 1000."));
    }
    Ok(())
}

fn check_actions(actions: &[types::AutomationRulesAction]) -> Result<(), ServiceError> {
    if actions.is_empty() || actions.len() > 1 {
        return Err(invalid_input("Actions must contain exactly one action."));
    }
    for a in actions {
        if a.finding_fields_update.is_none() {
            return Err(invalid_input("FindingFieldsUpdate is required for FINDING_FIELDS_UPDATE actions."));
        }
    }
    Ok(())
}

/// Only an administrator or a standalone account may manage automation rules.
fn check_not_member(state: &State, ctx: &RequestContext) -> Result<(), ServiceError> {
    if state.administrator_of(account(ctx), &ctx.region).is_some() {
        return Err(errors::access_denied(
            "Only the Security Hub administrator account can create and manage automation rules.",
        ));
    }
    Ok(())
}

fn metadata(c: &types::AutomationRulesConfig) -> types::AutomationRulesMetadata {
    types::AutomationRulesMetadata {
        rule_arn: c.rule_arn.clone(),
        rule_status: c.rule_status.clone(),
        rule_order: c.rule_order,
        rule_name: c.rule_name.clone(),
        description: c.description.clone(),
        is_terminal: c.is_terminal,
        created_at: c.created_at,
        updated_at: c.updated_at,
        created_by: c.created_by.clone(),
    }
}

fn unprocessed(arn: &str, code: i32, message: &str) -> types::UnprocessedAutomationRule {
    types::UnprocessedAutomationRule {
        rule_arn: Some(arn.to_string()),
        error_code: Some(code),
        error_message: Some(message.to_string()),
    }
}

/// A V2 rule by id or ARN.
fn v2_key<'a>(rules: &'a std::collections::BTreeMap<String, RuleV2Rec>, identifier: &str) -> Option<&'a str> {
    rules.iter().find(|(id, r)| *id == identifier || r.arn == identifier).map(|(id, _)| id.as_str())
}

impl SecurityHub {
    pub(crate) fn create_automation_rule_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomationRuleRequest,
    ) -> Result<types::CreateAutomationRuleResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        common::authorize_with(
            ctx,
            "CreateAutomationRule",
            &common::hub_arn(ctx, account(ctx)),
            common::tag_conditions(&tags),
        )?;
        check_order(input.rule_order)?;
        check_actions(&input.actions)?;
        let mut state = self.write();
        check_not_member(&state, ctx)?;
        let arn = common::arn(ctx, &format!("automation-rule/{}", uuid::Uuid::new_v4()));
        let h = hub_mut(&mut state, ctx)?;
        if h.automation_rules.len() >= MAX_RULES {
            return Err(errors::limit_exceeded("You can't create more than 100 automation rules."));
        }
        common::check_tags(&Default::default(), &tags)?;
        let config = types::AutomationRulesConfig {
            rule_arn: Some(arn.clone()),
            rule_status: Some(input.rule_status.unwrap_or_else(|| "ENABLED".into())),
            rule_order: Some(input.rule_order),
            rule_name: Some(input.rule_name),
            description: Some(input.description),
            is_terminal: Some(input.is_terminal.unwrap_or(false)),
            criteria: Some(input.criteria),
            actions: Some(input.actions),
            created_at: Some(ctx.received_at),
            updated_at: Some(ctx.received_at),
            created_by: Some(ctx.caller.arn.clone()),
        };
        h.automation_rules.insert(arn.clone(), RuleRec { config });
        if !tags.is_empty() {
            h.resource_tags.insert(arn.clone(), tags);
        }
        Ok(types::CreateAutomationRuleResponse { rule_arn: Some(arn) })
    }

    pub(crate) fn batch_get_automation_rules_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetAutomationRulesRequest,
    ) -> Result<types::BatchGetAutomationRulesResponse, ServiceError> {
        authorize_hub(ctx, "BatchGetAutomationRules")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let mut rules = Vec::new();
        let mut missing = Vec::new();
        for arn in &input.automation_rules_arns {
            match h.automation_rules.get(arn) {
                Some(r) => rules.push(r.config.clone()),
                None => missing.push(unprocessed(arn, 404, "Rule not found")),
            }
        }
        Ok(types::BatchGetAutomationRulesResponse { rules: Some(rules), unprocessed_automation_rules: Some(missing) })
    }

    pub(crate) fn batch_update_automation_rules_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateAutomationRulesRequest,
    ) -> Result<types::BatchUpdateAutomationRulesResponse, ServiceError> {
        authorize_hub(ctx, "BatchUpdateAutomationRules")?;
        let mut state = self.write();
        check_not_member(&state, ctx)?;
        let h = hub_mut(&mut state, ctx)?;
        let mut processed = Vec::new();
        let mut failed = Vec::new();
        for item in input.update_automation_rules_request_items {
            let Some(r) = h.automation_rules.get_mut(&item.rule_arn) else {
                failed.push(unprocessed(&item.rule_arn, 404, "Rule not found"));
                continue;
            };
            if let Some(o) = item.rule_order {
                if !(1..=1000).contains(&o) {
                    failed.push(unprocessed(&item.rule_arn, 400, "RuleOrder must be between 1 and 1000."));
                    continue;
                }
            }
            if let Some(a) = &item.actions {
                if let Err(e) = check_actions(a) {
                    failed.push(unprocessed(&item.rule_arn, 400, &e.message));
                    continue;
                }
            }
            let c = &mut r.config;
            if item.rule_status.is_some() {
                c.rule_status = item.rule_status;
            }
            if item.rule_order.is_some() {
                c.rule_order = item.rule_order;
            }
            if item.description.is_some() {
                c.description = item.description;
            }
            if item.rule_name.is_some() {
                c.rule_name = item.rule_name;
            }
            if item.is_terminal.is_some() {
                c.is_terminal = item.is_terminal;
            }
            if item.criteria.is_some() {
                c.criteria = item.criteria;
            }
            if item.actions.is_some() {
                c.actions = item.actions;
            }
            c.updated_at = Some(ctx.received_at);
            processed.push(item.rule_arn);
        }
        Ok(types::BatchUpdateAutomationRulesResponse {
            processed_automation_rules: Some(processed),
            unprocessed_automation_rules: Some(failed),
        })
    }

    pub(crate) fn batch_delete_automation_rules_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteAutomationRulesRequest,
    ) -> Result<types::BatchDeleteAutomationRulesResponse, ServiceError> {
        authorize_hub(ctx, "BatchDeleteAutomationRules")?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let mut processed = Vec::new();
        let mut failed = Vec::new();
        for arn in input.automation_rules_arns {
            if h.automation_rules.remove(&arn).is_some() {
                h.resource_tags.remove(&arn);
                processed.push(arn);
            } else {
                failed.push(unprocessed(&arn, 404, "Rule not found"));
            }
        }
        Ok(types::BatchDeleteAutomationRulesResponse {
            processed_automation_rules: Some(processed),
            unprocessed_automation_rules: Some(failed),
        })
    }

    pub(crate) fn list_automation_rules_op(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomationRulesRequest,
    ) -> Result<types::ListAutomationRulesResponse, ServiceError> {
        authorize_hub(ctx, "ListAutomationRules")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let mut rules: Vec<&RuleRec> = h.automation_rules.values().collect();
        rules.sort_by_key(|r| (r.config.rule_order, r.config.created_at));
        let all: Vec<types::AutomationRulesMetadata> = rules.into_iter().map(|r| metadata(&r.config)).collect();
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAutomationRulesResponse { automation_rules_metadata: Some(page), next_token })
    }

    // ---- V2 --------------------------------------------------------------------

    pub(crate) fn create_automation_rule_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomationRuleV2Request,
    ) -> Result<types::CreateAutomationRuleV2Response, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        common::authorize_with(
            ctx,
            "CreateAutomationRuleV2",
            &common::hub_arn(ctx, account(ctx)),
            common::tag_conditions(&tags),
        )?;
        if !(1.0..=1000.0).contains(&input.rule_order) {
            return Err(errors::validation("RuleOrder must be between 1 and 1000."));
        }
        let mut state = self.write();
        crate::v2::require_v2(&state, ctx)?;
        check_not_member(&state, ctx)?;
        let id = uuid::Uuid::new_v4().to_string();
        let arn = common::arn(ctx, &format!("automation-rulev2/{id}"));
        let h = hub_mut(&mut state, ctx)?;
        if h.automation_rules_v2.len() >= MAX_RULES {
            return Err(errors::service_quota_exceeded("You can't create more than 100 automation rules."));
        }
        if h.automation_rules_v2.values().any(|r| r.name == input.rule_name) {
            return Err(errors::conflict(format!("An automation rule named {} already exists.", input.rule_name)));
        }
        h.automation_rules_v2.insert(
            id.clone(),
            RuleV2Rec {
                arn: arn.clone(),
                id: id.clone(),
                name: input.rule_name,
                status: input.rule_status.unwrap_or_else(|| "ENABLED".into()),
                description: input.description,
                order: input.rule_order,
                criteria: input.criteria,
                actions: input.actions,
                created_at: ctx.received_at,
                updated_at: ctx.received_at,
            },
        );
        if !tags.is_empty() {
            h.resource_tags.insert(arn.clone(), tags);
        }
        Ok(types::CreateAutomationRuleV2Response { rule_arn: Some(arn), rule_id: Some(id) })
    }

    pub(crate) fn get_automation_rule_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomationRuleV2Request,
    ) -> Result<types::GetAutomationRuleV2Response, ServiceError> {
        authorize_hub(ctx, "GetAutomationRuleV2")?;
        let state = self.read();
        crate::v2::require_v2(&state, ctx)?;
        let h = hub(&state, ctx)?;
        let id = v2_key(&h.automation_rules_v2, &input.identifier).ok_or_else(|| rule_not_found(&input.identifier))?;
        let r = &h.automation_rules_v2[id];
        Ok(types::GetAutomationRuleV2Response {
            rule_arn: Some(r.arn.clone()),
            rule_id: Some(r.id.clone()),
            rule_order: Some(r.order),
            rule_name: Some(r.name.clone()),
            rule_status: Some(r.status.clone()),
            description: Some(r.description.clone()),
            criteria: Some(r.criteria.clone()),
            actions: Some(r.actions.clone()),
            created_at: Some(r.created_at),
            updated_at: Some(r.updated_at),
        })
    }

    pub(crate) fn update_automation_rule_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomationRuleV2Request,
    ) -> Result<types::UpdateAutomationRuleV2Response, ServiceError> {
        authorize_hub(ctx, "UpdateAutomationRuleV2")?;
        if let Some(o) = input.rule_order {
            if !(1.0..=1000.0).contains(&o) {
                return Err(errors::validation("RuleOrder must be between 1 and 1000."));
            }
        }
        let mut state = self.write();
        crate::v2::require_v2(&state, ctx)?;
        let h = hub_mut(&mut state, ctx)?;
        let id = v2_key(&h.automation_rules_v2, &input.identifier)
            .ok_or_else(|| rule_not_found(&input.identifier))?
            .to_string();
        let r = h.automation_rules_v2.get_mut(&id).expect("found");
        if let Some(v) = input.rule_status {
            r.status = v;
        }
        if let Some(v) = input.rule_order {
            r.order = v;
        }
        if let Some(v) = input.description {
            r.description = v;
        }
        if let Some(v) = input.rule_name {
            r.name = v;
        }
        if let Some(v) = input.criteria {
            r.criteria = v;
        }
        if let Some(v) = input.actions {
            r.actions = v;
        }
        r.updated_at = ctx.received_at;
        Ok(types::UpdateAutomationRuleV2Response {})
    }

    pub(crate) fn delete_automation_rule_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomationRuleV2Request,
    ) -> Result<types::DeleteAutomationRuleV2Response, ServiceError> {
        authorize_hub(ctx, "DeleteAutomationRuleV2")?;
        let mut state = self.write();
        crate::v2::require_v2(&state, ctx)?;
        let h = hub_mut(&mut state, ctx)?;
        let id = v2_key(&h.automation_rules_v2, &input.identifier)
            .ok_or_else(|| rule_not_found(&input.identifier))?
            .to_string();
        if let Some(r) = h.automation_rules_v2.remove(&id) {
            h.resource_tags.remove(&r.arn);
        }
        Ok(types::DeleteAutomationRuleV2Response {})
    }

    pub(crate) fn list_automation_rules_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomationRulesV2Request,
    ) -> Result<types::ListAutomationRulesV2Response, ServiceError> {
        authorize_hub(ctx, "ListAutomationRulesV2")?;
        let state = self.read();
        crate::v2::require_v2(&state, ctx)?;
        let h = hub(&state, ctx)?;
        let mut rules: Vec<&RuleV2Rec> = h.automation_rules_v2.values().collect();
        rules.sort_by(|a, b| a.order.partial_cmp(&b.order).unwrap_or(std::cmp::Ordering::Equal));
        let all: Vec<types::AutomationRulesMetadataV2> = rules
            .into_iter()
            .map(|r| types::AutomationRulesMetadataV2 {
                rule_arn: Some(r.arn.clone()),
                rule_id: Some(r.id.clone()),
                rule_order: Some(r.order),
                rule_name: Some(r.name.clone()),
                rule_status: Some(r.status.clone()),
                description: Some(r.description.clone()),
                actions: Some(
                    r.actions
                        .iter()
                        .map(|a| types::AutomationRulesActionTypeObjectV2 { r#type: Some(a.r#type.clone()) })
                        .collect(),
                ),
                created_at: Some(r.created_at),
                updated_at: Some(r.updated_at),
            })
            .collect();
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAutomationRulesV2Response { rules: Some(page), next_token })
    }
}

fn rule_not_found(id: &str) -> ServiceError {
    not_found(format!("Automation rule {id} not found."))
}
