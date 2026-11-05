//! Custom detection rules (GuardDuty's managed catalog), their
//! associations and organization configurations, and investigations.

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::common::*;
use crate::generated::types;
use crate::state::{Investigation, RuleAssociation, RuleOrgConfig};
use crate::GuardDuty;

/// `(id, name, description, severity, data source, tactic, technique,
/// expression)` of the rules in the catalog.
const RULES: &[Rule] = &[
    (
        "console-login-without-mfa",
        "Console sign-in without MFA",
        "An IAM user signed in to the AWS Management Console without multi-factor authentication.",
        "MEDIUM",
        "CloudTrailManagementEvent",
        "InitialAccess",
        "T1078",
        "SELECT * FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND additionalEventData.MFAUsed = 'No'",
    ),
    (
        "root-access-key-created",
        "Root user access key created",
        "An access key was created for the account's root user.",
        "HIGH",
        "CloudTrailManagementEvent",
        "Persistence",
        "T1098",
        "SELECT * FROM cloudtrail WHERE eventName = 'CreateAccessKey' AND userIdentity.type = 'Root'",
    ),
    (
        "cloudtrail-trail-deleted",
        "CloudTrail trail deleted",
        "A CloudTrail trail was deleted or its logging stopped.",
        "HIGH",
        "CloudTrailManagementEvent",
        "DefenseEvasion",
        "T1562",
        "SELECT * FROM cloudtrail WHERE eventName IN ('DeleteTrail', 'StopLogging')",
    ),
    (
        "kms-key-scheduled-deletion",
        "KMS key scheduled for deletion",
        "A customer managed KMS key was scheduled for deletion.",
        "MEDIUM",
        "CloudTrailManagementEvent",
        "Impact",
        "T1485",
        "SELECT * FROM cloudtrail WHERE eventName = 'ScheduleKeyDeletion'",
    ),
];

type Rule =
    (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

fn rule(id: &str) -> Result<&'static Rule, ServiceError> {
    RULES.iter().find(|r| r.0 == id).ok_or_else(|| not_found("The request is rejected because the rule was not found."))
}

fn rule_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:guardduty:{}::custom-detection-rule/{id}", ctx.partition, ctx.region)
}

fn association_arn(ctx: &RequestContext, account: &str, rule: &str, id: &str) -> String {
    format!("arn:{}:guardduty:{}:{account}:custom-detection-rule/{rule}/association/{id}", ctx.partition, ctx.region)
}

/// Dry runs end after 30 days.
fn expiry(a_mode: &str, from: chrono::DateTime<chrono::Utc>) -> Option<chrono::DateTime<chrono::Utc>> {
    (a_mode == "DRY_RUN").then(|| from + Duration::days(30))
}

fn assoc_not_found() -> ServiceError {
    not_found("The request is rejected because the rule association was not found.")
}

fn org_config_not_found() -> ServiceError {
    not_found("The request is rejected because the organization configuration was not found.")
}

impl GuardDuty {
    pub(crate) fn list_custom_detection_rules(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomDetectionRulesRequest,
    ) -> Result<types::ListCustomDetectionRulesResponse, ServiceError> {
        self.authorize(ctx, "ListCustomDetectionRules", "*", ConditionContext::new())?;
        let created = chrono::DateTime::<chrono::Utc>::from_timestamp(1_761_955_200, 0).unwrap_or(ctx.received_at);
        let all: Vec<types::RuleSummary> = RULES
            .iter()
            .filter(|r| {
                input.filters.iter().flatten().all(|f| {
                    let field = match f.name.to_ascii_lowercase().as_str() {
                        "severity" => r.3,
                        "datasource" | "data_source" => r.4,
                        "tactic" => r.5,
                        "technique" => r.6,
                        "name" => r.1,
                        _ => return true,
                    };
                    if f.condition.as_deref() == Some("CONTAINS") {
                        f.values.iter().any(|v| field.contains(v.as_str()))
                    } else {
                        f.values.iter().any(|v| v == field)
                    }
                })
            })
            .map(|r| types::RuleSummary {
                rule_id: r.0.into(),
                arn: rule_arn(ctx, r.0),
                name: r.1.into(),
                description: r.2.into(),
                severity: r.3.into(),
                data_source: r.4.into(),
                tactic: r.5.into(),
                technique: r.6.into(),
                service: "guardduty".into(),
                language: Some("SQL".into()),
                schema: Some("CloudTrail".into()),
                created_at: created,
                updated_at: Some(created),
            })
            .collect();
        let (rules, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListCustomDetectionRulesResponse { rules, next_token })
    }

    pub(crate) fn get_custom_detection_rule(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomDetectionRuleRequest,
    ) -> Result<types::GetCustomDetectionRuleResponse, ServiceError> {
        self.authorize(ctx, "GetCustomDetectionRule", &rule_arn(ctx, &input.rule_id), ConditionContext::new())?;
        let r = rule(&input.rule_id)?;
        let created = chrono::DateTime::<chrono::Utc>::from_timestamp(1_761_955_200, 0).unwrap_or(ctx.received_at);
        Ok(types::GetCustomDetectionRuleResponse {
            rule: types::RuleDetail {
                rule_id: r.0.into(),
                arn: rule_arn(ctx, r.0),
                name: r.1.into(),
                description: r.2.into(),
                severity: r.3.into(),
                data_source: r.4.into(),
                tactic: r.5.into(),
                technique: r.6.into(),
                service: "guardduty".into(),
                definition: types::RuleDefinition { expression: r.7.into() },
                language: Some("SQL".into()),
                schema: Some("CloudTrail".into()),
                runtime_monitoring_details: None,
                created_at: created,
                updated_at: Some(created),
            },
        })
    }

    fn association_detail(ctx: &RequestContext, account: &str, a: &RuleAssociation) -> types::AssociationDetail {
        types::AssociationDetail {
            association_id: a.id.clone(),
            arn: association_arn(ctx, account, &a.rule_id, &a.id),
            rule_id: a.rule_id.clone(),
            account_id: account.to_string(),
            mode: a.mode.clone(),
            created_at: a.created_at,
            updated_at: a.updated_at,
            expires_at: expiry(&a.mode, a.updated_at),
        }
    }

    pub(crate) fn create_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomDetectionRuleAssociationRequest,
    ) -> Result<types::CreateCustomDetectionRuleAssociationResponse, ServiceError> {
        if let Some(t) = &input.tags {
            validate_tags(t)?;
        }
        let mut cond = request_tag_context(input.tags.as_ref());
        cond.insert("guardduty:RuleId".into(), vec![input.rule_id.clone()]);
        self.authorize(ctx, "CreateCustomDetectionRuleAssociation", &rule_arn(ctx, &input.rule_id), cond)?;
        rule(&input.rule_id)?;
        let account = ctx.caller.account_id.clone();
        let mut state = self.lock();
        let acct = state.account_mut(&account, &ctx.region);
        if let Some(a) = acct.rule_associations.values().find(|a| a.rule_id == input.rule_id) {
            if a.mode == input.mode {
                return Ok(types::CreateCustomDetectionRuleAssociationResponse {
                    rule_association: Self::association_detail(ctx, &account, a),
                });
            }
            return Err(conflict("The request is rejected because the rule is already associated with the account."));
        }
        let a = RuleAssociation {
            id: hex_id(32),
            rule_id: input.rule_id,
            mode: input.mode,
            created_at: ctx.received_at,
            updated_at: ctx.received_at,
            tags: input.tags.unwrap_or_default(),
        };
        let detail = Self::association_detail(ctx, &account, &a);
        acct.rule_associations.insert(a.id.clone(), a);
        Ok(types::CreateCustomDetectionRuleAssociationResponse { rule_association: detail })
    }

    fn authorize_association(
        &self,
        ctx: &RequestContext,
        action: &str,
        rule_id: &str,
        id: &str,
    ) -> Result<(), ServiceError> {
        let tags = {
            let state = self.lock();
            state
                .account(&ctx.caller.account_id, &ctx.region)
                .and_then(|a| a.rule_associations.get(id))
                .map(|a| a.tags.clone())
                .unwrap_or_default()
        };
        self.authorize(
            ctx,
            action,
            &association_arn(ctx, &ctx.caller.account_id, rule_id, id),
            resource_tag_context(&tags),
        )
    }

    pub(crate) fn get_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomDetectionRuleAssociationRequest,
    ) -> Result<types::GetCustomDetectionRuleAssociationResponse, ServiceError> {
        self.authorize_association(ctx, "GetCustomDetectionRuleAssociation", &input.rule_id, &input.association_id)?;
        let state = self.lock();
        let a = state
            .account(&ctx.caller.account_id, &ctx.region)
            .and_then(|a| a.rule_associations.get(&input.association_id))
            .filter(|a| a.rule_id == input.rule_id)
            .ok_or_else(assoc_not_found)?;
        Ok(types::GetCustomDetectionRuleAssociationResponse {
            rule_association: Self::association_detail(ctx, &ctx.caller.account_id, a),
            tags: Some(a.tags.clone()),
        })
    }

    pub(crate) fn update_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomDetectionRuleAssociationRequest,
    ) -> Result<types::UpdateCustomDetectionRuleAssociationResponse, ServiceError> {
        self.authorize_association(ctx, "UpdateCustomDetectionRuleAssociation", &input.rule_id, &input.association_id)?;
        let mut state = self.lock();
        let a = state
            .account_mut(&ctx.caller.account_id, &ctx.region)
            .rule_associations
            .get_mut(&input.association_id)
            .filter(|a| a.rule_id == input.rule_id)
            .ok_or_else(assoc_not_found)?;
        if a.mode != input.mode {
            a.mode = input.mode;
            a.updated_at = ctx.received_at;
        }
        Ok(Default::default())
    }

    pub(crate) fn delete_custom_detection_rule_association(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomDetectionRuleAssociationRequest,
    ) -> Result<types::DeleteCustomDetectionRuleAssociationResponse, ServiceError> {
        self.authorize_association(ctx, "DeleteCustomDetectionRuleAssociation", &input.rule_id, &input.association_id)?;
        let mut state = self.lock();
        let assocs = &mut state.account_mut(&ctx.caller.account_id, &ctx.region).rule_associations;
        if assocs.get(&input.association_id).is_none_or(|a| a.rule_id != input.rule_id) {
            return Err(assoc_not_found());
        }
        assocs.remove(&input.association_id);
        Ok(Default::default())
    }

    pub(crate) fn list_custom_detection_rule_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomDetectionRuleAssociationsRequest,
    ) -> Result<types::ListCustomDetectionRuleAssociationsResponse, ServiceError> {
        self.authorize(ctx, "ListCustomDetectionRuleAssociations", "*", ConditionContext::new())?;
        let account = ctx.caller.account_id.clone();
        let state = self.lock();
        let all: Vec<types::AssociationSummary> = state
            .account(&account, &ctx.region)
            .map(|a| {
                a.rule_associations
                    .values()
                    .filter(|a| input.rule_id.as_ref().is_none_or(|r| *r == a.rule_id))
                    .filter(|a| input.mode.as_ref().is_none_or(|m| *m == a.mode))
                    .map(|a| types::AssociationSummary {
                        association_id: a.id.clone(),
                        arn: association_arn(ctx, &account, &a.rule_id, &a.id),
                        rule_id: a.rule_id.clone(),
                        mode: a.mode.clone(),
                        created_at: a.created_at,
                        updated_at: a.updated_at,
                        expires_at: expiry(&a.mode, a.updated_at),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (rule_associations, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListCustomDetectionRuleAssociationsResponse { rule_associations, next_token })
    }

    /// Organization rule configurations are the delegated administrator's.
    fn check_rule_org_admin(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        let org = self.organizations().and_then(|o| o.organization(&ctx.caller.account_id));
        let state = self.lock();
        match org {
            Some(o) if Self::org_admin_of(&state, &o.id, &ctx.region) == Some(ctx.caller.account_id.as_str()) => Ok(()),
            _ => Err(errors_access_denied()),
        }
    }

    pub(crate) fn create_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::CreateCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        self.authorize(
            ctx,
            "CreateCustomDetectionRuleOrgConfiguration",
            &rule_arn(ctx, &input.rule_id),
            ConditionContext::new(),
        )?;
        rule(&input.rule_id)?;
        self.check_rule_org_admin(ctx)?;
        let key = format!("{}/{}", input.rule_id, input.mode);
        let mut state = self.lock();
        let acct = state.account_mut(&ctx.caller.account_id, &ctx.region);
        if acct.rule_org_configs.contains_key(&key) {
            return Err(conflict("The request is rejected because the organization configuration already exists."));
        }
        acct.rule_org_configs.insert(
            key,
            RuleOrgConfig {
                rule_id: input.rule_id,
                mode: input.mode,
                include: input.include_account_ids.unwrap_or_default(),
                exclude: input.exclude_account_ids.unwrap_or_default(),
                created_at: ctx.received_at,
                updated_at: ctx.received_at,
            },
        );
        Ok(Default::default())
    }

    pub(crate) fn get_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::GetCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        self.authorize(
            ctx,
            "GetCustomDetectionRuleOrgConfiguration",
            &rule_arn(ctx, &input.rule_id),
            ConditionContext::new(),
        )?;
        let state = self.lock();
        let c = state
            .account(&ctx.caller.account_id, &ctx.region)
            .and_then(|a| a.rule_org_configs.get(&format!("{}/{}", input.rule_id, input.mode)))
            .ok_or_else(org_config_not_found)?;
        Ok(types::GetCustomDetectionRuleOrgConfigurationResponse {
            configuration: types::DetectionRuleOrgConfiguration {
                rule_id: c.rule_id.clone(),
                mode: c.mode.clone(),
                status: "ACTIVE".into(),
                status_reason: None,
                include_account_ids: c.include.clone(),
                exclude_account_ids: c.exclude.clone(),
                created_at: c.created_at,
                updated_at: c.updated_at,
                expires_at: expiry(&c.mode, c.updated_at),
            },
        })
    }

    pub(crate) fn update_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::UpdateCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        self.authorize(
            ctx,
            "UpdateCustomDetectionRuleOrgConfiguration",
            &rule_arn(ctx, &input.rule_id),
            ConditionContext::new(),
        )?;
        let mut state = self.lock();
        let c = state
            .account_mut(&ctx.caller.account_id, &ctx.region)
            .rule_org_configs
            .get_mut(&format!("{}/{}", input.rule_id, input.mode))
            .ok_or_else(org_config_not_found)?;
        if let Some(i) = input.include_account_ids {
            c.include = i;
        }
        if let Some(e) = input.exclude_account_ids {
            c.exclude = e;
        }
        c.updated_at = ctx.received_at;
        Ok(Default::default())
    }

    pub(crate) fn delete_custom_detection_rule_org_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomDetectionRuleOrgConfigurationRequest,
    ) -> Result<types::DeleteCustomDetectionRuleOrgConfigurationResponse, ServiceError> {
        self.authorize(
            ctx,
            "DeleteCustomDetectionRuleOrgConfiguration",
            &rule_arn(ctx, &input.rule_id),
            ConditionContext::new(),
        )?;
        let mut state = self.lock();
        state
            .account_mut(&ctx.caller.account_id, &ctx.region)
            .rule_org_configs
            .remove(&format!("{}/{}", input.rule_id, input.mode))
            .ok_or_else(org_config_not_found)?;
        Ok(Default::default())
    }

    pub(crate) fn list_custom_detection_rule_org_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomDetectionRuleOrgConfigurationsRequest,
    ) -> Result<types::ListCustomDetectionRuleOrgConfigurationsResponse, ServiceError> {
        self.authorize(ctx, "ListCustomDetectionRuleOrgConfigurations", "*", ConditionContext::new())?;
        let state = self.lock();
        let all: Vec<types::DetectionRuleOrgConfigurationSummary> = state
            .account(&ctx.caller.account_id, &ctx.region)
            .map(|a| {
                a.rule_org_configs
                    .values()
                    .filter(|_| input.status.as_ref().is_none_or(|s| s == "ACTIVE"))
                    .map(|c| types::DetectionRuleOrgConfigurationSummary {
                        rule_id: c.rule_id.clone(),
                        mode: c.mode.clone(),
                        status: "ACTIVE".into(),
                        status_reason: None,
                        created_at: c.created_at,
                        updated_at: c.updated_at,
                        expires_at: expiry(&c.mode, c.updated_at),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (configurations, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListCustomDetectionRuleOrgConfigurationsResponse { configurations, next_token })
    }

    // ---- investigations ---------------------------------------------------

    fn investigation_wire(ctx: &RequestContext, account: &str, i: &Investigation) -> types::Investigation {
        types::Investigation {
            investigation_id: i.id.clone(),
            status: "COMPLETED".into(),
            trigger_prompt: i.prompt.clone(),
            triggered_by: ctx.caller.arn.clone(),
            metadata: None,
            cloud: Some(types::CloudDetails {
                provider: "AWS".into(),
                region: ctx.region.clone(),
                account: account.to_string(),
            }),
            risk_level: Some("Info".into()),
            risk: Some("No activity matching the prompt was found in this account.".into()),
            confidence: Some("Low".into()),
            summary: Some("GuardDuty found no findings or activity related to the prompt.".into()),
            start_time: Some(i.started_at),
            end_time: Some(i.started_at),
            error: None,
        }
    }

    pub(crate) fn create_investigation(
        &self,
        ctx: &RequestContext,
        input: types::CreateInvestigationRequest,
    ) -> Result<types::CreateInvestigationResponse, ServiceError> {
        self.authorize_detector(ctx, "CreateInvestigation", &input.detector_id)?;
        let mut state = self.lock();
        let det = Self::owned_mut(&mut state, ctx, &input.detector_id)?;
        let id = hex_id(32);
        det.investigations.insert(
            id.clone(),
            Investigation { id: id.clone(), prompt: input.trigger_prompt, started_at: ctx.received_at },
        );
        Ok(types::CreateInvestigationResponse { investigation_id: id })
    }

    pub(crate) fn get_investigation(
        &self,
        ctx: &RequestContext,
        input: types::GetInvestigationRequest,
    ) -> Result<types::GetInvestigationResponse, ServiceError> {
        self.authorize_detector(ctx, "GetInvestigation", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let i = det
            .investigations
            .get(&input.investigation_id)
            .ok_or_else(|| not_found("The request is rejected because the investigation was not found."))?;
        Ok(types::GetInvestigationResponse { investigation: Self::investigation_wire(ctx, &ctx.caller.account_id, i) })
    }

    pub(crate) fn list_investigations(
        &self,
        ctx: &RequestContext,
        input: types::ListInvestigationsRequest,
    ) -> Result<types::ListInvestigationsResponse, ServiceError> {
        self.authorize_detector(ctx, "ListInvestigations", &input.detector_id)?;
        let state = self.lock();
        let det = Self::owned(&state, ctx, &input.detector_id)?;
        let mut items: Vec<&Investigation> = det.investigations.values().collect();
        items.sort_by_key(|i| i.started_at);
        if input.sort_criteria.as_ref().and_then(|s| s.order_by.as_deref()) != Some("ASC") {
            items.reverse();
        }
        let all = items
            .into_iter()
            .map(|i| types::InvestigationSummary {
                investigation_id: Some(i.id.clone()),
                status: Some("COMPLETED".into()),
                trigger_prompt: Some(i.prompt.clone()),
                risk_level: Some("Info".into()),
                confidence: Some("Low".into()),
                title: Some(i.prompt.chars().take(80).collect()),
                account_id: Some(ctx.caller.account_id.clone()),
                start_time: Some(i.started_at),
                end_time: Some(i.started_at),
            })
            .collect();
        let (investigations, next_token) = paginate(all, input.max_results, 50, input.next_token.as_deref())?;
        Ok(types::ListInvestigationsResponse { investigations, next_token })
    }
}

fn errors_access_denied() -> ServiceError {
    crate::generated::errors::access_denied(
        "The request is rejected because the current account is not the delegated GuardDuty administrator account of an organization.",
    )
}
