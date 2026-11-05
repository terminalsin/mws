//! Cost categories, cost allocation tags (with backfills) and resource tags.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::costs::{auth, page};
use crate::generated::types as t;
use crate::query::{check_expression, from_ms, month_start, ms, parse_time, time_str, validation};
use crate::state::{Account, Backfill, CostCategory, TagStatus};
use crate::CostExplorer;

const MAX_COST_CATEGORIES: usize = 50;
const MAX_RESOURCE_TAGS: usize = 200;
pub(crate) const BACKFILL_MS: i64 = 1_000;

fn not_found(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ResourceNotFoundException", 404, message)
}

pub(crate) fn arn(ctx: &RequestContext, kind: &str) -> String {
    format!("arn:{}:ce::{}:{kind}/{}", ctx.partition, ctx.caller.account_id, uuid::Uuid::new_v4())
}

pub(crate) fn tag_map(tags: Option<&[t::ResourceTag]>) -> Result<BTreeMap<String, String>, ServiceError> {
    let mut out = BTreeMap::new();
    for tag in tags.unwrap_or_default() {
        if tag.key.starts_with("aws:") {
            return Err(validation("Tag keys can't start with the reserved prefix aws:."));
        }
        out.insert(tag.key.clone(), tag.value.clone());
    }
    if out.len() > MAX_RESOURCE_TAGS {
        return Err(ServiceError::client("TooManyTagsException", 400, "Your resource has too many tags."));
    }
    Ok(out)
}

/// A cost category's effective start: the first of a month at most a year
/// back, by default this month.
fn effective_start(given: Option<&str>, now: DateTime<Utc>) -> Result<String, ServiceError> {
    let start = match given {
        None => month_start(now),
        Some(s) => {
            let t = parse_time(s)?;
            if t != month_start(t) {
                return Err(validation("EffectiveStart must be the first day of a month, at 00:00:00 UTC."));
            }
            if t < month_start(now - Duration::days(365)) || t > month_start(now) {
                return Err(validation("EffectiveStart can be set up to 12 months before the current month and no later than the current month."));
            }
            t
        }
    };
    Ok(time_str(start))
}

fn check_rules(rules: &[t::CostCategoryRule]) -> Result<(), ServiceError> {
    if rules.is_empty() {
        return Err(validation("Rules must contain at least one rule."));
    }
    for r in rules {
        match (&r.inherited_value, &r.rule, &r.value) {
            (Some(i), _, _) => {
                if i.dimension_name.as_deref() == Some("TAG") && i.dimension_key.is_none() {
                    return Err(validation("InheritedValue with DimensionName TAG needs a DimensionKey."));
                }
            }
            (None, Some(e), Some(_)) => check_expression(e)?,
            _ => return Err(validation("Each rule needs a Value and a Rule, or an InheritedValue.")),
        }
    }
    Ok(())
}

fn reference(c: &CostCategory) -> t::CostCategoryReference {
    let rules: Vec<t::CostCategoryRule> = serde_json::from_value(c.rules.clone()).unwrap_or_default();
    let values: BTreeSet<String> = rules.iter().filter_map(|r| r.value.clone()).collect();
    t::CostCategoryReference {
        cost_category_arn: Some(c.arn.clone()),
        name: Some(c.name.clone()),
        effective_start: Some(c.effective_start.clone()),
        effective_end: c.effective_end.clone(),
        number_of_rules: rules.len() as i32,
        processing_status: Some(vec![processing()]),
        values: Some(values.into_iter().collect()),
        default_value: c.default_value.clone(),
        supported_resource_types: None,
    }
}

fn processing() -> t::CostCategoryProcessingStatus {
    t::CostCategoryProcessingStatus { component: Some("COST_EXPLORER".into()), status: Some("APPLIED".into()) }
}

impl CostExplorer {
    pub(crate) fn with_account<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut Account) -> R) -> R {
        let mut st = self.lock();
        f(st.accounts.entry(ctx.caller.account_id.clone()).or_default())
    }

    pub(crate) fn create_cost_category_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateCostCategoryDefinitionRequest,
    ) -> Result<t::CreateCostCategoryDefinitionResponse, ServiceError> {
        auth(ctx, "CreateCostCategoryDefinition")?;
        check_rules(&input.rules)?;
        let start = effective_start(input.effective_start.as_deref(), ctx.received_at)?;
        let tags = tag_map(input.resource_tags.as_deref())?;
        let arn = arn(ctx, "costcategory");
        self.with_account(ctx, |acct| {
            if acct.cost_categories.values().any(|c| c.name == input.name) {
                return Err(validation(format!(
                    "Failed to create Cost Category: A Cost Category with the name {} already exists.",
                    input.name
                )));
            }
            if acct.cost_categories.len() >= MAX_COST_CATEGORIES {
                return Err(ServiceError::client(
                    "ServiceQuotaExceededException",
                    402,
                    "You've reached the limit on the number of cost categories you can create.",
                ));
            }
            acct.cost_categories.insert(
                arn.clone(),
                CostCategory {
                    arn: arn.clone(),
                    name: input.name.clone(),
                    effective_start: start.clone(),
                    effective_end: None,
                    rule_version: input.rule_version.clone(),
                    rules: serde_json::to_value(&input.rules).expect("rules serialize"),
                    split_charge_rules: serde_json::to_value(&input.split_charge_rules).expect("rules serialize"),
                    default_value: input.default_value.clone(),
                    tags,
                },
            );
            Ok(())
        })?;
        Ok(t::CreateCostCategoryDefinitionResponse { cost_category_arn: Some(arn), effective_start: Some(start) })
    }

    pub(crate) fn update_cost_category_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateCostCategoryDefinitionRequest,
    ) -> Result<t::UpdateCostCategoryDefinitionResponse, ServiceError> {
        auth(ctx, "UpdateCostCategoryDefinition")?;
        check_rules(&input.rules)?;
        let start = effective_start(input.effective_start.as_deref(), ctx.received_at)?;
        self.with_account(ctx, |acct| {
            let c = acct
                .cost_categories
                .get_mut(&input.cost_category_arn)
                .ok_or_else(|| missing_category(&input.cost_category_arn))?;
            c.effective_start = start.clone();
            c.rule_version = input.rule_version.clone();
            c.rules = serde_json::to_value(&input.rules).expect("rules serialize");
            c.split_charge_rules = serde_json::to_value(&input.split_charge_rules).expect("rules serialize");
            c.default_value = input.default_value.clone();
            Ok::<_, ServiceError>(())
        })?;
        Ok(t::UpdateCostCategoryDefinitionResponse {
            cost_category_arn: Some(input.cost_category_arn),
            effective_start: Some(start),
        })
    }

    pub(crate) fn describe_cost_category_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeCostCategoryDefinitionRequest,
    ) -> Result<t::DescribeCostCategoryDefinitionResponse, ServiceError> {
        auth(ctx, "DescribeCostCategoryDefinition")?;
        let c = self
            .with_account(ctx, |acct| acct.cost_categories.get(&input.cost_category_arn).cloned())
            .ok_or_else(|| missing_category(&input.cost_category_arn))?;
        Ok(t::DescribeCostCategoryDefinitionResponse {
            cost_category: Some(t::CostCategory {
                cost_category_arn: c.arn.clone(),
                effective_start: c.effective_start.clone(),
                effective_end: c.effective_end.clone(),
                name: c.name.clone(),
                rule_version: c.rule_version.clone(),
                rules: serde_json::from_value(c.rules.clone()).unwrap_or_default(),
                split_charge_rules: serde_json::from_value(c.split_charge_rules.clone()).unwrap_or_default(),
                processing_status: Some(vec![processing()]),
                default_value: c.default_value.clone(),
            }),
        })
    }

    pub(crate) fn delete_cost_category_definition_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteCostCategoryDefinitionRequest,
    ) -> Result<t::DeleteCostCategoryDefinitionResponse, ServiceError> {
        auth(ctx, "DeleteCostCategoryDefinition")?;
        self.with_account(ctx, |acct| acct.cost_categories.remove(&input.cost_category_arn))
            .ok_or_else(|| missing_category(&input.cost_category_arn))?;
        Ok(t::DeleteCostCategoryDefinitionResponse {
            cost_category_arn: Some(input.cost_category_arn),
            effective_end: Some(time_str(month_start(ctx.received_at))),
        })
    }

    pub(crate) fn list_cost_category_definitions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListCostCategoryDefinitionsRequest,
    ) -> Result<t::ListCostCategoryDefinitionsResponse, ServiceError> {
        auth(ctx, "ListCostCategoryDefinitions")?;
        let on = input.effective_on.as_deref().map(parse_time).transpose()?;
        let refs: Vec<_> = self.with_account(ctx, |acct| {
            acct.cost_categories
                .values()
                .filter(|c| on.is_none_or(|on| parse_time(&c.effective_start).is_ok_and(|s| s <= on)))
                .map(reference)
                .collect()
        });
        let (refs, next_token) = page(refs, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListCostCategoryDefinitionsResponse { cost_category_references: Some(refs), next_token })
    }

    pub(crate) fn list_cost_category_resource_associations_op(
        &self,
        ctx: &RequestContext,
        input: t::ListCostCategoryResourceAssociationsRequest,
    ) -> Result<t::ListCostCategoryResourceAssociationsResponse, ServiceError> {
        auth(ctx, "ListCostCategoryResourceAssociations")?;
        if let Some(arn) = &input.cost_category_arn {
            self.with_account(ctx, |acct| acct.cost_categories.contains_key(arn))
                .then_some(())
                .ok_or_else(|| missing_category(arn))?;
        }
        // No billing resources (RI/Savings Plans sharing groups) exist in MWS.
        Ok(t::ListCostCategoryResourceAssociationsResponse {
            cost_category_resource_associations: Some(Vec::new()),
            next_token: None,
        })
    }

    // ---- cost allocation tags -------------------------------------------------

    /// Tag keys in the caller's data, with when each was last used.
    fn tag_keys(&self, ctx: &RequestContext) -> BTreeMap<String, i64> {
        let st = self.lock();
        let mut keys = BTreeMap::new();
        for r in Self::visible(&st, &ctx.caller.account_id) {
            for k in r.tags.keys() {
                let e = keys.entry(k.clone()).or_insert(r.start);
                *e = (*e).max(r.start);
            }
        }
        keys
    }

    pub(crate) fn list_cost_allocation_tags_op(
        &self,
        ctx: &RequestContext,
        input: t::ListCostAllocationTagsRequest,
    ) -> Result<t::ListCostAllocationTagsResponse, ServiceError> {
        auth(ctx, "ListCostAllocationTags")?;
        let keys = self.tag_keys(ctx);
        let statuses = self.with_account(ctx, |acct| acct.tag_status.clone());
        let tags: Vec<t::CostAllocationTag> = keys
            .into_iter()
            .map(|(key, last_used)| {
                let status = statuses.get(&key);
                t::CostAllocationTag {
                    r#type: if key.starts_with("aws:") { "AWSGenerated" } else { "UserDefined" }.into(),
                    status: status.map_or("Inactive".into(), |s| s.status.clone()),
                    last_updated_date: status.map(|s| time_str(from_ms(s.updated))),
                    last_used_date: Some(time_str(from_ms(last_used))),
                    tag_key: key,
                }
            })
            .filter(|tag| {
                input.status.as_deref().is_none_or(|s| s == tag.status)
                    && input.r#type.as_deref().is_none_or(|ty| ty == tag.r#type)
                    && input.tag_keys.as_ref().is_none_or(|ks| ks.contains(&tag.tag_key))
            })
            .collect();
        let (tags, next_token) = page(tags, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListCostAllocationTagsResponse { cost_allocation_tags: Some(tags), next_token })
    }

    pub(crate) fn update_cost_allocation_tags_status_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateCostAllocationTagsStatusRequest,
    ) -> Result<t::UpdateCostAllocationTagsStatusResponse, ServiceError> {
        auth(ctx, "UpdateCostAllocationTagsStatus")?;
        let keys = self.tag_keys(ctx);
        let now = ms(ctx.received_at);
        let errors = self.with_account(ctx, |acct| {
            let mut errors = Vec::new();
            for entry in &input.cost_allocation_tags_status {
                if !keys.contains_key(&entry.tag_key) {
                    errors.push(t::UpdateCostAllocationTagsStatusError {
                        tag_key: Some(entry.tag_key.clone()),
                        code: Some("TagKeysNotFoundException".into()),
                        message: Some("Failed to update. Tag keys not found.".into()),
                    });
                    continue;
                }
                let s = acct
                    .tag_status
                    .entry(entry.tag_key.clone())
                    .or_insert_with(|| TagStatus { status: "Inactive".into(), ..Default::default() });
                if entry.status == "Active" && s.status != "Active" {
                    s.activated = Some(now);
                }
                s.status = entry.status.clone();
                s.updated = now;
            }
            errors
        });
        Ok(t::UpdateCostAllocationTagsStatusResponse { errors: Some(errors) })
    }

    pub(crate) fn start_cost_allocation_tag_backfill_op(
        &self,
        ctx: &RequestContext,
        input: t::StartCostAllocationTagBackfillRequest,
    ) -> Result<t::StartCostAllocationTagBackfillResponse, ServiceError> {
        auth(ctx, "StartCostAllocationTagBackfill")?;
        let from = parse_time(&input.backfill_from)?;
        let now = ctx.received_at;
        if from != month_start(from) {
            return Err(validation("BackfillFrom must be the first day of a month, at 00:00:00 UTC."));
        }
        if from < month_start(now - Duration::days(365)) || from > now {
            return Err(validation("BackfillFrom can be up to 12 months before the current month."));
        }
        let b = self.with_account(ctx, |acct| {
            if acct.backfills.iter().any(|b| b.completes > ms(now)) {
                return Err(ServiceError::client(
                    "BackfillLimitExceededException",
                    400,
                    "A backfill is already in progress. You can request another backfill after it completes.",
                ));
            }
            let b = Backfill { from: ms(from), requested: ms(now), completes: ms(now) + BACKFILL_MS };
            acct.backfills.push(b.clone());
            Ok(b)
        })?;
        Ok(t::StartCostAllocationTagBackfillResponse { backfill_request: Some(backfill_view(&b, ms(now))) })
    }

    pub(crate) fn list_cost_allocation_tag_backfill_history_op(
        &self,
        ctx: &RequestContext,
        input: t::ListCostAllocationTagBackfillHistoryRequest,
    ) -> Result<t::ListCostAllocationTagBackfillHistoryResponse, ServiceError> {
        auth(ctx, "ListCostAllocationTagBackfillHistory")?;
        let now = ms(ctx.received_at);
        let mut all = self.with_account(ctx, |acct| acct.backfills.clone());
        all.sort_by_key(|b| std::cmp::Reverse(b.requested));
        let views: Vec<_> = all.iter().map(|b| backfill_view(b, now)).collect();
        let (backfill_requests, next_token) = page(views, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListCostAllocationTagBackfillHistoryResponse { backfill_requests: Some(backfill_requests), next_token })
    }

    // ---- resource tags ----------------------------------------------------------

    fn with_resource_tags<R>(
        &self,
        ctx: &RequestContext,
        arn: &str,
        f: impl FnOnce(&mut BTreeMap<String, String>) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        self.with_account(ctx, |acct| {
            let tags = if let Some(c) = acct.cost_categories.get_mut(arn) {
                &mut c.tags
            } else if let Some(m) = acct.monitors.get_mut(arn) {
                &mut m.tags
            } else if let Some(s) = acct.subscriptions.get_mut(arn) {
                &mut s.tags
            } else {
                return Err(not_found(format!("Failed to find resource with ARN {arn}.")));
            };
            f(tags)
        })
    }

    pub(crate) fn tag_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::TagResourceRequest,
    ) -> Result<t::TagResourceResponse, ServiceError> {
        ctx.authorize("ce:TagResource", &input.resource_arn, Default::default())?;
        let new = tag_map(Some(&input.resource_tags))?;
        self.with_resource_tags(ctx, &input.resource_arn, |tags| {
            let mut merged = tags.clone();
            merged.extend(new);
            if merged.len() > MAX_RESOURCE_TAGS {
                return Err(ServiceError::client("TooManyTagsException", 400, "Your resource has too many tags."));
            }
            *tags = merged;
            Ok(())
        })?;
        Ok(t::TagResourceResponse {})
    }

    pub(crate) fn untag_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::UntagResourceRequest,
    ) -> Result<t::UntagResourceResponse, ServiceError> {
        ctx.authorize("ce:UntagResource", &input.resource_arn, Default::default())?;
        self.with_resource_tags(ctx, &input.resource_arn, |tags| {
            for k in &input.resource_tag_keys {
                tags.remove(k);
            }
            Ok(())
        })?;
        Ok(t::UntagResourceResponse {})
    }

    pub(crate) fn list_tags_for_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::ListTagsForResourceRequest,
    ) -> Result<t::ListTagsForResourceResponse, ServiceError> {
        ctx.authorize("ce:ListTagsForResource", &input.resource_arn, Default::default())?;
        let tags = self.with_resource_tags(ctx, &input.resource_arn, |tags| Ok(tags.clone()))?;
        Ok(t::ListTagsForResourceResponse {
            resource_tags: Some(tags.into_iter().map(|(key, value)| t::ResourceTag { key, value }).collect()),
        })
    }
}

fn missing_category(arn: &str) -> ServiceError {
    not_found(format!("No Cost Categories found with ID {}", arn.rsplit('/').next().unwrap_or(arn)))
}

fn backfill_view(b: &Backfill, now: i64) -> t::CostAllocationTagBackfillRequest {
    let done = b.completes <= now;
    t::CostAllocationTagBackfillRequest {
        backfill_from: Some(time_str(from_ms(b.from))),
        requested_at: Some(time_str(from_ms(b.requested))),
        completed_at: done.then(|| time_str(from_ms(b.completes))),
        backfill_status: Some(if done { "SUCCEEDED" } else { "PROCESSING" }.into()),
        last_updated_at: Some(time_str(from_ms(if done { b.completes } else { b.requested }))),
    }
}
