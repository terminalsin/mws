//! The hub itself: enabling and disabling Security Hub, its settings,
//! tags, product integrations, custom actions and the finding aggregator.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::catalog;
use crate::common::{
    self, account, authorize, authorize_hub, authorize_with, hub, hub_mut, invalid_input, iso, not_found,
    not_subscribed, paginate,
};
use crate::findings::subscription_arn;
use crate::generated::{errors, types};
use crate::state::{ActionTargetRec, AggregatorRec, Hub, StandardsSub, State};
use crate::SecurityHub;

/// A new hub, with the AWS integrations enabled and (if asked) the
/// default standards.
pub fn new_hub(partition: &str, account: &str, region: &str, now: DateTime<Utc>, default_standards: bool) -> Hub {
    let mut h = Hub {
        account: account.to_string(),
        region: region.to_string(),
        arn: format!("arn:{partition}:securityhub:{region}:{account}:hub/default"),
        subscribed_at: now,
        auto_enable_controls: true,
        control_finding_generator: "SECURITY_CONTROL".into(),
        tags: Default::default(),
        standards: Default::default(),
        control_overrides: Default::default(),
        security_controls: Default::default(),
        products: catalog::PRODUCTS
            .iter()
            .filter(|p| p.aws)
            .map(|p| catalog::product_arn(partition, region, p))
            .collect(),
        action_targets: Default::default(),
        insights: Default::default(),
        findings: Default::default(),
        automation_rules: Default::default(),
        automation_rules_v2: Default::default(),
        finding_aggregator: None,
        configuration_policies: Default::default(),
        policy_associations: Default::default(),
        connectors: Default::default(),
        resource_tags: Default::default(),
        evaluation: Default::default(),
    };
    if default_standards {
        for s in catalog::STANDARDS.iter().filter(|s| s.enabled_by_default) {
            enable_standard(&mut h, partition, s, BTreeMap::new(), now);
        }
    }
    h
}

pub fn standards_subscription_arn(partition: &str, region: &str, account: &str, key: &str) -> String {
    format!("arn:{partition}:securityhub:{region}:{account}:subscription/{key}")
}

/// Subscribe a hub to a standard (no-op if already subscribed); returns
/// the subscription ARN.
pub fn enable_standard(
    h: &mut Hub,
    partition: &str,
    s: &catalog::Standard,
    input: BTreeMap<String, String>,
    now: DateTime<Utc>,
) -> String {
    let arn = standards_subscription_arn(partition, &h.region, &h.account, s.key);
    let standards_arn = catalog::standards_arn(partition, &h.region, s);
    h.standards.entry(arn.clone()).or_insert(StandardsSub { standards_arn, input, enabled_at: now });
    arn
}

/// Enable Security Hub for an account (organization auto-enable, central
/// configuration, `CreateMembers` for organization accounts).
pub fn ensure_hub(
    state: &mut State,
    partition: &str,
    account: &str,
    region: &str,
    now: DateTime<Utc>,
    default_standards: bool,
) {
    let key = crate::state::key(account, region);
    state.hubs.entry(key).or_insert_with(|| new_hub(partition, account, region, now, default_standards));
}

impl SecurityHub {
    pub(crate) fn enable_security_hub_op(
        &self,
        ctx: &RequestContext,
        input: types::EnableSecurityHubRequest,
    ) -> Result<types::EnableSecurityHubResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        authorize_with(ctx, "EnableSecurityHub", &common::hub_arn(ctx, account(ctx)), common::tag_conditions(&tags))?;
        common::check_tags(&Default::default(), &tags)?;
        if self.read().hub(account(ctx), &ctx.region).is_some() {
            return Err(errors::resource_conflict("Account is already subscribed to Security Hub"));
        }
        // As in AWS: enabling creates AWSServiceRoleForSecurityHub, which
        // the caller must be allowed to do when the role does not exist yet.
        self.ensure_service_linked_role(ctx)?;
        let mut state = self.write();
        if state.hub(account(ctx), &ctx.region).is_some() {
            return Err(errors::resource_conflict("Account is already subscribed to Security Hub"));
        }
        let mut h = new_hub(
            &ctx.partition,
            account(ctx),
            &ctx.region,
            ctx.received_at,
            input.enable_default_standards.unwrap_or(true),
        );
        if let Some(g) = input.control_finding_generator {
            h.control_finding_generator = g;
        }
        h.tags = tags;
        state.hubs.insert(crate::state::key(account(ctx), &ctx.region), h);
        Ok(types::EnableSecurityHubResponse {})
    }

    /// Create Security Hub's service-linked role in the caller's account
    /// if it is missing, checking `iam:CreateServiceLinkedRole` as AWS does.
    pub(crate) fn ensure_service_linked_role(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        let Some(roles) = self.inner.roles.get() else { return Ok(()) };
        let acct = account(ctx);
        if roles.exists(&ctx.partition, acct) {
            return Ok(());
        }
        let role_arn = format!(
            "arn:{}:iam::{acct}:role/aws-service-role/{}/{}",
            ctx.partition,
            crate::evaluation::SERVICE_PRINCIPAL,
            crate::evaluation::SERVICE_LINKED_ROLE
        );
        let mut cond = mws_core::ConditionContext::new();
        cond.insert("iam:AWSServiceName".into(), vec![crate::evaluation::SERVICE_PRINCIPAL.into()]);
        ctx.authorize("iam:CreateServiceLinkedRole", &role_arn, cond)?;
        roles.create(acct);
        Ok(())
    }

    pub(crate) fn disable_security_hub_op(
        &self,
        ctx: &RequestContext,
        _input: types::DisableSecurityHubRequest,
    ) -> Result<types::DisableSecurityHubResponse, ServiceError> {
        authorize_hub(ctx, "DisableSecurityHub")?;
        let mut state = self.write();
        hub(&state, ctx)?;
        let key = crate::state::key(account(ctx), &ctx.region);
        if state.org_admins.iter().any(|(k, a)| a == account(ctx) && k.ends_with(&format!("/{}", ctx.region))) {
            return Err(invalid_input(
                "You can't disable Security Hub in the delegated administrator account. Remove the account as the delegated administrator first.",
            ));
        }
        if state.members.get(&key).is_some_and(|m| m.values().any(|m| m.status == "Enabled")) {
            return Err(invalid_input(
                "You can't disable Security Hub in an administrator account that has member accounts. Disassociate the member accounts first.",
            ));
        }
        if state.administrator_of(account(ctx), &ctx.region).is_some() {
            return Err(invalid_input(
                "You can't disable Security Hub in a member account. Disassociate the account from its administrator first.",
            ));
        }
        state.hubs.remove(&key);
        state.members.remove(&key);
        Ok(types::DisableSecurityHubResponse {})
    }

    pub(crate) fn describe_hub_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeHubRequest,
    ) -> Result<types::DescribeHubResponse, ServiceError> {
        let arn = input.hub_arn.clone().unwrap_or_else(|| common::hub_arn(ctx, account(ctx)));
        authorize(ctx, "DescribeHub", &arn)?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        if arn != h.arn {
            return Err(not_found(format!("Hub {arn} not found")));
        }
        Ok(types::DescribeHubResponse {
            hub_arn: Some(h.arn.clone()),
            subscribed_at: Some(iso(h.subscribed_at)),
            auto_enable_controls: Some(h.auto_enable_controls),
            control_finding_generator: Some(h.control_finding_generator.clone()),
        })
    }

    pub(crate) fn update_security_hub_configuration_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateSecurityHubConfigurationRequest,
    ) -> Result<types::UpdateSecurityHubConfigurationResponse, ServiceError> {
        authorize_hub(ctx, "UpdateSecurityHubConfiguration")?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        if let Some(v) = input.auto_enable_controls {
            h.auto_enable_controls = v;
        }
        if let Some(v) = input.control_finding_generator {
            h.control_finding_generator = v;
        }
        h.evaluation.dirty = true;
        Ok(types::UpdateSecurityHubConfigurationResponse {})
    }

    // ---- tags ------------------------------------------------------------------

    fn tags_slot<'s>(
        state: &'s mut State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<&'s mut crate::state::Tags, ServiceError> {
        let acct = account(ctx).to_string();
        if common::arn_account(arn) != Some(acct.as_str()) || common::arn_region(arn) != Some(ctx.region.as_str()) {
            return Err(not_found(format!("Resource {arn} not found")));
        }
        let key = crate::state::key(&acct, &ctx.region);
        let mut v2_aggregator = false;
        if let Some(v2) = state.hubs_v2.get_mut(&key) {
            if v2.arn == arn {
                return Ok(&mut v2.tags);
            }
            v2_aggregator = v2.aggregators.contains_key(arn);
        }
        let h = state.hubs.get_mut(&key).ok_or_else(|| not_subscribed(&acct))?;
        if h.arn == arn {
            return Ok(&mut h.tags);
        }
        let exists = h.automation_rules.contains_key(arn)
            || h.automation_rules_v2.values().any(|r| r.arn == arn)
            || h.configuration_policies.values().any(|p| p.arn == arn)
            || h.connectors.values().any(|c| c.arn == arn)
            || v2_aggregator
            || h.finding_aggregator.as_ref().is_some_and(|a| a.arn == arn);
        if !exists {
            return Err(not_found(format!("Resource {arn} not found")));
        }
        Ok(h.resource_tags.entry(arn.to_string()).or_default())
    }

    pub(crate) fn tag_resource_op(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        authorize_with(ctx, "TagResource", &input.resource_arn, common::tag_conditions(&input.tags))?;
        let mut state = self.write();
        let tags = Self::tags_slot(&mut state, ctx, &input.resource_arn)?;
        common::check_tags(tags, &input.tags)?;
        tags.extend(input.tags);
        Ok(types::TagResourceResponse {})
    }

    pub(crate) fn untag_resource_op(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut cond = mws_core::ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        authorize_with(ctx, "UntagResource", &input.resource_arn, cond)?;
        let mut state = self.write();
        let tags = Self::tags_slot(&mut state, ctx, &input.resource_arn)?;
        for k in &input.tag_keys {
            tags.remove(k);
        }
        Ok(types::UntagResourceResponse {})
    }

    pub(crate) fn list_tags_for_resource_op(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        authorize(ctx, "ListTagsForResource", &input.resource_arn)?;
        let mut state = self.write();
        let tags = Self::tags_slot(&mut state, ctx, &input.resource_arn)?.clone();
        Ok(types::ListTagsForResourceResponse { tags: Some(tags) })
    }

    // ---- products ----------------------------------------------------------------

    pub(crate) fn describe_products_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeProductsRequest,
    ) -> Result<types::DescribeProductsResponse, ServiceError> {
        authorize_hub(ctx, "DescribeProducts")?;
        let state = self.read();
        hub(&state, ctx)?;
        drop(state);
        let mut products: Vec<types::Product> = catalog::PRODUCTS
            .iter()
            .map(|p| types::Product {
                product_arn: catalog::product_arn(&ctx.partition, &ctx.region, p),
                product_name: Some(p.name.into()),
                company_name: Some(p.company.into()),
                description: Some(p.description.into()),
                categories: Some(p.categories.iter().map(|c| c.to_string()).collect()),
                integration_types: Some(p.integration_types.iter().map(|c| c.to_string()).collect()),
                marketplace_url: (!p.aws).then(|| {
                    format!(
                        "https://aws.amazon.com/marketplace/search/results?searchTerms={}",
                        p.name.replace(' ', "+")
                    )
                }),
                activation_url: None,
                product_subscription_resource_policy: None,
            })
            .collect();
        if let Some(arn) = &input.product_arn {
            products.retain(|p| p.product_arn == *arn);
        }
        let (page, next_token) = paginate(products, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::DescribeProductsResponse { products: page, next_token })
    }

    pub(crate) fn enable_import_findings_for_product_op(
        &self,
        ctx: &RequestContext,
        input: types::EnableImportFindingsForProductRequest,
    ) -> Result<types::EnableImportFindingsForProductResponse, ServiceError> {
        authorize(ctx, "EnableImportFindingsForProduct", &input.product_arn)?;
        let key = match crate::findings::product_of(&input.product_arn, &ctx.region) {
            Some(crate::findings::ProductRef::Catalog(p)) => p.key,
            _ => return Err(invalid_input(format!("Invalid ProductArn {}", input.product_arn))),
        };
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        if !h.products.insert(input.product_arn.clone()) {
            return Err(errors::resource_conflict("Product is already subscribed"));
        }
        Ok(types::EnableImportFindingsForProductResponse {
            product_subscription_arn: Some(subscription_arn(&ctx.partition, &ctx.region, account(ctx), key)),
        })
    }

    pub(crate) fn disable_import_findings_for_product_op(
        &self,
        ctx: &RequestContext,
        input: types::DisableImportFindingsForProductRequest,
    ) -> Result<types::DisableImportFindingsForProductResponse, ServiceError> {
        authorize(ctx, "DisableImportFindingsForProduct", &input.product_subscription_arn)?;
        let mut state = self.write();
        let acct = account(ctx).to_string();
        let h = hub_mut(&mut state, ctx)?;
        let product = h
            .products
            .iter()
            .find(|p| {
                let key = p.split("product/").nth(1).unwrap_or_default();
                subscription_arn(&ctx.partition, &ctx.region, &acct, key) == input.product_subscription_arn
            })
            .cloned()
            .ok_or_else(|| not_found(format!("Product subscription {} not found", input.product_subscription_arn)))?;
        h.products.remove(&product);
        Ok(types::DisableImportFindingsForProductResponse {})
    }

    pub(crate) fn list_enabled_products_for_import_op(
        &self,
        ctx: &RequestContext,
        input: types::ListEnabledProductsForImportRequest,
    ) -> Result<types::ListEnabledProductsForImportResponse, ServiceError> {
        authorize_hub(ctx, "ListEnabledProductsForImport")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let subs: Vec<String> = h
            .products
            .iter()
            .filter_map(|p| p.split("product/").nth(1))
            .map(|key| subscription_arn(&ctx.partition, &ctx.region, account(ctx), key))
            .collect();
        drop(state);
        let (page, next_token) = paginate(subs, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListEnabledProductsForImportResponse { product_subscriptions: Some(page), next_token })
    }

    // ---- custom actions ------------------------------------------------------------

    pub(crate) fn create_action_target_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateActionTargetRequest,
    ) -> Result<types::CreateActionTargetResponse, ServiceError> {
        authorize_hub(ctx, "CreateActionTarget")?;
        if input.id.is_empty() || input.id.len() > 20 || !input.id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(invalid_input("Id must be 1-20 alphanumeric characters."));
        }
        if input.name.len() > 20 {
            return Err(invalid_input("Name must be no longer than 20 characters."));
        }
        if input.description.len() > 256 {
            return Err(invalid_input("Description must be no longer than 256 characters."));
        }
        let arn = common::arn(ctx, &format!("action/custom/{}", input.id));
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        if h.action_targets.contains_key(&arn) {
            return Err(errors::resource_conflict(format!("Action target {arn} already exists")));
        }
        if h.action_targets.len() >= 50 {
            return Err(errors::limit_exceeded("You can't create more than 50 custom actions."));
        }
        h.action_targets.insert(arn.clone(), ActionTargetRec { name: input.name, description: input.description });
        Ok(types::CreateActionTargetResponse { action_target_arn: arn })
    }

    pub(crate) fn describe_action_targets_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeActionTargetsRequest,
    ) -> Result<types::DescribeActionTargetsResponse, ServiceError> {
        authorize_hub(ctx, "DescribeActionTargets")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let wire = |arn: &String, t: &ActionTargetRec| types::ActionTarget {
            action_target_arn: arn.clone(),
            name: t.name.clone(),
            description: t.description.clone(),
        };
        let targets: Vec<types::ActionTarget> = match &input.action_target_arns {
            Some(arns) if !arns.is_empty() => {
                let mut out = Vec::new();
                for a in arns {
                    let t = h.action_targets.get(a).ok_or_else(|| not_found(format!("Action target {a} not found")))?;
                    out.push(wire(a, t));
                }
                out
            }
            _ => h.action_targets.iter().map(|(a, t)| wire(a, t)).collect(),
        };
        drop(state);
        let (page, next_token) = paginate(targets, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::DescribeActionTargetsResponse { action_targets: page, next_token })
    }

    pub(crate) fn update_action_target_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateActionTargetRequest,
    ) -> Result<types::UpdateActionTargetResponse, ServiceError> {
        authorize(ctx, "UpdateActionTarget", &input.action_target_arn)?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let t = h
            .action_targets
            .get_mut(&input.action_target_arn)
            .ok_or_else(|| not_found(format!("Action target {} not found", input.action_target_arn)))?;
        if let Some(n) = input.name {
            t.name = n;
        }
        if let Some(d) = input.description {
            t.description = d;
        }
        Ok(types::UpdateActionTargetResponse {})
    }

    pub(crate) fn delete_action_target_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteActionTargetRequest,
    ) -> Result<types::DeleteActionTargetResponse, ServiceError> {
        authorize(ctx, "DeleteActionTarget", &input.action_target_arn)?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        h.action_targets
            .remove(&input.action_target_arn)
            .ok_or_else(|| not_found(format!("Action target {} not found", input.action_target_arn)))?;
        Ok(types::DeleteActionTargetResponse { action_target_arn: input.action_target_arn })
    }

    // ---- finding aggregator ------------------------------------------------------------

    pub(crate) fn create_finding_aggregator_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateFindingAggregatorRequest,
    ) -> Result<types::CreateFindingAggregatorResponse, ServiceError> {
        authorize_hub(ctx, "CreateFindingAggregator")?;
        let regions = check_linking(&input.region_linking_mode, input.regions.as_deref(), &ctx.region)?;
        let mut state = self.write();
        hub(&state, ctx)?;
        let acct = account(ctx).to_string();
        if state.hubs.iter().any(|(k, h)| k.starts_with(&format!("{acct}/")) && h.finding_aggregator.is_some()) {
            return Err(errors::resource_conflict("A finding aggregator already exists for this account."));
        }
        let arn = common::arn(ctx, &format!("finding-aggregator/{}", uuid::Uuid::new_v4()));
        let agg = AggregatorRec {
            arn: arn.clone(),
            region_linking_mode: input.region_linking_mode.clone(),
            regions: regions.clone(),
        };
        hub_mut(&mut state, ctx)?.finding_aggregator = Some(agg);
        Ok(types::CreateFindingAggregatorResponse {
            finding_aggregator_arn: Some(arn),
            finding_aggregation_region: Some(ctx.region.clone()),
            region_linking_mode: Some(input.region_linking_mode),
            regions: Some(regions),
        })
    }

    /// The aggregator with `arn` in any of the caller's Regions, as
    /// `(hub key, record)`.
    fn find_aggregator(
        state: &State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<(String, AggregatorRec), ServiceError> {
        let acct = account(ctx);
        state
            .hubs
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{acct}/")))
            .find_map(|(k, h)| h.finding_aggregator.as_ref().filter(|a| a.arn == arn).map(|a| (k.clone(), a.clone())))
            .ok_or_else(|| not_found(format!("Finding aggregator {arn} not found")))
    }

    pub(crate) fn get_finding_aggregator_op(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingAggregatorRequest,
    ) -> Result<types::GetFindingAggregatorResponse, ServiceError> {
        authorize(ctx, "GetFindingAggregator", &input.finding_aggregator_arn)?;
        let state = self.read();
        hub(&state, ctx)?;
        let (k, a) = Self::find_aggregator(&state, ctx, &input.finding_aggregator_arn)?;
        Ok(types::GetFindingAggregatorResponse {
            finding_aggregator_arn: Some(a.arn),
            finding_aggregation_region: k.split_once('/').map(|(_, r)| r.to_string()),
            region_linking_mode: Some(a.region_linking_mode),
            regions: Some(a.regions),
        })
    }

    pub(crate) fn update_finding_aggregator_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFindingAggregatorRequest,
    ) -> Result<types::UpdateFindingAggregatorResponse, ServiceError> {
        authorize(ctx, "UpdateFindingAggregator", &input.finding_aggregator_arn)?;
        let mut state = self.write();
        hub(&state, ctx)?;
        let (k, _) = Self::find_aggregator(&state, ctx, &input.finding_aggregator_arn)?;
        let home = k.split_once('/').map(|(_, r)| r.to_string()).unwrap_or_default();
        if home != ctx.region {
            return Err(invalid_input("UpdateFindingAggregator must be called from the aggregation Region."));
        }
        let regions = check_linking(&input.region_linking_mode, input.regions.as_deref(), &home)?;
        let h = state.hubs.get_mut(&k).expect("found");
        let a = h.finding_aggregator.as_mut().expect("found");
        a.region_linking_mode = input.region_linking_mode.clone();
        a.regions = regions.clone();
        Ok(types::UpdateFindingAggregatorResponse {
            finding_aggregator_arn: Some(input.finding_aggregator_arn),
            finding_aggregation_region: Some(home),
            region_linking_mode: Some(input.region_linking_mode),
            regions: Some(regions),
        })
    }

    pub(crate) fn delete_finding_aggregator_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFindingAggregatorRequest,
    ) -> Result<types::DeleteFindingAggregatorResponse, ServiceError> {
        authorize(ctx, "DeleteFindingAggregator", &input.finding_aggregator_arn)?;
        let mut state = self.write();
        hub(&state, ctx)?;
        let (k, _) = Self::find_aggregator(&state, ctx, &input.finding_aggregator_arn)?;
        let h = state.hubs.get_mut(&k).expect("found");
        h.finding_aggregator = None;
        h.resource_tags.remove(&input.finding_aggregator_arn);
        Ok(types::DeleteFindingAggregatorResponse {})
    }

    pub(crate) fn list_finding_aggregators_op(
        &self,
        ctx: &RequestContext,
        input: types::ListFindingAggregatorsRequest,
    ) -> Result<types::ListFindingAggregatorsResponse, ServiceError> {
        authorize_hub(ctx, "ListFindingAggregators")?;
        let state = self.read();
        hub(&state, ctx)?;
        let acct = account(ctx);
        let all: Vec<types::FindingAggregator> = state
            .hubs
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{acct}/")))
            .filter_map(|(_, h)| h.finding_aggregator.as_ref())
            .map(|a| types::FindingAggregator { finding_aggregator_arn: Some(a.arn.clone()) })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListFindingAggregatorsResponse { finding_aggregators: Some(page), next_token })
    }
}

/// Validate a Region linking mode and its Regions.
pub fn check_linking(mode: &str, regions: Option<&[String]>, home: &str) -> Result<Vec<String>, ServiceError> {
    let regions = regions.unwrap_or_default().to_vec();
    match mode {
        "ALL_REGIONS" | "NO_REGIONS" => {
            if !regions.is_empty() {
                return Err(invalid_input(format!("Regions can't be specified when RegionLinkingMode is {mode}.")));
            }
        }
        "ALL_REGIONS_EXCEPT_SPECIFIED" | "SPECIFIED_REGIONS" => {
            if regions.is_empty() {
                return Err(invalid_input(format!("Regions must be specified when RegionLinkingMode is {mode}.")));
            }
            if regions.iter().any(|r| r == home) {
                return Err(invalid_input("Regions can't include the aggregation Region."));
            }
        }
        other => return Err(invalid_input(format!("Invalid RegionLinkingMode {other}."))),
    }
    Ok(regions)
}
