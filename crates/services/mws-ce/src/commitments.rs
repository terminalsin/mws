//! Reserved Instances and Savings Plans: coverage of the on-demand usage
//! in the ledger, utilization (MWS sells no commitments, so there is
//! none), purchase recommendations, recommendation generation and
//! commitment purchase analyses.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::costs::{auth, page, NO_DATA};
use crate::generated::types as t;
use crate::query::{amount, check_expression, check_group_by, from_ms, ms, time_str, validation, Period, View};
use crate::state::{Analysis, CostRecord, Generation};
use crate::CostExplorer;

/// How long a recommendation generation or analysis takes.
const GENERATION_MS: i64 = 1000;
/// Compute Savings Plans rates relative to on-demand, for analyses.
const SAVINGS_PLAN_RATE: f64 = 0.72;

/// On-demand usage a reservation could cover: instance and node hours.
pub(crate) fn reservable(r: &CostRecord) -> bool {
    r.dimension("USAGE_TYPE").is_some_and(|u| ["BoxUsage", "InstanceUsage", "NodeUsage"].iter().any(|k| u.contains(k)))
}

/// Spend a Compute Savings Plan could cover: EC2 instances, Fargate and
/// Lambda compute.
fn savings_plan_eligible(r: &CostRecord) -> bool {
    let usage = r.dimension("USAGE_TYPE").unwrap_or_default();
    let service = r.dimension("SERVICE").unwrap_or_default();
    (usage.contains("BoxUsage") && service.contains("Elastic Compute Cloud"))
        || usage.contains("Fargate")
        || (service == "AWS Lambda" && (usage.contains("Lambda-GB-Second") || usage.contains("Request")))
}

fn on_demand(r: &CostRecord) -> bool {
    r.dimension("RECORD_TYPE").is_none_or(|t| t == "Usage")
        && r.dimension("PURCHASE_TYPE").is_none_or(|p| p == "On Demand Instances")
}

fn pct(part: f64, total: f64) -> String {
    if total > 0.0 {
        amount(part / total * 100.0)
    } else {
        "0".into()
    }
}

fn data_unavailable() -> ServiceError {
    ServiceError::client("DataUnavailableException", 400, NO_DATA)
}

fn generation_exists() -> ServiceError {
    ServiceError::client(
        "GenerationExistsException",
        400,
        "A request to generate a recommendation or analysis is already in progress.",
    )
}

/// The records of `view` in `period` that pass `filter` and `keep`, with
/// the share of each inside the period.
fn select<'a>(
    view: &'a View<'_>,
    filter: Option<&t::Expression>,
    period: &Period,
    keep: fn(&CostRecord) -> bool,
) -> Vec<(&'a CostRecord, f64)> {
    view.select(filter, ms(period.start), ms(period.end))
        .into_iter()
        .filter(|r| keep(r) && on_demand(r))
        .map(|r| (r, period.share(r)))
        .filter(|(_, s)| *s > 0.0)
        .collect()
}

fn hours_coverage(records: &[(&CostRecord, f64)]) -> t::Coverage {
    let hours: f64 = records.iter().map(|(r, s)| r.usage_quantity * s).sum();
    let units: f64 = records.iter().map(|(r, s)| r.normalized_usage_amount * s).sum();
    let cost: f64 = records.iter().map(|(r, s)| r.unblended_cost * s).sum();
    t::Coverage {
        coverage_hours: Some(t::CoverageHours {
            on_demand_hours: Some(amount(hours)),
            reserved_hours: Some("0".into()),
            total_running_hours: Some(amount(hours)),
            coverage_hours_percentage: Some("0".into()),
        }),
        coverage_normalized_units: Some(t::CoverageNormalizedUnits {
            on_demand_normalized_units: Some(amount(units)),
            reserved_normalized_units: Some("0".into()),
            total_running_normalized_units: Some(amount(units)),
            coverage_normalized_units_percentage: Some("0".into()),
        }),
        coverage_cost: Some(t::CoverageCost { on_demand_cost: Some(amount(cost)) }),
    }
}

fn group_attributes(view: &View<'_>, r: &CostRecord, groups: &[t::GroupDefinition]) -> BTreeMap<String, String> {
    groups
        .iter()
        .map(|g| {
            let key = g.key.clone().unwrap_or_default();
            let attr = match key.as_str() {
                "LINKED_ACCOUNT" => "linkedAccount".to_string(),
                "INSTANCE_TYPE" => "instanceType".to_string(),
                "REGION" => "region".to_string(),
                "SERVICE" => "service".to_string(),
                "INSTANCE_TYPE_FAMILY" => "instanceTypeFamily".to_string(),
                other => other.to_ascii_lowercase(),
            };
            (attr, view.group_key(r, g))
        })
        .collect()
}

fn zero_utilization() -> t::ReservationAggregates {
    let z = || Some("0".to_string());
    t::ReservationAggregates {
        utilization_percentage: z(),
        utilization_percentage_in_units: z(),
        purchased_hours: z(),
        purchased_units: z(),
        total_actual_hours: z(),
        total_actual_units: z(),
        unused_hours: z(),
        unused_units: z(),
        on_demand_cost_of_ri_hours_used: z(),
        net_ri_savings: z(),
        total_potential_ri_savings: z(),
        amortized_upfront_fee: z(),
        amortized_recurring_fee: z(),
        total_amortized_fee: z(),
        ri_cost_for_unused_hours: z(),
        realized_savings: z(),
        unrealized_savings: z(),
    }
}

fn granularity(given: Option<&str>) -> Result<&str, ServiceError> {
    match given.unwrap_or("MONTHLY") {
        g @ ("DAILY" | "MONTHLY") => Ok(g),
        _ => Err(validation("Granularity must be DAILY or MONTHLY for this operation.")),
    }
}

impl CostExplorer {
    pub(crate) fn get_reservation_coverage_op(
        &self,
        ctx: &RequestContext,
        input: t::GetReservationCoverageRequest,
    ) -> Result<t::GetReservationCoverageResponse, ServiceError> {
        auth(ctx, "GetReservationCoverage")?;
        let g = granularity(input.granularity.as_deref())?;
        let period = Period::parse(&input.time_period, g)?;
        if let Some(f) = &input.filter {
            check_expression(f)?;
        }
        let groups = input.group_by.clone().unwrap_or_default();
        check_group_by(&groups, false)?;
        let (coverages, total) = self.with_view(ctx, |view| {
            let all = select(view, input.filter.as_ref(), &period, reservable);
            let coverages: Vec<t::CoverageByTime> = period
                .split(g)
                .into_iter()
                .map(|p| {
                    let records = select(view, input.filter.as_ref(), &p, reservable);
                    let mut by_group: BTreeMap<BTreeMap<String, String>, Vec<(&CostRecord, f64)>> = BTreeMap::new();
                    if !groups.is_empty() {
                        for (r, s) in &records {
                            by_group.entry(group_attributes(view, r, &groups)).or_default().push((r, *s));
                        }
                    }
                    t::CoverageByTime {
                        time_period: Some(p.interval()),
                        groups: Some(
                            by_group
                                .into_iter()
                                .map(|(attributes, rs)| t::ReservationCoverageGroup {
                                    attributes: Some(attributes),
                                    coverage: Some(hours_coverage(&rs)),
                                })
                                .collect(),
                        ),
                        total: Some(hours_coverage(&records)),
                    }
                })
                .collect();
            (coverages, hours_coverage(&all))
        });
        let (coverages_by_time, next_page_token) =
            page(coverages, input.next_page_token.as_deref(), input.max_results, 1000)?;
        Ok(t::GetReservationCoverageResponse { coverages_by_time, total: Some(total), next_page_token })
    }

    pub(crate) fn get_reservation_utilization_op(
        &self,
        ctx: &RequestContext,
        input: t::GetReservationUtilizationRequest,
    ) -> Result<t::GetReservationUtilizationResponse, ServiceError> {
        auth(ctx, "GetReservationUtilization")?;
        let g = granularity(input.granularity.as_deref())?;
        Period::parse(&input.time_period, g)?;
        if let Some(f) = &input.filter {
            check_expression(f)?;
        }
        page(Vec::<()>::new(), input.next_page_token.as_deref(), input.max_results, 1000)?;
        Ok(t::GetReservationUtilizationResponse {
            utilizations_by_time: Vec::new(),
            total: Some(zero_utilization()),
            next_page_token: None,
        })
    }

    pub(crate) fn get_savings_plans_coverage_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSavingsPlansCoverageRequest,
    ) -> Result<t::GetSavingsPlansCoverageResponse, ServiceError> {
        auth(ctx, "GetSavingsPlansCoverage")?;
        let g = granularity(input.granularity.as_deref())?;
        let period = Period::parse(&input.time_period, g)?;
        if let Some(f) = &input.filter {
            check_expression(f)?;
        }
        let groups = input.group_by.clone().unwrap_or_default();
        check_group_by(&groups, false)?;
        let coverages = self.with_view(ctx, |view| {
            let mut out = Vec::new();
            for p in period.split(g) {
                let records = select(view, input.filter.as_ref(), &p, savings_plan_eligible);
                let mut by_group: BTreeMap<BTreeMap<String, String>, f64> = BTreeMap::new();
                for (r, s) in &records {
                    *by_group.entry(group_attributes(view, r, &groups)).or_default() += r.unblended_cost * s;
                }
                if by_group.is_empty() {
                    by_group.insert(BTreeMap::new(), 0.0);
                }
                for (attributes, cost) in by_group {
                    out.push(t::SavingsPlansCoverage {
                        attributes: Some(attributes),
                        coverage: Some(t::SavingsPlansCoverageData {
                            spend_covered_by_savings_plans: Some("0".into()),
                            on_demand_cost: Some(amount(cost)),
                            total_cost: Some(amount(cost)),
                            coverage_percentage: Some("0".into()),
                        }),
                        time_period: Some(p.interval()),
                    });
                }
            }
            out
        });
        let (savings_plans_coverages, next_token) =
            page(coverages, input.next_token.as_deref(), input.max_results, 1000)?;
        Ok(t::GetSavingsPlansCoverageResponse { savings_plans_coverages, next_token })
    }

    pub(crate) fn get_savings_plans_utilization_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSavingsPlansUtilizationRequest,
    ) -> Result<t::GetSavingsPlansUtilizationResponse, ServiceError> {
        auth(ctx, "GetSavingsPlansUtilization")?;
        Period::parse(&input.time_period, input.granularity.as_deref().unwrap_or("DAILY"))?;
        // AWS answers this way for accounts without Savings Plans.
        Err(data_unavailable())
    }

    pub(crate) fn get_savings_plans_utilization_details_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSavingsPlansUtilizationDetailsRequest,
    ) -> Result<t::GetSavingsPlansUtilizationDetailsResponse, ServiceError> {
        auth(ctx, "GetSavingsPlansUtilizationDetails")?;
        Period::parse(&input.time_period, "DAILY")?;
        Err(data_unavailable())
    }

    fn recommendation_id(&self, ctx: &RequestContext) -> (String, String) {
        (uuid::Uuid::new_v4().to_string(), time_str(ctx.received_at))
    }

    pub(crate) fn get_reservation_purchase_recommendation_op(
        &self,
        ctx: &RequestContext,
        input: t::GetReservationPurchaseRecommendationRequest,
    ) -> Result<t::GetReservationPurchaseRecommendationResponse, ServiceError> {
        auth(ctx, "GetReservationPurchaseRecommendation")?;
        const SERVICES: [&str; 7] = [
            "Amazon Elastic Compute Cloud - Compute",
            "Amazon Relational Database Service",
            "Amazon Redshift",
            "Amazon ElastiCache",
            "Amazon Elasticsearch Service",
            "Amazon OpenSearch Service",
            "Amazon MemoryDB Service",
        ];
        if !SERVICES.contains(&input.service.as_str()) {
            return Err(validation(format!("Service {} is not supported", input.service)));
        }
        page(Vec::<()>::new(), input.next_page_token.as_deref(), None, 1)?;
        let (recommendation_id, generation_timestamp) = self.recommendation_id(ctx);
        Ok(t::GetReservationPurchaseRecommendationResponse {
            metadata: Some(t::ReservationPurchaseRecommendationMetadata {
                recommendation_id: Some(recommendation_id),
                generation_timestamp: Some(generation_timestamp),
                additional_metadata: None,
            }),
            recommendations: Some(Vec::new()),
            next_page_token: None,
        })
    }

    pub(crate) fn get_rightsizing_recommendation_op(
        &self,
        ctx: &RequestContext,
        input: t::GetRightsizingRecommendationRequest,
    ) -> Result<t::GetRightsizingRecommendationResponse, ServiceError> {
        auth(ctx, "GetRightsizingRecommendation")?;
        if input.service != "AmazonEC2" {
            return Err(validation("Rightsizing recommendations are only available for AmazonEC2."));
        }
        page(Vec::<()>::new(), input.next_page_token.as_deref(), None, 1)?;
        let (recommendation_id, generation_timestamp) = self.recommendation_id(ctx);
        Ok(t::GetRightsizingRecommendationResponse {
            metadata: Some(t::RightsizingRecommendationMetadata {
                recommendation_id: Some(recommendation_id),
                generation_timestamp: Some(generation_timestamp),
                lookback_period_in_days: Some("FOURTEEN_DAYS".into()),
                additional_metadata: None,
            }),
            summary: Some(t::RightsizingRecommendationSummary {
                total_recommendation_count: Some("0".into()),
                estimated_total_monthly_savings_amount: Some("0".into()),
                savings_currency_code: Some("USD".into()),
                savings_percentage: Some("0".into()),
            }),
            rightsizing_recommendations: Some(Vec::new()),
            next_page_token: None,
            configuration: Some(input.configuration.unwrap_or(t::RightsizingRecommendationConfiguration {
                recommendation_target: "SAME_INSTANCE_FAMILY".into(),
                benefits_considered: true,
            })),
        })
    }

    pub(crate) fn get_savings_plans_purchase_recommendation_op(
        &self,
        ctx: &RequestContext,
        input: t::GetSavingsPlansPurchaseRecommendationRequest,
    ) -> Result<t::GetSavingsPlansPurchaseRecommendationResponse, ServiceError> {
        auth(ctx, "GetSavingsPlansPurchaseRecommendation")?;
        if let Some(f) = &input.filter {
            check_expression(f)?;
        }
        page(Vec::<()>::new(), input.next_page_token.as_deref(), None, 1)?;
        let (recommendation_id, generation_timestamp) = self.recommendation_id(ctx);
        Ok(t::GetSavingsPlansPurchaseRecommendationResponse {
            metadata: Some(t::SavingsPlansPurchaseRecommendationMetadata {
                recommendation_id: Some(recommendation_id),
                generation_timestamp: Some(generation_timestamp),
                additional_metadata: None,
            }),
            savings_plans_purchase_recommendation: Some(t::SavingsPlansPurchaseRecommendation {
                account_scope: Some(input.account_scope.unwrap_or_else(|| "PAYER".into())),
                savings_plans_type: Some(input.savings_plans_type),
                term_in_years: Some(input.term_in_years),
                payment_option: Some(input.payment_option),
                lookback_period_in_days: Some(input.lookback_period_in_days),
                savings_plans_purchase_recommendation_details: Some(Vec::new()),
                savings_plans_purchase_recommendation_summary: None,
            }),
            next_page_token: None,
        })
    }

    pub(crate) fn get_savings_plan_purchase_recommendation_details_op(
        &self,
        ctx: &RequestContext,
        _input: t::GetSavingsPlanPurchaseRecommendationDetailsRequest,
    ) -> Result<t::GetSavingsPlanPurchaseRecommendationDetailsResponse, ServiceError> {
        auth(ctx, "GetSavingsPlanPurchaseRecommendationDetails")?;
        // Recommendations never carry details, so no id names one.
        Err(data_unavailable())
    }

    pub(crate) fn start_savings_plans_purchase_recommendation_generation_op(
        &self,
        ctx: &RequestContext,
        _input: t::StartSavingsPlansPurchaseRecommendationGenerationRequest,
    ) -> Result<t::StartSavingsPlansPurchaseRecommendationGenerationResponse, ServiceError> {
        auth(ctx, "StartSavingsPlansPurchaseRecommendationGeneration")?;
        let now = ms(ctx.received_at);
        let g = Generation { id: uuid::Uuid::new_v4().to_string(), started: now, completes: now + GENERATION_MS };
        self.with_account(ctx, |acct| {
            if acct.generations.iter().any(|x| x.completes > now) {
                return Err(generation_exists());
            }
            acct.generations.push(g.clone());
            Ok(())
        })?;
        Ok(t::StartSavingsPlansPurchaseRecommendationGenerationResponse {
            recommendation_id: Some(g.id),
            generation_started_time: Some(time_str(from_ms(g.started))),
            estimated_completion_time: Some(time_str(from_ms(g.completes))),
        })
    }

    pub(crate) fn list_savings_plans_purchase_recommendation_generation_op(
        &self,
        ctx: &RequestContext,
        input: t::ListSavingsPlansPurchaseRecommendationGenerationRequest,
    ) -> Result<t::ListSavingsPlansPurchaseRecommendationGenerationResponse, ServiceError> {
        auth(ctx, "ListSavingsPlansPurchaseRecommendationGeneration")?;
        let now = ms(ctx.received_at);
        let mut list: Vec<t::GenerationSummary> = self.with_account(ctx, |acct| {
            acct.generations
                .iter()
                .map(|g| {
                    let done = g.completes <= now;
                    t::GenerationSummary {
                        recommendation_id: Some(g.id.clone()),
                        generation_status: Some(if done { "SUCCEEDED" } else { "PROCESSING" }.into()),
                        generation_started_time: Some(time_str(from_ms(g.started))),
                        generation_completion_time: done.then(|| time_str(from_ms(g.completes))),
                        estimated_completion_time: Some(time_str(from_ms(g.completes))),
                    }
                })
                .collect()
        });
        list.retain(|g| {
            input.generation_status.as_ref().is_none_or(|s| g.generation_status.as_ref() == Some(s))
                && input
                    .recommendation_ids
                    .as_ref()
                    .is_none_or(|ids| g.recommendation_id.as_ref().is_some_and(|id| ids.contains(id)))
        });
        list.reverse();
        let size = (input.page_size > 0).then_some(input.page_size);
        let (generation_summary_list, next_page_token) = page(list, input.next_page_token.as_deref(), size, 100)?;
        Ok(t::ListSavingsPlansPurchaseRecommendationGenerationResponse {
            generation_summary_list: Some(generation_summary_list),
            next_page_token,
        })
    }

    pub(crate) fn start_commitment_purchase_analysis_op(
        &self,
        ctx: &RequestContext,
        input: t::StartCommitmentPurchaseAnalysisRequest,
    ) -> Result<t::StartCommitmentPurchaseAnalysisResponse, ServiceError> {
        auth(ctx, "StartCommitmentPurchaseAnalysis")?;
        let config = input.commitment_purchase_analysis_configuration;
        let sp = config
            .savings_plans_purchase_analysis_configuration
            .as_ref()
            .ok_or_else(|| validation("SavingsPlansPurchaseAnalysisConfiguration is required."))?;
        let lookback = Period::parse(&sp.look_back_time_period, "HOURLY")?;
        let now = ms(ctx.received_at);
        let hours = ((ms(lookback.end) - ms(lookback.start)) as f64 / 3_600_000.0).max(1.0);
        let commitment: f64 = sp.savings_plans_to_add.iter().filter_map(|p| p.savings_plans_commitment).sum();
        let details = self.with_view(ctx, |view| {
            let records = select(view, None, &lookback, savings_plan_eligible);
            let mut hourly: BTreeMap<i64, f64> = BTreeMap::new();
            let (from, to) = (ms(lookback.start).div_euclid(3_600_000), ms(lookback.end).div_euclid(3_600_000));
            for (r, _) in &records {
                // Spread each record evenly over its hours in the period.
                let (first, last) = (r.start.div_euclid(3_600_000), (r.end - 1).max(r.start).div_euclid(3_600_000));
                let per_hour = r.unblended_cost / (last - first + 1) as f64;
                for h in first.max(from)..=last.min(to - 1) {
                    *hourly.entry(h).or_default() += per_hour;
                }
            }
            let spend: f64 = hourly.values().sum();
            let avg = spend / hours;
            let max = hourly.values().copied().fold(0.0, f64::max);
            let min = if (hourly.len() as f64) < hours {
                0.0
            } else {
                hourly.values().copied().fold(f64::INFINITY, f64::min)
            };
            // Each hour, the commitment covers up to commitment/rate of on-demand spend.
            let capacity = commitment / SAVINGS_PLAN_RATE;
            let covered: f64 = hourly.values().map(|v| v.min(capacity)).sum();
            let remaining = spend - covered;
            let commitment_cost = commitment * hours;
            let estimated_cost = commitment_cost + remaining;
            let savings = spend - estimated_cost;
            let used = covered * SAVINGS_PLAN_RATE;
            t::SavingsPlansPurchaseAnalysisDetails {
                currency_code: Some("USD".into()),
                lookback_period_in_hours: Some(amount(hours)),
                current_average_coverage: Some("0".into()),
                current_average_hourly_on_demand_spend: Some(amount(avg)),
                current_maximum_hourly_on_demand_spend: Some(amount(max)),
                current_minimum_hourly_on_demand_spend: Some(amount(if min.is_finite() { min } else { 0.0 })),
                current_on_demand_spend: Some(amount(spend)),
                existing_hourly_commitment: Some("0".into()),
                hourly_commitment_to_purchase: Some(amount(commitment)),
                estimated_average_coverage: Some(pct(covered, spend)),
                estimated_average_utilization: Some(pct(used, commitment_cost)),
                estimated_monthly_savings_amount: Some(amount(savings / hours * 730.0)),
                estimated_on_demand_cost: Some(amount(remaining)),
                estimated_on_demand_cost_with_current_commitment: Some(amount(spend)),
                estimated_roi: Some(pct(savings, commitment_cost)),
                estimated_savings_amount: Some(amount(savings)),
                estimated_savings_percentage: Some(pct(savings, spend)),
                estimated_commitment_cost: Some(amount(commitment_cost)),
                latest_usage_timestamp: hourly.keys().last().map(|h| time_str(from_ms(h * 3_600_000))),
                upfront_cost: Some("0".into()),
                additional_metadata: None,
                metrics_over_lookback_period: None,
            }
        });
        let analysis = Analysis {
            id: uuid::Uuid::new_v4().to_string(),
            started: now,
            completes: now + GENERATION_MS,
            config: serde_json::to_value(&config).expect("configuration serializes"),
            details: serde_json::to_value(t::AnalysisDetails {
                savings_plans_purchase_analysis_details: Some(details),
            })
            .expect("details serialize"),
        };
        self.with_account(ctx, |acct| {
            if acct.analyses.values().any(|a| a.completes > now) {
                return Err(generation_exists());
            }
            acct.analyses.insert(analysis.id.clone(), analysis.clone());
            Ok(())
        })?;
        Ok(t::StartCommitmentPurchaseAnalysisResponse {
            analysis_id: analysis.id,
            analysis_started_time: time_str(from_ms(analysis.started)),
            estimated_completion_time: time_str(from_ms(analysis.completes)),
        })
    }

    pub(crate) fn get_commitment_purchase_analysis_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCommitmentPurchaseAnalysisRequest,
    ) -> Result<t::GetCommitmentPurchaseAnalysisResponse, ServiceError> {
        auth(ctx, "GetCommitmentPurchaseAnalysis")?;
        let now = ms(ctx.received_at);
        let a = self.with_account(ctx, |acct| acct.analyses.get(&input.analysis_id).cloned()).ok_or_else(|| {
            ServiceError::client("AnalysisNotFoundException", 400, "The requested analysis can't be found.")
        })?;
        let done = a.completes <= now;
        Ok(t::GetCommitmentPurchaseAnalysisResponse {
            estimated_completion_time: time_str(from_ms(a.completes)),
            analysis_completion_time: done.then(|| time_str(from_ms(a.completes))),
            analysis_started_time: time_str(from_ms(a.started)),
            analysis_id: a.id,
            analysis_status: if done { "SUCCEEDED" } else { "PROCESSING" }.into(),
            error_code: None,
            analysis_details: if done { serde_json::from_value(a.details).ok() } else { None },
            commitment_purchase_analysis_configuration: serde_json::from_value(a.config).unwrap_or_default(),
        })
    }

    pub(crate) fn list_commitment_purchase_analyses_op(
        &self,
        ctx: &RequestContext,
        input: t::ListCommitmentPurchaseAnalysesRequest,
    ) -> Result<t::ListCommitmentPurchaseAnalysesResponse, ServiceError> {
        auth(ctx, "ListCommitmentPurchaseAnalyses")?;
        let now = ms(ctx.received_at);
        let mut list: Vec<(i64, t::AnalysisSummary)> = self.with_account(ctx, |acct| {
            acct.analyses
                .values()
                .map(|a| {
                    let done = a.completes <= now;
                    (
                        a.started,
                        t::AnalysisSummary {
                            estimated_completion_time: Some(time_str(from_ms(a.completes))),
                            analysis_completion_time: done.then(|| time_str(from_ms(a.completes))),
                            analysis_started_time: Some(time_str(from_ms(a.started))),
                            analysis_status: Some(if done { "SUCCEEDED" } else { "PROCESSING" }.into()),
                            error_code: None,
                            analysis_id: Some(a.id.clone()),
                            commitment_purchase_analysis_configuration: serde_json::from_value(a.config.clone()).ok(),
                        },
                    )
                })
                .collect()
        });
        list.retain(|(_, a)| {
            input.analysis_status.as_ref().is_none_or(|s| a.analysis_status.as_ref() == Some(s))
                && input
                    .analysis_ids
                    .as_ref()
                    .is_none_or(|ids| a.analysis_id.as_ref().is_some_and(|id| ids.contains(id)))
        });
        list.sort_by_key(|a| std::cmp::Reverse(a.0));
        let size = (input.page_size > 0).then_some(input.page_size);
        let (list, next_page_token) =
            page(list.into_iter().map(|(_, a)| a).collect(), input.next_page_token.as_deref(), size, 20)?;
        Ok(t::ListCommitmentPurchaseAnalysesResponse { analysis_summary_list: Some(list), next_page_token })
    }
}
