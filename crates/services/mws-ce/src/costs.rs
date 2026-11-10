//! Cost and usage queries: GetCostAndUsage (and with resources), values of
//! dimensions, tags and cost categories, forecasts, month-over-month
//! comparisons and approximate record counts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::generated::types as t;
use crate::query::{
    self, amount, check_expression, check_group_by, check_metrics, metric_value, month_start, ms, next_month,
    usage_unit, validation, Period, View, COST_METRICS,
};
use crate::state::{Account, CostRecord};
use crate::CostExplorer;

pub(crate) fn auth(ctx: &RequestContext, action: &str) -> Result<(), ServiceError> {
    ctx.authorize(&format!("ce:{action}"), "*", Default::default())
}

fn data_unavailable(message: &str) -> ServiceError {
    ServiceError::client("DataUnavailableException", 400, message)
}

pub(crate) const NO_DATA: &str =
    "Data is not available. Please try to adjust the time period. If you just enabled Cost Explorer, data might not be ingested yet";

fn unit_of(metric: &str, records: &[(&CostRecord, f64)]) -> String {
    if COST_METRICS.contains(&metric) {
        "USD".into()
    } else {
        usage_unit(records.iter().map(|(r, _)| *r))
    }
}

fn sum(metric: &str, records: &[(&CostRecord, f64)]) -> f64 {
    records.iter().map(|(r, share)| r.metric(metric) * share).sum()
}

pub(crate) fn metrics_map(metrics: &[String], records: &[(&CostRecord, f64)]) -> BTreeMap<String, t::MetricValue> {
    metrics.iter().map(|m| (m.clone(), metric_value(sum(m, records), &unit_of(m, records)))).collect()
}

/// Redistribute the costs of split charge rules' source values among their
/// targets, in groups keyed by cost category `c` at position `at`. Usage
/// metrics stay where they are.
fn apply_split_charges(
    c: &crate::state::CostCategory,
    at: usize,
    sums: &mut BTreeMap<Vec<String>, BTreeMap<String, (f64, String)>>,
) {
    let rules: Vec<t::CostCategorySplitChargeRule> =
        serde_json::from_value(c.split_charge_rules.clone()).unwrap_or_default();
    let key = |v: &str| format!("{}${v}", c.name);
    for rule in rules {
        let source = key(&rule.source);
        let targets: Vec<String> = rule.targets.iter().map(|t| key(t)).collect();
        let sources: Vec<Vec<String>> = sums.keys().filter(|k| k.get(at) == Some(&source)).cloned().collect();
        for src in sources {
            let Some(moved) = sums.remove(&src) else { continue };
            let mut kept = BTreeMap::new();
            for (metric, (value, unit)) in moved {
                if !COST_METRICS.contains(&metric.as_str()) {
                    kept.insert(metric, (value, unit));
                    continue;
                }
                let target_keys: Vec<Vec<String>> = targets
                    .iter()
                    .map(|t| {
                        let mut k = src.clone();
                        k[at] = t.clone();
                        k
                    })
                    .collect();
                let weights: Vec<f64> = match rule.method.as_str() {
                    "FIXED" => rule
                        .parameters
                        .iter()
                        .flatten()
                        .find(|p| p.r#type == "ALLOCATION_PERCENTAGES")
                        .map(|p| p.values.iter().map(|v| v.parse::<f64>().unwrap_or(0.0) / 100.0).collect())
                        .unwrap_or_default(),
                    "PROPORTIONAL" => {
                        let own: Vec<f64> = target_keys
                            .iter()
                            .map(|k| sums.get(k).and_then(|m| m.get(&metric)).map_or(0.0, |v| v.0))
                            .collect();
                        let total: f64 = own.iter().sum();
                        if total > 0.0 {
                            own.iter().map(|v| v / total).collect()
                        } else {
                            vec![1.0 / targets.len() as f64; targets.len()]
                        }
                    }
                    _ => vec![1.0 / targets.len().max(1) as f64; targets.len()],
                };
                for (k, w) in target_keys.into_iter().zip(weights) {
                    let entry = sums.entry(k).or_default().entry(metric.clone()).or_insert((0.0, unit.clone()));
                    entry.0 += value * w;
                }
            }
            if !kept.is_empty() {
                sums.insert(src, kept);
            }
        }
    }
}

/// Paginate a list with an opaque offset token.
pub(crate) fn page<T>(
    items: Vec<T>,
    token: Option<&str>,
    max: Option<i32>,
    default: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        None => 0,
        Some(tok) => tok
            .strip_prefix("CE")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n <= items.len())
            .ok_or_else(|| ServiceError::client("InvalidNextTokenException", 400, "Invalid NextToken"))?,
    };
    let size = max.map(|m| m.max(1) as usize).unwrap_or(default);
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then(|| format!("CE{end}"));
    Ok((items.into_iter().skip(start).take(size).collect(), next))
}

/// One page of GetCostAndUsage: results, account attributes, next token.
type CostPage = (Vec<t::ResultByTime>, Vec<t::DimensionValuesWithAttributes>, Option<String>);

/// The most time periods one GetCostAndUsage page holds, and the most
/// groups across them.
const PAGE_PERIODS: usize = 100;
const PAGE_GROUPS: usize = 1000;

/// One page of results by time: whole periods, until either limit is
/// reached (always at least one period).
fn page_results(
    results: Vec<t::ResultByTime>,
    token: Option<&str>,
) -> Result<(Vec<t::ResultByTime>, Option<String>), ServiceError> {
    let start = match token {
        None => 0,
        Some(tok) => tok
            .strip_prefix("CE")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n < results.len().max(1))
            .ok_or_else(|| ServiceError::client("InvalidNextTokenException", 400, "Invalid NextToken"))?,
    };
    let mut end = start;
    let mut groups = 0;
    while end < results.len() && end - start < PAGE_PERIODS {
        let n = results[end].groups.as_ref().map_or(0, Vec::len).max(1);
        if end > start && groups + n > PAGE_GROUPS {
            break;
        }
        groups += n;
        end += 1;
    }
    let next = (end < results.len()).then(|| format!("CE{end}"));
    Ok((results.into_iter().skip(start).take(end - start).collect(), next))
}

impl CostExplorer {
    /// Run `f` over what the caller may see.
    pub(crate) fn with_view<R>(&self, ctx: &RequestContext, f: impl FnOnce(&View<'_>) -> R) -> R {
        self.with_view_of(&ctx.caller.account_id, ms(ctx.received_at), f)
    }

    /// Run `f` over what `account` may see.
    pub(crate) fn with_view_of<R>(&self, account: &str, now: i64, f: impl FnOnce(&View<'_>) -> R) -> R {
        self.accrue(query::from_ms(now), false);
        let st = self.lock();
        let records = Self::visible(&st, account);
        let names = self.names(&records);
        let default = Account::default();
        let settings = st.accounts.get(account).unwrap_or(&default);
        let view = View { records: records.iter().collect(), account: settings, names: &names, now };
        f(&view)
    }

    #[allow(clippy::too_many_arguments)]
    fn results_by_time(
        view: &View<'_>,
        period: Period,
        granularity: &str,
        filter: Option<&t::Expression>,
        metrics: &[String],
        group_by: &[t::GroupDefinition],
        now: DateTime<Utc>,
    ) -> (Vec<t::ResultByTime>, BTreeSet<String>) {
        let mut accounts = BTreeSet::new();
        let current_month = month_start(now);
        let results = period
            .split(granularity)
            .into_iter()
            .map(|p| {
                let records: Vec<(&CostRecord, f64)> = view
                    .select(filter, ms(p.start), ms(p.end))
                    .into_iter()
                    .map(|r| (r, p.share(r)))
                    .filter(|(_, s)| *s > 0.0)
                    .collect();
                let estimated = p.end > current_month;
                if group_by.is_empty() {
                    return t::ResultByTime {
                        time_period: Some(p.interval()),
                        total: Some(metrics_map(metrics, &records)),
                        groups: Some(Vec::new()),
                        estimated,
                    };
                }
                let mut groups: BTreeMap<Vec<String>, Vec<(&CostRecord, f64)>> = BTreeMap::new();
                for (r, s) in records {
                    let keys: Vec<String> = group_by.iter().map(|g| view.group_key(r, g)).collect();
                    if group_by.iter().any(|g| g.key.as_deref() == Some("LINKED_ACCOUNT")) {
                        accounts.insert(r.account.clone());
                    }
                    groups.entry(keys).or_default().push((r, s));
                }
                let mut sums: BTreeMap<Vec<String>, BTreeMap<String, (f64, String)>> = groups
                    .into_iter()
                    .map(|(keys, rs)| {
                        let m = metrics.iter().map(|m| (m.clone(), (sum(m, &rs), unit_of(m, &rs)))).collect();
                        (keys, m)
                    })
                    .collect();
                for (i, g) in group_by.iter().enumerate() {
                    if g.r#type.as_deref() == Some("COST_CATEGORY") {
                        if let Some(c) = g.key.as_deref().and_then(|k| view.category(k)) {
                            apply_split_charges(c, i, &mut sums);
                        }
                    }
                }
                t::ResultByTime {
                    time_period: Some(p.interval()),
                    total: Some(BTreeMap::new()),
                    groups: Some(
                        sums.into_iter()
                            .map(|(keys, m)| t::Group {
                                keys: Some(keys),
                                metrics: Some(m.into_iter().map(|(k, (v, u))| (k, metric_value(v, &u))).collect()),
                            })
                            .collect(),
                    ),
                    estimated,
                }
            })
            .collect();
        (results, accounts)
    }

    #[allow(clippy::too_many_arguments)]
    fn cost_and_usage(
        &self,
        ctx: &RequestContext,
        interval: &t::DateInterval,
        granularity: &str,
        filter: Option<&t::Expression>,
        metrics: &[String],
        group_by: &[t::GroupDefinition],
        allow_resource: bool,
        token: Option<&str>,
    ) -> Result<CostPage, ServiceError> {
        let period = Period::parse(interval, granularity)?;
        period.check_window(ctx.received_at)?;
        check_metrics(metrics)?;
        check_group_by(group_by, allow_resource)?;
        if let Some(f) = filter {
            check_expression(f)?;
        }
        let (results, attrs) = self.with_view(ctx, |view| {
            let (results, accounts) =
                Self::results_by_time(view, period, granularity, filter, metrics, group_by, ctx.received_at);
            let attrs = accounts
                .into_iter()
                .map(|a| t::DimensionValuesWithAttributes {
                    attributes: Some(BTreeMap::from([(
                        "description".to_string(),
                        view.names.get(&a).cloned().unwrap_or_else(|| a.clone()),
                    )])),
                    value: Some(a),
                })
                .collect();
            (results, attrs)
        });
        let (results, next) = page_results(results, token)?;
        Ok((results, attrs, next))
    }

    pub(crate) fn get_cost_and_usage_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCostAndUsageRequest,
    ) -> Result<t::GetCostAndUsageResponse, ServiceError> {
        auth(ctx, "GetCostAndUsage")?;
        let group_by = input.group_by.clone().unwrap_or_default();
        let (results, attrs, next) = self.cost_and_usage(
            ctx,
            &input.time_period,
            &input.granularity,
            input.filter.as_ref(),
            &input.metrics,
            &group_by,
            false,
            input.next_page_token.as_deref(),
        )?;
        Ok(t::GetCostAndUsageResponse {
            next_page_token: next,
            group_definitions: input.group_by,
            results_by_time: Some(results),
            dimension_value_attributes: Some(attrs),
        })
    }

    pub(crate) fn get_cost_and_usage_with_resources_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCostAndUsageWithResourcesRequest,
    ) -> Result<t::GetCostAndUsageWithResourcesResponse, ServiceError> {
        auth(ctx, "GetCostAndUsageWithResources")?;
        let earliest = ctx.received_at - Duration::days(14);
        let start = query::parse_time(&input.time_period.start)?;
        if start < earliest.date_naive().and_hms_opt(0, 0, 0).expect("midnight").and_utc() {
            return Err(validation("Resource level data is only available for the last 14 days."));
        }
        let metrics = input.metrics.clone().unwrap_or_default();
        let group_by = input.group_by.clone().unwrap_or_default();
        let (results, attrs, next) = self.cost_and_usage(
            ctx,
            &input.time_period,
            &input.granularity,
            Some(&input.filter),
            &metrics,
            &group_by,
            true,
            input.next_page_token.as_deref(),
        )?;
        Ok(t::GetCostAndUsageWithResourcesResponse {
            next_page_token: next,
            group_definitions: input.group_by,
            results_by_time: Some(results),
            dimension_value_attributes: Some(attrs),
        })
    }

    pub(crate) fn get_dimension_values_op(
        &self,
        ctx: &RequestContext,
        input: t::GetDimensionValuesRequest,
    ) -> Result<t::GetDimensionValuesResponse, ServiceError> {
        auth(ctx, "GetDimensionValues")?;
        let period = Period::parse(&input.time_period, "DAILY")?;
        if let Some(f) = &input.filter {
            check_expression(f)?;
        }
        let context = input.context.as_deref().unwrap_or("COST_AND_USAGE");
        let search = input.search_string.as_deref().map(str::to_lowercase);
        let values = self.with_view(ctx, |view| {
            if context == "SAVINGS_PLANS" {
                return Vec::new();
            }
            let mut values: BTreeMap<String, Option<BTreeMap<String, String>>> = BTreeMap::new();
            for r in view.select(input.filter.as_ref(), ms(period.start), ms(period.end)) {
                if context == "RESERVATIONS" && !crate::commitments::reservable(r) {
                    continue;
                }
                let Some(v) = view.dimension(r, &input.dimension) else { continue };
                if search.as_ref().is_some_and(|s| !v.to_lowercase().contains(s)) {
                    continue;
                }
                let attrs = (input.dimension == "LINKED_ACCOUNT").then(|| {
                    BTreeMap::from([(
                        "description".to_string(),
                        view.names.get(&v).cloned().unwrap_or_else(|| v.clone()),
                    )])
                });
                values.insert(v, attrs);
            }
            values
                .into_iter()
                .map(|(value, attributes)| t::DimensionValuesWithAttributes {
                    value: Some(value),
                    attributes: Some(attributes.unwrap_or_default()),
                })
                .collect::<Vec<_>>()
        });
        let total = values.len() as i32;
        let (dimension_values, next_page_token) =
            page(values, input.next_page_token.as_deref(), input.max_results, 1000)?;
        Ok(t::GetDimensionValuesResponse {
            return_size: dimension_values.len() as i32,
            dimension_values,
            total_size: total,
            next_page_token,
        })
    }

    pub(crate) fn get_tags_op(
        &self,
        ctx: &RequestContext,
        input: t::GetTagsRequest,
    ) -> Result<t::GetTagsResponse, ServiceError> {
        auth(ctx, "GetTags")?;
        let period = Period::parse(&input.time_period, "DAILY")?;
        if let Some(f) = &input.filter {
            check_expression(f)?;
        }
        let search = input.search_string.as_deref().map(str::to_lowercase);
        let tags: Vec<String> = self.with_view(ctx, |view| {
            let mut out = BTreeSet::new();
            for r in view.select(input.filter.as_ref(), ms(period.start), ms(period.end)) {
                match &input.tag_key {
                    Some(k) => {
                        if let Some(v) = view.tag(r, k) {
                            out.insert(v);
                        }
                    }
                    None => out.extend(r.tags.keys().filter(|k| view.tag_visible(r, k)).cloned()),
                }
            }
            out.into_iter().filter(|v| search.as_ref().is_none_or(|s| v.to_lowercase().contains(s))).collect()
        });
        let total = tags.len() as i32;
        let (tags, next_page_token) = page(tags, input.next_page_token.as_deref(), input.max_results, 1000)?;
        Ok(t::GetTagsResponse { next_page_token, return_size: tags.len() as i32, tags, total_size: total })
    }

    pub(crate) fn get_cost_categories_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCostCategoriesRequest,
    ) -> Result<t::GetCostCategoriesResponse, ServiceError> {
        auth(ctx, "GetCostCategories")?;
        let period = Period::parse(&input.time_period, "DAILY")?;
        if let Some(f) = &input.filter {
            check_expression(f)?;
        }
        let search = input.search_string.as_deref().map(str::to_lowercase);
        let (names, values) = self.with_view(ctx, |view| {
            let records = view.select(input.filter.as_ref(), ms(period.start), ms(period.end));
            match &input.cost_category_name {
                None => {
                    let names: BTreeSet<String> = view
                        .account
                        .cost_categories
                        .values()
                        .filter(|c| records.iter().any(|r| view.category_value(r, &c.name, 0).is_some()))
                        .map(|c| c.name.clone())
                        .collect();
                    (Some(names.into_iter().collect::<Vec<_>>()), None)
                }
                Some(name) => {
                    let values: BTreeSet<String> =
                        records.iter().filter_map(|r| view.category_value(r, name, 0)).collect();
                    (None, Some(values.into_iter().collect::<Vec<_>>()))
                }
            }
        });
        let filter = |v: Vec<String>| -> Vec<String> {
            v.into_iter().filter(|x| search.as_ref().is_none_or(|s| x.to_lowercase().contains(s))).collect()
        };
        let names = names.map(filter);
        let values = values.map(filter);
        let total = names.as_ref().or(values.as_ref()).map_or(0, Vec::len) as i32;
        let (names, values, next) = match (names, values) {
            (Some(n), _) => {
                let (p, next) = page(n, input.next_page_token.as_deref(), input.max_results, 1000)?;
                (Some(p), None, next)
            }
            (None, Some(v)) => {
                let (p, next) = page(v, input.next_page_token.as_deref(), input.max_results, 1000)?;
                (None, Some(p), next)
            }
            _ => (None, None, None),
        };
        let size = names.as_ref().or(values.as_ref()).map_or(0, Vec::len) as i32;
        Ok(t::GetCostCategoriesResponse {
            next_page_token: next,
            cost_category_names: names,
            cost_category_values: values,
            return_size: size,
            total_size: total,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn forecast(
        &self,
        ctx: &RequestContext,
        interval: &t::DateInterval,
        metric: &str,
        granularity: &str,
        filter: Option<&t::Expression>,
        level: Option<i32>,
        usage: bool,
    ) -> Result<(t::MetricValue, Vec<t::ForecastResult>), ServiceError> {
        if granularity == "HOURLY" {
            return Err(validation("Forecasts support DAILY and MONTHLY granularity."));
        }
        let period = Period::parse(interval, granularity)?;
        let today = ctx.received_at.date_naive().and_hms_opt(0, 0, 0).expect("midnight").and_utc();
        if period.start < today {
            return Err(validation(
                "Start date must be equal to or greater than current date to avoid forecasting historical data",
            ));
        }
        if period.end > next_month(today + Duration::days(365)) {
            return Err(validation("End date must be within 12 months of the current date"));
        }
        if let Some(f) = filter {
            check_expression(f)?;
        }
        let metric_name = match metric {
            "AMORTIZED_COST" => "AmortizedCost",
            "BLENDED_COST" => "BlendedCost",
            "NET_AMORTIZED_COST" => "NetAmortizedCost",
            "NET_UNBLENDED_COST" => "NetUnblendedCost",
            "UNBLENDED_COST" => "UnblendedCost",
            "USAGE_QUANTITY" => "UsageQuantity",
            "NORMALIZED_USAGE_AMOUNT" => "NormalizedUsageAmount",
            other => return Err(validation(format!("Invalid metric {other}"))),
        };
        if usage != matches!(metric_name, "UsageQuantity" | "NormalizedUsageAmount") {
            return Err(validation(format!("Metric {metric} is not supported by this operation.")));
        }
        let history_start = today - Duration::days(90);
        let (daily, unit) = self.with_view(ctx, |view| {
            let records = view.select(filter, ms(history_start), ms(today));
            let mut daily: BTreeMap<i64, f64> = BTreeMap::new();
            for r in &records {
                let day = r.start.div_euclid(86_400_000);
                *daily.entry(day).or_default() += r.metric(metric_name);
            }
            let units: BTreeSet<&str> = records.iter().map(|r| r.unit.as_str()).collect();
            (daily, units.into_iter().map(str::to_string).collect::<Vec<_>>())
        });
        if usage && unit.len() > 1 {
            return Err(ServiceError::client(
                "UnresolvableUsageUnitException",
                400,
                "Usage unit can't be resolved. Filter by USAGE_TYPE or USAGE_TYPE_GROUP to forecast a single unit.",
            ));
        }
        let Some(first) = daily.keys().next().copied() else {
            return Err(data_unavailable("Insufficient amount of historical data to generate forecast."));
        };
        let last = today.timestamp_millis().div_euclid(86_400_000) - 1;
        let ys: Vec<f64> = (first..=last.max(first)).map(|d| daily.get(&d).copied().unwrap_or(0.0)).collect();
        let n = ys.len() as f64;
        let mean_x = (n - 1.0) / 2.0;
        let mean_y = ys.iter().sum::<f64>() / n;
        let (mut sxy, mut sxx) = (0.0, 0.0);
        for (i, y) in ys.iter().enumerate() {
            sxy += (i as f64 - mean_x) * (y - mean_y);
            sxx += (i as f64 - mean_x).powi(2);
        }
        let slope = if sxx > 0.0 { sxy / sxx } else { 0.0 };
        let intercept = mean_y - slope * mean_x;
        let sd = if n > 2.0 {
            (ys.iter().enumerate().map(|(i, y)| (y - (intercept + slope * i as f64)).powi(2)).sum::<f64>() / (n - 2.0))
                .sqrt()
        } else {
            mean_y.abs() * 0.1
        };
        let z = inverse_normal(0.5 + f64::from(level.unwrap_or(80)) / 200.0);
        let unit = if usage { unit.into_iter().next().unwrap_or_else(|| "N/A".into()) } else { "USD".into() };
        let mut total = 0.0;
        let results = period
            .split(granularity)
            .into_iter()
            .map(|p| {
                let mut mean = 0.0;
                let mut days: f64 = 0.0;
                let mut d = p.start;
                while d < p.end {
                    let x = (d.timestamp_millis().div_euclid(86_400_000) - first) as f64;
                    mean += (intercept + slope * x).max(0.0);
                    days += 1.0;
                    d += Duration::days(1);
                }
                total += mean;
                let spread = z * sd * days.sqrt();
                t::ForecastResult {
                    time_period: Some(p.interval()),
                    mean_value: Some(amount(mean)),
                    prediction_interval_lower_bound: Some(amount((mean - spread).max(0.0))),
                    prediction_interval_upper_bound: Some(amount(mean + spread)),
                }
            })
            .collect();
        Ok((metric_value(total, &unit), results))
    }

    pub(crate) fn get_cost_forecast_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCostForecastRequest,
    ) -> Result<t::GetCostForecastResponse, ServiceError> {
        auth(ctx, "GetCostForecast")?;
        let (total, results) = self.forecast(
            ctx,
            &input.time_period,
            &input.metric,
            &input.granularity,
            input.filter.as_ref(),
            input.prediction_interval_level,
            false,
        )?;
        Ok(t::GetCostForecastResponse { total: Some(total), forecast_results_by_time: Some(results) })
    }

    pub(crate) fn get_usage_forecast_op(
        &self,
        ctx: &RequestContext,
        input: t::GetUsageForecastRequest,
    ) -> Result<t::GetUsageForecastResponse, ServiceError> {
        auth(ctx, "GetUsageForecast")?;
        let (total, results) = self.forecast(
            ctx,
            &input.time_period,
            &input.metric,
            &input.granularity,
            input.filter.as_ref(),
            input.prediction_interval_level,
            true,
        )?;
        Ok(t::GetUsageForecastResponse { total: Some(total), forecast_results_by_time: Some(results) })
    }

    /// Records per group key in both periods of a comparison.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn compare(
        &self,
        ctx: &RequestContext,
        baseline: &t::DateInterval,
        comparison: &t::DateInterval,
        metric: &str,
        filter: Option<&t::Expression>,
        group_by: &[t::GroupDefinition],
        detail: Option<&str>,
    ) -> Result<(BTreeMap<Vec<String>, [BTreeMap<String, f64>; 2]>, [f64; 2], String), ServiceError> {
        let full_month = |i: &t::DateInterval, what: &str| -> Result<Period, ServiceError> {
            let p = Period::parse(i, "MONTHLY")?;
            if p.start != month_start(p.start) || p.end != next_month(p.start) {
                return Err(validation(format!("{what} must be exactly one calendar month, from the first day of a month to the first day of the next.")));
            }
            Ok(p)
        };
        let periods = [full_month(baseline, "BaselineTimePeriod")?, full_month(comparison, "ComparisonTimePeriod")?];
        check_metrics(&[metric.to_string()])?;
        check_group_by(group_by, false)?;
        if let Some(f) = filter {
            check_expression(f)?;
        }
        Ok(self.with_view(ctx, |view| {
            let mut groups: BTreeMap<Vec<String>, [BTreeMap<String, f64>; 2]> = BTreeMap::new();
            let mut totals = [0.0, 0.0];
            let mut all = Vec::new();
            for (i, p) in periods.iter().enumerate() {
                for r in view.select(filter, ms(p.start), ms(p.end)) {
                    let v = r.metric(metric) * p.share(r);
                    totals[i] += v;
                    let keys: Vec<String> = group_by.iter().map(|g| view.group_key(r, g)).collect();
                    let sub = detail.map(|d| view.dimension(r, d).unwrap_or_default()).unwrap_or_default();
                    *groups.entry(keys).or_default()[i].entry(sub).or_default() += v;
                    all.push(r);
                }
            }
            let unit = if COST_METRICS.contains(&metric) { "USD".to_string() } else { usage_unit(all) };
            (groups, totals, unit)
        }))
    }

    pub(crate) fn get_cost_and_usage_comparisons_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCostAndUsageComparisonsRequest,
    ) -> Result<t::GetCostAndUsageComparisonsResponse, ServiceError> {
        auth(ctx, "GetCostAndUsageComparisons")?;
        let group_by = input.group_by.clone().unwrap_or_default();
        let metric = input.metric_for_comparison.clone();
        let (groups, totals, unit) = self.compare(
            ctx,
            &input.baseline_time_period,
            &input.comparison_time_period,
            &metric,
            input.filter.as_ref(),
            &group_by,
            None,
        )?;
        let comparisons: Vec<t::CostAndUsageComparison> = groups
            .into_iter()
            .map(|(keys, [b, c])| t::CostAndUsageComparison {
                cost_and_usage_selector: Some(selector(&group_by, &keys)),
                metrics: Some(BTreeMap::from([(
                    metric.clone(),
                    comparison_value(b.values().sum(), c.values().sum(), &unit),
                )])),
            })
            .collect();
        let (comparisons, next_page_token) =
            page(comparisons, input.next_page_token.as_deref(), input.max_results, 1000)?;
        Ok(t::GetCostAndUsageComparisonsResponse {
            cost_and_usage_comparisons: Some(comparisons),
            total_cost_and_usage: Some(BTreeMap::from([(
                metric.clone(),
                comparison_value(totals[0], totals[1], &unit),
            )])),
            next_page_token,
        })
    }

    pub(crate) fn get_cost_comparison_drivers_op(
        &self,
        ctx: &RequestContext,
        input: t::GetCostComparisonDriversRequest,
    ) -> Result<t::GetCostComparisonDriversResponse, ServiceError> {
        auth(ctx, "GetCostComparisonDrivers")?;
        let group_by = input.group_by.clone().unwrap_or_else(|| {
            vec![t::GroupDefinition { r#type: Some("DIMENSION".into()), key: Some("SERVICE".into()) }]
        });
        let metric = input.metric_for_comparison.clone();
        let (groups, _, unit) = self.compare(
            ctx,
            &input.baseline_time_period,
            &input.comparison_time_period,
            &metric,
            input.filter.as_ref(),
            &group_by,
            Some("USAGE_TYPE"),
        )?;
        let drivers: Vec<t::CostComparisonDriver> = groups
            .into_iter()
            .map(|(keys, [b, c])| {
                let usage_types: BTreeSet<&String> = b.keys().chain(c.keys()).collect();
                let mut cost_drivers: Vec<(f64, t::CostDriver)> = usage_types
                    .into_iter()
                    .map(|ut| {
                        let (bv, cv) = (b.get(ut).copied().unwrap_or(0.0), c.get(ut).copied().unwrap_or(0.0));
                        let driver = t::CostDriver {
                            r#type: Some(
                                if bv == 0.0 {
                                    "NEW_USAGE"
                                } else if cv == 0.0 {
                                    "STOPPED_USAGE"
                                } else {
                                    "USAGE_CHANGE"
                                }
                                .into(),
                            ),
                            name: Some(ut.clone()),
                            metrics: Some(BTreeMap::from([(metric.clone(), comparison_value(bv, cv, &unit))])),
                        };
                        ((cv - bv).abs(), driver)
                    })
                    .filter(|(d, _)| *d > 0.0)
                    .collect();
                cost_drivers.sort_by(|a, b| b.0.total_cmp(&a.0));
                cost_drivers.truncate(10);
                t::CostComparisonDriver {
                    cost_selector: Some(selector(&group_by, &keys)),
                    metrics: Some(BTreeMap::from([(
                        metric.clone(),
                        comparison_value(b.values().sum(), c.values().sum(), &unit),
                    )])),
                    cost_drivers: Some(cost_drivers.into_iter().map(|(_, d)| d).collect()),
                }
            })
            .collect();
        let (drivers, next_page_token) = page(drivers, input.next_page_token.as_deref(), input.max_results, 10)?;
        Ok(t::GetCostComparisonDriversResponse { cost_comparison_drivers: Some(drivers), next_page_token })
    }

    pub(crate) fn get_approximate_usage_records_op(
        &self,
        ctx: &RequestContext,
        input: t::GetApproximateUsageRecordsRequest,
    ) -> Result<t::GetApproximateUsageRecordsResponse, ServiceError> {
        auth(ctx, "GetApproximateUsageRecords")?;
        let end = ctx.received_at.date_naive().and_hms_opt(0, 0, 0).expect("midnight").and_utc();
        let start = end - Duration::days(30);
        let wanted = input.services.clone().unwrap_or_default();
        let services = self.with_view(ctx, |view| {
            let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for r in view.select(None, ms(start), ms(end)) {
                let service = r.dimension("SERVICE_CODE").or(r.dimension("SERVICE")).unwrap_or_default().to_string();
                if !wanted.is_empty() && !wanted.contains(&service) {
                    continue;
                }
                let bucket = match input.granularity.as_str() {
                    "MONTHLY" => r.start.div_euclid(86_400_000 * 30),
                    "DAILY" => r.start.div_euclid(86_400_000),
                    _ => r.start.div_euclid(3_600_000),
                };
                let item = if input.approximation_dimension == "RESOURCE" {
                    format!("{}|{bucket}", r.dimension("RESOURCE_ID").unwrap_or_default())
                } else {
                    format!(
                        "{}|{}|{}|{bucket}",
                        r.account,
                        r.dimension("USAGE_TYPE").unwrap_or_default(),
                        r.dimension("OPERATION").unwrap_or_default()
                    )
                };
                seen.entry(service).or_default().insert(item);
            }
            seen.into_iter().map(|(k, v)| (k, v.len() as i64)).collect::<BTreeMap<_, _>>()
        });
        Ok(t::GetApproximateUsageRecordsResponse {
            total_records: services.values().sum(),
            services: Some(services),
            lookback_period: Some(t::DateInterval { start: query::date_str(start), end: query::date_str(end) }),
        })
    }
}

fn comparison_value(baseline: f64, comparison: f64, unit: &str) -> t::ComparisonMetricValue {
    t::ComparisonMetricValue {
        baseline_time_period_amount: Some(amount(baseline)),
        comparison_time_period_amount: Some(amount(comparison)),
        difference: Some(amount(comparison - baseline)),
        unit: Some(unit.into()),
    }
}

/// The filter expression that selects one group.
fn selector(group_by: &[t::GroupDefinition], keys: &[String]) -> t::Expression {
    let parts: Vec<t::Expression> = group_by
        .iter()
        .zip(keys)
        .map(|(g, k)| {
            let key = g.key.clone();
            match g.r#type.as_deref() {
                Some("TAG") => t::Expression {
                    tags: Some(t::TagValues {
                        key,
                        values: Some(vec![k.split_once('$').map_or(k.clone(), |(_, v)| v.to_string())]),
                        match_options: None,
                    }),
                    ..Default::default()
                },
                Some("COST_CATEGORY") => t::Expression {
                    cost_categories: Some(t::CostCategoryValues {
                        key,
                        values: Some(vec![k.split_once('$').map_or(k.clone(), |(_, v)| v.to_string())]),
                        match_options: None,
                    }),
                    ..Default::default()
                },
                _ => t::Expression {
                    dimensions: Some(t::DimensionValues { key, values: Some(vec![k.clone()]), match_options: None }),
                    ..Default::default()
                },
            }
        })
        .collect();
    match parts.len() {
        0 => t::Expression::default(),
        1 => parts.into_iter().next().expect("one part"),
        _ => t::Expression { and: Some(parts), ..Default::default() },
    }
}

/// The standard normal quantile (Acklam's approximation).
#[allow(clippy::excessive_precision)]
fn inverse_normal(p: f64) -> f64 {
    let p = p.clamp(1e-9, 1.0 - 1e-9);
    const A: [f64; 6] = [
        -3.969683028665376e1,
        2.209460984245205e2,
        -2.759285104469687e2,
        1.383577518672690e2,
        -3.066479806614716e1,
        2.506628277459239,
    ];
    const B: [f64; 5] =
        [-5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2, 6.680131188771972e1, -1.328068155288572e1];
    const C: [f64; 6] = [
        -7.784894002430293e-3,
        -3.223964580411365e-1,
        -2.400758277161838,
        -2.549732539343734,
        4.374664141464968,
        2.938163982698783,
    ];
    const D: [f64; 4] = [7.784695709041462e-3, 3.224671290700398e-1, 2.445134137142996, 3.754408661907416];
    let low = 0.02425;
    if p < low {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= 1.0 - low {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        -inverse_normal(1.0 - p)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn inverse_normal_matches_tables() {
        assert!((super::inverse_normal(0.9) - 1.2816).abs() < 1e-3);
        assert!((super::inverse_normal(0.975) - 1.96).abs() < 1e-3);
    }
}
