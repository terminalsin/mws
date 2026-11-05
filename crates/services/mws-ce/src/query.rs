//! Querying the ledger: dates and periods, filter expressions, group keys,
//! cost categories and amounts.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use mws_core::ServiceError;

use crate::generated::types as t;
use crate::state::{Account, CostCategory, CostRecord};

pub fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationException", 400, message)
}

pub const COST_METRICS: &[&str] =
    &["AmortizedCost", "BlendedCost", "NetAmortizedCost", "NetUnblendedCost", "UnblendedCost"];
pub const USAGE_METRICS: &[&str] = &["NormalizedUsageAmount", "UsageQuantity"];

/// A date (`2026-10-01`) or, for hourly data, a time (`2026-10-01T05:00:00Z`).
pub fn parse_time(s: &str) -> Result<DateTime<Utc>, ServiceError> {
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).expect("midnight")));
    }
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| validation(format!("Invalid date format: {s}. Use yyyy-MM-dd or yyyy-MM-ddThh:mm:ssZ.")))
}

pub fn ms(t: DateTime<Utc>) -> i64 {
    t.timestamp_millis()
}

pub fn date_str(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d").to_string()
}

pub fn time_str(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn from_ms(t: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(t).unwrap_or_default()
}

pub fn month_start(t: DateTime<Utc>) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(t.year(), t.month(), 1, 0, 0, 0).single().expect("valid month")
}

pub fn next_month(t: DateTime<Utc>) -> DateTime<Utc> {
    let (y, m) = if t.month() == 12 { (t.year() + 1, 1) } else { (t.year(), t.month() + 1) };
    Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).single().expect("valid month")
}

/// A checked time period.
#[derive(Debug, Clone, Copy)]
pub struct Period {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Hourly periods print times, others dates.
    pub hourly: bool,
}

impl Period {
    pub fn parse(interval: &t::DateInterval, granularity: &str) -> Result<Self, ServiceError> {
        let start = parse_time(&interval.start)?;
        let end = parse_time(&interval.end)?;
        if start >= end {
            return Err(validation("Start date (and hour) should be before end date (and hour)"));
        }
        Ok(Self { start, end, hourly: granularity == "HOURLY" })
    }

    pub fn interval(&self) -> t::DateInterval {
        let f = if self.hourly { time_str } else { date_str };
        t::DateInterval { start: f(self.start), end: f(self.end) }
    }

    /// The periods of `granularity` that cover this one.
    pub fn split(&self, granularity: &str) -> Vec<Period> {
        let mut out = Vec::new();
        let mut cur = self.start;
        while cur < self.end {
            let next = match granularity {
                "HOURLY" => cur + Duration::hours(1),
                "MONTHLY" => next_month(cur),
                _ => cur
                    .date_naive()
                    .succ_opt()
                    .map_or(self.end, |d| Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0).expect("midnight"))),
            }
            .min(self.end);
            out.push(Period { start: cur, end: next, hourly: self.hourly });
            cur = next;
        }
        out
    }

    /// How much of `r` falls in this period, from 0 to 1.
    pub fn share(&self, r: &CostRecord) -> f64 {
        let (s, e) = (ms(self.start), ms(self.end));
        if r.end <= r.start {
            return if r.start >= s && r.start < e { 1.0 } else { 0.0 };
        }
        let overlap = r.end.min(e) - r.start.max(s);
        if overlap <= 0 {
            0.0
        } else {
            overlap as f64 / (r.end - r.start) as f64
        }
    }
}

/// Everything a query sees: the caller's records, its payer's settings and
/// account names.
pub struct View<'a> {
    pub records: Vec<&'a CostRecord>,
    pub account: &'a Account,
    pub names: &'a BTreeMap<String, String>,
    /// Now, on the emulated clock.
    pub now: i64,
}

impl View<'_> {
    /// Whether cost allocation tag `key` is visible on `r`: the tag must be
    /// active, and the record no older than its activation (or a backfill
    /// since).
    pub fn tag_visible(&self, r: &CostRecord, key: &str) -> bool {
        let Some(status) = self.account.tag_status.get(key) else { return false };
        if status.status != "Active" {
            return false;
        }
        let activated = status.activated.unwrap_or(0);
        if r.start >= activated - activated.rem_euclid(3_600_000) {
            return true;
        }
        self.account.backfills.iter().any(|b| b.requested >= activated && b.completes <= self.now && r.start >= b.from)
    }

    pub fn tag(&self, r: &CostRecord, key: &str) -> Option<String> {
        if !self.tag_visible(r, key) {
            return None;
        }
        r.tags.get(key).cloned()
    }

    pub fn category(&self, name: &str) -> Option<&CostCategory> {
        self.account.cost_categories.values().find(|c| c.name == name)
    }

    /// The value cost category `name` gives `r`, or `None` when no rule
    /// matches and there is no default.
    pub fn category_value(&self, r: &CostRecord, name: &str, depth: usize) -> Option<String> {
        let c = self.category(name)?;
        if depth > 10 {
            return None;
        }
        if let Ok(start) = parse_time(&c.effective_start) {
            if r.start < ms(start) {
                return None;
            }
        }
        let rules: Vec<t::CostCategoryRule> = serde_json::from_value(c.rules.clone()).unwrap_or_default();
        for rule in rules {
            if let Some(inherited) = &rule.inherited_value {
                let v = match inherited.dimension_name.as_deref() {
                    Some("LINKED_ACCOUNT_NAME") => {
                        self.names.get(&r.account).cloned().or_else(|| Some(r.account.clone()))
                    }
                    Some("TAG") => inherited.dimension_key.as_deref().and_then(|k| self.tag(r, k)),
                    _ => None,
                };
                if let Some(v) = v.filter(|v| !v.is_empty()) {
                    return Some(v);
                }
                continue;
            }
            if let (Some(value), Some(expr)) = (&rule.value, &rule.rule) {
                if self.matches(r, expr, depth + 1) {
                    return Some(value.clone());
                }
            }
        }
        c.default_value.clone()
    }

    pub fn dimension(&self, r: &CostRecord, key: &str) -> Option<String> {
        match key {
            "LINKED_ACCOUNT_NAME" => self.names.get(&r.account).cloned(),
            _ => r.dimension(key).map(str::to_string),
        }
    }

    /// Whether `r` satisfies a filter expression.
    pub fn matches(&self, r: &CostRecord, e: &t::Expression, depth: usize) -> bool {
        if let Some(and) = &e.and {
            return and.iter().all(|x| self.matches(r, x, depth));
        }
        if let Some(or) = &e.or {
            return or.iter().any(|x| self.matches(r, x, depth));
        }
        if let Some(not) = &e.not {
            return !self.matches(r, not, depth);
        }
        if let Some(d) = &e.dimensions {
            let v = d.key.as_deref().and_then(|k| self.dimension(r, k));
            return values_match(v.as_deref(), d.values.as_deref().unwrap_or_default(), d.match_options.as_deref());
        }
        if let Some(tv) = &e.tags {
            let v = tv.key.as_deref().and_then(|k| self.tag(r, k));
            return values_match(v.as_deref(), tv.values.as_deref().unwrap_or_default(), tv.match_options.as_deref());
        }
        if let Some(c) = &e.cost_categories {
            let v = c.key.as_deref().and_then(|k| self.category_value(r, k, depth));
            return values_match(v.as_deref(), c.values.as_deref().unwrap_or_default(), c.match_options.as_deref());
        }
        true
    }

    /// The records in `period` that pass `filter`.
    pub fn select(&self, filter: Option<&t::Expression>, start: i64, end: i64) -> Vec<&CostRecord> {
        self.records
            .iter()
            .copied()
            .filter(|r| r.end.max(r.start + 1) > start && r.start < end)
            .filter(|r| filter.is_none_or(|f| self.matches(r, f, 0)))
            .collect()
    }

    /// The group key of `r` for one group definition, as Cost Explorer
    /// prints it (`value`, `tag$value`, `category$value`).
    pub fn group_key(&self, r: &CostRecord, g: &t::GroupDefinition) -> String {
        let key = g.key.as_deref().unwrap_or_default();
        match g.r#type.as_deref() {
            Some("TAG") => format!("{key}${}", self.tag(r, key).unwrap_or_default()),
            Some("COST_CATEGORY") => format!("{key}${}", self.category_value(r, key, 0).unwrap_or_default()),
            _ => match key {
                "LINKED_ACCOUNT" => r.account.clone(),
                _ => self.dimension(r, key).unwrap_or_else(|| default_dimension(key).to_string()),
            },
        }
    }
}

/// What a record without a value for `key` shows.
fn default_dimension(key: &str) -> &'static str {
    match key {
        "PURCHASE_TYPE" => "On Demand Instances",
        "RECORD_TYPE" => "Usage",
        "BILLING_ENTITY" => "AWS",
        "LEGAL_ENTITY_NAME" => "Amazon Web Services, Inc.",
        "INVOICING_ENTITY" => "Amazon Web Services, Inc.",
        "TENANCY" => "Shared",
        _ => "NoResourceId",
    }
}

fn values_match(actual: Option<&str>, wanted: &[String], options: Option<&[String]>) -> bool {
    let options = options.unwrap_or_default();
    let has = |o: &str| options.iter().any(|x| x == o);
    if has("ABSENT") {
        return actual.is_none_or(str::is_empty);
    }
    let Some(actual) = actual else { return wanted.iter().any(String::is_empty) };
    let insensitive = has("CASE_INSENSITIVE");
    let norm = |s: &str| if insensitive { s.to_lowercase() } else { s.to_string() };
    let a = norm(actual);
    wanted.iter().any(|w| {
        let w = norm(w);
        if has("STARTS_WITH") {
            a.starts_with(&w)
        } else if has("ENDS_WITH") {
            a.ends_with(&w)
        } else if has("CONTAINS") {
            a.contains(&w)
        } else if has("GREATER_THAN_OR_EQUAL") {
            match (a.parse::<f64>(), w.parse::<f64>()) {
                (Ok(x), Ok(y)) => x >= y,
                _ => a >= w,
            }
        } else {
            a == w
        }
    })
}

/// Check a filter expression's shape: exactly one operator per level.
pub fn check_expression(e: &t::Expression) -> Result<(), ServiceError> {
    let roots = [
        e.and.is_some(),
        e.or.is_some(),
        e.not.is_some(),
        e.dimensions.is_some(),
        e.tags.is_some(),
        e.cost_categories.is_some(),
        e.product_attributes.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if roots != 1 {
        return Err(validation("Expression has more than one roots. Only one root operator is allowed for each expression: And, Or, Not, Dimensions, Tags, CostCategories"));
    }
    for x in e.and.iter().chain(e.or.iter()).flatten() {
        check_expression(x)?;
    }
    if let Some(not) = &e.not {
        check_expression(not)?;
    }
    if let Some(d) = &e.dimensions {
        if d.key.is_none() {
            return Err(validation("Dimension key is required"));
        }
    }
    Ok(())
}

/// An amount as Cost Explorer prints it.
pub fn amount(v: f64) -> String {
    if v == 0.0 || !v.is_finite() {
        return "0".into();
    }
    let s = format!("{v:.10}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" {
        "0".into()
    } else {
        s.to_string()
    }
}

pub fn metric_value(v: f64, unit: &str) -> t::MetricValue {
    t::MetricValue { amount: Some(amount(v)), unit: Some(unit.into()) }
}

/// The unit of a usage metric over `records`: theirs when they agree,
/// otherwise `N/A`.
pub fn usage_unit<'a>(records: impl IntoIterator<Item = &'a CostRecord>) -> String {
    let units: BTreeSet<&str> = records.into_iter().map(|r| r.unit.as_str()).collect();
    match units.len() {
        1 => units.into_iter().next().unwrap_or("N/A").to_string(),
        _ => "N/A".into(),
    }
}

/// Validate and normalize the metric names a request asks for.
pub fn check_metrics(metrics: &[String]) -> Result<(), ServiceError> {
    if metrics.is_empty() {
        return Err(validation("Metrics is required"));
    }
    for m in metrics {
        if !COST_METRICS.contains(&m.as_str()) && !USAGE_METRICS.contains(&m.as_str()) {
            return Err(validation(format!(
                "Value '{m}' at 'metrics' failed to satisfy constraint: Member must satisfy enum value set: [AmortizedCost, BlendedCost, NetAmortizedCost, NetUnblendedCost, NormalizedUsageAmount, UnblendedCost, UsageQuantity]"
            )));
        }
    }
    Ok(())
}

pub fn check_group_by(groups: &[t::GroupDefinition], allow_resource: bool) -> Result<(), ServiceError> {
    if groups.len() > 2 {
        return Err(validation("You can only group by up to two different dimensions, tags, or cost categories."));
    }
    let mut seen = BTreeSet::new();
    for g in groups {
        let key = g.key.clone().unwrap_or_default();
        if !seen.insert((g.r#type.clone(), key.clone())) {
            return Err(validation("Group Definition contains duplicate key"));
        }
        if g.r#type.as_deref() == Some("DIMENSION") && key == "RESOURCE_ID" && !allow_resource {
            return Err(validation("Grouping by RESOURCE_ID is only supported by GetCostAndUsageWithResources."));
        }
    }
    Ok(())
}
