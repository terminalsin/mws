//! Derived usage beyond request charges: resource-hours and storage that
//! [`ResourceUsageSource`]s report (sampled on the emulated clock and
//! accrued hour by hour), and usage other services charge directly with
//! [`CostExplorer::record_usage`] (Marketplace metering, Bedrock tokens).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::query::{from_ms, month_start, ms, next_month};
use crate::state::CostRecord;
use crate::CostExplorer;

const HOUR_MS: i64 = 3_600_000;
/// How often API calls sample the usage sources (Cost Explorer queries
/// always do).
const SAMPLE_MS: i64 = 60_000;

/// How a resource's quantity accrues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsageRate {
    /// `quantity` units per hour (instance-hours, vCPU-hours).
    #[default]
    PerHour,
    /// `quantity` units held for a month (GB-months): each hour accrues
    /// `quantity / hours in the month`.
    PerMonth,
}

/// One billable line of a running resource.
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    pub account: String,
    pub region: String,
    /// The Cost Explorer service name (`Amazon Elastic Compute Cloud - Compute`).
    pub service: String,
    /// The full usage type, with its Region prefix (`USE2-BoxUsage:t3.micro`).
    pub usage_type: String,
    pub operation: String,
    /// `RESOURCE_ID`: an instance or volume id, a bucket name or an ARN.
    pub resource_id: String,
    /// `Hrs`, `vCPU-Hours`, `GB-Hours`, `GB-Mo`.
    pub unit: String,
    pub rate: UsageRate,
    pub quantity: f64,
    /// USD per unit.
    pub price: f64,
    pub instance_type: Option<String>,
    /// When the resource started being billed (launch, creation). `None`:
    /// from when Cost Explorer first sees it.
    pub started: Option<DateTime<Utc>>,
    /// When it stopped (stopped or terminated but still listed).
    pub ended: Option<DateTime<Utc>>,
    /// The resource's tags (cost allocation tags once activated).
    pub tags: BTreeMap<String, String>,
    /// Further dimensions (`DATABASE_ENGINE`, `CACHE_ENGINE`, ...).
    pub dimensions: BTreeMap<String, String>,
}

/// Reports every billable resource that exists now, across accounts and
/// Regions. Implemented over the services that own the resources; must
/// not call back into Cost Explorer.
pub trait ResourceUsageSource: Send + Sync {
    fn resources(&self) -> Vec<ResourceUsage>;
}

/// Usage another service charges as it happens (Marketplace metering,
/// Bedrock tokens), aggregated per hour and line item.
#[derive(Debug, Clone, Default)]
pub struct UsageCharge {
    pub account: String,
    pub region: String,
    /// When the usage happened, on the emulated clock.
    pub at: DateTime<Utc>,
    /// The Cost Explorer service name (`Amazon Bedrock`, a Marketplace
    /// product's title).
    pub service: String,
    pub usage_type: String,
    pub operation: String,
    pub resource_id: Option<String>,
    pub unit: String,
    pub quantity: f64,
    /// The total cost of `quantity`, in USD.
    pub cost: f64,
    pub tags: BTreeMap<String, String>,
    /// Further dimensions (`BILLING_ENTITY` = `AWS Marketplace`, ...).
    pub dimensions: BTreeMap<String, String>,
}

fn hours_in_month(at: i64) -> f64 {
    let t = from_ms(at);
    let (s, e) = (month_start(t), next_month(t));
    (ms(e) - ms(s)) as f64 / HOUR_MS as f64
}

fn add_cost(r: &mut CostRecord, quantity: f64, cost: f64) {
    r.usage_quantity += quantity;
    r.normalized_usage_amount += quantity;
    for v in [
        &mut r.unblended_cost,
        &mut r.blended_cost,
        &mut r.amortized_cost,
        &mut r.net_unblended_cost,
        &mut r.net_amortized_cost,
    ] {
        *v += cost;
    }
}

#[allow(clippy::too_many_arguments)]
fn line(
    payer: &str,
    account: &str,
    region: &str,
    hour: i64,
    service: &str,
    usage_type: &str,
    operation: &str,
    unit: &str,
    resource_id: Option<&str>,
    extra: &BTreeMap<String, String>,
) -> CostRecord {
    let mut dimensions = BTreeMap::new();
    dimensions.insert("SERVICE".to_string(), service.to_string());
    if let Some(code) = crate::pricing::service_code(service) {
        dimensions.insert("SERVICE_CODE".to_string(), code.to_string());
    }
    dimensions.insert("REGION".to_string(), region.to_string());
    dimensions.insert("USAGE_TYPE".to_string(), usage_type.to_string());
    dimensions.insert("OPERATION".to_string(), operation.to_string());
    dimensions.insert("RECORD_TYPE".to_string(), "Usage".to_string());
    if let Some(id) = resource_id {
        dimensions.insert("RESOURCE_ID".to_string(), id.to_string());
    }
    dimensions.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
    CostRecord {
        payer: payer.to_string(),
        account: account.to_string(),
        start: hour,
        end: hour + HOUR_MS,
        dimensions,
        unit: unit.to_string(),
        ..Default::default()
    }
}

impl CostExplorer {
    /// A source of running, billable resources (EC2 instances, volumes,
    /// databases, storage, ...).
    pub fn add_resource_source(&self, source: Arc<dyn ResourceUsageSource>) {
        self.inner.sources.write().expect("Cost Explorer sources lock poisoned").push(source);
    }

    /// Charge usage as it happens: Marketplace metering records, Bedrock
    /// tokens, anything billed per unit outside the request charges. The
    /// charge lands in the hour of `usage.at`, with `RESOURCE_ID` and tags
    /// when given.
    pub fn record_usage(&self, usage: UsageCharge) {
        let at = ms(usage.at);
        let hour = at - at.rem_euclid(HOUR_MS);
        let payer = self.payer_of(&usage.account);
        let key = format!(
            "{hour}|use|{}|{}|{}|{}|{}|{}",
            usage.account,
            usage.region,
            usage.service,
            usage.usage_type,
            usage.operation,
            usage.resource_id.as_deref().unwrap_or_default()
        );
        let mut st = self.lock();
        let r = st.derived.entry(key).or_insert_with(|| {
            line(
                &payer,
                &usage.account,
                &usage.region,
                hour,
                &usage.service,
                &usage.usage_type,
                &usage.operation,
                &usage.unit,
                usage.resource_id.as_deref(),
                &usage.dimensions,
            )
        });
        r.tags.extend(usage.tags);
        add_cost(r, usage.quantity, usage.cost);
    }

    /// Sample the resource sources and accrue what ran since the last
    /// sample, up to `now`. `throttled` samples at most once a minute of
    /// emulated time. Never call with the state lock held.
    pub(crate) fn accrue(&self, now: DateTime<Utc>, throttled: bool) {
        let now = ms(now);
        let sources = self.inner.sources.read().expect("Cost Explorer sources lock poisoned").clone();
        if sources.is_empty() {
            return;
        }
        {
            let mut st = self.lock();
            if now == st.last_sample || (throttled && (now - st.last_sample).abs() < SAMPLE_MS) {
                return;
            }
            st.last_sample = now;
        }
        let resources: Vec<ResourceUsage> = sources.iter().flat_map(|s| s.resources()).collect();
        let payers: BTreeMap<String, String> = resources
            .iter()
            .map(|r| r.account.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|a| {
                let p = self.payer_of(&a);
                (a, p)
            })
            .collect();
        let mut st = self.lock();
        let mut seen = BTreeSet::new();
        for r in resources {
            let key = format!("{}|{}|{}|{}", r.account, r.region, r.usage_type, r.resource_id);
            let prior = st.meters.get(&key).copied();
            let started = r.started.map(ms);
            let from = match (prior, started) {
                (Some(p), Some(s)) => p.max(s),
                (Some(p), None) => p,
                (None, Some(s)) => s,
                (None, None) => now,
            };
            let to = r.ended.map_or(now, |e| ms(e).min(now));
            seen.insert(key.clone());
            st.meters.insert(key, prior.unwrap_or(i64::MIN).max(to).max(from.min(now)));
            let payer = payers.get(&r.account).cloned().unwrap_or_else(|| r.account.clone());
            let mut extra = r.dimensions.clone();
            if let Some(t) = &r.instance_type {
                extra.insert("INSTANCE_TYPE".into(), t.clone());
            }
            // Nothing to accrue (a stopped database, an empty bucket): the
            // meter still moves on.
            let mut cur = if r.quantity == 0.0 { to } else { from };
            while cur < to {
                let hour = cur - cur.rem_euclid(HOUR_MS);
                let next = (hour + HOUR_MS).min(to);
                let hours = (next - cur) as f64 / HOUR_MS as f64;
                let quantity = match r.rate {
                    UsageRate::PerHour => r.quantity * hours,
                    UsageRate::PerMonth => r.quantity * hours / hours_in_month(hour),
                };
                let k =
                    format!("{hour}|res|{}|{}|{}|{}|{}", r.account, r.region, r.service, r.usage_type, r.resource_id);
                let rec = st.derived.entry(k).or_insert_with(|| {
                    line(
                        &payer,
                        &r.account,
                        &r.region,
                        hour,
                        &r.service,
                        &r.usage_type,
                        &r.operation,
                        &r.unit,
                        Some(&r.resource_id),
                        &extra,
                    )
                });
                rec.tags = r.tags.clone();
                add_cost(rec, quantity, quantity * r.price);
                cur = next;
            }
        }
        st.meters.retain(|k, _| seen.contains(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct One(ResourceUsage);
    impl ResourceUsageSource for One {
        fn resources(&self) -> Vec<ResourceUsage> {
            vec![self.0.clone()]
        }
    }

    #[test]
    fn instance_hours_accrue_by_hour_with_tags() {
        let ce = CostExplorer::new();
        let start = DateTime::parse_from_rfc3339("2026-10-01T10:30:00Z").unwrap().with_timezone(&Utc);
        ce.add_resource_source(Arc::new(One(ResourceUsage {
            account: "111111111111".into(),
            region: "us-east-1".into(),
            service: "Amazon Elastic Compute Cloud - Compute".into(),
            usage_type: "BoxUsage:t3.micro".into(),
            operation: "RunInstances".into(),
            resource_id: "i-1".into(),
            unit: "Hrs".into(),
            quantity: 1.0,
            price: 0.0104,
            started: Some(start),
            tags: BTreeMap::from([("team".into(), "web".into())]),
            ..Default::default()
        })));
        ce.accrue(start + chrono::Duration::hours(2), false);
        let recs = ce.records();
        assert_eq!(recs.len(), 3);
        let total: f64 = recs.iter().map(|r| r.usage_quantity).sum();
        assert!((total - 2.0).abs() < 1e-9, "{total}");
        assert!(recs.iter().all(|r| r.dimension("RESOURCE_ID") == Some("i-1") && r.tags["team"] == "web"));
        // Sampling again at the same time adds nothing.
        ce.accrue(start + chrono::Duration::hours(2), false);
        let again: f64 = ce.records().iter().map(|r| r.usage_quantity).sum();
        assert!((again - 2.0).abs() < 1e-9);
    }

    #[test]
    fn storage_accrues_a_share_of_the_month() {
        let ce = CostExplorer::new();
        let start = DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z").unwrap().with_timezone(&Utc);
        ce.add_resource_source(Arc::new(One(ResourceUsage {
            account: "111111111111".into(),
            region: "us-east-1".into(),
            service: "EC2 - Other".into(),
            usage_type: "EBS:VolumeUsage.gp3".into(),
            resource_id: "vol-1".into(),
            unit: "GB-Mo".into(),
            rate: UsageRate::PerMonth,
            quantity: 720.0,
            price: 0.08,
            started: Some(start),
            ..Default::default()
        })));
        ce.accrue(start + chrono::Duration::hours(1), false);
        let r = &ce.records()[0];
        // November has 720 hours: 720 GB for an hour is one GB-month.
        assert!((r.usage_quantity - 1.0).abs() < 1e-9);
        assert!((r.unblended_cost - 0.08).abs() < 1e-9);
    }
}
