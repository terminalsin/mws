//! Reserved Instances: a catalogue of offerings priced from the On-Demand
//! rates (Standard and Convertible, one and three years, three payment
//! options, Region or zone scope), purchases that queue until their
//! purchase time and retire when their term ends.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::pricing::{product_price, PRODUCTS};
use crate::util::{authorize, err, invalid_parameter, s, Filters};
use crate::{account_of, Ec2};

const YEAR: i64 = 31_536_000;
const DURATIONS: [i64; 2] = [YEAR, 3 * YEAR];
const CLASSES: [&str; 2] = ["standard", "convertible"];
const OFFERING_TYPES: [&str; 3] = ["No Upfront", "Partial Upfront", "All Upfront"];
const TENANCIES: [&str; 2] = ["default", "dedicated"];

/// Upfront (as hours of On-Demand use) and hourly (as a share of the
/// On-Demand rate) for a class, term and payment option.
fn terms(class: &str, years: i64, offering: &str) -> (f64, f64) {
    let three = years == 3;
    match (class, three, offering) {
        ("standard", false, "No Upfront") => (0.0, 0.63),
        ("standard", false, "Partial Upfront") => (0.30, 0.27),
        ("standard", false, _) => (0.56, 0.0),
        ("standard", true, "No Upfront") => (0.0, 0.45),
        ("standard", true, "Partial Upfront") => (0.20, 0.19),
        ("standard", true, _) => (0.38, 0.0),
        (_, false, "No Upfront") => (0.0, 0.73),
        (_, false, "Partial Upfront") => (0.35, 0.33),
        (_, false, _) => (0.67, 0.0),
        (_, true, "No Upfront") => (0.0, 0.55),
        (_, true, "Partial Upfront") => (0.25, 0.23),
        (_, true, _) => (0.47, 0.0),
    }
}

/// A stable offering id for an offering's attributes, shaped like AWS's
/// (a UUID).
fn offering_id(parts: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, parts.as_bytes());
    let h = hex::encode(&digest.as_ref()[..16]);
    format!("{}-{}-4{}-a{}-{}", &h[..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
}

/// Every offering in `region`, filtered as it is generated.
fn offerings(
    region: &str,
    keep: &mut dyn FnMut(&t::ReservedInstancesOffering) -> bool,
) -> Vec<t::ReservedInstancesOffering> {
    let zones = crate::catalog::zones(region);
    let mut scopes: Vec<Option<(String, String)>> = vec![None];
    scopes.extend(zones.into_iter().map(Some));
    let mut out = Vec::new();
    for itype in crate::catalog::INSTANCE_TYPES {
        for product in PRODUCTS {
            let Some(hourly) = product_price(itype.name, product) else { continue };
            for tenancy in TENANCIES {
                let hourly = if tenancy == "dedicated" { hourly * 1.1 } else { hourly };
                for class in CLASSES {
                    for duration in DURATIONS {
                        for offering in OFFERING_TYPES {
                            for scope in &scopes {
                                let years = duration / YEAR;
                                let (upfront, share) = terms(class, years, offering);
                                let hours = (duration / 3600) as f64;
                                let fixed = crate::pricing::round(upfront * hourly * hours).round();
                                let recurring = crate::pricing::round(share * hourly);
                                let key = format!(
                                    "{region}/{}/{product}/{tenancy}/{class}/{duration}/{offering}/{}",
                                    itype.name,
                                    scope.as_ref().map(|z| z.0.as_str()).unwrap_or("region")
                                );
                                let o = t::ReservedInstancesOffering {
                                    reserved_instances_offering_id: Some(offering_id(&key)),
                                    instance_type: Some(itype.name.into()),
                                    availability_zone: scope.as_ref().map(|z| z.0.clone()),
                                    availability_zone_id: scope.as_ref().map(|z| z.1.clone()),
                                    duration: Some(duration),
                                    usage_price: Some(0.0),
                                    fixed_price: Some(fixed as f32),
                                    product_description: Some(product.to_string()),
                                    currency_code: Some("USD".into()),
                                    instance_tenancy: Some(tenancy.into()),
                                    marketplace: Some(false),
                                    offering_class: Some(class.into()),
                                    offering_type: Some(offering.into()),
                                    pricing_details: Some(Vec::new()),
                                    recurring_charges: Some(if recurring > 0.0 {
                                        vec![t::RecurringCharge {
                                            amount: Some(recurring),
                                            frequency: Some("Hourly".into()),
                                        }]
                                    } else {
                                        Vec::new()
                                    }),
                                    scope: Some(if scope.is_some() { "Availability Zone" } else { "Region" }.into()),
                                };
                                if keep(&o) {
                                    out.push(o);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn token(n: usize) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("mws:{n}"))
}

fn untoken(tok: &str) -> Result<usize, ServiceError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(tok)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.strip_prefix("mws:").and_then(|n| n.parse().ok()))
        .ok_or_else(|| invalid_parameter(format!("Invalid value '{tok}' for nextToken")))
}

/// A reservation's state on the clock: queued until its start, retired
/// after its end.
fn current_state(ri: &t::ReservedInstances, now: DateTime<Utc>) -> String {
    match ri.state.as_deref() {
        Some("queued-deleted") => "queued-deleted".into(),
        _ if ri.start.is_some_and(|s| s > now) => "queued".into(),
        _ if ri.end.is_some_and(|e| e <= now) => "retired".into(),
        _ => "active".into(),
    }
}

impl Ec2 {
    pub(crate) fn describe_reserved_instances_offerings_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeReservedInstancesOfferingsRequest,
    ) -> Result<t::DescribeReservedInstancesOfferingsResult, ServiceError> {
        authorize(ctx, "DescribeReservedInstancesOfferings", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let ids = input.reserved_instances_offering_ids.clone().unwrap_or_default();
        let filters = Filters::new(&input.filters);
        let max = input.max_results.unwrap_or(100);
        if !(1..=100).contains(&max) {
            return Err(invalid_parameter(format!(
                "Value ( {max} ) for parameter maxResults is invalid. Expecting a value between 1 and 100."
            )));
        }
        let zone = match (&input.availability_zone, &input.availability_zone_id) {
            (Some(z), _) => Some(z.clone()),
            (None, Some(id)) => crate::catalog::zone_name(&ctx.region, id),
            _ => None,
        };
        if let Some(tenancy) = &input.instance_tenancy {
            if !matches!(tenancy.as_str(), "default" | "dedicated" | "host") {
                return Err(invalid_parameter(format!("Value ({tenancy}) for parameter instanceTenancy is invalid.")));
            }
        }
        let mut bad_filter = None;
        let items = offerings(&ctx.region, &mut |o| {
            let id = o.reserved_instances_offering_id.clone().unwrap_or_default();
            let ok = (ids.is_empty() || ids.contains(&id))
                && input.instance_type.as_ref().is_none_or(|t| o.instance_type.as_ref() == Some(t))
                && zone.as_ref().is_none_or(|z| o.availability_zone.as_ref() == Some(z))
                && input.offering_class.as_ref().is_none_or(|c| o.offering_class.as_ref() == Some(c))
                && input.offering_type.as_ref().is_none_or(|c| o.offering_type.as_ref() == Some(c))
                && input.product_description.as_ref().is_none_or(|c| o.product_description.as_ref() == Some(c))
                && input.instance_tenancy.as_ref().is_none_or(|c| o.instance_tenancy.as_ref() == Some(c))
                && input.min_duration.is_none_or(|d| o.duration.unwrap_or_default() >= d)
                && input.max_duration.is_none_or(|d| o.duration.unwrap_or_default() <= d);
            if !ok {
                return false;
            }
            let fixed = o.fixed_price.map(|p| p.to_string()).into_iter().collect::<Vec<_>>();
            let usage = o.usage_price.map(|p| p.to_string()).into_iter().collect::<Vec<_>>();
            let duration = o.duration.map(|p| p.to_string()).into_iter().collect::<Vec<_>>();
            match filters.matches(None, |name| {
                Some(match name {
                    "availability-zone" => s(&o.availability_zone),
                    "availability-zone-id" => s(&o.availability_zone_id),
                    "duration" => duration.clone(),
                    "fixed-price" => fixed.clone(),
                    "instance-type" => s(&o.instance_type),
                    "marketplace" => vec!["false".into()],
                    "product-description" => s(&o.product_description),
                    "reserved-instances-offering-id" => vec![id.clone()],
                    "scope" => s(&o.scope),
                    "usage-price" => usage.clone(),
                    _ => return None,
                })
            }) {
                Ok(keep) => keep,
                Err(e) => {
                    bad_filter.get_or_insert(e);
                    false
                }
            }
        });
        if let Some(e) = bad_filter {
            return Err(e);
        }
        let start = match input.next_token.as_deref().filter(|t| !t.is_empty()) {
            Some(tok) => untoken(tok)?,
            None => 0,
        };
        let max = max as usize;
        let next = (start + max < items.len()).then(|| token(start + max));
        let page = items.into_iter().skip(start).take(max).collect();
        Ok(t::DescribeReservedInstancesOfferingsResult { reserved_instances_offerings: Some(page), next_token: next })
    }

    pub(crate) fn purchase_reserved_instances_offering_op(
        &self,
        ctx: &RequestContext,
        input: t::PurchaseReservedInstancesOfferingRequest,
    ) -> Result<t::PurchaseReservedInstancesOfferingResult, ServiceError> {
        if input.instance_count < 1 {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter instanceCount is invalid. Expected a positive integer.",
                input.instance_count
            )));
        }
        let id = input.reserved_instances_offering_id.clone();
        let account = account_of(ctx);
        authorize(
            ctx,
            "PurchaseReservedInstancesOffering",
            &[(crate::util::arn(ctx, &account, "reserved-instances/*"), ConditionContext::new())],
            input.dry_run,
        )?;
        let offering =
            offerings(&ctx.region, &mut |o| o.reserved_instances_offering_id.as_deref() == Some(id.as_str()))
                .into_iter()
                .next()
                .ok_or_else(|| {
                    err(
                        "InvalidReservedInstancesOfferingId",
                        format!("The Reserved Instances Offering ID '{id}' is not valid."),
                    )
                })?;
        let upfront = offering.fixed_price.unwrap_or_default() as f64 * input.instance_count as f64;
        if let Some(limit) = &input.limit_price {
            if limit.amount.is_some_and(|a| a < upfront) {
                return Err(err(
                    "ReservedInstancesLimitPriceExceeded",
                    format!(
                        "The upfront price of {upfront:.2} is more than the limit price of {:.2}.",
                        limit.amount.unwrap_or_default()
                    ),
                ));
            }
        }
        let now = ctx.received_at;
        if let Some(at) = input.purchase_time {
            if at < now || at > now + chrono::Duration::days(3 * 365) {
                return Err(invalid_parameter(
                    "The purchase time must be in the future and no more than three years away.",
                ));
            }
        }
        let start = input.purchase_time.unwrap_or(now);
        let ri_id = uuid_v4();
        let ri = t::ReservedInstances {
            reserved_instances_id: Some(ri_id.clone()),
            instance_type: offering.instance_type,
            availability_zone: offering.availability_zone,
            availability_zone_id: offering.availability_zone_id,
            start: Some(start),
            end: Some(start + chrono::Duration::seconds(offering.duration.unwrap_or(YEAR))),
            duration: offering.duration,
            usage_price: offering.usage_price,
            fixed_price: offering.fixed_price,
            instance_count: Some(input.instance_count),
            product_description: offering.product_description,
            state: Some(if start > now { "queued" } else { "active" }.into()),
            currency_code: offering.currency_code,
            instance_tenancy: offering.instance_tenancy,
            offering_class: offering.offering_class,
            offering_type: offering.offering_type,
            recurring_charges: offering.recurring_charges,
            scope: offering.scope,
            tags: None,
        };
        self.with_region(ctx, |r| r.reserved_instances.insert(ri_id.clone(), ri));
        Ok(t::PurchaseReservedInstancesOfferingResult { reserved_instances_id: Some(ri_id) })
    }

    pub(crate) fn describe_reserved_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeReservedInstancesRequest,
    ) -> Result<t::DescribeReservedInstancesResult, ServiceError> {
        authorize(ctx, "DescribeReservedInstances", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let ids = input.reserved_instances_ids.clone().unwrap_or_default();
        let filters = Filters::new(&input.filters);
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            for id in &ids {
                if !r.reserved_instances.contains_key(id) {
                    return Err(err(
                        "InvalidReservedInstancesId.NotFound",
                        format!("The Reserved Instances ID '{id}' does not exist"),
                    ));
                }
            }
            let mut out = Vec::new();
            for ri in r.reserved_instances.values() {
                let mut ri = ri.clone();
                ri.state = Some(current_state(&ri, now));
                let id = ri.reserved_instances_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                if input.offering_class.as_ref().is_some_and(|c| ri.offering_class.as_ref() != Some(c))
                    || input.offering_type.as_ref().is_some_and(|c| ri.offering_type.as_ref() != Some(c))
                {
                    continue;
                }
                let ts = |t: Option<DateTime<Utc>>| {
                    t.map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()).into_iter().collect::<Vec<_>>()
                };
                let ok = filters.matches(ri.tags.as_ref(), |name| {
                    Some(match name {
                        "availability-zone" => s(&ri.availability_zone),
                        "availability-zone-id" => s(&ri.availability_zone_id),
                        "duration" => ri.duration.map(|d| d.to_string()).into_iter().collect(),
                        "end" => ts(ri.end),
                        "fixed-price" => ri.fixed_price.map(|d| d.to_string()).into_iter().collect(),
                        "instance-type" => s(&ri.instance_type),
                        "scope" => s(&ri.scope),
                        "product-description" => s(&ri.product_description),
                        "reserved-instances-id" => vec![id.clone()],
                        "start" => ts(ri.start),
                        "state" => s(&ri.state),
                        "usage-price" => ri.usage_price.map(|d| d.to_string()).into_iter().collect(),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(ri);
                }
            }
            Ok(t::DescribeReservedInstancesResult { reserved_instances: Some(out) })
        })
    }
}

fn uuid_v4() -> String {
    use rand::Rng;
    let b: [u8; 16] = rand::thread_rng().gen();
    let h = hex::encode(b);
    format!("{}-{}-4{}-a{}-{}", &h[..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offerings_are_priced_below_on_demand_and_ids_are_stable() {
        let a = offerings("us-east-1", &mut |o| o.instance_type.as_deref() == Some("m5.large"));
        let b = offerings("us-east-1", &mut |o| o.instance_type.as_deref() == Some("m5.large"));
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0].reserved_instances_offering_id, b[0].reserved_instances_offering_id);
        let all_upfront_1y = a
            .iter()
            .find(|o| {
                o.offering_type.as_deref() == Some("All Upfront")
                    && o.duration == Some(YEAR)
                    && o.offering_class.as_deref() == Some("standard")
                    && o.product_description.as_deref() == Some("Linux/UNIX")
                    && o.instance_tenancy.as_deref() == Some("default")
                    && o.scope.as_deref() == Some("Region")
            })
            .unwrap();
        let fixed = all_upfront_1y.fixed_price.unwrap() as f64;
        assert!(fixed > 0.0 && fixed < 0.096 * 8760.0);
    }
}
