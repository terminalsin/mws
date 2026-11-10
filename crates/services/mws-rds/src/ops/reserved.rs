//! Reserved DB instances: the offerings catalog (each class, engine,
//! term, payment option and deployment) and purchases, which turn
//! `active` once paid and `retired` when their term ends on the emulated
//! clock.

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, authorize_create};
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::util::{arn, invalid_parameter, paginate, request_tag_context, stable_token, tags_from, Filters};
use crate::Rds;

const ONE_YEAR: i32 = 31_536_000;
const THREE_YEARS: i32 = 94_608_000;
const PRODUCTS: &[&str] = &["postgresql", "mysql", "mariadb", "aurora-postgresql", "aurora-mysql"];
const OFFERING_TYPES: &[&str] = &["No Upfront", "Partial Upfront", "All Upfront"];
const MAX_RESERVED: usize = 40;

/// An approximate on-demand hourly price for a class and product.
fn hourly(class: &str, product: &str) -> f64 {
    let gib = catalog::memory_mib(class) as f64 / 1024.0;
    let per_gib = if class.starts_with("db.t") {
        0.018
    } else if class.starts_with("db.m") {
        0.0178
    } else {
        0.0141
    };
    let base = gib * per_gib;
    if product.starts_with("aurora") {
        base * 1.2
    } else {
        base
    }
}

fn round(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Every offering, in a stable order.
fn offerings() -> Vec<t::ReservedDBInstancesOffering> {
    let mut out = Vec::new();
    for (class, _, _) in catalog::CLASSES.iter().filter(|c| c.0 != "db.serverless") {
        for product in PRODUCTS {
            if product.starts_with("aurora") && (class.ends_with(".micro") || class.ends_with(".small")) {
                continue;
            }
            for duration in [ONE_YEAR, THREE_YEARS] {
                for offering in OFFERING_TYPES {
                    for multi_az in [false, true] {
                        if product.starts_with("aurora") && multi_az {
                            continue;
                        }
                        let h = hourly(class, product) * if multi_az { 2.0 } else { 1.0 };
                        let hours = f64::from(duration) / 3600.0;
                        let discount = if duration == ONE_YEAR { 1.0 } else { 0.8 };
                        let (fixed, recurring) = match *offering {
                            "No Upfront" => (0.0, h * 0.69 * discount),
                            "Partial Upfront" => (h * hours * 0.33 * discount, h * 0.33 * discount),
                            _ => (h * hours * 0.62 * discount, 0.0),
                        };
                        let id = uuid_like(&format!("{class}/{product}/{duration}/{offering}/{multi_az}"));
                        out.push(t::ReservedDBInstancesOffering {
                            reserved_db_instances_offering_id: Some(id),
                            db_instance_class: Some(class.to_string()),
                            duration: Some(duration),
                            fixed_price: Some(round(fixed)),
                            usage_price: Some(0.0),
                            currency_code: Some("USD".into()),
                            product_description: Some(product.to_string()),
                            offering_type: Some(offering.to_string()),
                            multi_az: Some(multi_az),
                            recurring_charges: Some(if recurring > 0.0 {
                                vec![t::RecurringCharge {
                                    recurring_charge_amount: Some(round(recurring)),
                                    recurring_charge_frequency: Some("Hourly".into()),
                                }]
                            } else {
                                Vec::new()
                            }),
                        });
                    }
                }
            }
        }
    }
    out
}

/// A stable UUID-shaped id.
fn uuid_like(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let h: String = Sha256::digest(seed.as_bytes()).iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn duration_filter(d: &Option<String>) -> Result<Option<i32>, ServiceError> {
    match d.as_deref() {
        None => Ok(None),
        Some("1") | Some("31536000") => Ok(Some(ONE_YEAR)),
        Some("3") | Some("94608000") => Ok(Some(THREE_YEARS)),
        Some(other) => {
            Err(invalid_parameter(format!("Invalid duration: {other}. Valid values are 1, 3, 31536000 and 94608000.")))
        }
    }
}

impl Rds {
    pub(crate) fn describe_reserved_db_instances_offerings_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeReservedDBInstancesOfferingsMessage,
    ) -> Result<t::ReservedDBInstancesOfferingMessage, ServiceError> {
        Filters::new(&input.filters, &[])?;
        authorize(ctx, "DescribeReservedDBInstancesOfferings", "*", ConditionContext::new())?;
        let duration = duration_filter(&input.duration)?;
        let all: Vec<_> = offerings()
            .into_iter()
            .filter(|o| {
                input
                    .reserved_db_instances_offering_id
                    .as_ref()
                    .is_none_or(|i| o.reserved_db_instances_offering_id.as_ref() == Some(i))
                    && input.db_instance_class.as_ref().is_none_or(|c| o.db_instance_class.as_ref() == Some(c))
                    && duration.is_none_or(|d| o.duration == Some(d))
                    && input.product_description.as_ref().is_none_or(|p| o.product_description.as_ref() == Some(p))
                    && input.offering_type.as_ref().is_none_or(|p| o.offering_type.as_ref() == Some(p))
                    && input.multi_az.is_none_or(|m| o.multi_az == Some(m))
            })
            .collect();
        if let Some(id) = &input.reserved_db_instances_offering_id {
            if all.is_empty() {
                return Err(errors::reserved_db_instances_offering_not_found_fault(format!(
                    "Specified offering does not exist: {id}"
                )));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::ReservedDBInstancesOfferingMessage { marker, reserved_db_instances_offerings: Some(page) })
    }

    pub(crate) fn purchase_reserved_db_instances_offering_op(
        &self,
        ctx: &RequestContext,
        input: t::PurchaseReservedDBInstancesOfferingMessage,
    ) -> Result<t::PurchaseReservedDBInstancesOfferingResult, ServiceError> {
        let offering = offerings()
            .into_iter()
            .find(|o| {
                o.reserved_db_instances_offering_id.as_deref() == Some(input.reserved_db_instances_offering_id.as_str())
            })
            .ok_or_else(|| {
                errors::reserved_db_instances_offering_not_found_fault(format!(
                    "Specified offering does not exist: {}",
                    input.reserved_db_instances_offering_id
                ))
            })?;
        let id = match &input.reserved_db_instance_id {
            Some(i) => crate::util::identifier("ReservedDBInstanceId", i, 255)?,
            None => format!("ri-{}", stable_token(&uuid::Uuid::new_v4().to_string(), 16)),
        };
        let tags = tags_from(&input.tags)?;
        let riarn = arn(ctx, "ri", &id);
        authorize_create(ctx, "PurchaseReservedDBInstancesOffering", &riarn, &tags, request_tag_context(&tags))?;
        let count = input.db_instance_count.unwrap_or(1);
        if count < 1 {
            return Err(invalid_parameter("DBInstanceCount must be at least 1."));
        }
        let ri = t::ReservedDBInstance {
            reserved_db_instance_id: Some(id.clone()),
            reserved_db_instances_offering_id: offering.reserved_db_instances_offering_id.clone(),
            db_instance_class: offering.db_instance_class.clone(),
            start_time: Some(ctx.received_at),
            duration: offering.duration,
            fixed_price: offering.fixed_price.map(|p| round(p * f64::from(count))),
            usage_price: offering.usage_price,
            currency_code: offering.currency_code.clone(),
            db_instance_count: Some(count),
            product_description: offering.product_description.clone(),
            offering_type: offering.offering_type.clone(),
            multi_az: offering.multi_az,
            state: Some("payment-pending".into()),
            recurring_charges: offering.recurring_charges.clone(),
            reserved_db_instance_arn: Some(riarn),
            lease_id: Some(uuid::Uuid::new_v4().to_string()),
        };
        self.with_region(ctx, |r| {
            if r.reserved.contains_key(&id) {
                return Err(errors::reserved_db_instance_already_exists_fault(format!(
                    "User already has a reservation with the given identifier {id}."
                )));
            }
            if r.reserved.values().filter(|x| x.item.state.as_deref() != Some("retired")).count() >= MAX_RESERVED {
                return Err(errors::reserved_db_instance_quota_exceeded_fault(
                    "Request would exceed the user's DB Instance quota.",
                ));
            }
            r.reserved.insert(id.clone(), crate::state::Tagged { item: ri.clone(), tags });
            Ok(())
        })?;
        Ok(t::PurchaseReservedDBInstancesOfferingResult { reserved_db_instance: Some(ri) })
    }

    pub(crate) fn describe_reserved_db_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeReservedDBInstancesMessage,
    ) -> Result<t::ReservedDBInstanceMessage, ServiceError> {
        Filters::new(&input.filters, &[])?;
        authorize(ctx, "DescribeReservedDBInstances", &arn(ctx, "ri", "*"), ConditionContext::new())?;
        let duration = duration_filter(&input.duration)?;
        let now = ctx.received_at;
        // Paid at once; retired when the term ends.
        let all: Vec<t::ReservedDBInstance> = self.with_region(ctx, |r| {
            for ri in r.reserved.values_mut() {
                let end = ri.item.start_time.map(|s| s + Duration::seconds(i64::from(ri.item.duration.unwrap_or(0))));
                ri.item.state = Some(if end.is_some_and(|e| now >= e) { "retired" } else { "active" }.into());
            }
            r.reserved.values().map(|x| x.item.clone()).collect()
        });
        let all: Vec<_> = all
            .into_iter()
            .filter(|o| {
                input.reserved_db_instance_id.as_ref().is_none_or(|i| o.reserved_db_instance_id.as_ref() == Some(i))
                    && input
                        .reserved_db_instances_offering_id
                        .as_ref()
                        .is_none_or(|i| o.reserved_db_instances_offering_id.as_ref() == Some(i))
                    && input.db_instance_class.as_ref().is_none_or(|c| o.db_instance_class.as_ref() == Some(c))
                    && duration.is_none_or(|d| o.duration == Some(d))
                    && input.product_description.as_ref().is_none_or(|p| o.product_description.as_ref() == Some(p))
                    && input.offering_type.as_ref().is_none_or(|p| o.offering_type.as_ref() == Some(p))
                    && input.multi_az.is_none_or(|m| o.multi_az == Some(m))
                    && input.lease_id.as_ref().is_none_or(|l| o.lease_id.as_ref() == Some(l))
            })
            .collect();
        if let Some(id) = &input.reserved_db_instance_id {
            if all.is_empty() {
                return Err(errors::reserved_db_instance_not_found_fault(format!("Reservation {id} not found.")));
            }
        }
        let (page, marker) = paginate(all, &input.marker, input.max_records)?;
        Ok(t::ReservedDBInstanceMessage { marker, reserved_db_instances: Some(page) })
    }
}
