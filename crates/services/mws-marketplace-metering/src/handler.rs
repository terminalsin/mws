//! The four Metering operations.

use chrono::{DateTime, Datelike, Duration, DurationRound, TimeZone, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_marketplace_entitlement::{Product, Subscription};

use crate::generated::{errors, types, Handler};
use crate::signing::{self, PUBLIC_KEY_VERSION};
use crate::state::{Allocation, MeteringRecord, Registration};
use crate::Metering;

/// How far ahead of the emulated clock a usage timestamp may be.
const FUTURE_SKEW: Duration = Duration::minutes(5);

fn hour_of(t: DateTime<Utc>) -> DateTime<Utc> {
    t.duration_trunc(Duration::hours(1)).unwrap_or(t)
}

fn invalid_product_code() -> ServiceError {
    errors::invalid_product_code(
        "The product code passed does not match the product code used for publishing the product.",
    )
}

fn not_entitled() -> ServiceError {
    errors::customer_not_entitled(
        "Exception thrown when the customer does not have a valid subscription for the product.",
    )
}

fn invalid_dimension() -> ServiceError {
    errors::invalid_usage_dimension(
        "The usage dimension does not match one of the UsageDimensions associated with products.",
    )
}

fn invalid_license() -> ServiceError {
    errors::invalid_license(
        "Ensure the LicenseArn is valid, matches the customer, and usage is within the license activation period.",
    )
}

fn invalid_customer() -> ServiceError {
    errors::invalid_customer_identifier("You have metered usage for a CustomerIdentifier that does not exist.")
}

/// The vendor-metered tags of a usage, checked as AWS does: allocations
/// add up to the quantity, keys are unique within an allocation, and no
/// two allocations carry the same set of tags.
fn allocations(quantity: i32, input: Option<&[types::UsageAllocation]>) -> Result<Vec<Allocation>, ServiceError> {
    let Some(input) = input else { return Ok(Vec::new()) };
    let sum: i64 = input.iter().map(|a| i64::from(a.allocated_usage_quantity)).sum();
    if sum != i64::from(quantity) {
        return Err(errors::invalid_usage_allocations(
            "Sum of allocated usage quantities is not equal to the usage quantity.",
        ));
    }
    let mut out: Vec<Allocation> = Vec::with_capacity(input.len());
    for a in input {
        let mut tags: Vec<(String, String)> =
            a.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        tags.sort();
        if tags.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(errors::invalid_tag("The tag is invalid, or the number of tags is greater than 5."));
        }
        if out.iter().any(|o| o.tags == tags) {
            return Err(errors::invalid_usage_allocations("Each usage allocation must have a unique set of tags."));
        }
        out.push(Allocation { allocated_usage_quantity: a.allocated_usage_quantity, tags });
    }
    Ok(out)
}

fn record_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl Metering {
    /// The caller may run `product`: it is the seller (testing its own
    /// listing) or its account holds an active subscription. Returns that
    /// subscription, if any.
    fn entitlement_of(&self, ctx: &RequestContext, product: &Product) -> Result<Option<Subscription>, ServiceError> {
        let account = &ctx.caller.account_id;
        match self.catalog.active_subscription(&product.product_code, account) {
            Some(s) => Ok(Some(s)),
            None if &product.seller_account_id == account => Ok(None),
            None => Err(not_entitled()),
        }
    }
}

/// A BatchMeterUsage record once its customer is known.
struct Resolved<'a> {
    input: &'a types::UsageRecord,
    product_code: String,
    subscription: Option<Subscription>,
    customer_account: String,
    allocations: Vec<Allocation>,
}

#[async_trait::async_trait]
impl Handler for Metering {
    async fn resolve_customer(
        &self,
        ctx: &RequestContext,
        input: types::ResolveCustomerRequest,
    ) -> Result<types::ResolveCustomerResult, ServiceError> {
        ctx.authorize("aws-marketplace:ResolveCustomer", "*", ConditionContext::new())?;
        let (sub, product) =
            match self.catalog.resolve_token(&input.registration_token, &ctx.caller.account_id, ctx.received_at) {
                Ok(found) => found,
                Err(mws_marketplace_entitlement::TokenError::Invalid) => {
                    return Err(errors::invalid_token("Registration token is invalid."))
                }
                Err(mws_marketplace_entitlement::TokenError::Expired) => {
                    return Err(errors::expired_token("The submitted registration token has expired."))
                }
            };
        Ok(types::ResolveCustomerResult {
            customer_identifier: Some(sub.customer_identifier),
            product_code: Some(product.product_code),
            customer_aws_account_id: Some(sub.customer_aws_account_id),
            license_arn: Some(sub.license_arn),
            metadata: Some(types::Metadata { agreement_id: Some(sub.agreement_id) }),
        })
    }

    async fn meter_usage(
        &self,
        ctx: &RequestContext,
        input: types::MeterUsageRequest,
    ) -> Result<types::MeterUsageResult, ServiceError> {
        ctx.authorize("aws-marketplace:MeterUsage", "*", ConditionContext::new())?;
        let product = self.catalog.product(&input.product_code).ok_or_else(invalid_product_code)?;
        if !product.has_dimension(&input.usage_dimension) {
            return Err(invalid_dimension());
        }
        let now = ctx.received_at;
        if input.timestamp < now - Duration::hours(6) || input.timestamp > now + FUTURE_SKEW {
            return Err(errors::timestamp_out_of_bounds(
                "The timestamp value passed in the request is out of allowed range.",
            ));
        }
        let quantity = input.usage_quantity.unwrap_or(0);
        let allocs = allocations(quantity, input.usage_allocations.as_deref())?;
        let subscription = self.entitlement_of(ctx, &product)?;
        if input.dry_run == Some(true) {
            return Err(ServiceError::client(
                "DryRunOperation",
                412,
                "Request would have succeeded, but DryRun flag is set.",
            ));
        }

        let reporter = ctx.caller.arn.clone();
        let hour = hour_of(input.timestamp);
        let mut st = self.lock();
        if let Some(token) = &input.client_token {
            if let Some(id) = st.client_tokens.get(token).cloned() {
                let same = st.records.iter().find(|r| r.metering_record_id == id).is_some_and(|r| {
                    r.product_code == input.product_code
                        && r.timestamp == input.timestamp
                        && r.dimension == input.usage_dimension
                        && r.quantity == quantity
                        && r.usage_allocations == allocs
                        && r.reported_by == reporter
                });
                if !same {
                    return Err(errors::idempotency_conflict("The ClientToken is being used for multiple requests."));
                }
                return Ok(types::MeterUsageResult { metering_record_id: Some(id) });
            }
        }
        // Once per reporting instance/task/pod, dimension and hour.
        let earlier = st.records.iter().find(|r| {
            r.operation == "MeterUsage"
                && r.reported_by == reporter
                && r.product_code == input.product_code
                && r.dimension == input.usage_dimension
                && hour_of(r.timestamp) == hour
        });
        if let Some(r) = earlier {
            if r.quantity != quantity || r.usage_allocations != allocs {
                return Err(errors::duplicate_request(
                    "A metering record has already been emitted by the same EC2 instance, ECS task, or EKS pod for the given {usageDimension, timestamp} with a different usageQuantity.",
                ));
            }
            let id = r.metering_record_id.clone();
            if let Some(token) = input.client_token {
                st.client_tokens.insert(token, id.clone());
            }
            return Ok(types::MeterUsageResult { metering_record_id: Some(id) });
        }
        let id = record_id();
        st.records.push(MeteringRecord {
            metering_record_id: id.clone(),
            operation: "MeterUsage".into(),
            product_code: input.product_code,
            customer_identifier: subscription.as_ref().map(|s| s.customer_identifier.clone()),
            customer_aws_account_id: ctx.caller.account_id.clone(),
            license_arn: subscription.map(|s| s.license_arn),
            dimension: input.usage_dimension,
            quantity,
            timestamp: input.timestamp,
            usage_allocations: allocs,
            reported_by: reporter,
            client_token: input.client_token.clone(),
            recorded_at: now,
        });
        if let Some(token) = input.client_token {
            st.client_tokens.insert(token, id.clone());
        }
        let accepted: Vec<MeteringRecord> = st.records.last().cloned().into_iter().collect();
        drop(st);
        self.report_accepted(&ctx.region, accepted);
        Ok(types::MeterUsageResult { metering_record_id: Some(id) })
    }

    async fn batch_meter_usage(
        &self,
        ctx: &RequestContext,
        input: types::BatchMeterUsageRequest,
    ) -> Result<types::BatchMeterUsageResult, ServiceError> {
        ctx.authorize("aws-marketplace:BatchMeterUsage", "*", ConditionContext::new())?;
        let seller = ctx.caller.account_id.clone();
        let now = ctx.received_at;
        // Legacy integrations name the product; Concurrent Agreements
        // integrations name a license per record instead.
        let batch_product = match input.product_code.as_str() {
            "" => None,
            code => Some(
                self.catalog
                    .product(code)
                    .filter(|p| p.seller_account_id == seller)
                    .ok_or_else(invalid_product_code)?,
            ),
        };
        let month_start = Utc.with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0).single().unwrap_or(now);
        let past_grace = now >= month_start + Duration::hours(6);

        // The whole batch fails on any invalid record.
        let mut resolved = Vec::with_capacity(input.usage_records.len());
        for rec in &input.usage_records {
            let by_license = match rec.license_arn.as_deref() {
                Some(arn) => Some(self.catalog.subscription_by_license(arn).ok_or_else(invalid_license)?),
                None => None,
            };
            let product = match (&batch_product, &by_license) {
                (Some(p), Some(s)) if s.product_code != p.product_code => return Err(invalid_license()),
                (Some(p), _) => p.clone(),
                (None, Some(s)) => self
                    .catalog
                    .product(&s.product_code)
                    .filter(|p| p.seller_account_id == seller)
                    .ok_or_else(invalid_license)?,
                (None, None) => return Err(invalid_product_code()),
            };
            let (subscription, customer_account) = if !rec.customer_identifier.is_empty() {
                let s = self
                    .catalog
                    .subscription(&rec.customer_identifier)
                    .filter(|s| s.product_code == product.product_code)
                    .ok_or_else(invalid_customer)?;
                if rec.customer_aws_account_id.as_ref().is_some_and(|a| a != &s.customer_aws_account_id) {
                    return Err(invalid_customer());
                }
                if by_license.as_ref().is_some_and(|l| l.customer_identifier != s.customer_identifier) {
                    return Err(invalid_license());
                }
                let account = s.customer_aws_account_id.clone();
                (Some(s), account)
            } else if let Some(account) = rec.customer_aws_account_id.clone() {
                match by_license {
                    Some(l) if l.customer_aws_account_id != account => return Err(invalid_license()),
                    Some(l) => (Some(l), account),
                    None => {
                        (self.catalog.subscriptions_of(&product.product_code, &account).into_iter().next(), account)
                    }
                }
            } else {
                return Err(invalid_customer());
            };
            if !product.has_dimension(&rec.dimension) {
                return Err(invalid_dimension());
            }
            let ts = rec.timestamp;
            if ts <= now - Duration::hours(24) || ts > now + FUTURE_SKEW || (past_grace && ts < month_start) {
                return Err(errors::timestamp_out_of_bounds(
                    "The timestamp value passed in the UsageRecord is out of allowed range.",
                ));
            }
            let allocs = allocations(rec.quantity.unwrap_or(0), rec.usage_allocations.as_deref())?;
            resolved.push(Resolved {
                input: rec,
                product_code: product.product_code.clone(),
                subscription,
                customer_account,
                allocations: allocs,
            });
        }

        let reporter = ctx.caller.arn.clone();
        let mut st = self.lock();
        let mut accepted = Vec::new();
        let mut results = Vec::with_capacity(resolved.len());
        for r in resolved {
            let quantity = r.input.quantity.unwrap_or(0);
            let result = |status: &str, id: Option<String>| types::UsageRecordResult {
                usage_record: Some(r.input.clone()),
                metering_record_id: id,
                status: Some(status.to_string()),
            };
            let Some(sub) = r.subscription.as_ref().filter(|s| s.is_active()) else {
                results.push(result("CustomerNotSubscribed", None));
                continue;
            };
            // One record per customer, dimension and hour; resending the
            // same record is idempotent.
            let hour = hour_of(r.input.timestamp);
            let earlier = st.records.iter().find(|e| {
                e.operation == "BatchMeterUsage"
                    && e.product_code == r.product_code
                    && e.customer_identifier.as_deref() == Some(sub.customer_identifier.as_str())
                    && e.dimension == r.input.dimension
                    && hour_of(e.timestamp) == hour
            });
            if let Some(e) = earlier {
                if e.quantity == quantity && e.usage_allocations == r.allocations && e.timestamp == r.input.timestamp {
                    results.push(result("Success", Some(e.metering_record_id.clone())));
                } else {
                    results.push(result("DuplicateRecord", None));
                }
                continue;
            }
            let id = record_id();
            st.records.push(MeteringRecord {
                metering_record_id: id.clone(),
                operation: "BatchMeterUsage".into(),
                product_code: r.product_code.clone(),
                customer_identifier: Some(sub.customer_identifier.clone()),
                customer_aws_account_id: r.customer_account.clone(),
                license_arn: Some(sub.license_arn.clone()),
                dimension: r.input.dimension.clone(),
                quantity,
                timestamp: r.input.timestamp,
                usage_allocations: r.allocations.clone(),
                reported_by: reporter.clone(),
                client_token: None,
                recorded_at: now,
            });
            accepted.push(st.records.last().cloned().expect("just pushed"));
            results.push(result("Success", Some(id)));
        }
        drop(st);
        self.report_accepted(&ctx.region, accepted);
        Ok(types::BatchMeterUsageResult { results: Some(results), unprocessed_records: Some(Vec::new()) })
    }

    async fn register_usage(
        &self,
        ctx: &RequestContext,
        input: types::RegisterUsageRequest,
    ) -> Result<types::RegisterUsageResult, ServiceError> {
        ctx.authorize("aws-marketplace:RegisterUsage", "*", ConditionContext::new())?;
        let product = self.catalog.product(&input.product_code).ok_or_else(invalid_product_code)?;
        if input.public_key_version != PUBLIC_KEY_VERSION {
            return Err(errors::invalid_public_key_version("Public Key version is invalid."));
        }
        let reporter = ctx.caller.arn.clone();
        // Entitlement is checked when a task or pod first registers; later
        // calls from it succeed even if the buyer has since unsubscribed.
        let registered_before = self
            .lock()
            .registrations
            .iter()
            .any(|r| r.product_code == product.product_code && r.registered_by == reporter);
        let subscription = if registered_before {
            self.catalog.subscriptions_of(&product.product_code, &ctx.caller.account_id).into_iter().next()
        } else {
            self.entitlement_of(ctx, &product)?
        };
        let now = ctx.received_at;
        let customer_identifier = subscription.as_ref().map(|s| s.customer_identifier.clone());
        let claims = serde_json::json!({
            "productCode": product.product_code,
            "publicKeyVersion": PUBLIC_KEY_VERSION,
            "customerIdentifier": customer_identifier,
            "customerAWSAccountId": ctx.caller.account_id,
            "nonce": input.nonce,
            "iat": now.timestamp(),
        });
        let mut st = self.lock();
        let signature = signing::sign_jwt(&mut st, &claims)?;
        st.registrations.push(Registration {
            product_code: product.product_code,
            customer_aws_account_id: ctx.caller.account_id.clone(),
            customer_identifier,
            nonce: input.nonce,
            registered_by: reporter,
            registered_at: now,
        });
        Ok(types::RegisterUsageResult { public_key_rotation_timestamp: None, signature: Some(signature) })
    }
}
