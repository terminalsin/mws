//! `GetEntitlements`.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::catalog::EntitlementValue;
use crate::generated::{errors, types, Handler};
use crate::{grant_is_current, Entitlement};

const PAGE_SIZE: usize = 25;

fn invalid(message: &str) -> ServiceError {
    errors::invalid_parameter(message)
}

fn encode_token(offset: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{{\"offset\":{offset}}}"))
}

fn decode_token(token: &str) -> Option<usize> {
    let raw = base64::engine::general_purpose::STANDARD.decode(token).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get("offset")?.as_u64().map(|n| n as usize)
}

fn wire_value(v: &EntitlementValue) -> types::EntitlementValue {
    let mut out = types::EntitlementValue::default();
    match v {
        EntitlementValue::IntegerValue(n) => out.integer_value = Some(*n),
        EntitlementValue::DoubleValue(n) => out.double_value = Some(*n),
        EntitlementValue::BooleanValue(b) => out.boolean_value = Some(*b),
        EntitlementValue::StringValue(s) => out.string_value = Some(s.clone()),
    }
    out
}

#[async_trait::async_trait]
impl Handler for Entitlement {
    async fn get_entitlements(
        &self,
        ctx: &RequestContext,
        input: types::GetEntitlementsRequest,
    ) -> Result<types::GetEntitlementsResult, ServiceError> {
        ctx.authorize("aws-marketplace:GetEntitlements", "*", ConditionContext::new())?;
        let filters = input.filter.unwrap_or_default();
        if filters.contains_key("CUSTOMER_IDENTIFIER") && filters.contains_key("CUSTOMER_AWS_ACCOUNT_ID") {
            return Err(invalid("CustomerIdentifier and CustomerAWSAccountId are mutually exclusive. Use one or the other, but not both."));
        }
        let offset = match &input.next_token {
            Some(t) => decode_token(t).ok_or_else(|| invalid("The NextToken is invalid."))?,
            None => 0,
        };
        let page = input.max_results.map_or(PAGE_SIZE, |n| n as usize);
        let now = ctx.received_at;

        let cat = self.lock();
        // Only the seller that listed a product can read its entitlements.
        let product = cat
            .products
            .get(&input.product_code)
            .filter(|p| p.seller_account_id == ctx.caller.account_id)
            .ok_or_else(|| invalid("The product code is invalid."))?;
        let matches = |key: &str, value: &str| filters.get(key).is_none_or(|vals| vals.iter().any(|v| v == value));

        let mut subs: Vec<_> =
            cat.subscriptions.values().filter(|s| s.product_code == product.product_code && s.is_active()).collect();
        subs.sort_by(|a, b| (a.subscribed_at, &a.customer_identifier).cmp(&(b.subscribed_at, &b.customer_identifier)));
        let all: Vec<types::Entitlement> = subs
            .into_iter()
            .filter(|s| matches("CUSTOMER_IDENTIFIER", &s.customer_identifier))
            .filter(|s| matches("CUSTOMER_AWS_ACCOUNT_ID", &s.customer_aws_account_id))
            .filter(|s| matches("LICENSE_ARN", &s.license_arn))
            .flat_map(|s| {
                s.entitlements.iter().filter(|g| grant_is_current(g, now) && matches("DIMENSION", &g.dimension)).map(
                    move |g| types::Entitlement {
                        product_code: Some(s.product_code.clone()),
                        dimension: Some(g.dimension.clone()),
                        customer_identifier: Some(s.customer_identifier.clone()),
                        customer_aws_account_id: Some(s.customer_aws_account_id.clone()),
                        value: Some(wire_value(&g.value)),
                        expiration_date: g.expiration_date,
                        license_arn: Some(s.license_arn.clone()),
                    },
                )
            })
            .collect();
        if offset > all.len() {
            return Err(invalid("The NextToken is invalid."));
        }
        let end = (offset + page).min(all.len());
        Ok(types::GetEntitlementsResult {
            entitlements: Some(all[offset..end].to_vec()),
            next_token: (end < all.len()).then(|| encode_token(end)),
        })
    }
}
