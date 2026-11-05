//! AWS Marketplace Entitlement Service for MWS, and the Marketplace catalog
//! it reads.
//!
//! `GetEntitlements` answers a seller with the active entitlements of
//! buyers subscribed to one of their products, filtered and paginated as
//! AWS does. The catalog behind it (products, subscriptions with their
//! license ARNs and agreement ids, entitlements, SaaS registration tokens)
//! has no SDK operations in AWS, so tests seed it through the control API
//! at `/_aws/marketplace/` ([`control`]). Marketplace Metering
//! (`mws-marketplace-metering`) reads the same catalog through
//! [`Entitlement`]'s public methods.
//!
//! Both Marketplace services sign as `aws-marketplace`; this one claims
//! requests whose `X-Amz-Target` (awsJson1.1) or rpcv2Cbor path names
//! `AWSMPEntitlementService`.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/entitlement_generated.rs"));
}

pub mod catalog;
pub mod control;
mod handler;

use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use catalog::{
    Catalog, Dimension, EntitlementGrant, EntitlementValue, Product, ProductType, Subscription, SubscriptionStatus,
};

/// Why a registration token did not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Unknown, malformed, or for a product another seller owns.
    Invalid,
    Expired,
}

/// The Entitlement Service and the Marketplace catalog. Cheap to clone;
/// clones share state.
#[derive(Clone)]
pub struct Entitlement {
    catalog: Arc<Mutex<Catalog>>,
    /// The seller account the control API assumes when none is given.
    default_account: String,
}

impl Entitlement {
    /// `default_account` is the seller of products listed without a
    /// `sellerAccountId` (MWS's default account).
    pub fn new(default_account: impl Into<String>) -> Self {
        Self { catalog: Arc::default(), default_account: default_account.into() }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Catalog> {
        self.catalog.lock().expect("Marketplace catalog lock poisoned")
    }

    /// A listed product.
    pub fn product(&self, product_code: &str) -> Option<Product> {
        self.lock().products.get(product_code).cloned()
    }

    /// A subscription by its customer identifier.
    pub fn subscription(&self, customer_identifier: &str) -> Option<Subscription> {
        self.lock().subscriptions.get(customer_identifier).cloned()
    }

    /// The subscription a license was granted for.
    pub fn subscription_by_license(&self, license_arn: &str) -> Option<Subscription> {
        self.lock().subscription_by_license(license_arn).cloned()
    }

    /// Every subscription (active or not) of `account` to `product_code`,
    /// active ones first, then oldest first.
    pub fn subscriptions_of(&self, product_code: &str, account: &str) -> Vec<Subscription> {
        let cat = self.lock();
        let mut subs: Vec<Subscription> = cat
            .subscriptions
            .values()
            .filter(|s| s.product_code == product_code && s.customer_aws_account_id == account)
            .cloned()
            .collect();
        subs.sort_by_key(|s| (!s.is_active(), s.subscribed_at));
        subs
    }

    /// The oldest active subscription of `account` to `product_code`.
    pub fn active_subscription(&self, product_code: &str, account: &str) -> Option<Subscription> {
        self.lock().active_subscriptions(product_code, account).next().cloned()
    }

    /// Resolve a SaaS registration token for `seller_account` at `now`.
    /// Tokens stay valid until they expire, like AWS's; a token for a
    /// product another seller owns is invalid to this one.
    pub fn resolve_token(
        &self,
        token: &str,
        seller_account: &str,
        now: DateTime<Utc>,
    ) -> Result<(Subscription, Product), TokenError> {
        let cat = self.lock();
        let t = cat.registration_tokens.get(token).ok_or(TokenError::Invalid)?;
        let sub = cat.subscriptions.get(&t.customer_identifier).ok_or(TokenError::Invalid)?;
        let product = cat.products.get(&sub.product_code).ok_or(TokenError::Invalid)?;
        if product.seller_account_id != seller_account {
            return Err(TokenError::Invalid);
        }
        if t.expires_at.is_some_and(|e| e <= now) {
            return Err(TokenError::Expired);
        }
        Ok((sub.clone(), product.clone()))
    }

    fn handles(request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
            || mws_proto_cbor::targets(generated::CBOR_SERVICE, request)
    }
}

/// `ExpirationDate` still ahead, or none.
pub fn grant_is_current(grant: &EntitlementGrant, now: DateTime<Utc>) -> bool {
    grant.expiration_date.is_none_or(|e| e > now)
}

#[async_trait::async_trait]
impl Service for Entitlement {
    fn signing_name(&self) -> &'static str {
        "aws-marketplace"
    }

    fn name(&self) -> &'static str {
        "marketplace-entitlement"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        Self::handles(request)
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        Self::handles(request)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(control::PREFIX)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some(response) = self.serve_control(&ctx, &request) {
            return response;
        }
        if mws_proto_cbor::is_cbor(&request) {
            generated::dispatch_cbor(self, &ctx, &request).await
        } else {
            generated::dispatch(self, &ctx, &request).await
        }
    }

    /// Current SDKs speak rpcv2Cbor to this service, so errors raised
    /// before dispatch (authentication) are rendered in it.
    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_cbor::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let cat = self.lock().clone();
        Some(serde_json::to_value(cat).expect("Marketplace catalog serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let cat: Catalog =
            serde_json::from_value(state).map_err(|e| format!("invalid Marketplace Entitlement state: {e}"))?;
        *self.lock() = cat;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = Catalog::default();
    }
}
