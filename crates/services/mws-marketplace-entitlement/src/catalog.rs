//! The AWS Marketplace catalog MWS keeps in place of the real Marketplace:
//! products sellers have listed, the subscriptions (agreements) buyers have
//! accepted, the entitlements each subscription grants, and the
//! registration tokens a SaaS fulfillment page receives. AWS fills this
//! through the Marketplace Management Portal and buyers' purchases, which
//! have no SDK operations here, so tests seed it through the control API
//! ([`crate::control`]). Metering reads it through [`crate::Entitlement`].

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// The account AWS Marketplace grants licenses from; license ARNs name it.
pub const MARKETPLACE_LICENSE_ACCOUNT: &str = "294406891311";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Catalog {
    /// By product code.
    pub products: BTreeMap<String, Product>,
    /// By customer identifier.
    pub subscriptions: BTreeMap<String, Subscription>,
    /// By token.
    pub registration_tokens: BTreeMap<String, RegistrationToken>,
}

/// How a product is delivered, which decides the metering calls it uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProductType {
    /// SaaS: ResolveCustomer, BatchMeterUsage, GetEntitlements.
    #[default]
    #[serde(rename = "SaaS", alias = "SAAS", alias = "saas")]
    Saas,
    /// AMI: MeterUsage from the buyer's instances.
    #[serde(rename = "AMI", alias = "ami")]
    Ami,
    /// Containers: RegisterUsage or MeterUsage from the buyer's tasks/pods.
    #[serde(rename = "Container", alias = "container", alias = "CONTAINER")]
    Container,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Product {
    pub product_code: String,
    pub seller_account_id: String,
    pub title: String,
    pub product_type: ProductType,
    /// The pricing dimensions (API names) metering and entitlements use.
    pub dimensions: Vec<Dimension>,
    pub created_at: Option<DateTime<Utc>>,
}

impl Product {
    pub fn has_dimension(&self, name: &str) -> bool {
        self.dimensions.iter().any(|d| d.name == name)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Dimension {
    pub name: String,
    pub description: Option<String>,
    /// What the buyer pays per unit, in USD (Cost Explorer charges
    /// metered usage at it; none means no charge).
    pub price: Option<f64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionStatus {
    #[default]
    Active,
    /// The buyer cancelled; metering reports `CustomerNotSubscribed` and
    /// GetEntitlements no longer lists it.
    Unsubscribed,
}

/// One buyer's agreement for one product.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Subscription {
    pub customer_identifier: String,
    #[serde(rename = "customerAWSAccountId", alias = "customerAwsAccountId")]
    pub customer_aws_account_id: String,
    pub product_code: String,
    pub license_arn: String,
    pub agreement_id: String,
    pub status: SubscriptionStatus,
    pub subscribed_at: Option<DateTime<Utc>>,
    pub unsubscribed_at: Option<DateTime<Utc>>,
    pub entitlements: Vec<EntitlementGrant>,
}

impl Subscription {
    pub fn is_active(&self) -> bool {
        self.status == SubscriptionStatus::Active
    }
}

/// Capacity a subscription grants in one dimension.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EntitlementGrant {
    pub dimension: String,
    pub value: EntitlementValue,
    pub expiration_date: Option<DateTime<Utc>>,
}

/// Exactly one of the four kinds of value AWS reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EntitlementValue {
    IntegerValue(i32),
    DoubleValue(f64),
    BooleanValue(bool),
    StringValue(String),
}

impl Default for EntitlementValue {
    fn default() -> Self {
        Self::BooleanValue(true)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RegistrationToken {
    pub registration_token: String,
    pub customer_identifier: String,
    pub expires_at: Option<DateTime<Utc>>,
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const LOWER36: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

fn random_from(alphabet: &[u8], len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char).collect()
}

/// A product code as AWS assigns them: 25 lowercase letters and digits.
pub fn new_product_code() -> String {
    random_from(LOWER36, 25)
}

/// A customer identifier: an opaque 11-character handle.
pub fn new_customer_identifier() -> String {
    random_from(BASE62, 11)
}

/// `arn:aws:license-manager::294406891311:license:l-<32 hex>`.
pub fn new_license_arn(partition: &str) -> String {
    format!(
        "arn:{partition}:license-manager::{MARKETPLACE_LICENSE_ACCOUNT}:license:l-{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// `agmt-` and 26 alphanumerics, the shape of Marketplace agreement ids.
pub fn new_agreement_id() -> String {
    format!("agmt-{}", random_from(LOWER36, 26))
}

/// An opaque registration token, as long and as URL-unsafe as real ones.
pub fn new_registration_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 96];
    rand::thread_rng().fill(&mut bytes[..]);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl Catalog {
    /// The active subscriptions of `account` to `product_code`, oldest first.
    pub fn active_subscriptions<'a>(
        &'a self,
        product_code: &'a str,
        account: &'a str,
    ) -> impl Iterator<Item = &'a Subscription> + 'a {
        let mut subs: Vec<&Subscription> = self
            .subscriptions
            .values()
            .filter(move |s| s.product_code == product_code && s.customer_aws_account_id == account && s.is_active())
            .collect();
        subs.sort_by_key(|s| s.subscribed_at);
        subs.into_iter()
    }

    pub fn subscription_by_license(&self, license_arn: &str) -> Option<&Subscription> {
        self.subscriptions.values().find(|s| s.license_arn == license_arn)
    }
}
