//! The Marketplace control API, served unsigned at `/_aws/marketplace/`.
//! It stands in for the Marketplace Management Portal (sellers listing
//! products) and for buyers subscribing, neither of which has an SDK
//! operation. Bodies and answers are JSON with camelCase members.
//!
//! | Request | Effect |
//! |---|---|
//! | `GET /_aws/marketplace/products` | list products |
//! | `POST /_aws/marketplace/products` | list a product: `{"sellerAccountId", "productType": "SaaS"\|"AMI"\|"Container", "dimensions": [{"name"}], "productCode"?, "title"?}` |
//! | `GET /_aws/marketplace/products/{code}` | one product |
//! | `DELETE /_aws/marketplace/products/{code}` | delist it and drop its subscriptions |
//! | `GET /_aws/marketplace/subscriptions[?productCode=&customerAWSAccountId=]` | list subscriptions |
//! | `POST /_aws/marketplace/subscriptions` | a buyer subscribes: `{"productCode", "customerAWSAccountId", "entitlements": [{"dimension", "value": {"integerValue": 10}, "expirationDate"?}], "customerIdentifier"?, "licenseArn"?, "agreementId"?}`; the answer carries a `registrationToken` |
//! | `GET /_aws/marketplace/subscriptions/{customerIdentifier}` | one subscription |
//! | `DELETE /_aws/marketplace/subscriptions/{customerIdentifier}` | the buyer unsubscribes |
//! | `PUT /_aws/marketplace/subscriptions/{customerIdentifier}/entitlements` | replace its entitlements: `{"entitlements": [...]}` |
//! | `POST /_aws/marketplace/registration-tokens` | a new token for the SaaS landing page: `{"customerIdentifier", "expiresInSeconds"?}` |

use bytes::Bytes;
use chrono::{DateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, RequestContext};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::catalog::{self, Dimension, EntitlementGrant, Product, ProductType, Subscription, SubscriptionStatus};
use crate::Entitlement;

pub const PREFIX: &str = "/_aws/marketplace/";

/// Registration tokens last this long unless the request says otherwise.
pub const DEFAULT_TOKEN_LIFETIME_SECONDS: i64 = 3600;

fn respond(status: u16, body: Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from(body.to_string()))
        .expect("static response parts are valid")
}

fn bad(message: impl Into<String>) -> HttpResponse {
    respond(400, json!({ "message": message.into() }))
}

fn not_found(message: impl Into<String>) -> HttpResponse {
    respond(404, json!({ "message": message.into() }))
}

fn query(request: &HttpRequest, name: &str) -> Option<String> {
    let q = request.uri().query()?;
    form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

fn body<T: for<'de> Deserialize<'de>>(request: &HttpRequest) -> Result<T, String> {
    let raw: &[u8] = if request.body().is_empty() { b"{}" } else { request.body() };
    serde_json::from_slice(raw).map_err(|e| format!("invalid request body: {e}"))
}

fn valid_account(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewProduct {
    product_code: Option<String>,
    seller_account_id: Option<String>,
    title: Option<String>,
    #[serde(default)]
    product_type: ProductType,
    #[serde(default)]
    dimensions: Vec<Dimension>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewSubscription {
    product_code: String,
    #[serde(rename = "customerAWSAccountId", alias = "customerAwsAccountId")]
    customer_aws_account_id: String,
    customer_identifier: Option<String>,
    license_arn: Option<String>,
    agreement_id: Option<String>,
    #[serde(default)]
    entitlements: Vec<EntitlementGrant>,
    token_expires_in_seconds: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entitlements {
    #[serde(default)]
    entitlements: Vec<EntitlementGrant>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewToken {
    customer_identifier: String,
    expires_in_seconds: Option<i64>,
}

fn check_grants(product: &Product, grants: &[EntitlementGrant]) -> Result<(), String> {
    for g in grants {
        if !product.has_dimension(&g.dimension) {
            return Err(format!(
                "dimension {:?} is not one of product {}'s dimensions",
                g.dimension, product.product_code
            ));
        }
    }
    Ok(())
}

impl Entitlement {
    pub(crate) fn serve_control(&self, ctx: &RequestContext, request: &HttpRequest) -> Option<HttpResponse> {
        let rest = request.uri().path().strip_prefix(PREFIX)?;
        let segments: Vec<String> = rest
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned())
            .collect();
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        let now = ctx.received_at;
        let method = request.method().clone();
        Some(match (method, segments.as_slice()) {
            (http::Method::GET, ["products"]) => {
                let cat = self.lock();
                respond(200, json!({ "products": cat.products.values().collect::<Vec<_>>() }))
            }
            (http::Method::POST, ["products"]) => match body::<NewProduct>(request) {
                Ok(p) => self.create_product(ctx, p, now),
                Err(r) => bad(r),
            },
            (http::Method::GET, ["products", code]) => match self.lock().products.get(*code) {
                Some(p) => respond(200, json!(p)),
                None => not_found(format!("no product {code}")),
            },
            (http::Method::DELETE, ["products", code]) => {
                let mut cat = self.lock();
                if cat.products.remove(*code).is_none() {
                    return Some(not_found(format!("no product {code}")));
                }
                let gone: Vec<String> = cat
                    .subscriptions
                    .values()
                    .filter(|s| s.product_code == *code)
                    .map(|s| s.customer_identifier.clone())
                    .collect();
                for id in &gone {
                    cat.subscriptions.remove(id);
                }
                cat.registration_tokens.retain(|_, t| !gone.contains(&t.customer_identifier));
                respond(200, json!({}))
            }
            (http::Method::GET, ["subscriptions"]) => {
                let product = query(request, "productCode");
                let account = query(request, "customerAWSAccountId");
                let cat = self.lock();
                let list: Vec<&Subscription> = cat
                    .subscriptions
                    .values()
                    .filter(|s| product.as_ref().is_none_or(|p| &s.product_code == p))
                    .filter(|s| account.as_ref().is_none_or(|a| &s.customer_aws_account_id == a))
                    .collect();
                respond(200, json!({ "subscriptions": list }))
            }
            (http::Method::POST, ["subscriptions"]) => match body::<NewSubscription>(request) {
                Ok(s) => self.subscribe(ctx, s, now),
                Err(r) => bad(r),
            },
            (http::Method::GET, ["subscriptions", id]) => match self.lock().subscriptions.get(*id) {
                Some(s) => respond(200, json!(s)),
                None => not_found(format!("no subscription for customer {id}")),
            },
            (http::Method::DELETE, ["subscriptions", id]) => {
                let mut cat = self.lock();
                let Some(s) = cat.subscriptions.get_mut(*id) else {
                    return Some(not_found(format!("no subscription for customer {id}")));
                };
                if s.is_active() {
                    s.status = SubscriptionStatus::Unsubscribed;
                    s.unsubscribed_at = Some(now);
                }
                respond(200, json!(s))
            }
            (http::Method::PUT, ["subscriptions", id, "entitlements"]) => {
                let grants = match body::<Entitlements>(request) {
                    Ok(e) => e.entitlements,
                    Err(r) => return Some(bad(r)),
                };
                let mut cat = self.lock();
                let Some(product_code) = cat.subscriptions.get(*id).map(|s| s.product_code.clone()) else {
                    return Some(not_found(format!("no subscription for customer {id}")));
                };
                if let Some(product) = cat.products.get(&product_code) {
                    if let Err(r) = check_grants(product, &grants) {
                        return Some(bad(r));
                    }
                }
                let s = cat.subscriptions.get_mut(*id).expect("checked above");
                s.entitlements = grants;
                respond(200, json!(s))
            }
            (http::Method::POST, ["registration-tokens"]) => match body::<NewToken>(request) {
                Ok(t) => {
                    let mut cat = self.lock();
                    if !cat.subscriptions.contains_key(&t.customer_identifier) {
                        return Some(not_found(format!("no subscription for customer {}", t.customer_identifier)));
                    }
                    let token = issue_token(&mut cat, &t.customer_identifier, now, t.expires_in_seconds);
                    respond(200, json!(token))
                }
                Err(r) => bad(r),
            },
            _ => not_found("not found"),
        })
    }

    fn create_product(&self, ctx: &RequestContext, p: NewProduct, now: DateTime<Utc>) -> HttpResponse {
        let seller = p.seller_account_id.unwrap_or_else(|| self.default_account.clone());
        if !valid_account(&seller) {
            return bad("sellerAccountId must be a 12-digit AWS account id");
        }
        let code = p.product_code.unwrap_or_else(catalog::new_product_code);
        if code.is_empty()
            || code.len() > 255
            || !code.bytes().all(|b| b.is_ascii_alphanumeric() || b"-/=:_.@".contains(&b))
        {
            return bad("productCode must be 1-255 characters of [-a-zA-Z0-9/=:_.@]");
        }
        let mut seen = std::collections::BTreeSet::new();
        for d in &p.dimensions {
            if d.name.is_empty() || d.name.len() > 255 {
                return bad("dimension names must be 1-255 characters");
            }
            if !seen.insert(d.name.clone()) {
                return bad(format!("duplicate dimension {:?}", d.name));
            }
        }
        let mut cat = self.lock();
        if cat.products.contains_key(&code) {
            return respond(409, json!({ "message": format!("product {code} already exists") }));
        }
        let product = Product {
            product_code: code.clone(),
            seller_account_id: seller,
            title: p.title.unwrap_or_else(|| code.clone()),
            product_type: p.product_type,
            dimensions: p.dimensions,
            created_at: Some(now),
        };
        let _ = ctx;
        cat.products.insert(code, product.clone());
        respond(200, json!(product))
    }

    fn subscribe(&self, ctx: &RequestContext, s: NewSubscription, now: DateTime<Utc>) -> HttpResponse {
        if !valid_account(&s.customer_aws_account_id) {
            return bad("customerAWSAccountId must be a 12-digit AWS account id");
        }
        let mut cat = self.lock();
        let Some(product) = cat.products.get(&s.product_code) else {
            return not_found(format!("no product {}", s.product_code));
        };
        if let Err(r) = check_grants(product, &s.entitlements) {
            return bad(r);
        }
        let id = s.customer_identifier.unwrap_or_else(catalog::new_customer_identifier);
        if id.is_empty() || id.chars().any(char::is_whitespace) {
            return bad("customerIdentifier must be non-empty and contain no whitespace");
        }
        if cat.subscriptions.contains_key(&id) {
            return respond(409, json!({ "message": format!("customer {id} already has a subscription") }));
        }
        let license_arn = s.license_arn.unwrap_or_else(|| catalog::new_license_arn(&ctx.partition));
        if cat.subscription_by_license(&license_arn).is_some() {
            return respond(409, json!({ "message": format!("license {license_arn} is already granted") }));
        }
        let sub = Subscription {
            customer_identifier: id.clone(),
            customer_aws_account_id: s.customer_aws_account_id,
            product_code: s.product_code,
            license_arn,
            agreement_id: s.agreement_id.unwrap_or_else(catalog::new_agreement_id),
            status: SubscriptionStatus::Active,
            subscribed_at: Some(now),
            unsubscribed_at: None,
            entitlements: s.entitlements,
        };
        cat.subscriptions.insert(id.clone(), sub.clone());
        let token = issue_token(&mut cat, &id, now, s.token_expires_in_seconds);
        let mut out = json!(sub);
        out["registrationToken"] = json!(token.registration_token);
        out["registrationTokenExpiresAt"] = json!(token.expires_at);
        respond(200, out)
    }
}

fn issue_token(
    cat: &mut catalog::Catalog,
    customer_identifier: &str,
    now: DateTime<Utc>,
    expires_in: Option<i64>,
) -> catalog::RegistrationToken {
    // Drop tokens that expired a day ago so the catalog does not grow.
    // `expiresInSeconds: 0` means the token never expires; a negative value
    // makes one that has already expired.
    cat.registration_tokens.retain(|_, t| t.expires_at.is_none_or(|e| e + chrono::Duration::days(1) > now));
    let seconds = expires_in.unwrap_or(DEFAULT_TOKEN_LIFETIME_SECONDS);
    let token = catalog::RegistrationToken {
        registration_token: catalog::new_registration_token(),
        customer_identifier: customer_identifier.to_string(),
        expires_at: (seconds != 0).then(|| now + chrono::Duration::seconds(seconds)),
    };
    cat.registration_tokens.insert(token.registration_token.clone(), token.clone());
    token
}
