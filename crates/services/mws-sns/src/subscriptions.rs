//! Subscriptions: subscribing, confirming, attributes and listing.

use std::collections::BTreeMap;

use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::names::{self, account_of, arn_parts};
use crate::state::{State, Subscription};
use crate::topics::{paginate, DEFAULT_DELIVERY_POLICY};
use crate::{errors, filter, Sns};

const PAGE: usize = 100;
const PROTOCOLS: &[&str] = &["http", "https", "email", "email-json", "sms", "sqs", "application", "lambda", "firehose"];
const SETTABLE: &[&str] = &[
    "DeliveryPolicy",
    "FilterPolicy",
    "FilterPolicyScope",
    "RawMessageDelivery",
    "RedrivePolicy",
    "SubscriptionRoleArn",
    "ReplayPolicy",
];
/// How long a confirmation token stays valid: three days.
const TOKEN_TTL_MS: i64 = 3 * 24 * 3600 * 1000;

fn check_endpoint(st: &State, protocol: &str, endpoint: &str) -> Result<(), ServiceError> {
    let service_arn = |service: &str, resource_prefix: &str| {
        arn_parts(endpoint).is_some_and(|(s, r, a, res)| {
            s == service
                && !r.is_empty()
                && a.len() == 12
                && res.starts_with(resource_prefix)
                && res.len() > resource_prefix.len()
        })
    };
    let ok = match protocol {
        "http" => endpoint.starts_with("http://") && endpoint.len() > 7,
        "https" => endpoint.starts_with("https://") && endpoint.len() > 8,
        "email" | "email-json" => {
            let (local, domain) = endpoint.split_once('@').unwrap_or(("", ""));
            if local.is_empty() || !domain.contains('.') || endpoint.contains(char::is_whitespace) {
                return Err(errors::invalid("Email address"));
            }
            true
        }
        "sms" => {
            let digits: String = endpoint.chars().filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '.')).collect();
            if !names::valid_phone_number(&digits) && !(digits.len() >= 7 && digits.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(errors::invalid(format!("Invalid SMS endpoint: {endpoint}")));
            }
            true
        }
        "sqs" => {
            if !service_arn("sqs", "") {
                return Err(errors::invalid("SQS endpoint ARN"));
            }
            true
        }
        "lambda" => {
            if !service_arn("lambda", "function:") {
                return Err(errors::invalid("Lambda endpoint ARN"));
            }
            true
        }
        "firehose" => {
            if !service_arn("firehose", "deliverystream/") {
                return Err(errors::invalid("Firehose endpoint ARN"));
            }
            true
        }
        "application" => {
            if !st.endpoints.contains_key(endpoint) {
                return Err(errors::invalid(format!("Application endpoint arn invalid:{endpoint}")));
            }
            true
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(errors::invalid("Endpoint must match the specified protocol"))
    }
}

/// Check one subscription attribute against the subscription it is for.
pub(crate) fn validate_attribute(
    name: &str,
    value: &str,
    protocol: &str,
    attributes: &BTreeMap<String, String>,
) -> Result<(), ServiceError> {
    match name {
        "RawMessageDelivery" => {
            if !matches!(value.to_ascii_lowercase().as_str(), "true" | "false") {
                return Err(errors::invalid("RawMessageDelivery: Invalid value"));
            }
            if !matches!(protocol, "sqs" | "http" | "https" | "firehose") && value.eq_ignore_ascii_case("true") {
                return Err(errors::invalid(format!(
                    "Delivery protocol [{protocol}] does not support raw message delivery."
                )));
            }
        }
        "FilterPolicy" => {
            if !value.is_empty() {
                let body = attributes.get("FilterPolicyScope").is_some_and(|s| s == "MessageBody");
                filter::validate(value, body)?;
            }
        }
        "FilterPolicyScope" => {
            if !matches!(value, "MessageAttributes" | "MessageBody") {
                return Err(errors::invalid(format!(
                    "FilterPolicyScope: Invalid value [{value}]. Please use either MessageBody or MessageAttributes"
                )));
            }
            if let Some(p) = attributes.get("FilterPolicy").filter(|p| !p.is_empty()) {
                filter::validate(p, value == "MessageBody")?;
            }
        }
        "RedrivePolicy" => {
            if !value.is_empty() {
                let v: serde_json::Value =
                    serde_json::from_str(value).map_err(|_| errors::invalid("RedrivePolicy: failed to parse JSON."))?;
                let target = v.get("deadLetterTargetArn").and_then(|t| t.as_str()).unwrap_or("");
                if !arn_parts(target).is_some_and(|(s, _, a, r)| s == "sqs" && a.len() == 12 && !r.is_empty()) {
                    return Err(errors::invalid("RedrivePolicy: deadLetterTargetArn is an invalid arn"));
                }
            }
        }
        "ReplayPolicy" => {
            if !value.is_empty() {
                crate::archive::parse_replay_policy(value)?;
            }
        }
        "DeliveryPolicy" => {
            if !value.is_empty() && !serde_json::from_str::<serde_json::Value>(value).is_ok_and(|v| v.is_object()) {
                return Err(errors::invalid(format!("{name}: failed to parse JSON.")));
            }
        }
        "SubscriptionRoleArn" => {
            if !value.is_empty() && !value.starts_with("arn:") {
                return Err(errors::invalid("SubscriptionRoleArn"));
            }
        }
        _ => return Err(errors::invalid("AttributeName")),
    }
    Ok(())
}

pub(crate) fn new_token() -> String {
    (0..4).map(|_| uuid::Uuid::new_v4().simple().to_string()).collect()
}

fn summary(s: &Subscription) -> types::Subscription {
    types::Subscription {
        subscription_arn: Some(if s.pending { "PendingConfirmation".to_string() } else { s.arn.clone() }),
        owner: Some(s.owner.clone()),
        protocol: Some(s.protocol.clone()),
        endpoint: Some(s.endpoint.clone()),
        topic_arn: Some(s.topic_arn.clone()),
    }
}

impl Sns {
    pub(crate) fn subscribe_impl(
        &self,
        ctx: &RequestContext,
        input: types::SubscribeInput,
    ) -> Result<types::SubscribeResponse, ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        let protocol = input.protocol.to_ascii_lowercase();
        let endpoint = input.endpoint.clone().unwrap_or_default();
        let mut c = ConditionContext::new();
        c.insert("sns:Protocol".into(), vec![protocol.clone()]);
        c.insert("sns:Endpoint".into(), vec![endpoint.clone()]);
        self.authorize_topic(ctx, "sns:Subscribe", &input.topic_arn, c)?;
        if !PROTOCOLS.contains(&protocol.as_str()) {
            return Err(errors::invalid(format!(
                "Amazon SNS does not support this protocol string: {}",
                input.protocol
            )));
        }
        if endpoint.is_empty() {
            return Err(errors::invalid("Endpoint"));
        }
        let attributes = input.attributes.unwrap_or_default();
        let account = account_of(ctx);
        let (sub, confirm) = {
            let mut st = self.lock();
            let topic = Self::topic(&st, &input.topic_arn)?;
            if topic.is_fifo() && !matches!(protocol.as_str(), "sqs" | "firehose") {
                return Err(errors::invalid(format!("Invalid protocol type: {protocol}")));
            }
            check_endpoint(&st, &protocol, &endpoint)?;
            for (k, v) in &attributes {
                if !SETTABLE.contains(&k.as_str()) {
                    return Err(errors::invalid(format!("Attributes Reason: Unknown attribute {k}")));
                }
                validate_attribute(k, v, &protocol, &attributes)?;
            }
            if attributes.get("ReplayPolicy").is_some_and(|p| !p.is_empty()) {
                Self::check_replay_target(topic)?;
            }
            if protocol == "firehose" && attributes.get("SubscriptionRoleArn").is_none_or(|r| r.is_empty()) {
                return Err(errors::invalid("Invalid parameter: SubscriptionRoleArn"));
            }
            let existing = st
                .subscriptions
                .values()
                .find(|s| s.topic_arn == input.topic_arn && s.protocol == protocol && s.endpoint == endpoint);
            if let Some(existing) = existing {
                let differs = attributes.iter().any(|(k, v)| existing.attributes.get(k) != Some(v));
                if differs {
                    return Err(errors::invalid(
                        "Attributes Reason: Subscription already exists with different attributes",
                    ));
                }
                let arn = if existing.pending && !input.return_subscription_arn {
                    "pending confirmation".to_string()
                } else {
                    existing.arn.clone()
                };
                return Ok(types::SubscribeResponse { subscription_arn: Some(arn) });
            }
            let needs_confirmation = match protocol.as_str() {
                "http" | "https" | "email" | "email-json" => true,
                // A queue in another account confirms by reading the
                // confirmation message, unless its owner subscribes it.
                "sqs" => arn_parts(&endpoint).is_some_and(|(_, _, a, _)| a != account),
                _ => false,
            };
            let mut stored = attributes.clone();
            stored.retain(|_, v| !v.is_empty());
            let sub = Subscription {
                arn: format!("{}:{}", input.topic_arn, uuid::Uuid::new_v4()),
                topic_arn: input.topic_arn.clone(),
                owner: account.clone(),
                protocol: protocol.clone(),
                endpoint: endpoint.clone(),
                attributes: stored,
                pending: needs_confirmation,
                token: needs_confirmation.then(new_token),
                authenticated: false,
                token_expires_ms: ctx.received_at.timestamp_millis() + TOKEN_TTL_MS,
                principal: ctx.caller.arn.clone(),
            };
            st.subscriptions.insert(sub.arn.clone(), sub.clone());
            let topic = Self::topic(&st, &input.topic_arn)?.clone();
            (sub, needs_confirmation.then_some(topic))
        };
        if sub.attributes.contains_key("ReplayPolicy") && !sub.pending {
            self.replay(ctx, &sub.arn);
        }
        if let Some(topic) = confirm {
            self.send_confirmation(ctx, &topic, &sub);
            let arn = if input.return_subscription_arn { sub.arn } else { "pending confirmation".to_string() };
            return Ok(types::SubscribeResponse { subscription_arn: Some(arn) });
        }
        Ok(types::SubscribeResponse { subscription_arn: Some(sub.arn) })
    }

    pub(crate) fn confirm_subscription_impl(
        &self,
        ctx: &RequestContext,
        input: types::ConfirmSubscriptionInput,
    ) -> Result<types::ConfirmSubscriptionResponse, ServiceError> {
        let anonymous = matches!(ctx.caller.kind, CallerKind::Anonymous);
        // The SubscribeURL is unsigned and carries the topic's own region.
        if anonymous {
            names::parse_sns_arn(&input.topic_arn).ok_or_else(|| errors::invalid("TopicArn"))?;
        } else {
            names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        }
        if !anonymous {
            self.authorize_topic(ctx, "sns:ConfirmSubscription", &input.topic_arn, ConditionContext::new())?;
        }
        let authenticate = input.authenticate_on_unsubscribe.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if authenticate && anonymous {
            return Err(errors::invalid("AuthenticateOnUnsubscribe Reason: requires a signed request"));
        }
        let mut st = self.lock();
        Self::topic(&st, &input.topic_arn)?;
        let now = ctx.received_at.timestamp_millis();
        let sub = st
            .subscriptions
            .values_mut()
            .find(|s| s.topic_arn == input.topic_arn && s.token.as_deref() == Some(input.token.as_str()))
            .ok_or_else(|| errors::invalid("Token"))?;
        if sub.pending && sub.token_expires_ms < now {
            return Err(errors::invalid("Token"));
        }
        sub.pending = false;
        if authenticate {
            sub.authenticated = true;
        }
        Ok(types::ConfirmSubscriptionResponse { subscription_arn: Some(sub.arn.clone()) })
    }

    pub(crate) fn unsubscribe_impl(
        &self,
        ctx: &RequestContext,
        input: types::UnsubscribeInput,
    ) -> Result<(), ServiceError> {
        let parsed = names::parse_sns_arn(&input.subscription_arn).ok_or_else(|| errors::invalid("SubscriptionArn"))?;
        let topic_arn = input.subscription_arn.rsplit_once(':').map(|(t, _)| t.to_string()).unwrap_or_default();
        let anonymous = matches!(ctx.caller.kind, CallerKind::Anonymous);
        if !anonymous {
            self.authorize_topic(ctx, "sns:Unsubscribe", &topic_arn, ConditionContext::new())?;
        }
        let mut st = self.lock();
        let sub = st.subscriptions.get(&input.subscription_arn).ok_or_else(errors::subscription_not_found)?;
        if anonymous {
            if sub.authenticated {
                return Err(errors::authorization_error(
                    "Unsubscribe is only allowed with a signed request for this subscription",
                ));
            }
        } else {
            let account = account_of(ctx);
            if account != sub.owner && account != parsed.account {
                return Err(errors::authorization_error(format!(
                    "User: {} is not authorized to perform: SNS:Unsubscribe on resource: {}",
                    ctx.caller.arn, input.subscription_arn
                )));
            }
        }
        let removed = st.subscriptions.remove(&input.subscription_arn);
        let topic = st.topics.get_mut(&topic_arn).map(|t| {
            t.subscriptions_deleted += 1;
            t.clone()
        });
        drop(st);
        if let (Some(topic), Some(sub)) = (topic, removed) {
            self.send_unsubscribe_confirmation(ctx, &topic, &sub);
        }
        Ok(())
    }

    pub(crate) fn get_subscription_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::GetSubscriptionAttributesInput,
    ) -> Result<types::GetSubscriptionAttributesResponse, ServiceError> {
        names::parse_sns_arn(&input.subscription_arn).ok_or_else(|| errors::invalid("SubscriptionArn"))?;
        let topic_arn = input.subscription_arn.rsplit_once(':').map(|(t, _)| t.to_string()).unwrap_or_default();
        self.authorize_topic(ctx, "sns:GetSubscriptionAttributes", &topic_arn, ConditionContext::new())?;
        let st = self.lock();
        let s = st.subscriptions.get(&input.subscription_arn).ok_or_else(errors::subscription_not_found)?;
        let mut out = s.attributes.clone();
        out.insert("SubscriptionArn".into(), s.arn.clone());
        out.insert("TopicArn".into(), s.topic_arn.clone());
        out.insert("Owner".into(), s.owner.clone());
        out.insert("Protocol".into(), s.protocol.clone());
        out.insert("Endpoint".into(), s.endpoint.clone());
        out.insert("PendingConfirmation".into(), s.pending.to_string());
        out.insert("ConfirmationWasAuthenticated".into(), s.authenticated.to_string());
        out.entry("RawMessageDelivery".into()).or_insert_with(|| "false".into());
        if !s.principal.is_empty() {
            out.insert("SubscriptionPrincipal".into(), s.principal.clone());
        }
        if out.contains_key("FilterPolicy") {
            out.entry("FilterPolicyScope".into()).or_insert_with(|| "MessageAttributes".into());
        }
        if matches!(s.protocol.as_str(), "http" | "https") {
            let topic_policy = st.topics.get(&s.topic_arn).and_then(|t| t.attributes.get("DeliveryPolicy").cloned());
            let effective = s
                .attributes
                .get("DeliveryPolicy")
                .cloned()
                .or_else(|| {
                    topic_policy.and_then(|p| {
                        serde_json::from_str::<serde_json::Value>(&p)
                            .ok()
                            .and_then(|v| v.get("http").map(|h| h.to_string()))
                    })
                })
                .unwrap_or_else(|| {
                    serde_json::from_str::<serde_json::Value>(DEFAULT_DELIVERY_POLICY)
                        .ok()
                        .and_then(|v| v.get("http").map(|h| h.to_string()))
                        .unwrap_or_default()
                });
            out.insert("EffectiveDeliveryPolicy".into(), effective);
        }
        Ok(types::GetSubscriptionAttributesResponse { attributes: Some(out) })
    }

    pub(crate) fn set_subscription_attributes_impl(
        &self,
        ctx: &RequestContext,
        input: types::SetSubscriptionAttributesInput,
    ) -> Result<(), ServiceError> {
        names::parse_sns_arn(&input.subscription_arn).ok_or_else(|| errors::invalid("SubscriptionArn"))?;
        let topic_arn = input.subscription_arn.rsplit_once(':').map(|(t, _)| t.to_string()).unwrap_or_default();
        self.authorize_topic(ctx, "sns:SetSubscriptionAttributes", &topic_arn, ConditionContext::new())?;
        if !SETTABLE.contains(&input.attribute_name.as_str()) {
            return Err(errors::invalid("AttributeName"));
        }
        let value = input.attribute_value.unwrap_or_default();
        let mut st = self.lock();
        let s = st.subscriptions.get_mut(&input.subscription_arn).ok_or_else(errors::subscription_not_found)?;
        validate_attribute(&input.attribute_name, &value, &s.protocol, &s.attributes)?;
        let replay = input.attribute_name == "ReplayPolicy" && !value.is_empty();
        if replay {
            let topic_arn = s.topic_arn.clone();
            Self::check_replay_target(Self::topic(&st, &topic_arn)?)?;
        }
        let s = st.subscriptions.get_mut(&input.subscription_arn).ok_or_else(errors::subscription_not_found)?;
        if input.attribute_name == "ReplayPolicy" {
            s.attributes.remove("ReplayStatus");
        }
        if value.is_empty() {
            s.attributes.remove(&input.attribute_name);
            if input.attribute_name == "FilterPolicy" {
                s.attributes.remove("FilterPolicyScope");
            }
        } else {
            s.attributes.insert(input.attribute_name, value);
        }
        let (arn, pending) = (s.arn.clone(), s.pending);
        drop(st);
        if replay && !pending {
            self.replay(ctx, &arn);
        }
        Ok(())
    }

    pub(crate) fn list_subscriptions_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListSubscriptionsInput,
    ) -> Result<types::ListSubscriptionsResponse, ServiceError> {
        let account = account_of(ctx);
        ctx.authorize(
            "sns:ListSubscriptions",
            &format!("arn:{}:sns:{}:{account}:*", ctx.partition, ctx.region),
            ConditionContext::new(),
        )?;
        let st = self.lock();
        let subs: Vec<&Subscription> = st
            .subscriptions
            .values()
            .filter(|s| {
                names::parse_sns_arn(&s.topic_arn)
                    .is_some_and(|t| t.region == ctx.region && (t.account == account || s.owner == account))
            })
            .collect();
        let arns: Vec<&str> = subs.iter().map(|s| s.arn.as_str()).collect();
        let (page, next) = paginate(&arns, input.next_token.as_deref(), PAGE)?;
        let out = page.iter().filter_map(|a| st.subscriptions.get(*a)).map(summary).collect();
        Ok(types::ListSubscriptionsResponse { subscriptions: Some(out), next_token: next })
    }

    pub(crate) fn list_subscriptions_by_topic_impl(
        &self,
        ctx: &RequestContext,
        input: types::ListSubscriptionsByTopicInput,
    ) -> Result<types::ListSubscriptionsByTopicResponse, ServiceError> {
        names::check_topic_arn(ctx, &input.topic_arn, "TopicArn")?;
        self.authorize_topic(ctx, "sns:ListSubscriptionsByTopic", &input.topic_arn, ConditionContext::new())?;
        let st = self.lock();
        Self::topic(&st, &input.topic_arn)?;
        let arns: Vec<&str> =
            st.subscriptions.values().filter(|s| s.topic_arn == input.topic_arn).map(|s| s.arn.as_str()).collect();
        let (page, next) = paginate(&arns, input.next_token.as_deref(), PAGE)?;
        let out = page.iter().filter_map(|a| st.subscriptions.get(*a)).map(summary).collect();
        Ok(types::ListSubscriptionsByTopicResponse { subscriptions: Some(out), next_token: next })
    }
}
