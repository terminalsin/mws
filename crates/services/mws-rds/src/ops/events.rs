//! Events (`DescribeEvents`), event categories and event subscriptions,
//! delivered to SNS topics and to EventBridge through [`crate::EventSink`].

use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, authorize_create, cond};
use crate::catalog::EVENT_CATEGORIES;
use crate::generated::{errors, types as t};
use crate::state::Tagged;
use crate::util::{account_of, arn, invalid_parameter, name_of, paginate, request_tag_context, tags_from, Filters};
use crate::{Rds, RdsEvent};

/// How long RDS keeps events.
const RETENTION_DAYS: i64 = 14;

const SOURCE_TYPES: &[&str] = &[
    "db-instance",
    "db-parameter-group",
    "db-security-group",
    "db-snapshot",
    "db-cluster",
    "db-cluster-snapshot",
    "custom-engine-version",
    "db-proxy",
    "blue-green-deployment",
];

impl Rds {
    /// Record an event and send it on.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit(
        &self,
        ctx: &RequestContext,
        source_type: &str,
        source_id: &str,
        source_arn: &str,
        categories: &[&str],
        message: &str,
        event_id: &str,
    ) {
        let now = self.now().max(ctx.received_at);
        let event = t::Event {
            source_identifier: Some(source_id.to_string()),
            source_type: Some(source_type.to_string()),
            message: Some(message.to_string()),
            event_categories: Some(categories.iter().map(|s| s.to_string()).collect()),
            date: Some(now),
            source_arn: Some(source_arn.to_string()),
        };
        let subscriptions: Vec<t::EventSubscription> = self.with_region(ctx, |r| {
            r.events.retain(|e| e.date.is_some_and(|d| d > now - Duration::days(RETENTION_DAYS)));
            r.events.push(event);
            r.event_subscriptions
                .values()
                .map(|s| s.item.clone())
                .filter(|s| s.enabled == Some(true))
                .filter(|s| s.source_type.as_deref().is_none_or(|st| st == source_type))
                .filter(|s| {
                    s.source_ids_list.as_ref().is_none_or(|ids| ids.is_empty() || ids.iter().any(|i| i == source_id))
                })
                .filter(|s| {
                    s.event_categories_list
                        .as_ref()
                        .is_none_or(|c| c.is_empty() || c.iter().any(|c| categories.contains(&c.as_str())))
                })
                .collect()
        });
        let Some(sink) = self.event_sink() else { return };
        let e = RdsEvent {
            account: account_of(ctx),
            region: ctx.region.clone(),
            source_type: source_type.to_string(),
            source_identifier: source_id.to_string(),
            source_arn: source_arn.to_string(),
            categories: categories.iter().map(|s| s.to_string()).collect(),
            message: message.to_string(),
            event_id: event_id.to_string(),
            time: now,
        };
        sink.put_event(ctx, &e);
        if subscriptions.is_empty() {
            return;
        }
        let console_kind = match source_type {
            "db-cluster" => "dbcluster",
            "db-snapshot" => "snapshot",
            "db-cluster-snapshot" => "db-cluster-snapshot",
            "db-parameter-group" => "parameter-group",
            _ => "dbinstance",
        };
        let message = serde_json::json!({
            "Event Source": source_type,
            "Event Time": now.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            "Identifier Link": format!(
                "https://console.aws.amazon.com/rds/home?region={}#{console_kind}:id={source_id}",
                ctx.region
            ),
            "Source ID": source_id,
            "Source ARN": source_arn,
            "Event ID": format!("http://docs.amazonwebservices.com/AmazonRDS/latest/UserGuide/USER_Events.html#{event_id}"),
            "Event Message": message,
        })
        .to_string();
        for s in subscriptions {
            if let Some(topic) = &s.sns_topic_arn {
                sink.notify_topic(ctx, topic, source_arn, "RDS Notification Message", &message);
            }
        }
    }

    pub(crate) fn describe_events_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeEventsMessage,
    ) -> Result<t::EventsMessage, ServiceError> {
        authorize(ctx, "DescribeEvents", &arn(ctx, "*", "*"), ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        if let Some(st) = &input.source_type {
            if !SOURCE_TYPES.contains(&st.as_str()) {
                return Err(invalid_parameter(format!("Invalid source type: {st}")));
            }
        }
        if input.source_identifier.is_some() && input.source_type.is_none() {
            return Err(invalid_parameter("Cannot specify source identifier without source type"));
        }
        let now = ctx.received_at;
        let end = input.end_time.unwrap_or(now);
        let start = match (input.start_time, input.duration) {
            (Some(s), _) => s,
            (None, Some(d)) => end - Duration::minutes(d as i64),
            (None, None) => end - Duration::hours(1),
        };
        let wanted_id = input.source_identifier.as_deref().map(name_of);
        let events: Vec<t::Event> = self.with_region(ctx, |r| {
            r.events
                .iter()
                .filter(|e| e.date.is_some_and(|d| d >= start && d <= end))
                .filter(|e| input.source_type.as_ref().is_none_or(|st| e.source_type.as_ref() == Some(st)))
                .filter(|e| wanted_id.as_ref().is_none_or(|id| e.source_identifier.as_ref() == Some(id)))
                .filter(|e| {
                    input
                        .event_categories
                        .as_ref()
                        .is_none_or(|c| c.is_empty() || e.event_categories.iter().flatten().any(|x| c.contains(x)))
                })
                .cloned()
                .collect()
        });
        let (page, marker) = paginate(events, &input.marker, input.max_records)?;
        Ok(t::EventsMessage { marker, events: Some(page) })
    }

    pub(crate) fn describe_event_categories_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeEventCategoriesMessage,
    ) -> Result<t::EventCategoriesMessage, ServiceError> {
        authorize(ctx, "DescribeEventCategories", "*", ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        if let Some(st) = &input.source_type {
            if !EVENT_CATEGORIES.iter().any(|(s, _)| s == st) {
                return Err(invalid_parameter(format!("Invalid source type: {st}")));
            }
        }
        Ok(t::EventCategoriesMessage {
            event_categories_map_list: Some(
                EVENT_CATEGORIES
                    .iter()
                    .filter(|(s, _)| input.source_type.as_deref().is_none_or(|w| w == *s))
                    .map(|(s, c)| t::EventCategoriesMap {
                        source_type: Some(s.to_string()),
                        event_categories: Some(c.iter().map(|x| x.to_string()).collect()),
                    })
                    .collect(),
            ),
        })
    }

    fn check_subscription(
        &self,
        source_type: &Option<String>,
        categories: &Option<Vec<String>>,
    ) -> Result<(), ServiceError> {
        if let Some(st) = source_type {
            if !SOURCE_TYPES.contains(&st.as_str()) {
                return Err(invalid_parameter(format!("Invalid source type: {st}")));
            }
        }
        for c in categories.iter().flatten() {
            let known = EVENT_CATEGORIES
                .iter()
                .filter(|(s, _)| source_type.as_deref().is_none_or(|w| w == *s))
                .any(|(_, cs)| cs.contains(&c.as_str()));
            if !known {
                return Err(errors::subscription_category_not_found_fault(format!("Category {c} not found.")));
            }
        }
        Ok(())
    }

    pub(crate) fn create_event_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateEventSubscriptionMessage,
    ) -> Result<t::CreateEventSubscriptionResult, ServiceError> {
        let name = input.subscription_name.clone();
        if name.is_empty()
            || name.len() > 255
            || !name.starts_with(|c: char| c.is_ascii_alphabetic())
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(invalid_parameter(
                "The parameter SubscriptionName is not a valid identifier. It must begin with a letter and contain only ASCII letters, digits, and hyphens.",
            ));
        }
        let tags = tags_from(&input.tags)?;
        let es_arn = arn(ctx, "es", &name);
        authorize_create(ctx, "CreateEventSubscription", &es_arn, &tags, request_tag_context(&tags))?;
        self.check_subscription(&input.source_type, &input.event_categories)?;
        if input.source_ids.as_ref().is_some_and(|i| !i.is_empty()) && input.source_type.is_none() {
            return Err(invalid_parameter("Source type must be specified when source IDs are specified."));
        }
        self.check_topic(ctx, &input.sns_topic_arn)?;
        let sub = t::EventSubscription {
            customer_aws_id: Some(account_of(ctx)),
            cust_subscription_id: Some(name.clone()),
            sns_topic_arn: Some(input.sns_topic_arn.clone()),
            status: Some("active".into()),
            subscription_creation_time: Some(ctx.received_at.format("%a %b %d %H:%M:%S UTC %Y").to_string()),
            source_type: input.source_type.clone(),
            source_ids_list: input.source_ids.clone().filter(|v| !v.is_empty()),
            event_categories_list: input.event_categories.clone().filter(|v| !v.is_empty()),
            enabled: Some(input.enabled.unwrap_or(true)),
            event_subscription_arn: Some(es_arn),
        };
        self.with_region(ctx, |r| {
            if r.event_subscriptions.contains_key(&name) {
                return Err(errors::subscription_already_exist_fault(format!("Subscription {name} already exists.")));
            }
            r.event_subscriptions.insert(name.clone(), Tagged { item: sub.clone(), tags });
            Ok(())
        })?;
        Ok(t::CreateEventSubscriptionResult { event_subscription: Some(sub) })
    }

    fn check_topic(&self, ctx: &RequestContext, topic: &str) -> Result<(), ServiceError> {
        let Some(sink) = self.event_sink() else { return Ok(()) };
        sink.check_topic(ctx, topic).map_err(|code| match code.as_str() {
            "SNSTopicArnNotFound" => errors::sns_topic_arn_not_found_fault("Topic not found"),
            "SNSNoAuthorization" => errors::sns_no_authorization_fault("Not authorized to publish to the topic"),
            _ => errors::sns_invalid_topic_fault(format!("Invalid SNS topic: {topic}")),
        })
    }

    fn subscription_mut<R>(
        &self,
        ctx: &RequestContext,
        name: &str,
        f: impl FnOnce(&mut t::EventSubscription) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        self.with_region(ctx, |r| match r.event_subscriptions.get_mut(name) {
            Some(s) => f(&mut s.item),
            None => Err(errors::subscription_not_found_fault(format!("Subscription {name} not found."))),
        })
    }

    pub(crate) fn modify_event_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyEventSubscriptionMessage,
    ) -> Result<t::ModifyEventSubscriptionResult, ServiceError> {
        authorize(ctx, "ModifyEventSubscription", &arn(ctx, "es", &input.subscription_name), ConditionContext::new())?;
        let current = self.subscription_mut(ctx, &input.subscription_name, |s| Ok(s.clone()))?;
        let source_type = input.source_type.clone().or(current.source_type);
        self.check_subscription(&source_type, &input.event_categories)?;
        if let Some(topic) = &input.sns_topic_arn {
            self.check_topic(ctx, topic)?;
        }
        let sub = self.subscription_mut(ctx, &input.subscription_name, |s| {
            if let Some(v) = input.sns_topic_arn {
                s.sns_topic_arn = Some(v);
            }
            if let Some(v) = input.source_type {
                s.source_type = Some(v);
            }
            if let Some(v) = input.event_categories {
                s.event_categories_list = Some(v).filter(|v| !v.is_empty());
            }
            if let Some(v) = input.enabled {
                s.enabled = Some(v);
            }
            Ok(s.clone())
        })?;
        Ok(t::ModifyEventSubscriptionResult { event_subscription: Some(sub) })
    }

    pub(crate) fn delete_event_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteEventSubscriptionMessage,
    ) -> Result<t::DeleteEventSubscriptionResult, ServiceError> {
        authorize(ctx, "DeleteEventSubscription", &arn(ctx, "es", &input.subscription_name), ConditionContext::new())?;
        let sub = self.with_region(ctx, |r| {
            r.event_subscriptions.remove(&input.subscription_name).map(|s| s.item).ok_or_else(|| {
                errors::subscription_not_found_fault(format!("Subscription {} not found.", input.subscription_name))
            })
        })?;
        Ok(t::DeleteEventSubscriptionResult {
            event_subscription: Some(t::EventSubscription { status: Some("deleting".into()), ..sub }),
        })
    }

    pub(crate) fn describe_event_subscriptions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeEventSubscriptionsMessage,
    ) -> Result<t::EventSubscriptionsMessage, ServiceError> {
        authorize(ctx, "DescribeEventSubscriptions", &arn(ctx, "es", "*"), ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        let subs: Vec<t::EventSubscription> = self.with_region(ctx, |r| {
            r.event_subscriptions
                .values()
                .map(|s| s.item.clone())
                .filter(|s| input.subscription_name.as_ref().is_none_or(|n| s.cust_subscription_id.as_ref() == Some(n)))
                .collect()
        });
        if let Some(n) = &input.subscription_name {
            if subs.is_empty() {
                return Err(errors::subscription_not_found_fault(format!("Subscription {n} not found.")));
            }
        }
        let (page, marker) = paginate(subs, &input.marker, input.max_records)?;
        Ok(t::EventSubscriptionsMessage { marker, event_subscriptions_list: Some(page) })
    }

    pub(crate) fn add_source_identifier_to_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::AddSourceIdentifierToSubscriptionMessage,
    ) -> Result<t::AddSourceIdentifierToSubscriptionResult, ServiceError> {
        authorize(ctx, "AddSourceIdentifierToSubscription", &arn(ctx, "es", &input.subscription_name), cond(&[]))?;
        let sub = self.subscription_mut(ctx, &input.subscription_name, |s| {
            let ids = s.source_ids_list.get_or_insert_with(Vec::new);
            if !ids.contains(&input.source_identifier) {
                ids.push(input.source_identifier.clone());
            }
            Ok(s.clone())
        })?;
        Ok(t::AddSourceIdentifierToSubscriptionResult { event_subscription: Some(sub) })
    }

    pub(crate) fn remove_source_identifier_from_subscription_op(
        &self,
        ctx: &RequestContext,
        input: t::RemoveSourceIdentifierFromSubscriptionMessage,
    ) -> Result<t::RemoveSourceIdentifierFromSubscriptionResult, ServiceError> {
        authorize(ctx, "RemoveSourceIdentifierFromSubscription", &arn(ctx, "es", &input.subscription_name), cond(&[]))?;
        let sub = self.subscription_mut(ctx, &input.subscription_name, |s| {
            let ids = s.source_ids_list.get_or_insert_with(Vec::new);
            if !ids.contains(&input.source_identifier) {
                return Err(errors::source_not_found_fault(format!(
                    "Source {} not found in subscription.",
                    input.source_identifier
                )));
            }
            ids.retain(|i| i != &input.source_identifier);
            if ids.is_empty() {
                s.source_ids_list = None;
            }
            Ok(s.clone())
        })?;
        Ok(t::RemoveSourceIdentifierFromSubscriptionResult { event_subscription: Some(sub) })
    }
}
