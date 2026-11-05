//! Configuration sets and their event destinations, tracking, delivery,
//! reputation, sending, suppression, VDM and archiving options. Both APIs
//! share them.

use mws_core::{RequestContext, ServiceError};

use crate::names::{self, authorize, region, region_ref};
use crate::state::{ConfigurationSet, EventDestination};
use crate::v1::types as t1;
use crate::v2::types as t2;
use crate::{v1, v2, Ses};

const MAX_CONFIGURATION_SETS: usize = 10_000;
const MAX_EVENT_DESTINATIONS: usize = 10;

/// v1 event type names to v2 ones.
pub fn v2_event_type(v1: &str) -> Option<&'static str> {
    Some(match v1 {
        "send" => "SEND",
        "reject" => "REJECT",
        "bounce" => "BOUNCE",
        "complaint" => "COMPLAINT",
        "delivery" => "DELIVERY",
        "open" => "OPEN",
        "click" => "CLICK",
        "renderingFailure" => "RENDERING_FAILURE",
        "deliveryDelay" => "DELIVERY_DELAY",
        "subscription" => "SUBSCRIPTION",
        _ => return None,
    })
}

pub fn v1_event_type(v2: &str) -> &'static str {
    match v2 {
        "SEND" => "send",
        "REJECT" => "reject",
        "BOUNCE" => "bounce",
        "COMPLAINT" => "complaint",
        "DELIVERY" => "delivery",
        "OPEN" => "open",
        "CLICK" => "click",
        "RENDERING_FAILURE" => "renderingFailure",
        "DELIVERY_DELAY" => "deliveryDelay",
        _ => "subscription",
    }
}

const V2_EVENT_TYPES: &[&str] = &[
    "SEND",
    "REJECT",
    "BOUNCE",
    "COMPLAINT",
    "DELIVERY",
    "OPEN",
    "CLICK",
    "RENDERING_FAILURE",
    "DELIVERY_DELAY",
    "SUBSCRIPTION",
];

fn cs_arn(ctx: &RequestContext, name: &str) -> String {
    names::arn(ctx, &format!("configuration-set/{name}"))
}

impl Ses {
    pub(crate) fn configuration_set(&self, ctx: &RequestContext, name: &str) -> Option<ConfigurationSet> {
        region_ref(&self.lock(), ctx).and_then(|r| r.configuration_sets.get(name).cloned())
    }

    fn create_set(&self, ctx: &RequestContext, cs: ConfigurationSet) -> Result<(), (bool, String)> {
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        if r.configuration_sets.contains_key(&cs.name) {
            return Err((true, format!("Configuration set <{}> already exists.", cs.name)));
        }
        if r.configuration_sets.len() >= MAX_CONFIGURATION_SETS {
            return Err((false, "Maximum number of configuration sets reached.".into()));
        }
        r.configuration_sets.insert(cs.name.clone(), cs);
        Ok(())
    }

    fn update_set<T>(
        &self,
        ctx: &RequestContext,
        name: &str,
        f: impl FnOnce(&mut ConfigurationSet) -> Result<T, ServiceError>,
    ) -> Option<Result<T, ServiceError>> {
        region(&mut self.lock(), ctx).configuration_sets.get_mut(name).map(f)
    }

    /// Check where an event destination would deliver.
    fn check_destination(
        &self,
        ctx: &RequestContext,
        set: &str,
        d: &EventDestination,
        v1_api: bool,
    ) -> Result<(), ServiceError> {
        let source_arn = cs_arn(ctx, set);
        let account = &ctx.caller.account_id;
        let count = [
            d.sns.is_some(),
            d.firehose.is_some(),
            d.cloudwatch.is_some(),
            d.eventbridge.is_some(),
            d.pinpoint.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if count != 1 {
            let m = "An event destination must have exactly one destination: SNS, Kinesis Firehose, CloudWatch, EventBridge or Pinpoint.";
            return Err(if v1_api { names::invalid_parameter(m) } else { v2::errors::bad_request(m) });
        }
        if d.matching_event_types.is_empty() {
            let m = "MatchingEventTypes must not be empty.";
            return Err(if v1_api { names::invalid_parameter(m) } else { v2::errors::bad_request(m) });
        }
        if let Some(topic) = &d.sns {
            self.links().check_sns(ctx, topic, account, &source_arn).map_err(|_| {
                let m = format!("SNS topic <{topic}> is invalid or SES is not authorized to publish to it.");
                if v1_api {
                    v1::errors::invalid_sns_destination(m)
                } else {
                    v2::errors::bad_request(m)
                }
            })?;
        }
        if let Some(f) = &d.firehose {
            self.links().check_firehose(ctx, &f.iam_role_arn, &f.delivery_stream_arn, account, &source_arn).map_err(
                |e| {
                    if v1_api {
                        v1::errors::invalid_firehose_destination(e)
                    } else {
                        v2::errors::bad_request(e)
                    }
                },
            )?;
        }
        if let Some(cw) = &d.cloudwatch {
            for dim in &cw.dimension_configurations {
                let ok = !dim.dimension_name.is_empty()
                    && dim.dimension_name.len() <= 256
                    && matches!(
                        dim.dimension_value_source.as_str(),
                        "MESSAGE_TAG" | "EMAIL_HEADER" | "LINK_TAG" | "messageTag" | "emailHeader" | "linkTag"
                    )
                    && !dim.default_dimension_value.is_empty();
                if !ok {
                    let m = format!("Invalid CloudWatch dimension configuration {}.", dim.dimension_name);
                    return Err(if v1_api {
                        v1::errors::invalid_cloud_watch_destination(m)
                    } else {
                        v2::errors::bad_request(m)
                    });
                }
            }
        }
        if let Some(bus) = &d.eventbridge {
            let default = format!("arn:{}:events:{}:{}:event-bus/default", ctx.partition, ctx.region, account);
            if bus != &default {
                return Err(v2::errors::bad_request(format!(
                    "Invalid event bus {bus}. Only the default event bus of the account and Region is supported."
                )));
            }
        }
        Ok(())
    }

    fn add_destination(
        &self,
        ctx: &RequestContext,
        set: &str,
        d: EventDestination,
        replace: bool,
    ) -> Result<(), DestErr> {
        let mut st = self.lock();
        let r = region(&mut st, ctx);
        let cs = r.configuration_sets.get_mut(set).ok_or(DestErr::NoSet)?;
        let pos = cs.event_destinations.iter().position(|e| e.name == d.name);
        match (replace, pos) {
            (false, Some(_)) => Err(DestErr::Exists),
            (true, None) => Err(DestErr::NoDestination),
            (true, Some(i)) => {
                cs.event_destinations[i] = d;
                Ok(())
            }
            (false, None) => {
                if cs.event_destinations.len() >= MAX_EVENT_DESTINATIONS {
                    return Err(DestErr::Limit);
                }
                cs.event_destinations.push(d);
                Ok(())
            }
        }
    }

    // ------------------------------------------------------------ v1

    pub(crate) fn create_configuration_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateConfigurationSetRequest,
    ) -> Result<(), ServiceError> {
        let name = input.configuration_set.name;
        authorize(ctx, "1", "CreateConfigurationSet", &cs_arn(ctx, &name))?;
        if !names::valid_name(&name) {
            return Err(v1::errors::invalid_configuration_set(format!(
                "Configuration set name {name} is invalid. It must contain only ASCII letters, numbers, underscores and dashes, and be at most 64 characters long."
            )));
        }
        let cs = ConfigurationSet { name, created: ctx.received_at, ..Default::default() };
        self.create_set(ctx, cs).map_err(|(exists, m)| {
            if exists {
                v1::errors::configuration_set_already_exists(m)
            } else {
                v1::errors::limit_exceeded(m)
            }
        })
    }

    pub(crate) fn delete_configuration_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteConfigurationSetRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "DeleteConfigurationSet", &cs_arn(ctx, &input.configuration_set_name))?;
        if region(&mut self.lock(), ctx).configuration_sets.remove(&input.configuration_set_name).is_none() {
            return Err(missing_v1(&input.configuration_set_name));
        }
        Ok(())
    }

    pub(crate) fn describe_configuration_set_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DescribeConfigurationSetRequest,
    ) -> Result<t1::DescribeConfigurationSetResponse, ServiceError> {
        authorize(ctx, "1", "DescribeConfigurationSet", &cs_arn(ctx, &input.configuration_set_name))?;
        let cs = self
            .configuration_set(ctx, &input.configuration_set_name)
            .ok_or_else(|| missing_v1(&input.configuration_set_name))?;
        let wanted = input.configuration_set_attribute_names.unwrap_or_default();
        let want = |a: &str| wanted.iter().any(|w| w == a);
        Ok(t1::DescribeConfigurationSetResponse {
            configuration_set: Some(t1::ConfigurationSet { name: cs.name.clone() }),
            event_destinations: want("eventDestinations")
                .then(|| cs.event_destinations.iter().map(to_v1_destination).collect()),
            tracking_options: want("trackingOptions").then(|| {
                cs.tracking
                    .as_ref()
                    .map(|t| t1::TrackingOptions { custom_redirect_domain: Some(t.custom_redirect_domain.clone()) })
                    .unwrap_or_default()
            }),
            delivery_options: want("deliveryOptions").then(|| t1::DeliveryOptions {
                tls_policy: Some(if cs.tls_policy == "REQUIRE" { "Require".into() } else { "Optional".into() }),
            }),
            reputation_options: want("reputationOptions").then_some(t1::ReputationOptions {
                sending_enabled: cs.sending_enabled,
                reputation_metrics_enabled: cs.reputation_metrics_enabled,
                last_fresh_start: cs.last_fresh_start,
            }),
        })
    }

    pub(crate) fn list_configuration_sets_v1(
        &self,
        ctx: &RequestContext,
        input: t1::ListConfigurationSetsRequest,
    ) -> Result<t1::ListConfigurationSetsResponse, ServiceError> {
        authorize(ctx, "1", "ListConfigurationSets", "*")?;
        let all: Vec<t1::ConfigurationSet> = region_ref(&self.lock(), ctx)
            .map(|r| r.configuration_sets.keys().map(|n| t1::ConfigurationSet { name: n.clone() }).collect())
            .unwrap_or_default();
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.max_items, 1000);
        Ok(t1::ListConfigurationSetsResponse { configuration_sets: Some(page), next_token: next })
    }

    fn v1_destination(d: t1::EventDestination) -> Result<EventDestination, ServiceError> {
        let mut types = Vec::new();
        for t in &d.matching_event_types {
            types.push(
                v2_event_type(t)
                    .ok_or_else(|| names::invalid_parameter(format!("Invalid event type {t}.")))?
                    .to_string(),
            );
        }
        Ok(EventDestination {
            name: d.name,
            enabled: d.enabled,
            matching_event_types: types,
            firehose: d.kinesis_firehose_destination.map(|f| t2::KinesisFirehoseDestination {
                iam_role_arn: f.iam_role_arn,
                delivery_stream_arn: f.delivery_stream_arn,
            }),
            cloudwatch: d.cloud_watch_destination.map(|c| t2::CloudWatchDestination {
                dimension_configurations: c
                    .dimension_configurations
                    .into_iter()
                    .map(|d| t2::CloudWatchDimensionConfiguration {
                        dimension_name: d.dimension_name,
                        dimension_value_source: match d.dimension_value_source.as_str() {
                            "messageTag" => "MESSAGE_TAG".into(),
                            "emailHeader" => "EMAIL_HEADER".into(),
                            "linkTag" => "LINK_TAG".into(),
                            other => other.to_string(),
                        },
                        default_dimension_value: d.default_dimension_value,
                    })
                    .collect(),
            }),
            sns: d.sns_destination.map(|s| s.topic_arn),
            eventbridge: None,
            pinpoint: None,
        })
    }

    pub(crate) fn create_configuration_set_event_destination_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateConfigurationSetEventDestinationRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "CreateConfigurationSetEventDestination", &cs_arn(ctx, &set))?;
        if self.configuration_set(ctx, &set).is_none() {
            return Err(missing_v1(&set));
        }
        let d = Self::v1_destination(input.event_destination)?;
        if !names::valid_name(&d.name) {
            return Err(names::invalid_parameter(format!("Invalid event destination name {}.", d.name)));
        }
        self.check_destination(ctx, &set, &d, true)?;
        let dname = d.name.clone();
        self.add_destination(ctx, &set, d, false).map_err(|e| e.v1(&set, &dname))
    }

    pub(crate) fn update_configuration_set_event_destination_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateConfigurationSetEventDestinationRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "UpdateConfigurationSetEventDestination", &cs_arn(ctx, &set))?;
        if self.configuration_set(ctx, &set).is_none() {
            return Err(missing_v1(&set));
        }
        let d = Self::v1_destination(input.event_destination)?;
        self.check_destination(ctx, &set, &d, true)?;
        let dname = d.name.clone();
        self.add_destination(ctx, &set, d, true).map_err(|e| e.v1(&set, &dname))
    }

    pub(crate) fn delete_configuration_set_event_destination_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteConfigurationSetEventDestinationRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "DeleteConfigurationSetEventDestination", &cs_arn(ctx, &set))?;
        let name = input.event_destination_name.clone();
        self.update_set(ctx, &set, |cs| {
            let before = cs.event_destinations.len();
            cs.event_destinations.retain(|d| d.name != name);
            if cs.event_destinations.len() == before {
                return Err(v1::errors::event_destination_does_not_exist(format!(
                    "No EventDestination found for {name}"
                )));
            }
            Ok(())
        })
        .unwrap_or_else(|| Err(missing_v1(&set)))
    }

    pub(crate) fn create_configuration_set_tracking_options_v1(
        &self,
        ctx: &RequestContext,
        input: t1::CreateConfigurationSetTrackingOptionsRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "CreateConfigurationSetTrackingOptions", &cs_arn(ctx, &set))?;
        let domain = input.tracking_options.custom_redirect_domain.unwrap_or_default();
        check_redirect_domain(&domain).map_err(v1::errors::invalid_tracking_options)?;
        self.update_set(ctx, &set, |cs| {
            if cs.tracking.is_some() {
                return Err(v1::errors::tracking_options_already_exists(format!(
                    "Tracking options already exist for configuration set {set}"
                )));
            }
            cs.tracking = Some(t2::TrackingOptions { custom_redirect_domain: domain, https_policy: None });
            Ok(())
        })
        .unwrap_or_else(|| Err(missing_v1(&input.configuration_set_name)))
    }

    pub(crate) fn update_configuration_set_tracking_options_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateConfigurationSetTrackingOptionsRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "UpdateConfigurationSetTrackingOptions", &cs_arn(ctx, &set))?;
        let domain = input.tracking_options.custom_redirect_domain.unwrap_or_default();
        check_redirect_domain(&domain).map_err(v1::errors::invalid_tracking_options)?;
        self.update_set(ctx, &set, |cs| {
            let Some(t) = cs.tracking.as_mut() else {
                return Err(v1::errors::tracking_options_does_not_exist(format!(
                    "Tracking options do not exist for configuration set {set}"
                )));
            };
            t.custom_redirect_domain = domain;
            Ok(())
        })
        .unwrap_or_else(|| Err(missing_v1(&input.configuration_set_name)))
    }

    pub(crate) fn delete_configuration_set_tracking_options_v1(
        &self,
        ctx: &RequestContext,
        input: t1::DeleteConfigurationSetTrackingOptionsRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "DeleteConfigurationSetTrackingOptions", &cs_arn(ctx, &set))?;
        self.update_set(ctx, &set, |cs| {
            if cs.tracking.take().is_none() {
                return Err(v1::errors::tracking_options_does_not_exist(format!(
                    "Tracking options do not exist for configuration set {set}"
                )));
            }
            Ok(())
        })
        .unwrap_or_else(|| Err(missing_v1(&input.configuration_set_name)))
    }

    pub(crate) fn put_configuration_set_delivery_options_v1(
        &self,
        ctx: &RequestContext,
        input: t1::PutConfigurationSetDeliveryOptionsRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "PutConfigurationSetDeliveryOptions", &cs_arn(ctx, &set))?;
        let policy = match input.delivery_options.and_then(|d| d.tls_policy).as_deref() {
            Some("Require") => "REQUIRE",
            Some("Optional") | None => "OPTIONAL",
            Some(other) => return Err(v1::errors::invalid_delivery_options(format!("Invalid TLS policy {other}."))),
        };
        self.update_set(ctx, &set, |cs| {
            cs.tls_policy = policy.into();
            Ok(())
        })
        .unwrap_or_else(|| Err(missing_v1(&set)))
    }

    pub(crate) fn update_configuration_set_reputation_metrics_enabled_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateConfigurationSetReputationMetricsEnabledRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "UpdateConfigurationSetReputationMetricsEnabled", &cs_arn(ctx, &set))?;
        self.update_set(ctx, &set, |cs| {
            cs.reputation_metrics_enabled = input.enabled;
            Ok(())
        })
        .unwrap_or_else(|| Err(missing_v1(&set)))
    }

    pub(crate) fn update_configuration_set_sending_enabled_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateConfigurationSetSendingEnabledRequest,
    ) -> Result<(), ServiceError> {
        let set = input.configuration_set_name.clone();
        authorize(ctx, "1", "UpdateConfigurationSetSendingEnabled", &cs_arn(ctx, &set))?;
        let now = ctx.received_at;
        self.update_set(ctx, &set, |cs| {
            if input.enabled && !cs.sending_enabled {
                cs.last_fresh_start = Some(now);
            }
            cs.sending_enabled = input.enabled;
            Ok(())
        })
        .unwrap_or_else(|| Err(missing_v1(&set)))
    }

    // ------------------------------------------------------------ v2

    fn set_v2(&self, ctx: &RequestContext, action: &str, name: &str) -> Result<ConfigurationSet, ServiceError> {
        let cs = self.configuration_set(ctx, name);
        names::authorize_tagged(
            ctx,
            "2",
            action,
            &cs_arn(ctx, name),
            &cs.as_ref().map(|c| c.tags.clone()).unwrap_or_default(),
        )?;
        cs.ok_or_else(|| missing_v2(name))
    }

    fn update_set_v2<T>(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
        f: impl FnOnce(&mut ConfigurationSet) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        self.set_v2(ctx, action, name)?;
        self.update_set(ctx, name, f).unwrap_or_else(|| Err(missing_v2(name)))
    }

    pub(crate) fn create_configuration_set_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateConfigurationSetRequest,
    ) -> Result<t2::CreateConfigurationSetResponse, ServiceError> {
        let name = input.configuration_set_name.clone();
        let tags = names::tags_pairs(input.tags.as_deref());
        names::authorize_create(ctx, "CreateConfigurationSet", &cs_arn(ctx, &name), &tags)?;
        names::check_tags(&tags)?;
        if !names::valid_name(&name) {
            return Err(v2::errors::bad_request(format!("Invalid configuration set name: {name}")));
        }
        if let Some(t) = &input.tracking_options {
            check_redirect_domain(&t.custom_redirect_domain).map_err(v2::errors::bad_request)?;
        }
        if let Some(pool) = input.delivery_options.as_ref().and_then(|d| d.sending_pool_name.as_ref()) {
            if !region_ref(&self.lock(), ctx).is_some_and(|r| r.dedicated_ip_pools.contains_key(pool)) {
                return Err(v2::errors::not_found(format!("Pool {pool} does not exist.")));
            }
        }
        let delivery = input.delivery_options.unwrap_or_default();
        check_max_delivery(delivery.max_delivery_seconds)?;
        let cs = ConfigurationSet {
            name,
            created: ctx.received_at,
            event_destinations: Vec::new(),
            tracking: input.tracking_options,
            tls_policy: delivery.tls_policy.unwrap_or_else(|| "OPTIONAL".into()),
            sending_pool_name: delivery.sending_pool_name,
            max_delivery_seconds: delivery.max_delivery_seconds,
            reputation_metrics_enabled: input
                .reputation_options
                .as_ref()
                .map(|r| r.reputation_metrics_enabled)
                .unwrap_or(false),
            last_fresh_start: input.reputation_options.and_then(|r| r.last_fresh_start),
            sending_enabled: input.sending_options.map(|s| s.sending_enabled).unwrap_or(true),
            suppression: input.suppression_options,
            vdm: input.vdm_options,
            archive_arn: input.archiving_options.and_then(|a| a.archive_arn),
            message_security: input.message_security_options,
            tags: tags.into_iter().collect(),
        };
        self.create_set(ctx, cs).map_err(|(exists, m)| {
            if exists {
                v2::errors::already_exists(m)
            } else {
                v2::errors::limit_exceeded(m)
            }
        })?;
        Ok(Default::default())
    }

    pub(crate) fn delete_configuration_set_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteConfigurationSetRequest,
    ) -> Result<t2::DeleteConfigurationSetResponse, ServiceError> {
        self.set_v2(ctx, "DeleteConfigurationSet", &input.configuration_set_name)?;
        region(&mut self.lock(), ctx).configuration_sets.remove(&input.configuration_set_name);
        Ok(Default::default())
    }

    pub(crate) fn get_configuration_set_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetConfigurationSetRequest,
    ) -> Result<t2::GetConfigurationSetResponse, ServiceError> {
        let cs = self.set_v2(ctx, "GetConfigurationSet", &input.configuration_set_name)?;
        Ok(t2::GetConfigurationSetResponse {
            configuration_set_name: Some(cs.name.clone()),
            tracking_options: cs.tracking.clone(),
            delivery_options: Some(t2::DeliveryOptions {
                tls_policy: Some(cs.tls_policy.clone()),
                sending_pool_name: cs.sending_pool_name.clone(),
                max_delivery_seconds: cs.max_delivery_seconds,
            }),
            reputation_options: Some(t2::ReputationOptions {
                reputation_metrics_enabled: cs.reputation_metrics_enabled,
                last_fresh_start: cs.last_fresh_start,
            }),
            sending_options: Some(t2::SendingOptions { sending_enabled: cs.sending_enabled }),
            tags: Some(names::tag_list(&cs.tags)),
            suppression_options: cs.suppression.clone(),
            vdm_options: cs.vdm.clone(),
            archiving_options: cs.archive_arn.clone().map(|a| t2::ArchivingOptions { archive_arn: Some(a) }),
            message_security_options: cs.message_security.clone(),
        })
    }

    pub(crate) fn list_configuration_sets_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListConfigurationSetsRequest,
    ) -> Result<t2::ListConfigurationSetsResponse, ServiceError> {
        authorize(ctx, "2", "ListConfigurationSets", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<String> =
            region_ref(&self.lock(), ctx).map(|r| r.configuration_sets.keys().cloned().collect()).unwrap_or_default();
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListConfigurationSetsResponse { configuration_sets: Some(page), next_token: next })
    }

    fn v2_destination(name: String, d: t2::EventDestinationDefinition) -> Result<EventDestination, ServiceError> {
        let types = d.matching_event_types.unwrap_or_default();
        if let Some(bad) = types.iter().find(|t| !V2_EVENT_TYPES.contains(&t.as_str())) {
            return Err(v2::errors::bad_request(format!("Invalid event type {bad}.")));
        }
        Ok(EventDestination {
            name,
            enabled: d.enabled,
            matching_event_types: types,
            firehose: d.kinesis_firehose_destination,
            cloudwatch: d.cloud_watch_destination,
            sns: d.sns_destination.map(|s| s.topic_arn),
            eventbridge: d.event_bridge_destination.map(|e| e.event_bus_arn),
            pinpoint: d.pinpoint_destination.and_then(|p| p.application_arn),
        })
    }

    pub(crate) fn create_configuration_set_event_destination_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateConfigurationSetEventDestinationRequest,
    ) -> Result<t2::CreateConfigurationSetEventDestinationResponse, ServiceError> {
        let set = input.configuration_set_name.clone();
        self.set_v2(ctx, "CreateConfigurationSetEventDestination", &set)?;
        if !names::valid_name(&input.event_destination_name) {
            return Err(v2::errors::bad_request(format!(
                "Invalid event destination name {}.",
                input.event_destination_name
            )));
        }
        let d = Self::v2_destination(input.event_destination_name, input.event_destination)?;
        self.check_destination(ctx, &set, &d, false)?;
        let dname = d.name.clone();
        self.add_destination(ctx, &set, d, false).map_err(|e| e.v2(&set, &dname))?;
        Ok(Default::default())
    }

    pub(crate) fn update_configuration_set_event_destination_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateConfigurationSetEventDestinationRequest,
    ) -> Result<t2::UpdateConfigurationSetEventDestinationResponse, ServiceError> {
        let set = input.configuration_set_name.clone();
        self.set_v2(ctx, "UpdateConfigurationSetEventDestination", &set)?;
        let d = Self::v2_destination(input.event_destination_name, input.event_destination)?;
        self.check_destination(ctx, &set, &d, false)?;
        let dname = d.name.clone();
        self.add_destination(ctx, &set, d, true).map_err(|e| e.v2(&set, &dname))?;
        Ok(Default::default())
    }

    pub(crate) fn delete_configuration_set_event_destination_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteConfigurationSetEventDestinationRequest,
    ) -> Result<t2::DeleteConfigurationSetEventDestinationResponse, ServiceError> {
        let name = input.event_destination_name.clone();
        self.update_set_v2(ctx, "DeleteConfigurationSetEventDestination", &input.configuration_set_name, |cs| {
            let before = cs.event_destinations.len();
            cs.event_destinations.retain(|d| d.name != name);
            if cs.event_destinations.len() == before {
                return Err(v2::errors::not_found(format!("Event destination {name} does not exist.")));
            }
            Ok(Default::default())
        })
    }

    pub(crate) fn get_configuration_set_event_destinations_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetConfigurationSetEventDestinationsRequest,
    ) -> Result<t2::GetConfigurationSetEventDestinationsResponse, ServiceError> {
        let cs = self.set_v2(ctx, "GetConfigurationSetEventDestinations", &input.configuration_set_name)?;
        Ok(t2::GetConfigurationSetEventDestinationsResponse {
            event_destinations: Some(cs.event_destinations.iter().map(to_v2_destination).collect()),
        })
    }

    pub(crate) fn put_configuration_set_archiving_options_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutConfigurationSetArchivingOptionsRequest,
    ) -> Result<t2::PutConfigurationSetArchivingOptionsResponse, ServiceError> {
        self.update_set_v2(ctx, "PutConfigurationSetArchivingOptions", &input.configuration_set_name, |cs| {
            cs.archive_arn = input.archive_arn.filter(|a| !a.is_empty());
            Ok(Default::default())
        })
    }

    pub(crate) fn put_configuration_set_delivery_options_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutConfigurationSetDeliveryOptionsRequest,
    ) -> Result<t2::PutConfigurationSetDeliveryOptionsResponse, ServiceError> {
        check_max_delivery(input.max_delivery_seconds)?;
        if let Some(pool) = &input.sending_pool_name {
            if !region_ref(&self.lock(), ctx).is_some_and(|r| r.dedicated_ip_pools.contains_key(pool)) {
                return Err(v2::errors::not_found(format!("Pool {pool} does not exist.")));
            }
        }
        self.update_set_v2(ctx, "PutConfigurationSetDeliveryOptions", &input.configuration_set_name, |cs| {
            if let Some(p) = input.tls_policy {
                cs.tls_policy = p;
            }
            cs.sending_pool_name = input.sending_pool_name;
            if input.max_delivery_seconds.is_some() {
                cs.max_delivery_seconds = input.max_delivery_seconds;
            }
            Ok(Default::default())
        })
    }

    pub(crate) fn put_configuration_set_reputation_options_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutConfigurationSetReputationOptionsRequest,
    ) -> Result<t2::PutConfigurationSetReputationOptionsResponse, ServiceError> {
        self.update_set_v2(ctx, "PutConfigurationSetReputationOptions", &input.configuration_set_name, |cs| {
            cs.reputation_metrics_enabled = input.reputation_metrics_enabled;
            Ok(Default::default())
        })
    }

    pub(crate) fn put_configuration_set_sending_options_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutConfigurationSetSendingOptionsRequest,
    ) -> Result<t2::PutConfigurationSetSendingOptionsResponse, ServiceError> {
        let now = ctx.received_at;
        self.update_set_v2(ctx, "PutConfigurationSetSendingOptions", &input.configuration_set_name, |cs| {
            let enabled = input.sending_enabled;
            if enabled && !cs.sending_enabled {
                cs.last_fresh_start = Some(now);
            }
            cs.sending_enabled = enabled;
            Ok(Default::default())
        })
    }

    pub(crate) fn put_configuration_set_suppression_options_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutConfigurationSetSuppressionOptionsRequest,
    ) -> Result<t2::PutConfigurationSetSuppressionOptionsResponse, ServiceError> {
        if let Some(bad) =
            input.suppressed_reasons.iter().flatten().find(|r| !matches!(r.as_str(), "BOUNCE" | "COMPLAINT"))
        {
            return Err(v2::errors::bad_request(format!("Invalid suppression reason {bad}.")));
        }
        self.update_set_v2(ctx, "PutConfigurationSetSuppressionOptions", &input.configuration_set_name, |cs| {
            cs.suppression = Some(t2::SuppressionOptions {
                suppressed_reasons: input.suppressed_reasons,
                suppression_scope: input.suppression_scope,
                validation_options: input.validation_options,
            });
            Ok(Default::default())
        })
    }

    pub(crate) fn put_configuration_set_tracking_options_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutConfigurationSetTrackingOptionsRequest,
    ) -> Result<t2::PutConfigurationSetTrackingOptionsResponse, ServiceError> {
        if let Some(d) = &input.custom_redirect_domain {
            check_redirect_domain(d).map_err(v2::errors::bad_request)?;
        }
        self.update_set_v2(ctx, "PutConfigurationSetTrackingOptions", &input.configuration_set_name, |cs| {
            cs.tracking = input
                .custom_redirect_domain
                .map(|d| t2::TrackingOptions { custom_redirect_domain: d, https_policy: input.https_policy });
            Ok(Default::default())
        })
    }

    pub(crate) fn put_configuration_set_vdm_options_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutConfigurationSetVdmOptionsRequest,
    ) -> Result<t2::PutConfigurationSetVdmOptionsResponse, ServiceError> {
        self.update_set_v2(ctx, "PutConfigurationSetVdmOptions", &input.configuration_set_name, |cs| {
            cs.vdm = input.vdm_options;
            Ok(Default::default())
        })
    }

    pub(crate) fn update_configuration_set_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateConfigurationSetRequest,
    ) -> Result<t2::UpdateConfigurationSetResponse, ServiceError> {
        self.update_set_v2(ctx, "UpdateConfigurationSet", &input.configuration_set_name, |cs| {
            if input.message_security_options.is_some() {
                cs.message_security = input.message_security_options;
            }
            Ok(Default::default())
        })
    }
}

enum DestErr {
    NoSet,
    Exists,
    NoDestination,
    Limit,
}

impl DestErr {
    fn v1(self, set: &str, name: &str) -> ServiceError {
        match self {
            DestErr::NoSet => missing_v1(set),
            DestErr::Exists => v1::errors::event_destination_already_exists(format!(
                "Event destination {name} already exists in configuration set {set}."
            )),
            DestErr::NoDestination => {
                v1::errors::event_destination_does_not_exist(format!("No EventDestination found for {name}"))
            }
            DestErr::Limit => v1::errors::limit_exceeded("Maximum number of event destinations reached."),
        }
    }

    fn v2(self, set: &str, name: &str) -> ServiceError {
        match self {
            DestErr::NoSet => missing_v2(set),
            DestErr::Exists => v2::errors::already_exists(format!("Event destination {name} already exists.")),
            DestErr::NoDestination => v2::errors::not_found(format!("Event destination {name} does not exist.")),
            DestErr::Limit => v2::errors::limit_exceeded("Maximum number of event destinations reached."),
        }
    }
}

fn missing_v1(name: &str) -> ServiceError {
    v1::errors::configuration_set_does_not_exist(format!("Configuration set <{name}> does not exist."))
        .with_field("ConfigurationSetName", mws_core::ErrorValue::String(name.to_string()))
}

fn missing_v2(name: &str) -> ServiceError {
    v2::errors::not_found(format!("Configuration set <{name}> does not exist."))
}

fn check_redirect_domain(d: &str) -> Result<(), String> {
    if d.is_empty() || names::is_domain(d) {
        Ok(())
    } else {
        Err(format!("Invalid custom redirect domain {d}."))
    }
}

fn check_max_delivery(s: Option<i64>) -> Result<(), ServiceError> {
    match s {
        Some(s) if !(300..=50_400).contains(&s) => {
            Err(v2::errors::bad_request("MaxDeliverySeconds must be between 300 and 50400."))
        }
        _ => Ok(()),
    }
}

fn to_v1_destination(d: &EventDestination) -> t1::EventDestination {
    t1::EventDestination {
        name: d.name.clone(),
        enabled: d.enabled,
        matching_event_types: d.matching_event_types.iter().map(|t| v1_event_type(t).to_string()).collect(),
        kinesis_firehose_destination: d.firehose.as_ref().map(|f| t1::KinesisFirehoseDestination {
            iam_role_arn: f.iam_role_arn.clone(),
            delivery_stream_arn: f.delivery_stream_arn.clone(),
        }),
        cloud_watch_destination: d.cloudwatch.as_ref().map(|c| t1::CloudWatchDestination {
            dimension_configurations: c
                .dimension_configurations
                .iter()
                .map(|d| t1::CloudWatchDimensionConfiguration {
                    dimension_name: d.dimension_name.clone(),
                    dimension_value_source: match d.dimension_value_source.as_str() {
                        "MESSAGE_TAG" => "messageTag".into(),
                        "EMAIL_HEADER" => "emailHeader".into(),
                        "LINK_TAG" => "linkTag".into(),
                        other => other.to_string(),
                    },
                    default_dimension_value: d.default_dimension_value.clone(),
                })
                .collect(),
        }),
        sns_destination: d.sns.clone().map(|t| t1::SNSDestination { topic_arn: t }),
    }
}

fn to_v2_destination(d: &EventDestination) -> t2::EventDestination {
    t2::EventDestination {
        name: d.name.clone(),
        enabled: d.enabled,
        matching_event_types: d.matching_event_types.clone(),
        kinesis_firehose_destination: d.firehose.clone(),
        cloud_watch_destination: d.cloudwatch.clone(),
        sns_destination: d.sns.clone().map(|t| t2::SnsDestination { topic_arn: t }),
        event_bridge_destination: d.eventbridge.clone().map(|b| t2::EventBridgeDestination { event_bus_arn: b }),
        pinpoint_destination: d.pinpoint.clone().map(|a| t2::PinpointDestination { application_arn: Some(a) }),
    }
}
