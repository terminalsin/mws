//! Tags on event buses and rules.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types;
use crate::names::{self, not_found, request_tags, validation, BusRef};
use crate::Events;

const MAX_TAGS: usize = 50;

impl Events {
    /// The account and Region of a taggable resource, after checking it
    /// exists.
    fn taggable(&self, ctx: &RequestContext, arn: &str) -> Result<(String, String), ServiceError> {
        let Some((partition, service, region, account, resource)) = names::split_arn(arn) else {
            return Err(validation(format!("Parameter ResourceARN is not valid. Reason: {arn} is not a valid ARN.")));
        };
        if service != "events" {
            return Err(validation(format!(
                "Parameter ResourceARN is not valid. Reason: {arn} is not an EventBridge ARN."
            )));
        }
        let bus_of = |name: &str| BusRef {
            partition: partition.to_string(),
            account: account.to_string(),
            region: region.to_string(),
            name: name.to_string(),
        };
        let exists = if let Some(name) = resource.strip_prefix("event-bus/") {
            self.bus_exists(ctx, &bus_of(name))
        } else if let Some(rest) = resource.strip_prefix("rule/") {
            let (bus, rule) = rest.rsplit_once('/').unwrap_or(("default", rest));
            let bus = bus_of(bus);
            if !self.bus_exists(ctx, &bus) {
                return Err(bus.missing());
            }
            let found = self.with_bus(ctx, &bus, |b| Ok(b.rules.contains_key(rule)))?;
            if !found {
                return Err(not_found(format!("Rule {rule} does not exist on EventBus {}.", bus.name)));
            }
            true
        } else {
            let st = self.lock();
            st.region(account, region).is_some_and(|r| {
                r.archives.values().any(|a| a.arn == arn)
                    || r.connections.values().any(|c| c.arn == arn)
                    || r.api_destinations.values().any(|d| d.arn == arn)
                    || r.endpoints.values().any(|e| e.arn == arn)
            })
        };
        if !exists {
            return Err(not_found(format!("Resource {arn} does not exist.")));
        }
        Ok((account.to_string(), region.to_string()))
    }

    pub fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        let extra = request_tags(input.tags.iter().map(|t| (&t.key, &t.value)));
        self.authorize_own(ctx, "events:TagResource", &input.resource_arn, extra)?;
        let (account, region) = self.taggable(ctx, &input.resource_arn)?;
        let mut st = self.lock();
        let r = st.region_mut(&ctx.partition, &account, &region, ctx.received_at);
        let tags = r.tags.entry(input.resource_arn.clone()).or_default();
        let mut merged = tags.clone();
        for t in input.tags {
            if t.key.starts_with("aws:") {
                return Err(validation("Invalid tag key: tag keys must not start with aws:."));
            }
            merged.insert(t.key, t.value);
        }
        if merged.len() > MAX_TAGS {
            return Err(crate::generated::errors::limit_exceeded("The resource has too many tags."));
        }
        *tags = merged;
        Ok(types::TagResourceResponse {})
    }

    pub fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut extra = ConditionContext::new();
        extra.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize_own(ctx, "events:UntagResource", &input.resource_arn, extra)?;
        let (account, region) = self.taggable(ctx, &input.resource_arn)?;
        let mut st = self.lock();
        let r = st.region_mut(&ctx.partition, &account, &region, ctx.received_at);
        if let Some(tags) = r.tags.get_mut(&input.resource_arn) {
            for k in &input.tag_keys {
                tags.remove(k);
            }
        }
        Ok(types::UntagResourceResponse {})
    }

    pub fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.authorize_own(ctx, "events:ListTagsForResource", &input.resource_arn, ConditionContext::new())?;
        let (account, region) = self.taggable(ctx, &input.resource_arn)?;
        let st = self.lock();
        let tags = st
            .region(&account, &region)
            .and_then(|r| r.tags.get(&input.resource_arn))
            .map(|t| t.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect())
            .unwrap_or_default();
        Ok(types::ListTagsForResourceResponse { tags: Some(tags) })
    }
}
