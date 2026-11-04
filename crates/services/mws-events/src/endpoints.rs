//! Global endpoints: a pair of event buses in two Regions that
//! `PutEvents` with an `EndpointId` reaches through the primary Region.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::{errors, types};
use crate::names::{self, arn, not_found, own_region, validation, BusRef};
use crate::state::Endpoint;
use crate::Events;

/// Where an endpoint sends an event; see [`Events::endpoint_route`].
#[derive(Debug, Clone)]
pub(crate) struct EndpointRoute {
    pub bus: BusRef,
    /// The other Region's bus, when the endpoint replicates events.
    pub replica: Option<BusRef>,
}

fn endpoint_missing(name: &str) -> ServiceError {
    not_found(format!("Endpoint {name} does not exist."))
}

fn check_buses(buses: &[types::EndpointEventBus], routing: &types::RoutingConfig) -> Result<(), ServiceError> {
    if buses.len() != 2 {
        return Err(validation(
            "Parameter EventBuses is not valid. Reason: Exactly two event buses must be specified.",
        ));
    }
    let a = BusRef::from_arn(&buses[0].event_bus_arn);
    let b = BusRef::from_arn(&buses[1].event_bus_arn);
    let (Some(a), Some(b)) = (a, b) else {
        return Err(validation("Parameter EventBuses is not valid. Reason: Provided Arn is not in correct format."));
    };
    if a.name != b.name || a.account != b.account {
        return Err(validation(
            "Parameter EventBuses is not valid. Reason: Event buses must have the same name and account.",
        ));
    }
    if a.region == b.region {
        return Err(validation("Parameter EventBuses is not valid. Reason: Event buses must be in different Regions."));
    }
    let secondary = &routing.failover_config.secondary.route;
    if *secondary != a.region && *secondary != b.region {
        return Err(validation(
            "Parameter RoutingConfig is not valid. Reason: The secondary route must be the Region of one of the event buses.",
        ));
    }
    Ok(())
}

fn endpoint_id() -> String {
    let mut rng = rand::thread_rng();
    let mut letters = |n: usize| (0..n).map(|_| (b'a' + rng.gen_range(0..26)) as char).collect::<String>();
    let a = letters(5);
    let b = letters(3);
    format!("{a}.{b}")
}

fn describe(e: &Endpoint) -> types::DescribeEndpointResponse {
    types::DescribeEndpointResponse {
        name: Some(e.name.clone()),
        description: e.description.clone(),
        arn: Some(e.arn.clone()),
        routing_config: e.routing_config.clone(),
        replication_config: e.replication_config.clone(),
        event_buses: Some(e.event_buses.clone()),
        role_arn: e.role_arn.clone(),
        endpoint_id: Some(e.endpoint_id.clone()),
        endpoint_url: Some(e.endpoint_url.clone()),
        state: Some(e.state.clone()),
        state_reason: None,
        creation_time: e.creation_time,
        last_modified_time: e.last_modified_time,
    }
}

impl Events {
    fn endpoint(&self, ctx: &RequestContext, name: &str) -> Result<Endpoint, ServiceError> {
        let mut st = self.lock();
        own_region(&mut st, ctx).endpoints.get(name).cloned().ok_or_else(|| endpoint_missing(name))
    }

    /// Where `PutEvents` with this endpoint id puts events: the primary
    /// Region's bus while the primary health check is healthy, the
    /// secondary Region's bus once it is not; and, with replication
    /// enabled (the default), a copy on the other bus too.
    pub(crate) fn endpoint_route(&self, ctx: &RequestContext, id: &str) -> Result<EndpointRoute, ServiceError> {
        let e = {
            let st = self.lock();
            let prefix = format!("{}/", ctx.caller.account_id);
            st.regions
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .flat_map(|(_, r)| r.endpoints.values())
                .find(|e| e.endpoint_id == id)
                .cloned()
        }
        .ok_or_else(|| {
            validation(format!("Parameter EndpointId is not valid. Reason: Endpoint {id} does not exist."))
        })?;
        let buses: Vec<BusRef> = e.event_buses.iter().filter_map(|b| BusRef::from_arn(&b.event_bus_arn)).collect();
        let failover = e.routing_config.as_ref().map(|r| &r.failover_config);
        let secondary_region = failover.map(|f| f.secondary.route.clone());
        let home = names::split_arn(&e.arn).map(|p| p.2.to_string()).unwrap_or_default();
        let secondary = buses.iter().find(|b| Some(&b.region) == secondary_region.as_ref());
        let primary = buses
            .iter()
            .find(|b| Some(&b.region) != secondary_region.as_ref())
            .or_else(|| buses.iter().find(|b| b.region == home))
            .or(buses.first())
            .cloned()
            .ok_or_else(|| validation("The endpoint has no event buses."))?;
        let healthy = failover
            .map(|f| f.primary.health_check.as_str())
            .and_then(|hc| self.health_checks().and_then(|h| h.healthy(hc)))
            .unwrap_or(true);
        let (bus, other) = match secondary {
            Some(s) if !healthy => (s.clone(), Some(primary)),
            Some(s) => (primary, Some(s.clone())),
            None => (primary, None),
        };
        let replicate = e.replication_config.as_ref().and_then(|r| r.state.as_deref()) != Some("DISABLED");
        Ok(EndpointRoute { bus, replica: other.filter(|_| replicate) })
    }

    pub fn create_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::CreateEndpointRequest,
    ) -> Result<types::CreateEndpointResponse, ServiceError> {
        let endpoint_arn = arn(ctx, &format!("endpoint/{}", input.name));
        ctx.authorize("events:CreateEndpoint", &endpoint_arn, ConditionContext::new())?;
        check_buses(&input.event_buses, &input.routing_config)?;
        let replication =
            input.replication_config.clone().unwrap_or(types::ReplicationConfig { state: Some("ENABLED".into()) });
        if replication.state.as_deref() != Some("DISABLED") && input.role_arn.is_none() {
            return Err(validation("Parameter RoleArn must be specified when event replication is enabled."));
        }
        let id = endpoint_id();
        let now = ctx.received_at;
        let e = Endpoint {
            name: input.name.clone(),
            arn: endpoint_arn,
            description: input.description,
            routing_config: Some(input.routing_config),
            replication_config: Some(replication),
            event_buses: input.event_buses,
            role_arn: input.role_arn,
            endpoint_url: format!("https://{id}.endpoint.events.amazonaws.com"),
            endpoint_id: id,
            state: "ACTIVE".into(),
            creation_time: Some(now),
            last_modified_time: Some(now),
        };
        let mut st = self.lock();
        let region = own_region(&mut st, ctx);
        if region.endpoints.contains_key(&input.name) {
            return Err(errors::resource_already_exists(format!("Endpoint {} already exists.", input.name)));
        }
        region.endpoints.insert(input.name, e.clone());
        Ok(types::CreateEndpointResponse {
            name: Some(e.name),
            arn: Some(e.arn),
            routing_config: e.routing_config,
            replication_config: e.replication_config,
            event_buses: Some(e.event_buses),
            role_arn: e.role_arn,
            state: Some("CREATING".into()),
        })
    }

    pub fn describe_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEndpointRequest,
    ) -> Result<types::DescribeEndpointResponse, ServiceError> {
        let e = self.endpoint(ctx, &input.name)?;
        ctx.authorize("events:DescribeEndpoint", &e.arn, ConditionContext::new())?;
        Ok(describe(&e))
    }

    pub fn list_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::ListEndpointsRequest,
    ) -> Result<types::ListEndpointsResponse, ServiceError> {
        ctx.authorize("events:ListEndpoints", "*", ConditionContext::new())?;
        let items: Vec<types::Endpoint> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .endpoints
                .values()
                .filter(|e| input.name_prefix.as_deref().is_none_or(|p| e.name.starts_with(p)))
                .filter(|_| input.home_region.as_deref().is_none_or(|h| h == ctx.region))
                .map(|e| {
                    let d = describe(e);
                    types::Endpoint {
                        name: d.name,
                        description: d.description,
                        arn: d.arn,
                        routing_config: d.routing_config,
                        replication_config: d.replication_config,
                        event_buses: d.event_buses,
                        role_arn: d.role_arn,
                        endpoint_id: d.endpoint_id,
                        endpoint_url: d.endpoint_url,
                        state: d.state,
                        state_reason: None,
                        creation_time: d.creation_time,
                        last_modified_time: d.last_modified_time,
                    }
                })
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(types::ListEndpointsResponse { endpoints: Some(page), next_token })
    }

    pub fn update_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEndpointRequest,
    ) -> Result<types::UpdateEndpointResponse, ServiceError> {
        let mut e = self.endpoint(ctx, &input.name)?;
        ctx.authorize("events:UpdateEndpoint", &e.arn, ConditionContext::new())?;
        if input.description.is_some() {
            e.description = input.description;
        }
        if input.routing_config.is_some() {
            e.routing_config = input.routing_config;
        }
        if input.replication_config.is_some() {
            e.replication_config = input.replication_config;
        }
        if let Some(b) = input.event_buses {
            e.event_buses = b;
        }
        if input.role_arn.is_some() {
            e.role_arn = input.role_arn;
        }
        if let Some(r) = &e.routing_config {
            check_buses(&e.event_buses, r)?;
        }
        e.last_modified_time = Some(ctx.received_at);
        let mut st = self.lock();
        own_region(&mut st, ctx).endpoints.insert(e.name.clone(), e.clone());
        Ok(types::UpdateEndpointResponse {
            name: Some(e.name),
            arn: Some(e.arn),
            routing_config: e.routing_config,
            replication_config: e.replication_config,
            event_buses: Some(e.event_buses),
            role_arn: e.role_arn,
            endpoint_id: Some(e.endpoint_id),
            endpoint_url: Some(e.endpoint_url),
            state: Some("UPDATING".into()),
        })
    }

    pub fn delete_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEndpointRequest,
    ) -> Result<types::DeleteEndpointResponse, ServiceError> {
        let e = self.endpoint(ctx, &input.name)?;
        ctx.authorize("events:DeleteEndpoint", &e.arn, ConditionContext::new())?;
        let mut st = self.lock();
        own_region(&mut st, ctx).endpoints.remove(&input.name);
        Ok(types::DeleteEndpointResponse {})
    }
}
