//! ECS gateways: shared Application Load Balancer front doors that clusters
//! associate with and services reach through gateway connectors. MWS keeps
//! the control plane (gateways, associations, routes and the resource ARNs
//! AWS would create); no load balancer receives traffic.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types as t};
use crate::names::{
    authorize, check_tags, cluster_name, hex_id, invalid, last_segment, paginate, request_tags, resource_tags,
    split_arn, Cond, Scope,
};
use crate::state::{GatewayAssociation, GatewayRouteRecord, Region};
use crate::{clusters, tags, Ecs};

fn gateway_not_found() -> ServiceError {
    errors::gateway_not_found("The specified gateway does not exist.")
}

/// The gateway an ARN or name refers to.
fn find<'a>(r: &'a Region, reference: &str) -> Option<&'a t::Gateway> {
    if reference.starts_with("arn:") {
        r.gateways.get(reference)
    } else {
        r.gateways
            .values()
            .filter(|g| g.status.as_deref() != Some("DELETED"))
            .find(|g| g.name.as_deref() == Some(reference))
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

fn describe_config(c: &t::GatewayConfiguration, current: i32) -> t::DescribeGatewayConfiguration {
    match c {
        t::GatewayConfiguration::HostSharedAlb(a) => {
            t::DescribeGatewayConfiguration::HostSharedAlb(t::DescribeGatewayAlbConfiguration {
                network_configuration: a.network_configuration.clone(),
                scheme: Some(a.scheme.clone().unwrap_or_else(|| "internet-facing".into())),
                access_logs: a.access_logs.clone(),
                web_acl_arn: a.web_acl_arn.clone(),
                port: Some(a.port.unwrap_or(443)),
                protocol: Some(a.protocol.clone().unwrap_or_else(|| "HTTPS".into())),
                max_alb_count: Some(a.max_alb_count.unwrap_or(1)),
                current_alb_count: Some(current),
                http_desync: Some(a.http_desync.clone().unwrap_or_else(|| "defensive".into())),
                test_traffic_rules: a.test_traffic_rules.clone(),
            })
        }
    }
}

/// The load balancer AWS would create for a gateway.
fn alb_arn(scope: &Scope, gateway: &t::Gateway) -> String {
    let id = last_segment(gateway.gateway_arn.as_deref().unwrap_or_default()).to_string();
    format!(
        "arn:{}:elasticloadbalancing:{}:{}:loadbalancer/app/ecs-gw-{}/{}",
        scope.partition,
        scope.region,
        scope.account,
        gateway.name.clone().unwrap_or_default(),
        id
    )
}

impl Ecs {
    /// Create, for every ACTIVE service whose latest revision has gateway
    /// connectors, a route on each gateway its cluster is associated with.
    fn sync_routes(r: &mut Region, scope: &Scope) {
        let mut wanted: Vec<(String, String, String, String)> = Vec::new();
        for (arn, svc) in &r.services {
            if svc.service.status.as_deref() != Some("ACTIVE") {
                continue;
            }
            let Some(rev) = r
                .service_revisions
                .values()
                .filter(|v| v.service_arn.as_deref() == Some(arn.as_str()))
                .max_by_key(|v| v.created_at)
            else {
                continue;
            };
            let cluster_arn = scope.cluster_arn(&svc.cluster);
            for gc in rev.gateway_connectors.iter().flatten() {
                for a in r.gateway_associations.values() {
                    if a.cluster_arn == cluster_arn && a.status == "ASSOCIATED" {
                        wanted.push((a.gateway_arn.clone(), cluster_arn.clone(), arn.clone(), gc.port_name.clone()));
                    }
                }
            }
        }
        for rec in r.gateway_routes.values_mut() {
            let key = (
                rec.gateway_arn.clone(),
                rec.cluster_arn.clone(),
                rec.route.service_arn.clone().unwrap_or_default(),
                rec.route.service_container_port_name.clone().unwrap_or_default(),
            );
            if !wanted.contains(&key) && rec.route.status.as_deref() == Some("ACTIVE") {
                rec.route.status = Some("DELETED".into());
            }
        }
        for (gateway_arn, cluster_arn, service_arn, port) in wanted {
            let exists = r.gateway_routes.values().any(|x| {
                x.gateway_arn == gateway_arn
                    && x.route.service_arn.as_deref() == Some(service_arn.as_str())
                    && x.route.service_container_port_name.as_deref() == Some(port.as_str())
                    && x.route.status.as_deref() == Some("ACTIVE")
            });
            if exists {
                continue;
            }
            let Some(gw) = r.gateways.get(&gateway_arn) else { continue };
            let gw_res = gateway_arn.splitn(2, ":gateway/").nth(1).unwrap_or_default().to_string();
            let route_arn = scope.arn(&format!("gateway-route/{gw_res}/{}", hex_id()));
            let lb = alb_arn(scope, gw);
            let service_name = last_segment(&service_arn).to_string();
            let route = t::GatewayRoute {
                gateway_route_arn: Some(route_arn.clone()),
                service_arn: Some(service_arn.clone()),
                service_container_port_name: Some(port.clone()),
                status: Some("ACTIVE".into()),
                service_url: Some(format!(
                    "https://{service_name}-{port}.{}.ecs.{}.on.aws",
                    gw.name.clone().unwrap_or_default(),
                    scope.region
                )),
                resources: Some(t::GatewayRouteResources::HostSharedAlb(vec![t::GatewayRouteAlbResources {
                    acm_certificate_arn: None,
                    load_balancer_arn: Some(lb.clone()),
                    listener_arn: Some(lb.replacen(":loadbalancer/", ":listener/", 1) + "/1"),
                    listener_rule_arn: Some(format!(
                        "{}/{}",
                        lb.replacen(":loadbalancer/", ":listener-rule/", 1),
                        hex_id()
                    )),
                    test_listener_rule_arns: Some(Vec::new()),
                    load_balancer_security_groups: Some(Vec::new()),
                    service_security_group_arn: None,
                }])),
            };
            r.gateway_routes.insert(route_arn, GatewayRouteRecord { route, gateway_arn, cluster_arn });
        }
    }

    fn gateway_for(&self, ctx: &RequestContext, action: &str, reference: &str) -> Result<t::Gateway, ServiceError> {
        let (gw, tags) = self.with_region(ctx, |r, _| {
            let g = find(r, reference).cloned();
            let tags = g.as_ref().and_then(|g| r.tags.get(g.gateway_arn.as_deref().unwrap_or_default()).cloned());
            (g, tags)
        });
        let arn = gw.as_ref().and_then(|g| g.gateway_arn.clone()).unwrap_or_else(|| {
            let scope = Scope::of(ctx);
            scope.arn(&format!("gateway/{reference}/*"))
        });
        authorize(ctx, action, &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        gw.filter(|g| g.status.as_deref() != Some("DELETED")).ok_or_else(gateway_not_found)
    }

    pub(crate) fn create_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateGatewayRequest,
    ) -> Result<t::CreateGatewayResponse, ServiceError> {
        if !valid_name(&input.name) {
            return Err(invalid(
                "Gateway name must be 1-32 characters: letters, numbers and hyphens, not starting or ending with a hyphen.",
            ));
        }
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let scope = Scope::of(ctx);
        let arn = scope.arn(&format!("gateway/{}/{}", input.name, hex_id()));
        authorize(ctx, "CreateGateway", &arn, Cond::new().extend(request_tags(input.tags.as_ref())))?;
        self.pass_role(ctx, &input.infrastructure_role_arn, "ecs.amazonaws.com")?;
        self.authorize_create_tags(ctx, &arn, "CreateGateway", input.tags.as_ref())?;
        let now = ctx.received_at;
        self.with_region(ctx, |r, _| {
            if let Some(token) = &input.client_token {
                if let Some((kind, existing)) = r.client_tokens.get(token) {
                    if kind == &format!("gateway:{}", input.name) {
                        let g = &r.gateways[existing];
                        return Ok(t::CreateGatewayResponse {
                            gateway_arn: g.gateway_arn.clone(),
                            name: g.name.clone(),
                            status: g.status.clone(),
                        });
                    }
                    return Err(invalid("The client token was already used with different parameters."));
                }
            }
            if find(r, &input.name).is_some() {
                return Err(invalid(format!("A gateway named {} already exists.", input.name)));
            }
            let mut gateway = t::Gateway {
                gateway_arn: Some(arn.clone()),
                name: Some(input.name.clone()),
                status: Some("ACTIVE".into()),
                status_reason: None,
                failures: Some(Vec::new()),
                infrastructure_role_arn: Some(input.infrastructure_role_arn.clone()),
                deletion_protection: Some(input.deletion_protection.unwrap_or(false)),
                configuration: Some(describe_config(&input.configuration, 1)),
                access_type: None,
                propagate_tags: Some(input.propagate_tags.clone().unwrap_or_else(|| "NONE".into())),
                tags: None,
                created_at: Some(now),
                updated_at: Some(now),
            };
            let t::GatewayConfiguration::HostSharedAlb(a) = &input.configuration;
            gateway.access_type =
                Some(if a.scheme.as_deref() == Some("internal") { "PRIVATE" } else { "PUBLIC" }.to_string());
            r.gateways.insert(arn.clone(), gateway);
            tags::store(r, &arn, input.tags.as_ref());
            if let Some(token) = &input.client_token {
                r.client_tokens.insert(token.clone(), (format!("gateway:{}", input.name), arn.clone()));
            }
            Ok(t::CreateGatewayResponse {
                gateway_arn: Some(arn.clone()),
                name: Some(input.name.clone()),
                status: Some("ACTIVE".into()),
            })
        })
    }

    pub(crate) fn describe_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeGatewayRequest,
    ) -> Result<t::DescribeGatewayResponse, ServiceError> {
        let mut g = self.gateway_for(ctx, "DescribeGateway", &input.gateway)?;
        let arn = g.gateway_arn.clone().unwrap_or_default();
        g.tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        Ok(t::DescribeGatewayResponse { gateway: Some(g) })
    }

    pub(crate) fn list_gateways_op(
        &self,
        ctx: &RequestContext,
        input: t::ListGatewaysRequest,
    ) -> Result<t::ListGatewaysResponse, ServiceError> {
        authorize(ctx, "ListGateways", "*", Cond::new())?;
        self.with_region(ctx, |r, _| {
            let out: Vec<t::GatewaySummary> = r
                .gateways
                .values()
                .filter(|g| match &input.status {
                    Some(s) => s.contains(&g.status.clone().unwrap_or_default()),
                    None => g.status.as_deref() != Some("DELETED"),
                })
                .filter(|g| input.names.as_ref().is_none_or(|n| n.contains(&g.name.clone().unwrap_or_default())))
                .map(|g| t::GatewaySummary {
                    gateway_arn: g.gateway_arn.clone(),
                    name: g.name.clone(),
                    status: g.status.clone(),
                    created_at: g.created_at,
                })
                .collect();
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListGatewaysResponse { gateways: Some(page), next_token })
        })
    }

    pub(crate) fn update_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateGatewayRequest,
    ) -> Result<t::UpdateGatewayResponse, ServiceError> {
        let g = self.gateway_for(ctx, "UpdateGateway", &input.gateway)?;
        if let Some(role) = &input.infrastructure_role_arn {
            self.pass_role(ctx, role, "ecs.amazonaws.com")?;
        }
        let arn = g.gateway_arn.clone().unwrap_or_default();
        let now = ctx.received_at;
        self.with_region(ctx, |r, _| {
            let g = r.gateways.get_mut(&arn).ok_or_else(gateway_not_found)?;
            if let Some(v) = &input.infrastructure_role_arn {
                g.infrastructure_role_arn = Some(v.clone());
            }
            if let Some(v) = input.deletion_protection {
                g.deletion_protection = Some(v);
            }
            if let Some(v) = &input.propagate_tags {
                g.propagate_tags = Some(v.clone());
            }
            if let (Some(t::UpdateGatewayConfiguration::HostSharedAlb(u)), Some(t::DescribeGatewayConfiguration::HostSharedAlb(c))) =
                (&input.configuration, g.configuration.as_mut())
            {
                if let Some(sg) = u.network_configuration.as_ref().and_then(|n| n.inbound_security_group.clone()) {
                    c.network_configuration.get_or_insert_with(Default::default).inbound_security_group = Some(sg);
                }
                if u.max_alb_count.is_some() {
                    c.max_alb_count = u.max_alb_count;
                }
                if u.web_acl_arn.is_some() {
                    c.web_acl_arn = u.web_acl_arn.clone();
                }
                if u.access_logs.is_some() {
                    c.access_logs = u.access_logs.clone();
                }
                if u.http_desync.is_some() {
                    c.http_desync = u.http_desync.clone();
                }
                if u.test_traffic_rules.is_some() {
                    c.test_traffic_rules = u.test_traffic_rules.clone();
                }
            }
            g.updated_at = Some(now);
            Ok(t::UpdateGatewayResponse { gateway_arn: g.gateway_arn.clone(), name: g.name.clone(), status: g.status.clone() })
        })
    }

    pub(crate) fn delete_gateway_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteGatewayRequest,
    ) -> Result<t::DeleteGatewayResponse, ServiceError> {
        let g = self.gateway_for(ctx, "DeleteGateway", &input.gateway)?;
        let arn = g.gateway_arn.clone().unwrap_or_default();
        let now = ctx.received_at;
        self.with_region(ctx, |r, _| {
            if g.deletion_protection == Some(true) {
                return Err(invalid("The gateway has deletion protection enabled. Disable it before deleting the gateway."));
            }
            if r.gateway_associations.values().any(|a| a.gateway_arn == arn && a.status == "ASSOCIATED") {
                return Err(errors::resource_in_use(
                    "The gateway is associated with one or more clusters. Disassociate them before deleting the gateway.",
                ));
            }
            let g = r.gateways.get_mut(&arn).ok_or_else(gateway_not_found)?;
            g.status = Some("DELETED".into());
            g.updated_at = Some(now);
            let out = t::DeleteGatewayResponse { gateway_arn: g.gateway_arn.clone(), name: g.name.clone(), status: g.status.clone() };
            r.tags.remove(&arn);
            Ok(out)
        })
    }

    fn association(
        &self,
        ctx: &RequestContext,
        action: &str,
        gateway: &str,
        cluster: &str,
    ) -> Result<(t::Gateway, String), ServiceError> {
        let g = self.gateway_for(ctx, action, gateway)?;
        let scope = Scope::of(ctx);
        let name = cluster_name(Some(cluster));
        authorize(ctx, action, &scope.cluster_arn(&name), Cond::new())?;
        self.with_region(ctx, |r, _| clusters::active(r, Some(&name)).map(|_| ()))?;
        Ok((g, scope.cluster_arn(&name)))
    }

    pub(crate) fn associate_gateway_with_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateGatewayWithClusterRequest,
    ) -> Result<t::AssociateGatewayWithClusterResponse, ServiceError> {
        let (g, cluster_arn) = self.association(ctx, "AssociateGatewayWithCluster", &input.gateway, &input.cluster)?;
        let gateway_arn = g.gateway_arn.clone().unwrap_or_default();
        self.with_region(ctx, |r, scope| {
            let key = format!("{gateway_arn}|{cluster_arn}");
            if r.gateway_associations.get(&key).is_some_and(|a| a.status == "ASSOCIATED") {
                return Err(invalid("The gateway is already associated with the cluster."));
            }
            r.gateway_associations.insert(
                key,
                GatewayAssociation { gateway_arn: gateway_arn.clone(), cluster_arn: cluster_arn.clone(), status: "ASSOCIATED".into() },
            );
            Self::sync_routes(r, scope);
            Ok(t::AssociateGatewayWithClusterResponse {
                gateway_arn: Some(gateway_arn.clone()),
                cluster_arn: Some(cluster_arn.clone()),
                status: Some("ASSOCIATED".into()),
            })
        })
    }

    pub(crate) fn disassociate_gateway_from_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::DisassociateGatewayFromClusterRequest,
    ) -> Result<t::DisassociateGatewayFromClusterResponse, ServiceError> {
        let (g, cluster_arn) =
            self.association(ctx, "DisassociateGatewayFromCluster", &input.gateway, &input.cluster)?;
        let gateway_arn = g.gateway_arn.clone().unwrap_or_default();
        self.with_region(ctx, |r, scope| {
            let key = format!("{gateway_arn}|{cluster_arn}");
            let a = r
                .gateway_associations
                .get_mut(&key)
                .filter(|a| a.status == "ASSOCIATED")
                .ok_or_else(|| invalid("The gateway is not associated with the cluster."))?;
            a.status = "DISASSOCIATED".into();
            Self::sync_routes(r, scope);
            Ok(t::DisassociateGatewayFromClusterResponse {
                gateway_arn: Some(gateway_arn.clone()),
                cluster_arn: Some(cluster_arn.clone()),
                status: Some("DISASSOCIATED".into()),
            })
        })
    }

    pub(crate) fn list_gateway_cluster_associations_op(
        &self,
        ctx: &RequestContext,
        input: t::ListGatewayClusterAssociationsRequest,
    ) -> Result<t::ListGatewayClusterAssociationsResponse, ServiceError> {
        authorize(ctx, "ListGatewayClusterAssociations", "*", Cond::new())?;
        let scope = Scope::of(ctx);
        let cluster = input.cluster.as_deref().map(|c| scope.cluster_arn(&cluster_name(Some(c))));
        self.with_region(ctx, |r, _| {
            let gateway = match &input.gateway {
                Some(g) => Some(find(r, g).and_then(|g| g.gateway_arn.clone()).ok_or_else(gateway_not_found)?),
                None => None,
            };
            let out: Vec<t::GatewayClusterAssociationSummary> = r
                .gateway_associations
                .values()
                .filter(|a| gateway.as_ref().is_none_or(|g| &a.gateway_arn == g))
                .filter(|a| cluster.as_ref().is_none_or(|c| &a.cluster_arn == c))
                .filter(|a| match &input.status {
                    Some(s) => s.contains(&a.status),
                    None => a.status == "ASSOCIATED",
                })
                .map(|a| t::GatewayClusterAssociationSummary {
                    gateway_arn: Some(a.gateway_arn.clone()),
                    cluster_arn: Some(a.cluster_arn.clone()),
                    status: Some(a.status.clone()),
                })
                .collect();
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListGatewayClusterAssociationsResponse { gateway_cluster_associations: Some(page), next_token })
        })
    }

    pub(crate) fn describe_gateway_resources_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeGatewayResourcesRequest,
    ) -> Result<t::DescribeGatewayResourcesResponse, ServiceError> {
        let g = self.gateway_for(ctx, "DescribeGatewayResources", &input.gateway)?;
        let arn = g.gateway_arn.clone().unwrap_or_default();
        self.with_region(ctx, |r, scope| {
            Self::sync_routes(r, scope);
            let lb = alb_arn(scope, &g);
            let routes: Vec<String> = r
                .gateway_routes
                .values()
                .filter(|x| x.gateway_arn == arn && x.route.status.as_deref() == Some("ACTIVE"))
                .filter_map(|x| x.route.gateway_route_arn.clone())
                .collect();
            let (page, next_token) = paginate(&routes, input.next_token.as_deref(), input.max_results, 100)?;
            let sg_id = format!("sg-{}", &hex_id()[..17]);
            Ok(t::DescribeGatewayResourcesResponse {
                gateway_resources: Some(t::GatewayResources {
                    gateway_arn: Some(arn.clone()),
                    resources: Some(t::GatewayInfrastructureResources::HostSharedAlb(vec![t::ElbGatewayResources {
                        load_balancer_arn: Some(lb.clone()),
                        listener_arn: Some(lb.replacen(":loadbalancer/", ":listener/", 1) + "/1"),
                        security_group: Some(format!(
                            "arn:{}:ec2:{}:{}:security-group/{sg_id}",
                            scope.partition, scope.region, scope.account
                        )),
                        gateway_route_arns: Some(page),
                    }])),
                }),
                next_token,
            })
        })
    }

    pub(crate) fn list_gateway_routes_op(
        &self,
        ctx: &RequestContext,
        input: t::ListGatewayRoutesRequest,
    ) -> Result<t::ListGatewayRoutesResponse, ServiceError> {
        authorize(ctx, "ListGatewayRoutes", "*", Cond::new())?;
        let scope = Scope::of(ctx);
        let cluster = input.cluster.as_deref().map(|c| scope.cluster_arn(&cluster_name(Some(c))));
        self.with_region(ctx, |r, scope| {
            Self::sync_routes(r, scope);
            let gateway = match &input.gateway {
                Some(g) => Some(find(r, g).and_then(|g| g.gateway_arn.clone()).ok_or_else(gateway_not_found)?),
                None => None,
            };
            let out: Vec<t::GatewayRouteSummary> = r
                .gateway_routes
                .values()
                .filter(|x| gateway.as_ref().is_none_or(|g| &x.gateway_arn == g))
                .filter(|x| cluster.as_ref().is_none_or(|c| &x.cluster_arn == c))
                .filter(|x| {
                    input.service.as_ref().is_none_or(|s| {
                        let arn = x.route.service_arn.as_deref().unwrap_or_default();
                        arn == s || last_segment(arn) == s
                    })
                })
                .filter(|x| {
                    input.service_container_port_name.as_ref().is_none_or(|p| x.route.service_container_port_name.as_ref() == Some(p))
                })
                .filter(|x| match &input.status {
                    Some(s) => s.contains(&x.route.status.clone().unwrap_or_default()),
                    None => x.route.status.as_deref() == Some("ACTIVE"),
                })
                .map(|x| t::GatewayRouteSummary {
                    gateway_route_arn: x.route.gateway_route_arn.clone(),
                    gateway_arn: Some(x.gateway_arn.clone()),
                    cluster_arn: Some(x.cluster_arn.clone()),
                    service_arn: x.route.service_arn.clone(),
                    service_container_port_name: x.route.service_container_port_name.clone(),
                    status: x.route.status.clone(),
                })
                .collect();
            let (page, next_token) = paginate(&out, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListGatewayRoutesResponse { gateway_routes: Some(page), next_token })
        })
    }

    pub(crate) fn describe_gateway_route_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeGatewayRouteRequest,
    ) -> Result<t::DescribeGatewayRouteResponse, ServiceError> {
        authorize(ctx, "DescribeGatewayRoute", &input.gateway_route_arn, Cond::new())?;
        if split_arn(&input.gateway_route_arn).is_none() {
            return Err(invalid("The gateway route ARN is invalid."));
        }
        self.with_region(ctx, |r, scope| {
            Self::sync_routes(r, scope);
            r.gateway_routes
                .get(&input.gateway_route_arn)
                .map(|x| t::DescribeGatewayRouteResponse { gateway_route: Some(x.route.clone()) })
                .ok_or_else(|| errors::resource_not_found("The specified gateway route does not exist."))
        })
    }
}
