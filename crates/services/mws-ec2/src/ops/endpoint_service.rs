//! VPC endpoint services (AWS PrivateLink): services an account offers
//! behind its Network or Gateway Load Balancers, the principals allowed to
//! connect, and the interface and Gateway Load Balancer endpoints other VPCs
//! (in any account) create to them, which wait for acceptance when the
//! service requires it.
//!
//! Endpoints get their interfaces and DNS names; traffic is not carried
//! through them.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::EndpointServiceRecord;
use crate::util::{
    arn, authorize, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context,
    resource_tag_context, s, some_tags, tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

fn service_not_found(id: &str) -> ServiceError {
    err("InvalidVpcEndpointServiceId.NotFound", format!("The Vpc Endpoint Service Id '{id}' does not exist"))
}

fn unsuccessful(id: &str, e: &ServiceError) -> t::UnsuccessfulItem {
    t::UnsuccessfulItem {
        resource_id: Some(id.into()),
        error: Some(t::UnsuccessfulItemError { code: Some(e.code.to_string()), message: Some(e.message.to_string()) }),
    }
}

pub(crate) fn custom_service_name(region: &str, id: &str) -> String {
    format!("com.amazonaws.vpce.{region}.{id}")
}

/// The service id in a custom service name.
pub(crate) fn custom_service_id(name: &str) -> Option<&str> {
    name.rsplit('.').next().filter(|id| id.starts_with("vpce-svc-") && name.starts_with("com.amazonaws.vpce."))
}

/// A custom endpoint service the caller can see.
pub(crate) struct Visible {
    pub owner: String,
    pub config: t::ServiceConfiguration,
}

/// Whether `permissions` let the caller connect.
fn allowed(permissions: &[t::AllowedPrincipal], ctx: &RequestContext) -> bool {
    let account = account_of(ctx);
    let root = format!("arn:{}:iam::{account}:root", ctx.partition);
    let caller = ctx.caller.arn.clone();
    // An assumed-role session counts as its role.
    let role = caller.strip_prefix(&format!("arn:{}:sts::{account}:assumed-role/", ctx.partition)).and_then(|rest| {
        rest.split('/').next().map(|name| format!("arn:{}:iam::{account}:role/{name}", ctx.partition))
    });
    permissions.iter().any(|p| match p.principal.as_deref() {
        Some("*") => true,
        Some(x) => x == root || x == caller || role.as_deref() == Some(x),
        None => false,
    })
}

/// A service as `DescribeVpcEndpointServices` lists it.
fn detail(config: &t::ServiceConfiguration, owner: &str, region: &str, own: bool) -> t::ServiceDetail {
    let pdns = config.private_dns_name_configuration.clone().unwrap_or_default();
    t::ServiceDetail {
        service_name: config.service_name.clone(),
        service_id: config.service_id.clone(),
        service_type: config.service_type.clone(),
        service_region: Some(region.into()),
        availability_zone_ids: config.availability_zone_ids.clone(),
        availability_zones: config.availability_zones.clone(),
        owner: Some(owner.into()),
        base_endpoint_dns_names: config.base_endpoint_dns_names.clone(),
        private_dns_name: config.private_dns_name.clone(),
        private_dns_names: config
            .private_dns_name
            .as_ref()
            .map(|n| vec![t::PrivateDnsDetails { private_dns_name: Some(n.clone()) }]),
        vpc_endpoint_policy_supported: Some(false),
        acceptance_required: config.acceptance_required,
        manages_vpc_endpoints: Some(false),
        payer_responsibility: config.payer_responsibility.clone(),
        tags: if own { config.tags.clone() } else { None },
        private_dns_name_verification_state: config
            .private_dns_name
            .as_ref()
            .map(|_| pdns.state.clone().unwrap_or_default()),
        supported_ip_address_types: config.supported_ip_address_types.clone(),
    }
}

impl Ec2 {
    /// The custom services in the caller's Region they own or may connect
    /// to, with their owners.
    pub(crate) fn visible_endpoint_services(&self, ctx: &RequestContext) -> Vec<Visible> {
        let account = account_of(ctx);
        let suffix = format!("/{}", ctx.region);
        let st = self.lock();
        let mut out = Vec::new();
        for (key, r) in &st.regions {
            let Some(owner) = key.strip_suffix(&suffix) else { continue };
            for svc in r.endpoint_services.values() {
                if owner == account || allowed(&svc.permissions, ctx) {
                    out.push(Visible { owner: owner.to_string(), config: svc.config.clone() });
                }
            }
        }
        out
    }

    /// `DescribeVpcEndpointServices` entries for custom services.
    pub(crate) fn custom_service_details(&self, ctx: &RequestContext) -> Vec<t::ServiceDetail> {
        let account = account_of(ctx);
        self.visible_endpoint_services(ctx)
            .into_iter()
            .filter(|v| v.config.service_state.as_deref() == Some("Available"))
            .map(|v| detail(&v.config, &v.owner, &ctx.region, v.owner == account))
            .collect()
    }

    /// The owning account of a service id in `region`.
    fn service_owner(&self, region: &str, id: &str) -> Option<String> {
        let suffix = format!("/{region}");
        let st = self.lock();
        st.regions.iter().find_map(|(key, r)| {
            r.endpoint_services.contains_key(id).then(|| key.strip_suffix(&suffix).map(str::to_string)).flatten()
        })
    }

    fn with_service<R>(
        &self,
        ctx: &RequestContext,
        id: &str,
        f: impl FnOnce(&mut EndpointServiceRecord) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        self.with_region(ctx, |r| {
            let svc = r.endpoint_services.get_mut(id).ok_or_else(|| service_not_found(id))?;
            f(svc)
        })
    }

    fn service_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        ids: &[String],
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let resources: Vec<(String, ConditionContext)> = self.with_region(ctx, |r| {
            ids.iter()
                .map(|id| {
                    (
                        arn(ctx, &account, &format!("vpc-endpoint-service/{id}")),
                        resource_tag_context(r.endpoint_services.get(id).and_then(|s| s.config.tags.as_ref())),
                    )
                })
                .collect()
        });
        authorize(ctx, action, &resources, dry_run)
    }

    /// Check load balancer ARNs: they must exist (when ELB is wired in) and
    /// be of `lb_type`; returns their zones.
    fn balancer_zones(
        &self,
        ctx: &RequestContext,
        arns: &[String],
        lb_type: &str,
    ) -> Result<Vec<String>, ServiceError> {
        let account = account_of(ctx);
        let mut zones: Vec<String> = Vec::new();
        for a in arns {
            let segment = if lb_type == "network" { "/net/" } else { "/gwy/" };
            if !a.starts_with("arn:") || !a.contains(":elasticloadbalancing:") || !a.contains(segment) {
                return Err(err(
                    "InvalidParameter",
                    format!("Load balancer ARN '{a}' is not a valid {lb_type} load balancer ARN."),
                ));
            }
            match self.load_balancers() {
                Some(lbs) => {
                    let (ty, z) = lbs
                        .load_balancer(&account, &ctx.region, a)
                        .ok_or_else(|| err("InvalidParameter", format!("The load balancer '{a}' does not exist.")))?;
                    if ty != lb_type {
                        return Err(err(
                            "InvalidParameter",
                            format!("The load balancer '{a}' is not a {lb_type} load balancer."),
                        ));
                    }
                    for zone in z {
                        if !zones.contains(&zone) {
                            zones.push(zone);
                        }
                    }
                }
                None => {
                    for (z, _) in crate::catalog::zones(&ctx.region) {
                        if !zones.contains(&z) {
                            zones.push(z);
                        }
                    }
                }
            }
        }
        zones.sort();
        Ok(zones)
    }

    pub(crate) fn create_vpc_endpoint_service_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVpcEndpointServiceConfigurationRequest,
    ) -> Result<t::CreateVpcEndpointServiceConfigurationResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "vpc-endpoint-service", &["vpc-endpoint-service"])?;
        let nlbs = input.network_load_balancer_arns.clone().unwrap_or_default();
        let gwlbs = input.gateway_load_balancer_arns.clone().unwrap_or_default();
        let (kind, lb_type, arns) = match (nlbs.is_empty(), gwlbs.is_empty()) {
            (false, true) => ("Interface", "network", nlbs.clone()),
            (true, false) => ("GatewayLoadBalancer", "gateway", gwlbs.clone()),
            (true, true) => return Err(missing_parameter("NetworkLoadBalancerArns or GatewayLoadBalancerArns")),
            (false, false) => {
                return Err(err(
                    "InvalidParameterCombination",
                    "NetworkLoadBalancerArns and GatewayLoadBalancerArns cannot be specified together.",
                ))
            }
        };
        if kind == "GatewayLoadBalancer" && input.private_dns_name.is_some() {
            return Err(err(
                "InvalidParameter",
                "Private DNS names are not supported for Gateway Load Balancer endpoint services.",
            ));
        }
        let ip_types = input.supported_ip_address_types.clone().unwrap_or_else(|| vec!["ipv4".into()]);
        for ip in &ip_types {
            if ip != "ipv4" && ip != "ipv6" {
                return Err(invalid_parameter(format!(
                    "Value ({ip}) for parameter supportedIpAddressTypes is invalid."
                )));
            }
        }
        let account = account_of(ctx);
        authorize(
            ctx,
            "CreateVpcEndpointServiceConfiguration",
            &[(arn(ctx, &account, "vpc-endpoint-service/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        let zones = self.balancer_zones(ctx, &arns, lb_type)?;
        let region = ctx.region.clone();
        self.with_region(ctx, |r| {
            let id = new_id("vpce-svc");
            let pdns = input.private_dns_name.as_ref().map(|name| {
                let token = new_id("x")[2..14].to_string();
                t::PrivateDnsNameConfiguration {
                    state: Some("pendingVerification".into()),
                    r#type: Some("TXT".into()),
                    value: Some(format!("vpce:{token}")),
                    name: Some(format!("_{}.{name}", &token[..8])),
                }
            });
            let mut regions = vec![t::SupportedRegionDetail {
                region: Some(region.clone()),
                service_state: Some("Available".into()),
            }];
            for other in input.supported_regions.iter().flatten() {
                if other != &region {
                    regions.push(t::SupportedRegionDetail {
                        region: Some(other.clone()),
                        service_state: Some("Available".into()),
                    });
                }
            }
            let config = t::ServiceConfiguration {
                service_type: Some(vec![t::ServiceTypeDetail { service_type: Some(kind.into()) }]),
                service_id: Some(id.clone()),
                service_name: Some(custom_service_name(&region, &id)),
                service_state: Some("Available".into()),
                availability_zone_ids: Some(zones.iter().filter_map(|z| crate::catalog::zone_id(&region, z)).collect()),
                availability_zones: Some(zones.clone()),
                acceptance_required: Some(input.acceptance_required.unwrap_or(true)),
                manages_vpc_endpoints: Some(false),
                network_load_balancer_arns: (!nlbs.is_empty()).then(|| nlbs.clone()),
                gateway_load_balancer_arns: (!gwlbs.is_empty()).then(|| gwlbs.clone()),
                supported_ip_address_types: Some(ip_types.clone()),
                base_endpoint_dns_names: (kind == "Interface")
                    .then(|| vec![format!("{id}.{region}.vpce.amazonaws.com")]),
                private_dns_name: input.private_dns_name.clone(),
                private_dns_name_configuration: pdns,
                payer_responsibility: Some("ServiceOwner".into()),
                tags: some_tags(tags.clone()),
                supported_regions: Some(regions),
                remote_access_enabled: Some(false),
            };
            r.endpoint_services.insert(
                id,
                EndpointServiceRecord {
                    config: config.clone(),
                    permissions: Vec::new(),
                    connections: Default::default(),
                },
            );
            Ok(t::CreateVpcEndpointServiceConfigurationResult {
                service_configuration: Some(config),
                client_token: input.client_token.clone(),
            })
        })
    }

    pub(crate) fn describe_vpc_endpoint_service_configurations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcEndpointServiceConfigurationsRequest,
    ) -> Result<t::DescribeVpcEndpointServiceConfigurationsResult, ServiceError> {
        authorize(
            ctx,
            "DescribeVpcEndpointServiceConfigurations",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let ids = input.service_ids.clone().unwrap_or_default();
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            for id in &ids {
                if !r.endpoint_services.contains_key(id) {
                    return Err(service_not_found(id));
                }
            }
            let mut out = Vec::new();
            for svc in r.endpoint_services.values() {
                let c = &svc.config;
                let id = c.service_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(c.tags.as_ref(), |name| {
                    Some(match name {
                        "service-name" => s(&c.service_name),
                        "service-id" => vec![id.clone()],
                        "service-state" => s(&c.service_state),
                        "supported-ip-address-types" => c.supported_ip_address_types.clone().unwrap_or_default(),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(c.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVpcEndpointServiceConfigurationsResult { service_configurations: Some(items), next_token })
        })
    }

    pub(crate) fn modify_vpc_endpoint_service_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVpcEndpointServiceConfigurationRequest,
    ) -> Result<t::ModifyVpcEndpointServiceConfigurationResult, ServiceError> {
        let id = input.service_id.clone();
        self.service_authorize(ctx, "ModifyVpcEndpointServiceConfiguration", std::slice::from_ref(&id), input.dry_run)?;
        if input.private_dns_name.is_some() && input.remove_private_dns_name == Some(true) {
            return Err(err(
                "InvalidParameterCombination",
                "PrivateDnsName and RemovePrivateDnsName cannot be specified together.",
            ));
        }
        let (nlbs, gwlbs) = self.with_service(ctx, &id, |svc| {
            Ok((
                svc.config.network_load_balancer_arns.clone().unwrap_or_default(),
                svc.config.gateway_load_balancer_arns.clone().unwrap_or_default(),
            ))
        })?;
        let edit = |current: Vec<String>, add: &Option<Vec<String>>, remove: &Option<Vec<String>>| -> Vec<String> {
            let mut v = current;
            for a in add.iter().flatten() {
                if !v.contains(a) {
                    v.push(a.clone());
                }
            }
            v.retain(|x| !remove.iter().flatten().any(|r| r == x));
            v
        };
        let nlbs2 = edit(nlbs.clone(), &input.add_network_load_balancer_arns, &input.remove_network_load_balancer_arns);
        let gwlbs2 =
            edit(gwlbs.clone(), &input.add_gateway_load_balancer_arns, &input.remove_gateway_load_balancer_arns);
        let interface = !nlbs.is_empty();
        if (interface && !gwlbs2.is_empty()) || (!interface && !nlbs2.is_empty()) {
            return Err(err(
                "InvalidParameterCombination",
                "An endpoint service cannot have both Network and Gateway Load Balancers.",
            ));
        }
        if nlbs2.is_empty() && gwlbs2.is_empty() {
            return Err(err("InvalidParameter", "An endpoint service must have at least one load balancer."));
        }
        let zones = if interface {
            self.balancer_zones(ctx, &nlbs2, "network")?
        } else {
            self.balancer_zones(ctx, &gwlbs2, "gateway")?
        };
        let region = ctx.region.clone();
        self.with_service(ctx, &id, |svc| {
            let c = &mut svc.config;
            if interface {
                c.network_load_balancer_arns = Some(nlbs2.clone());
            } else {
                c.gateway_load_balancer_arns = Some(gwlbs2.clone());
            }
            c.availability_zone_ids = Some(zones.iter().filter_map(|z| crate::catalog::zone_id(&region, z)).collect());
            c.availability_zones = Some(zones.clone());
            if let Some(a) = input.acceptance_required {
                c.acceptance_required = Some(a);
            }
            if let Some(name) = &input.private_dns_name {
                if !interface {
                    return Err(err(
                        "InvalidParameter",
                        "Private DNS names are not supported for Gateway Load Balancer endpoint services.",
                    ));
                }
                let token = new_id("x")[2..14].to_string();
                c.private_dns_name = Some(name.clone());
                c.private_dns_name_configuration = Some(t::PrivateDnsNameConfiguration {
                    state: Some("pendingVerification".into()),
                    r#type: Some("TXT".into()),
                    value: Some(format!("vpce:{token}")),
                    name: Some(format!("_{}.{name}", &token[..8])),
                });
            }
            if input.remove_private_dns_name == Some(true) {
                c.private_dns_name = None;
                c.private_dns_name_configuration = None;
            }
            let ips = edit(
                c.supported_ip_address_types.clone().unwrap_or_default(),
                &input.add_supported_ip_address_types,
                &input.remove_supported_ip_address_types,
            );
            if ips.is_empty() {
                return Err(err("InvalidParameter", "An endpoint service must support at least one IP address type."));
            }
            c.supported_ip_address_types = Some(ips);
            let mut regions = c.supported_regions.clone().unwrap_or_default();
            for add in input.add_supported_regions.iter().flatten() {
                if !regions.iter().any(|r| r.region.as_deref() == Some(add.as_str())) {
                    regions.push(t::SupportedRegionDetail {
                        region: Some(add.clone()),
                        service_state: Some("Available".into()),
                    });
                }
            }
            regions.retain(|r| {
                r.region.as_deref() == Some(region.as_str())
                    || !input.remove_supported_regions.iter().flatten().any(|x| Some(x.as_str()) == r.region.as_deref())
            });
            c.supported_regions = Some(regions);
            Ok(())
        })?;
        Ok(t::ModifyVpcEndpointServiceConfigurationResult { r#return: Some(true) })
    }

    pub(crate) fn delete_vpc_endpoint_service_configurations_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteVpcEndpointServiceConfigurationsRequest,
    ) -> Result<t::DeleteVpcEndpointServiceConfigurationsResult, ServiceError> {
        if input.service_ids.is_empty() {
            return Err(missing_parameter("ServiceIds"));
        }
        self.service_authorize(ctx, "DeleteVpcEndpointServiceConfigurations", &input.service_ids, input.dry_run)?;
        self.with_region(ctx, |r| {
            let mut failed = Vec::new();
            for id in &input.service_ids {
                let Some(svc) = r.endpoint_services.get(id) else {
                    failed.push(unsuccessful(
                        id,
                        &err(
                            "InvalidVpcEndpointService.NotFound",
                            format!("The VpcEndpointService Id '{id}' does not exist"),
                        ),
                    ));
                    continue;
                };
                let busy = svc.connections.values().any(|c| {
                    matches!(c.vpc_endpoint_state.as_deref(), Some("available" | "pendingAcceptance" | "pending"))
                });
                if busy {
                    failed.push(unsuccessful(
                        id,
                        &err("ExistingVpcEndpointConnections", "Service has existing active VPC Endpoint connections!"),
                    ));
                    continue;
                }
                r.endpoint_services.remove(id);
            }
            Ok(t::DeleteVpcEndpointServiceConfigurationsResult { unsuccessful: Some(failed) })
        })
    }

    pub(crate) fn describe_vpc_endpoint_service_permissions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcEndpointServicePermissionsRequest,
    ) -> Result<t::DescribeVpcEndpointServicePermissionsResult, ServiceError> {
        let id = input.service_id.clone();
        self.service_authorize(ctx, "DescribeVpcEndpointServicePermissions", std::slice::from_ref(&id), input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let all = self.with_service(ctx, &id, |svc| Ok(svc.permissions.clone()))?;
        let mut out = Vec::new();
        for p in all {
            let ok = filters.matches(p.tags.as_ref(), |name| {
                Some(match name {
                    "principal" => s(&p.principal),
                    "principal-type" => s(&p.principal_type),
                    _ => return None,
                })
            })?;
            if ok {
                out.push(p);
            }
        }
        let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeVpcEndpointServicePermissionsResult { allowed_principals: Some(items), next_token })
    }

    pub(crate) fn modify_vpc_endpoint_service_permissions_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVpcEndpointServicePermissionsRequest,
    ) -> Result<t::ModifyVpcEndpointServicePermissionsResult, ServiceError> {
        let id = input.service_id.clone();
        self.service_authorize(ctx, "ModifyVpcEndpointServicePermissions", std::slice::from_ref(&id), input.dry_run)?;
        let mut added = Vec::new();
        for p in input.add_allowed_principals.iter().flatten() {
            let kind = if p == "*" {
                "All"
            } else if p.ends_with(":root") && p.contains(":iam::") {
                "Account"
            } else if p.contains(":iam::") && p.contains(":role/") {
                "Role"
            } else if p.contains(":iam::") && p.contains(":user/") {
                "User"
            } else if p.contains(":organizations::") {
                "OrganizationUnit"
            } else if p.ends_with(".amazonaws.com") {
                "Service"
            } else {
                return Err(err("InvalidPrincipal", format!("Invalid Principal: '{p}'")));
            };
            added.push((p.clone(), kind));
        }
        self.with_service(ctx, &id, |svc| {
            let mut out = Vec::new();
            for (p, kind) in &added {
                if svc.permissions.iter().any(|x| x.principal.as_deref() == Some(p.as_str())) {
                    continue;
                }
                let perm = t::AllowedPrincipal {
                    principal_type: Some(kind.to_string()),
                    principal: Some(p.clone()),
                    service_permission_id: Some(new_id("vpce-svc-perm")),
                    tags: Some(Vec::new()),
                    service_id: Some(id.clone()),
                };
                out.push(t::AddedPrincipal {
                    principal_type: perm.principal_type.clone(),
                    principal: perm.principal.clone(),
                    service_permission_id: perm.service_permission_id.clone(),
                    service_id: Some(id.clone()),
                });
                svc.permissions.push(perm);
            }
            let remove = input.remove_allowed_principals.clone().unwrap_or_default();
            svc.permissions.retain(|x| !remove.iter().any(|r| x.principal.as_deref() == Some(r.as_str())));
            Ok(t::ModifyVpcEndpointServicePermissionsResult {
                added_principals: (!out.is_empty()).then_some(out),
                return_value: Some(true),
            })
        })
    }

    pub(crate) fn start_vpc_endpoint_service_private_dns_verification_op(
        &self,
        ctx: &RequestContext,
        input: t::StartVpcEndpointServicePrivateDnsVerificationRequest,
    ) -> Result<t::StartVpcEndpointServicePrivateDnsVerificationResult, ServiceError> {
        let id = input.service_id.clone();
        self.service_authorize(
            ctx,
            "StartVpcEndpointServicePrivateDnsVerification",
            std::slice::from_ref(&id),
            input.dry_run,
        )?;
        self.with_service(ctx, &id, |svc| {
            let Some(cfg) = svc.config.private_dns_name_configuration.as_mut() else {
                return Err(err("InvalidParameter", format!("The service {id} does not have a private DNS name.")));
            };
            // MWS cannot look the TXT record up; the name counts as verified.
            cfg.state = Some("verified".into());
            Ok(t::StartVpcEndpointServicePrivateDnsVerificationResult { return_value: Some(true) })
        })
    }

    pub(crate) fn modify_vpc_endpoint_service_payer_responsibility_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVpcEndpointServicePayerResponsibilityRequest,
    ) -> Result<t::ModifyVpcEndpointServicePayerResponsibilityResult, ServiceError> {
        let id = input.service_id.clone();
        self.service_authorize(
            ctx,
            "ModifyVpcEndpointServicePayerResponsibility",
            std::slice::from_ref(&id),
            input.dry_run,
        )?;
        if input.payer_responsibility != "ServiceOwner" {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter payerResponsibility is invalid. Valid values: ServiceOwner",
                input.payer_responsibility
            )));
        }
        self.with_service(ctx, &id, |svc| {
            svc.config.payer_responsibility = Some(input.payer_responsibility.clone());
            Ok(t::ModifyVpcEndpointServicePayerResponsibilityResult { return_value: Some(true) })
        })
    }

    pub(crate) fn describe_vpc_endpoint_connections_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcEndpointConnectionsRequest,
    ) -> Result<t::DescribeVpcEndpointConnectionsResult, ServiceError> {
        authorize(ctx, "DescribeVpcEndpointConnections", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for svc in r.endpoint_services.values() {
                for c in svc.connections.values() {
                    let ok = filters.matches(c.tags.as_ref(), |name| {
                        Some(match name {
                            "ip-address-type" => s(&c.ip_address_type),
                            "service-id" => s(&c.service_id),
                            "vpc-endpoint-owner" => s(&c.vpc_endpoint_owner),
                            "vpc-endpoint-state" => s(&c.vpc_endpoint_state),
                            "vpc-endpoint-id" => s(&c.vpc_endpoint_id),
                            "vpc-endpoint-region" => s(&c.vpc_endpoint_region),
                            _ => return None,
                        })
                    })?;
                    if ok {
                        out.push(c.clone());
                    }
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVpcEndpointConnectionsResult { vpc_endpoint_connections: Some(items), next_token })
        })
    }

    /// Accept or reject endpoint connections, keeping the consumers'
    /// endpoints in step.
    fn decide_connections(
        &self,
        ctx: &RequestContext,
        service_id: &str,
        endpoint_ids: &[String],
        accept: bool,
    ) -> Result<Vec<t::UnsuccessfulItem>, ServiceError> {
        let region = ctx.region.clone();
        let (changed, failed) = self.with_service(ctx, service_id, |svc| {
            let mut changed = Vec::new();
            let mut failed = Vec::new();
            for id in endpoint_ids {
                let Some(c) = svc.connections.get_mut(id) else {
                    failed.push(unsuccessful(
                        id,
                        &err("InvalidVpcEndpointId.NotFound", format!("The Vpc Endpoint Id '{id}' does not exist")),
                    ));
                    continue;
                };
                let state = c.vpc_endpoint_state.clone().unwrap_or_default();
                let ok = if accept {
                    state == "pendingAcceptance"
                } else {
                    state == "pendingAcceptance" || state == "available"
                };
                if !ok {
                    failed.push(unsuccessful(
                        id,
                        &err(
                            "InvalidVpcEndpointState",
                            format!(
                                "Endpoint {id} is in the {state} state and cannot be {}.",
                                if accept { "accepted" } else { "rejected" }
                            ),
                        ),
                    ));
                    continue;
                }
                let next = if accept { "available" } else { "rejected" };
                c.vpc_endpoint_state = Some(next.into());
                changed.push((id.clone(), c.vpc_endpoint_owner.clone().unwrap_or_default(), next));
            }
            Ok((changed, failed))
        })?;
        for (id, owner, next) in changed {
            self.with_region_of(&owner, &region, ctx, |r| {
                if let Some(ep) = r.vpc_endpoints.get_mut(&id) {
                    ep.state = Some(next.into());
                }
            });
        }
        Ok(failed)
    }

    pub(crate) fn accept_vpc_endpoint_connections_op(
        &self,
        ctx: &RequestContext,
        input: t::AcceptVpcEndpointConnectionsRequest,
    ) -> Result<t::AcceptVpcEndpointConnectionsResult, ServiceError> {
        let id = input.service_id.clone();
        self.service_authorize(ctx, "AcceptVpcEndpointConnections", std::slice::from_ref(&id), input.dry_run)?;
        let failed = self.decide_connections(ctx, &id, &input.vpc_endpoint_ids, true)?;
        Ok(t::AcceptVpcEndpointConnectionsResult { unsuccessful: Some(failed) })
    }

    pub(crate) fn reject_vpc_endpoint_connections_op(
        &self,
        ctx: &RequestContext,
        input: t::RejectVpcEndpointConnectionsRequest,
    ) -> Result<t::RejectVpcEndpointConnectionsResult, ServiceError> {
        let id = input.service_id.clone();
        self.service_authorize(ctx, "RejectVpcEndpointConnections", std::slice::from_ref(&id), input.dry_run)?;
        let failed = self.decide_connections(ctx, &id, &input.vpc_endpoint_ids, false)?;
        Ok(t::RejectVpcEndpointConnectionsResult { unsuccessful: Some(failed) })
    }

    /// `CreateVpcEndpoint` for a custom service.
    pub(crate) fn create_custom_vpc_endpoint(
        &self,
        ctx: &RequestContext,
        input: &t::CreateVpcEndpointRequest,
        tags: Vec<t::Tag>,
        service: Visible,
    ) -> Result<t::CreateVpcEndpointResult, ServiceError> {
        let account = account_of(ctx);
        let region = ctx.region.clone();
        let name = service.config.service_name.clone().unwrap_or_default();
        let service_id = service.config.service_id.clone().unwrap_or_default();
        let service_kind = service
            .config
            .service_type
            .iter()
            .flatten()
            .find_map(|t| t.service_type.clone())
            .unwrap_or_else(|| "Interface".into());
        let kind = input.vpc_endpoint_type.clone().unwrap_or_else(|| "Gateway".into());
        if kind != service_kind {
            return Err(err(
                "InvalidParameter",
                format!("The VPC endpoint service {name} does not support the VPC endpoint type {kind}."),
            ));
        }
        if input.policy_document.is_some() {
            return Err(err(
                "InvalidParameter",
                format!("The VPC endpoint service {name} does not support endpoint policies."),
            ));
        }
        let subnets = input.subnet_ids.clone().unwrap_or_default();
        if subnets.is_empty() {
            return Err(missing_parameter("SubnetIds"));
        }
        if kind == "GatewayLoadBalancer" {
            if subnets.len() != 1 {
                return Err(err("InvalidParameter", "A Gateway Load Balancer endpoint must be in exactly one subnet."));
            }
            if input.security_group_ids.as_ref().is_some_and(|g| !g.is_empty()) {
                return Err(err(
                    "InvalidParameter",
                    "Security groups are not supported for Gateway Load Balancer endpoints.",
                ));
            }
        }
        let verified_dns = service
            .config
            .private_dns_name_configuration
            .as_ref()
            .is_some_and(|c| c.state.as_deref() == Some("verified"));
        let private_dns = match input.private_dns_enabled {
            Some(true) if !verified_dns => {
                return Err(err(
                    "InvalidParameter",
                    format!("Private DNS can't be enabled because the service {name} does not provide a verified private DNS name."),
                ))
            }
            Some(v) => v,
            None => verified_dns,
        };
        let zones = service.config.availability_zones.clone().unwrap_or_default();
        let acceptance = service.config.acceptance_required.unwrap_or(true) && service.owner != account;
        let state = if acceptance { "pendingAcceptance" } else { "available" };
        let now = ctx.received_at;
        let ep = self.with_region(ctx, |r| -> Result<t::VpcEndpoint, ServiceError> {
            Kind::Vpc.check(&input.vpc_id)?;
            if !r.vpcs.contains_key(&input.vpc_id) {
                return Err(Kind::Vpc.not_found(&input.vpc_id));
            }
            for subnet in &subnets {
                let az = r.subnets.get(subnet).and_then(|s| s.availability_zone.clone());
                if let Some(az) = az {
                    if !zones.contains(&az) {
                        return Err(err(
                            "InvalidParameter",
                            format!("The VPC endpoint service {name} does not support the availability zone of the subnet: {subnet}."),
                        ));
                    }
                }
            }
            let id = new_id("vpce");
            let groups = if kind == "Interface" {
                super::eni::resolve_groups(r, &input.vpc_id, input.security_group_ids.as_deref())?
            } else {
                Vec::new()
            };
            let mut ep = t::VpcEndpoint {
                vpc_endpoint_id: Some(id.clone()),
                vpc_endpoint_type: Some(kind.clone()),
                vpc_id: Some(input.vpc_id.clone()),
                service_name: Some(name.clone()),
                state: Some(state.into()),
                route_table_ids: Some(Vec::new()),
                subnet_ids: Some(Vec::new()),
                groups: Some(
                    groups
                        .iter()
                        .map(|g| t::SecurityGroupIdentifier { group_id: g.group_id.clone(), group_name: g.group_name.clone() })
                        .collect(),
                ),
                private_dns_enabled: Some(private_dns),
                requester_managed: Some(false),
                network_interface_ids: Some(Vec::new()),
                creation_timestamp: Some(now),
                tags: some_tags(tags.clone()),
                owner_id: Some(account.clone()),
                ip_address_type: Some(input.ip_address_type.clone().unwrap_or_else(|| "ipv4".into())),
                service_region: Some(region.clone()),
                ..Default::default()
            };
            for subnet in &subnets {
                super::endpoint::add_endpoint_subnet(r, &account, &region, &mut ep, subnet, now, &input.subnet_configurations)?;
            }
            if kind == "Interface" {
                let label = new_id("x")[2..10].to_string();
                let zone = super::endpoint::vpce_zone(&region);
                let base = format!("{service_id}.{region}.vpce.amazonaws.com");
                let mut dns = vec![t::DnsEntry { dns_name: Some(format!("{id}-{label}.{base}")), hosted_zone_id: Some(zone.clone()) }];
                for subnet in &subnets {
                    if let Some(az) = r.subnets.get(subnet).and_then(|s| s.availability_zone.clone()) {
                        dns.push(t::DnsEntry { dns_name: Some(format!("{id}-{label}-{az}.{base}")), hosted_zone_id: Some(zone.clone()) });
                    }
                }
                if private_dns {
                    if let Some(n) = &service.config.private_dns_name {
                        dns.push(t::DnsEntry { dns_name: Some(n.clone()), hosted_zone_id: None });
                    }
                }
                ep.dns_entries = Some(dns);
            } else {
                ep.dns_entries = Some(Vec::new());
                ep.groups = None;
            }
            r.vpc_endpoints.insert(id, ep.clone());
            Ok(ep)
        })?;
        let connection = t::VpcEndpointConnection {
            service_id: Some(service_id.clone()),
            vpc_endpoint_id: ep.vpc_endpoint_id.clone(),
            vpc_endpoint_owner: Some(account.clone()),
            vpc_endpoint_state: Some(state.into()),
            creation_timestamp: Some(now),
            dns_entries: ep.dns_entries.clone(),
            network_load_balancer_arns: service.config.network_load_balancer_arns.clone(),
            gateway_load_balancer_arns: service.config.gateway_load_balancer_arns.clone(),
            ip_address_type: ep.ip_address_type.clone(),
            vpc_endpoint_connection_id: Some(new_id("vpce-con")),
            tags: Some(Vec::new()),
            vpc_endpoint_region: Some(region.clone()),
            payer_responsibilities: None,
        };
        let eid = ep.vpc_endpoint_id.clone().unwrap_or_default();
        self.with_region_of(&service.owner, &region, ctx, |r| {
            if let Some(svc) = r.endpoint_services.get_mut(&service_id) {
                svc.connections.insert(eid, connection);
            }
        });
        let mut shown = ep;
        if state == "available" {
            shown.state = Some("pending".into());
        }
        Ok(t::CreateVpcEndpointResult { vpc_endpoint: Some(shown), client_token: input.client_token.clone() })
    }

    /// Endpoints to custom services were deleted: their connections end.
    pub(crate) fn drop_endpoint_connections(&self, ctx: &RequestContext, deleted: &[(String, String)]) {
        let region = ctx.region.clone();
        for (endpoint, service_name) in deleted {
            let Some(service_id) = custom_service_id(service_name) else { continue };
            let Some(owner) = self.service_owner(&region, service_id) else { continue };
            self.with_region_of(&owner, &region, ctx, |r| {
                if let Some(svc) = r.endpoint_services.get_mut(service_id) {
                    svc.connections.remove(endpoint);
                }
            });
        }
    }
}
