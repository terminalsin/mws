//! VPC endpoints (gateway and interface) for AWS services, the endpoint
//! service catalogue, and prefix lists: the AWS-managed ones gateway
//! endpoints route to, and customer-managed ones with their versions.

use md5::{Digest, Md5};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::{PrefixListRecord, RegionState};
use crate::util::{
    arn, authorize, b, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context,
    resource_tag_context, s, some_tags, tags_for, Cidr, Filters, Kind,
};
use crate::{account_of, Ec2};

/// The policy an endpoint gets when none is given.
pub const DEFAULT_ENDPOINT_POLICY: &str =
    r#"{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}"#;

/// An AWS service that offers VPC endpoints.
struct EndpointService {
    /// The part of the service name after `com.amazonaws.<region>.`.
    suffix: &'static str,
    /// The DNS label(s) of its regional endpoint (`sts`, `api.ecr`).
    dns: &'static str,
    gateway: bool,
    interface: bool,
    /// Whether its private DNS name is a wildcard (`*.dkr.ecr...`).
    wildcard_dns: bool,
}

const fn svc(suffix: &'static str, dns: &'static str) -> EndpointService {
    EndpointService { suffix, dns, gateway: false, interface: true, wildcard_dns: false }
}

/// The AWS services MWS lists as endpoint services (AWS lists more; these
/// are the ones workloads in a VPC typically reach privately).
const SERVICES: &[EndpointService] = &[
    svc("acm-pca", "acm-pca"),
    svc("autoscaling", "autoscaling"),
    svc("bedrock", "bedrock"),
    svc("bedrock-agent-runtime", "bedrock-agent-runtime"),
    svc("bedrock-runtime", "bedrock-runtime"),
    svc("cloudformation", "cloudformation"),
    svc("cloudtrail", "cloudtrail"),
    svc("codeartifact.api", "codeartifact"),
    EndpointService { wildcard_dns: true, ..svc("codeartifact.repositories", "d.codeartifact") },
    EndpointService { gateway: true, ..svc("dynamodb", "dynamodb") },
    svc("ebs", "ebs"),
    svc("ec2", "ec2"),
    svc("ec2messages", "ec2messages"),
    svc("ecr.api", "api.ecr"),
    EndpointService { wildcard_dns: true, ..svc("ecr.dkr", "dkr.ecr") },
    svc("ecs", "ecs"),
    svc("eks", "eks"),
    svc("eks-auth", "eks-auth"),
    svc("elasticache", "elasticache"),
    svc("elasticfilesystem", "elasticfilesystem"),
    svc("elasticloadbalancing", "elasticloadbalancing"),
    svc("email-smtp", "email-smtp"),
    svc("events", "events"),
    svc("execute-api", "execute-api"),
    svc("guardduty-data", "guardduty-data"),
    svc("imagebuilder", "imagebuilder"),
    svc("kinesis-firehose", "firehose"),
    svc("kinesis-streams", "kinesis"),
    svc("kms", "kms"),
    svc("lambda", "lambda"),
    svc("logs", "logs"),
    svc("monitoring", "monitoring"),
    svc("ram", "ram"),
    svc("rds", "rds"),
    svc("rds-data", "rds-data"),
    EndpointService { gateway: true, wildcard_dns: true, ..svc("s3", "s3") },
    svc("secretsmanager", "secretsmanager"),
    svc("securityhub", "securityhub"),
    svc("servicequotas", "servicequotas"),
    svc("sns", "sns"),
    svc("sqs", "sqs"),
    svc("ssm", "ssm"),
    svc("ssmmessages", "ssmmessages"),
    svc("sts", "sts"),
];

/// The address ranges of the services gateway endpoints reach.
fn gateway_cidrs(suffix: &str) -> &'static [&'static str] {
    match suffix {
        "s3" => &[
            "16.15.176.0/20",
            "16.182.0.0/16",
            "18.34.0.0/19",
            "18.34.232.0/21",
            "3.5.0.0/19",
            "52.216.0.0/15",
            "54.231.0.0/16",
        ],
        "dynamodb" => &["3.218.180.0/22", "3.218.184.0/22", "52.94.0.0/22", "52.119.224.0/20"],
        _ => &[],
    }
}

/// A stable 8-hex-digit id for an AWS-owned resource in `region`. The real
/// ids of the us-east-1 lists are kept, so copied configuration matches.
fn aws_owned_id(prefix: &str, region: &str, name: &str) -> String {
    match (region, name) {
        ("us-east-1", "s3") => return "pl-63a5400a".into(),
        ("us-east-1", "dynamodb") => return "pl-02cd2c6b".into(),
        _ => {}
    }
    let digest = Md5::digest(format!("{region}/{name}").as_bytes());
    format!("{prefix}-{}", hex::encode(&digest[..4]))
}

/// An AWS-managed prefix list: id, name and entries.
pub struct AwsPrefixList {
    pub id: String,
    pub name: String,
    pub cidrs: Vec<String>,
}

/// The AWS-managed prefix lists of a Region (one per gateway service).
pub fn aws_prefix_lists(region: &str) -> Vec<AwsPrefixList> {
    SERVICES
        .iter()
        .filter(|s| s.gateway)
        .map(|s| AwsPrefixList {
            id: aws_owned_id("pl", region, s.suffix),
            name: format!("com.amazonaws.{region}.{}", s.suffix),
            cidrs: gateway_cidrs(s.suffix).iter().map(|c| c.to_string()).collect(),
        })
        .collect()
}

/// The CIDRs of any prefix list (AWS- or customer-managed) by id, at its
/// current version.
pub fn prefix_list_cidrs(r: &RegionState, region: &str, id: &str) -> Option<Vec<String>> {
    if let Some(rec) = r.prefix_lists.get(id) {
        return Some(rec.versions.last().into_iter().flatten().filter_map(|e| e.cidr.clone()).collect());
    }
    aws_prefix_lists(region).into_iter().find(|p| p.id == id).map(|p| p.cidrs)
}

fn service_name(region: &str, s: &EndpointService) -> String {
    format!("com.amazonaws.{region}.{}", s.suffix)
}

fn find_service<'a>(region: &str, name: &str) -> Option<&'a EndpointService> {
    SERVICES.iter().find(|s| service_name(region, s) == name)
}

/// The hosted zone id of a Region's `vpce.amazonaws.com` zone.
pub(crate) fn vpce_zone(region: &str) -> String {
    match region {
        "us-east-1" => "Z7HUB22UULQXV".into(),
        "us-east-2" => "ZC8PG0KIFKBRI".into(),
        "us-west-1" => "Z12I86A8N7VCZO".into(),
        "us-west-2" => "Z1YSA3EXCYUU9Z".into(),
        "eu-west-1" => "Z38GZ743OKFT7T".into(),
        "eu-central-1" => "Z273ZU8SZ5RJPC".into(),
        _ => format!("Z{}", hex::encode_upper(&Md5::digest(region.as_bytes())[..6])),
    }
}

fn private_dns_name(region: &str, s: &EndpointService) -> String {
    let base = format!("{}.{region}.amazonaws.com", s.dns);
    if s.wildcard_dns {
        format!("*.{base}")
    } else {
        base
    }
}

fn service_detail(region: &str, zones: &[String], s: &EndpointService, kind: &str) -> t::ServiceDetail {
    let interface = kind == "Interface";
    t::ServiceDetail {
        service_name: Some(service_name(region, s)),
        service_id: Some(aws_owned_id("vpce-svc", region, &format!("{}/{kind}", s.suffix))),
        service_type: Some(vec![t::ServiceTypeDetail { service_type: Some(kind.into()) }]),
        service_region: Some(region.into()),
        availability_zones: Some(zones.to_vec()),
        owner: Some("amazon".into()),
        base_endpoint_dns_names: Some(vec![if interface {
            format!("{}.{region}.vpce.amazonaws.com", s.dns)
        } else {
            format!("{}.{region}.amazonaws.com", s.dns)
        }]),
        private_dns_name: interface.then(|| private_dns_name(region, s)),
        private_dns_names: interface
            .then(|| vec![t::PrivateDnsDetails { private_dns_name: Some(private_dns_name(region, s)) }]),
        vpc_endpoint_policy_supported: Some(true),
        acceptance_required: Some(false),
        manages_vpc_endpoints: Some(false),
        private_dns_name_verification_state: interface.then(|| "verified".into()),
        supported_ip_address_types: Some(vec!["ipv4".into()]),
        ..Default::default()
    }
}

fn check_policy(doc: &str) -> Result<(), ServiceError> {
    let ok = serde_json::from_str::<serde_json::Value>(doc).is_ok_and(|v| v.get("Statement").is_some());
    if ok {
        Ok(())
    } else {
        Err(err("InvalidPolicyDocument", "The policy document is not valid JSON or has no Statement."))
    }
}

/// A random lowercase alphanumeric label for endpoint DNS names.
fn dns_label() -> String {
    new_id("x")[2..10].to_string()
}

fn endpoint_filter(e: &t::VpcEndpoint, name: &str) -> Option<Vec<String>> {
    Some(match name {
        "ip-address-type" => s(&e.ip_address_type),
        "service-name" => s(&e.service_name),
        "service-region" => s(&e.service_region),
        "vpc-id" => s(&e.vpc_id),
        "vpc-endpoint-id" => s(&e.vpc_endpoint_id),
        "vpc-endpoint-state" => s(&e.state),
        "vpc-endpoint-type" => s(&e.vpc_endpoint_type),
        "private-dns-enabled" => b(e.private_dns_enabled),
        _ => return None,
    })
}

impl Ec2 {
    // ---- VPC endpoints -----------------------------------------------------------------------

    pub(crate) fn create_vpc_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateVpcEndpointRequest,
    ) -> Result<t::CreateVpcEndpointResult, ServiceError> {
        let account = account_of(ctx);
        let region = ctx.region.clone();
        let tags = tags_for(&input.tag_specifications, "vpc-endpoint", &["vpc-endpoint"])?;
        Kind::Vpc.check(&input.vpc_id)?;
        let kind = input.vpc_endpoint_type.clone().unwrap_or_else(|| "Gateway".into());
        if !matches!(kind.as_str(), "Gateway" | "Interface" | "GatewayLoadBalancer" | "Resource" | "ServiceNetwork") {
            return Err(invalid_parameter(format!("Invalid value '{kind}' for VpcEndpointType")));
        }
        let name = input.service_name.clone().ok_or_else(|| missing_parameter("ServiceName"))?;
        let mut resources = vec![
            (arn(ctx, &account, "vpc-endpoint/*"), request_tag_context(&tags)),
            (arn(ctx, &account, &format!("vpc/{}", input.vpc_id)), ConditionContext::new()),
        ];
        for id in input.route_table_ids.iter().flatten() {
            resources.push((arn(ctx, &account, &format!("route-table/{id}")), ConditionContext::new()));
        }
        for id in input.subnet_ids.iter().flatten() {
            resources.push((arn(ctx, &account, &format!("subnet/{id}")), ConditionContext::new()));
        }
        for id in input.security_group_ids.iter().flatten() {
            resources.push((arn(ctx, &account, &format!("security-group/{id}")), ConditionContext::new()));
        }
        authorize(ctx, "CreateVpcEndpoint", &resources, input.dry_run)?;
        if super::endpoint_service::custom_service_id(&name).is_some() {
            let service = self
                .visible_endpoint_services(ctx)
                .into_iter()
                .find(|v| v.config.service_name.as_deref() == Some(name.as_str()))
                .filter(|v| v.config.service_state.as_deref() == Some("Available"))
                .ok_or_else(|| {
                    err("InvalidServiceName", format!("The Vpc Endpoint Service '{name}' does not exist"))
                })?;
            return self.create_custom_vpc_endpoint(ctx, &input, tags, service);
        }
        if let Some(p) = &input.policy_document {
            check_policy(p)?;
        }
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let vpc = r.vpcs.get(&input.vpc_id).ok_or_else(|| Kind::Vpc.not_found(&input.vpc_id))?.clone();
            let service = find_service(&region, &name).filter(|s| match kind.as_str() {
                "Gateway" => s.gateway,
                "Interface" => s.interface,
                _ => false,
            });
            let Some(service) = service else {
                return Err(err("InvalidServiceName", format!("The Vpc Endpoint Service '{name}' does not exist")));
            };
            let id = new_id("vpce");
            let mut ep = t::VpcEndpoint {
                vpc_endpoint_id: Some(id.clone()),
                vpc_endpoint_type: Some(kind.clone()),
                vpc_id: Some(input.vpc_id.clone()),
                service_name: Some(name.clone()),
                state: Some("available".into()),
                policy_document: Some(input.policy_document.clone().unwrap_or_else(|| DEFAULT_ENDPOINT_POLICY.into())),
                route_table_ids: Some(Vec::new()),
                subnet_ids: Some(Vec::new()),
                groups: Some(Vec::new()),
                private_dns_enabled: Some(false),
                requester_managed: Some(false),
                network_interface_ids: Some(Vec::new()),
                dns_entries: Some(Vec::new()),
                creation_timestamp: Some(now),
                tags: some_tags(tags),
                owner_id: Some(account.clone()),
                service_region: Some(region.clone()),
                ..Default::default()
            };
            if kind == "Gateway" {
                if input.subnet_ids.as_ref().is_some_and(|v| !v.is_empty()) {
                    return Err(err(
                        "InvalidParameter",
                        "Subnet IDs are not supported for VPC endpoints of type Gateway.",
                    ));
                }
                if input.private_dns_enabled == Some(true) {
                    return Err(err(
                        "InvalidParameter",
                        "PrivateDnsEnabled is not supported for VPC endpoints of type Gateway.",
                    ));
                }
                if r.vpc_endpoints.values().any(|e| {
                    e.vpc_id.as_deref() == Some(input.vpc_id.as_str())
                        && e.service_name.as_deref() == Some(name.as_str())
                        && e.vpc_endpoint_type.as_deref() == Some("Gateway")
                }) {
                    return Err(err(
                        "RouteAlreadyExists",
                        format!("route table already has a route with the prefix list of the service {name}"),
                    ));
                }
                ep.private_dns_enabled = None;
                ep.ip_address_type = Some("ipv4".into());
                let pl = aws_owned_id("pl", &region, service.suffix);
                for rtb in input.route_table_ids.iter().flatten() {
                    add_endpoint_route(r, &input.vpc_id, rtb, &pl, &id)?;
                    ep.route_table_ids.get_or_insert_with(Vec::new).push(rtb.clone());
                }
                ep.dns_entries = None;
                ep.network_interface_ids = None;
                ep.subnet_ids = None;
                ep.groups = None;
            } else {
                if input.route_table_ids.as_ref().is_some_and(|v| !v.is_empty()) {
                    return Err(err(
                        "InvalidParameter",
                        "Route table IDs are not supported for VPC endpoints of type Interface.",
                    ));
                }
                let private_dns = input.private_dns_enabled.unwrap_or(true);
                if private_dns {
                    check_private_dns(r, &region, &input.vpc_id, service, None)?;
                }
                let _ = &vpc;
                let groups = super::eni::resolve_groups(r, &input.vpc_id, input.security_group_ids.as_deref())?;
                ep.groups = Some(
                    groups
                        .iter()
                        .map(|g| t::SecurityGroupIdentifier {
                            group_id: g.group_id.clone(),
                            group_name: g.group_name.clone(),
                        })
                        .collect(),
                );
                ep.private_dns_enabled = Some(private_dns);
                ep.ip_address_type = Some(input.ip_address_type.clone().unwrap_or_else(|| "ipv4".into()));
                ep.dns_options = Some(t::DnsOptions {
                    dns_record_ip_type: Some(
                        input
                            .dns_options
                            .as_ref()
                            .and_then(|d| d.dns_record_ip_type.clone())
                            .unwrap_or_else(|| "ipv4".into()),
                    ),
                    private_dns_only_for_inbound_resolver_endpoint: input
                        .dns_options
                        .as_ref()
                        .and_then(|d| d.private_dns_only_for_inbound_resolver_endpoint),
                    ..Default::default()
                });
                let subnets: Vec<String> = input.subnet_ids.clone().unwrap_or_default();
                for subnet in &subnets {
                    add_endpoint_subnet(r, &account, &region, &mut ep, subnet, now, &input.subnet_configurations)?;
                }
                ep.dns_entries = Some(dns_entries(r, &region, &ep, service));
            }
            r.vpc_endpoints.insert(id, ep.clone());
            let mut shown = ep;
            shown.state = Some("pending".into());
            Ok(t::CreateVpcEndpointResult { vpc_endpoint: Some(shown), client_token: input.client_token.clone() })
        })
    }

    fn vpce_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        Kind::VpcEndpoint.check(id)?;
        let account = account_of(ctx);
        let tags = self.with_region(ctx, |r| r.vpc_endpoints.get(id).map(|e| e.tags.clone()));
        let tags = tags.ok_or_else(|| Kind::VpcEndpoint.not_found(id))?;
        authorize(
            ctx,
            action,
            &[(arn(ctx, &account, &format!("vpc-endpoint/{id}")), resource_tag_context(tags.as_ref()))],
            dry_run,
        )
    }

    pub(crate) fn modify_vpc_endpoint_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyVpcEndpointRequest,
    ) -> Result<t::ModifyVpcEndpointResult, ServiceError> {
        self.vpce_authorize(ctx, "ModifyVpcEndpoint", &input.vpc_endpoint_id, input.dry_run)?;
        if let Some(p) = &input.policy_document {
            check_policy(p)?;
        }
        if input.reset_policy == Some(true) && input.policy_document.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "The parameter PolicyDocument cannot be used with the parameter ResetPolicy",
            ));
        }
        let account = account_of(ctx);
        let region = ctx.region.clone();
        let now = ctx.received_at;
        let id = input.vpc_endpoint_id.clone();
        self.with_region(ctx, |r| {
            let mut ep = r.vpc_endpoints.get(&id).cloned().ok_or_else(|| Kind::VpcEndpoint.not_found(&id))?;
            let vpc_id = ep.vpc_id.clone().unwrap_or_default();
            let name = ep.service_name.clone().unwrap_or_default();
            let service = find_service(&region, &name);
            let gateway = ep.vpc_endpoint_type.as_deref() == Some("Gateway");
            if input.reset_policy == Some(true) {
                ep.policy_document = Some(DEFAULT_ENDPOINT_POLICY.into());
            }
            if let Some(p) = &input.policy_document {
                ep.policy_document = Some(p.clone());
            }
            let has = |v: &Option<Vec<String>>| v.as_ref().is_some_and(|v| !v.is_empty());
            if gateway {
                if has(&input.add_subnet_ids)
                    || has(&input.add_security_group_ids)
                    || input.private_dns_enabled.is_some()
                {
                    return Err(err(
                        "InvalidParameter",
                        "Subnets, security groups and private DNS are not supported for VPC endpoints of type Gateway.",
                    ));
                }
                let pl = service.map(|s| aws_owned_id("pl", &region, s.suffix)).unwrap_or_default();
                for rtb in input.add_route_table_ids.iter().flatten() {
                    if ep.route_table_ids.iter().flatten().any(|x| x == rtb) {
                        continue;
                    }
                    add_endpoint_route(r, &vpc_id, rtb, &pl, &id)?;
                    ep.route_table_ids.get_or_insert_with(Vec::new).push(rtb.clone());
                }
                for rtb in input.remove_route_table_ids.iter().flatten() {
                    Kind::RouteTable.check(rtb)?;
                    if !ep.route_table_ids.iter().flatten().any(|x| x == rtb) {
                        return Err(err(
                            "InvalidRouteTableId.NotFound",
                            format!("The routeTable ID '{rtb}' does not exist"),
                        ));
                    }
                    remove_endpoint_route(r, rtb, &id);
                    ep.route_table_ids.get_or_insert_with(Vec::new).retain(|x| x != rtb);
                }
            } else {
                if has(&input.add_route_table_ids) || has(&input.remove_route_table_ids) {
                    return Err(err(
                        "InvalidParameter",
                        "Route table IDs are not supported for VPC endpoints of type Interface.",
                    ));
                }
                for subnet in input.add_subnet_ids.iter().flatten() {
                    if ep.subnet_ids.iter().flatten().any(|x| x == subnet) {
                        continue;
                    }
                    add_endpoint_subnet(r, &account, &region, &mut ep, subnet, now, &input.subnet_configurations)?;
                }
                for subnet in input.remove_subnet_ids.iter().flatten() {
                    Kind::Subnet.check(subnet)?;
                    if !ep.subnet_ids.iter().flatten().any(|x| x == subnet) {
                        return Err(Kind::Subnet.not_found(subnet));
                    }
                    let enis: Vec<String> = ep
                        .network_interface_ids
                        .iter()
                        .flatten()
                        .filter(|e| r.network_interfaces.get(*e).and_then(|n| n.subnet_id.as_deref()) == Some(subnet))
                        .cloned()
                        .collect();
                    for e in &enis {
                        r.network_interfaces.remove(e);
                    }
                    ep.network_interface_ids.get_or_insert_with(Vec::new).retain(|e| !enis.contains(e));
                    ep.subnet_ids.get_or_insert_with(Vec::new).retain(|x| x != subnet);
                }
                let mut groups: Vec<String> = ep.groups.iter().flatten().filter_map(|g| g.group_id.clone()).collect();
                for g in input.add_security_group_ids.iter().flatten() {
                    if !groups.contains(g) {
                        groups.push(g.clone());
                    }
                }
                for g in input.remove_security_group_ids.iter().flatten() {
                    Kind::Group.check(g)?;
                    if !groups.contains(g) {
                        return Err(Kind::Group.not_found(g));
                    }
                    groups.retain(|x| x != g);
                }
                if groups.is_empty() {
                    return Err(err(
                        "InvalidParameter",
                        "An interface endpoint must have at least one security group.",
                    ));
                }
                let resolved = super::eni::resolve_groups(r, &vpc_id, Some(&groups))?;
                ep.groups = Some(
                    resolved
                        .iter()
                        .map(|g| t::SecurityGroupIdentifier {
                            group_id: g.group_id.clone(),
                            group_name: g.group_name.clone(),
                        })
                        .collect(),
                );
                for e in ep.network_interface_ids.iter().flatten() {
                    if let Some(n) = r.network_interfaces.get_mut(e) {
                        n.groups = Some(resolved.clone());
                    }
                }
                if let Some(on) = input.private_dns_enabled {
                    if on && ep.private_dns_enabled != Some(true) {
                        if let Some(service) = service {
                            check_private_dns(r, &region, &vpc_id, service, Some(&id))?;
                        }
                    }
                    ep.private_dns_enabled = Some(on);
                }
                if let Some(t) = &input.ip_address_type {
                    ep.ip_address_type = Some(t.clone());
                }
                if let Some(d) = &input.dns_options {
                    let opts = ep.dns_options.get_or_insert_with(Default::default);
                    if d.dns_record_ip_type.is_some() {
                        opts.dns_record_ip_type = d.dns_record_ip_type.clone();
                    }
                    if d.private_dns_only_for_inbound_resolver_endpoint.is_some() {
                        opts.private_dns_only_for_inbound_resolver_endpoint =
                            d.private_dns_only_for_inbound_resolver_endpoint;
                    }
                }
                if let Some(service) = service {
                    ep.dns_entries = Some(dns_entries(r, &region, &ep, service));
                }
            }
            r.vpc_endpoints.insert(id.clone(), ep);
            Ok(t::ModifyVpcEndpointResult { r#return: Some(true) })
        })
    }

    pub(crate) fn delete_vpc_endpoints_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteVpcEndpointsRequest,
    ) -> Result<t::DeleteVpcEndpointsResult, ServiceError> {
        let account = account_of(ctx);
        let resources: Vec<(String, ConditionContext)> = input
            .vpc_endpoint_ids
            .iter()
            .map(|id| (arn(ctx, &account, &format!("vpc-endpoint/{id}")), ConditionContext::new()))
            .collect();
        authorize(ctx, "DeleteVpcEndpoints", &resources, input.dry_run)?;
        let mut deleted = Vec::new();
        let result = self.with_region(ctx, |r| {
            let mut unsuccessful = Vec::new();
            for id in &input.vpc_endpoint_ids {
                let failure = match Kind::VpcEndpoint.check(id) {
                    Err(e) => Some(e),
                    Ok(()) if !r.vpc_endpoints.contains_key(id) => Some(Kind::VpcEndpoint.not_found(id)),
                    Ok(()) => None,
                };
                if let Some(e) = failure {
                    unsuccessful.push(t::UnsuccessfulItem {
                        resource_id: Some(id.clone()),
                        error: Some(t::UnsuccessfulItemError {
                            code: Some(e.code.to_string()),
                            message: Some(e.message.to_string()),
                        }),
                    });
                    continue;
                }
                let ep = r.vpc_endpoints.remove(id).expect("checked");
                deleted.push((id.clone(), ep.service_name.clone().unwrap_or_default()));
                for rtb in ep.route_table_ids.iter().flatten() {
                    remove_endpoint_route(r, rtb, id);
                }
                for eni in ep.network_interface_ids.iter().flatten() {
                    r.network_interfaces.remove(eni);
                }
            }
            Ok(t::DeleteVpcEndpointsResult { unsuccessful: Some(unsuccessful) })
        });
        self.drop_endpoint_connections(ctx, &deleted);
        result
    }

    pub(crate) fn describe_vpc_endpoints_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcEndpointsRequest,
    ) -> Result<t::DescribeVpcEndpointsResult, ServiceError> {
        authorize(ctx, "DescribeVpcEndpoints", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.vpc_endpoint_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::VpcEndpoint.check_all(&ids, |id| r.vpc_endpoints.contains_key(id))?;
            let mut out = Vec::new();
            for e in r.vpc_endpoints.values() {
                if !ids.is_empty() && !ids.contains(e.vpc_endpoint_id.as_ref().unwrap()) {
                    continue;
                }
                if filters.matches(e.tags.as_ref(), |name| endpoint_filter(e, name))? {
                    out.push(e.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeVpcEndpointsResult { vpc_endpoints: Some(items), next_token })
        })
    }

    pub(crate) fn describe_vpc_endpoint_services_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeVpcEndpointServicesRequest,
    ) -> Result<t::DescribeVpcEndpointServicesResult, ServiceError> {
        authorize(ctx, "DescribeVpcEndpointServices", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let region = ctx.region.clone();
        let zones: Vec<String> = crate::catalog::zones(&region).into_iter().map(|z| z.0).collect();
        let filters = Filters::new(&input.filters);
        let names = input.service_names.clone().unwrap_or_default();
        let custom = self.custom_service_details(ctx);
        for n in &names {
            if find_service(&region, n).is_none()
                && !custom.iter().any(|d| d.service_name.as_deref() == Some(n.as_str()))
            {
                return Err(err("InvalidServiceName", format!("The Vpc Endpoint Service '{n}' does not exist")));
            }
        }
        let mut details = Vec::new();
        for svc in SERVICES {
            let name = service_name(&region, svc);
            if !names.is_empty() && !names.contains(&name) {
                continue;
            }
            let kinds = [("Gateway", svc.gateway), ("Interface", svc.interface)];
            for (kind, offered) in kinds {
                if !offered {
                    continue;
                }
                let d = service_detail(&region, &zones, svc, kind);
                let ok = filters.matches(None, |f| {
                    Some(match f {
                        "service-name" => s(&d.service_name),
                        "service-type" => vec![kind.to_string()],
                        "service-region" => vec![region.clone()],
                        "owner" => vec!["amazon".into()],
                        "supported-ip-address-types" => vec!["ipv4".into()],
                        _ => return None,
                    })
                })?;
                if ok {
                    details.push(d);
                }
            }
        }
        for d in custom {
            let name = d.service_name.clone().unwrap_or_default();
            if !names.is_empty() && !names.contains(&name) {
                continue;
            }
            let ok = filters.matches(d.tags.as_ref(), |f| {
                Some(match f {
                    "service-name" => vec![name.clone()],
                    "service-type" => d.service_type.iter().flatten().filter_map(|t| t.service_type.clone()).collect(),
                    "service-region" => vec![region.clone()],
                    "owner" => s(&d.owner),
                    "supported-ip-address-types" => d.supported_ip_address_types.clone().unwrap_or_default(),
                    _ => return None,
                })
            })?;
            if ok {
                details.push(d);
            }
        }
        let (items, next_token) = paginate(details, input.max_results, &input.next_token)?;
        let mut service_names: Vec<String> = items.iter().filter_map(|d| d.service_name.clone()).collect();
        service_names.dedup();
        Ok(t::DescribeVpcEndpointServicesResult {
            service_names: Some(service_names),
            service_details: Some(items),
            next_token,
        })
    }

    // ---- prefix lists ------------------------------------------------------------------------

    pub(crate) fn describe_prefix_lists_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribePrefixListsRequest,
    ) -> Result<t::DescribePrefixListsResult, ServiceError> {
        authorize(ctx, "DescribePrefixLists", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.prefix_list_ids.clone().unwrap_or_default();
        let lists = aws_prefix_lists(&ctx.region);
        Kind::PrefixList.check_all(&ids, |id| lists.iter().any(|p| p.id == id))?;
        let mut out = Vec::new();
        for p in lists {
            if !ids.is_empty() && !ids.contains(&p.id) {
                continue;
            }
            let ok = filters.matches(None, |f| {
                Some(match f {
                    "prefix-list-id" => vec![p.id.clone()],
                    "prefix-list-name" => vec![p.name.clone()],
                    _ => return None,
                })
            })?;
            if ok {
                out.push(t::PrefixList {
                    cidrs: Some(p.cidrs),
                    prefix_list_id: Some(p.id),
                    prefix_list_name: Some(p.name),
                });
            }
        }
        let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribePrefixListsResult { prefix_lists: Some(items), next_token })
    }

    pub(crate) fn describe_managed_prefix_lists_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeManagedPrefixListsRequest,
    ) -> Result<t::DescribeManagedPrefixListsResult, ServiceError> {
        authorize(ctx, "DescribeManagedPrefixLists", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.prefix_list_ids.clone().unwrap_or_default();
        let region = ctx.region.clone();
        let partition = ctx.partition.clone();
        self.with_region(ctx, |r| {
            let mut all: Vec<t::ManagedPrefixList> = aws_prefix_lists(&region)
                .into_iter()
                .map(|p| t::ManagedPrefixList {
                    prefix_list_arn: Some(format!("arn:{partition}:ec2:{region}:aws:prefix-list/{}", p.id)),
                    prefix_list_id: Some(p.id),
                    prefix_list_name: Some(p.name),
                    address_family: Some("IPv4".into()),
                    state: Some("create-complete".into()),
                    max_entries: Some(p.cidrs.len() as i32),
                    owner_id: Some("AWS".into()),
                    ..Default::default()
                })
                .collect();
            all.extend(r.prefix_lists.values().map(|p| p.list.clone()));
            Kind::PrefixList.check_all(&ids, |id| all.iter().any(|p| p.prefix_list_id.as_deref() == Some(id)))?;
            let mut out = Vec::new();
            for p in all {
                if !ids.is_empty() && !ids.contains(p.prefix_list_id.as_ref().unwrap()) {
                    continue;
                }
                let ok = filters.matches(p.tags.as_ref(), |f| {
                    Some(match f {
                        "owner-id" => s(&p.owner_id),
                        "prefix-list-id" => s(&p.prefix_list_id),
                        "prefix-list-name" => s(&p.prefix_list_name),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(p);
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeManagedPrefixListsResult { prefix_lists: Some(items), next_token })
        })
    }

    pub(crate) fn get_managed_prefix_list_entries_op(
        &self,
        ctx: &RequestContext,
        input: t::GetManagedPrefixListEntriesRequest,
    ) -> Result<t::GetManagedPrefixListEntriesResult, ServiceError> {
        let account = account_of(ctx);
        Kind::PrefixList.check(&input.prefix_list_id)?;
        authorize(
            ctx,
            "GetManagedPrefixListEntries",
            &[(arn(ctx, &account, &format!("prefix-list/{}", input.prefix_list_id)), ConditionContext::new())],
            input.dry_run,
        )?;
        let region = ctx.region.clone();
        self.with_region(ctx, |r| {
            let entries: Vec<t::PrefixListEntry> = if let Some(rec) = r.prefix_lists.get(&input.prefix_list_id) {
                let latest = rec.versions.len() as i64;
                let v = input.target_version.unwrap_or(latest);
                if v < 1 || v > latest {
                    return Err(err(
                        "InvalidPrefixListVersion",
                        format!("The version {v} of prefix list {} does not exist", input.prefix_list_id),
                    ));
                }
                rec.versions[(v - 1) as usize].clone()
            } else {
                let cidrs = aws_prefix_lists(&region)
                    .into_iter()
                    .find(|p| p.id == input.prefix_list_id)
                    .map(|p| p.cidrs)
                    .ok_or_else(|| Kind::PrefixList.not_found(&input.prefix_list_id))?;
                cidrs.into_iter().map(|c| t::PrefixListEntry { cidr: Some(c), description: None }).collect()
            };
            let (items, next_token) = paginate(entries, input.max_results, &input.next_token)?;
            Ok(t::GetManagedPrefixListEntriesResult { entries: Some(items), next_token })
        })
    }

    pub(crate) fn create_managed_prefix_list_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateManagedPrefixListRequest,
    ) -> Result<t::CreateManagedPrefixListResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "prefix-list", &["prefix-list"])?;
        authorize(
            ctx,
            "CreateManagedPrefixList",
            &[(arn(ctx, &account, "prefix-list/*"), request_tag_context(&tags))],
            input.dry_run,
        )?;
        if input.prefix_list_name.to_ascii_lowercase().starts_with("com.amazonaws") {
            return Err(invalid_parameter("The prefix list name cannot start with com.amazonaws."));
        }
        if !matches!(input.address_family.as_str(), "IPv4" | "IPv6") {
            return Err(invalid_parameter(format!(
                "The address family {} is not valid. Valid values are IPv4 and IPv6.",
                input.address_family
            )));
        }
        if input.max_entries < 1 || input.max_entries > 1000 {
            return Err(invalid_parameter("The maximum number of entries must be between 1 and 1000."));
        }
        let entries = check_entries(&input.address_family, input.entries.iter().flatten(), input.max_entries)?;
        let id = new_id("pl");
        let list = t::ManagedPrefixList {
            prefix_list_id: Some(id.clone()),
            address_family: Some(input.address_family.clone()),
            state: Some("create-complete".into()),
            prefix_list_arn: Some(arn(ctx, &account, &format!("prefix-list/{id}"))),
            prefix_list_name: Some(input.prefix_list_name.clone()),
            max_entries: Some(input.max_entries),
            version: Some(1),
            tags: some_tags(tags),
            owner_id: Some(account.clone()),
            ..Default::default()
        };
        self.with_region(ctx, |r| {
            r.prefix_lists.insert(id, PrefixListRecord { list: list.clone(), versions: vec![entries] });
        });
        let mut shown = list;
        shown.state = Some("create-in-progress".into());
        Ok(t::CreateManagedPrefixListResult { prefix_list: Some(shown) })
    }

    fn pl_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        Kind::PrefixList.check(id)?;
        let account = account_of(ctx);
        let region = ctx.region.clone();
        let tags = self.with_region(ctx, |r| match r.prefix_lists.get(id) {
            Some(p) => Ok(p.list.tags.clone()),
            None if aws_prefix_lists(&region).iter().any(|p| p.id == id) => Err(err(
                "InvalidPrefixListModification",
                format!("The prefix list {id} is owned by AWS and cannot be modified."),
            )),
            None => Err(Kind::PrefixList.not_found(id)),
        })?;
        authorize(
            ctx,
            action,
            &[(arn(ctx, &account, &format!("prefix-list/{id}")), resource_tag_context(tags.as_ref()))],
            dry_run,
        )
    }

    pub(crate) fn modify_managed_prefix_list_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyManagedPrefixListRequest,
    ) -> Result<t::ModifyManagedPrefixListResult, ServiceError> {
        self.pl_authorize(ctx, "ModifyManagedPrefixList", &input.prefix_list_id, input.dry_run)?;
        let changes_entries = input.add_entries.as_ref().is_some_and(|v| !v.is_empty())
            || input.remove_entries.as_ref().is_some_and(|v| !v.is_empty());
        if changes_entries && input.max_entries.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "You cannot modify the entries and the maximum number of entries in the same request.",
            ));
        }
        self.with_region(ctx, |r| {
            let rec = r.prefix_lists.get_mut(&input.prefix_list_id).expect("checked");
            let latest = rec.versions.len() as i64;
            if let Some(v) = input.current_version {
                if v != latest {
                    return Err(err(
                        "PrefixListVersionMismatch",
                        format!(
                            "The prefix list {} has version {latest}, not the version {v} the request names.",
                            input.prefix_list_id
                        ),
                    ));
                }
            } else if changes_entries {
                return Err(missing_parameter("CurrentVersion"));
            }
            if let Some(name) = &input.prefix_list_name {
                rec.list.prefix_list_name = Some(name.clone());
            }
            let current = rec.versions.last().cloned().unwrap_or_default();
            if let Some(max) = input.max_entries {
                if (max as usize) < current.len() || max > 1000 {
                    return Err(invalid_parameter(format!(
                        "The maximum number of entries ({max}) must be between the current number of entries ({}) and 1000.",
                        current.len()
                    )));
                }
                rec.list.max_entries = Some(max);
            }
            if changes_entries {
                let family = rec.list.address_family.clone().unwrap_or_default();
                let mut next = current.clone();
                for e in input.remove_entries.iter().flatten() {
                    let before = next.len();
                    next.retain(|x| x.cidr.as_deref() != Some(e.cidr.as_str()));
                    if next.len() == before {
                        return Err(err(
                            "InvalidPrefixListModification",
                            format!("The CIDR {} is not an entry of prefix list {}.", e.cidr, input.prefix_list_id),
                        ));
                    }
                }
                let added = check_entries(&family, input.add_entries.iter().flatten(), i32::MAX)?;
                for a in added {
                    next.retain(|x| x.cidr != a.cidr);
                    next.push(a);
                }
                if next.len() > rec.list.max_entries.unwrap_or_default() as usize {
                    return Err(err(
                        "PrefixListMaxEntriesExceeded",
                        format!("The prefix list {} would exceed its maximum number of entries.", input.prefix_list_id),
                    ));
                }
                rec.versions.push(next);
                rec.list.version = Some(rec.versions.len() as i64);
            }
            rec.list.state = Some("modify-complete".into());
            let mut shown = rec.list.clone();
            shown.state = Some("modify-in-progress".into());
            Ok(t::ModifyManagedPrefixListResult { prefix_list: Some(shown) })
        })
    }

    pub(crate) fn delete_managed_prefix_list_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteManagedPrefixListRequest,
    ) -> Result<t::DeleteManagedPrefixListResult, ServiceError> {
        self.pl_authorize(ctx, "DeleteManagedPrefixList", &input.prefix_list_id, input.dry_run)?;
        let id = input.prefix_list_id.clone();
        self.with_region(ctx, |r| {
            if !prefix_list_associations(r, &id).is_empty() {
                return Err(err(
                    "PrefixListInUse",
                    format!("The prefix list {id} is referenced by security groups or route tables."),
                ));
            }
            let mut rec = r.prefix_lists.remove(&id).expect("checked");
            rec.list.state = Some("delete-in-progress".into());
            Ok(t::DeleteManagedPrefixListResult { prefix_list: Some(rec.list) })
        })
    }

    pub(crate) fn get_managed_prefix_list_associations_op(
        &self,
        ctx: &RequestContext,
        input: t::GetManagedPrefixListAssociationsRequest,
    ) -> Result<t::GetManagedPrefixListAssociationsResult, ServiceError> {
        self.pl_authorize(ctx, "GetManagedPrefixListAssociations", &input.prefix_list_id, input.dry_run)?;
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            let assocs: Vec<t::PrefixListAssociation> = prefix_list_associations(r, &input.prefix_list_id)
                .into_iter()
                .map(|id| t::PrefixListAssociation { resource_id: Some(id), resource_owner: Some(account.clone()) })
                .collect();
            let (items, next_token) = paginate(assocs, input.max_results, &input.next_token)?;
            Ok(t::GetManagedPrefixListAssociationsResult { prefix_list_associations: Some(items), next_token })
        })
    }
}

/// Security groups and route tables that reference a prefix list.
fn prefix_list_associations(r: &RegionState, id: &str) -> Vec<String> {
    let mut out: Vec<String> =
        r.sg_rules.values().filter(|x| x.prefix_list_id.as_deref() == Some(id)).map(|x| x.group_id.clone()).collect();
    out.extend(
        r.route_tables
            .values()
            .filter(|rt| rt.routes.iter().flatten().any(|x| x.destination_prefix_list_id.as_deref() == Some(id)))
            .filter_map(|rt| rt.route_table_id.clone()),
    );
    out.sort();
    out.dedup();
    out
}

fn check_entries<'a>(
    family: &str,
    entries: impl Iterator<Item = &'a t::AddPrefixListEntry>,
    max: i32,
) -> Result<Vec<t::PrefixListEntry>, ServiceError> {
    let mut out: Vec<t::PrefixListEntry> = Vec::new();
    for e in entries {
        let valid = if family == "IPv4" {
            Cidr::parse(&e.cidr).is_some()
        } else {
            e.cidr.contains(':') && e.cidr.contains('/')
        };
        if !valid {
            return Err(invalid_parameter(format!("The CIDR {} is not a valid {family} CIDR.", e.cidr)));
        }
        if out.iter().any(|x| x.cidr.as_deref() == Some(e.cidr.as_str())) {
            return Err(invalid_parameter(format!("The CIDR {} is duplicated.", e.cidr)));
        }
        out.push(t::PrefixListEntry { cidr: Some(e.cidr.clone()), description: e.description.clone() });
    }
    if out.len() > max as usize {
        return Err(err(
            "PrefixListMaxEntriesExceeded",
            format!("The number of entries ({}) exceeds the maximum number of entries ({max}).", out.len()),
        ));
    }
    Ok(out)
}

/// Private DNS for a service needs the VPC's DNS attributes and no other
/// endpoint in the VPC claiming the same name.
fn check_private_dns(
    r: &RegionState,
    region: &str,
    vpc_id: &str,
    service: &EndpointService,
    except: Option<&str>,
) -> Result<(), ServiceError> {
    let vpc = r.vpcs.get(vpc_id).ok_or_else(|| Kind::Vpc.not_found(vpc_id))?;
    if !vpc.enable_dns_support || !vpc.enable_dns_hostnames {
        return Err(err(
            "InvalidParameter",
            format!(
                "Enabling private DNS requires both enableDnsSupport and enableDnsHostnames VPC attributes set to true for {vpc_id}"
            ),
        ));
    }
    let name = service_name(region, service);
    let conflict = r.vpc_endpoints.values().any(|e| {
        e.vpc_id.as_deref() == Some(vpc_id)
            && e.service_name.as_deref() == Some(name.as_str())
            && e.vpc_endpoint_type.as_deref() == Some("Interface")
            && e.private_dns_enabled == Some(true)
            && e.vpc_endpoint_id.as_deref() != except
    });
    if conflict {
        return Err(err(
            "InvalidParameter",
            format!(
                "private-dns-enabled cannot be set because there is already a conflicting DNS domain for {} in the VPC {vpc_id}",
                private_dns_name(region, service)
            ),
        ));
    }
    Ok(())
}

/// Route a gateway endpoint's prefix list through `rtb`.
fn add_endpoint_route(
    r: &mut RegionState,
    vpc_id: &str,
    rtb: &str,
    pl: &str,
    endpoint_id: &str,
) -> Result<(), ServiceError> {
    Kind::RouteTable.check(rtb)?;
    let rt = r.route_tables.get_mut(rtb).ok_or_else(|| Kind::RouteTable.not_found(rtb))?;
    if rt.vpc_id.as_deref() != Some(vpc_id) {
        return Err(err("InvalidParameter", format!("route table {rtb} does not belong to vpc {vpc_id}")));
    }
    if rt.routes.iter().flatten().any(|x| x.destination_prefix_list_id.as_deref() == Some(pl)) {
        return Err(err(
            "RouteAlreadyExists",
            format!("route table {rtb} already has a route with destination-prefix-list-id {pl}"),
        ));
    }
    rt.routes.get_or_insert_with(Vec::new).push(t::Route {
        destination_prefix_list_id: Some(pl.into()),
        gateway_id: Some(endpoint_id.into()),
        origin: Some("CreateRoute".into()),
        state: Some("active".into()),
        ..Default::default()
    });
    Ok(())
}

fn remove_endpoint_route(r: &mut RegionState, rtb: &str, endpoint_id: &str) {
    if let Some(rt) = r.route_tables.get_mut(rtb) {
        if let Some(routes) = &mut rt.routes {
            routes.retain(|x| x.gateway_id.as_deref() != Some(endpoint_id));
        }
    }
}

/// Give an interface endpoint a network interface in `subnet` (one subnet
/// per Availability Zone).
pub(crate) fn add_endpoint_subnet(
    r: &mut RegionState,
    account: &str,
    region: &str,
    ep: &mut t::VpcEndpoint,
    subnet_id: &str,
    now: chrono::DateTime<chrono::Utc>,
    configs: &Option<Vec<t::SubnetConfiguration>>,
) -> Result<(), ServiceError> {
    Kind::Subnet.check(subnet_id)?;
    let subnet = r.subnets.get(subnet_id).ok_or_else(|| Kind::Subnet.not_found(subnet_id))?.clone();
    if subnet.vpc_id != ep.vpc_id {
        return Err(err(
            "InvalidParameter",
            format!("The subnet ID '{subnet_id}' does not belong to the VPC {}", ep.vpc_id.clone().unwrap_or_default()),
        ));
    }
    let same_zone = ep
        .subnet_ids
        .iter()
        .flatten()
        .any(|other| r.subnets.get(other).and_then(|s| s.availability_zone.clone()) == subnet.availability_zone);
    if same_zone {
        return Err(err(
            "DuplicateSubnetsInSameZone",
            format!(
                "Found another VPC endpoint subnet in the availability zone of {subnet_id}. VPC endpoint subnets should be in different availability zones supported by the VPC endpoint service."
            ),
        ));
    }
    let wanted =
        configs.iter().flatten().find(|c| c.subnet_id.as_deref() == Some(subnet_id)).and_then(|c| c.ipv4.clone());
    let ip = match wanted {
        Some(ip) => {
            super::vpc::check_ip(r, subnet_id, &ip)?;
            ip
        }
        None => super::vpc::allocate_ip(r, subnet_id)
            .ok_or_else(|| err("InsufficientFreeAddressesInSubnet", "Insufficient free IP addresses in subnet."))?,
    };
    let groups: Vec<t::GroupIdentifier> = ep
        .groups
        .iter()
        .flatten()
        .map(|g| t::GroupIdentifier { group_id: g.group_id.clone(), group_name: g.group_name.clone() })
        .collect();
    let id = ep.vpc_endpoint_id.clone().unwrap_or_default();
    let eni = super::eni::new_eni(
        r,
        account,
        region,
        &subnet,
        &ip,
        groups,
        &format!("VPC Endpoint Interface {id}"),
        "vpc_endpoint",
        now,
    );
    if let Some(n) = r.network_interfaces.get_mut(&eni) {
        n.requester_managed = Some(true);
        n.status = Some("in-use".into());
    }
    ep.network_interface_ids.get_or_insert_with(Vec::new).push(eni);
    ep.subnet_ids.get_or_insert_with(Vec::new).push(subnet_id.into());
    Ok(())
}

/// An interface endpoint's DNS names: the regional one, one per zone, and
/// the service's own name when private DNS is on.
fn dns_entries(r: &RegionState, region: &str, ep: &t::VpcEndpoint, service: &EndpointService) -> Vec<t::DnsEntry> {
    let id = ep.vpc_endpoint_id.clone().unwrap_or_default();
    // The label stays the same across modifications.
    let label = ep
        .dns_entries
        .iter()
        .flatten()
        .filter_map(|d| d.dns_name.as_deref())
        .find_map(|n| n.strip_prefix(&format!("{id}-")).and_then(|rest| rest.split('.').next()).map(str::to_string))
        .map(|l| l.split('-').next().unwrap_or_default().to_string())
        .unwrap_or_else(dns_label);
    let zone = vpce_zone(region);
    let base = format!("{}.{region}.vpce.amazonaws.com", service.dns);
    let mut out =
        vec![t::DnsEntry { dns_name: Some(format!("{id}-{label}.{base}")), hosted_zone_id: Some(zone.clone()) }];
    for subnet in ep.subnet_ids.iter().flatten() {
        if let Some(az) = r.subnets.get(subnet).and_then(|s| s.availability_zone.clone()) {
            out.push(t::DnsEntry {
                dns_name: Some(format!("{id}-{label}-{az}.{base}")),
                hosted_zone_id: Some(zone.clone()),
            });
        }
    }
    if ep.private_dns_enabled == Some(true) {
        let zone_id = format!("Z{}", hex::encode_upper(&Md5::digest(format!("{id}/private").as_bytes())[..10]));
        out.push(t::DnsEntry { dns_name: Some(private_dns_name(region, service)), hosted_zone_id: Some(zone_id) });
    }
    out
}
