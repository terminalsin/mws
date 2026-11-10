//! Classic Load Balancers (the `2012-06-01` API): load balancers with
//! listeners that forward straight to registered EC2 instances, a single
//! health check, stickiness and other policies. They share ELBv2's data
//! plane: HTTP/HTTPS listeners run the layer 7 proxy, TCP/SSL listeners
//! the layer 4 one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

use mws_core::{RequestContext, ServiceError};

use crate::classic_api::{errors, types as ct, Handler};
use crate::data::tls::TlsSettings;
use crate::data::FrontSpec;
use crate::health::{HealthKey, Probe, ProbeKind};
use crate::metrics::{dims, Batch};
use crate::names::{self, validation};
use crate::state::{ClassicLoadBalancer, RegionState, State};
use crate::{account_of, catalog, ClassicElb, Elb};

/// `arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/<name>`.
pub(crate) fn lb_arn(region_key: &str, name: &str) -> String {
    let (account, region) = region_key.split_once('|').unwrap_or_default();
    format!("arn:aws:{}:{region}:{account}:loadbalancer/{name}", names::SERVICE)
}

fn not_found(name: &str) -> ServiceError {
    errors::access_point_not_found(format!("There is no ACTIVE Load Balancer named '{name}'"))
}

fn find<'a>(r: &'a mut RegionState, name: &str) -> Result<&'a mut ClassicLoadBalancer, ServiceError> {
    r.classic.get_mut(name).ok_or_else(|| not_found(name))
}

fn default_attributes() -> ct::LoadBalancerAttributes {
    ct::LoadBalancerAttributes {
        cross_zone_load_balancing: Some(ct::CrossZoneLoadBalancing { enabled: false }),
        access_log: Some(ct::AccessLog { enabled: false, ..Default::default() }),
        connection_draining: Some(ct::ConnectionDraining { enabled: false, timeout: Some(300) }),
        connection_settings: Some(ct::ConnectionSettings { idle_timeout: 60 }),
        additional_attributes: Some(vec![ct::AdditionalAttribute {
            key: Some("elb.http.desyncmitigationmode".into()),
            value: Some("defensive".into()),
        }]),
    }
}

/// `(protocol, port, path)` of a health check target like `HTTP:80/ping`.
fn parse_target(target: &str) -> Option<(String, u16, Option<String>)> {
    let (proto, rest) = target.split_once(':')?;
    let proto = proto.to_ascii_uppercase();
    match proto.as_str() {
        "HTTP" | "HTTPS" => {
            let i = rest.find('/')?;
            let (port, path) = (&rest[..i], rest[i..].to_string());
            Some((proto, port.parse().ok()?, Some(path)))
        }
        "TCP" | "SSL" => Some((proto, rest.parse().ok()?, None)),
        _ => None,
    }
}

const PROTOCOLS: &[&str] = &["HTTP", "HTTPS", "TCP", "SSL"];

fn layer7(p: &str) -> bool {
    matches!(p.to_ascii_uppercase().as_str(), "HTTP" | "HTTPS")
}

/// Policy types and their attributes: `(type, description, attributes)`
/// with attributes as `(name, type, cardinality, default)`.
/// `(name, type, cardinality, default)`.
type AttributeType = (&'static str, &'static str, &'static str, &'static str);

const POLICY_TYPES: &[(&str, &str, &[AttributeType])] = &[
    ("ProxyProtocolPolicyType", "Policy that controls whether to include the IP address and port of the originating request for TCP messages. This policy operates on TCP listeners only.", &[("ProxyProtocol", "Boolean", "ONE", "")]),
    ("PublicKeyPolicyType", "Policy containing a list of public keys to accept when authenticating the back-end server(s). This policy cannot be applied directly to back-end servers or listeners but must be part of a BackendServerAuthenticationPolicyType.", &[("PublicKey", "String", "ONE", "")]),
    ("BackendServerAuthenticationPolicyType", "Policy that controls authentication to back-end server(s) and contains one or more policies, such as an instance of a PublicKeyPolicyType. This policy can be associated only with back-end servers that are using HTTPS/SSL.", &[("PublicKeyPolicyName", "PolicyName", "ONE_OR_MORE", "")]),
    ("LBCookieStickinessPolicyType", "Stickiness policy with session lifetimes controlled by the browser (user-agent) or a specified expiration period. This policy can be associated only with HTTP/HTTPS listeners.", &[("CookieExpirationPeriod", "Long", "ZERO_OR_ONE", "")]),
    ("AppCookieStickinessPolicyType", "Stickiness policy with session lifetimes controlled by the lifetime of the application-generated cookie. This policy can be associated only with HTTP/HTTPS listeners.", &[("CookieName", "String", "ONE", "")]),
    ("SSLNegotiationPolicyType", "Listener policy that defines the ciphers and protocols that will be accepted by the load balancer. This policy can be associated only with HTTPS/SSL listeners.", &[
        ("Reference-Security-Policy", "String", "ZERO_OR_ONE", ""),
        ("Protocol-TLSv1", "Boolean", "ZERO_OR_ONE", "false"),
        ("Protocol-TLSv1.1", "Boolean", "ZERO_OR_ONE", "false"),
        ("Protocol-TLSv1.2", "Boolean", "ZERO_OR_ONE", "false"),
        ("Server-Defined-Cipher-Order", "Boolean", "ZERO_OR_ONE", "false"),
    ]),
];

/// The predefined policies `DescribeLoadBalancerPolicies` lists without a
/// load balancer name.
fn sample_policies() -> Vec<ct::PolicyDescription> {
    let mut out: Vec<ct::PolicyDescription> = catalog::SSL_POLICIES
        .iter()
        .filter(|(n, p, _)| !n.contains("TLS13") && !p.contains(&"TLSv1.3"))
        .map(|(name, protocols, _)| ct::PolicyDescription {
            policy_name: Some(name.to_string()),
            policy_type_name: Some("SSLNegotiationPolicyType".into()),
            policy_attribute_descriptions: Some(
                ["TLSv1", "TLSv1.1", "TLSv1.2"]
                    .iter()
                    .map(|p| ct::PolicyAttributeDescription {
                        attribute_name: Some(format!("Protocol-{p}")),
                        attribute_value: Some(protocols.contains(p).to_string()),
                    })
                    .chain(std::iter::once(ct::PolicyAttributeDescription {
                        attribute_name: Some("Server-Defined-Cipher-Order".into()),
                        attribute_value: Some("true".into()),
                    }))
                    .collect(),
            ),
        })
        .collect();
    out.push(ct::PolicyDescription {
        policy_name: Some("ELBSample-ELBDefaultNegotiationPolicy".into()),
        policy_type_name: Some("SSLNegotiationPolicyType".into()),
        policy_attribute_descriptions: Some(vec![ct::PolicyAttributeDescription {
            attribute_name: Some("Reference-Security-Policy".into()),
            attribute_value: Some(catalog::DEFAULT_SSL_POLICY.into()),
        }]),
    });
    out
}

impl ClassicElb {
    fn with_region<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut RegionState) -> R) -> R {
        self.elb.with_region(ctx, f)
    }

    fn authorize(&self, ctx: &RequestContext, action: &str, name: &str) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let arn = lb_arn(&State::key(&account, &ctx.region), name);
        let tags: Vec<crate::v2::types::Tag> = self.with_region(ctx, |r| {
            r.classic
                .get(name)
                .map(|c| {
                    c.tags
                        .iter()
                        .map(|t| crate::v2::types::Tag { key: t.key.clone(), value: t.value.clone() })
                        .collect()
                })
                .unwrap_or_default()
        });
        names::authorize(ctx, action, &arn, names::resource_tag_context(&tags))
    }

    fn check_listener(&self, ctx: &RequestContext, l: &mut ct::Listener) -> Result<(), ServiceError> {
        let proto = l.protocol.to_ascii_uppercase();
        if !PROTOCOLS.contains(&proto.as_str()) {
            return Err(errors::unsupported_protocol(format!("Protocol '{}' is not supported", l.protocol)));
        }
        l.protocol = proto.clone();
        let instance = l.instance_protocol.clone().unwrap_or_else(|| match proto.as_str() {
            "HTTPS" => "HTTP".into(),
            "SSL" => "TCP".into(),
            p => p.into(),
        });
        let instance = instance.to_ascii_uppercase();
        if !PROTOCOLS.contains(&instance.as_str()) || layer7(&proto) != layer7(&instance) {
            return Err(validation(format!(
                "Listener protocol '{proto}' and instance protocol '{instance}' are not compatible"
            )));
        }
        l.instance_protocol = Some(instance);
        if !(1..=65535).contains(&l.load_balancer_port) || !(1..=65535).contains(&l.instance_port) {
            return Err(validation("Ports must be between 1 and 65535"));
        }
        match (proto.as_str(), &l.ssl_certificate_id) {
            ("HTTPS" | "SSL", None) => {
                return Err(validation("A certificate must be specified for HTTPS and SSL listeners"));
            }
            ("HTTPS" | "SSL", Some(cert)) => self.check_certificate(ctx, cert)?,
            (_, Some(_)) => return Err(validation("A certificate can only be specified for HTTPS and SSL listeners")),
            _ => {}
        }
        Ok(())
    }

    fn check_certificate(&self, ctx: &RequestContext, arn: &str) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        match self.elb.acm().and_then(|a| a.server_certificate(arn)) {
            Some(c) if c.account == account && c.region == ctx.region && c.status == "ISSUED" => Ok(()),
            _ => Err(errors::certificate_not_found(format!("Server Certificate not found for the key: {arn}"))),
        }
    }

    fn set_certificate_use(&self, ctx: &RequestContext, name: &str, cert: &str, in_use: bool) {
        if let Some(acm) = self.elb.acm() {
            let arn = lb_arn(&State::key(&account_of(ctx), &ctx.region), name);
            acm.set_in_use(cert, &arn, in_use);
        }
    }

    /// Subnets for AZ names (the default subnet of each AZ in the VPC).
    fn subnets_for_zones(
        &self,
        ctx: &RequestContext,
        vpc: Option<&str>,
        zones: &[String],
    ) -> Result<Vec<mws_ec2::SubnetInfo>, ServiceError> {
        let account = account_of(ctx);
        let Some(ec2) = self.elb.ec2() else { return Ok(Vec::new()) };
        let subnets = ec2.subnets_of_vpc(ctx, &account, vpc);
        zones
            .iter()
            .map(|z| {
                subnets
                    .iter()
                    .find(|s| &s.availability_zone == z)
                    .cloned()
                    .ok_or_else(|| errors::invalid_configuration_request(format!("Invalid Availability Zone: {z}")))
            })
            .collect()
    }

    fn resolve_subnets(
        &self,
        ctx: &RequestContext,
        ids: &[String],
        vpc: Option<&str>,
    ) -> Result<Vec<mws_ec2::SubnetInfo>, ServiceError> {
        let account = account_of(ctx);
        let Some(ec2) = self.elb.ec2() else { return Ok(Vec::new()) };
        let mut out: Vec<mws_ec2::SubnetInfo> = Vec::new();
        for id in ids {
            let s = ec2
                .subnet_info(ctx, &account, id)
                .ok_or_else(|| errors::subnet_not_found(format!("One or more subnets not found: {id}")))?;
            let expected = vpc.map(str::to_string).or_else(|| out.first().map(|f| f.vpc_id.clone()));
            if expected.as_ref().is_some_and(|v| *v != s.vpc_id) {
                return Err(errors::invalid_subnet(format!("Subnet {id} is not in the load balancer's VPC")));
            }
            if out.iter().any(|o| o.availability_zone == s.availability_zone) {
                return Err(errors::invalid_configuration_request(
                    "Only one subnet per Availability Zone can be attached to a load balancer",
                ));
            }
            out.push(s);
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl Handler for ClassicElb {
    async fn create_load_balancer(
        &self,
        ctx: &RequestContext,
        input: ct::CreateAccessPointInput,
    ) -> Result<ct::CreateAccessPointOutput, ServiceError> {
        let name = input.load_balancer_name.clone();
        names::check_name("Load balancer", &name)?;
        let account = account_of(ctx);
        let region_key = State::key(&account, &ctx.region);
        let tags = input.tags.clone().unwrap_or_default();
        let v2_tags: Vec<crate::v2::types::Tag> =
            tags.iter().map(|t| crate::v2::types::Tag { key: t.key.clone(), value: t.value.clone() }).collect();
        names::check_tags(&v2_tags).map_err(|e| {
            ServiceError::client(
                if e.code == "DuplicateTagKeys" { "DuplicateTagKeys" } else { "ValidationError" },
                400,
                e.message,
            )
        })?;
        self.elb.authorize_create(ctx, "CreateLoadBalancer", &lb_arn(&region_key, &name), &v2_tags)?;
        let mut listeners = input.listeners.clone();
        if listeners.is_empty() {
            return Err(validation("At least one listener must be specified"));
        }
        for l in &mut listeners {
            self.check_listener(ctx, l)?;
        }
        let scheme = input.scheme.clone().unwrap_or_else(|| "internet-facing".into());
        if !matches!(scheme.as_str(), "internet-facing" | "internal") {
            return Err(errors::invalid_scheme(format!("Invalid scheme: {scheme}")));
        }
        let subnets = match (
            input.subnets.as_ref().filter(|s| !s.is_empty()),
            input.availability_zones.as_ref().filter(|z| !z.is_empty()),
        ) {
            (Some(_), Some(_)) => return Err(validation("Specify either subnets or Availability Zones, not both")),
            (Some(s), None) => self.resolve_subnets(ctx, s, None)?,
            (None, Some(z)) => self.subnets_for_zones(ctx, None, z)?,
            (None, None) => return Err(validation("Either AvailabilityZones or SubnetIds must be specified")),
        };
        let vpc = subnets.first().map(|s| s.vpc_id.clone());
        let mut groups = input.security_groups.clone().unwrap_or_default();
        if let (Some(ec2), Some(vpc)) = (self.elb.ec2(), &vpc) {
            for g in &groups {
                if ec2.security_group_info(ctx, &account, g).is_none_or(|i| &i.vpc_id != vpc) {
                    return Err(errors::invalid_security_group(format!(
                        "One or more security groups are invalid: {g}"
                    )));
                }
            }
            if groups.is_empty() {
                groups.extend(ec2.vpc_info(ctx, &account, Some(vpc)).and_then(|v| v.default_security_group));
            }
        }
        let source_group = match (self.elb.ec2(), groups.first()) {
            (Some(ec2), Some(g)) => ec2.security_group_info(ctx, &account, g).map(|i| i.group_name),
            _ => None,
        };
        let max_load_balancers = self.elb.limit(ctx, "classic-load-balancers");
        let created = self.with_region(ctx, |r| {
            if let Some(existing) = r.classic.get(&name) {
                let same = existing
                    .description
                    .listener_descriptions
                    .iter()
                    .flatten()
                    .filter_map(|d| d.listener.clone())
                    .collect::<Vec<_>>()
                    == listeners;
                if same {
                    return Ok((existing.description.dns_name.clone(), false));
                }
                return Err(errors::duplicate_access_point_name(format!(
                    "Load Balancer named '{name}' already exists and it is configured with different parameters."
                )));
            }
            if r.classic.len() >= max_load_balancers {
                return Err(errors::too_many_access_points("Exceeded quota of account"));
            }
            let dns = format!(
                "{}{name}-{}.{}.elb.{}",
                if scheme == "internal" { "internal-" } else { "" },
                names::decimal_id(10),
                ctx.region,
                names::dns_suffix(&ctx.partition)
            );
            let first_port = listeners[0].instance_port;
            let description = ct::LoadBalancerDescription {
                load_balancer_name: Some(name.clone()),
                dns_name: Some(dns.clone()),
                canonical_hosted_zone_name: (scheme == "internet-facing").then(|| dns.clone()),
                canonical_hosted_zone_name_id: Some(names::canonical_hosted_zone(&ctx.region, "application").into()),
                listener_descriptions: Some(
                    listeners
                        .iter()
                        .map(|l| ct::ListenerDescription { listener: Some(l.clone()), policy_names: Some(Vec::new()) })
                        .collect(),
                ),
                policies: Some(ct::Policies {
                    app_cookie_stickiness_policies: Some(Vec::new()),
                    lb_cookie_stickiness_policies: Some(Vec::new()),
                    other_policies: Some(Vec::new()),
                }),
                backend_server_descriptions: Some(Vec::new()),
                availability_zones: Some(subnets.iter().map(|s| s.availability_zone.clone()).collect()),
                subnets: Some(subnets.iter().map(|s| s.subnet_id.clone()).collect()),
                vpc_id: vpc.clone(),
                instances: Some(Vec::new()),
                health_check: Some(ct::HealthCheck {
                    target: format!("TCP:{first_port}"),
                    interval: 30,
                    timeout: 5,
                    unhealthy_threshold: 2,
                    healthy_threshold: 10,
                }),
                source_security_group: Some(ct::SourceSecurityGroup {
                    owner_alias: Some(account.clone()),
                    group_name: source_group.clone(),
                }),
                security_groups: Some(groups.clone()),
                created_time: Some(ctx.received_at),
                scheme: Some(scheme.clone()),
            };
            r.classic.insert(
                name.clone(),
                ClassicLoadBalancer {
                    description,
                    attributes: default_attributes(),
                    policies: Vec::new(),
                    tags: tags.clone(),
                    instances: Vec::new(),
                    network_interfaces: Default::default(),
                },
            );
            Ok((Some(dns), true))
        })?;
        if created.1 {
            if let Err(e) = self.sync_interfaces(ctx, &name) {
                let removed = self.with_region(ctx, |r| r.classic.remove(&name));
                self.delete_interfaces(ctx, removed.map(|c| c.network_interfaces).unwrap_or_default());
                return Err(e);
            }
            for l in &listeners {
                if let Some(c) = &l.ssl_certificate_id {
                    self.set_certificate_use(ctx, &name, c, true);
                }
            }
        }
        self.elb.reconcile();
        Ok(ct::CreateAccessPointOutput { dns_name: created.0 })
    }

    async fn describe_load_balancers(
        &self,
        ctx: &RequestContext,
        input: ct::DescribeAccessPointsInput,
    ) -> Result<ct::DescribeAccessPointsOutput, ServiceError> {
        names::authorize(ctx, "DescribeLoadBalancers", "*", Default::default())?;
        let wanted = input.load_balancer_names.unwrap_or_default();
        let all = self.with_region(ctx, |r| -> Result<Vec<ct::LoadBalancerDescription>, ServiceError> {
            if wanted.is_empty() {
                return Ok(r.classic.values().map(describe).collect());
            }
            wanted.iter().map(|n| r.classic.get(n).map(describe).ok_or_else(|| not_found(n))).collect()
        })?;
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(ct::DescribeAccessPointsOutput { load_balancer_descriptions: Some(items), next_marker: next })
    }

    async fn delete_load_balancer(
        &self,
        ctx: &RequestContext,
        input: ct::DeleteAccessPointInput,
    ) -> Result<ct::DeleteAccessPointOutput, ServiceError> {
        self.authorize(ctx, "DeleteLoadBalancer", &input.load_balancer_name)?;
        let removed = self.with_region(ctx, |r| r.classic.remove(&input.load_balancer_name));
        if let Some(lb) = removed {
            self.delete_interfaces(ctx, lb.network_interfaces.clone());
            for l in lb.description.listener_descriptions.iter().flatten().filter_map(|d| d.listener.as_ref()) {
                if let Some(c) = &l.ssl_certificate_id {
                    self.set_certificate_use(ctx, &input.load_balancer_name, c, false);
                }
            }
            let group = format!("classic:{}:{}", State::key(&account_of(ctx), &ctx.region), input.load_balancer_name);
            self.elb.inner.health.forget_group(&group);
        }
        self.elb.reconcile();
        Ok(ct::DeleteAccessPointOutput {})
    }

    async fn create_load_balancer_listeners(
        &self,
        ctx: &RequestContext,
        input: ct::CreateLoadBalancerListenerInput,
    ) -> Result<ct::CreateLoadBalancerListenerOutput, ServiceError> {
        self.authorize(ctx, "CreateLoadBalancerListeners", &input.load_balancer_name)?;
        let mut listeners = input.listeners.clone();
        for l in &mut listeners {
            self.check_listener(ctx, l)?;
        }
        let added = self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            let descs = lb.description.listener_descriptions.get_or_insert_with(Vec::new);
            let mut added = Vec::new();
            for l in &listeners {
                match descs.iter().find(|d| d.listener.as_ref().is_some_and(|x| x.load_balancer_port == l.load_balancer_port)) {
                    Some(d) if d.listener.as_ref() == Some(l) => {}
                    Some(_) => {
                        return Err(errors::duplicate_listener(format!(
                            "A listener already exists for {} with LoadBalancerPort {}, but with a different InstancePort, Protocol, or SSLCertificateId",
                            input.load_balancer_name, l.load_balancer_port
                        )))
                    }
                    None => {
                        descs.push(ct::ListenerDescription { listener: Some(l.clone()), policy_names: Some(Vec::new()) });
                        added.push(l.clone());
                    }
                }
            }
            Ok(added)
        })?;
        for l in added {
            if let Some(c) = &l.ssl_certificate_id {
                self.set_certificate_use(ctx, &input.load_balancer_name, c, true);
            }
        }
        self.elb.reconcile();
        Ok(ct::CreateLoadBalancerListenerOutput {})
    }

    async fn delete_load_balancer_listeners(
        &self,
        ctx: &RequestContext,
        input: ct::DeleteLoadBalancerListenerInput,
    ) -> Result<ct::DeleteLoadBalancerListenerOutput, ServiceError> {
        self.authorize(ctx, "DeleteLoadBalancerListeners", &input.load_balancer_name)?;
        let removed = self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            let descs = lb.description.listener_descriptions.get_or_insert_with(Vec::new);
            let mut removed = Vec::new();
            descs.retain(|d| {
                let gone =
                    d.listener.as_ref().is_some_and(|l| input.load_balancer_ports.contains(&l.load_balancer_port));
                if gone {
                    removed.extend(d.listener.clone());
                }
                !gone
            });
            Ok::<_, ServiceError>(removed)
        })?;
        for l in removed {
            if let Some(c) = &l.ssl_certificate_id {
                self.set_certificate_use(ctx, &input.load_balancer_name, c, false);
            }
        }
        self.elb.reconcile();
        Ok(ct::DeleteLoadBalancerListenerOutput {})
    }

    async fn set_load_balancer_listener_ssl_certificate(
        &self,
        ctx: &RequestContext,
        input: ct::SetLoadBalancerListenerSSLCertificateInput,
    ) -> Result<ct::SetLoadBalancerListenerSSLCertificateOutput, ServiceError> {
        self.authorize(ctx, "SetLoadBalancerListenerSSLCertificate", &input.load_balancer_name)?;
        self.check_certificate(ctx, &input.ssl_certificate_id)?;
        let old = self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            let l = lb
                .description
                .listener_descriptions
                .iter_mut()
                .flatten()
                .filter_map(|d| d.listener.as_mut())
                .find(|l| l.load_balancer_port == input.load_balancer_port)
                .ok_or_else(|| {
                    errors::listener_not_found("LoadBalancer does not have a listnener configured at the given port.")
                })?;
            if !matches!(l.protocol.as_str(), "HTTPS" | "SSL") {
                return Err(errors::invalid_configuration_request("The listener is not an HTTPS or SSL listener"));
            }
            Ok(l.ssl_certificate_id.replace(input.ssl_certificate_id.clone()))
        })?;
        if let Some(old) = old {
            self.set_certificate_use(ctx, &input.load_balancer_name, &old, false);
        }
        self.set_certificate_use(ctx, &input.load_balancer_name, &input.ssl_certificate_id, true);
        Ok(ct::SetLoadBalancerListenerSSLCertificateOutput {})
    }

    async fn register_instances_with_load_balancer(
        &self,
        ctx: &RequestContext,
        input: ct::RegisterEndPointsInput,
    ) -> Result<ct::RegisterEndPointsOutput, ServiceError> {
        self.authorize(ctx, "RegisterInstancesWithLoadBalancer", &input.load_balancer_name)?;
        let account = account_of(ctx);
        let vpc = self.with_region(ctx, |r| {
            r.classic
                .get(&input.load_balancer_name)
                .map(|c| c.description.vpc_id.clone())
                .ok_or_else(|| not_found(&input.load_balancer_name))
        })?;
        for i in &input.instances {
            let id = i.instance_id.clone().unwrap_or_default();
            if let Some(ec2) = self.elb.ec2() {
                let ok = ec2
                    .instance_info(&account, &ctx.region, &id)
                    .is_some_and(|info| info.state != "terminated" && (vpc.is_none() || info.vpc_id == vpc));
                if !ok {
                    return Err(errors::invalid_end_point(format!("The specified EndPoint is not valid: {id}")));
                }
            }
        }
        let out = self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            for i in &input.instances {
                let id = i.instance_id.clone().unwrap_or_default();
                if !lb.instances.contains(&id) {
                    lb.instances.push(id);
                }
            }
            lb.description.instances =
                Some(lb.instances.iter().map(|i| ct::Instance { instance_id: Some(i.clone()) }).collect());
            Ok::<_, ServiceError>(lb.description.instances.clone())
        })?;
        self.elb.reconcile();
        Ok(ct::RegisterEndPointsOutput { instances: out })
    }

    async fn deregister_instances_from_load_balancer(
        &self,
        ctx: &RequestContext,
        input: ct::DeregisterEndPointsInput,
    ) -> Result<ct::DeregisterEndPointsOutput, ServiceError> {
        self.authorize(ctx, "DeregisterInstancesFromLoadBalancer", &input.load_balancer_name)?;
        let region_key = State::key(&account_of(ctx), &ctx.region);
        let out = self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            for i in &input.instances {
                let id = i.instance_id.clone().unwrap_or_default();
                if !lb.instances.contains(&id) {
                    return Err(errors::invalid_end_point(format!("The specified EndPoint is not valid: {id}")));
                }
            }
            lb.instances.retain(|x| !input.instances.iter().any(|i| i.instance_id.as_deref() == Some(x.as_str())));
            lb.description.instances =
                Some(lb.instances.iter().map(|i| ct::Instance { instance_id: Some(i.clone()) }).collect());
            Ok(lb.description.instances.clone())
        })?;
        for i in &input.instances {
            self.elb.inner.health.forget(&HealthKey::classic(
                &region_key,
                &input.load_balancer_name,
                i.instance_id.as_deref().unwrap_or_default(),
            ));
        }
        Ok(ct::DeregisterEndPointsOutput { instances: out })
    }

    async fn describe_instance_health(
        &self,
        ctx: &RequestContext,
        input: ct::DescribeEndPointStateInput,
    ) -> Result<ct::DescribeEndPointStateOutput, ServiceError> {
        names::authorize(ctx, "DescribeInstanceHealth", "*", Default::default())?;
        let account = account_of(ctx);
        let region_key = State::key(&account, &ctx.region);
        let registered = self.with_region(ctx, |r| {
            r.classic
                .get(&input.load_balancer_name)
                .map(|c| c.instances.clone())
                .ok_or_else(|| not_found(&input.load_balancer_name))
        })?;
        let wanted: Vec<String> = match &input.instances {
            Some(list) if !list.is_empty() => list.iter().filter_map(|i| i.instance_id.clone()).collect(),
            _ => registered.clone(),
        };
        let mut out = Vec::new();
        for id in wanted {
            if !registered.contains(&id) {
                return Err(errors::invalid_end_point(format!("The specified EndPoint is not valid: {id}")));
            }
            let (state, code, desc) =
                instance_health(&self.elb, &account, &ctx.region, &region_key, &input.load_balancer_name, &id);
            out.push(ct::InstanceState {
                instance_id: Some(id),
                state: Some(state.into()),
                reason_code: Some(code.into()),
                description: Some(desc),
            });
        }
        Ok(ct::DescribeEndPointStateOutput { instance_states: Some(out) })
    }

    async fn configure_health_check(
        &self,
        ctx: &RequestContext,
        input: ct::ConfigureHealthCheckInput,
    ) -> Result<ct::ConfigureHealthCheckOutput, ServiceError> {
        self.authorize(ctx, "ConfigureHealthCheck", &input.load_balancer_name)?;
        let hc = input.health_check.clone();
        if parse_target(&hc.target).is_none() {
            return Err(validation(format!("Invalid health check target: {}", hc.target)));
        }
        if hc.timeout >= hc.interval {
            return Err(validation("HealthCheck Timeout must be less than Interval"));
        }
        self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            lb.description.health_check = Some(hc.clone());
            Ok::<_, ServiceError>(())
        })?;
        let group = format!("classic:{}:{}", State::key(&account_of(ctx), &ctx.region), input.load_balancer_name);
        self.elb.inner.health.config_changed(&group);
        Ok(ct::ConfigureHealthCheckOutput { health_check: Some(hc) })
    }

    async fn describe_load_balancer_attributes(
        &self,
        ctx: &RequestContext,
        input: ct::DescribeLoadBalancerAttributesInput,
    ) -> Result<ct::DescribeLoadBalancerAttributesOutput, ServiceError> {
        names::authorize(ctx, "DescribeLoadBalancerAttributes", "*", Default::default())?;
        self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            Ok(ct::DescribeLoadBalancerAttributesOutput { load_balancer_attributes: Some(lb.attributes.clone()) })
        })
    }

    async fn modify_load_balancer_attributes(
        &self,
        ctx: &RequestContext,
        input: ct::ModifyLoadBalancerAttributesInput,
    ) -> Result<ct::ModifyLoadBalancerAttributesOutput, ServiceError> {
        self.authorize(ctx, "ModifyLoadBalancerAttributes", &input.load_balancer_name)?;
        let a = input.load_balancer_attributes.clone();
        if let Some(c) = &a.connection_settings {
            if !(1..=4000).contains(&c.idle_timeout) {
                return Err(validation("IdleTimeout must be between 1 and 4000 seconds"));
            }
        }
        if let Some(d) = &a.connection_draining {
            if d.timeout.is_some_and(|t| !(1..=3600).contains(&t)) {
                return Err(validation("ConnectionDraining timeout must be between 1 and 3600 seconds"));
            }
        }
        if let Some(l) = &a.access_log {
            if l.enabled && l.s3_bucket_name.as_deref().is_none_or(str::is_empty) {
                return Err(errors::invalid_configuration_request(
                    "The S3 bucket name must be specified when access logs are enabled",
                ));
            }
            if l.emit_interval.is_some_and(|i| i != 5 && i != 60) {
                return Err(validation("EmitInterval must be 5 or 60"));
            }
        }
        for extra in a.additional_attributes.iter().flatten() {
            if extra.key.as_deref() != Some("elb.http.desyncmitigationmode") {
                return Err(errors::load_balancer_attribute_not_found(format!(
                    "The specified load balancer attribute does not exist: {}",
                    extra.key.clone().unwrap_or_default()
                )));
            }
        }
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            let cur = &mut lb.attributes;
            if let Some(v) = a.cross_zone_load_balancing {
                cur.cross_zone_load_balancing = Some(v);
            }
            if let Some(mut v) = a.access_log {
                if v.enabled && v.emit_interval.is_none() {
                    v.emit_interval = Some(60);
                }
                let before = cur.access_log.clone().unwrap_or_default();
                let moved = !before.enabled
                    || before.s3_bucket_name != v.s3_bucket_name
                    || before.s3_bucket_prefix != v.s3_bucket_prefix;
                if v.enabled && moved {
                    let arn = lb_arn(&State::key(&account, &ctx.region), &input.load_balancer_name);
                    self.elb
                        .check_log_bucket(
                            &arn,
                            &account,
                            &ctx.region,
                            v.s3_bucket_name.as_deref().unwrap_or_default(),
                            v.s3_bucket_prefix.as_deref().unwrap_or_default(),
                        )
                        .map_err(errors::invalid_configuration_request)?;
                }
                cur.access_log = Some(v);
            }
            if let Some(mut v) = a.connection_draining {
                if v.timeout.is_none() {
                    v.timeout = Some(300);
                }
                cur.connection_draining = Some(v);
            }
            if let Some(v) = a.connection_settings {
                cur.connection_settings = Some(v);
            }
            if let Some(extra) = a.additional_attributes {
                cur.additional_attributes = Some(extra);
            }
            Ok(ct::ModifyLoadBalancerAttributesOutput {
                load_balancer_name: Some(input.load_balancer_name.clone()),
                load_balancer_attributes: Some(cur.clone()),
            })
        })
    }

    async fn create_app_cookie_stickiness_policy(
        &self,
        ctx: &RequestContext,
        input: ct::CreateAppCookieStickinessPolicyInput,
    ) -> Result<ct::CreateAppCookieStickinessPolicyOutput, ServiceError> {
        self.authorize(ctx, "CreateAppCookieStickinessPolicy", &input.load_balancer_name)?;
        self.add_policy(
            ctx,
            &input.load_balancer_name,
            &input.policy_name,
            "AppCookieStickinessPolicyType",
            vec![("CookieName".into(), input.cookie_name.clone())],
        )?;
        Ok(ct::CreateAppCookieStickinessPolicyOutput {})
    }

    async fn create_lb_cookie_stickiness_policy(
        &self,
        ctx: &RequestContext,
        input: ct::CreateLBCookieStickinessPolicyInput,
    ) -> Result<ct::CreateLBCookieStickinessPolicyOutput, ServiceError> {
        self.authorize(ctx, "CreateLBCookieStickinessPolicy", &input.load_balancer_name)?;
        let attrs = input
            .cookie_expiration_period
            .map(|p| vec![("CookieExpirationPeriod".to_string(), p.to_string())])
            .unwrap_or_default();
        self.add_policy(ctx, &input.load_balancer_name, &input.policy_name, "LBCookieStickinessPolicyType", attrs)?;
        Ok(ct::CreateLBCookieStickinessPolicyOutput {})
    }

    async fn create_load_balancer_policy(
        &self,
        ctx: &RequestContext,
        input: ct::CreateLoadBalancerPolicyInput,
    ) -> Result<ct::CreateLoadBalancerPolicyOutput, ServiceError> {
        self.authorize(ctx, "CreateLoadBalancerPolicy", &input.load_balancer_name)?;
        let Some((_, _, attr_types)) = POLICY_TYPES.iter().find(|p| p.0 == input.policy_type_name) else {
            return Err(errors::policy_type_not_found(format!(
                "One or more specified policy types do not exist: {}",
                input.policy_type_name
            )));
        };
        let mut attrs: Vec<(String, String)> = Vec::new();
        for a in input.policy_attributes.iter().flatten() {
            let name = a.attribute_name.clone().unwrap_or_default();
            let known = attr_types.iter().any(|(n, _, _, _)| *n == name)
                || (input.policy_type_name == "SSLNegotiationPolicyType"
                    && name.chars().next().is_some_and(|c| c.is_ascii_uppercase()));
            if !known {
                return Err(errors::invalid_configuration_request(format!(
                    "Policy attribute {name} is not valid for policy type {}",
                    input.policy_type_name
                )));
            }
            attrs.push((name, a.attribute_value.clone().unwrap_or_default()));
        }
        if input.policy_type_name == "SSLNegotiationPolicyType" {
            if let Some((_, reference)) = attrs.iter().find(|(n, _)| n == "Reference-Security-Policy") {
                let (_, protocols, _) = catalog::ssl_policy(reference).ok_or_else(|| {
                    errors::invalid_configuration_request(format!(
                        "Reference security policy {reference} does not exist"
                    ))
                })?;
                for p in ["TLSv1", "TLSv1.1", "TLSv1.2"] {
                    attrs.push((format!("Protocol-{p}"), protocols.contains(&p).to_string()));
                }
            }
        }
        self.add_policy(ctx, &input.load_balancer_name, &input.policy_name, &input.policy_type_name, attrs)?;
        Ok(ct::CreateLoadBalancerPolicyOutput {})
    }

    async fn delete_load_balancer_policy(
        &self,
        ctx: &RequestContext,
        input: ct::DeleteLoadBalancerPolicyInput,
    ) -> Result<ct::DeleteLoadBalancerPolicyOutput, ServiceError> {
        self.authorize(ctx, "DeleteLoadBalancerPolicy", &input.load_balancer_name)?;
        self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            let used = lb
                .description
                .listener_descriptions
                .iter()
                .flatten()
                .any(|d| d.policy_names.iter().flatten().any(|p| *p == input.policy_name))
                || lb
                    .description
                    .backend_server_descriptions
                    .iter()
                    .flatten()
                    .any(|d| d.policy_names.iter().flatten().any(|p| *p == input.policy_name));
            if used {
                return Err(errors::invalid_configuration_request(format!(
                    "Policy {} is in use and cannot be deleted",
                    input.policy_name
                )));
            }
            lb.policies.retain(|p| p.policy_name.as_deref() != Some(input.policy_name.as_str()));
            sync_policies(lb);
            Ok(ct::DeleteLoadBalancerPolicyOutput {})
        })
    }

    async fn describe_load_balancer_policies(
        &self,
        ctx: &RequestContext,
        input: ct::DescribeLoadBalancerPoliciesInput,
    ) -> Result<ct::DescribeLoadBalancerPoliciesOutput, ServiceError> {
        names::authorize(ctx, "DescribeLoadBalancerPolicies", "*", Default::default())?;
        let wanted = input.policy_names.unwrap_or_default();
        let pool = match &input.load_balancer_name {
            Some(name) => {
                let mut v = self.with_region(ctx, |r| {
                    r.classic.get(name).map(|c| c.policies.clone()).ok_or_else(|| not_found(name))
                })?;
                if !wanted.is_empty() {
                    v.extend(sample_policies());
                }
                v
            }
            None => sample_policies(),
        };
        if wanted.is_empty() {
            return Ok(ct::DescribeLoadBalancerPoliciesOutput { policy_descriptions: Some(pool) });
        }
        let mut out = Vec::new();
        for w in &wanted {
            let p = pool.iter().find(|p| p.policy_name.as_deref() == Some(w.as_str())).ok_or_else(|| {
                errors::policy_not_found(format!(
                    "There is no policy with name {w} for load balancer {}",
                    input.load_balancer_name.clone().unwrap_or_default()
                ))
            })?;
            out.push(p.clone());
        }
        Ok(ct::DescribeLoadBalancerPoliciesOutput { policy_descriptions: Some(out) })
    }

    async fn describe_load_balancer_policy_types(
        &self,
        ctx: &RequestContext,
        input: ct::DescribeLoadBalancerPolicyTypesInput,
    ) -> Result<ct::DescribeLoadBalancerPolicyTypesOutput, ServiceError> {
        names::authorize(ctx, "DescribeLoadBalancerPolicyTypes", "*", Default::default())?;
        let wanted = input.policy_type_names.unwrap_or_default();
        for w in &wanted {
            if !POLICY_TYPES.iter().any(|p| p.0 == w) {
                return Err(errors::policy_type_not_found(format!(
                    "One or more specified policy types do not exist: {w}"
                )));
            }
        }
        let out = POLICY_TYPES
            .iter()
            .filter(|p| wanted.is_empty() || wanted.iter().any(|w| w == p.0))
            .map(|(name, desc, attrs)| ct::PolicyTypeDescription {
                policy_type_name: Some(name.to_string()),
                description: Some(desc.to_string()),
                policy_attribute_type_descriptions: Some(
                    attrs
                        .iter()
                        .map(|(n, ty, card, def)| ct::PolicyAttributeTypeDescription {
                            attribute_name: Some(n.to_string()),
                            attribute_type: Some(ty.to_string()),
                            description: None,
                            default_value: (!def.is_empty()).then(|| def.to_string()),
                            cardinality: Some(card.to_string()),
                        })
                        .collect(),
                ),
            })
            .collect();
        Ok(ct::DescribeLoadBalancerPolicyTypesOutput { policy_type_descriptions: Some(out) })
    }

    async fn set_load_balancer_policies_of_listener(
        &self,
        ctx: &RequestContext,
        input: ct::SetLoadBalancerPoliciesOfListenerInput,
    ) -> Result<ct::SetLoadBalancerPoliciesOfListenerOutput, ServiceError> {
        self.authorize(ctx, "SetLoadBalancerPoliciesOfListener", &input.load_balancer_name)?;
        self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            for p in &input.policy_names {
                let policy =
                    lb.policies.iter().find(|x| x.policy_name.as_deref() == Some(p.as_str())).cloned().or_else(|| {
                        sample_policies().into_iter().find(|x| x.policy_name.as_deref() == Some(p.as_str()))
                    });
                if policy.is_none() {
                    return Err(errors::policy_not_found(format!(
                        "There is no policy with name {p} for load balancer {}",
                        input.load_balancer_name
                    )));
                }
            }
            let d = lb
                .description
                .listener_descriptions
                .iter_mut()
                .flatten()
                .find(|d| d.listener.as_ref().is_some_and(|l| l.load_balancer_port == input.load_balancer_port))
                .ok_or_else(|| {
                    errors::listener_not_found(format!("There is no listener on port {}", input.load_balancer_port))
                })?;
            d.policy_names = Some(input.policy_names.clone());
            Ok(ct::SetLoadBalancerPoliciesOfListenerOutput {})
        })
    }

    async fn set_load_balancer_policies_for_backend_server(
        &self,
        ctx: &RequestContext,
        input: ct::SetLoadBalancerPoliciesForBackendServerInput,
    ) -> Result<ct::SetLoadBalancerPoliciesForBackendServerOutput, ServiceError> {
        self.authorize(ctx, "SetLoadBalancerPoliciesForBackendServer", &input.load_balancer_name)?;
        self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            for p in &input.policy_names {
                if !lb.policies.iter().any(|x| x.policy_name.as_deref() == Some(p.as_str())) {
                    return Err(errors::policy_not_found(format!(
                        "There is no policy with name {p} for load balancer {}",
                        input.load_balancer_name
                    )));
                }
            }
            let backends = lb.description.backend_server_descriptions.get_or_insert_with(Vec::new);
            backends.retain(|b| b.instance_port != Some(input.instance_port));
            if !input.policy_names.is_empty() {
                backends.push(ct::BackendServerDescription {
                    instance_port: Some(input.instance_port),
                    policy_names: Some(input.policy_names.clone()),
                });
            }
            Ok(ct::SetLoadBalancerPoliciesForBackendServerOutput {})
        })
    }

    async fn apply_security_groups_to_load_balancer(
        &self,
        ctx: &RequestContext,
        input: ct::ApplySecurityGroupsToLoadBalancerInput,
    ) -> Result<ct::ApplySecurityGroupsToLoadBalancerOutput, ServiceError> {
        self.authorize(ctx, "ApplySecurityGroupsToLoadBalancer", &input.load_balancer_name)?;
        let account = account_of(ctx);
        let vpc = self.with_region(ctx, |r| {
            r.classic
                .get(&input.load_balancer_name)
                .map(|c| c.description.vpc_id.clone())
                .ok_or_else(|| not_found(&input.load_balancer_name))
        })?;
        if let (Some(ec2), Some(vpc)) = (self.elb.ec2(), &vpc) {
            for g in &input.security_groups {
                if ec2.security_group_info(ctx, &account, g).is_none_or(|i| &i.vpc_id != vpc) {
                    return Err(errors::invalid_security_group(format!(
                        "One or more security groups are invalid: {g}"
                    )));
                }
            }
        }
        self.with_region(ctx, |r| {
            let lb = find(r, &input.load_balancer_name)?;
            lb.description.security_groups = Some(input.security_groups.clone());
            Ok::<_, ServiceError>(())
        })?;
        self.sync_interfaces(ctx, &input.load_balancer_name)?;
        Ok(ct::ApplySecurityGroupsToLoadBalancerOutput { security_groups: Some(input.security_groups.clone()) })
    }

    async fn attach_load_balancer_to_subnets(
        &self,
        ctx: &RequestContext,
        input: ct::AttachLoadBalancerToSubnetsInput,
    ) -> Result<ct::AttachLoadBalancerToSubnetsOutput, ServiceError> {
        self.authorize(ctx, "AttachLoadBalancerToSubnets", &input.load_balancer_name)?;
        let (vpc, current) = self.with_region(ctx, |r| {
            r.classic
                .get(&input.load_balancer_name)
                .map(|c| (c.description.vpc_id.clone(), c.description.subnets.clone().unwrap_or_default()))
                .ok_or_else(|| not_found(&input.load_balancer_name))
        })?;
        let mut all = current.clone();
        for s in &input.subnets {
            if !all.contains(s) {
                all.push(s.clone());
            }
        }
        let resolved = self.resolve_subnets(ctx, &all, vpc.as_deref())?;
        self.set_subnets(ctx, &input.load_balancer_name, &resolved, &all)
            .map(|subnets| ct::AttachLoadBalancerToSubnetsOutput { subnets: Some(subnets) })
    }

    async fn detach_load_balancer_from_subnets(
        &self,
        ctx: &RequestContext,
        input: ct::DetachLoadBalancerFromSubnetsInput,
    ) -> Result<ct::DetachLoadBalancerFromSubnetsOutput, ServiceError> {
        self.authorize(ctx, "DetachLoadBalancerFromSubnets", &input.load_balancer_name)?;
        let (vpc, current) = self.with_region(ctx, |r| {
            r.classic
                .get(&input.load_balancer_name)
                .map(|c| (c.description.vpc_id.clone(), c.description.subnets.clone().unwrap_or_default()))
                .ok_or_else(|| not_found(&input.load_balancer_name))
        })?;
        let remaining: Vec<String> = current.into_iter().filter(|s| !input.subnets.contains(s)).collect();
        if remaining.is_empty() {
            return Err(validation("A load balancer must be attached to at least one subnet"));
        }
        let resolved = self.resolve_subnets(ctx, &remaining, vpc.as_deref())?;
        self.set_subnets(ctx, &input.load_balancer_name, &resolved, &remaining)
            .map(|subnets| ct::DetachLoadBalancerFromSubnetsOutput { subnets: Some(subnets) })
    }

    async fn enable_availability_zones_for_load_balancer(
        &self,
        ctx: &RequestContext,
        input: ct::AddAvailabilityZonesInput,
    ) -> Result<ct::AddAvailabilityZonesOutput, ServiceError> {
        self.authorize(ctx, "EnableAvailabilityZonesForLoadBalancer", &input.load_balancer_name)?;
        let (vpc, zones) = self.with_region(ctx, |r| {
            r.classic
                .get(&input.load_balancer_name)
                .map(|c| (c.description.vpc_id.clone(), c.description.availability_zones.clone().unwrap_or_default()))
                .ok_or_else(|| not_found(&input.load_balancer_name))
        })?;
        let mut all = zones;
        for z in &input.availability_zones {
            if !all.contains(z) {
                all.push(z.clone());
            }
        }
        let resolved = self.subnets_for_zones(ctx, vpc.as_deref(), &all)?;
        let ids: Vec<String> = resolved.iter().map(|s| s.subnet_id.clone()).collect();
        self.set_subnets(ctx, &input.load_balancer_name, &resolved, &ids)?;
        Ok(ct::AddAvailabilityZonesOutput { availability_zones: Some(all) })
    }

    async fn disable_availability_zones_for_load_balancer(
        &self,
        ctx: &RequestContext,
        input: ct::RemoveAvailabilityZonesInput,
    ) -> Result<ct::RemoveAvailabilityZonesOutput, ServiceError> {
        self.authorize(ctx, "DisableAvailabilityZonesForLoadBalancer", &input.load_balancer_name)?;
        let (vpc, zones) = self.with_region(ctx, |r| {
            r.classic
                .get(&input.load_balancer_name)
                .map(|c| (c.description.vpc_id.clone(), c.description.availability_zones.clone().unwrap_or_default()))
                .ok_or_else(|| not_found(&input.load_balancer_name))
        })?;
        let remaining: Vec<String> = zones.into_iter().filter(|z| !input.availability_zones.contains(z)).collect();
        if remaining.is_empty() {
            return Err(validation("A load balancer must be enabled in at least one Availability Zone"));
        }
        let resolved = self.subnets_for_zones(ctx, vpc.as_deref(), &remaining)?;
        let ids: Vec<String> = resolved.iter().map(|s| s.subnet_id.clone()).collect();
        self.set_subnets(ctx, &input.load_balancer_name, &resolved, &ids)?;
        Ok(ct::RemoveAvailabilityZonesOutput { availability_zones: Some(remaining) })
    }

    async fn add_tags(&self, ctx: &RequestContext, input: ct::AddTagsInput) -> Result<ct::AddTagsOutput, ServiceError> {
        let mut keys = BTreeSet::new();
        for t in &input.tags {
            if !keys.insert(t.key.clone()) {
                return Err(errors::duplicate_tag_keys(format!("Duplicate tag key: {}", t.key)));
            }
        }
        for name in &input.load_balancer_names {
            self.authorize(ctx, "AddTags", name)?;
        }
        self.with_region(ctx, |r| {
            for name in &input.load_balancer_names {
                find(r, name)?;
            }
            for name in &input.load_balancer_names {
                let lb = find(r, name)?;
                for t in &input.tags {
                    match lb.tags.iter_mut().find(|x| x.key == t.key) {
                        Some(x) => x.value = t.value.clone(),
                        None => lb.tags.push(t.clone()),
                    }
                }
                if lb.tags.len() > 50 {
                    return Err(errors::too_many_tags("Exceeded the limit of 50 tags"));
                }
            }
            Ok(ct::AddTagsOutput {})
        })
    }

    async fn remove_tags(
        &self,
        ctx: &RequestContext,
        input: ct::RemoveTagsInput,
    ) -> Result<ct::RemoveTagsOutput, ServiceError> {
        for name in &input.load_balancer_names {
            self.authorize(ctx, "RemoveTags", name)?;
        }
        self.with_region(ctx, |r| {
            for name in &input.load_balancer_names {
                let lb = find(r, name)?;
                lb.tags.retain(|t| !input.tags.iter().any(|k| k.key.as_deref() == Some(t.key.as_str())));
            }
            Ok(ct::RemoveTagsOutput {})
        })
    }

    async fn describe_tags(
        &self,
        ctx: &RequestContext,
        input: ct::DescribeTagsInput,
    ) -> Result<ct::DescribeTagsOutput, ServiceError> {
        names::authorize(ctx, "DescribeTags", "*", Default::default())?;
        if input.load_balancer_names.len() > 20 {
            return Err(validation("You can describe the tags of at most 20 load balancers at a time"));
        }
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for name in &input.load_balancer_names {
                let lb = r.classic.get(name).ok_or_else(|| not_found(name))?;
                out.push(ct::TagDescription { load_balancer_name: Some(name.clone()), tags: Some(lb.tags.clone()) });
            }
            Ok(ct::DescribeTagsOutput { tag_descriptions: Some(out) })
        })
    }

    async fn describe_account_limits(
        &self,
        ctx: &RequestContext,
        input: ct::DescribeAccountLimitsInput,
    ) -> Result<ct::DescribeAccountLimitsOutput, ServiceError> {
        names::authorize(ctx, "DescribeAccountLimits", "*", Default::default())?;
        let all: Vec<ct::Limit> = catalog::CLASSIC_LIMITS
            .iter()
            .map(|(n, m)| {
                let max = match catalog::quota_code(n) {
                    Some(_) => self.elb.limit(ctx, n).to_string(),
                    None => m.to_string(),
                };
                ct::Limit { name: Some(n.to_string()), max: Some(max) }
            })
            .collect();
        let (items, next) = names::page(&all, input.marker.as_deref(), input.page_size, 400)?;
        Ok(ct::DescribeAccountLimitsOutput { limits: Some(items), next_marker: next })
    }
}

impl ClassicElb {
    fn add_policy(
        &self,
        ctx: &RequestContext,
        lb: &str,
        policy: &str,
        ty: &str,
        attrs: Vec<(String, String)>,
    ) -> Result<(), ServiceError> {
        self.with_region(ctx, |r| {
            let lb_rec = find(r, lb)?;
            if lb_rec.policies.iter().any(|p| p.policy_name.as_deref() == Some(policy)) {
                return Err(errors::duplicate_policy_name(format!(
                    "Policy name {policy} already exists for load balancer {lb}"
                )));
            }
            if lb_rec.policies.len() >= 100 {
                return Err(errors::too_many_policies("Exceeded the limit of policies for this load balancer"));
            }
            lb_rec.policies.push(ct::PolicyDescription {
                policy_name: Some(policy.to_string()),
                policy_type_name: Some(ty.to_string()),
                policy_attribute_descriptions: Some(
                    attrs
                        .into_iter()
                        .map(|(n, v)| ct::PolicyAttributeDescription {
                            attribute_name: Some(n),
                            attribute_value: Some(v),
                        })
                        .collect(),
                ),
            });
            sync_policies(lb_rec);
            Ok(())
        })
    }

    fn set_subnets(
        &self,
        ctx: &RequestContext,
        name: &str,
        resolved: &[mws_ec2::SubnetInfo],
        ids: &[String],
    ) -> Result<Vec<String>, ServiceError> {
        self.with_region(ctx, |r| {
            let lb = find(r, name)?;
            lb.description.subnets = Some(ids.to_vec());
            if !resolved.is_empty() {
                lb.description.availability_zones =
                    Some(resolved.iter().map(|s| s.availability_zone.clone()).collect());
            }
            Ok::<_, ServiceError>(())
        })?;
        self.sync_interfaces(ctx, name)?;
        Ok(ids.to_vec())
    }

    /// Give the load balancer a requester-managed (`amazon-elb`) network
    /// interface described `ELB <name>` in each of its subnets, with its
    /// security groups and a public address when internet-facing, as AWS
    /// does for a load balancer in a VPC; drop those of subnets it left.
    fn sync_interfaces(&self, ctx: &RequestContext, name: &str) -> Result<(), ServiceError> {
        let Some(ec2) = self.elb.ec2() else { return Ok(()) };
        let account = account_of(ctx);
        let (subnets, groups, internet_facing, current) = self.with_region(ctx, |r| {
            let lb = find(r, name)?;
            Ok::<_, ServiceError>((
                lb.description.subnets.clone().unwrap_or_default(),
                lb.description.security_groups.clone().unwrap_or_default(),
                lb.description.scheme.as_deref() == Some("internet-facing"),
                lb.network_interfaces.clone(),
            ))
        })?;
        let description = format!("ELB {name}");
        let mut kept = BTreeMap::new();
        let mut made = Vec::new();
        for subnet in &subnets {
            if let Some(eni) = current.get(subnet) {
                ec2.set_task_interface_groups(ctx, &account, eni, &groups)?;
                kept.insert(subnet.clone(), eni.clone());
                continue;
            }
            match ec2.create_task_interface(ctx, &account, subnet, &groups, internet_facing, &description, "amazon-elb")
            {
                Ok(eni) => {
                    made.push(eni.eni_id.clone());
                    kept.insert(subnet.clone(), eni.eni_id);
                }
                Err(e) => {
                    for id in made {
                        ec2.delete_task_interface(ctx, &account, &id);
                    }
                    return Err(e);
                }
            }
        }
        let dropped: BTreeMap<String, String> = current.into_iter().filter(|(s, _)| !kept.contains_key(s)).collect();
        self.delete_interfaces(ctx, dropped);
        self.with_region(ctx, |r| {
            if let Some(lb) = r.classic.get_mut(name) {
                lb.network_interfaces = kept;
            }
        });
        Ok(())
    }

    fn delete_interfaces(&self, ctx: &RequestContext, enis: BTreeMap<String, String>) {
        let Some(ec2) = self.elb.ec2() else { return };
        let account = account_of(ctx);
        for id in enis.values() {
            ec2.delete_task_interface(ctx, &account, id);
        }
    }
}

/// Keep the description's `Policies` summary in step with the policies.
fn sync_policies(lb: &mut ClassicLoadBalancer) {
    let attr = |p: &ct::PolicyDescription, name: &str| {
        p.policy_attribute_descriptions
            .iter()
            .flatten()
            .find(|a| a.attribute_name.as_deref() == Some(name))
            .and_then(|a| a.attribute_value.clone())
    };
    let mut app = Vec::new();
    let mut lbc = Vec::new();
    let mut other = Vec::new();
    for p in &lb.policies {
        match p.policy_type_name.as_deref() {
            Some("AppCookieStickinessPolicyType") => app.push(ct::AppCookieStickinessPolicy {
                policy_name: p.policy_name.clone(),
                cookie_name: attr(p, "CookieName"),
            }),
            Some("LBCookieStickinessPolicyType") => lbc.push(ct::LBCookieStickinessPolicy {
                policy_name: p.policy_name.clone(),
                cookie_expiration_period: attr(p, "CookieExpirationPeriod").and_then(|v| v.parse().ok()),
            }),
            _ => other.extend(p.policy_name.clone()),
        }
    }
    lb.description.policies = Some(ct::Policies {
        app_cookie_stickiness_policies: Some(app),
        lb_cookie_stickiness_policies: Some(lbc),
        other_policies: Some(other),
    });
}

fn describe(c: &ClassicLoadBalancer) -> ct::LoadBalancerDescription {
    c.description.clone()
}

/// `(state, reason code, description)` as `DescribeInstanceHealth` shows.
pub(crate) fn instance_health(
    elb: &Elb,
    account: &str,
    region: &str,
    region_key: &str,
    lb: &str,
    id: &str,
) -> (&'static str, &'static str, String) {
    if let Some((state, _, _)) = crate::health::instance_state(elb, account, region, id) {
        if state != "running" {
            return ("OutOfService", "Instance", format!("Instance is in {state} state."));
        }
        // Nothing runs the instance, so probes could only fail.
        if crate::health::runs_nothing(elb, account, region, id) {
            return ("InService", "N/A", "N/A".into());
        }
    }
    match elb.inner.health.get(&HealthKey::classic(region_key, lb, id)) {
        Some(run) if run.healthy == Some(true) => ("InService", "N/A", "N/A".into()),
        Some(run) if run.healthy == Some(false) => (
            "OutOfService",
            "Instance",
            "Instance has failed at least the UnhealthyThreshold number of health checks consecutively.".into(),
        ),
        _ => ("OutOfService", "ELB", "Instance registration is still in progress.".into()),
    }
}

/// Health check probes for every Classic Load Balancer instance.
pub(crate) fn probes(elb: &Elb, st: &State) -> Vec<Probe> {
    let mut out = Vec::new();
    for (region_key, r) in &st.regions {
        let (account, region) = region_key.split_once('|').unwrap_or_default();
        for c in r.classic.values() {
            let Some(hc) = &c.description.health_check else { continue };
            let Some((proto, port, path)) = parse_target(&hc.target) else { continue };
            let kind = match proto.as_str() {
                "HTTP" => ProbeKind::Http { tls: false, path: path.unwrap_or_else(|| "/".into()), codes: "200".into() },
                "HTTPS" => ProbeKind::Http { tls: true, path: path.unwrap_or_else(|| "/".into()), codes: "200".into() },
                _ => ProbeKind::Tcp,
            };
            for id in &c.instances {
                if crate::health::runs_nothing(elb, account, region, id) {
                    continue;
                }
                let address = match crate::health::instance_state(elb, account, region, id) {
                    Some((s, Some(ip), _)) if s == "running" => ip.parse().ok().map(|ip| SocketAddr::new(ip, port)),
                    _ => continue,
                };
                out.push(Probe {
                    key: HealthKey::classic(region_key, c.name(), id),
                    account: account.into(),
                    region: region.into(),
                    kind: kind.clone(),
                    address,
                    timeout: Duration::from_secs(hc.timeout.max(1) as u64),
                    interval: Duration::from_secs(hc.interval.max(1) as u64),
                    healthy_threshold: hc.healthy_threshold.max(1) as u32,
                    unhealthy_threshold: hc.unhealthy_threshold.max(1) as u32,
                });
            }
        }
    }
    out
}

pub(crate) fn host_count_batches(elb: &Elb, account: &str, region: &str, r: &RegionState) -> Vec<Batch> {
    let region_key = State::key(account, region);
    r.classic
        .values()
        .map(|c| {
            let (mut healthy, mut unhealthy) = (0.0, 0.0);
            for id in &c.instances {
                if instance_health(elb, account, region, &region_key, c.name(), id).0 == "InService" {
                    healthy += 1.0;
                } else {
                    unhealthy += 1.0;
                }
            }
            let mut b = Batch::new(account, region, "AWS/ELB");
            let d = vec![dims(&[("LoadBalancerName", c.name())])];
            b.add("HealthyHostCount", "Count", healthy, &d);
            b.add("UnHealthyHostCount", "Count", unhealthy, &d);
            b
        })
        .collect()
}

/// In-service instances of a Classic Load Balancer with their addresses on
/// `instance_port`.
fn in_service(elb: &Elb, spec: &FrontSpec, c: &ClassicLoadBalancer, instance_port: i32) -> Vec<(String, SocketAddr)> {
    c.instances
        .iter()
        .filter(|id| {
            instance_health(elb, spec.account(), spec.region(), &spec.region_key, c.name(), id).0 == "InService"
        })
        .filter_map(|id| {
            let (_, ip, _) = crate::health::instance_state(elb, spec.account(), spec.region(), id)?;
            Some((id.clone(), SocketAddr::new(ip?.parse().ok()?, instance_port as u16)))
        })
        .collect()
}

fn listener_of(c: &ClassicLoadBalancer, port: i32) -> Option<ct::ListenerDescription> {
    c.description
        .listener_descriptions
        .iter()
        .flatten()
        .find(|d| d.listener.as_ref().is_some_and(|l| l.load_balancer_port == port))
        .cloned()
}

/// Route a Classic HTTP/HTTPS request.
pub(crate) fn decide(
    elb: &Elb,
    spec: &FrontSpec,
    parts: &http::request::Parts,
    _secure: bool,
) -> (crate::data::l7::Decision, String, String) {
    use crate::data::l7::{elb_error, Decision, Forward, Upstream};
    let host = parts.headers.get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let pq = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let st = elb.lock();
    let Some(c) = st.regions.get(&spec.region_key).and_then(|r| spec.classic.as_ref().and_then(|n| r.classic.get(n)))
    else {
        return (elb_error(503), host, pq);
    };
    let Some(ld) = listener_of(c, spec.port) else { return (elb_error(503), host, pq) };
    let listener = ld.listener.clone().unwrap_or_default();
    let targets = in_service(elb, spec, c, listener.instance_port);
    if targets.is_empty() {
        return (elb_error(503), host, pq);
    }
    let policies: Vec<&ct::PolicyDescription> = ld
        .policy_names
        .iter()
        .flatten()
        .filter_map(|n| c.policies.iter().find(|p| p.policy_name.as_deref() == Some(n.as_str())))
        .collect();
    let sticky_lb = policies.iter().find(|p| p.policy_type_name.as_deref() == Some("LBCookieStickinessPolicyType"));
    let mut set_cookie = None;
    let mut chosen = None;
    if sticky_lb.is_some() {
        if let Some(v) = parts
            .headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .find_map(|c| c.trim().strip_prefix("AWSELB=").map(str::to_string))
        {
            chosen = targets.iter().find(|(id, _)| hex::encode(id) == v).cloned();
        }
    }
    let target = chosen.unwrap_or_else(|| {
        let mut counters = elb.inner.data.counters.lock().expect("lock");
        let n = counters.entry(spec.key.clone()).or_insert(0);
        let t = targets[*n % targets.len()].clone();
        *n = n.wrapping_add(1);
        t
    });
    if let Some(p) = sticky_lb {
        let period = p
            .policy_attribute_descriptions
            .iter()
            .flatten()
            .find(|a| a.attribute_name.as_deref() == Some("CookieExpirationPeriod"))
            .and_then(|a| a.attribute_value.as_deref().and_then(|v| v.parse::<i64>().ok()));
        let mut cookie = format!("AWSELB={}; PATH=/", hex::encode(&target.0));
        if let Some(p) = period {
            cookie.push_str(&format!("; MAX-AGE={p}"));
        }
        set_cookie = Some(cookie);
    }
    let timeout = c.attributes.connection_settings.as_ref().map(|s| s.idle_timeout).unwrap_or(60) as u64;
    let tls = listener.instance_protocol.as_deref() == Some("HTTPS");
    let forward = Forward {
        tg_arn: None,
        target: (target.0, listener.instance_port),
        upstream: Upstream::Http { addr: target.1, tls, h2: false },
        set_cookies: set_cookie.into_iter().collect(),
        timeout: Duration::from_secs(timeout),
        preserve_host_port: true,
        tls_headers: false,
        xff_mode: "append".into(),
        xff_port: false,
    };
    (Decision::Forward(Box::new(forward)), host, pq)
}

/// Route a Classic TCP/SSL connection.
pub(crate) fn decide_l4(elb: &Elb, spec: &FrontSpec, name: &str) -> Option<crate::data::l4::L4Target> {
    let st = elb.lock();
    let c = st.regions.get(&spec.region_key)?.classic.get(name)?;
    let ld = listener_of(c, spec.port)?;
    let listener = ld.listener.clone()?;
    let targets = in_service(elb, spec, c, listener.instance_port);
    if targets.is_empty() {
        return None;
    }
    let mut counters = elb.inner.data.counters.lock().expect("lock");
    let n = counters.entry(spec.key.clone()).or_insert(0);
    let t = targets[*n % targets.len()].clone();
    *n = n.wrapping_add(1);
    let proxy_protocol = c
        .description
        .backend_server_descriptions
        .iter()
        .flatten()
        .filter(|b| b.instance_port == Some(listener.instance_port))
        .flat_map(|b| b.policy_names.iter().flatten())
        .filter_map(|n| c.policies.iter().find(|p| p.policy_name.as_deref() == Some(n.as_str())))
        .any(|p| p.policy_type_name.as_deref() == Some("ProxyProtocolPolicyType"));
    Some(crate::data::l4::L4Target {
        addr: t.1,
        tls: listener.instance_protocol.as_deref() == Some("SSL"),
        proxy_protocol,
        tg_arn: None,
    })
}

pub(crate) fn tls_settings(r: &RegionState, name: &str, port: i32) -> TlsSettings {
    let Some(c) = r.classic.get(name) else { return TlsSettings::default() };
    let Some(ld) = listener_of(c, port) else { return TlsSettings::default() };
    let cert = ld.listener.as_ref().and_then(|l| l.ssl_certificate_id.clone());
    let policy = ld
        .policy_names
        .iter()
        .flatten()
        .filter_map(|n| {
            c.policies
                .iter()
                .find(|p| p.policy_name.as_deref() == Some(n.as_str()))
                .cloned()
                .or_else(|| sample_policies().into_iter().find(|p| p.policy_name.as_deref() == Some(n.as_str())))
        })
        .find(|p| p.policy_type_name.as_deref() == Some("SSLNegotiationPolicyType"))
        .and_then(|p| {
            p.policy_attribute_descriptions
                .iter()
                .flatten()
                .find(|a| a.attribute_name.as_deref() == Some("Reference-Security-Policy"))
                .and_then(|a| a.attribute_value.clone())
                .or(p.policy_name.clone())
        });
    TlsSettings { certificates: cert.into_iter().collect(), policy, alpn: vec![b"http/1.1".to_vec()], mutual: None }
}
