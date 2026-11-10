//! Helpers every EC2 operation uses: ids, errors in EC2's wording, filters,
//! pagination, tags, CIDR arithmetic and authorization.

use std::net::Ipv4Addr;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::types as t;

// ---- ids ---------------------------------------------------------------------

/// A new resource id: `{prefix}-` and 17 hex digits, as EC2 issues them.
pub fn new_id(prefix: &str) -> String {
    let mut rng = rand::thread_rng();
    let hex: String = (0..17).map(|_| format!("{:x}", rng.gen_range(0..16u8))).collect();
    format!("{prefix}-{hex}")
}

pub fn arn(ctx: &RequestContext, account: &str, resource: &str) -> String {
    format!("arn:{}:ec2:{}:{account}:{resource}", ctx.partition, ctx.region)
}

// ---- errors ------------------------------------------------------------------

pub fn err(code: &str, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code.to_string(), 400, message)
}

pub fn invalid_parameter(message: impl Into<String>) -> ServiceError {
    err("InvalidParameterValue", message)
}

pub fn missing_parameter(name: &str) -> ServiceError {
    err("MissingParameter", format!("The request must contain the parameter {name}"))
}

/// The id kinds EC2 checks, with their error code stems and nouns.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Vpc,
    Subnet,
    Group,
    RouteTable,
    InternetGateway,
    NatGateway,
    Allocation,
    NetworkInterface,
    NetworkAcl,
    DhcpOptions,
    Image,
    Instance,
    Volume,
    Snapshot,
    KeyPairId,
    SecurityGroupRule,
    VpcEndpoint,
    PrefixList,
    EgressOnlyInternetGateway,
    CarrierGateway,
    CustomerGateway,
    VpnGateway,
    VpnConnection,
    VpcPeeringConnection,
    TransitGateway,
    TransitGatewayAttachment,
    TransitGatewayRouteTable,
    FlowLog,
    SubnetCidrReservation,
    Host,
    SpotInstanceRequest,
}

impl Kind {
    pub fn prefix(self) -> &'static str {
        match self {
            Kind::Vpc => "vpc",
            Kind::Subnet => "subnet",
            Kind::Group => "sg",
            Kind::RouteTable => "rtb",
            Kind::InternetGateway => "igw",
            Kind::NatGateway => "nat",
            Kind::Allocation => "eipalloc",
            Kind::NetworkInterface => "eni",
            Kind::NetworkAcl => "acl",
            Kind::DhcpOptions => "dopt",
            Kind::Image => "ami",
            Kind::Instance => "i",
            Kind::Volume => "vol",
            Kind::Snapshot => "snap",
            Kind::KeyPairId => "key",
            Kind::SecurityGroupRule => "sgr",
            Kind::VpcEndpoint => "vpce",
            Kind::PrefixList => "pl",
            Kind::EgressOnlyInternetGateway => "eigw",
            Kind::CarrierGateway => "cagw",
            Kind::CustomerGateway => "cgw",
            Kind::VpnGateway => "vgw",
            Kind::VpnConnection => "vpn",
            Kind::VpcPeeringConnection => "pcx",
            Kind::TransitGateway => "tgw",
            Kind::TransitGatewayAttachment => "tgw-attach",
            Kind::TransitGatewayRouteTable => "tgw-rtb",
            Kind::FlowLog => "fl",
            Kind::SubnetCidrReservation => "scr",
            Kind::Host => "h",
            Kind::SpotInstanceRequest => "sir",
        }
    }

    fn malformed_code(self) -> &'static str {
        match self {
            Kind::Vpc => "InvalidVpcID.Malformed",
            Kind::Subnet => "InvalidSubnetID.Malformed",
            Kind::Group => "InvalidGroupId.Malformed",
            Kind::RouteTable => "InvalidRouteTableId.Malformed",
            Kind::InternetGateway => "InvalidInternetGatewayId.Malformed",
            Kind::NatGateway => "InvalidNatGatewayID.Malformed",
            Kind::Allocation => "InvalidAllocationID.Malformed",
            Kind::NetworkInterface => "InvalidNetworkInterfaceId.Malformed",
            Kind::NetworkAcl => "InvalidNetworkAclId.Malformed",
            Kind::DhcpOptions => "InvalidDhcpOptionsId.Malformed",
            Kind::Image => "InvalidAMIID.Malformed",
            Kind::Instance => "InvalidInstanceID.Malformed",
            Kind::Volume => "InvalidVolumeID.Malformed",
            Kind::Snapshot => "InvalidSnapshotID.Malformed",
            Kind::KeyPairId => "InvalidKeyPairId.Malformed",
            Kind::SecurityGroupRule => "InvalidSecurityGroupRuleId.Malformed",
            Kind::VpcEndpoint => "InvalidVpcEndpointId.Malformed",
            Kind::PrefixList => "InvalidPrefixListId.Malformed",
            Kind::EgressOnlyInternetGateway => "InvalidEgressOnlyInternetGatewayId.Malformed",
            Kind::CarrierGateway => "InvalidCarrierGatewayID.Malformed",
            Kind::CustomerGateway => "InvalidCustomerGatewayId.Malformed",
            Kind::VpnGateway => "InvalidVpnGatewayID.Malformed",
            Kind::VpnConnection => "InvalidVpnConnectionID.Malformed",
            Kind::VpcPeeringConnection => "InvalidVpcPeeringConnectionId.Malformed",
            Kind::TransitGateway => "InvalidTransitGatewayID.Malformed",
            Kind::TransitGatewayAttachment => "InvalidTransitGatewayAttachmentID.Malformed",
            Kind::TransitGatewayRouteTable => "InvalidRouteTableID.Malformed",
            Kind::FlowLog => "InvalidFlowLogId.Malformed",
            Kind::SubnetCidrReservation => "InvalidSubnetCidrReservationID.Malformed",
            Kind::Host => "InvalidHostID.Malformed",
            Kind::SpotInstanceRequest => "InvalidSpotInstanceRequestID.Malformed",
        }
    }

    /// The `.NotFound` error for `id`.
    pub fn not_found(self, id: &str) -> ServiceError {
        let (code, msg) = match self {
            Kind::Vpc => ("InvalidVpcID.NotFound", format!("The vpc ID '{id}' does not exist")),
            Kind::Subnet => ("InvalidSubnetID.NotFound", format!("The subnet ID '{id}' does not exist")),
            Kind::Group => ("InvalidGroup.NotFound", format!("The security group '{id}' does not exist")),
            Kind::RouteTable => ("InvalidRouteTableID.NotFound", format!("The routeTable ID '{id}' does not exist")),
            Kind::InternetGateway => {
                ("InvalidInternetGatewayID.NotFound", format!("The internetGateway ID '{id}' does not exist"))
            }
            Kind::NatGateway => ("NatGatewayNotFound", format!("The Nat Gateway {id} was not found")),
            Kind::Allocation => ("InvalidAllocationID.NotFound", format!("The allocation ID '{id}' does not exist")),
            Kind::NetworkInterface => {
                ("InvalidNetworkInterfaceID.NotFound", format!("The networkInterface ID '{id}' does not exist"))
            }
            Kind::NetworkAcl => ("InvalidNetworkAclID.NotFound", format!("The networkAcl ID '{id}' does not exist")),
            Kind::DhcpOptions => ("InvalidDhcpOptionID.NotFound", format!("The dhcpOption ID '{id}' does not exist")),
            Kind::Image => ("InvalidAMIID.NotFound", format!("The image id '[{id}]' does not exist")),
            Kind::Instance => ("InvalidInstanceID.NotFound", format!("The instance ID '{id}' does not exist")),
            Kind::Volume => ("InvalidVolume.NotFound", format!("The volume '{id}' does not exist.")),
            Kind::Snapshot => ("InvalidSnapshot.NotFound", format!("The snapshot '{id}' does not exist.")),
            Kind::KeyPairId => ("InvalidKeyPair.NotFound", format!("The key pair '{id}' does not exist")),
            Kind::SecurityGroupRule => {
                ("InvalidSecurityGroupRuleId.NotFound", format!("The security group rule ID '{id}' does not exist"))
            }
            Kind::VpcEndpoint => ("InvalidVpcEndpoint.NotFound", format!("The Vpc Endpoint Id '{id}' does not exist")),
            Kind::PrefixList => ("InvalidPrefixListID.NotFound", format!("The prefix list ID '{id}' does not exist")),
            Kind::EgressOnlyInternetGateway => {
                ("InvalidGatewayID.NotFound", format!("The eigw ID '{id}' does not exist"))
            }
            Kind::CarrierGateway => {
                ("InvalidCarrierGatewayID.NotFound", format!("The CarrierGateway ID '{id}' does not exist"))
            }
            Kind::CustomerGateway => {
                ("InvalidCustomerGatewayID.NotFound", format!("The customerGateway ID '{id}' does not exist"))
            }
            Kind::VpnGateway => ("InvalidVpnGatewayID.NotFound", format!("The vpnGateway ID '{id}' does not exist")),
            Kind::VpnConnection => {
                ("InvalidVpnConnectionID.NotFound", format!("The vpnConnection ID '{id}' does not exist"))
            }
            Kind::VpcPeeringConnection => {
                ("InvalidVpcPeeringConnectionID.NotFound", format!("The vpcPeeringConnection ID '{id}' does not exist"))
            }
            Kind::TransitGateway => {
                ("InvalidTransitGatewayID.NotFound", format!("Transit Gateway {id} was deleted or does not exist."))
            }
            Kind::TransitGatewayAttachment => (
                "InvalidTransitGatewayAttachmentID.NotFound",
                format!("Transit Gateway Attachment {id} was deleted or does not exist."),
            ),
            Kind::TransitGatewayRouteTable => (
                "InvalidRouteTableID.NotFound",
                format!("Transit Gateway Route Table {id} was deleted or does not exist."),
            ),
            Kind::FlowLog => (
                "InvalidFlowLogId.NotFound",
                format!("These flow log ids in the input list are not found: [TotalCount: 1] {id}"),
            ),
            Kind::SubnetCidrReservation => (
                "InvalidSubnetCidrReservationID.NotFound",
                format!("The subnetCidrReservation ID '{id}' does not exist"),
            ),
            Kind::Host => ("InvalidHostID.NotFound", format!("The host ID '{id}' does not exist")),
            Kind::SpotInstanceRequest => {
                ("InvalidSpotInstanceRequestID.NotFound", format!("The spot instance request ID '{id}' does not exist"))
            }
        };
        err(code, msg)
    }

    /// Check that `id` looks like an id of this kind.
    pub fn check(self, id: &str) -> Result<(), ServiceError> {
        let ok = id
            .strip_prefix(self.prefix())
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|hex| (hex.len() == 8 || hex.len() == 17) && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        if ok {
            Ok(())
        } else {
            Err(err(self.malformed_code(), format!("Invalid id: \"{id}\"")))
        }
    }

    /// Check every id, then look each one up with `exists`.
    pub fn check_all(self, ids: &[String], exists: impl Fn(&str) -> bool) -> Result<(), ServiceError> {
        for id in ids {
            self.check(id)?;
        }
        for id in ids {
            if !exists(id) {
                return Err(self.not_found(id));
            }
        }
        Ok(())
    }
}

pub fn dry_run_error() -> ServiceError {
    ServiceError::client("DryRunOperation", 412, "Request would have succeeded, but DryRun flag is set.")
}

// ---- authorization -------------------------------------------------------------

/// Authorize `ec2:{action}` on each resource, as EC2 does: a denial is
/// `UnauthorizedOperation` with an encoded authorization message (which
/// `sts:DecodeAuthorizationMessage` decodes). Then honour `DryRun`.
///
/// A resource whose context carries request tags (`aws:TagKeys`, from
/// [`request_tag_context`]) is one the call creates with tags, so it is
/// also authorized as `ec2:CreateTags` (see [`authorize_tag_on_create`]).
pub fn authorize(
    ctx: &RequestContext,
    action: &str,
    resources: &[(String, ConditionContext)],
    dry_run: Option<bool>,
) -> Result<(), ServiceError> {
    let full = format!("ec2:{action}");
    for (resource, extra) in resources {
        authorize_one(ctx, &full, resource, extra)?;
    }
    authorize_tag_on_create(ctx, action, resources)?;
    if dry_run == Some(true) {
        return Err(dry_run_error());
    }
    Ok(())
}

/// Tag-on-create: a create call that tags what it creates also needs
/// `ec2:CreateTags` on each tagged resource, evaluated with
/// `ec2:CreateAction` set to the create action, the request tags and the
/// resource's other keys. A denial fails the whole call.
pub fn authorize_tag_on_create(
    ctx: &RequestContext,
    action: &str,
    resources: &[(String, ConditionContext)],
) -> Result<(), ServiceError> {
    if action == "CreateTags" {
        return Ok(());
    }
    for (resource, extra) in resources {
        if !extra.get("aws:TagKeys").is_some_and(|k| !k.is_empty()) {
            continue;
        }
        let mut context = extra.clone();
        context.insert("ec2:CreateAction".into(), vec![action.to_string()]);
        authorize_one(ctx, "ec2:CreateTags", resource, &context)?;
    }
    Ok(())
}

fn authorize_one(
    ctx: &RequestContext,
    full: &str,
    resource: &str,
    extra: &ConditionContext,
) -> Result<(), ServiceError> {
    let mut context = extra.clone();
    context.entry("ec2:Region".into()).or_insert_with(|| vec![ctx.region.clone()]);
    if let Err(e) = ctx.authorize(full, resource, context.clone()) {
        if e.code != "AccessDenied" {
            return Err(e);
        }
        let encoded = encode_failure(ctx, full, resource, &context);
        let reason = e.message.split(" because ").nth(1).map(|r| format!(" because {r}")).unwrap_or_default();
        let reason = reason.trim_end_matches('.').to_string();
        return Err(ServiceError::client(
            "UnauthorizedOperation",
            403,
            format!(
                "You are not authorized to perform this operation. User: {} is not authorized to perform: {full} on resource: {resource}{reason}. Encoded authorization failure message: {encoded}",
                ctx.caller.arn
            ),
        ));
    }
    Ok(())
}

fn encode_failure(ctx: &RequestContext, action: &str, resource: &str, context: &ConditionContext) -> String {
    let mut conditions: Vec<serde_json::Value> = ctx
        .global_condition_context()
        .into_iter()
        .chain(context.clone())
        .map(|(k, v)| {
            serde_json::json!({
                "key": k,
                "values": { "items": v.into_iter().map(|v| serde_json::json!({ "value": v })).collect::<Vec<_>>() }
            })
        })
        .collect();
    conditions.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    let doc = serde_json::json!({
        "allowed": false,
        "explicitDeny": false,
        "matchedStatements": { "items": [] },
        "failures": { "items": [] },
        "context": {
            "principal": { "id": ctx.caller.user_id, "arn": ctx.caller.arn },
            "action": action,
            "resource": resource,
            "conditions": { "items": conditions }
        }
    });
    base64::engine::general_purpose::STANDARD.encode(doc.to_string())
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a create request.
pub fn request_tag_context(tags: &[t::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags {
        if let Some(k) = &tag.key {
            c.insert(format!("aws:RequestTag/{k}"), vec![tag.value.clone().unwrap_or_default()]);
        }
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().filter_map(|t| t.key.clone()).collect());
    }
    c
}

/// `aws:ResourceTag/*` and `ec2:ResourceTag/*` for an existing resource.
pub fn resource_tag_context(tags: Option<&Vec<t::Tag>>) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags.into_iter().flatten() {
        if let Some(k) = &tag.key {
            let v = vec![tag.value.clone().unwrap_or_default()];
            c.insert(format!("aws:ResourceTag/{k}"), v.clone());
            c.insert(format!("ec2:ResourceTag/{k}"), v);
        }
    }
    c
}

// ---- tags ----------------------------------------------------------------------

/// The tags a create call's `TagSpecifications` give `resource_type`,
/// checking that every specification names a type this call creates.
pub fn tags_for(
    specs: &Option<Vec<t::TagSpecification>>,
    resource_type: &str,
    allowed: &[&str],
) -> Result<Vec<t::Tag>, ServiceError> {
    let mut out = Vec::new();
    for spec in specs.iter().flatten() {
        let rt = spec.resource_type.clone().unwrap_or_default();
        if !allowed.contains(&rt.as_str()) {
            return Err(invalid_parameter(format!("'{rt}' is not a valid taggable resource type for this operation.")));
        }
        if rt == resource_type {
            out.extend(spec.tags.iter().flatten().cloned());
        }
    }
    validate_tags(&out)?;
    Ok(out)
}

pub fn validate_tags(tags: &[t::Tag]) -> Result<(), ServiceError> {
    for tag in tags {
        let key = tag.key.as_deref().unwrap_or_default();
        if key.is_empty() {
            return Err(invalid_parameter("Tag key cannot be null or empty"));
        }
        if key.starts_with("aws:") {
            return Err(invalid_parameter("Tag keys starting with 'aws:' are reserved for internal use"));
        }
        if key.chars().count() > 128 {
            return Err(invalid_parameter(format!("Tag key exceeds the maximum length of 128 characters: {key}")));
        }
        if tag.value.as_deref().unwrap_or_default().chars().count() > 256 {
            return Err(invalid_parameter("Tag value exceeds the maximum length of 256 characters"));
        }
    }
    if tags.len() > 50 {
        return Err(err("TagLimitExceeded", "The maximum number of Tags for a resource has been reached."));
    }
    Ok(())
}

/// Tags in the API's form, or `None` when there are none (EC2 leaves out
/// an empty `tagSet`).
pub fn some_tags(tags: Vec<t::Tag>) -> Option<Vec<t::Tag>> {
    (!tags.is_empty()).then_some(tags)
}

// ---- filters -------------------------------------------------------------------

/// `Filter.N.Name` / `Filter.N.Value.M`: filters AND together, values OR.
pub struct Filters(Vec<(String, Vec<String>)>);

impl Filters {
    pub fn new(filters: &Option<Vec<t::Filter>>) -> Self {
        Self(
            filters
                .iter()
                .flatten()
                .map(|f| (f.name.clone().unwrap_or_default(), f.values.clone().unwrap_or_default()))
                .collect(),
        )
    }

    /// Whether a resource matches. `field` gives the values of a named
    /// filter (`None` for a name the resource type does not know); tag
    /// filters come from `tags`.
    pub fn matches(
        &self,
        tags: Option<&Vec<t::Tag>>,
        field: impl Fn(&str) -> Option<Vec<String>>,
    ) -> Result<bool, ServiceError> {
        for (name, wanted) in &self.0 {
            let tags = tags.map(Vec::as_slice).unwrap_or_default();
            let have: Vec<String> = if let Some(key) = name.strip_prefix("tag:") {
                tags.iter().filter(|t| t.key.as_deref() == Some(key)).filter_map(|t| t.value.clone()).collect()
            } else if name == "tag-key" {
                tags.iter().filter_map(|t| t.key.clone()).collect()
            } else if name == "tag-value" {
                tags.iter().filter_map(|t| t.value.clone()).collect()
            } else {
                match field(name) {
                    Some(v) => v,
                    None => return Err(invalid_parameter(format!("The filter '{name}' is invalid"))),
                }
            };
            if !wanted.iter().any(|w| have.iter().any(|h| glob(w, h))) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// EC2 filter values: `*` matches any run, `?` one character, `\` escapes.
pub fn glob(pattern: &str, text: &str) -> bool {
    fn go(p: &[char], t: &[char]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some(('*', rest)) => (0..=t.len()).any(|i| go(rest, &t[i..])),
            Some(('?', rest)) => !t.is_empty() && go(rest, &t[1..]),
            Some(('\\', rest)) if !rest.is_empty() => t.first() == Some(&rest[0]) && go(&rest[1..], &t[1..]),
            Some((c, rest)) => t.first() == Some(c) && go(rest, &t[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    go(&p, &t)
}

pub fn s(v: &Option<String>) -> Vec<String> {
    v.iter().cloned().collect()
}

pub fn b(v: Option<bool>) -> Vec<String> {
    v.map(|v| v.to_string()).into_iter().collect()
}

// ---- pagination ----------------------------------------------------------------

/// One page of `items`: EC2's `MaxResults` / `NextToken`.
pub fn paginate<T>(
    items: Vec<T>,
    max_results: Option<i32>,
    next_token: &Option<String>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token.as_deref().filter(|t| !t.is_empty()) {
        None => 0,
        Some(tok) => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(tok)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.strip_prefix("mws:").and_then(|n| n.parse::<usize>().ok()))
            .ok_or_else(|| invalid_parameter(format!("Invalid value '{tok}' for nextToken")))?,
    };
    let Some(max) = max_results else {
        return Ok((items.into_iter().skip(start).collect(), None));
    };
    let max = max.max(1) as usize;
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total)
        .then(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("mws:{}", start + max)));
    Ok((page, next))
}

// ---- CIDR arithmetic -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub base: u32,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, len) = s.split_once('/')?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let prefix: u8 = len.parse().ok().filter(|p| *p <= 32)?;
        Some(Self { base: u32::from(ip), prefix })
    }

    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    /// Whether the address is the network address (no host bits set).
    pub fn is_network(&self) -> bool {
        self.base & !self.mask() == 0
    }

    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix)
    }

    pub fn contains(&self, ip: u32) -> bool {
        ip & self.mask() == self.base & self.mask()
    }

    pub fn contains_cidr(&self, other: &Cidr) -> bool {
        other.prefix >= self.prefix && self.contains(other.base)
    }

    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.contains(other.base) || other.contains(self.base)
    }

    pub fn first(&self) -> u32 {
        self.base & self.mask()
    }

    pub fn last(&self) -> u32 {
        self.first() | !self.mask()
    }
}

pub fn ip_str(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

pub fn parse_ip(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(u32::from)
}

/// The private DNS name EC2 gives an address in `region`.
pub fn private_dns(region: &str, ip: &str) -> String {
    let host = format!("ip-{}", ip.replace('.', "-"));
    if region == "us-east-1" {
        format!("{host}.ec2.internal")
    } else {
        format!("{host}.{region}.compute.internal")
    }
}

/// The public DNS name EC2 gives a public address in `region`.
pub fn public_dns(region: &str, ip: &str) -> String {
    let host = format!("ec2-{}", ip.replace('.', "-"));
    if region == "us-east-1" {
        format!("{host}.compute-1.amazonaws.com")
    } else {
        format!("{host}.{region}.compute.amazonaws.com")
    }
}

/// A fresh public IPv4 address from a range EC2 hands out.
pub fn new_public_ip() -> String {
    let mut rng = rand::thread_rng();
    format!("54.{}.{}.{}", rng.gen_range(144..255), rng.gen_range(0..256), rng.gen_range(1..255))
}

pub fn new_mac() -> String {
    let mut rng = rand::thread_rng();
    let b: Vec<String> = (0..5).map(|_| format!("{:02x}", rng.gen::<u8>())).collect();
    format!("0e:{}", b.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("web-*", "web-1"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "ac"));
        assert!(glob("a\\*", "a*"));
        assert!(!glob("a\\*", "ab"));
    }

    #[test]
    fn cidrs() {
        let vpc = Cidr::parse("10.0.0.0/16").unwrap();
        let sub = Cidr::parse("10.0.1.0/24").unwrap();
        assert!(vpc.contains_cidr(&sub));
        assert!(!sub.contains_cidr(&vpc));
        assert!(Cidr::parse("10.0.1.0/24").unwrap().overlaps(&Cidr::parse("10.0.0.0/23").unwrap()));
        assert!(!Cidr::parse("10.0.1.5/24").unwrap().is_network());
        assert_eq!(sub.size(), 256);
    }

    #[test]
    fn pages() {
        let (p, next) = paginate((0..5).collect(), Some(2), &None).unwrap();
        assert_eq!(p, vec![0, 1]);
        let (p, next) = paginate((0..5).collect(), Some(2), &next).unwrap();
        assert_eq!(p, vec![2, 3]);
        let (p, next) = paginate((0..5).collect(), Some(2), &next).unwrap();
        assert_eq!(p, vec![4]);
        assert!(next.is_none());
    }

    #[test]
    fn ids() {
        assert!(Kind::Vpc.check(&new_id("vpc")).is_ok());
        assert_eq!(Kind::Vpc.check("vpc-xyz").unwrap_err().code, "InvalidVpcID.Malformed");
    }
}
