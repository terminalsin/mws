//! Security groups and their rules. Rules are stored one per peer (as
//! `DescribeSecurityGroupRules` shows them) and grouped into
//! `IpPermissions` for `DescribeSecurityGroups`.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::{RegionState, SgRule};
use crate::util::{
    arn, err, invalid_parameter, missing_parameter, new_id, paginate, request_tag_context, s, some_tags, tags_for,
    Cidr, Filters, Kind,
};
use crate::{account_of, Ec2};

pub fn new_default_group(r: &mut RegionState, account: &str, vpc_id: &str) -> String {
    let id = new_id("sg");
    r.security_groups.insert(
        id.clone(),
        t::SecurityGroup {
            group_id: Some(id.clone()),
            group_name: Some("default".into()),
            description: Some("default VPC security group".into()),
            vpc_id: Some(vpc_id.into()),
            owner_id: Some(account.into()),
            ..Default::default()
        },
    );
    let ingress = SgRule {
        id: new_id("sgr"),
        group_id: id.clone(),
        egress: false,
        protocol: "-1".into(),
        referenced_group_id: Some(id.clone()),
        referenced_user_id: Some(account.into()),
        ..Default::default()
    };
    r.sg_rules.insert(ingress.id.clone(), ingress);
    let egress = allow_all_egress(&id);
    r.sg_rules.insert(egress.id.clone(), egress);
    id
}

fn allow_all_egress(group_id: &str) -> SgRule {
    SgRule {
        id: new_id("sgr"),
        group_id: group_id.into(),
        egress: true,
        protocol: "-1".into(),
        cidr_ipv4: Some("0.0.0.0/0".into()),
        ..Default::default()
    }
}

fn normalize_protocol(p: &str) -> Result<String, ServiceError> {
    let p = p.to_ascii_lowercase();
    Ok(match p.as_str() {
        "-1" | "all" => "-1".into(),
        "tcp" | "6" => "tcp".into(),
        "udp" | "17" => "udp".into(),
        "icmp" | "1" => "icmp".into(),
        "icmpv6" | "58" => "icmpv6".into(),
        n if n.parse::<u8>().is_ok() => n.into(),
        other => {
            return Err(err(
                "InvalidParameterValue",
                format!("Invalid value '{other}' for IP protocol. Unknown protocol."),
            ))
        }
    })
}

fn ports(protocol: &str, from: Option<i32>, to: Option<i32>) -> Result<(Option<i32>, Option<i32>), ServiceError> {
    match protocol {
        "tcp" | "udp" => {
            let (Some(f), Some(t)) = (from, to) else {
                return Err(err(
                    "InvalidParameterValue",
                    "Invalid value 'Must specify both from and to ports with TCP/UDP.' for portRange",
                ));
            };
            if f > t || !(0..=65535).contains(&f) || !(0..=65535).contains(&t) {
                return Err(err(
                    "InvalidParameterValue",
                    format!("Invalid value 'Invalid TCP/UDP port range {f}-{t}' for portRange"),
                ));
            }
            Ok((Some(f), Some(t)))
        }
        "icmp" | "icmpv6" => Ok((Some(from.unwrap_or(-1)), Some(to.unwrap_or(-1)))),
        "-1" => Ok((None, None)),
        _ => Ok((from, to)),
    }
}

/// The rules an `IpPermission` list asks for (one per peer).
fn rules_from(
    r: &RegionState,
    account: &str,
    group_id: &str,
    egress: bool,
    perms: &[t::IpPermission],
) -> Result<Vec<SgRule>, ServiceError> {
    let mut out = Vec::new();
    for p in perms {
        let protocol = normalize_protocol(p.ip_protocol.as_deref().ok_or_else(|| missing_parameter("ipProtocol"))?)?;
        let (from, to) = ports(&protocol, p.from_port, p.to_port)?;
        let base = SgRule {
            group_id: group_id.into(),
            egress,
            protocol: protocol.clone(),
            from_port: from,
            to_port: to,
            ..Default::default()
        };
        let mut any = false;
        for range in p.ip_ranges.iter().flatten() {
            let cidr = range.cidr_ip.clone().unwrap_or_default();
            if Cidr::parse(&cidr).is_none() {
                return Err(invalid_parameter(format!("CIDR block {cidr} is malformed")));
            }
            out.push(SgRule { cidr_ipv4: Some(cidr), description: range.description.clone(), ..base.clone() });
            any = true;
        }
        for range in p.ipv6_ranges.iter().flatten() {
            out.push(SgRule {
                cidr_ipv6: range.cidr_ipv6.clone(),
                description: range.description.clone(),
                ..base.clone()
            });
            any = true;
        }
        for pl in p.prefix_list_ids.iter().flatten() {
            if let Some(id) = &pl.prefix_list_id {
                Kind::PrefixList.check(id)?;
            }
            out.push(SgRule {
                prefix_list_id: pl.prefix_list_id.clone(),
                description: pl.description.clone(),
                ..base.clone()
            });
            any = true;
        }
        for pair in p.user_id_group_pairs.iter().flatten() {
            let gid = match (&pair.group_id, &pair.group_name) {
                (Some(id), _) => id.clone(),
                (None, Some(name)) => {
                    let vpc = r.security_groups.get(group_id).and_then(|g| g.vpc_id.clone());
                    r.security_groups
                        .values()
                        .find(|g| g.group_name.as_deref() == Some(name.as_str()) && g.vpc_id == vpc)
                        .and_then(|g| g.group_id.clone())
                        .ok_or_else(|| Kind::Group.not_found(name))?
                }
                (None, None) => return Err(missing_parameter("groupId")),
            };
            if pair.user_id.as_deref().is_none_or(|u| u == account) && !r.security_groups.contains_key(&gid) {
                return Err(Kind::Group.not_found(&gid));
            }
            out.push(SgRule {
                referenced_group_id: Some(gid),
                referenced_user_id: Some(pair.user_id.clone().unwrap_or_else(|| account.into())),
                description: pair.description.clone(),
                ..base.clone()
            });
            any = true;
        }
        if !any {
            return Err(missing_parameter("IpPermissions"));
        }
    }
    Ok(out)
}

/// Legacy single-rule parameters (`CidrIp`, `IpProtocol`, ports, source
/// group) as an `IpPermission`.
fn legacy_permission(
    cidr_ip: &Option<String>,
    protocol: &Option<String>,
    from: Option<i32>,
    to: Option<i32>,
    source_group_name: &Option<String>,
    source_owner: &Option<String>,
) -> Option<t::IpPermission> {
    if cidr_ip.is_none() && protocol.is_none() && source_group_name.is_none() {
        return None;
    }
    let mut p = t::IpPermission {
        ip_protocol: Some(protocol.clone().unwrap_or_else(|| "-1".into())),
        from_port: from,
        to_port: to,
        ..Default::default()
    };
    if let Some(c) = cidr_ip {
        p.ip_ranges = Some(vec![t::IpRange { cidr_ip: Some(c.clone()), description: None }]);
    }
    if let Some(g) = source_group_name {
        p.ip_protocol = Some(protocol.clone().unwrap_or_else(|| "-1".into()));
        p.user_id_group_pairs = Some(vec![t::UserIdGroupPair {
            group_name: Some(g.clone()),
            user_id: source_owner.clone(),
            ..Default::default()
        }]);
    }
    Some(p)
}

fn same_rule(a: &SgRule, b: &SgRule) -> bool {
    a.group_id == b.group_id
        && a.egress == b.egress
        && a.protocol == b.protocol
        && a.from_port == b.from_port
        && a.to_port == b.to_port
        && a.cidr_ipv4 == b.cidr_ipv4
        && a.cidr_ipv6 == b.cidr_ipv6
        && a.prefix_list_id == b.prefix_list_id
        && a.referenced_group_id == b.referenced_group_id
}

fn describe_rule(rule: &SgRule) -> String {
    let peer = rule
        .cidr_ipv4
        .clone()
        .or_else(|| rule.cidr_ipv6.clone())
        .or_else(|| rule.prefix_list_id.clone())
        .or_else(|| rule.referenced_group_id.clone())
        .unwrap_or_default();
    let proto = if rule.protocol == "-1" { "ALL".to_string() } else { rule.protocol.to_uppercase() };
    match (rule.from_port, rule.to_port) {
        (Some(f), Some(t)) => format!("peer: {peer}, {proto}, from port: {f}, to port: {t}, ALLOW"),
        _ => format!("peer: {peer}, {proto}, ALLOW"),
    }
}

/// `IpPermissions` for one direction of a group.
fn permissions(r: &RegionState, group_id: &str, egress: bool) -> Vec<t::IpPermission> {
    let mut out: Vec<t::IpPermission> = Vec::new();
    for rule in r.sg_rules.values().filter(|x| x.group_id == group_id && x.egress == egress) {
        let pos = out.iter().position(|p| {
            p.ip_protocol.as_deref() == Some(rule.protocol.as_str())
                && p.from_port == rule.from_port
                && p.to_port == rule.to_port
        });
        let p = match pos {
            Some(i) => &mut out[i],
            None => {
                out.push(t::IpPermission {
                    ip_protocol: Some(rule.protocol.clone()),
                    from_port: rule.from_port,
                    to_port: rule.to_port,
                    ip_ranges: Some(Vec::new()),
                    ipv6_ranges: Some(Vec::new()),
                    prefix_list_ids: Some(Vec::new()),
                    user_id_group_pairs: Some(Vec::new()),
                });
                out.last_mut().expect("just pushed")
            }
        };
        if let Some(c) = &rule.cidr_ipv4 {
            p.ip_ranges
                .get_or_insert_with(Vec::new)
                .push(t::IpRange { cidr_ip: Some(c.clone()), description: rule.description.clone() });
        }
        if let Some(c) = &rule.cidr_ipv6 {
            p.ipv6_ranges
                .get_or_insert_with(Vec::new)
                .push(t::Ipv6Range { cidr_ipv6: Some(c.clone()), description: rule.description.clone() });
        }
        if let Some(c) = &rule.prefix_list_id {
            p.prefix_list_ids
                .get_or_insert_with(Vec::new)
                .push(t::PrefixListId { prefix_list_id: Some(c.clone()), description: rule.description.clone() });
        }
        if let Some(g) = &rule.referenced_group_id {
            p.user_id_group_pairs.get_or_insert_with(Vec::new).push(t::UserIdGroupPair {
                group_id: Some(g.clone()),
                user_id: rule.referenced_user_id.clone(),
                description: rule.description.clone(),
                ..Default::default()
            });
        }
    }
    out
}

pub fn render_group(r: &RegionState, ctx: &RequestContext, g: &t::SecurityGroup) -> t::SecurityGroup {
    let mut out = g.clone();
    let id = g.group_id.clone().unwrap_or_default();
    out.ip_permissions = Some(permissions(r, &id, false));
    out.ip_permissions_egress = Some(permissions(r, &id, true));
    out.security_group_arn = Some(arn(ctx, g.owner_id.as_deref().unwrap_or_default(), &format!("security-group/{id}")));
    out
}

fn render_rule(ctx: &RequestContext, account: &str, rule: &SgRule) -> t::SecurityGroupRule {
    t::SecurityGroupRule {
        security_group_rule_id: Some(rule.id.clone()),
        group_id: Some(rule.group_id.clone()),
        group_owner_id: Some(account.into()),
        is_egress: Some(rule.egress),
        ip_protocol: Some(rule.protocol.clone()),
        from_port: Some(rule.from_port.unwrap_or(-1)),
        to_port: Some(rule.to_port.unwrap_or(-1)),
        cidr_ipv4: rule.cidr_ipv4.clone(),
        cidr_ipv6: rule.cidr_ipv6.clone(),
        prefix_list_id: rule.prefix_list_id.clone(),
        referenced_group_info: rule.referenced_group_id.as_ref().map(|g| t::ReferencedSecurityGroup {
            group_id: Some(g.clone()),
            user_id: rule.referenced_user_id.clone(),
            ..Default::default()
        }),
        description: rule.description.clone(),
        tags: some_tags(rule.tags.clone()),
        security_group_rule_arn: Some(arn(ctx, account, &format!("security-group-rule/{}", rule.id))),
    }
}

fn revoked(rule: &SgRule) -> t::RevokedSecurityGroupRule {
    t::RevokedSecurityGroupRule {
        security_group_rule_id: Some(rule.id.clone()),
        group_id: Some(rule.group_id.clone()),
        is_egress: Some(rule.egress),
        ip_protocol: Some(rule.protocol.clone()),
        from_port: Some(rule.from_port.unwrap_or(-1)),
        to_port: Some(rule.to_port.unwrap_or(-1)),
        cidr_ipv4: rule.cidr_ipv4.clone(),
        cidr_ipv6: rule.cidr_ipv6.clone(),
        prefix_list_id: rule.prefix_list_id.clone(),
        referenced_group_id: rule.referenced_group_id.clone(),
        description: rule.description.clone(),
    }
}

/// The group a request names by id, or by name in the default VPC.
fn resolve_group(r: &RegionState, id: &Option<String>, name: &Option<String>) -> Result<String, ServiceError> {
    match (id, name) {
        (Some(id), _) => {
            Kind::Group.check(id)?;
            r.security_groups.contains_key(id).then(|| id.clone()).ok_or_else(|| Kind::Group.not_found(id))
        }
        (None, Some(name)) => {
            let default_vpc =
                r.vpcs.values().find(|v| v.vpc.is_default == Some(true)).and_then(|v| v.vpc.vpc_id.clone());
            r.security_groups
                .values()
                .find(|g| g.group_name.as_deref() == Some(name.as_str()) && g.vpc_id == default_vpc)
                .and_then(|g| g.group_id.clone())
                .ok_or_else(|| match default_vpc {
                    Some(v) => err(
                        "InvalidGroup.NotFound",
                        format!("The security group '{name}' does not exist in default VPC '{v}'"),
                    ),
                    None => err("VPCIdNotSpecified", "No default VPC for this user"),
                })
        }
        (None, None) => Err(missing_parameter("GroupId")),
    }
}

impl Ec2 {
    fn group_authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &Option<String>,
        name: &Option<String>,
        dry_run: Option<bool>,
    ) -> Result<String, ServiceError> {
        self.group_authorize_tagged(ctx, action, id, name, &[], dry_run)
    }

    /// [`Self::group_authorize`], plus `security-group-rule/*` with the
    /// tags the call gives its new rules (so tag-on-create applies).
    fn group_authorize_tagged(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &Option<String>,
        name: &Option<String>,
        rule_tags: &[t::Tag],
        dry_run: Option<bool>,
    ) -> Result<String, ServiceError> {
        let account = account_of(ctx);
        let gid = self.with_region(ctx, |r| resolve_group(r, id, name))?;
        let mut resources = vec![(arn(ctx, &account, &format!("security-group/{gid}")), ConditionContext::new())];
        if !rule_tags.is_empty() {
            resources.push((arn(ctx, &account, "security-group-rule/*"), request_tag_context(rule_tags)));
        }
        let resources = self.with_resource_context(ctx, resources);
        self.authorize_known(ctx, action, &resources, dry_run)?;
        Ok(gid)
    }

    pub(crate) fn create_security_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateSecurityGroupRequest,
    ) -> Result<t::CreateSecurityGroupResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "security-group", &["security-group"])?;
        let vpc_id = match &input.vpc_id {
            Some(v) => {
                Kind::Vpc.check(v)?;
                v.clone()
            }
            None => self
                .with_region(ctx, |r| {
                    r.vpcs.values().find(|v| v.vpc.is_default == Some(true)).and_then(|v| v.vpc.vpc_id.clone())
                })
                .ok_or_else(|| err("VPCIdNotSpecified", "No default VPC for this user"))?,
        };
        self.authorize_known(
            ctx,
            "CreateSecurityGroup",
            &[
                (arn(ctx, &account, "security-group/*"), {
                    let mut c = request_tag_context(&tags);
                    c.extend(crate::conditions::in_vpc(ctx, &account, &vpc_id));
                    c
                }),
                (
                    arn(ctx, &account, &format!("vpc/{vpc_id}")),
                    self.resource_context(ctx, &arn(ctx, &account, &format!("vpc/{vpc_id}"))),
                ),
            ],
            input.dry_run,
        )?;
        let name = input.group_name.clone();
        if name.is_empty() || name.chars().count() > 255 {
            return Err(invalid_parameter(format!(
                "Invalid value '{name}' for groupName. Length of group name must be between 1 and 255 characters."
            )));
        }
        if name.starts_with("sg-") {
            return Err(invalid_parameter("Group names may not be in the format sg-*"));
        }
        if input.description.chars().count() > 255 {
            return Err(invalid_parameter(
                "Invalid value for groupDescription. Length of description must be at most 255 characters.",
            ));
        }
        let limit = self.quota(&account, &ctx.region, crate::quotas::SECURITY_GROUPS, ctx.received_at);
        self.with_region(ctx, |r| {
            if !r.vpcs.contains_key(&vpc_id) {
                return Err(Kind::Vpc.not_found(&vpc_id));
            }
            if r.security_groups.len() as f64 >= limit {
                return Err(err(
                    "SecurityGroupLimitExceeded",
                    "The maximum number of security groups has been reached.",
                ));
            }
            if r.security_groups
                .values()
                .any(|g| g.group_name.as_deref() == Some(name.as_str()) && g.vpc_id.as_deref() == Some(vpc_id.as_str()))
            {
                return Err(err(
                    "InvalidGroup.Duplicate",
                    format!("The security group '{name}' already exists for VPC '{vpc_id}'"),
                ));
            }
            let id = new_id("sg");
            r.security_groups.insert(
                id.clone(),
                t::SecurityGroup {
                    group_id: Some(id.clone()),
                    group_name: Some(name.clone()),
                    description: Some(input.description.clone()),
                    vpc_id: Some(vpc_id.clone()),
                    owner_id: Some(account.clone()),
                    tags: some_tags(tags.clone()),
                    ..Default::default()
                },
            );
            let egress = allow_all_egress(&id);
            r.sg_rules.insert(egress.id.clone(), egress);
            Ok(t::CreateSecurityGroupResult {
                group_id: Some(id.clone()),
                tags: some_tags(tags),
                security_group_arn: Some(arn(ctx, &account, &format!("security-group/{id}"))),
            })
        })
    }

    pub(crate) fn delete_security_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteSecurityGroupRequest,
    ) -> Result<t::DeleteSecurityGroupResult, ServiceError> {
        let gid =
            self.group_authorize(ctx, "DeleteSecurityGroup", &input.group_id, &input.group_name, input.dry_run)?;
        self.with_region(ctx, |r| {
            let g = r.security_groups.get(&gid).ok_or_else(|| Kind::Group.not_found(&gid))?;
            if g.group_name.as_deref() == Some("default") {
                return Err(err(
                    "CannotDelete",
                    format!("the specified group: \"{gid}\" name: \"default\" cannot be deleted by a user"),
                ));
            }
            let in_use = r
                .network_interfaces
                .values()
                .any(|n| n.groups.iter().flatten().any(|x| x.group_id.as_deref() == Some(gid.as_str())));
            let referenced = r
                .sg_rules
                .values()
                .any(|x| x.group_id != gid && x.referenced_group_id.as_deref() == Some(gid.as_str()));
            if in_use || referenced {
                return Err(err("DependencyViolation", format!("resource {gid} has a dependent object")));
            }
            r.security_groups.remove(&gid);
            r.sg_rules.retain(|_, x| x.group_id != gid);
            Ok(t::DeleteSecurityGroupResult { r#return: Some(true), group_id: Some(gid.clone()) })
        })
    }

    pub(crate) fn describe_security_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSecurityGroupsRequest,
    ) -> Result<t::DescribeSecurityGroupsResult, ServiceError> {
        self.authorize_known(ctx, "DescribeSecurityGroups", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.group_ids.clone().unwrap_or_default();
        let names = input.group_names.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            Kind::Group.check_all(&ids, |id| r.security_groups.contains_key(id))?;
            let mut by_name = Vec::new();
            for n in &names {
                by_name.push(resolve_group(r, &None, &Some(n.clone()))?);
            }
            let mut out = Vec::new();
            for g in r.security_groups.values() {
                let id = g.group_id.clone().unwrap_or_default();
                if (!ids.is_empty() || !by_name.is_empty()) && !ids.contains(&id) && !by_name.contains(&id) {
                    continue;
                }
                let v = render_group(r, ctx, g);
                let perm_values = |egress: bool, f: &dyn Fn(&t::IpPermission) -> Vec<String>| -> Vec<String> {
                    let p = if egress { &v.ip_permissions_egress } else { &v.ip_permissions };
                    p.iter().flatten().flat_map(f).collect()
                };
                let ok = filters.matches(v.tags.as_ref(), |name| {
                    let (egress, field) = match name.strip_prefix("egress.") {
                        Some(rest) => (true, rest),
                        None => (false, name),
                    };
                    Some(match field {
                        "description" => s(&v.description),
                        "group-id" => s(&v.group_id),
                        "group-name" => s(&v.group_name),
                        "owner-id" => s(&v.owner_id),
                        "vpc-id" => s(&v.vpc_id),
                        "ip-permission.cidr" => perm_values(egress, &|p| {
                            p.ip_ranges.iter().flatten().filter_map(|x| x.cidr_ip.clone()).collect()
                        }),
                        "ip-permission.ipv6-cidr" => perm_values(egress, &|p| {
                            p.ipv6_ranges.iter().flatten().filter_map(|x| x.cidr_ipv6.clone()).collect()
                        }),
                        "ip-permission.prefix-list-id" => perm_values(egress, &|p| {
                            p.prefix_list_ids.iter().flatten().filter_map(|x| x.prefix_list_id.clone()).collect()
                        }),
                        "ip-permission.from-port" => {
                            perm_values(egress, &|p| p.from_port.map(|x| x.to_string()).into_iter().collect())
                        }
                        "ip-permission.to-port" => {
                            perm_values(egress, &|p| p.to_port.map(|x| x.to_string()).into_iter().collect())
                        }
                        "ip-permission.protocol" => {
                            perm_values(egress, &|p| p.ip_protocol.clone().into_iter().collect())
                        }
                        "ip-permission.group-id" => perm_values(egress, &|p| {
                            p.user_id_group_pairs.iter().flatten().filter_map(|x| x.group_id.clone()).collect()
                        }),
                        "ip-permission.user-id" => perm_values(egress, &|p| {
                            p.user_id_group_pairs.iter().flatten().filter_map(|x| x.user_id.clone()).collect()
                        }),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(v);
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeSecurityGroupsResult { security_groups: Some(items), next_token })
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_rules(
        &self,
        ctx: &RequestContext,
        action: &str,
        gid: &str,
        egress: bool,
        perms: Vec<t::IpPermission>,
        tags: Vec<t::Tag>,
    ) -> Result<Vec<t::SecurityGroupRule>, ServiceError> {
        let account = account_of(ctx);
        let limit = self.quota(&account, &ctx.region, crate::quotas::RULES_PER_GROUP, ctx.received_at);
        self.with_region(ctx, |r| {
            let group = r.security_groups.get(gid).ok_or_else(|| Kind::Group.not_found(gid))?;
            let _ = (group, action);
            let new_rules = rules_from(r, &account, gid, egress, &perms)?;
            for (i, rule) in new_rules.iter().enumerate() {
                if r.sg_rules.values().any(|x| same_rule(x, rule)) || new_rules[..i].iter().any(|x| same_rule(x, rule))
                {
                    return Err(err(
                        "InvalidPermission.Duplicate",
                        format!("the specified rule \"{}\" already exists", describe_rule(rule)),
                    ));
                }
            }
            let count = r.sg_rules.values().filter(|x| x.group_id == gid && x.egress == egress).count();
            if (count + new_rules.len()) as f64 > limit {
                return Err(err(
                    "RulesPerSecurityGroupLimitExceeded",
                    "The maximum number of rules per security group has been reached.",
                ));
            }
            let mut out = Vec::new();
            for mut rule in new_rules {
                rule.id = new_id("sgr");
                rule.tags = tags.clone();
                out.push(render_rule(ctx, &account, &rule));
                r.sg_rules.insert(rule.id.clone(), rule);
            }
            Ok(out)
        })
    }

    pub(crate) fn authorize_security_group_ingress_op(
        &self,
        ctx: &RequestContext,
        input: t::AuthorizeSecurityGroupIngressRequest,
    ) -> Result<t::AuthorizeSecurityGroupIngressResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "security-group-rule", &["security-group-rule"])?;
        let gid = self.group_authorize_tagged(
            ctx,
            "AuthorizeSecurityGroupIngress",
            &input.group_id,
            &input.group_name,
            &tags,
            input.dry_run,
        )?;
        let mut perms = input.ip_permissions.clone().unwrap_or_default();
        perms.extend(legacy_permission(
            &input.cidr_ip,
            &input.ip_protocol,
            input.from_port,
            input.to_port,
            &input.source_security_group_name,
            &input.source_security_group_owner_id,
        ));
        let rules = self.authorize_rules(ctx, "AuthorizeSecurityGroupIngress", &gid, false, perms, tags)?;
        Ok(t::AuthorizeSecurityGroupIngressResult { r#return: Some(true), security_group_rules: Some(rules) })
    }

    pub(crate) fn authorize_security_group_egress_op(
        &self,
        ctx: &RequestContext,
        input: t::AuthorizeSecurityGroupEgressRequest,
    ) -> Result<t::AuthorizeSecurityGroupEgressResult, ServiceError> {
        let tags = tags_for(&input.tag_specifications, "security-group-rule", &["security-group-rule"])?;
        let gid = self.group_authorize_tagged(
            ctx,
            "AuthorizeSecurityGroupEgress",
            &Some(input.group_id.clone()),
            &None,
            &tags,
            input.dry_run,
        )?;
        let mut perms = input.ip_permissions.clone().unwrap_or_default();
        perms.extend(legacy_permission(
            &input.cidr_ip,
            &input.ip_protocol,
            input.from_port,
            input.to_port,
            &input.source_security_group_name,
            &input.source_security_group_owner_id,
        ));
        let rules = self.authorize_rules(ctx, "AuthorizeSecurityGroupEgress", &gid, true, perms, tags)?;
        Ok(t::AuthorizeSecurityGroupEgressResult { r#return: Some(true), security_group_rules: Some(rules) })
    }

    fn revoke_rules(
        &self,
        ctx: &RequestContext,
        gid: &str,
        egress: bool,
        perms: Vec<t::IpPermission>,
        rule_ids: Vec<String>,
    ) -> Result<Vec<t::RevokedSecurityGroupRule>, ServiceError> {
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            let mut ids: Vec<String> = Vec::new();
            for id in &rule_ids {
                match r.sg_rules.get(id) {
                    Some(x) if x.group_id == gid && x.egress == egress => ids.push(id.clone()),
                    _ => return Err(Kind::SecurityGroupRule.not_found(id)),
                }
            }
            for wanted in rules_from(r, &account, gid, egress, &perms)? {
                let found = r.sg_rules.values().find(|x| same_rule(x, &wanted)).map(|x| x.id.clone());
                match found {
                    Some(id) => ids.push(id),
                    None => {
                        return Err(err(
                            "InvalidPermission.NotFound",
                            "The specified rule does not exist in this security group.",
                        ))
                    }
                }
            }
            Ok(ids.iter().filter_map(|id| r.sg_rules.remove(id)).map(|x| revoked(&x)).collect())
        })
    }

    pub(crate) fn revoke_security_group_ingress_op(
        &self,
        ctx: &RequestContext,
        input: t::RevokeSecurityGroupIngressRequest,
    ) -> Result<t::RevokeSecurityGroupIngressResult, ServiceError> {
        let gid =
            self.group_authorize(ctx, "RevokeSecurityGroupIngress", &input.group_id, &input.group_name, input.dry_run)?;
        let mut perms = input.ip_permissions.clone().unwrap_or_default();
        perms.extend(legacy_permission(
            &input.cidr_ip,
            &input.ip_protocol,
            input.from_port,
            input.to_port,
            &input.source_security_group_name,
            &input.source_security_group_owner_id,
        ));
        let revoked =
            self.revoke_rules(ctx, &gid, false, perms, input.security_group_rule_ids.clone().unwrap_or_default())?;
        Ok(t::RevokeSecurityGroupIngressResult {
            r#return: Some(true),
            revoked_security_group_rules: Some(revoked),
            unknown_ip_permissions: None,
        })
    }

    pub(crate) fn revoke_security_group_egress_op(
        &self,
        ctx: &RequestContext,
        input: t::RevokeSecurityGroupEgressRequest,
    ) -> Result<t::RevokeSecurityGroupEgressResult, ServiceError> {
        let gid = self.group_authorize(
            ctx,
            "RevokeSecurityGroupEgress",
            &Some(input.group_id.clone()),
            &None,
            input.dry_run,
        )?;
        let mut perms = input.ip_permissions.clone().unwrap_or_default();
        perms.extend(legacy_permission(
            &input.cidr_ip,
            &input.ip_protocol,
            input.from_port,
            input.to_port,
            &input.source_security_group_name,
            &input.source_security_group_owner_id,
        ));
        let revoked =
            self.revoke_rules(ctx, &gid, true, perms, input.security_group_rule_ids.clone().unwrap_or_default())?;
        Ok(t::RevokeSecurityGroupEgressResult {
            r#return: Some(true),
            revoked_security_group_rules: Some(revoked),
            unknown_ip_permissions: None,
        })
    }

    pub(crate) fn describe_security_group_rules_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeSecurityGroupRulesRequest,
    ) -> Result<t::DescribeSecurityGroupRulesResult, ServiceError> {
        self.authorize_known(
            ctx,
            "DescribeSecurityGroupRules",
            &[("*".into(), ConditionContext::new())],
            input.dry_run,
        )?;
        let filters = Filters::new(&input.filters);
        let ids = input.security_group_rule_ids.clone().unwrap_or_default();
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            Kind::SecurityGroupRule.check_all(&ids, |id| r.sg_rules.contains_key(id))?;
            let mut out = Vec::new();
            for rule in r.sg_rules.values() {
                if !ids.is_empty() && !ids.contains(&rule.id) {
                    continue;
                }
                let tags = some_tags(rule.tags.clone());
                let ok = filters.matches(tags.as_ref(), |name| {
                    Some(match name {
                        "group-id" => vec![rule.group_id.clone()],
                        "security-group-rule-id" => vec![rule.id.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(render_rule(ctx, &account, rule));
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeSecurityGroupRulesResult { security_group_rules: Some(items), next_token })
        })
    }

    pub(crate) fn modify_security_group_rules_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifySecurityGroupRulesRequest,
    ) -> Result<t::ModifySecurityGroupRulesResult, ServiceError> {
        let gid =
            self.group_authorize(ctx, "ModifySecurityGroupRules", &Some(input.group_id.clone()), &None, input.dry_run)?;
        self.with_region(ctx, |r| {
            for update in &input.security_group_rules {
                let existing = r
                    .sg_rules
                    .get(&update.security_group_rule_id)
                    .filter(|x| x.group_id == gid)
                    .cloned()
                    .ok_or_else(|| Kind::SecurityGroupRule.not_found(&update.security_group_rule_id))?;
                let Some(req) = &update.security_group_rule else { continue };
                let protocol =
                    normalize_protocol(req.ip_protocol.as_deref().ok_or_else(|| missing_parameter("IpProtocol"))?)?;
                let (from, to) = ports(&protocol, req.from_port, req.to_port)?;
                let rule = SgRule {
                    protocol,
                    from_port: from,
                    to_port: to,
                    cidr_ipv4: req.cidr_ipv4.clone(),
                    cidr_ipv6: req.cidr_ipv6.clone(),
                    prefix_list_id: req.prefix_list_id.clone(),
                    referenced_group_id: req.referenced_group_id.clone(),
                    referenced_user_id: req
                        .referenced_group_id
                        .as_ref()
                        .map(|_| existing.referenced_user_id.clone().unwrap_or_default()),
                    description: req.description.clone(),
                    ..existing
                };
                r.sg_rules.insert(rule.id.clone(), rule);
            }
            Ok(t::ModifySecurityGroupRulesResult { r#return: Some(true) })
        })
    }

    fn update_descriptions(
        &self,
        ctx: &RequestContext,
        gid: &str,
        egress: bool,
        perms: Vec<t::IpPermission>,
        descriptions: Vec<t::SecurityGroupRuleDescription>,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        self.with_region(ctx, |r| {
            for d in &descriptions {
                let id = d.security_group_rule_id.clone().unwrap_or_default();
                let rule = r
                    .sg_rules
                    .get_mut(&id)
                    .filter(|x| x.group_id == gid && x.egress == egress)
                    .ok_or_else(|| Kind::SecurityGroupRule.not_found(&id))?;
                rule.description = d.description.clone();
            }
            for wanted in rules_from(r, &account, gid, egress, &perms)? {
                let rule = r.sg_rules.values_mut().find(|x| same_rule(x, &wanted)).ok_or_else(|| {
                    err("InvalidPermission.NotFound", "The specified rule does not exist in this security group.")
                })?;
                rule.description = wanted.description.clone();
            }
            Ok(())
        })
    }

    pub(crate) fn update_security_group_rule_descriptions_ingress_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateSecurityGroupRuleDescriptionsIngressRequest,
    ) -> Result<t::UpdateSecurityGroupRuleDescriptionsIngressResult, ServiceError> {
        let gid = self.group_authorize(
            ctx,
            "UpdateSecurityGroupRuleDescriptionsIngress",
            &input.group_id,
            &input.group_name,
            input.dry_run,
        )?;
        self.update_descriptions(
            ctx,
            &gid,
            false,
            input.ip_permissions.clone().unwrap_or_default(),
            input.security_group_rule_descriptions.clone().unwrap_or_default(),
        )?;
        Ok(t::UpdateSecurityGroupRuleDescriptionsIngressResult { r#return: Some(true) })
    }

    pub(crate) fn update_security_group_rule_descriptions_egress_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateSecurityGroupRuleDescriptionsEgressRequest,
    ) -> Result<t::UpdateSecurityGroupRuleDescriptionsEgressResult, ServiceError> {
        let gid = self.group_authorize(
            ctx,
            "UpdateSecurityGroupRuleDescriptionsEgress",
            &input.group_id,
            &input.group_name,
            input.dry_run,
        )?;
        self.update_descriptions(
            ctx,
            &gid,
            true,
            input.ip_permissions.clone().unwrap_or_default(),
            input.security_group_rule_descriptions.clone().unwrap_or_default(),
        )?;
        Ok(t::UpdateSecurityGroupRuleDescriptionsEgressResult { r#return: Some(true) })
    }
}
