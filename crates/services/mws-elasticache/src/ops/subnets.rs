//! Cache subnet groups, and the EC2-Classic cache security groups (which
//! accounts created today cannot use).

use mws_core::{RequestContext, ServiceError};

use super::*;
use crate::generated::{errors, types as t};
use crate::state::RegionState;
use crate::{ElastiCache, SubnetInfo};

fn not_found(name: &str) -> ServiceError {
    errors::cache_subnet_group_not_found_fault(format!("Cache subnet group '{name}' does not exist."))
}

fn wire_subnet(s: &SubnetInfo) -> t::Subnet {
    t::Subnet {
        subnet_identifier: Some(s.subnet_id.clone()),
        subnet_availability_zone: Some(t::AvailabilityZone { name: Some(s.availability_zone.clone()) }),
        subnet_outpost: None,
        supported_network_types: Some(if s.ipv6 {
            vec!["ipv4".into(), "dual_stack".into()]
        } else {
            vec!["ipv4".into()]
        }),
    }
}

/// Look subnets up in EC2 (or, without EC2, accept well-formed ids in a
/// synthetic VPC).
fn resolve(svc: &ElastiCache, ctx: &RequestContext, ids: &[String]) -> Result<(String, Vec<SubnetInfo>), ServiceError> {
    if ids.is_empty() {
        return Err(invalid("The parameter SubnetIds must be provided and must not be empty."));
    }
    if ids.len() > 20 {
        return Err(errors::cache_subnet_quota_exceeded_fault("The request cannot be processed because it would exceed the allowed number of subnets in a cache subnet group."));
    }
    let account = crate::account_of(ctx);
    let mut out = Vec::new();
    for id in ids {
        let info = match svc.network() {
            Some(n) => n
                .subnet(&account, &ctx.region, id)
                .ok_or_else(|| errors::invalid_subnet(format!("The subnet ID {id} does not exist")))?,
            None => {
                if !id.starts_with("subnet-") {
                    return Err(errors::invalid_subnet(format!("The subnet ID {id} does not exist")));
                }
                let zones = crate::catalog::zones(&ctx.region);
                let idx = id.bytes().map(|b| b as usize).sum::<usize>() % zones.len();
                SubnetInfo {
                    subnet_id: id.clone(),
                    vpc_id: "vpc-00000000000000000".into(),
                    availability_zone: zones[idx].clone(),
                    ipv6: false,
                }
            }
        };
        out.push(info);
    }
    let vpc = out[0].vpc_id.clone();
    if out.iter().any(|s| s.vpc_id != vpc) {
        return Err(errors::invalid_subnet("Subnets in a cache subnet group must all belong to the same VPC."));
    }
    Ok((vpc, out))
}

fn group(
    ctx: &RequestContext,
    name: &str,
    description: &str,
    vpc: &str,
    subnets: &[SubnetInfo],
) -> t::CacheSubnetGroup {
    let dual = !subnets.is_empty() && subnets.iter().all(|s| s.ipv6);
    t::CacheSubnetGroup {
        cache_subnet_group_name: Some(name.into()),
        cache_subnet_group_description: Some(description.into()),
        vpc_id: Some(vpc.into()),
        subnets: Some(subnets.iter().map(wire_subnet).collect()),
        arn: Some(arn(ctx, "subnetgroup", name)),
        supported_network_types: Some(if dual {
            vec!["ipv4".into(), "dual_stack".into()]
        } else {
            vec!["ipv4".into()]
        }),
    }
}

/// The `default` subnet group (the default VPC's subnets), created on first
/// use as ElastiCache does.
pub(crate) fn ensure_default(
    svc: &ElastiCache,
    ctx: &RequestContext,
    r: &mut RegionState,
) -> Result<String, ServiceError> {
    if r.subnet_groups.contains_key("default") {
        return Ok("default".into());
    }
    let account = crate::account_of(ctx);
    let subnets = match svc.network() {
        Some(n) => n.default_subnets(&account, &ctx.region),
        None => crate::catalog::zones(&ctx.region)
            .into_iter()
            .take(3)
            .enumerate()
            .map(|(i, z)| SubnetInfo {
                subnet_id: format!("subnet-{:017x}", i + 1),
                vpc_id: "vpc-00000000000000000".into(),
                availability_zone: z,
                ipv6: false,
            })
            .collect(),
    };
    if subnets.is_empty() {
        return Err(errors::invalid_vpc_network_state_fault("No default VPC found; specify a cache subnet group."));
    }
    let vpc = subnets[0].vpc_id.clone();
    r.subnet_groups.insert("default".into(), group(ctx, "default", "default", &vpc, &subnets));
    Ok("default".into())
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateCacheSubnetGroupMessage,
) -> Result<t::CreateCacheSubnetGroupResult, ServiceError> {
    let name = input.cache_subnet_group_name.to_ascii_lowercase();
    if name.is_empty() || name.len() > 255 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(invalid("The parameter CacheSubnetGroupName must contain only ASCII letters, digits, and hyphens and be at most 255 characters long."));
    }
    if name == "default" {
        return Err(invalid("The cache subnet group name default is reserved."));
    }
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "subnetgroup", &name);
    authorize_create(ctx, "CreateCacheSubnetGroup", &resource, &tags, Default::default())?;
    let (vpc, subnets) = resolve(svc, ctx, &input.subnet_ids)?;
    svc.with_region(ctx, |r| {
        if r.subnet_groups.contains_key(&name) {
            return Err(errors::cache_subnet_group_already_exists_fault(format!(
                "Cache subnet group {name} already exists."
            )));
        }
        if r.subnet_groups.len() >= 150 {
            return Err(errors::cache_subnet_group_quota_exceeded_fault("Cache subnet group quota exceeded."));
        }
        let g = group(ctx, &name, &input.cache_subnet_group_description, &vpc, &subnets);
        r.subnet_groups.insert(name.clone(), g.clone());
        set_tags(r, &resource, input.tags.clone());
        Ok(t::CreateCacheSubnetGroupResult { cache_subnet_group: Some(g) })
    })
}

pub(crate) async fn modify(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyCacheSubnetGroupMessage,
) -> Result<t::ModifyCacheSubnetGroupResult, ServiceError> {
    let name = input.cache_subnet_group_name.to_ascii_lowercase();
    let resolved = match &input.subnet_ids {
        Some(ids) => Some(resolve(svc, ctx, ids)?),
        None => None,
    };
    svc.with_region(ctx, |r| {
        authorize(ctx, r, "ModifyCacheSubnetGroup", &arn(ctx, "subnetgroup", &name), Default::default())?;
        let used: Vec<String> = r
            .clusters
            .values()
            .filter(|c| c.info.cache_subnet_group_name.as_deref() == Some(&name))
            .flat_map(|c| c.info.cache_nodes.iter().flatten().filter_map(|n| n.customer_availability_zone.clone()))
            .collect();
        let g = r.subnet_groups.get_mut(&name).ok_or_else(|| not_found(&name))?;
        if let Some(d) = &input.cache_subnet_group_description {
            g.cache_subnet_group_description = Some(d.clone());
        }
        if let Some((vpc, subnets)) = resolved {
            if g.vpc_id.as_deref() != Some(&vpc) && !used.is_empty() {
                return Err(errors::subnet_in_use("The subnet group is in use and its VPC cannot change."));
            }
            let zones: Vec<&String> = subnets.iter().map(|s| &s.availability_zone).collect();
            if let Some(z) = used.iter().find(|z| !zones.contains(z)) {
                return Err(errors::subnet_in_use(format!(
                    "A subnet in availability zone {z} is in use by a cache node."
                )));
            }
            let fresh =
                group(ctx, &name, g.cache_subnet_group_description.as_deref().unwrap_or_default(), &vpc, &subnets);
            *g = fresh;
        }
        Ok(t::ModifyCacheSubnetGroupResult { cache_subnet_group: Some(g.clone()) })
    })
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteCacheSubnetGroupMessage,
) -> Result<(), ServiceError> {
    let name = input.cache_subnet_group_name.to_ascii_lowercase();
    svc.with_region(ctx, |r| {
        authorize(ctx, r, "DeleteCacheSubnetGroup", &arn(ctx, "subnetgroup", &name), Default::default())?;
        if !r.subnet_groups.contains_key(&name) {
            return Err(not_found(&name));
        }
        if r.clusters.values().any(|c| c.info.cache_subnet_group_name.as_deref() == Some(&name)) {
            return Err(errors::cache_subnet_group_in_use(format!("Cache subnet group {name} is currently in use.")));
        }
        r.subnet_groups.remove(&name);
        r.tags.remove(&arn(ctx, "subnetgroup", &name));
        Ok(())
    })
}

pub(crate) async fn describe(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeCacheSubnetGroupsMessage,
) -> Result<t::CacheSubnetGroupMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        let items: Vec<t::CacheSubnetGroup> = match input.cache_subnet_group_name.as_deref() {
            Some(n) => {
                let n = n.to_ascii_lowercase();
                authorize(ctx, r, "DescribeCacheSubnetGroups", &arn(ctx, "subnetgroup", &n), Default::default())?;
                vec![r.subnet_groups.get(&n).cloned().ok_or_else(|| not_found(&n))?]
            }
            None => {
                ctx.authorize(
                    "elasticache:DescribeCacheSubnetGroups",
                    &arn(ctx, "subnetgroup", "*"),
                    Default::default(),
                )?;
                r.subnet_groups.values().cloned().collect()
            }
        };
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::CacheSubnetGroupMessage { marker, cache_subnet_groups: Some(page) })
    })
}

// ---- cache security groups (EC2-Classic) ----------------------------------

const CLASSIC: &str = "Use of cache security groups is not permitted in this API version for your account.";

fn sg_not_found(name: &str) -> ServiceError {
    errors::cache_security_group_not_found_fault(format!("CacheSecurityGroup {name} not found."))
}

pub(crate) async fn create_security_group(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateCacheSecurityGroupMessage,
) -> Result<t::CreateCacheSecurityGroupResult, ServiceError> {
    ctx.authorize(
        "elasticache:CreateCacheSecurityGroup",
        &arn(ctx, "securitygroup", &input.cache_security_group_name),
        Default::default(),
    )?;
    Err(invalid(CLASSIC))
}

pub(crate) async fn delete_security_group(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteCacheSecurityGroupMessage,
) -> Result<(), ServiceError> {
    let name = input.cache_security_group_name;
    ctx.authorize("elasticache:DeleteCacheSecurityGroup", &arn(ctx, "securitygroup", &name), Default::default())?;
    if name == "default" {
        return Err(errors::invalid_cache_security_group_state_fault(
            "The default cache security group cannot be deleted.",
        ));
    }
    Err(sg_not_found(&name))
}

pub(crate) async fn describe_security_groups(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeCacheSecurityGroupsMessage,
) -> Result<t::CacheSecurityGroupMessage, ServiceError> {
    ctx.authorize("elasticache:DescribeCacheSecurityGroups", &arn(ctx, "securitygroup", "*"), Default::default())?;
    if let Some(n) = input.cache_security_group_name {
        return Err(sg_not_found(&n));
    }
    page::<t::CacheSecurityGroup>(vec![], input.marker.as_deref(), input.max_records)?;
    Ok(t::CacheSecurityGroupMessage { marker: None, cache_security_groups: Some(vec![]) })
}

pub(crate) async fn authorize_ingress(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::AuthorizeCacheSecurityGroupIngressMessage,
) -> Result<t::AuthorizeCacheSecurityGroupIngressResult, ServiceError> {
    ctx.authorize(
        "elasticache:AuthorizeCacheSecurityGroupIngress",
        &arn(ctx, "securitygroup", &input.cache_security_group_name),
        Default::default(),
    )?;
    Err(sg_not_found(&input.cache_security_group_name))
}

pub(crate) async fn revoke_ingress(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::RevokeCacheSecurityGroupIngressMessage,
) -> Result<t::RevokeCacheSecurityGroupIngressResult, ServiceError> {
    ctx.authorize(
        "elasticache:RevokeCacheSecurityGroupIngress",
        &arn(ctx, "securitygroup", &input.cache_security_group_name),
        Default::default(),
    )?;
    Err(sg_not_found(&input.cache_security_group_name))
}
