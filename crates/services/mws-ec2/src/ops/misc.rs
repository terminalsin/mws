//! Regions and zones, account attributes, instance types, key pairs and
//! tags.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::catalog;
use crate::generated::types as t;
use crate::keys;
use crate::state::{KeyPairRecord, RegionState};
use crate::util::{
    arn, authorize, err, invalid_parameter, new_id, paginate, request_tag_context, resource_tag_context, s, some_tags,
    tags_for, validate_tags, Filters, Kind,
};
use crate::{account_of, Ec2};

/// A resource id with its current tags.
type TagTarget = (String, Option<Vec<t::Tag>>);

impl Ec2 {
    // ---- Regions, zones, account -------------------------------------------------------------

    pub(crate) fn describe_regions_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeRegionsRequest,
    ) -> Result<t::DescribeRegionsResult, ServiceError> {
        authorize(ctx, "DescribeRegions", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let names = input.region_names.clone().unwrap_or_default();
        for n in &names {
            if !catalog::REGIONS.contains(&n.as_str()) {
                return Err(err("InvalidParameterValue", format!("Invalid region: {n}")));
            }
        }
        let mut out = Vec::new();
        for region in catalog::REGIONS {
            let status = catalog::region_opt_in_status(region);
            if !names.is_empty() && !names.iter().any(|n| n == region) {
                continue;
            }
            if names.is_empty() && input.all_regions != Some(true) && status == "not-opted-in" {
                continue;
            }
            let endpoint = format!("ec2.{region}.amazonaws.com");
            let ok = filters.matches(None, |name| {
                Some(match name {
                    "endpoint" => vec![endpoint.clone()],
                    "opt-in-status" => vec![status.to_string()],
                    "region-name" => vec![region.to_string()],
                    _ => return None,
                })
            })?;
            if ok {
                out.push(t::Region {
                    region_name: Some(region.to_string()),
                    endpoint: Some(endpoint),
                    opt_in_status: Some(status.into()),
                    ..Default::default()
                });
            }
        }
        Ok(t::DescribeRegionsResult { regions: Some(out) })
    }

    pub(crate) fn describe_availability_zones_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAvailabilityZonesRequest,
    ) -> Result<t::DescribeAvailabilityZonesResult, ServiceError> {
        authorize(ctx, "DescribeAvailabilityZones", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let names = input.zone_names.clone().unwrap_or_default();
        let ids = input.zone_ids.clone().unwrap_or_default();
        let zones = catalog::zones(&ctx.region);
        for n in &names {
            if !zones.iter().any(|z| &z.0 == n) {
                return Err(err("InvalidParameterValue", format!("The zone '{n}' does not exist.")));
            }
        }
        for n in &ids {
            if !zones.iter().any(|z| &z.1 == n) {
                return Err(err("InvalidParameterValue", format!("The zone id '{n}' does not exist.")));
            }
        }
        let mut out = Vec::new();
        for (name, id) in zones {
            if (!names.is_empty() || !ids.is_empty()) && !names.contains(&name) && !ids.contains(&id) {
                continue;
            }
            let z = t::AvailabilityZone {
                state: Some("available".into()),
                opt_in_status: Some("opt-in-not-required".into()),
                messages: Some(Vec::new()),
                region_name: Some(ctx.region.clone()),
                zone_name: Some(name.clone()),
                zone_id: Some(id.clone()),
                group_name: Some(format!("{}-zg-1", ctx.region)),
                group_long_name: Some(ctx.region.clone()),
                network_border_group: Some(ctx.region.clone()),
                zone_type: Some("availability-zone".into()),
                ..Default::default()
            };
            let ok = filters.matches(None, |f| {
                Some(match f {
                    "zone-name" => s(&z.zone_name),
                    "zone-id" => s(&z.zone_id),
                    "region-name" => s(&z.region_name),
                    "state" => s(&z.state),
                    "zone-type" => s(&z.zone_type),
                    "opt-in-status" => s(&z.opt_in_status),
                    "group-name" => s(&z.group_name),
                    "network-border-group" => s(&z.network_border_group),
                    _ => return None,
                })
            })?;
            if ok {
                out.push(z);
            }
        }
        Ok(t::DescribeAvailabilityZonesResult { availability_zones: Some(out) })
    }

    pub(crate) fn describe_account_attributes_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAccountAttributesRequest,
    ) -> Result<t::DescribeAccountAttributesResult, ServiceError> {
        authorize(ctx, "DescribeAccountAttributes", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let default_vpc = self
            .with_region(ctx, |r| {
                r.vpcs.values().find(|v| v.vpc.is_default == Some(true)).and_then(|v| v.vpc.vpc_id.clone())
            })
            .unwrap_or_else(|| "none".into());
        let all: Vec<(&str, Vec<String>)> = vec![
            ("supported-platforms", vec!["VPC".into()]),
            ("vpc-max-security-groups-per-interface", vec!["5".into()]),
            ("max-elastic-ips", vec!["5".into()]),
            ("max-instances", vec!["20".into()]),
            ("vpc-max-elastic-ips", vec!["5".into()]),
            ("default-vpc", vec![default_vpc]),
        ];
        let wanted = input.attribute_names.clone().unwrap_or_default();
        let out = all
            .into_iter()
            .filter(|(n, _)| wanted.is_empty() || wanted.iter().any(|w| w == n))
            .map(|(n, v)| t::AccountAttribute {
                attribute_name: Some(n.into()),
                attribute_values: Some(
                    v.into_iter().map(|v| t::AccountAttributeValue { attribute_value: Some(v) }).collect(),
                ),
            })
            .collect();
        Ok(t::DescribeAccountAttributesResult { account_attributes: Some(out) })
    }

    pub(crate) fn describe_instance_types_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstanceTypesRequest,
    ) -> Result<t::DescribeInstanceTypesResult, ServiceError> {
        authorize(ctx, "DescribeInstanceTypes", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let wanted = input.instance_types.clone().unwrap_or_default();
        for w in &wanted {
            if catalog::instance_type(w).is_none() {
                return Err(err(
                    "InvalidInstanceType",
                    format!("The following supplied instance types do not exist: [{w}]"),
                ));
            }
        }
        let mut out = Vec::new();
        for it in catalog::INSTANCE_TYPES {
            if !wanted.is_empty() && !wanted.iter().any(|w| w == it.name) {
                continue;
            }
            let info = catalog::instance_type_info(it);
            let ok = filters.matches(None, |f| {
                Some(match f {
                    "instance-type" => vec![it.name.to_string()],
                    "current-generation" => vec![info.current_generation.unwrap_or_default().to_string()],
                    "free-tier-eligible" => vec![info.free_tier_eligible.unwrap_or_default().to_string()],
                    "burstable-performance-supported" => vec![it.burstable.to_string()],
                    "processor-info.supported-architecture" => vec![it.arch.to_string()],
                    "vcpu-info.default-vcpus" => vec![it.vcpus.to_string()],
                    "memory-info.size-in-mib" => vec![it.memory_mib.to_string()],
                    "hypervisor" => s(&info.hypervisor),
                    _ => return None,
                })
            })?;
            if ok {
                out.push(info);
            }
        }
        let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeInstanceTypesResult { instance_types: Some(items), next_token })
    }

    pub(crate) fn describe_instance_type_offerings_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstanceTypeOfferingsRequest,
    ) -> Result<t::DescribeInstanceTypeOfferingsResult, ServiceError> {
        authorize(ctx, "DescribeInstanceTypeOfferings", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let location_type = input.location_type.clone().unwrap_or_else(|| "region".into());
        let locations: Vec<String> = match location_type.as_str() {
            "region" => vec![ctx.region.clone()],
            "availability-zone" => catalog::zones(&ctx.region).into_iter().map(|z| z.0).collect(),
            "availability-zone-id" => catalog::zones(&ctx.region).into_iter().map(|z| z.1).collect(),
            other => return Err(invalid_parameter(format!("Invalid value '{other}' for LocationType"))),
        };
        let mut out = Vec::new();
        for loc in &locations {
            for it in catalog::INSTANCE_TYPES {
                let ok = filters.matches(None, |f| {
                    Some(match f {
                        "instance-type" => vec![it.name.to_string()],
                        "location" => vec![loc.clone()],
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(t::InstanceTypeOffering {
                        instance_type: Some(it.name.into()),
                        location_type: Some(location_type.clone()),
                        location: Some(loc.clone()),
                    });
                }
            }
        }
        let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::DescribeInstanceTypeOfferingsResult { instance_type_offerings: Some(items), next_token })
    }

    // ---- key pairs --------------------------------------------------------------------------------

    pub(crate) fn create_key_pair_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateKeyPairRequest,
    ) -> Result<t::KeyPair, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "key-pair", &["key-pair"])?;
        authorize(
            ctx,
            "CreateKeyPair",
            &[(arn(ctx, &account, &format!("key-pair/{}", input.key_name)), request_tag_context(&tags))],
            input.dry_run,
        )?;
        check_key_name(&input.key_name)?;
        let key_type = input.key_type.clone().unwrap_or_else(|| "rsa".into());
        let format = input.key_format.clone().unwrap_or_else(|| "pem".into());
        if format != "pem" {
            return Err(err(
                "InvalidParameterValue",
                format!("MWS does not create key pairs in the '{format}' format; use 'pem'."),
            ));
        }
        let generated = match key_type.as_str() {
            "rsa" => keys::generate_rsa(),
            "ed25519" => keys::generate_ed25519(),
            other => return Err(invalid_parameter(format!("Invalid value '{other}' for keyType."))),
        }
        .map_err(|e| mws_core::ServiceError::server("InternalError", 500, e))?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if r.key_pairs.contains_key(&input.key_name) {
                return Err(err(
                    "InvalidKeyPair.Duplicate",
                    format!("The keypair '{}' already exists.", input.key_name),
                ));
            }
            let id = new_id("key");
            r.key_pairs.insert(
                input.key_name.clone(),
                KeyPairRecord {
                    info: t::KeyPairInfo {
                        key_pair_id: Some(id.clone()),
                        key_type: Some(key_type.clone()),
                        key_name: Some(input.key_name.clone()),
                        key_fingerprint: Some(generated.fingerprint.clone()),
                        create_time: Some(now),
                        tags: some_tags(tags.clone()),
                        public_key: None,
                    },
                    public_key: generated.public_key.clone(),
                },
            );
            Ok(t::KeyPair {
                key_pair_id: Some(id),
                key_name: Some(input.key_name.clone()),
                key_fingerprint: Some(generated.fingerprint.clone()),
                key_material: Some(generated.material.clone()),
                tags: some_tags(tags),
            })
        })
    }

    pub(crate) fn import_key_pair_op(
        &self,
        ctx: &RequestContext,
        input: t::ImportKeyPairRequest,
    ) -> Result<t::ImportKeyPairResult, ServiceError> {
        let account = account_of(ctx);
        let tags = tags_for(&input.tag_specifications, "key-pair", &["key-pair"])?;
        authorize(
            ctx,
            "ImportKeyPair",
            &[(arn(ctx, &account, &format!("key-pair/{}", input.key_name)), request_tag_context(&tags))],
            input.dry_run,
        )?;
        check_key_name(&input.key_name)?;
        let imported = keys::import(&input.public_key_material)
            .map_err(|_| err("InvalidKey.Format", "Key is not in valid OpenSSH public key format"))?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if r.key_pairs.contains_key(&input.key_name) {
                return Err(err(
                    "InvalidKeyPair.Duplicate",
                    format!("The keypair '{}' already exists.", input.key_name),
                ));
            }
            let id = new_id("key");
            r.key_pairs.insert(
                input.key_name.clone(),
                KeyPairRecord {
                    info: t::KeyPairInfo {
                        key_pair_id: Some(id.clone()),
                        key_type: Some(imported.key_type.into()),
                        key_name: Some(input.key_name.clone()),
                        key_fingerprint: Some(imported.fingerprint.clone()),
                        create_time: Some(now),
                        tags: some_tags(tags.clone()),
                        public_key: None,
                    },
                    public_key: imported.public_key.clone(),
                },
            );
            Ok(t::ImportKeyPairResult {
                key_pair_id: Some(id),
                key_name: Some(input.key_name.clone()),
                key_fingerprint: Some(imported.fingerprint.clone()),
                tags: some_tags(tags),
            })
        })
    }

    pub(crate) fn delete_key_pair_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteKeyPairRequest,
    ) -> Result<t::DeleteKeyPairResult, ServiceError> {
        let account = account_of(ctx);
        let found = self.with_region(ctx, |r| -> Result<Option<(String, String)>, ServiceError> {
            Ok(match (&input.key_name, &input.key_pair_id) {
                (_, Some(id)) => {
                    Kind::KeyPairId.check(id)?;
                    let k = r.key_pairs.values().find(|k| k.info.key_pair_id.as_deref() == Some(id.as_str()));
                    match k {
                        Some(k) => Some((k.info.key_name.clone().unwrap_or_default(), id.clone())),
                        None => {
                            return Err(err("InvalidKeyPair.NotFound", format!("The key pair '{id}' does not exist")))
                        }
                    }
                }
                (Some(name), None) => {
                    r.key_pairs.get(name).map(|k| (name.clone(), k.info.key_pair_id.clone().unwrap_or_default()))
                }
                (None, None) => return Err(crate::util::missing_parameter("KeyName")),
            })
        })?;
        let name = found.as_ref().map(|f| f.0.clone()).or_else(|| input.key_name.clone()).unwrap_or_default();
        authorize(
            ctx,
            "DeleteKeyPair",
            &[(arn(ctx, &account, &format!("key-pair/{name}")), ConditionContext::new())],
            input.dry_run,
        )?;
        // Deleting a key pair that does not exist succeeds, as in EC2.
        if let Some((name, _)) = &found {
            self.with_region(ctx, |r| r.key_pairs.remove(name));
        }
        Ok(t::DeleteKeyPairResult { r#return: Some(true), key_pair_id: found.map(|f| f.1) })
    }

    pub(crate) fn describe_key_pairs_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeKeyPairsRequest,
    ) -> Result<t::DescribeKeyPairsResult, ServiceError> {
        authorize(ctx, "DescribeKeyPairs", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let names = input.key_names.clone().unwrap_or_default();
        let ids = input.key_pair_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            for n in &names {
                if !r.key_pairs.contains_key(n) {
                    return Err(err("InvalidKeyPair.NotFound", format!("The key pair '{n}' does not exist")));
                }
            }
            for id in &ids {
                Kind::KeyPairId.check(id)?;
                if !r.key_pairs.values().any(|k| k.info.key_pair_id.as_deref() == Some(id.as_str())) {
                    return Err(err("InvalidKeyPair.NotFound", format!("The key pair '{id}' does not exist")));
                }
            }
            let mut out = Vec::new();
            for k in r.key_pairs.values() {
                let info = &k.info;
                let name = info.key_name.clone().unwrap_or_default();
                let id = info.key_pair_id.clone().unwrap_or_default();
                if (!names.is_empty() || !ids.is_empty()) && !names.contains(&name) && !ids.contains(&id) {
                    continue;
                }
                let ok = filters.matches(info.tags.as_ref(), |f| {
                    Some(match f {
                        "key-pair-id" => vec![id.clone()],
                        "key-name" => vec![name.clone()],
                        "fingerprint" => s(&info.key_fingerprint),
                        "key-type" => s(&info.key_type),
                        _ => return None,
                    })
                })?;
                if ok {
                    let mut info = info.clone();
                    if input.include_public_key == Some(true) {
                        info.public_key = Some(format!("{} {name}", k.public_key));
                    }
                    out.push(info);
                }
            }
            Ok(t::DescribeKeyPairsResult { key_pairs: Some(out) })
        })
    }

    // ---- tags -----------------------------------------------------------------------------------

    fn tag_targets(&self, ctx: &RequestContext, ids: &[String]) -> Result<Vec<TagTarget>, ServiceError> {
        self.with_region(ctx, |r| {
            ids.iter()
                .map(|id| {
                    let tags = r.tags_mut(id).map(|t| t.clone());
                    match tags {
                        Some(t) => Ok((id.clone(), t)),
                        None => Err(not_found_for(id)),
                    }
                })
                .collect()
        })
    }

    pub(crate) fn create_tags_op(&self, ctx: &RequestContext, input: t::CreateTagsRequest) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        validate_tags(&input.tags)?;
        let targets = self.tag_targets(ctx, &input.resources)?;
        let mut resources = Vec::new();
        for (id, existing) in &targets {
            let mut c = request_tag_context(&input.tags);
            c.extend(resource_tag_context(existing.as_ref()));
            resources.push((resource_arn(ctx, &account, id), c));
        }
        authorize(ctx, "CreateTags", &resources, input.dry_run)?;
        self.with_region(ctx, |r| {
            for id in &input.resources {
                if let Some(slot) = r.tags_mut(id) {
                    let mut tags = slot.take().unwrap_or_default();
                    for tag in &input.tags {
                        match tags.iter_mut().find(|t| t.key == tag.key) {
                            Some(existing) => existing.value = Some(tag.value.clone().unwrap_or_default()),
                            None => tags.push(t::Tag {
                                key: tag.key.clone(),
                                value: Some(tag.value.clone().unwrap_or_default()),
                            }),
                        }
                    }
                    if tags.len() > 50 {
                        return Err(err(
                            "TagLimitExceeded",
                            "The maximum number of Tags for a resource has been reached.",
                        ));
                    }
                    *slot = some_tags(tags);
                }
            }
            Ok(())
        })
    }

    pub(crate) fn delete_tags_op(&self, ctx: &RequestContext, input: t::DeleteTagsRequest) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let targets = self.tag_targets(ctx, &input.resources)?;
        let mut resources = Vec::new();
        for (id, existing) in &targets {
            let mut c = resource_tag_context(existing.as_ref());
            if let Some(tags) = &input.tags {
                c.insert("aws:TagKeys".into(), tags.iter().filter_map(|t| t.key.clone()).collect());
            }
            resources.push((resource_arn(ctx, &account, id), c));
        }
        authorize(ctx, "DeleteTags", &resources, input.dry_run)?;
        self.with_region(ctx, |r| {
            for id in &input.resources {
                if let Some(slot) = r.tags_mut(id) {
                    let mut tags = slot.take().unwrap_or_default();
                    match &input.tags {
                        None => tags.clear(),
                        Some(remove) => tags.retain(|t| {
                            !remove
                                .iter()
                                .any(|x| x.key == t.key && x.value.as_ref().is_none_or(|v| Some(v) == t.value.as_ref()))
                        }),
                    }
                    *slot = some_tags(tags);
                }
            }
            Ok(())
        })
    }

    pub(crate) fn describe_tags_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTagsRequest,
    ) -> Result<t::DescribeTagsResult, ServiceError> {
        authorize(ctx, "DescribeTags", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        self.with_region(ctx, |r| {
            let mut out = Vec::new();
            for (id, tags) in r.all_tags() {
                let rt = RegionState::resource_type(&id).unwrap_or_default();
                for tag in &tags {
                    let ok = filters.matches(None, |f| {
                        Some(match f {
                            "key" => s(&tag.key),
                            "value" => s(&tag.value),
                            "resource-id" => vec![id.clone()],
                            "resource-type" => vec![rt.to_string()],
                            _ => return None,
                        })
                    })?;
                    if ok {
                        out.push(t::TagDescription {
                            key: tag.key.clone(),
                            value: tag.value.clone(),
                            resource_id: Some(id.clone()),
                            resource_type: Some(rt.into()),
                        });
                    }
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeTagsResult { tags: Some(items), next_token })
        })
    }
}

fn check_key_name(name: &str) -> Result<(), ServiceError> {
    if name.is_empty() || name.chars().count() > 255 || !name.is_ascii() {
        return Err(invalid_parameter(format!("Invalid value '{name}' for keyName.")));
    }
    Ok(())
}

/// The ARN `CreateTags`/`DeleteTags` authorize for a resource id.
fn resource_arn(ctx: &RequestContext, account: &str, id: &str) -> String {
    let kind = RegionState::resource_type(id).unwrap_or("resource");
    match kind {
        "image" => format!("arn:{}:ec2:{}::image/{id}", ctx.partition, ctx.region),
        "snapshot" => format!("arn:{}:ec2:{}::snapshot/{id}", ctx.partition, ctx.region),
        _ => arn(ctx, account, &format!("{kind}/{id}")),
    }
}

fn not_found_for(id: &str) -> ServiceError {
    let kind = match id.rsplit_once('-').map(|(p, _)| p).unwrap_or_default() {
        "vpc" => Some(Kind::Vpc),
        "subnet" => Some(Kind::Subnet),
        "sg" => Some(Kind::Group),
        "rtb" => Some(Kind::RouteTable),
        "igw" => Some(Kind::InternetGateway),
        "nat" => Some(Kind::NatGateway),
        "eipalloc" => Some(Kind::Allocation),
        "eni" => Some(Kind::NetworkInterface),
        "acl" => Some(Kind::NetworkAcl),
        "dopt" => Some(Kind::DhcpOptions),
        "ami" => Some(Kind::Image),
        "i" => Some(Kind::Instance),
        "vol" => Some(Kind::Volume),
        "snap" => Some(Kind::Snapshot),
        "key" => Some(Kind::KeyPairId),
        "vpce" => Some(Kind::VpcEndpoint),
        "pl" => Some(Kind::PrefixList),
        "eigw" => Some(Kind::EgressOnlyInternetGateway),
        "cagw" => Some(Kind::CarrierGateway),
        "cgw" => Some(Kind::CustomerGateway),
        "vgw" => Some(Kind::VpnGateway),
        "vpn" => Some(Kind::VpnConnection),
        "pcx" => Some(Kind::VpcPeeringConnection),
        "tgw" => Some(Kind::TransitGateway),
        "tgw-attach" => Some(Kind::TransitGatewayAttachment),
        "tgw-rtb" => Some(Kind::TransitGatewayRouteTable),
        "fl" => Some(Kind::FlowLog),
        "scr" => Some(Kind::SubnetCidrReservation),
        _ => None,
    };
    match kind {
        Some(k) => match k.check(id) {
            Err(e) => e,
            Ok(()) => k.not_found(id),
        },
        None => err("InvalidID", format!("The ID '{id}' is not valid")),
    }
}
