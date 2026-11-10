//! IAM condition keys of EC2 resources, as the Service Authorization
//! Reference lists them per resource type: `ec2:Vpc` on VPC-scoped
//! resources, the instance and volume attributes, and the resource tags.
//!
//! Every resource a request names (the VPC in `CreateSubnet`, the groups
//! in `RunInstances`, ...) is authorized with its own keys, so policies
//! such as "only in tagged VPCs" or "only security groups in VPC X" see
//! the same values they see on AWS.

use mws_core::{ConditionContext, RequestContext};

use crate::generated::types as t;
use crate::state::RegionState;
use crate::util::{arn, resource_tag_context};
use crate::Ec2;

fn put(c: &mut ConditionContext, key: &str, value: Option<String>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        c.insert(key.to_string(), vec![v]);
    }
}

fn vpc_arn(ctx: &RequestContext, account: &str, vpc: &Option<String>) -> Option<String> {
    vpc.as_ref().map(|v| arn(ctx, account, &format!("vpc/{v}")))
}

fn subnet_arn(ctx: &RequestContext, account: &str, subnet: &Option<String>) -> Option<String> {
    subnet.as_ref().map(|s| arn(ctx, account, &format!("subnet/{s}")))
}

/// `ec2:Vpc` for a resource in `vpc`.
pub(crate) fn in_vpc(ctx: &RequestContext, account: &str, vpc: &str) -> ConditionContext {
    let mut c = ConditionContext::new();
    put(&mut c, "ec2:Vpc", vpc_arn(ctx, account, &Some(vpc.to_string())));
    c
}

/// The attributes of a volume, new or existing, as condition keys.
pub(crate) struct VolumeKeys<'a> {
    pub volume_type: &'a str,
    pub size: Option<i32>,
    pub encrypted: bool,
    pub iops: Option<i32>,
    pub throughput: Option<i32>,
    pub zone: Option<&'a str>,
    pub snapshot_id: Option<&'a str>,
    pub kms_key_id: Option<&'a str>,
}

/// `ec2:VolumeType`, `ec2:VolumeSize`, `ec2:Encrypted`, `ec2:VolumeIops`,
/// `ec2:VolumeThroughput`, `ec2:AvailabilityZone` and `ec2:ParentSnapshot`
/// on `volume/*`.
pub(crate) fn volume_keys(ctx: &RequestContext, v: &VolumeKeys) -> ConditionContext {
    let mut c = ConditionContext::new();
    put(&mut c, "ec2:VolumeType", Some(v.volume_type.to_string()));
    put(&mut c, "ec2:VolumeSize", v.size.map(|s| s.to_string()));
    put(&mut c, "ec2:Encrypted", Some(v.encrypted.to_string()));
    put(&mut c, "ec2:VolumeIops", v.iops.map(|s| s.to_string()));
    put(&mut c, "ec2:VolumeThroughput", v.throughput.map(|s| s.to_string()));
    put(&mut c, "ec2:AvailabilityZone", v.zone.map(str::to_string));
    put(&mut c, "ec2:ParentSnapshot", v.snapshot_id.map(|s| crate::ops::ebs::snapshot_arn(ctx, s)));
    put(&mut c, "ec2:KmsKeyId", v.kms_key_id.map(str::to_string));
    c
}

/// The keys of an existing volume.
pub(crate) fn volume(ctx: &RequestContext, v: &t::Volume) -> ConditionContext {
    let mut c = resource_tag_context(v.tags.as_ref());
    c.extend(volume_keys(
        ctx,
        &VolumeKeys {
            volume_type: v.volume_type.as_deref().unwrap_or("gp2"),
            size: v.size,
            encrypted: v.encrypted.unwrap_or(false),
            iops: v.iops,
            throughput: v.throughput,
            zone: v.availability_zone.as_deref(),
            snapshot_id: v.snapshot_id.as_deref().filter(|s| !s.is_empty()),
            kms_key_id: v.kms_key_id.as_deref(),
        },
    ));
    c
}

/// The launch attributes of an instance, new or existing, as condition keys.
#[derive(Default)]
pub(crate) struct InstanceKeys {
    pub instance_type: Option<String>,
    pub zone: Option<String>,
    pub tenancy: Option<String>,
    pub instance_profile: Option<String>,
    pub root_device_type: Option<String>,
    pub ebs_optimized: Option<bool>,
    pub http_tokens: Option<String>,
    pub http_endpoint: Option<String>,
    pub hop_limit: Option<i32>,
    pub metadata_tags: Option<String>,
    pub placement_group: Option<String>,
    pub vpc: Option<String>,
    pub subnet: Option<String>,
}

/// `ec2:InstanceType`, `ec2:Tenancy`, `ec2:InstanceProfile`,
/// `ec2:RootDeviceType`, `ec2:EbsOptimized`, the `ec2:Metadata*` keys,
/// `ec2:AvailabilityZone`, `ec2:PlacementGroup`, `ec2:Vpc` and
/// `ec2:Subnet` on `instance/*`.
pub(crate) fn instance_keys(ctx: &RequestContext, account: &str, k: InstanceKeys) -> ConditionContext {
    let mut c = ConditionContext::new();
    put(&mut c, "ec2:InstanceType", k.instance_type);
    put(&mut c, "ec2:AvailabilityZone", k.zone);
    put(&mut c, "ec2:Tenancy", k.tenancy);
    put(&mut c, "ec2:InstanceProfile", k.instance_profile);
    put(&mut c, "ec2:RootDeviceType", k.root_device_type);
    put(&mut c, "ec2:EbsOptimized", k.ebs_optimized.map(|b| b.to_string()));
    put(&mut c, "ec2:MetadataHttpTokens", k.http_tokens);
    put(&mut c, "ec2:MetadataHttpEndpoint", k.http_endpoint);
    put(&mut c, "ec2:MetadataHttpPutResponseHopLimit", k.hop_limit.map(|h| h.to_string()));
    put(&mut c, "ec2:InstanceMetadataTags", k.metadata_tags);
    put(
        &mut c,
        "ec2:PlacementGroup",
        k.placement_group.as_ref().map(|g| arn(ctx, account, &format!("placement-group/{g}"))),
    );
    put(&mut c, "ec2:Vpc", vpc_arn(ctx, account, &k.vpc));
    put(&mut c, "ec2:Subnet", subnet_arn(ctx, account, &k.subnet));
    c
}

/// The keys of an existing instance.
pub(crate) fn instance(ctx: &RequestContext, account: &str, i: &t::Instance) -> ConditionContext {
    let mut c = resource_tag_context(i.tags.as_ref());
    let placement = i.placement.clone().unwrap_or_default();
    let md = i.metadata_options.clone().unwrap_or_default();
    c.extend(instance_keys(
        ctx,
        account,
        InstanceKeys {
            instance_type: i.instance_type.clone(),
            zone: placement.availability_zone,
            tenancy: placement.tenancy,
            instance_profile: i.iam_instance_profile.as_ref().and_then(|p| p.arn.clone()),
            root_device_type: i.root_device_type.clone(),
            ebs_optimized: i.ebs_optimized,
            http_tokens: md.http_tokens,
            http_endpoint: md.http_endpoint,
            hop_limit: md.http_put_response_hop_limit,
            metadata_tags: md.instance_metadata_tags,
            placement_group: placement.group_name,
            vpc: i.vpc_id.clone(),
            subnet: i.subnet_id.clone(),
        },
    ));
    c
}

/// The condition keys of the existing resource `resource` (an EC2 ARN),
/// or just `ec2:Region` context for a wildcard or unknown one.
pub(crate) fn existing(r: &RegionState, ctx: &RequestContext, account: &str, resource: &str) -> ConditionContext {
    let Some(path) = resource.splitn(6, ':').nth(5) else {
        return ConditionContext::new();
    };
    let Some((kind, id)) = path.split_once('/') else {
        return ConditionContext::new();
    };
    let vpc_scoped = |tags: Option<&Vec<t::Tag>>, vpc: &Option<String>| {
        let mut c = resource_tag_context(tags);
        put(&mut c, "ec2:Vpc", vpc_arn(ctx, account, vpc));
        c
    };
    match kind {
        "vpc" => r
            .vpcs
            .get(id)
            .map(|v| {
                let mut c = resource_tag_context(v.vpc.tags.as_ref());
                put(&mut c, "ec2:VpcID", Some(id.to_string()));
                put(&mut c, "ec2:Tenancy", v.vpc.instance_tenancy.clone());
                c
            })
            .unwrap_or_default(),
        "subnet" => r
            .subnets
            .get(id)
            .map(|s| {
                let mut c = vpc_scoped(s.tags.as_ref(), &s.vpc_id);
                put(&mut c, "ec2:SubnetID", Some(id.to_string()));
                put(&mut c, "ec2:AvailabilityZone", s.availability_zone.clone());
                c
            })
            .unwrap_or_default(),
        "security-group" => r
            .security_groups
            .get(id)
            .map(|g| {
                let mut c = vpc_scoped(g.tags.as_ref(), &g.vpc_id);
                put(&mut c, "ec2:SecurityGroupID", Some(id.to_string()));
                c
            })
            .unwrap_or_default(),
        "network-interface" => r
            .network_interfaces
            .get(id)
            .map(|n| {
                let mut c = vpc_scoped(n.tag_set.as_ref(), &n.vpc_id);
                put(&mut c, "ec2:NetworkInterfaceID", Some(id.to_string()));
                put(&mut c, "ec2:Subnet", subnet_arn(ctx, account, &n.subnet_id));
                put(&mut c, "ec2:AvailabilityZone", n.availability_zone.clone());
                c
            })
            .unwrap_or_default(),
        "route-table" => r
            .route_tables
            .get(id)
            .map(|rt| {
                let mut c = vpc_scoped(rt.tags.as_ref(), &rt.vpc_id);
                put(&mut c, "ec2:RouteTableID", Some(id.to_string()));
                c
            })
            .unwrap_or_default(),
        "network-acl" => r
            .network_acls
            .get(id)
            .map(|a| {
                let mut c = vpc_scoped(a.tags.as_ref(), &a.vpc_id);
                put(&mut c, "ec2:NetworkAclID", Some(id.to_string()));
                c
            })
            .unwrap_or_default(),
        "internet-gateway" => r
            .internet_gateways
            .get(id)
            .map(|g| {
                let mut c = resource_tag_context(g.tags.as_ref());
                put(&mut c, "ec2:InternetGatewayID", Some(id.to_string()));
                c
            })
            .unwrap_or_default(),
        "natgateway" => r.nat_gateways.get(id).map(|g| resource_tag_context(g.tags.as_ref())).unwrap_or_default(),
        "vpc-endpoint" => r
            .vpc_endpoints
            .get(id)
            .map(|e| {
                let mut c = resource_tag_context(e.tags.as_ref());
                put(&mut c, "ec2:VpceServiceName", e.service_name.clone());
                c
            })
            .unwrap_or_default(),
        "elastic-ip" => r
            .addresses
            .values()
            .find(|a| a.allocation_id.as_deref() == Some(id))
            .map(|a| {
                let mut c = resource_tag_context(a.tags.as_ref());
                put(&mut c, "ec2:Domain", a.domain.clone());
                put(&mut c, "ec2:PublicIpAddress", a.public_ip.clone());
                c
            })
            .unwrap_or_default(),
        "instance" => r.instances.get(id).map(|i| instance(ctx, account, &i.instance)).unwrap_or_default(),
        "volume" => r.volumes.get(id).map(|v| volume(ctx, v)).unwrap_or_default(),
        "key-pair" => r
            .key_pairs
            .get(id)
            .map(|k| {
                let mut c = resource_tag_context(k.info.tags.as_ref());
                put(&mut c, "ec2:KeyPairName", Some(id.to_string()));
                put(&mut c, "ec2:KeyPairType", k.info.key_type.clone());
                c
            })
            .unwrap_or_default(),
        "dhcp-options" => r.dhcp_options.get(id).map(|d| resource_tag_context(d.tags.as_ref())).unwrap_or_default(),
        "egress-only-internet-gateway" => {
            r.egress_only_internet_gateways.get(id).map(|g| resource_tag_context(g.tags.as_ref())).unwrap_or_default()
        }
        "transit-gateway" => {
            r.transit_gateways.get(id).map(|g| resource_tag_context(g.tags.as_ref())).unwrap_or_default()
        }
        "vpn-gateway" => r.vpn_gateways.get(id).map(|g| resource_tag_context(g.tags.as_ref())).unwrap_or_default(),
        "vpc-peering-connection" => {
            r.vpc_peering_connections.get(id).map(|p| resource_tag_context(p.tags.as_ref())).unwrap_or_default()
        }
        _ => ConditionContext::new(),
    }
}

impl Ec2 {
    /// The condition keys of the existing resource `resource` (an ARN).
    pub(crate) fn resource_context(&self, ctx: &RequestContext, resource: &str) -> ConditionContext {
        let account = crate::account_of(ctx);
        self.with_region(ctx, |r| existing(r, ctx, &account, resource))
    }

    /// Give each named resource its real condition keys, keeping the keys
    /// the caller already set (request tags, `ec2:CreateAction`, ...).
    pub(crate) fn with_resource_context(
        &self,
        ctx: &RequestContext,
        resources: Vec<(String, ConditionContext)>,
    ) -> Vec<(String, ConditionContext)> {
        let account = crate::account_of(ctx);
        self.with_region(ctx, |r| {
            resources
                .into_iter()
                .map(|(arn, mut c)| {
                    for (k, v) in existing(r, ctx, &account, &arn) {
                        c.entry(k).or_insert(v);
                    }
                    (arn, c)
                })
                .collect()
        })
    }
}

impl Ec2 {
    /// [`crate::util::authorize`], with every resource the request names
    /// given its real condition keys first.
    pub(crate) fn authorize_known(
        &self,
        ctx: &RequestContext,
        action: &str,
        resources: &[(String, ConditionContext)],
        dry_run: Option<bool>,
    ) -> Result<(), mws_core::ServiceError> {
        let resources = self.with_resource_context(ctx, resources.to_vec());
        crate::util::authorize(ctx, action, &resources, dry_run)
    }
}
