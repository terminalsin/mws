//! EC2 state: one [`RegionState`] per account and Region. Resources are kept
//! in their API shapes (the generated types), plus what the API does not
//! show.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types as t;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `{account}/{region}`.
    pub regions: BTreeMap<String, RegionState>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionState {
    /// Whether the default VPC and its companions have been made.
    pub initialized: bool,
    pub vpcs: BTreeMap<String, VpcRecord>,
    pub subnets: BTreeMap<String, t::Subnet>,
    pub security_groups: BTreeMap<String, t::SecurityGroup>,
    pub sg_rules: BTreeMap<String, SgRule>,
    pub route_tables: BTreeMap<String, t::RouteTable>,
    pub internet_gateways: BTreeMap<String, t::InternetGateway>,
    pub nat_gateways: BTreeMap<String, t::NatGateway>,
    pub addresses: BTreeMap<String, t::Address>,
    pub network_interfaces: BTreeMap<String, t::NetworkInterface>,
    pub network_acls: BTreeMap<String, t::NetworkAcl>,
    pub dhcp_options: BTreeMap<String, t::DhcpOptions>,
    /// By key name.
    pub key_pairs: BTreeMap<String, KeyPairRecord>,
    /// Images registered in this account (the public catalogue is not
    /// stored).
    pub images: BTreeMap<String, ImageRecord>,
    pub instances: BTreeMap<String, InstanceRecord>,
    pub volumes: BTreeMap<String, t::Volume>,
    pub snapshots: BTreeMap<String, t::Snapshot>,
    pub iam_associations: BTreeMap<String, t::IamInstanceProfileAssociation>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VpcRecord {
    pub vpc: t::Vpc,
    pub enable_dns_support: bool,
    pub enable_dns_hostnames: bool,
    pub enable_network_address_usage_metrics: bool,
}

/// One security group rule (`sgr-`).
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SgRule {
    pub id: String,
    pub group_id: String,
    pub egress: bool,
    /// `-1`, `tcp`, `udp`, `icmp`, `icmpv6` or a protocol number.
    pub protocol: String,
    pub from_port: Option<i32>,
    pub to_port: Option<i32>,
    pub cidr_ipv4: Option<String>,
    pub cidr_ipv6: Option<String>,
    pub prefix_list_id: Option<String>,
    pub referenced_group_id: Option<String>,
    pub referenced_user_id: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<t::Tag>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyPairRecord {
    pub info: t::KeyPairInfo,
    /// OpenSSH `authorized_keys` line.
    pub public_key: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageRecord {
    pub image: t::Image,
    /// The container image instances of this AMI run.
    pub container_image: String,
    /// Whether MWS boots it as an OS image (see `backend::LaunchSpec::boot`).
    pub boot: bool,
    /// Whether the container image was made by `CreateImage` (and so is
    /// removed with the AMI).
    pub owned_container_image: bool,
    /// Account ids with launch permission (besides the owner).
    pub launch_users: Vec<String>,
    pub launch_public: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InstanceRecord {
    pub instance: t::Instance,
    pub reservation_id: String,
    pub owner_id: String,
    pub requester_id: Option<String>,
    /// Base64 user data, as given.
    pub user_data: Option<String>,
    /// The backend's handle, once launched.
    pub handle: Option<String>,
    pub container_image: String,
    pub boot: bool,
    pub disable_api_termination: bool,
    pub disable_api_stop: bool,
    pub shutdown_behavior: String,
    pub terminated_at: Option<DateTime<Utc>>,
    /// Whether the instance gets a public address whenever it starts.
    pub public_ip_on_start: bool,
    /// The instance profile's role, for instance metadata credentials.
    pub role_arn: Option<String>,
    /// Bumped on every state change, so a background task finishing late
    /// does not overwrite a newer one.
    pub generation: u64,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}/{region}")
    }
}

impl RegionState {
    /// The tag list of any taggable resource, by id.
    pub fn tags_mut(&mut self, id: &str) -> Option<&mut Option<Vec<t::Tag>>> {
        let prefix = id.split('-').next().unwrap_or_default();
        match prefix {
            "vpc" => self.vpcs.get_mut(id).map(|v| &mut v.vpc.tags),
            "subnet" => self.subnets.get_mut(id).map(|v| &mut v.tags),
            "sg" => self.security_groups.get_mut(id).map(|v| &mut v.tags),
            "rtb" => self.route_tables.get_mut(id).map(|v| &mut v.tags),
            "igw" => self.internet_gateways.get_mut(id).map(|v| &mut v.tags),
            "nat" => self.nat_gateways.get_mut(id).map(|v| &mut v.tags),
            "eipalloc" => self.addresses.get_mut(id).map(|v| &mut v.tags),
            "eni" => self.network_interfaces.get_mut(id).map(|v| &mut v.tag_set),
            "acl" => self.network_acls.get_mut(id).map(|v| &mut v.tags),
            "dopt" => self.dhcp_options.get_mut(id).map(|v| &mut v.tags),
            "key" => self
                .key_pairs
                .values_mut()
                .find(|k| k.info.key_pair_id.as_deref() == Some(id))
                .map(|k| &mut k.info.tags),
            "ami" => self.images.get_mut(id).map(|v| &mut v.image.tags),
            "i" => self.instances.get_mut(id).map(|v| &mut v.instance.tags),
            "vol" => self.volumes.get_mut(id).map(|v| &mut v.tags),
            "snap" => self.snapshots.get_mut(id).map(|v| &mut v.tags),
            _ => None,
        }
    }

    /// The `DescribeTags` resource type of an id.
    pub fn resource_type(id: &str) -> Option<&'static str> {
        Some(match id.split('-').next().unwrap_or_default() {
            "vpc" => "vpc",
            "subnet" => "subnet",
            "sg" => "security-group",
            "sgr" => "security-group-rule",
            "rtb" => "route-table",
            "igw" => "internet-gateway",
            "nat" => "natgateway",
            "eipalloc" => "elastic-ip",
            "eni" => "network-interface",
            "acl" => "network-acl",
            "dopt" => "dhcp-options",
            "key" => "key-pair",
            "ami" => "image",
            "i" => "instance",
            "vol" => "volume",
            "snap" => "snapshot",
            _ => return None,
        })
    }

    /// Every taggable resource id with its tags.
    pub fn all_tags(&self) -> Vec<(String, Vec<t::Tag>)> {
        let mut out: Vec<(String, Vec<t::Tag>)> = Vec::new();
        let mut push = |id: Option<&String>, tags: &Option<Vec<t::Tag>>| {
            if let (Some(id), Some(tags)) = (id, tags) {
                if !tags.is_empty() {
                    out.push((id.clone(), tags.clone()));
                }
            }
        };
        for v in self.vpcs.values() {
            push(v.vpc.vpc_id.as_ref(), &v.vpc.tags);
        }
        for v in self.subnets.values() {
            push(v.subnet_id.as_ref(), &v.tags);
        }
        for v in self.security_groups.values() {
            push(v.group_id.as_ref(), &v.tags);
        }
        for v in self.route_tables.values() {
            push(v.route_table_id.as_ref(), &v.tags);
        }
        for v in self.internet_gateways.values() {
            push(v.internet_gateway_id.as_ref(), &v.tags);
        }
        for v in self.nat_gateways.values() {
            push(v.nat_gateway_id.as_ref(), &v.tags);
        }
        for v in self.addresses.values() {
            push(v.allocation_id.as_ref(), &v.tags);
        }
        for v in self.network_interfaces.values() {
            push(v.network_interface_id.as_ref(), &v.tag_set);
        }
        for v in self.network_acls.values() {
            push(v.network_acl_id.as_ref(), &v.tags);
        }
        for v in self.dhcp_options.values() {
            push(v.dhcp_options_id.as_ref(), &v.tags);
        }
        for v in self.key_pairs.values() {
            push(v.info.key_pair_id.as_ref(), &v.info.tags);
        }
        for v in self.images.values() {
            push(v.image.image_id.as_ref(), &v.image.tags);
        }
        for v in self.instances.values() {
            push(v.instance.instance_id.as_ref(), &v.instance.tags);
        }
        for v in self.volumes.values() {
            push(v.volume_id.as_ref(), &v.tags);
        }
        for v in self.snapshots.values() {
            push(v.snapshot_id.as_ref(), &v.tags);
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}
