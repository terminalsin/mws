//! Instances: launch, the state machine (pending, running, stopping,
//! stopped, shutting-down, terminated), attributes, console output and
//! instance profile associations. State changes report the transitional
//! state at once and settle when the compute backend finishes, as in EC2.

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::backend::{LaunchSpec, NetworkSpec};
use crate::catalog;
use crate::generated::types as t;
use crate::state::{InstanceRecord, RegionState};
use crate::util::{
    arn, b, err, invalid_parameter, missing_parameter, new_id, paginate, private_dns, request_tag_context,
    resource_tag_context, s, some_tags, tags_for, Filters, Kind,
};
use crate::{account_of, Ec2};

/// How long terminated instances stay visible.
const TERMINATED_VISIBLE_FOR: i64 = 3600;

pub fn state(name: &str) -> t::InstanceState {
    let code = match name {
        "pending" => 0,
        "running" => 16,
        "shutting-down" => 32,
        "terminated" => 48,
        "stopping" => 64,
        "stopped" => 80,
        _ => 0,
    };
    t::InstanceState { code: Some(code), name: Some(name.into()) }
}

pub fn state_name(rec: &InstanceRecord) -> String {
    rec.instance.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default()
}

/// Finish every transition at once: what a restored state's instances do
/// when nothing is left running them.
pub fn settle_all(r: &mut RegionState) {
    for rec in r.instances.values_mut() {
        let next = match state_name(rec).as_str() {
            "pending" => "running",
            "stopping" => "stopped",
            "shutting-down" => "terminated",
            _ => continue,
        };
        rec.instance.state = Some(state(next));
    }
}

/// Forget instances terminated more than an hour ago (emulated clock).
pub fn expire_terminated(r: &mut RegionState, now: DateTime<Utc>) {
    r.instances.retain(|_, i| i.terminated_at.is_none_or(|at| now - at < Duration::seconds(TERMINATED_VISIBLE_FOR)));
}

fn gmt(now: DateTime<Utc>) -> String {
    now.format("%Y-%m-%d %H:%M:%S GMT").to_string()
}

/// The instance as `DescribeInstances` shows it: network interfaces,
/// addresses, groups and volumes come from their own records.
pub fn render(r: &RegionState, rec: &InstanceRecord) -> t::Instance {
    let mut i = rec.instance.clone();
    let id = i.instance_id.clone().unwrap_or_default();
    let mut enis: Vec<&t::NetworkInterface> = r
        .network_interfaces
        .values()
        .filter(|n| n.attachment.as_ref().is_some_and(|a| a.instance_id.as_deref() == Some(id.as_str())))
        .collect();
    enis.sort_by_key(|n| n.attachment.as_ref().and_then(|a| a.device_index));
    i.network_interfaces = Some(
        enis.iter()
            .map(|n| {
                let att = n.attachment.clone().unwrap_or_default();
                let assoc = n.association.as_ref().map(|a| t::InstanceNetworkInterfaceAssociation {
                    ip_owner_id: a.ip_owner_id.clone(),
                    public_dns_name: a.public_dns_name.clone(),
                    public_ip: a.public_ip.clone(),
                    ..Default::default()
                });
                t::InstanceNetworkInterface {
                    association: assoc.clone(),
                    attachment: Some(t::InstanceNetworkInterfaceAttachment {
                        attach_time: att.attach_time,
                        attachment_id: att.attachment_id.clone(),
                        delete_on_termination: att.delete_on_termination,
                        device_index: att.device_index,
                        status: att.status.clone(),
                        network_card_index: att.network_card_index,
                        ..Default::default()
                    }),
                    description: n.description.clone(),
                    groups: n.groups.clone(),
                    ipv6_addresses: Some(Vec::new()),
                    mac_address: n.mac_address.clone(),
                    network_interface_id: n.network_interface_id.clone(),
                    owner_id: n.owner_id.clone(),
                    private_dns_name: n.private_dns_name.clone(),
                    private_ip_address: n.private_ip_address.clone(),
                    private_ip_addresses: Some(
                        n.private_ip_addresses
                            .iter()
                            .flatten()
                            .map(|p| t::InstancePrivateIpAddress {
                                association: if p.primary == Some(true) { assoc.clone() } else { None },
                                primary: p.primary,
                                private_dns_name: p.private_dns_name.clone(),
                                private_ip_address: p.private_ip_address.clone(),
                            })
                            .collect(),
                    ),
                    source_dest_check: n.source_dest_check,
                    status: n.status.clone(),
                    subnet_id: n.subnet_id.clone(),
                    vpc_id: n.vpc_id.clone(),
                    interface_type: n.interface_type.clone(),
                    ..Default::default()
                }
            })
            .collect(),
    );
    if let Some(primary) = enis.first() {
        i.security_groups = primary.groups.clone();
        i.source_dest_check = primary.source_dest_check;
        i.public_ip_address = primary.association.as_ref().and_then(|a| a.public_ip.clone());
        i.public_dns_name =
            Some(primary.association.as_ref().and_then(|a| a.public_dns_name.clone()).unwrap_or_default());
    } else {
        i.public_ip_address = None;
        i.public_dns_name = Some(String::new());
    }
    let terminated = state_name(rec) == "terminated";
    if terminated {
        i.private_ip_address = None;
        i.subnet_id = None;
        i.vpc_id = None;
        i.private_dns_name = Some(String::new());
    }
    let mut volumes: Vec<t::InstanceBlockDeviceMapping> = r
        .volumes
        .values()
        .flat_map(|v| {
            v.attachments.iter().flatten().filter(|a| a.instance_id.as_deref() == Some(id.as_str())).map(|a| {
                t::InstanceBlockDeviceMapping {
                    device_name: a.device.clone(),
                    ebs: Some(t::EbsInstanceBlockDevice {
                        attach_time: a.attach_time,
                        delete_on_termination: a.delete_on_termination,
                        status: a.state.clone(),
                        volume_id: a.volume_id.clone(),
                        ..Default::default()
                    }),
                }
            })
        })
        .collect();
    volumes.sort_by(|a, b| a.device_name.cmp(&b.device_name));
    i.block_device_mappings = Some(volumes);
    i.iam_instance_profile = r
        .iam_associations
        .values()
        .find(|a| a.instance_id.as_deref() == Some(id.as_str()) && a.state.as_deref() == Some("associated"))
        .and_then(|a| a.iam_instance_profile.clone());
    i
}

fn time(t: Option<DateTime<Utc>>) -> Vec<String> {
    t.map(|t| t.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()).into_iter().collect()
}

fn num(n: Option<i32>) -> Vec<String> {
    n.map(|n| n.to_string()).into_iter().collect()
}

/// The values of a DescribeInstances filter for one instance, `None` for a
/// filter name EC2 does not document.
fn instance_filter(r: &RegionState, i: &t::Instance, rec: &InstanceRecord, name: &str) -> Option<Vec<String>> {
    let enis = i.network_interfaces.clone().unwrap_or_default();
    // The instance's interfaces as DescribeNetworkInterfaces shows them.
    let full: Vec<&t::NetworkInterface> = enis
        .iter()
        .filter_map(|n| n.network_interface_id.as_ref().and_then(|id| r.network_interfaces.get(id)))
        .collect();
    let eni =
        |f: &dyn Fn(&t::NetworkInterface) -> Vec<String>| -> Vec<String> { full.iter().flat_map(|n| f(n)).collect() };
    let addrs = |f: &dyn Fn(&t::NetworkInterfacePrivateIpAddress) -> Vec<String>| -> Vec<String> {
        full.iter().flat_map(|n| n.private_ip_addresses.iter().flatten()).flat_map(f).collect()
    };
    let attachment = |f: &dyn Fn(&t::InstanceNetworkInterfaceAttachment) -> Vec<String>| -> Vec<String> {
        enis.iter().filter_map(|n| n.attachment.as_ref()).flat_map(f).collect()
    };
    let bdm = |f: &dyn Fn(&t::InstanceBlockDeviceMapping, &t::EbsInstanceBlockDevice) -> Vec<String>| -> Vec<String> {
        i.block_device_mappings.iter().flatten().filter_map(|m| m.ebs.as_ref().map(|e| f(m, e))).flatten().collect()
    };
    let groups = i.security_groups.clone().unwrap_or_default();
    let placement = i.placement.clone().unwrap_or_default();
    let st = i.state.clone().unwrap_or_default();
    let md = i.metadata_options.clone().unwrap_or_default();
    let crs = i.capacity_reservation_specification.clone().unwrap_or_default();
    let dns_opts = i.private_dns_name_options.clone().unwrap_or_default();
    let profile = i.iam_instance_profile.clone().unwrap_or_default();
    if let Some(key) = name.strip_prefix("network-interface.tag:") {
        return Some(eni(&|n| {
            n.tag_set
                .iter()
                .flatten()
                .filter(|t| t.key.as_deref() == Some(key))
                .filter_map(|t| t.value.clone())
                .collect()
        }));
    }
    Some(match name {
        "affinity" => s(&placement.affinity),
        "architecture" => s(&i.architecture),
        "availability-zone" => s(&placement.availability_zone),
        "availability-zone-id" => s(&placement.availability_zone_id),
        "block-device-mapping.attach-time" => bdm(&|_, e| time(e.attach_time)),
        "block-device-mapping.delete-on-termination" => bdm(&|_, e| b(e.delete_on_termination)),
        "block-device-mapping.device-name" => bdm(&|m, _| s(&m.device_name)),
        "block-device-mapping.status" => bdm(&|_, e| s(&e.status)),
        "block-device-mapping.volume-id" => bdm(&|_, e| s(&e.volume_id)),
        "boot-mode" => s(&i.boot_mode),
        "current-instance-boot-mode" => s(&i.current_instance_boot_mode),
        "capacity-reservation-id" => s(&i.capacity_reservation_id),
        "capacity-reservation-specification.capacity-reservation-preference" => s(&crs.capacity_reservation_preference),
        "capacity-reservation-specification.capacity-reservation-target.capacity-reservation-id" => {
            crs.capacity_reservation_target.as_ref().map(|t| s(&t.capacity_reservation_id)).unwrap_or_default()
        }
        "capacity-reservation-specification.capacity-reservation-target.capacity-reservation-resource-group-arn" => crs
            .capacity_reservation_target
            .as_ref()
            .map(|t| s(&t.capacity_reservation_resource_group_arn))
            .unwrap_or_default(),
        "client-token" => s(&i.client_token),
        "dns-name" => s(&i.public_dns_name),
        "ebs-optimized" => b(i.ebs_optimized),
        "ena-support" => b(i.ena_support),
        "enclave-options.enabled" => b(i.enclave_options.as_ref().and_then(|o| o.enabled)),
        "hibernation-options.configured" => b(i.hibernation_options.as_ref().and_then(|o| o.configured)),
        "host-id" => s(&placement.host_id),
        "hypervisor" => s(&i.hypervisor),
        "iam-instance-profile.arn" => s(&profile.arn),
        "iam-instance-profile.id" => s(&profile.id),
        "image-id" => s(&i.image_id),
        "instance-id" => s(&i.instance_id),
        "instance-lifecycle" => s(&i.instance_lifecycle),
        "instance-state-code" => num(st.code),
        "instance-state-name" => s(&st.name),
        "instance-type" => s(&i.instance_type),
        "instance.group-id" | "group-id" => groups.iter().filter_map(|g| g.group_id.clone()).collect(),
        "instance.group-name" | "group-name" => groups.iter().filter_map(|g| g.group_name.clone()).collect(),
        "ip-address" => s(&i.public_ip_address),
        "ipv6-address" => {
            let mut v = s(&i.ipv6_address);
            v.extend(
                enis.iter().flat_map(|n| n.ipv6_addresses.iter().flatten()).filter_map(|a| a.ipv6_address.clone()),
            );
            v
        }
        "kernel-id" => s(&i.kernel_id),
        "key-name" => s(&i.key_name),
        "launch-index" | "ami-launch-index" => num(i.ami_launch_index),
        "launch-time" => time(i.launch_time),
        "maintenance-options.auto-recovery" => s(&i.maintenance_options.as_ref().and_then(|m| m.auto_recovery.clone())),
        "metadata-options.http-endpoint" => s(&md.http_endpoint),
        "metadata-options.http-protocol-ipv4" => {
            if md.http_endpoint.is_some() {
                vec!["enabled".into()]
            } else {
                Vec::new()
            }
        }
        "metadata-options.http-protocol-ipv6" => s(&md.http_protocol_ipv6),
        "metadata-options.http-put-response-hop-limit" => num(md.http_put_response_hop_limit),
        "metadata-options.http-tokens" => s(&md.http_tokens),
        "metadata-options.instance-metadata-tags" => s(&md.instance_metadata_tags),
        "metadata-options.state" => s(&md.state),
        "monitoring-state" => i.monitoring.as_ref().map(|m| s(&m.state)).unwrap_or_default(),
        "network-interface.addresses.association.allocation-id" => {
            addrs(&|a| a.association.as_ref().map(|x| s(&x.allocation_id)).unwrap_or_default())
        }
        "network-interface.addresses.association.association-id" => {
            addrs(&|a| a.association.as_ref().map(|x| s(&x.association_id)).unwrap_or_default())
        }
        "network-interface.addresses.association.carrier-ip" => {
            addrs(&|a| a.association.as_ref().map(|x| s(&x.carrier_ip)).unwrap_or_default())
        }
        "network-interface.addresses.association.customer-owned-ip" => {
            addrs(&|a| a.association.as_ref().map(|x| s(&x.customer_owned_ip)).unwrap_or_default())
        }
        "network-interface.addresses.association.ip-owner-id" => {
            addrs(&|a| a.association.as_ref().map(|x| s(&x.ip_owner_id)).unwrap_or_default())
        }
        "network-interface.addresses.association.public-dns-name" => {
            addrs(&|a| a.association.as_ref().map(|x| s(&x.public_dns_name)).unwrap_or_default())
        }
        "network-interface.addresses.association.public-ip" => {
            addrs(&|a| a.association.as_ref().map(|x| s(&x.public_ip)).unwrap_or_default())
        }
        "network-interface.addresses.primary" => addrs(&|a| b(a.primary)),
        "network-interface.addresses.private-dns-name" => addrs(&|a| s(&a.private_dns_name)),
        "network-interface.addresses.private-ip-address" | "network-interface.private-ip-address" => {
            addrs(&|a| s(&a.private_ip_address))
        }
        "network-interface.association.allocation-id" => {
            eni(&|n| n.association.as_ref().map(|x| s(&x.allocation_id)).unwrap_or_default())
        }
        "network-interface.association.association-id" => {
            eni(&|n| n.association.as_ref().map(|x| s(&x.association_id)).unwrap_or_default())
        }
        "network-interface.association.carrier-ip" => {
            eni(&|n| n.association.as_ref().map(|x| s(&x.carrier_ip)).unwrap_or_default())
        }
        "network-interface.association.customer-owned-ip" => {
            eni(&|n| n.association.as_ref().map(|x| s(&x.customer_owned_ip)).unwrap_or_default())
        }
        "network-interface.association.ip-owner-id" => {
            eni(&|n| n.association.as_ref().map(|x| s(&x.ip_owner_id)).unwrap_or_default())
        }
        "network-interface.association.public-dns-name" => {
            eni(&|n| n.association.as_ref().map(|x| s(&x.public_dns_name)).unwrap_or_default())
        }
        "network-interface.association.public-ip" => {
            eni(&|n| n.association.as_ref().map(|x| s(&x.public_ip)).unwrap_or_default())
        }
        "network-interface.attachment.attach-time" => attachment(&|a| time(a.attach_time)),
        "network-interface.attachment.attachment-id" => attachment(&|a| s(&a.attachment_id)),
        "network-interface.attachment.delete-on-termination" => attachment(&|a| b(a.delete_on_termination)),
        "network-interface.attachment.device-index" => attachment(&|a| num(a.device_index)),
        "network-interface.attachment.instance-id" => {
            if enis.iter().any(|n| n.attachment.is_some()) {
                s(&i.instance_id)
            } else {
                Vec::new()
            }
        }
        "network-interface.attachment.instance-owner-id" => {
            if enis.iter().any(|n| n.attachment.is_some()) {
                vec![rec.owner_id.clone()]
            } else {
                Vec::new()
            }
        }
        "network-interface.attachment.network-card-index" => attachment(&|a| num(a.network_card_index)),
        "network-interface.attachment.status" => attachment(&|a| s(&a.status)),
        "network-interface.availability-zone" => eni(&|n| s(&n.availability_zone)),
        "network-interface.deny-all-igw-traffic" => eni(&|n| b(n.deny_all_igw_traffic)),
        "network-interface.description" => eni(&|n| s(&n.description)),
        "network-interface.group-id" => {
            eni(&|n| n.groups.iter().flatten().filter_map(|g| g.group_id.clone()).collect())
        }
        "network-interface.group-name" => {
            eni(&|n| n.groups.iter().flatten().filter_map(|g| g.group_name.clone()).collect())
        }
        "network-interface.ipv4-prefixes.ipv4-prefix" => {
            enis.iter().flat_map(|n| n.ipv4_prefixes.iter().flatten()).filter_map(|p| p.ipv4_prefix.clone()).collect()
        }
        "network-interface.ipv6-address" | "network-interface.ipv6-addresses.ipv6-address" => {
            enis.iter().flat_map(|n| n.ipv6_addresses.iter().flatten()).filter_map(|a| a.ipv6_address.clone()).collect()
        }
        "network-interface.ipv6-addresses.is-primary-ipv6" => {
            enis.iter().flat_map(|n| n.ipv6_addresses.iter().flatten()).flat_map(|a| b(a.is_primary_ipv6)).collect()
        }
        "network-interface.ipv6-native" => eni(&|n| b(n.ipv6_native)),
        "network-interface.ipv6-prefixes.ipv6-prefix" => {
            enis.iter().flat_map(|n| n.ipv6_prefixes.iter().flatten()).filter_map(|p| p.ipv6_prefix.clone()).collect()
        }
        "network-interface.mac-address" => enis.iter().filter_map(|n| n.mac_address.clone()).collect(),
        "network-interface.network-interface-id" => {
            enis.iter().filter_map(|n| n.network_interface_id.clone()).collect()
        }
        "network-interface.outpost-arn" => eni(&|n| s(&n.outpost_arn)),
        "network-interface.owner-id" => enis.iter().filter_map(|n| n.owner_id.clone()).collect(),
        "network-interface.private-dns-name" => enis.iter().filter_map(|n| n.private_dns_name.clone()).collect(),
        "network-interface.public-dns-name" => eni(&|n| s(&n.public_dns_name)),
        "network-interface.requester-id" => eni(&|n| s(&n.requester_id)),
        "network-interface.requester-managed" => eni(&|n| b(n.requester_managed)),
        "network-interface.status" => enis.iter().filter_map(|n| n.status.clone()).collect(),
        "network-interface.source-dest-check" => enis.iter().flat_map(|n| b(n.source_dest_check)).collect(),
        "network-interface.subnet-id" => enis.iter().filter_map(|n| n.subnet_id.clone()).collect(),
        "network-interface.tag-key" => eni(&|n| n.tag_set.iter().flatten().filter_map(|t| t.key.clone()).collect()),
        "network-interface.tag-value" => eni(&|n| n.tag_set.iter().flatten().filter_map(|t| t.value.clone()).collect()),
        "network-interface.vpc-id" => enis.iter().filter_map(|n| n.vpc_id.clone()).collect(),
        "network-performance-options.bandwidth-weighting" => {
            s(&i.network_performance_options.as_ref().and_then(|o| o.bandwidth_weighting.clone()))
        }
        "operator.managed" => b(i.operator.as_ref().and_then(|o| o.managed).or(Some(false))),
        "operator.principal" => s(&i.operator.as_ref().and_then(|o| o.principal.clone())),
        "outpost-arn" => s(&i.outpost_arn),
        "owner-id" => vec![rec.owner_id.clone()],
        "placement-group-name" => s(&placement.group_name),
        "placement-partition-number" => num(placement.partition_number),
        "platform" => s(&i.platform),
        "platform-details" => s(&i.platform_details),
        "private-dns-name" => s(&i.private_dns_name),
        "private-dns-name-options.enable-resource-name-dns-a-record" => b(dns_opts.enable_resource_name_dns_a_record),
        "private-dns-name-options.enable-resource-name-dns-aaaa-record" => {
            b(dns_opts.enable_resource_name_dns_aaaa_record)
        }
        "private-dns-name-options.hostname-type" => s(&dns_opts.hostname_type),
        "private-ip-address" => s(&i.private_ip_address),
        "product-code" => i.product_codes.iter().flatten().filter_map(|p| p.product_code_id.clone()).collect(),
        "product-code.type" => i.product_codes.iter().flatten().filter_map(|p| p.product_code_type.clone()).collect(),
        "ramdisk-id" => s(&i.ramdisk_id),
        "reason" => s(&i.state_transition_reason),
        "requester-id" => rec.requester_id.clone().into_iter().collect(),
        "reservation-id" => vec![rec.reservation_id.clone()],
        "root-device-name" => s(&i.root_device_name),
        "root-device-type" => s(&i.root_device_type),
        "source-dest-check" => b(i.source_dest_check),
        "spot-instance-request-id" => s(&i.spot_instance_request_id),
        "state-reason-code" => i.state_reason.as_ref().map(|r| s(&r.code)).unwrap_or_default(),
        "state-reason-message" => i.state_reason.as_ref().map(|r| s(&r.message)).unwrap_or_default(),
        "subnet-id" => s(&i.subnet_id),
        "tenancy" => s(&placement.tenancy),
        "tpm-support" => s(&i.tpm_support),
        "usage-operation" => s(&i.usage_operation),
        "usage-operation-update-time" => time(i.usage_operation_update_time),
        "virtualization-type" => s(&i.virtualization_type),
        "vpc-id" => s(&i.vpc_id),
        _ => return None,
    })
}

/// What a background task does to an instance through the backend.
enum Transition {
    Launch(Box<LaunchSpec>),
    Start,
    Stop { force: bool },
    Terminate,
    Reboot,
}

/// `ws://` hosts as an instance's container sees MWS: loopback names
/// become the Docker host gateway.
fn endpoint_for_instance(endpoint: &str) -> String {
    for local in ["127.0.0.1", "localhost", "0.0.0.0", "[::1]"] {
        if let Some(rest) = endpoint.strip_prefix(&format!("http://{local}")) {
            return format!("http://host.docker.internal{rest}");
        }
    }
    endpoint.to_string()
}

impl Ec2 {
    /// Run `transition` for an instance in the background, then settle its
    /// state unless something newer changed it meanwhile. The metadata
    /// backend has nothing to wait for: it settles after the configured
    /// transition delay ([`Ec2::set_transition_delay`]), or inline when
    /// that is zero.
    async fn transition(
        &self,
        ctx: &RequestContext,
        account: &str,
        instance_id: &str,
        generation: u64,
        transition: Transition,
    ) {
        let this = self.clone();
        let ctx = ctx.clone();
        let account = account.to_string();
        let region = ctx.region.clone();
        let id = instance_id.to_string();
        let backend = self.backend();
        let delay = if backend.name() == "metadata" { Some(self.transition_delay()) } else { None };
        let inline = delay.is_some_and(|d| d.is_zero());
        let handle =
            self.with_region_of(&account, &region, &ctx, |r| r.instances.get(&id).and_then(|i| i.handle.clone()));
        let task = async move {
            let result = match (&transition, &handle) {
                (Transition::Launch(spec), _) => backend.launch(spec).await.map(|l| Some(l.handle)),
                (Transition::Start, Some(h)) => backend.start(h).await.map(|_| None),
                (Transition::Stop { force }, Some(h)) => backend.stop(h, *force).await.map(|_| None),
                (Transition::Terminate, Some(h)) => backend.terminate(h).await.map(|_| None),
                (Transition::Reboot, Some(h)) => backend.reboot(h).await.map(|_| None),
                (_, None) => Ok(None),
            };
            if let Some(d) = delay.filter(|d| !d.is_zero() && !matches!(transition, Transition::Reboot)) {
                tokio::time::sleep(d).await;
            }
            if let Err(e) = &result {
                tracing::warn!(instance = %id, backend = backend.name(), "instance backend operation failed: {e}");
            }
            // A booted instance's network namespace is new: give it its
            // security groups before it runs anything.
            if matches!(transition, Transition::Launch(_) | Transition::Start | Transition::Reboot) {
                if let Some(h) = result.as_ref().ok().and_then(|h| h.clone()).or_else(|| handle.clone()) {
                    this.firewall_on_boot(&account, &region, &id, &h).await;
                }
            }
            let now = chrono::Utc::now().max(ctx.received_at);
            let region_name = region.clone();
            let deleted = this.with_region_of(&account, &region, &ctx, |r| {
                let mut deleted = Vec::new();
                let Some(rec) = r.instances.get_mut(&id) else { return deleted };
                if rec.generation != generation {
                    return deleted;
                }
                match (transition, result) {
                    (Transition::Launch(_), Ok(h)) | (Transition::Start, Ok(h)) => {
                        rec.handle = h.or(rec.handle.take());
                        rec.instance.state = Some(state("running"));
                    }
                    (Transition::Launch(_), Err(e)) | (Transition::Start, Err(e)) => {
                        rec.instance.state = Some(state("terminated"));
                        rec.instance.state_transition_reason = Some("Server.InternalError".into());
                        rec.instance.state_reason = Some(t::StateReason {
                            code: Some("Server.InternalError".into()),
                            message: Some(format!("Server.InternalError: Internal error on launch ({e})")),
                        });
                        rec.terminated_at = Some(now);
                        deleted = release_resources(r, &id, &region_name);
                    }
                    (Transition::Stop { .. }, _) => {
                        rec.instance.state = Some(state("stopped"));
                    }
                    (Transition::Terminate, _) => {
                        rec.instance.state = Some(state("terminated"));
                        rec.handle = None;
                    }
                    (Transition::Reboot, _) => {}
                }
                deleted
            });
            this.sync_firewalls();
            for v in deleted {
                this.volume_job(crate::volumes::VolumeJob::Delete(v));
            }
        };
        if inline {
            task.await;
        } else {
            tokio::spawn(task);
        }
    }

    pub(crate) async fn run_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::RunInstancesRequest,
    ) -> Result<t::Reservation, ServiceError> {
        self.run_instances_with(ctx, input, Vec::new(), None).await
    }

    /// `RunInstances` for another AWS service (EC2 Auto Scaling), which may
    /// add `aws:` system tags (`aws:autoscaling:groupName`) to the
    /// instances. Authorization is the caller's: pass a context whose
    /// caller is the service's role.
    pub async fn run_instances_as_service(
        &self,
        ctx: &RequestContext,
        input: t::RunInstancesRequest,
        system_tags: Vec<t::Tag>,
    ) -> Result<t::Reservation, ServiceError> {
        self.run_instances_with(ctx, input, system_tags, None).await
    }

    /// `RunInstances` with `aws:` system tags, and for Spot requests that
    /// already exist (`RequestSpotInstances`, fleets), the request the
    /// instance fulfils.
    pub(crate) async fn run_instances_with(
        &self,
        ctx: &RequestContext,
        input: t::RunInstancesRequest,
        mut system_tags: Vec<t::Tag>,
        spot_request_id: Option<String>,
    ) -> Result<t::Reservation, ServiceError> {
        let account = account_of(ctx);
        let mut template_resource = None;
        let fingerprint = crate::idempotency::fingerprint(&input);
        let input = match input.launch_template.clone() {
            Some(spec) => {
                let lt = self.resolve_launch_template(ctx, &spec)?;
                let mut merged = super::launch_template::merge_run_instances(&lt.data, &input);
                merged.launch_template = None;
                system_tags.push(t::Tag { key: Some("aws:ec2launchtemplate:id".into()), value: Some(lt.id.clone()) });
                system_tags.push(t::Tag {
                    key: Some("aws:ec2launchtemplate:version".into()),
                    value: Some(lt.version.to_string()),
                });
                template_resource = Some(super::launch_template::template_arn(ctx, &account, &lt.id));
                merged
            }
            None => input,
        };
        if input.min_count < 1 {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter minCount is invalid. Expected a positive integer.",
                input.min_count
            )));
        }
        if input.max_count < input.min_count {
            return Err(invalid_parameter(format!(
                "Value ({}) for parameter maxCount is invalid. Expected a value greater than or equal to minCount.",
                input.max_count
            )));
        }
        let spot = match input.instance_market_options.as_ref().and_then(|m| m.market_type.as_deref()) {
            None => false,
            Some("spot") => true,
            Some(other) => {
                return Err(err("Unsupported", format!("The market type '{other}' is not supported for this request.")))
            }
        };
        let image_id = input.image_id.clone().ok_or_else(|| missing_parameter("ImageId"))?;
        let image = self.find_image(ctx, &image_id)?;
        if image.record.image.state.as_deref() == Some("disabled") {
            return Err(err("InvalidAMIID.Unavailable", format!("AMI '{image_id}' is disabled, and cannot be run")));
        }
        if image.record.image.state.as_deref() != Some("available") {
            return Err(err("InvalidAMIID.Unavailable", format!("AMI '{image_id}' is pending, and cannot be run")));
        }
        let instance_type = input.instance_type.clone().unwrap_or_else(|| "m1.small".into());
        let itype = catalog::instance_type(&instance_type)
            .ok_or_else(|| invalid_parameter(format!("Invalid value '{instance_type}' for InstanceType.")))?;
        let image_arch = image.record.image.architecture.clone().unwrap_or_else(|| "x86_64".into());
        if itype.arch != image_arch {
            return Err(invalid_parameter(format!(
                "The architecture '{}' of the specified instance type does not match the architecture '{image_arch}' of the specified AMI. Specify an instance type and an AMI that have matching architectures, and try again. You can use 'describe-instance-types' or 'describe-images' to discover the architecture of the instance type or AMI.",
                itype.arch
            )));
        }
        let tags = tags_for(&input.tag_specifications, "instance", &["instance", "volume", "network-interface"])?;
        let volume_tags = tags_for(&input.tag_specifications, "volume", &["instance", "volume", "network-interface"])?;
        let eni_tags =
            tags_for(&input.tag_specifications, "network-interface", &["instance", "volume", "network-interface"])?;
        let user_data_raw = match &input.user_data {
            Some(u) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(u.trim())
                    .map_err(|_| invalid_parameter("Invalid BASE64 encoding of user data."))?,
            ),
            None => None,
        };
        if user_data_raw.as_ref().is_some_and(|u| u.len() > 16384) {
            return Err(invalid_parameter("User data is limited to 16384 bytes"));
        }
        let ni_spec = input.network_interfaces.clone().unwrap_or_default();
        let primary_spec = ni_spec.iter().find(|n| n.device_index.unwrap_or(0) == 0).cloned();
        if primary_spec.is_some() && (input.subnet_id.is_some() || input.security_group_ids.is_some()) {
            return Err(err(
                "InvalidParameterCombination",
                "Network interfaces and an instance-level subnet ID may not be specified on the same request",
            ));
        }
        let region = ctx.region.clone();

        // Resolve the subnet, groups, key pair and instance profile.
        let profile = match &input.iam_instance_profile {
            Some(spec) => {
                let key = spec
                    .arn
                    .clone()
                    .or_else(|| spec.name.clone())
                    .ok_or_else(|| missing_parameter("IamInstanceProfile.Name"))?;
                let roles = self.roles().ok_or_else(|| invalid_parameter(format!("Value ({key}) for parameter iamInstanceProfile.name is invalid. Invalid IAM Instance Profile name")))?;
                let p = roles.instance_profile(&account, &key).ok_or_else(|| {
                    if spec.arn.is_some() {
                        invalid_parameter(format!("Value ({key}) for parameter iamInstanceProfile.arn is invalid. Invalid IAM Instance Profile ARN"))
                    } else {
                        invalid_parameter(format!("Value ({key}) for parameter iamInstanceProfile.name is invalid. Invalid IAM Instance Profile name"))
                    }
                })?;
                Some(p)
            }
            None => None,
        };
        let groups_limit = self.quota(&account, &ctx.region, crate::quotas::GROUPS_PER_INTERFACE, ctx.received_at);
        let (subnet, groups, key) = self.with_region(ctx, |r| -> Result<_, ServiceError> {
            let subnet_id = primary_spec.as_ref().and_then(|p| p.subnet_id.clone()).or_else(|| input.subnet_id.clone());
            let subnet = match subnet_id {
                Some(id) => {
                    Kind::Subnet.check(&id)?;
                    r.subnets.get(&id).cloned().ok_or_else(|| Kind::Subnet.not_found(&id))?
                }
                None => {
                    let default_vpc = r.vpcs.values().find(|v| v.vpc.is_default == Some(true)).and_then(|v| v.vpc.vpc_id.clone())
                        .ok_or_else(|| err("VPCIdNotSpecified", "No default VPC for this user. GroupName is only supported for EC2-Classic and default VPC."))?;
                    let zone = input.placement.as_ref().and_then(|p| p.availability_zone.clone());
                    let mut candidates: Vec<&t::Subnet> = r
                        .subnets
                        .values()
                        .filter(|s| s.vpc_id.as_deref() == Some(default_vpc.as_str()) && s.default_for_az == Some(true))
                        .filter(|s| zone.as_ref().is_none_or(|z| s.availability_zone.as_ref() == Some(z)))
                        .collect();
                    candidates.sort_by_key(|s| s.availability_zone.clone());
                    candidates.first().map(|s| (*s).clone()).ok_or_else(|| {
                        err("InvalidParameterValue", format!("Value ({}) for parameter availabilityZone is invalid.", zone.unwrap_or_default()))
                    })?
                }
            };
            if let Some(zone) = input.placement.as_ref().and_then(|p| p.availability_zone.clone()) {
                if subnet.availability_zone.as_ref() != Some(&zone) {
                    return Err(err("InvalidParameterValue", format!("Value ({zone}) for parameter availabilityZone is invalid. Subnet '{}' is in the availability zone {}", subnet.subnet_id.clone().unwrap_or_default(), subnet.availability_zone.clone().unwrap_or_default())));
                }
            }
            let vpc_id = subnet.vpc_id.clone().unwrap_or_default();
            let group_ids: Option<Vec<String>> = match (&primary_spec, &input.security_group_ids, &input.security_groups) {
                (Some(p), _, _) => p.groups.clone(),
                (None, Some(ids), _) => Some(ids.clone()),
                (None, None, Some(names)) => Some(
                    names
                        .iter()
                        .map(|n| {
                            r.security_groups
                                .values()
                                .find(|g| g.group_name.as_deref() == Some(n.as_str()) && g.vpc_id.as_deref() == Some(vpc_id.as_str()))
                                .and_then(|g| g.group_id.clone())
                                .ok_or_else(|| err("InvalidGroup.NotFound", format!("The security group '{n}' does not exist in VPC '{vpc_id}'")))
                        })
                        .collect::<Result<_, _>>()?,
                ),
                _ => None,
            };
            let groups = super::eni::resolve_groups(r, &vpc_id, group_ids.as_deref())?;
            super::eni::check_groups_per_interface(&groups, groups_limit)?;
            let key = match &input.key_name {
                Some(k) => Some(r.key_pairs.get(k).cloned().ok_or_else(|| err("InvalidKeyPair.NotFound", format!("The key pair '{k}' does not exist")))?),
                None => None,
            };
            Ok((subnet, groups, key))
        })?;
        let subnet_id = subnet.subnet_id.clone().unwrap_or_default();
        let vpc_id = subnet.vpc_id.clone().unwrap_or_default();
        let zone = subnet.availability_zone.clone().unwrap_or_default();
        let spot_options =
            input.instance_market_options.as_ref().and_then(|m| m.spot_options.clone()).unwrap_or_default();
        let spot_price = if spot {
            let price =
                crate::pricing::spot_price(&instance_type, &zone, "Linux/UNIX", ctx.received_at).ok_or_else(|| {
                    err(
                        "Unsupported",
                        format!("The instance type {instance_type} is not supported for Spot Instances."),
                    )
                })?;
            if spot_options.block_duration_minutes.is_some() {
                return Err(err(
                    "Unsupported",
                    "Spot Instances with a defined duration (Spot blocks) are no longer available.",
                ));
            }
            if let Some(max) = &spot_options.max_price {
                let m: f64 =
                    max.parse().map_err(|_| invalid_parameter(format!("Invalid value '{max}' for maxPrice.")))?;
                if m < price {
                    return Err(err(
                        "SpotMaxPriceTooLow",
                        format!("Your Spot request price of {m} is lower than the minimum required Spot request fulfillment price of {}.", crate::pricing::fmt_price(price)),
                    ));
                }
            }
            let persistent = spot_options.spot_instance_type.as_deref() == Some("persistent");
            if persistent
                && spot_options.instance_interruption_behavior.as_deref().unwrap_or("terminate") == "terminate"
            {
                return Err(invalid_parameter(
                    "The instance interruption behavior 'terminate' is not supported for persistent Spot requests launched with RunInstances. Specify 'stop' or 'hibernate'.",
                ));
            }
            Some(price)
        } else {
            None
        };
        let wants_host =
            input.placement.as_ref().is_some_and(|p| p.host_id.is_some() || p.tenancy.as_deref() == Some("host"));
        if wants_host && spot {
            return Err(err("InvalidParameterCombination", "Spot Instances cannot be launched on Dedicated Hosts."));
        }

        // Authorize every resource RunInstances touches.
        // The values the instance will launch with, as condition keys.
        let (metadata_defaults, planned_volumes) = self.with_region(ctx, |r| {
            let plans = super::ebs::plan_block_devices(
                ctx,
                &account,
                r,
                &image.record.image,
                input.block_device_mappings.as_deref().unwrap_or_default(),
            )
            .unwrap_or_default();
            (r.metadata_defaults.clone(), plans)
        });
        let image_v2 = image.record.image.imds_support.as_deref() == Some("v2.0");
        let md = input.metadata_options.clone().unwrap_or_default();
        let mut instance_cond = request_tag_context(&tags);
        instance_cond.extend(crate::conditions::instance_keys(
            ctx,
            &account,
            crate::conditions::InstanceKeys {
                instance_type: Some(instance_type.clone()),
                zone: subnet.availability_zone.clone(),
                tenancy: Some(if wants_host {
                    "host".into()
                } else {
                    input.placement.as_ref().and_then(|p| p.tenancy.clone()).unwrap_or_else(|| "default".into())
                }),
                instance_profile: profile.as_ref().map(|p| p.arn.clone()),
                root_device_type: Some(image.record.image.root_device_type.clone().unwrap_or_else(|| "ebs".into())),
                ebs_optimized: Some(input.ebs_optimized.unwrap_or(false)),
                http_tokens: Some(
                    md.http_tokens
                        .clone()
                        .or_else(|| image_v2.then(|| "required".into()))
                        .or_else(|| metadata_defaults.http_tokens.clone())
                        .unwrap_or_else(|| "optional".into()),
                ),
                http_endpoint: Some(
                    md.http_endpoint
                        .clone()
                        .or_else(|| metadata_defaults.http_endpoint.clone())
                        .unwrap_or_else(|| "enabled".into()),
                ),
                hop_limit: Some(
                    md.http_put_response_hop_limit
                        .or(image_v2.then_some(2))
                        .or(metadata_defaults.http_put_response_hop_limit)
                        .unwrap_or(1),
                ),
                metadata_tags: Some(
                    md.instance_metadata_tags
                        .clone()
                        .or_else(|| metadata_defaults.instance_metadata_tags.clone())
                        .unwrap_or_else(|| "disabled".into()),
                ),
                placement_group: input.placement.as_ref().and_then(|p| p.group_name.clone()),
                vpc: Some(vpc_id.clone()),
                subnet: Some(subnet_id.clone()),
            },
        ));
        instance_cond.insert("ec2:ImageID".into(), vec![image_id.clone()]);
        if let Some(lt) = &template_resource {
            instance_cond.insert("ec2:LaunchTemplate".into(), vec![lt.clone()]);
        }
        let mut eni_cond = request_tag_context(&eni_tags);
        eni_cond.insert("ec2:Vpc".into(), vec![arn(ctx, &account, &format!("vpc/{vpc_id}"))]);
        eni_cond.insert("ec2:Subnet".into(), vec![arn(ctx, &account, &format!("subnet/{subnet_id}"))]);
        if let Some(z) = &subnet.availability_zone {
            eni_cond.insert("ec2:AvailabilityZone".into(), vec![z.clone()]);
        }
        let mut resources = vec![
            (arn(ctx, &account, "instance/*"), instance_cond),
            (super::image::image_arn(ctx, &region, &image_id), resource_tag_context(image.record.image.tags.as_ref())),
            (arn(ctx, &account, &format!("subnet/{subnet_id}")), resource_tag_context(subnet.tags.as_ref())),
            (arn(ctx, &account, "network-interface/*"), eni_cond),
        ];
        // One `volume/*` per volume the launch creates, with its attributes.
        if planned_volumes.is_empty() {
            resources.push((arn(ctx, &account, "volume/*"), request_tag_context(&volume_tags)));
        }
        for v in &planned_volumes {
            let mut c = request_tag_context(&volume_tags);
            c.extend(crate::conditions::volume_keys(
                ctx,
                &crate::conditions::VolumeKeys {
                    volume_type: &v.volume_type,
                    size: Some(v.size),
                    encrypted: v.encrypted,
                    iops: v.iops,
                    throughput: v.throughput,
                    zone: subnet.availability_zone.as_deref(),
                    snapshot_id: v.snapshot_id.as_deref(),
                    kms_key_id: v.kms_key_id.as_deref(),
                },
            ));
            resources.push((arn(ctx, &account, "volume/*"), c));
        }
        for g in &groups {
            resources.push((
                arn(ctx, &account, &format!("security-group/{}", g.group_id.clone().unwrap_or_default())),
                ConditionContext::new(),
            ));
        }
        if let Some(k) = &key {
            resources.push((
                arn(ctx, &account, &format!("key-pair/{}", k.info.key_name.clone().unwrap_or_default())),
                resource_tag_context(k.info.tags.as_ref()),
            ));
        }
        if let Some(lt) = &template_resource {
            resources.push((lt.clone(), ConditionContext::new()));
        }
        self.authorize_known(ctx, "RunInstances", &resources, input.dry_run)?;
        if let Some(role) = profile.as_ref().and_then(|p| p.role_arn.clone()) {
            let mut c = ConditionContext::new();
            c.insert("iam:PassedToService".into(), vec!["ec2.amazonaws.com".into()]);
            ctx.authorize("iam:PassRole", &role, c).map_err(|e| {
                ServiceError::client(
                    "UnauthorizedOperation",
                    403,
                    format!("You are not authorized to perform this operation. {}", e.message),
                )
            })?;
        }
        // Idempotency: the same client token and parameters return the same
        // reservation.
        let token = input.client_token.as_deref();
        let existing = self.with_region(ctx, |r| {
            let rid = crate::idempotency::replay(r, "RunInstances", token, &fingerprint, |rid| {
                r.instances.values().any(|i| i.reservation_id == rid)
            })?;
            Ok::<_, ServiceError>(rid.map(|rid| {
                let instances: Vec<t::Instance> =
                    r.instances.values().filter(|i| i.reservation_id == rid).map(|rec| render(r, rec)).collect();
                (rid, instances)
            }))
        })?;
        if let Some((rid, instances)) = existing {
            return Ok(t::Reservation {
                reservation_id: Some(rid),
                owner_id: Some(account.clone()),
                groups: Some(Vec::new()),
                instances: Some(instances),
                requester_id: None,
            });
        }

        let now = ctx.received_at;
        let reservation_id = new_id("r");
        let metadata_v2 = image.record.image.imds_support.as_deref() == Some("v2.0");
        let wants_public = primary_spec
            .as_ref()
            .and_then(|p| p.associate_public_ip_address)
            .unwrap_or(subnet.map_public_ip_on_launch == Some(true));
        let endpoint = ctx.endpoint.clone();
        let mut launched: Vec<(String, u64, LaunchSpec)> = Vec::new();
        let vcpu_quota = crate::quotas::vcpu_quota(&instance_type);
        let vcpu_limit = self.quota(&account, &ctx.region, ("ec2", vcpu_quota), ctx.received_at);
        let instances = self.with_region(ctx, |r| -> Result<Vec<t::Instance>, ServiceError> {
            let used = crate::quotas::running_vcpus(r, vcpu_quota);
            let per_instance = itype.vcpus as f64;
            if used + per_instance * input.min_count as f64 > vcpu_limit {
                return Err(err(
                    "VcpuLimitExceeded",
                    format!("You have requested more vCPU capacity than your current vCPU limit of {vcpu_limit} allows for the instance bucket that the specified instance type belongs to. Please visit http://aws.amazon.com/contact-us/ec2-request to request an adjustment to this limit."),
                ));
            }
            let room = ((vcpu_limit - used) / per_instance).floor().max(0.0).min(u32::MAX as f64) as usize;
            let count = (input.max_count as usize).min(room).max(input.min_count as usize);
            if let Some(ip) = primary_spec.as_ref().and_then(|p| p.private_ip_address.clone()).or_else(|| input.private_ip_address.clone()) {
                if count > 1 {
                    return Err(err("InvalidParameterCombination", "Cannot specify an IP address when launching more than one instance"));
                }
                super::vpc::check_ip(r, &subnet_id, &ip)?;
            }
            let free = {
                let cidr = crate::util::Cidr::parse(subnet.cidr_block.as_deref().unwrap_or_default()).expect("valid subnet");
                cidr.size() as usize - 5 - super::vpc::used_ips(r, &subnet_id).len()
            };
            if free < input.min_count as usize {
                return Err(err("InsufficientFreeAddressesInSubnet", "There are not enough free addresses in subnet '{subnet_id}' to satisfy the requested number of instances."));
            }
            let count = count.min(free);
            let count = if wants_host {
                let room = super::hosts::room(r, input.placement.as_ref().expect("host placement"), &instance_type, &zone)?;
                if room < input.min_count as usize {
                    return Err(err(
                        "InsufficientHostCapacity",
                        format!("There is not enough capacity on the Dedicated Hosts to launch {} instances of type {instance_type}.", input.min_count),
                    ));
                }
                count.min(room)
            } else {
                count
            };
            let tenancy = if wants_host {
                "host".to_string()
            } else {
                input.placement.as_ref().and_then(|p| p.tenancy.clone()).unwrap_or_else(|| "default".into())
            };
            let partitions = super::settings::check_placement_group(r, input.placement.as_ref(), &zone, count)?;
            let reservation = super::settings::pick_reservation(
                r,
                input.capacity_reservation_specification.as_ref(),
                &instance_type,
                &zone,
                &tenancy,
                count,
                now,
            )?;
            let defaults = r.metadata_defaults.clone();
            let family = instance_type.split('.').next().unwrap_or_default().to_string();
            let credits = super::flow_logs::burstable_default(&instance_type).map(|d| {
                input
                    .credit_specification
                    .as_ref()
                    .map(|c| c.cpu_credits.clone())
                    .or_else(|| r.default_credit_specs.get(&family).cloned())
                    .unwrap_or_else(|| d.to_string())
            });
            let default_threads = if itype.arch == "arm64" || itype.vcpus == 1 { 1 } else { 2 };
            let threads = input.cpu_options.as_ref().and_then(|c| c.threads_per_core).unwrap_or(default_threads);
            let cores = input.cpu_options.as_ref().and_then(|c| c.core_count).unwrap_or(itype.vcpus as i32 / default_threads.max(1));
            if !(1..=2).contains(&threads) || cores < 1 || cores * threads > itype.vcpus as i32 {
                return Err(invalid_parameter(format!(
                    "The specified CPU options are not valid for instance type {instance_type}: {cores} cores with {threads} threads per core."
                )));
            }
            let dns_opts = input.private_dns_name_options.clone().unwrap_or_default();
            if let Some(h) = dns_opts.hostname_type.as_deref().filter(|h| !["ip-name", "resource-name"].contains(h)) {
                return Err(invalid_parameter(format!("Value ({h}) for parameter PrivateDnsHostnameType is invalid.")));
            }
            let plans = super::ebs::plan_block_devices(
                ctx,
                &account,
                r,
                &image.record.image,
                input.block_device_mappings.as_deref().unwrap_or_default(),
            )?;
            let mut out = Vec::new();
            for (index, partition) in partitions.iter().copied().enumerate().take(count) {
                let instance_id = new_id("i");
                let host_id = if wants_host {
                    Some(super::hosts::place(r, input.placement.as_ref().expect("host placement"), &instance_type, &zone)?)
                } else {
                    None
                };
                let ip = match primary_spec.as_ref().and_then(|p| p.private_ip_address.clone()).or_else(|| input.private_ip_address.clone()) {
                    Some(ip) => ip,
                    None => super::vpc::allocate_ip(r, &subnet_id).expect("counted free addresses"),
                };
                let eni_id = super::eni::new_eni(r, &account, &region, &subnet, &ip, groups.clone(), "", "interface", now);
                {
                    let eni = r.network_interfaces.get_mut(&eni_id).expect("just made");
                    eni.status = Some("in-use".into());
                    eni.tag_set = some_tags(eni_tags.clone());
                    eni.attachment = Some(t::NetworkInterfaceAttachment {
                        attachment_id: Some(new_id("eni-attach")),
                        attach_time: Some(now),
                        delete_on_termination: Some(primary_spec.as_ref().and_then(|p| p.delete_on_termination).unwrap_or(true)),
                        device_index: Some(0),
                        network_card_index: Some(0),
                        instance_id: Some(instance_id.clone()),
                        instance_owner_id: Some(account.clone()),
                        status: Some("attached".into()),
                        ..Default::default()
                    });
                }
                if wants_public {
                    super::eni::assign_public_ip(r, &region, &eni_id);
                }
                // The EBS volumes: the root volume and any data volumes.
                let root_device = image.record.image.root_device_name.clone().unwrap_or_else(|| "/dev/xvda".into());
                let mut data_volumes = Vec::new();
                for plan in &plans {
                    let vol_id = super::ebs::create_attached_volume(
                        r,
                        &account,
                        plan,
                        &instance_id,
                        subnet.availability_zone.clone(),
                        subnet.availability_zone_id.clone(),
                        volume_tags.clone(),
                        now,
                    );
                    if plan.device != root_device {
                        data_volumes.push(crate::backend::VolumeMount {
                            volume_id: vol_id,
                            device: plan.device.clone(),
                            snapshot_id: plan.snapshot_id.clone(),
                        });
                    }
                }
                let dns = if dns_opts.hostname_type.as_deref() == Some("resource-name") {
                    if region == "us-east-1" {
                        format!("{instance_id}.ec2.internal")
                    } else {
                        format!("{instance_id}.{region}.compute.internal")
                    }
                } else {
                    private_dns(&region, &ip)
                };
                if let Some(c) = &credits {
                    r.instance_credit_specifications.insert(instance_id.clone(), c.clone());
                }
                let instance = t::Instance {
                    instance_id: Some(instance_id.clone()),
                    image_id: Some(image_id.clone()),
                    state: Some(state("pending")),
                    private_dns_name: Some(dns.clone()),
                    public_dns_name: Some(String::new()),
                    state_transition_reason: Some(String::new()),
                    key_name: input.key_name.clone(),
                    ami_launch_index: Some(index as i32),
                    product_codes: Some(Vec::new()),
                    instance_type: Some(instance_type.clone()),
                    launch_time: Some(now),
                    placement: Some(t::Placement {
                        availability_zone: subnet.availability_zone.clone(),
                        availability_zone_id: subnet.availability_zone_id.clone(),
                        group_name: Some(input.placement.as_ref().and_then(|p| p.group_name.clone()).unwrap_or_default()),
                        tenancy: Some(if host_id.is_some() { "host".into() } else { input.placement.as_ref().and_then(|p| p.tenancy.clone()).unwrap_or_else(|| "default".into()) }),
                        host_id: host_id.clone(),
                        affinity: host_id.as_ref().map(|_| input.placement.as_ref().and_then(|p| p.affinity.clone()).unwrap_or_else(|| "default".into())),
                        partition_number: partition,
                        ..Default::default()
                    }),
                    monitoring: Some(t::Monitoring {
                        state: Some(if input.monitoring.as_ref().is_some_and(|m| m.enabled) { "enabled" } else { "disabled" }.into()),
                    }),
                    subnet_id: Some(subnet_id.clone()),
                    vpc_id: Some(vpc_id.clone()),
                    private_ip_address: Some(ip.clone()),
                    architecture: Some(image_arch.clone()),
                    root_device_type: Some("ebs".into()),
                    root_device_name: Some(root_device),
                    ebs_optimized: Some(input.ebs_optimized.unwrap_or(false)),
                    ena_support: Some(true),
                    hypervisor: Some("xen".into()),
                    client_token: input.client_token.clone(),
                    virtualization_type: Some("hvm".into()),
                    tags: some_tags(tags.iter().chain(&system_tags).cloned().collect()),
                    cpu_options: Some(t::CpuOptions {
                        core_count: Some(cores),
                        threads_per_core: Some(threads),
                        nested_virtualization: input.cpu_options.as_ref().and_then(|c| c.nested_virtualization.clone()),
                        ..Default::default()
                    }),
                    capacity_reservation_id: reservation.clone(),
                    capacity_reservation_specification: Some({
                        let spec = input.capacity_reservation_specification.clone().unwrap_or_default();
                        t::CapacityReservationSpecificationResponse {
                            capacity_reservation_preference: spec
                                .capacity_reservation_preference
                                .or_else(|| spec.capacity_reservation_target.is_none().then(|| "open".into())),
                            capacity_reservation_target: spec.capacity_reservation_target.map(|t| t::CapacityReservationTargetResponse {
                                capacity_reservation_id: t.capacity_reservation_id,
                                capacity_reservation_resource_group_arn: t.capacity_reservation_resource_group_arn,
                            }),
                        }
                    }),
                    hibernation_options: Some(t::HibernationOptions { configured: Some(input.hibernation_options.as_ref().and_then(|h| h.configured).unwrap_or(false)) }),
                    metadata_options: Some({
                        let req = input.metadata_options.clone().unwrap_or_default();
                        t::InstanceMetadataOptionsResponse {
                            state: Some("pending".into()),
                            // Request, then the AMI, then account defaults.
                            http_tokens: Some(req.http_tokens.or_else(|| metadata_v2.then(|| "required".into())).or_else(|| defaults.http_tokens.clone()).unwrap_or_else(|| "optional".into())),
                            http_put_response_hop_limit: Some(req.http_put_response_hop_limit.or(metadata_v2.then_some(2)).or(defaults.http_put_response_hop_limit).unwrap_or(1)),
                            http_endpoint: Some(req.http_endpoint.or_else(|| defaults.http_endpoint.clone()).unwrap_or_else(|| "enabled".into())),
                            http_protocol_ipv6: Some(req.http_protocol_ipv6.unwrap_or_else(|| "disabled".into())),
                            instance_metadata_tags: Some(req.instance_metadata_tags.or_else(|| defaults.instance_metadata_tags.clone()).unwrap_or_else(|| "disabled".into())),
                        }
                    }),
                    enclave_options: Some(t::EnclaveOptions { enabled: Some(false) }),
                    boot_mode: image.record.image.boot_mode.clone(),
                    current_instance_boot_mode: Some(if image_arch == "arm64" { "uefi" } else { "legacy-bios" }.into()),
                    platform_details: Some("Linux/UNIX".into()),
                    usage_operation: Some("RunInstances".into()),
                    usage_operation_update_time: Some(now),
                    private_dns_name_options: Some(t::PrivateDnsNameOptionsResponse {
                        hostname_type: Some(dns_opts.hostname_type.clone().unwrap_or_else(|| "ip-name".into())),
                        enable_resource_name_dns_a_record: Some(dns_opts.enable_resource_name_dns_a_record.unwrap_or(false)),
                        enable_resource_name_dns_aaaa_record: Some(dns_opts.enable_resource_name_dns_aaaa_record.unwrap_or(false)),
                    }),
                    maintenance_options: Some(t::InstanceMaintenanceOptions {
                        auto_recovery: Some(input.maintenance_options.as_ref().and_then(|m| m.auto_recovery.clone()).unwrap_or_else(|| "default".into())),
                        ..Default::default()
                    }),
                    network_performance_options: Some(t::InstanceNetworkPerformanceOptions { bandwidth_weighting: Some("default".into()) }),
                    instance_lifecycle: spot.then(|| "spot".to_string()),
                    spot_instance_request_id: spot.then(|| spot_request_id.clone().unwrap_or_else(|| new_id("sir")[..12].to_string())),
                    ..Default::default()
                };
                let role_arn = profile.as_ref().and_then(|p| p.role_arn.clone());
                if let Some(p) = &profile {
                    let assoc_id = new_id("iip-assoc");
                    r.iam_associations.insert(
                        assoc_id.clone(),
                        t::IamInstanceProfileAssociation {
                            association_id: Some(assoc_id),
                            instance_id: Some(instance_id.clone()),
                            iam_instance_profile: Some(t::IamInstanceProfile { arn: Some(p.arn.clone()), id: Some(p.id.clone()) }),
                            state: Some("associated".into()),
                            timestamp: Some(now),
                        },
                    );
                }
                let rec = InstanceRecord {
                    instance,
                    reservation_id: reservation_id.clone(),
                    owner_id: account.clone(),
                    requester_id: None,
                    user_data: input.user_data.clone(),
                    handle: None,
                    container_image: image.record.container_image.clone(),
                    boot: image.record.boot,
                    disable_api_termination: input.disable_api_termination.unwrap_or(false),
                    disable_api_stop: input.disable_api_stop.unwrap_or(false),
                    shutdown_behavior: input.instance_initiated_shutdown_behavior.clone().unwrap_or_else(|| "stop".into()),
                    terminated_at: None,
                    public_ip_on_start: wants_public,
                    role_arn,
                    generation: 1,
                };
                let mut env = vec![
                    ("AWS_REGION".to_string(), region.clone()),
                    ("AWS_DEFAULT_REGION".to_string(), region.clone()),
                ];
                if let Some(e) = &endpoint {
                    let e = endpoint_for_instance(e);
                    env.push(("AWS_ENDPOINT_URL".into(), e.clone()));
                    env.push((
                        "AWS_EC2_METADATA_SERVICE_ENDPOINT".into(),
                        format!("{e}{}{instance_id}", crate::imds::PREFIX),
                    ));
                }
                let spec = LaunchSpec {
                    instance_id: instance_id.clone(),
                    account_id: account.clone(),
                    region: region.clone(),
                    image: image.record.container_image.clone(),
                    boot: image.record.boot,
                    network: NetworkSpec {
                        vpc_id: vpc_id.clone(),
                        cidr_block: r.vpcs.get(&vpc_id).and_then(|v| v.vpc.cidr_block.clone()).unwrap_or_default(),
                    },
                    private_ip: ip.clone(),
                    hostname: dns.split('.').next().unwrap_or_default().to_string(),
                    instance_type: instance_type.clone(),
                    vcpus: itype.vcpus,
                    memory_mib: itype.memory_mib,
                    user_data: user_data_raw.clone(),
                    ssh_public_key: key.as_ref().map(|k| k.public_key.clone()),
                    env,
                    volumes: data_volumes,
                    extras: Default::default(),
                };
                launched.push((instance_id.clone(), 1, spec));
                if let (Some(price), None) = (spot_price, &spot_request_id) {
                    // Spot RunInstances makes a one-time (or persistent)
                    // Spot request too.
                    let sir = rec.instance.spot_instance_request_id.clone().unwrap_or_default();
                    super::spot::record_run_instances_request(r, &rec, &spot_options, price, now);
                    debug_assert!(r.spot_requests.contains_key(&sir));
                }
                r.instances.insert(instance_id.clone(), rec);
                out.push(render(r, &r.instances[&instance_id]));
            }
            crate::idempotency::remember(r, "RunInstances", token, &fingerprint, &reservation_id);
            Ok(out)
        })?;
        for (id, gen, mut spec) in launched {
            self.extend_launch(&mut spec);
            self.transition(ctx, &account, &id, gen, Transition::Launch(Box::new(spec))).await;
        }
        Ok(t::Reservation {
            reservation_id: Some(reservation_id),
            owner_id: Some(account),
            requester_id: None,
            groups: Some(Vec::new()),
            instances: Some(instances),
        })
    }

    pub(crate) fn describe_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstancesRequest,
    ) -> Result<t::DescribeInstancesResult, ServiceError> {
        self.authorize_known(ctx, "DescribeInstances", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.instance_ids.clone().unwrap_or_default();
        if !ids.is_empty() && input.max_results.is_some() {
            return Err(err(
                "InvalidParameterCombination",
                "The parameter instancesSet cannot be used with the parameter maxResults",
            ));
        }
        if let Some(m) = input.max_results {
            if !(5..=1000).contains(&m) {
                return Err(invalid_parameter(format!(
                    "Value ( {m} ) for parameter maxResults is invalid. Expecting a value greater than 5."
                )));
            }
        }
        self.with_region(ctx, |r| {
            Kind::Instance.check_all(&ids, |id| r.instances.contains_key(id))?;
            let mut reservations: Vec<t::Reservation> = Vec::new();
            let mut recs: Vec<&InstanceRecord> = r.instances.values().collect();
            recs.sort_by(|a, b| {
                (a.instance.launch_time, &a.reservation_id, a.instance.ami_launch_index).cmp(&(
                    b.instance.launch_time,
                    &b.reservation_id,
                    b.instance.ami_launch_index,
                ))
            });
            for rec in recs {
                let id = rec.instance.instance_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let i = render(r, rec);
                if !filters.matches(i.tags.as_ref(), |name| instance_filter(r, &i, rec, name))? {
                    continue;
                }
                match reservations
                    .iter_mut()
                    .find(|res| res.reservation_id.as_deref() == Some(rec.reservation_id.as_str()))
                {
                    Some(res) => res.instances.get_or_insert_with(Vec::new).push(i),
                    None => reservations.push(t::Reservation {
                        reservation_id: Some(rec.reservation_id.clone()),
                        owner_id: Some(rec.owner_id.clone()),
                        requester_id: rec.requester_id.clone(),
                        groups: Some(Vec::new()),
                        instances: Some(vec![i]),
                    }),
                }
            }
            let (items, next_token) = paginate(reservations, input.max_results, &input.next_token)?;
            Ok(t::DescribeInstancesResult { reservations: Some(items), next_token })
        })
    }

    /// Authorize `action` on each instance, checking ids exist.
    pub(crate) fn authorize_instances(
        &self,
        ctx: &RequestContext,
        action: &str,
        ids: &[String],
        dry_run: Option<bool>,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let contexts = self.with_region(ctx, |r| {
            Kind::Instance.check_all(ids, |id| r.instances.contains_key(id))?;
            Ok::<_, ServiceError>(
                ids.iter()
                    .map(|id| crate::conditions::instance(ctx, &account, &r.instances[id].instance))
                    .collect::<Vec<_>>(),
            )
        })?;
        let resources: Vec<(String, ConditionContext)> =
            ids.iter().zip(contexts).map(|(id, c)| (arn(ctx, &account, &format!("instance/{id}")), c)).collect();
        self.authorize_known(ctx, action, &resources, dry_run)
    }

    pub(crate) async fn start_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::StartInstancesRequest,
    ) -> Result<t::StartInstancesResult, ServiceError> {
        self.authorize_instances(ctx, "StartInstances", &input.instance_ids, input.dry_run)?;
        let account = account_of(ctx);
        let region = ctx.region.clone();
        let limits: std::collections::BTreeMap<&str, f64> = crate::quotas::VCPU_QUOTAS
            .iter()
            .map(|code| (*code, self.quota(&account, &region, ("ec2", code), ctx.received_at)))
            .collect();
        let (changes, todo) = self.with_region(ctx, |r| {
            for id in &input.instance_ids {
                let st = state_name(&r.instances[id]);
                if !matches!(st.as_str(), "stopped" | "running" | "pending") {
                    return Err(err(
                        "IncorrectInstanceState",
                        format!("The instance '{id}' is not in a state from which it can be started."),
                    ));
                }
            }
            let mut wanted: std::collections::BTreeMap<&str, f64> = Default::default();
            for id in &input.instance_ids {
                let rec = &r.instances[id];
                if state_name(rec) != "stopped" {
                    continue;
                }
                let ty = rec.instance.instance_type.as_deref().unwrap_or_default();
                let vcpus = catalog::instance_type(ty).map_or(1.0, |t| t.vcpus as f64);
                *wanted.entry(crate::quotas::vcpu_quota(ty)).or_default() += vcpus;
            }
            for (code, want) in wanted {
                let limit = limits.get(code).copied().unwrap_or(f64::INFINITY);
                if crate::quotas::running_vcpus(r, code) + want > limit {
                    return Err(err(
                        "VcpuLimitExceeded",
                        format!("You have requested more vCPU capacity than your current vCPU limit of {limit} allows for the instance bucket that the specified instance type belongs to. Please visit http://aws.amazon.com/contact-us/ec2-request to request an adjustment to this limit."),
                    ));
                }
            }
            let mut changes = Vec::new();
            let mut todo = Vec::new();
            for id in &input.instance_ids {
                let prev = r.instances[id].instance.state.clone();
                if state_name(&r.instances[id]) == "stopped" {
                    let wants_public = r.instances[id].public_ip_on_start;
                    let rec = r.instances.get_mut(id).expect("checked");
                    rec.instance.state = Some(state("pending"));
                    rec.instance.state_transition_reason = Some(String::new());
                    rec.instance.state_reason = None;
                    rec.generation += 1;
                    todo.push((id.clone(), rec.generation));
                    if wants_public {
                        if let Some(eni) = super::eni::primary_eni(r, id) {
                            if r.network_interfaces.get(&eni).is_some_and(|n| n.association.is_none()) {
                                super::eni::assign_public_ip(r, &region, &eni);
                            }
                        }
                    }
                }
                changes.push(t::InstanceStateChange {
                    instance_id: Some(id.clone()),
                    current_state: r.instances[id].instance.state.clone(),
                    previous_state: prev,
                });
            }
            Ok((changes, todo))
        })?;
        for (id, gen) in todo {
            self.transition(ctx, &account, &id, gen, Transition::Start).await;
        }
        Ok(t::StartInstancesResult { starting_instances: Some(changes) })
    }

    pub(crate) async fn stop_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::StopInstancesRequest,
    ) -> Result<t::StopInstancesResult, ServiceError> {
        self.authorize_instances(ctx, "StopInstances", &input.instance_ids, input.dry_run)?;
        let account = account_of(ctx);
        let now = ctx.received_at;
        let force = input.force == Some(true);
        let (changes, todo) = self.with_region(ctx, |r| {
            for id in &input.instance_ids {
                let rec = &r.instances[id];
                let st = state_name(rec);
                if !matches!(st.as_str(), "running" | "stopping" | "stopped") {
                    return Err(err("IncorrectInstanceState", format!("This instance '{id}' is not in a state from which it can be stopped.")));
                }
                if rec.disable_api_stop {
                    return Err(err("OperationNotPermitted", format!("The instance '{id}' may not be stopped. Modify its 'disableApiStop' instance attribute and try again.")));
                }
            }
            let mut changes = Vec::new();
            let mut todo = Vec::new();
            for id in &input.instance_ids {
                let prev = r.instances[id].instance.state.clone();
                if state_name(&r.instances[id]) == "running" {
                    let rec = r.instances.get_mut(id).expect("checked");
                    rec.instance.state = Some(state("stopping"));
                    rec.instance.state_transition_reason = Some(format!("User initiated ({})", gmt(now)));
                    rec.instance.state_reason = Some(t::StateReason {
                        code: Some("Client.UserInitiatedShutdown".into()),
                        message: Some("Client.UserInitiatedShutdown: User initiated shutdown".into()),
                    });
                    rec.generation += 1;
                    todo.push((id.clone(), rec.generation));
                    if let Some(eni) = super::eni::primary_eni(r, id) {
                        super::eni::release_public_ip(r, &eni);
                    }
                }
                changes.push(t::InstanceStateChange { instance_id: Some(id.clone()), current_state: r.instances[id].instance.state.clone(), previous_state: prev });
            }
            Ok((changes, todo))
        })?;
        for (id, gen) in todo {
            self.transition(ctx, &account, &id, gen, Transition::Stop { force }).await;
        }
        Ok(t::StopInstancesResult { stopping_instances: Some(changes) })
    }

    pub(crate) async fn reboot_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::RebootInstancesRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_instances(ctx, "RebootInstances", &input.instance_ids, input.dry_run)?;
        let account = account_of(ctx);
        let todo = self.with_region(ctx, |r| {
            for id in &input.instance_ids {
                if state_name(&r.instances[id]) == "terminated" {
                    return Err(err(
                        "IncorrectInstanceState",
                        format!("The instance '{id}' is not in a state from which it can be rebooted."),
                    ));
                }
            }
            Ok(input
                .instance_ids
                .iter()
                .filter(|id| state_name(&r.instances[*id]) == "running")
                .map(|id| (id.clone(), r.instances[id].generation))
                .collect::<Vec<_>>())
        })?;
        for (id, gen) in todo {
            self.transition(ctx, &account, &id, gen, Transition::Reboot).await;
        }
        Ok(())
    }

    pub(crate) async fn terminate_instances_op(
        &self,
        ctx: &RequestContext,
        input: t::TerminateInstancesRequest,
    ) -> Result<t::TerminateInstancesResult, ServiceError> {
        self.authorize_instances(ctx, "TerminateInstances", &input.instance_ids, input.dry_run)?;
        let account = account_of(ctx);
        let now = ctx.received_at;
        let region = ctx.region.clone();
        let mut deleted = Vec::new();
        let (changes, todo) = self.with_region(ctx, |r| {
            for id in &input.instance_ids {
                if r.instances[id].disable_api_termination {
                    return Err(err("OperationNotPermitted", format!("The instance '{id}' may not be terminated. Modify its 'disableApiTermination' instance attribute and try again.")));
                }
            }
            let mut changes = Vec::new();
            let mut todo = Vec::new();
            for id in &input.instance_ids {
                let prev = r.instances[id].instance.state.clone();
                let st = state_name(&r.instances[id]);
                if !matches!(st.as_str(), "terminated" | "shutting-down") {
                    let rec = r.instances.get_mut(id).expect("checked");
                    rec.instance.state = Some(state("shutting-down"));
                    rec.instance.state_transition_reason = Some(format!("User initiated ({})", gmt(now)));
                    rec.instance.state_reason = Some(t::StateReason {
                        code: Some("Client.UserInitiatedShutdown".into()),
                        message: Some("Client.UserInitiatedShutdown: User initiated shutdown".into()),
                    });
                    rec.terminated_at = Some(now);
                    rec.generation += 1;
                    todo.push((id.clone(), rec.generation));
                    deleted.extend(release_resources(r, id, &region));
                }
                changes.push(t::InstanceStateChange { instance_id: Some(id.clone()), current_state: r.instances[id].instance.state.clone(), previous_state: prev });
            }
            Ok((changes, todo))
        })?;
        for (id, gen) in todo {
            self.transition(ctx, &account, &id, gen, Transition::Terminate).await;
        }
        for v in deleted {
            self.volume_job(crate::volumes::VolumeJob::Delete(v));
        }
        Ok(t::TerminateInstancesResult { terminating_instances: Some(changes) })
    }

    pub(crate) fn describe_instance_status_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstanceStatusRequest,
    ) -> Result<t::DescribeInstanceStatusResult, ServiceError> {
        self.authorize_known(ctx, "DescribeInstanceStatus", &[("*".into(), ConditionContext::new())], input.dry_run)?;
        let filters = Filters::new(&input.filters);
        let ids = input.instance_ids.clone().unwrap_or_default();
        let all = input.include_all_instances == Some(true);
        self.with_region(ctx, |r| {
            Kind::Instance.check_all(&ids, |id| r.instances.contains_key(id))?;
            let mut out = Vec::new();
            for rec in r.instances.values() {
                let id = rec.instance.instance_id.clone().unwrap_or_default();
                if !ids.is_empty() && !ids.contains(&id) {
                    continue;
                }
                let st = state_name(rec);
                if !all && st != "running" {
                    continue;
                }
                let summary = |ok: bool| t::InstanceStatusSummary {
                    status: Some(if ok { "ok" } else { "not-applicable" }.into()),
                    details: ok.then(|| {
                        vec![t::InstanceStatusDetails {
                            name: Some("reachability".into()),
                            status: Some("passed".into()),
                            impaired_since: None,
                        }]
                    }),
                };
                let running = st == "running";
                let status = t::InstanceStatus {
                    instance_id: Some(id),
                    availability_zone: rec.instance.placement.as_ref().and_then(|p| p.availability_zone.clone()),
                    availability_zone_id: rec.instance.placement.as_ref().and_then(|p| p.availability_zone_id.clone()),
                    instance_state: rec.instance.state.clone(),
                    instance_status: Some(summary(running)),
                    system_status: Some(summary(running)),
                    attached_ebs_status: Some(t::EbsStatusSummary {
                        status: Some(if running { "ok" } else { "not-applicable" }.into()),
                        details: running.then(|| {
                            vec![t::EbsStatusDetails {
                                name: Some("reachability".into()),
                                status: Some("passed".into()),
                                impaired_since: None,
                            }]
                        }),
                    }),
                    events: Some(Vec::new()),
                    ..Default::default()
                };
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "availability-zone" => s(&status.availability_zone),
                        "instance-state-name" => vec![st.clone()],
                        "instance-state-code" => status
                            .instance_state
                            .as_ref()
                            .and_then(|s| s.code)
                            .map(|c| c.to_string())
                            .into_iter()
                            .collect(),
                        "instance-status.status" => {
                            status.instance_status.as_ref().map(|x| s(&x.status)).unwrap_or_default()
                        }
                        "system-status.status" => {
                            status.system_status.as_ref().map(|x| s(&x.status)).unwrap_or_default()
                        }
                        "instance-status.reachability" | "system-status.reachability" => {
                            vec![if running { "passed" } else { "not-applicable" }.to_string()]
                        }
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(status);
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeInstanceStatusResult { instance_statuses: Some(items), next_token })
        })
    }

    pub(crate) fn describe_instance_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeInstanceAttributeRequest,
    ) -> Result<t::InstanceAttribute, ServiceError> {
        self.authorize_instances(
            ctx,
            "DescribeInstanceAttribute",
            std::slice::from_ref(&input.instance_id),
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let rec = &r.instances[&input.instance_id];
            let i = render(r, rec);
            let mut out = t::InstanceAttribute { instance_id: Some(input.instance_id.clone()), ..Default::default() };
            let bv = |v: bool| Some(t::AttributeBooleanValue { value: Some(v) });
            let sv = |v: Option<String>| Some(t::AttributeValue { value: v });
            match input.attribute.as_str() {
                "instanceType" => out.instance_type = sv(i.instance_type.clone()),
                "kernel" => out.kernel_id = sv(i.kernel_id.clone()),
                "ramdisk" => out.ramdisk_id = sv(i.ramdisk_id.clone()),
                "userData" => out.user_data = sv(rec.user_data.clone()),
                "disableApiTermination" => out.disable_api_termination = bv(rec.disable_api_termination),
                "disableApiStop" => out.disable_api_stop = bv(rec.disable_api_stop),
                "instanceInitiatedShutdownBehavior" => {
                    out.instance_initiated_shutdown_behavior = sv(Some(rec.shutdown_behavior.clone()))
                }
                "rootDeviceName" => out.root_device_name = sv(i.root_device_name.clone()),
                "blockDeviceMapping" => out.block_device_mappings = i.block_device_mappings.clone(),
                "productCodes" => out.product_codes = Some(Vec::new()),
                "sourceDestCheck" => out.source_dest_check = bv(i.source_dest_check.unwrap_or(true)),
                "groupSet" => out.groups = i.security_groups.clone(),
                "ebsOptimized" => out.ebs_optimized = bv(i.ebs_optimized.unwrap_or(false)),
                "sriovNetSupport" => out.sriov_net_support = sv(Some("simple".into())),
                "enaSupport" => out.ena_support = bv(i.ena_support.unwrap_or(true)),
                "enclaveOptions" => out.enclave_options = Some(t::EnclaveOptions { enabled: Some(false) }),
                other => {
                    return Err(invalid_parameter(format!(
                        "Value ({other}) for parameter attribute is invalid. Unknown attribute."
                    )))
                }
            }
            Ok(out)
        })
    }

    pub(crate) fn modify_instance_attribute_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstanceAttributeRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_instances(
            ctx,
            "ModifyInstanceAttribute",
            std::slice::from_ref(&input.instance_id),
            input.dry_run,
        )?;
        let id = input.instance_id.clone();
        let groups_limit =
            self.quota(&account_of(ctx), &ctx.region, crate::quotas::GROUPS_PER_INTERFACE, ctx.received_at);
        self.with_region(ctx, |r| {
            let st = state_name(&r.instances[&id]);
            let must_be_stopped = |what: &str| -> Result<(), ServiceError> {
                if st != "stopped" {
                    return Err(err(
                        "IncorrectInstanceState",
                        format!("The instance '{id}' is not in the 'stopped' state."),
                    )
                    .with_context(what));
                }
                Ok(())
            };
            // The legacy `Attribute` + `Value` form.
            let (attr, value) = (input.attribute.clone(), input.value.clone());
            let instance_type = input
                .instance_type
                .as_ref()
                .and_then(|v| v.value.clone())
                .or_else(|| (attr.as_deref() == Some("instanceType")).then(|| value.clone()).flatten());
            if let Some(it) = instance_type {
                must_be_stopped("instanceType")?;
                let itype = catalog::instance_type(&it)
                    .ok_or_else(|| invalid_parameter(format!("Invalid value '{it}' for InstanceType.")))?;
                let rec = r.instances.get_mut(&id).expect("checked");
                if Some(itype.arch) != rec.instance.architecture.as_deref() {
                    return Err(invalid_parameter(format!(
                        "The instance type '{it}' does not support the architecture of the instance."
                    )));
                }
                rec.instance.instance_type = Some(it);
            }
            if let Some(ud) = input.user_data.as_ref().and_then(|v| v.value.clone()) {
                must_be_stopped("userData")?;
                let rec = r.instances.get_mut(&id).expect("checked");
                rec.user_data = Some(base64::engine::general_purpose::STANDARD.encode(ud));
            }
            let rec = r.instances.get_mut(&id).expect("checked");
            let flag = |v: &Option<t::AttributeBooleanValue>, name: &str| -> Option<bool> {
                v.as_ref()
                    .and_then(|v| v.value)
                    .or_else(|| (attr.as_deref() == Some(name)).then(|| value.as_deref() == Some("true")))
            };
            if let Some(v) = flag(&input.disable_api_termination, "disableApiTermination") {
                rec.disable_api_termination = v;
            }
            if let Some(v) = flag(&input.disable_api_stop, "disableApiStop") {
                rec.disable_api_stop = v;
            }
            if let Some(v) = flag(&input.ebs_optimized, "ebsOptimized") {
                rec.instance.ebs_optimized = Some(v);
            }
            if let Some(v) = flag(&input.ena_support, "enaSupport") {
                rec.instance.ena_support = Some(v);
            }
            if let Some(v) = input.instance_initiated_shutdown_behavior.as_ref().and_then(|v| v.value.clone()) {
                if v != "stop" && v != "terminate" {
                    return Err(invalid_parameter(format!(
                        "Value ({v}) for parameter instanceInitiatedShutdownBehavior is invalid."
                    )));
                }
                rec.shutdown_behavior = v;
            }
            let source_dest = flag(&input.source_dest_check, "sourceDestCheck");
            let groups = input.groups.clone();
            let vpc_id = rec.instance.vpc_id.clone().unwrap_or_default();
            if let Some(eni) = super::eni::primary_eni(r, &id) {
                if let Some(v) = source_dest {
                    if let Some(n) = r.network_interfaces.get_mut(&eni) {
                        n.source_dest_check = Some(v);
                    }
                }
                if let Some(g) = groups {
                    let resolved = super::eni::resolve_groups(r, &vpc_id, Some(&g))?;
                    super::eni::check_groups_per_interface(&resolved, groups_limit)?;
                    if let Some(n) = r.network_interfaces.get_mut(&eni) {
                        n.groups = Some(resolved);
                    }
                }
            }
            for m in input.block_device_mappings.iter().flatten() {
                let device = m.device_name.clone().unwrap_or_default();
                let Some(dot) = m.ebs.as_ref().and_then(|e| e.delete_on_termination) else { continue };
                let att = r.volumes.values_mut().flat_map(|v| v.attachments.iter_mut().flatten()).find(|a| {
                    a.instance_id.as_deref() == Some(id.as_str()) && a.device.as_deref() == Some(device.as_str())
                });
                match att {
                    Some(a) => a.delete_on_termination = Some(dot),
                    None => return Err(invalid_parameter(format!("No device is currently mapped at {device}"))),
                }
            }
            Ok(())
        })
    }

    pub(crate) fn modify_instance_metadata_options_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyInstanceMetadataOptionsRequest,
    ) -> Result<t::ModifyInstanceMetadataOptionsResult, ServiceError> {
        self.authorize_instances(
            ctx,
            "ModifyInstanceMetadataOptions",
            std::slice::from_ref(&input.instance_id),
            input.dry_run,
        )?;
        self.with_region(ctx, |r| {
            let rec = r.instances.get_mut(&input.instance_id).expect("checked");
            let m = rec.instance.metadata_options.get_or_insert_with(Default::default);
            if let Some(v) = &input.http_tokens {
                m.http_tokens = Some(v.clone());
            }
            if let Some(v) = input.http_put_response_hop_limit {
                if !(1..=64).contains(&v) {
                    return Err(invalid_parameter(format!(
                        "Value ({v}) for parameter httpPutResponseHopLimit is invalid."
                    )));
                }
                m.http_put_response_hop_limit = Some(v);
            }
            if let Some(v) = &input.http_endpoint {
                m.http_endpoint = Some(v.clone());
            }
            if let Some(v) = &input.http_protocol_ipv6 {
                m.http_protocol_ipv6 = Some(v.clone());
            }
            if let Some(v) = &input.instance_metadata_tags {
                m.instance_metadata_tags = Some(v.clone());
            }
            m.state = Some("applied".into());
            let mut shown = m.clone();
            shown.state = Some("pending".into());
            Ok(t::ModifyInstanceMetadataOptionsResult {
                instance_id: Some(input.instance_id.clone()),
                instance_metadata_options: Some(shown),
            })
        })
    }

    pub(crate) async fn get_console_output_op(
        &self,
        ctx: &RequestContext,
        input: t::GetConsoleOutputRequest,
    ) -> Result<t::GetConsoleOutputResult, ServiceError> {
        self.authorize_instances(ctx, "GetConsoleOutput", std::slice::from_ref(&input.instance_id), input.dry_run)?;
        let handle = self.with_region(ctx, |r| r.instances.get(&input.instance_id).and_then(|i| i.handle.clone()));
        let output = match handle {
            Some(h) => match self.backend().console_output(&h).await {
                Ok(text) if !text.is_empty() => Some(base64::engine::general_purpose::STANDARD.encode(text)),
                _ => None,
            },
            None => None,
        };
        Ok(t::GetConsoleOutputResult {
            instance_id: Some(input.instance_id.clone()),
            timestamp: Some(ctx.received_at),
            output,
        })
    }

    // ---- instance profile associations ----------------------------------------------------------

    fn resolve_profile(
        &self,
        ctx: &RequestContext,
        spec: &t::IamInstanceProfileSpecification,
    ) -> Result<crate::InstanceProfile, ServiceError> {
        let account = account_of(ctx);
        let key = spec
            .arn
            .clone()
            .or_else(|| spec.name.clone())
            .ok_or_else(|| missing_parameter("IamInstanceProfile.Name"))?;
        let invalid = || {
            invalid_parameter(format!(
                "Value ({key}) for parameter iamInstanceProfile is invalid. Invalid IAM Instance Profile"
            ))
        };
        let roles = self.roles().ok_or_else(invalid)?;
        let p = roles.instance_profile(&account, &key).ok_or_else(invalid)?;
        if let Some(role) = &p.role_arn {
            let mut c = ConditionContext::new();
            c.insert("iam:PassedToService".into(), vec!["ec2.amazonaws.com".into()]);
            ctx.authorize("iam:PassRole", role, c).map_err(|e| {
                ServiceError::client(
                    "UnauthorizedOperation",
                    403,
                    format!("You are not authorized to perform this operation. {}", e.message),
                )
            })?;
        }
        Ok(p)
    }

    pub(crate) fn associate_iam_instance_profile_op(
        &self,
        ctx: &RequestContext,
        input: t::AssociateIamInstanceProfileRequest,
    ) -> Result<t::AssociateIamInstanceProfileResult, ServiceError> {
        self.authorize_instances(ctx, "AssociateIamInstanceProfile", std::slice::from_ref(&input.instance_id), None)?;
        let p = self.resolve_profile(ctx, &input.iam_instance_profile)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let st = state_name(&r.instances[&input.instance_id]);
            if !matches!(st.as_str(), "pending" | "running" | "stopping" | "stopped") {
                return Err(err(
                    "IncorrectState",
                    format!("The instance '{}' is not in a valid state for this operation.", input.instance_id),
                ));
            }
            if r.iam_associations.values().any(|a| {
                a.instance_id.as_deref() == Some(input.instance_id.as_str()) && a.state.as_deref() == Some("associated")
            }) {
                return Err(err(
                    "IncorrectState",
                    format!("There is an existing association for instance {}", input.instance_id),
                ));
            }
            let id = new_id("iip-assoc");
            let assoc = t::IamInstanceProfileAssociation {
                association_id: Some(id.clone()),
                instance_id: Some(input.instance_id.clone()),
                iam_instance_profile: Some(t::IamInstanceProfile { arn: Some(p.arn.clone()), id: Some(p.id.clone()) }),
                state: Some("associated".into()),
                timestamp: Some(now),
            };
            r.iam_associations.insert(id, assoc.clone());
            if let Some(rec) = r.instances.get_mut(&input.instance_id) {
                rec.role_arn = p.role_arn.clone();
            }
            let mut shown = assoc;
            shown.state = Some("associating".into());
            Ok(t::AssociateIamInstanceProfileResult { iam_instance_profile_association: Some(shown) })
        })
    }

    pub(crate) fn replace_iam_instance_profile_association_op(
        &self,
        ctx: &RequestContext,
        input: t::ReplaceIamInstanceProfileAssociationRequest,
    ) -> Result<t::ReplaceIamInstanceProfileAssociationResult, ServiceError> {
        self.authorize_known(
            ctx,
            "ReplaceIamInstanceProfileAssociation",
            &[(arn(ctx, &account_of(ctx), "instance/*"), ConditionContext::new())],
            None,
        )?;
        let p = self.resolve_profile(ctx, &input.iam_instance_profile)?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let old = r
                .iam_associations
                .remove(&input.association_id)
                .filter(|a| a.state.as_deref() == Some("associated"))
                .ok_or_else(|| {
                    err(
                        "InvalidAssociationID.NotFound",
                        format!("An association with ID {} does not exist.", input.association_id),
                    )
                })?;
            let id = new_id("iip-assoc");
            let assoc = t::IamInstanceProfileAssociation {
                association_id: Some(id.clone()),
                instance_id: old.instance_id.clone(),
                iam_instance_profile: Some(t::IamInstanceProfile { arn: Some(p.arn.clone()), id: Some(p.id.clone()) }),
                state: Some("associated".into()),
                timestamp: Some(now),
            };
            r.iam_associations.insert(id, assoc.clone());
            if let Some(rec) = old.instance_id.as_ref().and_then(|i| r.instances.get_mut(i)) {
                rec.role_arn = p.role_arn.clone();
            }
            let mut shown = assoc;
            shown.state = Some("associating".into());
            Ok(t::ReplaceIamInstanceProfileAssociationResult { iam_instance_profile_association: Some(shown) })
        })
    }

    pub(crate) fn disassociate_iam_instance_profile_op(
        &self,
        ctx: &RequestContext,
        input: t::DisassociateIamInstanceProfileRequest,
    ) -> Result<t::DisassociateIamInstanceProfileResult, ServiceError> {
        self.authorize_known(
            ctx,
            "DisassociateIamInstanceProfile",
            &[(arn(ctx, &account_of(ctx), "instance/*"), ConditionContext::new())],
            None,
        )?;
        self.with_region(ctx, |r| {
            let old = r
                .iam_associations
                .remove(&input.association_id)
                .filter(|a| a.state.as_deref() == Some("associated"))
                .ok_or_else(|| {
                    err(
                        "InvalidAssociationID.NotFound",
                        format!("An association with ID {} does not exist.", input.association_id),
                    )
                })?;
            if let Some(rec) = old.instance_id.as_ref().and_then(|i| r.instances.get_mut(i)) {
                rec.role_arn = None;
            }
            let mut shown = old;
            shown.state = Some("disassociating".into());
            Ok(t::DisassociateIamInstanceProfileResult { iam_instance_profile_association: Some(shown) })
        })
    }

    pub(crate) fn describe_iam_instance_profile_associations_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeIamInstanceProfileAssociationsRequest,
    ) -> Result<t::DescribeIamInstanceProfileAssociationsResult, ServiceError> {
        self.authorize_known(
            ctx,
            "DescribeIamInstanceProfileAssociations",
            &[("*".into(), ConditionContext::new())],
            None,
        )?;
        let filters = Filters::new(&input.filters);
        let ids = input.association_ids.clone().unwrap_or_default();
        self.with_region(ctx, |r| {
            for id in &ids {
                if !r.iam_associations.contains_key(id) {
                    return Err(err(
                        "InvalidAssociationID.NotFound",
                        format!("An association with ID {id} does not exist."),
                    ));
                }
            }
            let mut out = Vec::new();
            for a in r.iam_associations.values() {
                if !ids.is_empty() && !ids.contains(a.association_id.as_ref().unwrap()) {
                    continue;
                }
                let ok = filters.matches(None, |name| {
                    Some(match name {
                        "instance-id" => s(&a.instance_id),
                        "state" => s(&a.state),
                        _ => return None,
                    })
                })?;
                if ok {
                    out.push(a.clone());
                }
            }
            let (items, next_token) = paginate(out, input.max_results, &input.next_token)?;
            Ok(t::DescribeIamInstanceProfileAssociationsResult {
                iam_instance_profile_associations: Some(items),
                next_token,
            })
        })
    }
}

/// What terminating an instance frees: interfaces that go with it,
/// Elastic IP associations, volumes that go with it, the instance profile
/// association.
/// Returns the volumes it deleted.
fn release_resources(r: &mut RegionState, instance_id: &str, _region: &str) -> Vec<String> {
    let enis: Vec<(String, bool)> = r
        .network_interfaces
        .values()
        .filter_map(|n| {
            let a = n.attachment.as_ref()?;
            (a.instance_id.as_deref() == Some(instance_id))
                .then(|| (n.network_interface_id.clone().unwrap_or_default(), a.delete_on_termination == Some(true)))
        })
        .collect();
    for (eni, delete) in enis {
        for a in r.addresses.values_mut() {
            if a.network_interface_id.as_deref() == Some(eni.as_str()) {
                a.association_id = None;
                a.network_interface_id = None;
                a.network_interface_owner_id = None;
                a.private_ip_address = None;
                a.instance_id = None;
            }
        }
        if delete {
            r.network_interfaces.remove(&eni);
        } else if let Some(n) = r.network_interfaces.get_mut(&eni) {
            n.attachment = None;
            n.status = Some("available".into());
            n.association = None;
        }
    }
    let mut delete_volumes = Vec::new();
    for v in r.volumes.values_mut() {
        let Some(atts) = &mut v.attachments else { continue };
        if let Some(pos) = atts.iter().position(|a| a.instance_id.as_deref() == Some(instance_id)) {
            let a = atts.remove(pos);
            if a.delete_on_termination == Some(true) {
                delete_volumes.push(v.volume_id.clone().unwrap_or_default());
            } else {
                v.state = Some("available".into());
            }
        }
    }
    for v in &delete_volumes {
        r.volumes.remove(v);
        r.volume_modifications.remove(v);
    }
    r.iam_associations.retain(|_, a| a.instance_id.as_deref() != Some(instance_id));
    if let Some(rec) = r.instances.get_mut(instance_id) {
        rec.role_arn = None;
    }
    delete_volumes
}

trait WithContext {
    fn with_context(self, what: &str) -> Self;
}

impl WithContext for ServiceError {
    fn with_context(self, _what: &str) -> Self {
        self
    }
}
