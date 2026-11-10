//! Mount targets: an EFS-managed network interface in one subnet per
//! Availability Zone, with security groups.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_ec2::{ServiceInterfaceError, ServiceInterfaceRequest};

use crate::generated::types as t;
use crate::state::MountTarget;
use crate::util::{account_of, bad_request, err, mt_not_found, new_id, page, wrong_state};
use crate::Efs;

/// Who the mount target interfaces belong to, as EC2 reports them.
const REQUESTER_ID: &str = "amazon-elasticfilesystem";

fn interface_error(e: ServiceInterfaceError) -> ServiceError {
    match e {
        ServiceInterfaceError::SubnetNotFound(id) => {
            err("SubnetNotFound", 400, format!("The subnet ID '{id}' does not exist"))
        }
        ServiceInterfaceError::SecurityGroupNotFound(id) => {
            err("SecurityGroupNotFound", 400, format!("The security group '{id}' does not exist"))
        }
        ServiceInterfaceError::SecurityGroupInOtherVpc(id) => err(
            "SecurityGroupNotFound",
            400,
            format!("The security group '{id}' does not exist in the mount target's VPC"),
        ),
        ServiceInterfaceError::InvalidIpAddress(ip) => {
            bad_request(format!("IP address {ip} is not within the subnet's address range."))
        }
        ServiceInterfaceError::IpAddressInUse(ip) => {
            err("IpAddressInUse", 409, format!("IP address {ip} is already in use in the subnet."))
        }
        ServiceInterfaceError::NoFreeAddresses => {
            err("NoFreeAddressesInSubnet", 409, "The subnet has no free IP addresses.")
        }
        ServiceInterfaceError::NetworkInterfaceNotFound(id) => {
            err("InternalServerError", 500, format!("Network interface {id} of the mount target is gone."))
        }
    }
}

fn check_group_count(groups: &[String]) -> Result<(), ServiceError> {
    if groups.len() > 5 {
        return Err(err("SecurityGroupLimitExceeded", 400, "A mount target can have at most 5 security groups."));
    }
    Ok(())
}

impl Efs {
    /// A copy of the caller's mount target.
    fn mount_target(&self, ctx: &RequestContext, id: &str) -> Result<MountTarget, ServiceError> {
        let account = account_of(ctx);
        let mut st = self.lock();
        st.region(&account, &ctx.region).mount_targets.get(id).cloned().ok_or_else(|| mt_not_found(id))
    }

    pub(crate) async fn create_mount_target(
        &self,
        ctx: &RequestContext,
        input: t::CreateMountTargetRequest,
    ) -> Result<t::MountTargetDescription, ServiceError> {
        let account = account_of(ctx);
        let fs = self.file_system(ctx, &input.file_system_id)?;
        self.authorize_fs(ctx, "CreateMountTarget", &fs, ConditionContext::new())?;
        if fs.description.life_cycle_state != "available" {
            return Err(wrong_state(fs.id(), &fs.description.life_cycle_state));
        }
        let groups = input.security_groups.clone().unwrap_or_default();
        check_group_count(&groups)?;
        let subnet = self
            .ec2()
            .subnet_info(ctx, &account, &input.subnet_id)
            .ok_or_else(|| interface_error(ServiceInterfaceError::SubnetNotFound(input.subnet_id.clone())))?;
        let ip_type = input.ip_address_type.clone().unwrap_or_else(|| {
            if input.ipv6_address.is_some() && input.ip_address.is_none() {
                "IPV6_ONLY".into()
            } else if input.ipv6_address.is_some() {
                "DUAL_STACK".into()
            } else {
                "IPV4_ONLY".into()
            }
        });
        if ip_type == "IPV4_ONLY" && input.ipv6_address.is_some() {
            return Err(bad_request("An IPv6 address can't be specified for an IPV4_ONLY mount target."));
        }
        if ip_type == "IPV6_ONLY" && input.ip_address.is_some() {
            return Err(bad_request("An IPv4 address can't be specified for an IPV6_ONLY mount target."));
        }
        let ipv6 = if ip_type == "IPV4_ONLY" {
            None
        } else {
            let Some(block) = subnet.ipv6_cidr_blocks.first() else {
                return Err(bad_request(format!("Subnet {} does not have an IPv6 CIDR block.", subnet.subnet_id)));
            };
            Some(input.ipv6_address.clone().unwrap_or_else(|| ipv6_in(block)))
        };
        if let Some(az) = &fs.description.availability_zone_name {
            if *az != subnet.availability_zone {
                return Err(err(
                    "AvailabilityZonesMismatch",
                    400,
                    format!(
                        "The Availability Zone of subnet {} ({}) does not match the file system's Availability Zone ({az}).",
                        subnet.subnet_id, subnet.availability_zone
                    ),
                ));
            }
        }
        {
            let mut st = self.lock();
            let region = st.region(&account, &ctx.region);
            let siblings: Vec<&MountTarget> =
                region.mount_targets.values().filter(|m| m.description.file_system_id == fs.id()).collect();
            if let Some(other) =
                siblings.iter().find(|m| m.description.vpc_id.as_deref() != Some(subnet.vpc_id.as_str()))
            {
                return Err(err(
                    "MountTargetConflict",
                    409,
                    format!(
                        "File system '{}' already has mount targets in VPC '{}'.",
                        fs.id(),
                        other.description.vpc_id.clone().unwrap_or_default()
                    ),
                ));
            }
            if siblings
                .iter()
                .any(|m| m.description.availability_zone_name.as_deref() == Some(subnet.availability_zone.as_str()))
            {
                return Err(err(
                    "MountTargetConflict",
                    409,
                    format!(
                        "File system '{}' already has a mount target in Availability Zone '{}'.",
                        fs.id(),
                        subnet.availability_zone
                    ),
                ));
            }
        }
        if !groups.is_empty() {
            self.ec2().check_security_groups(ctx, &account, &subnet.vpc_id, &groups).map_err(interface_error)?;
        }
        let long = {
            let st = self.lock();
            Self::long_ids(&st, &account, &ctx.region)
        };
        let id = new_id("fsmt", long);
        let eni = self
            .ec2()
            .create_service_interface(
                ctx,
                &account,
                &ServiceInterfaceRequest {
                    subnet_id: subnet.subnet_id.clone(),
                    ip_address: input.ip_address.clone(),
                    security_groups: groups,
                    description: format!("EFS mount target for {} ({id})", fs.id()),
                    interface_type: "efs".into(),
                    requester_id: REQUESTER_ID.into(),
                },
            )
            .map_err(interface_error)?;
        let description = t::MountTargetDescription {
            owner_id: Some(account.clone()),
            mount_target_id: id.clone(),
            file_system_id: fs.id().to_string(),
            subnet_id: subnet.subnet_id.clone(),
            life_cycle_state: "creating".into(),
            ip_address: (ip_type != "IPV6_ONLY").then(|| eni.ip_address.clone()),
            ipv6_address: ipv6,
            network_interface_id: Some(eni.network_interface_id.clone()),
            availability_zone_id: Some(subnet.availability_zone_id.clone()),
            availability_zone_name: Some(subnet.availability_zone.clone()),
            vpc_id: Some(subnet.vpc_id.clone()),
        };
        let mut st = self.lock();
        st.region(&account, &ctx.region).mount_targets.insert(
            id,
            MountTarget {
                description: description.clone(),
                security_groups: eni.security_groups,
                transition_ends: Some(ctx.received_at + crate::state::mount_target_create()),
            },
        );
        Ok(description)
    }

    pub(crate) async fn describe_mount_targets(
        &self,
        ctx: &RequestContext,
        input: t::DescribeMountTargetsRequest,
    ) -> Result<t::DescribeMountTargetsResponse, ServiceError> {
        let account = account_of(ctx);
        let given = [&input.file_system_id, &input.mount_target_id, &input.access_point_id]
            .iter()
            .filter(|v| v.is_some())
            .count();
        if given != 1 {
            return Err(bad_request("Specify exactly one of FileSystemId, MountTargetId or AccessPointId."));
        }
        let fs_id = if let Some(mt) = &input.mount_target_id {
            self.mount_target(ctx, mt)?.description.file_system_id
        } else if let Some(ap) = &input.access_point_id {
            self.access_point(ctx, ap)?.file_system_id.unwrap_or_default()
        } else {
            input.file_system_id.clone().unwrap_or_default()
        };
        let fs = self.file_system(ctx, &fs_id)?;
        self.authorize_fs(ctx, "DescribeMountTargets", &fs, ConditionContext::new())?;
        let mut st = self.lock();
        let all: Vec<t::MountTargetDescription> = st
            .region(&account, &ctx.region)
            .mount_targets
            .values()
            .filter(|m| m.description.file_system_id == fs.id())
            .filter(|m| input.mount_target_id.as_deref().is_none_or(|id| m.description.mount_target_id == id))
            .map(|m| m.description.clone())
            .collect();
        let (items, next) = page(all, |m| m.mount_target_id.clone(), input.marker.as_deref(), input.max_items, 10)?;
        Ok(t::DescribeMountTargetsResponse { marker: input.marker, mount_targets: Some(items), next_marker: next })
    }

    pub(crate) async fn describe_mount_target_security_groups(
        &self,
        ctx: &RequestContext,
        input: t::DescribeMountTargetSecurityGroupsRequest,
    ) -> Result<t::DescribeMountTargetSecurityGroupsResponse, ServiceError> {
        let mt = self.mount_target(ctx, &input.mount_target_id)?;
        let fs = self.file_system(ctx, &mt.description.file_system_id)?;
        self.authorize_fs(ctx, "DescribeMountTargetSecurityGroups", &fs, ConditionContext::new())?;
        if mt.description.life_cycle_state != "available" {
            return Err(err(
                "IncorrectMountTargetState",
                409,
                format!(
                    "Mount target '{}' is in the '{}' state.",
                    mt.description.mount_target_id, mt.description.life_cycle_state
                ),
            ));
        }
        Ok(t::DescribeMountTargetSecurityGroupsResponse { security_groups: mt.security_groups })
    }

    pub(crate) async fn modify_mount_target_security_groups(
        &self,
        ctx: &RequestContext,
        input: t::ModifyMountTargetSecurityGroupsRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let mt = self.mount_target(ctx, &input.mount_target_id)?;
        let fs = self.file_system(ctx, &mt.description.file_system_id)?;
        self.authorize_fs(ctx, "ModifyMountTargetSecurityGroups", &fs, ConditionContext::new())?;
        if mt.description.life_cycle_state != "available" {
            return Err(err(
                "IncorrectMountTargetState",
                409,
                format!(
                    "Mount target '{}' is in the '{}' state.",
                    mt.description.mount_target_id, mt.description.life_cycle_state
                ),
            ));
        }
        let groups = input.security_groups.clone().unwrap_or_default();
        check_group_count(&groups)?;
        let eni = mt.description.network_interface_id.clone().unwrap_or_default();
        let resolved =
            self.ec2().set_service_interface_groups(ctx, &account, &eni, &groups).map_err(interface_error)?;
        let mut st = self.lock();
        if let Some(m) = st.region(&account, &ctx.region).mount_targets.get_mut(&input.mount_target_id) {
            m.security_groups = resolved;
        }
        Ok(())
    }

    pub(crate) async fn delete_mount_target(
        &self,
        ctx: &RequestContext,
        input: t::DeleteMountTargetRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let mt = self.mount_target(ctx, &input.mount_target_id)?;
        let fs = self.file_system(ctx, &mt.description.file_system_id)?;
        self.authorize_fs(ctx, "DeleteMountTarget", &fs, ConditionContext::new())?;
        {
            let mut st = self.lock();
            st.region(&account, &ctx.region).mount_targets.remove(&input.mount_target_id);
        }
        if let Some(eni) = &mt.description.network_interface_id {
            self.ec2().delete_service_interface(ctx, &account, eni);
        }
        Ok(())
    }
}

/// An address in an IPv6 block (the block's prefix with a random host
/// part).
fn ipv6_in(block: &str) -> String {
    use rand::Rng;
    let prefix = block.split('/').next().unwrap_or("2600::");
    let Ok(base) = prefix.parse::<std::net::Ipv6Addr>() else { return prefix.to_string() };
    let mut segments = base.segments();
    let mut rng = rand::thread_rng();
    for s in segments.iter_mut().skip(4) {
        *s = rng.gen();
    }
    std::net::Ipv6Addr::from(segments).to_string()
}
