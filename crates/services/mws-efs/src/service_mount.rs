//! Mounting an access point for another AWS service's compute in a VPC
//! (Lambda's `FileSystemConfigs`): the service connects from its network
//! interfaces in the configured subnets, with TLS and IAM as the
//! service's execution role, through the access point.
//!
//! The checks are AWS's: the access point and its file system exist and
//! are available in the caller's account and Region; one of the subnets'
//! Availability Zones has an available mount target of the file system
//! in the subnets' VPC; that mount target's security groups let TCP 2049
//! in from the service's security groups (or its subnet's addresses);
//! and the file system policy, if any, allows
//! `elasticfilesystem:ClientMount` for the role session (and
//! `ClientWrite`, or the mount is read-only).

use std::path::PathBuf;

use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::state::State;
use crate::storage::relative;
use crate::Efs;

/// What a service mounts, and as whom.
#[derive(Debug, Clone, Default)]
pub struct ServiceMount {
    pub account: String,
    pub region: String,
    pub access_point_arn: String,
    pub subnet_ids: Vec<String>,
    pub security_group_ids: Vec<String>,
    /// The role the service mounts as, and its session name.
    pub role_arn: Option<String>,
    pub session_name: String,
}

/// Why a mount failed: Lambda's `EFSMountConnectivityException` (no
/// network path), `EFSMountFailureException` (refused), or
/// `EFSMountTimeoutException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceMountError {
    Connectivity(String),
    Failure(String),
}

/// A mounted directory on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMounted {
    pub dir: PathBuf,
    pub read_only: bool,
    /// `(uid, gid)` the root directory still has to be given: MWS creates
    /// it, but could not change its owner itself (it does not run as root),
    /// so the caller does that as root inside its container.
    pub owner: Option<(u32, u32)>,
}

/// The first usable address of a subnet (AWS reserves the first four).
fn subnet_address(cidr: &str) -> String {
    let base = cidr.split('/').next().unwrap_or_default();
    match base.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => std::net::Ipv4Addr::from(u32::from(ip).wrapping_add(4)).to_string(),
        Err(_) => String::new(),
    }
}

impl Efs {
    /// Decide and prepare a service's mount (see the module docs).
    pub fn mount_for_service(&self, m: &ServiceMount) -> Result<ServiceMounted, ServiceMountError> {
        use ServiceMountError::{Connectivity, Failure};
        let ap_id = crate::access_points::ap_id(&m.access_point_arn).to_string();
        let subnets: Vec<mws_ec2::SubnetSummary> =
            m.subnet_ids.iter().filter_map(|s| self.ec2().subnet_summary(&m.account, &m.region, s)).collect();
        if subnets.is_empty() {
            return Err(Connectivity(
                "EFS file systems can only be mounted from a function connected to a VPC.".into(),
            ));
        }
        let st = self.lock();
        let key = State::key(&m.account, &m.region);
        let r = st
            .regions
            .get(&key)
            .ok_or_else(|| Failure(format!("Access point {} does not exist.", m.access_point_arn)))?;
        let ap = r
            .access_points
            .get(&ap_id)
            .filter(|a| a.life_cycle_state.as_deref() == Some("available"))
            .ok_or_else(|| Failure(format!("Access point {} does not exist.", m.access_point_arn)))?
            .clone();
        let fs_id = ap.file_system_id.clone().unwrap_or_default();
        let (_, fs) = st.find_fs(&fs_id).ok_or_else(|| Failure(format!("File system {fs_id} does not exist.")))?;
        if fs.description.life_cycle_state != "available" {
            return Err(Connectivity(format!("File system {fs_id} is not available.")));
        }
        // A mount target in one of the subnets' zones, in their VPC.
        let reachable = subnets.iter().find_map(|s| {
            r.mount_targets
                .values()
                .find(|t| {
                    t.description.file_system_id == fs_id
                        && t.description.life_cycle_state == "available"
                        && t.description.vpc_id == s.vpc_id
                        && t.description.availability_zone_name == s.availability_zone
                })
                .map(|t| (t.clone(), s.clone()))
        });
        let Some((target, subnet)) = reachable else {
            return Err(Connectivity(format!(
                "Lambda was not able to connect to the EFS file system {fs_id}: it has no available mount target in the Availability Zones of the function's subnets."
            )));
        };
        let source_ip = subnet_address(subnet.cidr_block.as_deref().unwrap_or_default());
        if !self.ec2().ingress_allows_tcp(
            &m.account,
            &m.region,
            &target.security_groups,
            2049,
            &source_ip,
            &m.security_group_ids,
        ) {
            return Err(Connectivity(format!(
                "Lambda timed out connecting to mount target {} of {fs_id}: its security groups don't allow NFS (TCP 2049) from the function.",
                target.description.mount_target_id
            )));
        }
        // The file system policy, for the role's session (TLS and IAM).
        let mut read_only =
            fs.description.file_system_protection.as_ref().and_then(|p| p.replication_overwrite_protection.as_deref())
                == Some("REPLICATING");
        if let Some(doc) = &fs.policy {
            let policy = Policy::parse(doc, PolicyKind::Resource).map_err(|_| Failure("Access denied.".into()))?;
            let principal = match &m.role_arn {
                Some(role) => {
                    let partition = role.split(':').nth(1).unwrap_or("aws");
                    let name = role.rsplit('/').next().unwrap_or_default();
                    PrincipalInfo {
                        account_id: m.account.clone(),
                        arns: vec![format!(
                            "arn:{partition}:sts::{}:assumed-role/{name}/{}",
                            m.account, m.session_name
                        )],
                        role_arn: Some(role.clone()),
                        ..Default::default()
                    }
                }
                None => PrincipalInfo::default(),
            };
            let mut context = ConditionContext::new();
            context.insert("elasticfilesystem:AccessedViaMountTarget", vec!["true".into()]);
            context.insert("aws:SecureTransport", vec!["true".into()]);
            context.insert("aws:SourceIp", vec![source_ip.clone()]);
            context.insert("elasticfilesystem:AccessPointArn", vec![ap.access_point_arn.clone().unwrap_or_default()]);
            let arn = fs.description.file_system_arn.clone().unwrap_or_default();
            let allowed = |action: &str| {
                let e = policy.evaluate(&Request { action, resource: &arn, principal: &principal, context: &context });
                !e.denied() && e.allowed()
            };
            if !allowed("elasticfilesystem:ClientMount") {
                return Err(Failure(format!(
                    "Lambda was not able to mount the EFS file system {fs_id}: the file system policy denies elasticfilesystem:ClientMount."
                )));
            }
            if !allowed("elasticfilesystem:ClientWrite") {
                read_only = true;
            }
        }
        // The access point's root directory, made with its creation info.
        let root = ap.root_directory.as_ref().and_then(|r| r.path.clone()).unwrap_or_else(|| "/".into());
        let rel = relative(&root).ok_or_else(|| Failure("Access denied.".into()))?;
        let dir = self.storage().dir(fs.id()).join(rel);
        let mut owner = None;
        if !dir.exists() {
            let Some(info) = ap.root_directory.as_ref().and_then(|r| r.creation_info.clone()) else {
                return Err(Failure(format!(
                    "Lambda was not able to mount the EFS file system {fs_id}: the access point's root directory {root} does not exist."
                )));
            };
            std::fs::create_dir_all(&dir).map_err(|e| Failure(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = u32::from_str_radix(&info.permissions, 8).unwrap_or(0o755);
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode));
                let (uid, gid) = (info.owner_uid as u32, info.owner_gid as u32);
                if std::os::unix::fs::chown(&dir, Some(uid), Some(gid)).is_err() {
                    owner = Some((uid, gid));
                }
            }
        }
        Ok(ServiceMounted { dir, read_only, owner })
    }
}
