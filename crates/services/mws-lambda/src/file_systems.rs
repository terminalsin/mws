//! Amazon EFS file systems mounted into execution environments
//! (`FileSystemConfigs`): Lambda connects to an access point's mount
//! target from the function's VPC as its execution role, and the
//! directory appears at `LocalMountPath`. MWS bind-mounts the file
//! system's directory into the function's container, so this needs a
//! Docker-backed environment (a base image or a container image).

use std::path::PathBuf;

/// What to mount, for whom.
#[derive(Debug, Clone, Default)]
pub struct FileSystemMountRequest {
    pub account: String,
    pub region: String,
    pub access_point_arn: String,
    pub subnet_ids: Vec<String>,
    pub security_group_ids: Vec<String>,
    pub role_arn: Option<String>,
    /// The role session's name (the function's name).
    pub session_name: String,
}

/// Why a mount failed, as Lambda reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSystemMountError {
    /// `EFSMountConnectivityException`: no network path to a mount target.
    Connectivity(String),
    /// `EFSMountFailureException`: the mount was refused.
    Failure(String),
}

/// A mounted directory on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedFileSystem {
    pub dir: PathBuf,
    pub read_only: bool,
    /// `(uid, gid)` to give `dir` as root before the environment starts,
    /// when the file system could not do that itself.
    pub owner: Option<(u32, u32)>,
}

/// Where file systems come from: Amazon EFS, wired in by the server.
pub trait FileSystems: Send + Sync {
    fn mount(&self, req: &FileSystemMountRequest) -> Result<MountedFileSystem, FileSystemMountError>;
}
