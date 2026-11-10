//! Amazon Elastic File System for MWS.
//!
//! Every file system is a real directory on the host (under `MWS_EFS_DIR`,
//! see [`storage`]). Mount targets are requester-managed network interfaces
//! in MWS's EC2 subnets, with security groups. Instances that EC2 runs in
//! Docker get the directory tree shared in and a `mount` helper that
//! handles `mount -t efs` and `mount -t nfs4` the way the EFS mount helper
//! and NFS client would: the file system must have an available mount
//! target in the instance's VPC (in its Availability Zone for the plain
//! DNS name), the mount target's security groups must let NFS (TCP 2049)
//! in from the instance, and the file system policy must allow
//! `elasticfilesystem:ClientMount` (and `ClientWrite`, or the mount is
//! read-only). Access points pick and create the root directory (see
//! [`mount`]).
//!
//! Access points, file system policies, backup and lifecycle policies,
//! replication (which really copies the data to the destination file
//! system), tags and account preferences follow the API. Every call is
//! authorized through IAM with `aws:ResourceTag` conditions.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/efs_generated.rs"));
}

mod access_points;
mod file_systems;
mod handler;
pub mod mount;
mod mount_targets;
mod replication;
pub mod service_mount;
mod settings;
mod state;
pub mod storage;
mod tags;
mod util;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_ec2::Ec2;
use mws_kms::Kms;

use state::State;
use storage::Storage;

struct Inner {
    state: Mutex<State>,
    storage: Storage,
    ec2: Ec2,
    kms: Kms,
}

/// The EFS service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Efs {
    inner: Arc<Inner>,
}

impl Efs {
    /// File system data lives in directories under `root`.
    pub fn new(ec2: Ec2, kms: Kms, root: PathBuf) -> Self {
        if let Err(e) = std::fs::create_dir_all(&root) {
            tracing::warn!("EFS: creating {}: {e}", root.display());
        }
        Self { inner: Arc::new(Inner { state: Mutex::new(State::default()), storage: Storage::new(root), ec2, kms }) }
    }

    /// The default data root: `MWS_EFS_DIR`, or `mws-efs` in the temp
    /// directory.
    pub fn default_root() -> PathBuf {
        std::env::temp_dir().join("mws-efs")
    }

    /// The host directory that holds a file system's data (whether or not
    /// the file system exists).
    pub fn file_system_dir(&self, file_system_id: &str) -> PathBuf {
        self.inner.storage.dir(file_system_id)
    }

    pub fn data_root(&self) -> PathBuf {
        self.inner.storage.root().to_path_buf()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("EFS state lock poisoned")
    }

    pub(crate) fn storage(&self) -> &Storage {
        &self.inner.storage
    }

    pub(crate) fn ec2(&self) -> &Ec2 {
        &self.inner.ec2
    }

    pub(crate) fn kms(&self) -> &Kms {
        &self.inner.kms
    }
}

#[async_trait::async_trait]
impl Service for Efs {
    fn signing_name(&self) -> &'static str {
        "elasticfilesystem"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        let path = request.uri().path();
        path.starts_with("/2015-02-01/") || path.starts_with(mount::PREFIX)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(mount::PREFIX)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path().starts_with(mount::PREFIX) {
            return mount::serve(self, &ctx, &request);
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&*self.lock()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid EFS state: {e}"))?;
        for r in state.regions.values() {
            for id in r.file_systems.keys() {
                self.storage().create(id);
            }
        }
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        let old = std::mem::take(&mut *self.lock());
        for r in old.regions.values() {
            for id in r.file_systems.keys() {
                self.storage().delete(id);
            }
        }
    }
}
