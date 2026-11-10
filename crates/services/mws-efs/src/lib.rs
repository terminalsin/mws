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
mod billing;
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
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_ec2::Ec2;
use mws_kms::Kms;

pub use billing::FileSystemStorage;
use state::State;
use storage::Storage;

struct Inner {
    state: Mutex<State>,
    storage: Storage,
    ec2: Ec2,
    kms: Kms,
    /// How far the emulated clock (`RequestContext::received_at`) runs
    /// ahead of the wall clock, in milliseconds, as requests last showed
    /// it: lifecycle transitions finish on the emulated clock even for
    /// callers without a request (Lambda mounts).
    clock_skew_ms: AtomicI64,
    /// Network interfaces of deleted mount targets (region key, id), for
    /// EC2 to delete once no EFS lock is held.
    released_interfaces: Mutex<Vec<(String, String)>>,
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
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                storage: Storage::new(root),
                ec2,
                kms,
                clock_skew_ms: AtomicI64::new(0),
                released_interfaces: Mutex::new(Vec::new()),
            }),
        }
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

    /// The state, with the lifecycle transitions due by now finished.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        let mut st = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let (gone, enis) = st.settle(self.now());
        for id in gone {
            self.storage().delete(&id);
        }
        if !enis.is_empty() {
            self.inner.released_interfaces.lock().unwrap_or_else(|e| e.into_inner()).extend(enis);
        }
        st
    }

    /// Delete the network interfaces of mount targets that finished
    /// deleting. Never call with the state lock held.
    pub(crate) fn release_interfaces(&self, ctx: &RequestContext) {
        drop(self.lock());
        let enis = std::mem::take(&mut *self.inner.released_interfaces.lock().unwrap_or_else(|e| e.into_inner()));
        for (key, eni) in enis {
            let Some((account, region)) = key.split_once('/') else { continue };
            let ctx = RequestContext { region: region.to_string(), ..ctx.clone() };
            self.ec2().delete_service_interface(&ctx, account, &eni);
        }
    }

    /// The emulated time.
    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::milliseconds(self.inner.clock_skew_ms.load(Ordering::Relaxed))
    }

    /// Note how far ahead of the wall clock a request's time is.
    fn observe(&self, ctx: &RequestContext) {
        let skew = (ctx.received_at - chrono::Utc::now()).num_milliseconds();
        self.inner.clock_skew_ms.store(skew.max(0), Ordering::Relaxed);
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
        self.observe(&ctx);
        self.release_interfaces(&ctx);
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
        self.observe(&ctx);
        self.release_interfaces(&ctx);
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
        *self.inner.state.lock().unwrap_or_else(|e| e.into_inner()) = state;
        Ok(())
    }

    fn reset_state(&self) {
        let old = std::mem::take(&mut *self.inner.state.lock().unwrap_or_else(|e| e.into_inner()));
        for r in old.regions.values() {
            for id in r.file_systems.keys() {
                self.storage().delete(id);
            }
        }
    }
}
