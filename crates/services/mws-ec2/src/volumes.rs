//! EBS data on the compute backend. Volume and snapshot changes reach the
//! backend through one queue, worked in order, so a snapshot taken right
//! after a volume is created copies that volume, and an attachment sees
//! the volume it mounts.

use std::sync::OnceLock;

use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use crate::backend::VolumeMount;
use crate::state::State;
use crate::Ec2;

#[derive(Debug, Clone)]
pub(crate) enum VolumeJob {
    Create {
        volume_id: String,
        snapshot_id: Option<String>,
    },
    Delete(String),
    Snapshot {
        volume_id: String,
        snapshot_id: String,
    },
    CopySnapshot {
        source_id: String,
        snapshot_id: String,
    },
    DeleteSnapshot(String),
    /// Give an instance's container the data volumes its attachments name.
    Sync {
        account: String,
        region: String,
        instance_id: String,
    },
}

pub(crate) type VolumeQueue = OnceLock<UnboundedSender<VolumeJob>>;

/// The data volumes attached to `instance_id` (not its root device).
pub(crate) fn mounts(r: &crate::state::RegionState, instance_id: &str) -> Vec<VolumeMount> {
    let root = r.instances.get(instance_id).and_then(|i| i.instance.root_device_name.clone());
    let mut out: Vec<VolumeMount> = r
        .volumes
        .values()
        .flat_map(|v| {
            v.attachments
                .iter()
                .flatten()
                .filter(|a| a.instance_id.as_deref() == Some(instance_id) && a.device != root)
                .map(|a| VolumeMount {
                    volume_id: v.volume_id.clone().unwrap_or_default(),
                    device: a.device.clone().unwrap_or_default(),
                    snapshot_id: v.snapshot_id.clone().filter(|s| !s.is_empty()),
                })
        })
        .collect();
    out.sort_by(|a, b| a.device.cmp(&b.device));
    out
}

impl Ec2 {
    /// Queue a backend job (nothing for the metadata backend).
    pub(crate) fn volume_job(&self, job: VolumeJob) {
        if self.backend().name() == "metadata" {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let tx = self.inner.volume_jobs.get_or_init(|| {
            let (tx, mut rx) = unbounded_channel::<VolumeJob>();
            let me = self.clone();
            rt.spawn(async move {
                while let Some(job) = rx.recv().await {
                    me.run_volume_job(job).await;
                }
            });
            tx
        });
        let _ = tx.send(job);
    }

    async fn run_volume_job(&self, job: VolumeJob) {
        let backend = self.backend();
        // Deletes can race a container that is still letting go of the
        // volume: retry them for a few seconds.
        let attempts = if matches!(job, VolumeJob::Delete(_) | VolumeJob::DeleteSnapshot(_)) { 10 } else { 1 };
        for attempt in 0..attempts {
            let result = match &job {
                VolumeJob::Create { volume_id, snapshot_id } => {
                    backend.create_volume(volume_id, snapshot_id.as_deref()).await
                }
                VolumeJob::Delete(id) => backend.delete_volume(id).await,
                VolumeJob::Snapshot { volume_id, snapshot_id } => backend.create_snapshot(volume_id, snapshot_id).await,
                VolumeJob::CopySnapshot { source_id, snapshot_id } => {
                    backend.copy_snapshot(source_id, snapshot_id).await
                }
                VolumeJob::DeleteSnapshot(id) => backend.delete_snapshot(id).await,
                VolumeJob::Sync { account, region, instance_id } => {
                    self.sync_mounts(account, region, instance_id).await
                }
            };
            match result {
                Ok(()) => return,
                Err(e) if attempt + 1 == attempts => {
                    tracing::warn!(backend = backend.name(), ?job, "EBS backend operation failed: {e}");
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            }
        }
    }

    async fn sync_mounts(
        &self,
        account: &str,
        region: &str,
        instance_id: &str,
    ) -> Result<(), crate::backend::BackendError> {
        let key = State::key(account, region);
        let (handle, wanted) = {
            let state = self.lock();
            let Some(r) = state.regions.get(&key) else { return Ok(()) };
            let Some(rec) = r.instances.get(instance_id) else { return Ok(()) };
            (rec.handle.clone(), mounts(r, instance_id))
        };
        let Some(handle) = handle else { return Ok(()) };
        if let Some(new_handle) = self.backend().set_volumes(&handle, &wanted).await? {
            {
                let mut state = self.lock();
                if let Some(rec) = state.regions.get_mut(&key).and_then(|r| r.instances.get_mut(instance_id)) {
                    if rec.handle.as_deref() == Some(handle.as_str()) {
                        rec.handle = Some(new_handle.clone());
                    }
                }
            }
            // The new container needs its firewall (and waits for it).
            self.firewall_on_boot(account, region, instance_id, &new_handle).await;
        }
        Ok(())
    }
}
