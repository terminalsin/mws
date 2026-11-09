//! The backend behind `MWS_EC2_BACKEND=auto` and `docker`: Docker when a
//! daemon answers, metadata only while none does.
//!
//! `auto` used to decide once, at startup. MWS started before Docker
//! Desktop (or colima, OrbStack, a daemon still coming up) then never ran
//! a container for the rest of its life, and nothing but one startup log
//! line said so. This backend keeps probing in the background until a
//! daemon answers and switches new launches to containers from then on.
//!
//! Each instance stays on the backend that launched it: the metadata
//! backend's handles are instance ids (`i-...`), Docker's are container
//! ids, so operations on an instance go to the right one even for state
//! restored from `MWS_DB` that an earlier, Docker-less run saved.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use super::{
    BackendError, CommandOutput, ComputeBackend, DockerBackend, Firewall, LaunchSpec, Launched, MetadataBackend,
    VolumeMount,
};

/// How often the background probe asks the daemon again.
const PROBE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct AutoBackend {
    docker: DockerBackend,
    /// Whether new launches go to Docker.
    docker_up: Arc<AtomicBool>,
    /// Whether this choice was `auto` (it falls back to metadata) rather
    /// than `docker` (it never does).
    fallback: bool,
    /// Whether a launch has already warned that it ran no container.
    warned: AtomicBool,
}

impl AutoBackend {
    /// `MWS_EC2_BACKEND=docker`: always Docker for new instances.
    pub fn docker(docker: DockerBackend) -> Self {
        Self { docker, docker_up: Arc::new(AtomicBool::new(true)), fallback: false, warned: AtomicBool::new(false) }
    }

    /// `MWS_EC2_BACKEND=auto`: Docker once a daemon answers. Probes now and,
    /// while none answers, every few seconds on a background thread.
    pub fn auto(docker: DockerBackend) -> Self {
        let probe = docker.daemon_probe();
        let up = Arc::new(AtomicBool::new(probe.is_ok()));
        if let Err(e) = probe {
            tracing::warn!(
                cli = docker.cli(),
                "no Docker daemon answers ({e}); EC2 instances launch without containers until one does \
                 (MWS_EC2_BACKEND=docker requires Docker, =metadata never uses it)"
            );
            spawn_probe(docker.cli().to_string(), Arc::downgrade(&up));
        }
        Self { docker, docker_up: up, fallback: true, warned: AtomicBool::new(false) }
    }

    fn up(&self) -> bool {
        self.docker_up.load(Ordering::Acquire)
    }

    /// The backend new work goes to.
    fn current(&self) -> &dyn ComputeBackend {
        if self.up() {
            &self.docker
        } else {
            &MetadataBackend
        }
    }

    /// The backend that launched the instance behind `handle`.
    fn owner(&self, handle: &str) -> &dyn ComputeBackend {
        if is_metadata_handle(handle) {
            &MetadataBackend
        } else {
            &self.docker
        }
    }
}

/// Whether `handle` came from [`MetadataBackend`] (it hands out instance
/// ids; Docker hands out hex container ids).
fn is_metadata_handle(handle: &str) -> bool {
    handle.starts_with("i-")
}

/// Ask the daemon every [`PROBE_INTERVAL`] until it answers (then flip
/// `up`) or the backend is dropped.
fn spawn_probe(cli: String, up: Weak<AtomicBool>) {
    let probe = DockerBackend::new(cli);
    let spawned = std::thread::Builder::new().name("mws-ec2-docker-probe".into()).spawn(move || loop {
        std::thread::sleep(PROBE_INTERVAL);
        let Some(flag) = up.upgrade() else { return };
        if probe.daemon_probe().is_ok() {
            flag.store(true, Ordering::Release);
            tracing::info!(cli = probe.cli(), "Docker daemon answers; new EC2 instances run as containers");
            return;
        }
    });
    if let Err(e) = spawned {
        tracing::warn!("cannot start the Docker probe thread: {e}");
    }
}

#[async_trait::async_trait]
impl ComputeBackend for AutoBackend {
    fn name(&self) -> &'static str {
        self.current().name()
    }

    async fn launch(&self, spec: &LaunchSpec) -> Result<Launched, BackendError> {
        if self.fallback && !self.up() && !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                instance = %spec.instance_id,
                "no Docker daemon answers, so this instance runs no container (later launches will once one does)"
            );
        }
        self.current().launch(spec).await
    }

    async fn start(&self, handle: &str) -> Result<(), BackendError> {
        self.owner(handle).start(handle).await
    }

    async fn stop(&self, handle: &str, force: bool) -> Result<(), BackendError> {
        self.owner(handle).stop(handle, force).await
    }

    async fn reboot(&self, handle: &str) -> Result<(), BackendError> {
        self.owner(handle).reboot(handle).await
    }

    async fn terminate(&self, handle: &str) -> Result<(), BackendError> {
        self.owner(handle).terminate(handle).await
    }

    async fn console_output(&self, handle: &str) -> Result<String, BackendError> {
        self.owner(handle).console_output(handle).await
    }

    async fn create_image(&self, handle: &str, image_ref: &str) -> Result<String, BackendError> {
        self.owner(handle).create_image(handle, image_ref).await
    }

    async fn delete_image(&self, image_ref: &str) -> Result<(), BackendError> {
        self.current().delete_image(image_ref).await
    }

    async fn delete_network(&self, vpc_id: &str) -> Result<(), BackendError> {
        self.current().delete_network(vpc_id).await
    }

    fn filters_traffic(&self) -> bool {
        self.current().filters_traffic()
    }

    async fn apply_firewall(&self, handle: &str, firewall: &Firewall) -> Result<(), BackendError> {
        self.owner(handle).apply_firewall(handle, firewall).await
    }

    async fn network_ready(&self, handle: &str) -> Result<(), BackendError> {
        self.owner(handle).network_ready(handle).await
    }

    async fn build_image(
        &self,
        handle: &str,
        dockerfile: &str,
        files: &[(String, Vec<u8>)],
    ) -> Result<Option<Vec<u8>>, BackendError> {
        self.owner(handle).build_image(handle, dockerfile, files).await
    }

    async fn exec(&self, handle: &str, script: &str) -> Result<Option<CommandOutput>, BackendError> {
        self.owner(handle).exec(handle, script).await
    }

    async fn create_volume(&self, volume_id: &str, snapshot_id: Option<&str>) -> Result<(), BackendError> {
        self.current().create_volume(volume_id, snapshot_id).await
    }

    async fn delete_volume(&self, volume_id: &str) -> Result<(), BackendError> {
        self.current().delete_volume(volume_id).await
    }

    async fn create_snapshot(&self, volume_id: &str, snapshot_id: &str) -> Result<(), BackendError> {
        self.current().create_snapshot(volume_id, snapshot_id).await
    }

    async fn copy_snapshot(&self, source_id: &str, snapshot_id: &str) -> Result<(), BackendError> {
        self.current().copy_snapshot(source_id, snapshot_id).await
    }

    async fn delete_snapshot(&self, snapshot_id: &str) -> Result<(), BackendError> {
        self.current().delete_snapshot(snapshot_id).await
    }

    async fn set_volumes(&self, handle: &str, volumes: &[VolumeMount]) -> Result<Option<String>, BackendError> {
        self.owner(handle).set_volumes(handle, volumes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_route_to_the_backend_that_launched_them() {
        assert!(is_metadata_handle("i-0123456789abcdef0"));
        assert!(!is_metadata_handle("3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e"));
    }

    #[tokio::test]
    async fn auto_without_a_daemon_runs_metadata_and_keeps_metadata_handles() {
        let backend = AutoBackend::auto(DockerBackend::new("mws-no-such-docker-cli"));
        assert_eq!(backend.name(), "metadata");
        // A metadata instance's lifecycle never touches the (missing) CLI.
        backend.start("i-0123456789abcdef0").await.unwrap();
        backend.stop("i-0123456789abcdef0", false).await.unwrap();
        backend.terminate("i-0123456789abcdef0").await.unwrap();
    }

    #[tokio::test]
    async fn docker_choice_keeps_restored_metadata_instances_working() {
        let backend = AutoBackend::docker(DockerBackend::new("mws-no-such-docker-cli"));
        assert_eq!(backend.name(), "docker");
        backend.start("i-0123456789abcdef0").await.unwrap();
        assert!(backend.start("3f4e5d6c7b8a").await.is_err());
    }
}
