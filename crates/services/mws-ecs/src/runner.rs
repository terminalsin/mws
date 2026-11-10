//! Running a task: the lifecycle ECS reports (`PROVISIONING`, `PENDING`,
//! `ACTIVATING`, `RUNNING`, `DEACTIVATING`, `STOPPING`, `DEPROVISIONING`,
//! `STOPPED`) driven by what the backend does. Role credentials and
//! secrets are fetched before containers start, containers start in
//! `dependsOn` order, `awslogs` output is shipped to CloudWatch Logs, health
//! checks are polled, and an essential container exiting stops the task.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;

use crate::backend::{ContainerSpec, HealthCheckSpec, MountSpec, PortSpec, TaskNetwork, TaskSpec};
use crate::generated::types as t;
use crate::platform::{LogEvent, RoleCredentials};
use crate::state::{TaskCredentials, TaskRecord};
use crate::Ecs;

/// Mark a task stopped now.
pub fn finish_stopped(rec: &mut TaskRecord, now: DateTime<Utc>, reason: Option<String>) {
    let t = &mut rec.task;
    t.last_status = Some("STOPPED".into());
    t.desired_status = Some("STOPPED".into());
    t.stopping_at.get_or_insert(now);
    t.execution_stopped_at.get_or_insert(now);
    t.stopped_at = Some(now);
    if let Some(r) = reason {
        t.stopped_reason = Some(r);
    }
    t.stop_code.get_or_insert_with(|| "UserInitiated".into());
    t.connectivity = Some("DISCONNECTED".into());
    t.connectivity_at = Some(now);
    for c in t.containers.iter_mut().flatten() {
        c.last_status = Some("STOPPED".into());
        for a in c.managed_agents.iter_mut().flatten() {
            a.last_status = Some("STOPPED".into());
        }
    }
    for a in t.attachments.iter_mut().flatten() {
        a.status = Some("DELETED".into());
    }
    t.version += 1;
    rec.expires_at = Some(now + Duration::minutes(crate::tasks::STOPPED_RETENTION_MINUTES));
}

/// What the backend needs to know about a task record.
pub fn spec_of(rec: &TaskRecord) -> TaskSpec {
    let arn = rec.task.task_arn.clone().unwrap_or_default();
    let network = match rec.definition.network_mode.as_deref() {
        Some("awsvpc") => match &rec.vpc {
            Some((vpc, cidr, ip)) => {
                TaskNetwork::Awsvpc { vpc_id: vpc.clone(), vpc_cidr: cidr.clone(), ip: ip.clone() }
            }
            None => TaskNetwork::Awsvpc { vpc_id: String::new(), vpc_cidr: String::new(), ip: String::new() },
        },
        Some("host") => TaskNetwork::Host,
        Some("none") => TaskNetwork::None,
        _ => TaskNetwork::Bridge,
    };
    TaskSpec {
        task_id: arn.rsplit('/').next().unwrap_or_default().to_string(),
        task_arn: arn.clone(),
        cluster: rec.cluster.clone(),
        family: rec.definition.family.clone().unwrap_or_default(),
        revision: rec.definition.revision,
        account_id: crate::tasks::account_of_arn(&arn),
        region: crate::tasks::region_of_arn(&arn),
        network,
        volumes: rec
            .definition
            .volumes
            .iter()
            .flatten()
            .filter(|v| v.host.as_ref().and_then(|h| h.source_path.as_ref()).is_none())
            .filter_map(|v| v.name.clone())
            .collect(),
        pid_mode: rec.definition.pid_mode.clone(),
        ipc_mode: rec.definition.ipc_mode.clone(),
    }
}

/// The endpoint containers reach MWS at: loopback means the host, which
/// containers on a Docker network reach as `host.docker.internal`.
fn container_endpoint(endpoint: &str, network: &TaskNetwork) -> String {
    if matches!(network, TaskNetwork::Host) {
        return endpoint.to_string();
    }
    endpoint.replace("://127.0.0.1", "://host.docker.internal").replace("://localhost", "://host.docker.internal")
}

/// The endpoint containers fetch task role credentials from. The SDKs'
/// container credentials provider talks plain HTTP only to loopback and
/// ECS's link-local `169.254.170.2`, which the Docker backend routes to the
/// host for containers outside the host network.
pub(crate) fn credentials_endpoint(endpoint: &str, network: &TaskNetwork) -> String {
    if matches!(network, TaskNetwork::Host) {
        return endpoint.to_string();
    }
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return container_endpoint(endpoint, network);
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let port = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') || authority.starts_with('[') => format!(":{port}"),
        _ => String::new(),
    };
    format!("http://169.254.170.2{port}{path}")
}

/// `repositoryCredentials` secrets hold `{"username": ..., "password": ...}`.
fn registry_auth(secret: &str) -> Option<crate::backend::RegistryAuth> {
    let v: serde_json::Value = serde_json::from_str(secret).ok()?;
    Some(crate::backend::RegistryAuth {
        username: v.get("username")?.as_str()?.to_string(),
        password: v.get("password")?.as_str()?.to_string(),
    })
}

/// Why an ECR pull failed, as the ECS agent words it.
fn registry_failure(image: &str, architecture: &str, e: crate::platform::RegistryPullError) -> StartFailure {
    use crate::platform::RegistryPullError as E;
    let (host, rest) = image.split_once('/').unwrap_or(("", image));
    let (repo, reference) = match rest.rsplit_once('@') {
        Some((r, d)) => (r, d),
        None => match rest.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r, t),
            _ => (rest, "latest"),
        },
    };
    let sep = if reference.starts_with("sha256:") { "@" } else { ":" };
    let full = format!("{host}/{repo}{sep}{reference}");
    match e {
        E::Auth(e) => StartFailure::Secrets(format!(
            "unable to retrieve ecr registry auth: service call has been retried 3 time(s): {}: {}",
            e.code, e.message
        )),
        E::Denied => StartFailure::Pull(format!(
            "failed to resolve ref {full}: pulling from host {host} failed with status code [manifests {reference}]: 403 Forbidden"
        )),
        E::NotFound => StartFailure::Pull(format!("failed to resolve ref {full}: {full}: not found")),
        E::Unsupported => StartFailure::Pull(format!(
            "failed to resolve ref {full}: no match for platform in manifest linux/{architecture}: not found"
        )),
    }
}

/// Why a task failed to start, as ECS words it.
enum StartFailure {
    Pull(String),
    Secrets(String),
    Role(String),
    Start(String),
    Dependency(String),
}

impl StartFailure {
    fn reason(&self) -> String {
        match self {
            Self::Pull(e) => format!("CannotPullContainerError: pull image manifest has been retried 1 time(s): {e}"),
            Self::Secrets(e) => format!(
                "ResourceInitializationError: unable to pull secrets or registry auth: execution resource retrieval failed: {e}"
            ),
            Self::Role(e) => format!("ResourceInitializationError: unable to assume role: {e}"),
            Self::Start(e) => format!("CannotStartContainerError: {e}"),
            Self::Dependency(e) => e.clone(),
        }
    }
}

impl Ecs {
    pub(crate) fn start_runner(&self, region_key: &str, arn: &str) {
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return };
        let signal = Arc::new(tokio::sync::Notify::new());
        self.inner.runners.lock().expect("ECS runner lock poisoned").insert(arn.to_string(), signal.clone());
        let me = self.clone();
        let key = region_key.to_string();
        let arn = arn.to_string();
        rt.spawn(async move {
            me.run_task(&key, &arn, signal).await;
            me.inner.runners.lock().expect("ECS runner lock poisoned").remove(&arn);
        });
    }

    /// Apply `f` to a task record, if it still exists. Bumps its version.
    fn update_task<R>(&self, key: &str, arn: &str, f: impl FnOnce(&mut TaskRecord) -> R) -> Option<R> {
        let mut st = self.lock();
        let rec = st.regions.get_mut(key)?.tasks.get_mut(arn)?;
        let out = f(rec);
        rec.task.version += 1;
        Some(out)
    }

    fn snapshot(&self, key: &str, arn: &str) -> Option<TaskRecord> {
        self.lock().regions.get(key)?.tasks.get(arn).cloned()
    }

    fn stop_wanted(&self, key: &str, arn: &str) -> bool {
        self.snapshot(key, arn).is_none_or(|r| r.task.desired_status.as_deref() == Some("STOPPED"))
    }

    async fn run_task(&self, key: &str, arn: &str, signal: Arc<tokio::sync::Notify>) {
        let Some(rec) = self.snapshot(key, arn) else { return };
        let account = crate::tasks::account_of_arn(arn);
        let region = crate::tasks::region_of_arn(arn);
        let ctx = self.background_context(&account, &region);
        let backend = self.backend();
        let spec = spec_of(&rec);
        let now = || self.now();

        // PROVISIONING -> PENDING: the network interface is attached.
        if rec.task.last_status.as_deref() == Some("PROVISIONING") {
            self.update_task(key, arn, |r| {
                for a in r.task.attachments.iter_mut().flatten() {
                    a.status = Some("ATTACHED".into());
                }
                r.task.last_status = Some("PENDING".into());
            });
        }
        self.update_task(key, arn, |r| {
            r.task.connectivity = Some("CONNECTED".into());
            r.task.connectivity_at = Some(now());
        });

        let started = self.prepare_and_start(key, arn, &rec, &spec, ctx.as_ref(), &signal).await;
        let (handle, runtime_ids) = match started {
            Ok(v) => v,
            Err((failure, handle, ids)) => {
                if let Some(f) = failure {
                    self.update_task(key, arn, |r| {
                        r.task.stop_code = Some("TaskFailedToStart".into());
                        r.task.stopped_reason = Some(f.reason());
                        r.task.desired_status = Some("STOPPED".into());
                    });
                }
                self.tear_down_task(key, arn, &rec, &spec, handle.as_deref(), &ids, ctx.as_ref()).await;
                return;
            }
        };

        // RUNNING until told to stop or an essential container exits.
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::channel::<(String, i32)>(16);
        // Backends that run nothing have nothing to wait for.
        let waitable = if backend.name() == "metadata" { BTreeMap::new() } else { runtime_ids.clone() };
        for (name, id) in &waitable {
            let tx = exit_tx.clone();
            let backend = backend.clone();
            let (name, id) = (name.clone(), id.clone());
            tokio::spawn(async move {
                if let Ok(code) = backend.wait(&id).await {
                    let _ = tx.send((name, code)).await;
                }
            });
        }
        drop(exit_tx);
        let done = Arc::new(AtomicBool::new(false));
        self.watch_health(key, arn, &rec, &runtime_ids, done.clone());
        let essentials: Vec<String> = rec
            .definition
            .container_definitions
            .iter()
            .flatten()
            .filter(|c| c.essential.unwrap_or(true))
            .filter_map(|c| c.name.clone())
            .collect();
        let mut exited: BTreeMap<String, i32> = BTreeMap::new();
        let mut waits_open = !waitable.is_empty();
        loop {
            if self.stop_wanted(key, arn) {
                break;
            }
            tokio::select! {
                _ = signal.notified() => {}
                got = exit_rx.recv(), if waits_open => {
                    let Some((name, code)) = got else {
                        waits_open = false;
                        continue;
                    };
                    exited.insert(name.clone(), code);
                    let at = now();
                    self.update_task(key, arn, |r| {
                        if let Some(c) = r.task.containers.iter_mut().flatten().find(|c| c.name.as_deref() == Some(&name)) {
                            c.last_status = Some("STOPPED".into());
                            c.exit_code = Some(code);
                        }
                        if essentials.contains(&name) && r.task.desired_status.as_deref() != Some("STOPPED") {
                            r.task.desired_status = Some("STOPPED".into());
                            r.task.stop_code = Some("EssentialContainerExited".into());
                            r.task.stopped_reason = Some("Essential container in task exited".into());
                            r.task.stopping_at = Some(at);
                        }
                    });
                    if waitable.keys().all(|n| exited.contains_key(n)) {
                        break;
                    }
                }
            }
        }
        done.store(true, Ordering::SeqCst);

        // DEACTIVATING -> STOPPING: containers get SIGTERM, then SIGKILL
        // after their stop timeout.
        self.update_task(key, arn, |r| {
            r.task.last_status = Some("DEACTIVATING".into());
            r.task.desired_status = Some("STOPPED".into());
            r.task.stopping_at.get_or_insert(now());
        });
        self.update_task(key, arn, |r| r.task.last_status = Some("STOPPING".into()));
        let timeouts: BTreeMap<String, i32> = rec
            .definition
            .container_definitions
            .iter()
            .flatten()
            .map(|c| (c.name.clone().unwrap_or_default(), c.stop_timeout.unwrap_or(30)))
            .collect();
        let mut stops = Vec::new();
        for (name, id) in runtime_ids.iter().filter(|(n, _)| !exited.contains_key(*n)) {
            let backend = backend.clone();
            let id = id.clone();
            let timeout = timeouts.get(name).copied().unwrap_or(30);
            stops.push(tokio::spawn(async move { backend.stop(&id, timeout).await }));
        }
        for s in stops {
            let _ = s.await;
        }
        // Collect the exit codes the stops produced.
        let deadline = tokio::time::sleep(StdDuration::from_secs(5));
        tokio::pin!(deadline);
        while waits_open && !waitable.keys().all(|n| exited.contains_key(n)) {
            tokio::select! {
                got = exit_rx.recv() => match got {
                    Some((name, code)) => { exited.insert(name, code); }
                    None => break,
                },
                _ = &mut deadline => break,
            }
        }
        self.update_task(key, arn, |r| {
            for c in r.task.containers.iter_mut().flatten() {
                if let Some(code) = c.name.as_ref().and_then(|n| exited.get(n)) {
                    c.exit_code = Some(*code);
                }
                c.last_status = Some("STOPPED".into());
            }
        });
        let ids: Vec<String> = runtime_ids.values().cloned().collect();
        self.tear_down_task(key, arn, &rec, &spec, Some(&handle), &ids, ctx.as_ref()).await;
    }

    /// DEPROVISIONING -> STOPPED: remove the containers and the network
    /// interface.
    #[allow(clippy::too_many_arguments)]
    async fn tear_down_task(
        &self,
        key: &str,
        arn: &str,
        rec: &TaskRecord,
        spec: &TaskSpec,
        handle: Option<&str>,
        runtime_ids: &[String],
        ctx: Option<&RequestContext>,
    ) {
        if rec.definition.network_mode.as_deref() == Some("awsvpc") {
            self.update_task(key, arn, |r| {
                r.task.last_status = Some("DEPROVISIONING".into());
                for a in r.task.attachments.iter_mut().flatten() {
                    a.status = Some("DETACHED".into());
                }
            });
        }
        if let Some(h) = handle {
            self.backend().cleanup(spec, h, runtime_ids).await;
        }
        if let (Some(eni), Some(p), Some(ctx)) = (rec.eni_id.as_deref(), self.platform(), ctx) {
            p.delete_interface(ctx, &spec.account_id, eni);
        }
        let now = self.now();
        let mut st = self.lock();
        if let Some(r) = st.regions.get_mut(key).and_then(|r| r.tasks.get_mut(arn)) {
            finish_stopped(r, now, None);
        }
    }

    /// Credentials, image pulls, secrets, then the containers in
    /// dependency order. On failure returns why (if the task should be
    /// reported as failed to start) and what to clean up.
    #[allow(clippy::type_complexity)]
    async fn prepare_and_start(
        &self,
        key: &str,
        arn: &str,
        rec: &TaskRecord,
        spec: &TaskSpec,
        ctx: Option<&RequestContext>,
        signal: &tokio::sync::Notify,
    ) -> Result<(String, BTreeMap<String, String>), (Option<StartFailure>, Option<String>, Vec<String>)> {
        let backend = self.backend();
        let platform = self.platform();
        let def = &rec.definition;
        let now = self.now();

        // Task role credentials, as the containers will see them.
        let mut task_creds: Option<RoleCredentials> = None;
        if let (Some(role), Some(p)) = (def.task_role_arn.as_deref(), platform.as_ref()) {
            match p.assume_task_role(role, arn, &spec.account_id, now) {
                Ok(c) => task_creds = Some(c),
                Err(e) => return Err((Some(StartFailure::Role(e)), None, Vec::new())),
            }
        }
        if let (Some(c), Some(role)) = (&task_creds, def.task_role_arn.as_deref()) {
            let stored = TaskCredentials {
                role_arn: role.to_string(),
                access_key_id: c.access_key_id.clone(),
                secret_access_key: c.secret_access_key.clone(),
                session_token: c.session_token.clone(),
                expiration: Some(c.expiration),
            };
            self.update_task(key, arn, |r| r.credentials = Some(stored));
        }
        // The execution role pulls images from ECR, reads secrets and
        // registry credentials, and writes awslogs output. ECS assumes it
        // whenever the task definition names one; failing to is fatal only
        // for what needs it.
        let mut exec_ctx: Option<RequestContext> = None;
        let mut exec_error: Option<String> = None;
        if let (Some(role), Some(p), Some(base)) = (def.execution_role_arn.as_deref(), platform.as_ref(), ctx) {
            match p.assume_task_role(role, arn, &spec.account_id, now) {
                Ok(c) => exec_ctx = p.role_context(base, &c),
                Err(e) => exec_error = Some(e),
            }
        }
        let exec_failure = |what: &str| {
            let why = match &exec_error {
                Some(e) => format!("unable to assume the execution role: {e}"),
                None => "the task has no usable execution role".to_string(),
            };
            StartFailure::Secrets(format!("{what}{why}"))
        };
        if exec_error.is_some() && def.container_definitions.iter().flatten().any(|c| c.secrets.is_some()) {
            return Err((Some(exec_failure("")), None, Vec::new()));
        }
        if let (Some(e), true) = (&exec_error, def.container_definitions.iter().flatten().any(is_awslogs)) {
            tracing::warn!(task = arn, "ECS cannot assume the execution role: {e}");
        }

        // Pull images: ECR images from MWS's own registry as the execution
        // role, others from their registry (logged in with
        // `repositoryCredentials`).
        self.update_task(key, arn, |r| r.task.pull_started_at = Some(self.now()));
        let architecture = match def.runtime_platform.as_ref().and_then(|p| p.cpu_architecture.as_deref()) {
            Some("ARM64") => "arm64",
            _ => "amd64",
        };
        let fargate = rec.task.launch_type.as_deref() == Some("FARGATE");
        let mut digests = BTreeMap::new();
        let mut local_images: BTreeMap<String, String> = BTreeMap::new();
        for c in def.container_definitions.iter().flatten() {
            let image = c.image.clone().unwrap_or_default();
            let name = c.name.clone().unwrap_or_default();
            if let Some(p) = platform.as_ref().filter(|p| p.is_registry_image(&image, &spec.account_id, &spec.region)) {
                // Fargate pulls ECR images with the execution role; EC2
                // container instances without one use their instance role,
                // which MWS does not model.
                let pull_ctx = match (def.execution_role_arn.is_some(), exec_ctx.as_ref()) {
                    (true, Some(c)) => Some(c),
                    (false, _) if !fargate => None,
                    _ => {
                        return Err((Some(exec_failure("unable to retrieve ecr registry auth: ")), None, Vec::new()));
                    }
                };
                match p.pull_registry_image(pull_ctx, &image, &spec.account_id, &spec.region, architecture) {
                    Ok(pulled) => {
                        let tag = crate::backend::local_tag(&pulled.digest);
                        if let Err(e) = backend.load_image(&tag, &pulled).await {
                            return Err((Some(StartFailure::Pull(format!("{image}: {e}"))), None, Vec::new()));
                        }
                        digests.insert(name.clone(), Some(pulled.resolved_digest.clone()));
                        local_images.insert(name, tag);
                        continue;
                    }
                    Err(e) => return Err((Some(registry_failure(&image, architecture, e)), None, Vec::new())),
                }
            }
            let mut auth = None;
            if let (Some(rc), Some(p)) = (c.repository_credentials.as_ref(), platform.as_ref()) {
                let Some(ectx) = exec_ctx.as_ref() else {
                    return Err((Some(exec_failure("")), None, Vec::new()));
                };
                match p.read_secret(ectx, &rc.credentials_parameter).await {
                    Ok(v) => auth = registry_auth(&v),
                    Err(e) => {
                        return Err((
                            Some(StartFailure::Secrets(format!(
                                "unable to retrieve secret from asm: service call has been retried 1 time(s): {}: {}",
                                e.code, e.message
                            ))),
                            None,
                            Vec::new(),
                        ));
                    }
                }
                if auth.is_none() {
                    return Err((
                        Some(StartFailure::Secrets(format!(
                            "unable to retrieve secret from asm: the secret {} does not hold a username and password",
                            rc.credentials_parameter
                        ))),
                        None,
                        Vec::new(),
                    ));
                }
            }
            match backend.pull(&image, auth.as_ref()).await {
                Ok(d) => {
                    digests.insert(name, d);
                }
                Err(e) => return Err((Some(StartFailure::Pull(format!("{image}: {e}"))), None, Vec::new())),
            }
        }
        self.update_task(key, arn, |r| {
            r.task.pull_stopped_at = Some(self.now());
            for c in r.task.containers.iter_mut().flatten() {
                if let Some(Some(d)) = c.name.as_ref().and_then(|n| digests.get(n)) {
                    c.image_digest = Some(d.clone());
                }
            }
        });
        if self.stop_wanted(key, arn) {
            return Err((None, None, Vec::new()));
        }

        // Container specs, with secrets resolved.
        let endpoint = ctx.and_then(|c| c.endpoint.clone());
        let mut specs = Vec::new();
        for c in def.container_definitions.iter().flatten() {
            let mut env: Vec<(String, String)> = Vec::new();
            for kv in c.environment.iter().flatten() {
                env.push((kv.name.clone().unwrap_or_default(), kv.value.clone().unwrap_or_default()));
            }
            for s in c.secrets.iter().flatten() {
                let (Some(p), Some(ectx)) = (platform.as_ref(), exec_ctx.as_ref()) else {
                    if platform.is_some() {
                        return Err((
                            Some(StartFailure::Secrets("the task has no usable execution role".into())),
                            None,
                            Vec::new(),
                        ));
                    }
                    continue;
                };
                match p.read_secret(ectx, &s.value_from).await {
                    Ok(v) => env.push((s.name.clone(), v)),
                    Err(e) => {
                        let source = if s.value_from.contains(":secretsmanager:") { "asm" } else { "ssm" };
                        return Err((
                            Some(StartFailure::Secrets(format!(
                                "unable to retrieve secret from {source}: service call has been retried 1 time(s): {}: {}",
                                e.code, e.message
                            ))),
                            None,
                            Vec::new(),
                        ));
                    }
                }
            }
            let name = c.name.clone().unwrap_or_default();
            let task_id = &spec.task_id;
            if let Some(ep) = &endpoint {
                let ep = container_endpoint(ep, &spec.network);
                env.push((
                    "ECS_CONTAINER_METADATA_URI_V4".into(),
                    format!("{ep}{}{task_id}/{name}", crate::metadata::PREFIX),
                ));
                env.push((
                    "ECS_CONTAINER_METADATA_URI".into(),
                    format!("{ep}{}{task_id}/{name}/v3", crate::metadata::PREFIX),
                ));
                env.push(("AWS_ENDPOINT_URL".into(), ep.clone()));
            }
            env.push(("AWS_REGION".into(), spec.region.clone()));
            env.push(("AWS_DEFAULT_REGION".into(), spec.region.clone()));
            let exec_env = match rec.task.launch_type.as_deref() {
                Some("FARGATE") => "AWS_ECS_FARGATE",
                Some("MANAGED_INSTANCES") => "AWS_ECS_MANAGED_INSTANCES",
                _ => "AWS_ECS_EC2",
            };
            env.push(("AWS_EXECUTION_ENV".into(), exec_env.into()));
            // The SDKs' container credentials provider fetches (and
            // refreshes) the task role session; no keys are in the
            // environment.
            if let (Some(_), Some(ep)) = (&task_creds, &endpoint) {
                env.push((
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                    format!(
                        "{}{}{task_id}/credentials",
                        credentials_endpoint(ep, &spec.network),
                        crate::metadata::PREFIX
                    ),
                ));
            }
            let mut cspec = container_spec(def, c, env);
            if let Some(tag) = local_images.get(&name) {
                cspec.image = tag.clone();
            }
            specs.push(cspec);
        }

        // Shared namespace, then the containers.
        let handle = match backend.prepare(spec).await {
            Ok(h) => h,
            Err(e) => return Err((Some(StartFailure::Start(e.0)), None, Vec::new())),
        };
        self.update_task(key, arn, |r| {
            r.handle = Some(handle.clone());
            r.task.last_status = Some("ACTIVATING".into());
        });
        let order = start_order(def);
        let mut runtime_ids: BTreeMap<String, String> = BTreeMap::new();
        let metadata_only = backend.name() == "metadata";
        for name in order {
            if self.stop_wanted(key, arn) {
                return Err((None, Some(handle), runtime_ids.values().cloned().collect()));
            }
            let Some(cdef) = def.container_definitions.iter().flatten().find(|c| c.name.as_deref() == Some(&name))
            else {
                continue;
            };
            // Dependencies first.
            for dep in cdef.depends_on.iter().flatten() {
                if metadata_only {
                    break;
                }
                let Some(dep_id) = runtime_ids.get(&dep.container_name).cloned() else { continue };
                let ok = match dep.condition.as_str() {
                    "COMPLETE" => backend.wait(&dep_id).await.is_ok(),
                    "SUCCESS" => backend.wait(&dep_id).await.is_ok_and(|c| c == 0),
                    "HEALTHY" => {
                        let mut healthy = false;
                        let timeout = cdef.start_timeout.unwrap_or(180).max(1) as u64;
                        let deadline = std::time::Instant::now() + StdDuration::from_secs(timeout);
                        while std::time::Instant::now() < deadline {
                            if backend.health(&dep_id).await == "HEALTHY" {
                                healthy = true;
                                break;
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(StdDuration::from_secs(1)) => {}
                                _ = signal.notified() => { signal.notify_one(); break; }
                            }
                        }
                        healthy
                    }
                    _ => true,
                };
                if !ok {
                    return Err((
                        Some(StartFailure::Dependency(format!(
                            "Container {name} dependency {} with condition {} was not satisfied",
                            dep.container_name, dep.condition
                        ))),
                        Some(handle),
                        runtime_ids.values().cloned().collect(),
                    ));
                }
            }
            let cspec = specs.iter().find(|s| s.name == name).cloned().unwrap_or_default();
            match backend.start(spec, &handle, &cspec).await {
                Ok(started) => {
                    runtime_ids.insert(name.clone(), started.runtime_id.clone());
                    let at = self.now();
                    self.update_task(key, arn, |r| {
                        r.runtime_ids.insert(name.clone(), started.runtime_id.clone());
                        if let Some(c) =
                            r.task.containers.iter_mut().flatten().find(|c| c.name.as_deref() == Some(&name))
                        {
                            c.runtime_id = Some(started.runtime_id.clone());
                            c.last_status = Some("RUNNING".into());
                            c.network_bindings = Some(
                                started
                                    .bindings
                                    .iter()
                                    .map(|(cp, hp, proto, ip)| t::NetworkBinding {
                                        bind_ip: Some(ip.clone()),
                                        container_port: Some(*cp),
                                        host_port: Some(*hp),
                                        protocol: Some(proto.clone()),
                                        ..Default::default()
                                    })
                                    .collect(),
                            );
                            for a in c.managed_agents.iter_mut().flatten() {
                                a.last_status = Some("RUNNING".into());
                                a.last_started_at = Some(at);
                            }
                        }
                    });
                    if is_awslogs(cdef) {
                        self.ship_logs(cdef, &started.runtime_id, spec, exec_ctx.clone());
                    }
                }
                Err(e) => {
                    return Err((
                        Some(StartFailure::Start(e.0)),
                        Some(handle),
                        runtime_ids.values().cloned().collect(),
                    ));
                }
            }
        }
        let at = self.now();
        self.update_task(key, arn, |r| {
            r.task.last_status = Some("RUNNING".into());
            r.task.started_at = Some(at);
            r.reached_running = true;
            let any_checks = r.definition.container_definitions.iter().flatten().any(|c| c.health_check.is_some());
            if !any_checks {
                r.task.health_status = Some("UNKNOWN".into());
            }
        });
        Ok((handle, runtime_ids))
    }

    /// Poll container health checks while the task runs.
    fn watch_health(
        &self,
        key: &str,
        arn: &str,
        rec: &TaskRecord,
        ids: &BTreeMap<String, String>,
        done: Arc<AtomicBool>,
    ) {
        let checked: Vec<(String, String, bool)> = rec
            .definition
            .container_definitions
            .iter()
            .flatten()
            .filter(|c| c.health_check.is_some())
            .filter_map(|c| {
                let name = c.name.clone()?;
                Some((name.clone(), ids.get(&name)?.clone(), c.essential.unwrap_or(true)))
            })
            .collect();
        if checked.is_empty() {
            return;
        }
        let me = self.clone();
        let (key, arn) = (key.to_string(), arn.to_string());
        tokio::spawn(async move {
            while !done.load(Ordering::SeqCst) {
                let mut states = Vec::new();
                for (name, id, essential) in &checked {
                    states.push((name.clone(), me.backend().health(id).await, *essential));
                }
                let found = me.update_task(&key, &arn, |r| {
                    for (name, h, _) in &states {
                        if let Some(c) =
                            r.task.containers.iter_mut().flatten().find(|c| c.name.as_deref() == Some(name))
                        {
                            c.health_status = Some(h.clone());
                        }
                    }
                    let essential: Vec<&String> = states.iter().filter(|s| s.2).map(|s| &s.1).collect();
                    r.task.health_status = Some(
                        if essential.iter().any(|h| *h == "UNHEALTHY") {
                            "UNHEALTHY"
                        } else if !essential.is_empty() && essential.iter().all(|h| *h == "HEALTHY") {
                            "HEALTHY"
                        } else {
                            "UNKNOWN"
                        }
                        .into(),
                    );
                });
                if found.is_none() {
                    break;
                }
                tokio::time::sleep(StdDuration::from_secs(2)).await;
            }
        });
    }

    /// Ship a container's output to CloudWatch Logs, as the awslogs driver
    /// does with the execution role.
    fn ship_logs(
        &self,
        c: &t::ContainerDefinition,
        runtime_id: &str,
        spec: &TaskSpec,
        exec_ctx: Option<RequestContext>,
    ) {
        let (Some(platform), Some(mut ctx)) = (self.platform(), exec_ctx) else { return };
        let options = c.log_configuration.as_ref().and_then(|l| l.options.clone()).unwrap_or_default();
        let Some(group) = options.get("awslogs-group").cloned() else { return };
        if let Some(region) = options.get("awslogs-region") {
            ctx.region = region.clone();
        }
        let name = c.name.clone().unwrap_or_default();
        let stream = match options.get("awslogs-stream-prefix") {
            Some(prefix) => format!("{prefix}/{name}/{}", spec.task_id),
            None => runtime_id.to_string(),
        };
        let create = options.get("awslogs-create-group").is_some_and(|v| v == "true");
        let backend = self.backend();
        let runtime_id = runtime_id.to_string();
        tokio::spawn(async move {
            let Some(mut rx) = backend.follow_logs(&runtime_id).await else { return };
            let mut batch: Vec<LogEvent> = Vec::new();
            let mut first = true;
            loop {
                let flush = tokio::time::sleep(StdDuration::from_millis(500));
                tokio::pin!(flush);
                let closed = loop {
                    tokio::select! {
                        line = rx.recv() => match line {
                            Some(l) => batch.push(LogEvent { timestamp_ms: l.timestamp_ms, message: l.message }),
                            None => break true,
                        },
                        _ = &mut flush => break false,
                    }
                };
                if !batch.is_empty() || (first && create) {
                    let events = std::mem::take(&mut batch);
                    ctx.received_at = Utc::now();
                    if let Err(e) = platform.write_logs(&ctx, &group, &stream, create && first, events) {
                        tracing::warn!(group, stream, "awslogs: {}: {}", e.code, e.message);
                    }
                    first = false;
                }
                if closed {
                    break;
                }
            }
        });
    }
}

fn is_awslogs(c: &t::ContainerDefinition) -> bool {
    c.log_configuration.as_ref().is_some_and(|l| l.log_driver == "awslogs")
}

/// Containers in an order that starts dependencies (and link targets)
/// first.
fn start_order(def: &t::TaskDefinition) -> Vec<String> {
    let containers: Vec<&t::ContainerDefinition> = def.container_definitions.iter().flatten().collect();
    let mut order: Vec<String> = Vec::new();
    let mut visiting: Vec<String> = Vec::new();
    fn visit(name: &str, containers: &[&t::ContainerDefinition], order: &mut Vec<String>, visiting: &mut Vec<String>) {
        if order.iter().any(|n| n == name) || visiting.iter().any(|n| n == name) {
            return;
        }
        visiting.push(name.to_string());
        if let Some(c) = containers.iter().find(|c| c.name.as_deref() == Some(name)) {
            for d in c.depends_on.iter().flatten() {
                visit(&d.container_name, containers, order, visiting);
            }
            for l in c.links.iter().flatten() {
                visit(l.split(':').next().unwrap_or_default(), containers, order, visiting);
            }
            for v in c.volumes_from.iter().flatten() {
                if let Some(s) = &v.source_container {
                    visit(s, containers, order, visiting);
                }
            }
        }
        visiting.retain(|n| n != name);
        order.push(name.to_string());
    }
    for c in &containers {
        if let Some(n) = &c.name {
            visit(n, &containers, &mut order, &mut visiting);
        }
    }
    order
}

fn container_spec(def: &t::TaskDefinition, c: &t::ContainerDefinition, env: Vec<(String, String)>) -> ContainerSpec {
    let host_paths: BTreeMap<String, String> = def
        .volumes
        .iter()
        .flatten()
        .filter_map(|v| Some((v.name.clone()?, v.host.as_ref()?.source_path.clone()?)))
        .collect();
    let lp = c.linux_parameters.clone().unwrap_or_default();
    ContainerSpec {
        name: c.name.clone().unwrap_or_default(),
        image: c.image.clone().unwrap_or_default(),
        entry_point: c.entry_point.clone(),
        command: c.command.clone(),
        env,
        working_directory: c.working_directory.clone(),
        user: c.user.clone(),
        ports: c
            .port_mappings
            .iter()
            .flatten()
            .filter_map(|m| {
                Some(PortSpec {
                    container_port: m.container_port?,
                    host_port: m.host_port.unwrap_or(0),
                    protocol: m.protocol.clone().unwrap_or_else(|| "tcp".into()),
                })
            })
            .collect(),
        mounts: c
            .mount_points
            .iter()
            .flatten()
            .filter_map(|m| {
                let src = m.source_volume.clone()?;
                let (source, host_path) = match host_paths.get(&src) {
                    Some(p) => (p.clone(), true),
                    None => (src, false),
                };
                Some(MountSpec {
                    source,
                    host_path,
                    container_path: m.container_path.clone()?,
                    read_only: m.read_only.unwrap_or(false),
                })
            })
            .collect(),
        volumes_from: c
            .volumes_from
            .iter()
            .flatten()
            .filter_map(|v| Some((v.source_container.clone()?, v.read_only.unwrap_or(false))))
            .collect(),
        links: c.links.clone().unwrap_or_default(),
        cpu: c.cpu,
        memory: c.memory,
        memory_reservation: c.memory_reservation,
        privileged: c.privileged.unwrap_or(false),
        read_only_root: c.readonly_root_filesystem.unwrap_or(false),
        hostname: c.hostname.clone(),
        dns_servers: c.dns_servers.clone().unwrap_or_default(),
        dns_search: c.dns_search_domains.clone().unwrap_or_default(),
        extra_hosts: c.extra_hosts.iter().flatten().map(|h| (h.hostname.clone(), h.ip_address.clone())).collect(),
        labels: c.docker_labels.iter().flatten().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ulimits: c.ulimits.iter().flatten().map(|u| (u.name.clone(), u.soft_limit, u.hard_limit)).collect(),
        init: lp.init_process_enabled.unwrap_or(false),
        cap_add: lp.capabilities.as_ref().and_then(|c| c.add.clone()).unwrap_or_default(),
        cap_drop: lp.capabilities.as_ref().and_then(|c| c.drop.clone()).unwrap_or_default(),
        sysctls: c
            .system_controls
            .iter()
            .flatten()
            .filter_map(|s| Some((s.namespace.clone()?, s.value.clone()?)))
            .collect(),
        tmpfs: lp
            .tmpfs
            .iter()
            .flatten()
            .map(|t| (t.container_path.clone(), t.size, t.mount_options.clone().unwrap_or_default()))
            .collect(),
        shared_memory_mib: lp.shared_memory_size,
        interactive: c.interactive.unwrap_or(false),
        tty: c.pseudo_terminal.unwrap_or(false),
        stop_timeout: c.stop_timeout.unwrap_or(30),
        health_check: c.health_check.as_ref().map(|h| HealthCheckSpec {
            command: h.command.clone(),
            interval: h.interval.unwrap_or(30),
            timeout: h.timeout.unwrap_or(5),
            retries: h.retries.unwrap_or(3),
            start_period: h.start_period.unwrap_or(0),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::RegistryPullError;

    #[test]
    fn credentials_go_through_the_link_local_endpoint() {
        let bridge = TaskNetwork::Bridge;
        assert_eq!(credentials_endpoint("http://127.0.0.1:4566", &bridge), "http://169.254.170.2:4566");
        assert_eq!(credentials_endpoint("http://localhost:4566/", &bridge), "http://169.254.170.2:4566/");
        assert_eq!(credentials_endpoint("http://10.0.0.5", &bridge), "http://169.254.170.2");
        assert_eq!(credentials_endpoint("http://127.0.0.1:4566", &TaskNetwork::Host), "http://127.0.0.1:4566");
    }

    #[test]
    fn registry_failures_read_as_the_agent_words_them() {
        let image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/app";
        assert_eq!(
            registry_failure(image, "amd64", RegistryPullError::NotFound).reason(),
            "CannotPullContainerError: pull image manifest has been retried 1 time(s): failed to resolve ref 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest: 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest: not found"
        );
        assert_eq!(
            registry_failure(&format!("{image}:v1"), "amd64", RegistryPullError::Denied).reason(),
            "CannotPullContainerError: pull image manifest has been retried 1 time(s): failed to resolve ref 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1: pulling from host 123456789012.dkr.ecr.us-east-1.amazonaws.com failed with status code [manifests v1]: 403 Forbidden"
        );
        let denied = mws_core::ServiceError::new(
            "AccessDeniedException",
            400,
            mws_core::ErrorFault::Client,
            "not authorized to perform: ecr:GetAuthorizationToken",
        );
        assert!(registry_failure(image, "amd64", RegistryPullError::Auth(denied)).reason().starts_with(
            "ResourceInitializationError: unable to pull secrets or registry auth: execution resource retrieval failed: unable to retrieve ecr registry auth: service call has been retried 3 time(s): AccessDeniedException"
        ));
    }

    #[test]
    fn registry_credentials_hold_a_username_and_password() {
        let a = registry_auth(r#"{"username":"u","password":"p"}"#).unwrap();
        assert_eq!((a.username.as_str(), a.password.as_str()), ("u", "p"));
        assert!(registry_auth("plain").is_none());
    }
}
