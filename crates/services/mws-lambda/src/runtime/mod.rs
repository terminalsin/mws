//! Running functions: execution environments that are real local
//! processes speaking the Lambda Runtime API.
//!
//! Each environment is one process (an interpreter running MWS's runtime
//! client for `python*` and `nodejs*`, or the package's own `bootstrap` for
//! `provided*`) plus a Runtime API endpoint on a loopback port of its own
//! (`AWS_LAMBDA_RUNTIME_API`). An environment serves one invocation at a
//! time and stays warm for later ones; more are started when all are busy,
//! up to the function's reserved concurrency. Environments of a changed or
//! deleted function, and ones idle for a while, are shut down.
//!
//! Container image functions run the same way, as containers (see
//! [`container`]).

mod container;

use std::collections::{BTreeMap, HashMap, HashSet};

pub use container::{image_tag, ContainerLaunch};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::{mpsc, oneshot, watch};

const PYTHON_BOOTSTRAP: &str = include_str!("bootstrap.py");
const NODE_BOOTSTRAP: &str = include_str!("bootstrap.mjs");

/// How long an idle environment stays warm.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Time allowed for a new environment to initialize, on top of the
/// function timeout.
const INIT_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response a function may return (6 MB).
pub const MAX_RESPONSE: usize = 6 * 1024 * 1024;

/// Everything needed to start an environment for one function version.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// Environments are shared only between invocations with the same key
    /// (function ARN, version and revision).
    pub pool_key: String,
    pub function_arn: String,
    pub version: String,
    pub runtime: String,
    pub code_dir: PathBuf,
    /// Extracted layers, in the order the function lists them.
    pub layer_dirs: Vec<PathBuf>,
    /// The complete environment, Lambda's reserved variables included.
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
    pub memory_mb: i32,
    /// Set for container image functions, which run as containers.
    pub container: Option<ContainerLaunch>,
}

/// One invocation to run.
#[derive(Debug, Clone)]
pub struct Job {
    pub request_id: String,
    pub payload: Vec<u8>,
    pub invoked_arn: String,
    pub client_context: Option<String>,
}

/// How an invocation ended.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub payload: Vec<u8>,
    /// `Some("Unhandled")` when the function failed.
    pub function_error: Option<String>,
    /// The invocation's log lines, START to REPORT.
    pub logs: String,
}

#[derive(Debug)]
pub enum LaunchError {
    /// The runtime cannot run on this machine.
    Unsupported(String),
    /// Reserved concurrency is used up.
    Throttled,
    /// A container's entry point cannot start.
    InvalidEntrypoint(String),
    Io(String),
}

enum Reply {
    Response(Vec<u8>),
    Error(Vec<u8>),
}

struct Pending {
    job: Job,
    deadline_ms: i64,
    reply: oneshot::Sender<Reply>,
}

/// State the Runtime API endpoint shares with the environment.
struct Api {
    jobs: tokio::sync::Mutex<mpsc::UnboundedReceiver<Pending>>,
    inflight: Mutex<HashMap<String, oneshot::Sender<Reply>>>,
    init_error: watch::Sender<Option<Vec<u8>>>,
}

struct Env {
    function_arn: String,
    busy: Mutex<bool>,
    jobs: mpsc::UnboundedSender<Pending>,
    api: Arc<Api>,
    logs: Arc<Mutex<Vec<u8>>>,
    /// Set (with a description) once the process has exited.
    exited: watch::Receiver<Option<String>>,
    kill: Mutex<Option<oneshot::Sender<()>>>,
    server: tokio::task::JoinHandle<()>,
    last_used: Mutex<Instant>,
    initialized: Mutex<bool>,
}

impl Env {
    fn alive(&self) -> bool {
        self.exited.borrow().is_none()
    }

    fn shutdown(&self) {
        if let Some(k) = self.kill.lock().expect("lock").take() {
            let _ = k.send(());
        }
        self.server.abort();
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Every execution environment, by pool key.
pub struct Runtimes {
    base: PathBuf,
    pools: Mutex<HashMap<String, Vec<Arc<Env>>>>,
    /// Container images loaded into the engine by this process.
    images: Mutex<HashSet<String>>,
    /// Serializes image loads.
    loading: tokio::sync::Mutex<()>,
}

impl Default for Runtimes {
    fn default() -> Self {
        let base = std::env::temp_dir().join(format!("mws-lambda-{}", std::process::id()));
        Self {
            base,
            pools: Mutex::new(HashMap::new()),
            images: Mutex::new(HashSet::new()),
            loading: tokio::sync::Mutex::new(()),
        }
    }
}

impl Runtimes {
    /// Where code and layers are extracted.
    pub fn base_dir(&self) -> &Path {
        &self.base
    }

    /// Stop every environment of `function_arn` (it changed or is gone).
    pub fn retire(&self, function_arn: &str) {
        let mut pools = self.pools.lock().expect("lock");
        for envs in pools.values_mut() {
            envs.retain(|e| {
                let keep = e.function_arn != function_arn;
                if !keep {
                    e.shutdown();
                }
                keep
            });
        }
        pools.retain(|_, v| !v.is_empty());
    }

    /// Stop every environment.
    pub fn retire_all(&self) {
        let mut pools = self.pools.lock().expect("lock");
        for envs in pools.values() {
            for e in envs {
                e.shutdown();
            }
        }
        pools.clear();
    }

    /// How many environments of `function_arn` are running an invocation.
    fn busy_count(pools: &HashMap<String, Vec<Arc<Env>>>, function_arn: &str) -> usize {
        pools.values().flatten().filter(|e| e.function_arn == function_arn && *e.busy.lock().expect("lock")).count()
    }

    /// How many environments are running an invocation: of
    /// `function_arn`, or of every function.
    pub fn concurrent(&self, function_arn: Option<&str>) -> usize {
        let pools = self.pools.lock().expect("lock");
        pools
            .values()
            .flatten()
            .filter(|e| function_arn.is_none_or(|f| e.function_arn == f) && *e.busy.lock().expect("lock"))
            .count()
    }

    /// Run `job` in a warm environment, starting one if none is free.
    /// `reserved` is the function's reserved concurrency.
    pub async fn invoke(&self, spec: &LaunchSpec, job: Job, reserved: Option<i32>) -> Result<Outcome, LaunchError> {
        let env = self.checkout(spec, reserved)?;
        let outcome = run(&env, spec, job).await;
        *env.busy.lock().expect("lock") = false;
        *env.last_used.lock().expect("lock") = Instant::now();
        if !env.alive() {
            self.remove(&env);
        }
        Ok(outcome)
    }

    fn remove(&self, env: &Arc<Env>) {
        let mut pools = self.pools.lock().expect("lock");
        for envs in pools.values_mut() {
            envs.retain(|e| !Arc::ptr_eq(e, env));
        }
    }

    fn checkout(&self, spec: &LaunchSpec, reserved: Option<i32>) -> Result<Arc<Env>, LaunchError> {
        let mut pools = self.pools.lock().expect("lock");
        // Reap environments that died or sat idle too long.
        for envs in pools.values_mut() {
            envs.retain(|e| {
                let idle = !*e.busy.lock().expect("lock") && e.last_used.lock().expect("lock").elapsed() > IDLE_TIMEOUT;
                let keep = e.alive() && !idle;
                if !keep {
                    e.shutdown();
                }
                keep
            });
        }
        if let Some(envs) = pools.get(&spec.pool_key) {
            for e in envs {
                let mut busy = e.busy.lock().expect("lock");
                if !*busy && e.alive() {
                    *busy = true;
                    return Ok(e.clone());
                }
            }
        }
        if let Some(r) = reserved {
            if Self::busy_count(&pools, &spec.function_arn) >= r.max(0) as usize {
                return Err(LaunchError::Throttled);
            }
        }
        let env = Arc::new(self.launch(spec)?);
        *env.busy.lock().expect("lock") = true;
        pools.entry(spec.pool_key.clone()).or_default().push(env.clone());
        Ok(env)
    }

    fn write_runtime_files(&self) -> std::io::Result<PathBuf> {
        let dir = self.base.join("runtime");
        std::fs::create_dir_all(&dir)?;
        for (name, body) in [("bootstrap.py", PYTHON_BOOTSTRAP), ("bootstrap.mjs", NODE_BOOTSTRAP)] {
            let path = dir.join(name);
            if std::fs::read_to_string(&path).ok().as_deref() != Some(body) {
                std::fs::write(&path, body)?;
            }
        }
        Ok(dir)
    }

    fn launch(&self, spec: &LaunchSpec) -> Result<Env, LaunchError> {
        let io = |e: std::io::Error| LaunchError::Io(e.to_string());
        let runtime_dir = self.write_runtime_files().map_err(io)?;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(io)?;
        listener.set_nonblocking(true).map_err(io)?;
        let addr = listener.local_addr().map_err(io)?;
        let listener = tokio::net::TcpListener::from_std(listener).map_err(io)?;

        let (jobs_tx, jobs_rx) = mpsc::unbounded_channel();
        let (init_tx, _) = watch::channel(None);
        let api = Arc::new(Api {
            jobs: tokio::sync::Mutex::new(jobs_rx),
            inflight: Mutex::new(HashMap::new()),
            init_error: init_tx,
        });
        let server = tokio::spawn(serve_api(listener, api.clone()));

        let mut env_vars = spec.env.clone();
        env_vars.insert("AWS_LAMBDA_RUNTIME_API".into(), addr.to_string());
        let mut container_name = None;
        let mut cmd = match &spec.container {
            Some(c) => {
                env_vars.insert("LAMBDA_RUNTIME_DIR".into(), "/var/runtime".into());
                env_vars.insert("LAMBDA_TASK_ROOT".into(), "/var/task".into());
                let name = format!("mws-lambda-{}", uuid::Uuid::new_v4().simple());
                let run =
                    container::command(c, &name, &spec.function_arn, spec.memory_mb, &env_vars).inspect_err(|_| {
                        server.abort();
                    })?;
                container_name = Some(name);
                let mut cmd = tokio::process::Command::new(run.program);
                cmd.args(&run.args).envs(&run.env);
                cmd
            }
            None => {
                let (program, args) = command_for(spec, &runtime_dir).inspect_err(|_| server.abort())?;
                env_vars.insert("LAMBDA_RUNTIME_DIR".into(), runtime_dir.display().to_string());
                env_vars.insert("LAMBDA_TASK_ROOT".into(), spec.code_dir.display().to_string());
                add_search_paths(&mut env_vars, spec);
                let mut cmd = tokio::process::Command::new(program);
                cmd.args(&args).current_dir(&spec.code_dir).env_clear().envs(&env_vars);
                cmd
            }
        };
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| {
            server.abort();
            LaunchError::Io(format!("starting {}: {e}", cmd.as_std().get_program().to_string_lossy()))
        })?;

        let logs = Arc::new(Mutex::new(Vec::new()));
        let label = spec.function_arn.rsplit(':').next().unwrap_or_default().to_string();
        if let Some(out) = child.stdout.take() {
            tokio::spawn(pump(out, logs.clone(), label.clone()));
        }
        if let Some(err) = child.stderr.take() {
            tokio::spawn(pump(err, logs.clone(), label));
        }
        let (exit_tx, exit_rx) = watch::channel(None);
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let status = tokio::select! {
                s = child.wait() => s,
                _ = kill_rx => {
                    if let Some(name) = &container_name {
                        container::remove(name).await;
                    }
                    let _ = child.kill().await;
                    child.wait().await
                }
            };
            let desc = match status {
                Ok(s) => match s.code() {
                    Some(c) => format!("exit status {c}"),
                    None => "signal: killed".to_string(),
                },
                Err(e) => e.to_string(),
            };
            let _ = exit_tx.send(Some(desc));
        });

        Ok(Env {
            function_arn: spec.function_arn.clone(),
            busy: Mutex::new(false),
            jobs: jobs_tx,
            api,
            logs,
            exited: exit_rx,
            kill: Mutex::new(Some(kill_tx)),
            server,
            last_used: Mutex::new(Instant::now()),
            initialized: Mutex::new(false),
        })
    }
}

/// The program and arguments that start `spec`'s runtime.
fn command_for(spec: &LaunchSpec, runtime_dir: &Path) -> Result<(PathBuf, Vec<String>), LaunchError> {
    let r = spec.runtime.as_str();
    if let Some(version) = r.strip_prefix("python") {
        // `MWS_LAMBDA_PYTHON` picks the interpreter (e.g. one with boto3
        // installed, as Lambda's Python runtimes have).
        let python = std::env::var_os("MWS_LAMBDA_PYTHON")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .or_else(|| find_program(&[&format!("python{version}"), "python3"]))
            .ok_or_else(|| LaunchError::Unsupported(format!("no Python interpreter found for {r}")))?;
        return Ok((python, vec![runtime_dir.join("bootstrap.py").display().to_string()]));
    }
    if r.starts_with("nodejs") {
        let node = std::env::var_os("MWS_LAMBDA_NODE")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .or_else(|| find_program(&["node"]))
            .ok_or_else(|| LaunchError::Unsupported(format!("no node binary found for {r}")))?;
        return Ok((node, vec![runtime_dir.join("bootstrap.mjs").display().to_string()]));
    }
    if r.starts_with("provided") || r == "go1.x" {
        let bootstrap = spec.code_dir.join("bootstrap");
        if !bootstrap.is_file() {
            return Err(LaunchError::Unsupported("Couldn't find valid bootstrap(s): [/var/task/bootstrap]".into()));
        }
        make_executable(&bootstrap);
        return Ok((bootstrap, Vec::new()));
    }
    Err(LaunchError::Unsupported(format!("MWS cannot run the {r} runtime locally")))
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut p = meta.permissions();
        p.set_mode(p.mode() | 0o755);
        let _ = std::fs::set_permissions(path, p);
    }
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn find_program(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for name in names {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Layer and runtime search paths, as Lambda sets them up under `/opt`.
fn add_search_paths(env: &mut BTreeMap<String, String>, spec: &LaunchSpec) {
    let sep = if cfg!(windows) { ";" } else { ":" };
    // Later layers take precedence, as their files overwrite earlier ones.
    let layers: Vec<&PathBuf> = spec.layer_dirs.iter().rev().collect();
    let join = |parts: Vec<String>, existing: Option<&String>| {
        let mut v: Vec<String> = parts;
        if let Some(e) = existing.filter(|e| !e.is_empty()) {
            v.push(e.clone());
        }
        v.join(sep)
    };
    let code = spec.code_dir.display().to_string();
    if spec.runtime.starts_with("python") {
        let ver = spec.runtime.trim_start_matches("python");
        let mut parts = vec![code.clone()];
        for l in &layers {
            parts.push(l.join("python").display().to_string());
            parts.push(l.join(format!("python/lib/python{ver}/site-packages")).display().to_string());
        }
        let v = join(parts, env.get("PYTHONPATH"));
        env.insert("PYTHONPATH".into(), v);
        env.entry("PYTHONUNBUFFERED".into()).or_insert_with(|| "1".into());
    }
    if spec.runtime.starts_with("nodejs") {
        let major = spec.runtime.trim_start_matches("nodejs").trim_end_matches(".x");
        let mut parts = Vec::new();
        for l in &layers {
            parts.push(l.join("nodejs/node_modules").display().to_string());
            parts.push(l.join(format!("nodejs/node{major}/node_modules")).display().to_string());
        }
        parts.push(spec.code_dir.join("node_modules").display().to_string());
        let v = join(parts, env.get("NODE_PATH"));
        env.insert("NODE_PATH".into(), v);
    }
    let bins: Vec<String> = layers.iter().map(|l| l.join("bin").display().to_string()).collect();
    let v = join(bins, env.get("PATH"));
    env.insert("PATH".into(), v);
    let libs: Vec<String> = layers.iter().map(|l| l.join("lib").display().to_string()).collect();
    let v = join(libs, env.get("LD_LIBRARY_PATH"));
    env.insert("LD_LIBRARY_PATH".into(), v);
}

/// Copy a process stream into the environment's log, line by line.
async fn pump(stream: impl AsyncRead + Unpin, logs: Arc<Mutex<Vec<u8>>>, label: String) {
    let mut lines = BufReader::new(stream).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::info!(target: "mws_lambda::function", function = %label, "{line}");
        let mut l = logs.lock().expect("lock");
        l.extend_from_slice(line.as_bytes());
        l.push(b'\n');
        // Keep the buffer bounded; invocations only need their own tail.
        if l.len() > 1 << 20 {
            let cut = l.len() - (1 << 19);
            l.drain(..cut);
        }
    }
}

fn append_log(env: &Env, line: &str) {
    let mut l = env.logs.lock().expect("lock");
    l.extend_from_slice(line.as_bytes());
    l.push(b'\n');
}

async fn run(env: &Arc<Env>, spec: &LaunchSpec, job: Job) -> Outcome {
    let started = Instant::now();
    let first = !std::mem::replace(&mut *env.initialized.lock().expect("lock"), true);
    let log_start = env.logs.lock().expect("lock").len();
    let request_id = job.request_id.clone();
    append_log(env, &format!("START RequestId: {request_id} Version: {}", spec.version));
    let deadline_ms = chrono::Utc::now().timestamp_millis() + spec.timeout.as_millis() as i64;
    let (reply_tx, reply_rx) = oneshot::channel();
    let _ = env.jobs.send(Pending { job, deadline_ms, reply: reply_tx });

    let limit = spec.timeout + if first { INIT_TIMEOUT } else { Duration::ZERO };
    let mut exited = env.exited.clone();
    let mut init_error = env.api.init_error.subscribe();
    let result = tokio::select! {
        r = reply_rx => match r {
            Ok(Reply::Response(p)) => Ok(p),
            Ok(Reply::Error(p)) => Err(p),
            Err(_) => Err(sandbox_error("Runtime.ExitError", &request_id, "Runtime exited without providing a reason")),
        },
        _ = tokio::time::sleep(limit) => {
            env.shutdown();
            let secs = spec.timeout.as_secs_f64();
            append_log(env, &format!("{} {request_id} Task timed out after {secs:.2} seconds", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ")));
            Err(sandbox_error("Sandbox.Timedout", &request_id, &format!("Task timed out after {secs:.2} seconds")))
        }
        status = exited.wait_for(Option::is_some) => {
            let desc = status.ok().and_then(|s| s.clone()).unwrap_or_default();
            // An init error the runtime reported says more than the exit.
            match env.api.init_error.borrow().clone() {
                Some(p) => Err(p),
                None => match (&spec.container, desc.as_str()) {
                    // The engine's command line reports a container whose
                    // entry point cannot start with these.
                    (Some(c), "exit status 126" | "exit status 127") => Err(sandbox_error(
                        "Runtime.InvalidEntrypoint",
                        &request_id,
                        &format!(
                            "fork/exec {}: no such file or directory",
                            c.entrypoint.first().or(c.command.first()).map(String::as_str).unwrap_or_default()
                        ),
                    )),
                    (Some(_), "exit status 137") => {
                        Err(sandbox_error("Runtime.ExitError", &request_id, "Runtime exited with error: signal: killed"))
                    }
                    _ => Err(sandbox_error("Runtime.ExitError", &request_id, &format!("Runtime exited with error: {desc}"))),
                },
            }
        }
        e = init_error.wait_for(Option::is_some) => {
            env.shutdown();
            Err(e.ok().and_then(|e| e.clone()).unwrap_or_default())
        }
    };
    // Give the log pumps a moment to drain what the function printed
    // before it answered.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (payload, function_error) = match result {
        Ok(p) if p.len() > MAX_RESPONSE => (
            serde_json::json!({
                "errorMessage": format!("Response payload size exceeded maximum allowed payload size ({MAX_RESPONSE} bytes)."),
                "errorType": "Function.ResponseSizeTooLarge",
            })
            .to_string()
            .into_bytes(),
            Some("Unhandled".to_string()),
        ),
        Ok(p) => (p, None),
        Err(p) => (p, Some("Unhandled".to_string())),
    };
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    append_log(env, &format!("END RequestId: {request_id}"));
    append_log(
        env,
        &format!(
            "REPORT RequestId: {request_id}\tDuration: {ms:.2} ms\tBilled Duration: {} ms\tMemory Size: {} MB\tMax Memory Used: {} MB",
            ms.ceil() as u64,
            spec.memory_mb,
            (spec.memory_mb / 3).max(16)
        ),
    );
    let logs = {
        let l = env.logs.lock().expect("lock");
        String::from_utf8_lossy(&l[log_start.min(l.len())..]).into_owned()
    };
    Outcome { payload, function_error, logs }
}

fn sandbox_error(error_type: &str, request_id: &str, message: &str) -> Vec<u8> {
    serde_json::json!({ "errorType": error_type, "errorMessage": format!("RequestId: {request_id} Error: {message}") })
        .to_string()
        .into_bytes()
}

// ---- the Runtime API endpoint -----------------------------------------------

async fn serve_api(listener: tokio::net::TcpListener, api: Arc<Api>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let api = api.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                let api = api.clone();
                async move { Ok::<_, Infallible>(handle_api(&api, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
}

fn reply(status: u16, body: serde_json::Value) -> http::Response<Full<Bytes>> {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("valid response")
}

async fn handle_api(api: &Api, req: http::Request<hyper::body::Incoming>) -> http::Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let rest = path.strip_prefix("/2018-06-01/runtime").unwrap_or("");
    match (method.as_str(), rest) {
        ("GET", "/invocation/next") => {
            let pending = api.jobs.lock().await.recv().await;
            let Some(p) = pending else {
                return reply(
                    500,
                    serde_json::json!({"errorType": "Runtime.Shutdown", "errorMessage": "shutting down"}),
                );
            };
            let id = p.job.request_id.clone();
            api.inflight.lock().expect("lock").insert(id.clone(), p.reply);
            let mut b = http::Response::builder()
                .status(200)
                .header("Lambda-Runtime-Aws-Request-Id", &id)
                .header("Lambda-Runtime-Deadline-Ms", p.deadline_ms.to_string())
                .header("Lambda-Runtime-Invoked-Function-Arn", &p.job.invoked_arn)
                .header("Lambda-Runtime-Trace-Id", trace_id(&id))
                .header("content-type", "application/json");
            if let Some(c) = &p.job.client_context {
                b = b.header("Lambda-Runtime-Client-Context", c);
            }
            b.body(Full::new(Bytes::from(p.job.payload))).expect("valid response")
        }
        ("POST", "/init/error") => {
            let payload = if body.is_empty() { b"{}".to_vec() } else { body.to_vec() };
            let _ = api.init_error.send(Some(payload));
            reply(202, serde_json::json!({"status": "OK"}))
        }
        ("POST", r) if r.starts_with("/invocation/") => {
            let tail = &r["/invocation/".len()..];
            let (id, kind) = match tail.rsplit_once('/') {
                Some(x) => x,
                None => return reply(404, serde_json::json!({"errorType": "InvalidRequest"})),
            };
            let Some(tx) = api.inflight.lock().expect("lock").remove(id) else {
                return reply(
                    400,
                    serde_json::json!({"errorType": "InvalidRequestID", "errorMessage": "Invalid request ID"}),
                );
            };
            let msg = match kind {
                "response" => Reply::Response(body.to_vec()),
                "error" => Reply::Error(if body.is_empty() { b"{}".to_vec() } else { body.to_vec() }),
                _ => return reply(404, serde_json::json!({"errorType": "InvalidRequest"})),
            };
            let _ = tx.send(msg);
            reply(202, serde_json::json!({"status": "OK"}))
        }
        _ => reply(404, serde_json::json!({"errorType": "InvalidRequest", "errorMessage": "unknown Runtime API path"})),
    }
}

/// An X-Ray style trace header for a request.
fn trace_id(request_id: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let hex: String = request_id.chars().filter(char::is_ascii_hexdigit).take(24).collect();
    format!("Root=1-{now:08x}-{hex:0<24};Parent={};Sampled=0;Lineage=1:0:0", &hex[..hex.len().min(16)])
}
