//! Managed runtimes (`nodejs*`, `python*`, `java*`, `dotnet*`, `ruby*`,
//! `provided*`) in AWS's own Lambda base images.
//!
//! With Docker, each execution environment of a `.zip` function is a
//! container of the runtime's base image (`public.ecr.aws/lambda/<lang>:<v>`,
//! the image AWS publishes for exactly this): the deployment package is
//! mounted at `/var/task` and the layers at `/opt`, read-only, and the
//! image's own runtime interface client talks to MWS's Runtime API. So the
//! language version, the bundled AWS SDK and the runtime's behaviour are
//! AWS's. Without Docker, `python*`, `nodejs*` and `provided*` functions run
//! as local processes (see [`super::command_for`]).
//!
//! `MWS_LAMBDA_RUNTIME_EXECUTOR` chooses: `auto` (the binary's default:
//! base images when a Docker daemon answers, local processes otherwise or
//! when an image cannot be pulled), `docker` (base images only) or `local`
//! (local processes only; the library's default).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use super::container::{docker, push_env, run_args, RunArgs};
use super::{find_program, make_executable, LaunchError, LaunchSpec, Runtimes};

/// Where the base images come from, unless `MWS_LAMBDA_IMAGE_REPOSITORY`
/// names a mirror.
const DEFAULT_REPOSITORY: &str = "public.ecr.aws/lambda";
/// How long a failed Docker probe is trusted before probing again.
const PROBE_RETRY: Duration = Duration::from_secs(30);

/// What runs functions of managed runtimes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeExecutor {
    /// AWS's base images when Docker is available, local processes
    /// otherwise.
    Auto,
    /// AWS's base images only.
    Docker,
    /// Local processes only.
    #[default]
    Local,
}

impl RuntimeExecutor {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "" | "auto" => Some(Self::Auto),
            "docker" | "podman" | "container" | "image" => Some(Self::Docker),
            "local" | "process" | "host" => Some(Self::Local),
            _ => None,
        }
    }
}

/// How a managed runtime's container starts.
#[derive(Debug, Clone)]
pub struct ManagedLaunch {
    /// The base image, e.g. `public.ecr.aws/lambda/nodejs:22`.
    pub image: String,
    /// `linux/amd64` or `linux/arm64` when the function's architecture is
    /// not the host's.
    pub platform: Option<String>,
}

/// The base image AWS publishes for `runtime`, by tag.
pub fn base_image(runtime: &str) -> Option<String> {
    let repo = std::env::var("MWS_LAMBDA_IMAGE_REPOSITORY")
        .ok()
        .map(|r| r.trim().trim_end_matches('/').to_string())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| DEFAULT_REPOSITORY.to_string());
    let (lang, tag) = image_name(runtime)?;
    Some(format!("{repo}/{lang}:{tag}"))
}

/// The repository and tag of `runtime`'s base image.
fn image_name(runtime: &str) -> Option<(&'static str, String)> {
    let r = runtime;
    fn tagged(v: &str) -> Option<&str> {
        (!v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')).then_some(v)
    }
    if let Some(v) = r.strip_prefix("nodejs") {
        return tagged(v.trim_end_matches(".x")).map(|v| ("nodejs", v.to_string()));
    }
    if let Some(v) = r.strip_prefix("python") {
        return tagged(v).map(|v| ("python", v.to_string()));
    }
    if let Some(v) = r.strip_prefix("java") {
        return tagged(v).map(|v| ("java", v.to_string()));
    }
    if let Some(v) = r.strip_prefix("dotnetcore") {
        return tagged(v).map(|v| ("dotnet", format!("core{v}")));
    }
    if let Some(v) = r.strip_prefix("dotnet") {
        return tagged(v).map(|v| ("dotnet", v.to_string()));
    }
    if let Some(v) = r.strip_prefix("ruby") {
        return tagged(v).map(|v| ("ruby", v.to_string()));
    }
    if r == "provided" {
        return Some(("provided", "alami".into()));
    }
    if let Some(v) = r.strip_prefix("provided.") {
        return tagged(v).map(|v| ("provided", v.to_string()));
    }
    if r == "go1.x" {
        return Some(("go", "1".into()));
    }
    None
}

/// Whether `runtime` can run as a local process on this machine.
fn runs_locally(runtime: &str) -> bool {
    if let Some(v) = runtime.strip_prefix("python") {
        return std::env::var_os("MWS_LAMBDA_PYTHON").is_some_and(|p| !p.is_empty())
            || find_program(&[&format!("python{v}"), "python3"]).is_some();
    }
    if runtime.starts_with("nodejs") {
        return std::env::var_os("MWS_LAMBDA_NODE").is_some_and(|p| !p.is_empty()) || find_program(&["node"]).is_some();
    }
    runtime.starts_with("provided") || runtime == "go1.x"
}

/// Docker's name for a function architecture.
fn docker_arch(architecture: &str) -> &'static str {
    if architecture == "arm64" {
        "arm64"
    } else {
        "amd64"
    }
}

/// The architecture of the machine MWS runs on, in Docker's terms.
fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" | "arm64" => "arm64",
        _ => "amd64",
    }
}

impl Runtimes {
    /// Choose what runs functions of managed runtimes.
    pub fn set_executor(&self, executor: RuntimeExecutor) {
        *self.executor.lock().expect("lock") = executor;
    }

    pub fn executor(&self) -> RuntimeExecutor {
        *self.executor.lock().expect("lock")
    }

    /// Whether a Docker daemon answers. A success is remembered; a failure
    /// is probed again after a while, so Docker started later is found.
    async fn docker_available(&self) -> bool {
        if let Some((ok, at)) = *self.docker_probe.lock().expect("lock") {
            if ok || at.elapsed() < PROBE_RETRY {
                return ok;
            }
        }
        let ok = tokio::process::Command::new(docker())
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success());
        *self.docker_probe.lock().expect("lock") = Some((ok, Instant::now()));
        ok
    }

    /// How `runtime` functions of `architecture` run: in a base image
    /// (`Some`) or as local processes (`None`). Pulls the image first if
    /// Docker does not have it yet.
    pub async fn plan_managed(&self, runtime: &str, architecture: &str) -> Result<Option<ManagedLaunch>, LaunchError> {
        let executor = self.executor();
        if executor == RuntimeExecutor::Local {
            return Ok(None);
        }
        let Some(image) = base_image(runtime) else {
            return match executor {
                RuntimeExecutor::Docker => {
                    Err(LaunchError::Unsupported(format!("MWS has no Lambda base image for the {runtime} runtime")))
                }
                _ => Ok(None),
            };
        };
        if !self.docker_available().await {
            return match executor {
                RuntimeExecutor::Docker => Err(LaunchError::Unsupported(format!(
                    "MWS_LAMBDA_RUNTIME_EXECUTOR is docker, but Docker is not available to run {image}"
                ))),
                _ => Ok(None),
            };
        }
        let arch = docker_arch(architecture);
        let platform = (arch != host_arch()).then(|| format!("linux/{arch}"));
        match self.ensure_base_image(&image, platform.as_deref()).await {
            Ok(()) => Ok(Some(ManagedLaunch { image, platform })),
            Err(e) if executor == RuntimeExecutor::Auto && runs_locally(runtime) => {
                tracing::warn!("cannot use {image} ({e}); running {runtime} functions as local processes");
                Ok(None)
            }
            Err(e) => Err(LaunchError::Unsupported(format!(
                "MWS runs {runtime} functions in {image}, which could not be pulled: {e}"
            ))),
        }
    }

    /// Make sure Docker has `image` (for `platform`), pulling it once.
    /// A failed pull is not retried by this process.
    async fn ensure_base_image(&self, image: &str, platform: Option<&str>) -> Result<(), String> {
        let key = format!("{image}|{}", platform.unwrap_or_default());
        if self.images.lock().expect("lock").contains(&key) {
            return Ok(());
        }
        if let Some(e) = self.pull_failures.lock().expect("lock").get(&key) {
            return Err(e.clone());
        }
        let _guard = self.loading.lock().await;
        if self.images.lock().expect("lock").contains(&key) {
            return Ok(());
        }
        let inspect = tokio::process::Command::new(docker())
            .args(["image", "inspect", "--format", "{{.Architecture}}", image])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await
            .map_err(|e| e.to_string())?;
        let have = inspect.status.success()
            && platform.is_none_or(|p| p.ends_with(&format!("/{}", String::from_utf8_lossy(&inspect.stdout).trim())));
        if !have {
            tracing::info!("pulling Lambda base image {image}");
            let mut cmd = tokio::process::Command::new(docker());
            cmd.arg("pull").arg("-q");
            if let Some(p) = platform {
                cmd.args(["--platform", p]);
            }
            let out = cmd.arg(image).stdin(Stdio::null()).output().await.map_err(|e| e.to_string())?;
            if !out.status.success() {
                let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let e = if e.is_empty() { format!("docker pull exited with {}", out.status) } else { e };
                self.pull_failures.lock().expect("lock").insert(key, e.clone());
                return Err(e);
            }
        }
        self.images.lock().expect("lock").insert(key);
        Ok(())
    }

    /// The layers merged into one directory for `/opt`, later layers over
    /// earlier ones as Lambda extracts them.
    fn merged_layers(&self, layers: &[PathBuf]) -> std::io::Result<Option<PathBuf>> {
        match layers {
            [] => Ok(None),
            [one] => Ok(Some(one.clone())),
            many => {
                let key: Vec<String> = many.iter().map(|l| l.display().to_string()).collect();
                let hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(key.join("\n").as_bytes()));
                let dir = self.base.join("opt").join(&hex[..32]);
                if !dir.join(".mws-complete").exists() {
                    for l in many {
                        copy_tree(l, &dir)?;
                    }
                    std::fs::write(dir.join(".mws-complete"), b"")?;
                }
                Ok(Some(dir))
            }
        }
    }
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".mws-complete" {
            continue;
        }
        let (src, dst) = (entry.path(), to.join(&name));
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            let _ = std::fs::remove_file(&dst);
            #[cfg(unix)]
            if kind.is_symlink() {
                std::os::unix::fs::symlink(std::fs::read_link(&src)?, &dst)?;
                continue;
            }
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// The `docker run` command line of a managed runtime's environment.
pub(super) fn command(
    runtimes: &Runtimes,
    m: &ManagedLaunch,
    spec: &LaunchSpec,
    name: &str,
    env: &BTreeMap<String, String>,
) -> Result<super::container::Command, LaunchError> {
    let io = |e: std::io::Error| LaunchError::Io(e.to_string());
    let opt = runtimes.merged_layers(&spec.layer_dirs).map_err(io)?;
    // Custom runtimes start the package's `bootstrap` (or a layer's), as
    // Lambda's init does; the other images start their own runtime client
    // through `/lambda-entrypoint.sh <handler>`.
    let entrypoint = if spec.runtime.starts_with("provided") || spec.runtime == "go1.x" {
        let candidates = [
            (spec.code_dir.join("bootstrap"), "/var/task/bootstrap"),
            (opt.clone().unwrap_or_default().join("bootstrap"), "/opt/bootstrap"),
        ];
        let Some((host, inside)) = candidates.iter().find(|(h, _)| h.is_file()) else {
            return Err(LaunchError::Unsupported(
                "Couldn't find valid bootstrap(s): [/var/task/bootstrap /opt/bootstrap]".into(),
            ));
        };
        make_executable(host);
        Some(inside.to_string())
    } else {
        None
    };
    let mut args = run_args(&RunArgs {
        name,
        function_arn: &spec.function_arn,
        memory_mb: spec.memory_mb,
        ephemeral_mb: spec.ephemeral_mb,
        platform: m.platform.as_deref(),
    });
    args.push("-v".into());
    args.push(format!("{}:/var/task:ro", spec.code_dir.display()));
    if let Some(opt) = &opt {
        args.push("-v".into());
        args.push(format!("{}:/opt:ro", opt.display()));
    }
    if let Some(e) = &entrypoint {
        args.push("--entrypoint".into());
        args.push(e.clone());
    }
    let mut by_name = BTreeMap::new();
    push_env(&mut args, env, &mut by_name);
    args.push(m.image.clone());
    if entrypoint.is_none() {
        args.push(env.get("_HANDLER").cloned().unwrap_or_default());
    }
    Ok(super::container::Command { program: docker(), args, env: by_name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtimes_map_to_aws_base_images() {
        for (runtime, image) in [
            ("nodejs22.x", "nodejs:22"),
            ("nodejs18.x", "nodejs:18"),
            ("python3.13", "python:3.13"),
            ("java21", "java:21"),
            ("java8.al2", "java:8.al2"),
            ("dotnet8", "dotnet:8"),
            ("dotnetcore3.1", "dotnet:core3.1"),
            ("ruby3.3", "ruby:3.3"),
            ("provided.al2023", "provided:al2023"),
            ("provided.al2", "provided:al2"),
            ("provided", "provided:alami"),
        ] {
            assert_eq!(base_image(runtime).as_deref(), Some(format!("public.ecr.aws/lambda/{image}").as_str()));
        }
        assert_eq!(base_image("cobol"), None);
        assert_eq!(base_image("nodejs"), None);
    }

    #[test]
    fn executor_names() {
        assert_eq!(RuntimeExecutor::parse("auto"), Some(RuntimeExecutor::Auto));
        assert_eq!(RuntimeExecutor::parse("Docker"), Some(RuntimeExecutor::Docker));
        assert_eq!(RuntimeExecutor::parse("local"), Some(RuntimeExecutor::Local));
        assert_eq!(RuntimeExecutor::parse("bogus"), None);
    }
}
