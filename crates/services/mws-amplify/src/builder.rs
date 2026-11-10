//! Builds for apps connected to a Git repository: clone, run the build
//! spec's commands with `bash` (or `sh`), deploy the artifacts.
//!
//! The build spec is the branch's, else the app's, else `amplify.yml` (or
//! `amplify.yaml`) in the repository. Monorepos use `applications:` with
//! `appRoot`; the one named by the `AMPLIFY_MONOREPO_APP_ROOT` environment
//! variable is built, else the first. `customHttp.yml` in the app root
//! sets the site's custom headers.
//!
//! Builds never see MWS's own environment: each command starts from an
//! empty environment with a `PATH`, a fresh `HOME` and a locale, then the
//! app's and branch's variables, Amplify's (`AWS_APP_ID`, `AWS_BRANCH`,
//! `AWS_JOB_ID`, ...), credentials for the app's service role
//! (`iamServiceRoleArn`, assumed as `amplify.amazonaws.com`) and the
//! Amplify secrets in Parameter Store as the `secrets` JSON map. Without a
//! service role a build gets no credentials.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncReadExt;

use crate::deploy::{glob_regex, Files};
use crate::jobs::JobRef;
use crate::Amplify;

/// Amplify's default build timeout.
const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_LOG: usize = 4 * 1024 * 1024;
/// How long a job stays `PROVISIONING` while its build environment is set
/// up, so pollers see the state as on Amplify.
const PROVISION_TIME: Duration = Duration::from_millis(500);
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The environment every build command starts from: nothing of MWS's own
/// but a `PATH` to find tools, a `HOME` inside the build directory (so no
/// `~/.aws`, `~/.gitconfig` or `~/.npmrc` of the host is read) and a locale.
fn base_env(dir: &Path) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let path = std::env::var("PATH").ok().filter(|p| !p.is_empty()).unwrap_or_else(|| DEFAULT_PATH.into());
    env.insert("PATH".into(), path);
    env.insert("HOME".into(), dir.join("home").to_string_lossy().into_owned());
    env.insert("TMPDIR".into(), dir.join("tmp").to_string_lossy().into_owned());
    env.insert("LANG".into(), "C.UTF-8".into());
    env.insert("CI".into(), "true".into());
    env
}

/// A command that sees `env` and nothing else.
fn command(program: &str, env: &BTreeMap<String, String>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    cmd.env_clear().envs(env);
    cmd
}

/// The `secrets` map from parameters under `prefix`: names relative to it.
fn add_secrets(secrets: &mut BTreeMap<String, String>, prefix: &str, params: Vec<(String, String)>) {
    for (name, value) in params {
        if let Some(key) = name.strip_prefix(prefix).filter(|k| !k.is_empty()) {
            secrets.insert(key.to_string(), value);
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct BuildSpec {
    env: Option<EnvSection>,
    backend: Option<Phases>,
    frontend: Option<Frontend>,
    applications: Vec<Application>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EnvSection {
    variables: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Application {
    app_root: Option<String>,
    backend: Option<Phases>,
    frontend: Option<Frontend>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Frontend {
    phases: BTreeMap<String, Phase>,
    artifacts: Option<Artifacts>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Phases {
    phases: BTreeMap<String, Phase>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Phase {
    commands: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Artifacts {
    base_directory: Option<String>,
    files: Vec<String>,
}

struct Plan {
    app_root: PathBuf,
    script: String,
    base_directory: PathBuf,
    patterns: Vec<String>,
    env: BTreeMap<String, String>,
}

fn yaml_scalar(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn plan(spec_text: &str, checkout: &Path, env: &BTreeMap<String, String>) -> Result<Plan, String> {
    let spec: BuildSpec = serde_yaml::from_str(spec_text).map_err(|e| format!("Invalid build spec: {e}"))?;
    let (root, backend, frontend) = if spec.applications.is_empty() {
        (None, spec.backend, spec.frontend)
    } else {
        let wanted = env.get("AMPLIFY_MONOREPO_APP_ROOT").map(|r| r.trim_matches('/').to_string());
        let mut apps = spec.applications;
        let index = wanted
            .and_then(|w| {
                apps.iter().position(|a| a.app_root.as_deref().map(|r| r.trim_matches('/')) == Some(w.as_str()))
            })
            .unwrap_or(0);
        let app = apps.swap_remove(index);
        (app.app_root, app.backend, app.frontend)
    };
    let frontend = frontend.ok_or("The build spec has no frontend section.")?;
    let app_root = match root.as_deref().map(|r| r.trim_matches('/')).filter(|r| !r.is_empty()) {
        Some(r) if !r.split('/').any(|c| c == "..") => checkout.join(r),
        Some(r) => return Err(format!("Invalid appRoot {r}")),
        None => checkout.to_path_buf(),
    };
    let mut env = env.clone();
    for (k, v) in spec.env.map(|e| e.variables).unwrap_or_default() {
        env.entry(k).or_insert_with(|| yaml_scalar(&v));
    }
    let mut script = String::from("set -e\n");
    let mut add = |section: &str, phases: &BTreeMap<String, Phase>| {
        for phase in ["preBuild", "build", "postBuild"] {
            let Some(p) = phases.get(phase) else { continue };
            script.push_str(&format!("echo {}\n", shell_quote(&format!("## Starting {section} {phase} phase"))));
            for c in &p.commands {
                script.push_str(&format!("echo {}\n{c}\n", shell_quote(&format!("# Executing command: {c}"))));
            }
        }
    };
    if let Some(b) = &backend {
        add("backend", &b.phases);
    }
    add("frontend", &frontend.phases);
    let artifacts = frontend.artifacts.unwrap_or_default();
    let base = artifacts.base_directory.unwrap_or_else(|| "/".into());
    let base = base.trim_matches('/');
    if base.split('/').any(|c| c == "..") {
        return Err(format!("Invalid artifacts baseDirectory {base}"));
    }
    let base_directory = if base.is_empty() { app_root.clone() } else { app_root.join(base) };
    let patterns = if artifacts.files.is_empty() { vec!["**/*".to_string()] } else { artifacts.files };
    Ok(Plan { app_root, script, base_directory, patterns, env })
}

/// Collect the files under `dir` that match any of `patterns`.
fn collect(dir: &Path, patterns: &[String]) -> Result<Files, String> {
    let globs: Vec<regex::Regex> = patterns.iter().filter_map(|p| glob_regex(p)).collect();
    let mut files = Files::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| format!("Reading {} failed: {e}", d.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                if entry.file_name() != ".git" {
                    stack.push(path);
                }
                continue;
            }
            let rel = path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().replace('\\', "/");
            if globs.iter().any(|g| g.is_match(&rel)) {
                if let Ok(data) = std::fs::read(&path) {
                    files.insert(rel, data);
                }
            }
        }
    }
    Ok(files)
}

/// Run a command, appending its output to the job log; `Err` on failure,
/// timeout or stop.
async fn run(
    amplify: &Amplify,
    job: &JobRef,
    stop: &tokio::sync::Notify,
    mut cmd: tokio::process::Command,
    what: &str,
) -> Result<String, String> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("Starting {what} failed: {e}"))?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let collect_output = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _ = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        out.extend_from_slice(&err);
        out
    };
    let result = tokio::select! {
        r = async { let out = collect_output.await; (child.wait().await, out) } => Some(r),
        _ = stop.notified() => None,
        _ = tokio::time::sleep(BUILD_TIMEOUT) => {
            amplify.append_log(job, "Build timed out");
            None
        }
    };
    let Some((status, output)) = result else {
        return Err(format!("{what} was stopped."));
    };
    let mut text = String::from_utf8_lossy(&output).to_string();
    if text.len() > MAX_LOG {
        text.truncate(MAX_LOG);
    }
    amplify.append_log(job, &text);
    match status {
        Ok(s) if s.success() => Ok(text),
        Ok(s) => Err(format!("{what} failed with {s}.")),
        Err(e) => Err(format!("{what} failed: {e}")),
    }
}

fn shell() -> &'static str {
    if Path::new("/bin/bash").exists() || Path::new("/usr/bin/bash").exists() {
        "bash"
    } else {
        "sh"
    }
}

/// The URL git clones, with the access token for HTTPS repositories.
fn clone_url(repository: &str, token: Option<&str>) -> String {
    match (repository.strip_prefix("https://"), token) {
        (Some(rest), Some(t)) if !t.is_empty() && !rest.contains('@') => format!("https://x-access-token:{t}@{rest}"),
        _ => repository.to_string(),
    }
}

/// What a build needs to know about its app.
struct AppFacts {
    account: String,
    region: String,
    app_arn: String,
    service_role: Option<String>,
}

impl Amplify {
    pub(crate) async fn run_build(&self, job: JobRef, stop: Arc<tokio::sync::Notify>) {
        let lock = self.branch_lock(&job.app_id, &job.branch);
        let _guard = tokio::select! {
            g = lock.lock() => g,
            _ = stop.notified() => {
                self.finish_job(&job, false, Some("Job was stopped before it started.".into()));
                return;
            }
        };
        if self.job_status(&job).as_deref() != Some("PENDING") {
            self.inner.running.lock().expect("running jobs lock").remove(&job.key());
            return;
        }
        self.with_job(&job, |j| j.summary.status = "PROVISIONING".into());
        let dir = std::env::temp_dir().join("mws-amplify").join(format!(
            "{}-{}-{}-{}",
            job.app_id,
            crate::names::display_name(&job.branch),
            job.job_id,
            uuid::Uuid::new_v4().simple()
        ));
        let result = self.run_build_steps(&job, &stop, &dir).await;
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(()) => self.finish_job(&job, true, None),
            Err(e) => self.finish_job(&job, false, Some(e)),
        }
    }

    /// Set up the build's environment while the job is `PROVISIONING`: the
    /// service role's credentials and the app's secrets.
    async fn provision(
        &self,
        job: &JobRef,
        stop: &tokio::sync::Notify,
        dir: &Path,
        app: &AppFacts,
    ) -> Result<BTreeMap<String, String>, String> {
        for d in ["home", "tmp"] {
            std::fs::create_dir_all(dir.join(d)).map_err(|e| format!("Creating the build directory failed: {e}"))?;
        }
        let mut env = base_env(dir);
        env.insert("AWS_REGION".into(), app.region.clone());
        env.insert("AWS_DEFAULT_REGION".into(), app.region.clone());
        let role = app.service_role.as_deref().filter(|r| !r.is_empty());
        match (role, self.platform()) {
            (Some(role), Some(platform)) => {
                let mut template = job.ctx.clone();
                template.region = app.region.clone();
                template.received_at = job.clock.now();
                template.source_ip = None;
                let session_name = format!("amplify-{}-{}", job.app_id, job.job_id);
                let session = platform
                    .assume_role(&template, role, &session_name, &app.account, &app.app_arn)
                    .map_err(|e| {
                        tracing::debug!("Amplify could not assume {role}: {e}");
                        "Unable to assume specified IAM Role. Please ensure the selected IAM Role has sufficient permissions and the Trust Relationship is configured correctly.".to_string()
                    })?;
                self.append_log(job, &format!("Assumed the service role {role}"));
                env.insert("AWS_ACCESS_KEY_ID".into(), session.access_key_id.clone());
                env.insert("AWS_SECRET_ACCESS_KEY".into(), session.secret_access_key.clone());
                env.insert("AWS_SESSION_TOKEN".into(), session.session_token.clone());
                let mut secrets = BTreeMap::new();
                let shared = format!("/amplify/shared/{}/", job.app_id);
                let own = format!("/amplify/{}/{}/", job.app_id, job.branch);
                for prefix in [shared, own] {
                    match platform.parameters_by_path(&session.context, &prefix).await {
                        Ok(params) => add_secrets(&mut secrets, &prefix, params),
                        Err(e) => self.append_log(job, &format!("Unable to read secrets under {prefix}: {e}")),
                    }
                }
                if !secrets.is_empty() {
                    self.append_log(job, &format!("Loaded {} secrets from Parameter Store", secrets.len()));
                    env.insert("secrets".into(), serde_json::to_string(&secrets).unwrap_or_default());
                }
            }
            _ => {
                // No role, no credentials: SDKs in the build must not find
                // any elsewhere either.
                env.insert("AWS_EC2_METADATA_DISABLED".into(), "true".into());
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(PROVISION_TIME) => Ok(env),
            _ = stop.notified() => Err("The build was stopped.".into()),
        }
    }

    async fn run_build_steps(&self, job: &JobRef, stop: &tokio::sync::Notify, dir: &Path) -> Result<(), String> {
        let (repository, token, branch_arn, spec, mut env, commit, app) = {
            let st = self.read();
            let rec = st.apps.get(&job.app_id).ok_or("The app was deleted.")?;
            let b = rec.branches.get(&job.branch).ok_or("The branch was deleted.")?;
            let j = b.jobs.get(&job.job_id).ok_or("The job was deleted.")?;
            let mut env = rec.app.environment_variables.clone();
            env.extend(b.branch.environment_variables.clone());
            let spec = b.branch.build_spec.clone().or(rec.app.build_spec.clone());
            let app = AppFacts {
                account: rec.account.clone(),
                region: rec.region.clone(),
                app_arn: rec.app.app_arn.clone(),
                service_role: rec.app.iam_service_role_arn.clone(),
            };
            (
                rec.app.repository.clone(),
                rec.repository_token.clone(),
                b.branch.branch_arn.clone(),
                spec,
                env,
                j.summary.commit_id.clone(),
                app,
            )
        };
        let base = self.provision(job, stop, dir, &app).await?;
        self.with_job(job, |j| j.summary.status = "RUNNING".into());
        self.set_step(job, "BUILD", "RUNNING");

        self.append_log(job, &format!("Cloning repository: {repository}"));
        let checkout = dir.join("src");
        let mut git_env = base_env(dir);
        git_env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        git_env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
        let mut clone = command("git", &git_env);
        clone.arg("clone").arg("--quiet");
        let pinned = !commit.is_empty() && commit != "HEAD";
        if !pinned {
            clone.args(["--depth", "1", "--branch", &job.branch]);
        }
        clone.arg(clone_url(&repository, token.as_deref())).arg(&checkout);
        run(self, job, stop, clone, "git clone")
            .await
            .map_err(|e| e.replace(token.as_deref().unwrap_or("\u{0}"), "****"))?;
        if pinned {
            let mut co = command("git", &git_env);
            co.current_dir(&checkout).args(["checkout", "--quiet", &commit]);
            run(self, job, stop, co, "git checkout").await?;
        }
        let mut rev = command("git", &git_env);
        rev.current_dir(&checkout).args(["log", "-1", "--format=%H%n%s"]);
        let head = run(self, job, stop, rev, "git log").await?;
        let mut lines = head.lines();
        let (sha, subject) = (lines.next().unwrap_or("").to_string(), lines.next().unwrap_or("").to_string());
        self.with_job(job, |j| {
            if j.summary.commit_id.is_empty() || j.summary.commit_id == "HEAD" {
                j.summary.commit_id = sha.clone();
            }
            if j.summary.commit_message.is_empty() {
                j.summary.commit_message = subject.clone();
            }
        });

        let spec = match spec {
            Some(s) => s,
            None => ["amplify.yml", "amplify.yaml"]
                .iter()
                .find_map(|f| std::fs::read_to_string(checkout.join(f)).ok())
                .ok_or("No build spec: set buildSpec on the app or branch, or add amplify.yml to the repository.")?,
        };
        env.insert("AWS_APP_ID".into(), job.app_id.clone());
        env.insert("AWS_BRANCH".into(), job.branch.clone());
        env.insert("AWS_BRANCH_ARN".into(), branch_arn);
        env.insert("AWS_JOB_ID".into(), format!("{:010}", job.job_id));
        env.insert("AWS_COMMIT_ID".into(), sha);
        env.insert("AWS_CLONE_URL".into(), repository.clone());
        env.insert("AWS_ENDPOINT_URL".into(), job.endpoint.clone());
        // Amplify's own variables and the credentials win over the app's.
        let mut build_env = env;
        build_env.extend(base);
        let plan = plan(&spec, &checkout, &build_env)?;
        let mut sh = command(shell(), &plan.env);
        sh.current_dir(&plan.app_root).arg("-c").arg(&plan.script);
        run(self, job, stop, sh, "The build").await?;
        let files = collect(&plan.base_directory, &plan.patterns)?;
        if files.is_empty() {
            return Err(format!("No artifacts were found in {}.", plan.base_directory.display()));
        }
        let custom_headers = ["customHttp.yml", "customHttp.yaml"]
            .iter()
            .find_map(|f| std::fs::read_to_string(plan.app_root.join(f)).ok());
        self.set_step(job, "BUILD", "SUCCEED");

        self.set_step(job, "DEPLOY", "RUNNING");
        self.append_log(job, &format!("Deploying {} files", files.len()));
        self.publish(job, files, custom_headers, true);
        self.set_step(job, "DEPLOY", "SUCCEED");
        self.set_step(job, "VERIFY", "RUNNING");
        self.set_step(job, "VERIFY", "SUCCEED");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_frontend_builds() {
        let spec = "version: 1\nfrontend:\n  phases:\n    preBuild:\n      commands:\n        - npm ci\n    build:\n      commands:\n        - npm run build\n  artifacts:\n    baseDirectory: dist\n    files:\n      - '**/*'\n";
        let p = plan(spec, Path::new("/src"), &BTreeMap::new()).unwrap();
        assert!(p.script.contains("npm ci\n") && p.script.contains("npm run build\n"));
        assert_eq!(p.base_directory, Path::new("/src/dist"));
    }

    #[test]
    fn plans_monorepo_apps() {
        let spec = "version: 1\napplications:\n  - appRoot: web\n    frontend:\n      phases:\n        build:\n          commands: [make]\n      artifacts:\n        baseDirectory: out\n";
        let p = plan(spec, Path::new("/src"), &BTreeMap::new()).unwrap();
        assert_eq!(p.app_root, Path::new("/src/web"));
        assert_eq!(p.base_directory, Path::new("/src/web/out"));
    }
}
