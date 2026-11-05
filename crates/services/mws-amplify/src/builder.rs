//! Builds for apps connected to a Git repository: clone, run the build
//! spec's commands with `bash` (or `sh`), deploy the artifacts.
//!
//! The build spec is the branch's, else the app's, else `amplify.yml` (or
//! `amplify.yaml`) in the repository. Monorepos use `applications:` with
//! `appRoot`; the one named by the `AMPLIFY_MONOREPO_APP_ROOT` environment
//! variable is built, else the first. `customHttp.yml` in the app root
//! sets the site's custom headers.

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
            .and_then(|w| apps.iter().position(|a| a.app_root.as_deref().map(|r| r.trim_matches('/')) == Some(w.as_str())))
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
        let dir = std::env::temp_dir()
            .join("mws-amplify")
            .join(format!("{}-{}-{}-{}", job.app_id, crate::names::display_name(&job.branch), job.job_id, uuid::Uuid::new_v4().simple()));
        let result = self.run_build_steps(&job, &stop, &dir).await;
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(()) => self.finish_job(&job, true, None),
            Err(e) => self.finish_job(&job, false, Some(e)),
        }
    }

    async fn run_build_steps(&self, job: &JobRef, stop: &tokio::sync::Notify, dir: &Path) -> Result<(), String> {
        let (repository, token, branch_arn, spec, mut env, commit) = {
            let st = self.read();
            let rec = st.apps.get(&job.app_id).ok_or("The app was deleted.")?;
            let b = rec.branches.get(&job.branch).ok_or("The branch was deleted.")?;
            let j = b.jobs.get(&job.job_id).ok_or("The job was deleted.")?;
            let mut env = rec.app.environment_variables.clone();
            env.extend(b.branch.environment_variables.clone());
            let spec = b.branch.build_spec.clone().or(rec.app.build_spec.clone());
            (
                rec.app.repository.clone(),
                rec.repository_token.clone(),
                b.branch.branch_arn.clone(),
                spec,
                env,
                j.summary.commit_id.clone(),
            )
        };
        self.with_job(job, |j| j.summary.status = "RUNNING".into());
        self.set_step(job, "BUILD", "RUNNING");

        self.append_log(job, &format!("Cloning repository: {repository}"));
        std::fs::create_dir_all(dir).map_err(|e| format!("Creating the build directory failed: {e}"))?;
        let checkout = dir.join("src");
        let mut clone = tokio::process::Command::new("git");
        clone.env("GIT_TERMINAL_PROMPT", "0").arg("clone").arg("--quiet");
        let pinned = !commit.is_empty() && commit != "HEAD";
        if !pinned {
            clone.args(["--depth", "1", "--branch", &job.branch]);
        }
        clone.arg(clone_url(&repository, token.as_deref())).arg(&checkout);
        run(self, job, stop, clone, "git clone").await.map_err(|e| e.replace(token.as_deref().unwrap_or("\u{0}"), "****"))?;
        if pinned {
            let mut co = tokio::process::Command::new("git");
            co.current_dir(&checkout).args(["checkout", "--quiet", &commit]);
            run(self, job, stop, co, "git checkout").await?;
        }
        let mut rev = tokio::process::Command::new("git");
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
        let plan = plan(&spec, &checkout, &env)?;
        let mut sh = tokio::process::Command::new(shell());
        sh.current_dir(&plan.app_root).arg("-c").arg(&plan.script).envs(&plan.env);
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
