//! Jobs: manual deployments, repository builds, their steps, artifacts and
//! logs, and access logs.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::apps::{app, app_mut, authorize, branch, branch_mut};
use crate::deploy::{Files, Origin, Source};
use crate::generated::types;
use crate::names::{self, bad_request, not_found};
use crate::state::{ArtifactRecord, Download, JobRecord, Site};
use crate::Amplify;

/// How long download links (artifacts, logs) work.
const LINK_TTL_SECS: i64 = 3600;
/// Access log entries kept per app.
const ACCESS_LOG_LIMIT: usize = 10_000;

pub(crate) const UPLOAD_PREFIX: &str = "/_aws/amplify/uploads/";
pub(crate) const DOWNLOAD_PREFIX: &str = "/_aws/amplify/downloads/";

/// The emulated clock as of a request, for work that continues after it.
#[derive(Clone, Copy)]
pub(crate) struct Clock {
    offset: Duration,
}

impl Clock {
    pub fn of(ctx: &RequestContext) -> Self {
        Self { offset: ctx.received_at - Utc::now() }
    }
    pub fn now(&self) -> DateTime<Utc> {
        Utc::now() + self.offset
    }
}

/// Where a job runs: enough to find it again and to build links.
#[derive(Clone)]
pub(crate) struct JobRef {
    pub app_id: String,
    pub branch: String,
    pub job_id: u64,
    pub endpoint: String,
    pub clock: Clock,
}

impl JobRef {
    pub fn key(&self) -> String {
        format!("{}/{}/{}", self.app_id, self.branch, self.job_id)
    }
}

pub(crate) fn endpoint(ctx: &RequestContext) -> String {
    ctx.endpoint.clone().unwrap_or_else(|| "http://localhost:4566".into())
}

fn parse_job_id(id: &str) -> Result<u64, ServiceError> {
    id.parse::<u64>().map_err(|_| not_found("Job", id))
}

fn step(name: &str, now: DateTime<Utc>) -> types::Step {
    types::Step {
        step_name: name.into(),
        start_time: now,
        status: "PENDING".into(),
        end_time: now,
        ..Default::default()
    }
}

impl Amplify {
    /// Add a job to a branch and return its id.
    pub(crate) fn new_job(
        &self,
        app_id: &str,
        branch_name: &str,
        job_type: &str,
        commit: (String, String, DateTime<Utc>),
        now: DateTime<Utc>,
    ) -> Option<u64> {
        let mut st = self.write();
        let b = st.apps.get_mut(app_id)?.branches.get_mut(branch_name)?;
        let id = b.next_job.max(1);
        b.next_job = id + 1;
        let summary = types::JobSummary {
            job_arn: names::job_arn(&b.branch.branch_arn, id),
            job_id: id.to_string(),
            commit_id: commit.0,
            commit_message: commit.1,
            commit_time: commit.2,
            start_time: now,
            status: "PENDING".into(),
            end_time: None,
            job_type: job_type.into(),
            source_url: None,
            source_url_type: None,
        };
        b.jobs.insert(id, JobRecord { summary, ..JobRecord::default() });
        Some(id)
    }

    /// Change a job, if it (still) exists.
    pub(crate) fn with_job<T>(&self, job: &JobRef, f: impl FnOnce(&mut JobRecord) -> T) -> Option<T> {
        let mut st = self.write();
        let j = st.apps.get_mut(&job.app_id)?.branches.get_mut(&job.branch)?.jobs.get_mut(&job.job_id)?;
        Some(f(j))
    }

    pub(crate) fn job_status(&self, job: &JobRef) -> Option<String> {
        let st = self.read();
        Some(st.apps.get(&job.app_id)?.branches.get(&job.branch)?.jobs.get(&job.job_id)?.summary.status.clone())
    }

    pub(crate) fn append_log(&self, job: &JobRef, line: &str) {
        let now = job.clock.now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        self.with_job(job, |j| {
            for l in line.lines() {
                j.log.push_str(&format!("{now} [INFO]: {l}\n"));
            }
        });
    }

    pub(crate) fn set_step(&self, job: &JobRef, name: &str, status: &str) {
        let now = job.clock.now();
        self.with_job(job, |j| {
            if let Some(s) = j.steps.iter_mut().find(|s| s.step_name == name) {
                if s.status == "PENDING" {
                    s.start_time = now;
                }
                s.status = status.into();
                s.end_time = now;
            }
        });
    }

    /// A link that downloads `data` for an hour.
    pub(crate) fn download_link(
        &self,
        endpoint: &str,
        now: DateTime<Utc>,
        content_type: &str,
        data: Vec<u8>,
    ) -> String {
        let token = names::random_alnum(40);
        let mut st = self.write();
        let blob = st.put_blob(data);
        let expires = now.timestamp() + LINK_TTL_SECS;
        st.downloads.retain(|_, d| d.expires > now.timestamp());
        st.downloads.insert(token.clone(), Download { content_type: content_type.into(), blob, expires });
        st.collect_garbage();
        format!("{endpoint}{DOWNLOAD_PREFIX}{token}")
    }

    /// End a job: publish its log behind each step's `logUrl` and set the
    /// final status. A stopped job ends `CANCELLED` whatever happened.
    pub(crate) fn finish_job(&self, job: &JobRef, ok: bool, reason: Option<String>) {
        let now = job.clock.now();
        let cancelled = self.job_status(job).is_some_and(|s| s == "CANCELLING" || s == "CANCELLED");
        if let Some(r) = &reason {
            self.append_log(job, r);
        }
        let log = self.with_job(job, |j| j.log.clone()).unwrap_or_default();
        let url = self.download_link(&job.endpoint, now, "text/plain", log.into_bytes());
        let status = if cancelled {
            "CANCELLED"
        } else if ok {
            "SUCCEED"
        } else {
            "FAILED"
        };
        self.with_job(job, |j| {
            j.summary.status = status.into();
            j.summary.end_time = Some(now);
            for s in &mut j.steps {
                s.log_url = Some(url.clone());
                if matches!(s.status.as_str(), "PENDING" | "RUNNING") {
                    s.status = if status == "SUCCEED" { "SUCCEED" } else { status }.into();
                    s.end_time = now;
                    if !ok && s.status_reason.is_none() {
                        s.status_reason = reason.clone();
                    }
                }
            }
            j.uploaded.clear();
        });
        self.inner.running.lock().expect("running jobs lock").remove(&job.key());
        self.write().collect_garbage();
    }

    /// Make `files` what the branch serves, and keep them as the job's
    /// artifact.
    pub(crate) fn publish(&self, job: &JobRef, files: Files, custom_headers: Option<String>, artifact: bool) {
        let artifact_zip = artifact.then(|| crate::deploy::zip_files(&files));
        let mut st = self.write();
        let mut site = Site { job_id: job.job_id.to_string(), files: BTreeMap::new(), custom_headers };
        for (path, data) in files {
            site.files.insert(path, st.put_blob(data));
        }
        let artifact = artifact_zip.map(|zip| st.put_blob(zip));
        let Some(rec) = st.apps.get_mut(&job.app_id) else { return };
        let (account, region) = (rec.account.clone(), rec.region.clone());
        let Some(b) = rec.branches.get_mut(&job.branch) else { return };
        b.site = Some(site);
        let mut artifact_id = None;
        if let Some(blob) = artifact {
            let id = uuid::Uuid::new_v4().to_string();
            if let Some(j) = b.jobs.get_mut(&job.job_id) {
                j.artifact_ids.push(id.clone());
            }
            artifact_id = Some((id, blob));
        }
        if let Some((id, blob)) = artifact_id {
            st.artifacts.insert(
                id,
                ArtifactRecord {
                    account,
                    region,
                    app_id: job.app_id.clone(),
                    branch_name: job.branch.clone(),
                    job_id: job.job_id,
                    file_name: "artifacts.zip".into(),
                    blob,
                },
            );
        }
        st.collect_garbage();
    }

    /// One job at a time per branch.
    pub(crate) fn branch_lock(&self, app_id: &str, branch: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.inner.branch_locks.lock().expect("branch locks").entry(format!("{app_id}/{branch}")).or_default().clone()
    }

    pub(crate) fn register_running(&self, job: &JobRef) -> Arc<tokio::sync::Notify> {
        let stop = Arc::new(tokio::sync::Notify::new());
        self.inner.running.lock().expect("running jobs lock").insert(job.key(), stop.clone());
        stop
    }

    /// Stop running jobs whose key starts with `prefix` (`appId/` or
    /// `appId/branch/`).
    pub(crate) fn stop_jobs(&self, prefix: &str) {
        let mut running = self.inner.running.lock().expect("running jobs lock");
        let keys: Vec<String> = running.keys().filter(|k| k.starts_with(prefix)).cloned().collect();
        for k in keys {
            if let Some(stop) = running.remove(&k) {
                stop.notify_one();
            }
        }
    }

    /// Run a manual deployment in the background.
    fn spawn_deployment(&self, job: JobRef, source: Source) {
        let this = self.clone();
        tokio::spawn(async move {
            let lock = this.branch_lock(&job.app_id, &job.branch);
            let _guard = lock.lock().await;
            if this.job_status(&job).as_deref() != Some("PENDING") {
                return;
            }
            let start = job.clock.now();
            this.with_job(&job, |j| {
                j.summary.status = "RUNNING".into();
                j.steps = vec![step("DEPLOY", start)];
            });
            this.set_step(&job, "DEPLOY", "RUNNING");
            let (account, branch_arn, current) = {
                let st = this.read();
                let Some(rec) = st.apps.get(&job.app_id) else { return };
                let Some(b) = rec.branches.get(&job.branch) else { return };
                let current = b.site.as_ref().map(|s| s.files.clone()).unwrap_or_default();
                (rec.account.clone(), b.branch.branch_arn.clone(), current)
            };
            this.append_log(&job, "Starting deployment");
            let origin = Origin { account: &account, branch_arn: &branch_arn };
            match this.fetch_source(&source, &origin, &current).await {
                Ok(files) => {
                    this.append_log(&job, &format!("Deploying {} files", files.len()));
                    this.publish(&job, files, None, false);
                    this.append_log(&job, "Deployment complete");
                    this.finish_job(&job, true, None);
                }
                Err(e) => this.finish_job(&job, false, Some(e)),
            }
        });
    }

    pub(crate) async fn create_deployment(
        &self,
        ctx: &RequestContext,
        input: types::CreateDeploymentRequest,
    ) -> Result<types::CreateDeploymentResult, ServiceError> {
        let job_id = {
            let st = self.read();
            let rec = app(ctx, &st, &input.app_id)?;
            let b = branch(rec, &input.branch_name)?;
            authorize(ctx, "CreateDeployment", &b.branch.branch_arn, ConditionContext::new())?;
            if !rec.app.repository.is_empty() {
                return Err(bad_request("Operation not supported. App is already connected a repository."));
            }
            drop(st);
            let now = ctx.received_at;
            self.new_job(&input.app_id, &input.branch_name, "MANUAL", (String::new(), String::new(), now), now)
                .ok_or_else(|| not_found("Branch", &input.branch_name))?
        };
        let base = endpoint(ctx);
        let mut st = self.write();
        let mut upload = |file: Option<String>| {
            let token = names::random_alnum(40);
            st.uploads.insert(
                token.clone(),
                crate::state::Upload {
                    app_id: input.app_id.clone(),
                    branch_name: input.branch_name.clone(),
                    job_id,
                    file: file.clone(),
                },
            );
            match file {
                Some(f) => format!("{base}{UPLOAD_PREFIX}{token}/{}", names::encode_segment(&f)),
                None => format!("{base}{UPLOAD_PREFIX}{token}"),
            }
        };
        let zip_upload_url = upload(None);
        let mut file_upload_urls = BTreeMap::new();
        let file_map = input.file_map.clone().unwrap_or_default();
        for path in file_map.keys() {
            file_upload_urls.insert(path.clone(), upload(Some(path.clone())));
        }
        let j = st
            .apps
            .get_mut(&input.app_id)
            .and_then(|a| a.branches.get_mut(&input.branch_name))
            .and_then(|b| b.jobs.get_mut(&job_id))
            .expect("job just created");
        j.summary.status = "CREATED".into();
        j.expected_files = file_map;
        Ok(types::CreateDeploymentResult { job_id: Some(job_id.to_string()), file_upload_urls, zip_upload_url })
    }

    pub(crate) async fn start_deployment(
        &self,
        ctx: &RequestContext,
        input: types::StartDeploymentRequest,
    ) -> Result<types::StartDeploymentResult, ServiceError> {
        let now = ctx.received_at;
        let (job_id, source) = {
            let mut st = self.write();
            let rec = app_mut(ctx, &mut st, &input.app_id)?;
            let connected = !rec.app.repository.is_empty();
            let b = branch_mut(rec, &input.branch_name)?;
            authorize(ctx, "StartDeployment", &b.branch.branch_arn, ConditionContext::new())?;
            if connected {
                return Err(bad_request("Operation not supported. App is already connected a repository."));
            }
            match (input.job_id.as_deref().filter(|j| !j.is_empty()), input.source_url.as_deref()) {
                (Some(id), _) => {
                    let n = parse_job_id(id)?;
                    let j = b.jobs.get_mut(&n).ok_or_else(|| not_found("Job", id))?;
                    if j.summary.status != "CREATED" {
                        return Err(bad_request(format!("Job {id} has already been started.")));
                    }
                    j.summary.status = "PENDING".into();
                    j.summary.start_time = now;
                    let source = Source::Uploaded { uploaded: j.uploaded.clone(), expected: j.expected_files.clone() };
                    (n, source)
                }
                (None, Some(url)) => {
                    let kind = input.source_url_type.clone().unwrap_or_else(|| "ZIP".into());
                    drop(st);
                    let n = self
                        .new_job(&input.app_id, &input.branch_name, "MANUAL", (String::new(), String::new(), now), now)
                        .ok_or_else(|| not_found("Branch", &input.branch_name))?;
                    let job = JobRef {
                        app_id: input.app_id.clone(),
                        branch: input.branch_name.clone(),
                        job_id: n,
                        endpoint: endpoint(ctx),
                        clock: Clock::of(ctx),
                    };
                    self.with_job(&job, |j| {
                        j.summary.source_url = Some(url.to_string());
                        j.summary.source_url_type = Some(kind.clone());
                    });
                    (n, Source::Url { url: url.to_string(), kind })
                }
                (None, None) => {
                    return Err(bad_request("Either jobId or sourceUrl must be provided."));
                }
            }
        };
        let job = JobRef {
            app_id: input.app_id,
            branch: input.branch_name,
            job_id,
            endpoint: endpoint(ctx),
            clock: Clock::of(ctx),
        };
        let summary = self.with_job(&job, |j| j.summary.clone()).expect("job exists");
        self.spawn_deployment(job, source);
        Ok(types::StartDeploymentResult { job_summary: summary })
    }

    pub(crate) async fn start_job(
        &self,
        ctx: &RequestContext,
        input: types::StartJobRequest,
    ) -> Result<types::StartJobResult, ServiceError> {
        let now = ctx.received_at;
        let commit = {
            let st = self.read();
            let rec = app(ctx, &st, &input.app_id)?;
            let b = branch(rec, &input.branch_name)?;
            authorize(ctx, "StartJob", &b.branch.branch_arn, ConditionContext::new())?;
            if rec.app.repository.is_empty() {
                return Err(bad_request(
                    "Operation not supported. App is not connected to a repository; use StartDeployment.",
                ));
            }
            if input.job_type == "RETRY" {
                let id = input
                    .job_id
                    .as_deref()
                    .filter(|j| !j.is_empty())
                    .ok_or_else(|| bad_request("jobId is required to retry a job."))?;
                let j = b.jobs.get(&parse_job_id(id)?).ok_or_else(|| not_found("Job", id))?;
                if !matches!(j.summary.status.as_str(), "FAILED" | "CANCELLED") {
                    return Err(bad_request(format!("Job {id} can only be retried after it failed or was cancelled.")));
                }
                (j.summary.commit_id.clone(), j.summary.commit_message.clone(), j.summary.commit_time)
            } else {
                (
                    input.commit_id.clone().filter(|c| !c.is_empty()).unwrap_or_else(|| "HEAD".into()),
                    input.commit_message.clone().unwrap_or_default(),
                    input.commit_time.unwrap_or(now),
                )
            }
        };
        let summary = self.start_build(ctx, &input.app_id, &input.branch_name, &input.job_type, commit)?;
        Ok(types::StartJobResult { job_summary: summary })
    }

    /// Create a build job and run it in the background.
    pub(crate) fn start_build(
        &self,
        ctx: &RequestContext,
        app_id: &str,
        branch_name: &str,
        job_type: &str,
        commit: (String, String, DateTime<Utc>),
    ) -> Result<types::JobSummary, ServiceError> {
        let now = ctx.received_at;
        let id =
            self.new_job(app_id, branch_name, job_type, commit, now).ok_or_else(|| not_found("Branch", branch_name))?;
        let job = JobRef {
            app_id: app_id.into(),
            branch: branch_name.into(),
            job_id: id,
            endpoint: endpoint(ctx),
            clock: Clock::of(ctx),
        };
        self.with_job(&job, |j| {
            j.steps = vec![step("BUILD", now), step("DEPLOY", now), step("VERIFY", now)];
        });
        let summary = self.with_job(&job, |j| j.summary.clone()).expect("job exists");
        let stop = self.register_running(&job);
        let this = self.clone();
        tokio::spawn(async move { this.run_build(job, stop).await });
        Ok(summary)
    }

    pub(crate) async fn stop_job(
        &self,
        ctx: &RequestContext,
        input: types::StopJobRequest,
    ) -> Result<types::StopJobResult, ServiceError> {
        let summary = {
            let mut st = self.write();
            let rec = app_mut(ctx, &mut st, &input.app_id)?;
            let b = branch_mut(rec, &input.branch_name)?;
            let n = parse_job_id(&input.job_id)?;
            let j = b.jobs.get_mut(&n).ok_or_else(|| not_found("Job", &input.job_id))?;
            authorize(ctx, "StopJob", &j.summary.job_arn, ConditionContext::new())?;
            match j.summary.status.as_str() {
                "CREATED" | "PENDING" => {
                    j.summary.status = "CANCELLED".into();
                    j.summary.end_time = Some(ctx.received_at);
                    for s in &mut j.steps {
                        s.status = "CANCELLED".into();
                        s.end_time = ctx.received_at;
                    }
                }
                "PROVISIONING" | "RUNNING" => j.summary.status = "CANCELLING".into(),
                _ => return Err(bad_request(format!("Job {} is not running.", input.job_id))),
            }
            j.summary.clone()
        };
        let key = format!("{}/{}/{}", input.app_id, input.branch_name, input.job_id);
        if let Some(stop) = self.inner.running.lock().expect("running jobs lock").get(&key) {
            stop.notify_one();
        }
        Ok(types::StopJobResult { job_summary: summary })
    }

    pub(crate) async fn get_job(
        &self,
        ctx: &RequestContext,
        input: types::GetJobRequest,
    ) -> Result<types::GetJobResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        let b = branch(rec, &input.branch_name)?;
        let j = b.jobs.get(&parse_job_id(&input.job_id)?).ok_or_else(|| not_found("Job", &input.job_id))?;
        authorize(ctx, "GetJob", &j.summary.job_arn, ConditionContext::new())?;
        Ok(types::GetJobResult { job: types::Job { summary: j.summary.clone(), steps: j.steps.clone() } })
    }

    pub(crate) async fn list_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListJobsRequest,
    ) -> Result<types::ListJobsResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        let b = branch(rec, &input.branch_name)?;
        authorize(ctx, "ListJobs", &format!("{}/jobs/*", b.branch.branch_arn), ConditionContext::new())?;
        let all: Vec<types::JobSummary> = b.jobs.values().rev().map(|j| j.summary.clone()).collect();
        let (job_summaries, next_token) = names::paginate(&all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListJobsResult { job_summaries, next_token })
    }

    pub(crate) async fn delete_job(
        &self,
        ctx: &RequestContext,
        input: types::DeleteJobRequest,
    ) -> Result<types::DeleteJobResult, ServiceError> {
        let mut st = self.write();
        let rec = app_mut(ctx, &mut st, &input.app_id)?;
        let b = branch_mut(rec, &input.branch_name)?;
        let n = parse_job_id(&input.job_id)?;
        let j = b.jobs.get(&n).ok_or_else(|| not_found("Job", &input.job_id))?;
        authorize(ctx, "DeleteJob", &j.summary.job_arn, ConditionContext::new())?;
        if matches!(j.summary.status.as_str(), "PENDING" | "PROVISIONING" | "RUNNING" | "CANCELLING") {
            return Err(bad_request(format!("Job {} is running and cannot be deleted.", input.job_id)));
        }
        let j = b.jobs.remove(&n).expect("job exists");
        for id in &j.artifact_ids {
            st.artifacts.remove(id);
        }
        st.uploads.retain(|_, u| !(u.app_id == input.app_id && u.branch_name == input.branch_name && u.job_id == n));
        st.collect_garbage();
        Ok(types::DeleteJobResult { job_summary: j.summary })
    }

    pub(crate) async fn list_artifacts(
        &self,
        ctx: &RequestContext,
        input: types::ListArtifactsRequest,
    ) -> Result<types::ListArtifactsResult, ServiceError> {
        let st = self.read();
        let rec = app(ctx, &st, &input.app_id)?;
        let b = branch(rec, &input.branch_name)?;
        let j = b.jobs.get(&parse_job_id(&input.job_id)?).ok_or_else(|| not_found("Job", &input.job_id))?;
        authorize(ctx, "ListArtifacts", &j.summary.job_arn, ConditionContext::new())?;
        let all: Vec<types::Artifact> = j
            .artifact_ids
            .iter()
            .filter_map(|id| st.artifacts.get(id).map(|a| (id, a)))
            .map(|(id, a)| types::Artifact { artifact_file_name: a.file_name.clone(), artifact_id: id.clone() })
            .collect();
        let (artifacts, next_token) = names::paginate(&all, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListArtifactsResult { artifacts, next_token })
    }

    pub(crate) async fn get_artifact_url(
        &self,
        ctx: &RequestContext,
        input: types::GetArtifactUrlRequest,
    ) -> Result<types::GetArtifactUrlResult, ServiceError> {
        let (blob, arn) = {
            let st = self.read();
            let a = st
                .artifacts
                .get(&input.artifact_id)
                .filter(|a| a.account == ctx.caller.account_id && a.region == ctx.region)
                .ok_or_else(|| not_found("Artifact", &input.artifact_id))?;
            let rec = app(ctx, &st, &a.app_id)?;
            let b = branch(rec, &a.branch_name)?;
            let arn = format!("{}/jobs/{:010}/artifacts/{}", b.branch.branch_arn, a.job_id, input.artifact_id);
            (st.blobs.get(&a.blob).map(|b| b.0.clone()).unwrap_or_default(), arn)
        };
        authorize(ctx, "GetArtifactUrl", &arn, ConditionContext::new())?;
        let artifact_url = self.download_link(&endpoint(ctx), ctx.received_at, "application/zip", blob);
        Ok(types::GetArtifactUrlResult { artifact_id: input.artifact_id, artifact_url })
    }

    pub(crate) async fn generate_access_logs(
        &self,
        ctx: &RequestContext,
        input: types::GenerateAccessLogsRequest,
    ) -> Result<types::GenerateAccessLogsResult, ServiceError> {
        let csv = {
            let st = self.read();
            let rec = app(ctx, &st, &input.app_id)?;
            authorize(ctx, "GenerateAccessLogs", &rec.app.app_arn, ConditionContext::new())?;
            if !crate::domains::app_has_domain(rec, &input.domain_name) {
                return Err(not_found("Domain", &input.domain_name));
            }
            let domain = input.domain_name.trim_end_matches('.').to_ascii_lowercase();
            let mut csv = String::from(
                "date,time,x-edge-location,sc-bytes,c-ip,cs-method,cs(Host),cs-uri-stem,sc-status,cs(Referer),cs(User-Agent),cs-uri-query,cs(Cookie),x-edge-result-type,x-edge-request-id,x-host-header,cs-protocol,cs-bytes,time-taken,x-forwarded-for,ssl-protocol,ssl-cipher,x-edge-response-result-type,cs-protocol-version,fle-status,fle-encrypted-fields,c-port,time-to-first-byte,x-edge-detailed-result-type,sc-content-type,sc-content-len,sc-range-start,sc-range-end\n",
            );
            let field = |s: &str| if s.is_empty() { "-".to_string() } else { s.replace([',', '\n'], " ") };
            for e in &rec.access_log {
                if input.start_time.is_some_and(|t| e.time < t) || input.end_time.is_some_and(|t| e.time > t) {
                    continue;
                }
                if !(e.host == domain || e.host.ends_with(&format!(".{domain}"))) {
                    continue;
                }
                let result = if e.status < 400 { "Miss" } else { "Error" };
                csv.push_str(&format!(
                    "{},{},MWS,{},{},{},{},{},{},{},{},{},-,{result},{},{},http,0,0.001,-,-,-,{result},HTTP/1.1,-,-,-,0.001,{result},{},{},-,-\n",
                    e.time.format("%Y-%m-%d"),
                    e.time.format("%H:%M:%S"),
                    e.bytes,
                    field(&e.client_ip),
                    e.method,
                    field(&e.host),
                    field(&e.path),
                    e.status,
                    field(&e.referer),
                    field(&e.user_agent),
                    field(&e.query),
                    e.request_id,
                    field(&e.host),
                    field(&e.content_type),
                    e.bytes,
                ));
            }
            csv
        };
        let log_url = self.download_link(&endpoint(ctx), ctx.received_at, "text/csv", csv.into_bytes());
        Ok(types::GenerateAccessLogsResult { log_url: Some(log_url) })
    }

    pub(crate) fn record_access(&self, app_id: &str, entry: crate::state::AccessEntry) {
        let mut st = self.write();
        if let Some(rec) = st.apps.get_mut(app_id) {
            rec.access_log.push(entry);
            if rec.access_log.len() > ACCESS_LOG_LIMIT {
                let excess = rec.access_log.len() - ACCESS_LOG_LIMIT;
                rec.access_log.drain(..excess);
            }
        }
    }
}
