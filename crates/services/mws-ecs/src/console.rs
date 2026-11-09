//! The console's terminal and file browser for running task containers:
//! `/_aws/ecs/tasks/<cluster>/<task-id>/<container>/{exec,files,file,dir}`
//! (see [`mws_core::shell`]). Requests are signed and need
//! `ecs:ExecuteCommand` on the task, and the task must have been run with
//! execute command enabled, as ECS Exec requires.

use std::sync::Arc;

use bytes::Bytes;
use mws_core::shell::{self, Output, Shell};
use mws_core::{HttpRequest, HttpResponse, RequestContext};

use crate::backend::ContainerBackend;
use crate::names::{authorize, resource_tags, Cond, Scope};
use crate::tasks::task_arn;
use crate::Ecs;

pub const PREFIX: &str = "/_aws/ecs/tasks/";

struct ContainerShell {
    backend: Arc<dyn ContainerBackend>,
    runtime_id: String,
}

#[async_trait::async_trait]
impl Shell for ContainerShell {
    async fn run(&self, script: &str, stdin: Option<Bytes>) -> Result<Output, String> {
        match self.backend.shell(&self.runtime_id, script, stdin.as_deref()).await {
            Ok(Some(o)) => Ok(o),
            Ok(None) => Err("This task has no running container: MWS runs ECS with the metadata-only backend (set MWS_ECS_BACKEND=docker).".into()),
            Err(e) => Err(e.0),
        }
    }
}

pub async fn serve(ecs: &Ecs, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let rest = request.uri().path().strip_prefix(PREFIX).unwrap_or_default();
    let mut parts = rest.splitn(4, '/');
    let (Some(cluster), Some(task), Some(container)) = (parts.next(), parts.next(), parts.next()) else {
        return shell::error(404, "Use /_aws/ecs/tasks/<cluster>/<task-id>/<container>/<exec|files|file|dir>.");
    };
    let rest = parts.next().unwrap_or_default();
    let scope = Scope::of(ctx);
    let arn = task_arn(&scope, cluster, task);
    let tags = ecs.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
    let cond = Cond::new()
        .cluster(&scope, cluster)
        .with("ecs:task", arn.clone())
        .with("ecs:container-name", container.to_string())
        .extend(resource_tags(tags.as_ref()));
    if let Err(e) = authorize(ctx, "ExecuteCommand", &arn, cond) {
        return shell::error(403, e.message);
    }
    let found = ecs.with_region(ctx, |r, _| {
        let rec = r.tasks.get(&arn).ok_or((404, "The referenced task was not found.".to_string()))?;
        if rec.task.last_status.as_deref() != Some("RUNNING") {
            return Err((409, "The task is not running.".to_string()));
        }
        if !rec.task.enable_execute_command {
            return Err((
                409,
                "The execute command failed because execute command was not enabled when the task was run.".to_string(),
            ));
        }
        rec.runtime_ids
            .get(container)
            .cloned()
            .ok_or((404, format!("The container {container} was not found in the task.")))
    });
    match found {
        Ok(runtime_id) => shell::serve(&ContainerShell { backend: ecs.backend(), runtime_id }, request, rest).await,
        Err((status, message)) => shell::error(status, message),
    }
}
