//! The console's terminal and file browser for running instances:
//! `/_aws/ec2/instances/<instance-id>/{exec,files,file,dir}` (see
//! [`mws_core::shell`]). Requests are signed and need `ssm:StartSession`
//! on the instance, the permission AWS Session Manager asks for.

use std::sync::Arc;

use bytes::Bytes;
use mws_core::shell::{self, Output, Shell};
use mws_core::{ConditionContext, HttpRequest, HttpResponse, RequestContext};

use crate::backend::ComputeBackend;
use crate::state::State;
use crate::{account_of, util, Ec2};

pub const PREFIX: &str = "/_aws/ec2/instances/";

struct InstanceShell {
    backend: Arc<dyn ComputeBackend>,
    handle: String,
}

#[async_trait::async_trait]
impl Shell for InstanceShell {
    async fn run(&self, script: &str, stdin: Option<Bytes>) -> Result<Output, String> {
        match self.backend.exec_input(&self.handle, script, stdin.as_deref()).await {
            Ok(Some(o)) => Ok(Output { exit_code: o.exit_code, stdout: o.stdout, stderr: o.stderr }),
            Ok(None) => Err("This instance has no running machine to connect to: MWS runs EC2 with the metadata-only backend (set MWS_EC2_BACKEND=docker).".into()),
            Err(e) => Err(e.0),
        }
    }
}

pub async fn serve(ec2: &Ec2, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let rest = request.uri().path().strip_prefix(PREFIX).unwrap_or_default();
    let (id, rest) = rest.split_once('/').unwrap_or((rest, ""));
    let account = account_of(ctx);
    let arn = util::arn(ctx, &account, &format!("instance/{id}"));
    if let Err(e) = ctx.authorize("ssm:StartSession", &arn, ConditionContext::new()) {
        return shell::error(403, e.message);
    }
    let handle = {
        let state = ec2.lock();
        let Some(inst) = state.regions.get(&State::key(&account, &ctx.region)).and_then(|r| r.instances.get(id)) else {
            return shell::error(404, format!("The instance ID '{id}' does not exist"));
        };
        if inst.instance.state.as_ref().and_then(|s| s.name.as_deref()) != Some("running") {
            return shell::error(409, format!("Instance {id} is not running."));
        }
        match inst.handle.clone() {
            Some(h) => h,
            None => return shell::error(409, format!("Instance {id} has not started yet.")),
        }
    };
    shell::serve(&InstanceShell { backend: ec2.backend(), handle }, request, rest).await
}
