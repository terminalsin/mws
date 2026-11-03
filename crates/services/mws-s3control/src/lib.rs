//! Amazon S3 Control for MWS.
//!
//! Access points (with their policies and Block Public Access settings),
//! S3 Object Lambda access points (with their transformation
//! configurations and policies), account-level Block Public Access, and
//! tags on those resources. S3 serves data through access points by asking
//! this service about them ([`mws_s3::AccessPointDirectory`]).
//!
//! S3 Control signs as `s3`, like S3, and is told apart by its versioned
//! paths (`/v20180820/...`). Requests name the account in the
//! `x-amz-account-id` header (SDKs also prefix it to the host).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/s3control_generated.rs"));
}

mod access_points;
mod handler;
mod state;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use state::State;

/// The S3 Control service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct S3Control {
    state: Arc<RwLock<State>>,
    s3: Option<mws_s3::S3>,
}

impl S3Control {
    pub fn new() -> Self {
        Self::default()
    }

    /// S3 Control for `s3`'s buckets: access points are checked against
    /// them, and `s3` is told about access points.
    pub fn for_s3(s3: mws_s3::S3) -> Self {
        let control = Self { state: Default::default(), s3: Some(s3.clone()) };
        s3.set_access_points(Arc::new(control.clone()));
        control
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().expect("S3 Control state lock poisoned")
    }

    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().expect("S3 Control state lock poisoned")
    }
}

const SERVICE_INFO: mws_proto_restxml::ServiceInfo = generated::SERVICE_INFO;

#[async_trait::async_trait]
impl Service for S3Control {
    fn signing_name(&self) -> &'static str {
        "s3"
    }

    fn name(&self) -> &'static str {
        "s3control"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with("/v20180820/")
    }

    fn signs_raw_path(&self) -> bool {
        true
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restxml::error_response(&SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        Some(serde_json::to_value(&*self.read()).expect("S3 Control state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid S3 Control state: {e}"))?;
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
    }
}

impl mws_s3::AccessPointDirectory for S3Control {
    fn access_point(&self, account_id: &str, name: &str) -> Option<mws_s3::AccessPoint> {
        let st = self.read();
        st.access_points.values().find(|a| a.account_id == account_id && a.name == name).map(state::AccessPoint::public)
    }

    fn access_point_by_alias(&self, alias: &str) -> Option<mws_s3::AccessPoint> {
        let st = self.read();
        st.access_points.values().find(|a| a.alias == alias).map(state::AccessPoint::public)
    }

    fn object_lambda(&self, account_id: &str, name: &str) -> Option<mws_s3::ObjectLambdaAccessPoint> {
        let st = self.read();
        st.object_lambdas
            .values()
            .find(|a| a.account_id == account_id && a.name == name)
            .map(state::ObjectLambda::public)
    }

    fn object_lambda_by_alias(&self, alias: &str) -> Option<mws_s3::ObjectLambdaAccessPoint> {
        let st = self.read();
        st.object_lambdas.values().find(|a| a.alias == alias).map(state::ObjectLambda::public)
    }

    fn account_public_access_block(&self, account_id: &str) -> Option<mws_s3::AccountPublicAccessBlock> {
        let st = self.read();
        st.public_access_blocks.get(account_id).map(|p| mws_s3::AccountPublicAccessBlock {
            block_public_acls: p.block_public_acls,
            ignore_public_acls: p.ignore_public_acls,
            block_public_policy: p.block_public_policy,
            restrict_public_buckets: p.restrict_public_buckets,
        })
    }
}
