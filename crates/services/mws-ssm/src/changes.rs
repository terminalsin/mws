//! "Parameter Store Change" events: AWS puts one on the account's default
//! EventBridge bus whenever a parameter is created, updated, deleted or has
//! a version labelled. The composition root plugs EventBridge in through
//! [`ParameterChangeSink`].

use chrono::{DateTime, Utc};
use mws_core::RequestContext;

use crate::names::ParamRef;
use crate::state::Version;
use crate::Ssm;

/// One change to a parameter, as its EventBridge event describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterChange {
    pub partition: String,
    pub account: String,
    pub region: String,
    /// The parameter's ARN.
    pub arn: String,
    /// The parameter's name as written.
    pub name: String,
    /// `Create`, `Update`, `Delete` or `LabelParameterVersion`.
    pub operation: String,
    /// `String`, `StringList` or `SecureString`.
    pub parameter_type: String,
    pub description: Option<String>,
    pub time: DateTime<Utc>,
}

/// Where parameter changes go (EventBridge, in MWS).
pub trait ParameterChangeSink: Send + Sync {
    fn parameter_changed(&self, ctx: &RequestContext, change: ParameterChange);
}

impl Ssm {
    /// Send changes of parameters to `sink`.
    pub fn set_change_sink(&self, sink: std::sync::Arc<dyn ParameterChangeSink>) {
        *self.changes.write().expect("SSM change sink lock poisoned") = Some(sink);
    }

    /// Report `operation` on `r` (whose latest version is `v`). Call it
    /// without holding the state lock.
    pub(crate) fn changed(&self, ctx: &RequestContext, r: &ParamRef, operation: &str, v: &Version) {
        let sink = self.changes.read().expect("SSM change sink lock poisoned").clone();
        let Some(sink) = sink else { return };
        sink.parameter_changed(
            ctx,
            ParameterChange {
                partition: r.partition.clone(),
                account: r.account.clone(),
                region: r.region.clone(),
                arn: crate::names::arn(&r.partition, &r.region, &r.account, &v.name),
                name: v.name.clone(),
                operation: operation.to_string(),
                parameter_type: v.param_type.clone(),
                description: v.description.clone(),
                time: ctx.received_at,
            },
        );
    }
}
