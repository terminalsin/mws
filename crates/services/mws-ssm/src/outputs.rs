//! Where Run Command output and notifications go. The SSM Agent uploads a
//! command's output to S3 (`OutputS3BucketName`) and CloudWatch Logs
//! (`CloudWatchOutputConfig`) with the node's instance profile role, and
//! downloads `aws:downloadContent` objects the same way; Systems Manager
//! publishes `NotificationConfig` notifications to SNS as the command's
//! `ServiceRoleArn`. The composition root provides all of this through
//! [`CommandOutputs`].

use mws_core::RequestContext;

/// The node a write is made from (its instance profile role is used).
#[derive(Clone, Copy)]
pub struct NodeRef<'a> {
    /// A template for the request (clock, authorizer); its caller is
    /// replaced by the node's role.
    pub ctx: &'a RequestContext,
    pub account: &'a str,
    pub region: &'a str,
    pub instance_id: &'a str,
}

/// One SNS notification about a command or an invocation.
#[derive(Debug, Clone)]
pub struct CommandNotification {
    pub account: String,
    pub region: String,
    /// The command's `ServiceRoleArn`, which Systems Manager assumes.
    pub role_arn: String,
    pub topic_arn: String,
    /// The command's ARN, as `aws:SourceArn`.
    pub source_arn: String,
    pub message: String,
}

#[async_trait::async_trait]
pub trait CommandOutputs: Send + Sync {
    /// `PutObject` as the node's role.
    async fn put_object(&self, node: NodeRef<'_>, bucket: &str, key: &str, body: Vec<u8>) -> Result<(), String>;

    /// `GetObject` as the node's role.
    async fn get_object(&self, node: NodeRef<'_>, bucket: &str, key: &str) -> Result<Vec<u8>, String>;

    /// `CreateLogGroup` (when missing), `CreateLogStream` and
    /// `PutLogEvents` as the node's role; events are (milliseconds,
    /// message).
    async fn put_log_events(
        &self,
        node: NodeRef<'_>,
        group: &str,
        stream: &str,
        events: Vec<(i64, String)>,
    ) -> Result<(), String>;

    /// Publish `n` to its topic as its role.
    async fn notify(&self, ctx: &RequestContext, n: CommandNotification) -> Result<(), String>;

    /// The actions the node's instance profile role lacks among `actions`
    /// (on `*`), or an error when the role cannot be used at all. Nodes
    /// whose role may not call `ssm:UpdateInstanceInformation` never
    /// register.
    fn missing_node_permissions(
        &self,
        ctx: &RequestContext,
        account: &str,
        region: &str,
        instance_id: &str,
        actions: &[&str],
    ) -> Result<Vec<String>, String> {
        let _ = (ctx, account, region, instance_id, actions);
        Ok(Vec::new())
    }
}

impl crate::Ssm {
    /// Send command output and notifications through `outputs`.
    pub fn set_command_outputs(&self, outputs: std::sync::Arc<dyn CommandOutputs>) {
        *self.outputs.write().expect("SSM outputs lock poisoned") = Some(outputs);
    }

    pub(crate) fn command_outputs(&self) -> Option<std::sync::Arc<dyn CommandOutputs>> {
        self.outputs.read().expect("SSM outputs lock poisoned").clone()
    }
}
