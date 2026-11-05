//! What other MWS services may do to CloudWatch Logs directly, where AWS
//! couples them: AWS service principals (Route 53 query logging, Lambda,
//! ...) writing log events into a customer's log group. Access is decided
//! by the account's CloudWatch Logs resource policies alone, as for
//! service principals in AWS.

use std::fmt;

use mws_iam_policy::{ConditionContext, Policy, PolicyKind, PrincipalInfo, Request};

use crate::generated::types;
use crate::names::GroupRef;
use crate::state::LogStream;
use crate::Logs;

/// Who is writing, and where.
#[derive(Debug, Clone)]
pub struct ServiceLogWriter<'a> {
    pub partition: &'a str,
    pub account: &'a str,
    pub region: &'a str,
    pub log_group: &'a str,
    /// The service principal, e.g. `route53.amazonaws.com`.
    pub service_principal: &'a str,
    /// `aws:SourceAccount` and `aws:SourceArn` for the resource policy.
    pub source_account: &'a str,
    pub source_arn: &'a str,
}

/// One event to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLogEvent {
    pub timestamp: i64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceLogError {
    NoSuchLogGroup,
    /// No resource policy lets the service principal do this.
    AccessDenied {
        action: String,
    },
    /// CloudWatch Logs refused the events.
    Rejected(String),
}

impl fmt::Display for ServiceLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceLogError::NoSuchLogGroup => write!(f, "The specified log group does not exist."),
            ServiceLogError::AccessDenied { action } => write!(f, "Access denied for {action}"),
            ServiceLogError::Rejected(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ServiceLogError {}

impl Logs {
    fn group_ref(w: &ServiceLogWriter<'_>) -> GroupRef {
        GroupRef {
            partition: w.partition.to_string(),
            account: w.account.to_string(),
            region: w.region.to_string(),
            name: w.log_group.to_string(),
        }
    }

    /// Check that the log group exists and that its resource policies let
    /// the service principal create streams and put events in it, as AWS
    /// services verify before relying on a log group.
    pub fn check_service_access(&self, w: &ServiceLogWriter<'_>, stream: &str) -> Result<(), ServiceLogError> {
        let g = Self::group_ref(w);
        let st = self.lock();
        st.group(&g).map_err(|_| ServiceLogError::NoSuchLogGroup)?;
        let doc = self.policies_for(&st, &g);
        drop(st);
        let policy = doc.and_then(|d| Policy::parse(&d, PolicyKind::Resource).ok());
        let principal = PrincipalInfo { service: Some(w.service_principal.to_string()), ..Default::default() };
        let mut context = ConditionContext::new();
        context.insert("aws:SourceAccount", vec![w.source_account.to_string()]);
        context.insert("aws:SourceArn", vec![w.source_arn.to_string()]);
        context.insert("aws:PrincipalServiceName", vec![w.service_principal.to_string()]);
        context.insert("aws:PrincipalIsAWSService", vec!["true".to_string()]);
        let resource = g.stream_arn(stream);
        for action in ["logs:CreateLogStream", "logs:PutLogEvents"] {
            let allowed = policy.as_ref().is_some_and(|p| {
                let e = p.evaluate(&Request { action, resource: &resource, principal: &principal, context: &context });
                e.allowed() && !e.denied()
            });
            if !allowed {
                return Err(ServiceLogError::AccessDenied { action: action.to_string() });
            }
        }
        Ok(())
    }

    /// Write events as a service principal, creating the stream when it
    /// does not exist yet. Live tail sessions see them like any others.
    pub fn put_log_events_as_service(
        &self,
        w: &ServiceLogWriter<'_>,
        stream: &str,
        events: Vec<ServiceLogEvent>,
        now_ms: i64,
    ) -> Result<(), ServiceLogError> {
        self.check_service_access(w, stream)?;
        let g = Self::group_ref(w);
        {
            let mut st = self.lock();
            let group = st.group_mut(&g).map_err(|_| ServiceLogError::NoSuchLogGroup)?;
            group.streams.entry(stream.to_string()).or_insert_with(|| LogStream {
                name: stream.to_string(),
                creation_time: now_ms,
                ..LogStream::default()
            });
        }
        let mut events: Vec<types::InputLogEvent> =
            events.into_iter().map(|e| types::InputLogEvent { timestamp: e.timestamp, message: e.message }).collect();
        events.sort_by_key(|e| e.timestamp);
        let accepted =
            self.store_events(&g, stream, events, now_ms).map_err(|e| ServiceLogError::Rejected(e.message))?;
        self.tails.publish(&g, stream, &accepted.stored);
        self.forward(None, &g, stream, &accepted.stored);
        self.publish_metrics(&g, &accepted.stored);
        Ok(())
    }
}

impl Logs {
    /// Write events the way the AWS service code acting for a caller does
    /// (Lambda for a function's execution role): create the log group and
    /// stream when they are missing, then put the events, each step
    /// authorized as `ctx`'s caller. A step the caller may not take fails
    /// the write, which the calling service usually drops silently.
    pub fn put_log_events_as_caller(
        &self,
        ctx: &mws_core::RequestContext,
        log_group: &str,
        stream: &str,
        events: Vec<ServiceLogEvent>,
    ) -> Result<(), mws_core::ServiceError> {
        self.put_log_events_for_caller(ctx, log_group, stream, events, true)
    }

    /// [`Logs::put_log_events_as_caller`] for writers that create only the
    /// stream (the ECS `awslogs` driver without `awslogs-create-group`): a
    /// missing group fails the write with `ResourceNotFoundException`.
    pub fn put_log_events_as_caller_existing_group(
        &self,
        ctx: &mws_core::RequestContext,
        log_group: &str,
        stream: &str,
        events: Vec<ServiceLogEvent>,
    ) -> Result<(), mws_core::ServiceError> {
        self.put_log_events_for_caller(ctx, log_group, stream, events, false)
    }

    fn put_log_events_for_caller(
        &self,
        ctx: &mws_core::RequestContext,
        log_group: &str,
        stream: &str,
        events: Vec<ServiceLogEvent>,
        create_group: bool,
    ) -> Result<(), mws_core::ServiceError> {
        let exists = |e: &mws_core::ServiceError| e.code == "ResourceAlreadyExistsException";
        let g = GroupRef::own(ctx, log_group);
        let (has_group, has_stream) = {
            let st = self.lock();
            match st.group(&g) {
                Ok(group) => (true, group.streams.contains_key(stream)),
                Err(_) => (false, false),
            }
        };
        if !has_group && create_group {
            let input = types::CreateLogGroupRequest { log_group_name: log_group.to_string(), ..Default::default() };
            self.create_log_group(ctx, input).or_else(|e| if exists(&e) { Ok(()) } else { Err(e) })?;
        }
        if !has_stream {
            let input = types::CreateLogStreamRequest {
                log_group_name: log_group.to_string(),
                log_stream_name: stream.to_string(),
            };
            self.create_log_stream(ctx, input).or_else(|e| if exists(&e) { Ok(()) } else { Err(e) })?;
        }
        let mut log_events: Vec<types::InputLogEvent> =
            events.into_iter().map(|e| types::InputLogEvent { timestamp: e.timestamp, message: e.message }).collect();
        log_events.sort_by_key(|e| e.timestamp);
        let input = types::PutLogEventsRequest {
            log_group_name: log_group.to_string(),
            log_stream_name: stream.to_string(),
            log_events,
            ..Default::default()
        };
        self.put_log_events(ctx, input).map(|_| ())
    }
}
