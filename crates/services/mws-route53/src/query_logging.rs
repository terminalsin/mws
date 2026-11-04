//! DNS query logging configurations. The log group must exist in
//! CloudWatch Logs and its resource policy must let `route53.amazonaws.com`
//! write to it; the DNS responder then logs every query it answers for the
//! zone, in the Route 53 query log format.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::{arn, max_items, strip_id, Route53};

fn no_such(id: &str) -> ServiceError {
    errors::no_such_query_logging_config(format!("There is no DNS query logging configuration with the ID {id}"))
}

/// Route 53 query logs must go to a CloudWatch Logs group in us-east-1.
fn check_log_group(log_group_arn: &str) -> Result<(), ServiceError> {
    let parts: Vec<&str> = log_group_arn.splitn(7, ':').collect();
    let valid = parts.len() >= 7
        && parts[0] == "arn"
        && parts[2] == "logs"
        && parts[5] == "log-group"
        && !parts[6].is_empty()
        && parts[4].len() == 12;
    if !valid {
        return Err(errors::invalid_input(format!(
            "Invalid input: {log_group_arn} is not a valid CloudWatch Logs log group ARN."
        )));
    }
    if parts[3] != "us-east-1" {
        return Err(errors::invalid_input(
            "Invalid input: The CloudWatch Logs log group must be in the us-east-1 region.",
        ));
    }
    Ok(())
}

/// Where one zone's query logs go.
pub(crate) struct LogTarget {
    partition: String,
    account: String,
    region: String,
    group: String,
    zone_id: String,
    source_arn: String,
}

/// Route 53 names a stream after the zone and the edge location that
/// answered; MWS answers from one place.
pub(crate) const EDGE_LOCATION: &str = "MWS1";

impl LogTarget {
    /// `arn` has passed [`check_log_group`].
    pub(crate) fn parse(arn: &str, zone_id: &str) -> Self {
        let parts: Vec<&str> = arn.splitn(7, ':').collect();
        let group = parts.get(6).copied().unwrap_or_default();
        LogTarget {
            partition: parts.get(1).copied().unwrap_or("aws").to_string(),
            region: parts.get(3).copied().unwrap_or_default().to_string(),
            account: parts.get(4).copied().unwrap_or_default().to_string(),
            group: group.strip_suffix(":*").unwrap_or(group).to_string(),
            zone_id: zone_id.to_string(),
            source_arn: format!("arn:{}:route53:::hostedzone/{zone_id}", parts.get(1).copied().unwrap_or("aws")),
        }
    }

    pub(crate) fn writer(&self) -> mws_logs::ServiceLogWriter<'_> {
        mws_logs::ServiceLogWriter {
            partition: &self.partition,
            account: &self.account,
            region: &self.region,
            log_group: &self.group,
            service_principal: "route53.amazonaws.com",
            source_account: &self.account,
            source_arn: &self.source_arn,
        }
    }

    pub(crate) fn stream(&self) -> String {
        format!("{}/{EDGE_LOCATION}", self.zone_id)
    }
}

impl Route53 {
    /// Write one query log line for an answered query, if the zone has a
    /// query logging configuration. Delivery failures are dropped, as in
    /// AWS.
    pub(crate) fn log_query(&self, zone_id: &str, line: impl FnOnce(&str) -> String) {
        let Some(logs) = &self.logs else { return };
        let target = {
            let st = self.lock_all();
            let Some(owner) = st.zone_owner(zone_id) else { return };
            let state = &st.accounts[owner];
            let Some(cfg) = state.query_logging.values().find(|q| q.hosted_zone_id == zone_id) else { return };
            LogTarget::parse(&cfg.cloud_watch_logs_log_group_arn, zone_id)
        };
        let now = chrono::Utc::now();
        let event = mws_logs::ServiceLogEvent { timestamp: now.timestamp_millis(), message: line(&target.zone_id) };
        let _ = logs.put_log_events_as_service(&target.writer(), &target.stream(), vec![event], now.timestamp_millis());
    }

    pub(crate) fn create_query_logging_config(
        &self,
        ctx: &RequestContext,
        input: types::CreateQueryLoggingConfigRequest,
    ) -> Result<types::CreateQueryLoggingConfigResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "CreateQueryLoggingConfig", &arn(ctx, "hostedzone", &zone_id))?;
        check_log_group(&input.cloud_watch_logs_log_group_arn)?;
        if let Some(logs) = &self.logs {
            let target = LogTarget::parse(&input.cloud_watch_logs_log_group_arn, &zone_id);
            logs.check_service_access(&target.writer(), &target.stream()).map_err(|e| match e {
                mws_logs::ServiceLogError::NoSuchLogGroup => errors::no_such_cloud_watch_logs_log_group(
                    "The specified CloudWatch Logs log group doesn't exist.",
                ),
                _ => errors::insufficient_cloud_watch_logs_resource_policy(
                    "The resource policy that you're using for Route 53 query logging doesn't grant Route 53 sufficient permission to create a log stream in the specified log group.",
                ),
            })?;
        }
        let mut st = self.lock(ctx);
        if st.zone(&zone_id)?.private {
            return Err(errors::invalid_input(
                "Invalid input: Query logging is not supported for private hosted zones.",
            ));
        }
        if st.query_logging.values().any(|q| q.hosted_zone_id == zone_id) {
            return Err(errors::query_logging_config_already_exists(
                "You can create only one query logging configuration for a hosted zone, and a query logging configuration already exists for this hosted zone.",
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let config = types::QueryLoggingConfig {
            id: id.clone(),
            hosted_zone_id: zone_id,
            cloud_watch_logs_log_group_arn: input.cloud_watch_logs_log_group_arn,
        };
        st.query_logging.insert(id.clone(), config.clone());
        Ok(types::CreateQueryLoggingConfigResponse {
            query_logging_config: config,
            location: format!("https://route53.amazonaws.com/2013-04-01/queryloggingconfig/{id}"),
        })
    }

    pub(crate) fn get_query_logging_config(
        &self,
        ctx: &RequestContext,
        input: types::GetQueryLoggingConfigRequest,
    ) -> Result<types::GetQueryLoggingConfigResponse, ServiceError> {
        self.authorize(ctx, "GetQueryLoggingConfig", &arn(ctx, "queryloggingconfig", &input.id))?;
        let st = self.lock(ctx);
        let config = st.query_logging.get(&input.id).cloned().ok_or_else(|| no_such(&input.id))?;
        Ok(types::GetQueryLoggingConfigResponse { query_logging_config: config })
    }

    pub(crate) fn delete_query_logging_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteQueryLoggingConfigRequest,
    ) -> Result<types::DeleteQueryLoggingConfigResponse, ServiceError> {
        self.authorize(ctx, "DeleteQueryLoggingConfig", &arn(ctx, "queryloggingconfig", &input.id))?;
        let mut st = self.lock(ctx);
        st.query_logging.remove(&input.id).ok_or_else(|| no_such(&input.id))?;
        Ok(types::DeleteQueryLoggingConfigResponse {})
    }

    pub(crate) fn list_query_logging_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListQueryLoggingConfigsRequest,
    ) -> Result<types::ListQueryLoggingConfigsResponse, ServiceError> {
        self.authorize(ctx, "ListQueryLoggingConfigs", "*")?;
        let limit = max_items(input.max_results, 100, 100);
        let st = self.lock(ctx);
        let zone = input.hosted_zone_id.as_deref().map(strip_id);
        if let Some(z) = zone {
            st.zone(z)?;
        }
        let all: Vec<&types::QueryLoggingConfig> = st
            .query_logging
            .values()
            .filter(|q| zone.is_none_or(|z| q.hosted_zone_id == z))
            .filter(|q| input.next_token.as_deref().is_none_or(|t| q.id.as_str() >= t))
            .collect();
        Ok(types::ListQueryLoggingConfigsResponse {
            query_logging_configs: all.iter().take(limit).map(|q| (*q).clone()).collect(),
            next_token: all.get(limit).map(|q| q.id.clone()),
        })
    }
}
