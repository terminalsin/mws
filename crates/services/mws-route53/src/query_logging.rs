//! DNS query logging configurations. MWS records the configuration; it has
//! no CloudWatch Logs to write to.

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

impl Route53 {
    pub(crate) fn create_query_logging_config(
        &self,
        ctx: &RequestContext,
        input: types::CreateQueryLoggingConfigRequest,
    ) -> Result<types::CreateQueryLoggingConfigResponse, ServiceError> {
        let zone_id = strip_id(&input.hosted_zone_id).to_string();
        self.authorize(ctx, "CreateQueryLoggingConfig", &arn(ctx, "hostedzone", &zone_id))?;
        check_log_group(&input.cloud_watch_logs_log_group_arn)?;
        let mut st = self.lock();
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
        let st = self.lock();
        let config = st.query_logging.get(&input.id).cloned().ok_or_else(|| no_such(&input.id))?;
        Ok(types::GetQueryLoggingConfigResponse { query_logging_config: config })
    }

    pub(crate) fn delete_query_logging_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteQueryLoggingConfigRequest,
    ) -> Result<types::DeleteQueryLoggingConfigResponse, ServiceError> {
        self.authorize(ctx, "DeleteQueryLoggingConfig", &arn(ctx, "queryloggingconfig", &input.id))?;
        let mut st = self.lock();
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
        let st = self.lock();
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
