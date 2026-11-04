//! Health checks: their configuration, and what the checkers in
//! [`crate::probe`] report about them.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::HealthCheck;
use crate::{arn, max_items, Route53};

pub(crate) fn no_such_health_check(id: &str) -> ServiceError {
    errors::no_such_health_check(format!("No health check exists with the specified ID {id}"))
}

/// Fill in the defaults Route 53 reports for omitted settings.
fn with_defaults(mut c: types::HealthCheckConfig) -> types::HealthCheckConfig {
    let https = c.r#type.starts_with("HTTPS");
    let endpoint = matches!(c.r#type.as_str(), "HTTP" | "HTTPS" | "HTTP_STR_MATCH" | "HTTPS_STR_MATCH" | "TCP");
    if endpoint {
        c.port.get_or_insert(if https { 443 } else { 80 });
        c.request_interval.get_or_insert(30);
        c.failure_threshold.get_or_insert(3);
        c.measure_latency.get_or_insert(false);
        if https {
            c.enable_sni.get_or_insert(true);
        }
    }
    c.inverted.get_or_insert(false);
    c.disabled.get_or_insert(false);
    c
}

fn validate(c: &types::HealthCheckConfig) -> Result<(), ServiceError> {
    let endpoint = matches!(c.r#type.as_str(), "HTTP" | "HTTPS" | "HTTP_STR_MATCH" | "HTTPS_STR_MATCH" | "TCP");
    if endpoint && c.ip_address.is_none() && c.fully_qualified_domain_name.is_none() {
        return Err(errors::invalid_input(
            "Invalid parameter : Either IPAddress or FullyQualifiedDomainName must be specified",
        ));
    }
    if c.r#type.ends_with("STR_MATCH") && c.search_string.is_none() {
        return Err(errors::invalid_input("Invalid parameter : SearchString is required for STR_MATCH health checks"));
    }
    if c.r#type == "CALCULATED" && c.child_health_checks.is_none() {
        return Err(errors::invalid_input(
            "Invalid parameter : ChildHealthChecks is required for CALCULATED health checks",
        ));
    }
    Ok(())
}

impl Route53 {
    pub(crate) fn create_health_check(
        &self,
        ctx: &RequestContext,
        input: types::CreateHealthCheckRequest,
    ) -> Result<types::CreateHealthCheckResponse, ServiceError> {
        self.authorize(ctx, "CreateHealthCheck", "*")?;
        validate(&input.health_check_config)?;
        let config = with_defaults(input.health_check_config);
        let mut st = self.lock(ctx);
        if let Some(existing) = st.health_checks.values().find(|h| h.check.caller_reference == input.caller_reference) {
            // Same caller reference and settings is an idempotent retry.
            if existing.check.health_check_config == config {
                let check = existing.check.clone();
                return Ok(types::CreateHealthCheckResponse {
                    location: format!("https://route53.amazonaws.com/2013-04-01/healthcheck/{}", check.id),
                    health_check: check,
                });
            }
            return Err(errors::health_check_already_exists(format!(
                "A health check with the caller reference {} already exists, and the settings are different.",
                input.caller_reference
            )));
        }
        if st.health_checks.len() as i64 >= crate::limits::MAX_HEALTH_CHECKS_BY_OWNER {
            return Err(errors::too_many_health_checks(
                "This health check can't be created because the current account has reached the limit on the number of active health checks.",
            ));
        }
        let id = uuid();
        let check = types::HealthCheck {
            id: id.clone(),
            caller_reference: input.caller_reference,
            linked_service: None,
            health_check_config: config,
            health_check_version: 1,
            cloud_watch_alarm_configuration: None,
        };
        st.health_checks.insert(id.clone(), HealthCheck { check: check.clone(), tags: BTreeMap::new() });
        drop(st);
        self.ensure_prober();
        Ok(types::CreateHealthCheckResponse {
            health_check: check,
            location: format!("https://route53.amazonaws.com/2013-04-01/healthcheck/{id}"),
        })
    }

    pub(crate) fn get_health_check(
        &self,
        ctx: &RequestContext,
        input: types::GetHealthCheckRequest,
    ) -> Result<types::GetHealthCheckResponse, ServiceError> {
        let id = &input.health_check_id;
        self.authorize(ctx, "GetHealthCheck", &arn(ctx, "healthcheck", id))?;
        let st = self.lock(ctx);
        let h = st.health_check(id)?;
        Ok(types::GetHealthCheckResponse { health_check: h.check.clone() })
    }

    pub(crate) fn get_health_check_count(
        &self,
        ctx: &RequestContext,
        _input: types::GetHealthCheckCountRequest,
    ) -> Result<types::GetHealthCheckCountResponse, ServiceError> {
        self.authorize(ctx, "GetHealthCheckCount", "*")?;
        Ok(types::GetHealthCheckCountResponse { health_check_count: self.lock(ctx).health_checks.len() as i64 })
    }

    pub(crate) fn list_health_checks(
        &self,
        ctx: &RequestContext,
        input: types::ListHealthChecksRequest,
    ) -> Result<types::ListHealthChecksResponse, ServiceError> {
        self.authorize(ctx, "ListHealthChecks", "*")?;
        let limit = max_items(input.max_items, 100, 1000);
        let st = self.lock(ctx);
        let all: Vec<&HealthCheck> = st
            .health_checks
            .values()
            .filter(|h| input.marker.as_deref().is_none_or(|m| h.check.id.as_str() >= m))
            .collect();
        let next = all.get(limit).map(|h| h.check.id.clone());
        Ok(types::ListHealthChecksResponse {
            health_checks: all.iter().take(limit).map(|h| h.check.clone()).collect(),
            marker: input.marker.unwrap_or_default(),
            is_truncated: next.is_some(),
            next_marker: next,
            max_items: limit as i32,
        })
    }

    pub(crate) fn update_health_check(
        &self,
        ctx: &RequestContext,
        input: types::UpdateHealthCheckRequest,
    ) -> Result<types::UpdateHealthCheckResponse, ServiceError> {
        let id = input.health_check_id.clone();
        self.authorize(ctx, "UpdateHealthCheck", &arn(ctx, "healthcheck", &id))?;
        let mut st = self.lock(ctx);
        let h = st.health_check_mut(&id)?;
        if let Some(v) = input.health_check_version {
            if v != h.check.health_check_version {
                return Err(errors::health_check_version_mismatch(
                    "The value of HealthCheckVersion in the request doesn't match the value of HealthCheckVersion in the health check.",
                ));
            }
        }
        let c = &mut h.check.health_check_config;
        for el in input.reset_elements.iter().flatten() {
            match el.as_str() {
                "FullyQualifiedDomainName" => c.fully_qualified_domain_name = None,
                "Regions" => c.regions = None,
                "ResourcePath" => c.resource_path = None,
                "ChildHealthChecks" => c.child_health_checks = None,
                _ => {}
            }
        }
        macro_rules! set {
            ($($f:ident),*) => { $( if input.$f.is_some() { c.$f = input.$f.clone(); } )* };
        }
        set!(
            ip_address,
            port,
            resource_path,
            fully_qualified_domain_name,
            search_string,
            failure_threshold,
            inverted,
            disabled,
            health_threshold,
            child_health_checks,
            enable_sni,
            regions,
            alarm_identifier,
            insufficient_data_health_status
        );
        h.check.health_check_version += 1;
        Ok(types::UpdateHealthCheckResponse { health_check: h.check.clone() })
    }

    pub(crate) fn delete_health_check(
        &self,
        ctx: &RequestContext,
        input: types::DeleteHealthCheckRequest,
    ) -> Result<types::DeleteHealthCheckResponse, ServiceError> {
        let id = input.health_check_id;
        self.authorize(ctx, "DeleteHealthCheck", &arn(ctx, "healthcheck", &id))?;
        let mut st = self.lock(ctx);
        st.health_check(&id)?;
        let in_use =
            st.zones.values().flat_map(|z| z.records.values()).any(|r| r.health_check_id.as_deref() == Some(&id));
        if in_use {
            return Err(errors::health_check_in_use(format!(
                "The health check {id} is still referenced from at least one resource record set."
            )));
        }
        st.health_checks.remove(&id);
        Ok(types::DeleteHealthCheckResponse {})
    }
}

fn uuid() -> String {
    use rand::Rng;
    let b: [u8; 16] = rand::thread_rng().gen();
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-4{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
}

/// Route 53 health checker regions and one checker address in each.
const CHECKERS: &[(&str, &str)] = &[
    ("us-east-1", "107.23.255.10"),
    ("us-west-1", "54.183.255.140"),
    ("us-west-2", "54.244.52.200"),
    ("eu-west-1", "176.34.159.200"),
    ("ap-southeast-1", "54.251.31.140"),
    ("ap-southeast-2", "54.252.79.140"),
    ("ap-northeast-1", "54.248.220.10"),
    ("sa-east-1", "177.71.207.140"),
];

impl Route53 {
    fn endpoint_check(&self, ctx: &RequestContext, id: &str) -> Result<types::HealthCheckConfig, ServiceError> {
        let st = self.lock(ctx);
        let check = st.health_check(id)?;
        let config = check.check.health_check_config.clone();
        if matches!(config.r#type.as_str(), "CALCULATED" | "CLOUDWATCH_METRIC" | "RECOVERY_CONTROL") {
            return Err(errors::invalid_input(format!(
                "Invalid input: Health check {id} of type {} doesn't have checker observations.",
                config.r#type
            )));
        }
        Ok(config)
    }

    /// Every checker region reports the observation of MWS's one checker.
    pub(crate) fn get_health_check_status(
        &self,
        ctx: &RequestContext,
        input: types::GetHealthCheckStatusRequest,
    ) -> Result<types::GetHealthCheckStatusResponse, ServiceError> {
        let id = &input.health_check_id;
        self.authorize(ctx, "GetHealthCheckStatus", &arn(ctx, "healthcheck", id))?;
        self.endpoint_check(ctx, id)?;
        let (last, _) = self.observations(id);
        Ok(types::GetHealthCheckStatusResponse { health_check_observations: observations(last) })
    }

    pub(crate) fn get_health_check_last_failure_reason(
        &self,
        ctx: &RequestContext,
        input: types::GetHealthCheckLastFailureReasonRequest,
    ) -> Result<types::GetHealthCheckLastFailureReasonResponse, ServiceError> {
        let id = &input.health_check_id;
        self.authorize(ctx, "GetHealthCheckLastFailureReason", &arn(ctx, "healthcheck", id))?;
        self.endpoint_check(ctx, id)?;
        let (_, failure) = self.observations(id);
        Ok(types::GetHealthCheckLastFailureReasonResponse { health_check_observations: observations(failure) })
    }
}

/// One observation per checker region, or none before the first probe.
fn observations(seen: Option<crate::probe::Observation>) -> Vec<types::HealthCheckObservation> {
    let Some(seen) = seen else { return Vec::new() };
    CHECKERS
        .iter()
        .map(|(region, ip)| types::HealthCheckObservation {
            region: Some(region.to_string()),
            ip_address: Some(ip.to_string()),
            status_report: Some(types::StatusReport { status: Some(seen.report.clone()), checked_time: Some(seen.at) }),
        })
        .collect()
}
