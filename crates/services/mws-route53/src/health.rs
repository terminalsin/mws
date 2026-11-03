//! Health checks. MWS stores and returns their configuration; it does not
//! probe endpoints.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::{HealthCheck, State};
use crate::{arn, max_items, Route53};

pub(crate) fn no_such_health_check(id: &str) -> ServiceError {
    errors::no_such_health_check(format!("No health check exists with the specified ID {id}"))
}

impl State {
    pub(crate) fn health_check_mut(&mut self, id: &str) -> Result<&mut HealthCheck, ServiceError> {
        self.health_checks.get_mut(id).ok_or_else(|| no_such_health_check(id))
    }
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
        let mut st = self.lock();
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
        let st = self.lock();
        let h = st.health_checks.get(id).ok_or_else(|| no_such_health_check(id))?;
        Ok(types::GetHealthCheckResponse { health_check: h.check.clone() })
    }

    pub(crate) fn get_health_check_count(
        &self,
        ctx: &RequestContext,
        _input: types::GetHealthCheckCountRequest,
    ) -> Result<types::GetHealthCheckCountResponse, ServiceError> {
        self.authorize(ctx, "GetHealthCheckCount", "*")?;
        Ok(types::GetHealthCheckCountResponse { health_check_count: self.lock().health_checks.len() as i64 })
    }

    pub(crate) fn list_health_checks(
        &self,
        ctx: &RequestContext,
        input: types::ListHealthChecksRequest,
    ) -> Result<types::ListHealthChecksResponse, ServiceError> {
        self.authorize(ctx, "ListHealthChecks", "*")?;
        let limit = max_items(input.max_items, 100, 1000);
        let st = self.lock();
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
        let mut st = self.lock();
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
        let mut st = self.lock();
        if !st.health_checks.contains_key(&id) {
            return Err(no_such_health_check(&id));
        }
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
