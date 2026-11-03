//! Managed ACME endpoints: endpoints, domain prevalidations, external
//! account bindings and the ACME accounts registered through them. The
//! protocol side lives in [`crate::acme_server`].

use base64::Engine;
use chrono::Duration;
use mws_core::{ConditionContext, RequestContext, Service, ServiceError};
use serde_json::json;

use crate::common::{self, split_arn, Tags};
use crate::generated::{errors, types};
use crate::state::{AcmeAccount, AcmeDomainValidation, AcmeEndpoint, Eab};
use crate::validation::{dns_record, public_domain_problem};
use crate::Acm;

pub const KEY_ALGORITHMS: &[&str] = &["RSA_2048", "EC_prime256v1", "EC_secp384r1"];
const ENDPOINT_QUOTA: usize = 10;
const DOMAIN_VALIDATION_QUOTA: usize = 100;
const EAB_QUOTA: usize = 100;

fn endpoint_not_found(arn: &str) -> ServiceError {
    errors::resource_not_found(format!("Could not find ACME endpoint {arn}."))
}

fn enabled(o: &Option<String>, default: bool) -> bool {
    o.as_deref().map(|v| v == "ENABLED").unwrap_or(default)
}

fn flag(b: bool) -> Option<String> {
    Some(if b { "ENABLED" } else { "DISABLED" }.into())
}

fn ca_wire(e: &AcmeEndpoint) -> types::CertificateAuthority {
    types::CertificateAuthority::PublicCertificateAuthority(types::PublicCertificateAuthority {
        allowed_key_algorithms: Some(e.allowed_key_algorithms.clone()),
    })
}

fn allowed_algorithms(ca: &types::CertificateAuthority) -> Result<Vec<String>, ServiceError> {
    let types::CertificateAuthority::PublicCertificateAuthority(p) = ca;
    let algs =
        p.allowed_key_algorithms.clone().unwrap_or_else(|| KEY_ALGORITHMS.iter().map(|s| s.to_string()).collect());
    if algs.is_empty() {
        return Err(errors::validation("AllowedKeyAlgorithms must contain at least one key algorithm."));
    }
    Ok(algs)
}

fn endpoint_summary(e: &AcmeEndpoint) -> types::AcmeEndpointSummary {
    types::AcmeEndpointSummary {
        acme_endpoint_arn: Some(e.arn.clone()),
        endpoint_url: Some(e.url.clone()),
        status: Some(e.status.clone()),
        failure_reason: None,
        authorization_behavior: Some(e.authorization_behavior.clone()),
        contact: Some(e.contact.clone()),
        certificate_authority: Some(ca_wire(e)),
        certificate_tags: Some(common::tags_to_wire(&e.certificate_tags)),
        created_at: Some(e.created_at),
        updated_at: Some(e.updated_at),
    }
}

fn dv_details(d: &AcmeDomainValidation) -> types::PrevalidationDetails {
    types::PrevalidationDetails::DnsPrevalidation(types::DnsPrevalidationDetails {
        domain_scope: Some(types::DomainScope {
            exact_domain: flag(d.exact),
            subdomains: flag(d.subdomains),
            wildcards: flag(d.wildcards),
        }),
        hosted_zone_id: d.hosted_zone_id.clone(),
        resource_record: Some(types::ResourceRecord {
            name: d.record_name.clone(),
            r#type: "CNAME".into(),
            value: d.record_value.clone(),
        }),
    })
}

fn dv_failure(d: &AcmeDomainValidation) -> Option<types::FailureDetails> {
    d.failure.as_ref().map(|(r, m)| types::FailureDetails { reason: Some(r.clone()), message: Some(m.clone()) })
}

fn eab_summary(e: &Eab) -> types::AcmeExternalAccountBindingSummary {
    types::AcmeExternalAccountBindingSummary {
        acme_external_account_binding_arn: Some(e.arn.clone()),
        acme_endpoint_arn: Some(e.endpoint_arn.clone()),
        role_arn: Some(e.role_arn.clone()),
        expires_at: e.expires_at,
        revoked_at: e.revoked_at,
        last_used_at: e.last_used_at,
        created_at: Some(e.created_at),
        updated_at: Some(e.updated_at),
    }
}

fn eab_wire(e: &Eab) -> types::AcmeExternalAccountBinding {
    let s = eab_summary(e);
    types::AcmeExternalAccountBinding {
        acme_external_account_binding_arn: s.acme_external_account_binding_arn,
        acme_endpoint_arn: s.acme_endpoint_arn,
        role_arn: s.role_arn,
        expires_at: s.expires_at,
        revoked_at: s.revoked_at,
        last_used_at: s.last_used_at,
        created_at: s.created_at,
        updated_at: s.updated_at,
    }
}

fn account_summary(a: &AcmeAccount) -> types::AcmeAccountSummary {
    types::AcmeAccountSummary {
        account_url: Some(a.url.clone()),
        public_key_thumbprint: Some(a.thumbprint.clone()),
        status: Some(a.status.clone()),
        created_at: Some(a.created_at),
        acme_external_account_binding_arn: a.eab_arn.clone(),
        contacts: Some(a.contacts.clone()),
    }
}

impl Acm {
    fn authorize_acme(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let tags = self.resource_tags(arn).unwrap_or_default();
        let mut cond = common::resource_tag_context(&tags);
        cond.extend(extra);
        ctx.authorize(&format!("acm:{action}"), arn, cond)
    }

    fn resource_tags(&self, arn: &str) -> Option<Tags> {
        let st = self.lock();
        st.endpoints
            .get(arn)
            .map(|e| e.tags.clone())
            .or_else(|| st.domain_validations.get(arn).map(|d| d.tags.clone()))
            .or_else(|| st.eabs.get(arn).map(|e| e.tags.clone()))
    }

    fn endpoint(&self, ctx: &RequestContext, arn: &str) -> Result<AcmeEndpoint, ServiceError> {
        let st = self.lock();
        st.endpoints
            .get(arn)
            .filter(|e| common::is_local(ctx, &e.arn) && e.status != "DELETING")
            .cloned()
            .ok_or_else(|| endpoint_not_found(arn))
    }

    fn create_token(&self, ctx: &RequestContext, kind: &str, token: &Option<String>) -> Option<String> {
        let key = format!("{}|{kind}|{}", ctx.caller.account_id, token.as_deref()?);
        self.lock().create_tokens.get(&key).cloned()
    }

    fn remember_token(&self, ctx: &RequestContext, kind: &str, token: &Option<String>, arn: &str) {
        if let Some(t) = token {
            self.lock().create_tokens.insert(format!("{}|{kind}|{t}", ctx.caller.account_id), arn.to_string());
        }
    }

    pub(crate) fn create_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::CreateAcmeEndpointRequest,
    ) -> Result<types::CreateAcmeEndpointResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        ctx.authorize("acm:CreateAcmeEndpoint", "*", common::request_tag_context(&tags))?;
        if let Some(arn) = self.create_token(ctx, "endpoint", &input.idempotency_token) {
            return Ok(types::CreateAcmeEndpointResponse { acme_endpoint_arn: Some(arn) });
        }
        common::validate_tags(&tags)?;
        let cert_tags = input.certificate_tags.clone().unwrap_or_default();
        common::validate_tags(&cert_tags)?;
        if tags.len() > common::MAX_TAGS || cert_tags.len() > common::MAX_TAGS {
            return Err(errors::too_many_tags(format!("A resource can have at most {} tags.", common::MAX_TAGS)));
        }
        let allowed = allowed_algorithms(&input.certificate_authority)?;
        let now = ctx.received_at;
        let id = uuid::Uuid::new_v4().simple().to_string();
        let arn = format!("arn:{}:acm:{}:{}:acme-endpoint/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
        let base = ctx.endpoint.clone().unwrap_or_default();
        let endpoint = AcmeEndpoint {
            arn: arn.clone(),
            account: ctx.caller.account_id.clone(),
            id: id.clone(),
            url: format!("{base}{}/{id}/directory", crate::acme_server::PREFIX),
            status: "ACTIVE".into(),
            authorization_behavior: input.authorization_behavior,
            contact: input.contact,
            allowed_key_algorithms: allowed,
            certificate_tags: common::tags_from_wire(&cert_tags),
            tags: common::tags_from_wire(&tags),
            created_at: now,
            updated_at: now,
        };
        {
            let mut st = self.lock();
            let count = st.endpoints.values().filter(|e| common::is_local(ctx, &e.arn)).count();
            if count >= ENDPOINT_QUOTA {
                return Err(errors::service_quota_exceeded(format!(
                    "You have reached the quota of {ENDPOINT_QUOTA} ACME endpoints."
                )));
            }
            st.endpoints.insert(arn.clone(), endpoint);
        }
        self.remember_token(ctx, "endpoint", &input.idempotency_token, &arn);
        Ok(types::CreateAcmeEndpointResponse { acme_endpoint_arn: Some(arn) })
    }

    pub(crate) fn describe_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeEndpointRequest,
    ) -> Result<types::DescribeAcmeEndpointResponse, ServiceError> {
        self.authorize_acme(ctx, "DescribeAcmeEndpoint", &input.acme_endpoint_arn, ConditionContext::new())?;
        let e = self.endpoint(ctx, &input.acme_endpoint_arn)?;
        let s = endpoint_summary(&e);
        Ok(types::DescribeAcmeEndpointResponse {
            acme_endpoint: Some(types::AcmeEndpoint {
                acme_endpoint_arn: s.acme_endpoint_arn,
                endpoint_url: s.endpoint_url,
                status: s.status,
                failure_reason: s.failure_reason,
                authorization_behavior: s.authorization_behavior,
                contact: s.contact,
                certificate_authority: s.certificate_authority,
                certificate_tags: s.certificate_tags,
                created_at: s.created_at,
                updated_at: s.updated_at,
            }),
        })
    }

    pub(crate) fn list_acme_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeEndpointsRequest,
    ) -> Result<types::ListAcmeEndpointsResponse, ServiceError> {
        ctx.authorize("acm:ListAcmeEndpoints", "*", ConditionContext::new())?;
        let items: Vec<_> = {
            let st = self.lock();
            st.endpoints.values().filter(|e| common::is_local(ctx, &e.arn)).map(endpoint_summary).collect()
        };
        let (page, next) = common::paginate(items, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAcmeEndpointsResponse { acme_endpoints: Some(page), next_token: next })
    }

    pub(crate) fn update_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAcmeEndpointRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_acme(ctx, "UpdateAcmeEndpoint", &input.acme_endpoint_arn, ConditionContext::new())?;
        self.endpoint(ctx, &input.acme_endpoint_arn)?;
        let allowed = input.certificate_authority.as_ref().map(allowed_algorithms).transpose()?;
        let mut st = self.lock();
        let e = st
            .endpoints
            .get_mut(&input.acme_endpoint_arn)
            .ok_or_else(|| endpoint_not_found(&input.acme_endpoint_arn))?;
        if let Some(b) = input.authorization_behavior {
            e.authorization_behavior = b;
        }
        if let Some(c) = input.contact {
            e.contact = c;
        }
        if let Some(a) = allowed {
            e.allowed_key_algorithms = a;
        }
        e.updated_at = ctx.received_at;
        Ok(())
    }

    pub(crate) fn delete_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAcmeEndpointRequest,
    ) -> Result<(), ServiceError> {
        let arn = input.acme_endpoint_arn;
        self.authorize_acme(ctx, "DeleteAcmeEndpoint", &arn, ConditionContext::new())?;
        self.endpoint(ctx, &arn)?;
        let mut st = self.lock();
        st.endpoints.remove(&arn);
        st.domain_validations.retain(|_, d| d.endpoint_arn != arn);
        st.eabs.retain(|_, e| e.endpoint_arn != arn);
        st.acme_accounts.retain(|_, a| a.endpoint_arn != arn);
        st.acme_orders.retain(|_, o| o.endpoint_arn != arn);
        Ok(())
    }

    // --- domain validations ---

    /// Publish the validation record in the hosted zone as the caller, as
    /// ACM does, and return the failure if that does not work.
    async fn publish_dv_record(
        &self,
        ctx: &RequestContext,
        domain: &str,
        zone_id: &str,
        name: &str,
        value: &str,
    ) -> Option<(String, String)> {
        let Some(r53) = &self.route53 else {
            return Some(("HOSTED_ZONE_NOT_FOUND".into(), format!("Hosted zone {zone_id} was not found.")));
        };
        let Some((zone_name, private)) = r53.hosted_zone_name(zone_id) else {
            return Some(("HOSTED_ZONE_NOT_FOUND".into(), format!("Hosted zone {zone_id} was not found.")));
        };
        if private {
            return Some((
                "HOSTED_ZONE_NOT_FOUND".into(),
                format!("Hosted zone {zone_id} is not a public hosted zone."),
            ));
        }
        let zone_bare = zone_name.trim_end_matches('.');
        if !(domain == zone_bare || domain.ends_with(&format!(".{zone_bare}"))) {
            return Some((
                "DOMAIN_MISMATCH".into(),
                format!("The domain {domain} is not in hosted zone {zone_id} ({zone_bare})."),
            ));
        }
        let change = json!({
            "HostedZoneId": zone_id,
            "ChangeBatch": {
                "Comment": "ACM ACME domain prevalidation",
                "Changes": [{
                    "Action": "UPSERT",
                    "ResourceRecordSet": {"Name": name, "Type": "CNAME", "TTL": 300, "ResourceRecords": [{"Value": value}]}
                }]
            }
        });
        match r53.invoke(ctx.clone(), "ChangeResourceRecordSets", change).await {
            Ok(_) => None,
            Err(e) if e.status == 403 => Some(("ACCESS_DENIED".into(), e.message)),
            Err(e) => Some(("INVALID_CHANGE_BATCH".into(), e.message)),
        }
    }

    async fn apply_prevalidation(
        &self,
        ctx: &RequestContext,
        dv: &mut AcmeDomainValidation,
        options: &types::DnsPrevalidationOptions,
    ) {
        let scope = options.domain_scope.clone().unwrap_or_default();
        dv.exact = enabled(&scope.exact_domain, true);
        dv.subdomains = enabled(&scope.subdomains, false);
        dv.wildcards = enabled(&scope.wildcards, false);
        dv.hosted_zone_id = options.hosted_zone_id.clone();
        dv.failure = None;
        dv.status = "VALIDATING".into();
        if let Some(problem) = public_domain_problem(&dv.domain) {
            dv.status = "INVALID".into();
            dv.failure = Some((problem.into(), format!("The domain {} cannot be validated publicly.", dv.domain)));
            return;
        }
        if let Some(zone) = &dv.hosted_zone_id {
            if let Some(failure) =
                self.publish_dv_record(ctx, &dv.domain, zone, &dv.record_name, &dv.record_value).await
            {
                dv.status = "INVALID".into();
                dv.failure = Some(failure);
            }
        }
    }

    pub(crate) async fn create_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::CreateAcmeDomainValidationRequest,
    ) -> Result<types::CreateAcmeDomainValidationResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize_acme(
            ctx,
            "CreateAcmeDomainValidation",
            &input.acme_endpoint_arn,
            common::request_tag_context(&tags),
        )?;
        if let Some(arn) = self.create_token(ctx, "domain-validation", &input.idempotency_token) {
            return Ok(types::CreateAcmeDomainValidationResponse { acme_domain_validation_arn: arn });
        }
        let endpoint = self.endpoint(ctx, &input.acme_endpoint_arn)?;
        common::validate_tags(&tags)?;
        let domain = input.domain_name.to_ascii_lowercase();
        let types::PrevalidationOptions::DnsPrevalidation(options) = &input.prevalidation_options;
        let scope = options.domain_scope.clone().unwrap_or_default();
        if !enabled(&scope.exact_domain, true)
            && !enabled(&scope.subdomains, false)
            && !enabled(&scope.wildcards, false)
        {
            return Err(errors::validation("At least one of ExactDomain, Subdomains and Wildcards must be ENABLED."));
        }
        {
            let st = self.lock();
            let existing: Vec<_> = st.domain_validations.values().filter(|d| d.endpoint_arn == endpoint.arn).collect();
            if existing.iter().any(|d| d.domain == domain) {
                return Err(errors::conflict(format!(
                    "A domain validation for {domain} already exists on ACME endpoint {}.",
                    endpoint.arn
                )));
            }
            if existing.len() >= DOMAIN_VALIDATION_QUOTA {
                return Err(errors::service_quota_exceeded(format!(
                    "An ACME endpoint can have at most {DOMAIN_VALIDATION_QUOTA} domain validations."
                )));
            }
        }
        let now = ctx.received_at;
        let record = dns_record(&endpoint.account, &domain);
        let arn = format!("{}/acme-domain-validation/{}", endpoint.arn, uuid::Uuid::new_v4().simple());
        let mut dv = AcmeDomainValidation {
            arn: arn.clone(),
            endpoint_arn: endpoint.arn.clone(),
            domain,
            exact: true,
            subdomains: false,
            wildcards: false,
            hosted_zone_id: None,
            record_name: record.name,
            record_value: record.value,
            status: "VALIDATING".into(),
            failure: None,
            tags: common::tags_from_wire(&tags),
            created_at: now,
            updated_at: now,
        };
        self.apply_prevalidation(ctx, &mut dv, options).await;
        self.lock().domain_validations.insert(arn.clone(), dv);
        self.remember_token(ctx, "domain-validation", &input.idempotency_token, &arn);
        self.refresh(ctx);
        Ok(types::CreateAcmeDomainValidationResponse { acme_domain_validation_arn: arn })
    }

    fn domain_validation(&self, ctx: &RequestContext, arn: &str) -> Result<AcmeDomainValidation, ServiceError> {
        let missing = || errors::resource_not_found(format!("Could not find ACME domain validation {arn}."));
        if !common::is_local(ctx, arn) {
            return Err(missing());
        }
        self.lock().domain_validations.get(arn).cloned().ok_or_else(missing)
    }

    pub(crate) fn describe_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeDomainValidationRequest,
    ) -> Result<types::DescribeAcmeDomainValidationResponse, ServiceError> {
        let arn = &input.acme_domain_validation_arn;
        self.authorize_acme(ctx, "DescribeAcmeDomainValidation", arn, ConditionContext::new())?;
        self.refresh(ctx);
        let d = self.domain_validation(ctx, arn)?;
        Ok(types::DescribeAcmeDomainValidationResponse {
            acme_domain_validation: Some(types::AcmeDomainValidation {
                acme_domain_validation_arn: Some(d.arn.clone()),
                acme_endpoint_arn: Some(d.endpoint_arn.clone()),
                domain_name: Some(d.domain.clone()),
                prevalidation_type: Some("DNS_PREVALIDATION".into()),
                prevalidation_details: Some(dv_details(&d)),
                status: Some(d.status.clone()),
                failure_details: dv_failure(&d),
                created_at: Some(d.created_at),
                updated_at: Some(d.updated_at),
            }),
        })
    }

    pub(crate) fn list_acme_domain_validations(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeDomainValidationsRequest,
    ) -> Result<types::ListAcmeDomainValidationsResponse, ServiceError> {
        self.authorize_acme(ctx, "ListAcmeDomainValidations", &input.acme_endpoint_arn, ConditionContext::new())?;
        self.refresh(ctx);
        self.endpoint(ctx, &input.acme_endpoint_arn)?;
        let items: Vec<_> = {
            let st = self.lock();
            st.domain_validations
                .values()
                .filter(|d| d.endpoint_arn == input.acme_endpoint_arn)
                .map(|d| types::AcmeDomainValidationSummary {
                    acme_domain_validation_arn: Some(d.arn.clone()),
                    acme_endpoint_arn: Some(d.endpoint_arn.clone()),
                    domain_name: Some(d.domain.clone()),
                    prevalidation_type: Some("DNS_PREVALIDATION".into()),
                    prevalidation_details: Some(dv_details(d)),
                    status: Some(d.status.clone()),
                    failure_details: dv_failure(d),
                    created_at: Some(d.created_at),
                    updated_at: Some(d.updated_at),
                })
                .collect()
        };
        let (page, next) = common::paginate(items, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAcmeDomainValidationsResponse { acme_domain_validations: Some(page), next_token: next })
    }

    pub(crate) async fn update_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAcmeDomainValidationRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.acme_domain_validation_arn;
        self.authorize_acme(ctx, "UpdateAcmeDomainValidation", arn, ConditionContext::new())?;
        let mut dv = self.domain_validation(ctx, arn)?;
        if dv.status == "DELETING" {
            return Err(errors::conflict(format!("ACME domain validation {arn} is being deleted.")));
        }
        if let Some(types::PrevalidationOptions::DnsPrevalidation(options)) = &input.prevalidation_options {
            self.apply_prevalidation(ctx, &mut dv, options).await;
        }
        dv.updated_at = ctx.received_at;
        self.lock().domain_validations.insert(arn.clone(), dv);
        self.refresh(ctx);
        Ok(())
    }

    pub(crate) fn delete_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAcmeDomainValidationRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.acme_domain_validation_arn;
        self.authorize_acme(ctx, "DeleteAcmeDomainValidation", arn, ConditionContext::new())?;
        self.domain_validation(ctx, arn)?;
        self.lock().domain_validations.remove(arn);
        Ok(())
    }

    // --- external account bindings ---

    pub(crate) fn create_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::CreateAcmeExternalAccountBindingRequest,
    ) -> Result<types::CreateAcmeExternalAccountBindingResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        let mut cond = common::request_tag_context(&tags);
        cond.insert("iam:PassedToService".into(), vec!["acm.amazonaws.com".into()]);
        self.authorize_acme(ctx, "CreateAcmeExternalAccountBinding", &input.acme_endpoint_arn, cond)?;
        // Handing ACME clients a role is passing it to ACM.
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec!["acm.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", &input.role_arn, pass)?;
        if let Some(arn) = self.create_token(ctx, "eab", &input.idempotency_token) {
            let st = self.lock();
            if let Some(e) = st.eabs.get(&arn) {
                return Ok(types::CreateAcmeExternalAccountBindingResponse {
                    external_account_binding: Some(eab_wire(e)),
                });
            }
        }
        let endpoint = self.endpoint(ctx, &input.acme_endpoint_arn)?;
        common::validate_tags(&tags)?;
        let now = ctx.received_at;
        let expires_at = input.expiration.as_ref().map(|e| {
            now + match e.r#type.as_str() {
                "MINUTES" => Duration::minutes(e.value),
                "HOURS" => Duration::hours(e.value),
                _ => Duration::days(e.value),
            }
        });
        let id = uuid::Uuid::new_v4().simple().to_string();
        let mac: [u8; 32] = rand::random();
        let eab = Eab {
            arn: format!("{}/acme-external-account-binding/{id}", endpoint.arn),
            endpoint_arn: endpoint.arn.clone(),
            role_arn: input.role_arn,
            key_id: uuid::Uuid::new_v4().simple().to_string(),
            mac_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac),
            expires_at,
            revoked_at: None,
            last_used_at: None,
            tags: common::tags_from_wire(&tags),
            created_at: now,
            updated_at: now,
        };
        let wire = eab_wire(&eab);
        {
            let mut st = self.lock();
            if st.eabs.values().filter(|e| e.endpoint_arn == endpoint.arn).count() >= EAB_QUOTA {
                return Err(errors::service_quota_exceeded(format!(
                    "An ACME endpoint can have at most {EAB_QUOTA} external account bindings."
                )));
            }
            st.eabs.insert(eab.arn.clone(), eab.clone());
        }
        self.remember_token(ctx, "eab", &input.idempotency_token, &eab.arn);
        Ok(types::CreateAcmeExternalAccountBindingResponse { external_account_binding: Some(wire) })
    }

    fn eab(&self, ctx: &RequestContext, arn: &str) -> Result<Eab, ServiceError> {
        let missing = || errors::resource_not_found(format!("Could not find external account binding {arn}."));
        if !common::is_local(ctx, arn) {
            return Err(missing());
        }
        self.lock().eabs.get(arn).cloned().ok_or_else(missing)
    }

    pub(crate) fn describe_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeExternalAccountBindingRequest,
    ) -> Result<types::DescribeAcmeExternalAccountBindingResponse, ServiceError> {
        let arn = &input.acme_external_account_binding_arn;
        self.authorize_acme(ctx, "DescribeAcmeExternalAccountBinding", arn, ConditionContext::new())?;
        let e = self.eab(ctx, arn)?;
        Ok(types::DescribeAcmeExternalAccountBindingResponse { external_account_binding: Some(eab_wire(&e)) })
    }

    pub(crate) fn get_acme_external_account_binding_credentials(
        &self,
        ctx: &RequestContext,
        input: types::GetAcmeExternalAccountBindingCredentialsRequest,
    ) -> Result<types::GetAcmeExternalAccountBindingCredentialsResponse, ServiceError> {
        let arn = &input.acme_external_account_binding_arn;
        self.authorize_acme(ctx, "GetAcmeExternalAccountBindingCredentials", arn, ConditionContext::new())?;
        let e = self.eab(ctx, arn)?;
        Ok(types::GetAcmeExternalAccountBindingCredentialsResponse { key_id: Some(e.key_id), mac_key: Some(e.mac_key) })
    }

    pub(crate) fn list_acme_external_account_bindings(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeExternalAccountBindingsRequest,
    ) -> Result<types::ListAcmeExternalAccountBindingsResponse, ServiceError> {
        self.authorize_acme(ctx, "ListAcmeExternalAccountBindings", &input.acme_endpoint_arn, ConditionContext::new())?;
        self.endpoint(ctx, &input.acme_endpoint_arn)?;
        let items: Vec<_> = {
            let st = self.lock();
            st.eabs.values().filter(|e| e.endpoint_arn == input.acme_endpoint_arn).map(eab_summary).collect()
        };
        let (page, next) = common::paginate(items, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAcmeExternalAccountBindingsResponse { external_account_bindings: Some(page), next_token: next })
    }

    pub(crate) fn revoke_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::RevokeAcmeExternalAccountBindingRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.acme_external_account_binding_arn;
        self.authorize_acme(ctx, "RevokeAcmeExternalAccountBinding", arn, ConditionContext::new())?;
        let e = self.eab(ctx, arn)?;
        if e.revoked_at.is_some() {
            return Err(errors::conflict(format!("External account binding {arn} is already revoked.")));
        }
        let now = ctx.received_at;
        if let Some(e) = self.lock().eabs.get_mut(arn) {
            e.revoked_at = Some(now);
            e.updated_at = now;
        }
        Ok(())
    }

    pub(crate) fn delete_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAcmeExternalAccountBindingRequest,
    ) -> Result<(), ServiceError> {
        let arn = &input.acme_external_account_binding_arn;
        self.authorize_acme(ctx, "DeleteAcmeExternalAccountBinding", arn, ConditionContext::new())?;
        self.eab(ctx, arn)?;
        self.lock().eabs.remove(arn);
        Ok(())
    }

    // --- ACME accounts ---

    fn acme_account(&self, ctx: &RequestContext, endpoint_arn: &str, url: &str) -> Result<AcmeAccount, ServiceError> {
        self.endpoint(ctx, endpoint_arn)?;
        let st = self.lock();
        st.acme_accounts
            .values()
            .find(|a| a.endpoint_arn == endpoint_arn && a.url == url)
            .cloned()
            .ok_or_else(|| errors::resource_not_found(format!("Could not find ACME account {url}.")))
    }

    pub(crate) fn describe_acme_account(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeAccountRequest,
    ) -> Result<types::DescribeAcmeAccountResponse, ServiceError> {
        self.authorize_acme(ctx, "DescribeAcmeAccount", &input.acme_endpoint_arn, ConditionContext::new())?;
        let a = self.acme_account(ctx, &input.acme_endpoint_arn, &input.account_url)?;
        let s = account_summary(&a);
        Ok(types::DescribeAcmeAccountResponse {
            acme_account: Some(types::AcmeAccount {
                account_url: s.account_url,
                public_key_thumbprint: s.public_key_thumbprint,
                status: s.status,
                created_at: s.created_at,
                acme_external_account_binding_arn: s.acme_external_account_binding_arn,
                contacts: s.contacts,
            }),
        })
    }

    pub(crate) fn list_acme_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeAccountsRequest,
    ) -> Result<types::ListAcmeAccountsResponse, ServiceError> {
        self.authorize_acme(ctx, "ListAcmeAccounts", &input.acme_endpoint_arn, ConditionContext::new())?;
        self.endpoint(ctx, &input.acme_endpoint_arn)?;
        let mut items: Vec<_> = {
            let st = self.lock();
            st.acme_accounts.values().filter(|a| a.endpoint_arn == input.acme_endpoint_arn).cloned().collect()
        };
        items.sort_by_key(|a| a.created_at);
        let items = items.iter().map(account_summary).collect();
        let (page, next) = common::paginate(items, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAcmeAccountsResponse { acme_accounts: Some(page), next_token: next })
    }

    pub(crate) fn revoke_acme_account(
        &self,
        ctx: &RequestContext,
        input: types::RevokeAcmeAccountRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_acme(ctx, "RevokeAcmeAccount", &input.acme_endpoint_arn, ConditionContext::new())?;
        let a = self.acme_account(ctx, &input.acme_endpoint_arn, &input.account_url)?;
        if a.status == "REVOKED" {
            return Err(errors::conflict(format!("ACME account {} is already revoked.", a.url)));
        }
        if let Some(a) = self.lock().acme_accounts.get_mut(&a.id) {
            a.status = "REVOKED".into();
        }
        Ok(())
    }

    // --- tags on ACME resources ---

    fn check_taggable(&self, ctx: &RequestContext, arn: &str) -> Result<(), ServiceError> {
        match split_arn(ctx, arn) {
            Some((_, _, r)) if r.starts_with("certificate/") => Err(errors::validation(
                "Use AddTagsToCertificate, RemoveTagsFromCertificate and ListTagsForCertificate for certificates.",
            )),
            Some((_, _, r)) if r.starts_with("acme-endpoint/") => {
                if common::is_local(ctx, arn) && self.resource_tags(arn).is_some() {
                    Ok(())
                } else {
                    Err(errors::resource_not_found(format!("Could not find resource {arn}.")))
                }
            }
            _ => Err(common::invalid_arn(arn)),
        }
    }

    fn with_tags(&self, arn: &str, f: impl FnOnce(&mut Tags) -> Result<(), ServiceError>) -> Result<(), ServiceError> {
        let mut st = self.lock();
        let tags = if let Some(e) = st.endpoints.get_mut(arn) {
            &mut e.tags
        } else if let Some(d) = st.domain_validations.get_mut(arn) {
            &mut d.tags
        } else if let Some(e) = st.eabs.get_mut(arn) {
            &mut e.tags
        } else {
            return Err(errors::resource_not_found(format!("Could not find resource {arn}.")));
        };
        f(tags)
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        self.authorize_acme(ctx, "TagResource", &input.resource_arn, common::request_tag_context(&input.tags))?;
        self.check_taggable(ctx, &input.resource_arn)?;
        self.with_tags(&input.resource_arn, |tags| common::merge_tags(tags, &input.tags))
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        let mut cond = ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize_acme(ctx, "UntagResource", &input.resource_arn, cond)?;
        self.check_taggable(ctx, &input.resource_arn)?;
        self.with_tags(&input.resource_arn, |tags| {
            tags.retain(|(k, _)| !input.tag_keys.contains(k));
            Ok(())
        })
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.authorize_acme(ctx, "ListTagsForResource", &input.resource_arn, ConditionContext::new())?;
        self.check_taggable(ctx, &input.resource_arn)?;
        let tags = self.resource_tags(&input.resource_arn).unwrap_or_default();
        Ok(types::ListTagsForResourceResponse { tags: Some(common::tags_to_wire(&tags)) })
    }
}
