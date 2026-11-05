//! The Service Quotas operations.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::catalog::{self, QuotaDef};
use crate::generated::{types as t, Handler};
use crate::state::{self, Account, AutoManagement, Report, ReportEntry, Request, APPROVAL_MS};
use crate::ServiceQuotas;

const MAX_TAGS: usize = 50;

fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

fn no_such_resource(message: impl Into<String>) -> ServiceError {
    err("NoSuchResourceException", 404, message)
}

fn illegal(message: impl Into<String>) -> ServiceError {
    err("IllegalArgumentException", 400, message)
}

pub(crate) fn new_request_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn service_name(code: &str) -> Result<&'static str, ServiceError> {
    catalog::service_name(code).ok_or_else(|| no_such_resource("The request failed because the specified service does not exist."))
}

fn quota_def(service: &str, code: &str) -> Result<&'static QuotaDef, ServiceError> {
    service_name(service)?;
    catalog::quota(service, code).ok_or_else(|| no_such_resource("The request failed because the specified quota does not exist."))
}

fn quota_arn(ctx: &RequestContext, def: &QuotaDef) -> String {
    format!(
        "arn:{}:servicequotas:{}:{}:{}/{}",
        ctx.partition, ctx.region, ctx.caller.account_id, def.service, def.code
    )
}

fn ms(t: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(t).unwrap_or_default()
}

fn auth(ctx: &RequestContext, action: &str, resource: &str) -> Result<(), ServiceError> {
    ctx.authorize(&format!("servicequotas:{action}"), resource, Default::default())
}

/// Page `items` with an opaque offset token.
fn page<T>(items: Vec<T>, token: Option<&str>, max: Option<i32>, default: usize) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        None => 0,
        Some(t) => t
            .strip_prefix("sq-")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n <= items.len())
            .ok_or_else(|| err("InvalidPaginationTokenException", 400, "Invalid pagination token."))?,
    };
    let size = max.map(|m| m.max(1) as usize).unwrap_or(default);
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then(|| format!("sq-{end}"));
    Ok((items.into_iter().skip(start).take(size).collect(), next))
}

impl ServiceQuotas {
    fn quota_view(&self, ctx: &RequestContext, def: &QuotaDef, value: f64) -> t::ServiceQuota {
        t::ServiceQuota {
            service_code: Some(def.service.into()),
            service_name: catalog::service_name(def.service).map(Into::into),
            quota_arn: Some(quota_arn(ctx, def)),
            quota_code: Some(def.code.into()),
            quota_name: Some(def.name.into()),
            value: Some(value),
            unit: Some(def.unit.into()),
            adjustable: def.adjustable,
            global_quota: def.global,
            usage_metric: def.usage.map(|u| t::MetricInfo {
                metric_namespace: Some(u.namespace.into()),
                metric_name: Some(u.name.into()),
                metric_dimensions: Some(u.dimensions.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
                metric_statistic_recommendation: Some(u.statistic.into()),
            }),
            period: None,
            error_reason: None,
            quota_applied_at_level: Some("ACCOUNT".into()),
            quota_context: None,
            description: (!def.description.is_empty()).then(|| def.description.into()),
        }
    }

    fn applied(&self, ctx: &RequestContext, def: &QuotaDef) -> f64 {
        self.applied_value(&ctx.caller.account_id, &ctx.region, def.service, def.code, ctx.received_at)
    }

    /// The caller's account, settled, under the state lock.
    fn with_account<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut Account) -> R) -> R {
        self.apply_template(&ctx.caller.account_id, ctx.received_at);
        let mut st = self.lock();
        let acct = st.accounts.entry(ctx.caller.account_id.clone()).or_default();
        acct.settle(ctx.received_at.timestamp_millis());
        f(acct)
    }

    fn request_view(&self, ctx: &RequestContext, r: &Request) -> t::RequestedServiceQuotaChange {
        let def = catalog::quota(&r.service, &r.code);
        t::RequestedServiceQuotaChange {
            id: Some(r.id.clone()),
            request_type: r.request_type.clone(),
            case_id: r.case_id.clone(),
            service_code: Some(r.service.clone()),
            service_name: catalog::service_name(&r.service).map(Into::into),
            quota_code: Some(r.code.clone()),
            quota_name: def.map(|d| d.name.into()),
            desired_value: Some(r.desired),
            status: Some(r.status.clone()),
            created: Some(ms(r.created)),
            last_updated: Some(ms(r.updated)),
            requester: Some(r.requester.clone()),
            quota_arn: Some(format!(
                "arn:{}:servicequotas:{}:{}:{}/{}",
                ctx.partition, r.region, ctx.caller.account_id, r.service, r.code
            )),
            global_quota: r.global,
            unit: def.map(|d| d.unit.into()),
            quota_requested_at_level: Some("ACCOUNT".into()),
            quota_context: None,
        }
    }

    /// The caller's organization, for template operations, which the
    /// management account makes in US East (N. Virginia).
    fn template_owner(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        if ctx.region != "us-east-1" {
            return Err(err(
                "TemplatesNotAvailableInRegionException",
                404,
                "The Service Quotas template is not available in this AWS Region.",
            ));
        }
        let org = self
            .inner
            .organizations
            .get()
            .and_then(|o| o.account(&ctx.caller.account_id))
            .ok_or_else(|| {
                err(
                    "NoAvailableOrganizationException",
                    403,
                    "The account making this call is not a member of an organization.",
                )
            })?;
        if org.management_account_id != ctx.caller.account_id {
            return Err(err(
                "AccessDeniedException",
                403,
                "You do not have sufficient permission to perform this action: only the management account of an organization can manage the quota request template.",
            ));
        }
        if !org.all_features {
            return Err(err(
                "OrganizationNotInAllFeaturesModeException",
                400,
                "The organization that your AWS account belongs to is not in All Features mode.",
            ));
        }
        Ok(())
    }

    fn template_entry(key: &str, desired: f64) -> Option<t::ServiceQuotaIncreaseRequestInTemplate> {
        let mut parts = key.splitn(3, '|');
        let (region, service, code) = (parts.next()?, parts.next()?, parts.next()?);
        let def = catalog::quota(service, code)?;
        Some(t::ServiceQuotaIncreaseRequestInTemplate {
            service_code: Some(service.into()),
            service_name: catalog::service_name(service).map(Into::into),
            quota_code: Some(code.into()),
            quota_name: Some(def.name.into()),
            desired_value: Some(desired),
            aws_region: Some(region.into()),
            unit: Some(def.unit.into()),
            global_quota: def.global,
        })
    }

    fn template_key(service: &str, code: &str, region: &str) -> Result<String, ServiceError> {
        let def = quota_def(service, code)?;
        // Template entries are kept per Region even for global quotas.
        Ok(state::key(region, false, def.service, def.code))
    }

    /// The quota a tagging ARN names, checked against the caller.
    fn tagged_quota(&self, ctx: &RequestContext, arn: &str) -> Result<&'static QuotaDef, ServiceError> {
        let bad = || no_such_resource(format!("The resource {arn} does not exist."));
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[0] != "arn" || parts[2] != "servicequotas" {
            return Err(illegal(format!("Invalid ARN: {arn}")));
        }
        if parts[4] != ctx.caller.account_id {
            return Err(bad());
        }
        let (service, code) = parts[5].split_once('/').ok_or_else(bad)?;
        catalog::quota(service, code).ok_or_else(bad)
    }
}

#[async_trait::async_trait]
impl Handler for ServiceQuotas {
    async fn list_services(&self, ctx: &RequestContext, input: t::ListServicesRequest) -> Result<t::ListServicesResponse, ServiceError> {
        auth(ctx, "ListServices", "*")?;
        let all: Vec<t::ServiceInfo> = catalog::SERVICES
            .iter()
            .map(|(c, n)| t::ServiceInfo { service_code: Some((*c).into()), service_name: Some((*n).into()) })
            .collect();
        let (services, next_token) = page(all, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListServicesResponse { next_token, services: Some(services) })
    }

    async fn get_aws_default_service_quota(
        &self,
        ctx: &RequestContext,
        input: t::GetAWSDefaultServiceQuotaRequest,
    ) -> Result<t::GetAWSDefaultServiceQuotaResponse, ServiceError> {
        auth(ctx, "GetAWSDefaultServiceQuota", "*")?;
        let def = quota_def(&input.service_code, &input.quota_code)?;
        Ok(t::GetAWSDefaultServiceQuotaResponse { quota: Some(self.quota_view(ctx, def, def.default_in(&ctx.region))) })
    }

    async fn list_aws_default_service_quotas(
        &self,
        ctx: &RequestContext,
        input: t::ListAWSDefaultServiceQuotasRequest,
    ) -> Result<t::ListAWSDefaultServiceQuotasResponse, ServiceError> {
        auth(ctx, "ListAWSDefaultServiceQuotas", "*")?;
        service_name(&input.service_code)?;
        let all: Vec<t::ServiceQuota> = catalog::quotas_of(&input.service_code)
            .map(|d| self.quota_view(ctx, d, d.default_in(&ctx.region)))
            .collect();
        let (quotas, next_token) = page(all, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListAWSDefaultServiceQuotasResponse { next_token, quotas: Some(quotas) })
    }

    async fn get_service_quota(&self, ctx: &RequestContext, input: t::GetServiceQuotaRequest) -> Result<t::GetServiceQuotaResponse, ServiceError> {
        let def = quota_def(&input.service_code, &input.quota_code)?;
        auth(ctx, "GetServiceQuota", &quota_arn(ctx, def))?;
        let value = self.applied(ctx, def);
        Ok(t::GetServiceQuotaResponse { quota: Some(self.quota_view(ctx, def, value)) })
    }

    async fn list_service_quotas(&self, ctx: &RequestContext, input: t::ListServiceQuotasRequest) -> Result<t::ListServiceQuotasResponse, ServiceError> {
        auth(ctx, "ListServiceQuotas", "*")?;
        service_name(&input.service_code)?;
        let level = input.quota_applied_at_level.as_deref().unwrap_or("ACCOUNT");
        let all: Vec<t::ServiceQuota> = if level == "RESOURCE" {
            Vec::new()
        } else {
            catalog::quotas_of(&input.service_code)
                .filter(|d| input.quota_code.as_deref().is_none_or(|c| c == d.code))
                .map(|d| self.quota_view(ctx, d, self.applied(ctx, d)))
                .collect()
        };
        let (quotas, next_token) = page(all, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListServiceQuotasResponse { next_token, quotas: Some(quotas) })
    }

    async fn request_service_quota_increase(
        &self,
        ctx: &RequestContext,
        input: t::RequestServiceQuotaIncreaseRequest,
    ) -> Result<t::RequestServiceQuotaIncreaseResponse, ServiceError> {
        let def = quota_def(&input.service_code, &input.quota_code)?;
        let mut context = mws_core::ConditionContext::new();
        context.insert("servicequotas:service".into(), vec![def.service.into()]);
        ctx.authorize("servicequotas:RequestServiceQuotaIncrease", &quota_arn(ctx, def), context)?;
        if !def.adjustable {
            return Err(illegal(format!("The quota {} for service {} is not adjustable.", def.code, def.service)));
        }
        let current = self.applied(ctx, def);
        if input.desired_value <= current {
            return Err(illegal(format!(
                "The requested value {} is less than or equal to the current value {}.",
                input.desired_value, current
            )));
        }
        let now = ctx.received_at.timestamp_millis();
        let requester = format!("{{\"accountId\":\"{}\",\"callerArn\":\"{}\"}}", ctx.caller.account_id, ctx.caller.arn);
        let request = self.with_account(ctx, |acct| {
            if acct.requests.values().any(|r| r.open() && r.service == def.service && r.code == def.code && (def.global || r.region == ctx.region)) {
                return Err(err(
                    "ResourceAlreadyExistsException",
                    400,
                    "Only one open service quota increase request is allowed per quota.",
                ));
            }
            let id = new_request_id();
            let r = Request {
                id: id.clone(),
                service: def.service.into(),
                code: def.code.into(),
                region: ctx.region.clone(),
                global: def.global,
                desired: input.desired_value,
                status: "PENDING".into(),
                created: now,
                updated: now,
                case_id: None,
                requester,
                request_type: None,
                settles_at: now + APPROVAL_MS,
            };
            acct.requests.insert(id, r.clone());
            Ok(r)
        })?;
        Ok(t::RequestServiceQuotaIncreaseResponse { requested_quota: Some(self.request_view(ctx, &request)) })
    }

    async fn get_requested_service_quota_change(
        &self,
        ctx: &RequestContext,
        input: t::GetRequestedServiceQuotaChangeRequest,
    ) -> Result<t::GetRequestedServiceQuotaChangeResponse, ServiceError> {
        auth(ctx, "GetRequestedServiceQuotaChange", "*")?;
        let r = self
            .with_account(ctx, |acct| acct.requests.get(&input.request_id).cloned())
            .ok_or_else(|| no_such_resource("The request failed because the specified request ID does not exist."))?;
        Ok(t::GetRequestedServiceQuotaChangeResponse { requested_quota: Some(self.request_view(ctx, &r)) })
    }

    async fn list_requested_service_quota_change_history(
        &self,
        ctx: &RequestContext,
        input: t::ListRequestedServiceQuotaChangeHistoryRequest,
    ) -> Result<t::ListRequestedServiceQuotaChangeHistoryResponse, ServiceError> {
        auth(ctx, "ListRequestedServiceQuotaChangeHistory", "*")?;
        if let Some(s) = &input.service_code {
            service_name(s)?;
        }
        let level = input.quota_requested_at_level.as_deref().unwrap_or("ACCOUNT");
        let mut all = self.with_account(ctx, |acct| acct.requests.values().cloned().collect::<Vec<_>>());
        all.retain(|r| {
            (r.global || r.region == ctx.region)
                && input.service_code.as_deref().is_none_or(|s| s == r.service)
                && input.status.as_deref().is_none_or(|s| s == r.status)
                && level != "RESOURCE"
        });
        all.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
        let views: Vec<_> = all.iter().map(|r| self.request_view(ctx, r)).collect();
        let (requested_quotas, next_token) = page(views, input.next_token.as_deref(), input.max_results, 20)?;
        Ok(t::ListRequestedServiceQuotaChangeHistoryResponse { next_token, requested_quotas: Some(requested_quotas) })
    }

    async fn list_requested_service_quota_change_history_by_quota(
        &self,
        ctx: &RequestContext,
        input: t::ListRequestedServiceQuotaChangeHistoryByQuotaRequest,
    ) -> Result<t::ListRequestedServiceQuotaChangeHistoryByQuotaResponse, ServiceError> {
        auth(ctx, "ListRequestedServiceQuotaChangeHistoryByQuota", "*")?;
        let def = quota_def(&input.service_code, &input.quota_code)?;
        let level = input.quota_requested_at_level.as_deref().unwrap_or("ACCOUNT");
        let mut all = self.with_account(ctx, |acct| acct.requests.values().cloned().collect::<Vec<_>>());
        all.retain(|r| {
            r.service == def.service
                && r.code == def.code
                && (r.global || r.region == ctx.region)
                && input.status.as_deref().is_none_or(|s| s == r.status)
                && level != "RESOURCE"
        });
        all.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
        let views: Vec<_> = all.iter().map(|r| self.request_view(ctx, r)).collect();
        let (requested_quotas, next_token) = page(views, input.next_token.as_deref(), input.max_results, 20)?;
        Ok(t::ListRequestedServiceQuotaChangeHistoryByQuotaResponse { next_token, requested_quotas: Some(requested_quotas) })
    }

    async fn create_support_case(&self, ctx: &RequestContext, input: t::CreateSupportCaseRequest) -> Result<t::CreateSupportCaseResponse, ServiceError> {
        auth(ctx, "CreateSupportCase", "*")?;
        let now = ctx.received_at.timestamp_millis();
        self.with_account(ctx, |acct| {
            let r = acct
                .requests
                .get_mut(&input.request_id)
                .ok_or_else(|| no_such_resource("The request failed because the specified request ID does not exist."))?;
            if r.case_id.is_some() {
                return Err(err("ResourceAlreadyExistsException", 400, "A support case already exists for this request."));
            }
            if !r.open() {
                return Err(err(
                    "InvalidResourceStateException",
                    405,
                    format!("The request is in the {} state and can't be escalated to a support case.", r.status),
                ));
            }
            r.case_id = Some(format!("{}", 10_000_000_000u64 + (now as u64 % 1_000_000_000)));
            r.status = "CASE_OPENED".into();
            r.updated = now;
            // The case is reviewed like the request was.
            r.settles_at = now + APPROVAL_MS;
            Ok(())
        })?;
        Ok(t::CreateSupportCaseResponse {})
    }

    async fn associate_service_quota_template(
        &self,
        ctx: &RequestContext,
        _input: t::AssociateServiceQuotaTemplateRequest,
    ) -> Result<t::AssociateServiceQuotaTemplateResponse, ServiceError> {
        auth(ctx, "AssociateServiceQuotaTemplate", "*")?;
        self.template_owner(ctx)?;
        let now = ctx.received_at.timestamp_millis();
        self.with_account(ctx, |acct| {
            acct.template_associated_at.get_or_insert(now);
        });
        Ok(t::AssociateServiceQuotaTemplateResponse {})
    }

    async fn disassociate_service_quota_template(
        &self,
        ctx: &RequestContext,
        _input: t::DisassociateServiceQuotaTemplateRequest,
    ) -> Result<t::DisassociateServiceQuotaTemplateResponse, ServiceError> {
        auth(ctx, "DisassociateServiceQuotaTemplate", "*")?;
        self.template_owner(ctx)?;
        self.with_account(ctx, |acct| match acct.template_associated_at.take() {
            Some(_) => Ok(()),
            None => Err(err(
                "ServiceQuotaTemplateNotInUseException",
                400,
                "The quota request template is not associated with your organization.",
            )),
        })?;
        Ok(t::DisassociateServiceQuotaTemplateResponse {})
    }

    async fn get_association_for_service_quota_template(
        &self,
        ctx: &RequestContext,
        _input: t::GetAssociationForServiceQuotaTemplateRequest,
    ) -> Result<t::GetAssociationForServiceQuotaTemplateResponse, ServiceError> {
        auth(ctx, "GetAssociationForServiceQuotaTemplate", "*")?;
        self.template_owner(ctx)?;
        let associated = self.with_account(ctx, |acct| acct.template_associated_at.is_some());
        Ok(t::GetAssociationForServiceQuotaTemplateResponse {
            service_quota_template_association_status: Some(if associated { "ASSOCIATED" } else { "DISASSOCIATED" }.into()),
        })
    }

    async fn put_service_quota_increase_request_into_template(
        &self,
        ctx: &RequestContext,
        input: t::PutServiceQuotaIncreaseRequestIntoTemplateRequest,
    ) -> Result<t::PutServiceQuotaIncreaseRequestIntoTemplateResponse, ServiceError> {
        auth(ctx, "PutServiceQuotaIncreaseRequestIntoTemplate", "*")?;
        self.template_owner(ctx)?;
        let key = Self::template_key(&input.service_code, &input.quota_code, &input.aws_region)?;
        let def = quota_def(&input.service_code, &input.quota_code)?;
        if !def.adjustable {
            return Err(illegal(format!("The quota {} for service {} is not adjustable.", def.code, def.service)));
        }
        if input.desired_value <= def.default_in(&input.aws_region) {
            return Err(illegal("The desired value must be greater than the quota's default value."));
        }
        self.with_account(ctx, |acct| {
            if acct.template.len() >= 10 && !acct.template.contains_key(&key) {
                return Err(err(
                    "QuotaExceededException",
                    409,
                    "You have reached the maximum number of quota increase requests in the template.",
                ));
            }
            acct.template.insert(key.clone(), input.desired_value);
            Ok(())
        })?;
        Ok(t::PutServiceQuotaIncreaseRequestIntoTemplateResponse {
            service_quota_increase_request_in_template: Self::template_entry(&key, input.desired_value),
        })
    }

    async fn get_service_quota_increase_request_from_template(
        &self,
        ctx: &RequestContext,
        input: t::GetServiceQuotaIncreaseRequestFromTemplateRequest,
    ) -> Result<t::GetServiceQuotaIncreaseRequestFromTemplateResponse, ServiceError> {
        auth(ctx, "GetServiceQuotaIncreaseRequestFromTemplate", "*")?;
        self.template_owner(ctx)?;
        let key = Self::template_key(&input.service_code, &input.quota_code, &input.aws_region)?;
        let desired = self
            .with_account(ctx, |acct| acct.template.get(&key).copied())
            .ok_or_else(|| no_such_resource("The request failed because the specified quota is not in the template."))?;
        Ok(t::GetServiceQuotaIncreaseRequestFromTemplateResponse {
            service_quota_increase_request_in_template: Self::template_entry(&key, desired),
        })
    }

    async fn delete_service_quota_increase_request_from_template(
        &self,
        ctx: &RequestContext,
        input: t::DeleteServiceQuotaIncreaseRequestFromTemplateRequest,
    ) -> Result<t::DeleteServiceQuotaIncreaseRequestFromTemplateResponse, ServiceError> {
        auth(ctx, "DeleteServiceQuotaIncreaseRequestFromTemplate", "*")?;
        self.template_owner(ctx)?;
        let key = Self::template_key(&input.service_code, &input.quota_code, &input.aws_region)?;
        self.with_account(ctx, |acct| acct.template.remove(&key))
            .ok_or_else(|| no_such_resource("The request failed because the specified quota is not in the template."))?;
        Ok(t::DeleteServiceQuotaIncreaseRequestFromTemplateResponse {})
    }

    async fn list_service_quota_increase_requests_in_template(
        &self,
        ctx: &RequestContext,
        input: t::ListServiceQuotaIncreaseRequestsInTemplateRequest,
    ) -> Result<t::ListServiceQuotaIncreaseRequestsInTemplateResponse, ServiceError> {
        auth(ctx, "ListServiceQuotaIncreaseRequestsInTemplate", "*")?;
        self.template_owner(ctx)?;
        let entries = self.with_account(ctx, |acct| acct.template.clone());
        let all: Vec<_> = entries
            .iter()
            .filter_map(|(k, v)| Self::template_entry(k, *v))
            .filter(|e| {
                input.service_code.as_deref().is_none_or(|s| e.service_code.as_deref() == Some(s))
                    && input.aws_region.as_deref().is_none_or(|r| e.aws_region.as_deref() == Some(r))
            })
            .collect();
        let (list, next_token) = page(all, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListServiceQuotaIncreaseRequestsInTemplateResponse {
            service_quota_increase_request_in_template_list: Some(list),
            next_token,
        })
    }

    async fn tag_resource(&self, ctx: &RequestContext, input: t::TagResourceRequest) -> Result<t::TagResourceResponse, ServiceError> {
        let def = self.tagged_quota(ctx, &input.resource_arn)?;
        let _ = def;
        let mut context = mws_core::ConditionContext::new();
        for tag in &input.tags {
            context.insert(format!("aws:RequestTag/{}", tag.key), vec![tag.value.clone()]);
        }
        context.insert("aws:TagKeys".into(), input.tags.iter().map(|t| t.key.clone()).collect());
        ctx.authorize("servicequotas:TagResource", &input.resource_arn, context)?;
        self.with_account(ctx, |acct| {
            let tags = acct.tags.entry(input.resource_arn.clone()).or_default();
            let mut merged = tags.clone();
            for tag in &input.tags {
                if tag.key.starts_with("aws:") {
                    return Err(illegal("Tag keys can't start with the reserved prefix aws:."));
                }
                merged.insert(tag.key.clone(), tag.value.clone());
            }
            if merged.len() > MAX_TAGS {
                return Err(err("TooManyTagsException", 400, "You've exceeded the number of tags allowed for a resource."));
            }
            *tags = merged;
            Ok(())
        })?;
        Ok(t::TagResourceResponse {})
    }

    async fn untag_resource(&self, ctx: &RequestContext, input: t::UntagResourceRequest) -> Result<t::UntagResourceResponse, ServiceError> {
        self.tagged_quota(ctx, &input.resource_arn)?;
        let mut context = mws_core::ConditionContext::new();
        context.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("servicequotas:UntagResource", &input.resource_arn, context)?;
        self.with_account(ctx, |acct| {
            if let Some(tags) = acct.tags.get_mut(&input.resource_arn) {
                for k in &input.tag_keys {
                    tags.remove(k);
                }
            }
        });
        Ok(t::UntagResourceResponse {})
    }

    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: t::ListTagsForResourceRequest,
    ) -> Result<t::ListTagsForResourceResponse, ServiceError> {
        self.tagged_quota(ctx, &input.resource_arn)?;
        ctx.authorize("servicequotas:ListTagsForResource", &input.resource_arn, Default::default())?;
        let tags = self.with_account(ctx, |acct| acct.tags.get(&input.resource_arn).cloned().unwrap_or_default());
        Ok(t::ListTagsForResourceResponse {
            tags: Some(tags.into_iter().map(|(key, value)| t::Tag { key, value }).collect()),
        })
    }

    async fn start_auto_management(
        &self,
        ctx: &RequestContext,
        input: t::StartAutoManagementRequest,
    ) -> Result<t::StartAutoManagementResponse, ServiceError> {
        auth(ctx, "StartAutoManagement", "*")?;
        let exclusions = exclusions(input.exclusion_list.as_ref())?;
        self.with_account(ctx, |acct| {
            acct.auto_management = Some(AutoManagement {
                opt_in_level: input.opt_in_level.clone(),
                opt_in_type: input.opt_in_type.clone(),
                notification_arn: input.notification_arn.clone(),
                exclusions,
            });
        });
        Ok(t::StartAutoManagementResponse {})
    }

    async fn update_auto_management(
        &self,
        ctx: &RequestContext,
        input: t::UpdateAutoManagementRequest,
    ) -> Result<t::UpdateAutoManagementResponse, ServiceError> {
        auth(ctx, "UpdateAutoManagement", "*")?;
        let exclusions = match input.exclusion_list.as_ref() {
            Some(e) => Some(exclusions(Some(e))?),
            None => None,
        };
        self.with_account(ctx, |acct| {
            let am = acct.auto_management.as_mut().ok_or_else(|| {
                err("InvalidResourceStateException", 405, "Automatic management is not enabled for this account.")
            })?;
            if let Some(t) = &input.opt_in_type {
                am.opt_in_type = t.clone();
            }
            if let Some(n) = &input.notification_arn {
                am.notification_arn = Some(n.clone());
            }
            if let Some(e) = exclusions {
                am.exclusions = e;
            }
            Ok(())
        })?;
        Ok(t::UpdateAutoManagementResponse {})
    }

    async fn stop_auto_management(
        &self,
        ctx: &RequestContext,
        _input: t::StopAutoManagementRequest,
    ) -> Result<t::StopAutoManagementResponse, ServiceError> {
        auth(ctx, "StopAutoManagement", "*")?;
        self.with_account(ctx, |acct| {
            acct.auto_management.take().map(|_| ()).ok_or_else(|| {
                err("InvalidResourceStateException", 405, "Automatic management is not enabled for this account.")
            })
        })?;
        Ok(t::StopAutoManagementResponse {})
    }

    async fn get_auto_management_configuration(
        &self,
        ctx: &RequestContext,
        _input: t::GetAutoManagementConfigurationRequest,
    ) -> Result<t::GetAutoManagementConfigurationResponse, ServiceError> {
        auth(ctx, "GetAutoManagementConfiguration", "*")?;
        let am = self.with_account(ctx, |acct| acct.auto_management.clone());
        Ok(match am {
            None => t::GetAutoManagementConfigurationResponse {
                opt_in_status: Some("DISABLED".into()),
                ..Default::default()
            },
            Some(am) => t::GetAutoManagementConfigurationResponse {
                opt_in_level: Some(am.opt_in_level),
                opt_in_type: Some(am.opt_in_type),
                notification_arn: am.notification_arn,
                opt_in_status: Some("ENABLED".into()),
                exclusion_list: Some(
                    am.exclusions
                        .into_iter()
                        .map(|(service, codes)| {
                            let infos = codes
                                .into_iter()
                                .map(|code| t::QuotaInfo {
                                    quota_name: catalog::quota(&service, &code).map(|d| d.name.into()),
                                    quota_code: Some(code),
                                })
                                .collect();
                            (service, infos)
                        })
                        .collect(),
                ),
            },
        })
    }

    async fn start_quota_utilization_report(
        &self,
        ctx: &RequestContext,
        _input: t::StartQuotaUtilizationReportRequest,
    ) -> Result<t::StartQuotaUtilizationReportResponse, ServiceError> {
        auth(ctx, "StartQuotaUtilizationReport", "*")?;
        let usage = self.measure(&ctx.caller.account_id, &ctx.region);
        let mut entries: Vec<ReportEntry> = usage
            .into_iter()
            .filter_map(|((service, code), usage)| {
                let def = catalog::quota(service, code)?;
                Some(ReportEntry { service: service.into(), code: code.into(), usage, applied: self.applied(ctx, def) })
            })
            .collect();
        entries.sort_by(|a, b| utilization(b).total_cmp(&utilization(a)).then(a.code.cmp(&b.code)));
        let id = uuid::Uuid::new_v4().to_string();
        let report = Report { id: id.clone(), generated_at: ctx.received_at.timestamp_millis(), entries };
        self.with_account(ctx, |acct| {
            acct.reports.insert(id.clone(), report);
        });
        Ok(t::StartQuotaUtilizationReportResponse {
            report_id: Some(id),
            status: Some("PENDING".into()),
            message: Some("Your quota utilization report is being generated.".into()),
        })
    }

    async fn get_quota_utilization_report(
        &self,
        ctx: &RequestContext,
        input: t::GetQuotaUtilizationReportRequest,
    ) -> Result<t::GetQuotaUtilizationReportResponse, ServiceError> {
        auth(ctx, "GetQuotaUtilizationReport", "*")?;
        let report = self
            .with_account(ctx, |acct| acct.reports.get(&input.report_id).cloned())
            .ok_or_else(|| no_such_resource(format!("The report {} does not exist.", input.report_id)))?;
        let total = report.entries.len() as i32;
        let infos: Vec<t::QuotaUtilizationInfo> = report
            .entries
            .iter()
            .filter_map(|e| {
                let def = catalog::quota(&e.service, &e.code)?;
                Some(t::QuotaUtilizationInfo {
                    quota_code: Some(e.code.clone()),
                    service_code: Some(e.service.clone()),
                    quota_name: Some(def.name.into()),
                    namespace: def.usage.map(|u| u.namespace.into()),
                    utilization: Some((utilization(e) * 100.0).round() / 100.0),
                    default_value: Some(def.default_in(&ctx.region)),
                    applied_value: Some(e.applied),
                    service_name: catalog::service_name(&e.service).map(Into::into),
                    adjustable: def.adjustable,
                })
            })
            .collect();
        let (quotas, next_token) = page(infos, input.next_token.as_deref(), input.max_results, 1000)?;
        Ok(t::GetQuotaUtilizationReportResponse {
            report_id: Some(report.id),
            status: Some("COMPLETED".into()),
            generated_at: Some(ms(report.generated_at)),
            total_count: Some(total),
            quotas: Some(quotas),
            next_token,
            error_code: None,
            error_message: None,
        })
    }
}

/// Utilization as a percentage of the applied value.
fn utilization(e: &ReportEntry) -> f64 {
    if e.applied > 0.0 {
        e.usage / e.applied * 100.0
    } else if e.usage > 0.0 {
        100.0
    } else {
        0.0
    }
}

fn exclusions(list: Option<&BTreeMap<String, Vec<String>>>) -> Result<BTreeMap<String, Vec<String>>, ServiceError> {
    let mut out = BTreeMap::new();
    for (service, codes) in list.into_iter().flatten() {
        service_name(service)?;
        for code in codes {
            quota_def(service, code)?;
        }
        out.insert(service.clone(), codes.clone());
    }
    Ok(out)
}
