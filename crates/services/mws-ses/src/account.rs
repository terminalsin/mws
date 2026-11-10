//! Account-level settings: sending, the sandbox and production access,
//! quotas and statistics, the account suppression list, VDM metrics and
//! message insights.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, DurationRound, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::names::{self, authorize};
use crate::send;
use crate::state::{Region, Suppressed};
use crate::v1::types as t1;
use crate::v2::types as t2;
use crate::{v2, Ses};

/// How long AWS takes to review a production access request.
pub const REVIEW_HOURS: i64 = 24;

/// Decide a pending production access review whose time has come: it is
/// granted (50,000 messages a day, 14 a second) once 24 hours have passed.
pub(crate) fn settle_review(r: &mut Region, now: DateTime<Utc>) {
    if r.account.review_opened.is_some_and(|t| now - t >= Duration::hours(REVIEW_HOURS)) {
        decide_review(r, "GRANTED");
    }
}

/// Close the account's production access review as `GRANTED` or `DENIED`
/// (opening one first if none is pending, so tests can skip the request).
pub(crate) fn decide_review(r: &mut Region, status: &str) {
    r.account.review_opened = None;
    let details = r.account.details.get_or_insert_with(|| t2::AccountDetails {
        mail_type: Some("TRANSACTIONAL".into()),
        website_url: Some("https://example.com".into()),
        ..Default::default()
    });
    let case_id = details.review_details.as_ref().and_then(|v| v.case_id.clone()).unwrap_or_else(names::case_id);
    details.review_details = Some(t2::ReviewDetails { status: Some(status.into()), case_id: Some(case_id) });
    if status == "GRANTED" {
        r.account.production_access = true;
    }
}

impl Ses {
    // ------------------------------------------------------------ v1

    pub(crate) fn get_account_sending_enabled_v1(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<t1::GetAccountSendingEnabledResponse, ServiceError> {
        authorize(ctx, "1", "GetAccountSendingEnabled", "*")?;
        let enabled = self.with_region(ctx, |r| r.account.sending_enabled);
        Ok(t1::GetAccountSendingEnabledResponse { enabled })
    }

    pub(crate) fn update_account_sending_enabled_v1(
        &self,
        ctx: &RequestContext,
        input: t1::UpdateAccountSendingEnabledRequest,
    ) -> Result<(), ServiceError> {
        authorize(ctx, "1", "UpdateAccountSendingEnabled", "*")?;
        self.with_region(ctx, |r| r.account.sending_enabled = input.enabled);
        Ok(())
    }

    pub(crate) fn get_send_quota_v1(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<t1::GetSendQuotaResponse, ServiceError> {
        authorize(ctx, "1", "GetSendQuota", "*")?;
        let now = ctx.received_at;
        let (max, rate, sent) =
            self.with_region(ctx, |r| (send::max_24h(r), send::max_rate(r), send::sent_last_24h(r, now)));
        Ok(t1::GetSendQuotaResponse { max24_hour_send: max, max_send_rate: rate, sent_last24_hours: sent })
    }

    pub(crate) fn get_send_statistics_v1(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<t1::GetSendStatisticsResponse, ServiceError> {
        authorize(ctx, "1", "GetSendStatistics", "*")?;
        let now = ctx.received_at;
        let points = self.with_region(ctx, |r| {
            let mut buckets: BTreeMap<DateTime<Utc>, [i64; 4]> = BTreeMap::new();
            for s in r.sends.iter().filter(|s| now - s.timestamp < Duration::days(14)) {
                let t = s.timestamp.duration_trunc(Duration::minutes(15)).unwrap_or(s.timestamp);
                let b = buckets.entry(t).or_default();
                b[0] += s.recipients.len() as i64;
                for (_, kind, _, _) in &s.events {
                    match kind.as_str() {
                        "BOUNCE" => b[1] += 1,
                        "COMPLAINT" => b[2] += 1,
                        "REJECT" => b[3] += 1,
                        _ => {}
                    }
                }
            }
            buckets
                .into_iter()
                .map(|(t, b)| t1::SendDataPoint {
                    timestamp: Some(t),
                    delivery_attempts: b[0],
                    bounces: b[1],
                    complaints: b[2],
                    rejects: b[3],
                })
                .collect()
        });
        Ok(t1::GetSendStatisticsResponse { send_data_points: Some(points) })
    }

    // ------------------------------------------------------------ v2

    pub(crate) fn get_account_v2(
        &self,
        ctx: &RequestContext,
        _input: t2::GetAccountRequest,
    ) -> Result<t2::GetAccountResponse, ServiceError> {
        authorize(ctx, "2", "GetAccount", "*")?;
        let now = ctx.received_at;
        Ok(self.with_region(ctx, |r| {
            let a = &r.account;
            t2::GetAccountResponse {
                dedicated_ip_auto_warmup_enabled: a.dedicated_ip_auto_warmup,
                enforcement_status: Some("HEALTHY".into()),
                production_access_enabled: a.production_access,
                send_quota: Some(t2::SendQuota {
                    max24_hour_send: send::max_24h(r),
                    max_send_rate: send::max_rate(r),
                    sent_last24_hours: send::sent_last_24h(r, now),
                }),
                sending_enabled: a.sending_enabled,
                suppression_attributes: Some(t2::SuppressionAttributes {
                    suppressed_reasons: Some(a.suppressed_reasons.clone()),
                    validation_attributes: a.suppression_validation.clone(),
                }),
                details: a.details.clone(),
                vdm_attributes: a
                    .vdm
                    .clone()
                    .or_else(|| Some(t2::VdmAttributes { vdm_enabled: "DISABLED".into(), ..Default::default() })),
                pricing_attributes: a
                    .pricing_plan
                    .clone()
                    .map(|p| t2::PricingAttributes { current_plan: Some(p.clone()), next_plan: Some(p) }),
            }
        }))
    }

    pub(crate) fn put_account_details_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutAccountDetailsRequest,
    ) -> Result<t2::PutAccountDetailsResponse, ServiceError> {
        authorize(ctx, "2", "PutAccountDetails", "*")?;
        if !matches!(input.mail_type.as_str(), "MARKETING" | "TRANSACTIONAL") {
            return Err(v2::errors::bad_request(format!("Invalid MailType {}.", input.mail_type)));
        }
        let request = input.production_access_enabled.unwrap_or(false);
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let review = r.account.details.as_ref().and_then(|d| d.review_details.clone());
            let status = review.as_ref().and_then(|v| v.status.clone());
            if request && r.account.production_access {
                return Err(v2::errors::conflict("Production access has already been granted for this account."));
            }
            if request && status.as_deref() == Some("PENDING") {
                return Err(v2::errors::conflict(
                    "A request for production access is already being reviewed for this account.",
                ));
            }
            // Asking for production access opens a support case. The
            // account stays in the sandbox while it is reviewed (24 hours
            // on the emulated clock, or `POST /_aws/ses/production-access`).
            let review_details = if request {
                r.account.review_opened = Some(now);
                Some(t2::ReviewDetails { status: Some("PENDING".into()), case_id: Some(names::case_id()) })
            } else {
                review
            };
            r.account.details = Some(t2::AccountDetails {
                mail_type: Some(input.mail_type),
                website_url: Some(input.website_url),
                contact_language: input.contact_language,
                use_case_description: input.use_case_description,
                additional_contact_email_addresses: input.additional_contact_email_addresses,
                review_details,
            });
            Ok(Default::default())
        })
    }

    pub(crate) fn put_account_dedicated_ip_warmup_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutAccountDedicatedIpWarmupAttributesRequest,
    ) -> Result<t2::PutAccountDedicatedIpWarmupAttributesResponse, ServiceError> {
        authorize(ctx, "2", "PutAccountDedicatedIpWarmupAttributes", "*")?;
        self.with_region(ctx, |r| r.account.dedicated_ip_auto_warmup = input.auto_warmup_enabled);
        Ok(Default::default())
    }

    pub(crate) fn put_account_pricing_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutAccountPricingAttributesRequest,
    ) -> Result<t2::PutAccountPricingAttributesResponse, ServiceError> {
        authorize(ctx, "2", "PutAccountPricingAttributes", "*")?;
        self.with_region(ctx, |r| r.account.pricing_plan = Some(input.plan));
        Ok(Default::default())
    }

    pub(crate) fn put_account_sending_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutAccountSendingAttributesRequest,
    ) -> Result<t2::PutAccountSendingAttributesResponse, ServiceError> {
        authorize(ctx, "2", "PutAccountSendingAttributes", "*")?;
        self.with_region(ctx, |r| r.account.sending_enabled = input.sending_enabled);
        Ok(Default::default())
    }

    pub(crate) fn put_account_suppression_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutAccountSuppressionAttributesRequest,
    ) -> Result<t2::PutAccountSuppressionAttributesResponse, ServiceError> {
        authorize(ctx, "2", "PutAccountSuppressionAttributes", "*")?;
        let reasons = input.suppressed_reasons.unwrap_or_default();
        if let Some(bad) = reasons.iter().find(|r| !matches!(r.as_str(), "BOUNCE" | "COMPLAINT")) {
            return Err(v2::errors::bad_request(format!("Invalid suppression reason {bad}.")));
        }
        self.with_region(ctx, |r| {
            r.account.suppressed_reasons = reasons;
            if input.validation_attributes.is_some() {
                r.account.suppression_validation = input.validation_attributes;
            }
        });
        Ok(Default::default())
    }

    pub(crate) fn put_account_vdm_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutAccountVdmAttributesRequest,
    ) -> Result<t2::PutAccountVdmAttributesResponse, ServiceError> {
        authorize(ctx, "2", "PutAccountVdmAttributes", "*")?;
        self.with_region(ctx, |r| r.account.vdm = Some(input.vdm_attributes));
        Ok(Default::default())
    }

    // ------------------------------------------------------------ suppression list

    fn check_tenant(&self, ctx: &RequestContext, tenant: Option<&str>) -> Result<(), ServiceError> {
        if let Some(t) = tenant {
            if !self.with_region(ctx, |r| r.tenants.contains_key(t)) {
                return Err(v2::errors::not_found(format!("Tenant {t} does not exist.")));
            }
        }
        Ok(())
    }

    pub(crate) fn put_suppressed_destination_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutSuppressedDestinationRequest,
    ) -> Result<t2::PutSuppressedDestinationResponse, ServiceError> {
        authorize(ctx, "2", "PutSuppressedDestination", "*")?;
        if !matches!(input.reason.as_str(), "BOUNCE" | "COMPLAINT") {
            return Err(v2::errors::bad_request(format!("Invalid suppression reason {}.", input.reason)));
        }
        names::check_address(&input.email_address)
            .map_err(|m| v2::errors::bad_request(format!("Invalid email address: {m}")))?;
        self.check_tenant(ctx, input.tenant_name.as_deref())?;
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            r.suppressed.insert(
                input.email_address.to_ascii_lowercase(),
                Suppressed {
                    email: input.email_address,
                    reason: input.reason,
                    last_update: now,
                    message_id: None,
                    feedback_id: None,
                    tenant: input.tenant_name,
                },
            );
        });
        Ok(Default::default())
    }

    pub(crate) fn get_suppressed_destination_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetSuppressedDestinationRequest,
    ) -> Result<t2::GetSuppressedDestinationResponse, ServiceError> {
        authorize(ctx, "2", "GetSuppressedDestination", "*")?;
        self.check_tenant(ctx, input.tenant_name.as_deref())?;
        let s = self
            .with_region(ctx, |r| r.suppressed.get(&input.email_address.to_ascii_lowercase()).cloned())
            .ok_or_else(|| {
                v2::errors::not_found(format!(
                    "Email address {} does not exist on your suppression list.",
                    input.email_address
                ))
            })?;
        Ok(t2::GetSuppressedDestinationResponse {
            suppressed_destination: t2::SuppressedDestination {
                email_address: s.email,
                reason: s.reason,
                last_update_time: s.last_update,
                attributes: (s.message_id.is_some() || s.feedback_id.is_some()).then_some(
                    t2::SuppressedDestinationAttributes { message_id: s.message_id, feedback_id: s.feedback_id },
                ),
                tenant_name: s.tenant,
            },
        })
    }

    pub(crate) fn delete_suppressed_destination_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteSuppressedDestinationRequest,
    ) -> Result<t2::DeleteSuppressedDestinationResponse, ServiceError> {
        authorize(ctx, "2", "DeleteSuppressedDestination", "*")?;
        self.check_tenant(ctx, input.tenant_name.as_deref())?;
        if self.with_region(ctx, |r| r.suppressed.remove(&input.email_address.to_ascii_lowercase())).is_none() {
            return Err(v2::errors::not_found(format!(
                "Email address {} does not exist on your suppression list.",
                input.email_address
            )));
        }
        Ok(Default::default())
    }

    pub(crate) fn list_suppressed_destinations_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListSuppressedDestinationsRequest,
    ) -> Result<t2::ListSuppressedDestinationsResponse, ServiceError> {
        authorize(ctx, "2", "ListSuppressedDestinations", "*")?;
        if input.next_token.as_deref().is_some_and(|t| t.parse::<usize>().is_err()) {
            return Err(v2::errors::invalid_next_token("The NextToken is invalid."));
        }
        self.check_tenant(ctx, input.tenant_name.as_deref())?;
        let reasons = input.reasons.unwrap_or_default();
        let all: Vec<t2::SuppressedDestinationSummary> = self.with_region(ctx, |r| {
            r.suppressed
                .values()
                .filter(|s| reasons.is_empty() || reasons.contains(&s.reason))
                .filter(|s| input.start_date.is_none_or(|d| s.last_update >= d))
                .filter(|s| input.end_date.is_none_or(|d| s.last_update <= d))
                .filter(|s| input.tenant_name.is_none() || s.tenant == input.tenant_name)
                .map(|s| t2::SuppressedDestinationSummary {
                    email_address: s.email.clone(),
                    reason: s.reason.clone(),
                    last_update_time: s.last_update,
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 1000);
        Ok(t2::ListSuppressedDestinationsResponse { suppressed_destination_summaries: Some(page), next_token: next })
    }

    // ------------------------------------------------------------ metrics and insights

    pub(crate) fn batch_get_metric_data_v2(
        &self,
        ctx: &RequestContext,
        input: t2::BatchGetMetricDataRequest,
    ) -> Result<t2::BatchGetMetricDataResponse, ServiceError> {
        authorize(ctx, "2", "BatchGetMetricData", "*")?;
        if input.queries.is_empty() || input.queries.len() > 10 {
            return Err(v2::errors::bad_request("Between 1 and 10 queries are required."));
        }
        let mut results = Vec::new();
        let mut errors = Vec::new();
        let region = self.region_snapshot(ctx).unwrap_or_default();
        for q in input.queries {
            if q.namespace != "VDM" {
                errors.push(t2::MetricDataError {
                    id: Some(q.id),
                    code: Some("ACCESS_DENIED".into()),
                    message: Some(format!("Unsupported namespace {}.", q.namespace)),
                });
                continue;
            }
            let dims = q.dimensions.clone().unwrap_or_default();
            let mut days: BTreeMap<DateTime<Utc>, i64> = BTreeMap::new();
            for s in &region.sends {
                if let Some(id) = dims.get("EMAIL_IDENTITY") {
                    if &s.identity != id {
                        continue;
                    }
                }
                if let Some(cs) = dims.get("CONFIGURATION_SET") {
                    if s.configuration_set.as_ref() != Some(cs) {
                        continue;
                    }
                }
                let count = |kind: &str, detail: Option<&str>| {
                    s.events
                        .iter()
                        .filter(|(_, k, t, d)| {
                            k == kind
                                && *t >= q.start_date
                                && *t <= q.end_date
                                && detail.is_none_or(|x| d.as_deref() == Some(x))
                        })
                        .count() as i64
                };
                let n = match q.metric.as_str() {
                    "SEND" => count("SEND", None),
                    "DELIVERY" => count("DELIVERY", None),
                    "PERMANENT_BOUNCE" => count("BOUNCE", Some("Permanent")),
                    "TRANSIENT_BOUNCE" => count("BOUNCE", Some("Transient")),
                    "COMPLAINT" | "DELIVERY_COMPLAINT" => count("COMPLAINT", None),
                    "OPEN" | "DELIVERY_OPEN" => count("OPEN", None),
                    "CLICK" | "DELIVERY_CLICK" => count("CLICK", None),
                    _ => 0,
                };
                if n > 0 || (s.timestamp >= q.start_date && s.timestamp <= q.end_date) {
                    let day = s.timestamp.duration_trunc(Duration::days(1)).unwrap_or(s.timestamp);
                    *days.entry(day).or_default() += n;
                }
            }
            results.push(t2::MetricDataResult {
                id: Some(q.id),
                timestamps: Some(days.keys().cloned().collect()),
                values: Some(days.values().cloned().collect()),
            });
        }
        Ok(t2::BatchGetMetricDataResponse { results: Some(results), errors: Some(errors) })
    }

    pub(crate) fn get_message_insights_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetMessageInsightsRequest,
    ) -> Result<t2::GetMessageInsightsResponse, ServiceError> {
        authorize(ctx, "2", "GetMessageInsights", "*")?;
        let s = self
            .with_region(ctx, |r| r.sends.iter().find(|s| s.message_id == input.message_id).cloned())
            .ok_or_else(|| v2::errors::not_found(format!("Message {} does not exist.", input.message_id)))?;
        let insights = s
            .recipients
            .iter()
            .map(|rcpt| t2::EmailInsights {
                destination: Some(rcpt.clone()),
                isp: Some(isp_of(rcpt)),
                events: Some(
                    s.events
                        .iter()
                        .filter(|(r, _, _, _)| r == rcpt || r.is_empty())
                        .map(|(_, kind, t, detail)| t2::InsightsEvent {
                            timestamp: Some(*t),
                            r#type: Some(kind.clone()),
                            details: match kind.as_str() {
                                "BOUNCE" => Some(t2::EventDetails {
                                    bounce: Some(t2::Bounce {
                                        bounce_type: detail.clone().map(|d| d.to_ascii_uppercase()),
                                        ..Default::default()
                                    }),
                                    complaint: None,
                                }),
                                "COMPLAINT" => Some(t2::EventDetails {
                                    bounce: None,
                                    complaint: Some(t2::Complaint {
                                        complaint_feedback_type: detail.clone(),
                                        ..Default::default()
                                    }),
                                }),
                                _ => None,
                            },
                        })
                        .collect(),
                ),
            })
            .collect();
        Ok(t2::GetMessageInsightsResponse {
            message_id: Some(s.message_id),
            from_email_address: Some(s.from),
            subject: Some(s.subject),
            email_tags: Some(
                s.tags
                    .iter()
                    .filter(|(k, _)| !k.starts_with("ses:"))
                    .map(|(k, v)| t2::MessageTag { name: k.clone(), value: v.first().cloned().unwrap_or_default() })
                    .collect(),
            ),
            insights: Some(insights),
        })
    }

    pub(crate) fn get_email_address_insights_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetEmailAddressInsightsRequest,
    ) -> Result<t2::GetEmailAddressInsightsResponse, ServiceError> {
        authorize(ctx, "2", "GetEmailAddressInsights", "*")?;
        let syntax = names::check_address(&input.email_address).is_ok();
        let local = names::bare_address(&input.email_address).split('@').next().unwrap_or("").to_ascii_lowercase();
        let role = matches!(
            local.as_str(),
            "admin" | "info" | "support" | "sales" | "postmaster" | "abuse" | "noreply" | "no-reply" | "webmaster"
        );
        let domain = names::domain_of(&input.email_address).unwrap_or_default();
        let dns = syntax
            && (names::is_simulator(&input.email_address)
                || !self.links().dns(&domain, "MX").is_empty()
                || domain.contains('.'));
        let verdict = |b: bool| {
            Some(t2::EmailAddressInsightsVerdict { confidence_verdict: Some(if b { "HIGH" } else { "LOW" }.into()) })
        };
        let valid = syntax && dns;
        Ok(t2::GetEmailAddressInsightsResponse {
            mailbox_validation: Some(t2::MailboxValidation {
                is_valid: verdict(valid),
                evaluations: Some(t2::EmailAddressInsightsMailboxEvaluations {
                    has_valid_syntax: verdict(syntax),
                    has_valid_dns_records: verdict(dns),
                    mailbox_exists: verdict(valid),
                    is_role_address: verdict(role),
                    is_disposable: verdict(false),
                    is_random_input: verdict(false),
                }),
            }),
        })
    }
}

/// The mailbox provider of an address, as message insights name it.
fn isp_of(address: &str) -> String {
    let d = names::domain_of(address).unwrap_or_default();
    match d.as_str() {
        "gmail.com" | "googlemail.com" => "Gmail",
        "yahoo.com" | "ymail.com" => "Yahoo",
        "outlook.com" | "hotmail.com" | "live.com" => "Hotmail",
        "icloud.com" | "me.com" => "iCloud",
        "aol.com" => "AOL",
        _ => "Other",
    }
    .into()
}
