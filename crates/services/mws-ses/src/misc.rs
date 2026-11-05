//! The rest of SES v2: dedicated IPs and pools, the deliverability
//! dashboard, import and export jobs (which really read from and write to
//! S3), multi-Region endpoints, tenants, reputation entities,
//! recommendations and resource tags.

use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::names::{self, authorize};
use crate::public::S3Put;
use crate::state::{
    DedicatedIpPool, ExportJob, ImportJob, MultiRegionEndpoint, Region, Suppressed, Tenant, TestReport,
};
use crate::v2::types as t2;
use crate::{v2, Ses};

fn split_s3_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("s3://")?;
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    Some((bucket.to_string(), key.to_string()))
}

impl Ses {
    // ------------------------------------------------------------ dedicated IPs

    pub(crate) fn create_dedicated_ip_pool_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateDedicatedIpPoolRequest,
    ) -> Result<t2::CreateDedicatedIpPoolResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        names::authorize_create(
            ctx,
            "CreateDedicatedIpPool",
            &names::arn(ctx, &format!("dedicated-ip-pool/{}", input.pool_name)),
            &tags,
        )?;
        names::check_tags(&tags)?;
        if !names::valid_name(&input.pool_name) {
            return Err(v2::errors::bad_request(format!("Invalid pool name {}.", input.pool_name)));
        }
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if r.dedicated_ip_pools.contains_key(&input.pool_name) {
                return Err(v2::errors::already_exists(format!("Pool {} already exists.", input.pool_name)));
            }
            if r.dedicated_ip_pools.len() >= 50 {
                return Err(v2::errors::limit_exceeded("Maximum number of dedicated IP pools reached."));
            }
            r.dedicated_ip_pools.insert(
                input.pool_name.clone(),
                DedicatedIpPool {
                    name: input.pool_name,
                    scaling_mode: input.scaling_mode.unwrap_or_else(|| "STANDARD".into()),
                    created: now,
                    tags: tags.into_iter().collect(),
                },
            );
            Ok(Default::default())
        })
    }

    fn pool_v2(&self, ctx: &RequestContext, action: &str, name: &str) -> Result<DedicatedIpPool, ServiceError> {
        let pool = self.with_region(ctx, |r| r.dedicated_ip_pools.get(name).cloned());
        let arn = names::arn(ctx, &format!("dedicated-ip-pool/{name}"));
        names::authorize_tagged(ctx, "2", action, &arn, &pool.as_ref().map(|p| p.tags.clone()).unwrap_or_default())?;
        pool.ok_or_else(|| v2::errors::not_found(format!("Pool {name} does not exist.")))
    }

    pub(crate) fn get_dedicated_ip_pool_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetDedicatedIpPoolRequest,
    ) -> Result<t2::GetDedicatedIpPoolResponse, ServiceError> {
        let p = self.pool_v2(ctx, "GetDedicatedIpPool", &input.pool_name)?;
        Ok(t2::GetDedicatedIpPoolResponse {
            dedicated_ip_pool: Some(t2::DedicatedIpPool { pool_name: p.name, scaling_mode: p.scaling_mode }),
        })
    }

    pub(crate) fn delete_dedicated_ip_pool_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteDedicatedIpPoolRequest,
    ) -> Result<t2::DeleteDedicatedIpPoolResponse, ServiceError> {
        self.pool_v2(ctx, "DeleteDedicatedIpPool", &input.pool_name)?;
        self.with_region(ctx, |r| r.dedicated_ip_pools.remove(&input.pool_name));
        Ok(Default::default())
    }

    pub(crate) fn list_dedicated_ip_pools_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListDedicatedIpPoolsRequest,
    ) -> Result<t2::ListDedicatedIpPoolsResponse, ServiceError> {
        authorize(ctx, "2", "ListDedicatedIpPools", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<String> = self.with_region(ctx, |r| r.dedicated_ip_pools.keys().cloned().collect());
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListDedicatedIpPoolsResponse { dedicated_ip_pools: Some(page), next_token: next })
    }

    pub(crate) fn put_dedicated_ip_pool_scaling_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutDedicatedIpPoolScalingAttributesRequest,
    ) -> Result<t2::PutDedicatedIpPoolScalingAttributesResponse, ServiceError> {
        let p = self.pool_v2(ctx, "PutDedicatedIpPoolScalingAttributes", &input.pool_name)?;
        if p.scaling_mode == "MANAGED" && input.scaling_mode == "STANDARD" {
            return Err(v2::errors::bad_request("A managed pool cannot be changed to a standard pool."));
        }
        self.with_region(ctx, |r| {
            if let Some(p) = r.dedicated_ip_pools.get_mut(&input.pool_name) {
                p.scaling_mode = input.scaling_mode;
            }
        });
        Ok(Default::default())
    }

    /// MWS has no dedicated IPs to lease, as an account that never bought
    /// any.
    fn no_ip(ip: &str) -> ServiceError {
        v2::errors::not_found(format!("Dedicated IP {ip} does not exist."))
    }

    pub(crate) fn get_dedicated_ip_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetDedicatedIpRequest,
    ) -> Result<t2::GetDedicatedIpResponse, ServiceError> {
        authorize(ctx, "2", "GetDedicatedIp", "*")?;
        Err(Self::no_ip(&input.ip))
    }

    pub(crate) fn get_dedicated_ips_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetDedicatedIpsRequest,
    ) -> Result<t2::GetDedicatedIpsResponse, ServiceError> {
        authorize(ctx, "2", "GetDedicatedIps", "*")?;
        if let Some(p) = &input.pool_name {
            self.pool_v2(ctx, "GetDedicatedIps", p)?;
        }
        Ok(t2::GetDedicatedIpsResponse { dedicated_ips: Some(Vec::new()), next_token: None })
    }

    pub(crate) fn put_dedicated_ip_in_pool_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutDedicatedIpInPoolRequest,
    ) -> Result<t2::PutDedicatedIpInPoolResponse, ServiceError> {
        authorize(ctx, "2", "PutDedicatedIpInPool", "*")?;
        self.pool_v2(ctx, "PutDedicatedIpInPool", &input.destination_pool_name)?;
        Err(Self::no_ip(&input.ip))
    }

    pub(crate) fn put_dedicated_ip_warmup_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutDedicatedIpWarmupAttributesRequest,
    ) -> Result<t2::PutDedicatedIpWarmupAttributesResponse, ServiceError> {
        authorize(ctx, "2", "PutDedicatedIpWarmupAttributes", "*")?;
        Err(Self::no_ip(&input.ip))
    }

    // ------------------------------------------------------------ deliverability dashboard

    pub(crate) fn get_deliverability_dashboard_options_v2(
        &self,
        ctx: &RequestContext,
        _input: t2::GetDeliverabilityDashboardOptionsRequest,
    ) -> Result<t2::GetDeliverabilityDashboardOptionsResponse, ServiceError> {
        authorize(ctx, "2", "GetDeliverabilityDashboardOptions", "*")?;
        let d = self.with_region(ctx, |r| r.dashboard.clone());
        Ok(t2::GetDeliverabilityDashboardOptionsResponse {
            dashboard_enabled: d.enabled,
            subscription_expiry_date: d.subscription_expiry,
            account_status: Some(if d.enabled { "ACTIVE" } else { "DISABLED" }.into()),
            active_subscribed_domains: Some(d.domains),
            pending_expiration_subscribed_domains: Some(Vec::new()),
        })
    }

    pub(crate) fn put_deliverability_dashboard_option_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutDeliverabilityDashboardOptionRequest,
    ) -> Result<t2::PutDeliverabilityDashboardOptionResponse, ServiceError> {
        authorize(ctx, "2", "PutDeliverabilityDashboardOption", "*")?;
        let now = ctx.received_at;
        let mut domains = input.subscribed_domains.unwrap_or_default();
        self.with_region(ctx, |r| {
            for d in &mut domains {
                let name = d.domain.clone().unwrap_or_default();
                if !r.identities.get(&name).is_some_and(|i| i.is_domain() && i.verified()) {
                    return Err(v2::errors::not_found(format!("Domain {name} is not a verified identity.")));
                }
                d.subscription_start_date.get_or_insert(now);
            }
            r.dashboard.enabled = input.dashboard_enabled;
            r.dashboard.subscription_expiry = input.dashboard_enabled.then(|| now + Duration::days(30));
            r.dashboard.domains = if input.dashboard_enabled { domains } else { Vec::new() };
            Ok(Default::default())
        })
    }

    fn require_dashboard(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        if self.with_region(ctx, |r| r.dashboard.enabled) {
            Ok(())
        } else {
            Err(v2::errors::not_found("The Deliverability dashboard is not enabled for this account."))
        }
    }

    pub(crate) fn get_blacklist_reports_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetBlacklistReportsRequest,
    ) -> Result<t2::GetBlacklistReportsResponse, ServiceError> {
        authorize(ctx, "2", "GetBlacklistReports", "*")?;
        self.require_dashboard(ctx)?;
        Ok(t2::GetBlacklistReportsResponse {
            blacklist_report: input.blacklist_item_names.into_iter().map(|n| (n, Vec::new())).collect(),
        })
    }

    pub(crate) fn get_domain_deliverability_campaign_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetDomainDeliverabilityCampaignRequest,
    ) -> Result<t2::GetDomainDeliverabilityCampaignResponse, ServiceError> {
        authorize(ctx, "2", "GetDomainDeliverabilityCampaign", "*")?;
        self.require_dashboard(ctx)?;
        Err(v2::errors::not_found(format!("Campaign {} does not exist.", input.campaign_id)))
    }

    pub(crate) fn list_domain_deliverability_campaigns_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListDomainDeliverabilityCampaignsRequest,
    ) -> Result<t2::ListDomainDeliverabilityCampaignsResponse, ServiceError> {
        authorize(ctx, "2", "ListDomainDeliverabilityCampaigns", "*")?;
        self.require_dashboard(ctx)?;
        if !self.with_region(ctx, |r| {
            r.dashboard.domains.iter().any(|d| d.domain.as_deref() == Some(input.subscribed_domain.as_str()))
        }) {
            return Err(v2::errors::not_found(format!("Domain {} is not subscribed.", input.subscribed_domain)));
        }
        Ok(t2::ListDomainDeliverabilityCampaignsResponse {
            domain_deliverability_campaigns: Vec::new(),
            next_token: None,
        })
    }

    pub(crate) fn get_domain_statistics_report_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetDomainStatisticsReportRequest,
    ) -> Result<t2::GetDomainStatisticsReportResponse, ServiceError> {
        authorize(ctx, "2", "GetDomainStatisticsReport", "*")?;
        self.require_dashboard(ctx)?;
        let domain = input.domain.to_ascii_lowercase();
        let (start, end) = (input.start_date, input.end_date);
        let sends = self.with_region(ctx, |r| {
            r.sends
                .iter()
                .filter(|s| {
                    names::domain_of(&s.from).is_some_and(|d| d == domain) && s.timestamp >= start && s.timestamp <= end
                })
                .cloned()
                .collect::<Vec<_>>()
        });
        let mut days: BTreeMap<chrono::NaiveDate, i64> = BTreeMap::new();
        for s in &sends {
            *days.entry(s.timestamp.date_naive()).or_default() += s.recipients.len() as i64;
        }
        let stats = |n: i64| t2::VolumeStatistics {
            inbox_raw_count: Some(n),
            spam_raw_count: Some(0),
            projected_inbox: Some(n),
            projected_spam: Some(0),
        };
        let total: i64 = days.values().sum();
        Ok(t2::GetDomainStatisticsReportResponse {
            overall_volume: t2::OverallVolume {
                volume_statistics: Some(stats(total)),
                read_rate_percent: Some(0.0),
                domain_isp_placements: Some(Vec::new()),
            },
            daily_volumes: days
                .into_iter()
                .map(|(d, n)| t2::DailyVolume {
                    start_date: d.and_hms_opt(0, 0, 0).map(|t| t.and_utc()),
                    volume_statistics: Some(stats(n)),
                    domain_isp_placements: Some(Vec::new()),
                })
                .collect(),
        })
    }

    pub(crate) fn create_deliverability_test_report_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateDeliverabilityTestReportRequest,
    ) -> Result<t2::CreateDeliverabilityTestReportResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        names::authorize_create(
            ctx,
            "CreateDeliverabilityTestReport",
            &names::arn(ctx, "deliverability-test-report/*"),
            &tags,
        )?;
        names::check_tags(&tags)?;
        self.require_dashboard(ctx)?;
        if !self.is_verified_sender(ctx, &input.from_email_address) {
            return Err(v2::errors::message_rejected(format!(
                "Email address is not verified. The following identities failed the check in region {}: {}",
                names::upper_region(ctx),
                input.from_email_address
            )));
        }
        let (subject, raw) = match (&input.content.simple, &input.content.raw, &input.content.template) {
            (Some(m), _, _) => (m.subject.data.clone(), String::new()),
            (_, Some(r), _) => (crate::mime::parse(&r.data).subject(), String::from_utf8_lossy(&r.data).into_owned()),
            (_, _, Some(t)) => (t.template_name.clone().unwrap_or_default(), String::new()),
            _ => return Err(v2::errors::bad_request("Content is required.")),
        };
        let id = uuid::Uuid::new_v4().to_string();
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            r.test_reports.insert(
                id.clone(),
                TestReport {
                    id: id.clone(),
                    name: input.report_name,
                    subject,
                    from: input.from_email_address,
                    created: now,
                    status: "COMPLETED".into(),
                    raw,
                    tags: tags.into_iter().collect(),
                },
            )
        });
        Ok(t2::CreateDeliverabilityTestReportResponse { report_id: id, deliverability_test_status: "COMPLETED".into() })
    }

    fn report_summary(r: &TestReport) -> t2::DeliverabilityTestReport {
        t2::DeliverabilityTestReport {
            report_id: Some(r.id.clone()),
            report_name: r.name.clone(),
            subject: Some(r.subject.clone()),
            from_email_address: Some(r.from.clone()),
            create_date: Some(r.created),
            deliverability_test_status: Some(r.status.clone()),
        }
    }

    pub(crate) fn get_deliverability_test_report_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetDeliverabilityTestReportRequest,
    ) -> Result<t2::GetDeliverabilityTestReportResponse, ServiceError> {
        authorize(
            ctx,
            "2",
            "GetDeliverabilityTestReport",
            &names::arn(ctx, &format!("deliverability-test-report/{}", input.report_id)),
        )?;
        let r = self
            .with_region(ctx, |r| r.test_reports.get(&input.report_id).cloned())
            .ok_or_else(|| v2::errors::not_found(format!("Report {} does not exist.", input.report_id)))?;
        let placement = t2::PlacementStatistics {
            inbox_percentage: Some(100.0),
            spam_percentage: Some(0.0),
            missing_percentage: Some(0.0),
            spf_percentage: Some(100.0),
            dkim_percentage: Some(100.0),
        };
        Ok(t2::GetDeliverabilityTestReportResponse {
            deliverability_test_report: Self::report_summary(&r),
            overall_placement: placement.clone(),
            isp_placements: ["Gmail", "Hotmail", "Yahoo", "AOL"]
                .iter()
                .map(|n| t2::IspPlacement {
                    isp_name: Some(n.to_string()),
                    placement_statistics: Some(placement.clone()),
                })
                .collect(),
            message: (!r.raw.is_empty()).then(|| r.raw.clone()),
            tags: Some(names::tag_list(&r.tags)),
        })
    }

    pub(crate) fn list_deliverability_test_reports_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListDeliverabilityTestReportsRequest,
    ) -> Result<t2::ListDeliverabilityTestReportsResponse, ServiceError> {
        authorize(ctx, "2", "ListDeliverabilityTestReports", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<_> = self.with_region(ctx, |r| r.test_reports.values().map(Self::report_summary).collect());
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListDeliverabilityTestReportsResponse { deliverability_test_reports: page, next_token: next })
    }

    // ------------------------------------------------------------ import and export jobs

    pub(crate) fn create_import_job_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateImportJobRequest,
    ) -> Result<t2::CreateImportJobResponse, ServiceError> {
        authorize(ctx, "2", "CreateImportJob", "*")?;
        let dest = input.import_destination.clone();
        if dest.suppression_list_destination.is_none() == dest.contact_list_destination.is_none() {
            return Err(v2::errors::bad_request("Exactly one import destination is required."));
        }
        if let Some(c) = &dest.contact_list_destination {
            if !self.with_region(ctx, |r| r.contact_lists.contains_key(&c.contact_list_name)) {
                return Err(v2::errors::bad_request(format!("List with name {} does not exist.", c.contact_list_name)));
            }
        }
        let (bucket, key) = split_s3_url(&input.import_data_source.s3_url)
            .ok_or_else(|| v2::errors::bad_request(format!("Invalid S3 URL {}.", input.import_data_source.s3_url)))?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = ctx.received_at;
        let mut job = ImportJob {
            id: id.clone(),
            destination: dest.clone(),
            source: input.import_data_source.clone(),
            status: "COMPLETED".into(),
            created: now,
            completed: Some(now),
            ..Default::default()
        };
        match self.links().get_s3(ctx, &bucket, &key) {
            Err(e) => {
                job.status = "FAILED".into();
                job.failure = Some(format!("Could not read {}: {e}", input.import_data_source.s3_url));
            }
            Ok(data) => {
                let records = parse_import(&data, &input.import_data_source.data_format);
                self.with_region(ctx, |r| {
                    for rec in records {
                        job.processed += 1;
                        if apply_import(r, &dest, &rec, now).is_err() {
                            job.failed += 1;
                        }
                    }
                });
            }
        }
        self.with_region(ctx, |r| r.import_jobs.insert(id.clone(), job));
        Ok(t2::CreateImportJobResponse { job_id: Some(id) })
    }

    pub(crate) fn get_import_job_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetImportJobRequest,
    ) -> Result<t2::GetImportJobResponse, ServiceError> {
        authorize(ctx, "2", "GetImportJob", "*")?;
        let j = self
            .with_region(ctx, |r| r.import_jobs.get(&input.job_id).cloned())
            .ok_or_else(|| v2::errors::not_found(format!("Import job {} does not exist.", input.job_id)))?;
        Ok(t2::GetImportJobResponse {
            job_id: Some(j.id),
            import_destination: Some(j.destination),
            import_data_source: Some(j.source),
            failure_info: j.failure.map(|m| t2::FailureInfo { failed_records_s3_url: None, error_message: Some(m) }),
            job_status: Some(j.status),
            created_timestamp: Some(j.created),
            completed_timestamp: j.completed,
            processed_records_count: Some(j.processed),
            failed_records_count: Some(j.failed),
        })
    }

    pub(crate) fn list_import_jobs_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListImportJobsRequest,
    ) -> Result<t2::ListImportJobsResponse, ServiceError> {
        authorize(ctx, "2", "ListImportJobs", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::ImportJobSummary> = self.with_region(ctx, |r| {
            r.import_jobs
                .values()
                .filter(|j| match input.import_destination_type.as_deref() {
                    Some("SUPPRESSION_LIST") => j.destination.suppression_list_destination.is_some(),
                    Some("CONTACT_LIST") => j.destination.contact_list_destination.is_some(),
                    _ => true,
                })
                .map(|j| t2::ImportJobSummary {
                    job_id: Some(j.id.clone()),
                    import_destination: Some(j.destination.clone()),
                    job_status: Some(j.status.clone()),
                    created_timestamp: Some(j.created),
                    processed_records_count: Some(j.processed),
                    failed_records_count: Some(j.failed),
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListImportJobsResponse { import_jobs: Some(page), next_token: next })
    }

    pub(crate) async fn create_export_job_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateExportJobRequest,
    ) -> Result<t2::CreateExportJobResponse, ServiceError> {
        authorize(ctx, "2", "CreateExportJob", "*")?;
        let src = input.export_data_source.clone();
        let source_type = match (&src.metrics_data_source, &src.message_insights_data_source) {
            (Some(_), None) => "METRICS_DATA",
            (None, Some(_)) => "MESSAGE_INSIGHTS",
            _ => return Err(v2::errors::bad_request("Exactly one export data source is required.")),
        };
        let format = input.export_destination.data_format.clone();
        if !matches!(format.as_str(), "CSV" | "JSON") {
            return Err(v2::errors::bad_request(format!("Invalid data format {format}.")));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let now = ctx.received_at;
        let rows: Vec<BTreeMap<String, String>> = self.with_region(ctx, |r| {
            let (start, end) = match (&src.metrics_data_source, &src.message_insights_data_source) {
                (Some(m), _) => (m.start_date, m.end_date),
                (_, Some(m)) => (m.start_date, m.end_date),
                _ => (now, now),
            };
            r.sends
                .iter()
                .filter(|s| s.timestamp >= start && s.timestamp <= end)
                .flat_map(|s| {
                    s.recipients.iter().map(move |rcpt| {
                        let last = s
                            .events
                            .iter()
                            .rev()
                            .find(|(r, _, _, _)| r == rcpt)
                            .map(|e| e.1.clone())
                            .unwrap_or_else(|| "SEND".into());
                        BTreeMap::from([
                            ("MESSAGE_ID".to_string(), s.message_id.clone()),
                            ("EMAIL_ADDRESS".to_string(), s.from.clone()),
                            ("DESTINATION".to_string(), rcpt.clone()),
                            ("SUBJECT".to_string(), s.subject.clone()),
                            ("SEND_TIMESTAMP".to_string(), names::iso(s.timestamp)),
                            ("LAST_DELIVERY_EVENT".to_string(), last),
                            ("CONFIGURATION_SET".to_string(), s.configuration_set.clone().unwrap_or_default()),
                        ])
                    })
                })
                .collect()
        });
        let body = if format == "JSON" {
            rows.iter().map(|r| serde_json::to_string(r).unwrap_or_default()).collect::<Vec<_>>().join("\n")
        } else {
            let header: Vec<String> = rows.first().map(|r| r.keys().cloned().collect()).unwrap_or_default();
            let mut out = header.join(",");
            for r in &rows {
                out.push('\n');
                out.push_str(
                    &r.values().map(|v| format!("\"{}\"", v.replace('"', "\"\""))).collect::<Vec<_>>().join(","),
                );
            }
            out
        };
        let mut job = ExportJob {
            id: id.clone(),
            source_type: source_type.into(),
            source: src,
            destination: input.export_destination.clone(),
            status: "COMPLETED".into(),
            created: now,
            completed: Some(now),
            processed: rows.len() as i32,
            exported: rows.len() as i32,
            failure: None,
        };
        if let Some(url) = &input.export_destination.s3_url {
            let (bucket, prefix) =
                split_s3_url(url).ok_or_else(|| v2::errors::bad_request(format!("Invalid S3 URL {url}.")))?;
            let key = format!(
                "{}{id}.{}",
                if prefix.is_empty() || prefix.ends_with('/') { prefix.clone() } else { format!("{prefix}/") },
                format.to_ascii_lowercase()
            );
            let source_arn = names::arn(ctx, &format!("export-job/{id}"));
            let put = S3Put {
                bucket: &bucket,
                key: &key,
                body: body.into_bytes(),
                source_account: &ctx.caller.account_id,
                source_arn: &source_arn,
                kms_key_arn: None,
                role_arn: None,
            };
            if let Err(e) = self.links().put_s3(ctx, put).await {
                job.status = "FAILED".into();
                job.exported = 0;
                job.failure = Some(format!("Could not write to {url}: {e}"));
            }
        }
        self.with_region(ctx, |r| r.export_jobs.insert(id.clone(), job));
        Ok(t2::CreateExportJobResponse { job_id: Some(id) })
    }

    pub(crate) fn get_export_job_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetExportJobRequest,
    ) -> Result<t2::GetExportJobResponse, ServiceError> {
        authorize(ctx, "2", "GetExportJob", "*")?;
        let j = self
            .with_region(ctx, |r| r.export_jobs.get(&input.job_id).cloned())
            .ok_or_else(|| v2::errors::not_found(format!("Export job {} does not exist.", input.job_id)))?;
        Ok(t2::GetExportJobResponse {
            job_id: Some(j.id),
            export_source_type: Some(j.source_type),
            job_status: Some(j.status),
            export_destination: Some(j.destination),
            export_data_source: Some(j.source),
            created_timestamp: Some(j.created),
            completed_timestamp: j.completed,
            failure_info: j.failure.map(|m| t2::FailureInfo { failed_records_s3_url: None, error_message: Some(m) }),
            statistics: Some(t2::ExportStatistics {
                processed_records_count: Some(j.processed),
                exported_records_count: Some(j.exported),
            }),
        })
    }

    pub(crate) fn cancel_export_job_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CancelExportJobRequest,
    ) -> Result<t2::CancelExportJobResponse, ServiceError> {
        authorize(ctx, "2", "CancelExportJob", "*")?;
        self.with_region(ctx, |r| match r.export_jobs.get_mut(&input.job_id) {
            None => Err(v2::errors::not_found(format!("Export job {} does not exist.", input.job_id))),
            Some(j) if j.status == "COMPLETED" || j.status == "FAILED" => {
                Err(v2::errors::conflict(format!("Export job {} has already finished.", input.job_id)))
            }
            Some(j) => {
                j.status = "CANCELLED".into();
                Ok(Default::default())
            }
        })
    }

    pub(crate) fn list_export_jobs_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListExportJobsRequest,
    ) -> Result<t2::ListExportJobsResponse, ServiceError> {
        authorize(ctx, "2", "ListExportJobs", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::ExportJobSummary> = self.with_region(ctx, |r| {
            r.export_jobs
                .values()
                .filter(|j| input.export_source_type.as_ref().is_none_or(|t| &j.source_type == t))
                .filter(|j| input.job_status.as_ref().is_none_or(|s| &j.status == s))
                .map(|j| t2::ExportJobSummary {
                    job_id: Some(j.id.clone()),
                    export_source_type: Some(j.source_type.clone()),
                    job_status: Some(j.status.clone()),
                    created_timestamp: Some(j.created),
                    completed_timestamp: j.completed,
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListExportJobsResponse { export_jobs: Some(page), next_token: next })
    }

    // ------------------------------------------------------------ multi-Region endpoints

    pub(crate) fn create_multi_region_endpoint_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateMultiRegionEndpointRequest,
    ) -> Result<t2::CreateMultiRegionEndpointResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        names::authorize_create(
            ctx,
            "CreateMultiRegionEndpoint",
            &names::arn(ctx, &format!("multi-region-endpoint/{}", input.endpoint_name)),
            &tags,
        )?;
        names::check_tags(&tags)?;
        let regions: Vec<String> = input.details.routes_details.iter().map(|r| r.region.clone()).collect();
        if regions.len() != 1 || regions[0] == ctx.region {
            return Err(v2::errors::bad_request("Exactly one secondary Region, other than the primary, is required."));
        }
        let id = format!("{}.{}", names::token(8), names::token(8));
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            if r.multi_region_endpoints.contains_key(&input.endpoint_name) {
                return Err(v2::errors::already_exists(format!("Endpoint {} already exists.", input.endpoint_name)));
            }
            r.multi_region_endpoints.insert(
                input.endpoint_name.clone(),
                MultiRegionEndpoint {
                    name: input.endpoint_name,
                    id: id.clone(),
                    regions: std::iter::once(ctx.region.clone()).chain(regions).collect(),
                    created: now,
                    updated: now,
                    tags: tags.into_iter().collect(),
                },
            );
            Ok(())
        })?;
        Ok(t2::CreateMultiRegionEndpointResponse { status: Some("READY".into()), endpoint_id: Some(id) })
    }

    pub(crate) fn get_multi_region_endpoint_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetMultiRegionEndpointRequest,
    ) -> Result<t2::GetMultiRegionEndpointResponse, ServiceError> {
        authorize(
            ctx,
            "2",
            "GetMultiRegionEndpoint",
            &names::arn(ctx, &format!("multi-region-endpoint/{}", input.endpoint_name)),
        )?;
        let m = self
            .with_region(ctx, |r| r.multi_region_endpoints.get(&input.endpoint_name).cloned())
            .ok_or_else(|| v2::errors::not_found(format!("Endpoint {} does not exist.", input.endpoint_name)))?;
        Ok(t2::GetMultiRegionEndpointResponse {
            endpoint_name: Some(m.name),
            endpoint_id: Some(m.id),
            routes: Some(m.regions.into_iter().map(|r| t2::Route { region: r }).collect()),
            status: Some("READY".into()),
            created_timestamp: Some(m.created),
            last_updated_timestamp: Some(m.updated),
        })
    }

    pub(crate) fn delete_multi_region_endpoint_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteMultiRegionEndpointRequest,
    ) -> Result<t2::DeleteMultiRegionEndpointResponse, ServiceError> {
        authorize(
            ctx,
            "2",
            "DeleteMultiRegionEndpoint",
            &names::arn(ctx, &format!("multi-region-endpoint/{}", input.endpoint_name)),
        )?;
        self.with_region(ctx, |r| r.multi_region_endpoints.remove(&input.endpoint_name))
            .ok_or_else(|| v2::errors::not_found(format!("Endpoint {} does not exist.", input.endpoint_name)))?;
        Ok(t2::DeleteMultiRegionEndpointResponse { status: Some("DELETING".into()) })
    }

    pub(crate) fn list_multi_region_endpoints_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListMultiRegionEndpointsRequest,
    ) -> Result<t2::ListMultiRegionEndpointsResponse, ServiceError> {
        authorize(ctx, "2", "ListMultiRegionEndpoints", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::MultiRegionEndpoint> = self.with_region(ctx, |r| {
            r.multi_region_endpoints
                .values()
                .map(|m| t2::MultiRegionEndpoint {
                    endpoint_name: Some(m.name.clone()),
                    status: Some("READY".into()),
                    endpoint_id: Some(m.id.clone()),
                    regions: Some(m.regions.clone()),
                    created_timestamp: Some(m.created),
                    last_updated_timestamp: Some(m.updated),
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListMultiRegionEndpointsResponse { multi_region_endpoints: Some(page), next_token: next })
    }

    // ------------------------------------------------------------ tenants

    fn tenant_info(t: &Tenant) -> t2::Tenant {
        t2::Tenant {
            tenant_name: Some(t.name.clone()),
            tenant_id: Some(t.id.clone()),
            tenant_arn: Some(t.arn.clone()),
            created_timestamp: Some(t.created),
            tags: Some(names::tag_list(&t.tags)),
            sending_status: Some(t.sending_status.clone()),
            suppression_attributes: t.suppression.clone(),
        }
    }

    fn with_tenant<T>(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: &str,
        f: impl FnOnce(&mut Tenant) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let t = self.with_region(ctx, |r| r.tenants.get(name).cloned());
        let arn = t.as_ref().map(|t| t.arn.clone()).unwrap_or_else(|| names::arn(ctx, &format!("tenant/{name}")));
        names::authorize_tagged(ctx, "2", action, &arn, &t.as_ref().map(|t| t.tags.clone()).unwrap_or_default())?;
        self.with_region(ctx, |r| match r.tenants.get_mut(name) {
            Some(t) => f(t),
            None => Err(v2::errors::not_found(format!("Tenant {name} does not exist."))),
        })
    }

    pub(crate) fn create_tenant_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateTenantRequest,
    ) -> Result<t2::CreateTenantResponse, ServiceError> {
        let tags = names::tags_pairs(input.tags.as_deref());
        let id = format!("tn-{}", names::token(20));
        let arn = names::arn(ctx, &format!("tenant/{}/{id}", input.tenant_name));
        names::authorize_create(ctx, "CreateTenant", &arn, &tags)?;
        names::check_tags(&tags)?;
        let now = ctx.received_at;
        let t = self.with_region(ctx, |r| {
            if r.tenants.contains_key(&input.tenant_name) {
                return Err(v2::errors::already_exists(format!("Tenant {} already exists.", input.tenant_name)));
            }
            let t = Tenant {
                name: input.tenant_name.clone(),
                id,
                arn,
                created: now,
                tags: tags.into_iter().collect(),
                sending_status: "ENABLED".into(),
                suppression: input.suppression_attributes,
                resources: BTreeMap::new(),
            };
            r.tenants.insert(t.name.clone(), t.clone());
            Ok(t)
        })?;
        let i = Self::tenant_info(&t);
        Ok(t2::CreateTenantResponse {
            tenant_name: i.tenant_name,
            tenant_id: i.tenant_id,
            tenant_arn: i.tenant_arn,
            created_timestamp: i.created_timestamp,
            tags: i.tags,
            sending_status: i.sending_status,
            suppression_attributes: i.suppression_attributes,
        })
    }

    pub(crate) fn get_tenant_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetTenantRequest,
    ) -> Result<t2::GetTenantResponse, ServiceError> {
        let t = self.with_tenant(ctx, "GetTenant", &input.tenant_name, |t| Ok(t.clone()))?;
        Ok(t2::GetTenantResponse { tenant: Some(Self::tenant_info(&t)) })
    }

    pub(crate) fn delete_tenant_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteTenantRequest,
    ) -> Result<t2::DeleteTenantResponse, ServiceError> {
        self.with_tenant(ctx, "DeleteTenant", &input.tenant_name, |_| Ok(()))?;
        self.with_region(ctx, |r| r.tenants.remove(&input.tenant_name));
        Ok(Default::default())
    }

    pub(crate) fn list_tenants_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListTenantsRequest,
    ) -> Result<t2::ListTenantsResponse, ServiceError> {
        authorize(ctx, "2", "ListTenants", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::TenantInfo> = self.with_region(ctx, |r| {
            r.tenants
                .values()
                .map(|t| t2::TenantInfo {
                    tenant_name: Some(t.name.clone()),
                    tenant_id: Some(t.id.clone()),
                    tenant_arn: Some(t.arn.clone()),
                    created_timestamp: Some(t.created),
                    sending_status: Some(t.sending_status.clone()),
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListTenantsResponse { tenants: Some(page), next_token: next })
    }

    pub(crate) fn put_tenant_suppression_attributes_v2(
        &self,
        ctx: &RequestContext,
        input: t2::PutTenantSuppressionAttributesRequest,
    ) -> Result<t2::PutTenantSuppressionAttributesResponse, ServiceError> {
        self.with_tenant(ctx, "PutTenantSuppressionAttributes", &input.tenant_name, |t| {
            t.suppression = Some(t2::TenantSuppressionAttributes {
                suppressed_reasons: input.suppressed_reasons,
                suppression_scope: input.suppression_scope,
            });
            Ok(Default::default())
        })
    }

    /// The type of a resource a tenant can be associated with.
    fn resource_type(arn: &str) -> Option<&'static str> {
        let resource = arn.splitn(6, ':').nth(5)?;
        Some(match resource.split('/').next()? {
            "identity" => "EMAIL_IDENTITY",
            "configuration-set" => "CONFIGURATION_SET",
            "template" => "EMAIL_TEMPLATE",
            _ => return None,
        })
    }

    fn resource_exists(r: &Region, arn: &str) -> bool {
        let Some(resource) = arn.splitn(6, ':').nth(5) else { return false };
        let Some((kind, name)) = resource.split_once('/') else { return false };
        match kind {
            "identity" => r.identities.contains_key(&names::canonical_identity(name)),
            "configuration-set" => r.configuration_sets.contains_key(name),
            "template" => r.templates.contains_key(name),
            _ => false,
        }
    }

    pub(crate) fn create_tenant_resource_association_v2(
        &self,
        ctx: &RequestContext,
        input: t2::CreateTenantResourceAssociationRequest,
    ) -> Result<t2::CreateTenantResourceAssociationResponse, ServiceError> {
        if Self::resource_type(&input.resource_arn).is_none() {
            return Err(v2::errors::bad_request(format!("Invalid resource ARN {}.", input.resource_arn)));
        }
        if !self.with_region(ctx, |r| Self::resource_exists(r, &input.resource_arn)) {
            return Err(v2::errors::not_found(format!("Resource {} does not exist.", input.resource_arn)));
        }
        let now = ctx.received_at;
        self.with_tenant(ctx, "CreateTenantResourceAssociation", &input.tenant_name, |t| {
            if t.resources.contains_key(&input.resource_arn) {
                return Err(v2::errors::already_exists("The resource is already associated with the tenant."));
            }
            t.resources.insert(input.resource_arn, now);
            Ok(Default::default())
        })
    }

    pub(crate) fn delete_tenant_resource_association_v2(
        &self,
        ctx: &RequestContext,
        input: t2::DeleteTenantResourceAssociationRequest,
    ) -> Result<t2::DeleteTenantResourceAssociationResponse, ServiceError> {
        self.with_tenant(ctx, "DeleteTenantResourceAssociation", &input.tenant_name, |t| {
            t.resources
                .remove(&input.resource_arn)
                .ok_or_else(|| v2::errors::not_found("The resource is not associated with the tenant."))?;
            Ok(Default::default())
        })
    }

    pub(crate) fn list_tenant_resources_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListTenantResourcesRequest,
    ) -> Result<t2::ListTenantResourcesResponse, ServiceError> {
        names::check_token(input.next_token.as_deref())?;
        let want = input.filter.as_ref().and_then(|f| f.get("RESOURCE_TYPE").cloned());
        let all = self.with_tenant(ctx, "ListTenantResources", &input.tenant_name, |t| {
            Ok(t.resources
                .keys()
                .filter_map(|arn| {
                    let ty = Self::resource_type(arn)?;
                    want.as_ref()
                        .is_none_or(|w| w == ty)
                        .then(|| t2::TenantResource { resource_type: Some(ty.into()), resource_arn: Some(arn.clone()) })
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListTenantResourcesResponse { tenant_resources: Some(page), next_token: next })
    }

    pub(crate) fn list_resource_tenants_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListResourceTenantsRequest,
    ) -> Result<t2::ListResourceTenantsResponse, ServiceError> {
        authorize(ctx, "2", "ListResourceTenants", &input.resource_arn)?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::ResourceTenantMetadata> = self.with_region(ctx, |r| {
            r.tenants
                .values()
                .filter_map(|t| {
                    t.resources.get(&input.resource_arn).map(|at| t2::ResourceTenantMetadata {
                        tenant_name: Some(t.name.clone()),
                        tenant_id: Some(t.id.clone()),
                        resource_arn: Some(input.resource_arn.clone()),
                        associated_timestamp: Some(*at),
                    })
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListResourceTenantsResponse { resource_tenants: Some(page), next_token: next })
    }

    // ------------------------------------------------------------ reputation entities

    fn reputation_entity(r: &Region, ty: &str, reference: &str) -> t2::ReputationEntity {
        let key = format!("{ty}/{reference}");
        let custom = r.reputation_entities.get(&key).cloned().unwrap_or_default();
        let customer = custom.customer_status.clone().unwrap_or_else(|| "ENABLED".into());
        t2::ReputationEntity {
            reputation_entity_reference: Some(reference.to_string()),
            reputation_entity_type: Some(ty.to_string()),
            reputation_management_policy: custom.policy.clone(),
            customer_managed_status: Some(t2::StatusRecord {
                status: Some(customer.clone()),
                cause: None,
                last_updated_timestamp: custom.customer_updated,
            }),
            aws_ses_managed_status: Some(t2::StatusRecord {
                status: Some("ENABLED".into()),
                cause: None,
                last_updated_timestamp: None,
            }),
            sending_status_aggregate: Some(customer),
            reputation_impact: Some("LOW".into()),
        }
    }

    pub(crate) fn get_reputation_entity_v2(
        &self,
        ctx: &RequestContext,
        input: t2::GetReputationEntityRequest,
    ) -> Result<t2::GetReputationEntityResponse, ServiceError> {
        authorize(ctx, "2", "GetReputationEntity", &input.reputation_entity_reference)?;
        let e = self.with_region(ctx, |r| {
            if input.reputation_entity_type == "RESOURCE"
                && !Self::resource_exists(r, &input.reputation_entity_reference)
            {
                return None;
            }
            Some(Self::reputation_entity(r, &input.reputation_entity_type, &input.reputation_entity_reference))
        });
        let e = e.ok_or_else(|| {
            v2::errors::not_found(format!("Reputation entity {} does not exist.", input.reputation_entity_reference))
        })?;
        Ok(t2::GetReputationEntityResponse { reputation_entity: Some(e) })
    }

    pub(crate) fn list_reputation_entities_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListReputationEntitiesRequest,
    ) -> Result<t2::ListReputationEntitiesResponse, ServiceError> {
        authorize(ctx, "2", "ListReputationEntities", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let all: Vec<t2::ReputationEntity> = self.with_region(ctx, |r| {
            let mut arns: Vec<String> = r
                .identities
                .keys()
                .map(|i| names::arn(ctx, &format!("identity/{i}")))
                .chain(r.configuration_sets.keys().map(|c| names::arn(ctx, &format!("configuration-set/{c}"))))
                .collect();
            arns.sort();
            arns.iter().map(|a| Self::reputation_entity(r, "RESOURCE", a)).collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListReputationEntitiesResponse { reputation_entities: Some(page), next_token: next })
    }

    pub(crate) fn update_reputation_entity_customer_managed_status_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateReputationEntityCustomerManagedStatusRequest,
    ) -> Result<t2::UpdateReputationEntityCustomerManagedStatusResponse, ServiceError> {
        authorize(ctx, "2", "UpdateReputationEntityCustomerManagedStatus", &input.reputation_entity_reference)?;
        if !matches!(input.sending_status.as_str(), "ENABLED" | "DISABLED" | "REINSTATED") {
            return Err(v2::errors::bad_request(format!("Invalid sending status {}.", input.sending_status)));
        }
        let now = ctx.received_at;
        self.with_region(ctx, |r| {
            let e = r
                .reputation_entities
                .entry(format!("{}/{}", input.reputation_entity_type, input.reputation_entity_reference))
                .or_default();
            e.customer_status = Some(input.sending_status);
            e.customer_updated = Some(now);
        });
        Ok(Default::default())
    }

    pub(crate) fn update_reputation_entity_policy_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UpdateReputationEntityPolicyRequest,
    ) -> Result<t2::UpdateReputationEntityPolicyResponse, ServiceError> {
        authorize(ctx, "2", "UpdateReputationEntityPolicy", &input.reputation_entity_reference)?;
        self.with_region(ctx, |r| {
            let e = r
                .reputation_entities
                .entry(format!("{}/{}", input.reputation_entity_type, input.reputation_entity_reference))
                .or_default();
            e.policy = Some(input.reputation_entity_policy);
        });
        Ok(Default::default())
    }

    pub(crate) fn list_recommendations_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListRecommendationsRequest,
    ) -> Result<t2::ListRecommendationsResponse, ServiceError> {
        authorize(ctx, "2", "ListRecommendations", "*")?;
        names::check_token(input.next_token.as_deref())?;
        let now = Utc::now();
        let all: Vec<t2::Recommendation> = self.with_region(ctx, |r| {
            if r.account.vdm.as_ref().is_none_or(|v| v.vdm_enabled != "ENABLED") {
                return Vec::new();
            }
            r.identities
                .values()
                .filter(|i| i.is_domain() && i.dkim_status != "SUCCESS")
                .map(|i| t2::Recommendation {
                    resource_arn: Some(names::arn(ctx, &format!("identity/{}", i.name))),
                    r#type: Some("DKIM".into()),
                    description: Some(format!("DKIM is not set up for {}.", i.name)),
                    status: Some("OPEN".into()),
                    created_timestamp: Some(i.created),
                    last_updated_timestamp: Some(now),
                    impact: Some("HIGH".into()),
                })
                .collect()
        });
        let (page, next) = names::paginate(&all, input.next_token.as_deref(), input.page_size, 100);
        Ok(t2::ListRecommendationsResponse { recommendations: Some(page), next_token: next })
    }

    // ------------------------------------------------------------ tags

    /// The tags of the resource `arn` names, for reading or changing.
    fn with_tags<T>(
        &self,
        ctx: &RequestContext,
        arn: &str,
        f: impl FnOnce(&mut BTreeMap<String, String>) -> T,
    ) -> Result<T, ServiceError> {
        let missing = || v2::errors::not_found(format!("Resource {arn} does not exist."));
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[2] != "ses" || parts[4] != ctx.caller.account_id || parts[3] != ctx.region {
            return Err(v2::errors::bad_request(format!("Invalid resource ARN {arn}.")));
        }
        let (kind, name) = parts[5].split_once('/').ok_or_else(missing)?;
        self.with_region(ctx, |r| {
            let tags = match kind {
                "identity" => r.identities.get_mut(&names::canonical_identity(name)).map(|i| &mut i.tags),
                "configuration-set" => r.configuration_sets.get_mut(name).map(|c| &mut c.tags),
                "template" => r.templates.get_mut(name).map(|t| &mut t.tags),
                "custom-verification-email-template" => {
                    r.custom_verification_templates.get_mut(name).map(|t| &mut t.tags)
                }
                "contact-list" => r.contact_lists.get_mut(name).map(|l| &mut l.tags),
                "dedicated-ip-pool" => r.dedicated_ip_pools.get_mut(name).map(|p| &mut p.tags),
                "deliverability-test-report" => r.test_reports.get_mut(name).map(|t| &mut t.tags),
                "multi-region-endpoint" => r.multi_region_endpoints.get_mut(name).map(|m| &mut m.tags),
                "tenant" => {
                    let tname = name.split('/').next().unwrap_or(name);
                    r.tenants.get_mut(tname).map(|t| &mut t.tags)
                }
                _ => None,
            };
            tags.map(f).ok_or_else(missing)
        })
    }

    pub(crate) fn list_tags_for_resource_v2(
        &self,
        ctx: &RequestContext,
        input: t2::ListTagsForResourceRequest,
    ) -> Result<t2::ListTagsForResourceResponse, ServiceError> {
        authorize(ctx, "2", "ListTagsForResource", &input.resource_arn)?;
        let tags = self.with_tags(ctx, &input.resource_arn, |t| names::tag_list(t))?;
        Ok(t2::ListTagsForResourceResponse { tags })
    }

    pub(crate) fn tag_resource_v2(
        &self,
        ctx: &RequestContext,
        input: t2::TagResourceRequest,
    ) -> Result<t2::TagResourceResponse, ServiceError> {
        let pairs = names::tags_pairs(Some(&input.tags));
        names::authorize_create(ctx, "TagResource", &input.resource_arn, &pairs)?;
        names::check_tags(&pairs)?;
        self.with_tags(ctx, &input.resource_arn, |t| {
            for (k, v) in &pairs {
                t.insert(k.clone(), v.clone());
            }
            if t.len() > 50 {
                return Err(v2::errors::bad_request("Too many tags. The maximum number of tags is 50."));
            }
            Ok(())
        })??;
        Ok(Default::default())
    }

    pub(crate) fn untag_resource_v2(
        &self,
        ctx: &RequestContext,
        input: t2::UntagResourceRequest,
    ) -> Result<t2::UntagResourceResponse, ServiceError> {
        let mut c = names::api_version("2");
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("ses:UntagResource", &input.resource_arn, c)?;
        self.with_tags(ctx, &input.resource_arn, |t| {
            for k in &input.tag_keys {
                t.remove(k);
            }
        })?;
        Ok(Default::default())
    }
}

/// Records of an import file: one map of field to value each.
fn parse_import(data: &[u8], format: &str) -> Vec<BTreeMap<String, String>> {
    let text = String::from_utf8_lossy(data);
    if format == "JSON" {
        return text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| {
                v.as_object().map(|o| {
                    o.iter()
                        .map(|(k, v)| {
                            (k.to_ascii_lowercase(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))
                        })
                        .collect()
                })
            })
            .collect();
    }
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let Some(header) = lines.next() else { return Vec::new() };
    let cols: Vec<String> = header.split(',').map(|c| c.trim().trim_matches('"').to_ascii_lowercase()).collect();
    lines
        .map(|l| cols.iter().cloned().zip(l.split(',').map(|v| v.trim().trim_matches('"').to_string())).collect())
        .collect()
}

fn apply_import(
    r: &mut Region,
    dest: &t2::ImportDestination,
    rec: &BTreeMap<String, String>,
    now: chrono::DateTime<Utc>,
) -> Result<(), ()> {
    let email = rec.get("emailaddress").or_else(|| rec.get("email")).ok_or(())?.clone();
    names::check_address(&email).map_err(|_| ())?;
    if let Some(s) = &dest.suppression_list_destination {
        let key = email.to_ascii_lowercase();
        if s.suppression_list_import_action == "DELETE" {
            r.suppressed.remove(&key);
        } else {
            let reason = rec.get("reason").map(|r| r.to_ascii_uppercase()).unwrap_or_else(|| "BOUNCE".into());
            if !matches!(reason.as_str(), "BOUNCE" | "COMPLAINT") {
                return Err(());
            }
            r.suppressed.insert(key, Suppressed { email, reason, last_update: now, ..Default::default() });
        }
        return Ok(());
    }
    let c = dest.contact_list_destination.as_ref().ok_or(())?;
    let list = r.contact_lists.get_mut(&c.contact_list_name).ok_or(())?;
    let key = email.to_ascii_lowercase();
    if c.contact_list_import_action == "DELETE" {
        list.contacts.remove(&key);
        return Ok(());
    }
    let contact = list.contacts.entry(key).or_insert_with(|| crate::state::Contact {
        email: email.clone(),
        created: now,
        ..Default::default()
    });
    if let Some(u) = rec.get("unsubscribeall") {
        contact.unsubscribe_all = u.eq_ignore_ascii_case("true");
    }
    if let Some(a) = rec.get("attributesdata") {
        contact.attributes = Some(a.clone());
    }
    contact.updated = now;
    Ok(())
}
