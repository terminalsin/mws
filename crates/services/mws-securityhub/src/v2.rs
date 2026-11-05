//! The Security Hub V2 API: enabling it, its features, aggregators, OCSF
//! findings (the stored findings in OCSF form), statistics and trends,
//! resources and software inventories derived from findings, export jobs
//! to S3, product listings and free trials. Remediation and recommended
//! policy analysis is not modelled: those calls answer with no results.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};
use serde_json::{json, Value};

use crate::catalog;
use crate::common::{self, account, authorize_hub, iso, not_found, paginate};
use crate::filters;
use crate::findings::{sort_criteria, visible_findings};
use crate::generated::{errors, types};
use crate::ocsf;
use crate::state::{key, AggregatorRec, ExportJobRec, HubV2, State};
use crate::SecurityHub;

/// Security Hub V2 must be enabled for the caller.
pub fn require_v2(state: &State, ctx: &RequestContext) -> Result<(), ServiceError> {
    if state.hubs_v2.contains_key(&key(account(ctx), &ctx.region)) {
        Ok(())
    } else {
        Err(errors::access_denied(format!("Account {} is not subscribed to AWS Security Hub V2", account(ctx))))
    }
}

/// Visible findings as OCSF documents.
fn ocsf_docs(state: &State, ctx: &RequestContext) -> Vec<Value> {
    visible_findings(state, account(ctx), &ctx.region)
        .into_iter()
        .map(|(_, _, f)| ocsf::to_ocsf(&f.finding, &f.v2))
        .collect()
}

fn ocsf_filtered<T: serde::Serialize>(state: &State, ctx: &RequestContext, filters: Option<&T>) -> Vec<Value> {
    let f = filters.map(filters::to_json).unwrap_or(Value::Null);
    ocsf_docs(state, ctx).into_iter().filter(|d| filters::matches_composite(d, &f, ctx.received_at)).collect()
}

/// Count documents by the values at `path`.
fn group(docs: &[Value], path: &str, order: Option<&str>, max: Option<i32>) -> Vec<types::GroupByValue> {
    let mut counts: BTreeMap<String, i32> = BTreeMap::new();
    for d in docs {
        for v in filters::group_values(d, path) {
            *counts.entry(v).or_default() += 1;
        }
    }
    let mut v: Vec<(String, i32)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if order == Some("asc") {
        v.reverse();
    }
    v.truncate(max.filter(|m| *m > 0).unwrap_or(25) as usize);
    v.into_iter()
        .map(|(field_value, count)| types::GroupByValue { field_value: Some(field_value), count: Some(count) })
        .collect()
}

/// Resource inventory derived from findings, as documents with the V2
/// resource field names.
/// Per (finding type, product): product name, total, counts by severity id.
type Summaries = BTreeMap<String, (String, i32, [i32; 8])>;

fn resource_docs(state: &State, ctx: &RequestContext) -> Vec<Value> {
    let mut by: BTreeMap<(String, String, String), (Value, Summaries)> = BTreeMap::new();
    for (_, _, f) in visible_findings(state, account(ctx), &ctx.region) {
        let fd = &f.finding;
        let acct = fd.get("AwsAccountId").and_then(Value::as_str).unwrap_or_default().to_string();
        let region = fd.get("Region").and_then(Value::as_str).unwrap_or_default().to_string();
        let product = fd.get("ProductName").and_then(Value::as_str).unwrap_or_default().to_string();
        let sev = ocsf::to_ocsf(fd, &f.v2).get("severity_id").and_then(Value::as_i64).unwrap_or(0);
        let finding_type =
            fd.get("Types").and_then(|t| t.get(0)).and_then(Value::as_str).unwrap_or("Unknown").to_string();
        for r in fd.get("Resources").and_then(Value::as_array).into_iter().flatten() {
            let id = r.get("Id").and_then(Value::as_str).unwrap_or_default().to_string();
            let entry = by.entry((acct.clone(), region.clone(), id.clone())).or_insert_with(|| {
                let tags: Vec<Value> = r
                    .get("Tags")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                    .map(|(k, v)| json!({"Key": k, "Value": v}))
                    .collect();
                (
                    json!({
                        "ResourceId": id,
                        "ResourceGuid": format!("{acct}/{region}/{id}"),
                        "AccountId": acct,
                        "Region": region,
                        "ResourceType": r.get("Type"),
                        "ResourceProvider": r.get("Provider").cloned().unwrap_or(json!("AWS")),
                        "ResourceCloudPartition": r.get("Partition"),
                        "ResourceRegion": r.get("Region"),
                        "ResourceName": id.rsplit(['/', ':']).next(),
                        "ResourceOwnerAccountId": acct,
                        "ResourceTags": tags,
                        "ResourceDetailCaptureTime": fd.get("UpdatedAt"),
                        "ResourceConfig": r.get("Details").cloned().unwrap_or(json!({})).to_string(),
                    }),
                    BTreeMap::new(),
                )
            });
            let s = entry.1.entry(format!("{finding_type}\n{product}")).or_insert_with(|| (product.clone(), 0, [0; 8]));
            s.1 += 1;
            let idx = match sev {
                1 => 1,
                2 => 2,
                3 => 3,
                4 => 4,
                5 => 5,
                6 => 6,
                0 => 0,
                _ => 7,
            };
            s.2[idx] += 1;
        }
    }
    by.into_values()
        .map(|(mut doc, summaries)| {
            let list: Vec<Value> = summaries
                .into_iter()
                .map(|(k, (product, total, s))| {
                    json!({
                        "FindingType": k.split('\n').next(),
                        "ProductName": product,
                        "TotalFindings": total,
                        "Severities": {"Unknown": s[0], "Informational": s[1], "Low": s[2], "Medium": s[3], "High": s[4], "Critical": s[5], "Fatal": s[6], "Other": s[7]},
                    })
                })
                .collect();
            doc["FindingsSummary"] = Value::Array(list);
            doc
        })
        .collect()
}

fn resource_wire(d: &Value) -> types::ResourceResult {
    let s = |k: &str| d.get(k).and_then(Value::as_str).map(str::to_string);
    types::ResourceResult {
        resource_guid: s("ResourceGuid"),
        resource_id: s("ResourceId").unwrap_or_default(),
        account_id: s("AccountId").unwrap_or_default(),
        region: s("Region").unwrap_or_default(),
        resource_provider: s("ResourceProvider"),
        resource_owner_account_id: s("ResourceOwnerAccountId"),
        resource_cloud_partition: s("ResourceCloudPartition"),
        resource_region: s("ResourceRegion"),
        resource_type: s("ResourceType").unwrap_or_default(),
        resource_name: s("ResourceName"),
        resource_detail_capture_time_dt: s("ResourceDetailCaptureTime").unwrap_or_default(),
        resource_config: s("ResourceConfig").unwrap_or_else(|| "{}".into()),
        resource_tags: Some(
            d.get("ResourceTags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|t| types::ResourceTag {
                    key: t.get("Key").and_then(Value::as_str).unwrap_or_default().into(),
                    value: t.get("Value").and_then(Value::as_str).unwrap_or_default().into(),
                })
                .collect(),
        ),
        findings_summary: Some(
            d.get("FindingsSummary")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|f| {
                    let sev =
                        |k: &str| f.get("Severities").and_then(|s| s.get(k)).and_then(Value::as_i64).map(|v| v as i32);
                    types::ResourceFindingsSummary {
                        finding_type: f.get("FindingType").and_then(Value::as_str).unwrap_or_default().into(),
                        product_name: f.get("ProductName").and_then(Value::as_str).unwrap_or_default().into(),
                        total_findings: f.get("TotalFindings").and_then(Value::as_i64).unwrap_or(0) as i32,
                        severities: Some(types::ResourceSeverityBreakdown {
                            other: sev("Other"),
                            fatal: sev("Fatal"),
                            critical: sev("Critical"),
                            high: sev("High"),
                            medium: sev("Medium"),
                            low: sev("Low"),
                            informational: sev("Informational"),
                            unknown: sev("Unknown"),
                        }),
                    }
                })
                .collect(),
        ),
        ..Default::default()
    }
}

/// Software packages from vulnerability findings: one document per
/// (package, resource).
fn software_docs(state: &State, ctx: &RequestContext) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (_, _, f) in visible_findings(state, account(ctx), &ctx.region) {
        let fd = &f.finding;
        for v in fd.get("Vulnerabilities").and_then(Value::as_array).into_iter().flatten() {
            for p in v.get("VulnerablePackages").and_then(Value::as_array).into_iter().flatten() {
                for r in fd.get("Resources").and_then(Value::as_array).into_iter().flatten() {
                    let doc = json!({
                        "AccountId": fd.get("AwsAccountId"),
                        "Region": fd.get("Region"),
                        "PackageName": p.get("Name"),
                        "PackageVersion": p.get("Version"),
                        "PackageType": p.get("PackageManager").cloned().unwrap_or(json!("OS")),
                        "ResourceId": r.get("Id"),
                        "ResourceType": r.get("Type"),
                        "ResourceRegion": r.get("Region"),
                        "ResourceProvider": r.get("Provider").cloned().unwrap_or(json!("AWS")),
                        "ResourceCloudPartition": r.get("Partition"),
                        "ResourceOwnerAccountId": fd.get("AwsAccountId"),
                    });
                    if seen.insert(doc.to_string()) {
                        out.push(doc);
                    }
                }
            }
        }
    }
    out
}

impl SecurityHub {
    pub(crate) fn enable_security_hub_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::EnableSecurityHubV2Request,
    ) -> Result<types::EnableSecurityHubV2Response, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        let arn = common::arn(ctx, "hubv2/default");
        common::authorize_with(ctx, "EnableSecurityHubV2", &arn, common::tag_conditions(&tags))?;
        common::check_tags(&Default::default(), &tags)?;
        let mut state = self.write();
        let k = key(account(ctx), &ctx.region);
        if state.hubs_v2.contains_key(&k) {
            return Err(errors::resource_conflict("Account is already subscribed to Security Hub V2"));
        }
        state.hubs_v2.insert(
            k,
            HubV2 {
                arn: arn.clone(),
                subscribed_at: ctx.received_at,
                tags,
                features: Default::default(),
                aggregators: Default::default(),
                export_jobs: Default::default(),
                client_tokens: Default::default(),
            },
        );
        Ok(types::EnableSecurityHubV2Response { hub_v2_arn: Some(arn) })
    }

    pub(crate) fn disable_security_hub_v2_op(
        &self,
        ctx: &RequestContext,
        _input: types::DisableSecurityHubV2Request,
    ) -> Result<types::DisableSecurityHubV2Response, ServiceError> {
        common::authorize(ctx, "DisableSecurityHubV2", &common::arn(ctx, "hubv2/default"))?;
        let mut state = self.write();
        require_v2(&state, ctx)?;
        state.hubs_v2.remove(&key(account(ctx), &ctx.region));
        Ok(types::DisableSecurityHubV2Response {})
    }

    pub(crate) fn describe_security_hub_v2_op(
        &self,
        ctx: &RequestContext,
        _input: types::DescribeSecurityHubV2Request,
    ) -> Result<types::DescribeSecurityHubV2Response, ServiceError> {
        common::authorize(ctx, "DescribeSecurityHubV2", &common::arn(ctx, "hubv2/default"))?;
        let state = self.read();
        let h = state
            .hubs_v2
            .get(&key(account(ctx), &ctx.region))
            .ok_or_else(|| not_found(format!("Account {} is not subscribed to AWS Security Hub V2", account(ctx))))?;
        Ok(types::DescribeSecurityHubV2Response {
            hub_v2_arn: Some(h.arn.clone()),
            subscribed_at: Some(iso(h.subscribed_at)),
            features: Some(
                h.features
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            types::FeatureDetail { feature_status: Some(v.clone()), updated_at: Some(h.subscribed_at) },
                        )
                    })
                    .collect(),
            ),
        })
    }

    fn set_feature(&self, ctx: &RequestContext, name: &str, status: &str) -> Result<(), ServiceError> {
        if !types::FEATURE_NAME.contains(&name) {
            return Err(errors::validation(format!("Invalid FeatureName {name}")));
        }
        let mut state = self.write();
        require_v2(&state, ctx)?;
        let h = state.hubs_v2.get_mut(&key(account(ctx), &ctx.region)).expect("checked");
        h.features.insert(name.to_string(), status.to_string());
        Ok(())
    }

    pub(crate) fn enable_security_hub_feature_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::EnableSecurityHubFeatureV2Request,
    ) -> Result<types::EnableSecurityHubFeatureV2Response, ServiceError> {
        common::authorize(ctx, "EnableSecurityHubFeatureV2", &common::arn(ctx, "hubv2/default"))?;
        self.set_feature(ctx, &input.feature_name, "ENABLED")?;
        Ok(types::EnableSecurityHubFeatureV2Response {})
    }

    pub(crate) fn disable_security_hub_feature_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::DisableSecurityHubFeatureV2Request,
    ) -> Result<types::DisableSecurityHubFeatureV2Response, ServiceError> {
        common::authorize(ctx, "DisableSecurityHubFeatureV2", &common::arn(ctx, "hubv2/default"))?;
        self.set_feature(ctx, &input.feature_name, "DISABLED")?;
        Ok(types::DisableSecurityHubFeatureV2Response {})
    }

    // ---- aggregators -------------------------------------------------------------

    fn find_aggregator_v2(
        state: &State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<(String, AggregatorRec), ServiceError> {
        let acct = account(ctx);
        state
            .hubs_v2
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{acct}/")))
            .find_map(|(k, h)| h.aggregators.get(arn).map(|a| (k.clone(), a.clone())))
            .ok_or_else(|| not_found(format!("Aggregator {arn} not found")))
    }

    pub(crate) fn create_aggregator_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateAggregatorV2Request,
    ) -> Result<types::CreateAggregatorV2Response, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        common::authorize_with(
            ctx,
            "CreateAggregatorV2",
            &common::arn(ctx, "hubv2/default"),
            common::tag_conditions(&tags),
        )?;
        let regions =
            crate::hub::check_linking(&input.region_linking_mode, input.linked_regions.as_deref(), &ctx.region)
                .map_err(|e| errors::validation(e.message))?;
        let mut state = self.write();
        require_v2(&state, ctx)?;
        let acct = account(ctx).to_string();
        if state.hubs_v2.iter().any(|(k, h)| k.starts_with(&format!("{acct}/")) && !h.aggregators.is_empty()) {
            return Err(errors::conflict("An aggregator already exists for this account."));
        }
        let arn = common::arn(ctx, &format!("aggregatorv2/{}", uuid::Uuid::new_v4()));
        let h = state.hubs_v2.get_mut(&key(&acct, &ctx.region)).expect("checked");
        h.aggregators.insert(
            arn.clone(),
            AggregatorRec {
                arn: arn.clone(),
                region_linking_mode: input.region_linking_mode.clone(),
                regions: regions.clone(),
            },
        );
        if !tags.is_empty() {
            if let Some(h1) = state.hub_mut(&acct, &ctx.region) {
                h1.resource_tags.insert(arn.clone(), tags);
            }
        }
        Ok(types::CreateAggregatorV2Response {
            aggregator_v2_arn: Some(arn),
            aggregation_region: Some(ctx.region.clone()),
            region_linking_mode: Some(input.region_linking_mode),
            linked_regions: Some(regions),
        })
    }

    pub(crate) fn get_aggregator_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetAggregatorV2Request,
    ) -> Result<types::GetAggregatorV2Response, ServiceError> {
        common::authorize(ctx, "GetAggregatorV2", &input.aggregator_v2_arn)?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let (k, a) = Self::find_aggregator_v2(&state, ctx, &input.aggregator_v2_arn)?;
        Ok(types::GetAggregatorV2Response {
            aggregator_v2_arn: Some(a.arn),
            aggregation_region: k.split_once('/').map(|(_, r)| r.to_string()),
            region_linking_mode: Some(a.region_linking_mode),
            linked_regions: Some(a.regions),
        })
    }

    pub(crate) fn update_aggregator_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAggregatorV2Request,
    ) -> Result<types::UpdateAggregatorV2Response, ServiceError> {
        common::authorize(ctx, "UpdateAggregatorV2", &input.aggregator_v2_arn)?;
        let mut state = self.write();
        require_v2(&state, ctx)?;
        let (k, _) = Self::find_aggregator_v2(&state, ctx, &input.aggregator_v2_arn)?;
        let home = k.split_once('/').map(|(_, r)| r.to_string()).unwrap_or_default();
        let regions = crate::hub::check_linking(&input.region_linking_mode, input.linked_regions.as_deref(), &home)
            .map_err(|e| errors::validation(e.message))?;
        let a = state.hubs_v2.get_mut(&k).and_then(|h| h.aggregators.get_mut(&input.aggregator_v2_arn)).expect("found");
        a.region_linking_mode = input.region_linking_mode.clone();
        a.regions = regions.clone();
        Ok(types::UpdateAggregatorV2Response {
            aggregator_v2_arn: Some(input.aggregator_v2_arn),
            aggregation_region: Some(home),
            region_linking_mode: Some(input.region_linking_mode),
            linked_regions: Some(regions),
        })
    }

    pub(crate) fn delete_aggregator_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAggregatorV2Request,
    ) -> Result<types::DeleteAggregatorV2Response, ServiceError> {
        common::authorize(ctx, "DeleteAggregatorV2", &input.aggregator_v2_arn)?;
        let mut state = self.write();
        require_v2(&state, ctx)?;
        let (k, _) = Self::find_aggregator_v2(&state, ctx, &input.aggregator_v2_arn)?;
        state.hubs_v2.get_mut(&k).expect("found").aggregators.remove(&input.aggregator_v2_arn);
        Ok(types::DeleteAggregatorV2Response {})
    }

    pub(crate) fn list_aggregators_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::ListAggregatorsV2Request,
    ) -> Result<types::ListAggregatorsV2Response, ServiceError> {
        common::authorize(ctx, "ListAggregatorsV2", &common::arn(ctx, "hubv2/default"))?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let acct = account(ctx);
        let all: Vec<types::AggregatorV2> = state
            .hubs_v2
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{acct}/")))
            .flat_map(|(_, h)| h.aggregators.keys())
            .map(|a| types::AggregatorV2 { aggregator_v2_arn: Some(a.clone()) })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAggregatorsV2Response { aggregators_v2: Some(page), next_token })
    }

    // ---- findings ------------------------------------------------------------------

    pub(crate) fn get_findings_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsV2Request,
    ) -> Result<types::GetFindingsV2Response, ServiceError> {
        authorize_hub(ctx, "GetFindingsV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let mut docs = ocsf_filtered(&state, ctx, input.filters.as_ref());
        drop(state);
        filters::sort(
            &mut docs,
            &sort_criteria(input.sort_criteria.as_deref(), "finding_info.modified_time_dt"),
            false,
        );
        let (page, next_token) = paginate(docs, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetFindingsV2Response { findings: Some(page.iter().map(Value::to_string).collect()), next_token })
    }

    pub(crate) fn batch_update_findings_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateFindingsV2Request,
    ) -> Result<types::BatchUpdateFindingsV2Response, ServiceError> {
        authorize_hub(ctx, "BatchUpdateFindingsV2")?;
        if input.comment.is_none() && input.severity_id.is_none() && input.status_id.is_none() {
            return Err(errors::validation("At least one of Comment, SeverityId or StatusId must be provided."));
        }
        let mut processed = Vec::new();
        let mut unprocessed = Vec::new();
        let mut state = self.write();
        require_v2(&state, ctx)?;
        let keys = crate::findings::visible_keys(&state, account(ctx), &ctx.region);
        let mut targets: Vec<(Option<String>, Option<types::OcsfFindingIdentifier>)> =
            input.metadata_uids.unwrap_or_default().into_iter().map(|u| (Some(u), None)).collect();
        targets.extend(input.finding_identifiers.unwrap_or_default().into_iter().map(|i| (None, Some(i))));
        for (uid, ident) in targets {
            let mut hit = false;
            for k in &keys {
                let Some(h) = state.hubs.get_mut(k) else { continue };
                for rec in h.findings.values_mut() {
                    let f = &rec.finding;
                    let matches = match (&uid, &ident) {
                        (Some(u), _) => ocsf::metadata_uid(f) == *u,
                        (None, Some(i)) => {
                            f.get("AwsAccountId").and_then(Value::as_str) == Some(&i.cloud_account_uid)
                                && f.get("Id").and_then(Value::as_str) == Some(&i.finding_info_uid)
                                && f.get("ProductArn").and_then(Value::as_str) == Some(&i.metadata_product_uid)
                        }
                        _ => false,
                    };
                    if matches {
                        if input.comment.is_some() {
                            rec.v2.comment = input.comment.clone();
                        }
                        if input.severity_id.is_some() {
                            rec.v2.severity_id = input.severity_id;
                        }
                        if input.status_id.is_some() {
                            rec.v2.status_id = input.status_id;
                        }
                        hit = true;
                    }
                }
            }
            if hit {
                processed.push(types::BatchUpdateFindingsV2ProcessedFinding {
                    finding_identifier: ident,
                    metadata_uid: uid,
                });
            } else {
                unprocessed.push(types::BatchUpdateFindingsV2UnprocessedFinding {
                    finding_identifier: ident,
                    metadata_uid: uid,
                    error_code: Some("ResourceNotFoundException".into()),
                    error_message: Some("Finding not found".into()),
                });
            }
        }
        Ok(types::BatchUpdateFindingsV2Response { processed_findings: processed, unprocessed_findings: unprocessed })
    }

    pub(crate) fn get_finding_statistics_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingStatisticsV2Request,
    ) -> Result<types::GetFindingStatisticsV2Response, ServiceError> {
        authorize_hub(ctx, "GetFindingStatisticsV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let results = input
            .group_by_rules
            .iter()
            .map(|r| {
                let docs = ocsf_filtered(&state, ctx, r.filters.as_ref());
                types::GroupByResult {
                    group_by_field: Some(r.group_by_field.clone()),
                    group_by_values: Some(group(
                        &docs,
                        &r.group_by_field,
                        input.sort_order.as_deref(),
                        input.max_statistic_results,
                    )),
                }
            })
            .collect();
        Ok(types::GetFindingStatisticsV2Response { group_by_results: Some(results) })
    }

    pub(crate) fn get_findings_trends_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsTrendsV2Request,
    ) -> Result<types::GetFindingsTrendsV2Response, ServiceError> {
        authorize_hub(ctx, "GetFindingsTrendsV2")?;
        if input.end_time <= input.start_time {
            return Err(errors::validation("EndTime must be after StartTime."));
        }
        let state = self.read();
        require_v2(&state, ctx)?;
        let f = input.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
        let docs: Vec<(DateTime<Utc>, i64)> = visible_findings(&state, account(ctx), &ctx.region)
            .into_iter()
            .filter_map(|(_, _, rec)| {
                let o = ocsf::to_ocsf(&rec.finding, &rec.v2);
                let flat = json!({
                    "account_id": o["cloud"]["account"]["uid"],
                    "region": o["cloud"]["region"],
                    "finding_types": o["finding_info"]["types"],
                    "finding_status": o["status"],
                    "finding_compliance_status": o["compliance"]["status"],
                    "finding_control_id": o["compliance"]["control"],
                    "finding_class_name": o["class_name"],
                    "finding_provider": o["metadata"]["product"]["name"],
                    "finding_activity_name": o["activity_name"],
                    "resource_cloud_providers": "AWS",
                    "resource_regions": o["resources"].as_array().map(|r| r.iter().map(|x| x["region"].clone()).collect::<Vec<_>>()),
                });
                if !filters::matches_composite(&flat, &f, ctx.received_at) {
                    return None;
                }
                let created = o["finding_info"]["created_time_dt"].as_str().and_then(common::parse_time)?;
                Some((created, o["severity_id"].as_i64().unwrap_or(0)))
            })
            .collect();
        drop(state);
        let span = input.end_time - input.start_time;
        let (granularity, step) = if span <= Duration::days(90) {
            ("Daily", Duration::days(1))
        } else if span <= Duration::days(365) {
            ("Weekly", Duration::weeks(1))
        } else {
            ("Monthly", Duration::days(30))
        };
        let mut metrics = Vec::new();
        let mut t = input.start_time;
        while t <= input.end_time {
            let mut c = types::SeverityTrendsCount::default();
            for (created, sev) in &docs {
                if *created <= t {
                    match sev {
                        0 => c.unknown += 1,
                        1 => c.informational += 1,
                        2 => c.low += 1,
                        3 => c.medium += 1,
                        4 => c.high += 1,
                        5 => c.critical += 1,
                        6 => c.fatal += 1,
                        _ => c.other += 1,
                    }
                }
            }
            metrics.push(types::TrendsMetricsResult {
                timestamp: t,
                trends_values: types::TrendsValues { severity_trends: c },
            });
            t += step;
        }
        let (page, next_token) = paginate(metrics, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetFindingsTrendsV2Response { granularity: granularity.into(), trends_metrics: page, next_token })
    }

    // ---- resources -------------------------------------------------------------------

    pub(crate) fn get_resources_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcesV2Request,
    ) -> Result<types::GetResourcesV2Response, ServiceError> {
        authorize_hub(ctx, "GetResourcesV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let f = input.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
        let mut docs: Vec<Value> = resource_docs(&state, ctx)
            .into_iter()
            .filter(|d| filters::matches_composite(d, &f, ctx.received_at))
            .collect();
        drop(state);
        filters::sort(&mut docs, &sort_criteria(input.sort_criteria.as_deref(), "ResourceDetailCaptureTime"), false);
        let (page, next_token) = paginate(docs, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetResourcesV2Response { resources: page.iter().map(resource_wire).collect(), next_token })
    }

    pub(crate) fn get_resources_statistics_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcesStatisticsV2Request,
    ) -> Result<types::GetResourcesStatisticsV2Response, ServiceError> {
        authorize_hub(ctx, "GetResourcesStatisticsV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let all = resource_docs(&state, ctx);
        let results = input
            .group_by_rules
            .iter()
            .map(|r| {
                let f = r.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
                let docs: Vec<Value> =
                    all.iter().filter(|d| filters::matches_composite(d, &f, ctx.received_at)).cloned().collect();
                types::GroupByResult {
                    group_by_field: Some(r.group_by_field.clone()),
                    group_by_values: Some(group(
                        &docs,
                        &r.group_by_field,
                        input.sort_order.as_deref(),
                        input.max_statistic_results,
                    )),
                }
            })
            .collect();
        Ok(types::GetResourcesStatisticsV2Response { group_by_results: results })
    }

    pub(crate) fn get_resources_trends_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcesTrendsV2Request,
    ) -> Result<types::GetResourcesTrendsV2Response, ServiceError> {
        authorize_hub(ctx, "GetResourcesTrendsV2")?;
        if input.end_time <= input.start_time {
            return Err(errors::validation("EndTime must be after StartTime."));
        }
        let state = self.read();
        require_v2(&state, ctx)?;
        let f = input.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
        let times: Vec<DateTime<Utc>> = resource_docs(&state, ctx)
            .into_iter()
            .filter(|d| {
                let flat = json!({
                    "account_id": d["AccountId"], "region": d["Region"], "resource_type": d["ResourceType"],
                    "resource_cloud_provider": d["ResourceProvider"], "resource_region": d["ResourceRegion"],
                    "resource_owner_id": d["ResourceOwnerAccountId"],
                });
                filters::matches_composite(&flat, &f, ctx.received_at)
            })
            .filter_map(|d| d["ResourceDetailCaptureTime"].as_str().and_then(common::parse_time))
            .collect();
        drop(state);
        let mut metrics = Vec::new();
        let mut t = input.start_time;
        while t <= input.end_time {
            let n = times.iter().filter(|x| **x <= t).count() as i64;
            metrics.push(types::ResourcesTrendsMetricsResult {
                timestamp: t,
                trends_values: types::ResourcesTrendsValues {
                    resources_count: types::ResourcesCount { all_resources: n },
                },
            });
            t += Duration::days(1);
        }
        let (page, next_token) = paginate(metrics, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetResourcesTrendsV2Response { granularity: "Daily".into(), trends_metrics: page, next_token })
    }

    // ---- software ----------------------------------------------------------------------

    pub(crate) fn get_software_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetSoftwareV2Request,
    ) -> Result<types::GetSoftwareV2Response, ServiceError> {
        authorize_hub(ctx, "GetSoftwareV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let f = input.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
        let mut counts: BTreeMap<(String, Option<String>, String), i32> = BTreeMap::new();
        for d in software_docs(&state, ctx).into_iter().filter(|d| filters::matches_composite(d, &f, ctx.received_at)) {
            let k = (
                d["PackageName"].as_str().unwrap_or_default().to_string(),
                d["PackageVersion"].as_str().map(str::to_string),
                d["PackageType"].as_str().unwrap_or_default().to_string(),
            );
            *counts.entry(k).or_default() += 1;
        }
        drop(state);
        let all: Vec<types::SoftwareResult> = counts
            .into_iter()
            .map(|((package_name, package_version, package_type), resource_count)| types::SoftwareResult {
                package_name,
                package_version,
                package_type,
                resource_count,
            })
            .collect();
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetSoftwareV2Response { software: page, next_token })
    }

    pub(crate) fn get_software_resources_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetSoftwareResourcesV2Request,
    ) -> Result<types::GetSoftwareResourcesV2Response, ServiceError> {
        authorize_hub(ctx, "GetSoftwareResourcesV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let f = input.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
        let mut docs: Vec<Value> = software_docs(&state, ctx)
            .into_iter()
            .filter(|d| {
                d["PackageName"].as_str() == Some(&input.package_name)
                    && d["PackageType"].as_str() == Some(&input.package_type)
                    && input.package_version.as_ref().is_none_or(|v| d["PackageVersion"].as_str() == Some(v))
                    && filters::matches_composite(d, &f, ctx.received_at)
            })
            .collect();
        drop(state);
        filters::sort(&mut docs, &sort_criteria(input.sort_criteria.as_deref(), "ResourceId"), false);
        let (page, next_token) = paginate(docs, input.max_results, 100, input.next_token.as_deref())?;
        let s = |d: &Value, k: &str| d[k].as_str().map(str::to_string);
        Ok(types::GetSoftwareResourcesV2Response {
            software_resources: page
                .iter()
                .map(|d| types::SoftwareResourceResult {
                    account_id: s(d, "AccountId").unwrap_or_default(),
                    resource_type: s(d, "ResourceType").unwrap_or_default(),
                    region: s(d, "Region").unwrap_or_default(),
                    resource_id: s(d, "ResourceId").unwrap_or_default(),
                    resource_provider: s(d, "ResourceProvider"),
                    resource_owner_org_id: None,
                    resource_owner_account_id: s(d, "ResourceOwnerAccountId"),
                    resource_cloud_partition: s(d, "ResourceCloudPartition"),
                    resource_region: s(d, "ResourceRegion"),
                })
                .collect(),
            next_token,
        })
    }

    pub(crate) fn get_software_statistics_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetSoftwareStatisticsV2Request,
    ) -> Result<types::GetSoftwareStatisticsV2Response, ServiceError> {
        authorize_hub(ctx, "GetSoftwareStatisticsV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let all = software_docs(&state, ctx);
        let results = input
            .group_by_rules
            .iter()
            .map(|r| {
                let f = r.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
                let docs: Vec<Value> =
                    all.iter().filter(|d| filters::matches_composite(d, &f, ctx.received_at)).cloned().collect();
                types::GroupByResult {
                    group_by_field: Some(r.group_by_field.clone()),
                    group_by_values: Some(group(
                        &docs,
                        &r.group_by_field,
                        input.sort_order.as_deref(),
                        input.max_statistic_results,
                    )),
                }
            })
            .collect();
        Ok(types::GetSoftwareStatisticsV2Response { group_by_results: results })
    }

    // ---- export jobs ---------------------------------------------------------------------

    pub(crate) fn start_export_job_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::StartExportJobV2Request,
    ) -> Result<types::StartExportJobV2Response, ServiceError> {
        authorize_hub(ctx, "StartExportJobV2")?;
        let types::ExportDestination::S3(dest) = &input.destination;
        let types::ExportOutput::Findings(out) = &input.output_configuration;
        let bucket = dest
            .bucket_arn
            .strip_prefix(&format!("arn:{}:s3:::", ctx.partition))
            .filter(|b| !b.is_empty() && !b.contains('/'))
            .ok_or_else(|| errors::validation(format!("Invalid BucketArn {}", dest.bucket_arn)))?
            .to_string();
        let (docs, existing) = {
            let state = self.read();
            require_v2(&state, ctx)?;
            let h = &state.hubs_v2[&key(account(ctx), &ctx.region)];
            let existing = input.client_token.as_ref().and_then(|t| h.client_tokens.get(t)).cloned();
            (ocsf_filtered(&state, ctx, out.filters.as_ref()), existing)
        };
        if let Some(id) = existing {
            return Ok(types::StartExportJobV2Response { export_job_id: id });
        }
        let id = uuid::Uuid::new_v4().to_string();
        let selected = out.selected_fields.clone().unwrap_or_default();
        let lines: Vec<String> = docs
            .iter()
            .map(|d| {
                if selected.is_empty() {
                    return d.to_string();
                }
                let mut m = serde_json::Map::new();
                for f in &selected {
                    if let Some(v) = filters::values_at(d, f).first() {
                        m.insert(f.clone(), (*v).clone());
                    }
                }
                Value::Object(m).to_string()
            })
            .collect();
        let body = if out.format == "JSON" { format!("[{}]", lines.join(",")) } else { lines.join("\n") };
        let prefix = dest.object_prefix.clone().map(|p| format!("{}/", p.trim_end_matches('/'))).unwrap_or_default();
        let object_key = format!("{prefix}AWSSecurityHub/{}/{}/{id}/findings.json", account(ctx), ctx.region);
        let outcome = match self.inner.exports.get() {
            Some(sink) => sink.put_object(ctx, &bucket, &object_key, body.into_bytes(), Some(&dest.kms_key_arn)),
            None => Err("Export destinations are not available.".to_string()),
        };
        let (status, code, message) = match outcome {
            Ok(()) => ("SUCCEEDED", None, None),
            Err(m) => (
                "FAILED",
                Some(
                    if m.contains("NoSuchBucket") || m.contains("not exist") {
                        "RESOURCE_NOT_FOUND"
                    } else {
                        "ACCESS_DENIED"
                    }
                    .to_string(),
                ),
                Some(m),
            ),
        };
        let mut state = self.write();
        let h = state
            .hubs_v2
            .get_mut(&key(account(ctx), &ctx.region))
            .ok_or_else(|| not_found("Security Hub V2 was disabled"))?;
        h.export_jobs.insert(
            id.clone(),
            ExportJobRec {
                id: id.clone(),
                name: input.name,
                status: status.into(),
                data_type: "FINDINGS".into(),
                output: input.output_configuration,
                scopes: input.scopes,
                destination: input.destination,
                started_at: ctx.received_at,
                ended_at: Some(ctx.received_at),
                failure_code: code,
                failure_message: message,
            },
        );
        if let Some(t) = input.client_token {
            h.client_tokens.insert(t, id.clone());
        }
        Ok(types::StartExportJobV2Response { export_job_id: id })
    }

    pub(crate) fn get_export_job_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetExportJobV2Request,
    ) -> Result<types::GetExportJobV2Response, ServiceError> {
        authorize_hub(ctx, "GetExportJobV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let j = state.hubs_v2[&key(account(ctx), &ctx.region)]
            .export_jobs
            .get(&input.export_job_id)
            .cloned()
            .ok_or_else(|| not_found(format!("Export job {} not found", input.export_job_id)))?;
        Ok(types::GetExportJobV2Response {
            export_job_id: j.id,
            name: j.name,
            status: j.status,
            data_type: j.data_type,
            output_configuration: Some(j.output),
            scopes: j.scopes,
            destination: j.destination,
            failure_code: j.failure_code,
            failure_message: j.failure_message,
            started_at: j.started_at,
            ended_at: j.ended_at,
        })
    }

    pub(crate) fn list_export_jobs_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::ListExportJobsV2Request,
    ) -> Result<types::ListExportJobsV2Response, ServiceError> {
        authorize_hub(ctx, "ListExportJobsV2")?;
        let state = self.read();
        require_v2(&state, ctx)?;
        let mut jobs: Vec<ExportJobRec> = state.hubs_v2[&key(account(ctx), &ctx.region)]
            .export_jobs
            .values()
            .filter(|j| input.status.as_ref().is_none_or(|s| *s == j.status))
            .filter(|j| input.data_type.as_ref().is_none_or(|s| *s == j.data_type))
            .cloned()
            .collect();
        drop(state);
        jobs.sort_by_key(|j| std::cmp::Reverse(j.started_at));
        let all: Vec<types::ExportSummary> = jobs
            .into_iter()
            .map(|j| {
                let types::ExportOutput::Findings(o) = &j.output;
                types::ExportSummary {
                    export_job_id: j.id,
                    name: j.name,
                    status: j.status,
                    data_type: j.data_type,
                    output_configuration: Some(types::ExportOutputSummary::Findings(types::FindingsOutputSummary {
                        format: o.format.clone(),
                    })),
                    scopes: j.scopes,
                    destination: j.destination,
                    failure_code: j.failure_code,
                    failure_message: j.failure_message,
                    started_at: j.started_at,
                    ended_at: j.ended_at,
                }
            })
            .collect();
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListExportJobsV2Response { items: page, next_token })
    }

    pub(crate) fn cancel_export_job_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::CancelExportJobV2Request,
    ) -> Result<types::CancelExportJobV2Response, ServiceError> {
        authorize_hub(ctx, "CancelExportJobV2")?;
        let mut state = self.write();
        require_v2(&state, ctx)?;
        let j = state
            .hubs_v2
            .get_mut(&key(account(ctx), &ctx.region))
            .and_then(|h| h.export_jobs.get_mut(&input.export_job_id))
            .ok_or_else(|| not_found(format!("Export job {} not found", input.export_job_id)))?;
        if j.status != "RUNNING" {
            return Err(errors::conflict(format!("Export job {} is already {}.", j.id, j.status)));
        }
        j.status = "CANCELLED".into();
        Ok(types::CancelExportJobV2Response { export_job_id: input.export_job_id, status: "CANCELLED".into() })
    }

    // ---- remediations and recommendations -------------------------------------------------

    pub(crate) fn get_remediations_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetRemediationsV2Request,
    ) -> Result<types::GetRemediationsV2Response, ServiceError> {
        authorize_hub(ctx, "GetRemediationsV2")?;
        require_v2(&self.read(), ctx)?;
        paginate(Vec::<types::RemediationV2Item>::new(), input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetRemediationsV2Response { items: Vec::new(), next_token: None })
    }

    pub(crate) fn list_exposures_by_remediation_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::ListExposuresByRemediationV2Request,
    ) -> Result<types::ListExposuresByRemediationV2Response, ServiceError> {
        authorize_hub(ctx, "ListExposuresByRemediationV2")?;
        require_v2(&self.read(), ctx)?;
        Err(not_found(format!("Remediation target {} not found", input.target_uid)))
    }

    fn finding_by_uid(&self, ctx: &RequestContext, uid: &str) -> Result<Value, ServiceError> {
        let state = self.read();
        require_v2(&state, ctx)?;
        visible_findings(&state, account(ctx), &ctx.region)
            .into_iter()
            .find(|(_, _, f)| ocsf::metadata_uid(&f.finding) == uid)
            .map(|(_, _, f)| f.finding.clone())
            .ok_or_else(|| not_found(format!("Finding {uid} not found")))
    }

    pub(crate) fn generate_recommended_policy_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GenerateRecommendedPolicyV2Request,
    ) -> Result<types::GenerateRecommendedPolicyV2Response, ServiceError> {
        authorize_hub(ctx, "GenerateRecommendedPolicyV2")?;
        self.finding_by_uid(ctx, &input.metadata_uid)?;
        Ok(types::GenerateRecommendedPolicyV2Response {})
    }

    pub(crate) fn get_recommended_policy_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::GetRecommendedPolicyV2Request,
    ) -> Result<types::GetRecommendedPolicyV2Response, ServiceError> {
        authorize_hub(ctx, "GetRecommendedPolicyV2")?;
        let f = self.finding_by_uid(ctx, &input.metadata_uid)?;
        let resource = filters::values_at(&f, "Resources[].Id").first().and_then(|v| v.as_str()).map(str::to_string);
        Ok(types::GetRecommendedPolicyV2Response {
            next_token: None,
            recommendation_type: Some("UNUSED_PERMISSION_RECOMMENDATION".into()),
            recommendation_steps: Some(Vec::new()),
            error: Some(types::RecommendationError {
                code: Some("UNSUPPORTED_FINDING".into()),
                message: Some(
                    "Recommended policies are only generated for unused permission findings from IAM Access Analyzer."
                        .into(),
                ),
            }),
            status: Some("FAILED".into()),
            resource_arn: resource,
        })
    }

    // ---- products and free trials --------------------------------------------------------

    pub(crate) fn describe_products_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeProductsV2Request,
    ) -> Result<types::DescribeProductsV2Response, ServiceError> {
        common::authorize(ctx, "DescribeProductsV2", &common::arn(ctx, "hubv2/default"))?;
        let all: Vec<types::ProductV2> = catalog::PRODUCTS
            .iter()
            .map(|p| types::ProductV2 {
                product_v2_name: Some(p.name.into()),
                company_name: Some(p.company.into()),
                description: Some(p.description.into()),
                categories: Some(p.categories.iter().map(|c| c.to_string()).collect()),
                integration_v2_types: Some(p.integration_types.iter().map(|c| c.to_string()).collect()),
                marketplace_url: None,
                activation_url: None,
                marketplace_product_id: None,
            })
            .collect();
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::DescribeProductsV2Response { products_v2: page, next_token })
    }

    pub(crate) fn list_free_trial_statuses_v2_op(
        &self,
        ctx: &RequestContext,
        input: types::ListFreeTrialStatusesV2Request,
    ) -> Result<types::ListFreeTrialStatusesV2Response, ServiceError> {
        common::authorize(ctx, "ListFreeTrialStatusesV2", &common::arn(ctx, "hubv2/default"))?;
        let state = self.read();
        let mut accounts = input.account_ids.clone().unwrap_or_default();
        if accounts.is_empty() {
            accounts.push(account(ctx).to_string());
            if let Some(m) = state.members.get(&key(account(ctx), &ctx.region)) {
                accounts.extend(m.iter().filter(|(_, m)| m.status == "Enabled").map(|(a, _)| a.clone()));
            }
        }
        let wanted = input.statuses.unwrap_or_default();
        let all: Vec<types::AccountFreeTrialStatus> = accounts
            .into_iter()
            .filter_map(|a| {
                let h = state.hubs_v2.get(&key(&a, &ctx.region))?;
                let expires = h.subscribed_at + Duration::days(30);
                let status = if ctx.received_at < expires { "ACTIVE" } else { "INACTIVE" };
                if !wanted.is_empty() && !wanted.iter().any(|w| w == status) {
                    return None;
                }
                Some(types::AccountFreeTrialStatus {
                    account_id: a,
                    evaluated_at: ctx.received_at,
                    free_trial_statuses: vec![types::FreeTrialStatus {
                        feature_type: "SECURITY_HUB_V2".into(),
                        status: status.into(),
                        started_at: h.subscribed_at,
                        expires_at: expires,
                    }],
                })
            })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListFreeTrialStatusesV2Response { account_free_trial_statuses: page, next_token })
    }
}
