//! Multi-Region Access Points: created, deleted and given policies through
//! asynchronous requests (which MWS completes at once, so
//! `DescribeMultiRegionAccessPointOperation` reports `SUCCEEDED`), with
//! per-Region routes and their traffic dials.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::generated::types;
use crate::S3Control;

fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

fn no_such_mrap() -> ServiceError {
    err("NoSuchMultiRegionAccessPoint", 404, "The specified Multi-Region Access Point does not exist")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Mrap {
    pub name: String,
    pub account_id: String,
    pub alias: String,
    pub created: Option<DateTime<Utc>>,
    pub public_access_block: Option<types::PublicAccessBlockConfiguration>,
    pub regions: Vec<types::RegionReport>,
    pub routes: Vec<types::MultiRegionAccessPointRoute>,
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AsyncRequest {
    pub account_id: String,
    pub operation: types::AsyncOperation,
}

fn alias() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let s: String = (0..13).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect();
    format!("{s}.mrap")
}

fn check_name(name: &str) -> Result<(), ServiceError> {
    let ok = (3..=50).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(err("InvalidRequest", 400, "Your Multi-Region Access Point name is invalid"))
    }
}

impl S3Control {
    fn mrap_arn(ctx: &RequestContext, account: &str, alias: &str) -> String {
        format!("arn:{}:s3::{account}:accesspoint/{alias}", ctx.partition)
    }

    fn mrap_key(account: &str, name: &str) -> String {
        format!("{account}/{name}")
    }

    /// A name, alias or ARN reduced to the stored access point.
    fn find_mrap(&self, account: &str, name: &str) -> Result<Mrap, ServiceError> {
        let short = name.rsplit_once("accesspoint/").map_or(name, |(_, n)| n);
        let st = self.read();
        st.mraps
            .values()
            .find(|m| m.account_id == account && (m.name == short || m.alias == short))
            .cloned()
            .ok_or_else(no_such_mrap)
    }

    fn record_request(
        &self,
        ctx: &RequestContext,
        account: &str,
        operation: &str,
        token: &str,
        params: types::AsyncRequestParameters,
        result: Result<String, ServiceError>,
    ) -> String {
        let kind = match operation {
            "CreateMultiRegionAccessPoint" => "create",
            "DeleteMultiRegionAccessPoint" => "delete",
            _ => "put-policy",
        };
        // Retried client tokens return the original request.
        if let Some(existing) = self.read().mrap_requests.values().find(|r| {
            r.account_id == account
                && r.operation.operation.as_deref() == Some(operation)
                && r.operation.request_token_arn.as_deref().is_some_and(|a| a.ends_with(token))
        }) {
            return existing.operation.request_token_arn.clone().unwrap_or_default();
        }
        let arn = format!("arn:{}:s3:us-west-2:{account}:async-request/mrap/{kind}/{token}", ctx.partition);
        let (status, details) = match result {
            Ok(name) => (
                "SUCCEEDED",
                types::AsyncResponseDetails {
                    multi_region_access_point_details: Some(types::MultiRegionAccessPointsAsyncResponse {
                        regions: Some(vec![types::MultiRegionAccessPointRegionalResponse {
                            name: Some(name),
                            request_status: Some("COMPLETED".into()),
                        }]),
                    }),
                    error_details: None,
                },
            ),
            Err(e) => (
                "FAILED",
                types::AsyncResponseDetails {
                    multi_region_access_point_details: None,
                    error_details: Some(types::AsyncErrorDetails {
                        code: Some(e.code.to_string()),
                        message: Some(e.message.clone()),
                        resource: None,
                        request_id: Some(ctx.request_id.clone()),
                    }),
                },
            ),
        };
        let op = types::AsyncOperation {
            creation_time: Some(ctx.received_at),
            operation: Some(operation.to_string()),
            request_token_arn: Some(arn.clone()),
            request_parameters: Some(params),
            request_status: Some(status.into()),
            response_details: Some(details),
        };
        self.write().mrap_requests.insert(arn.clone(), AsyncRequest { account_id: account.to_string(), operation: op });
        arn
    }

    pub(crate) async fn create_multi_region_access_point(
        &self,
        ctx: &RequestContext,
        input: types::CreateMultiRegionAccessPointRequest,
    ) -> Result<types::CreateMultiRegionAccessPointResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let d = input.details.clone();
        ctx.authorize(
            "s3:CreateMultiRegionAccessPoint",
            &format!("arn:{}:s3::{account}:accesspoint/{}", ctx.partition, d.name),
            ConditionContext::new(),
        )?;
        check_name(&d.name)?;
        if d.regions.is_empty() || d.regions.len() > 17 {
            return Err(err("InvalidRequest", 400, "A Multi-Region Access Point needs between 1 and 17 Regions"));
        }
        let mut regions = Vec::new();
        for r in &d.regions {
            let (owner, region) = match &self.s3 {
                Some(s3) => (
                    s3.bucket_owner(&r.bucket)
                        .ok_or_else(|| err("NoSuchBucket", 404, "The specified bucket does not exist"))?,
                    s3.bucket_region(&r.bucket).unwrap_or_else(|| ctx.region.clone()),
                ),
                None => (account.clone(), ctx.region.clone()),
            };
            if r.bucket_account_id.as_ref().is_some_and(|a| a != &owner) {
                return Err(err("AccessDenied", 403, "Access Denied"));
            }
            if regions.iter().any(|x: &types::RegionReport| x.region.as_deref() == Some(region.as_str())) {
                return Err(err("InvalidRequest", 400, "Each Region may appear only once"));
            }
            regions.push(types::RegionReport {
                bucket: Some(r.bucket.clone()),
                region: Some(region),
                bucket_account_id: Some(owner),
            });
        }
        let result = {
            let mut st = self.write();
            let k = Self::mrap_key(&account, &d.name);
            match st.mraps.entry(k) {
                std::collections::btree_map::Entry::Occupied(_) => {
                    Err(err("MultiRegionAccessPointAlreadyExists", 409, "The Multi-Region Access Point already exists"))
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    let routes = regions
                        .iter()
                        .map(|r| types::MultiRegionAccessPointRoute {
                            bucket: r.bucket.clone(),
                            region: r.region.clone(),
                            traffic_dial_percentage: 100,
                        })
                        .collect();
                    slot.insert(Mrap {
                        name: d.name.clone(),
                        account_id: account.clone(),
                        alias: alias(),
                        created: Some(ctx.received_at),
                        public_access_block: d.public_access_block.clone(),
                        regions,
                        routes,
                        policy: None,
                    });
                    Ok(d.name.clone())
                }
            }
        };
        let params =
            types::AsyncRequestParameters { create_multi_region_access_point_request: Some(d), ..Default::default() };
        let arn =
            self.record_request(ctx, &account, "CreateMultiRegionAccessPoint", &input.client_token, params, result);
        Ok(types::CreateMultiRegionAccessPointResult { request_token_arn: Some(arn) })
    }

    pub(crate) async fn delete_multi_region_access_point(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMultiRegionAccessPointRequest,
    ) -> Result<types::DeleteMultiRegionAccessPointResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let name = input.details.name.clone();
        let found = self.find_mrap(&account, &name);
        let arn = found.as_ref().map(|m| Self::mrap_arn(ctx, &account, &m.alias)).unwrap_or_else(|_| "*".into());
        ctx.authorize("s3:DeleteMultiRegionAccessPoint", &arn, ConditionContext::new())?;
        let result = found.map(|m| {
            self.write().mraps.remove(&Self::mrap_key(&account, &m.name));
            m.name
        });
        let params = types::AsyncRequestParameters {
            delete_multi_region_access_point_request: Some(input.details),
            ..Default::default()
        };
        let arn =
            self.record_request(ctx, &account, "DeleteMultiRegionAccessPoint", &input.client_token, params, result);
        Ok(types::DeleteMultiRegionAccessPointResult { request_token_arn: Some(arn) })
    }

    pub(crate) async fn put_multi_region_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutMultiRegionAccessPointPolicyRequest,
    ) -> Result<types::PutMultiRegionAccessPointPolicyResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let m = self.find_mrap(&account, &input.details.name)?;
        let arn = Self::mrap_arn(ctx, &account, &m.alias);
        ctx.authorize("s3:PutMultiRegionAccessPointPolicy", &arn, ConditionContext::new())?;
        let policy = input.details.policy.clone();
        let result = if serde_json::from_str::<serde_json::Value>(&policy).is_err() {
            Err(err("MalformedPolicy", 400, "Policies must be valid JSON"))
        } else if m.public_access_block.as_ref().is_none_or(|p| p.block_public_policy)
            && mws_s3::policy_is_public(&policy)
        {
            Err(err("AccessDenied", 403, "Access Denied"))
        } else {
            if let Some(stored) = self.write().mraps.get_mut(&Self::mrap_key(&account, &m.name)) {
                stored.policy = Some(policy);
            }
            Ok(m.name.clone())
        };
        let params = types::AsyncRequestParameters {
            put_multi_region_access_point_policy_request: Some(input.details),
            ..Default::default()
        };
        let arn =
            self.record_request(ctx, &account, "PutMultiRegionAccessPointPolicy", &input.client_token, params, result);
        Ok(types::PutMultiRegionAccessPointPolicyResult { request_token_arn: Some(arn) })
    }

    pub(crate) async fn describe_multi_region_access_point_operation(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMultiRegionAccessPointOperationRequest,
    ) -> Result<types::DescribeMultiRegionAccessPointOperationResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:DescribeMultiRegionAccessPointOperation", &input.request_token_arn, ConditionContext::new())?;
        let st = self.read();
        let r = st
            .mrap_requests
            .get(&input.request_token_arn)
            .filter(|r| r.account_id == account)
            .ok_or_else(|| err("NoSuchAsyncRequest", 404, "The specified asynchronous request does not exist"))?;
        Ok(types::DescribeMultiRegionAccessPointOperationResult { async_operation: Some(r.operation.clone()) })
    }

    fn mrap_report(m: &Mrap) -> types::MultiRegionAccessPointReport {
        types::MultiRegionAccessPointReport {
            name: Some(m.name.clone()),
            alias: Some(m.alias.clone()),
            created_at: m.created,
            public_access_block: Some(m.public_access_block.clone().unwrap_or(types::PublicAccessBlockConfiguration {
                block_public_acls: true,
                ignore_public_acls: true,
                block_public_policy: true,
                restrict_public_buckets: true,
            })),
            status: Some("READY".into()),
            regions: Some(m.regions.clone()),
        }
    }

    pub(crate) async fn get_multi_region_access_point(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointRequest,
    ) -> Result<types::GetMultiRegionAccessPointResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let m = self.find_mrap(&account, &input.name)?;
        ctx.authorize(
            "s3:GetMultiRegionAccessPoint",
            &Self::mrap_arn(ctx, &account, &m.alias),
            ConditionContext::new(),
        )?;
        Ok(types::GetMultiRegionAccessPointResult { access_point: Some(Self::mrap_report(&m)) })
    }

    pub(crate) async fn list_multi_region_access_points(
        &self,
        ctx: &RequestContext,
        input: types::ListMultiRegionAccessPointsRequest,
    ) -> Result<types::ListMultiRegionAccessPointsResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListMultiRegionAccessPoints", "*", ConditionContext::new())?;
        let items: Vec<types::MultiRegionAccessPointReport> =
            self.read().mraps.values().filter(|m| m.account_id == account).map(Self::mrap_report).collect();
        let max = (if input.max_results <= 0 { 100 } else { input.max_results }).clamp(1, 100) as usize;
        let start = input.next_token.as_deref().and_then(|t| t.parse::<usize>().ok()).unwrap_or(0);
        let next = (items.len() > start + max).then(|| (start + max).to_string());
        Ok(types::ListMultiRegionAccessPointsResult {
            access_points: Some(items.into_iter().skip(start).take(max).collect()),
            next_token: next,
        })
    }

    pub(crate) async fn get_multi_region_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointPolicyRequest,
    ) -> Result<types::GetMultiRegionAccessPointPolicyResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let m = self.find_mrap(&account, &input.name)?;
        ctx.authorize(
            "s3:GetMultiRegionAccessPointPolicy",
            &Self::mrap_arn(ctx, &account, &m.alias),
            ConditionContext::new(),
        )?;
        let Some(policy) = m.policy else {
            return Err(err("NoSuchAccessPointPolicy", 404, "The specified accesspoint policy does not exist"));
        };
        Ok(types::GetMultiRegionAccessPointPolicyResult {
            policy: Some(types::MultiRegionAccessPointPolicyDocument {
                established: Some(types::EstablishedMultiRegionAccessPointPolicy { policy: Some(policy.clone()) }),
                proposed: Some(types::ProposedMultiRegionAccessPointPolicy { policy: Some(policy) }),
            }),
        })
    }

    pub(crate) async fn get_multi_region_access_point_policy_status(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointPolicyStatusRequest,
    ) -> Result<types::GetMultiRegionAccessPointPolicyStatusResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let m = self.find_mrap(&account, &input.name)?;
        ctx.authorize(
            "s3:GetMultiRegionAccessPointPolicyStatus",
            &Self::mrap_arn(ctx, &account, &m.alias),
            ConditionContext::new(),
        )?;
        let is_public = m.policy.as_deref().is_some_and(mws_s3::policy_is_public);
        Ok(types::GetMultiRegionAccessPointPolicyStatusResult { established: Some(types::PolicyStatus { is_public }) })
    }

    pub(crate) async fn get_multi_region_access_point_routes(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointRoutesRequest,
    ) -> Result<types::GetMultiRegionAccessPointRoutesResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let m = self.find_mrap(&account, &input.mrap)?;
        ctx.authorize(
            "s3:GetMultiRegionAccessPointRoutes",
            &Self::mrap_arn(ctx, &account, &m.alias),
            ConditionContext::new(),
        )?;
        Ok(types::GetMultiRegionAccessPointRoutesResult { mrap: Some(input.mrap), routes: Some(m.routes) })
    }

    pub(crate) async fn submit_multi_region_access_point_routes(
        &self,
        ctx: &RequestContext,
        input: types::SubmitMultiRegionAccessPointRoutesRequest,
    ) -> Result<types::SubmitMultiRegionAccessPointRoutesResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let m = self.find_mrap(&account, &input.mrap)?;
        ctx.authorize(
            "s3:SubmitMultiRegionAccessPointRoutes",
            &Self::mrap_arn(ctx, &account, &m.alias),
            ConditionContext::new(),
        )?;
        let mut st = self.write();
        let stored = st.mraps.get_mut(&Self::mrap_key(&account, &m.name)).ok_or_else(no_such_mrap)?;
        for update in input.route_updates {
            if !(0..=100).contains(&update.traffic_dial_percentage) {
                return Err(err("InvalidRequest", 400, "TrafficDialPercentage must be between 0 and 100"));
            }
            let route = stored.routes.iter_mut().find(|r| {
                (update.bucket.is_some() && r.bucket == update.bucket)
                    || (update.region.is_some() && r.region == update.region)
            });
            match route {
                Some(r) => r.traffic_dial_percentage = update.traffic_dial_percentage,
                None => {
                    return Err(err(
                        "InvalidRequest",
                        400,
                        "The route names a bucket or Region not in this Multi-Region Access Point",
                    ))
                }
            }
        }
        Ok(types::SubmitMultiRegionAccessPointRoutesResult {})
    }
}
