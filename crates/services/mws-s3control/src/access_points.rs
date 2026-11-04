//! Access points, Object Lambda access points, account-level Block Public
//! Access and tags.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::types;
use crate::state::{AccessPoint, ObjectLambda};
use crate::S3Control;

fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

fn no_such_access_point() -> ServiceError {
    err("NoSuchAccessPoint", 404, "The specified accesspoint does not exist")
}

fn no_such_policy() -> ServiceError {
    err("NoSuchAccessPointPolicy", 404, "The specified accesspoint policy does not exist")
}

fn invalid(message: impl Into<String>) -> ServiceError {
    err("InvalidRequest", 400, message)
}

/// A name or ARN, as the `Name` members take them, reduced to the name.
fn short_name(name: &str) -> &str {
    if name.starts_with("arn:") {
        name.rsplit_once("accesspoint/").map_or(name, |(_, n)| n)
    } else {
        name
    }
}

fn random_suffix(n: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

/// Access point names: 3-50 characters of lowercase letters, numbers and
/// hyphens, starting and ending with a letter or number, not ending in
/// `-s3alias` or `--ol-s3`.
fn check_name(name: &str) -> Result<(), ServiceError> {
    let ok = (3..=50).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.starts_with("xn--")
        && !name.ends_with("-s3alias")
        && !name.ends_with("--ol-s3");
    if ok {
        Ok(())
    } else {
        Err(invalid("Your Access Point name is invalid"))
    }
}

/// The account in the request must be the caller's (or the caller must be
/// allowed into it through IAM, which the ARN check covers).
pub(crate) fn account(ctx: &RequestContext, account_id: &str) -> Result<String, ServiceError> {
    if account_id.len() != 12 || !account_id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("Account id is not valid"));
    }
    let _ = ctx;
    Ok(account_id.to_string())
}

pub(crate) fn tags_context(tags: &[types::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for t in tags {
        c.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone()]);
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect());
    }
    c
}

fn ap_arn(ctx: &RequestContext, account: &str, name: &str) -> String {
    format!("arn:{}:s3:{}:{account}:accesspoint/{name}", ctx.partition, ctx.region)
}

fn olap_arn(ctx: &RequestContext, account: &str, name: &str) -> String {
    format!("arn:{}:s3-object-lambda:{}:{account}:accesspoint/{name}", ctx.partition, ctx.region)
}

/// Check an access point policy: valid JSON whose resources all lie
/// within the access point.
fn check_policy(policy: &str, arn: &str) -> Result<(), ServiceError> {
    let malformed = |m: &str| err("MalformedPolicy", 400, m.to_string());
    let v: serde_json::Value =
        serde_json::from_str(policy).map_err(|_| malformed("This policy contains invalid Json"))?;
    let statements = match v.get("Statement") {
        Some(serde_json::Value::Array(a)) => a.clone(),
        Some(s @ serde_json::Value::Object(_)) => vec![s.clone()],
        _ => return Err(malformed("Missing required field Statement")),
    };
    for s in statements {
        let resources = match s.get("Resource").or_else(|| s.get("NotResource")) {
            Some(serde_json::Value::String(r)) => vec![r.clone()],
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            _ => return Err(malformed("Missing required field Resource")),
        };
        for r in resources {
            if !(r == arn
                || r.starts_with(&format!("{arn}/"))
                || (r.ends_with('*') && arn.starts_with(r.trim_end_matches('*'))))
            {
                return Err(malformed("Policy has invalid resource"));
            }
        }
    }
    mws_iam_policy::Policy::parse(policy, mws_iam_policy::PolicyKind::Resource).map_err(|e| malformed(&e.0))?;
    Ok(())
}

/// Scopes name up to ten prefixes (each at most 256 characters, `*` only
/// at the end) and S3's object and listing permissions.
fn check_scope(scope: &types::Scope) -> Result<(), ServiceError> {
    const PERMISSIONS: &[&str] = &[
        "GetObject",
        "GetObjectAttributes",
        "ListMultipartUploadParts",
        "ListBucket",
        "ListBucketMultipartUploads",
        "PutObject",
        "DeleteObject",
        "AbortMultipartUpload",
    ];
    let prefixes = scope.prefixes.as_deref().unwrap_or_default();
    if prefixes.len() > 10 {
        return Err(invalid("A scope can have at most 10 prefixes"));
    }
    for p in prefixes {
        let star = p.find('*');
        if p.is_empty() || p.len() > 256 || star.is_some_and(|i| i != p.len() - 1) {
            return Err(invalid(format!("Invalid prefix in scope: {p}")));
        }
    }
    for p in scope.permissions.as_deref().unwrap_or_default() {
        if !PERMISSIONS.contains(&p.as_str()) {
            return Err(invalid(format!("Invalid permission in scope: {p}")));
        }
    }
    Ok(())
}

fn paginate<T: Clone>(items: &[T], token: Option<&str>, max: i32) -> (Vec<T>, Option<String>) {
    let start = token.and_then(|t| t.parse::<usize>().ok()).unwrap_or(0).min(items.len());
    let max = if max <= 0 { 1000 } else { max.min(1000) as usize };
    let end = (start + max).min(items.len());
    (items[start..end].to_vec(), (end < items.len()).then(|| end.to_string()))
}

impl S3Control {
    fn find_ap(&self, account: &str, name: &str) -> Result<AccessPoint, ServiceError> {
        let name = short_name(name);
        self.read()
            .access_points
            .values()
            .find(|a| a.account_id == account && a.name == name)
            .cloned()
            .ok_or_else(no_such_access_point)
    }

    fn find_olap(&self, account: &str, name: &str) -> Result<ObjectLambda, ServiceError> {
        let name = short_name(name);
        self.read()
            .object_lambdas
            .values()
            .find(|a| a.account_id == account && a.name == name)
            .cloned()
            .ok_or_else(no_such_access_point)
    }

    fn account_pab(&self, account: &str) -> types::PublicAccessBlockConfiguration {
        self.read().public_access_blocks.get(account).cloned().unwrap_or_default()
    }

    fn block_public_policy(
        &self,
        ctx: &RequestContext,
        ap: bool,
        account: &str,
        policy: &str,
        arn: &str,
        action: &str,
    ) -> Result<(), ServiceError> {
        if ap && mws_s3::policy_is_public(policy) {
            return Err(mws_core::ServiceError::client(
                "AccessDenied",
                403,
                format!(
                    "User: {} is not authorized to perform: {action} on resource: \"{arn}\" because public policies are blocked by the BlockPublicPolicy block public access setting.",
                    ctx.caller.arn
                ),
            ));
        }
        let _ = account;
        Ok(())
    }

    // ---- access points ---------------------------------------------------

    pub fn create_access_point(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessPointRequest,
    ) -> Result<types::CreateAccessPointResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        let arn = ap_arn(ctx, &account, &input.name);
        let tags = input.tags.clone().unwrap_or_default();
        let mut c = tags_context(&tags);
        c.insert("s3:DataAccessPointAccount".into(), vec![account.clone()]);
        ctx.authorize("s3:CreateAccessPoint", &arn, c)?;
        check_name(&input.name)?;
        let directory = input.bucket.ends_with("--x-s3");
        if directory {
            // `name--usw2-az1--xa-s3` for bucket `bucket--usw2-az1--x-s3`.
            let zone = input.bucket.trim_end_matches("--x-s3").rsplit_once("--").map(|(_, z)| z).unwrap_or_default();
            if zone.is_empty() || !input.name.ends_with(&format!("--{zone}--xa-s3")) {
                return Err(invalid(format!(
                    "The access point name must be suffixed with the zone ID of the directory bucket followed by --xa-s3 (--{zone}--xa-s3)."
                )));
            }
        } else if input.scope.is_some() {
            return Err(invalid("Scope is only supported for access points attached to directory buckets."));
        }
        if let Some(scope) = &input.scope {
            check_scope(scope)?;
        }
        let owner = match &self.s3 {
            Some(s3) => Some(
                s3.bucket_owner(&input.bucket)
                    .ok_or_else(|| err("NoSuchBucket", 404, "The specified bucket does not exist"))?,
            ),
            None => None,
        };
        let bucket_account = input.bucket_account_id.clone().or(owner.clone()).unwrap_or_else(|| account.clone());
        if owner.as_deref().is_some_and(|o| o != bucket_account) {
            return Err(err("AccessDenied", 403, "Access Denied"));
        }
        let mut st = self.write();
        if let Some(existing) = st.access_points.get(&arn) {
            let _ = existing;
            return Err(err(
                "AccessPointAlreadyOwnedByYou",
                409,
                "Your previous request to create the named accesspoint succeeded and you already own it.",
            ));
        }
        let alias =
            if directory { input.name.clone() } else { format!("{}-{}-s3alias", input.name, random_suffix(34)) };
        st.access_points.insert(
            arn.clone(),
            AccessPoint {
                name: input.name,
                arn: arn.clone(),
                account_id: account,
                region: ctx.region.clone(),
                bucket: input.bucket,
                bucket_account_id: bucket_account,
                alias: alias.clone(),
                vpc_id: input.vpc_configuration.map(|v| v.vpc_id),
                public_access_block: input.public_access_block_configuration,
                policy: None,
                created: Some(ctx.received_at),
                tags: tags.into_iter().map(|t| (t.key, t.value)).collect(),
                scope: input.scope,
            },
        );
        Ok(types::CreateAccessPointResult { access_point_arn: Some(arn), alias: Some(alias) })
    }

    pub fn get_access_point(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointRequest,
    ) -> Result<types::GetAccessPointResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize("s3:GetAccessPoint", &ap_arn(ctx, &account, short_name(&input.name)), ConditionContext::new())?;
        let ap = self.find_ap(&account, &input.name)?;
        let region = &ap.region;
        let endpoints = BTreeMap::from([
            ("ipv4".to_string(), format!("s3-accesspoint.{region}.amazonaws.com")),
            ("fips".to_string(), format!("s3-accesspoint-fips.{region}.amazonaws.com")),
            ("fips_dualstack".to_string(), format!("s3-accesspoint-fips.dualstack.{region}.amazonaws.com")),
            ("dualstack".to_string(), format!("s3-accesspoint.dualstack.{region}.amazonaws.com")),
        ]);
        Ok(types::GetAccessPointResult {
            name: Some(ap.name.clone()),
            bucket: Some(ap.bucket.clone()),
            network_origin: Some(ap.network_origin().to_string()),
            vpc_configuration: ap.vpc_id.clone().map(|vpc_id| types::VpcConfiguration { vpc_id }),
            public_access_block_configuration: Some(ap.pab()),
            creation_date: ap.created,
            alias: Some(ap.alias.clone()),
            access_point_arn: Some(ap.arn.clone()),
            endpoints: Some(endpoints),
            bucket_account_id: Some(ap.bucket_account_id.clone()),
            data_source_id: None,
            data_source_type: None,
        })
    }

    pub fn delete_access_point(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DeleteAccessPoint",
            &ap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let ap = self.find_ap(&account, &input.name)?;
        self.write().access_points.remove(&ap.arn);
        Ok(())
    }

    pub fn list_access_points(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsRequest,
    ) -> Result<types::ListAccessPointsResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListAccessPoints", "*", ConditionContext::new())?;
        let items: Vec<types::AccessPoint> = self
            .read()
            .access_points
            .values()
            .filter(|a| a.account_id == account && a.region == ctx.region && !a.directory())
            .filter(|a| input.bucket.as_deref().is_none_or(|b| a.bucket == b))
            .map(|a| types::AccessPoint {
                name: a.name.clone(),
                network_origin: a.network_origin().to_string(),
                vpc_configuration: a.vpc_id.clone().map(|vpc_id| types::VpcConfiguration { vpc_id }),
                bucket: a.bucket.clone(),
                access_point_arn: Some(a.arn.clone()),
                alias: Some(a.alias.clone()),
                bucket_account_id: Some(a.bucket_account_id.clone()),
                data_source_id: None,
                data_source_type: None,
            })
            .collect();
        let (page, next) = paginate(&items, input.next_token.as_deref(), input.max_results);
        Ok(types::ListAccessPointsResult { access_point_list: Some(page), next_token: next })
    }

    pub fn put_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointPolicyRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        let arn = ap_arn(ctx, &account, short_name(&input.name));
        ctx.authorize("s3:PutAccessPointPolicy", &arn, ConditionContext::new())?;
        let ap = self.find_ap(&account, &input.name)?;
        check_policy(&input.policy, &ap.arn)?;
        let block = ap.pab().block_public_policy || self.account_pab(&account).block_public_policy;
        self.block_public_policy(ctx, block, &account, &input.policy, &ap.arn, "s3:PutAccessPointPolicy")?;
        if let Some(a) = self.write().access_points.get_mut(&ap.arn) {
            a.policy = Some(input.policy);
        }
        Ok(())
    }

    pub fn get_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyRequest,
    ) -> Result<types::GetAccessPointPolicyResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetAccessPointPolicy",
            &ap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let ap = self.find_ap(&account, &input.name)?;
        Ok(types::GetAccessPointPolicyResult { policy: Some(ap.policy.ok_or_else(no_such_policy)?) })
    }

    pub fn delete_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointPolicyRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DeleteAccessPointPolicy",
            &ap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let ap = self.find_ap(&account, &input.name)?;
        if let Some(a) = self.write().access_points.get_mut(&ap.arn) {
            a.policy = None;
        }
        Ok(())
    }

    pub fn get_access_point_policy_status(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyStatusRequest,
    ) -> Result<types::GetAccessPointPolicyStatusResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetAccessPointPolicyStatus",
            &ap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let ap = self.find_ap(&account, &input.name)?;
        let policy = ap.policy.ok_or_else(no_such_policy)?;
        Ok(types::GetAccessPointPolicyStatusResult {
            policy_status: Some(types::PolicyStatus { is_public: mws_s3::policy_is_public(&policy) }),
        })
    }

    // ---- Object Lambda access points ---------------------------------------

    fn check_olap_configuration(
        &self,
        account: &str,
        c: &types::ObjectLambdaConfiguration,
    ) -> Result<(), ServiceError> {
        if c.transformation_configurations.is_empty() {
            return Err(invalid("TransformationConfigurations must not be empty."));
        }
        for t in &c.transformation_configurations {
            for a in &t.actions {
                if !matches!(a.as_str(), "GetObject" | "HeadObject" | "ListObjects" | "ListObjectsV2") {
                    return Err(invalid(format!("Invalid transformation action: {a}")));
                }
            }
        }
        for f in c.allowed_features.iter().flatten() {
            if !matches!(
                f.as_str(),
                "GetObject-Range" | "GetObject-PartNumber" | "HeadObject-Range" | "HeadObject-PartNumber"
            ) {
                return Err(invalid(format!("Invalid allowed feature: {f}")));
            }
        }
        let supporting = &c.supporting_access_point;
        let name = short_name(supporting);
        let exists = self.read().access_points.values().any(|a| {
            (a.arn == *supporting || (!supporting.starts_with("arn:") && a.name == name)) && a.account_id == account
        });
        if !exists {
            return Err(invalid("The supporting access point does not exist."));
        }
        Ok(())
    }

    fn normalize_supporting(
        &self,
        account: &str,
        mut c: types::ObjectLambdaConfiguration,
    ) -> types::ObjectLambdaConfiguration {
        if !c.supporting_access_point.starts_with("arn:") {
            if let Some(a) = self
                .read()
                .access_points
                .values()
                .find(|a| a.account_id == account && a.name == c.supporting_access_point)
            {
                c.supporting_access_point = a.arn.clone();
            }
        }
        c
    }

    pub fn create_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessPointForObjectLambdaRequest,
    ) -> Result<types::CreateAccessPointForObjectLambdaResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        let arn = olap_arn(ctx, &account, &input.name);
        ctx.authorize("s3:CreateAccessPointForObjectLambda", &arn, ConditionContext::new())?;
        check_name(&input.name)?;
        if input.name.len() > 45 {
            return Err(invalid("Your Access Point name is invalid"));
        }
        self.check_olap_configuration(&account, &input.configuration)?;
        let configuration = self.normalize_supporting(&account, input.configuration);
        let mut st = self.write();
        if st.object_lambdas.contains_key(&arn) {
            return Err(err(
                "AccessPointAlreadyOwnedByYou",
                409,
                "Your previous request to create the named accesspoint succeeded and you already own it.",
            ));
        }
        let alias = format!("{}-{}--ol-s3", input.name, random_suffix(34));
        st.object_lambdas.insert(
            arn.clone(),
            ObjectLambda {
                name: input.name,
                arn: arn.clone(),
                account_id: account,
                region: ctx.region.clone(),
                alias: alias.clone(),
                configuration: Some(configuration),
                policy: None,
                created: Some(ctx.received_at),
            },
        );
        Ok(types::CreateAccessPointForObjectLambdaResult {
            object_lambda_access_point_arn: Some(arn),
            alias: Some(types::ObjectLambdaAccessPointAlias { value: Some(alias), status: Some("READY".into()) }),
        })
    }

    pub fn get_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointForObjectLambdaResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetAccessPointForObjectLambda",
            &olap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let o = self.find_olap(&account, &input.name)?;
        Ok(types::GetAccessPointForObjectLambdaResult {
            name: Some(o.name),
            public_access_block_configuration: Some(types::PublicAccessBlockConfiguration {
                block_public_acls: true,
                ignore_public_acls: true,
                block_public_policy: true,
                restrict_public_buckets: true,
            }),
            creation_date: o.created,
            alias: Some(types::ObjectLambdaAccessPointAlias { value: Some(o.alias), status: Some("READY".into()) }),
        })
    }

    pub fn delete_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DeleteAccessPointForObjectLambda",
            &olap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let o = self.find_olap(&account, &input.name)?;
        self.write().object_lambdas.remove(&o.arn);
        Ok(())
    }

    pub fn list_access_points_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsForObjectLambdaRequest,
    ) -> Result<types::ListAccessPointsForObjectLambdaResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListAccessPointsForObjectLambda", "*", ConditionContext::new())?;
        let items: Vec<types::ObjectLambdaAccessPoint> = self
            .read()
            .object_lambdas
            .values()
            .filter(|o| o.account_id == account && o.region == ctx.region)
            .map(|o| types::ObjectLambdaAccessPoint {
                name: o.name.clone(),
                object_lambda_access_point_arn: Some(o.arn.clone()),
                alias: Some(types::ObjectLambdaAccessPointAlias {
                    value: Some(o.alias.clone()),
                    status: Some("READY".into()),
                }),
            })
            .collect();
        let (page, next) = paginate(&items, input.next_token.as_deref(), input.max_results);
        Ok(types::ListAccessPointsForObjectLambdaResult {
            object_lambda_access_point_list: Some(page),
            next_token: next,
        })
    }

    pub fn put_access_point_configuration_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointConfigurationForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:PutAccessPointConfigurationForObjectLambda",
            &olap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let o = self.find_olap(&account, &input.name)?;
        self.check_olap_configuration(&account, &input.configuration)?;
        let configuration = self.normalize_supporting(&account, input.configuration);
        if let Some(x) = self.write().object_lambdas.get_mut(&o.arn) {
            x.configuration = Some(configuration);
        }
        Ok(())
    }

    pub fn get_access_point_configuration_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointConfigurationForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointConfigurationForObjectLambdaResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetAccessPointConfigurationForObjectLambda",
            &olap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let o = self.find_olap(&account, &input.name)?;
        Ok(types::GetAccessPointConfigurationForObjectLambdaResult { configuration: o.configuration })
    }

    pub fn put_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        let arn = olap_arn(ctx, &account, short_name(&input.name));
        ctx.authorize("s3:PutAccessPointPolicyForObjectLambda", &arn, ConditionContext::new())?;
        let o = self.find_olap(&account, &input.name)?;
        check_policy(&input.policy, &o.arn)?;
        // Object Lambda access points always block public access.
        self.block_public_policy(ctx, true, &account, &input.policy, &o.arn, "s3:PutAccessPointPolicyForObjectLambda")?;
        if let Some(x) = self.write().object_lambdas.get_mut(&o.arn) {
            x.policy = Some(input.policy);
        }
        Ok(())
    }

    pub fn get_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointPolicyForObjectLambdaResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetAccessPointPolicyForObjectLambda",
            &olap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let o = self.find_olap(&account, &input.name)?;
        Ok(types::GetAccessPointPolicyForObjectLambdaResult { policy: Some(o.policy.ok_or_else(no_such_policy)?) })
    }

    pub fn delete_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DeleteAccessPointPolicyForObjectLambda",
            &olap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let o = self.find_olap(&account, &input.name)?;
        if let Some(x) = self.write().object_lambdas.get_mut(&o.arn) {
            x.policy = None;
        }
        Ok(())
    }

    pub fn get_access_point_policy_status_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyStatusForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointPolicyStatusForObjectLambdaResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetAccessPointPolicyStatusForObjectLambda",
            &olap_arn(ctx, &account, short_name(&input.name)),
            ConditionContext::new(),
        )?;
        let o = self.find_olap(&account, &input.name)?;
        let policy = o.policy.ok_or_else(no_such_policy)?;
        Ok(types::GetAccessPointPolicyStatusForObjectLambdaResult {
            policy_status: Some(types::PolicyStatus { is_public: mws_s3::policy_is_public(&policy) }),
        })
    }

    // ---- account Block Public Access ---------------------------------------

    pub fn put_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::PutPublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize("s3:PutAccountPublicAccessBlock", "*", ConditionContext::new())?;
        self.write().public_access_blocks.insert(account, input.public_access_block_configuration);
        Ok(())
    }

    pub fn get_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::GetPublicAccessBlockRequest,
    ) -> Result<types::GetPublicAccessBlockOutput, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize("s3:GetAccountPublicAccessBlock", "*", ConditionContext::new())?;
        let c = self.read().public_access_blocks.get(&account).cloned().ok_or_else(|| {
            err("NoSuchPublicAccessBlockConfiguration", 404, "The public access block configuration was not found")
        })?;
        Ok(types::GetPublicAccessBlockOutput { public_access_block_configuration: Some(c) })
    }

    pub fn delete_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::DeletePublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize("s3:PutAccountPublicAccessBlock", "*", ConditionContext::new())?;
        self.write().public_access_blocks.remove(&account);
        Ok(())
    }

    // ---- tags --------------------------------------------------------------

    fn with_tags<R>(&self, arn: &str, f: impl FnOnce(&mut BTreeMap<String, String>) -> R) -> Result<R, ServiceError> {
        // Access Grants resources and Storage Lens groups keep their tags
        // beside them.
        let other = self.access_grants_resource_exists(arn) || self.storage_lens_group_exists(arn);
        let mut st = self.write();
        if other {
            return Ok(f(st.resource_tags.entry(arn.to_string()).or_default()));
        }
        match st.access_points.get_mut(arn) {
            Some(a) => Ok(f(&mut a.tags)),
            None => Err(no_such_access_point()),
        }
    }

    // ---- directory bucket access points --------------------------------------

    pub fn list_access_points_for_directory_buckets(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsForDirectoryBucketsRequest,
    ) -> Result<types::ListAccessPointsForDirectoryBucketsResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        ctx.authorize("s3express:ListAccessPointsForDirectoryBuckets", "*", ConditionContext::new())?;
        let items: Vec<types::AccessPoint> = self
            .read()
            .access_points
            .values()
            .filter(|a| a.account_id == account && a.region == ctx.region && a.directory())
            .filter(|a| input.directory_bucket.as_deref().is_none_or(|b| a.bucket == b))
            .map(|a| types::AccessPoint {
                name: a.name.clone(),
                network_origin: a.network_origin().to_string(),
                vpc_configuration: a.vpc_id.clone().map(|vpc_id| types::VpcConfiguration { vpc_id }),
                bucket: a.bucket.clone(),
                access_point_arn: Some(a.arn.clone()),
                alias: Some(a.alias.clone()),
                bucket_account_id: Some(a.bucket_account_id.clone()),
                data_source_id: None,
                data_source_type: None,
            })
            .collect();
        let (page, next) = paginate(&items, input.next_token.as_deref(), input.max_results);
        Ok(types::ListAccessPointsForDirectoryBucketsResult { access_point_list: Some(page), next_token: next })
    }

    fn directory_ap(&self, account: &str, name: &str) -> Result<AccessPoint, ServiceError> {
        let ap = self.find_ap(account, name)?;
        if !ap.directory() {
            return Err(invalid("Scope is only supported for access points attached to directory buckets."));
        }
        Ok(ap)
    }

    pub fn put_access_point_scope(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointScopeRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        let arn = ap_arn(ctx, &account, short_name(&input.name));
        ctx.authorize("s3express:PutAccessPointScope", &arn, ConditionContext::new())?;
        check_scope(&input.scope)?;
        let ap = self.directory_ap(&account, &input.name)?;
        if let Some(a) = self.write().access_points.get_mut(&ap.arn) {
            a.scope = Some(input.scope);
        }
        Ok(())
    }

    pub fn get_access_point_scope(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointScopeRequest,
    ) -> Result<types::GetAccessPointScopeResult, ServiceError> {
        let account = account(ctx, &input.account_id)?;
        let arn = ap_arn(ctx, &account, short_name(&input.name));
        ctx.authorize("s3express:GetAccessPointScope", &arn, ConditionContext::new())?;
        let ap = self.directory_ap(&account, &input.name)?;
        Ok(types::GetAccessPointScopeResult { scope: Some(ap.scope.unwrap_or_default()) })
    }

    pub fn delete_access_point_scope(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointScopeRequest,
    ) -> Result<(), ServiceError> {
        let account = account(ctx, &input.account_id)?;
        let arn = ap_arn(ctx, &account, short_name(&input.name));
        ctx.authorize("s3express:DeleteAccessPointScope", &arn, ConditionContext::new())?;
        let ap = self.directory_ap(&account, &input.name)?;
        if let Some(a) = self.write().access_points.get_mut(&ap.arn) {
            a.scope = None;
        }
        Ok(())
    }

    pub fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResult, ServiceError> {
        account(ctx, &input.account_id)?;
        ctx.authorize("s3:TagResource", &input.resource_arn, tags_context(&input.tags))?;
        let tags = input.tags;
        self.with_tags(&input.resource_arn, |t| {
            for tag in tags {
                t.insert(tag.key, tag.value);
            }
            if t.len() > 50 {
                return Err(invalid("Object tags cannot be greater than 50"));
            }
            Ok(())
        })??;
        Ok(types::TagResourceResult {})
    }

    pub fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResult, ServiceError> {
        account(ctx, &input.account_id)?;
        let mut c = ConditionContext::new();
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("s3:UntagResource", &input.resource_arn, c)?;
        self.with_tags(&input.resource_arn, |t| {
            for k in &input.tag_keys {
                t.remove(k);
            }
        })?;
        Ok(types::UntagResourceResult {})
    }

    pub fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResult, ServiceError> {
        account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListTagsForResource", &input.resource_arn, ConditionContext::new())?;
        let tags = self.with_tags(&input.resource_arn, |t| t.clone())?;
        Ok(types::ListTagsForResourceResult {
            tags: Some(tags.into_iter().map(|(key, value)| types::Tag { key, value }).collect()),
        })
    }
}
