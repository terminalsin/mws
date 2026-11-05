//! Trails: create, describe, update and delete them, start and stop
//! logging, and their event, Insights and event configuration selectors.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, not_found_trail, parse_arn, trail_arn, validate_trail_name};
use crate::resources::check_tags;
use crate::selectors;
use crate::state::{State, Trail};
use crate::CloudTrail;

const PRINCIPAL: &str = "cloudtrail.amazonaws.com";
const MAX_TRAILS_PER_REGION: usize = 5;

/// What a trail's settings resolve to, after checking them.
struct Settings {
    s3_bucket_name: String,
    s3_key_prefix: Option<String>,
    sns_topic_name: Option<String>,
    sns_topic_arn: Option<String>,
    cw_group: Option<String>,
    cw_role: Option<String>,
    kms_key_id: Option<String>,
    organization_id: Option<String>,
}

fn opt(s: &Option<String>) -> Option<String> {
    s.clone().filter(|s| !s.is_empty())
}

fn trail_view(t: &Trail) -> types::Trail {
    types::Trail {
        name: Some(t.name.clone()),
        s3_bucket_name: Some(t.s3_bucket_name.clone()),
        s3_key_prefix: t.s3_key_prefix.clone(),
        sns_topic_name: t.sns_topic_name.clone(),
        sns_topic_arn: t.sns_topic_arn.clone(),
        include_global_service_events: Some(t.include_global_service_events),
        is_multi_region_trail: Some(t.is_multi_region_trail),
        home_region: Some(t.home_region.clone()),
        trail_arn: Some(t.arn.clone()),
        log_file_validation_enabled: Some(t.log_file_validation_enabled),
        cloud_watch_logs_log_group_arn: t.cloud_watch_logs_log_group_arn.clone(),
        cloud_watch_logs_role_arn: t.cloud_watch_logs_role_arn.clone(),
        kms_key_id: t.kms_key_id.clone(),
        has_custom_event_selectors: Some(t.has_custom_event_selectors()),
        has_insight_selectors: Some(!t.insight_selectors.is_empty()),
        is_organization_trail: Some(t.is_organization_trail),
        ..Default::default()
    }
}

impl CloudTrail {
    /// Find the trail a `Name` parameter (a name or an ARN) means, as seen
    /// from the caller's account and Region. Returns its owner and ARN.
    pub(crate) fn find_trail(
        &self,
        st: &State,
        ctx: &RequestContext,
        name: &str,
    ) -> Result<(String, String), ServiceError> {
        let caller = &ctx.caller.account_id;
        let org = self.organization(caller).map(|o| o.organization_id);
        let visible = |owner: &str, t: &Trail| {
            owner == caller || (t.is_organization_trail && org.is_some() && t.organization_id == org)
        };
        if name.starts_with("arn:") {
            let arn = parse_arn(name)
                .filter(|a| a.kind == "trail")
                .ok_or_else(|| errors::cloud_trail_arn_invalid(format!("Invalid trail ARN: {name}")))?;
            let found = st
                .accounts
                .get(&arn.account)
                .and_then(|a| a.trails.get(name))
                .filter(|t| visible(&arn.account, t))
                .filter(|t| t.home_region == ctx.region || t.is_multi_region_trail);
            return match found {
                Some(_) => Ok((arn.account, name.to_string())),
                None => Err(not_found_trail(name, caller)),
            };
        }
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
            validate_trail_name(name)?;
        }
        let mut best: Option<(String, String, bool)> = None;
        for (owner, account) in &st.accounts {
            for t in account.trails.values() {
                if t.name != name || !visible(owner, t) {
                    continue;
                }
                let home = t.home_region == ctx.region;
                if !(home || t.is_multi_region_trail) {
                    continue;
                }
                let own = owner == caller;
                if best.as_ref().is_none_or(|(_, _, b_own)| own && !b_own) || home {
                    best = Some((owner.clone(), t.arn.clone(), own));
                }
            }
        }
        best.map(|(o, a, _)| (o, a)).ok_or_else(|| not_found_trail(&trail_arn(ctx, &ctx.region, caller, name), caller))
    }

    /// Like [`CloudTrail::find_trail`], for changes: the caller must own
    /// the trail and call from its home Region.
    fn find_own_trail(&self, st: &State, ctx: &RequestContext, name: &str) -> Result<String, ServiceError> {
        let (owner, arn) = self.find_trail(st, ctx, name)?;
        if owner != ctx.caller.account_id {
            return Err(errors::not_organization_master_account(
                "The request was rejected because the account is not the management account of the organization.",
            ));
        }
        let t = &st.accounts[&owner].trails[&arn];
        if t.home_region != ctx.region {
            return Err(errors::invalid_home_region("This operation must be called from the trail's home region"));
        }
        Ok(arn)
    }

    fn trail<'a>(st: &'a State, owner: &str, arn: &str) -> &'a Trail {
        &st.accounts[owner].trails[arn]
    }

    fn trail_mut<'a>(st: &'a mut State, owner: &str, arn: &str) -> &'a mut Trail {
        st.accounts.get_mut(owner).and_then(|a| a.trails.get_mut(arn)).expect("trail exists")
    }

    /// Check the destinations a trail is created or updated with, as AWS
    /// does before accepting them.
    #[allow(clippy::too_many_arguments)]
    fn check_settings(
        &self,
        ctx: &RequestContext,
        arn: &str,
        bucket: &str,
        prefix: Option<String>,
        sns: Option<String>,
        cw_group: Option<String>,
        cw_role: Option<String>,
        kms_key: Option<String>,
        organization: bool,
    ) -> Result<Settings, ServiceError> {
        let account = ctx.caller.account_id.clone();
        if bucket.is_empty() {
            return Err(errors::invalid_s3_bucket_name("S3 bucket name cannot be empty."));
        }
        if let Some(p) = &prefix {
            if p.len() > 200 {
                return Err(errors::invalid_s3_prefix("S3 prefix cannot be longer than 200 characters."));
            }
        }
        let organization_id = if organization {
            let org = self
                .organization(&account)
                .ok_or_else(|| errors::organizations_not_in_use("This account is not part of an organization."))?;
            let delegated = self
                .lock()
                .accounts
                .get(&org.management_account_id)
                .is_some_and(|a| a.delegated_admins.contains(&account));
            if !org.is_management(&account) && !delegated {
                return Err(errors::not_organization_master_account(
                    "The request was rejected because the account is not the management account of the organization.",
                ));
            }
            if !org.all_features {
                return Err(errors::organization_not_in_all_features_mode(
                    "This organization is in consolidated billing mode. All features must be enabled.",
                ));
            }
            if !org.trusted_services.iter().any(|s| s == PRINCIPAL) {
                return Err(errors::cloud_trail_access_not_enabled(
                    "This organization does not have CloudTrail service access enabled. Enable trusted access for CloudTrail in AWS Organizations.",
                ));
            }
            Some(org.organization_id)
        } else {
            None
        };
        // The bucket must exist and its policy must let CloudTrail write.
        if let Some(s3) = self.inner.s3.get() {
            let base = match prefix.as_deref().filter(|p| !p.is_empty()) {
                Some(p) => format!("{p}/AWSLogs/"),
                None => "AWSLogs/".to_string(),
            };
            let key = match &organization_id {
                Some(o) => format!("{base}{o}/{account}/CloudTrail/"),
                None => format!("{base}{account}/CloudTrail/"),
            };
            let put = mws_s3::ServicePutObject {
                bucket,
                key: &key,
                body: Vec::new(),
                content_type: "application/json",
                service_principal: PRINCIPAL,
                source_account: &account,
                source_arn: arn,
                acl: Some("bucket-owner-full-control"),
                partition: &ctx.partition,
            };
            match s3.check_service_access(&put, &["s3:GetBucketAcl", "s3:PutObject"]) {
                Ok(()) => {}
                Err(mws_s3::ServicePutError::NoSuchBucket) => {
                    return Err(errors::s3_bucket_does_not_exist(format!("S3 bucket {bucket} does not exist.")))
                }
                Err(_) => {
                    return Err(errors::insufficient_s3_bucket_policy(format!(
                        "Incorrect S3 bucket policy is detected for bucket: {bucket}"
                    )))
                }
            }
        }
        // An SNS topic, by name or ARN, whose policy lets CloudTrail publish.
        let (sns_topic_name, sns_topic_arn) = match sns {
            Some(t) => {
                let topic_arn = if t.starts_with("arn:") {
                    t.clone()
                } else {
                    format!("arn:{}:sns:{}:{account}:{t}", ctx.partition, ctx.region)
                };
                if let Some(sns) = self.inner.sns.get() {
                    let p = mws_sns::ServicePublish {
                        topic_arn: &topic_arn,
                        service_principal: PRINCIPAL,
                        source_arn: arn,
                        source_account: &account,
                        message: String::new(),
                        subject: None,
                        attributes: Default::default(),
                        message_group_id: None,
                        message_deduplication_id: None,
                    };
                    sns.check_service_publish(&p).map_err(|_| {
                        errors::insufficient_sns_topic_policy(
                            "SNS Topic does not exist or the topic policy is incorrect!",
                        )
                    })?;
                }
                (Some(t), Some(topic_arn))
            }
            None => (None, None),
        };
        // CloudWatch Logs needs both a log group and a role CloudTrail can
        // assume that may write to it; the caller must be able to pass it.
        let (cw_group, cw_role) = match (cw_group, cw_role) {
            (None, None) => (None, None),
            (Some(g), Some(r)) => {
                self.check_logs_role(ctx, arn, &g, &r)?;
                (Some(g), Some(r))
            }
            _ => {
                return Err(errors::invalid_parameter_combination("You must specify a log group and a role ARN."));
            }
        };
        let kms_key_id = match kms_key {
            Some(k) => Some(self.check_trail_key(arn, &account, bucket, &k)?),
            None => None,
        };
        Ok(Settings {
            s3_bucket_name: bucket.to_string(),
            s3_key_prefix: prefix,
            sns_topic_name,
            sns_topic_arn,
            cw_group,
            cw_role,
            kms_key_id,
            organization_id,
        })
    }

    fn check_logs_role(&self, ctx: &RequestContext, trail: &str, group: &str, role: &str) -> Result<(), ServiceError> {
        let parts: Vec<&str> = group.splitn(7, ':').collect();
        if parts.len() < 7 || parts[0] != "arn" || parts[2] != "logs" || parts[5] != "log-group" {
            return Err(errors::invalid_cloud_watch_logs_log_group_arn(format!(
                "CloudWatch Logs log group ARN {group} is not valid."
            )));
        }
        if !role.starts_with("arn:") || !role.contains(":role/") {
            return Err(errors::invalid_cloud_watch_logs_role_arn(format!("Role ARN {role} is not valid.")));
        }
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec![PRINCIPAL.into()]);
        ctx.authorize("iam:PassRole", role, pass)?;
        let denied = || {
            errors::invalid_cloud_watch_logs_role_arn(
                "Access denied. Verify in IAM that the role has adequate permissions.",
            )
        };
        let Some(sts) = self.inner.sts.get() else { return Ok(()) };
        let role_ctx = self.role_context(sts, ctx, role, trail).map_err(|_| denied())?;
        let name = parts[6].trim_end_matches(":*");
        let stream = format!(
            "arn:{}:logs:{}:{}:log-group:{name}:log-stream:{}_CloudTrail_{}",
            parts[1], parts[3], parts[4], ctx.caller.account_id, ctx.region
        );
        for action in ["logs:CreateLogStream", "logs:PutLogEvents"] {
            role_ctx.authorize(action, &stream, ConditionContext::new()).map_err(|_| denied())?;
        }
        Ok(())
    }

    /// A request context acting as `role`, assumed by CloudTrail for
    /// `source_arn`.
    pub(crate) fn role_context(
        &self,
        sts: &mws_sts::Sts,
        ctx: &RequestContext,
        role: &str,
        source_arn: &str,
    ) -> Result<RequestContext, String> {
        let account = parse_arn(source_arn).map(|a| a.account).unwrap_or_else(|| ctx.caller.account_id.clone());
        let creds = sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: role,
                service_principal: PRINCIPAL,
                session_name: "CloudTrail",
                duration_seconds: 900,
                source_account: Some(&account),
                source_arn: Some(source_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("{e:?}"))?;
        let resolved = sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .map_err(|e| format!("{e:?}"))?
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    /// Resolve a trail's KMS key to its ARN, checking that the key policy
    /// lets CloudTrail encrypt for this trail.
    fn check_trail_key(&self, trail: &str, account: &str, bucket: &str, key: &str) -> Result<String, ServiceError> {
        let Some(kms) = self.inner.kms.get() else { return Ok(key.to_string()) };
        let mut c = ConditionContext::new();
        c.insert("aws:SourceArn".into(), vec![trail.to_string()]);
        c.insert("aws:SourceAccount".into(), vec![account.to_string()]);
        c.insert("kms:EncryptionContext:aws:cloudtrail:arn".into(), vec![trail.to_string()]);
        match kms.key_for_service(key, PRINCIPAL, &["kms:GenerateDataKey"], &c) {
            Ok(k) => Ok(k.arn),
            Err(e) if e.code == "NotFoundException" => {
                Err(errors::kms_key_not_found(format!("KMS key {key} does not exist or is not accessible.")))
            }
            Err(e) if e.code == "DisabledException" => {
                Err(errors::kms_key_disabled(format!("KMS key {key} is disabled.")))
            }
            Err(_) => Err(errors::insufficient_encryption_policy(format!(
                "Insufficient permissions to access S3 bucket {bucket} or KMS key {key}."
            ))),
        }
    }

    pub(crate) fn create_trail(
        &self,
        ctx: &RequestContext,
        input: types::CreateTrailRequest,
    ) -> Result<types::CreateTrailResponse, ServiceError> {
        let account = ctx.caller.account_id.clone();
        let arn = trail_arn(ctx, &ctx.region, &account, &input.name);
        ctx.authorize("cloudtrail:CreateTrail", &arn, ConditionContext::new())?;
        validate_trail_name(&input.name)?;
        let multi = input.is_multi_region_trail.unwrap_or(false);
        let global = input.include_global_service_events.unwrap_or(true);
        if multi && !global {
            return Err(errors::invalid_parameter_combination(
                "Multi-Region trail must include global service events.",
            ));
        }
        let tags = input.tags_list.clone().unwrap_or_default();
        check_tags(&tags)?;
        {
            let st = self.lock();
            if let Some(a) = st.accounts.get(&account) {
                let here = |t: &&Trail| t.home_region == ctx.region || t.is_multi_region_trail;
                if a.trails.values().filter(here).any(|t| t.name == input.name) {
                    return Err(errors::trail_already_exists(format!(
                        "Trail {} already exists for customer: {account}",
                        input.name
                    )));
                }
                if a.trails.values().filter(here).count() >= MAX_TRAILS_PER_REGION {
                    return Err(errors::maximum_number_of_trails_exceeded(format!(
                        "User: {account} already has {MAX_TRAILS_PER_REGION} trails in {}.",
                        ctx.region
                    )));
                }
            }
        }
        let s = self.check_settings(
            ctx,
            &arn,
            &input.s3_bucket_name,
            opt(&input.s3_key_prefix),
            opt(&input.sns_topic_name),
            opt(&input.cloud_watch_logs_log_group_arn),
            opt(&input.cloud_watch_logs_role_arn),
            opt(&input.kms_key_id),
            input.is_organization_trail.unwrap_or(false),
        )?;
        let trail = Trail {
            name: input.name.clone(),
            arn: arn.clone(),
            account: account.clone(),
            home_region: ctx.region.clone(),
            s3_bucket_name: s.s3_bucket_name,
            s3_key_prefix: s.s3_key_prefix,
            sns_topic_name: s.sns_topic_name,
            sns_topic_arn: s.sns_topic_arn,
            include_global_service_events: global,
            is_multi_region_trail: multi,
            log_file_validation_enabled: input.enable_log_file_validation.unwrap_or(false),
            cloud_watch_logs_log_group_arn: s.cw_group,
            cloud_watch_logs_role_arn: s.cw_role,
            kms_key_id: s.kms_key_id,
            is_organization_trail: s.organization_id.is_some(),
            organization_id: s.organization_id,
            tags,
            ..Trail::default()
        };
        let out = trail_view(&trail);
        self.lock().account(&account).trails.insert(arn, trail);
        Ok(types::CreateTrailResponse {
            name: out.name,
            s3_bucket_name: out.s3_bucket_name,
            s3_key_prefix: out.s3_key_prefix,
            sns_topic_name: out.sns_topic_name,
            sns_topic_arn: out.sns_topic_arn,
            include_global_service_events: out.include_global_service_events,
            is_multi_region_trail: out.is_multi_region_trail,
            trail_arn: out.trail_arn,
            log_file_validation_enabled: out.log_file_validation_enabled,
            cloud_watch_logs_log_group_arn: out.cloud_watch_logs_log_group_arn,
            cloud_watch_logs_role_arn: out.cloud_watch_logs_role_arn,
            kms_key_id: out.kms_key_id,
            is_organization_trail: out.is_organization_trail,
            recursive_logging: None,
        })
    }

    pub(crate) fn update_trail(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTrailRequest,
    ) -> Result<types::UpdateTrailResponse, ServiceError> {
        let (arn, current) = {
            let st = self.lock();
            let arn = self.find_own_trail(&st, ctx, &input.name)?;
            let t = Self::trail(&st, &ctx.caller.account_id, &arn).clone();
            (arn, t)
        };
        ctx.authorize("cloudtrail:UpdateTrail", &arn, ConditionContext::new())?;
        let multi = input.is_multi_region_trail.unwrap_or(current.is_multi_region_trail);
        let global = input.include_global_service_events.unwrap_or(current.include_global_service_events);
        if multi && !global {
            return Err(errors::invalid_parameter_combination(
                "Multi-Region trail must include global service events.",
            ));
        }
        // An empty string clears an optional setting.
        let pick = |new: &Option<String>, old: &Option<String>| match new {
            Some(v) if v.is_empty() => None,
            Some(v) => Some(v.clone()),
            None => old.clone(),
        };
        let s = self.check_settings(
            ctx,
            &arn,
            input.s3_bucket_name.as_deref().filter(|b| !b.is_empty()).unwrap_or(&current.s3_bucket_name),
            pick(&input.s3_key_prefix, &current.s3_key_prefix),
            pick(&input.sns_topic_name, &current.sns_topic_name),
            pick(&input.cloud_watch_logs_log_group_arn, &current.cloud_watch_logs_log_group_arn),
            pick(&input.cloud_watch_logs_role_arn, &current.cloud_watch_logs_role_arn),
            pick(&input.kms_key_id, &current.kms_key_id),
            input.is_organization_trail.unwrap_or(current.is_organization_trail),
        )?;
        let mut st = self.lock();
        let t = Self::trail_mut(&mut st, &ctx.caller.account_id, &arn);
        t.s3_bucket_name = s.s3_bucket_name;
        t.s3_key_prefix = s.s3_key_prefix;
        t.sns_topic_name = s.sns_topic_name;
        t.sns_topic_arn = s.sns_topic_arn;
        t.cloud_watch_logs_log_group_arn = s.cw_group;
        t.cloud_watch_logs_role_arn = s.cw_role;
        t.kms_key_id = s.kms_key_id;
        t.is_organization_trail = s.organization_id.is_some();
        t.organization_id = s.organization_id;
        t.is_multi_region_trail = multi;
        t.include_global_service_events = global;
        if let Some(v) = input.enable_log_file_validation {
            t.log_file_validation_enabled = v;
        }
        let out = trail_view(t);
        Ok(types::UpdateTrailResponse {
            name: out.name,
            s3_bucket_name: out.s3_bucket_name,
            s3_key_prefix: out.s3_key_prefix,
            sns_topic_name: out.sns_topic_name,
            sns_topic_arn: out.sns_topic_arn,
            include_global_service_events: out.include_global_service_events,
            is_multi_region_trail: out.is_multi_region_trail,
            trail_arn: out.trail_arn,
            log_file_validation_enabled: out.log_file_validation_enabled,
            cloud_watch_logs_log_group_arn: out.cloud_watch_logs_log_group_arn,
            cloud_watch_logs_role_arn: out.cloud_watch_logs_role_arn,
            kms_key_id: out.kms_key_id,
            is_organization_trail: out.is_organization_trail,
            recursive_logging: None,
        })
    }

    pub(crate) fn delete_trail(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTrailRequest,
    ) -> Result<types::DeleteTrailResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_own_trail(&st, ctx, &input.name)?;
        ctx.authorize("cloudtrail:DeleteTrail", &arn, ConditionContext::new())?;
        st.account(&ctx.caller.account_id).trails.remove(&arn);
        Ok(types::DeleteTrailResponse {})
    }

    pub(crate) fn get_trail(
        &self,
        ctx: &RequestContext,
        input: types::GetTrailRequest,
    ) -> Result<types::GetTrailResponse, ServiceError> {
        let st = self.lock();
        let (owner, arn) = self.find_trail(&st, ctx, &input.name)?;
        ctx.authorize("cloudtrail:GetTrail", &arn, ConditionContext::new())?;
        Ok(types::GetTrailResponse { trail: Some(trail_view(Self::trail(&st, &owner, &arn))) })
    }

    /// Every trail the caller sees in its Region: its own, the shadows of
    /// its multi-Region trails, and its organization's trails.
    fn visible_trails(&self, st: &State, ctx: &RequestContext, shadows: bool) -> Vec<Trail> {
        let caller = &ctx.caller.account_id;
        let org = self.organization(caller).map(|o| o.organization_id);
        let mut out = Vec::new();
        for (owner, a) in &st.accounts {
            for t in a.trails.values() {
                let own = owner == caller;
                let org_trail = !own && t.is_organization_trail && org.is_some() && t.organization_id == org;
                if !own && !org_trail {
                    continue;
                }
                let home = t.home_region == ctx.region && own;
                if home || (shadows && (t.is_multi_region_trail || org_trail)) {
                    out.push(t.clone());
                }
            }
        }
        out
    }

    pub(crate) fn describe_trails(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTrailsRequest,
    ) -> Result<types::DescribeTrailsResponse, ServiceError> {
        ctx.authorize("cloudtrail:DescribeTrails", "*", ConditionContext::new())?;
        let st = self.lock();
        let shadows = input.include_shadow_trails.unwrap_or(true);
        let names = input.trail_name_list.unwrap_or_default();
        let trails: Vec<types::Trail> = if names.is_empty() {
            self.visible_trails(&st, ctx, shadows).iter().map(trail_view).collect()
        } else {
            let mut out = Vec::new();
            for n in &names {
                match self.find_trail(&st, ctx, n) {
                    Ok((owner, arn)) => {
                        let t = Self::trail(&st, &owner, &arn);
                        if shadows || t.home_region == ctx.region {
                            out.push(trail_view(t));
                        }
                    }
                    Err(e) if e.code == errors::TRAIL_NOT_FOUND => {}
                    Err(e) => return Err(e),
                }
            }
            out
        };
        Ok(types::DescribeTrailsResponse { trail_list: Some(trails) })
    }

    pub(crate) fn list_trails(
        &self,
        ctx: &RequestContext,
        input: types::ListTrailsRequest,
    ) -> Result<types::ListTrailsResponse, ServiceError> {
        ctx.authorize("cloudtrail:ListTrails", "*", ConditionContext::new())?;
        let st = self.lock();
        let caller = &ctx.caller.account_id;
        let org = self.organization(caller).map(|o| o.organization_id);
        let mut all: Vec<types::TrailInfo> = Vec::new();
        for (owner, a) in &st.accounts {
            for t in a.trails.values() {
                if owner == caller || (t.is_organization_trail && org.is_some() && t.organization_id == org) {
                    all.push(types::TrailInfo {
                        trail_arn: Some(t.arn.clone()),
                        name: Some(t.name.clone()),
                        home_region: Some(t.home_region.clone()),
                    });
                }
            }
        }
        let (trails, next) = names::page(&all, input.next_token.as_deref(), 50)?;
        Ok(types::ListTrailsResponse { trails: Some(trails), next_token: next })
    }

    pub(crate) fn get_trail_status(
        &self,
        ctx: &RequestContext,
        input: types::GetTrailStatusRequest,
    ) -> Result<types::GetTrailStatusResponse, ServiceError> {
        let st = self.lock();
        let (owner, arn) = self.find_trail(&st, ctx, &input.name)?;
        ctx.authorize("cloudtrail:GetTrailStatus", &arn, ConditionContext::new())?;
        let t = Self::trail(&st, &owner, &arn);
        let s = &t.status;
        let text = |d: &Option<chrono::DateTime<chrono::Utc>>| d.map(crate::record::time_string);
        Ok(types::GetTrailStatusResponse {
            is_logging: Some(t.is_logging),
            latest_delivery_error: s.latest_delivery_error.clone(),
            latest_notification_error: s.latest_notification_error.clone(),
            latest_delivery_time: s.latest_delivery_time,
            latest_notification_time: s.latest_notification_time,
            start_logging_time: t.start_logging_time,
            stop_logging_time: t.stop_logging_time,
            latest_cloud_watch_logs_delivery_error: s.latest_cloud_watch_logs_delivery_error.clone(),
            latest_cloud_watch_logs_delivery_time: s.latest_cloud_watch_logs_delivery_time,
            latest_digest_delivery_time: s.latest_digest_delivery_time,
            latest_digest_delivery_error: s.latest_digest_delivery_error.clone(),
            latest_delivery_attempt_time: Some(text(&s.latest_delivery_attempt_time).unwrap_or_default()),
            latest_notification_attempt_time: Some(text(&s.latest_notification_attempt_time).unwrap_or_default()),
            latest_notification_attempt_succeeded: Some(
                text(&s.latest_notification_attempt_succeeded).unwrap_or_default(),
            ),
            latest_delivery_attempt_succeeded: Some(text(&s.latest_delivery_attempt_succeeded).unwrap_or_default()),
            time_logging_started: Some(text(&t.start_logging_time).unwrap_or_default()),
            time_logging_stopped: Some(text(&t.stop_logging_time).unwrap_or_default()),
        })
    }

    pub(crate) fn start_logging(
        &self,
        ctx: &RequestContext,
        input: types::StartLoggingRequest,
    ) -> Result<types::StartLoggingResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_own_trail(&st, ctx, &input.name)?;
        ctx.authorize("cloudtrail:StartLogging", &arn, ConditionContext::new())?;
        let t = Self::trail_mut(&mut st, &ctx.caller.account_id, &arn);
        if !t.is_logging {
            t.is_logging = true;
            t.start_logging_time = Some(ctx.received_at);
        }
        Ok(types::StartLoggingResponse {})
    }

    pub(crate) fn stop_logging(
        &self,
        ctx: &RequestContext,
        input: types::StopLoggingRequest,
    ) -> Result<types::StopLoggingResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_own_trail(&st, ctx, &input.name)?;
        ctx.authorize("cloudtrail:StopLogging", &arn, ConditionContext::new())?;
        let t = Self::trail_mut(&mut st, &ctx.caller.account_id, &arn);
        if t.is_logging {
            t.is_logging = false;
            t.stop_logging_time = Some(ctx.received_at);
        }
        Ok(types::StopLoggingResponse {})
    }

    pub(crate) fn put_event_selectors(
        &self,
        ctx: &RequestContext,
        input: types::PutEventSelectorsRequest,
    ) -> Result<types::PutEventSelectorsResponse, ServiceError> {
        let mut st = self.lock();
        let arn = self.find_own_trail(&st, ctx, &input.trail_name)?;
        ctx.authorize("cloudtrail:PutEventSelectors", &arn, ConditionContext::new())?;
        match (&input.event_selectors, &input.advanced_event_selectors) {
            (Some(_), Some(_)) => {
                return Err(errors::invalid_parameter_combination(
                    "You cannot specify both EventSelectors and AdvancedEventSelectors in the same request.",
                ))
            }
            (None, None) => {
                return Err(errors::invalid_parameter_combination(
                    "You must specify either EventSelectors or AdvancedEventSelectors.",
                ))
            }
            (Some(b), None) => selectors::validate_basic(b)?,
            (None, Some(a)) => selectors::validate_advanced(a, true)?,
        }
        let t = Self::trail_mut(&mut st, &ctx.caller.account_id, &arn);
        t.event_selectors = input.event_selectors.clone();
        t.advanced_event_selectors = input.advanced_event_selectors.clone();
        Ok(types::PutEventSelectorsResponse {
            trail_arn: Some(arn),
            event_selectors: input.event_selectors,
            advanced_event_selectors: input.advanced_event_selectors,
        })
    }

    pub(crate) fn get_event_selectors(
        &self,
        ctx: &RequestContext,
        input: types::GetEventSelectorsRequest,
    ) -> Result<types::GetEventSelectorsResponse, ServiceError> {
        let st = self.lock();
        let (owner, arn) = self.find_trail(&st, ctx, &input.trail_name)?;
        ctx.authorize("cloudtrail:GetEventSelectors", &arn, ConditionContext::new())?;
        let t = Self::trail(&st, &owner, &arn);
        let (basic, advanced) = match (&t.event_selectors, &t.advanced_event_selectors) {
            (_, Some(a)) => (None, Some(a.clone())),
            (Some(b), None) => (Some(b.clone()), None),
            (None, None) => (Some(selectors::default_selectors()), None),
        };
        Ok(types::GetEventSelectorsResponse {
            trail_arn: Some(arn),
            event_selectors: basic,
            advanced_event_selectors: advanced,
        })
    }

    pub(crate) fn put_insight_selectors(
        &self,
        ctx: &RequestContext,
        input: types::PutInsightSelectorsRequest,
    ) -> Result<types::PutInsightSelectorsResponse, ServiceError> {
        for s in &input.insight_selectors {
            let t = s.insight_type.as_deref().unwrap_or_default();
            if !types::INSIGHT_TYPE.contains(&t) {
                return Err(errors::invalid_insight_selectors(format!("Insight type {t} is not valid.")));
            }
        }
        match (&input.trail_name, &input.event_data_store) {
            (Some(_), Some(_)) => Err(errors::invalid_parameter_combination(
                "You cannot specify both TrailName and EventDataStore in the same request.",
            )),
            (Some(name), None) => {
                let mut st = self.lock();
                let arn = self.find_own_trail(&st, ctx, name)?;
                ctx.authorize("cloudtrail:PutInsightSelectors", &arn, ConditionContext::new())?;
                let t = Self::trail_mut(&mut st, &ctx.caller.account_id, &arn);
                t.insight_selectors = input.insight_selectors.clone();
                Ok(types::PutInsightSelectorsResponse {
                    trail_arn: Some(arn),
                    insight_selectors: Some(input.insight_selectors),
                    ..Default::default()
                })
            }
            (None, Some(eds)) => {
                self.put_eds_insight_selectors(ctx, eds, input.insights_destination.as_deref(), input.insight_selectors)
            }
            (None, None) => {
                Err(errors::invalid_parameter_combination("You must specify either TrailName or EventDataStore."))
            }
        }
    }

    pub(crate) fn get_insight_selectors(
        &self,
        ctx: &RequestContext,
        input: types::GetInsightSelectorsRequest,
    ) -> Result<types::GetInsightSelectorsResponse, ServiceError> {
        match (&input.trail_name, &input.event_data_store) {
            (Some(_), Some(_)) => Err(errors::invalid_parameter_combination(
                "You cannot specify both TrailName and EventDataStore in the same request.",
            )),
            (Some(name), None) => {
                let st = self.lock();
                let (owner, arn) = self.find_trail(&st, ctx, name)?;
                ctx.authorize("cloudtrail:GetInsightSelectors", &arn, ConditionContext::new())?;
                let t = Self::trail(&st, &owner, &arn);
                if t.insight_selectors.is_empty() {
                    return Err(errors::insight_not_enabled(format!(
                        "Trail {} does not have Insights enabled. Enable Insights on the trail, and then try the operation again.",
                        t.name
                    )));
                }
                Ok(types::GetInsightSelectorsResponse {
                    trail_arn: Some(arn),
                    insight_selectors: Some(t.insight_selectors.clone()),
                    ..Default::default()
                })
            }
            (None, Some(eds)) => self.get_eds_insight_selectors(ctx, eds),
            (None, None) => {
                Err(errors::invalid_parameter_combination("You must specify either TrailName or EventDataStore."))
            }
        }
    }

    pub(crate) fn put_event_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutEventConfigurationRequest,
    ) -> Result<types::PutEventConfigurationResponse, ServiceError> {
        if let Some(sel) = &input.context_key_selectors {
            if sel.len() > 2 {
                return Err(errors::invalid_parameter("You can specify at most 2 context key selectors."));
            }
        }
        match (&input.trail_name, &input.event_data_store) {
            (Some(_), Some(_)) => Err(errors::invalid_parameter_combination(
                "You cannot specify both TrailName and EventDataStore in the same request.",
            )),
            (Some(name), None) => {
                let mut st = self.lock();
                let arn = self.find_own_trail(&st, ctx, name)?;
                ctx.authorize("cloudtrail:PutEventConfiguration", &arn, ConditionContext::new())?;
                let t = Self::trail_mut(&mut st, &ctx.caller.account_id, &arn);
                if input.max_event_size.is_some() {
                    t.max_event_size = input.max_event_size.clone();
                }
                if input.context_key_selectors.is_some() {
                    t.context_key_selectors = input.context_key_selectors.clone();
                }
                if input.aggregation_configurations.is_some() {
                    t.aggregation_configurations = input.aggregation_configurations.clone();
                }
                Ok(types::PutEventConfigurationResponse {
                    trail_arn: Some(arn),
                    event_data_store_arn: None,
                    max_event_size: t.max_event_size.clone(),
                    context_key_selectors: t.context_key_selectors.clone(),
                    aggregation_configurations: t.aggregation_configurations.clone(),
                })
            }
            (None, Some(eds)) => {
                let eds = eds.clone();
                self.put_eds_event_configuration(ctx, &eds, input)
            }
            (None, None) => {
                Err(errors::invalid_parameter_combination("You must specify either TrailName or EventDataStore."))
            }
        }
    }

    pub(crate) fn get_event_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetEventConfigurationRequest,
    ) -> Result<types::GetEventConfigurationResponse, ServiceError> {
        match (&input.trail_name, &input.event_data_store) {
            (Some(_), Some(_)) => Err(errors::invalid_parameter_combination(
                "You cannot specify both TrailName and EventDataStore in the same request.",
            )),
            (Some(name), None) => {
                let st = self.lock();
                let (owner, arn) = self.find_trail(&st, ctx, name)?;
                ctx.authorize("cloudtrail:GetEventConfiguration", &arn, ConditionContext::new())?;
                let t = Self::trail(&st, &owner, &arn);
                Ok(types::GetEventConfigurationResponse {
                    trail_arn: Some(arn),
                    event_data_store_arn: None,
                    max_event_size: Some(t.max_event_size.clone().unwrap_or_else(|| "Standard".into())),
                    context_key_selectors: t.context_key_selectors.clone(),
                    aggregation_configurations: t.aggregation_configurations.clone(),
                })
            }
            (None, Some(eds)) => self.get_eds_event_configuration(ctx, eds),
            (None, None) => {
                Err(errors::invalid_parameter_combination("You must specify either TrailName or EventDataStore."))
            }
        }
    }

    pub(crate) fn trail_tags_mut<'a>(
        &self,
        st: &'a mut State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<&'a mut Vec<types::Tag>, ServiceError> {
        let (owner, arn) = self.find_trail(st, ctx, arn)?;
        Ok(&mut Self::trail_mut(st, &owner, &arn).tags)
    }

    pub(crate) fn trail_tags(
        &self,
        st: &State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<Vec<types::Tag>, ServiceError> {
        let (owner, arn) = self.find_trail(st, ctx, arn)?;
        Ok(Self::trail(st, &owner, &arn).tags.clone())
    }
}
