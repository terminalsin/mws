//! Fargate profiles: which pods run on Fargate, in which subnets, as which
//! pod execution role.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::durations;
use crate::util::{self, text};
use crate::Eks;

/// Service Quotas: Fargate profiles per cluster.
const FARGATE_PROFILES_QUOTA: &str = "L-33415657";

fn not_found(cluster: &str, name: &str) -> ServiceError {
    errors::resource_not_found(format!("No Fargate Profile found with name: {name}."))
        .with_field("clusterName", text(cluster))
        .with_field("fargateProfileName", text(name))
}

impl Eks {
    pub(crate) async fn create_fargate_profile(
        &self,
        ctx: &RequestContext,
        input: types::CreateFargateProfileRequest,
    ) -> Result<types::CreateFargateProfileResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.fargate_profile_name.clone();
        let cluster_arn = util::cluster_arn(ctx, &cluster);
        let max_profiles = self.quota(ctx, FARGATE_PROFILES_QUOTA);
        let (cluster_subnets, vpc_id) = {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            util::authorize(
                ctx,
                "CreateFargateProfile",
                &cluster_arn,
                rec.cluster.tags.as_ref(),
                input.tags.as_ref(),
                ConditionContext::new(),
            )?;
            if rec.registered {
                return Err(errors::invalid_request("Fargate profiles are not supported on registered clusters.")
                    .with_field("clusterName", text(&cluster)));
            }
            if rec.fargate_profiles.contains_key(&name) {
                return Err(errors::invalid_parameter(format!(
                    "A Fargate Profile already exists with this name in the cluster: {name}."
                ))
                .with_field("clusterName", text(&cluster))
                .with_field("fargateProfileName", text(&name)));
            }
            if rec.fargate_profiles.len() >= max_profiles {
                return Err(errors::resource_limit_exceeded(format!(
                    "You have reached the limit of {max_profiles} Fargate profiles for cluster {cluster}."
                ))
                .with_field("clusterName", text(&cluster)));
            }
            if rec.fargate_profiles.values().any(|f| matches!(f.status.as_deref(), Some("CREATING" | "DELETING"))) {
                return Err(errors::resource_limit_exceeded(
                    "Only one Fargate Profile can be in CREATING or DELETING status at a time.",
                )
                .with_field("clusterName", text(&cluster)));
            }
            let vpc = rec.cluster.resources_vpc_config.as_ref();
            (vpc.and_then(|v| v.subnet_ids.clone()).unwrap_or_default(), vpc.and_then(|v| v.vpc_id.clone()))
        };
        util::check_create_tags(input.tags.as_ref())?;
        let selectors = input.selectors.clone().unwrap_or_default();
        if selectors.is_empty() {
            return Err(errors::invalid_parameter("Fargate Profile must have at least one selector."));
        }
        if selectors.len() > 5 {
            return Err(errors::invalid_parameter("A Fargate Profile can have at most 5 selectors."));
        }
        if selectors.iter().any(|s| s.namespace.as_deref().unwrap_or_default().is_empty()) {
            return Err(errors::invalid_parameter("Each Fargate Profile selector must specify a namespace."));
        }
        let role = input.pod_execution_role_arn.clone();
        self.check_role(
            ctx,
            &role,
            "eks-fargate-pods.amazonaws.com",
            || format!("The role with name {} cannot be found.", util::arn_name(&role)),
            || format!("Pod execution role {role} must trust eks-fargate-pods.amazonaws.com."),
        )?;
        let subnets = input.subnets.clone().unwrap_or(cluster_subnets);
        if let Some(facts) = self.subnet_facts(ctx, &subnets).await? {
            if let Some(vpc) = &vpc_id {
                if let Some(s) = facts.iter().find(|s| &s.vpc_id != vpc) {
                    return Err(errors::invalid_parameter(format!(
                        "Subnet {} is not in the cluster VPC {vpc}.",
                        s.subnet_id
                    )));
                }
            }
        }
        let profile = types::FargateProfile {
            fargate_profile_name: Some(name.clone()),
            fargate_profile_arn: Some(util::arn(ctx, &format!("fargateprofile/{cluster}/{name}/{}", util::uuid()))),
            cluster_name: Some(cluster.clone()),
            created_at: Some(ctx.received_at),
            pod_execution_role_arn: Some(role.clone()),
            subnets: Some(subnets),
            selectors: Some(selectors),
            status: Some("CREATING".into()),
            tags: Some(input.tags.clone().unwrap_or_default()),
            health: Some(types::FargateProfileHealth { issues: Some(Vec::new()) }),
        };
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &cluster)?;
        crate::access::ensure_node_entry(ctx, rec, &cluster, &role, "FARGATE_LINUX");
        rec.begin(format!("fargate/{name}"), ctx.received_at, durations::FARGATE_PROFILE);
        rec.fargate_profiles.insert(name, profile.clone());
        Ok(types::CreateFargateProfileResponse { fargate_profile: Some(profile) })
    }

    pub(crate) async fn describe_fargate_profile(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFargateProfileRequest,
    ) -> Result<types::DescribeFargateProfileResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let f = rec
            .fargate_profiles
            .get(&input.fargate_profile_name)
            .ok_or_else(|| not_found(&input.cluster_name, &input.fargate_profile_name))?;
        util::authorize(
            ctx,
            "DescribeFargateProfile",
            f.fargate_profile_arn.as_deref().unwrap_or_default(),
            f.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribeFargateProfileResponse { fargate_profile: Some(f.clone()) })
    }

    pub(crate) async fn list_fargate_profiles(
        &self,
        ctx: &RequestContext,
        input: types::ListFargateProfilesRequest,
    ) -> Result<types::ListFargateProfilesResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "ListFargateProfiles", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let names: Vec<String> = rec.fargate_profiles.keys().cloned().collect();
        let (items, next) = util::page(&names, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListFargateProfilesResponse { fargate_profile_names: Some(items), next_token: next })
    }

    pub(crate) async fn delete_fargate_profile(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFargateProfileRequest,
    ) -> Result<types::DeleteFargateProfileResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let f = rec
            .fargate_profiles
            .get_mut(&input.fargate_profile_name)
            .ok_or_else(|| not_found(&input.cluster_name, &input.fargate_profile_name))?;
        util::authorize(
            ctx,
            "DeleteFargateProfile",
            f.fargate_profile_arn.as_deref().unwrap_or_default(),
            f.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        f.status = Some("DELETING".into());
        let response = f.clone();
        rec.begin(format!("fargate/{}", input.fargate_profile_name), ctx.received_at, durations::FARGATE_PROFILE);
        Ok(types::DeleteFargateProfileResponse { fargate_profile: Some(response) })
    }
}
