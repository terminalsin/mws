//! Service-linked roles, and role templates (which only AWS publishes, so a
//! standalone MWS account has none).

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{DeletionTask, Role, State};
use crate::{ids, wire, Iam};

/// A service that can have a service-linked role: its principal, the role
/// name AWS gives it, the AWS managed policy attached to it, and whether
/// `CreateServiceLinkedRole` accepts a `CustomSuffix` for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlrSpec {
    pub principal: &'static str,
    pub role_name: &'static str,
    pub policy: &'static str,
    pub custom_suffix: bool,
}

const fn slr(principal: &'static str, role_name: &'static str, policy: &'static str) -> SlrSpec {
    SlrSpec { principal, role_name, policy, custom_suffix: false }
}

const fn slr_suffix(principal: &'static str, role_name: &'static str, policy: &'static str) -> SlrSpec {
    SlrSpec { principal, role_name, policy, custom_suffix: true }
}

/// Service-linked roles as AWS names them (IAM User Guide, "AWS services
/// that work with IAM", and each service's "Using service-linked roles").
const SERVICE_LINKED_ROLES: &[SlrSpec] = &[
    slr("access-analyzer.amazonaws.com", "AWSServiceRoleForAccessAnalyzer", "AccessAnalyzerServiceRolePolicy"),
    slr("acm.amazonaws.com", "AWSServiceRoleForCertificateManager", "CertificateManagerServiceRolePolicy"),
    slr("ops.apigateway.amazonaws.com", "AWSServiceRoleForAPIGateway", "APIGatewayServiceRolePolicy"),
    slr(
        "appstream.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_AppStreamFleet",
        "AWSApplicationAutoscalingAppStreamFleetPolicy",
    ),
    slr(
        "cassandra.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_CassandraTable",
        "AWSApplicationAutoscalingCassandraTablePolicy",
    ),
    slr(
        "comprehend.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_ComprehendEndpoint",
        "AWSApplicationAutoscalingComprehendEndpointPolicy",
    ),
    slr(
        "custom-resource.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_CustomResource",
        "AWSApplicationAutoScalingCustomResourcePolicy",
    ),
    slr(
        "dynamodb.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable",
        "AWSApplicationAutoscalingDynamoDBTablePolicy",
    ),
    slr(
        "ec2.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest",
        "AWSApplicationAutoscalingEC2SpotFleetRequestPolicy",
    ),
    slr(
        "ecs.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_ECSService",
        "AWSApplicationAutoscalingECSServicePolicy",
    ),
    slr(
        "elasticache.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_ElastiCacheRG",
        "AWSApplicationAutoscalingElastiCacheRGPolicy",
    ),
    slr(
        "kafka.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_KafkaCluster",
        "AWSApplicationAutoscalingKafkaClusterPolicy",
    ),
    slr(
        "lambda.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_LambdaConcurrency",
        "AWSApplicationAutoscalingLambdaConcurrencyPolicy",
    ),
    slr(
        "neptune.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_NeptuneCluster",
        "AWSApplicationAutoscalingNeptuneClusterPolicy",
    ),
    slr(
        "rds.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_RDSCluster",
        "AWSApplicationAutoscalingRDSClusterPolicy",
    ),
    slr(
        "sagemaker.application-autoscaling.amazonaws.com",
        "AWSServiceRoleForApplicationAutoScaling_SageMakerEndpoint",
        "AWSApplicationAutoscalingSageMakerEndpointPolicy",
    ),
    slr_suffix("autoscaling.amazonaws.com", "AWSServiceRoleForAutoScaling", "AutoScalingServiceRolePolicy"),
    slr("backup.amazonaws.com", "AWSServiceRoleForBackup", "AWSBackupServiceLinkedRolePolicyForBackup"),
    slr("cloud9.amazonaws.com", "AWSServiceRoleForAWSCloud9", "AWSCloud9ServiceRolePolicy"),
    slr("logger.cloudfront.amazonaws.com", "AWSServiceRoleForCloudFrontLogger", "AWSCloudFrontLogger"),
    slr("cloudtrail.amazonaws.com", "AWSServiceRoleForCloudTrail", "CloudTrailServiceRolePolicy"),
    slr("events.amazonaws.com", "AWSServiceRoleForCloudWatchEvents", "CloudWatchEventsServiceRolePolicy"),
    slr(
        "cloudwatch-crossaccount.amazonaws.com",
        "AWSServiceRoleForCloudWatchCrossAccount",
        "CloudWatch-CrossAccountAccess",
    ),
    slr("compute-optimizer.amazonaws.com", "AWSServiceRoleForComputeOptimizer", "ComputeOptimizerServiceRolePolicy"),
    slr("config.amazonaws.com", "AWSServiceRoleForConfig", "AWSConfigServiceRolePolicy"),
    slr("dax.amazonaws.com", "AWSServiceRoleForDAX", "AmazonDAXServiceRolePolicy"),
    slr("ec2fleet.amazonaws.com", "AWSServiceRoleForEC2Fleet", "AWSEC2FleetServiceRolePolicy"),
    slr("spot.amazonaws.com", "AWSServiceRoleForEC2Spot", "AWSEC2SpotServiceRolePolicy"),
    slr("spotfleet.amazonaws.com", "AWSServiceRoleForEC2SpotFleet", "AWSEC2SpotFleetServiceRolePolicy"),
    slr("transitgateway.amazonaws.com", "AWSServiceRoleForVPCTransitGateway", "AWSVPCTransitGatewayServiceRolePolicy"),
    slr("ecs.amazonaws.com", "AWSServiceRoleForECS", "AmazonECSServiceRolePolicy"),
    slr(
        "elasticfilesystem.amazonaws.com",
        "AWSServiceRoleForAmazonElasticFileSystem",
        "AmazonElasticFileSystemServiceRolePolicy",
    ),
    slr("eks.amazonaws.com", "AWSServiceRoleForAmazonEKS", "AmazonEKSServiceRolePolicy"),
    slr("eks-fargate.amazonaws.com", "AWSServiceRoleForAmazonEKSForFargate", "AmazonEKSForFargateServiceRolePolicy"),
    slr("eks-nodegroup.amazonaws.com", "AWSServiceRoleForAmazonEKSNodegroup", "AWSServiceRoleForAmazonEKSNodegroup"),
    slr("elasticache.amazonaws.com", "AWSServiceRoleForElastiCache", "ElastiCacheServiceRolePolicy"),
    slr_suffix(
        "elasticbeanstalk.amazonaws.com",
        "AWSServiceRoleForElasticBeanstalk",
        "AWSElasticBeanstalkServiceRolePolicy",
    ),
    slr(
        "elasticloadbalancing.amazonaws.com",
        "AWSServiceRoleForElasticLoadBalancing",
        "AWSElasticLoadBalancingServiceRolePolicy",
    ),
    slr("elasticmapreduce.amazonaws.com", "AWSServiceRoleForEMRCleanup", "AmazonEMRCleanupPolicy"),
    slr("es.amazonaws.com", "AWSServiceRoleForAmazonElasticsearchService", "AmazonElasticsearchServiceRolePolicy"),
    slr("fms.amazonaws.com", "AWSServiceRoleForFMS", "AWSFMSServiceRolePolicy"),
    slr("fsx.amazonaws.com", "AWSServiceRoleForAmazonFSx", "AmazonFSxServiceRolePolicy"),
    slr("globalaccelerator.amazonaws.com", "AWSServiceRoleForGlobalAccelerator", "AWSGlobalAcceleratorSLRPolicy"),
    slr("guardduty.amazonaws.com", "AWSServiceRoleForAmazonGuardDuty", "AmazonGuardDutyServiceRolePolicy"),
    slr(
        "malware-protection.guardduty.amazonaws.com",
        "AWSServiceRoleForAmazonGuardDutyMalwareProtection",
        "AmazonGuardDutyMalwareProtectionServiceRolePolicy",
    ),
    slr("imagebuilder.amazonaws.com", "AWSServiceRoleForImageBuilder", "AWSServiceRoleForImageBuilder"),
    slr("inspector2.amazonaws.com", "AWSServiceRoleForAmazonInspector2", "AmazonInspector2ServiceRolePolicy"),
    slr("kafka.amazonaws.com", "AWSServiceRoleForKafka", "KafkaServiceRolePolicy"),
    slr(
        "cks.kms.amazonaws.com",
        "AWSServiceRoleForKeyManagementServiceCustomKeyStores",
        "AWSKeyManagementServiceCustomKeyStoresServiceRolePolicy",
    ),
    slr(
        "mrk.kms.amazonaws.com",
        "AWSServiceRoleForKeyManagementServiceMultiRegionKeys",
        "AWSKeyManagementServiceMultiRegionKeysServiceRolePolicy",
    ),
    slr("replicator.lambda.amazonaws.com", "AWSServiceRoleForLambdaReplicator", "AWSLambdaReplicator"),
    slr("delivery.logs.amazonaws.com", "AWSServiceRoleForLogDelivery", "AWSLogDeliveryServiceRolePolicy"),
    slr("macie.amazonaws.com", "AWSServiceRoleForAmazonMacie", "AmazonMacieServiceRolePolicy"),
    slr(
        "opensearchservice.amazonaws.com",
        "AWSServiceRoleForAmazonOpenSearchService",
        "AmazonOpenSearchServiceRolePolicy",
    ),
    slr("organizations.amazonaws.com", "AWSServiceRoleForOrganizations", "AWSOrganizationsServiceTrustPolicy"),
    slr("ram.amazonaws.com", "AWSServiceRoleForResourceAccessManager", "AWSResourceAccessManagerServiceRolePolicy"),
    slr("rds.amazonaws.com", "AWSServiceRoleForRDS", "AmazonRDSServiceRolePolicy"),
    slr("redshift.amazonaws.com", "AWSServiceRoleForRedshift", "AmazonRedshiftServiceLinkedRolePolicy"),
    slr("route53resolver.amazonaws.com", "AWSServiceRoleForRoute53Resolver", "Route53ResolverServiceRolePolicy"),
    slr("storage-lens.s3.amazonaws.com", "AWSServiceRoleForS3StorageLens", "S3StorageLensServiceRolePolicy"),
    slr("securityhub.amazonaws.com", "AWSServiceRoleForSecurityHub", "AWSSecurityHubServiceRolePolicy"),
    slr("servicequotas.amazonaws.com", "AWSServiceRoleForServiceQuotas", "ServiceQuotasServiceRolePolicy"),
    slr("ssm.amazonaws.com", "AWSServiceRoleForAmazonSSM", "AmazonSSMServiceRolePolicy"),
    slr("sso.amazonaws.com", "AWSServiceRoleForSSO", "AWSSSOServiceRolePolicy"),
    slr("support.amazonaws.com", "AWSServiceRoleForSupport", "AWSSupportServiceRolePolicy"),
    slr("trustedadvisor.amazonaws.com", "AWSServiceRoleForTrustedAdvisor", "AWSTrustedAdvisorServiceRolePolicy"),
];

/// The service-linked role AWS defines for a service principal.
pub fn service_linked_role(principal: &str) -> Option<&'static SlrSpec> {
    SERVICE_LINKED_ROLES.iter().find(|s| s.principal == principal)
}

/// The role name MWS gave a service's role before it knew AWS's names: a
/// CamelCase of the principal (`AWSServiceRoleForSso`), with a few fixed
/// stems. Only used to rename roles in saved state.
pub(crate) fn legacy_name(service: &str) -> String {
    const KNOWN: &[(&str, &str)] = &[
        ("autoscaling.amazonaws.com", "AutoScaling"),
        ("elasticloadbalancing.amazonaws.com", "ElasticLoadBalancing"),
        ("ecs.amazonaws.com", "ECS"),
        ("eks.amazonaws.com", "AmazonEKS"),
        ("rds.amazonaws.com", "RDS"),
        ("organizations.amazonaws.com", "Organizations"),
        ("support.amazonaws.com", "Support"),
        ("trustedadvisor.amazonaws.com", "TrustedAdvisor"),
        ("config.amazonaws.com", "Config"),
        ("cloudtrail.amazonaws.com", "CloudTrail"),
        ("ssm.amazonaws.com", "AmazonSSM"),
        ("lambda.amazonaws.com", "Lambda"),
        ("guardduty.amazonaws.com", "AmazonGuardDuty"),
        ("route53resolver.amazonaws.com", "Route53Resolver"),
        ("acm.amazonaws.com", "CertificateManager"),
    ];
    let stem = match KNOWN.iter().find(|(svc, _)| *svc == service) {
        Some((_, s)) => s.to_string(),
        None => service
            .trim_end_matches(".amazonaws.com")
            .split(['.', '-'])
            .map(|w| {
                let mut c = w.chars();
                c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default()
            })
            .collect(),
    };
    format!("AWSServiceRoleFor{stem}")
}

/// Rename service-linked roles that saved state holds under MWS's old
/// derived names (`AWSServiceRoleForSso`, `AWSServiceRoleForRam`) to the
/// names AWS uses.
pub(crate) fn migrate_role_names(partition: &str, account: &str, state: &mut State) {
    let stale: Vec<(String, &'static SlrSpec)> = state
        .roles
        .iter()
        .filter_map(|(key, r)| {
            let service = r.path.strip_prefix("/aws-service-role/")?.strip_suffix('/')?;
            let spec = service_linked_role(service)?;
            (r.name != spec.role_name && r.name.eq_ignore_ascii_case(&legacy_name(service)))
                .then(|| (key.clone(), spec))
        })
        .collect();
    for (key, spec) in stale {
        let new_key = spec.role_name.to_lowercase();
        if new_key != key && state.roles.contains_key(&new_key) {
            continue;
        }
        let Some(mut role) = state.roles.remove(&key) else { continue };
        role.name = spec.role_name.to_string();
        role.arn = format!("arn:{partition}:iam::{account}:role{}{}", role.path, role.name);
        for ip in state.instance_profiles.values_mut() {
            for r in ip.roles.iter_mut().filter(|r| **r == key) {
                *r = new_key.clone();
            }
        }
        state.roles.insert(new_key, role);
    }
}

/// Resources that still use a service-linked role, in one region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleUsage {
    pub region: String,
    /// Resource ARNs.
    pub resources: Vec<String>,
}

/// Implemented by services that use service-linked roles, so that
/// `DeleteServiceLinkedRole` fails while their resources still need the
/// role. Register with
/// [`Iam::register_service_linked_role_usage`](crate::Iam::register_service_linked_role_usage).
/// IAM calls it without holding its state lock.
pub trait ServiceLinkedRoleUsage: Send + Sync {
    /// Resources in `account` that use the service-linked role `role_arn`
    /// of service principal `service`. Empty when none do (or the service
    /// is not this one).
    fn usage(&self, account: &str, service: &str, role_arn: &str) -> Vec<RoleUsage>;
}

/// How long a deletion task stays `IN_PROGRESS` (emulated clock).
pub const DELETION_SECONDS: i64 = 5;
/// The region IAM reports its own (global) resources in.
const GLOBAL_REGION: &str = "us-east-1";
const IN_USE_REASON: &str = "The service-linked role is in use by resources in this account.";

fn is_service_linked(r: &Role) -> bool {
    r.path.starts_with("/aws-service-role/")
}

pub(crate) fn protected(name: &str) -> ServiceError {
    errors::unmodifiable_entity(format!(
        "Cannot perform the operation on the protected role '{name}' - this role is only modifiable by AWS"
    ))
}

fn no_template(arn: &str) -> ServiceError {
    errors::no_such_entity(format!("The role template with ARN {arn} cannot be found."))
}

impl Iam {
    pub fn create_service_linked_role(
        &self,
        ctx: &RequestContext,
        input: types::CreateServiceLinkedRoleRequest,
    ) -> Result<types::CreateServiceLinkedRoleResponse, ServiceError> {
        let service = input.aws_service_name.clone();
        let spec = service_linked_role(&service).ok_or_else(|| {
            errors::invalid_input(format!("Unrecognized service principal: {}", input.aws_service_name))
        })?;
        let mut name = spec.role_name.to_string();
        if let Some(s) = &input.custom_suffix {
            if !spec.custom_suffix {
                return Err(errors::invalid_input(format!("Custom suffix is not allowed for service {service}")));
            }
            name = format!("{name}_{s}");
        }
        let path = format!("/aws-service-role/{service}/");
        let arn = self.entity_arn("role", &path, &name);
        self.authorize_with(ctx, "CreateServiceLinkedRole", &arn, single("iam:AWSServiceName", service.clone()))?;
        let limit = self.limit(ctx, &ROLES_PER_ACCOUNT);
        let mut state = self.write();
        let key = name.to_lowercase();
        if state.roles.contains_key(&key) {
            return Err(errors::invalid_input(format!(
                "Service role name {name} has been taken in this account, please try a different suffix."
            )));
        }
        if state.roles.len() >= limit {
            return Err(quota_exceeded(ROLES_PER_ACCOUNT.name, limit));
        }
        let policy_arn =
            format!("arn:{}:iam::aws:policy/aws-service-role/{}", self.inner.config.partition, spec.policy);
        let trust = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}"#
        );
        let role = Role {
            name,
            path,
            id: ids::unique_id("AROA"),
            arn,
            created: ctx.received_at,
            trust_policy: trust,
            description: input.description,
            max_session_duration: 3600,
            permissions_boundary: None,
            tags: vec![],
            inline: Default::default(),
            attached: state.policies.contains_key(&policy_arn).then(|| policy_arn.clone()).into_iter().collect(),
            last_used: None,
        };
        let mut out = wire::role(&role);
        out.role_last_used = None;
        state.roles.insert(key, role);
        Ok(types::CreateServiceLinkedRoleResponse { role: Some(out) })
    }

    /// Start deleting a service-linked role. The task is `IN_PROGRESS` for a
    /// few seconds of emulated time; then it fails if a resource still uses
    /// the role, and otherwise deletes it (see `settle_deletion_tasks`).
    pub fn delete_service_linked_role(
        &self,
        ctx: &RequestContext,
        input: types::DeleteServiceLinkedRoleRequest,
    ) -> Result<types::DeleteServiceLinkedRoleResponse, ServiceError> {
        self.authorize(ctx, "DeleteServiceLinkedRole", &self.role_arn_or_default(&input.role_name))?;
        let mut state = self.write();
        let role = state.role(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if !is_service_linked(role) {
            return Err(errors::invalid_input(format!("Role {} is not a service-linked role.", input.role_name)));
        }
        let (role_name, role_id) = (role.name.clone(), role.id.clone());
        if let Some(t) = state
            .deletion_tasks
            .values()
            .find(|t| t.status == "IN_PROGRESS" && t.role_id.as_deref() == Some(role_id.as_str()))
        {
            return Ok(types::DeleteServiceLinkedRoleResponse { deletion_task_id: t.id.clone() });
        }
        let service = role.path.trim_start_matches("/aws-service-role/").trim_end_matches('/').to_string();
        let id = format!("task/aws-service-role/{service}/{role_name}/{}", uuid::Uuid::new_v4());
        state.deletion_tasks.insert(
            id.clone(),
            DeletionTask {
                id: id.clone(),
                role: role_name,
                status: "IN_PROGRESS".into(),
                role_id: Some(role_id),
                started: Some(ctx.received_at),
                reason: None,
                usage: vec![],
            },
        );
        Ok(types::DeleteServiceLinkedRoleResponse { deletion_task_id: id })
    }

    pub fn get_service_linked_role_deletion_status(
        &self,
        ctx: &RequestContext,
        input: types::GetServiceLinkedRoleDeletionStatusRequest,
    ) -> Result<types::GetServiceLinkedRoleDeletionStatusResponse, ServiceError> {
        self.authorize(ctx, "GetServiceLinkedRoleDeletionStatus", "*")?;
        if !input.deletion_task_id.starts_with("task/aws-service-role/") {
            return Err(errors::invalid_input(format!("Invalid deletion task id: {}", input.deletion_task_id)));
        }
        let state = self.read();
        let task = state.deletion_tasks.get(&input.deletion_task_id).ok_or_else(|| {
            errors::no_such_entity(format!("Deletion task {} cannot be found.", input.deletion_task_id))
        })?;
        let reason = (task.status == "FAILED").then(|| types::DeletionTaskFailureReasonType {
            reason: task.reason.clone(),
            role_usage_list: Some(
                task.usage
                    .iter()
                    .map(|(region, resources)| types::RoleUsageType {
                        region: Some(region.clone()),
                        resources: Some(resources.clone()),
                    })
                    .collect(),
            ),
        });
        Ok(types::GetServiceLinkedRoleDeletionStatusResponse { status: task.status.clone(), reason })
    }

    /// Finish service-linked role deletion tasks whose time has come: fail
    /// those whose role is still in use (by an IAM instance profile, or by
    /// resources a registered service reports), delete the others' roles.
    /// Takes the state lock itself; call it with no lock held.
    pub(crate) fn settle_deletion_tasks(&self, now: DateTime<Utc>) {
        struct Due {
            account: String,
            task: String,
            role: Option<(String, String, String)>,
            service: String,
            usage: BTreeMap<String, Vec<String>>,
        }
        let mut due: Vec<Due> = {
            let accounts = self.inner.accounts.read().expect("IAM state lock poisoned");
            let mut due = vec![];
            for (account, state) in accounts.iter() {
                for t in state.deletion_tasks.values() {
                    let ready = t.started.is_none_or(|s| now - s >= Duration::seconds(DELETION_SECONDS));
                    if t.status != "IN_PROGRESS" || !ready {
                        continue;
                    }
                    let role = state.role(&t.role).filter(|r| t.role_id.as_deref().is_none_or(|id| id == r.id));
                    let mut usage = BTreeMap::<String, Vec<String>>::new();
                    let service = role
                        .map(|r| r.path.trim_start_matches("/aws-service-role/").trim_end_matches('/').to_string())
                        .unwrap_or_default();
                    if let Some(r) = role {
                        let key = r.name.to_lowercase();
                        let profiles: Vec<String> = state
                            .instance_profiles
                            .values()
                            .filter(|ip| ip.roles.contains(&key))
                            .map(|ip| ip.arn.clone())
                            .collect();
                        if !profiles.is_empty() {
                            usage.insert(GLOBAL_REGION.to_string(), profiles);
                        }
                    }
                    due.push(Due {
                        account: account.clone(),
                        task: t.id.clone(),
                        role: role.map(|r| (r.name.to_lowercase(), r.arn.clone(), r.id.clone())),
                        service,
                        usage,
                    });
                }
            }
            due
        };
        if due.is_empty() {
            return;
        }
        let hooks = self.inner.slr_usage.read().expect("IAM SLR usage lock poisoned").clone();
        for d in &mut due {
            let Some((_, arn, _)) = &d.role else { continue };
            for hook in &hooks {
                for u in hook.usage(&d.account, &d.service, arn) {
                    if !u.resources.is_empty() {
                        d.usage.entry(u.region).or_default().extend(u.resources);
                    }
                }
            }
        }
        let mut accounts = self.inner.accounts.write().expect("IAM state lock poisoned");
        for d in due {
            let Some(state) = accounts.get_mut(&d.account) else { continue };
            if state.deletion_tasks.get(&d.task).is_none_or(|t| t.status != "IN_PROGRESS") {
                continue;
            }
            let mut retired = None;
            let task = state.deletion_tasks.get_mut(&d.task).expect("task exists");
            if d.usage.is_empty() {
                task.status = "SUCCEEDED".into();
                retired = d.role;
            } else {
                task.status = "FAILED".into();
                task.reason = Some(IN_USE_REASON.into());
                task.usage = d.usage.into_iter().collect();
            }
            if let Some((key, arn, id)) = retired {
                if state.roles.get(&key).is_some_and(|r| r.id == id) {
                    state.roles.remove(&key);
                    retire_principal(&mut accounts, &arn, &id);
                }
            }
        }
    }

    pub fn get_role_template_version(
        &self,
        ctx: &RequestContext,
        input: types::GetRoleTemplateVersionRequest,
    ) -> Result<types::GetRoleTemplateVersionResponse, ServiceError> {
        self.authorize(ctx, "GetRoleTemplateVersion", &input.template_arn)?;
        Err(no_template(&input.template_arn))
    }

    pub fn acquire_role(
        &self,
        ctx: &RequestContext,
        input: types::AcquireRoleRequest,
    ) -> Result<types::AcquireRoleResponse, ServiceError> {
        self.authorize(ctx, "AcquireRole", &input.template_arn)?;
        Err(no_template(&input.template_arn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_are_awss() {
        assert_eq!(service_linked_role("sso.amazonaws.com").unwrap().role_name, "AWSServiceRoleForSSO");
        assert_eq!(
            service_linked_role("ram.amazonaws.com").unwrap().role_name,
            "AWSServiceRoleForResourceAccessManager"
        );
        assert_eq!(service_linked_role("spot.amazonaws.com").unwrap().role_name, "AWSServiceRoleForEC2Spot");
        assert!(service_linked_role("custom-thing.amazonaws.com").is_none());
        assert!(SERVICE_LINKED_ROLES.iter().all(|s| s.role_name.starts_with("AWSServiceRoleFor")));
    }

    #[test]
    fn legacy_names_are_migrated() {
        let mut state = State::default();
        for (name, service) in
            [("AWSServiceRoleForSso", "sso.amazonaws.com"), ("AWSServiceRoleForRam", "ram.amazonaws.com")]
        {
            let path = format!("/aws-service-role/{service}/");
            state.roles.insert(
                name.to_lowercase(),
                Role {
                    name: name.into(),
                    arn: format!("arn:aws:iam::111111111111:role{path}{name}"),
                    path,
                    id: "AROAEXAMPLE".into(),
                    created: Utc::now(),
                    trust_policy: "{}".into(),
                    description: None,
                    max_session_duration: 3600,
                    permissions_boundary: None,
                    tags: vec![],
                    inline: Default::default(),
                    attached: Default::default(),
                    last_used: None,
                },
            );
        }
        migrate_role_names("aws", "111111111111", &mut state);
        assert_eq!(state.role("AWSServiceRoleForSSO").unwrap().name, "AWSServiceRoleForSSO");
        let ram = state.role("AWSServiceRoleForResourceAccessManager").unwrap();
        assert_eq!(
            ram.arn,
            "arn:aws:iam::111111111111:role/aws-service-role/ram.amazonaws.com/AWSServiceRoleForResourceAccessManager"
        );
        assert!(state.role("AWSServiceRoleForRam").is_none());
    }
}
