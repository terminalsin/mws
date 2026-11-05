//! EKS capabilities: managed Argo CD, AWS Controllers for Kubernetes (ACK)
//! and Kube Resource Orchestrator (kro) running for a cluster.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::updates::Target;
use crate::util::{self, param, text};
use crate::Eks;

pub(crate) fn not_found(name: &str) -> ServiceError {
    errors::resource_not_found(format!("No capability found with name: {name}."))
}

fn version_of(kind: &str) -> &'static str {
    match kind {
        "ARGOCD" => "v3.1.8-eks-1",
        "ACK" => "v1.0.0-eks-1",
        _ => "v0.5.1-eks-1",
    }
}

fn summary(c: &types::Capability) -> types::CapabilitySummary {
    types::CapabilitySummary {
        capability_name: c.capability_name.clone(),
        arn: c.arn.clone(),
        r#type: c.r#type.clone(),
        status: c.status.clone(),
        version: c.version.clone(),
        created_at: c.created_at,
        modified_at: c.modified_at,
    }
}

fn role_mappings_json(m: &[types::ArgoCdRoleMapping]) -> String {
    serde_json::to_string(
        &m.iter()
            .map(|r| {
                serde_json::json!({
                    "role": r.role,
                    "identities": r.identities.iter().map(|i| serde_json::json!({"id": i.id, "type": i.r#type})).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default()
}

impl Eks {
    pub(crate) async fn create_capability(
        &self,
        ctx: &RequestContext,
        input: types::CreateCapabilityRequest,
    ) -> Result<types::CreateCapabilityResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.capability_name.clone();
        let cluster_arn = util::cluster_arn(ctx, &cluster);
        {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &cluster)?;
            util::authorize(
                ctx,
                "CreateCapability",
                &cluster_arn,
                rec.cluster.tags.as_ref(),
                input.tags.as_ref(),
                ConditionContext::new(),
            )?;
        }
        util::check_create_tags(input.tags.as_ref())?;
        let role = input.role_arn.clone();
        self.check_role(
            ctx,
            &role,
            "capabilities.eks.amazonaws.com",
            || format!("The role {role} does not exist."),
            || format!("Role {role} must trust capabilities.eks.amazonaws.com."),
        )?;
        let config = input.configuration.clone().unwrap_or_default();
        if input.r#type == "ARGOCD" && config.argo_cd.is_none() {
            return Err(errors::invalid_parameter("An Argo CD capability requires configuration.argoCd."));
        }
        if input.r#type != "ARGOCD" && config.argo_cd.is_some() {
            return Err(errors::invalid_parameter(format!(
                "configuration.argoCd can't be specified for a capability of type {}.",
                input.r#type
            )));
        }
        if input.r#type != "ACK" && config.ack.is_some() {
            return Err(errors::invalid_parameter(format!(
                "configuration.ack can't be specified for a capability of type {}.",
                input.r#type
            )));
        }
        let id = util::random(b"0123456789abcdef", 12);
        let account = util::account(ctx).to_string();
        let configuration = types::CapabilityConfigurationResponse {
            argo_cd: config.argo_cd.as_ref().map(|a| {
                let prefix = a.endpoint_prefix.clone().unwrap_or_else(|| id.clone());
                let idc_region = a.aws_idc.idc_region.clone().unwrap_or_else(|| ctx.region.clone());
                let instance = util::arn_name(&a.aws_idc.idc_instance_arn).to_string();
                types::ArgoCdConfigResponse {
                    namespace: Some(a.namespace.clone().unwrap_or_else(|| "argocd".into())),
                    aws_idc: Some(types::ArgoCdAwsIdcConfigResponse {
                        idc_instance_arn: Some(a.aws_idc.idc_instance_arn.clone()),
                        idc_region: Some(idc_region),
                        idc_managed_application_arn: Some(format!(
                            "arn:{}:sso::{account}:application/{instance}/apl-{}",
                            ctx.partition,
                            util::random(b"0123456789abcdef", 16)
                        )),
                    }),
                    rbac_role_mappings: a.rbac_role_mappings.clone(),
                    network_access: a
                        .network_access
                        .as_ref()
                        .map(|n| types::ArgoCdNetworkAccessConfigResponse { vpce_ids: n.vpce_ids.clone() }),
                    server_url: Some(format!("https://{prefix}.eks-capabilities.{}.amazonaws.com", ctx.region)),
                    endpoint_prefix: Some(prefix),
                }
            }),
            ack: config.ack.as_ref().map(|a| types::AckConfigResponse {
                enable_cross_namespace: a.enable_cross_namespace,
                disabled_services: a.disabled_services.clone(),
            }),
        };
        let now = ctx.received_at;
        let capability = types::Capability {
            capability_name: Some(name.clone()),
            arn: Some(util::arn(ctx, &format!("capability/{cluster}/{name}/{}", util::uuid()))),
            cluster_name: Some(cluster.clone()),
            r#type: Some(input.r#type.clone()),
            role_arn: Some(role),
            status: Some("CREATING".into()),
            version: Some(version_of(&input.r#type).into()),
            configuration: Some(configuration),
            tags: Some(input.tags.clone().unwrap_or_default()),
            health: Some(types::CapabilityHealth { issues: Some(Vec::new()) }),
            created_at: Some(now),
            modified_at: Some(now),
            delete_propagation_policy: Some(input.delete_propagation_policy.clone()),
        };
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &cluster)?;
        if rec.capabilities.contains_key(&name) {
            return Err(errors::resource_in_use(format!("Capability {name} already exists."))
                .with_field("clusterName", text(&cluster)));
        }
        if rec.capabilities.values().any(|c| c.r#type.as_deref() == Some(input.r#type.as_str())) {
            return Err(errors::resource_limit_exceeded(format!(
                "The cluster already has a capability of type {}.",
                input.r#type
            ))
            .with_field("clusterName", text(&cluster)));
        }
        rec.capabilities.insert(name, capability.clone());
        Ok(types::CreateCapabilityResponse { capability: Some(capability) })
    }

    pub(crate) async fn describe_capability(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCapabilityRequest,
    ) -> Result<types::DescribeCapabilityResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let c = rec.capabilities.get(&input.capability_name).ok_or_else(|| not_found(&input.capability_name))?;
        util::authorize(
            ctx,
            "DescribeCapability",
            c.arn.as_deref().unwrap_or_default(),
            c.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribeCapabilityResponse { capability: Some(c.clone()) })
    }

    pub(crate) async fn list_capabilities(
        &self,
        ctx: &RequestContext,
        input: types::ListCapabilitiesRequest,
    ) -> Result<types::ListCapabilitiesResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "ListCapabilities", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let all: Vec<_> = rec.capabilities.values().map(summary).collect();
        let (items, next) = util::page(&all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListCapabilitiesResponse { capabilities: Some(items), next_token: next })
    }

    pub(crate) async fn update_capability(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCapabilityRequest,
    ) -> Result<types::UpdateCapabilityResponse, ServiceError> {
        {
            let mut st = self.write();
            let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
            let c = rec.capabilities.get(&input.capability_name).ok_or_else(|| not_found(&input.capability_name))?;
            util::authorize(
                ctx,
                "UpdateCapability",
                c.arn.as_deref().unwrap_or_default(),
                c.tags.as_ref(),
                None,
                ConditionContext::new(),
            )?;
        }
        if let Some(role) = &input.role_arn {
            self.check_role(
                ctx,
                role,
                "capabilities.eks.amazonaws.com",
                || format!("The role {role} does not exist."),
                || format!("Role {role} must trust capabilities.eks.amazonaws.com."),
            )?;
        }
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let name = input.capability_name.clone();
        let c = rec.capabilities.get_mut(&name).ok_or_else(|| not_found(&name))?;
        if c.status.as_deref() != Some("ACTIVE") && c.status.as_deref() != Some("DEGRADED") {
            return Err(errors::resource_in_use(format!(
                "Capability {name} is in {} state and cannot be updated.",
                c.status.as_deref().unwrap_or_default()
            )));
        }
        let mut params = Vec::new();
        if let Some(r) = &input.role_arn {
            params.push(param("RoleArn", r.clone()));
            c.role_arn = Some(r.clone());
        }
        if let Some(p) = &input.delete_propagation_policy {
            c.delete_propagation_policy = Some(p.clone());
        }
        let kind = c.r#type.clone().unwrap_or_default();
        if let Some(cfg) = &input.configuration {
            let current = c.configuration.get_or_insert_with(Default::default);
            if let Some(argo) = &cfg.argo_cd {
                if kind != "ARGOCD" {
                    return Err(errors::invalid_parameter(format!(
                        "configuration.argoCd can't be specified for a capability of type {kind}."
                    )));
                }
                let a = current.argo_cd.get_or_insert_with(Default::default);
                if let Some(m) = &argo.rbac_role_mappings {
                    let list = a.rbac_role_mappings.get_or_insert_with(Vec::new);
                    if let Some(add) = &m.add_or_update_role_mappings {
                        params.push(param("RoleMappingsToAddOrUpdate", role_mappings_json(add)));
                        for r in add {
                            list.retain(|x| x.role != r.role);
                            list.push(r.clone());
                        }
                    }
                    if let Some(remove) = &m.remove_role_mappings {
                        params.push(param("RoleMappingsToRemove", role_mappings_json(remove)));
                        list.retain(|x| !remove.iter().any(|r| r.role == x.role));
                    }
                }
                if let Some(n) = &argo.network_access {
                    params.push(param("NetworkAccess", util::json_list(n.vpce_ids.as_deref().unwrap_or_default())));
                    a.network_access = Some(types::ArgoCdNetworkAccessConfigResponse { vpce_ids: n.vpce_ids.clone() });
                }
            }
            if let Some(ack) = &cfg.ack {
                if kind != "ACK" {
                    return Err(errors::invalid_parameter(format!(
                        "configuration.ack can't be specified for a capability of type {kind}."
                    )));
                }
                let a = current.ack.get_or_insert_with(Default::default);
                if let Some(e) = ack.enable_cross_namespace {
                    params.push(param("EnableCrossNamespace", e.to_string()));
                    a.enable_cross_namespace = Some(e);
                }
                if let Some(d) = &ack.disabled_services {
                    params.push(param("DisabledServices", util::json_list(d)));
                    a.disabled_services = Some(d.clone());
                }
            }
        }
        c.status = Some("UPDATING".into());
        c.modified_at = Some(ctx.received_at);
        let update =
            crate::updates::push(rec, ctx.received_at, "CapabilityUpdate", params, Some(Target::Capability(&name)));
        Ok(types::UpdateCapabilityResponse { update: Some(update) })
    }

    pub(crate) async fn delete_capability(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCapabilityRequest,
    ) -> Result<types::DeleteCapabilityResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let c = rec.capabilities.get_mut(&input.capability_name).ok_or_else(|| not_found(&input.capability_name))?;
        util::authorize(
            ctx,
            "DeleteCapability",
            c.arn.as_deref().unwrap_or_default(),
            c.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        c.status = Some("DELETING".into());
        c.modified_at = Some(ctx.received_at);
        Ok(types::DeleteCapabilityResponse { capability: Some(c.clone()) })
    }
}
