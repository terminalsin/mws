//! EKS add-ons: the catalog (`DescribeAddonVersions`,
//! `DescribeAddonConfiguration`) and the add-ons installed on a cluster,
//! with the Pod Identity associations they own.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::catalog::{self, AddonSpec};
use crate::generated::{errors, types};
use crate::updates::Target;
use crate::util::{self, param, text};
use crate::Eks;

pub(crate) fn not_found(cluster: &str, addon: &str) -> ServiceError {
    errors::resource_not_found(format!("No addon: {addon} found in cluster: {cluster}"))
        .with_field("clusterName", text(cluster))
        .with_field("addonName", text(addon))
}

fn check_configuration(values: &str) -> Result<(), ServiceError> {
    let trimmed = values.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            errors::invalid_parameter(format!("ConfigurationValue provided in request is not supported: {e}"))
        })?;
        if !v.is_object() {
            return Err(errors::invalid_parameter(
                "ConfigurationValue provided in request is not supported: Json schema validation failed",
            ));
        }
    }
    Ok(())
}

fn version_infos(spec: &AddonSpec, kube_minor: Option<u32>) -> Vec<types::AddonVersionInfo> {
    spec.versions
        .iter()
        .filter(|(_, lo, hi)| kube_minor.is_none_or(|m| (*lo..=*hi).contains(&m)))
        .map(|(v, lo, hi)| types::AddonVersionInfo {
            addon_version: Some(v.to_string()),
            architecture: Some(vec!["amd64".into(), "arm64".into()]),
            compute_types: Some(vec!["ec2".into(), "hybrid".into()]),
            compatibilities: Some(
                catalog::VERSIONS
                    .iter()
                    .filter(|k| (*lo..=*hi).contains(&k.minor()))
                    .filter(|k| kube_minor.is_none_or(|m| m == k.minor()))
                    .map(|k| types::Compatibility {
                        cluster_version: Some(k.version.into()),
                        platform_versions: Some(vec!["*".into()]),
                        default_version: spec.default_for(k.minor()) == Some(*v),
                    })
                    .collect(),
            ),
            requires_configuration: false,
            requires_iam_permissions: !spec.pod_identity.is_empty(),
        })
        .collect()
}

impl Eks {
    fn check_pod_identities(
        &self,
        ctx: &RequestContext,
        addon: &str,
        spec: &AddonSpec,
        pias: &[types::AddonPodIdentityAssociations],
    ) -> Result<(), ServiceError> {
        for p in pias {
            if !spec.pod_identity.iter().any(|(sa, _)| *sa == p.service_account) {
                return Err(errors::invalid_parameter(format!(
                    "The service account {} is not used by addon {addon}.",
                    p.service_account
                )));
            }
            util::pass_role(ctx, &p.role_arn, "pods.eks.amazonaws.com")?;
        }
        Ok(())
    }

    pub(crate) async fn create_addon(
        &self,
        ctx: &RequestContext,
        input: types::CreateAddonRequest,
    ) -> Result<types::CreateAddonResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.addon_name.clone();
        let cluster_arn = util::cluster_arn(ctx, &cluster);
        if let Some(role) = &input.service_account_role_arn {
            util::pass_role(ctx, role, "eks.amazonaws.com")?;
        }
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &cluster)?;
        let mut c = ConditionContext::new();
        c.insert("eks:addonName".into(), vec![name.clone()]);
        util::authorize(ctx, "CreateAddon", &cluster_arn, rec.cluster.tags.as_ref(), input.tags.as_ref(), c)?;
        util::check_create_tags(input.tags.as_ref())?;
        if rec.registered {
            return Err(errors::invalid_request("Add-ons are not supported on registered clusters.")
                .with_field("clusterName", text(&cluster)));
        }
        if rec.addons.contains_key(&name) {
            return Err(errors::resource_in_use(format!("Addon already exists: {name}"))
                .with_field("clusterName", text(&cluster))
                .with_field("addonName", text(&name)));
        }
        let kube_version = rec.cluster.version.clone().unwrap_or_default();
        let minor = catalog::minor(&kube_version).unwrap_or_default();
        let spec = catalog::addon(&name).ok_or_else(|| {
            errors::invalid_parameter(format!(
                "Addon {name} specified is not supported in {kube_version} cluster version"
            ))
            .with_field("addonName", text(&name))
        })?;
        let version = match &input.addon_version {
            Some(v) if spec.supports(v, minor) => v.clone(),
            Some(_) => {
                return Err(errors::invalid_parameter("Addon version specified is not supported")
                    .with_field("clusterName", text(&cluster))
                    .with_field("addonName", text(&name)))
            }
            None => spec
                .default_for(minor)
                .ok_or_else(|| {
                    errors::invalid_parameter(format!(
                        "Addon {name} specified is not supported in {kube_version} cluster version"
                    ))
                })?
                .to_string(),
        };
        if let Some(v) = &input.configuration_values {
            check_configuration(v)?;
        }
        let pias = input.pod_identity_associations.clone().unwrap_or_default();
        self.check_pod_identities(ctx, &name, spec, &pias)?;
        let namespace = input
            .namespace_config
            .as_ref()
            .and_then(|n| n.namespace.clone())
            .unwrap_or_else(|| spec.default_namespace.to_string());
        let arn = util::arn(ctx, &format!("addon/{cluster}/{name}/{}", util::uuid()));
        let now = ctx.received_at;
        let mut pia_arns = Vec::new();
        for p in &pias {
            let assoc = crate::identity::new_association(
                ctx,
                &cluster,
                &namespace,
                &p.service_account,
                &p.role_arn,
                None,
                Some(arn.clone()),
            );
            pia_arns.push(assoc.association_arn.clone().unwrap_or_default());
            rec.pod_identities.insert(assoc.association_id.clone().unwrap_or_default(), assoc);
        }
        let addon = types::Addon {
            addon_name: Some(name.clone()),
            cluster_name: Some(cluster.clone()),
            status: Some("CREATING".into()),
            addon_version: Some(version),
            health: Some(types::AddonHealth { issues: Some(Vec::new()) }),
            addon_arn: Some(arn),
            created_at: Some(now),
            modified_at: Some(now),
            service_account_role_arn: input.service_account_role_arn.clone(),
            tags: Some(input.tags.clone().unwrap_or_default()),
            publisher: Some(spec.publisher.into()),
            owner: Some(spec.owner.into()),
            marketplace_information: None,
            configuration_values: input.configuration_values.clone(),
            pod_identity_associations: (!pia_arns.is_empty()).then_some(pia_arns),
            namespace_config: input
                .namespace_config
                .as_ref()
                .map(|_| types::AddonNamespaceConfigResponse { namespace: Some(namespace) }),
        };
        rec.addons.insert(name, addon.clone());
        Ok(types::CreateAddonResponse { addon: Some(addon) })
    }

    pub(crate) async fn describe_addon(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddonRequest,
    ) -> Result<types::DescribeAddonResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let a = rec.addons.get(&input.addon_name).ok_or_else(|| not_found(&input.cluster_name, &input.addon_name))?;
        util::authorize(
            ctx,
            "DescribeAddon",
            a.addon_arn.as_deref().unwrap_or_default(),
            a.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribeAddonResponse { addon: Some(a.clone()) })
    }

    pub(crate) async fn list_addons(
        &self,
        ctx: &RequestContext,
        input: types::ListAddonsRequest,
    ) -> Result<types::ListAddonsResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "ListAddons", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        let names: Vec<String> = rec.addons.keys().cloned().collect();
        let (items, next) = util::page(&names, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAddonsResponse { addons: Some(items), next_token: next })
    }

    pub(crate) async fn update_addon(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAddonRequest,
    ) -> Result<types::UpdateAddonResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let name = input.addon_name.clone();
        if let Some(role) = input.service_account_role_arn.as_ref().filter(|r| !r.is_empty()) {
            util::pass_role(ctx, role, "eks.amazonaws.com")?;
        }
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &cluster)?;
        let a = rec.addons.get(&name).ok_or_else(|| not_found(&cluster, &name))?;
        util::authorize(
            ctx,
            "UpdateAddon",
            a.addon_arn.as_deref().unwrap_or_default(),
            a.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        if a.status.as_deref() != Some("ACTIVE") && a.status.as_deref() != Some("DEGRADED") {
            return Err(errors::resource_in_use(format!(
                "Addon {name} is in {} state and cannot be updated.",
                a.status.as_deref().unwrap_or_default()
            ))
            .with_field("addonName", text(&name)));
        }
        let addon_arn = a.addon_arn.clone().unwrap_or_default();
        let namespace = a.namespace_config.as_ref().and_then(|n| n.namespace.clone());
        let minor = catalog::minor(rec.cluster.version.as_deref().unwrap_or_default()).unwrap_or_default();
        let spec = catalog::addon(&name).expect("installed add-ons are in the catalog");
        let mut params = Vec::new();
        if let Some(v) = &input.addon_version {
            if !spec.supports(v, minor) {
                return Err(errors::invalid_parameter("Addon version specified is not supported")
                    .with_field("addonName", text(&name)));
            }
            params.push(param("AddonVersion", v.clone()));
        }
        if let Some(r) = &input.service_account_role_arn {
            params.push(param("ServiceAccountRoleArn", r.clone()));
        }
        if let Some(r) = &input.resolve_conflicts {
            params.push(param("ResolveConflicts", r.clone()));
        }
        if let Some(c) = &input.configuration_values {
            check_configuration(c)?;
            params.push(param("ConfigurationValues", c.clone()));
        }
        if let Some(pias) = &input.pod_identity_associations {
            self.check_pod_identities(ctx, &name, spec, pias)?;
            params.push(param(
                "PodIdentityAssociations",
                serde_json::to_string(
                    &pias
                        .iter()
                        .map(|p| serde_json::json!({"serviceAccount": p.service_account, "roleArn": p.role_arn}))
                        .collect::<Vec<_>>(),
                )
                .unwrap_or_default(),
            ));
            // Replace the associations the add-on owns.
            rec.pod_identities.retain(|_, p| p.owner_arn.as_deref() != Some(addon_arn.as_str()));
            let ns = namespace.clone().unwrap_or_else(|| spec.default_namespace.to_string());
            let mut arns = Vec::new();
            for p in pias {
                let assoc = crate::identity::new_association(
                    ctx,
                    &cluster,
                    &ns,
                    &p.service_account,
                    &p.role_arn,
                    None,
                    Some(addon_arn.clone()),
                );
                arns.push(assoc.association_arn.clone().unwrap_or_default());
                rec.pod_identities.insert(assoc.association_id.clone().unwrap_or_default(), assoc);
            }
            let a = rec.addons.get_mut(&name).expect("checked");
            a.pod_identity_associations = (!arns.is_empty()).then_some(arns);
        }
        let a = rec.addons.get_mut(&name).expect("checked");
        if let Some(v) = &input.addon_version {
            a.addon_version = Some(v.clone());
        }
        if let Some(r) = &input.service_account_role_arn {
            a.service_account_role_arn = (!r.is_empty()).then(|| r.clone());
        }
        if let Some(c) = &input.configuration_values {
            a.configuration_values = Some(c.clone());
        }
        a.status = Some("UPDATING".into());
        a.modified_at = Some(ctx.received_at);
        let update = crate::updates::push(rec, ctx.received_at, "AddonUpdate", params, Some(Target::Addon(&name)));
        Ok(types::UpdateAddonResponse { update: Some(update) })
    }

    pub(crate) async fn delete_addon(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAddonRequest,
    ) -> Result<types::DeleteAddonResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let a =
            rec.addons.get_mut(&input.addon_name).ok_or_else(|| not_found(&input.cluster_name, &input.addon_name))?;
        util::authorize(
            ctx,
            "DeleteAddon",
            a.addon_arn.as_deref().unwrap_or_default(),
            a.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        a.status = Some("DELETING".into());
        a.modified_at = Some(ctx.received_at);
        let response = a.clone();
        let owner = response.addon_arn.clone();
        rec.pod_identities.retain(|_, p| p.owner_arn != owner);
        Ok(types::DeleteAddonResponse { addon: Some(response) })
    }

    pub(crate) async fn describe_addon_versions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddonVersionsRequest,
    ) -> Result<types::DescribeAddonVersionsResponse, ServiceError> {
        util::authorize(ctx, "DescribeAddonVersions", "*", None, None, ConditionContext::new())?;
        let minor = match &input.kubernetes_version {
            Some(v) => Some(
                catalog::minor(v)
                    .ok_or_else(|| errors::invalid_parameter(format!("The kubernetesVersion {v} is invalid.")))?,
            ),
            None => None,
        };
        let types_filter = input.types.clone().unwrap_or_default();
        let publishers = input.publishers.clone().unwrap_or_default();
        let owners = input.owners.clone().unwrap_or_default();
        if let Some(name) = &input.addon_name {
            if catalog::addon(name).is_none() {
                return Err(
                    errors::resource_not_found(format!("Addon {name} not found.")).with_field("addonName", text(name))
                );
            }
        }
        let infos: Vec<types::AddonInfo> = catalog::ADDONS
            .iter()
            .filter(|a| input.addon_name.as_deref().is_none_or(|n| n == a.name))
            .filter(|a| types_filter.is_empty() || types_filter.iter().any(|t| t == a.kind))
            .filter(|a| publishers.is_empty() || publishers.iter().any(|p| p == a.publisher))
            .filter(|a| owners.is_empty() || owners.iter().any(|o| o == a.owner))
            .map(|a| types::AddonInfo {
                addon_name: Some(a.name.into()),
                r#type: Some(a.kind.into()),
                addon_versions: Some(version_infos(a, minor)),
                publisher: Some(a.publisher.into()),
                owner: Some(a.owner.into()),
                marketplace_information: None,
                default_namespace: Some(a.default_namespace.into()),
            })
            .filter(|a| a.addon_versions.as_ref().is_some_and(|v| !v.is_empty()))
            .collect();
        let (items, next) = util::page(&infos, input.max_results, input.next_token.as_deref())?;
        Ok(types::DescribeAddonVersionsResponse { addons: Some(items), next_token: next })
    }

    pub(crate) async fn describe_addon_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddonConfigurationRequest,
    ) -> Result<types::DescribeAddonConfigurationResponse, ServiceError> {
        util::authorize(ctx, "DescribeAddonConfiguration", "*", None, None, ConditionContext::new())?;
        let spec = catalog::addon(&input.addon_name).ok_or_else(|| {
            errors::resource_not_found(format!("Addon {} not found.", input.addon_name))
                .with_field("addonName", text(&input.addon_name))
        })?;
        if !spec.versions.iter().any(|(v, _, _)| *v == input.addon_version) {
            return Err(errors::invalid_parameter("Addon version specified is not supported")
                .with_field("addonName", text(&input.addon_name)));
        }
        Ok(types::DescribeAddonConfigurationResponse {
            addon_name: Some(spec.name.into()),
            addon_version: Some(input.addon_version.clone()),
            configuration_schema: Some(spec.schema.into()),
            pod_identity_configuration: Some(
                spec.pod_identity
                    .iter()
                    .map(|(sa, policy)| types::AddonPodIdentityConfiguration {
                        service_account: Some(sa.to_string()),
                        recommended_managed_policies: Some(vec![format!(
                            "arn:{}:iam::aws:policy/{}{policy}",
                            ctx.partition,
                            if matches!(*policy, "AmazonEBSCSIDriverPolicy" | "AmazonEFSCSIDriverPolicy") {
                                "service-role/"
                            } else {
                                ""
                            }
                        )]),
                    })
                    .collect(),
            ),
        })
    }
}
