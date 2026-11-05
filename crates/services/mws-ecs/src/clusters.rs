//! Clusters.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types as t};
use crate::names::{
    authorize, check_tags, cluster_name, cluster_not_found, failure, invalid, paginate, request_tags, resource_tags,
    Cond, Scope,
};
use crate::state::Region;
use crate::{capacity, settings, tags, Ecs};

pub fn valid_cluster_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The live (not `INACTIVE`) cluster a request names.
pub fn active<'a>(r: &'a Region, reference: Option<&str>) -> Result<&'a t::Cluster, ServiceError> {
    let name = cluster_name(reference);
    match r.clusters.get(&name) {
        Some(c) if c.status.as_deref() == Some("INACTIVE") => {
            Err(errors::cluster_not_found("The referenced cluster was inactive."))
        }
        Some(c) => Ok(c),
        None => Err(cluster_not_found()),
    }
}

fn is_pending(status: Option<&str>) -> bool {
    matches!(status, Some("PROVISIONING" | "PENDING" | "ACTIVATING"))
}

/// A cluster as ECS describes it, with counts and the parts `include`
/// asks for.
pub fn render(r: &Region, c: &t::Cluster, include: &[String]) -> t::Cluster {
    let mut out = c.clone();
    let name = c.cluster_name.clone().unwrap_or_default();
    let tasks: Vec<_> = r.tasks.values().filter(|t| t.cluster == name).collect();
    let running = |lt: Option<&str>| {
        tasks
            .iter()
            .filter(|t| t.task.last_status.as_deref() == Some("RUNNING"))
            .filter(|t| lt.is_none_or(|lt| t.task.launch_type.as_deref() == Some(lt)))
            .count() as i32
    };
    let pending = |lt: Option<&str>| {
        tasks
            .iter()
            .filter(|t| is_pending(t.task.last_status.as_deref()))
            .filter(|t| lt.is_none_or(|lt| t.task.launch_type.as_deref() == Some(lt)))
            .count() as i32
    };
    out.running_tasks_count = running(None);
    out.pending_tasks_count = pending(None);
    out.registered_container_instances_count = r
        .container_instances
        .values()
        .filter(|i| i.cluster == name && matches!(i.instance.status.as_deref(), Some("ACTIVE" | "DRAINING")))
        .count() as i32;
    let services: Vec<_> = r.services.values().filter(|s| s.cluster == name).collect();
    out.active_services_count =
        services.iter().filter(|s| s.service.status.as_deref() == Some("ACTIVE")).count() as i32;
    let want = |f: &str| include.iter().any(|i| i == f);
    out.statistics = want("STATISTICS").then(|| {
        let svc = |status: &str, lt: &str| {
            services
                .iter()
                .filter(|s| s.service.status.as_deref() == Some(status))
                .filter(|s| s.service.launch_type.as_deref().unwrap_or("EC2") == lt)
                .count()
                .to_string()
        };
        let kv = |n: &str, v: String| t::KeyValuePair { name: Some(n.into()), value: Some(v) };
        vec![
            kv("runningEC2TasksCount", running(Some("EC2")).to_string()),
            kv("runningFargateTasksCount", running(Some("FARGATE")).to_string()),
            kv("pendingEC2TasksCount", pending(Some("EC2")).to_string()),
            kv("pendingFargateTasksCount", pending(Some("FARGATE")).to_string()),
            kv("activeEC2ServiceCount", svc("ACTIVE", "EC2")),
            kv("activeFargateServiceCount", svc("ACTIVE", "FARGATE")),
            kv("drainingEC2ServiceCount", svc("DRAINING", "EC2")),
            kv("drainingFargateServiceCount", svc("DRAINING", "FARGATE")),
        ]
    });
    out.tags = if want("TAGS") {
        Some(r.tags.get(c.cluster_arn.as_deref().unwrap_or_default()).cloned().unwrap_or_default())
    } else {
        None
    };
    if !want("SETTINGS") {
        out.settings = None;
    }
    if !want("CONFIGURATIONS") {
        out.configuration = None;
    }
    if !want("ATTACHMENTS") {
        out.attachments = None;
    }
    out
}

/// What CreateCluster and the update operations return: everything but
/// statistics and tags.
fn render_full(r: &Region, c: &t::Cluster) -> t::Cluster {
    let mut out = render(r, c, &["SETTINGS".into(), "CONFIGURATIONS".into(), "ATTACHMENTS".into()]);
    if out.attachments.as_ref().is_some_and(|a| a.is_empty()) {
        out.attachments = None;
    }
    out
}

fn check_settings(settings: &[t::ClusterSetting]) -> Result<(), ServiceError> {
    for s in settings {
        let value = s.value.as_deref().unwrap_or_default();
        if !["enabled", "disabled", "enhanced"].contains(&value) {
            return Err(invalid(format!(
                "The value '{value}' is not valid for the cluster setting 'containerInsights'. Valid values are: enabled, disabled, enhanced."
            )));
        }
    }
    Ok(())
}

fn merge_settings(current: &mut Vec<t::ClusterSetting>, new: &[t::ClusterSetting]) {
    for s in new {
        current.retain(|c| c.name != s.name);
        current.push(s.clone());
    }
}

impl Ecs {
    pub(crate) fn create_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateClusterRequest,
    ) -> Result<t::CreateClusterResponse, ServiceError> {
        let name = input.cluster_name.clone().unwrap_or_else(|| "default".into());
        if !valid_cluster_name(&name) {
            return Err(invalid(
                "Cluster name can only contain letters (uppercase and lowercase), numbers, hyphens (-), and underscores (_).",
            ));
        }
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let scope = Scope::of(ctx);
        let arn = scope.cluster_arn(&name);
        authorize(ctx, "CreateCluster", &arn, Cond::new().extend(request_tags(input.tags.as_ref())))?;
        if let Some(s) = &input.settings {
            check_settings(s)?;
        }
        self.with_region(ctx, |r, scope| {
            let providers = input.capacity_providers.clone().unwrap_or_default();
            let strategy = input.default_capacity_provider_strategy.clone().unwrap_or_default();
            capacity::check_cluster_providers(r, scope, &name, &providers, &strategy)?;
            if let Some(existing) = r.clusters.get(&name).filter(|c| c.status.as_deref() == Some("ACTIVE")) {
                // CreateCluster on an existing cluster returns it.
                return Ok(t::CreateClusterResponse { cluster: Some(render_full(r, existing)) });
            }
            let (insights, _) =
                settings::effective(r, scope, &settings::caller_principal(ctx, scope), "containerInsights");
            let mut cluster_settings =
                vec![t::ClusterSetting { name: Some("containerInsights".into()), value: Some(insights) }];
            merge_settings(&mut cluster_settings, input.settings.as_deref().unwrap_or_default());
            let cluster = t::Cluster {
                cluster_arn: Some(arn.clone()),
                cluster_name: Some(name.clone()),
                configuration: input.configuration.clone(),
                status: Some("ACTIVE".into()),
                settings: Some(cluster_settings),
                capacity_providers: Some(providers),
                default_capacity_provider_strategy: Some(strategy),
                attachments: Some(Vec::new()),
                service_connect_defaults: input
                    .service_connect_defaults
                    .as_ref()
                    .map(|d| t::ClusterServiceConnectDefaults { namespace: Some(namespace_arn(scope, &d.namespace)) }),
                ..Default::default()
            };
            r.tags.remove(&arn);
            tags::store(r, &arn, input.tags.as_ref());
            r.clusters.insert(name.clone(), cluster);
            let c = &r.clusters[&name];
            Ok(t::CreateClusterResponse { cluster: Some(render_full(r, c)) })
        })
    }

    pub(crate) fn describe_clusters_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeClustersRequest,
    ) -> Result<t::DescribeClustersResponse, ServiceError> {
        let refs = input.clusters.clone().unwrap_or_else(|| vec!["default".into()]);
        if refs.len() > 100 {
            return Err(invalid("Clusters cannot have more than 100 elements"));
        }
        let include = input.include.clone().unwrap_or_default();
        let scope = Scope::of(ctx);
        let mut clusters = Vec::new();
        let mut failures = Vec::new();
        for reference in refs {
            let name = cluster_name(Some(&reference));
            let arn = scope.cluster_arn(&name);
            let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
            authorize(ctx, "DescribeClusters", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
            self.with_region(ctx, |r, _| match r.clusters.get(&name) {
                Some(c) => clusters.push(render(r, c, &include)),
                None => failures.push(failure(arn.clone(), "MISSING")),
            });
        }
        Ok(t::DescribeClustersResponse { clusters: Some(clusters), failures: Some(failures) })
    }

    pub(crate) fn list_clusters_op(
        &self,
        ctx: &RequestContext,
        input: t::ListClustersRequest,
    ) -> Result<t::ListClustersResponse, ServiceError> {
        authorize(ctx, "ListClusters", "*", Cond::new())?;
        self.with_region(ctx, |r, _| {
            let arns: Vec<String> = r
                .clusters
                .values()
                .filter(|c| c.status.as_deref() != Some("INACTIVE"))
                .filter_map(|c| c.cluster_arn.clone())
                .collect();
            let (page, next_token) = paginate(&arns, input.next_token.as_deref(), input.max_results, 100)?;
            Ok(t::ListClustersResponse { cluster_arns: Some(page), next_token })
        })
    }

    pub(crate) fn delete_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteClusterRequest,
    ) -> Result<t::DeleteClusterResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let name = cluster_name(Some(&input.cluster));
        let arn = scope.cluster_arn(&name);
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "DeleteCluster", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        self.with_region(ctx, |r, _| {
            active(r, Some(&input.cluster))?;
            if r.container_instances.values().any(|i| {
                i.cluster == name && matches!(i.instance.status.as_deref(), Some("ACTIVE" | "DRAINING" | "REGISTERING"))
            }) {
                return Err(errors::cluster_contains_container_instances(
                    "The Cluster cannot be deleted while Container Instances are active or draining.",
                ));
            }
            if r.services.values().any(|s| s.cluster == name && s.service.status.as_deref() != Some("INACTIVE")) {
                return Err(errors::cluster_contains_services(
                    "The Cluster cannot be deleted while Services are active.",
                ));
            }
            if r.tasks.values().any(|t| t.cluster == name && t.task.last_status.as_deref() != Some("STOPPED")) {
                return Err(errors::cluster_contains_tasks("The Cluster cannot be deleted while Tasks are active."));
            }
            if r.gateway_associations.values().any(|a| a.cluster_arn == arn && a.status == "ACTIVE") {
                return Err(errors::cluster_contains_services(
                    "The Cluster cannot be deleted while gateways are associated with it.",
                ));
            }
            let c = r.clusters.get_mut(&name).expect("checked above");
            c.status = Some("INACTIVE".into());
            c.capacity_providers = Some(Vec::new());
            c.default_capacity_provider_strategy = Some(Vec::new());
            let c = r.clusters[&name].clone();
            r.tags.remove(&arn);
            Ok(t::DeleteClusterResponse { cluster: Some(render_full(r, &c)) })
        })
    }

    pub(crate) fn update_cluster_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateClusterRequest,
    ) -> Result<t::UpdateClusterResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let name = cluster_name(Some(&input.cluster));
        let arn = scope.cluster_arn(&name);
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "UpdateCluster", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        if let Some(s) = &input.settings {
            check_settings(s)?;
        }
        self.with_region(ctx, |r, scope| {
            active(r, Some(&input.cluster))?;
            let c = r.clusters.get_mut(&name).expect("checked above");
            if let Some(s) = &input.settings {
                merge_settings(c.settings.get_or_insert_with(Vec::new), s);
            }
            if let Some(conf) = input.configuration {
                c.configuration = Some(conf);
            }
            if let Some(d) = &input.service_connect_defaults {
                c.service_connect_defaults =
                    Some(t::ClusterServiceConnectDefaults { namespace: Some(namespace_arn(scope, &d.namespace)) });
            }
            let c = r.clusters[&name].clone();
            Ok(t::UpdateClusterResponse { cluster: Some(render_full(r, &c)) })
        })
    }

    pub(crate) fn update_cluster_settings_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateClusterSettingsRequest,
    ) -> Result<t::UpdateClusterSettingsResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let name = cluster_name(Some(&input.cluster));
        let arn = scope.cluster_arn(&name);
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "UpdateClusterSettings", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        check_settings(&input.settings)?;
        self.with_region(ctx, |r, _| {
            active(r, Some(&input.cluster))?;
            let c = r.clusters.get_mut(&name).expect("checked above");
            merge_settings(c.settings.get_or_insert_with(Vec::new), &input.settings);
            let c = r.clusters[&name].clone();
            Ok(t::UpdateClusterSettingsResponse { cluster: Some(render_full(r, &c)) })
        })
    }

    pub(crate) fn put_cluster_capacity_providers_op(
        &self,
        ctx: &RequestContext,
        input: t::PutClusterCapacityProvidersRequest,
    ) -> Result<t::PutClusterCapacityProvidersResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let name = cluster_name(Some(&input.cluster));
        let arn = scope.cluster_arn(&name);
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "PutClusterCapacityProviders", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        self.with_region(ctx, |r, scope| {
            active(r, Some(&input.cluster))?;
            capacity::check_cluster_providers(
                r,
                scope,
                &name,
                &input.capacity_providers,
                &input.default_capacity_provider_strategy,
            )?;
            // Providers services still use cannot be removed.
            let names: Vec<String> = input.capacity_providers.iter().map(|p| capacity::provider_name(p)).collect();
            for s in r.services.values().filter(|s| s.cluster == name && s.service.status.as_deref() == Some("ACTIVE"))
            {
                for item in s.service.capacity_provider_strategy.iter().flatten() {
                    if !names.contains(&item.capacity_provider) {
                        return Err(errors::resource_in_use(format!(
                            "The specified capacity provider '{}' is in use and cannot be removed.",
                            item.capacity_provider
                        )));
                    }
                }
            }
            let c = r.clusters.get_mut(&name).expect("checked above");
            c.capacity_providers = Some(names);
            c.default_capacity_provider_strategy = Some(
                input
                    .default_capacity_provider_strategy
                    .iter()
                    .map(|i| t::CapacityProviderStrategyItem {
                        capacity_provider: capacity::provider_name(&i.capacity_provider),
                        ..i.clone()
                    })
                    .collect(),
            );
            let c = r.clusters[&name].clone();
            Ok(t::PutClusterCapacityProvidersResponse { cluster: Some(render_full(r, &c)) })
        })
    }
}

/// Cloud Map namespaces are named by ARN or by name.
fn namespace_arn(scope: &Scope, namespace: &str) -> String {
    if namespace.starts_with("arn:") {
        namespace.to_string()
    } else {
        format!("arn:{}:servicediscovery:{}:{}:namespace/{namespace}", scope.partition, scope.region, scope.account)
    }
}
