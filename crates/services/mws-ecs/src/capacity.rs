//! Capacity providers: the built-in `FARGATE` and `FARGATE_SPOT`, and
//! Auto Scaling group and Managed Instances providers.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types as t};
use crate::names::{
    authorize, check_tags, failure, invalid, last_segment, paginate, request_tags, resource_tags, Cond, Scope,
};
use crate::state::Region;
use crate::{tags, Ecs};

pub const BUILT_IN: &[&str] = &["FARGATE", "FARGATE_SPOT"];

/// A provider's name from a reference (name or ARN).
pub fn provider_name(reference: &str) -> String {
    last_segment(reference).to_string()
}

fn built_in(scope: &Scope, name: &str) -> t::CapacityProvider {
    t::CapacityProvider {
        capacity_provider_arn: Some(scope.arn(&format!("capacity-provider/{name}"))),
        name: Some(name.into()),
        status: Some("ACTIVE".into()),
        r#type: Some(name.into()),
        tags: Some(Vec::new()),
        ..Default::default()
    }
}

/// The provider a reference names, built in or custom.
pub fn find(r: &Region, scope: &Scope, reference: &str) -> Option<t::CapacityProvider> {
    let name = provider_name(reference);
    if BUILT_IN.contains(&name.as_str()) {
        return Some(built_in(scope, &name));
    }
    r.capacity_providers.get(&name).filter(|c| c.status.as_deref() == Some("ACTIVE")).cloned()
}

/// The checks CreateCluster and PutClusterCapacityProviders make.
pub fn check_cluster_providers(
    r: &Region,
    scope: &Scope,
    cluster: &str,
    providers: &[String],
    strategy: &[t::CapacityProviderStrategyItem],
) -> Result<(), ServiceError> {
    for p in providers {
        let Some(cp) = find(r, scope, p) else {
            return Err(invalid(format!(
                "The specified capacity provider '{p}' does not exist. Specify a valid name or ARN and try again."
            )));
        };
        if let Some(owner) = cp.cluster.as_deref() {
            if owner != cluster {
                return Err(invalid(format!(
                    "The specified capacity provider '{p}' is associated with another cluster."
                )));
            }
        }
        if cp.auto_scaling_group_provider.is_some()
            && r.clusters.iter().any(|(name, c)| {
                name != cluster
                    && c.status.as_deref() == Some("ACTIVE")
                    && c.capacity_providers.iter().flatten().any(|x| provider_name(x) == provider_name(p))
            })
        {
            return Err(errors::resource_in_use(format!(
                "The specified capacity provider '{p}' is already associated with another cluster."
            )));
        }
    }
    check_strategy(strategy)?;
    let names: Vec<String> = providers.iter().map(|p| provider_name(p)).collect();
    for item in strategy {
        if !names.contains(&provider_name(&item.capacity_provider)) {
            return Err(invalid(
                "The specified capacity provider strategy cannot contain a capacity provider that is not associated with the cluster. Associate the capacity provider with the cluster or specify a valid capacity provider and try again.",
            ));
        }
    }
    Ok(())
}

/// Weights, bases and mixing rules of a capacity provider strategy.
pub fn check_strategy(strategy: &[t::CapacityProviderStrategyItem]) -> Result<(), ServiceError> {
    if strategy.len() > 20 {
        return Err(invalid("The capacity provider strategy cannot contain more than 20 capacity providers."));
    }
    if strategy.iter().filter(|i| i.base > 0).count() > 1 {
        return Err(invalid("Only one capacity provider in a capacity provider strategy can have a base defined."));
    }
    if !strategy.is_empty() && strategy.iter().all(|i| i.weight == 0) {
        return Err(invalid(
            "At least one capacity provider in a capacity provider strategy must have a weight greater than zero.",
        ));
    }
    let fargate = strategy.iter().any(|i| BUILT_IN.contains(&provider_name(&i.capacity_provider).as_str()));
    let other = strategy.iter().any(|i| !BUILT_IN.contains(&provider_name(&i.capacity_provider).as_str()));
    if fargate && other {
        return Err(invalid(
            "A capacity provider strategy cannot contain a mix of capacity providers using Auto Scaling groups and Fargate providers. Specify one or the other and try again.",
        ));
    }
    for i in strategy {
        if !(0..=1000).contains(&i.weight) || !(0..=100_000).contains(&i.base) {
            return Err(invalid("The capacity provider strategy weight must be between 0 and 1000, and base between 0 and 100000."));
        }
    }
    Ok(())
}

/// Which provider of a strategy the next task goes to, given how many
/// tasks each already has: bases first, then by weight.
pub fn pick(strategy: &[t::CapacityProviderStrategyItem], counts: &[usize]) -> usize {
    for (i, item) in strategy.iter().enumerate() {
        if counts[i] < item.base as usize {
            return i;
        }
    }
    let total_weight: i32 = strategy.iter().map(|i| i.weight).sum();
    if total_weight == 0 {
        return 0;
    }
    let total: usize = counts.iter().sum::<usize>() + 1;
    // The provider furthest below its weighted share.
    let mut best = 0;
    let mut best_deficit = f64::MIN;
    for (i, item) in strategy.iter().enumerate() {
        if item.weight == 0 {
            continue;
        }
        let share = total as f64 * item.weight as f64 / total_weight as f64;
        let deficit = share - counts[i] as f64;
        if deficit > best_deficit {
            best = i;
            best_deficit = deficit;
        }
    }
    best
}

fn valid_provider_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

impl Ecs {
    pub(crate) fn create_capacity_provider_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateCapacityProviderRequest,
    ) -> Result<t::CreateCapacityProviderResponse, ServiceError> {
        let lower = input.name.to_ascii_lowercase();
        if ["aws", "ecs", "fargate"].iter().any(|p| lower.starts_with(p)) {
            return Err(invalid(
                "The specified capacity provider name is invalid. Capacity provider names can't begin with 'aws', 'ecs', or 'fargate'. Specify a valid name and try again.",
            ));
        }
        if !valid_provider_name(&input.name) {
            return Err(invalid(
                "The specified capacity provider name is invalid. Up to 255 characters are allowed, including letters (upper and lowercase), numbers, underscores, periods, and hyphens.",
            ));
        }
        match (&input.auto_scaling_group_provider, &input.managed_instances_provider) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(invalid(
                    "Specify either an Auto Scaling group provider or a Managed Instances provider, but not both.",
                ));
            }
            (None, Some(_)) if input.cluster.is_none() => {
                return Err(invalid("A cluster must be specified for a Managed Instances capacity provider."));
            }
            _ => {}
        }
        if let Some(tags) = &input.tags {
            check_tags(tags)?;
        }
        let scope = Scope::of(ctx);
        let arn = scope.arn(&format!("capacity-provider/{}", input.name));
        authorize(ctx, "CreateCapacityProvider", &arn, Cond::new().extend(request_tags(input.tags.as_ref())))?;
        self.with_region(ctx, |r, _| {
            if r.capacity_providers.get(&input.name).is_some_and(|c| c.status.as_deref() != Some("INACTIVE")) {
                return Err(client_exists());
            }
            if let Some(asg) = &input.auto_scaling_group_provider {
                if !asg.auto_scaling_group_arn.starts_with("arn:") {
                    return Err(invalid("The specified Auto Scaling group ARN is invalid."));
                }
                if r.capacity_providers.values().any(|c| {
                    c.status.as_deref() == Some("ACTIVE")
                        && c.auto_scaling_group_provider.as_ref().map(|a| &a.auto_scaling_group_arn)
                            == Some(&asg.auto_scaling_group_arn)
                }) {
                    return Err(invalid(
                        "The specified Auto Scaling group is already in use by another capacity provider.",
                    ));
                }
            }
            let cluster = input.cluster.as_deref().map(|c| crate::names::cluster_name(Some(c)));
            if let Some(c) = &cluster {
                crate::clusters::active(r, Some(c))?;
            }
            let mut asg = input.auto_scaling_group_provider.clone();
            if let Some(a) = asg.as_mut() {
                let ms = a.managed_scaling.get_or_insert_with(Default::default);
                ms.status.get_or_insert_with(|| "DISABLED".into());
                ms.target_capacity.get_or_insert(100);
                ms.minimum_scaling_step_size.get_or_insert(1);
                ms.maximum_scaling_step_size.get_or_insert(10_000);
                ms.instance_warmup_period.get_or_insert(300);
                a.managed_termination_protection.get_or_insert_with(|| "DISABLED".into());
                a.managed_draining.get_or_insert_with(|| "ENABLED".into());
            }
            let cp = t::CapacityProvider {
                capacity_provider_arn: Some(arn.clone()),
                name: Some(input.name.clone()),
                cluster: cluster.clone(),
                status: Some("ACTIVE".into()),
                r#type: Some(if asg.is_some() { "EC2_AUTOSCALING" } else { "MANAGED_INSTANCES" }.into()),
                auto_scaling_group_provider: asg,
                managed_instances_provider: input.managed_instances_provider.as_ref().map(|m| {
                    t::ManagedInstancesProvider {
                        infrastructure_role_arn: Some(m.infrastructure_role_arn.clone()),
                        instance_launch_template: Some(m.instance_launch_template.clone()),
                        propagate_tags: m.propagate_tags.clone(),
                        infrastructure_optimization: m.infrastructure_optimization.clone(),
                        auto_repair_configuration: m.auto_repair_configuration.clone(),
                    }
                }),
                update_status: None,
                update_status_reason: None,
                tags: None,
            };
            tags::store(r, &arn, input.tags.as_ref());
            r.capacity_providers.insert(input.name.clone(), cp.clone());
            if let Some(c) = cluster.and_then(|c| r.clusters.get_mut(&c)) {
                c.capacity_providers.get_or_insert_with(Vec::new).push(input.name.clone());
            }
            Ok(t::CreateCapacityProviderResponse { capacity_provider: Some(render(r, &cp, true)) })
        })
    }

    pub(crate) fn describe_capacity_providers_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeCapacityProvidersRequest,
    ) -> Result<t::DescribeCapacityProvidersResponse, ServiceError> {
        authorize(ctx, "DescribeCapacityProviders", "*", Cond::new())?;
        let with_tags = input.include.iter().flatten().any(|i| i == "TAGS");
        self.with_region(ctx, |r, scope| {
            let cluster = input.cluster.as_deref().map(|c| crate::names::cluster_name(Some(c)));
            let mut found = Vec::new();
            let mut failures = Vec::new();
            match &input.capacity_providers {
                Some(refs) => {
                    for p in refs {
                        let name = provider_name(p);
                        let cp = if BUILT_IN.contains(&name.as_str()) {
                            Some(built_in(scope, &name))
                        } else {
                            r.capacity_providers.get(&name).cloned()
                        };
                        match cp {
                            Some(cp) => found.push(render(r, &cp, with_tags)),
                            None => failures.push(failure(p.clone(), "MISSING")),
                        }
                    }
                }
                None => {
                    found.extend(BUILT_IN.iter().map(|n| built_in(scope, n)));
                    found.extend(
                        r.capacity_providers
                            .values()
                            .filter(|c| c.status.as_deref() != Some("INACTIVE"))
                            .filter(|c| cluster.is_none() || c.cluster == cluster)
                            .map(|c| render(r, c, with_tags)),
                    );
                }
            }
            let (page, next_token) = paginate(&found, input.next_token.as_deref(), input.max_results, 10)?;
            Ok(t::DescribeCapacityProvidersResponse {
                capacity_providers: Some(page),
                failures: Some(failures),
                next_token,
            })
        })
    }

    pub(crate) fn update_capacity_provider_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateCapacityProviderRequest,
    ) -> Result<t::UpdateCapacityProviderResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let name = provider_name(&input.name);
        let arn = scope.arn(&format!("capacity-provider/{name}"));
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "UpdateCapacityProvider", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        self.with_region(ctx, |r, _| {
            let cp = r
                .capacity_providers
                .get_mut(&name)
                .filter(|c| c.status.as_deref() == Some("ACTIVE"))
                .ok_or_else(|| invalid("The specified capacity provider does not exist."))?;
            if let Some(u) = &input.auto_scaling_group_provider {
                let Some(asg) = cp.auto_scaling_group_provider.as_mut() else {
                    return Err(invalid("The capacity provider does not use an Auto Scaling group."));
                };
                if let Some(ms) = &u.managed_scaling {
                    let cur = asg.managed_scaling.get_or_insert_with(Default::default);
                    if ms.status.is_some() {
                        cur.status = ms.status.clone();
                    }
                    if ms.target_capacity.is_some() {
                        cur.target_capacity = ms.target_capacity;
                    }
                    if ms.minimum_scaling_step_size.is_some() {
                        cur.minimum_scaling_step_size = ms.minimum_scaling_step_size;
                    }
                    if ms.maximum_scaling_step_size.is_some() {
                        cur.maximum_scaling_step_size = ms.maximum_scaling_step_size;
                    }
                    if ms.instance_warmup_period.is_some() {
                        cur.instance_warmup_period = ms.instance_warmup_period;
                    }
                }
                if u.managed_termination_protection.is_some() {
                    asg.managed_termination_protection = u.managed_termination_protection.clone();
                }
                if u.managed_draining.is_some() {
                    asg.managed_draining = u.managed_draining.clone();
                }
            }
            if let Some(m) = &input.managed_instances_provider {
                let Some(cur) = cp.managed_instances_provider.as_mut() else {
                    return Err(invalid("The capacity provider is not a Managed Instances capacity provider."));
                };
                cur.infrastructure_role_arn = Some(m.infrastructure_role_arn.clone());
                if m.propagate_tags.is_some() {
                    cur.propagate_tags = m.propagate_tags.clone();
                }
                if m.infrastructure_optimization.is_some() {
                    cur.infrastructure_optimization = m.infrastructure_optimization.clone();
                }
                if m.auto_repair_configuration.is_some() {
                    cur.auto_repair_configuration = m.auto_repair_configuration.clone();
                }
            }
            cp.update_status = Some("UPDATE_COMPLETE".into());
            let cp = cp.clone();
            Ok(t::UpdateCapacityProviderResponse { capacity_provider: Some(render(r, &cp, false)) })
        })
    }

    pub(crate) fn delete_capacity_provider_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteCapacityProviderRequest,
    ) -> Result<t::DeleteCapacityProviderResponse, ServiceError> {
        let scope = Scope::of(ctx);
        let name = provider_name(&input.capacity_provider);
        let arn = scope.arn(&format!("capacity-provider/{name}"));
        let tags = self.with_region(ctx, |r, _| r.tags.get(&arn).cloned());
        authorize(ctx, "DeleteCapacityProvider", &arn, Cond::new().extend(resource_tags(tags.as_ref())))?;
        self.with_region(ctx, |r, _| {
            if BUILT_IN.contains(&name.as_str()) {
                return Err(invalid("The specified capacity provider is reserved and cannot be deleted."));
            }
            if !r.capacity_providers.get(&name).is_some_and(|c| c.status.as_deref() == Some("ACTIVE")) {
                return Err(invalid("The specified capacity provider does not exist."));
            }
            let managed_by = r.capacity_providers[&name].cluster.clone();
            let in_use_by_cluster = r.clusters.iter().any(|(cname, c)| {
                Some(cname) != managed_by.as_ref()
                    && c.status.as_deref() == Some("ACTIVE")
                    && c.capacity_providers.iter().flatten().any(|p| provider_name(p) == name)
            });
            let in_use_by_service = r.services.values().any(|s| {
                s.service.status.as_deref() == Some("ACTIVE")
                    && s.service.capacity_provider_strategy.iter().flatten().any(|i| provider_name(&i.capacity_provider) == name)
            });
            if in_use_by_cluster || in_use_by_service {
                return Err(errors::resource_in_use(
                    "The specified capacity provider is in use and must be disassociated from the cluster before it can be deleted.",
                ));
            }
            if let Some(c) = managed_by.and_then(|c| r.clusters.get_mut(&c)) {
                if let Some(list) = c.capacity_providers.as_mut() {
                    list.retain(|p| provider_name(p) != name);
                }
            }
            let cp = r.capacity_providers.get_mut(&name).expect("checked above");
            cp.status = Some("INACTIVE".into());
            cp.update_status = Some("DELETE_COMPLETE".into());
            let cp = cp.clone();
            r.tags.remove(&arn);
            Ok(t::DeleteCapacityProviderResponse { capacity_provider: Some(render(r, &cp, false)) })
        })
    }
}

fn client_exists() -> ServiceError {
    invalid("The specified capacity provider already exists. To change the configuration of an existing capacity provider, update the capacity provider.")
}

fn render(r: &Region, cp: &t::CapacityProvider, with_tags: bool) -> t::CapacityProvider {
    let mut out = cp.clone();
    out.tags = with_tags
        .then(|| r.tags.get(cp.capacity_provider_arn.as_deref().unwrap_or_default()).cloned().unwrap_or_default());
    out
}
