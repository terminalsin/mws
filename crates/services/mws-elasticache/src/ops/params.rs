//! Cache parameter groups and their parameters.

use mws_core::{RequestContext, ServiceError};

use super::*;
use crate::catalog;
use crate::engine;
use crate::generated::{errors, types as t};
use crate::state::{ParameterGroup, RegionState};
use crate::ElastiCache;

fn not_found(name: &str) -> ServiceError {
    errors::cache_parameter_group_not_found_fault(format!("CacheParameterGroup {name} not found."))
}

/// The family of a default (`default.redis7`, `default.redis7.cluster.on`)
/// or custom group.
pub(crate) fn family_of(r: &RegionState, name: &str) -> Option<String> {
    if let Some(g) = r.parameter_groups.get(name) {
        return g.info.cache_parameter_group_family.clone();
    }
    let family = name.strip_prefix("default.")?;
    let family = family.strip_suffix(".cluster.on").unwrap_or(family);
    catalog::default_groups(family).iter().any(|g| g == name).then(|| family.to_string())
}

fn is_default(name: &str) -> bool {
    name.starts_with("default.")
}

/// Every parameter of a group with its current value and source.
fn values(r: &RegionState, name: &str) -> Option<Vec<(&'static catalog::Param, String, &'static str)>> {
    let family = family_of(r, name)?;
    let custom = r.parameter_groups.get(name);
    let cluster = name.ends_with(".cluster.on");
    Some(
        catalog::parameters(&family)
            .into_iter()
            .map(|(p, default)| {
                if let Some(v) = custom.and_then(|g| g.values.get(p.name)) {
                    (p, v.clone(), "user")
                } else if p.name == "cluster-enabled" && cluster {
                    (p, "yes".to_string(), "system")
                } else {
                    (p, default, "system")
                }
            })
            .collect(),
    )
}

pub(crate) fn cluster_enabled(r: &RegionState, name: &str) -> bool {
    values(r, name).is_some_and(|v| v.iter().any(|(p, v, _)| p.name == "cluster-enabled" && v == "yes"))
}

/// The values to hand the engine (names it knows).
pub(crate) fn engine_values(r: &RegionState, name: &str) -> Vec<(String, String)> {
    let Some(vals) = values(r, name) else { return vec![] };
    let memcached = family_of(r, name).is_some_and(|f| f.starts_with("memcached"));
    vals.into_iter().filter(|(p, _, _)| memcached || p.engine).map(|(p, v, _)| (p.name.to_string(), v)).collect()
}

fn group_info(ctx: &RequestContext, name: &str, family: &str, description: &str) -> t::CacheParameterGroup {
    t::CacheParameterGroup {
        cache_parameter_group_name: Some(name.into()),
        cache_parameter_group_family: Some(family.into()),
        description: Some(description.into()),
        is_global: Some(false),
        arn: Some(arn(ctx, "parametergroup", name)),
    }
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateCacheParameterGroupMessage,
) -> Result<t::CreateCacheParameterGroupResult, ServiceError> {
    let name = input.cache_parameter_group_name.to_ascii_lowercase();
    identifier("CacheParameterGroupName", &name, 255)?;
    if is_default(&name) {
        return Err(invalid("The parameter group name cannot begin with \"default.\"."));
    }
    let family = input.cache_parameter_group_family.clone();
    if catalog::family_engine(&family).is_none() {
        return Err(invalid(format!("Invalid parameter group family: {family}")));
    }
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "parametergroup", &name);
    authorize_create(ctx, "CreateCacheParameterGroup", &resource, &tags, Default::default())?;
    svc.with_region(ctx, |r| {
        if r.parameter_groups.contains_key(&name) {
            return Err(errors::cache_parameter_group_already_exists_fault(format!(
                "Parameter group {name} already exists."
            )));
        }
        if r.parameter_groups.len() >= 150 {
            return Err(errors::cache_parameter_group_quota_exceeded_fault("Cache parameter group quota exceeded."));
        }
        let info = group_info(ctx, &name, &family, &input.description);
        r.parameter_groups.insert(name.clone(), ParameterGroup { info: info.clone(), values: Default::default() });
        set_tags(r, &resource, input.tags.clone());
        Ok(t::CreateCacheParameterGroupResult { cache_parameter_group: Some(info) })
    })
}

fn in_use(r: &RegionState, name: &str) -> bool {
    r.clusters.values().any(|c| {
        c.info.cache_parameter_group.as_ref().and_then(|g| g.cache_parameter_group_name.as_deref()) == Some(name)
    })
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteCacheParameterGroupMessage,
) -> Result<(), ServiceError> {
    let name = input.cache_parameter_group_name.to_ascii_lowercase();
    svc.with_region(ctx, |r| {
        authorize(ctx, r, "DeleteCacheParameterGroup", &arn(ctx, "parametergroup", &name), Default::default())?;
        if is_default(&name) {
            return Err(errors::invalid_cache_parameter_group_state_fault(
                "Cannot delete default cache parameter group.",
            ));
        }
        if !r.parameter_groups.contains_key(&name) {
            return Err(not_found(&name));
        }
        if in_use(r, &name) {
            return Err(errors::invalid_cache_parameter_group_state_fault(format!(
                "Cache parameter group {name} is in use by a cache cluster."
            )));
        }
        r.parameter_groups.remove(&name);
        r.tags.remove(&arn(ctx, "parametergroup", &name));
        Ok(())
    })
}

/// Push a group's engine values to every node that uses it.
fn push(svc: &ElastiCache, ctx: &RequestContext, name: &str) {
    let (nodes, commands) = svc.with_region(ctx, |r| {
        let commands: Vec<Vec<String>> = engine_values(r, name)
            .into_iter()
            .filter(|(k, _)| family_of(r, name).is_some_and(|f| !f.starts_with("memcached")) && !k.is_empty())
            .map(|(k, v)| vec!["CONFIG".into(), "SET".into(), k, v])
            .collect();
        let mut nodes = Vec::new();
        for c in r.clusters.values() {
            let uses = c.info.cache_parameter_group.as_ref().and_then(|g| g.cache_parameter_group_name.as_deref())
                == Some(name);
            if uses {
                for n in engine::nodes_of(r, c.info.replication_group_id.as_deref(), Some(c.id())) {
                    if !nodes.iter().any(|(p, _)| *p == n.0) {
                        nodes.push(n);
                    }
                }
            }
        }
        (nodes, commands)
    });
    engine::run_everywhere(svc, nodes, commands);
}

pub(crate) async fn modify(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyCacheParameterGroupMessage,
) -> Result<t::CacheParameterGroupNameMessage, ServiceError> {
    let name = input.cache_parameter_group_name.to_ascii_lowercase();
    if input.parameter_name_values.is_empty() || input.parameter_name_values.len() > 20 {
        return Err(invalid("Between 1 and 20 parameters can be modified at a time."));
    }
    svc.with_region(ctx, |r| {
        authorize(ctx, r, "ModifyCacheParameterGroup", &arn(ctx, "parametergroup", &name), Default::default())?;
        if is_default(&name) {
            return Err(errors::invalid_cache_parameter_group_state_fault(
                "Default parameter groups cannot be modified.",
            ));
        }
        let family = family_of(r, &name).ok_or_else(|| not_found(&name))?;
        let mut updates = Vec::new();
        for pv in &input.parameter_name_values {
            let pname = pv.parameter_name.clone().unwrap_or_default();
            let value = pv.parameter_value.clone().unwrap_or_default();
            let p = catalog::parameter(&family, &pname)
                .ok_or_else(|| invalid(format!("Unrecognized parameter name: {pname}")))?;
            if !p.modifiable {
                return Err(invalid(format!("Parameter {pname} is not modifiable.")));
            }
            if !catalog::value_allowed(p, &value) {
                return Err(invalid(format!("Unsupported value {value} for parameter {pname}.")));
            }
            updates.push((pname, value));
        }
        let g = r.parameter_groups.get_mut(&name).ok_or_else(|| not_found(&name))?;
        for (k, v) in updates {
            g.values.insert(k, v);
        }
        Ok(())
    })?;
    push(svc, ctx, &name);
    Ok(t::CacheParameterGroupNameMessage { cache_parameter_group_name: Some(name) })
}

pub(crate) async fn reset(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ResetCacheParameterGroupMessage,
) -> Result<t::CacheParameterGroupNameMessage, ServiceError> {
    let name = input.cache_parameter_group_name.to_ascii_lowercase();
    svc.with_region(ctx, |r| {
        authorize(ctx, r, "ResetCacheParameterGroup", &arn(ctx, "parametergroup", &name), Default::default())?;
        if is_default(&name) {
            return Err(errors::invalid_cache_parameter_group_state_fault(
                "Default parameter groups cannot be modified.",
            ));
        }
        let g = r.parameter_groups.get_mut(&name).ok_or_else(|| not_found(&name))?;
        let names: Vec<String> =
            input.parameter_name_values.iter().flatten().filter_map(|p| p.parameter_name.clone()).collect();
        match (input.reset_all_parameters == Some(true), names.is_empty()) {
            (true, true) => g.values.clear(),
            (false, false) => {
                for n in names {
                    g.values.remove(&n);
                }
            }
            (true, false) => {
                return Err(combination("ResetAllParameters cannot be used together with ParameterNameValues."))
            }
            (false, true) => {
                return Err(combination("Either ResetAllParameters or ParameterNameValues must be specified."))
            }
        }
        Ok(())
    })?;
    push(svc, ctx, &name);
    Ok(t::CacheParameterGroupNameMessage { cache_parameter_group_name: Some(name) })
}

pub(crate) async fn describe_groups(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeCacheParameterGroupsMessage,
) -> Result<t::CacheParameterGroupsMessage, ServiceError> {
    svc.with_region(ctx, |r| {
        let mut all: Vec<t::CacheParameterGroup> = Vec::new();
        for family in catalog::families() {
            for g in catalog::default_groups(family) {
                all.push(group_info(ctx, &g, family, &format!("Default parameter group for {family}")));
            }
        }
        all.extend(r.parameter_groups.values().map(|g| g.info.clone()));
        let items = match input.cache_parameter_group_name.as_deref() {
            Some(n) => {
                let n = n.to_ascii_lowercase();
                let found: Vec<_> =
                    all.into_iter().filter(|g| g.cache_parameter_group_name.as_deref() == Some(&n)).collect();
                if found.is_empty() {
                    return Err(not_found(&n));
                }
                authorize(ctx, r, "DescribeCacheParameterGroups", &arn(ctx, "parametergroup", &n), Default::default())?;
                found
            }
            None => {
                ctx.authorize(
                    "elasticache:DescribeCacheParameterGroups",
                    &arn(ctx, "parametergroup", "*"),
                    Default::default(),
                )?;
                all
            }
        };
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::CacheParameterGroupsMessage { marker, cache_parameter_groups: Some(page) })
    })
}

pub(crate) async fn describe_parameters(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeCacheParametersMessage,
) -> Result<t::CacheParameterGroupDetails, ServiceError> {
    let name = input.cache_parameter_group_name.to_ascii_lowercase();
    svc.with_region(ctx, |r| {
        authorize(ctx, r, "DescribeCacheParameters", &arn(ctx, "parametergroup", &name), Default::default())?;
        let vals = values(r, &name).ok_or_else(|| not_found(&name))?;
        let family = family_of(r, &name).unwrap_or_default();
        let items: Vec<t::Parameter> = vals
            .into_iter()
            .filter(|(_, _, src)| {
                input.source.as_deref().is_none_or(|s| s == *src || (s == "engine-default" && *src == "system"))
            })
            .map(|(p, v, src)| catalog::to_wire(p, &v, src))
            .collect();
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        let engine = catalog::family_engine(&family).unwrap_or(crate::EngineKind::Redis);
        Ok(t::CacheParameterGroupDetails {
            marker: marker.clone(),
            parameters: Some(page),
            cache_node_type_specific_parameters: marker.is_none().then(|| catalog::node_type_specific(engine)),
        })
    })
}

pub(crate) async fn describe_defaults(
    _svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeEngineDefaultParametersMessage,
) -> Result<t::DescribeEngineDefaultParametersResult, ServiceError> {
    ctx.authorize("elasticache:DescribeEngineDefaultParameters", "*", Default::default())?;
    let family = input.cache_parameter_group_family.clone();
    let engine =
        catalog::family_engine(&family).ok_or_else(|| invalid(format!("Invalid parameter group family: {family}")))?;
    let items: Vec<t::Parameter> =
        catalog::parameters(&family).into_iter().map(|(p, v)| catalog::to_wire(p, &v, "system")).collect();
    let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
    Ok(t::DescribeEngineDefaultParametersResult {
        engine_defaults: Some(t::EngineDefaults {
            cache_parameter_group_family: Some(family),
            marker: marker.clone(),
            parameters: Some(page),
            cache_node_type_specific_parameters: marker.is_none().then(|| catalog::node_type_specific(engine)),
        }),
    })
}
