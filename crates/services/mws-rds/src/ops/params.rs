//! DB parameter groups and DB cluster parameter groups. Both kinds share
//! one implementation; `cluster` picks the kind.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, authorize_create};
use crate::catalog::{self, Param};
use crate::generated::{errors, types as t};
use crate::state::{ParamGroup, RegionState};
use crate::util::{
    arn, invalid_combination, invalid_parameter, name_of, paginate, request_tag_context, tags_from, Filters,
};
use crate::Rds;

pub fn not_found(cluster: bool, name: &str) -> ServiceError {
    if cluster {
        errors::db_cluster_parameter_group_not_found_fault(format!("DBClusterParameterGroup not found: {name}"))
    } else {
        errors::db_parameter_group_not_found_fault(format!("DBParameterGroup not found: {name}"))
    }
}

fn kind(cluster: bool) -> &'static str {
    if cluster {
        "cluster-pg"
    } else {
        "pg"
    }
}

fn groups(r: &mut RegionState, cluster: bool) -> &mut std::collections::BTreeMap<String, ParamGroup> {
    if cluster {
        &mut r.cluster_parameter_groups
    } else {
        &mut r.parameter_groups
    }
}

fn shape(g: &ParamGroup) -> t::DBParameterGroup {
    t::DBParameterGroup {
        db_parameter_group_name: Some(g.name.clone()),
        db_parameter_group_family: Some(g.family.clone()),
        description: Some(g.description.clone()),
        db_parameter_group_arn: Some(g.arn.clone()),
    }
}

fn cluster_shape(g: &ParamGroup) -> t::DBClusterParameterGroup {
    t::DBClusterParameterGroup {
        db_cluster_parameter_group_name: Some(g.name.clone()),
        db_parameter_group_family: Some(g.family.clone()),
        description: Some(g.description.clone()),
        db_cluster_parameter_group_arn: Some(g.arn.clone()),
    }
}

/// The parameters of a group, as `DescribeDBParameters` lists them.
fn parameters(g: &ParamGroup, cluster: bool) -> Vec<t::Parameter> {
    let known = catalog::family_params(&g.family, cluster);
    let mut out: Vec<t::Parameter> = known
        .iter()
        .map(|p| match g.values.get(p.name) {
            Some(v) => catalog::to_parameter(p, Some(v.clone()), "user"),
            None => catalog::to_parameter(p, None, if p.value.is_some() { "system" } else { "engine-default" }),
        })
        .collect();
    for (name, value) in &g.values {
        if !known.iter().any(|p| p.name == name) {
            out.push(t::Parameter {
                parameter_name: Some(name.clone()),
                parameter_value: Some(value.clone()),
                source: Some("user".into()),
                apply_type: Some("dynamic".into()),
                data_type: Some("string".into()),
                is_modifiable: Some(true),
                apply_method: Some("pending-reboot".into()),
                ..Default::default()
            });
        }
    }
    out.sort_by(|a, b| a.parameter_name.cmp(&b.parameter_name));
    out
}

impl Rds {
    /// A (cluster) parameter group, creating a family's default group on
    /// first use.
    pub(crate) fn param_group(
        &self,
        ctx: &RequestContext,
        name: &str,
        cluster: bool,
    ) -> Result<ParamGroup, ServiceError> {
        let name = name.to_ascii_lowercase();
        if let Some(g) = self.with_region(ctx, |r| groups(r, cluster).get(&name).cloned()) {
            return Ok(g);
        }
        let family = name.strip_prefix("default.").ok_or_else(|| not_found(cluster, &name))?;
        let (engine, _) = catalog::family(family).ok_or_else(|| not_found(cluster, &name))?;
        if cluster && !engine.aurora && !matches!(engine.kind, catalog::Kind::Postgres | catalog::Kind::Mysql) {
            return Err(not_found(cluster, &name));
        }
        let g = ParamGroup {
            name: name.clone(),
            family: family.to_string(),
            description: format!("Default {}parameter group for {family}", if cluster { "cluster " } else { "" }),
            arn: arn(ctx, kind(cluster), &name),
            values: Default::default(),
            tags: Vec::new(),
        };
        self.with_region(ctx, |r| {
            groups(r, cluster).entry(name).or_insert_with(|| g.clone());
        });
        Ok(g)
    }

    fn create_param_group(
        &self,
        ctx: &RequestContext,
        name: &str,
        family: &str,
        description: &str,
        tags: &Option<Vec<t::Tag>>,
        cluster: bool,
    ) -> Result<ParamGroup, ServiceError> {
        let param = if cluster { "DBClusterParameterGroupName" } else { "DBParameterGroupName" };
        let name = name.to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 255
            || !name.starts_with(|c: char| c.is_ascii_alphabetic())
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            || name.ends_with('-')
            || name.contains("--")
        {
            return Err(invalid_parameter(format!(
                "The parameter {param} is not a valid identifier. Identifiers must begin with a letter; must contain only ASCII letters, digits, and hyphens; and must not end with a hyphen or contain two consecutive hyphens."
            )));
        }
        let tags = tags_from(tags)?;
        let action = if cluster { "CreateDBClusterParameterGroup" } else { "CreateDBParameterGroup" };
        authorize_create(ctx, action, &arn(ctx, kind(cluster), &name), &tags, request_tag_context(&tags))?;
        let family = family.to_ascii_lowercase();
        if catalog::family(&family).is_none() {
            return Err(invalid_parameter(format!(
                "ParameterGroupFamily {family} is not a valid parameter group family"
            )));
        }
        if name.starts_with("default.") {
            return Err(invalid_parameter(format!("{param} cannot start with the prefix default.")));
        }
        let g = ParamGroup {
            name: name.clone(),
            family,
            description: description.to_string(),
            arn: arn(ctx, kind(cluster), &name),
            values: Default::default(),
            tags,
        };
        self.with_region(ctx, |r| {
            let gs = groups(r, cluster);
            if gs.contains_key(&name) {
                // Cluster parameter groups use the same error.
                return Err(errors::db_parameter_group_already_exists_fault(format!(
                    "Parameter group {name} already exists"
                )));
            }
            gs.insert(name.clone(), g.clone());
            Ok(())
        })?;
        Ok(g)
    }

    pub(crate) fn create_db_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBParameterGroupMessage,
    ) -> Result<t::CreateDBParameterGroupResult, ServiceError> {
        let g = self.create_param_group(
            ctx,
            &input.db_parameter_group_name,
            &input.db_parameter_group_family,
            &input.description,
            &input.tags,
            false,
        )?;
        Ok(t::CreateDBParameterGroupResult { db_parameter_group: Some(shape(&g)) })
    }

    pub(crate) fn create_db_cluster_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBClusterParameterGroupMessage,
    ) -> Result<t::CreateDBClusterParameterGroupResult, ServiceError> {
        let g = self.create_param_group(
            ctx,
            &input.db_cluster_parameter_group_name,
            &input.db_parameter_group_family,
            &input.description,
            &input.tags,
            true,
        )?;
        Ok(t::CreateDBClusterParameterGroupResult { db_cluster_parameter_group: Some(cluster_shape(&g)) })
    }

    fn copy_param_group(
        &self,
        ctx: &RequestContext,
        source: &str,
        target: &str,
        description: &str,
        tags: &Option<Vec<t::Tag>>,
        cluster: bool,
    ) -> Result<ParamGroup, ServiceError> {
        let src = self.param_group(ctx, &name_of(source), cluster)?;
        let mut g = self.create_param_group(ctx, target, &src.family, description, tags, cluster)?;
        g.values = src.values;
        let saved = g.clone();
        self.with_region(ctx, |r| groups(r, cluster).insert(saved.name.clone(), saved));
        Ok(g)
    }

    pub(crate) fn copy_db_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CopyDBParameterGroupMessage,
    ) -> Result<t::CopyDBParameterGroupResult, ServiceError> {
        let g = self.copy_param_group(
            ctx,
            &input.source_db_parameter_group_identifier,
            &input.target_db_parameter_group_identifier,
            &input.target_db_parameter_group_description,
            &input.tags,
            false,
        )?;
        Ok(t::CopyDBParameterGroupResult { db_parameter_group: Some(shape(&g)) })
    }

    pub(crate) fn copy_db_cluster_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CopyDBClusterParameterGroupMessage,
    ) -> Result<t::CopyDBClusterParameterGroupResult, ServiceError> {
        let g = self.copy_param_group(
            ctx,
            &input.source_db_cluster_parameter_group_identifier,
            &input.target_db_cluster_parameter_group_identifier,
            &input.target_db_cluster_parameter_group_description,
            &input.tags,
            true,
        )?;
        Ok(t::CopyDBClusterParameterGroupResult { db_cluster_parameter_group: Some(cluster_shape(&g)) })
    }

    /// Set (or with `reset`, clear) parameters of a group, then mark the
    /// databases using it.
    fn modify_params(
        &self,
        ctx: &RequestContext,
        name: &str,
        parameters: &[t::Parameter],
        reset_all: bool,
        reset: bool,
        cluster: bool,
    ) -> Result<String, ServiceError> {
        let name = name.to_ascii_lowercase();
        let action = match (cluster, reset) {
            (false, false) => "ModifyDBParameterGroup",
            (false, true) => "ResetDBParameterGroup",
            (true, false) => "ModifyDBClusterParameterGroup",
            (true, true) => "ResetDBClusterParameterGroup",
        };
        authorize(ctx, action, &arn(ctx, kind(cluster), &name), ConditionContext::new())?;
        let g = self.param_group(ctx, &name, cluster)?;
        if g.name.starts_with("default.") {
            return Err(invalid_parameter(format!(
                "Default {}parameter groups cannot be modified.",
                if cluster { "cluster " } else { "" }
            )));
        }
        if !reset && parameters.is_empty() {
            return Err(invalid_parameter("The parameter Parameters must be provided and must not be empty."));
        }
        if parameters.len() > 20 {
            return Err(invalid_parameter("You can modify up to 20 parameters in a single request."));
        }
        if reset && reset_all && !parameters.is_empty() {
            return Err(invalid_combination("Cannot specify parameters when ResetAllParameters is true."));
        }
        let known = catalog::family_params(&g.family, cluster);
        let all_known: Vec<Param> =
            catalog::family(&g.family).map(|(e, _)| catalog::params(e.kind).to_vec()).unwrap_or_default();
        let mut static_change = false;
        for p in parameters {
            let pname = p.parameter_name.clone().unwrap_or_default();
            if pname.is_empty() {
                return Err(invalid_parameter("The parameter ParameterName must be provided and must not be blank."));
            }
            let method = p.apply_method.clone().unwrap_or_default();
            if !reset && method.is_empty() {
                return Err(invalid_parameter(format!(
                    "The parameter ApplyMethod must be provided for parameter {pname}"
                )));
            }
            if !method.is_empty() && method != "immediate" && method != "pending-reboot" {
                return Err(invalid_parameter(format!("Invalid apply method: {method}")));
            }
            let spec = known.iter().find(|k| k.name == pname);
            if spec.is_none() && all_known.iter().any(|k| k.name == pname) {
                return Err(invalid_parameter(format!(
                    "Could not find parameter with name: {pname}. It is a {} parameter.",
                    if cluster { "DB instance" } else { "DB cluster" }
                )));
            }
            if let Some(spec) = spec {
                if !spec.modifiable {
                    return Err(invalid_parameter(format!("The parameter {pname} cannot be modified.")));
                }
                if spec.apply_type == "static" {
                    if method == "immediate" {
                        return Err(invalid_combination("cannot use immediate apply method for static parameter"));
                    }
                    static_change = true;
                }
                if !reset {
                    let value = p.parameter_value.clone().unwrap_or_default();
                    check_value(spec, &value)?;
                }
            }
        }
        let changed = self.with_region(ctx, |r| {
            let Some(g) = groups(r, cluster).get_mut(&name) else { return false };
            if reset && reset_all {
                g.values.clear();
            }
            for p in parameters {
                let pname = p.parameter_name.clone().unwrap_or_default();
                if reset {
                    g.values.remove(&pname);
                } else {
                    g.values.insert(pname, p.parameter_value.clone().unwrap_or_default());
                }
            }
            true
        });
        if changed {
            self.mark_param_users(ctx, &name, cluster, static_change || reset_all);
            self.emit(
                ctx,
                "db-parameter-group",
                &name,
                &arn(ctx, kind(cluster), &name),
                &["configuration change"],
                "Updated parameter group.",
                "RDS-EVENT-0037",
            );
        }
        Ok(name)
    }

    /// Databases using a group whose static parameters changed wait for a
    /// reboot; MWS's backends read parameters at (re)start, so every change
    /// waits for one there.
    fn mark_param_users(&self, ctx: &RequestContext, name: &str, cluster: bool, static_change: bool) {
        let status = if static_change { "pending-reboot" } else { "in-sync" };
        self.with_region(ctx, |r| {
            if cluster {
                for c in r.clusters.values_mut() {
                    if c.cluster.db_cluster_parameter_group.as_deref() == Some(name) {
                        c.pending_reboot = true;
                        for m in c.cluster.db_cluster_members.iter_mut().flatten() {
                            m.db_cluster_parameter_group_status = Some(status.into());
                        }
                    }
                }
            } else {
                for i in r.instances.values_mut() {
                    for g in i.db.db_parameter_groups.iter_mut().flatten() {
                        if g.db_parameter_group_name.as_deref() == Some(name) {
                            g.parameter_apply_status = Some(status.into());
                            i.pending_reboot = true;
                        }
                    }
                }
            }
        });
    }

    pub(crate) fn modify_db_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBParameterGroupMessage,
    ) -> Result<t::DBParameterGroupNameMessage, ServiceError> {
        let name = self.modify_params(ctx, &input.db_parameter_group_name, &input.parameters, false, false, false)?;
        Ok(t::DBParameterGroupNameMessage { db_parameter_group_name: Some(name) })
    }

    pub(crate) fn reset_db_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ResetDBParameterGroupMessage,
    ) -> Result<t::DBParameterGroupNameMessage, ServiceError> {
        let params = input.parameters.clone().unwrap_or_default();
        let all = input.reset_all_parameters.unwrap_or(false);
        if !all && params.is_empty() {
            return Err(invalid_combination("Either ResetAllParameters or Parameters must be specified."));
        }
        let name = self.modify_params(ctx, &input.db_parameter_group_name, &params, all, true, false)?;
        Ok(t::DBParameterGroupNameMessage { db_parameter_group_name: Some(name) })
    }

    pub(crate) fn modify_db_cluster_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBClusterParameterGroupMessage,
    ) -> Result<t::DBClusterParameterGroupNameMessage, ServiceError> {
        let name =
            self.modify_params(ctx, &input.db_cluster_parameter_group_name, &input.parameters, false, false, true)?;
        Ok(t::DBClusterParameterGroupNameMessage { db_cluster_parameter_group_name: Some(name) })
    }

    pub(crate) fn reset_db_cluster_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ResetDBClusterParameterGroupMessage,
    ) -> Result<t::DBClusterParameterGroupNameMessage, ServiceError> {
        let params = input.parameters.clone().unwrap_or_default();
        let all = input.reset_all_parameters.unwrap_or(false);
        if !all && params.is_empty() {
            return Err(invalid_combination("Either ResetAllParameters or Parameters must be specified."));
        }
        let name = self.modify_params(ctx, &input.db_cluster_parameter_group_name, &params, all, true, true)?;
        Ok(t::DBClusterParameterGroupNameMessage { db_cluster_parameter_group_name: Some(name) })
    }

    fn delete_param_group(&self, ctx: &RequestContext, name: &str, cluster: bool) -> Result<(), ServiceError> {
        let name = name.to_ascii_lowercase();
        let action = if cluster { "DeleteDBClusterParameterGroup" } else { "DeleteDBParameterGroup" };
        authorize(ctx, action, &arn(ctx, kind(cluster), &name), ConditionContext::new())?;
        if name.starts_with("default.") {
            return Err(errors::invalid_db_parameter_group_state_fault(format!(
                "Default {}parameter group cannot be deleted",
                if cluster { "cluster " } else { "" }
            )));
        }
        self.with_region(ctx, |r| {
            let used = if cluster {
                r.clusters.values().any(|c| c.cluster.db_cluster_parameter_group.as_deref() == Some(name.as_str()))
            } else {
                r.instances.values().any(|i| {
                    i.db.db_parameter_groups
                        .iter()
                        .flatten()
                        .any(|g| g.db_parameter_group_name.as_deref() == Some(name.as_str()))
                })
            };
            if !groups(r, cluster).contains_key(&name) {
                return Err(not_found(cluster, &name));
            }
            if used {
                return Err(errors::invalid_db_parameter_group_state_fault(format!(
                    "One or more database instances are still members of this parameter group {name}, so the group cannot be deleted"
                )));
            }
            groups(r, cluster).remove(&name);
            Ok(())
        })
    }

    pub(crate) fn delete_db_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBParameterGroupMessage,
    ) -> Result<(), ServiceError> {
        self.delete_param_group(ctx, &input.db_parameter_group_name, false)
    }

    pub(crate) fn delete_db_cluster_parameter_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBClusterParameterGroupMessage,
    ) -> Result<(), ServiceError> {
        self.delete_param_group(ctx, &input.db_cluster_parameter_group_name, true)
    }

    fn list_param_groups(
        &self,
        ctx: &RequestContext,
        name: &Option<String>,
        filters: &Option<Vec<t::Filter>>,
        cluster: bool,
    ) -> Result<Vec<ParamGroup>, ServiceError> {
        let action = if cluster { "DescribeDBClusterParameterGroups" } else { "DescribeDBParameterGroups" };
        let resource = arn(ctx, kind(cluster), name.as_deref().unwrap_or("*"));
        authorize(ctx, action, &resource, ConditionContext::new())?;
        Filters::new(filters, &[])?;
        if let Some(n) = name {
            return Ok(vec![self.param_group(ctx, &name_of(n), cluster)?]);
        }
        Ok(self.with_region(ctx, |r| groups(r, cluster).values().cloned().collect()))
    }

    pub(crate) fn describe_db_parameter_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBParameterGroupsMessage,
    ) -> Result<t::DBParameterGroupsMessage, ServiceError> {
        let all = self.list_param_groups(ctx, &input.db_parameter_group_name, &input.filters, false)?;
        let (page, marker) = paginate(all.iter().map(shape).collect(), &input.marker, input.max_records)?;
        Ok(t::DBParameterGroupsMessage { marker, db_parameter_groups: Some(page) })
    }

    pub(crate) fn describe_db_cluster_parameter_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClusterParameterGroupsMessage,
    ) -> Result<t::DBClusterParameterGroupsMessage, ServiceError> {
        let all = self.list_param_groups(ctx, &input.db_cluster_parameter_group_name, &input.filters, true)?;
        let (page, marker) = paginate(all.iter().map(cluster_shape).collect(), &input.marker, input.max_records)?;
        Ok(t::DBClusterParameterGroupsMessage { marker, db_cluster_parameter_groups: Some(page) })
    }

    fn group_parameters(
        &self,
        ctx: &RequestContext,
        name: &str,
        source: &Option<String>,
        filters: &Option<Vec<t::Filter>>,
        cluster: bool,
    ) -> Result<Vec<t::Parameter>, ServiceError> {
        let action = if cluster { "DescribeDBClusterParameters" } else { "DescribeDBParameters" };
        authorize(ctx, action, &arn(ctx, kind(cluster), &name.to_ascii_lowercase()), ConditionContext::new())?;
        let f = Filters::new(filters, &["parameter-name", "apply-type", "apply-method", "is-modifiable"])?;
        if let Some(s) = source {
            if !["user", "system", "engine-default", "engine"].contains(&s.as_str()) {
                return Err(invalid_parameter(format!("Invalid source: {s}")));
            }
        }
        let g = self.param_group(ctx, name, cluster)?;
        Ok(parameters(&g, cluster)
            .into_iter()
            .filter(|p| source.as_ref().is_none_or(|s| p.source.as_ref() == Some(s)))
            .filter(|p| {
                f.matches(|n| match n {
                    "parameter-name" => p.parameter_name.iter().cloned().collect(),
                    "apply-type" => p.apply_type.iter().cloned().collect(),
                    "apply-method" => p.apply_method.iter().cloned().collect(),
                    "is-modifiable" => p.is_modifiable.iter().map(|b| b.to_string()).collect(),
                    _ => Vec::new(),
                })
            })
            .collect())
    }

    pub(crate) fn describe_db_parameters_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBParametersMessage,
    ) -> Result<t::DBParameterGroupDetails, ServiceError> {
        let params =
            self.group_parameters(ctx, &input.db_parameter_group_name, &input.source, &input.filters, false)?;
        let (page, marker) = paginate(params, &input.marker, input.max_records)?;
        Ok(t::DBParameterGroupDetails { parameters: Some(page), marker })
    }

    pub(crate) fn describe_db_cluster_parameters_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBClusterParametersMessage,
    ) -> Result<t::DBClusterParameterGroupDetails, ServiceError> {
        let params =
            self.group_parameters(ctx, &input.db_cluster_parameter_group_name, &input.source, &input.filters, true)?;
        let (page, marker) = paginate(params, &input.marker, input.max_records)?;
        Ok(t::DBClusterParameterGroupDetails { parameters: Some(page), marker })
    }

    pub(crate) fn describe_engine_default_parameters_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeEngineDefaultParametersMessage,
    ) -> Result<t::DescribeEngineDefaultParametersResult, ServiceError> {
        authorize(ctx, "DescribeEngineDefaultParameters", "*", ConditionContext::new())?;
        let defaults = engine_defaults(&input.db_parameter_group_family, false, &input.marker, input.max_records)?;
        Ok(t::DescribeEngineDefaultParametersResult { engine_defaults: Some(defaults) })
    }

    pub(crate) fn describe_engine_default_cluster_parameters_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeEngineDefaultClusterParametersMessage,
    ) -> Result<t::DescribeEngineDefaultClusterParametersResult, ServiceError> {
        authorize(ctx, "DescribeEngineDefaultClusterParameters", "*", ConditionContext::new())?;
        let defaults = engine_defaults(&input.db_parameter_group_family, true, &input.marker, input.max_records)?;
        Ok(t::DescribeEngineDefaultClusterParametersResult { engine_defaults: Some(defaults) })
    }
}

fn engine_defaults(
    family: &str,
    cluster: bool,
    marker: &Option<String>,
    max: Option<i32>,
) -> Result<t::EngineDefaults, ServiceError> {
    if catalog::family(family).is_none() {
        return Err(invalid_parameter(format!("ParameterGroupFamily {family} is not a valid parameter group family")));
    }
    let params: Vec<t::Parameter> = catalog::family_params(family, cluster)
        .iter()
        .map(|p| catalog::to_parameter(p, None, if p.value.is_some() { "system" } else { "engine-default" }))
        .collect();
    let (page, marker) = paginate(params, marker, max)?;
    Ok(t::EngineDefaults { db_parameter_group_family: Some(family.to_string()), marker, parameters: Some(page) })
}

/// Check a value against a parameter's allowed values.
fn check_value(p: &Param, value: &str) -> Result<(), ServiceError> {
    let Some(allowed) = p.allowed else { return Ok(()) };
    if value.contains('{') {
        return Ok(());
    }
    let bad = || invalid_parameter(format!("Value: {value} is not allowed for: {}", p.name));
    match p.data_type {
        "integer" | "real" | "float" => {
            let v: f64 = value.parse().map_err(|_| bad())?;
            let ok = allowed.split(',').any(|range| {
                // `a-b` where `a` may itself be negative.
                let (lo, hi) = match range.strip_prefix('-') {
                    Some(rest) => match rest.split_once('-') {
                        Some((a, b)) => (format!("-{a}"), b.to_string()),
                        None => (range.to_string(), range.to_string()),
                    },
                    None => match range.split_once('-') {
                        Some((a, b)) => (a.to_string(), b.to_string()),
                        None => (range.to_string(), range.to_string()),
                    },
                };
                matches!((lo.parse::<f64>(), hi.parse::<f64>()), (Ok(l), Ok(h)) if v >= l && v <= h)
            });
            if ok {
                Ok(())
            } else {
                Err(bad())
            }
        }
        "list" => {
            let options: Vec<&str> = allowed.split(',').collect();
            if value.split(',').map(str::trim).all(|v| v.is_empty() || options.contains(&v)) {
                Ok(())
            } else {
                Err(bad())
            }
        }
        _ => {
            if allowed.split(',').any(|a| a.eq_ignore_ascii_case(value)) {
                Ok(())
            } else {
                Err(bad())
            }
        }
    }
}
