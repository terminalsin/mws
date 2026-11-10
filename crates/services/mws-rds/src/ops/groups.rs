//! DB subnet groups and option groups.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{authorize, authorize_create};
use crate::catalog;
use crate::generated::{errors, types as t};
use crate::state::{RegionState, Tagged};
use crate::util::{arn, group_name, invalid_parameter, name_of, paginate, request_tag_context, tags_from, Filters};
use crate::{Rds, Subnet};

pub fn subnet_group_not_found(name: &str) -> ServiceError {
    errors::db_subnet_group_not_found_fault(format!("DBSubnetGroup '{name}' not found."))
}

pub fn option_group_not_found(name: &str) -> ServiceError {
    errors::option_group_not_found_fault(format!("Specified OptionGroupName: {name} not found."))
}

fn subnet_group_shape(ctx: &RequestContext, name: &str, description: &str, subnets: &[Subnet]) -> t::DBSubnetGroup {
    t::DBSubnetGroup {
        db_subnet_group_name: Some(name.to_string()),
        db_subnet_group_description: Some(description.to_string()),
        vpc_id: subnets.first().map(|s| s.vpc_id.clone()),
        subnet_group_status: Some("Complete".into()),
        subnets: Some(
            subnets
                .iter()
                .map(|s| t::Subnet {
                    subnet_identifier: Some(s.subnet_id.clone()),
                    subnet_availability_zone: Some(t::AvailabilityZone { name: Some(s.availability_zone.clone()) }),
                    subnet_status: Some("Active".into()),
                    ..Default::default()
                })
                .collect(),
        ),
        db_subnet_group_arn: Some(arn(ctx, "subgrp", name)),
        supported_network_types: Some(vec!["IPV4".into()]),
    }
}

impl Rds {
    /// The subnet group `name`, creating `default` from the default VPC on
    /// first use.
    pub(crate) fn subnet_group(&self, ctx: &RequestContext, name: &str) -> Result<t::DBSubnetGroup, ServiceError> {
        let name = name.to_ascii_lowercase();
        if let Some(g) = self.with_region(ctx, |r| r.subnet_groups.get(&name).map(|g| g.item.clone())) {
            return Ok(g);
        }
        if name != "default" {
            return Err(subnet_group_not_found(&name));
        }
        let subnets = self.default_subnets(ctx);
        if subnets.is_empty() {
            return Err(errors::invalid_vpc_network_state_fault(
                "Cannot create a DB instance in the default VPC because it does not exist. Specify a DB subnet group.",
            ));
        }
        let g = subnet_group_shape(ctx, "default", "default", &subnets);
        self.with_region(ctx, |r| {
            r.subnet_groups.entry(name).or_insert_with(|| Tagged { item: g.clone(), tags: Vec::new() }).item.clone()
        });
        Ok(g)
    }

    fn checked_subnets(&self, ctx: &RequestContext, ids: &[String]) -> Result<Vec<Subnet>, ServiceError> {
        if ids.is_empty() {
            return Err(invalid_parameter("The parameter SubnetIds must be provided and must not be empty."));
        }
        let found = self.lookup_subnets(ctx, ids);
        if found.len() != ids.len() {
            return Err(errors::invalid_subnet(format!("Some input subnets in :[{}] are invalid.", ids.join(", "))));
        }
        if found.iter().any(|s| s.vpc_id != found[0].vpc_id) {
            return Err(errors::invalid_subnet("Subnets must all belong to the same VPC.".to_string()));
        }
        let mut zones: Vec<&str> = found.iter().map(|s| s.availability_zone.as_str()).collect();
        zones.sort();
        zones.dedup();
        if zones.len() < 2 {
            return Err(errors::db_subnet_group_does_not_cover_enough_a_zs(format!(
                "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. Current AZ coverage: {}. Add subnets to cover at least 2 AZs.",
                zones.join(", ")
            )));
        }
        Ok(found)
    }

    pub(crate) fn create_db_subnet_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDBSubnetGroupMessage,
    ) -> Result<t::CreateDBSubnetGroupResult, ServiceError> {
        let name = group_name("DBSubnetGroupName", &input.db_subnet_group_name, &['.', '_', ' '])?;
        let tags = tags_from(&input.tags)?;
        authorize_create(ctx, "CreateDBSubnetGroup", &arn(ctx, "subgrp", &name), &tags, request_tag_context(&tags))?;
        if name == "default" {
            return Err(invalid_parameter("DBSubnetGroupName default is reserved and cannot be used."));
        }
        let subnets = self.checked_subnets(ctx, &input.subnet_ids)?;
        let g = subnet_group_shape(ctx, &name, &input.db_subnet_group_description, &subnets);
        self.with_region(ctx, |r| {
            if r.subnet_groups.contains_key(&name) {
                return Err(errors::db_subnet_group_already_exists_fault(format!(
                    "The DB subnet group '{name}' already exists."
                )));
            }
            r.subnet_groups.insert(name.clone(), Tagged { item: g.clone(), tags });
            Ok(())
        })?;
        Ok(t::CreateDBSubnetGroupResult { db_subnet_group: Some(g) })
    }

    pub(crate) fn modify_db_subnet_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyDBSubnetGroupMessage,
    ) -> Result<t::ModifyDBSubnetGroupResult, ServiceError> {
        let name = input.db_subnet_group_name.to_ascii_lowercase();
        authorize(ctx, "ModifyDBSubnetGroup", &arn(ctx, "subgrp", &name), ConditionContext::new())?;
        let current = self.subnet_group(ctx, &name)?;
        let subnets = self.checked_subnets(ctx, &input.subnet_ids)?;
        if current.vpc_id.as_deref().is_some_and(|v| v != subnets[0].vpc_id) {
            let in_use = self.with_region(ctx, |r| subnet_group_users(r, &name).first().cloned());
            if let Some(user) = in_use {
                return Err(errors::invalid_db_subnet_group_state_fault(format!(
                    "Cannot change the VPC of subnet group '{name}' because it is used by {user}."
                )));
            }
        }
        let description =
            input.db_subnet_group_description.clone().or(current.db_subnet_group_description).unwrap_or_default();
        let g = subnet_group_shape(ctx, &name, &description, &subnets);
        self.with_region(ctx, |r| {
            if let Some(x) = r.subnet_groups.get_mut(&name) {
                x.item = g.clone();
            }
        });
        Ok(t::ModifyDBSubnetGroupResult { db_subnet_group: Some(g) })
    }

    pub(crate) fn delete_db_subnet_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDBSubnetGroupMessage,
    ) -> Result<(), ServiceError> {
        let name = input.db_subnet_group_name.to_ascii_lowercase();
        authorize(ctx, "DeleteDBSubnetGroup", &arn(ctx, "subgrp", &name), ConditionContext::new())?;
        self.with_region(ctx, |r| {
            if !r.subnet_groups.contains_key(&name) {
                return Err(subnet_group_not_found(&name));
            }
            if let Some(user) = subnet_group_users(r, &name).first() {
                return Err(errors::invalid_db_subnet_group_state_fault(format!(
                    "Cannot delete the subnet group '{name}' because at least one database instance: {user} is still using it."
                )));
            }
            r.subnet_groups.remove(&name);
            Ok(())
        })
    }

    pub(crate) fn describe_db_subnet_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeDBSubnetGroupsMessage,
    ) -> Result<t::DBSubnetGroupMessage, ServiceError> {
        let wanted = input.db_subnet_group_name.as_deref().map(|n| n.to_ascii_lowercase());
        authorize(
            ctx,
            "DescribeDBSubnetGroups",
            &arn(ctx, "subgrp", wanted.as_deref().unwrap_or("*")),
            ConditionContext::new(),
        )?;
        Filters::new(&input.filters, &[])?;
        if let Some(n) = &wanted {
            let g = self.subnet_group(ctx, n)?;
            return Ok(t::DBSubnetGroupMessage { marker: None, db_subnet_groups: Some(vec![g]) });
        }
        let groups: Vec<t::DBSubnetGroup> =
            self.with_region(ctx, |r| r.subnet_groups.values().map(|g| g.item.clone()).collect());
        let (page, marker) = paginate(groups, &input.marker, input.max_records)?;
        Ok(t::DBSubnetGroupMessage { marker, db_subnet_groups: Some(page) })
    }

    // ---- option groups ----------------------------------------------------

    /// The option group `name`, creating a default one (`default:<engine>-<major>`)
    /// on first use.
    pub(crate) fn option_group(&self, ctx: &RequestContext, name: &str) -> Result<t::OptionGroup, ServiceError> {
        let name = name.to_ascii_lowercase();
        if let Some(g) = self.with_region(ctx, |r| r.option_groups.get(&name).map(|g| g.item.clone())) {
            return Ok(g);
        }
        let Some(rest) = name.strip_prefix("default:") else { return Err(option_group_not_found(&name)) };
        let (engine, major) = catalog::ENGINES
            .iter()
            .flat_map(|e| e.versions.iter().map(move |v| (e, v)))
            .find(|(e, v)| e.default_option_group(v) == name)
            .map(|(e, v)| (e.name, v.major))
            .ok_or_else(|| option_group_not_found(&name))?;
        let _ = rest;
        let g = t::OptionGroup {
            option_group_name: Some(name.clone()),
            option_group_description: Some(format!("Default option group for {engine} {major}")),
            engine_name: Some(engine.into()),
            major_engine_version: Some(major.into()),
            options: Some(Vec::new()),
            allows_vpc_and_non_vpc_instance_memberships: Some(true),
            option_group_arn: Some(arn(ctx, "og", &name)),
            ..Default::default()
        };
        self.with_region(ctx, |r| {
            r.option_groups.entry(name).or_insert_with(|| Tagged { item: g.clone(), tags: Vec::new() });
        });
        Ok(g)
    }

    pub(crate) fn create_option_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateOptionGroupMessage,
    ) -> Result<t::CreateOptionGroupResult, ServiceError> {
        let name = group_name("OptionGroupName", &input.option_group_name, &[])?;
        let tags = tags_from(&input.tags)?;
        authorize_create(ctx, "CreateOptionGroup", &arn(ctx, "og", &name), &tags, request_tag_context(&tags))?;
        let engine = catalog::engine(&input.engine_name)
            .ok_or_else(|| invalid_parameter(format!("Invalid DB engine: {}", input.engine_name)))?;
        if !engine.versions.iter().any(|v| v.major == input.major_engine_version) {
            return Err(invalid_parameter(format!(
                "Cannot find major version {} for {}",
                input.major_engine_version, engine.name
            )));
        }
        let g = t::OptionGroup {
            option_group_name: Some(name.clone()),
            option_group_description: Some(input.option_group_description.clone()),
            engine_name: Some(engine.name.into()),
            major_engine_version: Some(input.major_engine_version.clone()),
            options: Some(Vec::new()),
            allows_vpc_and_non_vpc_instance_memberships: Some(true),
            option_group_arn: Some(arn(ctx, "og", &name)),
            ..Default::default()
        };
        self.with_region(ctx, |r| {
            if r.option_groups.contains_key(&name) {
                return Err(errors::option_group_already_exists_fault(format!("Option group {name} already exists.")));
            }
            r.option_groups.insert(name.clone(), Tagged { item: g.clone(), tags });
            Ok(())
        })?;
        Ok(t::CreateOptionGroupResult { option_group: Some(g) })
    }

    pub(crate) fn copy_option_group_op(
        &self,
        ctx: &RequestContext,
        input: t::CopyOptionGroupMessage,
    ) -> Result<t::CopyOptionGroupResult, ServiceError> {
        let source = name_of(&input.source_option_group_identifier);
        let target = group_name("TargetOptionGroupIdentifier", &input.target_option_group_identifier, &[])?;
        let tags = tags_from(&input.tags)?;
        authorize_create(ctx, "CopyOptionGroup", &arn(ctx, "og", &target), &tags, request_tag_context(&tags))?;
        let src = self.option_group(ctx, &source)?;
        let g = t::OptionGroup {
            option_group_name: Some(target.clone()),
            option_group_description: Some(input.target_option_group_description.clone()),
            option_group_arn: Some(arn(ctx, "og", &target)),
            ..src
        };
        self.with_region(ctx, |r| {
            if r.option_groups.contains_key(&target) {
                return Err(errors::option_group_already_exists_fault(format!(
                    "Option group {target} already exists."
                )));
            }
            r.option_groups.insert(target.clone(), Tagged { item: g.clone(), tags });
            Ok(())
        })?;
        Ok(t::CopyOptionGroupResult { option_group: Some(g) })
    }

    pub(crate) fn modify_option_group_op(
        &self,
        ctx: &RequestContext,
        input: t::ModifyOptionGroupMessage,
    ) -> Result<t::ModifyOptionGroupResult, ServiceError> {
        let name = input.option_group_name.to_ascii_lowercase();
        authorize(ctx, "ModifyOptionGroup", &arn(ctx, "og", &name), ConditionContext::new())?;
        if name.starts_with("default:") {
            return Err(invalid_parameter("Default option groups cannot be modified."));
        }
        let mut g = self.option_group(ctx, &name)?;
        let options = g.options.get_or_insert_with(Vec::new);
        for remove in input.options_to_remove.iter().flatten() {
            if !options.iter().any(|o| o.option_name.as_ref() == Some(remove)) {
                return Err(invalid_parameter(format!("Option {remove} is not in the option group {name}.")));
            }
            options.retain(|o| o.option_name.as_ref() != Some(remove));
        }
        for add in input.options_to_include.iter().flatten() {
            options.retain(|o| o.option_name.as_ref() != Some(&add.option_name));
            options.push(t::Option {
                option_name: Some(add.option_name.clone()),
                option_description: Some(add.option_name.clone()),
                persistent: Some(false),
                permanent: Some(false),
                port: add.port,
                option_version: add.option_version.clone(),
                option_settings: add.option_settings.clone(),
                db_security_group_memberships: Some(Vec::new()),
                vpc_security_group_memberships: Some(
                    add.vpc_security_group_memberships
                        .iter()
                        .flatten()
                        .map(|id| t::VpcSecurityGroupMembership {
                            vpc_security_group_id: Some(id.clone()),
                            status: Some("active".into()),
                        })
                        .collect(),
                ),
            });
        }
        self.with_region(ctx, |r| {
            if let Some(x) = r.option_groups.get_mut(&name) {
                x.item = g.clone();
            }
        });
        Ok(t::ModifyOptionGroupResult { option_group: Some(g) })
    }

    pub(crate) fn delete_option_group_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteOptionGroupMessage,
    ) -> Result<(), ServiceError> {
        let name = input.option_group_name.to_ascii_lowercase();
        authorize(ctx, "DeleteOptionGroup", &arn(ctx, "og", &name), ConditionContext::new())?;
        if name.starts_with("default:") {
            return Err(errors::invalid_option_group_state_fault(format!(
                "Default option group {name} cannot be deleted."
            )));
        }
        self.with_region(ctx, |r| {
            if !r.option_groups.contains_key(&name) {
                return Err(option_group_not_found(&name));
            }
            let used = r.instances.values().find(|i| {
                i.db.option_group_memberships
                    .iter()
                    .flatten()
                    .any(|m| m.option_group_name.as_deref() == Some(name.as_str()))
            });
            if let Some(i) = used {
                return Err(errors::invalid_option_group_state_fault(format!(
                    "The option group '{name}' cannot be deleted because it is in use by {}.",
                    i.db.db_instance_identifier.clone().unwrap_or_default()
                )));
            }
            r.option_groups.remove(&name);
            Ok(())
        })
    }

    pub(crate) fn describe_option_groups_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeOptionGroupsMessage,
    ) -> Result<t::OptionGroups, ServiceError> {
        authorize(ctx, "DescribeOptionGroups", &arn(ctx, "og", "*"), ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        if let Some(n) = &input.option_group_name {
            let g = self.option_group(ctx, n)?;
            return Ok(t::OptionGroups { option_groups_list: Some(vec![g]), marker: None });
        }
        let groups: Vec<t::OptionGroup> = self.with_region(ctx, |r| {
            r.option_groups
                .values()
                .map(|g| g.item.clone())
                .filter(|g| input.engine_name.as_ref().is_none_or(|e| g.engine_name.as_ref() == Some(e)))
                .filter(|g| {
                    input.major_engine_version.as_ref().is_none_or(|v| g.major_engine_version.as_ref() == Some(v))
                })
                .collect()
        });
        let (page, marker) = paginate(groups, &input.marker, input.max_records)?;
        Ok(t::OptionGroups { option_groups_list: Some(page), marker })
    }

    pub(crate) fn describe_option_group_options_op(
        &self,
        ctx: &RequestContext,
        input: t::DescribeOptionGroupOptionsMessage,
    ) -> Result<t::OptionGroupOptionsMessage, ServiceError> {
        authorize(ctx, "DescribeOptionGroupOptions", "*", ConditionContext::new())?;
        Filters::new(&input.filters, &[])?;
        let engine = catalog::engine(&input.engine_name)
            .ok_or_else(|| invalid_parameter(format!("Invalid DB engine: {}", input.engine_name)))?;
        let options: Vec<t::OptionGroupOption> = match engine.kind {
            catalog::Kind::Mysql | catalog::Kind::Mariadb if !engine.aurora => engine
                .versions
                .iter()
                .filter(|v| input.major_engine_version.as_ref().is_none_or(|m| *m == v.major))
                .map(|v| t::OptionGroupOption {
                    name: Some("MARIADB_AUDIT_PLUGIN".into()),
                    description: Some("MariaDB Audit Plugin".into()),
                    engine_name: Some(engine.name.into()),
                    major_engine_version: Some(v.major.into()),
                    port_required: Some(false),
                    persistent: Some(false),
                    permanent: Some(false),
                    vpc_only: Some(false),
                    ..Default::default()
                })
                .collect(),
            _ => Vec::new(),
        };
        let (page, marker) = paginate(options, &input.marker, input.max_records)?;
        Ok(t::OptionGroupOptionsMessage { option_group_options: Some(page), marker })
    }
}

/// Instances and clusters using subnet group `name`.
fn subnet_group_users(r: &RegionState, name: &str) -> Vec<String> {
    let mut out: Vec<String> = r
        .instances
        .values()
        .filter(|i| i.db.db_subnet_group.as_ref().and_then(|g| g.db_subnet_group_name.as_deref()) == Some(name))
        .filter_map(|i| i.db.db_instance_identifier.clone())
        .collect();
    out.extend(
        r.clusters
            .values()
            .filter(|c| c.cluster.db_subnet_group.as_deref() == Some(name))
            .filter_map(|c| c.cluster.db_cluster_identifier.clone()),
    );
    out
}
