//! Package group operations.

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::domains::tags_to_map;
use crate::generated::types;
use crate::groups::{self, Pattern, RESTRICTION_TYPES, ROOT};
use crate::names::{self, conflict, domain_not_found, validation, Coordinates};
use crate::state::{Domain, PackageGroup};
use crate::{request_tags, CodeArtifact};

const MODES: &[&str] = &["ALLOW", "ALLOW_SPECIFIC_REPOSITORIES", "BLOCK", "INHERIT"];

fn reference(g: &PackageGroup) -> types::PackageGroupReference {
    types::PackageGroupReference { arn: Some(g.arn.clone()), pattern: Some(g.pattern.clone()) }
}

fn origin_configuration(d: &Domain, g: &PackageGroup) -> types::PackageGroupOriginConfiguration {
    let mut restrictions = BTreeMap::new();
    for kind in RESTRICTION_TYPES {
        let mode = g.restrictions.get(*kind).cloned().unwrap_or_else(|| "INHERIT".into());
        let (effective, from) = groups::effective(d, g, kind);
        let count = from.allowed_repositories.get(*kind).map_or(0, |r| r.len() as i64);
        restrictions.insert(
            kind.to_string(),
            types::PackageGroupOriginRestriction {
                mode: Some(mode.clone()),
                effective_mode: Some(effective),
                inherited_from: (mode == "INHERIT").then(|| reference(from)),
                repositories_count: Some(count),
            },
        );
    }
    types::PackageGroupOriginConfiguration { restrictions: Some(restrictions) }
}

pub(crate) fn describe(d: &Domain, g: &PackageGroup) -> types::PackageGroupDescription {
    types::PackageGroupDescription {
        arn: Some(g.arn.clone()),
        pattern: Some(g.pattern.clone()),
        domain_name: Some(d.name.clone()),
        domain_owner: Some(d.owner.clone()),
        created_time: Some(g.created),
        contact_info: g.contact_info.clone(),
        description: g.description.clone(),
        origin_configuration: Some(origin_configuration(d, g)),
        parent: groups::parent(d, &g.pattern).map(reference),
    }
}

fn summary(d: &Domain, g: &PackageGroup) -> types::PackageGroupSummary {
    let x = describe(d, g);
    types::PackageGroupSummary {
        arn: x.arn,
        pattern: x.pattern,
        domain_name: x.domain_name,
        domain_owner: x.domain_owner,
        created_time: x.created_time,
        contact_info: x.contact_info,
        description: x.description,
        origin_configuration: x.origin_configuration,
        parent: x.parent,
    }
}

fn group_not_found(pattern: &str) -> ServiceError {
    names::not_found("package-group", pattern, format!("Package group not found. Package group: '{pattern}'"))
}

/// Accept the pattern or the ARN of a group.
fn pattern_of(input: &str) -> String {
    match input.split_once(":package-group/") {
        Some((_, rest)) => {
            let p = rest.find('/').map_or("", |i| &rest[i..]);
            p.replace("%24", "$").replace("%7E", "~").replace("%2A", "*")
        }
        None => input.to_string(),
    }
}

impl CodeArtifact {
    fn authorize_group(
        &self,
        ctx: &RequestContext,
        owner: &str,
        domain: &str,
        pattern: &str,
        action: &str,
        extra: mws_core::ConditionContext,
    ) -> Result<(), ServiceError> {
        let arn = names::package_group_arn(&ctx.partition, &ctx.region, owner, domain, pattern);
        let (policy, mut cond) = {
            let st = self.read();
            let d = st.domains.get(&Self::key(ctx, owner, domain));
            (
                d.and_then(|d| d.policy.as_ref().map(|p| p.document.clone())),
                d.and_then(|d| d.groups.get(pattern)).map(|g| crate::resource_tags(&g.tags)).unwrap_or_default(),
            )
        };
        cond.extend(extra);
        ctx.authorize_with_resource_policy(action, &arn, policy.as_deref(), cond)
    }

    pub(crate) fn create_package_group(
        &self,
        ctx: &RequestContext,
        input: types::CreatePackageGroupRequest,
    ) -> Result<types::CreatePackageGroupResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let tags = input.tags.unwrap_or_default();
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &input.package_group,
            "codeartifact:CreatePackageGroup",
            request_tags(&tags),
        )?;
        Pattern::parse(&input.package_group)?;
        let mut st = self.write();
        let d = st
            .domains
            .get_mut(&Self::key(ctx, &owner, &input.domain))
            .ok_or_else(|| domain_not_found(&input.domain))?;
        if d.groups.contains_key(&input.package_group) {
            return Err(conflict(
                "package-group",
                &input.package_group,
                format!("Package group already exists. Package group: '{}'", input.package_group),
            ));
        }
        let mut g = PackageGroup {
            pattern: input.package_group.clone(),
            arn: names::package_group_arn(&ctx.partition, &ctx.region, &owner, &input.domain, &input.package_group),
            created: ctx.received_at,
            contact_info: input.contact_info,
            description: input.description,
            tags: tags_to_map(&tags),
            ..Default::default()
        };
        for t in RESTRICTION_TYPES {
            g.restrictions.insert(t.to_string(), "INHERIT".into());
        }
        d.groups.insert(g.pattern.clone(), g);
        let out = describe(d, &d.groups[&input.package_group]);
        Ok(types::CreatePackageGroupResult { package_group: Some(out) })
    }

    pub(crate) fn describe_package_group(
        &self,
        ctx: &RequestContext,
        input: types::DescribePackageGroupRequest,
    ) -> Result<types::DescribePackageGroupResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let pattern = pattern_of(&input.package_group);
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &pattern,
            "codeartifact:DescribePackageGroup",
            Default::default(),
        )?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        let g = d.groups.get(&pattern).ok_or_else(|| group_not_found(&pattern))?;
        Ok(types::DescribePackageGroupResult { package_group: Some(describe(d, g)) })
    }

    pub(crate) fn delete_package_group(
        &self,
        ctx: &RequestContext,
        input: types::DeletePackageGroupRequest,
    ) -> Result<types::DeletePackageGroupResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let pattern = pattern_of(&input.package_group);
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &pattern,
            "codeartifact:DeletePackageGroup",
            Default::default(),
        )?;
        if pattern == ROOT {
            return Err(validation("The root package group cannot be deleted."));
        }
        let mut st = self.write();
        let d = st
            .domains
            .get_mut(&Self::key(ctx, &owner, &input.domain))
            .ok_or_else(|| domain_not_found(&input.domain))?;
        let g = d.groups.get(&pattern).ok_or_else(|| group_not_found(&pattern))?;
        let has_children = d
            .groups
            .values()
            .any(|c| c.pattern != pattern && groups::parent(d, &c.pattern).is_some_and(|p| p.pattern == pattern));
        if has_children {
            return Err(conflict(
                "package-group",
                &pattern,
                format!("Package group '{pattern}' cannot be deleted because it has child package groups."),
            ));
        }
        let out = describe(d, g);
        d.groups.remove(&pattern);
        Ok(types::DeletePackageGroupResult { package_group: Some(out) })
    }

    pub(crate) fn update_package_group(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePackageGroupRequest,
    ) -> Result<types::UpdatePackageGroupResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let pattern = pattern_of(&input.package_group);
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &pattern,
            "codeartifact:UpdatePackageGroup",
            Default::default(),
        )?;
        let mut st = self.write();
        let d = st
            .domains
            .get_mut(&Self::key(ctx, &owner, &input.domain))
            .ok_or_else(|| domain_not_found(&input.domain))?;
        let g = d.groups.get_mut(&pattern).ok_or_else(|| group_not_found(&pattern))?;
        if let Some(c) = input.contact_info {
            g.contact_info = Some(c);
        }
        if let Some(desc) = input.description {
            g.description = Some(desc);
        }
        let out = describe(d, &d.groups[&pattern]);
        Ok(types::UpdatePackageGroupResult { package_group: Some(out) })
    }

    pub(crate) fn update_package_group_origin_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePackageGroupOriginConfigurationRequest,
    ) -> Result<types::UpdatePackageGroupOriginConfigurationResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let pattern = pattern_of(&input.package_group);
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &pattern,
            "codeartifact:UpdatePackageGroupOriginConfiguration",
            Default::default(),
        )?;
        let restrictions = input.restrictions.unwrap_or_default();
        for (kind, mode) in &restrictions {
            if !RESTRICTION_TYPES.contains(&kind.as_str()) {
                return Err(validation(format!("Invalid origin restriction type: '{kind}'")));
            }
            if !MODES.contains(&mode.as_str()) {
                return Err(validation(format!("Invalid origin restriction mode: '{mode}'")));
            }
            if pattern == ROOT && mode == "INHERIT" {
                return Err(validation("The root package group cannot inherit its origin configuration."));
            }
        }
        let mut st = self.write();
        let d = st
            .domains
            .get_mut(&Self::key(ctx, &owner, &input.domain))
            .ok_or_else(|| domain_not_found(&input.domain))?;
        let repos: Vec<String> = d.repositories.keys().cloned().collect();
        let g = d.groups.get_mut(&pattern).ok_or_else(|| group_not_found(&pattern))?;
        let mut updates: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for (kind, mode) in restrictions {
            g.restrictions.insert(kind, mode);
        }
        for (list, verb) in
            [(&input.add_allowed_repositories, "ADDED"), (&input.remove_allowed_repositories, "REMOVED")]
        {
            for a in list.iter().flatten() {
                let (Some(repo), Some(kind)) = (&a.repository_name, &a.origin_restriction_type) else {
                    return Err(validation("repositoryName and originRestrictionType are required."));
                };
                if !RESTRICTION_TYPES.contains(&kind.as_str()) {
                    return Err(validation(format!("Invalid origin restriction type: '{kind}'")));
                }
                if !repos.contains(repo) {
                    return Err(names::repository_not_found(repo));
                }
                let set = g.allowed_repositories.entry(kind.clone()).or_default();
                let changed = if verb == "ADDED" { set.insert(repo.clone()) } else { set.remove(repo) };
                if changed {
                    updates.entry(kind.clone()).or_default().entry(verb.to_string()).or_default().push(repo.clone());
                }
            }
        }
        let out = describe(d, &d.groups[&pattern]);
        Ok(types::UpdatePackageGroupOriginConfigurationResult {
            package_group: Some(out),
            allowed_repository_updates: Some(updates),
        })
    }

    pub(crate) fn list_package_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageGroupsRequest,
    ) -> Result<types::ListPackageGroupsResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:ListPackageGroups")?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        let prefix = input.prefix.unwrap_or_default();
        let all: Vec<_> = d.groups.values().filter(|g| g.pattern.starts_with(&prefix)).map(|g| summary(d, g)).collect();
        let (package_groups, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListPackageGroupsResult { package_groups: Some(package_groups), next_token })
    }

    pub(crate) fn list_sub_package_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListSubPackageGroupsRequest,
    ) -> Result<types::ListSubPackageGroupsResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let pattern = pattern_of(&input.package_group);
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &pattern,
            "codeartifact:ListSubPackageGroups",
            Default::default(),
        )?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        d.groups.get(&pattern).ok_or_else(|| group_not_found(&pattern))?;
        let all: Vec<_> = d
            .groups
            .values()
            .filter(|c| groups::parent(d, &c.pattern).is_some_and(|p| p.pattern == pattern))
            .map(|g| summary(d, g))
            .collect();
        let (package_groups, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListSubPackageGroupsResult { package_groups: Some(package_groups), next_token })
    }

    pub(crate) fn list_allowed_repositories_for_group(
        &self,
        ctx: &RequestContext,
        input: types::ListAllowedRepositoriesForGroupRequest,
    ) -> Result<types::ListAllowedRepositoriesForGroupResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let pattern = pattern_of(&input.package_group);
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &pattern,
            "codeartifact:ListAllowedRepositoriesForGroup",
            Default::default(),
        )?;
        if !RESTRICTION_TYPES.contains(&input.origin_restriction_type.as_str()) {
            return Err(validation(format!("Invalid origin restriction type: '{}'", input.origin_restriction_type)));
        }
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        let g = d.groups.get(&pattern).ok_or_else(|| group_not_found(&pattern))?;
        let all: Vec<String> =
            g.allowed_repositories.get(&input.origin_restriction_type).into_iter().flatten().cloned().collect();
        let (allowed_repositories, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListAllowedRepositoriesForGroupResult {
            allowed_repositories: Some(allowed_repositories),
            next_token,
        })
    }

    pub(crate) fn list_associated_packages(
        &self,
        ctx: &RequestContext,
        input: types::ListAssociatedPackagesRequest,
    ) -> Result<types::ListAssociatedPackagesResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        let pattern = pattern_of(&input.package_group);
        self.authorize_group(
            ctx,
            &owner,
            &input.domain,
            &pattern,
            "codeartifact:ListAssociatedPackages",
            Default::default(),
        )?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        d.groups.get(&pattern).ok_or_else(|| group_not_found(&pattern))?;
        let mut seen = std::collections::BTreeMap::new();
        for p in d.repositories.values().flat_map(|r| r.packages.values()) {
            let c = Coordinates { format: p.format.clone(), namespace: p.namespace.clone(), name: p.name.clone() };
            if let Some((g, assoc)) = groups::associated(d, &c) {
                if g.pattern == pattern {
                    seen.insert(
                        c.key(),
                        types::AssociatedPackage {
                            format: Some(c.format.clone()),
                            namespace: c.namespace.clone(),
                            package: Some(c.name.clone()),
                            association_type: Some(assoc.as_str().into()),
                        },
                    );
                }
            }
        }
        let all: Vec<_> = seen.into_values().collect();
        let (packages, next_token) = names::page(&all, input.max_results, input.next_token.as_deref());
        Ok(types::ListAssociatedPackagesResult { packages: Some(packages), next_token })
    }

    pub(crate) fn get_associated_package_group(
        &self,
        ctx: &RequestContext,
        input: types::GetAssociatedPackageGroupRequest,
    ) -> Result<types::GetAssociatedPackageGroupResult, ServiceError> {
        let owner = Self::owner(ctx, input.domain_owner.as_deref());
        self.authorize_domain(ctx, &owner, &input.domain, "codeartifact:GetAssociatedPackageGroup")?;
        let c = names::check_coordinates(&input.format, input.namespace.as_deref(), &input.package)?;
        let st = self.read();
        let d =
            st.domains.get(&Self::key(ctx, &owner, &input.domain)).ok_or_else(|| domain_not_found(&input.domain))?;
        let (g, assoc) = groups::associated(d, &c).ok_or_else(|| group_not_found(ROOT))?;
        Ok(types::GetAssociatedPackageGroupResult {
            package_group: Some(describe(d, g)),
            association_type: Some(assoc.as_str().into()),
        })
    }
}
