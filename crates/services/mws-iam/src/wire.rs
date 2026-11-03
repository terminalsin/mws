//! Conversions from state to generated wire types.

use crate::common::{encode_document, tags_to_wire};
use crate::generated::types;
use crate::state::{Group, InstanceProfile, ManagedPolicy, PolicyVersion, Role, State, User};

pub fn boundary(arn: &Option<String>) -> Option<types::AttachedPermissionsBoundary> {
    arn.as_ref().map(|arn| types::AttachedPermissionsBoundary {
        permissions_boundary_type: Some("PermissionsBoundaryPolicy".into()),
        permissions_boundary_arn: Some(arn.clone()),
    })
}

/// `User` as returned by GetUser (with tags and boundary).
pub fn user(u: &User) -> types::User {
    types::User {
        path: u.path.clone(),
        user_name: u.name.clone(),
        user_id: u.id.clone(),
        arn: u.arn.clone(),
        create_date: u.created,
        password_last_used: u.password_last_used,
        permissions_boundary: boundary(&u.permissions_boundary),
        tags: tags_to_wire(&u.tags),
    }
}

/// `User` as returned in lists (ListUsers omits tags and boundary).
pub fn user_summary(u: &User) -> types::User {
    types::User { permissions_boundary: None, tags: None, ..user(u) }
}

pub fn group(g: &Group) -> types::Group {
    types::Group {
        path: g.path.clone(),
        group_name: g.name.clone(),
        group_id: g.id.clone(),
        arn: g.arn.clone(),
        create_date: g.created,
    }
}

pub fn role(r: &Role) -> types::Role {
    types::Role {
        path: r.path.clone(),
        role_name: r.name.clone(),
        role_id: r.id.clone(),
        arn: r.arn.clone(),
        create_date: r.created,
        assume_role_policy_document: Some(encode_document(&r.trust_policy)),
        description: r.description.clone(),
        max_session_duration: Some(r.max_session_duration),
        permissions_boundary: boundary(&r.permissions_boundary),
        tags: tags_to_wire(&r.tags),
        role_last_used: Some(types::RoleLastUsed {
            last_used_date: r.last_used.as_ref().map(|(t, _)| *t),
            region: r.last_used.as_ref().map(|(_, region)| region.clone()),
        }),
        source_role_template: None,
    }
}

/// `Role` as returned by ListRoles (no tags, boundary or last-used).
pub fn role_summary(r: &Role) -> types::Role {
    types::Role { permissions_boundary: None, tags: None, role_last_used: None, ..role(r) }
}

pub fn policy(p: &ManagedPolicy, state: &State) -> types::Policy {
    types::Policy {
        policy_name: Some(p.name.clone()),
        policy_id: Some(p.id.clone()),
        arn: Some(p.arn.clone()),
        path: Some(p.path.clone()),
        default_version_id: Some(p.default_version.clone()),
        attachment_count: Some(state.attachment_count(&p.arn) as i32),
        permissions_boundary_usage_count: Some(state.boundary_usage_count(&p.arn) as i32),
        is_attachable: true,
        description: p.description.clone(),
        create_date: Some(p.created),
        update_date: Some(p.updated),
        tags: tags_to_wire(&p.tags),
    }
}

pub fn policy_version(p: &ManagedPolicy, v: &PolicyVersion, with_document: bool) -> types::PolicyVersion {
    types::PolicyVersion {
        document: with_document.then(|| encode_document(&v.document)),
        version_id: Some(v.id.clone()),
        is_default_version: v.id == p.default_version,
        create_date: Some(v.created),
    }
}

pub fn instance_profile(ip: &InstanceProfile, state: &State) -> types::InstanceProfile {
    types::InstanceProfile {
        path: ip.path.clone(),
        instance_profile_name: ip.name.clone(),
        instance_profile_id: ip.id.clone(),
        arn: ip.arn.clone(),
        create_date: ip.created,
        roles: ip.roles.iter().filter_map(|r| state.role(r)).map(role).collect(),
        tags: tags_to_wire(&ip.tags),
    }
}

pub fn attached(arns: &std::collections::BTreeSet<String>, state: &State) -> Vec<types::AttachedPolicy> {
    arns.iter()
        .map(|arn| types::AttachedPolicy {
            policy_name: state.policies.get(arn).map(|p| p.name.clone()),
            policy_arn: Some(arn.clone()),
        })
        .collect()
}
