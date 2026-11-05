//! Users and user groups (role-based access control). A replication
//! group's user group becomes the ACL users of its nodes.

use mws_core::{RequestContext, ServiceError};

use super::*;
use crate::engine;
use crate::generated::{errors, types as t};
use crate::state::{RegionState, User};
use crate::ElastiCache;

fn not_found(id: &str) -> ServiceError {
    errors::user_not_found_fault(format!("User {id} not found."))
}

pub(crate) fn group_not_found(id: &str) -> ServiceError {
    errors::user_group_not_found_fault(format!("User group {id} not found."))
}

/// Every Region starts with the `default` user.
pub(crate) fn init_region(r: &mut RegionState, partition: &str, account: &str, region: &str) {
    let partition = if partition.is_empty() { "aws" } else { partition };
    r.users.entry("default".into()).or_insert_with(|| User {
        info: t::User {
            user_id: Some("default".into()),
            user_name: Some("default".into()),
            status: Some("active".into()),
            engine: Some("redis".into()),
            minimum_engine_version: Some("6.0".into()),
            access_string: Some("on ~* +@all".into()),
            user_group_ids: Some(vec![]),
            authentication: Some(t::Authentication { r#type: Some("no-password".into()), password_count: None }),
            arn: Some(format!("arn:{partition}:elasticache:{region}:{account}:user:default")),
        },
        passwords: vec![],
    });
}

/// `ACL SETUSER` commands for the users of `groups`.
pub(crate) fn acl_commands(r: &RegionState, groups: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for gid in groups {
        let Some(g) = r.user_groups.get(gid) else { continue };
        for uid in g.user_ids.iter().flatten() {
            let Some(u) = r.users.get(uid) else { continue };
            out.push(setuser(u));
        }
    }
    out
}

fn setuser(u: &User) -> Vec<String> {
    let mut cmd: Vec<String> =
        vec!["ACL".into(), "SETUSER".into(), u.info.user_name.clone().unwrap_or_default(), "reset".into()];
    cmd.extend(u.info.access_string.as_deref().unwrap_or_default().split_whitespace().map(str::to_string));
    let kind = u.info.authentication.as_ref().and_then(|a| a.r#type.clone()).unwrap_or_default();
    match kind.as_str() {
        "no-password" | "no-password-required" => cmd.push("nopass".into()),
        _ => cmd.extend(u.passwords.iter().map(|p| format!(">{p}"))),
    }
    cmd
}

/// Commands that undo the users of groups no longer attached.
pub(crate) fn reset_acl_commands(r: &RegionState, before: &[String], after: &[String]) -> Vec<Vec<String>> {
    let names = |groups: &[String]| -> Vec<String> {
        groups
            .iter()
            .filter_map(|g| r.user_groups.get(g))
            .flat_map(|g| g.user_ids.clone().unwrap_or_default())
            .filter_map(|u| r.users.get(&u).and_then(|u| u.info.user_name.clone()))
            .collect()
    };
    let keep = names(after);
    let mut out = Vec::new();
    for n in names(before) {
        if keep.contains(&n) {
            continue;
        }
        if n == "default" {
            out.push(
                ["ACL", "SETUSER", "default", "reset", "on", "nopass", "~*", "&*", "+@all"].map(String::from).to_vec(),
            );
        } else {
            out.push(vec!["ACL".into(), "DELUSER".into(), n]);
        }
    }
    out
}

/// Re-apply the ACLs of every replication group using one of `groups`.
fn sync(svc: &ElastiCache, ctx: &RequestContext, groups: &[String], extra: Vec<Vec<String>>) {
    let key = region_key(ctx);
    let rgs: Vec<String> = svc.with_region(ctx, |r| {
        groups
            .iter()
            .filter_map(|g| r.user_groups.get(g))
            .flat_map(|g| g.replication_groups.clone().unwrap_or_default())
            .collect()
    });
    for rg in rgs {
        if !extra.is_empty() {
            let nodes = svc.with_key(&key, ctx, |r| engine::nodes_of(r, Some(&rg), None));
            engine::run_everywhere(svc, nodes, extra.clone());
        }
        engine::sync_users(svc, ctx, &key, &rg);
    }
}

fn check_engine(e: &str) -> Result<String, ServiceError> {
    let e = e.to_ascii_lowercase();
    if matches!(e.as_str(), "redis" | "valkey") {
        Ok(e)
    } else {
        Err(invalid(format!("Invalid engine: {e}. Only redis and valkey are supported.")))
    }
}

fn check_access_string(s: &str) -> Result<(), ServiceError> {
    let ok = s.split_whitespace().all(|tok| {
        matches!(
            tok,
            "on" | "off"
                | "nopass"
                | "allkeys"
                | "allchannels"
                | "allcommands"
                | "nocommands"
                | "resetkeys"
                | "resetchannels"
        ) || tok.starts_with(['~', '&', '+', '-', '%'])
    });
    if ok && !s.trim().is_empty() {
        Ok(())
    } else {
        Err(invalid(format!("Access string {s} is invalid.")))
    }
}

/// Passwords and authentication type from a request.
fn credentials(
    passwords: &Option<Vec<String>>,
    no_password: Option<bool>,
    mode: &Option<t::AuthenticationMode>,
) -> Result<Option<(String, Vec<String>)>, ServiceError> {
    let check = |ps: &[String]| -> Result<(), ServiceError> {
        if ps.is_empty() || ps.len() > 2 {
            return Err(invalid("A user can have 1 or 2 passwords."));
        }
        for p in ps {
            if !(16..=128).contains(&p.len()) {
                return Err(invalid("Passwords must be between 16 and 128 characters long."));
            }
        }
        Ok(())
    };
    if let Some(m) = mode {
        let kind = m.r#type.clone().unwrap_or_default();
        return match kind.as_str() {
            "password" => {
                let ps = m.passwords.clone().or(passwords.clone()).unwrap_or_default();
                check(&ps)?;
                Ok(Some(("password".into(), ps)))
            }
            "no-password-required" => Ok(Some(("no-password-required".into(), vec![]))),
            "iam" => Ok(Some(("iam".into(), vec![]))),
            other => Err(invalid(format!("Invalid authentication type: {other}"))),
        };
    }
    match (passwords, no_password) {
        (Some(ps), Some(true)) if !ps.is_empty() => {
            Err(combination("Passwords cannot be specified when NoPasswordRequired is true."))
        }
        (Some(ps), _) if !ps.is_empty() => {
            check(ps)?;
            Ok(Some(("password".into(), ps.clone())))
        }
        (_, Some(true)) => Ok(Some(("no-password".into(), vec![]))),
        _ => Ok(None),
    }
}

fn authentication(kind: &str, passwords: &[String]) -> t::Authentication {
    t::Authentication {
        r#type: Some(kind.to_string()),
        password_count: (kind == "password").then_some(passwords.len() as i32),
    }
}

pub(crate) async fn create(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateUserMessage,
) -> Result<t::User, ServiceError> {
    let id = identifier("UserId", &input.user_id, 40)?;
    let engine = check_engine(&input.engine)?;
    check_access_string(&input.access_string)?;
    let (kind, passwords) = credentials(&input.passwords, input.no_password_required, &input.authentication_mode)?
        .ok_or_else(|| {
            invalid("No password was provided. Specify Passwords, NoPasswordRequired or AuthenticationMode.")
        })?;
    if input.user_name.is_empty() {
        return Err(invalid("The parameter UserName must be provided and must not be blank."));
    }
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "user", &id);
    authorize_create(ctx, "CreateUser", &resource, &tags, cond(&[("UserAuthenticationMode", Some(kind.clone()))]))?;
    svc.with_region(ctx, |r| {
        if r.users.contains_key(&id) {
            return Err(errors::user_already_exists_fault(format!("User {id} already exists.")));
        }
        if r.users.len() >= 1000 {
            return Err(errors::user_quota_exceeded_fault("User quota exceeded."));
        }
        let info = t::User {
            user_id: Some(id.clone()),
            user_name: Some(input.user_name.clone()),
            status: Some("active".into()),
            engine: Some(engine),
            minimum_engine_version: Some("6.0".into()),
            access_string: Some(input.access_string.clone()),
            user_group_ids: Some(vec![]),
            authentication: Some(authentication(&kind, &passwords)),
            arn: Some(resource.clone()),
        };
        r.users.insert(id.clone(), User { info: info.clone(), passwords });
        set_tags(r, &resource, input.tags.clone());
        Ok(info)
    })
}

pub(crate) async fn modify(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyUserMessage,
) -> Result<t::User, ServiceError> {
    let id = input.user_id.to_ascii_lowercase();
    let creds = credentials(&input.passwords, input.no_password_required, &input.authentication_mode)?;
    let (info, groups) = svc.with_region(ctx, |r| {
        let u = r.users.get(&id).ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "ModifyUser", u.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if u.info.status.as_deref() != Some("active") {
            return Err(errors::invalid_user_state_fault(format!("User {id} is not in active state.")));
        }
        let mut u = u.clone();
        if let Some(a) = &input.access_string {
            check_access_string(a)?;
            u.info.access_string = Some(a.clone());
        }
        if let Some(a) = &input.append_access_string {
            check_access_string(a)?;
            let cur = u.info.access_string.clone().unwrap_or_default();
            u.info.access_string = Some(format!("{cur} {a}").trim().to_string());
        }
        if let Some((kind, ps)) = creds {
            u.info.authentication = Some(authentication(&kind, &ps));
            u.passwords = ps;
        }
        if let Some(e) = &input.engine {
            u.info.engine = Some(check_engine(e)?);
        }
        let groups = u.info.user_group_ids.clone().unwrap_or_default();
        r.users.insert(id.clone(), u.clone());
        Ok((u.info, groups))
    })?;
    sync(svc, ctx, &groups, vec![]);
    Ok(info)
}

pub(crate) async fn delete(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteUserMessage,
) -> Result<t::User, ServiceError> {
    let id = input.user_id.to_ascii_lowercase();
    svc.with_region(ctx, |r| {
        let u = r.users.get(&id).ok_or_else(|| not_found(&id))?;
        authorize(ctx, r, "DeleteUser", u.info.arn.as_deref().unwrap_or_default(), Default::default())?;
        if id == "default" {
            return Err(errors::invalid_user_state_fault("The default user cannot be deleted."));
        }
        if u.info.user_group_ids.as_ref().is_some_and(|g| !g.is_empty()) {
            if u.info.user_name.as_deref() == Some("default") {
                return Err(errors::default_user_associated_to_user_group_fault(format!(
                    "User {id} is the default user of a user group."
                )));
            }
            return Err(errors::invalid_user_state_fault(format!("User {id} is associated with a user group.")));
        }
        let mut u = r.users.remove(&id).unwrap_or_default();
        r.tags.remove(u.info.arn.as_deref().unwrap_or_default());
        u.info.status = Some("deleting".into());
        Ok(u.info)
    })
}

pub(crate) async fn describe(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeUsersMessage,
) -> Result<t::DescribeUsersResult, ServiceError> {
    svc.with_region(ctx, |r| {
        ctx.authorize("elasticache:DescribeUsers", &arn(ctx, "user", "*"), Default::default())?;
        if let Some(id) = &input.user_id {
            if !r.users.contains_key(&id.to_ascii_lowercase()) {
                return Err(not_found(id));
            }
        }
        let mut filter_ids: Option<Vec<String>> = None;
        for f in input.filters.iter().flatten() {
            if f.name != "user-id" {
                return Err(invalid(format!("Invalid filter name: {}", f.name)));
            }
            filter_ids = Some(f.values.clone());
        }
        let items: Vec<t::User> = r
            .users
            .values()
            .filter(|u| {
                input.user_id.as_deref().is_none_or(|id| u.info.user_id.as_deref() == Some(&id.to_ascii_lowercase()))
            })
            .filter(|u| input.engine.as_deref().is_none_or(|e| u.info.engine.as_deref() == Some(e)))
            .filter(|u| filter_ids.as_ref().is_none_or(|ids| ids.iter().any(|i| u.info.user_id.as_deref() == Some(i))))
            .map(|u| u.info.clone())
            .collect();
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::DescribeUsersResult { users: Some(page), marker })
    })
}

/// Check that `users` exist, have distinct names and include `default`.
fn check_members(r: &RegionState, users: &[String], engine: &str) -> Result<(), ServiceError> {
    let mut names = Vec::new();
    for u in users {
        let user = r.users.get(u).ok_or_else(|| not_found(u))?;
        let name = user.info.user_name.clone().unwrap_or_default();
        if names.contains(&name) {
            return Err(errors::duplicate_user_name_fault(format!("Duplicate user name {name} in user group.")));
        }
        if engine == "valkey" && user.info.engine.as_deref() == Some("memcached") {
            return Err(combination(format!("User {u} is for another engine.")));
        }
        names.push(name);
    }
    if !names.iter().any(|n| n == "default") {
        return Err(errors::default_user_required("User group needs to contain a user with the user name default."));
    }
    Ok(())
}

pub(crate) async fn create_group(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::CreateUserGroupMessage,
) -> Result<t::UserGroup, ServiceError> {
    let id = identifier("UserGroupId", &input.user_group_id, 40)?;
    let engine = check_engine(&input.engine)?;
    let tags = input.tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    let resource = arn(ctx, "usergroup", &id);
    authorize_create(ctx, "CreateUserGroup", &resource, &tags, Default::default())?;
    let users = input.user_ids.clone().unwrap_or_default();
    svc.with_region(ctx, |r| {
        if r.user_groups.contains_key(&id) {
            return Err(errors::user_group_already_exists_fault(format!("User group {id} already exists.")));
        }
        if r.user_groups.len() >= 100 {
            return Err(errors::user_group_quota_exceeded_fault("User group quota exceeded."));
        }
        check_members(r, &users, &engine)?;
        for u in &users {
            if let Some(user) = r.users.get_mut(u) {
                user.info.user_group_ids.get_or_insert_with(Vec::new).push(id.clone());
            }
        }
        let g = t::UserGroup {
            user_group_id: Some(id.clone()),
            status: Some("active".into()),
            engine: Some(engine),
            user_ids: Some(users),
            minimum_engine_version: Some("6.0".into()),
            pending_changes: None,
            replication_groups: Some(vec![]),
            serverless_caches: Some(vec![]),
            arn: Some(resource.clone()),
        };
        r.user_groups.insert(id.clone(), g.clone());
        set_tags(r, &resource, input.tags.clone());
        Ok(g)
    })
}

pub(crate) async fn modify_group(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::ModifyUserGroupMessage,
) -> Result<t::UserGroup, ServiceError> {
    let id = input.user_group_id.to_ascii_lowercase();
    let (g, removed_cmds) = svc.with_region(ctx, |r| {
        let g = r.user_groups.get(&id).cloned().ok_or_else(|| group_not_found(&id))?;
        authorize(ctx, r, "ModifyUserGroup", g.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.status.as_deref() != Some("active") {
            return Err(errors::invalid_user_group_state_fault(format!("User group {id} is not in active state.")));
        }
        let mut users = g.user_ids.clone().unwrap_or_default();
        let add = input.user_ids_to_add.clone().unwrap_or_default();
        let remove = input.user_ids_to_remove.clone().unwrap_or_default();
        if add.is_empty() && remove.is_empty() && input.engine.is_none() {
            return Err(combination("Specify UserIdsToAdd, UserIdsToRemove or Engine."));
        }
        for u in &remove {
            if !users.contains(u) {
                return Err(not_found(u));
            }
        }
        users.retain(|u| !remove.contains(u));
        for u in &add {
            if !users.contains(u) {
                users.push(u.clone());
            }
        }
        let engine = match &input.engine {
            Some(e) => check_engine(e)?,
            None => g.engine.clone().unwrap_or_default(),
        };
        check_members(r, &users, &engine)?;
        // Names removed from the nodes.
        let removed_names: Vec<String> = remove
            .iter()
            .filter_map(|u| r.users.get(u).and_then(|u| u.info.user_name.clone()))
            .filter(|n| {
                !users.iter().any(|u| r.users.get(u).and_then(|x| x.info.user_name.as_deref()) == Some(n.as_str()))
            })
            .collect();
        for u in &remove {
            if let Some(user) = r.users.get_mut(u) {
                if let Some(list) = user.info.user_group_ids.as_mut() {
                    list.retain(|x| x != &id);
                }
            }
        }
        for u in &add {
            if let Some(user) = r.users.get_mut(u) {
                let list = user.info.user_group_ids.get_or_insert_with(Vec::new);
                if !list.contains(&id) {
                    list.push(id.clone());
                }
            }
        }
        let g = r.user_groups.get_mut(&id).expect("checked");
        g.user_ids = Some(users);
        g.engine = Some(engine);
        let cmds = removed_names.into_iter().map(|n| vec!["ACL".into(), "DELUSER".into(), n]).collect();
        Ok((g.clone(), cmds))
    })?;
    sync(svc, ctx, std::slice::from_ref(&id), removed_cmds);
    Ok(g)
}

pub(crate) async fn delete_group(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DeleteUserGroupMessage,
) -> Result<t::UserGroup, ServiceError> {
    let id = input.user_group_id.to_ascii_lowercase();
    svc.with_region(ctx, |r| {
        let g = r.user_groups.get(&id).cloned().ok_or_else(|| group_not_found(&id))?;
        authorize(ctx, r, "DeleteUserGroup", g.arn.as_deref().unwrap_or_default(), Default::default())?;
        if g.replication_groups.as_ref().is_some_and(|l| !l.is_empty())
            || g.serverless_caches.as_ref().is_some_and(|l| !l.is_empty())
        {
            return Err(errors::invalid_user_group_state_fault(format!(
                "User group {id} is associated with a replication group or serverless cache."
            )));
        }
        for u in g.user_ids.iter().flatten() {
            if let Some(user) = r.users.get_mut(u) {
                if let Some(list) = user.info.user_group_ids.as_mut() {
                    list.retain(|x| x != &id);
                }
            }
        }
        r.user_groups.remove(&id);
        r.tags.remove(g.arn.as_deref().unwrap_or_default());
        let mut g = g;
        g.status = Some("deleting".into());
        Ok(g)
    })
}

pub(crate) async fn describe_groups(
    svc: &ElastiCache,
    ctx: &RequestContext,
    input: t::DescribeUserGroupsMessage,
) -> Result<t::DescribeUserGroupsResult, ServiceError> {
    svc.with_region(ctx, |r| {
        ctx.authorize("elasticache:DescribeUserGroups", &arn(ctx, "usergroup", "*"), Default::default())?;
        let items: Vec<t::UserGroup> = match input.user_group_id.as_deref() {
            Some(id) => {
                vec![r.user_groups.get(&id.to_ascii_lowercase()).cloned().ok_or_else(|| group_not_found(id))?]
            }
            None => r.user_groups.values().cloned().collect(),
        };
        let (page, marker) = page(items, input.marker.as_deref(), input.max_records)?;
        Ok(t::DescribeUserGroupsResult { user_groups: Some(page), marker })
    })
}
