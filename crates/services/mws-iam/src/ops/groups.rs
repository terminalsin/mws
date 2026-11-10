//! Groups and membership.

use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{Group, User};
use crate::{ids, wire, Iam};

impl Iam {
    pub fn create_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateGroupRequest,
    ) -> Result<types::CreateGroupResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let arn = self.entity_arn("group", &path, &input.group_name);
        self.authorize(ctx, "CreateGroup", &arn)?;
        let limit = self.limit(ctx, &GROUPS_PER_ACCOUNT);
        let mut state = self.write();
        let key = input.group_name.to_lowercase();
        if state.groups.contains_key(&key) {
            return Err(errors::entity_already_exists(format!("Group with name {} already exists.", input.group_name)));
        }
        if state.groups.len() >= limit {
            return Err(quota_exceeded(GROUPS_PER_ACCOUNT.name, limit));
        }
        let group = Group {
            name: input.group_name,
            path,
            id: ids::unique_id("AGPA"),
            arn,
            created: ctx.received_at,
            inline: Default::default(),
            attached: Default::default(),
            members: Default::default(),
        };
        let out = wire::group(&group);
        state.groups.insert(key, group);
        Ok(types::CreateGroupResponse { group: out })
    }

    pub fn get_group(
        &self,
        ctx: &RequestContext,
        input: types::GetGroupRequest,
    ) -> Result<types::GetGroupResponse, ServiceError> {
        self.authorize(ctx, "GetGroup", &self.group_arn_or_default(&input.group_name))?;
        let state = self.read();
        let g = state.group(&input.group_name).ok_or_else(|| no_such_group(&input.group_name))?;
        let users: Vec<User> = g.members.iter().filter_map(|m| state.user(m)).cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&users, |u| u.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::GetGroupResponse {
            group: wire::group(g),
            users: page.iter().map(wire::user_summary).collect(),
            is_truncated,
            marker,
        })
    }

    pub fn list_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListGroupsRequest,
    ) -> Result<types::ListGroupsResponse, ServiceError> {
        self.authorize(ctx, "ListGroups", &self.arn("group/"))?;
        let prefix = input.path_prefix.unwrap_or_else(|| "/".into());
        let groups: Vec<Group> = self.read().groups.values().filter(|g| g.path.starts_with(&prefix)).cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&groups, |g| g.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListGroupsResponse { groups: page.iter().map(wire::group).collect(), is_truncated, marker })
    }

    pub fn list_groups_for_user(
        &self,
        ctx: &RequestContext,
        input: types::ListGroupsForUserRequest,
    ) -> Result<types::ListGroupsForUserResponse, ServiceError> {
        self.authorize(ctx, "ListGroupsForUser", &self.user_arn_or_default(&input.user_name))?;
        let state = self.read();
        state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        let groups: Vec<Group> = state.groups_for_user(&input.user_name).into_iter().cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&groups, |g| g.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListGroupsForUserResponse { groups: page.iter().map(wire::group).collect(), is_truncated, marker })
    }

    pub fn update_group(&self, ctx: &RequestContext, input: types::UpdateGroupRequest) -> Result<(), ServiceError> {
        self.authorize(ctx, "UpdateGroup", &self.group_arn_or_default(&input.group_name))?;
        let mut state = self.write();
        let mut g = state.group(&input.group_name).cloned().ok_or_else(|| no_such_group(&input.group_name))?;
        let old_key = g.name.to_lowercase();
        if let Some(n) = &input.new_group_name {
            if n.to_lowercase() != old_key && state.groups.contains_key(&n.to_lowercase()) {
                return Err(errors::entity_already_exists(format!("Group with name {n} already exists.")));
            }
            g.name = n.clone();
        }
        if let Some(p) = input.new_path {
            g.path = p;
        }
        g.arn = self.entity_arn("group", &g.path, &g.name);
        state.groups.remove(&old_key);
        state.groups.insert(g.name.to_lowercase(), g);
        Ok(())
    }

    pub fn delete_group(&self, ctx: &RequestContext, input: types::DeleteGroupRequest) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteGroup", &self.group_arn_or_default(&input.group_name))?;
        let mut state = self.write();
        let g = state.group(&input.group_name).ok_or_else(|| no_such_group(&input.group_name))?;
        if !g.members.is_empty() {
            return Err(errors::delete_conflict("Cannot delete entity, must remove users from group first."));
        }
        if !g.inline.is_empty() {
            return Err(errors::delete_conflict("Cannot delete entity, must delete policies first."));
        }
        if !g.attached.is_empty() {
            return Err(errors::delete_conflict("Cannot delete entity, must detach all policies first."));
        }
        state.groups.remove(&input.group_name.to_lowercase());
        Ok(())
    }

    pub fn add_user_to_group(
        &self,
        ctx: &RequestContext,
        input: types::AddUserToGroupRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "AddUserToGroup", &self.group_arn_or_default(&input.group_name))?;
        let mut state = self.write();
        state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        state.group(&input.group_name).ok_or_else(|| no_such_group(&input.group_name))?;
        let member = input.user_name.to_lowercase();
        let groups = state.groups_for_user(&input.user_name);
        let already = groups.iter().any(|g| g.name.eq_ignore_ascii_case(&input.group_name));
        if !already && groups.len() >= GROUPS_PER_USER {
            return Err(quota_exceeded("GroupsPerUser", GROUPS_PER_USER));
        }
        let g = state.group_mut(&input.group_name).ok_or_else(|| no_such_group(&input.group_name))?;
        g.members.insert(member);
        Ok(())
    }

    pub fn remove_user_from_group(
        &self,
        ctx: &RequestContext,
        input: types::RemoveUserFromGroupRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "RemoveUserFromGroup", &self.group_arn_or_default(&input.group_name))?;
        let mut state = self.write();
        state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        let g = state.group_mut(&input.group_name).ok_or_else(|| no_such_group(&input.group_name))?;
        if !g.members.remove(&input.user_name.to_lowercase()) {
            return Err(errors::no_such_entity(format!(
                "The user with name {} cannot be found in group {}.",
                input.user_name, input.group_name
            )));
        }
        Ok(())
    }
}
