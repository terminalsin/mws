//! Account assignments and permission set provisioning.

use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{Assignment, InstanceKind};
use crate::SsoAdmin;

fn op_status(
    request_id: &str,
    status: &str,
    failure: Option<String>,
    a: &Assignment,
    at: chrono::DateTime<chrono::Utc>,
) -> types::AccountAssignmentOperationStatus {
    types::AccountAssignmentOperationStatus {
        status: Some(status.into()),
        request_id: Some(request_id.into()),
        failure_reason: failure,
        target_id: Some(a.account.clone()),
        target_type: Some("AWS_ACCOUNT".into()),
        permission_set_arn: Some(a.permission_set.clone()),
        principal_type: Some(a.principal_type.clone()),
        principal_id: Some(a.principal_id.clone()),
        created_date: Some(at),
    }
}

fn status_metadata(s: &types::AccountAssignmentOperationStatus) -> types::AccountAssignmentOperationStatusMetadata {
    types::AccountAssignmentOperationStatusMetadata {
        status: s.status.clone(),
        request_id: s.request_id.clone(),
        created_date: s.created_date,
    }
}

fn filter_status<T>(
    items: Vec<T>,
    filter: &Option<types::OperationStatusFilter>,
    status: impl Fn(&T) -> Option<&str>,
) -> Vec<T> {
    match filter.as_ref().and_then(|f| f.status.as_deref()) {
        Some(want) => items.into_iter().filter(|i| status(i) == Some(want)).collect(),
        None => items,
    }
}

impl SsoAdmin {
    /// Check `account` is one this instance can assign access to.
    fn check_target(&self, r: &InstanceRef, account: &str) -> Result<(), ServiceError> {
        match r.kind {
            InstanceKind::Account => {
                if account != r.owner {
                    return Err(errors::validation(format!(
                        "An account instance can only assign access to its own account {}.",
                        r.owner
                    )));
                }
            }
            InstanceKind::Organization => {
                let owner_org = self.iam.organization_of(&r.owner).map(|o| o.organization_id);
                let target_org = self.iam.organization_of(account);
                if owner_org.is_none() || target_org.as_ref().map(|o| o.organization_id.clone()) != owner_org {
                    return Err(errors::validation(format!(
                        "The target account {account} is not a member of the organization."
                    )));
                }
                if r.delegated && target_org.is_some_and(|o| o.is_management(account)) {
                    return Err(errors::access_denied(
                        "A delegated administrator can't manage access to the management account.",
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_principal(&self, r: &InstanceRef, kind: &str, id: &str) -> Result<(), ServiceError> {
        let exists = match kind {
            "USER" => self.identity.user_exists(&r.identity_store_id, id),
            "GROUP" => self.identity.group_exists(&r.identity_store_id, id),
            _ => false,
        };
        if exists {
            Ok(())
        } else {
            Err(not_found(format!(
                "Principal {id} of type {kind} doesn't exist in identity store {}.",
                r.identity_store_id
            )))
        }
    }

    pub(crate) fn create_account_assignment(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccountAssignmentRequest,
    ) -> Result<types::CreateAccountAssignmentResponse, ServiceError> {
        let r =
            self.permission_set(ctx, &input.instance_arn, &input.permission_set_arn, "sso:CreateAccountAssignment")?;
        self.check_target(&r, &input.target_id)?;
        self.check_principal(&r, &input.principal_type, &input.principal_id)?;
        let a = Assignment {
            account: input.target_id,
            permission_set: input.permission_set_arn,
            principal_type: input.principal_type,
            principal_id: input.principal_id,
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let provisioned = {
            let st = self.lock();
            st.instances
                .get(&r.arn)
                .is_some_and(|i| i.provisioned.contains_key(&(a.permission_set.clone(), a.account.clone())))
        };
        let result = if provisioned {
            Ok(())
        } else {
            self.provision_into(&ctx.partition, &r.arn, &a.permission_set, &a.account).map(|_| ())
        };
        let final_status = match &result {
            Ok(()) => op_status(&request_id, "SUCCEEDED", None, &a, ctx.received_at),
            Err(reason) => op_status(&request_id, "FAILED", Some(reason.clone()), &a, ctx.received_at),
        };
        self.with_instance(&r.arn, |i| {
            if result.is_ok() {
                i.assignments.insert(a.clone());
            }
            i.creations.insert(request_id.clone(), final_status);
            Ok(())
        })?;
        Ok(types::CreateAccountAssignmentResponse {
            account_assignment_creation_status: Some(op_status(&request_id, "IN_PROGRESS", None, &a, ctx.received_at)),
        })
    }

    pub(crate) fn delete_account_assignment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccountAssignmentRequest,
    ) -> Result<types::DeleteAccountAssignmentResponse, ServiceError> {
        let r =
            self.permission_set(ctx, &input.instance_arn, &input.permission_set_arn, "sso:DeleteAccountAssignment")?;
        self.check_target(&r, &input.target_id)?;
        let a = Assignment {
            account: input.target_id,
            permission_set: input.permission_set_arn,
            principal_type: input.principal_type,
            principal_id: input.principal_id,
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let last = self.with_instance(&r.arn, |i| {
            if !i.assignments.remove(&a) {
                return Err(not_found("The account assignment doesn't exist."));
            }
            i.deletions.insert(request_id.clone(), op_status(&request_id, "SUCCEEDED", None, &a, ctx.received_at));
            Ok(!i.assignments.iter().any(|x| x.account == a.account && x.permission_set == a.permission_set))
        })?;
        if last {
            self.deprovision(&r.arn, &a.permission_set, &a.account);
        }
        Ok(types::DeleteAccountAssignmentResponse {
            account_assignment_deletion_status: Some(op_status(&request_id, "IN_PROGRESS", None, &a, ctx.received_at)),
        })
    }

    pub(crate) fn describe_account_assignment_creation_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountAssignmentCreationStatusRequest,
    ) -> Result<types::DescribeAccountAssignmentCreationStatusResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:DescribeAccountAssignmentCreationStatus", None)?;
        let id = input.account_assignment_creation_request_id;
        self.with_instance(&r.arn, |i| {
            let s = i.creations.get(&id).cloned().ok_or_else(|| not_found(format!("Request {id} doesn't exist.")))?;
            Ok(types::DescribeAccountAssignmentCreationStatusResponse { account_assignment_creation_status: Some(s) })
        })
    }

    pub(crate) fn describe_account_assignment_deletion_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountAssignmentDeletionStatusRequest,
    ) -> Result<types::DescribeAccountAssignmentDeletionStatusResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:DescribeAccountAssignmentDeletionStatus", None)?;
        let id = input.account_assignment_deletion_request_id;
        self.with_instance(&r.arn, |i| {
            let s = i.deletions.get(&id).cloned().ok_or_else(|| not_found(format!("Request {id} doesn't exist.")))?;
            Ok(types::DescribeAccountAssignmentDeletionStatusResponse { account_assignment_deletion_status: Some(s) })
        })
    }

    pub(crate) fn list_account_assignment_creation_status(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountAssignmentCreationStatusRequest,
    ) -> Result<types::ListAccountAssignmentCreationStatusResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListAccountAssignmentCreationStatus", None)?;
        let all = self.with_instance(&r.arn, |i| Ok(i.creations.values().map(status_metadata).collect::<Vec<_>>()))?;
        let all = filter_status(all, &input.filter, |m| m.status.as_deref());
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAccountAssignmentCreationStatusResponse {
            account_assignments_creation_status: Some(page),
            next_token,
        })
    }

    pub(crate) fn list_account_assignment_deletion_status(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountAssignmentDeletionStatusRequest,
    ) -> Result<types::ListAccountAssignmentDeletionStatusResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListAccountAssignmentDeletionStatus", None)?;
        let all = self.with_instance(&r.arn, |i| Ok(i.deletions.values().map(status_metadata).collect::<Vec<_>>()))?;
        let all = filter_status(all, &input.filter, |m| m.status.as_deref());
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAccountAssignmentDeletionStatusResponse {
            account_assignments_deletion_status: Some(page),
            next_token,
        })
    }

    pub(crate) fn list_account_assignments(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountAssignmentsRequest,
    ) -> Result<types::ListAccountAssignmentsResponse, ServiceError> {
        let r =
            self.permission_set(ctx, &input.instance_arn, &input.permission_set_arn, "sso:ListAccountAssignments")?;
        let all = self.with_instance(&r.arn, |i| {
            Ok(i.assignments
                .iter()
                .filter(|a| a.account == input.account_id && a.permission_set == input.permission_set_arn)
                .map(|a| types::AccountAssignment {
                    account_id: Some(a.account.clone()),
                    permission_set_arn: Some(a.permission_set.clone()),
                    principal_type: Some(a.principal_type.clone()),
                    principal_id: Some(a.principal_id.clone()),
                })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAccountAssignmentsResponse { account_assignments: Some(page), next_token })
    }

    pub(crate) fn list_account_assignments_for_principal(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountAssignmentsForPrincipalRequest,
    ) -> Result<types::ListAccountAssignmentsForPrincipalResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListAccountAssignmentsForPrincipal", None)?;
        let account = input.filter.and_then(|f| f.account_id);
        let all = self.with_instance(&r.arn, |i| {
            Ok(i.assignments
                .iter()
                .filter(|a| a.principal_type == input.principal_type && a.principal_id == input.principal_id)
                .filter(|a| account.as_ref().is_none_or(|acct| *acct == a.account))
                .map(|a| types::AccountAssignmentForPrincipal {
                    account_id: Some(a.account.clone()),
                    permission_set_arn: Some(a.permission_set.clone()),
                    principal_id: Some(a.principal_id.clone()),
                    principal_type: Some(a.principal_type.clone()),
                })
                .collect::<Vec<_>>())
        })?;
        let max = (input.max_results > 0).then_some(input.max_results);
        let (page, next_token) = paginate(all, max, 100, input.next_token.as_deref())?;
        Ok(types::ListAccountAssignmentsForPrincipalResponse { account_assignments: Some(page), next_token })
    }

    pub(crate) fn provision_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::ProvisionPermissionSetRequest,
    ) -> Result<types::ProvisionPermissionSetResponse, ServiceError> {
        let r =
            self.permission_set(ctx, &input.instance_arn, &input.permission_set_arn, "sso:ProvisionPermissionSet")?;
        let ps = input.permission_set_arn.clone();
        let accounts: Vec<String> = match (input.target_type.as_str(), &input.target_id) {
            ("AWS_ACCOUNT", Some(id)) => {
                self.check_target(&r, id)?;
                vec![id.clone()]
            }
            ("AWS_ACCOUNT", None) => {
                return Err(errors::validation("TargetId is required when TargetType is AWS_ACCOUNT."))
            }
            ("ALL_PROVISIONED_ACCOUNTS", Some(_)) => {
                return Err(errors::validation("TargetId must not be set when TargetType is ALL_PROVISIONED_ACCOUNTS."))
            }
            _ => self.with_instance(&r.arn, |i| {
                Ok(i.provisioned.keys().filter(|(p, _)| *p == ps).map(|(_, a)| a.clone()).collect())
            })?,
        };
        let mut failure = None;
        for account in &accounts {
            if let Err(reason) = self.provision_into(&ctx.partition, &r.arn, &ps, account) {
                failure = Some(reason);
                break;
            }
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let account_id = input.target_id.clone();
        let status = |s: &str, failure: Option<String>| types::PermissionSetProvisioningStatus {
            status: Some(s.into()),
            request_id: Some(request_id.clone()),
            account_id: account_id.clone(),
            permission_set_arn: Some(ps.clone()),
            failure_reason: failure,
            created_date: Some(ctx.received_at),
        };
        let done = match failure {
            None => status("SUCCEEDED", None),
            Some(f) => status("FAILED", Some(f)),
        };
        self.with_instance(&r.arn, |i| {
            i.provisionings.insert(request_id.clone(), done);
            Ok(())
        })?;
        Ok(types::ProvisionPermissionSetResponse {
            permission_set_provisioning_status: Some(status("IN_PROGRESS", None)),
        })
    }

    pub(crate) fn describe_permission_set_provisioning_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribePermissionSetProvisioningStatusRequest,
    ) -> Result<types::DescribePermissionSetProvisioningStatusResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:DescribePermissionSetProvisioningStatus", None)?;
        let id = input.provision_permission_set_request_id;
        self.with_instance(&r.arn, |i| {
            let s =
                i.provisionings.get(&id).cloned().ok_or_else(|| not_found(format!("Request {id} doesn't exist.")))?;
            Ok(types::DescribePermissionSetProvisioningStatusResponse { permission_set_provisioning_status: Some(s) })
        })
    }

    pub(crate) fn list_permission_set_provisioning_status(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionSetProvisioningStatusRequest,
    ) -> Result<types::ListPermissionSetProvisioningStatusResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListPermissionSetProvisioningStatus", None)?;
        let all = self.with_instance(&r.arn, |i| {
            Ok(i.provisionings
                .values()
                .map(|s| types::PermissionSetProvisioningStatusMetadata {
                    status: s.status.clone(),
                    request_id: s.request_id.clone(),
                    created_date: s.created_date,
                })
                .collect::<Vec<_>>())
        })?;
        let all = filter_status(all, &input.filter, |m| m.status.as_deref());
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListPermissionSetProvisioningStatusResponse {
            permission_sets_provisioning_status: Some(page),
            next_token,
        })
    }

    pub(crate) fn list_accounts_for_provisioned_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountsForProvisionedPermissionSetRequest,
    ) -> Result<types::ListAccountsForProvisionedPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:ListAccountsForProvisionedPermissionSet",
        )?;
        let ps = input.permission_set_arn.clone();
        let want = input.provisioning_status.clone();
        let all = self.with_instance(&r.arn, |i| {
            let version = i.permission_sets.get(&ps).map(|p| p.version).unwrap_or_default();
            Ok(i.provisioned
                .iter()
                .filter(|((p, _), _)| *p == ps)
                .filter(|(_, v)| match want.as_deref() {
                    Some("LATEST_PERMISSION_SET_PROVISIONED") => v.version == version,
                    Some("LATEST_PERMISSION_SET_NOT_PROVISIONED") => v.version != version,
                    _ => true,
                })
                .map(|((_, a), _)| a.clone())
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListAccountsForProvisionedPermissionSetResponse { account_ids: Some(page), next_token })
    }

    pub(crate) fn list_permission_sets_provisioned_to_account(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionSetsProvisionedToAccountRequest,
    ) -> Result<types::ListPermissionSetsProvisionedToAccountResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListPermissionSetsProvisionedToAccount", None)?;
        let account = input.account_id.clone();
        let want = input.provisioning_status.clone();
        let all = self.with_instance(&r.arn, |i| {
            Ok(i.provisioned
                .iter()
                .filter(|((_, a), _)| *a == account)
                .filter(|((p, _), v)| {
                    let version = i.permission_sets.get(p).map(|p| p.version).unwrap_or_default();
                    match want.as_deref() {
                        Some("LATEST_PERMISSION_SET_PROVISIONED") => v.version == version,
                        Some("LATEST_PERMISSION_SET_NOT_PROVISIONED") => v.version != version,
                        _ => true,
                    }
                })
                .map(|((p, _), _)| p.clone())
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListPermissionSetsProvisionedToAccountResponse { permission_sets: Some(page), next_token })
    }
}
