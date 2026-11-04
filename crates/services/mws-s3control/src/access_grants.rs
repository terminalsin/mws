//! S3 Access Grants: an instance per account and Region, locations (S3
//! prefixes with the IAM role that serves them) and grants of READ, WRITE
//! or READWRITE on parts of a location to IAM principals or directory
//! identities.
//!
//! `GetDataAccess` is real: it finds the caller's most specific matching
//! grant, assumes the location's role as `access-grants.s3.amazonaws.com`
//! and vends temporary credentials whose session policy allows only the
//! granted (or, with `Privilege=Minimal`, the requested) scope.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::generated::types;
use crate::S3Control;

const SERVICE_PRINCIPAL: &str = "access-grants.s3.amazonaws.com";

fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

fn no_instance() -> ServiceError {
    err("AccessGrantsInstanceNotExistsError", 404, "Access Grants Instance does not exist")
}

fn no_location() -> ServiceError {
    err("AccessGrantsLocationNotExistsError", 404, "Access Grants Location does not exist")
}

fn no_grant() -> ServiceError {
    err("AccessGrantNotExistsError", 404, "Access Grant does not exist")
}

fn invalid(message: impl Into<String>) -> ServiceError {
    err("InvalidRequest", 400, message)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Instance {
    pub account_id: String,
    pub region: String,
    pub arn: String,
    pub created: Option<DateTime<Utc>>,
    pub identity_center_arn: Option<String>,
    pub application_arn: Option<String>,
    pub policy: Option<String>,
    pub policy_organization: Option<String>,
    pub policy_created: Option<DateTime<Utc>>,
    pub locations: BTreeMap<String, Location>,
    pub grants: BTreeMap<String, Grant>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Location {
    pub id: String,
    pub arn: String,
    pub scope: String,
    pub role: String,
    pub created: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Grant {
    pub id: String,
    pub arn: String,
    pub location_id: String,
    pub sub_prefix: Option<String>,
    pub grantee_type: String,
    pub grantee_identifier: String,
    pub permission: String,
    pub application_arn: Option<String>,
    pub object: bool,
    pub scope: String,
    pub created: Option<DateTime<Utc>>,
}

impl Grant {
    fn grantee(&self) -> types::Grantee {
        types::Grantee {
            grantee_type: Some(self.grantee_type.clone()),
            grantee_identifier: Some(self.grantee_identifier.clone()),
        }
    }

    fn location_configuration(&self) -> Option<types::AccessGrantsLocationConfiguration> {
        self.sub_prefix.clone().map(|p| types::AccessGrantsLocationConfiguration { s3_sub_prefix: Some(p) })
    }

    /// Whether this grant's scope covers `target` (an `s3://` path, a
    /// trailing `*` meaning "everything under").
    fn covers(&self, target: &str) -> bool {
        if self.object {
            return self.scope == target;
        }
        let base = self.scope.trim_end_matches('*');
        target.trim_end_matches('*').starts_with(base)
    }

    fn satisfies(&self, permission: &str) -> bool {
        self.permission == "READWRITE" || self.permission == permission
    }
}

fn key(account: &str, region: &str) -> String {
    format!("{account}/{region}")
}

fn random_id(n: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

fn check_prefix(scope: &str) -> Result<(), ServiceError> {
    if !scope.starts_with("s3://") {
        return Err(invalid(format!("The S3 path {scope} must start with s3://")));
    }
    Ok(())
}

/// A grant's scope: its location's scope extended by the sub-prefix.
fn grant_scope(location: &str, sub_prefix: Option<&str>) -> String {
    let base = location.trim_end_matches('*');
    let base = if base == "s3://" || base.ends_with('/') { base.to_string() } else { format!("{base}/") };
    format!("{base}{}", sub_prefix.unwrap_or("*"))
}

fn page<T: Clone>(
    items: Vec<(String, T)>,
    token: Option<&str>,
    max: i32,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let max = (if max <= 0 { 1000 } else { max }).clamp(1, 1000) as usize;
    let start = match token {
        Some(t) => {
            items.iter().position(|(k, _)| k == t).ok_or_else(|| invalid("The continuation token is not valid"))?
        }
        None => 0,
    };
    let next = items.get(start + max).map(|(k, _)| k.clone());
    Ok((items.into_iter().skip(start).take(max).map(|(_, v)| v).collect(), next))
}

/// The IAM identity a grant names for `caller`: the role for role
/// sessions, the user (or root) ARN otherwise.
fn caller_identity(ctx: &RequestContext) -> String {
    let c = &ctx.caller;
    match &c.kind {
        CallerKind::AssumedRole { role_name, .. } => {
            format!("arn:{}:iam::{}:role/{role_name}", ctx.partition, c.account_id)
        }
        _ => c.arn.clone(),
    }
}

/// Actions a permission allows on objects.
fn object_actions(permission: &str) -> Vec<&'static str> {
    let read = [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectAcl",
        "s3:GetObjectVersionAcl",
        "s3:ListMultipartUploadParts",
    ];
    let write = [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:PutObjectVersionAcl",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:AbortMultipartUpload",
    ];
    match permission {
        "READ" => read.to_vec(),
        "WRITE" => write.to_vec(),
        _ => read.iter().chain(write.iter()).copied().collect(),
    }
}

/// The session policy for credentials scoped to `scope`.
fn session_policy(partition: &str, scope: &str, permission: &str) -> String {
    let path = scope.trim_start_matches("s3://");
    let (bucket, prefix) = path.split_once('/').unwrap_or((path, ""));
    let mut statements = vec![json!({
        "Effect": "Allow",
        "Action": object_actions(permission),
        "Resource": format!("arn:{partition}:s3:::{bucket}/{}", if prefix.is_empty() { "*" } else { prefix }),
    })];
    if permission != "WRITE" {
        statements.push(json!({
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": format!("arn:{partition}:s3:::{bucket}"),
            "Condition": {"StringLike": {"s3:prefix": if prefix.is_empty() { "*" } else { prefix }}},
        }));
    }
    json!({"Version": "2012-10-17", "Statement": statements}).to_string()
}

impl S3Control {
    fn instance_arn(ctx: &RequestContext, account: &str) -> String {
        format!("arn:{}:s3:{}:{account}:access-grants/default", ctx.partition, ctx.region)
    }

    fn with_instance<R>(
        &self,
        ctx: &RequestContext,
        account: &str,
        f: impl FnOnce(&mut Instance) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let mut st = self.write();
        let i = st.access_grants.get_mut(&key(account, &ctx.region)).ok_or_else(no_instance)?;
        f(i)
    }

    fn instance(&self, ctx: &RequestContext, account: &str) -> Result<Instance, ServiceError> {
        self.read().access_grants.get(&key(account, &ctx.region)).cloned().ok_or_else(no_instance)
    }

    pub(crate) fn store_tags(&self, arn: &str, tags: Option<Vec<types::Tag>>) {
        let tags: BTreeMap<String, String> = tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
        if !tags.is_empty() {
            self.write().resource_tags.insert(arn.to_string(), tags);
        }
    }

    pub(crate) async fn create_access_grants_instance(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessGrantsInstanceRequest,
    ) -> Result<types::CreateAccessGrantsInstanceResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::instance_arn(ctx, &account);
        ctx.authorize(
            "s3:CreateAccessGrantsInstance",
            &arn,
            crate::access_points::tags_context(input.tags.as_deref().unwrap_or_default()),
        )?;
        let instance = {
            let mut st = self.write();
            let k = key(&account, &ctx.region);
            if st.access_grants.contains_key(&k) {
                return Err(err(
                    "AccessGrantsInstanceAlreadyExists",
                    409,
                    "Access Grants Instance already exists in this account and Region",
                ));
            }
            let instance = Instance {
                account_id: account.clone(),
                region: ctx.region.clone(),
                arn: arn.clone(),
                created: Some(ctx.received_at),
                application_arn: input.identity_center_arn.as_ref().map(|_| application_arn(ctx, &account)),
                identity_center_arn: input.identity_center_arn.clone(),
                ..Default::default()
            };
            st.access_grants.insert(k, instance.clone());
            instance
        };
        self.store_tags(&arn, input.tags);
        Ok(types::CreateAccessGrantsInstanceResult {
            created_at: instance.created,
            access_grants_instance_id: Some("default".into()),
            access_grants_instance_arn: Some(arn),
            identity_center_arn: instance.identity_center_arn.clone(),
            identity_center_instance_arn: instance.identity_center_arn,
            identity_center_application_arn: instance.application_arn,
        })
    }

    pub(crate) async fn get_access_grants_instance(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsInstanceRequest,
    ) -> Result<types::GetAccessGrantsInstanceResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:GetAccessGrantsInstance", &Self::instance_arn(ctx, &account), ConditionContext::new())?;
        let i = self.instance(ctx, &account)?;
        Ok(types::GetAccessGrantsInstanceResult {
            access_grants_instance_arn: Some(i.arn),
            access_grants_instance_id: Some("default".into()),
            identity_center_arn: i.identity_center_arn.clone(),
            identity_center_instance_arn: i.identity_center_arn,
            identity_center_application_arn: i.application_arn,
            created_at: i.created,
        })
    }

    pub(crate) async fn delete_access_grants_instance(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantsInstanceRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::instance_arn(ctx, &account);
        ctx.authorize("s3:DeleteAccessGrantsInstance", &arn, ConditionContext::new())?;
        let mut st = self.write();
        let k = key(&account, &ctx.region);
        let i = st.access_grants.get(&k).ok_or_else(no_instance)?;
        if !i.locations.is_empty() || !i.grants.is_empty() {
            return Err(err(
                "AccessGrantsInstanceNotEmptyError",
                409,
                "Please clean up locations before deleting the access grants instance",
            ));
        }
        st.access_grants.remove(&k);
        st.resource_tags.remove(&arn);
        Ok(())
    }

    pub(crate) async fn list_access_grants_instances(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessGrantsInstancesRequest,
    ) -> Result<types::ListAccessGrantsInstancesResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListAccessGrantsInstances", "*", ConditionContext::new())?;
        let st = self.read();
        let items: Vec<(String, types::ListAccessGrantsInstanceEntry)> = st
            .access_grants
            .values()
            .filter(|i| i.account_id == account)
            .map(|i| {
                (
                    i.arn.clone(),
                    types::ListAccessGrantsInstanceEntry {
                        access_grants_instance_id: Some("default".into()),
                        access_grants_instance_arn: Some(i.arn.clone()),
                        created_at: i.created,
                        identity_center_arn: i.identity_center_arn.clone(),
                        identity_center_instance_arn: i.identity_center_arn.clone(),
                        identity_center_application_arn: i.application_arn.clone(),
                    },
                )
            })
            .collect();
        let (list, next) = page(items, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAccessGrantsInstancesResult { next_token: next, access_grants_instances_list: Some(list) })
    }

    pub(crate) async fn associate_access_grants_identity_center(
        &self,
        ctx: &RequestContext,
        input: types::AssociateAccessGrantsIdentityCenterRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:AssociateAccessGrantsIdentityCenter",
            &Self::instance_arn(ctx, &account),
            ConditionContext::new(),
        )?;
        let app = application_arn(ctx, &account);
        self.with_instance(ctx, &account, |i| {
            i.identity_center_arn = Some(input.identity_center_arn);
            i.application_arn = Some(app);
            Ok(())
        })
    }

    pub(crate) async fn dissociate_access_grants_identity_center(
        &self,
        ctx: &RequestContext,
        input: types::DissociateAccessGrantsIdentityCenterRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DissociateAccessGrantsIdentityCenter",
            &Self::instance_arn(ctx, &account),
            ConditionContext::new(),
        )?;
        self.with_instance(ctx, &account, |i| {
            i.identity_center_arn = None;
            i.application_arn = None;
            Ok(())
        })
    }

    pub(crate) async fn put_access_grants_instance_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessGrantsInstanceResourcePolicyRequest,
    ) -> Result<types::PutAccessGrantsInstanceResourcePolicyResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:PutAccessGrantsInstanceResourcePolicy",
            &Self::instance_arn(ctx, &account),
            ConditionContext::new(),
        )?;
        if serde_json::from_str::<serde_json::Value>(&input.policy).is_err() {
            return Err(err("MalformedPolicy", 400, "Policies must be valid JSON"));
        }
        let now = ctx.received_at;
        self.with_instance(ctx, &account, |i| {
            i.policy = Some(input.policy.clone());
            i.policy_organization = input.organization.clone();
            i.policy_created = Some(now);
            Ok(types::PutAccessGrantsInstanceResourcePolicyResult {
                policy: Some(input.policy),
                organization: input.organization,
                created_at: Some(now),
            })
        })
    }

    pub(crate) async fn get_access_grants_instance_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsInstanceResourcePolicyRequest,
    ) -> Result<types::GetAccessGrantsInstanceResourcePolicyResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetAccessGrantsInstanceResourcePolicy",
            &Self::instance_arn(ctx, &account),
            ConditionContext::new(),
        )?;
        let i = self.instance(ctx, &account)?;
        let Some(policy) = i.policy else {
            return Err(err(
                "AccessGrantsInstanceResourcePolicyNotExists",
                404,
                "Access Grants Instance Resource Policy does not exist",
            ));
        };
        Ok(types::GetAccessGrantsInstanceResourcePolicyResult {
            policy: Some(policy),
            organization: i.policy_organization,
            created_at: i.policy_created,
        })
    }

    pub(crate) async fn delete_access_grants_instance_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantsInstanceResourcePolicyRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DeleteAccessGrantsInstanceResourcePolicy",
            &Self::instance_arn(ctx, &account),
            ConditionContext::new(),
        )?;
        self.with_instance(ctx, &account, |i| {
            i.policy = None;
            i.policy_organization = None;
            i.policy_created = None;
            Ok(())
        })
    }

    pub(crate) async fn get_access_grants_instance_for_prefix(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsInstanceForPrefixRequest,
    ) -> Result<types::GetAccessGrantsInstanceForPrefixResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        check_prefix(&input.s3_prefix)?;
        ctx.authorize("s3:GetAccessGrantsInstanceForPrefix", "*", ConditionContext::new())?;
        let st = self.read();
        let found = st.access_grants.values().filter(|i| i.region == ctx.region).find(|i| {
            i.locations
                .values()
                .any(|l| input.s3_prefix.trim_end_matches('*').starts_with(l.scope.trim_end_matches('*')))
        });
        let i = found.ok_or_else(no_location)?;
        let _ = account;
        Ok(types::GetAccessGrantsInstanceForPrefixResult {
            access_grants_instance_arn: Some(i.arn.clone()),
            access_grants_instance_id: Some("default".into()),
        })
    }

    fn location_entry(l: &Location) -> types::ListAccessGrantsLocationsEntry {
        types::ListAccessGrantsLocationsEntry {
            created_at: l.created,
            access_grants_location_id: Some(l.id.clone()),
            access_grants_location_arn: Some(l.arn.clone()),
            location_scope: Some(l.scope.clone()),
            iam_role_arn: Some(l.role.clone()),
        }
    }

    pub(crate) async fn create_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessGrantsLocationRequest,
    ) -> Result<types::CreateAccessGrantsLocationResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        check_prefix(&input.location_scope)?;
        let instance_arn = Self::instance_arn(ctx, &account);
        ctx.authorize(
            "s3:CreateAccessGrantsLocation",
            &instance_arn,
            crate::access_points::tags_context(input.tags.as_deref().unwrap_or_default()),
        )?;
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec![SERVICE_PRINCIPAL.into()]);
        ctx.authorize("iam:PassRole", &input.iam_role_arn, pass)?;
        let now = ctx.received_at;
        let location = self.with_instance(ctx, &account, |i| {
            if i.locations.values().any(|l| l.scope == input.location_scope) {
                return Err(err(
                    "AccessGrantsLocationAlreadyExistsError",
                    409,
                    "Access Grants Location already exists for this location scope",
                ));
            }
            let id = if input.location_scope == "s3://" { "default".to_string() } else { random_id(26) };
            let l = Location {
                arn: format!("{}/location/{id}", i.arn),
                id: id.clone(),
                scope: input.location_scope.clone(),
                role: input.iam_role_arn.clone(),
                created: Some(now),
            };
            i.locations.insert(id, l.clone());
            Ok(l)
        })?;
        self.store_tags(&location.arn, input.tags);
        let e = Self::location_entry(&location);
        Ok(types::CreateAccessGrantsLocationResult {
            created_at: e.created_at,
            access_grants_location_id: e.access_grants_location_id,
            access_grants_location_arn: e.access_grants_location_arn,
            location_scope: e.location_scope,
            iam_role_arn: e.iam_role_arn,
        })
    }

    pub(crate) async fn get_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsLocationRequest,
    ) -> Result<types::GetAccessGrantsLocationResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let i = self.instance(ctx, &account)?;
        let l = i.locations.get(&input.access_grants_location_id).ok_or_else(no_location)?;
        ctx.authorize("s3:GetAccessGrantsLocation", &l.arn, ConditionContext::new())?;
        let e = Self::location_entry(l);
        Ok(types::GetAccessGrantsLocationResult {
            created_at: e.created_at,
            access_grants_location_id: e.access_grants_location_id,
            access_grants_location_arn: e.access_grants_location_arn,
            location_scope: e.location_scope,
            iam_role_arn: e.iam_role_arn,
        })
    }

    pub(crate) async fn update_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccessGrantsLocationRequest,
    ) -> Result<types::UpdateAccessGrantsLocationResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let i = self.instance(ctx, &account)?;
        let arn = i.locations.get(&input.access_grants_location_id).ok_or_else(no_location)?.arn.clone();
        ctx.authorize("s3:UpdateAccessGrantsLocation", &arn, ConditionContext::new())?;
        let mut pass = ConditionContext::new();
        pass.insert("iam:PassedToService".into(), vec![SERVICE_PRINCIPAL.into()]);
        ctx.authorize("iam:PassRole", &input.iam_role_arn, pass)?;
        let l = self.with_instance(ctx, &account, |i| {
            let l = i.locations.get_mut(&input.access_grants_location_id).ok_or_else(no_location)?;
            l.role = input.iam_role_arn.clone();
            Ok(l.clone())
        })?;
        let e = Self::location_entry(&l);
        Ok(types::UpdateAccessGrantsLocationResult {
            created_at: e.created_at,
            access_grants_location_id: e.access_grants_location_id,
            access_grants_location_arn: e.access_grants_location_arn,
            location_scope: e.location_scope,
            iam_role_arn: e.iam_role_arn,
        })
    }

    pub(crate) async fn delete_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantsLocationRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let i = self.instance(ctx, &account)?;
        let arn = i.locations.get(&input.access_grants_location_id).ok_or_else(no_location)?.arn.clone();
        ctx.authorize("s3:DeleteAccessGrantsLocation", &arn, ConditionContext::new())?;
        self.with_instance(ctx, &account, |i| {
            if i.grants.values().any(|g| g.location_id == input.access_grants_location_id) {
                return Err(err(
                    "AccessGrantsLocationNotEmptyError",
                    409,
                    "Please delete access grants before deleting the access grants location",
                ));
            }
            i.locations.remove(&input.access_grants_location_id);
            Ok(())
        })?;
        self.write().resource_tags.remove(&arn);
        Ok(())
    }

    pub(crate) async fn list_access_grants_locations(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessGrantsLocationsRequest,
    ) -> Result<types::ListAccessGrantsLocationsResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListAccessGrantsLocations", &Self::instance_arn(ctx, &account), ConditionContext::new())?;
        let i = self.instance(ctx, &account)?;
        let items = i
            .locations
            .values()
            .filter(|l| input.location_scope.as_ref().is_none_or(|s| &l.scope == s))
            .map(|l| (l.id.clone(), Self::location_entry(l)))
            .collect();
        let (list, next) = page(items, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAccessGrantsLocationsResult { next_token: next, access_grants_locations_list: Some(list) })
    }

    pub(crate) async fn create_access_grant(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessGrantRequest,
    ) -> Result<types::CreateAccessGrantResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:CreateAccessGrant",
            &Self::instance_arn(ctx, &account),
            crate::access_points::tags_context(input.tags.as_deref().unwrap_or_default()),
        )?;
        let grantee_type = input.grantee.grantee_type.clone().unwrap_or_default();
        let grantee_id = input.grantee.grantee_identifier.clone().unwrap_or_default();
        if grantee_type.is_empty() || grantee_id.is_empty() {
            return Err(invalid("Grantee type and identifier are required"));
        }
        if grantee_type == "IAM" && !grantee_id.starts_with("arn:") {
            return Err(invalid(format!("Grantee identifier {grantee_id} is not a valid IAM principal ARN")));
        }
        let sub_prefix = input.access_grants_location_configuration.as_ref().and_then(|c| c.s3_sub_prefix.clone());
        let object = input.s3_prefix_type.as_deref() == Some("Object");
        if object && sub_prefix.as_deref().is_none_or(|p| p.contains('*')) {
            return Err(invalid("An Object grant needs a sub-prefix that names one object, without wildcards"));
        }
        let now = ctx.received_at;
        let grant = self.with_instance(ctx, &account, |i| {
            let l = i.locations.get(&input.access_grants_location_id).ok_or_else(no_location)?;
            let scope = grant_scope(&l.scope, sub_prefix.as_deref());
            if i.grants
                .values()
                .any(|g| g.scope == scope && g.grantee_identifier == grantee_id && g.permission == input.permission)
            {
                return Err(err("AccessGrantAlreadyExists", 409, "An access grant with these settings already exists"));
            }
            let id = random_id(26);
            let g = Grant {
                arn: format!("{}/grant/{id}", i.arn),
                id: id.clone(),
                location_id: l.id.clone(),
                sub_prefix: sub_prefix.clone(),
                grantee_type: grantee_type.clone(),
                grantee_identifier: grantee_id.clone(),
                permission: input.permission.clone(),
                application_arn: input.application_arn.clone(),
                object,
                scope,
                created: Some(now),
            };
            i.grants.insert(id, g.clone());
            Ok(g)
        })?;
        self.store_tags(&grant.arn, input.tags);
        Ok(types::CreateAccessGrantResult {
            created_at: grant.created,
            access_grant_id: Some(grant.id.clone()),
            access_grant_arn: Some(grant.arn.clone()),
            grantee: Some(grant.grantee()),
            access_grants_location_id: Some(grant.location_id.clone()),
            access_grants_location_configuration: grant.location_configuration(),
            permission: Some(grant.permission.clone()),
            application_arn: grant.application_arn.clone(),
            grant_scope: Some(grant.scope.clone()),
        })
    }

    fn grant_entry(g: &Grant) -> types::ListAccessGrantEntry {
        types::ListAccessGrantEntry {
            created_at: g.created,
            access_grant_id: Some(g.id.clone()),
            access_grant_arn: Some(g.arn.clone()),
            grantee: Some(g.grantee()),
            permission: Some(g.permission.clone()),
            access_grants_location_id: Some(g.location_id.clone()),
            access_grants_location_configuration: g.location_configuration(),
            grant_scope: Some(g.scope.clone()),
            application_arn: g.application_arn.clone(),
        }
    }

    pub(crate) async fn get_access_grant(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantRequest,
    ) -> Result<types::GetAccessGrantResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let i = self.instance(ctx, &account)?;
        let g = i.grants.get(&input.access_grant_id).ok_or_else(no_grant)?;
        ctx.authorize("s3:GetAccessGrant", &g.arn, ConditionContext::new())?;
        let e = Self::grant_entry(g);
        Ok(types::GetAccessGrantResult {
            created_at: e.created_at,
            access_grant_id: e.access_grant_id,
            access_grant_arn: e.access_grant_arn,
            grantee: e.grantee,
            permission: e.permission,
            access_grants_location_id: e.access_grants_location_id,
            access_grants_location_configuration: e.access_grants_location_configuration,
            grant_scope: e.grant_scope,
            application_arn: e.application_arn,
        })
    }

    pub(crate) async fn delete_access_grant(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let i = self.instance(ctx, &account)?;
        let arn = i.grants.get(&input.access_grant_id).ok_or_else(no_grant)?.arn.clone();
        ctx.authorize("s3:DeleteAccessGrant", &arn, ConditionContext::new())?;
        self.with_instance(ctx, &account, |i| {
            i.grants.remove(&input.access_grant_id);
            Ok(())
        })?;
        self.write().resource_tags.remove(&arn);
        Ok(())
    }

    pub(crate) async fn list_access_grants(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessGrantsRequest,
    ) -> Result<types::ListAccessGrantsResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListAccessGrants", &Self::instance_arn(ctx, &account), ConditionContext::new())?;
        let i = self.instance(ctx, &account)?;
        let items = i
            .grants
            .values()
            .filter(|g| input.grantee_type.as_ref().is_none_or(|t| &g.grantee_type == t))
            .filter(|g| input.grantee_identifier.as_ref().is_none_or(|t| &g.grantee_identifier == t))
            .filter(|g| input.permission.as_ref().is_none_or(|t| &g.permission == t))
            .filter(|g| input.grant_scope.as_ref().is_none_or(|t| &g.scope == t))
            .filter(|g| input.application_arn.as_ref().is_none_or(|t| g.application_arn.as_ref() == Some(t)))
            .map(|g| (g.id.clone(), Self::grant_entry(g)))
            .collect();
        let (list, next) = page(items, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAccessGrantsResult { next_token: next, access_grants_list: Some(list) })
    }

    pub(crate) async fn list_caller_access_grants(
        &self,
        ctx: &RequestContext,
        input: types::ListCallerAccessGrantsRequest,
    ) -> Result<types::ListCallerAccessGrantsResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let i = self.instance(ctx, &account)?;
        ctx.authorize_with_resource_policy(
            "s3:ListCallerAccessGrants",
            &i.arn,
            i.policy.as_deref(),
            ConditionContext::new(),
        )?;
        let me = caller_identity(ctx);
        let items =
            i.grants
                .values()
                .filter(|g| g.grantee_type == "IAM" && g.grantee_identifier == me)
                .filter(|g| {
                    input.grant_scope.as_ref().is_none_or(|s| {
                        g.covers(s) || g.scope.trim_end_matches('*').starts_with(s.trim_end_matches('*'))
                    })
                })
                .filter(|g| !input.allowed_by_application || g.application_arn.is_some())
                .map(|g| {
                    (
                        g.id.clone(),
                        types::ListCallerAccessGrantsEntry {
                            permission: Some(g.permission.clone()),
                            grant_scope: Some(g.scope.clone()),
                            application_arn: g.application_arn.clone(),
                        },
                    )
                })
                .collect();
        let (list, next) = page(items, input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListCallerAccessGrantsResult { next_token: next, caller_access_grants_list: Some(list) })
    }

    pub(crate) async fn get_data_access(
        &self,
        ctx: &RequestContext,
        input: types::GetDataAccessRequest,
    ) -> Result<types::GetDataAccessResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        check_prefix(&input.target)?;
        let i = self.instance(ctx, &account)?;
        ctx.authorize_with_resource_policy("s3:GetDataAccess", &i.arn, i.policy.as_deref(), ConditionContext::new())?;
        let duration = input.duration_seconds.unwrap_or(3600);
        if !(900..=43200).contains(&duration) {
            return Err(invalid("DurationSeconds must be between 900 and 43200"));
        }
        let object_target = input.target_type.as_deref() == Some("Object");
        let me = caller_identity(ctx);
        let grant = i
            .grants
            .values()
            .filter(|g| g.grantee_type == "IAM" && g.grantee_identifier == me)
            .filter(|g| g.satisfies(&input.permission))
            .filter(|g| g.covers(&input.target))
            .max_by_key(|g| g.scope.len())
            .cloned()
            .ok_or_else(|| err("AccessDenied", 403, "You do not have access to the requested S3 prefix"))?;
        let location = i.locations.get(&grant.location_id).ok_or_else(no_location)?;
        let scope = if input.privilege.as_deref() == Some("Minimal") || object_target {
            input.target.clone()
        } else {
            grant.scope.clone()
        };
        let policy = session_policy(&ctx.partition, &scope, &input.permission);
        let sts = self.sts.get().ok_or_else(|| err("InternalError", 500, "STS is not available"))?;
        let creds = sts
            .assume_role_as_service_with_policy(
                &mws_sts::ServiceAssume {
                    role_arn: &location.role,
                    service_principal: SERVICE_PRINCIPAL,
                    session_name: "access-grants",
                    duration_seconds: duration,
                    source_account: Some(&account),
                    source_arn: Some(&i.arn),
                    now: ctx.received_at,
                },
                Some(policy),
            )
            .map_err(|_| {
                err(
                    "AccessDenied",
                    403,
                    format!("S3 Access Grants could not assume the location's role {}", location.role),
                )
            })?;
        Ok(types::GetDataAccessResult {
            credentials: Some(types::Credentials {
                access_key_id: Some(creds.access_key_id),
                secret_access_key: Some(creds.secret_access_key),
                session_token: Some(creds.session_token),
                expiration: Some(creds.expiration),
            }),
            matched_grant_target: Some(grant.scope.clone()),
            grantee: Some(grant.grantee()),
        })
    }

    /// Whether `arn` is an Access Grants resource that takes tags.
    pub(crate) fn access_grants_resource_exists(&self, arn: &str) -> bool {
        let st = self.read();
        st.access_grants.values().any(|i| {
            i.arn == arn || i.locations.values().any(|l| l.arn == arn) || i.grants.values().any(|g| g.arn == arn)
        })
    }
}

fn application_arn(ctx: &RequestContext, account: &str) -> String {
    format!("arn:{}:sso::{account}:application/ssoins-{}/apl-{}", ctx.partition, random_id(16), random_id(16))
}
