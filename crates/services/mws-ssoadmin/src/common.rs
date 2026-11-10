//! Helpers shared by the operations: ids, paging, and finding the instance
//! a request addresses.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::state::{Instance, InstanceKind, State, Tags};
use crate::SsoAdmin;

pub const SERVICE_PRINCIPAL: &str = "sso.amazonaws.com";

pub fn hex(n: usize) -> String {
    let mut s = String::new();
    while s.len() < n {
        s.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    s.truncate(n);
    s
}

pub fn paginate<T>(
    items: Vec<T>,
    max: Option<i32>,
    default_max: usize,
    token: Option<&str>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token.filter(|t| !t.is_empty()) {
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| errors::validation("The NextToken provided is invalid."))?,
        None => 0,
    };
    let max = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(default_max);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total).then(|| format!("mws-{}", start + max));
    Ok((page, next))
}

pub fn not_found(message: impl Into<String>) -> ServiceError {
    errors::resource_not_found(message)
}

pub fn instance_not_found(arn: &str) -> ServiceError {
    not_found(format!("Instance {arn} doesn't exist."))
}

pub fn permission_set_not_found(arn: &str) -> ServiceError {
    not_found(format!("Could not find PermissionSet with PermissionSetArn {arn}."))
}

pub fn tags_from(tags: Option<Vec<types::Tag>>) -> Result<Tags, ServiceError> {
    let tags = tags.unwrap_or_default();
    if tags.len() > 50 {
        return Err(errors::validation("Tags exceed the maximum number of 50 tags per resource."));
    }
    Ok(tags.into_iter().map(|t| (t.key, t.value)).collect())
}

pub fn tags_to(tags: &Tags) -> Vec<types::Tag> {
    tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()
}

/// The instance id within any Identity Center ARN
/// (`.../ssoins-xxxxxxxxxxxxxxxx/...`).
pub fn instance_id_in(arn: &str) -> Option<&str> {
    arn.split(['/', ':']).find(|p| p.starts_with("ssoins-") || p.starts_with("ins-"))
}

/// Seconds in an ISO 8601 duration like `PT1H` or `PT2H30M`.
pub fn duration_seconds(d: &str) -> Option<i64> {
    let t = d.strip_prefix("PT")?;
    let mut total = 0i64;
    let mut num = String::new();
    for c in t.chars() {
        match c {
            '0'..='9' | '.' => num.push(c),
            'H' | 'M' | 'S' => {
                let n: f64 = num.parse().ok()?;
                num.clear();
                total += (n * match c {
                    'H' => 3600.0,
                    'M' => 60.0,
                    _ => 1.0,
                }) as i64;
            }
            _ => return None,
        }
    }
    num.is_empty().then_some(total)
}

/// What an operation needs to know about the instance it addresses.
#[derive(Debug, Clone)]
pub struct InstanceRef {
    pub arn: String,
    pub owner: String,
    pub kind: InstanceKind,
    pub identity_store_id: String,
    /// Whether the caller is the organization's delegated administrator
    /// rather than the owner.
    pub delegated: bool,
}

impl SsoAdmin {
    /// Whether the caller's account manages `inst`: its owner, or (for an
    /// organization instance) the organization's delegated administrator for
    /// IAM Identity Center.
    pub(crate) fn manages(&self, caller: &str, inst: &Instance) -> Option<bool> {
        if caller == inst.owner {
            return Some(false);
        }
        if inst.kind != InstanceKind::Organization {
            return None;
        }
        let org = self.iam.organization_of(caller)?;
        let owner_org = self.iam.organization_of(&inst.owner)?;
        (org.organization_id == owner_org.organization_id
            && org.delegated_admin_for.iter().any(|s| s == SERVICE_PRINCIPAL))
        .then_some(true)
    }

    /// Find the instance, check the caller manages it, then authorize
    /// `action` on `resource` (the instance ARN when `None`).
    pub(crate) fn instance(
        &self,
        ctx: &RequestContext,
        instance_arn: &str,
        action: &str,
        resource: Option<&str>,
    ) -> Result<InstanceRef, ServiceError> {
        let resource = resource.unwrap_or(instance_arn);
        self.instance_on(ctx, instance_arn, action, &[resource], ConditionContext::new())
    }

    /// Find the instance, check the caller manages it, then authorize
    /// `action` on each of `resources` (AWS evaluates an action on every
    /// resource type the Service Authorization Reference lists for it), each
    /// with its own `aws:ResourceTag/...` keys and `extra` (request tags).
    pub(crate) fn instance_on(
        &self,
        ctx: &RequestContext,
        instance_arn: &str,
        action: &str,
        resources: &[&str],
        extra: ConditionContext,
    ) -> Result<InstanceRef, ServiceError> {
        let found = {
            let st = self.lock();
            st.instances.get(instance_arn).map(|i| {
                let tags: Vec<Tags> =
                    resources.iter().map(|r| resource_tags(i, r).cloned().unwrap_or_default()).collect();
                (self.manages(&ctx.caller.account_id, i), i.clone(), tags)
            })
        };
        let (delegated, inst, tags) = match found {
            Some((Some(d), i, t)) => (d, i, t),
            Some((None, _, _)) => {
                return Err(errors::access_denied(format!(
                    "User: {} is not authorized to perform: {action} on resource: {instance_arn}",
                    ctx.caller.arn
                )))
            }
            None => return Err(instance_not_found(instance_arn)),
        };
        for (resource, tags) in resources.iter().zip(&tags) {
            let mut cond = extra.clone();
            for (k, v) in tags {
                cond.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
            }
            ctx.authorize(action, resource, cond)?;
        }
        Ok(InstanceRef {
            arn: inst.arn,
            owner: inst.owner,
            kind: inst.kind,
            identity_store_id: inst.identity_store_id,
            delegated,
        })
    }

    /// Run `f` on the instance under the state lock.
    pub(crate) fn with_instance<T>(
        &self,
        arn: &str,
        f: impl FnOnce(&mut Instance) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let mut st = self.lock();
        let inst = st.instances.get_mut(arn).ok_or_else(|| instance_not_found(arn))?;
        f(inst)
    }

    /// The instance that owns an ARN (an application, a trusted token
    /// issuer, a permission set).
    pub(crate) fn instance_arn_for(&self, st: &State, arn: &str) -> Option<String> {
        let id = instance_id_in(arn)?;
        st.instances.values().find(|i| i.id == id).map(|i| i.arn.clone())
    }
}

/// The tags of an instance, permission set, application or trusted token
/// issuer of `i`.
pub fn resource_tags<'a>(i: &'a Instance, arn: &str) -> Option<&'a Tags> {
    if i.arn == arn {
        return Some(&i.tags);
    }
    if let Some(p) = i.permission_sets.get(arn) {
        return Some(&p.tags);
    }
    if let Some(a) = i.applications.get(arn) {
        return Some(&a.tags);
    }
    i.token_issuers.get(arn).map(|t| &t.tags)
}

/// `aws:RequestTag/...` and `aws:TagKeys` for tags a request sets.
pub fn request_tag_context(tags: &Tags) -> ConditionContext {
    let mut ctx = ConditionContext::new();
    if tags.is_empty() {
        return ctx;
    }
    for (k, v) in tags {
        ctx.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
    }
    ctx.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    ctx
}

/// The ARN IAM policies use for an AWS account in Identity Center actions.
pub fn account_resource(partition: &str, account: &str) -> String {
    format!("arn:{partition}:sso:::account/{account}")
}
