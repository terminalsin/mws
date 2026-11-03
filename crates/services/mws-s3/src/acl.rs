//! Access control lists: canned ACLs, `x-amz-grant-*` headers, and which
//! grant permits which action.

use mws_core::{Caller, CallerKind, ServiceError};

use crate::auth::canonical_id;
use crate::errors;
use crate::generated::types;

pub const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
pub const AUTHENTICATED_USERS: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";
pub const LOG_DELIVERY: &str = "http://acs.amazonaws.com/groups/s3/LogDelivery";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Read,
    Write,
    ReadAcp,
    WriteAcp,
    FullControl,
}

impl Permission {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "READ" => Self::Read,
            "WRITE" => Self::Write,
            "READ_ACP" => Self::ReadAcp,
            "WRITE_ACP" => Self::WriteAcp,
            "FULL_CONTROL" => Self::FullControl,
            _ => return None,
        })
    }

    pub fn covers(self, needed: Permission) -> bool {
        self == Self::FullControl || self == needed
    }
}

/// The bucket ACL permission an action needs.
pub fn bucket_permission(action: &str) -> Option<Permission> {
    Some(match action {
        "s3:ListBucket" | "s3:ListBucketVersions" | "s3:ListBucketMultipartUploads" => Permission::Read,
        "s3:PutObject" | "s3:DeleteObject" | "s3:DeleteObjectVersion" | "s3:AbortMultipartUpload" => Permission::Write,
        "s3:GetBucketAcl" => Permission::ReadAcp,
        "s3:PutBucketAcl" => Permission::WriteAcp,
        _ => return None,
    })
}

/// The object ACL permission an action needs.
pub fn object_permission(action: &str) -> Option<Permission> {
    Some(match action {
        "s3:GetObject" | "s3:GetObjectVersion" | "s3:GetObjectAttributes" | "s3:GetObjectVersionAttributes" => {
            Permission::Read
        }
        "s3:GetObjectAcl" | "s3:GetObjectVersionAcl" => Permission::ReadAcp,
        "s3:PutObjectAcl" | "s3:PutObjectVersionAcl" => Permission::WriteAcp,
        _ => return None,
    })
}

pub fn grantee_matches(grantee: &types::Grantee, caller: &Caller, ignore_public: bool) -> bool {
    match grantee.r#type.as_str() {
        "Group" => match grantee.uri.as_deref() {
            Some(ALL_USERS) => !ignore_public,
            Some(AUTHENTICATED_USERS) => !ignore_public && caller.kind != CallerKind::Anonymous,
            _ => false,
        },
        // A grant to an account lets its root act; its IAM principals still
        // need identity policies, which the authorizer already consulted.
        "CanonicalUser" => {
            caller.kind == CallerKind::Root && grantee.id.as_deref() == Some(canonical_id(&caller.account_id).as_str())
        }
        _ => false,
    }
}

pub fn owner(account_id: &str) -> types::Owner {
    types::Owner { id: Some(canonical_id(account_id)), display_name: None }
}

fn canonical_grant(id: String, permission: &str) -> types::Grant {
    types::Grant {
        grantee: Some(types::Grantee { r#type: "CanonicalUser".into(), id: Some(id), ..Default::default() }),
        permission: Some(permission.into()),
    }
}

fn group_grant(uri: &str, permission: &str) -> types::Grant {
    types::Grant {
        grantee: Some(types::Grantee { r#type: "Group".into(), uri: Some(uri.into()), ..Default::default() }),
        permission: Some(permission.into()),
    }
}

/// Grants for a canned ACL. `bucket_owner` matters for the
/// `bucket-owner-*` ACLs on objects.
pub fn canned(acl: &str, owner: &str, bucket_owner: &str) -> Result<Vec<types::Grant>, ServiceError> {
    let mut grants = vec![canonical_grant(canonical_id(owner), "FULL_CONTROL")];
    match acl {
        "private" | "aws-exec-read" => {}
        "public-read" => grants.push(group_grant(ALL_USERS, "READ")),
        "public-read-write" => {
            grants.push(group_grant(ALL_USERS, "READ"));
            grants.push(group_grant(ALL_USERS, "WRITE"));
        }
        "authenticated-read" => grants.push(group_grant(AUTHENTICATED_USERS, "READ")),
        "log-delivery-write" => {
            grants.push(group_grant(LOG_DELIVERY, "WRITE"));
            grants.push(group_grant(LOG_DELIVERY, "READ_ACP"));
        }
        "bucket-owner-read" => {
            if owner != bucket_owner {
                grants.push(canonical_grant(canonical_id(bucket_owner), "READ"));
            }
        }
        "bucket-owner-full-control" => {
            if owner != bucket_owner {
                grants.push(canonical_grant(canonical_id(bucket_owner), "FULL_CONTROL"));
            }
        }
        other => return Err(errors::invalid_argument("", "x-amz-acl", other)),
    }
    Ok(grants)
}

/// Explicit grant headers (`x-amz-grant-read: id="...", uri="..."`).
pub struct GrantHeaders<'a> {
    pub full_control: Option<&'a str>,
    pub read: Option<&'a str>,
    pub read_acp: Option<&'a str>,
    pub write: Option<&'a str>,
    pub write_acp: Option<&'a str>,
}

impl GrantHeaders<'_> {
    pub fn any(&self) -> bool {
        self.full_control.is_some()
            || self.read.is_some()
            || self.read_acp.is_some()
            || self.write.is_some()
            || self.write_acp.is_some()
    }

    pub fn grants(&self) -> Result<Vec<types::Grant>, ServiceError> {
        let mut out = Vec::new();
        for (value, perm) in [
            (self.full_control, "FULL_CONTROL"),
            (self.read, "READ"),
            (self.read_acp, "READ_ACP"),
            (self.write, "WRITE"),
            (self.write_acp, "WRITE_ACP"),
        ] {
            let Some(value) = value else { continue };
            for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let (kind, v) =
                    item.split_once('=').ok_or_else(|| errors::invalid_argument("", "x-amz-grant", item))?;
                let v = v.trim().trim_matches('"').to_string();
                let grantee = match kind.trim().to_ascii_lowercase().as_str() {
                    "id" => types::Grantee { r#type: "CanonicalUser".into(), id: Some(v), ..Default::default() },
                    "uri" => types::Grantee { r#type: "Group".into(), uri: Some(v), ..Default::default() },
                    "emailaddress" => {
                        return Err(ServiceError::client(
                            "UnresolvableGrantByEmailAddress",
                            400,
                            "The e-mail address you provided does not match any account on record.",
                        ))
                    }
                    _ => return Err(errors::invalid_argument("", "x-amz-grant", item)),
                };
                out.push(types::Grant { grantee: Some(grantee), permission: Some(perm.into()) });
            }
        }
        Ok(out)
    }
}

/// Check grants a client supplied: known grantee types, group URIs and
/// canonical ids of accounts MWS knows.
pub fn validate_grants(grants: &[types::Grant], known_account: &str) -> Result<(), ServiceError> {
    for g in grants {
        let Some(grantee) = &g.grantee else { return Err(errors::malformed_xml()) };
        if g.permission.as_deref().and_then(Permission::parse).is_none() {
            return Err(errors::malformed_xml());
        }
        match grantee.r#type.as_str() {
            "CanonicalUser" => {
                let id = grantee.id.as_deref().unwrap_or_default();
                if id != canonical_id(known_account) {
                    return Err(errors::invalid_argument("Invalid id", "CanonicalUser/ID", id));
                }
            }
            "Group" => {
                let uri = grantee.uri.as_deref().unwrap_or_default();
                if ![ALL_USERS, AUTHENTICATED_USERS, LOG_DELIVERY].contains(&uri) {
                    return Err(errors::invalid_argument("Invalid group uri", "Group/URI", uri));
                }
            }
            "AmazonCustomerByEmail" => {
                return Err(ServiceError::client(
                    "UnresolvableGrantByEmailAddress",
                    400,
                    "The e-mail address you provided does not match any account on record.",
                ))
            }
            _ => return Err(errors::malformed_xml()),
        }
    }
    Ok(())
}

/// Whether grants give anything to everyone (Block Public Access).
pub fn is_public(grants: &[types::Grant]) -> bool {
    grants.iter().any(|g| {
        g.grantee.as_ref().is_some_and(|e| {
            e.r#type == "Group" && matches!(e.uri.as_deref(), Some(ALL_USERS) | Some(AUTHENTICATED_USERS))
        })
    })
}

/// Whether grants are just the owner's FULL_CONTROL (what ACL-disabled
/// buckets accept).
pub fn is_owner_only(grants: &[types::Grant], owner: &str) -> bool {
    let id = canonical_id(owner);
    grants.iter().all(|g| {
        g.permission.as_deref() == Some("FULL_CONTROL")
            && g.grantee.as_ref().is_some_and(|e| e.r#type == "CanonicalUser" && e.id.as_deref() == Some(id.as_str()))
    })
}
