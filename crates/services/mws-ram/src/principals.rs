//! Who a share can name as principal, and who that covers.

use mws_core::ServiceError;
use mws_iam::AccountOrganization;

use crate::generated::errors;
use crate::Ram;

/// RAM's service principal (for trusted access to Organizations).
pub const RAM_SERVICE_PRINCIPAL: &str = "ram.amazonaws.com";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
    Account(String),
    Organization {
        org_id: String,
    },
    OrganizationalUnit {
        org_id: String,
        ou_id: String,
    },
    /// An IAM role or user, in `account`.
    Iam {
        arn: String,
        account: String,
    },
    Service(String),
}

impl PrincipalKind {
    pub fn parse(p: &str) -> Result<Self, ServiceError> {
        if p.len() == 12 && p.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(Self::Account(p.to_string()));
        }
        if let Some(rest) = p.strip_prefix("arn:") {
            let parts: Vec<&str> = rest.splitn(5, ':').collect();
            if parts.len() == 5 {
                let (service, account, resource) = (parts[1], parts[3], parts[4]);
                match service {
                    "organizations" => {
                        if let Some(org) = resource.strip_prefix("organization/") {
                            if org.starts_with("o-") {
                                return Ok(Self::Organization { org_id: org.to_string() });
                            }
                        }
                        if let Some(path) = resource.strip_prefix("ou/") {
                            if let Some((org, ou)) = path.split_once('/') {
                                if org.starts_with("o-") && ou.starts_with("ou-") {
                                    return Ok(Self::OrganizationalUnit { org_id: org.into(), ou_id: ou.into() });
                                }
                            }
                        }
                    }
                    "iam" if resource.starts_with("role/") || resource.starts_with("user/") => {
                        return Ok(Self::Iam { arn: p.to_string(), account: account.to_string() });
                    }
                    _ => {}
                }
            }
            return Err(errors::malformed_arn(format!("The format of ARN {p} is not valid.")));
        }
        let service_like = p.ends_with(".amazonaws.com")
            && p.len() > ".amazonaws.com".len()
            && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
        if service_like {
            return Ok(Self::Service(p.to_string()));
        }
        Err(errors::invalid_parameter(format!("Principal ID {p} is malformed. Verify the ID and try again.")))
    }

    /// The account a principal belongs to, for accounts and IAM principals.
    pub fn account(&self) -> Option<&str> {
        match self {
            Self::Account(a) | Self::Iam { account: a, .. } => Some(a),
            _ => None,
        }
    }
}

impl Ram {
    pub(crate) fn org_of(&self, account: &str) -> Option<AccountOrganization> {
        self.iam.organization_of(account)
    }

    /// Whether the owner's organization lets RAM share with it.
    pub(crate) fn org_sharing_enabled(&self, owner: &str) -> Option<AccountOrganization> {
        self.org_of(owner).filter(|o| o.all_features && o.trusted_services.iter().any(|s| s == RAM_SERVICE_PRINCIPAL))
    }

    /// Whether `account` is inside the owner's organization with sharing
    /// enabled, so it needs no invitation.
    pub(crate) fn internal(&self, owner: &str, account: &str) -> bool {
        match (self.org_sharing_enabled(owner), self.org_of(account)) {
            (Some(o), Some(a)) => o.organization_id == a.organization_id,
            _ => false,
        }
    }

    /// Whether a principal association covers `account`.
    pub(crate) fn covers(&self, principal: &str, owner: &str, account: &str) -> bool {
        match PrincipalKind::parse(principal) {
            Ok(PrincipalKind::Account(a)) | Ok(PrincipalKind::Iam { account: a, .. }) => a == account,
            Ok(PrincipalKind::Organization { org_id }) => {
                account != owner && self.org_of(account).is_some_and(|o| o.organization_id == org_id)
            }
            Ok(PrincipalKind::OrganizationalUnit { org_id, ou_id }) => {
                account != owner
                    && self
                        .org_of(account)
                        .is_some_and(|o| o.organization_id == org_id && o.org_path.split('/').any(|s| s == ou_id))
            }
            _ => false,
        }
    }
}
