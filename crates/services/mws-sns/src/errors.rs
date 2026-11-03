//! SNS's error wording.

use mws_core::ServiceError;

pub use crate::generated::errors::*;

/// `InvalidParameter` with SNS's `Invalid parameter: ...` prefix.
pub fn invalid(what: impl std::fmt::Display) -> ServiceError {
    invalid_parameter(format!("Invalid parameter: {what}"))
}

pub fn topic_not_found() -> ServiceError {
    not_found("Topic does not exist")
}

pub fn subscription_not_found() -> ServiceError {
    not_found("Subscription does not exist")
}

pub fn application_not_found() -> ServiceError {
    not_found("PlatformApplication does not exist")
}

pub fn endpoint_not_found() -> ServiceError {
    not_found("Endpoint does not exist")
}

pub fn resource_missing() -> ServiceError {
    resource_not_found("Resource does not exist")
}

/// SNS reports authorization failures as `AuthorizationError`, and the
/// gateway's generic errors keep their codes.
pub fn sns_error(e: ServiceError) -> ServiceError {
    if e.code == "AccessDenied" {
        let mut out = authorization_error(e.message);
        out.fields = e.fields;
        out
    } else {
        e
    }
}
