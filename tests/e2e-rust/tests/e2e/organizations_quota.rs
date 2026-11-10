//! The Organizations account quota through the official SDK: 10 accounts
//! per organization by default, open invitations included.

use aws_sdk_organizations::error::ProvideErrorMetadata;
use aws_sdk_organizations::operation::invite_account_to_organization::InviteAccountToOrganizationError;
use aws_sdk_organizations::types::{HandshakeParty, HandshakePartyType};
use aws_sdk_organizations::Client as Orgs;
use mws_e2e::Mws;

/// Create an account and describe its creation: `(state, failure reason)`.
async fn create(orgs: &Orgs, name: &str) -> (String, Option<String>) {
    let out = orgs.create_account().email(format!("{name}@example.com")).account_name(name).send().await.unwrap();
    assert_eq!(out.create_account_status().unwrap().state().unwrap().as_str(), "IN_PROGRESS");
    let request_id = out.create_account_status().unwrap().id().unwrap();
    let status = orgs.describe_create_account_status().create_account_request_id(request_id).send().await.unwrap();
    let status = status.create_account_status().unwrap();
    (status.state().unwrap().as_str().to_string(), status.failure_reason().map(|r| r.as_str().to_string()))
}

fn account(id: &str) -> HandshakeParty {
    HandshakeParty::builder().r#type(HandshakePartyType::Account).id(id).build().unwrap()
}

#[tokio::test]
async fn organizations_hold_ten_accounts_counting_open_invitations() {
    let mws = Mws::start().await;
    let orgs = Orgs::new(&mws.root_sdk_config().await);
    orgs.create_organization().send().await.unwrap();
    // The management account and eight more.
    for i in 0..8 {
        assert_eq!(create(&orgs, &format!("member{i}")).await, ("SUCCEEDED".to_string(), None));
    }
    // An open invitation takes the tenth place.
    let invite = orgs.invite_account_to_organization().target(account("111122223333")).send().await.unwrap();
    let handshake = invite.handshake().unwrap().id().unwrap().to_string();
    assert_eq!(create(&orgs, "eleventh").await, ("FAILED".to_string(), Some("ACCOUNT_LIMIT_EXCEEDED".to_string())));
    let err = orgs.invite_account_to_organization().target(account("444455556666")).send().await.unwrap_err();
    assert_eq!(err.code(), Some("HandshakeConstraintViolationException"));
    assert_eq!(err.message(), Some("You have reached the limit on the number of accounts in your organization."));
    match err.into_service_error() {
        InviteAccountToOrganizationError::HandshakeConstraintViolationException(e) => {
            assert_eq!(e.reason().unwrap().as_str(), "ACCOUNT_NUMBER_LIMIT_EXCEEDED")
        }
        other => panic!("unexpected error {other:?}"),
    }

    // Cancelling the invitation frees its place.
    orgs.cancel_handshake().handshake_id(&handshake).send().await.unwrap();
    assert_eq!(create(&orgs, "tenth").await, ("SUCCEEDED".to_string(), None));
    assert_eq!(orgs.list_accounts().send().await.unwrap().accounts().len(), 10);
    assert_eq!(create(&orgs, "eleventh").await.1.as_deref(), Some("ACCOUNT_LIMIT_EXCEEDED"));
}
