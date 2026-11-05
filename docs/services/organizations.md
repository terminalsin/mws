# AWS Organizations

> Crate: [`mws-organizations`](../../crates/services/mws-organizations) · Tests: [`tests/e2e-rust/tests/e2e/organizations.rs`](../../tests/e2e-rust/tests/e2e/organizations.rs)

All 63 operations are generated from the AWS model (awsJson1.1).

## Behaviour

Implemented: organizations (all features or consolidated billing), roots, nested
OUs (depth limit), `CreateAccount` creating real member accounts with their own
IAM namespace and `OrganizationAccountAccessRole`, moving, removing, leaving and
closing accounts, invitations and the other handshakes (enable all features,
billing responsibility transfers), every policy type with per-type validation
and attachment limits, `EnablePolicyType`/`DisablePolicyType` (FullAWSAccess and
RCPFullAWSAccess attached everywhere), effective management policies merged with
the inheritance operators, trusted service access, delegated administrators, the
organization resource policy, and tags.

SCPs and RCPs are enforced by the IAM engine for member accounts.
`CreateGovCloudAccount` fails as it does for accounts without GovCloud.

See also: [all services](README.md) · [authentication and authorization](../security.md).
