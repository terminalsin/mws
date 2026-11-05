# AWS Identity and Access Management

> Crate: [`mws-iam`](../../crates/services/mws-iam) · Tests: [`tests/e2e-rust/tests/e2e/iam.rs`](../../tests/e2e-rust/tests/e2e/iam.rs)

All 180 operations are generated from the AWS model (awsQuery) and implemented, validating input like AWS. IAM also hosts the authorizer that every other service calls (see [authentication and authorization](../security.md)).

✅ supported · 🟡 partial · ❌ not supported

## Identities

| Feature | Status | Details |
| --- | :---: | --- |
| Users, groups and roles | ✅ | Create, update, delete, list and tag, with paths, unique ids, AWS's name rules and limits; deleted principals leave unique ids in policies, as on AWS. |
| Access keys | ✅ | Real keys that authenticate SigV4 requests at once; ids encode the account; last-used data comes from requests MWS actually authorized. |
| Login profiles and passwords | ✅ | Console passwords, the account password policy and `ChangePassword`. |
| Virtual MFA devices | ✅ | Real TOTP seeds and QR code PNGs; codes are checked by `EnableMFADevice`/`ResyncMFADevice` and by STS. |
| SSH keys, signing and server certificates | ✅ | Key pair and certificate checks as in IAM. |
| Service-specific credentials | ✅ | Created, reset, listed and deleted. |
| Instance profiles | ✅ | Roles attached to instance profiles, used by EC2 instances. |
| Service-linked roles | ✅ | Created with their AWS trust policies; deletion tasks. |

## Policies

| Feature | Status | Details |
| --- | :---: | --- |
| Managed and inline policies | ✅ | Versions (up to five, default version), attach/detach to users, groups and roles, policy grammar and size validation. |
| Permissions boundaries | ✅ | Set and removed on users and roles; enforced by the authorizer. |
| AWS managed policies | 🟡 | A trimmed subset covering the services MWS emulates. |
| Policy simulator | ✅ | `SimulatePrincipalPolicy` and `SimulateCustomPolicy` with context keys, resource policies and boundaries. |

## Federation and account

| Feature | Status | Details |
| --- | :---: | --- |
| OIDC and SAML providers | ✅ | Thumbprints, client ids, metadata documents and tags; used by STS federation. |
| Outbound web identity federation | ✅ | Enable/disable and the issuer, for `sts:GetWebIdentityToken`. |
| Delegation requests | ✅ | The full lifecycle: created, associated, accepted or rejected, finalized, and expired after seven days. |
| Account aliases, summary and properties | ✅ | `GetAccountSummary` counts real entities. |
| Authorization details | ✅ | `GetAccountAuthorizationDetails` with every filter. |

## Reports

| Feature | Status | Details |
| --- | :---: | --- |
| Credential report | ✅ | Generated from real users, keys, passwords and MFA devices. |
| Access advisor | ✅ | Service last accessed details and `ListPoliciesGrantingServiceAccess`, from requests MWS actually authorized. |
| Organizations access reports | ✅ | Follow the caller's organization in Organizations. |
| Centralized root access | ✅ | Follows the caller's organization (`EnableOrganizationsRootCredentialsManagement` and sessions). |
| AWS role templates | ❌ | None exist in MWS. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
