# AWS Identity and Access Management

> Crate: [`mws-iam`](../../crates/services/mws-iam) · Tests: [`tests/e2e-rust/tests/e2e/iam.rs`](../../tests/e2e-rust/tests/e2e/iam.rs)

All 180 operations are generated from the AWS model (awsQuery) and implemented, validating input like AWS. IAM also hosts the authorizer that every other service calls (see [authentication and authorization](../security.md)).

✅ supported · 🟡 partial · ❌ not supported

## Identities

| Feature | Status | Details |
| --- | :---: | --- |
| Users, groups and roles | ✅ | Create, update, delete, list and tag, with paths, unique ids, AWS's name rules and limits; deleted principals leave unique ids in policies, as on AWS. Paths under `/aws-service-role/` and `/aws-reserved/` are refused (`InvalidInput`, "The specified value for path is reserved for AWS use"), since only AWS makes roles there. Creating with `Tags` also needs `iam:Tag<Entity>` (`TagRole`, `TagUser`, `TagPolicy`, ...) on the new resource. Account quotas (users 5000, groups 300, roles 1000, customer managed policies 1500, policy versions 10000, instance profiles 1000, OIDC providers 100) and 10 groups per user are enforced with `LimitExceeded`; roles and managed policies per role follow Service Quotas. |
| Access keys | ✅ | Real keys that authenticate SigV4 requests at once; ids encode the account; last-used data comes from requests MWS actually authorized. |
| Login profiles and passwords | ✅ | Console passwords, the account password policy and `ChangePassword`. |
| Virtual MFA devices | ✅ | Real TOTP seeds and QR code PNGs; codes are checked by `EnableMFADevice`/`ResyncMFADevice` and by STS. |
| SSH keys, signing and server certificates | ✅ | Key pair and certificate checks as in IAM. |
| Service-specific credentials | ✅ | Created, reset, listed and deleted. |
| Instance profiles | ✅ | Roles attached to instance profiles, used by EC2 instances. |
| Service-linked roles | ✅ | AWS's role names per service principal (`AWSServiceRoleForSSO`, `AWSServiceRoleForResourceAccessManager`, `AWSServiceRoleForEC2Spot`, the Application Auto Scaling per-target roles, ...) and their trust policies; unknown services and unsupported `CustomSuffix` values are refused with `InvalidInput`. Deletion tasks stay `IN_PROGRESS` for five seconds of emulated time, then `SUCCEEDED`, or `FAILED` with a `RoleUsageList` while the role is in an instance profile or a service reports that its resources use it. Services that do not report usage yet never block deletion. |

## Policies

| Feature | Status | Details |
| --- | :---: | --- |
| Managed and inline policies | ✅ | Versions (up to five, default version), attach/detach to users, groups and roles, policy grammar and size validation. |
| Permissions boundaries | ✅ | Set and removed on users and roles; enforced by the authorizer. |
| AWS managed policies | ✅ | All of them (about 1,600, including `/service-role/`, `/aws-service-role/`, `/job-function/` and `/root-task/` ones), in every account, with their real names, paths, policy ids, dates, default version and document, so `ReadOnlyAccess` covers every service. They are global as in AWS: accounts store only their attachments, `ListPolicies` pages through them (with `Scope`, `PathPrefix`, `OnlyAttached`) and `GetAccountAuthorizationDetails` includes only the attached ones. Deprecated, non-attachable ones (`AWSConfigRole`) refuse to attach. Service-linked roles get their service's policy (`AWSSSOServiceRolePolicy`, `AWSResourceAccessManagerServiceRolePolicy`, ...). Gaps: only the default version exists (no older versions in `ListPolicyVersions`), and only some have a `Description` (no public dump has them). Regenerate the data with [`scripts/update-managed-policies.py`](../../crates/services/mws-iam/scripts/update-managed-policies.py). |
| Policy simulator | ✅ | `SimulatePrincipalPolicy` and `SimulateCustomPolicy` with context keys, resource policies and boundaries. |

## Federation and account

| Feature | Status | Details |
| --- | :---: | --- |
| OIDC and SAML providers | ✅ | Thumbprints, client ids, metadata documents and tags; used by STS federation. |
| Outbound web identity federation | ✅ | Enable/disable and the issuer, for `sts:GetWebIdentityToken`. |
| Delegation requests | ✅ | The full lifecycle: created, associated, accepted or rejected, finalized, and expired after seven days of emulated time (`/_mws/clock`). |
| Account aliases, summary and properties | ✅ | `GetAccountSummary` counts real entities. |
| Authorization details | ✅ | `GetAccountAuthorizationDetails` with every filter. |

## Reports

| Feature | Status | Details |
| --- | :---: | --- |
| Credential report | ✅ | Generated from real users, keys, passwords and MFA devices; expires four hours later on the emulated clock, which also stamps creation dates and key and password ages. |
| Access advisor | ✅ | Service last accessed details and `ListPoliciesGrantingServiceAccess`, from requests MWS actually authorized. |
| Organizations access reports | ✅ | Follow the caller's organization in Organizations. |
| Centralized root access | ✅ | Follows the caller's organization (`EnableOrganizationsRootCredentialsManagement` and sessions). |
| AWS role templates | ❌ | None exist in MWS. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
