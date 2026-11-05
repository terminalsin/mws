# AWS IAM Identity Center

> Crates: [`mws-ssoadmin`](../../crates/services/mws-ssoadmin), [`mws-identitystore`](../../crates/services/mws-identitystore), [`mws-ssooidc`](../../crates/services/mws-ssooidc), [`mws-ssoportal`](../../crates/services/mws-ssoportal) · Tests: [`identity_center.rs`](../../tests/e2e-rust/tests/e2e/identity_center.rs), [`identity_center_apps.rs`](../../tests/e2e-rust/tests/e2e/identity_center_apps.rs), [`identitystore.rs`](../../tests/e2e-rust/tests/e2e/identitystore.rs)

IAM Identity Center is four APIs, all generated from the AWS models and fully implemented:

| API | SDK client | Operations | Protocol |
| --- | --- | --- | --- |
| SSO Admin | `ssoadmin` | 79 / 79 | awsJson 1.1 |
| Identity Store | `identitystore` | 22 / 22 | awsJson 1.1 |
| SSO OIDC | `ssooidc` | 4 / 4 | restJson1 |
| AWS access portal | `sso` | 4 / 4 | restJson1 |

Permission sets become real IAM roles in the accounts they are assigned in,
and the access portal hands out real STS credentials for those roles, so
`aws sso login` and SDK SSO profiles work end to end against MWS.

✅ supported · 🟡 partial · ❌ not supported

## Instances

| Feature | Status | Details |
| --- | :---: | --- |
| Organization instance | 🟡 | `CreateInstance` in an Organizations management account creates the organization instance (AWS enables it from the console, and refuses `CreateInstance` there). It enables trusted access for `sso.amazonaws.com` and the `AWSServiceRoleForSSO` service-linked role. |
| Account instances | ✅ | `CreateInstance` anywhere else; one instance per account; permission sets off until `UpdateInstance` enables them; assignments only to the owning account. |
| Delegated administrators | ✅ | A delegated administrator for `sso.amazonaws.com` in the same organization manages the organization instance (but can't delete it). |
| Regions | 🟡 | `AddRegion`, `RemoveRegion`, `DescribeRegion`, `ListRegions`; replication completes at once. |
| Encryption configuration | 🟡 | Stored and returned; customer managed KMS keys aren't checked. |
| Attributes for access control | ✅ | `${path:...}` sources (including `enterprise.*`) resolved from the user and sent as session tags on portal credentials. |
| Tags | ✅ | On instances, permission sets, applications and trusted token issuers. |

## Identity Store

| Feature | Status | Details |
| --- | :---: | --- |
| Users and groups | ✅ | Every SCIM attribute in the model, case-insensitive unique user names, emails and group display names, `UpdateUser`/`UpdateGroup` attribute operations (nested `name.*`, multi-valued attributes, `aws:identitystore:enterprise` extensions). |
| Memberships | ✅ | `IsMemberInGroups`, memberships by group and by member. |
| Lookups | ✅ | `GetUserId`/`GetGroupId` by unique attribute or external id; `ListUsers`/`ListGroups` filters. |
| Concurrency | ✅ | Revisions with `ConflictException` (`CONCURRENT_MODIFICATION`). |
| Access | ✅ | IAM authorization on the store and entity ARNs; other accounts of the organization may read. |
| Identity store settings | 🟡 | `UpdateIdentityStore` network configuration is stored, not enforced. |
| External identity providers and SCIM | ❌ | The identity source is always the Identity Center directory. |

## Permission sets and account assignments

| Feature | Status | Details |
| --- | :---: | --- |
| Permission sets | ✅ | Session duration (PT1H to PT12H), relay state, AWS and customer managed policies (up to 20), inline policy (validated as IAM does), permissions boundary. |
| Account assignments | ✅ | Users and groups, in member accounts or the management account. Creation and deletion answer `IN_PROGRESS`; the status operations report `SUCCEEDED` or `FAILED` with AWS's reason. |
| Provisioned roles | ✅ | `AWSReservedSSO_<permission set>_<id>` under `/aws-reserved/sso.amazonaws.com/` with the permission set's policies (`AwsSSOInlinePolicy`), boundary and session duration, trusting the account's `AWSSSO_<id>_DO_NOT_DELETE` SAML provider. Removing the last assignment deletes the role. |
| Protected roles | ✅ | Account users can't change or delete reserved roles (`UnmodifiableEntity`). |
| Customer managed policies | ✅ | Must exist in each account, or provisioning fails with AWS's 404 reason. |
| Re-provisioning | ✅ | Permission set changes reach roles on `ProvisionPermissionSet`; `LATEST_PERMISSION_SET_PROVISIONED` and `..._NOT_PROVISIONED` filters. |
| AWS managed policies | 🟡 | Any AWS managed policy ARN attaches; only those MWS's IAM knows grant permissions. |

## Sign-in and the access portal

| Feature | Status | Details |
| --- | :---: | --- |
| Client registration | ✅ | Public clients; grant types, redirect URIs, scopes and issuer URL; 90-day client secrets. |
| Device authorization | ✅ | `StartDeviceAuthorization` with the start URL (`https://d-xxxxxxxxxx.awsapps.com/start` or `https://ssoins-....portal.<region>.app.aws`); `authorization_pending` until the user answers. |
| Authorization code with PKCE | ✅ | `/authorize` redirects back with a code and `state`; `S256` and `plain` challenges. |
| Refresh tokens | ✅ | Single use; access tokens last an hour with a refresh token and eight hours without. |
| Browser sign-in | 🟡 | The verification page at `/_aws/sso-oidc/device` and `/authorize` ask only for a user name or email (MWS keeps no passwords). Tests can `POST` `user_code` and `username` (or `decision=deny`) to the device page, or pass `username` to `/authorize`. |
| `GetRoleCredentials` | ✅ | Real STS credentials for the provisioned role through its SAML trust policy, the session named after the user, for the permission set's session duration, tagged with the access control attributes. Unassigned roles answer `ForbiddenException`. |
| `ListAccounts`, `ListAccountRoles`, `Logout` | ✅ | From the user's direct and group assignments, with account names from Organizations. |
| `slow_down` | ❌ | Polling faster than the interval isn't penalized. |

## Applications and trusted identity propagation

| Feature | Status | Details |
| --- | :---: | --- |
| Customer managed OAuth applications | ✅ | Applications, assignment configuration and assignments, access scopes, IAM authentication method, grants, session configuration. |
| SAML 2.0 applications | 🟡 | The custom SAML provider exists; MWS doesn't serve SAML assertions to applications. |
| Trusted token issuers | ✅ | OIDC JWT issuers mapping a claim to an Identity Store attribute. |
| `CreateTokenWithIAM` | ✅ | Authorization code, refresh token, JWT bearer (trusted token issuer, audiences, signature checked through OIDC discovery unless `MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION`) and token exchange; the actor policy must allow the caller, and assignments are enforced. Returns an ID token with `sts:identity_context`. |
| Identity-enhanced sessions | ❌ | The identity context can't be passed to STS `ProvidedContexts` yet. |

See also: [all services](README.md) · [IAM](iam.md) · [STS](sts.md) · [Organizations](organizations.md).
