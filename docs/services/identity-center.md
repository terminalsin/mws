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
| Regions | ✅ | `AddRegion`, `RemoveRegion`, `DescribeRegion`, `ListRegions`. Replication completes at once (MWS has one copy of the data). |
| Encryption configuration | ✅ | AWS owned or customer managed keys. A customer managed key must be an enabled symmetric encryption key whose key policy lets `sso.amazonaws.com` and `identitystore.amazonaws.com` use it for this instance (AWS's baseline key policy), or `UpdateInstance` fails. |
| Attributes for access control | ✅ | `${path:...}` sources (including `enterprise.*`) resolved from the user and sent as session tags on portal credentials. |
| Tags | ✅ | On instances, permission sets, applications and trusted token issuers. |
| Authorization | ✅ | Each action is authorized on every resource the Service Authorization Reference lists for it: permission set operations on the instance and the permission set, `CreateAccountAssignment`/`DeleteAccountAssignment`/`ListAccountAssignments`/`ProvisionPermissionSet` also on `arn:aws:sso:::account/<id>`, `ListPermissionSetsProvisionedToAccount` on the instance and the account. `aws:ResourceTag/*` comes from each resource's tags; creates and `TagResource` pass `aws:RequestTag/*` and `aws:TagKeys`, `UntagResource` `aws:TagKeys`. |

## Identity Store

| Feature | Status | Details |
| --- | :---: | --- |
| Users and groups | ✅ | Every SCIM attribute in the model, case-insensitive unique user names, emails and group display names, `UpdateUser`/`UpdateGroup` attribute operations (nested `name.*`, multi-valued attributes, `aws:identitystore:enterprise` extensions). |
| Memberships | ✅ | `IsMemberInGroups`, memberships by group and by member. |
| Lookups | ✅ | `GetUserId`/`GetGroupId` by unique attribute or external id; `ListUsers`/`ListGroups` filters. |
| Concurrency | ✅ | Revisions with `ConflictException` (`CONCURRENT_MODIFICATION`). |
| Access | ✅ | IAM authorization on the store and entity ARNs; other accounts of the organization may read, and the delegated administrator for `sso.amazonaws.com` may also write the organization instance's store (the one the management account owns). |
| Network controls | ✅ | `UpdateIdentityStore` network configuration is enforced on every Identity Store call: requests never arrive through a VPC endpoint or from a VPC in MWS, so a store requiring either admits only source IPs in `ApiAllowSourceIps`. |
| External identity providers and SCIM | ❌ | The identity source is always the Identity Center directory: there is no SCIM endpoint or external SAML identity provider (AWS configures both in the console). |

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
| `slow_down` | ✅ | Polling a pending device code faster than the interval answers `SlowDownException` and adds five seconds to the interval (RFC 8628). |

## Applications and trusted identity propagation

| Feature | Status | Details |
| --- | :---: | --- |
| Customer managed OAuth applications | ✅ | Applications, assignment configuration and assignments, access scopes, IAM authentication method, grants, session configuration. |
| SAML 2.0 applications | ❌ | As in AWS, the API creates only OAuth applications (`CreateApplication` with the custom SAML provider is refused); SAML applications are configured in the console, which MWS doesn't have. |
| Trusted token issuers | ✅ | OIDC JWT issuers mapping a claim to an Identity Store attribute. |
| `CreateTokenWithIAM` | ✅ | Authorization code, refresh token, JWT bearer (trusted token issuer, audiences, signature checked through OIDC discovery unless `MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION`) and token exchange; the actor policy must allow the caller, and assignments are enforced. Returns an ID token with `sts:identity_context`. |
| Identity-enhanced sessions | ✅ | The `identityContext` is an STS trusted context assertion: `AssumeRole` with `ProvidedContexts` (provider `arn:aws:iam::aws:contextProvider/IdentityCenter`, trust policy allowing `sts:SetContext`) gives the session the `identitystore:UserId` and `identitystore:IdentityStoreArn` condition keys. |

See also: [all services](README.md) · [IAM](iam.md) · [STS](sts.md) · [Organizations](organizations.md).
