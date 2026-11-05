# AWS Resource Access Manager

> Crate: [`mws-ram`](../../crates/services/mws-ram) · Tests: [`tests/e2e-rust/tests/e2e/ram.rs`](../../tests/e2e-rust/tests/e2e/ram.rs)

All 35 operations are generated from the AWS model (restJson1) and implemented. Shares really grant access: when a share holds a resource, RAM writes a resource policy onto it, built from each attached permission's template and bound to each principal, and the owning service enforces it like any other resource policy.

✅ supported · 🟡 partial · ❌ not supported

## Sharing

| Feature | Status | Details |
| --- | :---: | --- |
| Private CA certificate authorities | ✅ | Another account can issue certificates from a shared CA under its own IAM policies; removing the principal, the resource, the permission or the share takes the access away. |
| Other resource types | ❌ | Only `acm-pca:CertificateAuthority` is shareable; `ListResourceTypes` lists what is. |
| Principals | ✅ | Accounts, the organization, OUs (`aws:PrincipalOrgPaths`), IAM roles and users, and service principals (with `aws:SourceAccount` or `aws:SourceArn` from `Sources`). |
| Invitations | ✅ | Accounts outside the organization, or any account while organization sharing is off, get an invitation; the association stays `ASSOCIATING` until accepted, and invitations expire after 7 days on the emulated clock. |
| Organization sharing | ✅ | `EnableSharingWithAwsOrganization` enables trusted access for `ram.amazonaws.com` and creates the service-linked role; organization principals then need no invitation. |
| `AllowExternalPrincipals` | ✅ | Accounts outside the organization are refused when it is false. |
| Global resources | ❌ | Shares only cover resources in their own Region. |

## Permissions

| Feature | Status | Details |
| --- | :---: | --- |
| AWS managed permissions | ✅ | The seven Private CA permissions (default, end-entity client and server auth, subordinate path length 0, revoke and the passthrough templates) with their `acm-pca:TemplateArn` conditions. |
| Customer managed permissions | ✅ | Templates validated against the resource type's actions, versions, default versions, and replacing permissions on shares (`ReplacePermissionAssociations` work items). |
| Shares created from policy | 🟡 | A Private CA `PutPolicy` appears as a `CREATED_FROM_POLICY` share and can be promoted to `STANDARD`; after promotion the CA keeps both policies and MWS evaluates both. |

## API behaviour

| Feature | Status | Details |
| --- | :---: | --- |
| IAM condition keys | ✅ | `aws:RequestTag`, `aws:ResourceTag`, `aws:TagKeys`, `ram:RequestedResourceType`, `ram:Principal`, `ram:ShareOwnerAccountId` and the other RAM keys. |
| Pagination and client tokens | ✅ | `InvalidNextTokenException` and `IdempotentParameterMismatchException` as on AWS. |

See also: [all services](README.md) · [Private CA](acm-pca.md) · [Organizations](organizations.md).
