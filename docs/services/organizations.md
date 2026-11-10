# AWS Organizations

> Crate: [`mws-organizations`](../../crates/services/mws-organizations) · Tests: [`tests/e2e-rust/tests/e2e/organizations.rs`](../../tests/e2e-rust/tests/e2e/organizations.rs), [`organizations_quota.rs`](../../tests/e2e-rust/tests/e2e/organizations_quota.rs)

All 63 operations are generated from the AWS model (awsJson1.1) and implemented. Member accounts are real accounts, and the IAM authorizer enforces the organization's policies.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Organizations and roots | ✅ | All features or consolidated billing only. |
| Organizational units | ✅ | Nested OUs with the depth limit; moving accounts between them. |
| `CreateAccount` | ✅ | Real member accounts with their own IAM namespace and an `OrganizationAccountAccessRole` you can assume. |
| Account quota | 🟡 | 10 accounts per organization (AWS's default), counting members and open invitations. Over it, `CreateAccount` ends `FAILED` with `ACCOUNT_LIMIT_EXCEEDED` and `InviteAccountToOrganization` answers `HandshakeConstraintViolationException` (`ACCOUNT_NUMBER_LIMIT_EXCEEDED`). The Service Quotas value `L-29A0C5DF` of the management account is read when Service Quotas' catalog has it (it doesn't yet, so the limit can't be raised). There is no account creation rate limit. |
| Account lifecycle | ✅ | Removing, leaving and closing accounts. |
| Handshakes | ✅ | Invitations, enabling all features and billing responsibility transfers. |
| Policies | ✅ | Every policy type, with per-type validation and attachment limits; `EnablePolicyType`/`DisablePolicyType` attach `FullAWSAccess` and `RCPFullAWSAccess` everywhere. |
| SCPs and RCPs | ✅ | Enforced on every request from member accounts; every level of the OU tree must allow. `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths` and `aws:ResourceOrg*` are set. |
| Effective management policies | ✅ | Tag, backup and other management policies merged with the inheritance operators. |
| Trusted access and delegated administrators | ✅ | Per service principal. |
| Organization resource policy and tags | ✅ | Stored, returned and evaluated. |
| `CreateGovCloudAccount` | ❌ | Fails as it does for accounts without GovCloud access. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
