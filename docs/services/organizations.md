# AWS Organizations

> Crate: [`mws-organizations`](../../crates/services/mws-organizations) · Tests: [`tests/e2e-rust/tests/e2e/organizations.rs`](../../tests/e2e-rust/tests/e2e/organizations.rs)

All 63 operations are generated from the AWS model (awsJson1.1) and implemented. Member accounts are real accounts, and the IAM authorizer enforces the organization's policies.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Organizations and roots | ✅ | All features or consolidated billing only. |
| Organizational units | ✅ | Nested OUs with the depth limit; moving accounts between them. |
| `CreateAccount` | ✅ | Real member accounts with their own IAM namespace and an `OrganizationAccountAccessRole` you can assume. |
| Account lifecycle | ✅ | Removing, leaving and closing accounts. |
| Handshakes | ✅ | Invitations, enabling all features and billing responsibility transfers. |
| Policies | ✅ | Every policy type, with per-type validation and attachment limits; `EnablePolicyType`/`DisablePolicyType` attach `FullAWSAccess` and `RCPFullAWSAccess` everywhere. |
| SCPs and RCPs | ✅ | Enforced on every request from member accounts; every level of the OU tree must allow. `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths` and `aws:ResourceOrg*` are set. |
| Effective management policies | ✅ | Tag, backup and other management policies merged with the inheritance operators. |
| Trusted access and delegated administrators | ✅ | Per service principal. |
| Organization resource policy and tags | ✅ | Stored, returned and evaluated. |
| `CreateGovCloudAccount` | ❌ | Fails as it does for accounts without GovCloud access. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
