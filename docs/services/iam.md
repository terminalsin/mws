# AWS Identity and Access Management

> Crate: [`mws-iam`](../../crates/services/mws-iam) · Tests: [`tests/e2e-rust/tests/e2e/iam.rs`](../../tests/e2e-rust/tests/e2e/iam.rs)

All 180 operations are implemented, generated from the AWS model and validating
input like AWS: users, groups, roles, access keys, login profiles, managed and
inline policies, permissions boundaries, tags, instance profiles, OIDC and SAML
providers, virtual MFA devices (real TOTP codes, QR PNGs), SSH public keys,
signing and server certificates (key pair checks), service-specific credentials,
the password policy and `ChangePassword`, the credential report, access advisor
(service last accessed, `ListPoliciesGrantingServiceAccess`), service-linked
roles, delegation requests, outbound web identity federation, account properties
and summary, authorization details, and the policy simulator.

## Behaviour

Centralized root access and Organizations access reports follow the caller's
organization, and no AWS role templates exist. Access-key last use, access
advisor and Organizations access reports come from the requests MWS actually
authorized.

See also: [all services](README.md) · [authentication and authorization](../security.md).
