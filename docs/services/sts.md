# AWS Security Token Service

> Crate: [`mws-sts`](../../crates/services/mws-sts) · Tests: [`tests/e2e-rust/tests/e2e/sts.rs`](../../tests/e2e-rust/tests/e2e/sts.rs)

All operations: `GetCallerIdentity`, `AssumeRole` (trust policies, session
policies, tags, transitive tags, external id, source identity, role chaining
limits), MFA codes checked against IAM virtual devices, `GetSessionToken`,
`GetFederationToken`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML`
(assertions are checked like AWS, and the response or assertion must carry a
valid XML signature from a certificate in the provider's metadata),
`GetWebIdentityToken` (RS256/ES384 JWTs), `GetDelegatedAccessToken`,
`DecodeAuthorizationMessage`, `GetAccessKeyInfo`, and `AssumeRoot` (root task
sessions in member accounts once the organization enables root sessions).

## Behaviour

Cross-account `AssumeRole` into member accounts.

See also: [all services](README.md) · [authentication and authorization](../security.md).
