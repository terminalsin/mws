# AWS Security Token Service

> Crate: [`mws-sts`](../../crates/services/mws-sts) · Tests: [`tests/e2e-rust/tests/e2e/sts.rs`](../../tests/e2e-rust/tests/e2e/sts.rs)

All 11 operations are generated from the AWS model (awsQuery) and implemented. Temporary credentials are real: MWS recognizes them on every service until they expire.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| `GetCallerIdentity` | ✅ | The caller's account, ARN and user id, for users, roles, sessions and the root user. |
| `AssumeRole` | ✅ | Trust policies, session policies, session tags and transitive tags, external id, source identity, role chaining limits, and cross-account roles in member accounts. |
| MFA | ✅ | `SerialNumber`/`TokenCode` checked against IAM virtual MFA devices. |
| `GetSessionToken` and `GetFederationToken` | ✅ | Session credentials and federated users with session policies. |
| `AssumeRoleWithWebIdentity` | ✅ | Token signatures verified through OpenID Connect discovery and the provider's TLS certificate or thumbprint, audience and subject conditions. |
| `AssumeRoleWithSAML` | ✅ | Assertions checked as AWS checks them; the response or assertion must carry a valid XML signature from a certificate in the provider's metadata. |
| `GetWebIdentityToken` | ✅ | RS256 and ES384 JWTs signed with MWS's keys, which MWS's own web identity federation accepts. |
| `GetDelegatedAccessToken` | ✅ | Trades the token of an accepted IAM delegation request for credentials. |
| `DecodeAuthorizationMessage` | ✅ | Decodes the encoded messages of `UnauthorizedOperation` errors (EC2). |
| `GetAccessKeyInfo` | ✅ | The account of any access key id. |
| `AssumeRoot` | ✅ | Root task sessions in member accounts once the organization enables root sessions. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
