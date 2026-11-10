# AWS Security Token Service

> Crate: [`mws-sts`](../../crates/services/mws-sts) · Tests: [`tests/e2e-rust/tests/e2e/sts.rs`](../../tests/e2e-rust/tests/e2e/sts.rs), [`sts_fidelity.rs`](../../tests/e2e-rust/tests/e2e/sts_fidelity.rs)

All 11 operations are generated from the AWS model (awsQuery) and implemented. Temporary credentials are real: MWS recognizes them on every service until they expire.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| `GetCallerIdentity` | ✅ | The caller's account, ARN and user id, for users, roles, sessions and the root user. |
| `AssumeRole` | ✅ | Trust policies, session policies, session tags and transitive tags, external id, source identity, role chaining limits, and cross-account roles in member accounts. |
| MFA | ✅ | `SerialNumber`/`TokenCode` checked against IAM virtual MFA devices. On `AssumeRole` the code is verified first, so trust and identity policies see `aws:MultiFactorAuthPresent=true` and `aws:MultiFactorAuthAge` (the cross-account MFA pattern works); a wrong code is `AccessDenied` "MultiFactorAuthentication failed with invalid MFA one time pass code." |
| `GetSessionToken` and `GetFederationToken` | ✅ | Session credentials and federated users with session policies. |
| `AssumeRoleWithWebIdentity` | ✅ | Token signatures verified through OpenID Connect discovery and the provider's TLS certificate or thumbprint, audience and subject conditions. The trust policy is evaluated within the resource control policies of the role's organization (SCPs don't apply: the caller is unsigned), with the global request keys (`aws:SourceIp`, `aws:CurrentTime`, `aws:EpochTime`, `aws:RequestedRegion`, `aws:SecureTransport`) and `aws:ResourceAccount`/`aws:ResourceOrgID`/`aws:ResourceOrgPaths`. Session tags need `sts:TagSession` and a source identity `sts:SetSourceIdentity`. |
| `AssumeRoleWithSAML` | ✅ | Assertions checked as AWS checks them; the response or assertion must carry a valid XML signature from a certificate in the provider's metadata. RCPs and global keys apply as for web identity; `SourceIdentity` in the assertion needs `sts:SetSourceIdentity` and session tags `sts:TagSession` in the trust policy. |
| `GetWebIdentityToken` | ✅ | RS256 and ES384 JWTs signed with MWS's keys, which MWS's own web identity federation accepts. `iat`/`exp` follow the emulated clock, as the expiry checks do. |
| `GetDelegatedAccessToken` | ✅ | Trades the token of an accepted IAM delegation request for credentials. |
| `DecodeAuthorizationMessage` | ✅ | Decodes the encoded messages of `UnauthorizedOperation` errors (EC2). |
| `GetAccessKeyInfo` | ✅ | The account of any access key id. |
| `AssumeRoot` | ✅ | Root task sessions in member accounts once the organization enables root sessions. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
