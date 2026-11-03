# MWS

A lightweight local stand-in for AWS, written in Rust, for testing code that
talks to AWS. Point an unmodified AWS SDK at it and it should behave like the
real service: same wire protocol, same validation messages, same error codes,
real SigV4 authentication.

It is not meant to carry load or store data durably. It is meant to tell you
whether your code would work against AWS.

## Status

| Service | State |
| --- | --- |
| IAM | All 180 operations are generated from the AWS model and validate input like AWS. About 100 are implemented: users, groups, roles, access keys, login profiles, managed policies and versions, inline policies, attachments, permissions boundaries, tags, instance profiles, OIDC providers, account aliases and summary, authorization details, and the policy simulator. The rest return `NotImplemented`. |
| STS | `GetCallerIdentity`, `AssumeRole` (trust policies, session policies, tags, transitive tags, external id, source identity, role chaining limits), `GetSessionToken`, `GetFederationToken`, `AssumeRoleWithWebIdentity`, `GetAccessKeyInfo`. |
| Route 53 | All 71 operations are generated from the AWS model (restXml). Implemented: public and private hosted zones (create, get, list, list by name and by VPC, count, comment, delete, VPC associate/disassociate), atomic `ChangeResourceRecordSets` (CREATE, UPSERT, DELETE with Route 53's `InvalidChangeBatch` messages, CNAME conflicts, apex rules, A/AAAA value checks), `ListResourceRecordSets` in Route 53's order with pagination and `\052` escaping, `GetChange`, health checks, and tags. Changes report `PENDING` and then `INSYNC`. An optional DNS responder serves the zones over UDP. |
| Private CA | Planned (step 4) |

Authentication is real: requests must carry a valid SigV4 signature (header or
presigned URL) from a known access key or STS session.

Authorization is real too. Every call to every service is evaluated against
the caller's IAM policies with AWS's evaluation logic: explicit deny wins;
identity policies (inline, managed, group) must allow; permissions boundaries
and session policies cap them; resource policies and role trust policies are
honoured (including account-level delegation). Conditions support every
operator (`String*`, `Numeric*`, `Date*`, `Bool`, `IpAddress`, `Arn*`,
`Binary*`, `Null`, `...IfExists`, `ForAllValues:`/`ForAnyValue:`) and policy
variables such as `${aws:username}`. Denials use AWS's message wording.

The account root user is allowed everything, as in AWS. Notes:
`AssumeRoleWithWebIdentity` checks issuer, audience and expiry but does not
verify token signatures, and AWS managed policies are a trimmed subset
covering the services MWS emulates.

## Running

```sh
cargo run -p mws            # listens on 0.0.0.0:4566
```

| Variable | Default |
| --- | --- |
| `MWS_LISTEN` | `0.0.0.0:4566` |
| `MWS_ACCOUNT_ID` | `123456789012` |
| `MWS_ROOT_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00` |
| `MWS_ROOT_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |
| `MWS_DNS_LISTEN` | unset; e.g. `127.0.0.1:5353` starts the Route 53 DNS responder |
| `RUST_LOG` | `info` |

Then use any SDK or the CLI with the endpoint overridden:

```sh
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=AKIAMWSROOTEXAMPLE00
export AWS_SECRET_ACCESS_KEY=mwsRootSecretAccessKeyEXAMPLEKEY00000000
export AWS_REGION=us-east-1
aws iam create-user --user-name alice
aws iam create-access-key --user-name alice   # these keys now authenticate as alice
```

## Layout

```
crates/
  mws-core          service-agnostic contracts: ServiceError, RequestContext, Caller,
                    Authorizer, CredentialStore, Service
  mws-sigv4         SigV4 verification (header + presigned query)
  mws-smithy        reads Smithy JSON AST models
  mws-codegen       generates server stubs from Smithy models (build-time)
  mws-proto-query   awsQuery protocol runtime (form decoding, XML, errors)
  mws-proto-restxml restXml protocol runtime (HTTP binding, routing, XML, errors)
  mws-xml           XML writer and reader shared by the XML protocols
  mws-server        HTTP front door: authenticates, routes by signing name
  mws               the binary; the only crate that knows which services exist
  services/
    mws-iam         IAM: model/iam.json + behaviour
    mws-iam-policy  the IAM policy language and evaluation logic
    mws-sts         STS: temporary credentials over IAM identities
    mws-route53     Route 53: hosted zones, record sets, health checks, DNS responder
tests/
  e2e-rust          official Rust SDK against an in-process MWS
  e2e-python        boto3 against the mws binary
```

Each service is its own crate that depends only on generic crates. Shared
crates are protocol or infrastructure code, never service logic.

## Testing

```sh
cargo test --workspace
cargo build -p mws && pip install -r tests/e2e-python/requirements.txt && pytest tests/e2e-python
```
