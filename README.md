# MWS

A lightweight local stand-in for AWS, written in Rust, for testing code that
talks to AWS. Point an unmodified AWS SDK at it and it should behave like the
real service: same wire protocol, same validation messages, same error codes,
real SigV4 authentication.

It is not meant to carry load. It is meant to tell you whether your code
would work against AWS. State lives in memory by default; it can optionally
be saved to a local SQLite file, seeded from a scenario file, reset between
tests and snapshotted (see [State, scenarios and snapshots](#state-scenarios-and-snapshots)).

## Status

| Service | State |
| --- | --- |
| IAM | All 180 operations are implemented, generated from the AWS model and validating input like AWS: users, groups, roles, access keys, login profiles, managed and inline policies, permissions boundaries, tags, instance profiles, OIDC and SAML providers, virtual MFA devices (real TOTP codes, QR PNGs), SSH public keys, signing and server certificates (key pair checks), service-specific credentials, the password policy and `ChangePassword`, the credential report, access advisor (service last accessed, `ListPoliciesGrantingServiceAccess`), service-linked roles, delegation requests, outbound web identity federation, account properties and summary, authorization details, and the policy simulator. Centralized root access and Organizations access reports follow the caller's organization (access reports find no service usage), and no AWS role templates exist. Access advisor reports no authentication history. |
| STS | All operations: `GetCallerIdentity`, `AssumeRole` (trust policies, session policies, tags, transitive tags, external id, source identity, role chaining limits), MFA codes checked against IAM virtual devices, `GetSessionToken`, `GetFederationToken`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML` (assertions are checked like AWS but signatures are not verified), `GetWebIdentityToken` (RS256/ES384 JWTs), `GetDelegatedAccessToken`, `DecodeAuthorizationMessage`, `GetAccessKeyInfo`, and `AssumeRoot` (root task sessions in member accounts once the organization enables root sessions). Cross-account `AssumeRole` into member accounts. |
| Organizations | All 63 operations are generated from the AWS model (awsJson1.1). Implemented: organizations (all features or consolidated billing), roots, nested OUs (depth limit), `CreateAccount` creating real member accounts with their own IAM namespace and `OrganizationAccountAccessRole`, moving, removing, leaving and closing accounts, invitations and the other handshakes (enable all features, billing responsibility transfers), every policy type with per-type validation and attachment limits, `EnablePolicyType`/`DisablePolicyType` (FullAWSAccess and RCPFullAWSAccess attached everywhere), effective management policies merged with the inheritance operators, trusted service access, delegated administrators, the organization resource policy, and tags. SCPs and RCPs are enforced by the IAM engine for member accounts. `CreateGovCloudAccount` fails as it does for accounts without GovCloud. |
| Route 53 | All 71 operations are generated from the AWS model (restXml). Implemented: public and private hosted zones (create, get, list, list by name and by VPC, count, comment, delete, VPC associate/disassociate), atomic `ChangeResourceRecordSets` (CREATE, UPSERT, DELETE with Route 53's `InvalidChangeBatch` messages, CNAME conflicts, apex rules, A/AAAA value checks), `ListResourceRecordSets` in Route 53's order with pagination and `\052` escaping, `GetChange`, health checks (status always healthy), traffic policies and instances, DNSSEC key-signing keys backed by real KMS keys (the key policy must allow `dnssec-route53.amazonaws.com`; DNSKEY and DS records come from the key's public key), reusable delegation sets, CIDR collections, query logging configs, VPC association authorizations, limits, `TestDNSAnswer`, geo locations, and tags. Changes report `PENDING` and then `INSYNC`. An optional DNS responder serves the zones over UDP. |
| Private CA | All 23 operations are generated from the AWS model (awsJson1.1). Implemented: root and subordinate CAs with real keys (RSA 2048/3072/4096, EC P-256/P-384/P-521), CSRs, self-issued root certificates, import with chain checks, `IssueCertificate` with ACM PCA templates (end-entity, server/client auth, code signing, OCSP, root, subordinate path lengths), validity rules, `GetCertificate` with chains, revocation, disable/delete/restore, tags, permissions, and CA resource policies evaluated by the IAM engine. Certificates verify with standard X.509 tooling. CRLs and audit reports (JSON or CSV) are written into S3 buckets as `acm-pca.amazonaws.com`, so the bucket policy must allow it as in AWS (checked when the CRL bucket is configured and when a report is requested); OCSP is answered unsigned. Not yet: API passthrough extensions, and hash/curve combinations other than the natural ones for EC keys. |
| S3 | 109 of 112 operations, generated from the AWS model (restXml with S3's quirks: no error wrapping, `x-id` routing, `x-amz-meta-*`, raw payloads). Path-style and virtual-hosted addressing, SigV4 headers, presigned URLs and `aws-chunked` streaming uploads with chunk and trailer signatures (Signature Version 2 is refused as for new buckets). Buckets (global names, per-account listing, `ExpectedBucketOwner`), objects with metadata, ranges, conditional reads and writes, checksums (CRC32/CRC32C/CRC64NVME/SHA1/SHA256, composite and full-object multipart), multipart uploads and copies, versioning with delete markers, `ListObjects`/`V2`/`ListObjectVersions` with delimiters and pagination, `DeleteObjects`, `CopyObject`, tagging, object attributes, ACLs and ownership controls, Block Public Access, bucket policies evaluated by the IAM engine (cross-account needs both sides, anonymous access through public policies or ACLs), CORS with preflight, SSE-S3, SSE-C and SSE-KMS through KMS with the caller's permissions, Object Lock (retention, legal hold), and the bucket configuration APIs (lifecycle, website, logging, notifications, replication, analytics/metrics/inventory/intelligent tiering, accelerate, request payment). Lifecycle rules act on the emulated clock (`POST /_mws/clock {"advanceSeconds":n}` moves it; expiration, noncurrent expiration, transitions, multipart abort, `x-amz-expiration`), and replication rules copy new versions and delete markers to the destination as the configured role, with replication status on both sides. `SelectObjectContent` runs S3 Select SQL (projections, `WHERE`, `LIMIT`, `CAST`, `LIKE`/`IN`/`BETWEEN`/`CASE`, string functions, `COUNT`/`SUM`/`AVG`/`MIN`/`MAX`) over CSV and JSON (DOCUMENT/LINES), GZIP or BZIP2 compressed, with scan ranges, streamed as event-stream `Records`/`Progress`/`Stats`/`End`. Object annotations, torrents, and S3 Metadata journal/inventory/annotation table configurations (described, not queryable). Other configurations (notifications, website, logging, analytics) are stored and returned; archived objects restore instantly. Not yet: Parquet input for Select, directory bucket sessions (`CreateSession`), `RenameObject` and Object Lambda's `WriteGetObjectResponse`. |
| KMS | All 56 operations are generated from the AWS model (awsJson1.1). Keys do real cryptography: symmetric keys encrypt with AES-256-GCM and bind the encryption context, `Decrypt` finds the key from the ciphertext, and RSA, ECC (P-256/384/521, secp256k1), Ed25519, ML-DSA, HMAC, ECDH and ML-KEM keys sign, verify, encrypt, MAC, agree and encapsulate with results that check out in standard tooling. Data keys and data key pairs, `ReEncrypt`, `GenerateRandom`, aliases, tags, enable/disable, scheduled deletion (lazy, by wall clock), automatic and on-demand rotation (old ciphertexts keep decrypting), imported key material (all wrapping algorithms, expiry, re-import of the same material only), multi-Region keys and replicas, and `DryRun`. Key policies are evaluated the way KMS does (the key policy must allow the caller, directly or by delegating to IAM), with the policy lockout safety check, and grants (with encryption context constraints) allow their grantees. Other services use KMS keys through the crate's API (`kms:ViaService`, AWS managed `alias/aws/*` keys, service principals). Not supported: SM2 (China Regions only), Nitro Enclaves `Recipient`, `ED25519_PH_SHA_512` and ML-DSA `EXTERNAL_MU`; custom key stores can be managed but never connect (no CloudHSM, no reachable XKS proxy). |

Authentication is real: requests must carry a valid SigV4 signature (header or
presigned URL) from a known access key or STS session.

Authorization is real too. Every call to every service is evaluated against
the caller's IAM policies with AWS's evaluation logic: explicit deny wins;
identity policies (inline, managed, group) must allow; permissions boundaries
and session policies cap them; resource policies and role trust policies are
honoured (including account-level delegation). Requests across accounts need
both the caller's identity policies and the resource's policy. For member
accounts of an organization, service control policies (every level of the OU
tree must allow) and resource control policies apply too, and the
`aws:PrincipalOrgID`/`aws:PrincipalOrgPaths`/`aws:ResourceOrg*` keys are set.
Conditions support every
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
| `MWS_DB` | unset (in memory); a path such as `.mws/state.db` keeps state in SQLite across restarts |
| `MWS_SCENARIO` | unset; a scenario file run at startup and used as the reset baseline |
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

## State, scenarios and snapshots

**Persistence.** With `MWS_DB` set, every service's state is written to that
SQLite file shortly after each change (within about 250 ms) and again on
shutdown (Ctrl-C or SIGTERM), and comes back on the next start. Temporary
STS credentials survive too, until they expire.

**Scenarios.** A scenario is a JSON list of API calls that sets up state.
Each step names the service (its signing name), the operation, and the input
in the same shape as `aws ... --cli-input-json`. Steps go through the real
handlers, so they are validated and authorized like SDK calls (as the root
user unless a step sets `accessKeyId`). A step with an `id` exposes its output
to later steps as `${id.Path.To.Field}`, with optional `|basename` (strip
`/hostedzone/`) and `|base64` (for blob inputs such as a CSR) filters.
If any step fails, the whole scenario is rolled back and the error names the
step.

```json
{
  "steps": [
    { "service": "iam", "action": "CreateUser", "input": { "UserName": "deployer" } },
    { "id": "key", "service": "iam", "action": "CreateAccessKey", "input": { "UserName": "deployer" } },
    { "id": "zone", "service": "route53", "action": "CreateHostedZone",
      "input": { "Name": "example.internal", "CallerReference": "seed" } },
    { "service": "route53", "action": "ChangeResourceRecordSets",
      "input": { "HostedZoneId": "${zone.HostedZone.Id|basename}", "ChangeBatch": { "Changes": [
        { "Action": "CREATE", "ResourceRecordSet": { "Name": "api.example.internal", "Type": "A",
          "TTL": 60, "ResourceRecords": [{ "Value": "10.0.0.10" }] } } ] } } }
  ]
}
```

[`examples/scenario.json`](examples/scenario.json) also creates a role and
a Private CA and activates it with a self-signed root certificate.

`MWS_SCENARIO` runs a scenario at startup on an empty emulator, and the
result becomes the **baseline** that `POST /_mws/reset` returns to. With
`MWS_DB` as well, the scenario runs only once: later starts restore the saved
state. If the scenario file changes, the saved state is replaced by a fresh
run of the new scenario (the old state is kept as a snapshot named
`before-scenario-change-...`).

**Control API.** Plain unsigned JSON over HTTP on the same port:

| Request | Effect |
| --- | --- |
| `GET /_mws/health` | liveness and the emulated services |
| `GET /_mws/state` | export the whole emulator's state |
| `PUT /_mws/state` | replace it with an exported document |
| `POST /_mws/reset` | back to the baseline (`?to=empty` for a fresh emulator) |
| `POST /_mws/scenario` | run a scenario now; returns the outputs of steps with an `id`. `?baseline=true` makes the result the new baseline |
| `GET /_mws/snapshots` | list named snapshots |
| `PUT /_mws/snapshots/{name}` | save the current state |
| `GET /_mws/snapshots/{name}` | export a snapshot |
| `POST /_mws/snapshots/{name}/restore` | replace the current state with a snapshot |
| `DELETE /_mws/snapshots/{name}` | delete a snapshot |
| `GET /_mws/clock` | the emulated time and its offset from the wall clock |
| `POST /_mws/clock` | move the emulated time: `{"advanceSeconds": n}` or `{"offsetSeconds": n}` (time-based behaviour such as S3 lifecycle follows it; signatures still use the wall clock) |

A typical test suite starts MWS with a scenario and calls `POST /_mws/reset`
before each test. Snapshots live in the database when `MWS_DB` is set, and in
memory otherwise. The control API is unauthenticated, like the rest of a
local emulator: don't expose the port beyond your machine.

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
  mws-proto-json    awsJson1.0/1.1 protocol runtime (X-Amz-Target, JSON, errors)
  mws-xml           XML writer and reader shared by the XML protocols
  mws-server        HTTP front door: authenticates, routes by signing name; the
                    /_mws control API, scenarios, snapshots and persistence
  mws-store         SQLite persistence of opaque per-service state documents
  mws               the binary; the only crate that knows which services exist
  services/
    mws-iam         IAM: model/iam.json + behaviour
    mws-iam-policy  the IAM policy language and evaluation logic
    mws-sts         STS: temporary credentials over IAM identities
    mws-route53     Route 53: hosted zones, record sets, health checks, DNS responder
    mws-acmpca      AWS Private CA: CAs and real X.509 issuance
    mws-kms         KMS: keys with real cryptography, key policies, grants, aliases
    mws-s3          S3: buckets, objects, multipart, versioning, policies, SSE, lifecycle, replication, Select
examples/
  scenario.json     a sample scenario: IAM user and role, a hosted zone, an active CA
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
