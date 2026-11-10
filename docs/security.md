# Authentication and authorization

MWS authenticates and authorizes every request the way AWS does. This is what
makes it useful for testing IAM policies: a policy that works against MWS
should work against AWS, and a request AWS would deny is denied.

## Authentication

Requests must carry a valid [SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
signature, either in the `Authorization` header or as a presigned URL, from a
known access key or STS session. S3 also accepts its `aws-chunked` streaming
uploads with chunk and trailer signatures, browser POST uploads with signed
policies, and directory bucket session credentials. Bedrock also accepts its
API keys as bearer tokens: long-term keys are IAM service-specific
credentials and short-term keys carry a presigned SigV4 URL (see
[Bedrock](services/bedrock.md)).

Failures come back the way each service reports them:

| Protocol | Unknown key | Bad signature |
| --- | --- | --- |
| awsQuery (IAM, STS, SNS, SQS legacy) | `InvalidClientTokenId` | `SignatureDoesNotMatch` |
| awsJson | `UnrecognizedClientException` (400) | `InvalidSignatureException` (400) |
| restJson (Lambda) | `UnrecognizedClientException` (403) | `InvalidSignatureException` (403) |
| S3 | `InvalidAccessKeyId` | `SignatureDoesNotMatch` |

Unsigned requests get `MissingAuthenticationToken` (or
`MissingAuthenticationTokenException`) in the protocol of the service they
address. Access key ids encode their account, as on AWS, so
`sts:GetAccessKeyInfo` works on any of them.

## Authorization

Every handler calls the IAM authorizer before it acts, with the action, the
resource ARN and the request's condition keys. The authorizer implements
AWS's policy evaluation logic:

1. An explicit `Deny` in any applicable policy wins.
2. For member accounts of an organization, service control policies (every
   level of the OU tree must allow) and resource control policies must allow.
3. Resource-based policies (bucket, key, queue, topic, secret, CA, bus and
   other policies) and role trust policies are honoured, including
   account-level delegation.
4. Identity policies (inline, managed and group policies) must allow, capped
   by permissions boundaries and session policies.
5. Requests across accounts need both the caller's identity policies and the
   resource's policy, except where AWS lets a resource policy alone grant.

KMS key policies are authoritative as in KMS: the key policy must allow the
caller, directly or by delegating to IAM.

### Conditions

Every condition operator is supported: `String*`, `Numeric*`, `Date*`,
`Bool`, `IpAddress`, `Arn*`, `Binary*`, `Null`, the `...IfExists` variants and
the `ForAllValues:`/`ForAnyValue:` set operators. Policy variables such as
`${aws:username}` and `${aws:PrincipalTag/team}` are substituted. Global keys
include `aws:PrincipalArn`, `aws:PrincipalTag/*`, `aws:RequestTag/*`,
`aws:ResourceTag/*`, `aws:TagKeys`, `aws:SourceIp`, `aws:SecureTransport`,
`aws:ResourceAccount` and the organization keys `aws:PrincipalOrgID`,
`aws:PrincipalOrgPaths` and `aws:ResourceOrg*`, plus each service's own keys
(such as `kms:ViaService` or `s3:prefix`).

Denials use AWS's message wording, so tests can assert on them.

### Root user and managed policies

The account root user is allowed everything, as on AWS (except where SCPs or
resource policies restrict it). Every AWS managed policy (about 1,600, with
their real names, paths and documents) exists in every account, so
`ReadOnlyAccess`, `AdministratorAccess` and the service roles' policies
behave as on AWS. Service-linked roles get their service's policy, and roles
under the reserved `/aws-service-role/` and `/aws-reserved/` paths can only
be made by AWS, as there.

## Federation

- `AssumeRoleWithWebIdentity` verifies token signatures as AWS does. It
  fetches the issuer's keys through OpenID Connect discovery
  (`https://<issuer>/.well-known/openid-configuration`, then `jwks_uri`) and
  trusts the provider's TLS certificate when it chains to a public root or
  matches a thumbprint on the IAM OIDC provider. A local identity provider with
  a self-signed certificate therefore works once its thumbprint is registered.
- Tokens from MWS's own `GetWebIdentityToken` are checked against MWS's keys.
- `AssumeRoleWithSAML` requires the response or assertion to carry a valid XML
  signature from a certificate in the provider's metadata.

Test suites that hand-craft tokens can set
`MWS_SKIP_FEDERATION_SIGNATURE_VERIFICATION=1` to skip signature checks.

## Services acting on your behalf

When one service calls another (S3 delivering an event notification, Lambda
reading an SQS queue, Firehose writing to S3, CloudWatch publishing an alarm
to SNS), it does so as AWS does: either as the service principal, judged by
the target's resource policy alone with `aws:SourceArn` and
`aws:SourceAccount` (for example `s3.amazonaws.com` against a topic policy),
or by assuming the role you configured through STS, which checks the role's
trust policy. Configuring such a role needs `iam:PassRole`. A missing
permission breaks the integration in MWS just as it would on AWS, and
CloudTrail records the service's call as its own event.

## What is not protected

MWS is a local test tool. The `/_mws` control API is unauthenticated, and so
are the instance metadata service and the endpoints AWS itself leaves open
(such as presigned URLs and function URLs with `AuthType: NONE`). Do not
expose MWS beyond your machine or CI runner.
