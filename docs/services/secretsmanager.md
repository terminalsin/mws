# AWS Secrets Manager

> Crate: [`mws-secretsmanager`](../../crates/services/mws-secretsmanager) · Tests: [`tests/e2e-rust/tests/e2e/secretsmanager.rs`](../../tests/e2e-rust/tests/e2e/secretsmanager.rs)

All 23 operations are generated from the AWS model (awsJson1.1).

## Behaviour

Implemented: secrets with string or binary values, versions and staging labels
moved as Secrets Manager moves them (`AWSCURRENT`, `AWSPREVIOUS` following it,
`AWSPENDING`, custom labels, deprecated versions, idempotent
`ClientRequestToken`s), name, ARN and partial-ARN lookup (Regional: another
Region's ARN finds nothing; IAM is asked before the lookup, so an unauthorized
caller gets `AccessDeniedException`, not `ResourceNotFoundException`), retried
`CreateSecret` calls ignored, the 100-versions and 20-staging-labels quotas
(`LimitExceededException`), `ValidationException` for model constraints,
`BatchGetSecretValue` with per-secret errors, `ListSecrets` filters
(case-sensitive name and tag prefixes, descriptions word by word, negation, and
the free-text search splitting words like the console), sorting and pages,
`GetRandomPassword`, tags, and deletion with a recovery window on the emulated
clock, `RestoreSecret` and forced deletion (which succeeds for secrets that
don't exist).

Every version is sealed with AES-256-GCM under a KMS data key generated through
Secrets Manager (`kms:ViaService`, the secret ARN and version id as encryption
context), so customer managed keys need `kms:Decrypt` and disabled keys fail
with `DecryptionFailure`/`EncryptionFailure`; `aws/secretsmanager` is created on
first use. Resource policies are evaluated by the IAM engine with Secrets
Manager's condition keys, `BlockPublicPolicy` and `ValidateResourcePolicy`
reject public statements.

Rotation really runs: `RotateSecret` checks that the function policy allows
`secretsmanager.amazonaws.com`, adds the empty `AWSPENDING` version and invokes
the Lambda function through `createSecret`, `setSecret`, `testSecret` and
`finishSecret`; the function calls back with its execution role. Schedules
(`AutomaticallyAfterDays`, `rate()`, `cron()` with `Duration` windows) set
`NextRotationDate` and start rotations when the emulated clock reaches the
window.

Replicas live in their Region with their own KMS key, follow every change to the
primary, are read-only, and can be removed or promoted. Managed external secrets
(`Type`, `ExternalSecretRotation*`) are stored but not rotated (no partners to
call).

See also: [all services](README.md) · [authentication and authorization](../security.md).
