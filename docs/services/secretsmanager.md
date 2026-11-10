# AWS Secrets Manager

> Crate: [`mws-secretsmanager`](../../crates/services/mws-secretsmanager) · Tests: [`tests/e2e-rust/tests/e2e/secretsmanager.rs`](../../tests/e2e-rust/tests/e2e/secretsmanager.rs), [`secretsmanager_lifecycle.rs`](../../tests/e2e-rust/tests/e2e/secretsmanager_lifecycle.rs)

All 23 operations are generated from the AWS model (awsJson1.1) and implemented.

✅ supported · 🟡 partial · ❌ not supported

## Secrets

| Feature | Status | Details |
| --- | :---: | --- |
| Values and versions | ✅ | String or binary values; staging labels move as Secrets Manager moves them (`AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING`, custom labels, deprecated versions); idempotent `ClientRequestToken`s. |
| Lookup | ✅ | By name, ARN or partial ARN, per Region; IAM is asked before the lookup, so an unauthorized caller gets `AccessDeniedException`, not `ResourceNotFoundException`. |
| Quotas and validation | ✅ | 100 versions and 20 staging labels per secret (`LimitExceededException`), model constraints as `ValidationException`. |
| `BatchGetSecretValue` | ✅ | With per-secret errors. |
| `ListSecrets` | ✅ | Name, tag and description filters, negation, free-text search split like the console, sorting and pages. |
| Deletion | ✅ | Recovery windows on the emulated clock, `RestoreSecret`, and forced deletion. Forced deletion is asynchronous as on AWS: for the settle window (`MWS_ASYNC_DELAY_MS`, default 500 ms) the secret is marked for deletion and `CreateSecret` with its name fails ("...already scheduled for deletion."). |
| Secrets managed by other services | ✅ | Secrets with an `OwningService` (RDS `rds!db-...` master secrets) refuse `PutSecretValue`, `UpdateSecret`, `UpdateSecretVersionStage` and `DeleteSecret` (`InvalidRequestException`); the owner changes them, and `RotateSecret` rotates through it. |
| `GetRandomPassword` and tags | ✅ | As in Secrets Manager. |

## Security

| Feature | Status | Details |
| --- | :---: | --- |
| Encryption | ✅ | Every version is sealed with AES-256-GCM under a KMS data key (`kms:ViaService`, the secret ARN and version as encryption context); `aws/secretsmanager` is created on first use; disabled keys fail with `DecryptionFailure`/`EncryptionFailure`. |
| Resource policies | ✅ | Evaluated by the IAM engine with Secrets Manager's condition keys; `BlockPublicPolicy` and `ValidateResourcePolicy` reject public statements. |

## Rotation and replication

| Feature | Status | Details |
| --- | :---: | --- |
| Rotation | ✅ | Really runs: the function policy must allow `secretsmanager.amazonaws.com`, and the Lambda function is invoked through `createSecret`, `setSecret`, `testSecret` and `finishSecret`. A failed rotation keeps its `AWSPENDING` version and is reattempted with it: by `RotateSecret` with the same `ClientRequestToken`, after any other `RotateSecret` (which is refused with "A previous rotation isn't complete. That rotation will be reattempted."), and in the next scheduled window. |
| Schedules | ✅ | `AutomaticallyAfterDays`, `rate()` and `cron()` with `Duration` windows set `NextRotationDate` and start rotations on the emulated clock. |
| Replicas | ✅ | Live in their Region with their own KMS key, follow every change to the primary, are read-only, and can be removed or promoted. New replicas are `InProgress` for the settle window, then `InSync`. |
| Managed external secrets | 🟡 | Stored, but not rotated (there are no partners to call). |

See also: [all services](README.md) · [authentication and authorization](../security.md).
