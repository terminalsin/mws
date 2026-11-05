# AWS Systems Manager Parameter Store

> Crate: [`mws-ssm`](../../crates/services/mws-ssm) · Tests: [`tests/e2e-rust/tests/e2e/ssm.rs`](../../tests/e2e-rust/tests/e2e/ssm.rs)

The Parameter Store part of Systems Manager: 19 of the 152 SSM operations are generated from the AWS model (awsJson1.1) and implemented. The rest of Systems Manager answers `NotImplemented`.

✅ supported · 🟡 partial · ❌ not supported

## Parameters

| Feature | Status | Details |
| --- | :---: | --- |
| Parameter operations | ✅ | `PutParameter`, `GetParameter(s)`, `GetParametersByPath`, `DescribeParameters`, `GetParameterHistory`, `DeleteParameter(s)`, labels, tags and service settings. |
| Versions and labels | ✅ | Up to 100 versions (`ParameterMaxVersionLimitExceeded` when the oldest is labelled); read by name, ARN, `name:version` or `name:label`. |
| Names | ✅ | AWS's rules: reserved `aws`/`ssm` prefixes, 15 hierarchy levels, `foo` and `/foo` are the same parameter. |
| Types and tiers | ✅ | `String`, `StringList` and `SecureString`; `text`, `aws:ec2:image` and `aws:ssm:integration` data types; allowed patterns; Standard, Advanced and Intelligent-Tiering with their size limits and the account's default tier. |
| Filters | ✅ | Every `ParameterFilters` key and option. |
| SecureStrings | ✅ | Really encrypted with KMS for the caller (`alias/aws/ssm` by default, `kms:ViaService`, `PARAMETER_ARN` context, envelope encryption for advanced parameters); `WithDecryption` needs `kms:Decrypt`. |
| Parameter policies | ✅ | Validated; `Expiration` deletes on the emulated clock, and each policy sends its "Parameter Store Policy Action" event to EventBridge. |
| Sharing | ✅ | Advanced parameters shared with other accounts through resource policies (read by ARN, `DescribeParameters --shared`). |
| Secrets Manager references | ✅ | `/aws/reference/secretsmanager/<id>` reads the secret as the caller. |
| Public parameters | ✅ | `/aws/service/` Region and service catalogues and the latest Amazon Linux, ECS and EKS AMI parameters, whose ids match EC2's public AMIs. |
| Change events | ✅ | "Parameter Store Change" events on the default bus. |

## Rest of Systems Manager

| Feature | Status | Details |
| --- | :---: | --- |
| Run Command, Automation, State Manager | ❌ | Not yet. |
| Documents, managed nodes, hybrid activations | ❌ | Not yet. |
| Inventory, compliance, Patch Manager, maintenance windows | ❌ | Not yet. |
| Session Manager, OpsCenter, Change Calendar, Explorer | ❌ | Not yet. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
