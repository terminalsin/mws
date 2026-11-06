# AWS Systems Manager

> Crate: [`mws-ssm`](../../crates/services/mws-ssm) · Tests: [`tests/e2e-rust/tests/e2e/ssm.rs`](../../tests/e2e-rust/tests/e2e/ssm.rs), [`ssm_run_command.rs`](../../tests/e2e-rust/tests/e2e/ssm_run_command.rs)

Parameter Store, documents, managed nodes, Run Command, maintenance windows and Patch Manager baselines: 76 of the 152 SSM operations are generated from the AWS model (awsJson1.1) and implemented. The rest answer `NotImplemented`.

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

## Documents

| Feature | Status | Details |
| --- | :---: | --- |
| Documents | ✅ | JSON and YAML content checked for its document type and schema version, versions with names, the default version, `GetDocument` in either format, `DuplicateDocumentContent`, deleting a version or the whole document, tags. |
| AWS-owned documents | 🟡 | Every account sees `AWS-RunShellScript`, `AWS-RunPowerShellScript`, `AWS-RunPatchBaseline`, `AWS-UpdateSSMAgent`, `AWS-ConfigureAWSPackage`, `AWS-StartPortForwardingSession` and `AWS-StartInteractiveCommand`; the hundreds of others are missing. |
| Sharing | ✅ | `ModifyDocumentPermission` with accounts or `All`, and a shared version; shared documents are used by ARN. |

## Managed nodes and Run Command

| Feature | Status | Details |
| --- | :---: | --- |
| Managed nodes | 🟡 | EC2 instances launched with an instance profile are managed nodes: `DescribeInstanceInformation` lists them `Online` while running and `ConnectionLost` when stopped, with the platform from their AMI and the profile's role. MWS does not check that the role allows Systems Manager. |
| Run Command | ✅ | `SendCommand` by instance ids or targets (`tag:<key>`, `tag-key`), with parameters checked and defaults filled in. `aws:runShellScript` steps really run in Docker-backed instances, with `workingDirectory` and `timeoutSeconds`; output, exit codes, status and timing come back through `GetCommandInvocation` and `ListCommandInvocations`. Preconditions skip steps for other platforms, `CancelCommand` cancels. With the metadata backend, commands succeed with no output. |
| Command output | 🟡 | Output is not written to S3 or CloudWatch Logs, and no SNS notifications are sent. Other plugins (`aws:configurePackage`, ...) report success without doing anything. |
| Hybrid activations | 🟡 | Created, listed (with expiry) and deleted; no agent can register with them. |

## Maintenance windows

| Feature | Status | Details |
| --- | :---: | --- |
| Windows, targets and tasks | ✅ | `cron`, `rate` and `at` schedules with time zones, offsets, start and end dates, duration and cutoff checks; targets by tag or instance id; Run Command, Lambda, Automation and Step Functions tasks with priorities; `Safe` deregistration; schedules and next execution times. |
| Executions | 🟡 | Windows run on the emulated clock: Run Command tasks send commands to the targeted nodes (with `{{RESOURCE_ID}}` and the other pseudo parameters), Lambda tasks invoke the function as the task's `ServiceRoleArn`. Overlapping runs are `SKIPPED_OVERLAPPING`, and executions report "Maintenance Window Execution State-change Notification" events to EventBridge. Automation and Step Functions tasks fail, and Lambda tasks need a service role (the service-linked role is not emulated). |

## Patch Manager

| Feature | Status | Details |
| --- | :---: | --- |
| Patch baselines | 🟡 | AWS's predefined default baseline for each operating system (their ids differ from AWS's), custom baselines, defaults, patch groups and `DescribePatchGroupState` counts of tagged nodes. MWS has no patch catalogue: available and effective patch lists are empty, and nothing scans or installs patches. |

## Rest of Systems Manager

| Feature | Status | Details |
| --- | :---: | --- |
| Automation, State Manager associations | ❌ | Not yet. |
| Inventory, compliance | ❌ | Not yet. |
| Session Manager, OpsCenter, Change Calendar, Explorer | ❌ | Not yet. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
