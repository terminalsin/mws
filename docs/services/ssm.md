# AWS Systems Manager

> Crate: [`mws-ssm`](../../crates/services/mws-ssm) · Tests: [`tests/e2e-rust/tests/e2e/ssm.rs`](../../tests/e2e-rust/tests/e2e/ssm.rs), [`ssm_run_command.rs`](../../tests/e2e-rust/tests/e2e/ssm_run_command.rs)

Parameter Store, documents, managed nodes, Run Command, maintenance windows, Patch Manager, State Manager, inventory, compliance, change calendars, resource data syncs, Automation, Change Manager and OpsCenter: 139 of the 152 SSM operations are generated from the AWS model (awsJson1.1) and implemented. The rest answer `NotImplemented`.

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
| AWS-owned documents | 🟡 | Every account sees `AWS-RunShellScript`, `AWS-RunPowerShellScript`, `AWS-RunPatchBaseline`, `AWS-UpdateSSMAgent`, `AWS-ConfigureAWSPackage`, `AWS-StartPortForwardingSession`, `AWS-StartInteractiveCommand`, `AWS-GatherSoftwareInventory`, `AWS-StopEC2Instance`, `AWS-StartEC2Instance`, `AWS-RestartEC2Instance` and `AWS-CreateImage`; the hundreds of others are missing. |
| Reviews | ✅ | `UpdateDocumentMetadata` review actions (send for review, comment, approve, reject) and `ListDocumentMetadataHistory`. |
| Sharing | ✅ | `ModifyDocumentPermission` with accounts or `All`, and a shared version; shared documents are used by ARN. |

## Managed nodes and Run Command

| Feature | Status | Details |
| --- | :---: | --- |
| Managed nodes | 🟡 | EC2 instances launched with an instance profile are managed nodes: `DescribeInstanceInformation` lists them `Online` while running and `ConnectionLost` when stopped, with the platform from their AMI and the profile's role. MWS does not check that the role allows Systems Manager. |
| Run Command | ✅ | `SendCommand` by instance ids or targets (`tag:<key>`, `tag-key`), with parameters checked and defaults filled in. `aws:runShellScript` steps really run in Docker-backed instances, with `workingDirectory` and `timeoutSeconds`; output, exit codes, status and timing come back through `GetCommandInvocation` and `ListCommandInvocations`. Preconditions skip steps for other platforms, `CancelCommand` cancels. With the metadata backend, commands succeed with no output. |
| Command output | 🟡 | Output is not written to S3 or CloudWatch Logs, and no SNS notifications are sent. Other plugins (`aws:configurePackage`, ...) report success without doing anything. |
| Node views | ✅ | `ListNodes`, `ListNodesSummary` (counts by attribute) and `DescribeInstanceProperties`. `UpdateManagedInstanceRole` only applies to hybrid nodes, so EC2 nodes answer `InvalidInstanceId`. |
| Hybrid activations | 🟡 | Created, listed (with expiry) and deleted; no agent can register with them. |

## Maintenance windows

| Feature | Status | Details |
| --- | :---: | --- |
| Windows, targets and tasks | ✅ | `cron`, `rate` and `at` schedules with time zones, offsets, start and end dates, duration and cutoff checks; targets by tag or instance id; Run Command, Lambda, Automation and Step Functions tasks with priorities; `Safe` deregistration; schedules and next execution times. |
| Executions | 🟡 | Windows run on the emulated clock: Run Command tasks send commands to the targeted nodes (with `{{RESOURCE_ID}}` and the other pseudo parameters), Lambda tasks invoke the function and Automation tasks run the runbook as the task's `ServiceRoleArn`. Overlapping runs are `SKIPPED_OVERLAPPING`, and executions report "Maintenance Window Execution State-change Notification" events to EventBridge. Step Functions tasks fail, and Lambda and Automation tasks need a service role (the service-linked role is not emulated). |

## Patch Manager

| Feature | Status | Details |
| --- | :---: | --- |
| Patch baselines | ✅ | AWS's predefined default baseline for each operating system (their ids differ from AWS's), custom baselines, defaults, patch groups and `DescribePatchGroupState` counts of tagged nodes. |
| Scanning and installing | 🟡 | `AWS-RunPatchBaseline` (`Scan`/`Install`) on Docker-backed Linux nodes asks the node's package manager (dnf/yum, apt) for missing updates and installs them, then records `DescribeInstancePatchStates` (by node and patch group), `DescribeInstancePatches`, Patch compliance and `AWS:PatchSummary` inventory. Metadata-backed nodes report a clean scan. Baseline approval rules are not applied to the package list, and Windows nodes are not patched. |
| Snapshots and properties | 🟡 | `GetDeployablePatchSnapshotForInstance` and `DescribePatchProperties` answer from the baseline; there is no patch catalogue for available patches. |

## State Manager

| Feature | Status | Details |
| --- | :---: | --- |
| Associations | ✅ | Create (one or batch), describe, list with filters, update (versioned, `InvalidAssociationVersion` on a stale version), delete, status, versions and tags. Targets by instance id, `*`, tag or tag key. |
| Applying | ✅ | Associations apply on creation (unless `ApplyOnlyAtCronInterval`), on update, on `StartAssociationsOnce`, when their `cron`/`rate` schedule comes due on the emulated clock, and when a node newly matches the targets. Command and Policy documents run through Run Command; closed change calendars skip a run. |
| Results | ✅ | `DescribeAssociationExecutions`, `DescribeAssociationExecutionTargets`, the association overview, `DescribeInstanceAssociationsStatus`, `DescribeEffectiveInstanceAssociations` and Association compliance (unless `SyncCompliance` is `MANUAL`). |
| Output locations, rate controls | 🟡 | Accepted and returned; output is not written to S3, and all targets run at once. |

## Inventory and compliance

| Feature | Status | Details |
| --- | :---: | --- |
| Inventory | ✅ | `PutInventory` with custom types and versioned schemas, `GetInventory` with filters, aggregators and result attributes, `GetInventorySchema`, `ListInventoryEntries`, `DeleteInventory` (dry run, disable or delete schema) and `DescribeInventoryDeletions`. Every managed node reports `AWS:InstanceInformation` and `AWS:Tag`. |
| Gathering | 🟡 | `AWS-GatherSoftwareInventory` associations collect installed packages (rpm, dpkg, apk) and network interfaces from Docker-backed nodes. Files, services, registry and Windows updates are not gathered. |
| Compliance | ✅ | `PutComplianceItems`, `ListComplianceItems`, `ListResourceComplianceSummaries` and `ListComplianceSummaries` over custom, Association and Patch compliance. |
| Resource data syncs | 🟡 | `SyncToDestination` syncs write each node's inventory as JSON lines into S3 (`<Type>/accountid=/region=/resourcetype=ManagedInstanceInventory/<node>.json`) as Systems Manager, honouring the bucket policy and SSE-KMS. `SyncFromSource` (Explorer) syncs are stored but gather nothing. |

## Automation

| Feature | Status | Details |
| --- | :---: | --- |
| Runbooks | ✅ | `StartAutomationExecution` runs Automation documents step by step: typed parameters with defaults, allowed values and patterns, `{{ }}` references to parameters, step outputs, `automation:` and `global:` variables, runbook variables and `{{ssm:...}}` parameters; `nextStep`, `isEnd`, `onFailure` (`Abort`, `Continue`, `step:`), `isCritical`, `maxAttempts` and `timeoutSeconds` on the emulated clock; runbook outputs. |
| Identity | ✅ | Steps run as the caller, or as the runbook's `assumeRole` assumed by `ssm.amazonaws.com` (its trust policy must allow that; otherwise "The defined assume role is unable to be assumed."). Every API call is authorized as that identity. |
| Actions | 🟡 | `aws:executeAwsApi` (any emulated service, JSONPath output selectors), `aws:waitForAwsResourceProperty`, `aws:assertAwsResourceProperty`, `aws:branch`, `aws:sleep`, `aws:pause`, `aws:approve` (approvers, minimum approvals, SNS notification), `aws:runCommand`, `aws:invokeLambdaFunction`, `aws:executeScript` (Python runs locally with the identity's credentials and `AWS_ENDPOINT_URL`; PowerShell needs `pwsh`), `aws:executeAutomation`, `aws:changeInstanceState`, `aws:runInstances`, `aws:createImage`, `aws:copyImage`, `aws:deleteImage`, `aws:createTags`, `aws:createStack`, `aws:deleteStack`, `aws:updateVariable` and `aws:loop`. `aws:executeStateMachine` and `aws:invokeWebhook` fail; script attachments are not supported. |
| Control | ✅ | Interactive mode (`StartStep`/`StopStep`), `SendAutomationSignal` (`Approve`, `Reject`, `Resume`), `StopAutomationExecution` (`Cancel` or `Complete`), CloudWatch alarms that stop a run, step and execution listings with every filter. |
| Rate control | ✅ | `Targets` (parameter values, tags, tag keys) or `TargetMaps` run one child execution per target with `MaxConcurrency` and `MaxErrors`. |
| Multiple accounts and Regions | 🟡 | `TargetLocations` assume `AWS-SystemsManager-AutomationAdministrationRole`, which assumes each account's execution role through STS, and run the runbook there (it must be shared with those accounts). `TargetLocationsURL` is not supported. |
| Execution previews | ✅ | `StartExecutionPreview` counts mutating, non-mutating and undetermined steps, Regions, accounts and targets. |
| EventBridge | ✅ | Rules can target `automation-definition/<name>` ARNs, with the event input as parameters. |

## Change Manager and OpsCenter

| Feature | Status | Details |
| --- | :---: | --- |
| Change requests | ✅ | `StartChangeRequestExecution` with an `Automation.ChangeTemplate` document: an OpsItem of type `/aws/changerequest` tracks it, its `aws:approve` steps wait for approvers (`AutoApprove` only when the template allows it), then it waits for `ScheduledTime` and runs its runbooks as child executions. `Reject` rejects it and `Revoke` cancels a scheduled one. Change calendars are not consulted. |
| OpsItems | ✅ | Create, get, update, delete and describe with every filter key; types, categories, severities and statuses checked; `/aws/dedup` deduplication; related items; tags. Notifications are stored but not sent. |
| Events | ✅ | EventBridge rules with an `opsitem` target create OpsItems (deduplicated by source, detail type and resources), listed by `ListOpsItemEvents`. |
| Explorer | 🟡 | `GetOpsSummary` over `AWS:OpsItem` and `AWS:EC2InstanceInformation` with filters, result attributes and count aggregators; other OpsData types are not collected. |
| OpsMetadata | ✅ | Application Manager metadata: create, get (paged), update, delete and list, with the 5-key limit. |

## Change Calendar

| Feature | Status | Details |
| --- | :---: | --- |
| Calendars | ✅ | `ChangeCalendar` documents (iCalendar, `DEFAULT_OPEN` or `DEFAULT_CLOSED`) and `GetCalendarState` at any time, with the next transition. Associations skip runs while a calendar they name is closed. |

## Rest of Systems Manager

| Feature | Status | Details |
| --- | :---: | --- |
| Session Manager, just-in-time access, multicloud connectors | ❌ | Not yet. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
