# Amazon GuardDuty

> Crate: [`mws-guardduty`](../../crates/services/mws-guardduty) · Tests: [`tests/e2e-rust/tests/e2e/guardduty.rs`](../../tests/e2e-rust/tests/e2e/guardduty.rs)

All 102 operations are generated from the AWS model (restJson1) and implemented. MWS does not analyse CloudTrail, VPC flow logs or DNS queries, so findings come from `CreateSampleFindings` and malware scans.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Detectors | ✅ | One per account and Region, publishing frequency, enable/disable, service-linked role ARN, tags with `aws:ResourceTag` and `aws:RequestTag` conditions. |
| Protection plans | ✅ | `Features` (S3, EKS audit logs, runtime monitoring with additional configuration, EBS malware, RDS, Lambda, AI protection) and the legacy `DataSources`, kept consistent; mixing both in one request is rejected as AWS does. |
| Sample findings | ✅ | Every finding type (about 190) with AWS's sample shape: `[SAMPLE]` titles, `GeneratedFinding*` placeholders, `additionalInfo.sample: true`, per-type severity and resource. Generating a sample again increments `service.count`. |
| Finding queries | ✅ | `ListFindings` and `GetFindingsStatistics` with finding criteria (`Eq`, `Neq`, `Equals`, `NotEquals`, `Gt`/`Gte`/`Lt`/`Lte`, `Matches` wildcards) over any finding attribute, sorting, pagination, every `GroupBy`. |
| Archive and feedback | ✅ | Archive, unarchive and feedback; a member managed by an administrator cannot archive its own findings. |
| Filters | ✅ | `NOOP` and `ARCHIVE` (suppression rules) with ranks; suppressed findings are archived and not published. An administrator's suppression rules apply to its members. |
| EventBridge | ✅ | `GuardDuty Finding` events (source `aws.guardduty`) for new and updated findings, in the finding's account and its administrator's; malware object scans send `GuardDuty Malware Protection Object Scan Result`. Events are sent at once, not on the publishing frequency. |
| Publishing destinations | ✅ | Findings written to S3 as gzipped JSON Lines under `AWSLogs/<account>/GuardDuty/<region>/`, as `guardduty.amazonaws.com` with SSE-KMS under the destination's key (bucket and key policies apply). Failures show as `UNABLE_TO_PUBLISH_FIX_DESTINATION_PROPERTY`. |
| Security Hub | ✅ | New and updated findings are imported as ASFF from product `aws/guardduty` (types, severity labels, resources, `aws/guardduty/...` product fields) when the account has Security Hub enabled. |
| Threat lists | 🟡 | IP sets, threat intel sets, threat entity sets and trusted entity sets with AWS's limits; locations are validated but list contents are not fetched or matched. |
| Members by invitation | ✅ | Create, invite, accept (also the deprecated master operations), decline, delete, disassociate, stop and start monitoring, member detector features; the administrator sees members' findings. |
| Organizations | ✅ | `EnableOrganizationAdminAccount` (management account) enables trusted access and registers the delegated administrator in Organizations; the administrator adds organization accounts as members without invitations, `AutoEnableOrganizationMembers` `ALL`/`NEW` enables detectors and features as accounts appear, organization statistics. |
| Malware protection | 🟡 | Protection plans for S3 buckets with prefixes; `SendObjectMalwareScan`, `StartMalwareScan` and EBS scans complete immediately as `NO_THREATS_FOUND`. Objects are not scanned or tagged. |
| Custom detection rules | 🟡 | A small built-in catalog with associations (`DRY_RUN` expires, `LIVE`) and organization configurations; rules do not run. |
| Investigations | 🟡 | Stored and complete immediately with no results. |
| Coverage and usage | 🟡 | Coverage is empty, usage costs are zero, free trial days are 30. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
