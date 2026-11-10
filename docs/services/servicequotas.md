# Service Quotas

> Crate: [`mws-servicequotas`](../../crates/services/mws-servicequotas) · Tests: [`tests/e2e-rust/tests/e2e/servicequotas.rs`](../../tests/e2e-rust/tests/e2e/servicequotas.rs)

All 26 operations are generated from the AWS model (awsJson1.1) and implemented. Services enforce the applied values, and usage is published to CloudWatch so quota alarms work.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Starting values | ✅ | `MWS_QUOTA_PROFILE=established` (the default) starts accounts at AWS's defaults except EC2 vCPU quotas of 1152 per instance class, so suites that launch many instances need no increases; `new-account` uses AWS's exact new-account defaults (5 standard vCPUs). `GetAWSDefaultServiceQuota` always reports AWS's default. |
| Catalogue | 🟡 | About 190 quotas across 32 services with AWS's quota codes, names, units, defaults (some differ by Region, as in AWS), adjustability and global scope, plus each quota's `UsageMetric`, including ECS (clusters, services per cluster), Fargate vCPUs, ECR repositories and images, and Lambda ENIs per VPC. Not all of AWS's thousands of quotas: no SQS or CodeArtifact quotas yet; quotas outside the catalogue answer `NoSuchResourceException` and are unlimited to enforcing services. ECS, Fargate and ECR quotas are reported but not enforced. |
| Increase requests | ✅ | Checked like AWS (adjustable quota, a value above the current one, one open request per quota). Requests up to 20 times the quota's starting value are approved a second later on the emulated clock; larger ones go to `CASE_OPENED` (with a case id) after that second, like requests escalated with `CreateSupportCase`, and a case is reviewed for a day of emulated time before it ends as the review policy says (`APPROVED` by default). The new value applies everywhere once approved. |
| Review control | ✅ | Unsigned at `/_aws/servicequotas/`: `GET`/`POST review` reads or sets `autoApprove` (false: nothing settles by itself), `approvalSeconds`, `caseThresholdFactor`, `caseReviewSeconds` and `caseOutcome` (`APPROVED`, `DENIED`, `NOT_APPROVED`, `INVALID_REQUEST`, `CASE_CLOSED`); `GET requests[?account=]` lists requests; `POST requests/{id}` with `{"status": ...}` decides an open request now (or escalates it with `CASE_OPENED`). |
| Quota request template | ✅ | Management account with all features, `us-east-1` only, at most 10 entries; raises quotas in member accounts created after it was associated. |
| EC2 and VPC enforcement | ✅ | On-Demand and Spot vCPUs per instance class (`L-1216C47A` and friends) in `RunInstances`/`StartInstances` (`VcpuLimitExceeded`), Elastic IPs (`AddressLimitExceeded`), VPCs per Region (`VpcLimitExceeded`), rules per security group. |
| Other enforcement | ✅ | S3 buckets (`TooManyBuckets`), IAM roles and managed policies per role (`LimitExceeded`), Lambda concurrent executions; Auto Scaling groups and launch configurations (`LimitExceeded`, and `DescribeAccountLimits`); Application, Network and Classic Load Balancers, target groups and rules per ALB (`TooManyLoadBalancers`, `TooManyTargetGroups`, and `DescribeAccountLimits`); RDS DB instances, clusters and manual snapshots (`InstanceQuotaExceeded`, `DBClusterQuotaExceededFault`, `SnapshotQuotaExceeded`, and `DescribeAccountAttributes`); EKS clusters, managed node groups, nodes per node group and Fargate profiles (`ResourceLimitExceededException`); Bedrock on-demand and cross-Region requests and tokens per minute per model (`ThrottlingException`) and the minimum records per batch inference job. Other quotas are reported but not enforced. |
| `AWS/Usage` metrics | ✅ | `ResourceCount` (EC2 vCPUs per class, Elastic IPs, VPCs, buckets, roles) once a minute on the emulated clock, `CallCount` for every API call (`Type=API`, `Resource=<operation>`). |
| `SERVICE_QUOTA()` | ✅ | In CloudWatch metric math, so `usage / SERVICE_QUOTA(usage) * 100` alarms fire as usage nears the quota. |
| Utilization reports | ✅ | Computed from current usage, sorted by utilization. |
| Automatic management | ✅ | `NotifyAndAdjust` requests an increase (to twice the applied value) for each adjustable quota whose usage reaches 80%, once a minute on the emulated clock, honouring the exclusion list; the requests show `RequestType: AutomaticManagement`. `NotifyOnly` is recorded. No User Notifications are sent. |
| Tags | ✅ | On quotas, at most 50. |

See also: [all services](README.md) · [CloudWatch](cloudwatch.md).
