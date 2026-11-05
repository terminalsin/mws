# Service Quotas

> Crate: [`mws-servicequotas`](../../crates/services/mws-servicequotas) · Tests: [`tests/e2e-rust/tests/e2e/servicequotas.rs`](../../tests/e2e-rust/tests/e2e/servicequotas.rs)

All 26 operations are generated from the AWS model (awsJson1.1) and implemented. Services enforce the applied values, and usage is published to CloudWatch so quota alarms work.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Starting values | ✅ | `MWS_QUOTA_PROFILE=established` (the default) starts accounts at AWS's defaults except EC2 vCPU quotas of 1152 per instance class, so suites that launch many instances need no increases; `new-account` uses AWS's exact new-account defaults (5 standard vCPUs). `GetAWSDefaultServiceQuota` always reports AWS's default. |
| Catalogue | 🟡 | About 150 quotas across 28 services with AWS's quota codes, names, units, defaults (some differ by Region, as in AWS), adjustability and global scope, plus each quota's `UsageMetric`. Not all of AWS's thousands of quotas. |
| Increase requests | ✅ | Checked like AWS (adjustable quota, a value above the current one, one open request per quota) and approved a second later on the emulated clock; the new value applies everywhere. `CreateSupportCase` opens a case on a pending request. Requests are never denied. |
| Quota request template | ✅ | Management account with all features, `us-east-1` only, at most 10 entries; raises quotas in member accounts created after it was associated. |
| EC2 and VPC enforcement | ✅ | On-Demand and Spot vCPUs per instance class (`L-1216C47A` and friends) in `RunInstances`/`StartInstances` (`VcpuLimitExceeded`), Elastic IPs (`AddressLimitExceeded`), VPCs per Region (`VpcLimitExceeded`), rules per security group. |
| Other enforcement | ✅ | S3 buckets (`TooManyBuckets`), IAM roles and managed policies per role (`LimitExceeded`), Lambda concurrent executions (`PutFunctionConcurrency`, `GetAccountSettings`). Other quotas are reported but not enforced. |
| `AWS/Usage` metrics | ✅ | `ResourceCount` (EC2 vCPUs per class, Elastic IPs, VPCs, buckets, roles) once a minute on the emulated clock, `CallCount` for every API call (`Type=API`, `Resource=<operation>`). |
| `SERVICE_QUOTA()` | ✅ | In CloudWatch metric math, so `usage / SERVICE_QUOTA(usage) * 100` alarms fire as usage nears the quota. |
| Utilization reports | ✅ | Computed from current usage, sorted by utilization. |
| Automatic management | 🟡 | Start, update, stop and get are recorded; quotas are not raised automatically. |
| Tags | ✅ | On quotas, at most 50. |

See also: [all services](README.md) · [CloudWatch](cloudwatch.md).
