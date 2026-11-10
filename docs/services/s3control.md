# Amazon S3 Control

> Crate: [`mws-s3control`](../../crates/services/mws-s3control) · Tests: [`tests/e2e-rust/tests/e2e/s3_control_parity.rs`](../../tests/e2e-rust/tests/e2e/s3_control_parity.rs)

All 97 operations are generated from the AWS model (restXml, `{AccountId}.` host prefix, `x-amz-account-id`), and 79 are implemented; the 18 S3 on Outposts bucket operations (`CreateBucket`, `GetBucket`, `ListRegionalBuckets`, `PutBucketPolicy`, ...) answer `NotImplemented`.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Access points | ✅ | Create, get, list and delete, VPC network origins, their own Block Public Access, policies with `BlockPublicPolicy` checks, policy status and tags. S3 serves data through them. |
| Object Lambda access points | ✅ | Transformation configurations, allowed features, policies and policy status. |
| Account Block Public Access | ✅ | Applied by S3 to every bucket of the account. |
| Batch Operations | ✅ | Jobs run one operation over every object of a CSV, S3 Inventory or generated manifest, as the job's IAM role, with confirmation and completion reports. |
| Access Grants | ✅ | Instances, locations and grants; `GetDataAccess` vends temporary credentials scoped to the grant through STS. |
| Multi-Region access points | 🟡 | Managed (asynchronous requests complete at once), but the data plane (`*.mrap` requests) is not served. |
| Storage Lens | ✅ | Dashboards (including the `default-account-dashboard`) and Storage Lens groups. |
| Directory bucket access points | 🟡 | Managed, but their scope is not enforced on data requests. |
| Outposts buckets | ❌ | Not supported. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
