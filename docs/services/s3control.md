# Amazon S3 Control

> Crate: [`mws-s3control`](../../crates/services/mws-s3control) · Tests: [`tests/e2e-rust/tests/e2e/s3_control_parity.rs`](../../tests/e2e-rust/tests/e2e/s3_control_parity.rs)

All 97 operations are generated from the AWS model (restXml, `{AccountId}.` host
prefix, `x-amz-account-id`).

## Behaviour

Implemented: access points (create, get, list, delete, VPC network origin, their
own Block Public Access, policies with `BlockPublicPolicy` checks, policy
status, tags), Object Lambda access points (create, get, list, delete,
transformation configurations, allowed features, policies, policy status) and
account-level Block Public Access, which S3 applies to every bucket of the
account. Batch Operations jobs run for real (one operation over every object of
a CSV, S3 Inventory or generated manifest, as the job's IAM role, with
confirmation and completion reports), Access Grants vend credentials scoped to
the grant through STS, multi-Region access points are managed (asynchronous
requests complete at once), Storage Lens dashboards (with the
`default-account-dashboard`) and Storage Lens groups are managed, and access
points for directory buckets are managed.

## Known gaps

The multi-Region access point data plane (`*.mrap` requests), data-plane scope
enforcement for directory bucket access points, and Outposts buckets.

See also: [all services](README.md) · [authentication and authorization](../security.md).
