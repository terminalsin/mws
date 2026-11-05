# Amazon ECR

> Crate: [`mws-ecr`](../../crates/services/mws-ecr) · Tests: [`tests/e2e-rust/tests/e2e/ecr.rs`](../../tests/e2e-rust/tests/e2e/ecr.rs)

All 62 operations are generated from the AWS model (awsJson 1.1), and MWS
serves a real Docker registry (HTTP API v2, OCI distribution) on its own
address, so `docker login`, `docker push` and `docker pull` work with the
password from `GetAuthorizationToken`.

## Using Docker

```sh
export MWS_ECR_REGISTRY_HOST=localhost:4566   # repository URIs name MWS
aws ecr create-repository --repository-name team/app
aws ecr get-login-password | docker login -u AWS --password-stdin localhost:4566
docker push localhost:4566/team/app:v1
docker pull localhost:4566/team/app:v1
```

Docker treats `localhost` and `127.0.0.0/8` registries as insecure (plain
HTTP) by default. The registry runs every request as the caller who asked for
the password, with that caller's IAM, repository-policy and SCP permissions
(`ecr:BatchGetImage` to pull a manifest, `ecr:PutImage` to push one, and so
on). Without `MWS_ECR_REGISTRY_HOST`, repository URIs are AWS's
`<account>.dkr.ecr.<region>.amazonaws.com/<name>`; a `Host` of that form (via
DNS or `/etc/hosts`) selects that account and Region's registry. The variable
may contain `{account}` and `{region}`.

## Behaviour

Repositories with tag mutability (and exclusion filters), scan-on-push,
AES256 or KMS encryption (MWS KMS checks the key and the caller's
permissions), tags with ABAC conditions, and repository policies evaluated by
the IAM engine. Images are real OCI content: layers uploaded in parts through
the API (part ordering and size rules) or the registry (monolithic, chunked
and cross-repository mounts when `BLOB_MOUNTING` is enabled), and manifests
stored byte for byte: Docker schema 2, OCI image manifests and indexes,
multi-architecture lists (children must exist; `ImageReferencedByManifestList`)
and artifacts with `subject` (`ListImageReferrers` and the OCI referrers API).
`BatchGetImage` and pulls record `lastRecordedPullTime` unless the principal
is a registered pull-time update exclusion.

Lifecycle policies (`imageCountMoreThan`, `sinceImagePushed`,
`sinceImagePulled`, `sinceImageTransitioned`; expire or transition to the
archive storage class, claimed by rule priority) run on the emulated clock, as
do previews. `UpdateImageStorageClass` archives and restores images (restores
take 20 minutes; archived images can't be pulled). Replication rules copy
pushed images to other Regions and accounts (the destination's registry
policy must allow `ecr:ReplicateImage`), backfills copy existing ones, and
`DescribeImageReplicationStatus` reports each copy. Pull-through cache rules,
repository creation templates (`CREATE_ON_PUSH` creates repositories on first
push with the template's settings), registry policies, scanning
configurations, account settings and signing configurations are all stored
and validated. Image push, delete, scan and lifecycle events go to
EventBridge as `aws.ecr`.

## Known gaps

Pull-through cache rules don't fetch from the upstream registry, scans find
no vulnerabilities (there is no vulnerability database), images aren't signed
(AWS Signer isn't emulated, so matching pushes report signing `FAILED`), and
`_catalog` answers `UNSUPPORTED`, as in AWS. On a plain `localhost` address
the registry challenges with `Bearer` (Docker then fetches a token from
`/_registry/token`), where AWS uses `Basic`.

See also: [ECR Public](ecr-public.md) · [all services](README.md) · [authentication and authorization](../security.md).
