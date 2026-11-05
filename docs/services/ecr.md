# Amazon ECR

> Crate: [`mws-ecr`](../../crates/services/mws-ecr) · Tests: [`tests/e2e-rust/tests/e2e/ecr.rs`](../../tests/e2e-rust/tests/e2e/ecr.rs)

All 62 operations are generated from the AWS model (awsJson1.1) and implemented. MWS also serves a real Docker registry (HTTP API v2 and the OCI distribution spec, from the generic [`mws-oci`](../../crates/mws-oci) crate) on its own address, so `docker login`, `docker push` and `docker pull` work with the password from `GetAuthorizationToken`.

✅ supported · 🟡 partial · ❌ not supported

## Using Docker

```sh
export MWS_ECR_REGISTRY_HOST=localhost:4566   # repository URIs name MWS
aws ecr create-repository --repository-name team/app
aws ecr get-login-password | docker login -u AWS --password-stdin localhost:4566
docker push localhost:4566/team/app:v1
docker pull localhost:4566/team/app:v1
```

Docker talks plain HTTP to `localhost` and `127.0.0.0/8` registries by default. Without `MWS_ECR_REGISTRY_HOST`, repository URIs are AWS's `<account>.dkr.ecr.<region>.amazonaws.com/<name>`; a `Host` of that form (through DNS or `/etc/hosts`) selects that account's and Region's registry.

## Registry endpoint

| Feature | Status | Details |
| --- | :---: | --- |
| `docker login` | ✅ | The `GetAuthorizationToken` password as Basic credentials, or exchanged at `/_registry/token` (GET with Basic, or the OAuth2 password grant Docker POSTs). Passwords last 12 hours. |
| Authorization | ✅ | Each request runs as the caller who asked for the password, with IAM, repository policies and SCPs: `ecr:BatchGetImage` to read a manifest, `ecr:GetDownloadUrlForLayer` for a blob, `ecr:PutImage` to push a manifest, and so on. |
| Pushes | ✅ | Monolithic, chunked (`Content-Range`) and resumable uploads; cross-repository mounts when the `BLOB_MOUNTING` account setting is `ENABLED`. |
| Pulls | ✅ | Manifests by tag or digest (with `Docker-Content-Digest`), blobs with `Range`, `tags/list` with pagination, the OCI referrers API. |
| Create on push | ✅ | A `CREATE_ON_PUSH` creation template creates the repository on first push, with the template's settings. |
| `_catalog` | ❌ | Answers `UNSUPPORTED`, as in AWS. |
| Challenge scheme | 🟡 | On a plain `localhost` address the registry challenges with `Bearer` (Docker then fetches a token); AWS uses `Basic`. |

## Repositories and images

| Feature | Status | Details |
| --- | :---: | --- |
| Repositories | ✅ | Name validation, tag mutability with exclusion filters, scan-on-push, tags with ABAC conditions, `force` deletes. |
| Encryption | ✅ | AES256, or KMS keys from MWS KMS (the caller's permissions on the key are checked; `aws/ecr` is created on first use). |
| Layers | ✅ | `InitiateLayerUpload`, `UploadLayerPart` (ordered parts, size rules), `CompleteLayerUpload` (digest checks), `BatchCheckLayerAvailability`, and `GetDownloadUrlForLayer` links that expire. |
| Manifests | ✅ | Stored byte for byte: Docker schema 2 and manifest lists, OCI manifests and indexes (children must exist; `ImageReferencedByManifestList`), media type and digest checks, immutable tags. |
| Artifacts | ✅ | Manifests with `subject` and `artifactType`; `ListImageReferrers` with filters. |
| Pull times | ✅ | `BatchGetImage` and pulls record `lastRecordedPullTime`, except for principals registered as pull-time update exclusions. |
| Storage classes | ✅ | `UpdateImageStorageClass` archives images (they can't be pulled) and restores them in 20 minutes on the emulated clock. |
| Scans | 🟡 | Basic scans (on push or `StartImageScan`, once a day) complete with no findings: there is no vulnerability database. Enhanced scanning is stored only. |
| Signing | 🟡 | Signing configurations are stored and validated; images that match a rule report signing `FAILED`, since AWS Signer isn't emulated. |

## Registry

| Feature | Status | Details |
| --- | :---: | --- |
| Lifecycle policies | ✅ | `imageCountMoreThan`, `sinceImagePushed`, `sinceImagePulled` and `sinceImageTransitioned`; expire or transition to the archive class, claimed by rule priority; run on the emulated clock, and previews. |
| Replication | ✅ | Rules copy pushed images to other Regions and accounts (the destination's registry policy must allow `ecr:ReplicateImage`); backfills copy existing images; `DescribeImageReplicationStatus`. |
| Registry policies and settings | ✅ | Registry policies, scanning configuration, account settings (`BASIC_SCAN_TYPE_VERSION`, `REGISTRY_POLICY_SCOPE`, `BLOB_MOUNTING`). |
| Creation templates | ✅ | Prefix matching (longest first, then `ROOT`) for `CREATE_ON_PUSH`, `REPLICATION` and `PULL_THROUGH_CACHE`. |
| Pull-through cache rules | 🟡 | Stored and validated; images are not fetched from the upstream registry. |
| Events | ✅ | Image push, delete, scan and lifecycle actions go to EventBridge as `aws.ecr`. |

See also: [ECR Public](ecr-public.md) · [all services](README.md) · [authentication and authorization](../security.md).
