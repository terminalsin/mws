# Amazon ECR Public

> Crate: [`mws-ecr-public`](../../crates/services/mws-ecr-public) · Tests: [`tests/e2e-rust/tests/e2e/ecr_public.rs`](../../tests/e2e-rust/tests/e2e/ecr_public.rs)

All 23 operations are generated from the AWS model (awsJson 1.1). Each
account has one public registry with a default alias, served as a real Docker
registry under `/v2/public.ecr.aws/<alias>/` on MWS's address.

## Using Docker

```sh
export MWS_ECR_PUBLIC_REGISTRY_HOST=localhost:4566/public.ecr.aws
aws ecr-public create-repository --repository-name tools --region us-east-1
aws ecr-public get-login-password --region us-east-1 | docker login -u AWS --password-stdin localhost:4566
docker push localhost:4566/public.ecr.aws/<alias>/tools:v1
docker logout localhost:4566
docker pull localhost:4566/public.ecr.aws/<alias>/tools:v1   # anonymous
```

Pulls need no credentials, as on `public.ecr.aws`; pushes run as the caller
who asked for the password, with `ecr-public:*` permissions checked by IAM and
the repository policy. The alias is in `DescribeRegistries`. Without
`MWS_ECR_PUBLIC_REGISTRY_HOST`, repository URIs name `public.ecr.aws`.

## Behaviour

Registries with display names (`PutRegistryCatalogData`), repositories with
catalog data (description, architectures and operating systems from AWS's
allowed values, about and usage text, PNG or JPEG logos served at
`logoUrl`), tags, repository policies, and images uploaded through the layer
API or pushed with Docker, with `DescribeImages`, `DescribeImageTags` and
`BatchDeleteImage` (removing one of several tags only untags).
`GetAuthorizationToken` requires `ecr-public:GetAuthorizationToken` and
`sts:GetServiceBearerToken`.

## Known gaps

Registry verification and custom aliases (`verified` is always false), and
Marketplace certification.

See also: [ECR](ecr.md) · [all services](README.md) · [authentication and authorization](../security.md).
