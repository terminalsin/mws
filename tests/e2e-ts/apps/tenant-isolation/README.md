# tenant-isolation

Multi-tenant storage in one S3 bucket, isolated by IAM rather than by
application code.

- [`src/provision.ts`](src/provision.ts) creates the bucket, a backend IAM
  user that may only assume one role, and the role `tenant-data-access`. Its
  trust policy requires a `tenant` session tag, and its single ABAC policy
  allows `tenants/${aws:PrincipalTag/tenant}/*`.
- [`src/tenant-storage.ts`](src/tenant-storage.ts) gives each request an S3
  client whose credentials come from `fromTemporaryCredentials` with the
  tenant as a session tag.

The tests show tenants reading and listing their own files, IAM denying reads
and listings of another tenant's prefix, the assumed-role identity from
`GetCallerIdentity`, `AssumeRole` refused without a tag, and the backend
user having no direct data access.
