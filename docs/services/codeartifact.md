# AWS CodeArtifact

> Crate: [`mws-codeartifact`](../../crates/services/mws-codeartifact) · Tests: [`tests/e2e-rust/tests/e2e/codeartifact.rs`](../../tests/e2e-rust/tests/e2e/codeartifact.rs)

All 48 operations, generated from the AWS model (restJson1), plus repository
endpoints for every package format: `npm`, `pip`/`twine`, Maven/Gradle,
`cargo`, `gem`/Bundler, NuGet and Swift clients publish to and install from
them.

## Control plane

| Feature | Status | Details |
| --- | --- | --- |
| Domains | ✅ | Create, describe, list, delete (refused while repositories exist), KMS encryption key (`aws/codeartifact` by default; a customer managed key must exist, be an enabled symmetric key, and allow the caller `kms:DescribeKey` and `kms:CreateGrant`), repository count and asset size |
| Repositories | ✅ | Upstreams in priority order (must exist, at most 10, `codeartifact:AssociateWithDownstreamRepository` on each), descriptions, `ListRepositories`/`ListRepositoriesInDomain` with prefixes, deletion refused while another repository uses it as an upstream |
| External connections | ✅ | Every `public:*` connection, one per repository, each really fetching from its registry (see below) |
| Permissions policies | ✅ | Domain and repository policies, evaluated with IAM on every call (cross-account domains via `domainOwner`), `policyRevision` checks |
| Authorization tokens | ✅ | `GetAuthorizationToken` also needs `sts:GetServiceBearerToken` (`sts:AWSServiceName`), 900 to 43,200 seconds or `0` for the session's lifetime, never outliving the caller's credentials |
| Packages and versions | ✅ | List and describe, statuses (`Published`, `Unfinished`, `Unlisted`, `Archived`, `Disposed`), `UpdatePackageVersionsStatus`/`Delete`/`Dispose` with per-version `failedVersions` (`NOT_FOUND`, `MISMATCHED_STATUS`, `MISMATCHED_REVISION`, ...), revisions, origins (`INTERNAL`/`EXTERNAL` and the domain entry point) |
| `CopyPackageVersions` | ✅ | `versions` or `versionRevisions`, `allowOverwrite`, `includeFromUpstream` |
| Assets, readmes, dependencies | ✅ | `ListPackageVersionAssets` with MD5/SHA-1/SHA-256/SHA-512, `GetPackageVersionAsset`, readmes and dependencies from npm manifests, PyPI metadata, POMs, Cargo publish metadata, gemspecs, `.nuspec` files and Swift release metadata |
| Generic packages | ✅ | `PublishPackageVersion` with SHA-256 check and `unfinished` |
| Package origin controls | ✅ | `PutPackageOriginConfiguration`; published packages default to publish `ALLOW`/upstream `BLOCK`, packages from upstreams to the reverse |
| Package groups | ✅ | Pattern syntax (`$`, `~`, `*`), most-specific association, weak matches (case and separator variants) blocked, parents and sub-groups, `INHERIT` and `ALLOW_SPECIFIC_REPOSITORIES` for `PUBLISH`, `INTERNAL_UPSTREAM` and `EXTERNAL_UPSTREAM` |
| Tags | ✅ | Domains, repositories and package groups, with `aws:RequestTag`/`aws:ResourceTag` conditions |

## Repository endpoints

`GetRepositoryEndpoint` returns
`<endpoint>/_aws/codeartifact/<region>/<domain>-<owner>/<format>/<repo>/`. The
AWS host (`<domain>-<owner>.d.codeartifact.<region>.amazonaws.com`) is served
too, for clients whose resolver points it at MWS. Requests authenticate with an
authorization token, as `Bearer` (npm, Cargo), as the basic-auth password of user
`aws` (pip, twine, Maven, Gradle, Bundler, NuGet, Swift) or as the whole
`Authorization` header (`gem push` with `GEM_HOST_API_KEY`); unauthenticated requests get `401` with a
`Basic` challenge. They act as the token's principal: reads need
`codeartifact:ReadFromRepository`, publishing `codeartifact:PublishPackageVersion`
on the package, with the repository policy.

| Format | Status | Details |
| --- | --- | --- |
| npm | ✅ | Packuments (merged across upstreams and the external connection), tarballs, `npm publish`, dist-tags, `npm ping`/`whoami` |
| PyPI | ✅ | Simple API (PEP 503) index and downloads, twine uploads (`multipart/form-data`, SHA-256 checked), name normalization |
| Maven | ✅ | Deploy and resolve, checksums, generated `maven-metadata.xml`; versions stay `Unfinished` until the artifact's metadata lists them; SNAPSHOT versions take new files |
| Cargo | ✅ | Sparse index (`sparse+<endpoint>`, `auth-required`), `cargo publish`, downloads, `cargo yank`/`--undo` (`Unlisted`), search |
| RubyGems | ✅ | Compact index (`versions`, `info/<gem>`, `names`) for Bundler and `gem`, `.gem` downloads, `gem push` (metadata from the gem's spec), platform gems |
| NuGet | ✅ | V3 service index, package base address (versions, `.nupkg`, `.nuspec`), registrations, search, push (`PUT api/v2/package`), `dotnet nuget delete` unlists |
| Swift | ✅ | SE-0292 registry: release lists, release metadata with checksums, `Package.swift` and `Package@swift-*.swift` manifests, archives with `Digest`, identifier lookup by repository URL, publishing (`swift package-registry publish`) |
| Upstreams | ✅ | Searched depth-first in priority order; versions fetched through upstreams are kept in each repository on the way |
| External connections | ✅ | Each connection fetches from its public registry (npmjs, PyPI, the Maven repositories, `index.crates.io`, `api.nuget.org`, `rubygems.org`), or `MWS_CODEARTIFACT_<NAME>_URL` (for example a local Verdaccio) |

## Known gaps

- npm `unpublish`, `npm audit` and `gem yank` (CodeArtifact supports none of them).
- Assets are stored in MWS state, not encrypted with the domain's KMS key.
- The external connection client does not go through an HTTP proxy.

See also: [all services](README.md) · [authentication and authorization](../security.md).
