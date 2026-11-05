# AWS Amplify Hosting

> Crate: [`mws-amplify`](../../crates/services/mws-amplify) · Tests: [`tests/e2e-rust/tests/e2e/amplify.rs`](../../tests/e2e-rust/tests/e2e/amplify.rs)

All 37 operations are generated from the AWS model (restJson1) and implemented. Deployments are really served: a branch's site answers HTTP requests on MWS's own endpoint.

✅ supported · 🟡 partial · ❌ not supported

## Apps and branches

| Feature | Status | Details |
| --- | :---: | --- |
| Apps | ✅ | App ids like Amplify's (`d` and 13 characters), `<appId>.amplifyapp.com` default domains, platforms, environment variables, build specs, cache and job configs, the default `/<*>` → `/index.html` (`404-200`) rule, the production branch. |
| Branches | ✅ | Stages, display names (`feature/x` serves as `feature-x`), environment variables, build specs, basic auth, backends, at most 50 per app, `NotFoundException`/`BadRequestException` as Amplify answers them. |
| Backend environments | ✅ | Create, get, list (by name), delete. |
| Webhooks | ✅ | Webhook URLs in Amplify's format. `POST <endpoint>/prod/webhooks?id=...&token=...` (the URL's path and query on MWS's endpoint) starts a `WEB_HOOK` build of the branch. |
| Tags | ✅ | On apps and branches, with `aws:RequestTag`, `aws:ResourceTag` and `aws:TagKeys` conditions. |
| Auto branch creation | 🟡 | Settings are kept; branches are not created from repository pushes. |
| Pull request previews | 🟡 | Settings are kept; no previews are built. |

## Deployments and builds

| Feature | Status | Details |
| --- | :---: | --- |
| Manual deployments | ✅ | `CreateDeployment` hands out upload URLs on MWS (`PUT` the zip, or each file of a `fileMap`; files with the MD5 of the current deployment need no upload), `StartDeployment` deploys them. |
| Deploying from S3 | ✅ | `sourceUrl` `s3://bucket/key.zip` (`ZIP`) or `s3://bucket/prefix/` (`BUCKET_PREFIX`), read as `amplify.amazonaws.com`: the bucket policy must allow `s3:GetObject` (and `s3:ListBucket` for prefixes), with `aws:SourceAccount`/`aws:SourceArn` (the branch ARN). |
| Deploying from a URL | ✅ | Any `http(s)://` URL of a zip, such as a presigned S3 URL. |
| Repository builds | ✅ | `StartJob` (`RELEASE`, `RETRY` of the same commit, `MANUAL`, `WEB_HOOK`) clones the repository with `git` (HTTPS with the access token, or a local path), runs the branch's, app's or repository's `amplify.yml` phases (backend, then frontend `preBuild`/`build`/`postBuild`; `applications` with `appRoot` for monorepos) with `bash`, and deploys `artifacts.baseDirectory`/`files`. Builds see the app and branch environment variables plus `AWS_APP_ID`, `AWS_BRANCH`, `AWS_JOB_ID`, `AWS_COMMIT_ID` and `AWS_ENDPOINT_URL`. One job runs at a time per branch; 30-minute timeout. |
| Jobs | ✅ | `PENDING` → `RUNNING` → `SUCCEED`/`FAILED`, `BUILD`/`DEPLOY`/`VERIFY` steps with logs behind `logUrl`, `StopJob` (`CANCELLING` → `CANCELLED`, the build process is killed), `DeleteJob` for finished jobs, newest first in `ListJobs`. |
| Artifacts | ✅ | Each build's deployed files as `artifacts.zip`; `GetArtifactUrl` links to it for an hour. |
| Build containers | 🟡 | Builds run on the host with its tools, not in Amplify's build image. |
| SSR (`WEB_COMPUTE`) | ❌ | Compute (server-side rendering) apps are kept but served as static files. |

## Hosting

| Feature | Status | Details |
| --- | :---: | --- |
| Branch sites | ✅ | Served when the request's `Host` is `<branch>.<appId>.amplifyapp.<anything>` (so `http://main.<appId>.amplifyapp.localhost:4566/` opens in a browser), and at `<endpoint>/_aws/amplify/sites/<appId>/<branch>/<path>`. `index.html` for directories, `301` to add a trailing slash, content types, ETags and `304`s, `HEAD`. |
| Rewrites and redirects | ✅ | `customRules` in order: `301`/`302` redirects, `200` rewrites (to a path, or proxied to an external URL), `404` and `404-200` when the file does not exist; `<*>` and `<placeholder>` sources and targets, full-URL sources, `</regex/>` sources (lookahead works, so the usual single-page-app rule does). |
| Country conditions | ❌ | Rules with a `condition` never match: a local request has no country. |
| Basic auth | ✅ | Branch credentials, else the app's; `401` with `WWW-Authenticate: Basic`. |
| Custom headers | ✅ | The app's `customHeaders` YAML, or `customHttp.yml` from a repository build, by glob pattern. |
| Access logs | ✅ | `GenerateAccessLogs` returns a link to CSV logs (CloudFront's columns) of the requests a domain served in the time range. |
| Skew protection, performance mode, WAF | 🟡 | Settings are kept; they change nothing. |

## Custom domains

| Feature | Status | Details |
| --- | :---: | --- |
| Domain associations | ✅ | Subdomains map to branches; `customDomains` on branches; one app per domain; Amplify-managed or custom (us-east-1 ACM) certificates. |
| Verification through Route 53 | ✅ | The managed certificate's validation CNAME, then each subdomain's CNAME to the app's distribution: `PENDING_VERIFICATION` → `AWAITING_APP_CNAME` → `AVAILABLE`. When the caller's account has a public hosted zone for the domain, Amplify writes those records itself; otherwise they can be created in any public zone. |
| Serving custom domains | ✅ | A request whose `Host` is an associated subdomain serves its branch. |
| Auto subdomains | 🟡 | Settings are kept; no subdomains are created for new branches. |

See also: [all services](README.md) · [authentication and authorization](../security.md).
