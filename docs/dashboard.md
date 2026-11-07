# Web console

[`dashboard/`](../dashboard) is a browser console for MWS: browse and change
resources across services, read what SNS and SES "sent", and drive MWS's own
control plane (clock, snapshots, reset, state export). Every page reads live
state through the AWS SDK for JavaScript v3, signed with real credentials and
authorized by MWS's IAM engine, so the console sees exactly what your code
sees.

```sh
cargo run -p mws                       # in one terminal
cd dashboard && npm ci && npm run dev  # http://localhost:3000
```

For a production build, `npm run build && npm start`.

## Architecture: Next.js multi-zones

The console is six [Next.js](https://nextjs.org) apps, each owning part of the
URL space. The **shell** serves `/` and `/control` and forwards every other
zone's base path to that zone's own server with rewrites, so the browser sees
one site while each zone builds, deploys and fails on its own.

| Zone | Base path | Port | Services |
| --- | --- | --- | --- |
| `shell` | `/` | 3000 | Overview, control plane (`/_mws`) |
| `storage` | `/storage` | 3001 | S3 |
| `messaging` | `/messaging` | 3002 | SQS, SNS (+ outbox), EventBridge, SES (+ outbox) |
| `security` | `/security` | 3003 | IAM, KMS, Secrets Manager, SSM Parameter Store |
| `compute` | `/compute` | 3004 | Lambda (invoke with log tail), EC2 |
| `observability` | `/observability` | 3005 | CloudWatch Logs, alarms, metrics |

The zones share two workspace packages and nothing else:

- `@mws-dashboard/ui`: the frame (sidebar, top bar, region picker), components
  and styles, and [`zones.json`](../dashboard/packages/ui/zones.json), the
  contract that says which zone owns which base path, its port and its
  navigation entries. The shell's rewrites, `scripts/zones.mjs` and every
  sidebar read it.
- `@mws-dashboard/aws`: server-side helpers: SDK client settings (endpoint,
  credentials, the region from the shared `mws-region` cookie), calls to
  `/_mws` and `/_aws`, and the wrapper that turns server actions into results.

Each zone depends only on the SDK clients of its own services. Pages are React
Server Components that call the SDK on the server; changes are server actions,
so no credentials reach the browser. Links inside a zone navigate on the
client; links to another zone load a new document from that zone.

### Adding a page or a zone

- A page in an existing zone: add it under `apps/<zone>/app/` and, if it
  belongs in the sidebar, an entry in `zones.json`.
- A new zone: copy a zone app, give it a new base path and port in
  `zones.json`, and add it to `ZoneId` in `packages/ui/src/zones.ts`. The
  shell picks up the rewrite without changes.

## Configuration

| Variable | Default | Used by |
| --- | --- | --- |
| `MWS_ENDPOINT` | `http://127.0.0.1:4566` | every zone (SDK calls and `/_mws`) |
| `MWS_REGION` | `us-east-1` | the region until one is picked in the top bar |
| `MWS_ACCESS_KEY_ID`, `MWS_SECRET_ACCESS_KEY`, `MWS_SESSION_TOKEN` | the root user | who the console calls MWS as |
| `MWS_DASHBOARD_<ZONE>_URL` | `http://127.0.0.1:<port>` | the shell, at build time: where a zone runs |
| `MWS_DASHBOARD_ORIGINS` | none | extra `host:port` origins allowed to send server actions (when the shell is not on port 3000) |

Calling as a less privileged identity shows what that identity may see:
point `MWS_ACCESS_KEY_ID` and `MWS_SECRET_ACCESS_KEY` at an IAM user's keys
and pages show MWS's `AccessDenied` messages where the policy says no.

## Tests

[`dashboard/e2e`](../dashboard/e2e) drives the built console with
[Playwright](https://playwright.dev) against a running MWS: one spec per zone,
each creating resources with unique names through the UI (and seeding with the
SDK only what the UI cannot create, such as a Lambda deployment package).

```sh
cargo run -p mws &
cd dashboard && npm ci && npm run build
npx playwright install chromium
npm test                      # starts every zone with scripts/zones.mjs
```

`npm run typecheck` type-checks every package. CI runs the `dashboard` job
whenever `dashboard/` or any crate changes.
