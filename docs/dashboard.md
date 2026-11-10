# Web console

[`dashboard/`](../dashboard) is a browser console for MWS: browse and change
resources across services, search everything from one box (⌘K), read what
SNS and SES "sent", and drive MWS's own control plane (clock, snapshots,
reset, state export). Every page reads live
state through the AWS SDK for JavaScript v3, signed with real credentials and
authorized by MWS's IAM engine, so the console sees exactly what your code
sees.

```sh
cargo run -p mws                       # in one terminal
cd dashboard && npm ci && npm run dev  # http://localhost:3000
```

For a production build, `npm run build && npm start`.

## Architecture: Next.js multi-zones

The console is ten [Next.js](https://nextjs.org) apps, each owning part of the
URL space. The **shell** serves `/` and `/control` and forwards every other
zone's base path to that zone's own server with rewrites, so the browser sees
one site while each zone builds, deploys and fails on its own.

| Zone | Base path | Port | Services |
| --- | --- | --- | --- |
| `shell` | `/` | 3000 | Home, search, control plane (`/_mws`) |
| `storage` | `/storage` | 3001 | S3 (objects, previews, presigned URLs, versioning, policy, tags) |
| `messaging` | `/messaging` | 3002 | SQS (DLQs, redrive), SNS (+ outbox), EventBridge (buses, rules), SES (+ outbox) |
| `security` | `/security` | 3003 | IAM (users, roles, groups, policies, access keys), KMS, Secrets Manager, Parameter Store |
| `compute` | `/compute` | 3004 | Lambda (create, invoke, edit code, configuration, triggers), EC2 (instances, images, key pairs, security groups) |
| `observability` | `/observability` | 3005 | CloudWatch Logs, alarms, metrics |
| `networking` | `/networking` | 3006 | VPC (resource map), Route 53, load balancers, Global Accelerator, ACM, Private CA |
| `data` | `/data` | 3007 | RDS, ElastiCache, ECR, ECS, EKS, EFS, Kinesis, Firehose |
| `governance` | `/governance` | 3008 | Organizations, CloudFormation, CloudTrail, Service Quotas, Cost Explorer, Security Hub, GuardDuty, Identity Center, RAM |
| `platform` | `/platform` | 3009 | Bedrock (model catalog, chat playground, guardrails, inference profiles, invocation logging, model providers), Amplify (apps, branches, deploys), CodeArtifact (repositories, packages, connection instructions), Image Builder, Auto Scaling, Marketplace (catalog, subscriptions, metering) |

The zones share two workspace packages and nothing else:

- `@mws-dashboard/ui`: the frame (sidebar, toolbar with search and region),
  components and styles; [`zones.json`](../dashboard/packages/ui/zones.json),
  which says which zone owns which base path and port (the shell's rewrites
  and `scripts/zones.mjs` read it); and the service catalog
  (`src/catalog.ts`): every service's name, category, official icon and, once
  it has pages, its zone and path. The sidebar is built from the catalog.
- `@mws-dashboard/aws`: server-side helpers: SDK client settings (endpoint,
  credentials, the region from the shared `mws-region` cookie), calls to
  `/_mws` and `/_aws`, and the wrapper that turns server actions into results.
- `@mws-dashboard/ai`: embeddings and what the console builds on them (see
  [Curation](#curation)).

Each zone depends only on the SDK clients of its own services. Pages are React
Server Components that call the SDK on the server; changes are server actions,
so no credentials reach the browser. Links inside a zone navigate on the
client; links to another zone load a new document from that zone.

Every zone also serves `<basePath>/api/inventory`: its resources as
`{items, errors}`, each item with a service id, type, name, link, optional
tags and an optional *signal* (an alarm firing, a key or secret pending
deletion, a dead-letter queue filling up). The shell reads these for search
and the home page, so it never calls another zone's services itself.

### Adding a page or a zone

- A page in an existing zone: add it under `apps/<zone>/app/`. A new service
  gets `zone` and `path` in the catalog, which puts it in the sidebar.
- A new zone: copy a zone app, give it a new base path and port in
  `zones.json`, and add it to `ZoneId` in `packages/ui/src/zones.ts`. The
  shell picks up the rewrite without changes. Serve `api/inventory` so the
  zone's resources are searchable.


Running EC2 instances and ECS task containers have Terminal, Files and Logs
tabs. The terminal runs one command at a time; `cd` carries over, and ↑/↓
walk the history. The file explorer can browse, preview text and images,
download, upload, create folders and delete. These tabs need the Docker
backends (see [EC2](services/ec2.md#terminal-and-files) and
[ECS](services/ecs.md#terminal-and-files)).

Create forms offer to make what a resource needs. A prerequisite field
(a service role, a destination bucket, a launch template, an infrastructure
configuration) has two modes: pick an existing one, or "create
automatically" (the sparkle button), which makes it on submit and reuses it
next time: `AmazonEKSClusterRole` and `AmazonEKSNodeRole` for EKS,
`<function>-role` for Lambda, a bucket and `KinesisFirehoseServiceRole-<stream>`
for Firehose, `aws-cloudtrail-logs-<account>-<region>` with CloudTrail's
bucket policy, `AmazonBedrockInvocationLoggingRole` and its log group, a
`<group>-template` launch template for Auto Scaling, and a `default`
Image Builder infrastructure configuration with
`EC2InstanceProfileForImageBuilder`. The field starts on "create" when
nothing suitable exists. Helpers live in `packages/aws/src/auto.ts`.

## Design

The layout is the AWS console's: a top bar (Services menu, search,
account, region), a per-service sidebar with the same sections AWS has
(`nav` in `packages/ui/src/catalog.ts`, e.g. IAM: Users, Roles, Groups,
Policies), the zone's other services below it, and AWS's tab names on detail
pages. The look follows IBM's [Carbon](https://carbondesignsystem.com): IBM
Plex type, the Gray 10 / Gray 100 themes with Blue 60 for interaction, square
corners, flat layers separated by 1px rules, line tabs, bottom-border fields
and left-aligned buttons. Styles are [Tailwind CSS](https://tailwindcss.com)
v4 (`packages/ui/src/styles.css`): the Carbon tokens are theme variables, so
zones can use utilities such as `bg-layer` or `text-secondary`, and the shared
components are classes composed with `@apply`. Each zone has a
`postcss.config.mjs` that runs Tailwind. Rules the pages keep to:

- **Show, don't label.** If something can be an icon, it is one; self-evident
  things are not described; facts nobody acts on are left out (an empty
  value is not shown as a dash, it is not shown).
- **Real icons and logos.** Services and resources use the official AWS
  Architecture Icons (the [`aws-icons`](https://www.npmjs.com/package/aws-icons)
  package); runtimes and operating systems use their own logos
  ([`simple-icons`](https://simpleicons.org)). `node scripts/icons.mjs` copies
  every icon the source mentions (`"service/…"`, `"resource/…"`,
  `"category/…"`, `"brand/…"`) into the shell's `public/icons`, where all
  zones load them; run it after using a new icon.
- **Signals first.** What needs attention (an alarm, a port open to the
  internet, a deletion pending) is shown in color with an icon, and gathered
  on the home page.
- **Every wait is visible, every change is felt.** Asynchronous UI runs on
  small state machines (`packages/ui/src/machine.ts`, `useMachine`), whose
  state is exposed as `data-state` for styles to animate: forms go
  idle → pending → succeeded/failed (spinner, a check that pops, a shake), the
  search palette debounces → loads → shows results, nothing or a failure,
  navigation runs a progress bar across the top, and toasts enter, wait
  (paused on hover) and leave. Every page has a `loading.tsx` that renders a
  `PageSkeleton` shaped like it (list, resource or home), so a click shows the
  next page's outline at once.
- **Motion only with a purpose** (Apple's rule). Content never animates in:
  pages, rows and charts appear as they are, and a skeleton is replaced in
  place, so a load is one transition, not a skeleton followed by staggered
  fades. Sheets, the search palette and the Services menu open at once and
  animate as they close. Controls morph between states (the submit button's
  spinner to a check, a deleting row fading back, a failed submit shaking).
  Motion that carries information stays: the progress bar, skeleton shimmer,
  a breathing dot on states still changing ("creating", "pending"), numbers
  counting to a new value, a toast's remaining time. Moving between zones
  keeps the top bar and sidebar still (cross-document view transitions).
  `prefers-reduced-motion` turns all of it off.

## Curation

Long lists are grouped by what the resources are rather than shown flat:

- **Search** (⌘K and `/search`) ranks every zone's inventory by meaning and
  words together (embeddings blended with keyword scores).
- **Sections** come from classifiers: buckets by purpose (logs, websites,
  artifacts, backups, data, media), roles by who may assume them (services,
  this account, other accounts, federated users), log groups by what writes
  them, secrets by what they unlock. Each class has a rule and a prototype;
  items no rule matches go to the class whose prototype they are closest to.
- **Applications** on the home page and the Lambda list group resources that
  belong together: by CloudFormation stack or `app`/`project` tags first, then
  by names that cluster.

Embeddings come from Bedrock, by default MWS's own, so everything works
offline and without keys. MWS's Bedrock echo backend returns deterministic
vectors from text features, which with the keyword blend and the rules gives
sensible groupings; for real semantics either run MWS with a model backend
(`MWS_BEDROCK_BACKEND`), point the console at real Bedrock, or use a local
model:

| `MWS_DASHBOARD_AI` | Embeddings from |
| --- | --- |
| `bedrock` (default) | Bedrock at `MWS_DASHBOARD_AI_ENDPOINT` (default: MWS), model `MWS_DASHBOARD_EMBED_MODEL` (default `amazon.titan-embed-text-v2:0`) |
| `aws` | real Amazon Bedrock with the default AWS credential chain, region `MWS_DASHBOARD_AI_REGION` |
| `local` | a local sentence-transformer through `@huggingface/transformers` (install it first; downloads the model once) |
| `lexical` | hashed word and character features, no model at all |

When the chosen source fails the console falls back to `lexical`.

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
SDK only what the UI cannot create, such as Lambda code that logs or metric
data). `npm test -w @mws-dashboard/ai` runs the unit tests of the curation
code.

```sh
cargo run -p mws &
cd dashboard && npm ci && npm run build
npx playwright install chromium
npm test                      # starts every zone with scripts/zones.mjs
```

`npm run typecheck` type-checks every package. CI runs the `dashboard` job
whenever `dashboard/` or any crate changes.
