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

## Architecture: one app, a package per service

Every AWS service's pages are their own workspace package under
[`services/<id>/`](../dashboard/services) (`@mws-dashboard/service-<id>`), and
one [Next.js](https://nextjs.org) app, [`apps/console`](../dashboard/apps/console),
serves all of them from a single server on port 3000. The console app itself
owns only home (`/`), search and the control plane (`/control`).

A service package holds:

- `routes/`: its pages, laid out like the URLs they serve.
  `services/s3/routes/s3/[bucket]/page.tsx` is `/s3/<bucket>`; CloudWatch
  owns `/logs`, `/alarms` and `/metrics`; API routes go under
  `routes/api/<id>/` (S3's downloads are `/api/s3/object`).
- `lib/`: its SDK clients and helpers.
- `inventory.ts` (optional): the resources it contributes to search and the
  home page, each with a service id, type, name, link, optional tags and an
  optional *signal* (an alarm firing, a key or secret pending deletion, a
  dead-letter queue filling up).
- `package.json`: the SDK clients it uses, and nothing from another service.

Next.js only serves routes from the app's own `app/` folder, so
[`scripts/services.mjs`](../dashboard/scripts/services.mjs) mounts the
packages: for every route file it writes a one-line re-export into
`apps/console/app/(services)/` (git-ignored; route segment options such as
`dynamic` are copied, since Next.js reads them statically), gives every
service folder its own error boundary so a failing page stays inside its
service, and writes the inventory registry the home page reads. `npm run dev`,
`build` and `typecheck` run it first, and `npm run dev` keeps re-running it as
routes are added or removed.

The same script enforces the isolation and fails the build when a service
breaks it: a service may import its own files, the npm packages its
`package.json` declares and the shared packages below, never another service
(link to another service's pages by URL instead), and two services may not
claim the same URL.

The shared packages:

- `@mws-dashboard/ui`: the frame (sidebar, toolbar with search and region),
  components and styles, and the service catalog (`src/catalog.ts`): every
  service's name, category, official icon, landing path and sidebar sections.
  The sidebar and Services menu are built from it.
- `@mws-dashboard/aws`: server-side helpers: SDK client settings (endpoint,
  credentials, the region from the `mws-region` cookie), calls to `/_mws` and
  `/_aws`, and the wrapper that turns server actions into results.
- `@mws-dashboard/ai`: embeddings and what the console builds on them (see
  [Curation](#curation)).

Pages are React Server Components that call the SDK on the server; changes
are server actions, so no credentials reach the browser. Because everything is
one app, links between services navigate on the client and the frame never
reloads.

Earlier versions ran ten Next.js servers (multi-zones) with services grouped
into them. One server per service would have meant 41 dev servers of a few
hundred MB each; compiling the packages into one app gives the same code
isolation with one dev server and a production build of about 20 seconds.

### Adding a page or a service

- A page: add it under the service's `routes/`. `npm run dev` mounts it.
- A service: create `services/<id>/` with a `package.json` named
  `@mws-dashboard/service-<id>` (copy one), its `routes/` and, if it has
  resources worth searching, an `inventory.ts` exporting `inventory`, an array
  of functions returning `InventoryItem[]`. Give it a `path` (and `nav`) in the
  catalog, which puts it in the sidebar, then `npm install` to link it.

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

### Form validation and repairs

Fields validate in place, and say how to fix what they reject. `Field`
(`packages/ui`) checks its control against one merged rule:

1. the operation's Smithy constraints, generated from the models MWS serves
   (`scripts/constraints.mjs` writes `packages/ui/src/model/<model>.ts`,
   git-ignored, on every build, type check and dev start):
   `import { CreateFunction } from "@mws-dashboard/ui/model/lambda"`, then
   `<Field rule={CreateFunction.FunctionName}>`;
2. the control's own attributes (`required`, `maxLength`, `min`, `type`...);
3. what the page adds: `format` (`json`, `yaml` (YAML or JSON documents),
   `keyvalue` (one `Key=value` per line), `policy`, `path`, `arn`, `cidr`,
   `ipv4`, `email`, `emails` (a comma-separated list), `domain`,
   `email-or-domain`, `url`, `s3url`, `bucket`, `name`, `port`, `phone`,
   `tags` for `key=value` lines, `branch` for Git branch names), `taken` (names that exist), `reserved`
   (prefixes AWS keeps, offered without them),
   `known` (values the field usually points at), `generate` (`name`,
   `token`, `password`, `uuid`, or a prefix/suffix), `arn` (the ARN template
   a bare name expands to) and `hint` (a readable pattern message).

A problem replaces the field's hint once the person leaves the field or
submits, and comes with repairs as chips: a fix (reshaped to the pattern,
shortened, clamped, network address, repaired JSON, a policy document
rebuilt from a bare statement with its casing fixed, `https://` added, a phone number in E.164, an SSH remote as
its HTTPS URL, the scheme a pattern requires, a Git-safe branch name), a
suggestion ("did you mean" among enum values, `known` values, all of them
when there are only a few, or common email domains) or a generated value. Every repair is checked against the whole rule
before it is offered. A blocked submit focuses and shakes the first field.

Errors MWS returns land on their field too: `act` turns AWS validation
messages (`Value 'x' at 'roleName' failed to satisfy constraint: ...`) back
into rules, so a backend rejection gets the same repairs; "already exists"
errors land on the field marked `unique` with the next free name; anything
else is mapped with `act(run, { revalidate, fields: { QueueName: "name",
NoSuchEntityException: "role" } })` (error codes as the JS SDK names them, `e.name`), and `throw new FieldError(field, message)` targets
a field directly; its optional `repairs` carry fixes only the action can work
out (CloudFormation's template errors offer the closest logical id, resource
type or section, see `services/cloudformation/lib/repairs.ts`). Only issues no field claims show under the form. All of
this lives in the console (`validation.ts`, `fields.tsx`); MWS itself only
returns what AWS returns. SQS's create-queue sheet is the reference use.

## Design

The layout is the AWS console's: a top bar (Services menu, search,
account, region), a per-service sidebar with the same sections AWS has
(`nav` in `packages/ui/src/catalog.ts`, e.g. IAM: Users, Roles, Groups,
Policies), the other services of its category below it, and AWS's tab names on detail
pages. The look follows IBM's [Carbon](https://carbondesignsystem.com): IBM
Plex type, the Gray 10 / Gray 100 themes with Blue 60 for interaction, square
corners, flat layers separated by 1px rules, line tabs, bottom-border fields
and left-aligned buttons. Styles are [Tailwind CSS](https://tailwindcss.com)
v4 (`packages/ui/src/styles.css`): the Carbon tokens are theme variables, so
pages can use utilities such as `bg-layer` or `text-secondary`, and the shared
components are classes composed with `@apply`. The console's
`postcss.config.mjs` runs Tailwind. Rules the pages keep to:

- **Show, don't label.** If something can be an icon, it is one; self-evident
  things are not described; facts nobody acts on are left out (an empty
  value is not shown as a dash, it is not shown).
- **Real icons and logos.** Services and resources use the official AWS
  Architecture Icons (the [`aws-icons`](https://www.npmjs.com/package/aws-icons)
  package); runtimes and operating systems use their own logos
  ([`simple-icons`](https://simpleicons.org)). `node scripts/icons.mjs` copies
  every icon the source mentions (`"service/…"`, `"resource/…"`,
  `"category/…"`, `"brand/…"`) into the console's `public/icons`; run it after using a new icon.
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
  counting to a new value, a toast's remaining time. Moving between services
  keeps the top bar and sidebar still.
  `prefers-reduced-motion` turns all of it off.
- **Recipes, not improvisation.** Timings and curves follow
  [transitions.dev](https://transitions.dev): one smooth-out curve
  (`cubic-bezier(0.22, 1, 0.36, 1)`) for surfaces, ease-in-out for swaps,
  durations by role (`--duration-quick` 150ms for closing, `--duration-fast`
  250ms for swaps and the tab indicator, `--duration-emphasis` 500ms for the
  success check), closing quicker than opening. Pieces live in
  `packages/ui/src/motion.tsx` (`Segments` with a sliding indicator that moves
  on the click, `CountUp` whose changed digits swap in place, `CheckMark`,
  `Asciify`) and `loaders.tsx` (`DotMatrix`, 4×4 dot loaders whose pattern
  names the wait: `scan` for search, `orbit` for a running command, `pulse`
  for an answer, `twinkle` for a listing). States reserve their space, so a
  button keeps its width from label to spinner to check, and anything that can
  reverse (dialogs, menus, disclosures) uses transitions, which turn around
  from where they are. Image previews (S3 objects, instance files) carry an
  ASCII lens under the pointer (`Asciify`, after canvasui.dev's), which runs
  only while someone points at the image.

## Curation

Long lists are grouped by what the resources are rather than shown flat:

- **Search** (⌘K and `/search`) ranks every service's inventory by meaning and
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
| `MWS_ENDPOINT` | `http://127.0.0.1:4566` | every page (SDK calls and `/_mws`) |
| `MWS_REGION` | `us-east-1` | the region until one is picked in the top bar |
| `MWS_ACCESS_KEY_ID`, `MWS_SECRET_ACCESS_KEY`, `MWS_SESSION_TOKEN` | the root user | who the console calls MWS as |
| `MWS_DASHBOARD_PORT` | `3000` | `npm run dev` / `npm start`: the console's port |
| `MWS_DASHBOARD_ORIGINS` | none | extra `host:port` origins allowed to send server actions (when a proxy serves the console under another host) |

Calling as a less privileged identity shows what that identity may see:
point `MWS_ACCESS_KEY_ID` and `MWS_SECRET_ACCESS_KEY` at an IAM user's keys
and pages show MWS's `AccessDenied` messages where the policy says no.

## Tests

[`dashboard/e2e`](../dashboard/e2e) drives the built console with
[Playwright](https://playwright.dev) against a running MWS: one spec per service (`e2e/<id>.spec.ts`, plus
`console.spec.ts` for home, search and the frame),
each creating resources with unique names through the UI (and seeding with the
SDK only what the UI cannot create, such as Lambda code that logs or metric
data). `npm test -w @mws-dashboard/ai` runs the unit tests of the curation
code.

```sh
cargo run -p mws &
cd dashboard && npm ci && npm run build
npx playwright install chromium
npm test                      # starts the console with scripts/console.mjs
```

`npm run typecheck` type-checks every package. CI runs the `dashboard` job
whenever `dashboard/` or any crate changes.
