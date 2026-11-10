# MWS console

A web console for MWS covering 41 services with the AWS console's layout.
Each service is its own package (`services/<id>/`), and one Next.js app
(`apps/console`) mounts them all into a single server. See
[docs/dashboard.md](../docs/dashboard.md) for the architecture, design rules,
configuration and tests.

```sh
cargo run -p mws          # from the repository root
npm ci && npm run dev     # here (Node.js 22.12+); open http://localhost:3000
```

| Command | What it does |
| --- | --- |
| `npm run dev` | Mounts the service packages, watches them and starts `next dev` (port `MWS_DASHBOARD_PORT`, default 3000) |
| `npm run build && npm start` | Production build (about 20 seconds) and server |
| `npm run typecheck` | Type-checks every package |
| `npm test` | Playwright, one spec per service in `e2e/`, against a running MWS |
| `node scripts/icons.mjs` | Copies newly used AWS and brand icons into the console |

| Path | Contents |
| --- | --- |
| `apps/console` | The Next.js app: home, search, the control plane, `/api/resources` |
| `services/<id>` | One service's pages (`routes/`), helpers (`lib/`) and search inventory |
| `packages/ui` | Frame, components, fields and validation, pickers, policy editor, motion |
| `packages/aws` | Server-side SDK settings, `/_mws` calls, auto-created prerequisites |
| `packages/ai` | Embeddings for search and grouping |
| `scripts` | Mounting and isolation checks, Smithy constraints, icons |
| `e2e` | Playwright specs |
