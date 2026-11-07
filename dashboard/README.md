# MWS console

A web console for MWS, built as Next.js multi-zone microfrontends: a shell
app plus one app per group of services, stitched into one site by the
shell's rewrites. See [docs/dashboard.md](../docs/dashboard.md) for the
architecture, configuration and tests.

```sh
cargo run -p mws          # from the repository root
npm ci && npm run dev     # here; open http://localhost:3000
```
