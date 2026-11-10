# MWS console

A web console for MWS: one package per AWS service (`services/<id>/`),
mounted into a single Next.js app (`apps/console`) that serves them all. See [docs/dashboard.md](../docs/dashboard.md) for the
architecture, configuration and tests.

```sh
cargo run -p mws          # from the repository root
npm ci && npm run dev     # here; open http://localhost:3000
```
