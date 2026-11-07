# MWS documentation

## Guides

- [Getting started](getting-started.md): build, run, and point an SDK at MWS.
- [Configuration](configuration.md): every environment variable.
- [State, scenarios and snapshots](state.md): persistence, seed data, resets,
  the control API and the emulated clock.
- [Testing](testing.md): using MWS in your test suite, and running MWS's own
  tests.
- [Web console](dashboard.md): the Next.js dashboard for browsing and changing
  resources and driving the control plane.

## Reference

- [Services](services/README.md): what each emulated service does and its
  known gaps.
- [Authentication and authorization](security.md): SigV4, the IAM policy
  engine, federation and service-to-service access.
- [Architecture](architecture.md): request flow, code generation, protocols
  and the crate layout.

## Project

- [Contributing](../CONTRIBUTING.md): design rules, adding a service, and the
  checks every change must pass.
