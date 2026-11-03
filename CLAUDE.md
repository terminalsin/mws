# MWS working notes

Local, spec-faithful AWS emulator in Rust. Goal: unmodified AWS SDKs (endpoint
override only) see the same behaviour as real AWS. Fidelity beats breadth.

## Rules

- **Strict silos.** One crate per service under `crates/services/`. A service
  crate may depend on generic crates (`mws-core`, `mws-proto-*`, codegen) and,
  only where AWS itself couples them, on another service's public API (e.g.
  STS on IAM identities). Generic crates must never mention a specific service.
- **Wire layer is generated.** Each service vendors its official Smithy JSON
  model (from `aws/api-models-aws`) in `model/` and runs `mws-codegen` from
  `build.rs`. Don't hand-write request/response types; fix the generator.
- **Match AWS wording.** Error codes, HTTP statuses and messages should be what
  AWS returns. Validation messages come from the model's constraints.
- **Authorize in handlers.** Every handler calls `ctx.authorize("svc:Action",
  resource_arn, ...)` before acting, even while the authorizer allows all.
- **Prove it with real SDKs.** Behaviour changes get an E2E test in
  `tests/e2e-rust` (official Rust SDK) and, where useful, `tests/e2e-python`
  (boto3).

## Adding a service

1. Put the Smithy model in `crates/services/mws-<svc>/model/`.
2. Generate in `build.rs` with the protocol's codegen entry point (add a new
   `mws-proto-<protocol>` runtime + codegen module if the protocol is new).
3. Implement the generated `Handler` and `mws_core::Service`.
4. Register it in `crates/mws/src/lib.rs`.

## Checks

`cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
