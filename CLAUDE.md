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
  resource_arn, condition_keys)` before acting. The IAM authorizer reads IAM
  state, so in `mws-iam` never call it while holding the state lock.
  Resource policies: `authorize_with_resource_policy` when either the
  resource or identity policy may grant (bucket/CA policies),
  `authorize_with_required_resource_policy` when the resource policy must
  allow (KMS key policies).
- **Prove it with real SDKs.** Behaviour changes get an E2E test in
  `tests/e2e-rust/tests/e2e/` (official Rust SDK) and, where useful,
  `tests/e2e-python` (boto3). Add Rust tests as modules of `e2e/main.rs`,
  never as new files directly under `tests/`: every test binary links all
  the SDKs, which costs minutes of build and gigabytes of disk.

## Adding a service

1. Put the Smithy model in `crates/services/mws-<svc>/model/`.
2. Generate in `build.rs` with the protocol's codegen entry point (add a new
   `mws-proto-<protocol>` runtime + codegen module if the protocol is new).
   Protocols so far: `build_aws_query` (IAM, STS, SES v1), `build_rest_xml`
   (Route 53, S3), `build_rest_json` (Lambda, RAM, Connector for SCEP, SES v2,
   GuardDuty; honours `@jsonName`),
   `build_aws_json` (ACM PCA, KMS, CloudWatch Logs, SQS,
   Kinesis, Firehose, CloudWatch, Marketplace) and `build_ec2_query` (EC2; it takes
   the list of operations to generate, because all 811 take minutes to
   compile; the rest answer `NotImplemented`). Models with the `rpcv2Cbor` trait (CloudWatch, Marketplace Entitlement) also get
   `dispatch_cbor` from `build_aws_json` (runtime in `mws-proto-cbor`).
   `awsQueryCompatible` models (SQS, CloudWatch) also get an awsQuery codec
   (`build_aws_query_compatible`, or `build_aws_query` when the model
   names awsQuery itself) for the requests older SDKs still send. Pass the service's validation
   error code in the options (`InvalidInput`, `ValidationException`, ...).
   The restXml generator panics on bindings it does not support yet; extend
   it rather than working around it in the service.
3. Implement the generated `Handler` and `mws_core::Service`, including
   `invoke` (forward to `generated::invoke`, which lets scenario files call
   the service) and, if the service keeps state, `export_state`,
   `import_state` and `reset_state`. State types derive serde and use
   `#[serde(default)]` so older saved state still loads; maps with non-string
   keys need a custom (de)serializer.
4. Register it in `crates/mws/src/lib.rs`.

## Checks

`cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --all-targets`

On pull requests CI runs only what a change affects (`.github/scripts/plan.py`,
see docs/testing.md). It matches e2e modules to services by name, so name a
new module after its service crate (`<svc>.rs`, `<svc>_<topic>.rs`) or add an
alias in `MODULE_ALIASES`. Docker-backed tests run one at a time per runner
(`.config/nextest.toml`): put `docker` in the module or test name.
