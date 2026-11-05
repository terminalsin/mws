# Contributing to MWS

Thank you for your interest in improving MWS. The project's single goal is
that unmodified AWS SDKs, with only the endpoint overridden, see the same
behaviour as real AWS. The most valuable contributions are the ones that close
a gap between the two.

## Reporting a difference from AWS

The best bug report shows a request and two responses: what AWS returns and
what MWS returns. Include the SDK and its version, the operation, and, where
you can, the HTTP status, error code and message from both. A failing SDK
test (see [Testing](docs/testing.md)) is even better.

## Design rules

These rules keep the codebase consistent. Pull requests are reviewed against
them.

- **Fidelity beats breadth.** Implement an operation the way AWS behaves, or
  leave it answering `NotImplemented`. Don't ship approximate behaviour
  silently; if a simplification is unavoidable, document it on the service's
  page under [docs/services](docs/services).
- **Strict silos.** One crate per service under `crates/services/`. A service
  crate may depend on generic crates (`mws-core`, `mws-proto-*`, the code
  generator) and, only where AWS itself couples them, on another service's
  public API (for example STS on IAM identities). Generic crates must never
  mention a specific service. Cross-service glue that would form a dependency
  cycle goes in `crates/mws/src/links.rs` behind a trait the producing service
  defines.
- **The wire layer is generated.** Each service vendors its official Smithy
  JSON model from [`aws/api-models-aws`](https://github.com/aws/api-models-aws)
  in `model/` and runs `mws-codegen` from `build.rs`. Don't hand-write request
  or response types; fix the generator instead.
- **Match AWS wording.** Error codes, HTTP statuses and messages should be
  exactly what AWS returns. Validation messages come from the model's
  constraints.
- **Authorize in handlers.** Every handler calls
  `ctx.authorize("svc:Action", resource_arn, condition_keys)` before acting.
  Use `authorize_with_resource_policy` when either the resource or the identity
  policy may grant (bucket and CA policies), and
  `authorize_with_required_resource_policy` when the resource policy must
  allow (KMS key policies). The IAM authorizer reads IAM state, so inside
  `mws-iam` never call it while holding the state lock.
- **Use the caller's account and Region.** Build ARNs from the request
  context, never from fixed values; MWS is multi-account.
- **Prove it with real SDKs.** Every behaviour change comes with an end-to-end
  test using the official Rust SDK in `tests/e2e-rust/tests/e2e/` and, where
  useful, boto3 in `tests/e2e-python`.

## Adding a service

1. Put the service's Smithy model in `crates/services/mws-<svc>/model/`.
2. Generate the wire layer in `build.rs` with the protocol's codegen entry
   point. If the protocol is new, add a `mws-proto-<protocol>` runtime crate
   and a codegen module for it.

   | Protocol | Entry point | Used by |
   | --- | --- | --- |
   | awsQuery | `build_aws_query` | IAM, STS, SNS |
   | restXml | `build_rest_xml` | Route 53, S3, S3 Control |
   | awsJson | `build_aws_json` | KMS, Private CA, Logs, SQS, Kinesis, Firehose, CloudWatch, ... |
   | restJson1 | `build_rest_json` | Lambda |
   | ec2Query | `build_ec2_query` | EC2 |

   `build_ec2_query` takes the list of operations to generate, because all
   811 EC2 operations take minutes to compile; the rest answer
   `NotImplemented`. Models with the `rpcv2Cbor` trait also get
   `dispatch_cbor` from `build_aws_json` (runtime in `mws-proto-cbor`).
   `awsQueryCompatible` models also get an awsQuery codec for older SDKs
   (`build_aws_query_compatible`, or `build_aws_query` when the model names
   awsQuery itself). Pass the service's validation error code in the options
   (`InvalidInput`, `ValidationException`, ...). The restXml generator panics
   on bindings it does not support yet: extend it rather than working around
   it in the service.
3. Implement the generated `Handler` trait and `mws_core::Service`, including
   `invoke` (forward to `generated::invoke`, so scenario files can call the
   service) and, if the service keeps state, `export_state`, `import_state`
   and `reset_state`. State types derive serde and use `#[serde(default)]` so
   older saved state still loads; maps with non-string keys need a custom
   (de)serializer.
4. Register the service in [`crates/mws/src/lib.rs`](crates/mws/src/lib.rs).
5. Add a page under [`docs/services`](docs/services) and a row to the tables in
   the [README](README.md) and [docs/services/README.md](docs/services/README.md).

## Tests

Add Rust SDK tests as modules of
[`tests/e2e-rust/tests/e2e/main.rs`](tests/e2e-rust/tests/e2e/main.rs), never
as new files directly under `tests/`: every test binary links all the SDKs,
which costs minutes of build time and gigabytes of disk.

## Before you open a pull request

Run the same checks as CI:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

A full local build is large. Setting
`CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_INCREMENTAL=0`, as CI does,
keeps `target/` small. To iterate on one service, run just its tests, for
example `cargo test -p mws-e2e --test e2e sqs::`.

Keep pull requests focused on one change, describe the AWS behaviour they
reproduce, and update the service's documentation page when behaviour or
known gaps change.

## License

By contributing, you agree that your contributions are dual licensed under
the [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE) licenses, as described
in the [README](README.md#license).
