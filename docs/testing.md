# Testing

This page covers two things: using MWS to test your own code, and running
MWS's own test suites.

## Testing your code with MWS

### Keep MWS out of your application code

Don't configure endpoints in application code. Create SDK clients exactly as
you would for AWS, and set `AWS_ENDPOINT_URL`, the Region and the
credentials for the test run. The one client setting worth passing is
path-style addressing on S3 clients (`forcePathStyle: true`,
`force_path_style(true)` or `addressing_style: "path"`), which keeps bucket
names out of the host name of a local endpoint.

Setting the credentials explicitly for the test run also guarantees that a
test can never reach a real AWS account by accident.

### Start once, reset between tests

Starting MWS is fast, but a suite is faster still when it starts MWS once and
returns to a known state before each test:

```sh
MWS_SCENARIO=tests/fixtures/seed.json mws &      # seed users, roles, buckets, ...
```

```python
import pytest, urllib.request

@pytest.fixture(autouse=True)
def clean_mws():
    urllib.request.urlopen(urllib.request.Request(
        "http://localhost:4566/_mws/reset", method="POST"))
```

`POST /_mws/reset` returns to the scenario's result (the baseline), and
`?to=empty` returns to a fresh emulator. Alternatively, save a snapshot with
`PUT /_mws/snapshots/{name}` and restore it with
`POST /_mws/snapshots/{name}/restore`. See
[State, scenarios and snapshots](state.md).

If tests run in parallel against one MWS, use unique resource names (a random
suffix per test) instead of resetting.

### Test with least-privilege identities

Running everything as the root user proves only that your code calls the
right APIs. To prove your IAM policies are right too, create the roles your
application uses in production (in the scenario or in a fixture), assume them,
and run the code under test with those credentials. MWS denies exactly what
AWS would deny, with the same `AccessDenied` messages.

### Make time pass

Expiry, retention, rotation and schedules follow MWS's emulated clock.
Advance it instead of sleeping, and move it back afterwards:

```sh
curl -X POST localhost:4566/_mws/clock -d '{"advanceSeconds": 3600}'
curl -X POST localhost:4566/_mws/clock -d '{"offsetSeconds": 0}'
```

### Examples

[`tests/e2e-ts`](../tests/e2e-ts) holds six small but realistic applications
written with the AWS SDK for JavaScript v3, each with a Vitest suite that runs
it end to end against MWS: S3/SNS/SQS upload pipelines, EventBridge and
Lambda, SSM/Secrets Manager/KMS configuration, IAM/STS tenant isolation with
ABAC, CloudWatch observability, and Kinesis/Firehose clickstreams. The
application code never mentions MWS.

## Running MWS's own tests

MWS is verified end to end with the official SDKs. Every implemented
operation of every service is exercised by at least one SDK test.

| Suite | Location | What it runs |
| --- | --- | --- |
| Rust | [`tests/e2e-rust`](../tests/e2e-rust) | The official AWS SDK for Rust against an in-process MWS |
| Python | [`tests/e2e-python`](../tests/e2e-python) | boto3 against the `mws` binary |
| TypeScript | [`tests/e2e-ts`](../tests/e2e-ts) | Example apps on the AWS SDK for JavaScript v3 against a running MWS |
| Dashboard | [`dashboard/e2e`](../dashboard/e2e) | Playwright against the web console and a running MWS ([details](dashboard.md#tests)) |
| Parity | [`tests/parity`](../tests/parity) | boto3 calls sent to MWS and LocalStack side by side, with a diff report |

### Rust

```sh
cargo test --workspace --all-targets          # also builds target/debug/mws
cargo test -p mws-e2e --test e2e sqs::        # one service's tests
```

The Rust SDK tests are a single test binary,
[`tests/e2e-rust/tests/e2e/main.rs`](../tests/e2e-rust/tests/e2e/main.rs),
with one module per service. Every test binary links all the SDKs, which costs
minutes of build time and gigabytes of disk, so new tests go into a module of
that binary rather than a new file under `tests/`.

The full workspace build is large. Building with
`CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_INCREMENTAL=0`, as CI does,
keeps `target/` small enough for a typical laptop or CI runner.

### Python

```sh
pip install -r tests/e2e-python/requirements.txt
pytest tests/e2e-python               # uses target/debug/mws, or MWS_BIN
```

### TypeScript

```sh
cargo run -p mws &
cd tests/e2e-ts && npm ci && npm test
```

### Parity with LocalStack

[`tests/parity`](../tests/parity) sends identical boto3 calls to a running
MWS and a running LocalStack, for every MWS service LocalStack also offers,
and writes a report of every difference (status, error code and message,
response fields, headers) with the full raw HTTP of both sides and a verdict
on which side is likely wrong. LocalStack is a reference, not ground truth:
the verdicts lean on documented AWS behaviour and the official service
models. Both emulators default to port 4566, so run MWS on another port:

```sh
pip install -r tests/parity/requirements.txt
localstack start                                   # LocalStack on 4566
MWS_LISTEN=127.0.0.1:4567 cargo run -p mws &       # MWS on 4567
cd tests/parity && python -m parity                # report in tests/parity/reports/
```

See its [README](../tests/parity/README.md) for options, the report format
and how to add scenarios. CI runs only the suite's own checks (scenario
validation and a self-test that compares two MWS instances); LocalStack runs
stay on your machine.

### Continuous integration

[CI](../.github/workflows/ci.yml) runs formatting, Clippy with warnings
denied, the Rust and Python suites, and the TypeScript and web console
(Playwright) suites against the built binary.

On a pull request, [`plan.py`](../.github/scripts/plan.py) reads the
workspace graph and the changed files and runs only what the change can
affect:

- Clippy on the crates the change touches.
- Unit tests of those crates and of every crate that depends on them.
- The end-to-end modules of the affected services. Modules are matched to
  service crates by name (`lambda_sqs` runs for `mws-lambda` and `mws-sqs`),
  and modules named after no service, such as `parity` and `state`, run
  whenever any service changes. A change to `crates/mws` or to the e2e
  helpers runs every module.
- Everything when a shared crate (`mws-core`, the gateway, codegen, the
  protocol crates, ...), the CI setup, or an existing dependency's version
  changes. Pushes to master, the nightly run and manual runs are always full.

`python3 .github/scripts/plan.py --base origin/master` prints the plan for a
branch, and `--explain-modules` prints the module-to-service mapping. The plan
also appears in each run's summary.

One job builds every test binary once (sccache keeps unchanged crates,
workspace crates included, out of the compile) and archives them with
[cargo-nextest](https://nexte.st); a matrix of jobs then runs the unit tests
and the end-to-end modules in shards grouped by service, while the boto3 and
TypeScript suites and the web console's Playwright tests run against the same
`mws` binary. To run tests the way CI
does: `cargo nextest run --profile ci -E 'test(/^sqs::/)'`.
