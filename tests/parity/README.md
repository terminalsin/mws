# MWS vs LocalStack parity suite

Sends the same boto3 calls to a running MWS and a running LocalStack, and
reports every difference: HTTP status, error code and message, response
fields and values, and selected headers. Generated values (ids, ARNs'
account ids, timestamps, endpoints, tokens) are normalized first, so they
don't count as differences.

LocalStack is a **reference, not ground truth**. MWS aims at real AWS, so
each disparity gets a verdict on which side is likely wrong, built from
evidence about AWS itself (see [Verdicts](#verdicts)).

## Run it

You need Python 3.10+, MWS and LocalStack. Both listen on port 4566 by
default, so run them on different ports. The suite defaults to LocalStack on
4566 and MWS on 4567.

```sh
pip install -r tests/parity/requirements.txt

# Terminal 1: LocalStack on 4566 (as you normally run it)
localstack start            # or: docker run --rm -p 4566:4566 -v /var/run/docker.sock:/var/run/docker.sock localstack/localstack

# Terminal 2: MWS on 4567
MWS_LISTEN=127.0.0.1:4567 MWS_EC2_BACKEND=metadata cargo run -p mws

# Terminal 3
cd tests/parity
python -m parity            # every MWS service, scenarios + probes
```

Or let the suite start both (MWS from `target/debug/mws`, `$MWS_BIN` or
`cargo run`; LocalStack from Docker, passing `LOCALSTACK_AUTH_TOKEN` through
if it is set):

```sh
python -m parity --start-mws --start-localstack --localstack http://localhost:4568
```

The report lands in `tests/parity/reports/<timestamp>/` (git-ignored); the
last line of the output gives its path.

### Useful options

| option | what it does |
| --- | --- |
| `--mws URL`, `--localstack URL` | endpoints (also `PARITY_MWS_ENDPOINT`, `PARITY_LOCALSTACK_ENDPOINT`) |
| `--services sqs,s3` / `--exclude ec2` | which services (boto3 names; default every MWS service) |
| `--mode scenarios\|probes\|read\|validation\|all` | what to run (default `all`) |
| `--case 'sqs/fifo-queue/*'` | only cases whose id matches the glob (repeatable) |
| `--operation CreateQueue` | only calls of this model operation (repeatable) |
| `--jobs N` | services compared in parallel (default 4) |
| `--out DIR` | report directory |
| `--keep-matches` | full detail of matching calls in report.json too |
| `--fail-on disparity\|mws` | exit 1 on any disparity, or only when MWS is likely wrong |
| `--list` | list services, their MWS crates and scenarios |
| `--mws-key/--mws-secret`, `--localstack-key/--localstack-secret` | credentials (MWS root and `test`/`test` by default) |
| `--start-mws`, `--mws-bin`, `--start-localstack`, `--localstack-image` | let the suite start the emulators |

Lambda invocations need a Python runtime on the MWS side and the Docker
socket mounted into LocalStack. MWS's EC2 Docker backend isn't needed:
nothing here starts instances, databases, caches or clusters.

## What runs

**Every MWS service** is covered: the list is read from the Smithy models
under `crates/services/*/model`, so a new service is picked up without
editing the suite.

- **Scenarios** (`parity/scenarios/`) are hand-written call sequences per
  service: create, read, update, list, tag, the common error cases
  (not found, already exists, invalid input), then cleanup. Each side keeps
  its own variables (`${queue_url}` is MWS's URL on the MWS side), and both
  use the same resource names, so names compare equal.
- **Read probes** call every `List*`/`Describe*`/`Get*` operation that has
  no required input. State differs between emulators, so only the shape of
  the response is compared.
- **Validation probes** call every operation that has required input with
  none of it (client-side validation off). AWS rejects all of them, so they
  compare how each side reports the missing members.

Services LocalStack doesn't offer in your edition (not listed in
`/_localstack/health` and answering "not included in your license" or "not
yet emulated") are reported as **skipped**, and so are single operations it
doesn't implement.

## Reading the report

`report.md` is the index: a per-service table, then the cases grouped by
verdict, **MWS likely wrong: fix these first** at the top. `report.json`
holds the same data plus the run's metadata (both emulators' health and
version) in machine-readable form.

Every case that isn't a match has its own `cases/<service>/<case>.md` and
`.json` with everything needed to fix it without rerunning anything:

- the service, model operation and boto3 method, the scenario and step,
- where the MWS code and Smithy model live (`crates/services/mws-…`),
- the exact request parameters (per side when variables differ),
- for each side: status, error, SDK exception and traceback, the parsed
  response raw and normalized, and the **raw HTTP exchange** (method, URL,
  every request and response header, both bodies),
- the normalized differences with severity, the model checks, the
  documented AWS expectation if the scenario has one, and the verdict,
- the command that reruns just that case.

Outcomes:

| outcome | meaning |
| --- | --- |
| `disparity` | the two sides answered differently |
| `spec` | both sides agree, but MWS departs from the AWS model |
| `minor` | only wording, header, ordering or empty-vs-absent differences |
| `blocked` | an earlier step failed on one side, so this call couldn't be made there |
| `match` | identical after normalization |
| `skipped` | LocalStack doesn't offer it |

## Verdicts

Each disparity is labelled `mws`, `localstack`, `both` or `undetermined`
(with a confidence), from this evidence, strongest first:

1. **Documented AWS behaviour** written into the scenario (`expect=`). The
   suite's own tests check every expected error against the Smithy model.
2. **The official service model**: whether an error code is declared for
   the operation (read from MWS's vendored Smithy model, which also carries
   awsQuery error codes botocore drops), the declared HTTP status of errors
   (REST and query protocols) and of successful responses, enum values,
   required output members, members a JSON response sends that the model
   doesn't define, and the protocol's content type.
3. **Broken-emulator signs**: 5xx answers, "not implemented" errors,
   accepting a request with every required member missing, and responses
   the SDK can't parse.

With no evidence either way the verdict is `undetermined`; the case file
lists hints (such as which side omits a field) to check against AWS's
documentation. When MWS turns out to be right, add an `expect=` to the
scenario so later runs judge it automatically.

## Writing scenarios

```python
from ..dsl import aws_error, aws_ok, scenario

@scenario("sqs", "standard queue lifecycle")
def _(s):
    s.call("create_queue", QueueName="${name}", save={"url": "QueueUrl"})
    s.call("get_queue_url", QueueName="${name}-missing",
           expect=aws_error("AWS.SimpleQueueService.NonExistentQueue", 400))
    s.call("receive_message", QueueUrl="${url}", _until="Messages", _wait=10)
    s.cleanup("delete_queue", QueueUrl="${url}")
```

- `${var}`: lowercase variable names only (so CloudFormation's `${AWS::…}`
  and `${Param}` pass through). Built-ins: `name` (unique per scenario and
  run), `alnum` (the same without hyphens), `run`, `account`, `region`.
- `save={"var": "JMESPath"}` stores a value from the response, per side.
- `service="iam"` makes one step call another service.
- `expect=aws_error(code, status, message=regex)` / `aws_ok(fields, status)`:
  what real AWS answers, from its documentation. Only add what you're sure of.
- `_until` (JMESPath or callable) polls a call until true; errors are
  retried until `_wait` seconds pass.
- `_shape_only=True` compares types and fields but not values (for lists
  that depend on other state), `_ignore=["Path.To[].Field"]` skips paths,
  `_raw=True` turns client-side validation off, `_params=lambda v: {...}`
  computes arguments, `_note` explains the step in the report.
- `s.cleanup(...)` steps run even after the LocalStack side turned out not
  to offer the service.

Check your scenarios offline (no emulator needed):

```sh
pytest tests/parity/tests
```
