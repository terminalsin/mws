# State, scenarios and snapshots

By default MWS keeps all state in memory and starts empty, apart from the
root account and the resources AWS creates for every account (such as the
default VPC and the default event bus). Test suites usually want more control
than that, so MWS can persist state, seed it from a file, reset it, snapshot
it and move its clock.

## Persistence

With `MWS_DB` set, every service's state is written to that
SQLite file shortly after each change (within about 250 ms) and again on
shutdown (Ctrl-C or SIGTERM), and comes back on the next start. Temporary
STS credentials survive too, until they expire.

## Scenarios

A scenario is a JSON list of API calls that sets up state.
Each step names the service (its signing name), the operation, and the input
in the same shape as `aws ... --cli-input-json`. Steps go through the real
handlers, so they are validated and authorized like SDK calls (as the root
user unless a step sets `accessKeyId`). A step with an `id` exposes its output
to later steps as `${id.Path.To.Field}`, with optional `|basename` (strip
`/hostedzone/`) and `|base64` (for blob inputs such as a CSR) filters.
If any step fails, the whole scenario is rolled back and the error names the
step.

```json
{
  "steps": [
    { "service": "iam", "action": "CreateUser", "input": { "UserName": "deployer" } },
    { "id": "key", "service": "iam", "action": "CreateAccessKey", "input": { "UserName": "deployer" } },
    { "id": "zone", "service": "route53", "action": "CreateHostedZone",
      "input": { "Name": "example.internal", "CallerReference": "seed" } },
    { "service": "route53", "action": "ChangeResourceRecordSets",
      "input": { "HostedZoneId": "${zone.HostedZone.Id|basename}", "ChangeBatch": { "Changes": [
        { "Action": "CREATE", "ResourceRecordSet": { "Name": "api.example.internal", "Type": "A",
          "TTL": 60, "ResourceRecords": [{ "Value": "10.0.0.10" }] } } ] } } }
  ]
}
```

[`examples/scenario.json`](../examples/scenario.json) also creates a role and
a Private CA and activates it with a self-signed root certificate.

### Baselines

`MWS_SCENARIO` runs a scenario at startup on an empty emulator, and the
result becomes the baseline that `POST /_mws/reset` returns to. With
`MWS_DB` as well, the scenario runs only once: later starts restore the saved
state. If the scenario file changes, the saved state is replaced by a fresh
run of the new scenario (the old state is kept as a snapshot named
`before-scenario-change-...`).

## Control API

Plain unsigned JSON over HTTP on the same port:

| Request | Effect |
| --- | --- |
| `GET /_mws/health` | liveness and the emulated services |
| `GET /_mws/state` | export the whole emulator's state |
| `PUT /_mws/state` | replace it with an exported document |
| `POST /_mws/reset` | back to the baseline (`?to=empty` for a fresh emulator) |
| `POST /_mws/scenario` | run a scenario now; returns the outputs of steps with an `id`. `?baseline=true` makes the result the new baseline |
| `GET /_mws/snapshots` | list named snapshots |
| `PUT /_mws/snapshots/{name}` | save the current state |
| `GET /_mws/snapshots/{name}` | export a snapshot |
| `POST /_mws/snapshots/{name}/restore` | replace the current state with a snapshot |
| `DELETE /_mws/snapshots/{name}` | delete a snapshot |
| `GET /_mws/clock` | the emulated time and its offset from the wall clock |
| `POST /_mws/clock` | move the emulated time: `{"advanceSeconds": n}` or `{"offsetSeconds": n}` (time-based behaviour such as S3 lifecycle follows it; signatures still use the wall clock) |

A typical test suite starts MWS with a scenario and calls `POST /_mws/reset`
before each test. Snapshots live in the database when `MWS_DB` is set, and in
memory otherwise. The control API is unauthenticated, like the rest of a
local emulator: don't expose the port beyond your machine.

## The emulated clock

MWS keeps an emulated clock that starts at the wall clock. Moving it forward
with `POST /_mws/clock` makes time-based behaviour happen without waiting:
S3 lifecycle rules, SQS retention and delays, KMS key deletion and rotation,
Secrets Manager rotation schedules, certificate expiry in ACM and Private CA,
CloudWatch alarm evaluation, Firehose buffering and EventBridge schedules all
follow it. Signatures are still checked against the wall clock, so SDKs keep
working.

```sh
curl -X POST http://localhost:4566/_mws/clock -d '{"advanceSeconds": 86400}'
```

The clock is shared by every client of the emulator. A test that moves it
should move it back (`{"offsetSeconds": 0}`) so that it does not disturb other
tests running against the same instance.
