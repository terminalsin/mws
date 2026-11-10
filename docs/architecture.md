# Architecture

MWS is a Cargo workspace of small crates. One binary (`mws`) wires a generic
HTTP gateway to one crate per AWS service. This page explains how a request
flows through it and why the code is split the way it is.

## Design principles

- **Fidelity beats breadth.** An operation is either implemented the way AWS
  behaves or answers `NotImplemented`. Error codes, HTTP statuses and messages
  match AWS's.
- **The wire layer is generated.** Every service vendors its official Smithy
  model from [`aws/api-models-aws`](https://github.com/aws/api-models-aws).
  Request and response types, routing, validation and serialization are
  generated from it at build time, never written by hand.
- **Strict silos.** Each service is its own crate. Generic crates never
  mention a specific service. A service depends on another service's public API
  only where AWS itself couples them (STS issues credentials for IAM
  identities; S3 encrypts with KMS keys).
- **Authorize in handlers.** Every handler calls the IAM authorizer with the
  action, resource ARN and condition keys before it acts.
- **Prove it with real SDKs.** Behaviour is verified by end-to-end tests that
  use the official AWS SDKs, not by unit tests of the emulator's own types.

## Request flow

```
            ┌──────────────────────── mws-server ───────────────────────┐
 HTTP  ───▶ │  /_mws control API?  ──yes──▶ state, snapshots, clock      │
            │        │ no                                                │
            │        ▼                                                   │
            │  SigV4 verification (mws-sigv4) against the credential     │
            │  store: IAM access keys, STS sessions, S3 sessions         │
            │        │                                                   │
            │        ▼                                                   │
            │  route by signing name / X-Amz-Target / host / path        │
            └────────┼───────────────────────────────────────────────────┘
                     ▼
            ┌──────────────── service crate (e.g. mws-sqs) ──────────────┐
            │  generated dispatch: decode, validate (model constraints)  │
            │        ▼                                                   │
            │  Handler::operation(ctx, input)                            │
            │        ├── ctx.authorize("sqs:SendMessage", arn, keys) ──▶ IAM policy engine
            │        ├── behaviour and state                             │
            │        └── calls into other services' public APIs          │
            │        ▼                                                   │
            │  generated encoder: response or AWS-shaped error           │
            └────────────────────────────────────────────────────────────┘
```

1. **Gateway.** `mws-server` accepts HTTP/1.1 and HTTP/2, serves the
   unauthenticated `/_mws` control API, verifies the SigV4 signature (header
   or presigned query, `aws-chunked` payloads) and resolves the caller. It
   knows no service by name: services register themselves through the
   `mws_core::Service` trait and say which requests they recognize.
2. **Generated layer.** Each service's `build.rs` runs `mws-codegen` on its
   Smithy model. The generated code decodes the request in the service's
   protocol, validates it against the model's constraints (with AWS's
   validation messages) and calls the matching method of a generated
   `Handler` trait.
3. **Handler.** The service implements `Handler`. Each method authorizes the
   call, applies the behaviour, and returns either an output shape or a
   `ServiceError`, which the generated layer encodes as that protocol's error.
4. **Authorization.** `ctx.authorize` goes to the IAM crate's authorizer,
   which evaluates identity policies, permissions boundaries, session
   policies, resource policies, SCPs and RCPs with
   [`mws-iam-policy`](../crates/services/mws-iam-policy). See
   [Authentication and authorization](security.md).
5. **Audit.** The generated layer hands each call's operation name, rendered
   request parameters, response elements and error to `mws_core::trail`, and
   the gateway passes them to every registered `ApiCallObserver` after the
   call. CloudTrail is the observer that turns them into records.

## Protocols

AWS services speak one of a handful of wire protocols. MWS has one runtime
crate per protocol and one generator module per protocol in `mws-codegen`.

| Protocol | Runtime crate | Services |
| --- | --- | --- |
| awsQuery | `mws-proto-query` | IAM, STS, SNS; legacy SQS and CloudWatch requests |
| awsJson 1.0 / 1.1 | `mws-proto-json` | KMS, Organizations, Private CA, ACM, Secrets Manager, SSM, SQS, EventBridge, Kinesis, Firehose, CloudWatch Logs, CloudWatch |
| restXml | `mws-proto-restxml` | Route 53, S3, S3 Control |
| restJson1 | `mws-proto-restjson` | Lambda |
| Smithy RPC v2 CBOR | `mws-proto-cbor` | CloudWatch |
| ec2Query | `mws-proto-ec2` | EC2 |

Models with the `awsQueryCompatible` trait (SQS, CloudWatch) also get an
awsQuery codec for the requests older SDKs still send, and their JSON errors
carry the query error code in `x-amzn-query-error`. Event streams (S3 Select,
CloudWatch Logs live tail, Kinesis `SubscribeToShard`, Lambda response
streaming) are generated too.

## Crates

```
crates/
  mws                the binary; the only crate that knows which services exist
  mws-server         HTTP front door: authentication, routing, /_mws control API,
                     scenarios, snapshots and persistence
  mws-core           service-agnostic contracts: ServiceError, RequestContext,
                     Caller, Authorizer, CredentialStore, Service, ApiCallObserver
  mws-sigv4          SigV4 verification (header and presigned query)
  mws-smithy         reads Smithy JSON AST models
  mws-codegen        generates server stubs from Smithy models (build time)
  mws-proto-*        protocol runtimes (query, json, restxml, restjson, cbor, ec2)
  mws-xml            XML writer and reader shared by the XML protocols
  mws-store          SQLite persistence of opaque per-service state documents
  mws-schedule       schedule expressions (rate(...), six-field cron(...))
  mws-parquet        a small Apache Parquet writer (S3 Inventory, RDS exports)
  mws-event-pattern  the AWS event pattern language (EventBridge, Lambda filters)
  services/
    mws-iam            IAM, multi-account, and the authorizer every service calls
    mws-iam-policy     the IAM policy language and evaluation logic (pure)
    mws-sts            temporary credentials over IAM identities
    mws-organizations  organizations, OUs, member accounts, SCPs and RCPs
    mws-kms            keys with real cryptography, key policies and grants
    mws-s3             buckets and objects, policies, SSE, lifecycle, replication, Select
    mws-s3control      access points, Object Lambda, Batch Operations, Access Grants
    mws-lambda         functions that run on local runtimes via the Runtime API
    mws-ec2            EC2 and VPC, instances run by a pluggable compute backend
    mws-globalaccelerator static anycast IPs, listeners, endpoint groups, custom routing
    mws-route53        hosted zones, record sets, health checks, DNS responder
    mws-acmpca         Private CA: CAs and real X.509 issuance
    mws-acm            public, private and imported certificates, DNS validation
    mws-secretsmanager KMS-sealed secret versions, rotation through Lambda
    mws-ssm            Parameter Store: versioned parameters, SecureStrings
    mws-sqs            standard and FIFO queues
    mws-sns            topics, subscriptions, signed deliveries
    mws-events         EventBridge buses, rules and targets
    mws-kinesis        Kinesis Data Streams: shards, resharding, enhanced fan-out
    mws-firehose       buffered delivery to S3, HTTP endpoints, Splunk, OpenSearch
    mws-cloudwatch     metrics, metric math, alarms that act, dashboards
    mws-logs           CloudWatch Logs: events, filter patterns, Insights, live tail
    mws-cloudtrail     records every API call; trails, event history, Insights, Lake
    mws-cloudtrail-data PutAuditEvents into CloudTrail Lake channels
tests/
  e2e-rust           official Rust SDK against an in-process MWS
  e2e-python         boto3 against the mws binary
  e2e-ts             example applications on the AWS SDK for JavaScript v3
```

## Cross-service behaviour

Many AWS features span services: S3 event notifications land in SQS, alarms
publish to SNS, Firehose writes to S3. In AWS each of these is an API call
that one service makes to another, as its service principal or with a role
you configured. MWS is moving all of them to work the same way:

- `mws_core::ServiceClient` calls any service's operation by name
  (`client.call(&ctx, "sqs", "SendMessage", json)`), through the target's
  own generated `invoke`. The target validates and authorizes the call like
  an SDK request, and CloudTrail records it as a call of its own. The caller
  needs no crate dependency on the target.
- `RequestContext::as_service(principal, source_account, source_arn)` makes
  the caller an AWS service principal (`CallerKind::Service`). The IAM
  authorizer then evaluates only the resource policy (and KMS key policy),
  with `aws:PrincipalIsAWSService`, `aws:PrincipalServiceName`,
  `aws:SourceArn`, `aws:SourceAccount` and `aws:SourceOrgID`, and no SCPs
  or RCPs, as in AWS.
- `mws_core::deferred::defer` queues a delivery to run once the handler has
  returned (and dropped its locks), before the response goes out. The front
  door and `ServiceClient` run deferred work; outside a request it is
  spawned.
- `ServiceClient::deliver` retries a service principal's call that failed
  with a retryable error (5xx, throttling) on the emulated clock, with the
  caller's retry policy. Queued calls are part of the state document
  (`deliveries`); `GET /_mws/deliveries` lists them and
  `POST /_mws/deliveries/drain` retries every pending one now. S3 event
  notifications use it.
- `ServiceClient::run_job` puts a service's own retries on the same queue:
  the service registers an `mws_core::outbox::Retrier` that makes each
  attempt and handles the give-up (dead-letter queue, on-failure
  destination). EventBridge target deliveries, Lambda asynchronous
  invocations and SNS HTTP/S deliveries retry this way, so their retries
  follow `/_mws/clock` and survive a snapshot.

S3, SNS and EventBridge deliveries to SQS and Lambda, S3 and EventBridge
deliveries to SNS, and CloudWatch alarm actions on SNS and Lambda go
through `ServiceClient`; those services no longer depend on the Lambda or
SNS crates for it. Older integrations still call another
crate's typed public API (for example `Kms::encrypt_via` from S3, or
`Sts::assume_role_as_service` for service roles), or a small trait the
producing service defines (such as `mws_s3::NotificationDestination` or
`mws_lambda::DestinationSink`) that the `mws` binary implements in
[`crates/mws/src/links.rs`](../crates/mws/src/links.rs). New integrations
should use `ServiceClient`.

## State

Each stateful service keeps its state behind its own lock and implements
`export_state`, `import_state` and `reset_state` from `mws_core::Service`.
State types derive serde with `#[serde(default)]`, so state saved by an older
version still loads. `mws-store` persists each service's document opaquely;
the gateway drives snapshots, resets and scenarios without knowing any
service's schema. Scenario steps call services through the generated
`invoke`, so they are validated and authorized like SDK calls.

Time-based behaviour reads the request's `received_at`, which follows the
[emulated clock](state.md#the-emulated-clock).
