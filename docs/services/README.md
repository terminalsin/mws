# Services

MWS emulates 22 AWS services. Each is generated from AWS's official Smithy
model, so every operation in the model is routed and validated; operations
outside the implemented set answer `NotImplemented`. Each service's page lists
its features in a table: ✅ supported, 🟡 partial, ❌ not supported yet.

Every service shares the same foundations:

- **SigV4 authentication** and **IAM authorization** on every call, including
  the service's resource policies and condition keys
  ([details](../security.md)).
- **Accounts and Regions.** Resources are scoped to the caller's account and
  the Region the request is signed for, with ARNs to match. Member accounts
  created through Organizations are real accounts.
- **AWS errors.** Error codes, HTTP statuses and messages match AWS's,
  including validation messages generated from the model's constraints.
- **State** that can be exported, persisted, snapshotted and reset
  ([details](../state.md)).

## Identity and security

| Service | Operations | What's emulated |
| --- | --- | --- |
| [IAM](iam.md) | 180 / 180 | Users, groups, roles, policies, boundaries, MFA, certificates, access advisor, credential report, policy simulator |
| [STS](sts.md) | 11 / 11 | `AssumeRole` and its variants, web identity and SAML federation with signature checks, session tags, `AssumeRoot` |
| [Organizations](organizations.md) | 63 / 63 | Organizations, OUs, real member accounts, SCPs and RCPs enforced on every call |
| [KMS](kms.md) | 56 / 56 | Symmetric, asymmetric, HMAC and post-quantum keys with real cryptography, key policies, grants, rotation |
| [Private CA](acm-pca.md) | 23 / 23 | Root and subordinate CAs issuing real X.509 certificates, CRLs in S3, OCSP, audit reports |
| [Certificate Manager](acm.md) | 40 / 40 | Public certificates with real DNS validation through Route 53, private certificates, imports, expiry events |
| [Secrets Manager](secretsmanager.md) | 23 / 23 | KMS-sealed secret versions, staging labels, rotation that runs your Lambda function, replicas |

## Storage

| Service | Operations | What's emulated |
| --- | --- | --- |
| [S3](s3.md) | 111 / 112 | Objects, multipart, versioning, checksums, policies, SSE, lifecycle, replication, notifications, Select, directory buckets |
| [S3 Control](s3control.md) | 97 / 97 | Access points, Object Lambda, Batch Operations, Access Grants, multi-Region access points, Storage Lens |

## Compute and networking

| Service | Operations | What's emulated |
| --- | --- | --- |
| [Lambda](lambda.md) | 68 / 88 | Python, Node.js and custom runtimes that really run, SQS and Kinesis event sources, destinations, function URLs |
| [EC2 and VPC](ec2.md) | 120 / 811 | Default VPCs, subnets, security groups, NAT gateways and VPC endpoints that filter and route real Docker traffic, AMIs, instances as Docker containers, instance metadata and profiles |
| [Route 53](route53.md) | 71 / 71 | Public and private hosted zones, all routing policies, health checks, DNSSEC key management, an optional real DNS responder |

## Application integration

| Service | Operations | What's emulated |
| --- | --- | --- |
| [SQS](sqs.md) | 23 / 23 | Standard and FIFO queues, visibility timeouts, long polling, dead-letter queues, redrive, SSE |
| [SNS](sns.md) | 42 / 42 | Topics, filter policies and signed deliveries to SQS, Lambda, HTTP and more, FIFO topics |
| [EventBridge](events.md) | 57 / 57 | Buses, the full event pattern language, schedules, archives and replays, API destinations |
| [SSM Parameter Store](ssm.md) | 19 / 152 | Versioned and labelled parameters, KMS SecureStrings, parameter policies, public parameters |

## Streaming

| Service | Operations | What's emulated |
| --- | --- | --- |
| [Kinesis Data Streams](kinesis.md) | 45 / 45 | Real shards, resharding, enhanced fan-out over event streams, KMS encryption |
| [Firehose](firehose.md) | 12 / 12 | Buffered delivery to S3, HTTP endpoints, Splunk and OpenSearch, Lambda processors, dynamic partitioning |

## Observability

| Service | Operations | What's emulated |
| --- | --- | --- |
| [CloudWatch](cloudwatch.md) | 55 / 55 | Metrics, statistics and percentiles, metric math, alarms that act, dashboards, metric streams |
| [CloudWatch Logs](logs.md) | 118 / 118 | Log events, filter patterns, Logs Insights, live tail, subscriptions, metric filters, exports |

## Marketplace

| Service | Operations | What's emulated |
| --- | --- | --- |
| [Marketplace Metering and Entitlement](marketplace.md) | 5 / 5 | SaaS registration tokens, batch and hourly metering with AWS's dedup and time windows, signed `RegisterUsage`, entitlements, a seedable catalog |

## How services connect

Services are wired together where AWS wires them, and each integration runs
with the permissions AWS would use:

- S3 event notifications deliver to SQS, SNS, Lambda and EventBridge.
- SNS delivers to SQS, Lambda, HTTP(S) endpoints and more.
- Lambda polls SQS queues and Kinesis streams, and sends asynchronous results
  to SQS, SNS, EventBridge or another function.
- EventBridge targets include Lambda, SQS, SNS, Kinesis, Firehose, CloudWatch
  Logs, other buses and API destinations.
- CloudWatch Logs subscriptions deliver to Lambda, Kinesis and Firehose, and
  metric filters publish CloudWatch metrics.
- CloudWatch alarms notify SNS, invoke Lambda and emit EventBridge events.
- Firehose writes to S3 and reads from Kinesis; metric streams feed Firehose.
- S3, SQS, SNS, Secrets Manager, SSM and others encrypt with KMS keys.
- ACM validates certificates through Route 53 and issues private certificates
  from Private CA, which writes its CRLs into S3.
- Secrets Manager rotation runs your Lambda function; SSM resolves Secrets
  Manager references.
- EC2 instances and Lambda functions receive role credentials from STS.
- Marketplace Metering and the Entitlement Service share one Marketplace
  catalog of products, subscriptions and entitlements.
