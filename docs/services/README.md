# Services

MWS emulates 33 AWS services. Each is generated from AWS's official Smithy
MWS emulates 30 AWS services. Each is generated from AWS's official Smithy
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
| [IAM Identity Center](identity-center.md) | 109 / 109 | Users and groups, permission sets provisioned as real `AWSReservedSSO_*` roles, device and PKCE sign-in, portal credentials, `CreateTokenWithIAM` |
| [KMS](kms.md) | 56 / 56 | Symmetric, asymmetric, HMAC and post-quantum keys with real cryptography, key policies, grants, rotation |
| [Private CA](acm-pca.md) | 23 / 23 | Root and subordinate CAs issuing real X.509 certificates, CRLs in S3, OCSP, audit reports |
| [Connector for SCEP](pca-connector-scep.md) | 12 / 12 | Real SCEP endpoints enrolling devices with certificates from a Private CA shared through RAM |
| [Certificate Manager](acm.md) | 40 / 40 | Public certificates with real DNS validation through Route 53, private certificates, imports, expiry events |
| [GuardDuty](guardduty.md) | 102 / 102 | Detectors and features, sample findings to EventBridge and S3, suppression rules, members, Organizations delegated administrator |
| [Resource Access Manager](ram.md) | 35 / 35 | Shares that grant real cross-account access to Private CAs, invitations, organization sharing, managed permissions |
| [Security Hub](securityhub.md) | 126 / 126 | ASFF findings with every filter, workflow and history, insights, automation rules, standards and controls, members and Organizations delegated administration, central configuration, the V2 OCSF API with exports to S3 |
| [Secrets Manager](secretsmanager.md) | 23 / 23 | KMS-sealed secret versions, staging labels, rotation that runs your Lambda function, replicas |

## Storage

| Service | Operations | What's emulated |
| --- | --- | --- |
| [S3](s3.md) | 111 / 112 | Objects, multipart, versioning, checksums, policies, SSE, lifecycle, replication, notifications, Select, directory buckets |
| [S3 Control](s3control.md) | 97 / 97 | Access points, Object Lambda, Batch Operations, Access Grants, multi-Region access points, Storage Lens |
| [EFS](efs.md) | 31 / 31 | File systems as real directories, mount targets in VPC subnets, access points, policies, replication, mounts from Docker instances |

## Compute and networking

| Service | Operations | What's emulated |
| --- | --- | --- |
| [Lambda](lambda.md) | 68 / 88 | Python, Node.js and custom runtimes that really run, SQS and Kinesis event sources, destinations, function URLs |
| [Global Accelerator](globalaccelerator.md) | 56 / 56 | Static anycast IPs, listeners, endpoint groups with health from EC2 and ELB, custom routing port mappings, BYOIP, cross-account attachments |
| [EC2 and VPC](ec2.md) | 164 / 811 | Default VPCs, subnets, security groups, NAT gateways and VPC endpoints that filter and route real Docker traffic, AMIs, instances as Docker containers, instance metadata and profiles |
| [EC2 Auto Scaling](autoscaling.md) | 68 / 68 | Groups that launch, replace and terminate real EC2 instances, lifecycle hooks, suspended processes, simple, step and target tracking policies driven by CloudWatch alarms, schedules, instance refreshes, warm pools, load balancer registration |
| [EC2 Image Builder](imagebuilder.md) | 77 / 77 | Components, recipes and pipelines whose builds launch EC2 instances, run AWSTOE components and produce real AMIs, distribution, lifecycle policies |
| [Elastic Load Balancing](elb.md) | 80 / 80 | Application, Network and Classic Load Balancers whose listeners really proxy: rules, stickiness, HTTPS with ACM certificates, mutual TLS, Lambda targets, health checks, metrics |
| [RDS and Aurora](rds.md) | 103 / 168 | PostgreSQL, MySQL and MariaDB instances and Aurora clusters that really run in Docker, snapshots and restores, read replicas, global databases, managed master passwords |
| [EKS](eks.md) | 70 / 70 | Clusters in your VPC, managed node groups as Auto Scaling groups, add-ons, access entries, Pod Identity, OIDC providers |
| [ECR](ecr.md) | 62 / 62 | A real Docker registry (`docker push`/`pull` with `GetAuthorizationToken`), lifecycle policies, replication, creation templates |
| [ECR Public](ecr-public.md) | 23 / 23 | Public registries with aliases and catalog data, anonymous pulls, authenticated pushes |
| [ECS](ecs.md) | 88 / 88 | Clusters, tasks as Docker containers with awsvpc interfaces, services with rolling deployments and circuit breakers, task metadata, secrets and awslogs |
| [Route 53](route53.md) | 71 / 71 | Public and private hosted zones, all routing policies, health checks, DNSSEC key management, an optional real DNS responder |
| [Amplify Hosting](amplify.md) | 37 / 37 | Apps and branches whose deployments are really served: manual and S3 deploys, Git builds, rewrites, basic auth, custom domains |

## Databases

| Service | Operations | What's emulated |
| --- | --- | --- |
| [ElastiCache](elasticache.md) | 77 / 77 | Valkey, Redis OSS and Memcached nodes as Docker containers, replication and cluster mode with failover and resharding, RBAC, TLS, CloudWatch metrics, snapshots to S3, serverless caches, global datastores |

## Application integration

| Service | Operations | What's emulated |
| --- | --- | --- |
| [SQS](sqs.md) | 23 / 23 | Standard and FIFO queues, visibility timeouts, long polling, dead-letter queues, redrive, SSE |
| [SNS](sns.md) | 42 / 42 | Topics, filter policies and signed deliveries to SQS, Lambda, HTTP and more, FIFO topics |
| [SES v1 and v2](ses.md) | 187 / 187 | Verified identities (Route 53 DKIM), the sandbox, an outbox, templates, event destinations, receipt rules fed by a local SMTP listener |
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
| [CloudTrail](cloudtrail.md) | 61 / 61 | Every API call recorded; trails delivering to S3, CloudWatch Logs and EventBridge; event history; Insights; Lake SQL queries, imports and channels |

## Marketplace

| Service | Operations | What's emulated |
| --- | --- | --- |
| [Marketplace Metering and Entitlement](marketplace.md) | 5 / 5 | SaaS registration tokens, batch and hourly metering with AWS's dedup and time windows, signed `RegisterUsage`, entitlements, a seedable catalog |

## Developer tools

| Service | Operations | What's emulated |
| --- | --- | --- |
| [CodeArtifact](codeartifact.md) | 48 / 48 | Domains, repositories with upstreams and external connections, package groups, and npm, PyPI, Maven, Cargo, RubyGems, NuGet and Swift endpoints real clients use |
## Cost and usage management

| [Service Quotas](servicequotas.md) | 26 / 26 | AWS's quota codes and defaults, increase requests that services enforce, `AWS/Usage` metrics for quota alarms |
| [Cost Explorer](ce.md) | 47 / 47 | Seeded and derived cost data, grouping and filters, forecasts, cost categories, allocation tags, anomaly alerts |
## Management

| [CloudFormation](cloudformation.md) | 35 / 90 | Stacks that create real resources in the other services, change sets, rollbacks, nested stacks, custom resources, drift detection |

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
- RAM shares Private CAs across accounts and with Connector for SCEP, whose
  SCEP endpoints issue device certificates from the shared CA.
- Secrets Manager rotation runs your Lambda function; SSM resolves Secrets
  Manager references.
- GuardDuty sends findings to EventBridge and S3 (under KMS) and registers
  its delegated administrator with Organizations.
- EC2 instances and Lambda functions receive role credentials from STS.
- EC2 instances, ECS tasks and Lambda functions receive role credentials from STS.
- Amplify deploys sites from S3 buckets (as `amplify.amazonaws.com`) and
  verifies custom domains through Route 53.
- Global Accelerator endpoints and custom routing subnets are checked against
  EC2 and Elastic Load Balancing, and endpoint health follows the instances'
  state and the load balancers' target health.
- Load balancers place themselves in EC2 subnets, serve ACM certificates,
  forward to EC2 instances, IP addresses and Lambda functions, read trust
  stores from S3 and publish CloudWatch metrics.
- RDS places databases in EC2 subnets and security groups, keeps managed
  master passwords in Secrets Manager (and rotates them), encrypts with KMS,
  and sends events to EventBridge and SNS.
- Marketplace Metering and the Entitlement Service share one Marketplace
  catalog of products, subscriptions and entitlements.
- EC2, S3, IAM, Lambda, Auto Scaling, ELB, RDS and EKS enforce Service
  Quotas' applied values, and usage is published to CloudWatch's
  `AWS/Usage` namespace.
- Cost Explorer charges API calls at their request prices, follows
  Organizations for consolidated billing and sends anomaly alerts to SNS.
- CloudFormation deploys stacks through every other service's API, as the
  caller or the stack's service role.
- Security Hub registers its delegated administrator in Organizations, sends
  findings events to EventBridge and exports findings to S3 with KMS.
- Auto Scaling groups launch and terminate EC2 instances, register them with
  load balancers, scale on CloudWatch alarms they create, publish group
  metrics and notify SNS, SQS and EventBridge.
- Image Builder launches EC2 instances, creates and copies AMIs, writes SSM
  parameters, logs to CloudWatch Logs and S3, notifies SNS and emits
  EventBridge events.
- SES verifies domains through Route 53, publishes events to SNS, EventBridge,
  Firehose and CloudWatch, and its receipt rules write to S3, invoke Lambda and
  publish to SNS.
- EKS creates cluster security groups in EC2 and runs managed node groups as
  Auto Scaling groups with EKS launch templates and IAM instance profiles,
  from AMIs SSM publishes.
- EFS mount targets are network interfaces in EC2 subnets, and Docker-backed
  instances mount EFS file systems, subject to security groups and the file
  system policy.
- CodeArtifact authorization tokens act as the IAM principal that requested
  them, and domains are encrypted with KMS keys.
- CloudTrail records every API call and delivers it to S3 (log and signed
  digest files), CloudWatch Logs, SNS and EventBridge.
