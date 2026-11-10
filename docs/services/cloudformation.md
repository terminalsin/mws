# AWS CloudFormation

> Crate: [`mws-cloudformation`](../../crates/services/mws-cloudformation) · Tests: [`cloudformation.rs`](../../tests/e2e-rust/tests/e2e/cloudformation.rs), [`cloudformation_stacksets.rs`](../../tests/e2e-rust/tests/e2e/cloudformation_stacksets.rs), [`cloudformation_registry.rs`](../../tests/e2e-rust/tests/e2e/cloudformation_registry.rs), [`cloudformation_iac.rs`](../../tests/e2e-rust/tests/e2e/cloudformation_iac.rs), [`cloudformation_lifecycle.rs`](../../tests/e2e-rust/tests/e2e/cloudformation_lifecycle.rs), [`cloudformation_databases.rs`](../../tests/e2e-rust/tests/e2e/cloudformation_databases.rs), [`cloudformation_compute.rs`](../../tests/e2e-rust/tests/e2e/cloudformation_compute.rs)

All 90 of the model's operations are implemented (awsQuery): stacks, change
sets (including `IMPORT`), drift detection, stack policies, exports, StackSets,
the private registry (resource types, modules, hooks), the IaC generator
(resource scans and generated templates), stack refactors and `DescribeEvents`.
Every operation is called by an official Rust SDK test.

## Behaviour

Stacks deploy real resources: every resource provider calls the owning MWS
service's API, with the caller's identity (or the stack's service role, assumed
as `cloudformation.amazonaws.com`, after an `iam:PassRole` check) and
`aws:CalledVia` = `cloudformation.amazonaws.com`, so IAM, SCPs and resource
policies apply exactly as they do to direct calls. Operations run in the
background on the emulated clock, so SDK waiters and `DescribeStackEvents`
polling see the same status progression as on AWS.

| Feature | Status | Details |
| --- | --- | --- |
| Templates | ✅ | JSON and YAML (short-form tags), `TemplateURL` from MWS S3, structure and reference checks with AWS's `Template format error:` messages, circular dependency detection |
| Parameters | ✅ | All types including `List<…>`, `AWS::EC2::*::Id` and `AWS::SSM::Parameter::Value<…>` (resolved from Parameter Store), constraints, `NoEcho`, `UsePreviousValue` |
| Intrinsic functions | ✅ | `Ref`, `Fn::GetAtt`, `Fn::Sub`, `Fn::Join`, `Fn::Select`, `Fn::Split`, `Fn::If`, `Fn::FindInMap`, `Fn::GetAZs`, `Fn::Base64`, `Fn::Cidr`, `Fn::ImportValue`, conditions, pseudo parameters, `AWS::NoValue`; `AWS::LanguageExtensions` adds `Fn::Length`, `Fn::ToJsonString` and `FindInMap` defaults |
| Dynamic references | ✅ | `{{resolve:ssm:…}}`, `{{resolve:ssm-secure:…}}`, `{{resolve:secretsmanager:…}}` |
| Stack lifecycle | ✅ | Create, update (in place, with interruption, or replacement then cleanup), delete; `OnFailure`, `DisableRollback`, rollback, `ContinueUpdateRollback`, `CancelUpdateStack`, `RollbackStack`, `TimeoutInMinutes`, termination protection, `RetainResources`; replacing a resource whose template sets its name is refused (`CloudFormation cannot update a stack when a custom-named resource requires replacing. Rename … and update the stack again.`) |
| Capabilities | ✅ | `CAPABILITY_IAM` / `CAPABILITY_NAMED_IAM` (which covers `CAPABILITY_IAM`) checked on the processed template; `CAPABILITY_AUTO_EXPAND` for transforms run by CreateStack/UpdateStack (change sets process them without it) and for nested stacks, which run with the capabilities the root stack was given |
| Rollback triggers | ✅ | `RollbackConfiguration` is stored and echoed by `DescribeStacks`/`DescribeChangeSet`; a trigger alarm (metric or composite) in `ALARM` during the operation or the `MonitoringTimeInMinutes` window rolls it back. The window runs on the emulated clock as CloudFormation last saw it in a request |
| Resource attributes | ✅ | `DependsOn`, `Condition`, `DeletionPolicy`/`UpdateReplacePolicy` (`Retain`, `RetainExceptOnCreate`, `Snapshot`, `Delete`), `CreationPolicy` signals. Rollbacks delete what the failed operation created unless its policy is `Retain` (`DELETE_SKIPPED`) and the stack's `RetainExceptOnCreate` is off; `RetainExceptOnCreate` resources are always deleted then. `Snapshot` snapshots `AWS::EC2::Volume` (and the RDS and ElastiCache types) before deleting; other types are deleted, as AWS falls back to `Delete` |
| Change sets | ✅ | `CREATE` and `UPDATE` with Add/Modify/Remove, `Replacement` (`True`/`Conditional`/`False`) and property details, execution, the "didn't contain changes" failure. Created asynchronously (`CREATE_PENDING` → `CREATE_IN_PROGRESS` → `CREATE_COMPLETE`/`FAILED`, `ExecutionStatus` `UNAVAILABLE` until then); executing is `EXECUTE_IN_PROGRESS` until the stack operation ends, then `EXECUTE_COMPLETE` or `EXECUTE_FAILED`. Stacks in states UpdateStack refuses (`ROLLBACK_COMPLETE`, `UPDATE_ROLLBACK_FAILED`, …) are refused with the same `ValidationError` |
| Change sets: `IMPORT` | ✅ | `ResourcesToImport` looked up in the owning service; `DeletionPolicy` required, no other changes allowed, resources another stack manages refused; `IMPORT_COMPLETE` / `IMPORT_ROLLBACK_COMPLETE` |
| Exports and imports | ✅ | `ListExports`, `ListImports`, exports in use block updates and deletes |
| Nested stacks | ✅ | `AWS::CloudFormation::Stack` with `Outputs.*` attributes, `ParentId`/`RootId` |
| Custom resources | ✅ | Lambda- and SNS-backed, `cfn-response` for inline Python and Node.js code, `ResponseURL` callbacks |
| Wait conditions and signals | ✅ | Wait condition handles (presigned-style URLs on MWS), `SignalResource`, creation policy counts and timeouts |
| Stack policies | ✅ | `SetStackPolicy`, `StackPolicyDuringUpdateBody`, `Update:*` actions with AWS's denial messages |
| Drift detection | 🟡 | Stack and resource drift with property differences for SQS, S3, Logs, Kinesis, EC2 VPCs and instances, ECS clusters and services, ECR repositories, EFS file systems, ELBv2 load balancers and target groups and SES configuration sets; other types report `NOT_CHECKED` |
| Notifications | ✅ | Stack events published to `NotificationARNs` in AWS's message format |
| StackSets | ✅ | Self-managed (administration role assumed as `cloudformation.amazonaws.com`, then the execution role in each target account) and service-managed (Organizations OUs, auto-deployment, delegated administrators); operation preferences (concurrency, failure tolerance, region order, `PARALLEL`), account gate Lambda, overrides, drift, import of existing stacks, retained deletes |
| Registry: resource types | ✅ | `RegisterType` from a `cfn submit`-style zip in S3 (`schema.json`, `.rpdk-config`, handler package); handlers run as Lambda functions speaking the CloudFormation CLI handler protocol, with callbacks and `RecordHandlerProgress`; versions, default version, `TestType` contract tests, `PublishType`, publishers, `ActivateType`/`DeactivateType`, type configuration |
| Registry: modules | ✅ | `MODULE` types expand into the parent template with prefixed logical ids; `Module.Resource` references in the parent resolve |
| Hooks | ✅ | Hook handlers run before create, update and delete with `FAIL`/`WARN` failure modes and target filters; hook events and `GetHookResult`/`ListHookResults` |
| Resource scans | 🟡 | Full and partial (type filters, `Svc::*` wildcards) scans of 17 resource types (see below), managed-by-stack flags, tag and prefix filters, related resources |
| Generated templates | ✅ | From scanned resources or an existing stack; JSON or YAML; `Retain` policies; references between included resources become `Ref`/`Fn::GetAtt`; write-only properties reported |
| Stack refactors | ✅ | Moves (auto-detected by logical id, or mapped manually) and renames across stacks, new stacks with `EnableStackCreation`; refuses added, deleted or changed resources; exports re-resolved across stacks; `OBSOLETE` when a stack changes; rollback on failure |
| `DescribeEvents` | ✅ | Events grouped by operation id with operation type and status, change set creation events, `FailedEvents` filter |
| Registry: built-in types | 🟡 | `ListTypes` and `DescribeType` describe the resource types MWS deploys (schemas are synthesized, not AWS's) |
| Transforms | ✅ | Run server-side: `Fn::ForEach` (`AWS::LanguageExtensions`, in any section, nested, `${Id}`/`&{Id}` keys), `AWS::Include` through `Fn::Transform` (S3 `s3://` or HTTPS locations), user macros (`AWS::CloudFormation::Macro`; the macro's Lambda gets AWS's event and its fragment replaces the template or snippet). `GetTemplate` returns `Original` (default) or `Processed` |
| SAM (`AWS::Serverless-2016-10-31`) | 🟡 | `AWS::Serverless::Function` (role with managed policies, inline statements and common policy templates; `SQS`, `Kinesis`, `DynamoDB`, `SNS`, `S3`, `Schedule`, `EventBridgeRule` events; `Globals.Function`), `LayerVersion` and `Application` (template URL). Types needing services MWS does not deploy (API Gateway, DynamoDB, Step Functions) fail the transform |

## Resource types

| Service | Types |
| --- | --- |
| CloudFormation | `Stack`, `CustomResource` / `Custom::*`, `WaitCondition`, `WaitConditionHandle` |
| IAM | `Role`, `User`, `Group`, `Policy`, `ManagedPolicy`, `RolePolicy`, `UserPolicy`, `GroupPolicy`, `InstanceProfile`, `AccessKey`, `UserToGroupAddition`, `OIDCProvider` |
| S3 | `Bucket` (versioning, encryption, public access block, CORS, lifecycle, ownership, website, notifications, object lock, tags), `BucketPolicy` |
| SQS | `Queue`, `QueuePolicy`, `QueueInlinePolicy` |
| SNS | `Topic`, `Subscription`, `TopicPolicy`, `TopicInlinePolicy` |
| Lambda | `Function` (inline `ZipFile` or S3 code), `Permission`, `EventSourceMapping`, `Version`, `Alias`, `Url`, `LayerVersion` |
| KMS | `Key`, `Alias` |
| SSM | `Parameter` |
| Secrets Manager | `Secret` (with `GenerateSecretString`), `ResourcePolicy` |
| CloudWatch Logs | `LogGroup`, `LogStream`, `MetricFilter`, `SubscriptionFilter` |
| EventBridge | `EventBus`, `Rule` (with targets) |
| Kinesis and Firehose | `Kinesis::Stream`, `KinesisFirehose::DeliveryStream` |
| CloudWatch | `Alarm`, `CompositeAlarm`, `Dashboard` |
| Route 53 | `HostedZone`, `RecordSet`, `RecordSetGroup`, `HealthCheck` |
| ACM | `Certificate` (DNS validation records written to `HostedZoneId`, waits for `ISSUED`) |
| Private CA | `CertificateAuthority`, `CertificateAuthorityActivation`, `Certificate`, `Permission` |
| EC2 and VPC | `VPC`, `Subnet`, `SecurityGroup`, `SecurityGroupIngress`, `SecurityGroupEgress`, `InternetGateway`, `VPCGatewayAttachment`, `RouteTable`, `Route`, `SubnetRouteTableAssociation`, `EIP`, `EIPAssociation`, `NatGateway`, `NetworkInterface`, `NetworkAcl`, `NetworkAclEntry`, `SubnetNetworkAclAssociation`, `KeyPair` (private key in `/ec2/keypair/<id>`), `Volume`, `VolumeAttachment`, `Instance` |
| ECS | `Cluster`, `TaskDefinition`, `Service` (waits for a steady state; `ForceNewDeployment`), `CapacityProvider`, `ClusterCapacityProviderAssociations`, `TaskSet` |
| ECR | `Repository` (scanning, mutability, encryption, repository and lifecycle policies, `EmptyOnDelete`), `RegistryPolicy`, `ReplicationConfiguration`, `PullThroughCacheRule`, `RepositoryCreationTemplate` |
| EFS | `FileSystem` (lifecycle, backup and file system policies, protection, replication; waits for `available`), `MountTarget`, `AccessPoint` |
| Elastic Load Balancing | `ElasticLoadBalancingV2::LoadBalancer` (waits for `active`), `TargetGroup`, `Listener`, `ListenerRule`, `ListenerCertificate`; Classic `ElasticLoadBalancing::LoadBalancer` (listeners, health check, instances, attributes, policies) |
| SES | `EmailIdentity` (DKIM token attributes), `ConfigurationSet`, `ConfigurationSetEventDestination`, `Template`, `ContactList`, `DedicatedIpPool`, `ReceiptRuleSet`, `ReceiptRule`, `ReceiptFilter` |
| RDS | `DBInstance` (create, restore from `DBSnapshotIdentifier`, read replica from `SourceDBInstanceIdentifier`; waits for `available`; `Endpoint.*`, `DBInstanceArn`, `DbiResourceId`, `MasterUserSecret.SecretArn`, `CertificateDetails.*`), `DBCluster` (create, restore from snapshot or point in time; `Endpoint.*`, `ReadEndpoint.Address`, `DBClusterArn`, `DBClusterResourceId`), `DBSubnetGroup`, `DBParameterGroup`, `DBClusterParameterGroup` (parameters applied `immediate` or `pending-reboot` by their apply type), `OptionGroup`, `EventSubscription`; `DeletionPolicy: Snapshot` takes a manual DB or cluster snapshot named `<stack>-<logical id>-<random>` |
| ElastiCache | `CacheCluster` (`RedisEndpoint.*`, `ConfigurationEndpoint.*`), `ReplicationGroup` (`PrimaryEndPoint.*`, `ReaderEndPoint.*`, `ReadEndPoint.*`, `ConfigurationEndPoint.*`; replica and shard counts change in place), `ServerlessCache`, `SubnetGroup`, `ParameterGroup`, `User`, `UserGroup`; all wait for `available`/`active`; `DeletionPolicy: Snapshot` snapshots Redis/Valkey clusters and replication groups |
| Auto Scaling | `AutoScalingGroup` (waits until its desired capacity is `InService`; notifications, metrics collection, `PropagateAtLaunch` tags; deletes by scaling in to zero first), `LaunchConfiguration`, `ScalingPolicy`, `LifecycleHook`, `ScheduledAction`, `WarmPool` |
| EKS | `Cluster` (waits for `ACTIVE`; version, VPC endpoint, logging, access and other config updates in place; `Arn`, `Endpoint`, `CertificateAuthorityData`, `ClusterSecurityGroupId`, `OpenIdConnectIssuerUrl`, `EncryptionConfigKeyArn`), `Nodegroup`, `Addon`, `FargateProfile` (all wait for `ACTIVE`), `AccessEntry` (with `AccessPolicies`), `PodIdentityAssociation` |
| GuardDuty | `Detector`, `IPSet`, `ThreatIntelSet`, `Filter`, `MalwareProtectionPlan` |
| Security Hub | `Hub`, `Standard` (waits for `READY`; `DisabledStandardsControls`), `AutomationRule`, `Insight`, `FindingAggregator`, `DelegatedAdmin` |

Resource scans (and so `IMPORT` change sets) cover `AWS::CloudWatch::Alarm`,
`AWS::EC2::SecurityGroup`, `AWS::EC2::Subnet`, `AWS::EC2::VPC`,
`AWS::Events::Rule`, `AWS::IAM::Role`, `AWS::IAM::User`, `AWS::KMS::Key`,
`AWS::Kinesis::Stream`, `AWS::Lambda::Function`, `AWS::Logs::LogGroup`,
`AWS::Route53::HostedZone`, `AWS::S3::Bucket`, `AWS::SNS::Topic`,
`AWS::SQS::Queue`, `AWS::SSM::Parameter` and `AWS::SecretsManager::Secret`.

## Known gaps

- Resource scans cover the 17 types above, not every type CloudFormation can
  deploy. Lambda code is not readable back, so generated templates mark it as
  a write-only placeholder, as AWS does.
- Registry handlers are real Lambda functions named
  `CloudFormation-resource-<Type>-<version>` (and `-hook-` for hooks), running
  as the `AWSServiceRoleForCloudFormationRegistry` role. On AWS they run in
  CloudFormation's own account, so they are invisible; in MWS they show up in
  `ListFunctions` and `ListRoles` for the registering account.
- `GetTemplate` returns templates with modules already expanded; AWS returns
  the original under `Original` and the expansion under `Processed`
  (transforms do keep both).
- Change set creation runs right after the call returns, so a client
  usually sees `CREATE_COMPLETE` on its first `DescribeChangeSet`; templates
  with transforms (macro Lambda calls) take longer.
- Template-level macros get no `params` (MWS only takes macro names in
  `Transform`, not `{Name, Parameters}` objects). The wording of the
  rollback-trigger stack reason is MWS's own.
- Wait condition, creation policy, custom resource and `TimeoutInMinutes`
  timers still use the wall clock.
- Refactor actions don't list the system tag changes (`TagResources`), since
  MWS doesn't add system tags (below).
- Resources are created one at a time in dependency order; AWS creates
  independent resources in parallel, so event order can differ.
- Resource handler error messages wrap the service's error the way AWS does, but
  request ids in them are random.
- The `aws:cloudformation:stack-name`, `stack-id` and `logical-id` tags AWS adds
  to resources are not added.
- Only the resource types above deploy; templates with other types fail
  validation with `Unrecognized resource types`.
- Changing a nested name (`AWS::SES::Template` `Template.TemplateName`,
  `ReceiptRule` `Rule.Name`, `ConfigurationSetEventDestination`
  `EventDestination.Name`) fails the update (`NotUpdatable`) instead of
  replacing the resource. `TargetGroup.LoadBalancerArns` is read when the
  target group is created or updated, not when it is referenced.
- `AWS::RDS::DBInstance` does not restore to a point in time
  (`RestoreTime`/`UseLatestRestorableTime`), and `AutoScalingGroup`
  `UpdatePolicy` (rolling and replacing updates) is not applied: changes are
  made in place with `UpdateAutoScalingGroup`.
- `DescribeType` schemas are synthesized from what MWS supports and are not AWS's
  published schemas.

See also: [all services](README.md) · [authentication and authorization](../security.md).
