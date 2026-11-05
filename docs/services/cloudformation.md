# AWS CloudFormation

> Crate: [`mws-cloudformation`](../../crates/services/mws-cloudformation) · Tests: [`tests/e2e-rust/tests/e2e/cloudformation.rs`](../../tests/e2e-rust/tests/e2e/cloudformation.rs)

35 of the model's 90 operations are implemented (awsQuery): stacks, change
sets, drift detection, stack policies, exports and the template tools. The rest
(StackSets, the registry's write operations, generated templates, resource
scans, refactors and hooks) answer `NotImplemented`.

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
| Stack lifecycle | ✅ | Create, update (in place, with interruption, or replacement then cleanup), delete; `OnFailure`, `DisableRollback`, rollback, `ContinueUpdateRollback`, `CancelUpdateStack`, `RollbackStack`, `TimeoutInMinutes`, termination protection, `RetainResources` |
| Resource attributes | ✅ | `DependsOn`, `Condition`, `DeletionPolicy`/`UpdateReplacePolicy` (`Retain`, `Delete`), `CreationPolicy` signals |
| Change sets | ✅ | `CREATE` and `UPDATE` with Add/Modify/Remove, `Replacement` (`True`/`Conditional`/`False`) and property details, execution, the "didn't contain changes" failure |
| Change sets: `IMPORT` | ❌ | Rejected |
| Exports and imports | ✅ | `ListExports`, `ListImports`, exports in use block updates and deletes |
| Nested stacks | ✅ | `AWS::CloudFormation::Stack` with `Outputs.*` attributes, `ParentId`/`RootId` |
| Custom resources | ✅ | Lambda- and SNS-backed, `cfn-response` for inline Python and Node.js code, `ResponseURL` callbacks |
| Wait conditions and signals | ✅ | Wait condition handles (presigned-style URLs on MWS), `SignalResource`, creation policy counts and timeouts |
| Stack policies | ✅ | `SetStackPolicy`, `StackPolicyDuringUpdateBody`, `Update:*` actions with AWS's denial messages |
| Drift detection | 🟡 | Stack and resource drift with property differences for SQS, S3, Logs, Kinesis, EC2 VPCs and instances; other types report `NOT_CHECKED` |
| Notifications | ✅ | Stack events published to `NotificationARNs` in AWS's message format |
| Registry | 🟡 | `ListTypes` and `DescribeType` describe the resource types MWS deploys (schemas are synthesized, not AWS's); no registration |
| StackSets, hooks, generated templates, resource scans, refactors | ❌ | `NotImplemented` |
| SAM (`AWS::Serverless-2016-10-31`) | ❌ | Rejected with a message |

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

## Known gaps

- StackSets, `IMPORT` change sets, the registry's write operations (publishing
  and activating types), generated templates, resource scans, stack refactors
  and hooks are not implemented.
- Resources are created one at a time in dependency order; AWS creates
  independent resources in parallel, so event order can differ.
- Resource handler error messages wrap the service's error the way AWS does, but
  request ids in them are random.
- The `aws:cloudformation:stack-name`, `stack-id` and `logical-id` tags AWS adds
  to resources are not added.
- Only the resource types above deploy; templates with other types fail
  validation with `Unrecognized resource types`.
- `DescribeType` schemas are synthesized from what MWS supports and are not AWS's
  published schemas.

See also: [all services](README.md) · [authentication and authorization](../security.md).
