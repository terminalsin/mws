# EC2 Image Builder

> Crate: [`mws-imagebuilder`](../../crates/services/mws-imagebuilder) · Tests: [`tests/e2e-rust/tests/e2e/imagebuilder.rs`](../../tests/e2e-rust/tests/e2e/imagebuilder.rs)

All 77 operations of the model are implemented (restJson1). Builds are real: they launch instances in MWS's [EC2](ec2.md) and output ordinary AMIs you can `RunInstances` from.

✅ supported · 🟡 partial · ❌ not supported

## Resources

| Feature | Status | Details |
| --- | :---: | --- |
| Components | ✅ | AWSTOE YAML documents (validated: phases, actions, parameters), inline or from an S3 `uri`; shell scripts through `ImportComponent`; `BUILD` or `TEST` type from the phases; component parameters checked in recipes. |
| Image and container recipes | ✅ | Parent images as AMI ids, Image Builder image ARNs (managed, own or shared) or `ssm:` parameters resolved at build time; block devices, working directory, user data, Dockerfile templates. |
| Infrastructure configurations | ✅ | The instance profile must exist in IAM (`iam:PassRole` checked); subnets, security groups, key pairs, SNS topics and metadata options are validated against MWS. |
| Distribution configurations | ✅ | AMI names with `{{ imagebuilder:buildDate }}` and `{{ imagebuilder:buildVersion }}`, tags, launch permissions, target accounts, KMS keys, SSM parameter outputs; one entry per Region. |
| Versioning | ✅ | Semantic versions with build numbers, `1.x.x` wildcards in ARNs, latest-version references, `byName` listings, `Self`, `Shared` and `Amazon` owners. |
| AWS-managed resources | ✅ | Components (`update-linux`, `hello-world-linux`, `reboot-linux`, `aws-cli-version-2-linux`, `amazon-cloudwatch-agent-linux`, `docker-ce-linux`, `python-3-linux`, ...), images (Amazon Linux 2023 x86/arm64, Amazon Linux 2, Ubuntu 24.04 and 22.04, mapped to EC2's public AMIs) and workflows (`build-image`, `test-image`, `build-container`, `test-container`). |
| Idempotency and dependencies | ✅ | Client tokens (`IdempotentParameterMismatchException` on a changed request); deletes fail with `ResourceDependencyException` while something uses the resource. |
| Marketplace and third-party components | ❌ | None exist; `GetMarketplaceResource` answers not found and `ThirdParty` lists nothing. |

## Builds

| Feature | Status | Details |
| --- | :---: | --- |
| Pipelines | ✅ | Manual runs and cron schedules on the emulated clock, `EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE` (builds only when a resolved input changed), auto-disable after consecutive failures, image tests on or off. |
| Build workflow | ✅ | Steps recorded as workflow and step executions: launch the build instance with the infrastructure configuration, run the build and validate phases, collect packages, `CreateImage`, terminate; then a test instance runs the test phases. Image state moves `PENDING`, `BUILDING`, `TESTING`, `DISTRIBUTING`, `INTEGRATING`, `AVAILABLE` (or `FAILED` with the failing component and step, or `CANCELLED`). |
| Components that run | ✅ | With EC2's Docker backend the AWSTOE steps run inside the build instance's container (`ExecuteBash`, file and folder actions, `S3Download` through the AWS CLI, `WebDownload`, `UpdateOS`, `Assert`, ...), and the AMI is a `docker commit` of the result. With the metadata backend steps succeed without running. |
| Custom workflows | ✅ | `WaitForAction` with `ListWaitingWorkflowSteps` and `SendWorkflowStepAction` (resume or stop), JSONPath step inputs, `if` conditions, parameters, `onFailure`. |
| Distribution | ✅ | `CopyImage` to other Regions, copies into target accounts, launch permissions, AMI tags, SSM parameters with the AMI id; `DistributeImage` redistributes an existing image. |
| Cancel, retry, import | 🟡 | `CancelImageCreation`, `RetryImage` and `ImportDiskImage` (an AMI from an S3 ISO) work; `ImportVmImage` reports that the import task does not exist because VM Import/Export is not emulated. |
| Launch template updates | ❌ | EC2 has no launch templates yet; the setting is ignored. |
| Container images | 🟡 | Container recipes build, but nothing is pushed to ECR (not emulated yet). |
| Scan findings | 🟡 | `ListImageScanFindings` and the aggregations answer empty lists (no Inspector). |
| AWSTOE coverage | 🟡 | Windows-only actions are no-ops, a step's `loop` runs it once, `ExecuteDocument` fails the step; schedule time zones other than UTC are treated as UTC. |

## Lifecycle and integrations

| Feature | Status | Details |
| --- | :---: | --- |
| Lifecycle policies | ✅ | Run daily on the emulated clock: deprecate, disable or delete images and their AMIs by count or age (with `retainAtLeast`), selected by recipe or tags, with exclusion rules; executions and their resources are listed. |
| Resource state updates | ✅ | `StartResourceStateUpdate` deprecates, disables or deletes one image and its AMIs. |
| Logs and notifications | ✅ | Build logs in CloudWatch Logs (`/aws/imagebuilder/<recipe>`) and the infrastructure configuration's S3 bucket; the SNS topic gets the image document; `EC2 Image Builder Image State Change` events go to EventBridge. |
| Resource policies | ✅ | Component, image, image recipe and container recipe policies share resources with other accounts (`Owner=Shared`). |
| Authorization and tags | ✅ | Every call is authorized as `imagebuilder:<Action>` with tag conditions; tags on every resource. |

See also: [all services](README.md) · [EC2](ec2.md).
