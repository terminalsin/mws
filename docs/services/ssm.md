# AWS Systems Manager Parameter Store

> Crate: [`mws-ssm`](../../crates/services/mws-ssm) · Tests: [`tests/e2e-rust/tests/e2e/ssm.rs`](../../tests/e2e-rust/tests/e2e/ssm.rs)

The Parameter Store part of Systems Manager: 19 of the 152 SSM operations,
generated from the AWS model (awsJson1.1).

## Behaviour

`PutParameter`, `GetParameter`, `GetParameters`, `GetParametersByPath`,
`DescribeParameters`, `GetParameterHistory`, `DeleteParameter(s)`,
`LabelParameterVersion`, `UnlabelParameterVersion`, tags, service settings, and
resource policies. Parameters keep up to 100 versions
(`ParameterMaxVersionLimitExceeded` when the oldest is labelled), are read by
name, ARN, `name:version` or `name:label`, and follow AWS's naming rules
(reserved `aws`/`ssm` prefixes, 15 hierarchy levels, `foo` and `/foo` being the
same parameter).

`String`, `StringList` and `SecureString` types,
`text`/`aws:ec2:image`/`aws:ssm:integration` data types, allowed patterns,
Standard/Advanced/Intelligent-Tiering tiers with their size limits and the
account's default tier setting, and every `ParameterFilters` key and option.
SecureStrings are really encrypted with KMS for the caller (`alias/aws/ssm` by
default, `kms:ViaService`, encryption context `PARAMETER_ARN`; envelope
encryption for advanced parameters), so `WithDecryption` needs `kms:Decrypt`.

Parameter policies are validated, and `Expiration` deletes the parameter when
the emulated clock passes it. Advanced parameters can be shared with other
accounts through resource policies (read by ARN, `DescribeParameters --shared`).
`/aws/reference/secretsmanager/<id>[:version-or-label]` names read the secret
from Secrets Manager as the caller (`secretsmanager:GetSecretValue` and the
secret's KMS key apply). Every policy sends its "Parameter Store Policy Action"
event to EventBridge when the emulated clock reaches it
(`ExpirationNotification` and `NoChangeNotification` then show `Finished`).

Public parameters under `/aws/service/` answer `GetParameter(s)` and
`GetParametersByPath` with account-less ARNs: the Region and service catalogues
under `global-infrastructure/` and the latest Amazon Linux, ECS- and
EKS-optimized AMI parameters (stable made-up `ami-` ids per Region, since there
is no EC2). Creating, updating, deleting and labelling a parameter sends a
"Parameter Store Change" event to the default bus.

## Known gaps

The rest of Systems Manager, which answers `NotImplemented`: Run Command,
Automation and runbooks, State Manager associations, documents, managed nodes
and hybrid activations, inventory, compliance, Patch Manager, maintenance
windows, Session Manager, OpsCenter and OpsMetadata, Change Calendar, Explorer
resource data syncs and node/access requests.

See also: [all services](README.md) · [authentication and authorization](../security.md).
