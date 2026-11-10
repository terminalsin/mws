// Starting points for new roles and policies: who the role trusts (with the
// AWS managed policy that role usually needs), and the common customer
// managed policies. Plain data, shared by server and client.

export interface RolePreset {
  id: string;
  label: string;
  icon: string;
  group: string;
  /** The service principal it trusts; empty for account and custom trust. */
  service?: string;
  /** Who else may assume it: "account" trusts this account's principals. */
  trust?: "account" | "cross-account" | "github" | "saml" | "custom";
  name: string;
  /** An AWS managed policy the role usually needs, attached on create. */
  attach?: string;
}

const P = "arn:aws:iam::aws:policy/";

export const ROLE_PRESETS: RolePreset[] = [
  { id: "lambda", label: "Lambda", icon: "service/AWSLambda", group: "Compute", service: "lambda.amazonaws.com", name: "lambda-role", attach: `${P}service-role/AWSLambdaBasicExecutionRole` },
  { id: "ec2", label: "EC2", icon: "service/AmazonEC2", group: "Compute", service: "ec2.amazonaws.com", name: "ec2-role", attach: `${P}AmazonSSMManagedInstanceCore` },
  { id: "ecs-tasks", label: "ECS task", icon: "service/AmazonElasticContainerService", group: "Compute", service: "ecs-tasks.amazonaws.com", name: "ecs-task-role", attach: `${P}service-role/AmazonECSTaskExecutionRolePolicy` },
  { id: "eks", label: "EKS cluster", icon: "service/AmazonElasticKubernetesService", group: "Compute", service: "eks.amazonaws.com", name: "eks-cluster-role", attach: `${P}AmazonEKSClusterPolicy` },
  { id: "eks-pods", label: "EKS pods", icon: "service/AmazonElasticKubernetesService", group: "Compute", service: "pods.eks.amazonaws.com", name: "eks-pod-role" },
  { id: "imagebuilder", label: "Image Builder", icon: "service/AmazonEC2ImageBuilder", group: "Compute", service: "imagebuilder.amazonaws.com", name: "imagebuilder-role" },
  { id: "autoscaling", label: "Auto Scaling", icon: "resource/AmazonEC2AutoScaling", group: "Compute", service: "autoscaling.amazonaws.com", name: "autoscaling-role" },
  { id: "events", label: "EventBridge", icon: "service/AmazonEventBridge", group: "Integration", service: "events.amazonaws.com", name: "events-role" },
  { id: "scheduler", label: "Scheduler", icon: "resource/AmazonEventBridgeScheduler", group: "Integration", service: "scheduler.amazonaws.com", name: "scheduler-role" },
  { id: "states", label: "Step Functions", icon: "service/AWSStepFunctions", group: "Integration", service: "states.amazonaws.com", name: "states-role", attach: `${P}service-role/AWSLambdaRole` },
  { id: "sns", label: "SNS", icon: "service/AmazonSimpleNotificationService", group: "Integration", service: "sns.amazonaws.com", name: "sns-delivery-role" },
  { id: "apigateway", label: "API Gateway", icon: "service/AmazonAPIGateway", group: "Integration", service: "apigateway.amazonaws.com", name: "apigateway-role", attach: `${P}service-role/AmazonAPIGatewayPushToCloudWatchLogs` },
  { id: "firehose", label: "Firehose", icon: "service/AmazonDataFirehose", group: "Data", service: "firehose.amazonaws.com", name: "firehose-role" },
  { id: "logs", label: "CloudWatch Logs", icon: "resource/AmazonCloudWatchLogs", group: "Data", service: "logs.amazonaws.com", name: "logs-subscription-role" },
  { id: "glue", label: "Glue", icon: "service/AWSGlue", group: "Data", service: "glue.amazonaws.com", name: "glue-role", attach: `${P}service-role/AWSGlueServiceRole` },
  { id: "s3", label: "S3 replication", icon: "service/AmazonSimpleStorageService", group: "Data", service: "s3.amazonaws.com", name: "s3-replication-role" },
  { id: "rds", label: "RDS monitoring", icon: "service/AmazonRDS", group: "Data", service: "monitoring.rds.amazonaws.com", name: "rds-monitoring-role", attach: `${P}service-role/AmazonRDSEnhancedMonitoringRole` },
  { id: "bedrock", label: "Bedrock", icon: "service/AmazonBedrock", group: "Data", service: "bedrock.amazonaws.com", name: "bedrock-role" },
  { id: "codebuild", label: "CodeBuild", icon: "service/AWSCodeBuild", group: "Developer", service: "codebuild.amazonaws.com", name: "codebuild-role", attach: `${P}CloudWatchLogsFullAccess` },
  { id: "cloudformation", label: "CloudFormation", icon: "service/AWSCloudFormation", group: "Developer", service: "cloudformation.amazonaws.com", name: "cloudformation-deploy-role" },
  { id: "amplify", label: "Amplify", icon: "service/AWSAmplify", group: "Developer", service: "amplify.amazonaws.com", name: "amplify-role" },
  { id: "ses", label: "SES", icon: "service/AmazonSimpleEmailService", group: "Developer", service: "ses.amazonaws.com", name: "ses-role" },
  { id: "account", label: "This account", icon: "resource/AWSOrganizationsAccount", group: "People and other accounts", trust: "account", name: "account-role" },
  { id: "cross-account", label: "Another account", icon: "group/AWSAccount", group: "People and other accounts", trust: "cross-account", name: "cross-account-role" },
  { id: "github", label: "GitHub Actions", icon: "brand/githubactions", group: "People and other accounts", trust: "github", name: "github-actions-deploy" },
  { id: "saml", label: "SAML", icon: "resource/AWSIdentityAccessManagementLongTermSecurityCredential", group: "People and other accounts", trust: "saml", name: "saml-federated-role" },
  { id: "custom", label: "Custom", icon: "resource/AWSIdentityAccessManagementPermissions", group: "People and other accounts", trust: "custom", name: "" },
];

export interface PolicyPreset {
  id: string;
  label: string;
  icon: string;
  group: string;
  name: string;
  description?: string;
  /** The document's statements; Resource "*" unless the template narrows it. */
  statements: object[];
}

const allow = (Action: string | string[], Resource: string | string[] = "*", extra: object = {}) => ({ Effect: "Allow", Action, Resource, ...extra });
const deny = (Action: string | string[], Resource: string | string[] = "*", extra: object = {}) => ({ Effect: "Deny", Action, Resource, ...extra });

export const POLICY_PRESETS: PolicyPreset[] = [
  // Storage and data
  { id: "s3-read", group: "Storage and data", label: "S3 read", icon: "service/AmazonSimpleStorageService", name: "S3ReadOnly", description: "Read objects in a bucket", statements: [allow(["s3:ListBucket"], "arn:aws:s3:::BUCKET"), allow(["s3:GetObject"], "arn:aws:s3:::BUCKET/*")] },
  { id: "s3-write", group: "Storage and data", label: "S3 read/write", icon: "resource/AmazonSimpleStorageServiceBucket", name: "S3ReadWrite", description: "Read and write objects in a bucket", statements: [allow(["s3:ListBucket"], "arn:aws:s3:::BUCKET"), allow(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], "arn:aws:s3:::BUCKET/*")] },
  { id: "s3-prefix", group: "Storage and data", label: "S3 home folder", icon: "resource/AmazonSimpleStorageServiceObject", name: "S3UserHomeFolder", description: "Each user reads and writes only home/<their name>/", statements: [allow("s3:ListBucket", "arn:aws:s3:::BUCKET", { Condition: { StringLike: { "s3:prefix": ["home/${aws:username}/*"] } } }), allow(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], "arn:aws:s3:::BUCKET/home/${aws:username}/*")] },
  { id: "dynamodb", group: "Storage and data", label: "DynamoDB", icon: "service/AmazonDynamoDB", name: "DynamoDBReadWrite", description: "Read and write items in a table", statements: [allow(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem"], "arn:aws:dynamodb:*:*:table/TABLE")] },
  { id: "secrets", group: "Storage and data", label: "Secrets", icon: "service/AWSSecretsManager", name: "SecretsRead", description: "Read secret values", statements: [allow(["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"])] },
  { id: "params", group: "Storage and data", label: "Parameters", icon: "resource/AWSSystemsManagerParameterStore", name: "ParameterStoreRead", description: "Read parameters under a path", statements: [allow(["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"], "arn:aws:ssm:*:*:parameter/app/*"), allow("kms:Decrypt", "*", { Condition: { StringLike: { "kms:ViaService": "ssm.*.amazonaws.com" } } })] },
  { id: "kms", group: "Storage and data", label: "KMS", icon: "service/AWSKeyManagementService", name: "KMSEncryptDecrypt", description: "Encrypt and decrypt with a key", statements: [allow(["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"])] },
  // Messaging and events
  { id: "sqs-consume", group: "Messaging and events", label: "SQS consumer", icon: "service/AmazonSimpleQueueService", name: "SQSConsume", description: "Receive and delete messages", statements: [allow(["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"])] },
  { id: "sqs-send", group: "Messaging and events", label: "SQS producer", icon: "resource/AmazonSimpleQueueServiceQueue", name: "SQSSend", description: "Send messages to queues", statements: [allow(["sqs:SendMessage", "sqs:GetQueueUrl"])] },
  { id: "sns", group: "Messaging and events", label: "SNS publish", icon: "service/AmazonSimpleNotificationService", name: "SNSPublish", description: "Publish to topics", statements: [allow("sns:Publish")] },
  { id: "events", group: "Messaging and events", label: "Put events", icon: "service/AmazonEventBridge", name: "EventBridgePutEvents", description: "Send events to buses", statements: [allow("events:PutEvents")] },
  { id: "kinesis", group: "Messaging and events", label: "Kinesis", icon: "service/AmazonKinesisDataStreams", name: "KinesisProduceConsume", description: "Put and read records", statements: [allow(["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStreamSummary", "kinesis:ListShards"])] },
  // Compute and apps
  { id: "lambda", group: "Compute and apps", label: "Invoke Lambda", icon: "service/AWSLambda", name: "LambdaInvoke", description: "Invoke functions", statements: [allow("lambda:InvokeFunction")] },
  { id: "lambda-deploy", group: "Compute and apps", label: "Deploy Lambda", icon: "resource/AWSLambdaLambdaFunction", name: "LambdaDeploy", description: "Update function code and pass its role", statements: [allow(["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:GetFunction", "lambda:PublishVersion", "lambda:UpdateAlias"]), allow("iam:PassRole", "*", { Condition: { StringEquals: { "iam:PassedToService": "lambda.amazonaws.com" } } })] },
  { id: "ecr-pull", group: "Compute and apps", label: "ECR pull", icon: "service/AmazonElasticContainerRegistry", name: "ECRPull", description: "Pull container images", statements: [allow(["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"])] },
  { id: "ecr-push", group: "Compute and apps", label: "ECR push", icon: "resource/AmazonElasticContainerRegistryRegistry", name: "ECRPush", description: "Push container images (CI)", statements: [allow("ecr:GetAuthorizationToken"), allow(["ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage"], "arn:aws:ecr:*:*:repository/REPOSITORY")] },
  { id: "bedrock", group: "Compute and apps", label: "Bedrock", icon: "service/AmazonBedrock", name: "BedrockInvoke", description: "Invoke foundation models", statements: [allow(["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], "arn:aws:bedrock:*::foundation-model/*")] },
  { id: "ec2-ops", group: "Compute and apps", label: "EC2 operator", icon: "service/AmazonEC2", name: "EC2StartStopByTag", description: "Start and stop instances tagged with your team", statements: [allow("ec2:Describe*"), allow(["ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances"], "*", { Condition: { StringEquals: { "aws:ResourceTag/team": "${aws:PrincipalTag/team}" } } })] },
  // Observability
  { id: "logs", group: "Observability", label: "Write logs", icon: "resource/AmazonCloudWatchLogs", name: "LogsWrite", description: "Write log events", statements: [allow(["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"])] },
  { id: "logs-read", group: "Observability", label: "Read logs", icon: "service/AmazonCloudWatch", name: "LogsRead", description: "Search and read log events", statements: [allow(["logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:GetLogEvents", "logs:FilterLogEvents", "logs:StartQuery", "logs:GetQueryResults"])] },
  { id: "metrics", group: "Observability", label: "Put metrics", icon: "resource/AmazonCloudWatchAlarm", name: "CloudWatchPutMetrics", description: "Publish custom metrics", statements: [allow("cloudwatch:PutMetricData", "*", { Condition: { StringEquals: { "cloudwatch:namespace": "MyApp" } } })] },
  // Guardrails
  { id: "mfa", group: "Guardrails", label: "Require MFA", icon: "resource/AWSIdentityAccessManagementLongTermSecurityCredential", name: "DenyWithoutMFA", description: "Deny everything but MFA setup until signed in with MFA", statements: [{ Sid: "DenyAllExceptMFASetupWithoutMFA", Effect: "Deny", NotAction: ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:GetUser", "iam:ListMFADevices", "iam:ListVirtualMFADevices", "iam:ResyncMFADevice", "sts:GetSessionToken"], Resource: "*", Condition: { BoolIfExists: { "aws:MultiFactorAuthPresent": "false" } } }] },
  { id: "regions", group: "Guardrails", label: "Restrict Regions", icon: "group/Region", name: "DenyOutsideRegions", description: "Deny requests outside chosen Regions", statements: [deny("*", "*", { Condition: { StringNotEquals: { "aws:RequestedRegion": ["us-east-1", "us-west-2"] } } })] },
  { id: "ip", group: "Guardrails", label: "Office IPs only", icon: "resource/Internet", name: "DenyOutsideOfficeIPs", description: "Deny requests from outside an IP range", statements: [deny("*", "*", { Condition: { NotIpAddress: { "aws:SourceIp": ["203.0.113.0/24"] }, Bool: { "aws:ViaAWSService": "false" } } })] },
  { id: "self-manage", group: "Guardrails", label: "Own credentials", icon: "resource/User", name: "ManageOwnCredentials", description: "Users manage their own password, keys and MFA", statements: [allow(["iam:ChangePassword", "iam:GetUser", "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:ListMFADevices", "iam:EnableMFADevice", "iam:ResyncMFADevice"], "arn:aws:iam::*:user/${aws:username}"), allow(["iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice"], "arn:aws:iam::*:mfa/${aws:username}")] },
  { id: "abac", group: "Guardrails", label: "Team tags (ABAC)", icon: "resource/AWSIdentityAccessManagementPermissions", name: "TeamTagAccess", description: "Act only on resources tagged with your team", statements: [allow("*", "*", { Condition: { StringEquals: { "aws:ResourceTag/team": "${aws:PrincipalTag/team}" } } })] },
  { id: "custom", group: "Guardrails", label: "Custom", icon: "resource/AWSIdentityAccessManagementPermissions", name: "", statements: [allow("s3:GetObject")] },
];

export const policyJson = (p: PolicyPreset) =>
  JSON.stringify({ Version: "2012-10-17", Statement: p.statements.map((s) => JSON.parse(JSON.stringify(s))) }, null, 2);

const doc = (statement: object) => JSON.stringify({ Version: "2012-10-17", Statement: [statement] }, null, 2);

export const trustJson = (account: string) => doc({ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: "sts:AssumeRole" });

/** The trust policy a preset starts from. */
export function presetTrust(p: RolePreset, account: string | null): string | undefined {
  const acct = account ?? "123456789012";
  switch (p.trust) {
    case "account":
      return trustJson(acct);
    case "cross-account":
      return doc({ Effect: "Allow", Principal: { AWS: "arn:aws:iam::OTHER_ACCOUNT_ID:root" }, Action: "sts:AssumeRole", Condition: { StringEquals: { "sts:ExternalId": "choose-a-shared-secret" } } });
    case "github":
      return doc({
        Effect: "Allow",
        Principal: { Federated: `arn:aws:iam::${acct}:oidc-provider/token.actions.githubusercontent.com` },
        Action: "sts:AssumeRoleWithWebIdentity",
        Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" }, StringLike: { "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:ref:refs/heads/main" } },
      });
    case "saml":
      return doc({ Effect: "Allow", Principal: { Federated: `arn:aws:iam::${acct}:saml-provider/PROVIDER` }, Action: ["sts:AssumeRoleWithSAML", "sts:TagSession"], Condition: { StringEquals: { "SAML:aud": "https://signin.aws.amazon.com/saml" } } });
    case "custom":
      return undefined;
    default:
      return p.service ? doc({ Effect: "Allow", Principal: { Service: p.service }, Action: "sts:AssumeRole" }) : undefined;
  }
}

/** AWS managed policies people attach most, as tiles on the attach form. */
export const COMMON_POLICIES: { id: string; label: string; icon: string }[] = [
  { id: "AdministratorAccess", label: "Admin", icon: "category/SecurityIdentity" },
  { id: "PowerUserAccess", label: "Power user", icon: "resource/AWSIdentityAccessManagementPermissions" },
  { id: "ReadOnlyAccess", label: "Read only", icon: "resource/AWSIdentityAccessManagementIAMAccessAnalyzer" },
  { id: "AmazonS3FullAccess", label: "S3", icon: "service/AmazonSimpleStorageService" },
  { id: "AmazonDynamoDBFullAccess", label: "DynamoDB", icon: "service/AmazonDynamoDB" },
  { id: "AmazonSQSFullAccess", label: "SQS", icon: "service/AmazonSimpleQueueService" },
  { id: "AWSLambda_FullAccess", label: "Lambda", icon: "service/AWSLambda" },
  { id: "AmazonEC2FullAccess", label: "EC2", icon: "service/AmazonEC2" },
  { id: "CloudWatchLogsFullAccess", label: "Logs", icon: "resource/AmazonCloudWatchLogs" },
].map((p) => ({ ...p, title: p.id }));

export const managedArn = (name: string) => `arn:aws:iam::aws:policy/${name}`;

export interface OidcPreset {
  id: string;
  label: string;
  icon: string;
  group: string;
  url: string;
  audience: string;
  /** The URL needs the person's own tenant or host filled in. */
  tenant?: boolean;
}

export const OIDC_PRESETS: OidcPreset[] = [
  { id: "github", label: "GitHub Actions", icon: "brand/githubactions", group: "CI/CD", url: "https://token.actions.githubusercontent.com", audience: "sts.amazonaws.com" },
  { id: "gitlab", label: "GitLab", icon: "brand/gitlab", group: "CI/CD", url: "https://gitlab.com", audience: "https://gitlab.com" },
  { id: "terraform", label: "HCP Terraform", icon: "brand/terraform", group: "CI/CD", url: "https://app.terraform.io", audience: "aws.workload.identity" },
  { id: "bitbucket", label: "Bitbucket", icon: "brand/bitbucket", group: "CI/CD", url: "https://api.bitbucket.org/2.0/workspaces/WORKSPACE/pipelines-config/identity/oidc", audience: "", tenant: true },
  { id: "circleci", label: "CircleCI", icon: "brand/circleci", group: "CI/CD", url: "https://oidc.circleci.com/org/ORG_ID", audience: "", tenant: true },
  { id: "buildkite", label: "Buildkite", icon: "brand/buildkite", group: "CI/CD", url: "https://agent.buildkite.com", audience: "sts.amazonaws.com" },
  { id: "google", label: "Google", icon: "brand/google", group: "Identity", url: "https://accounts.google.com", audience: "" },
  { id: "okta", label: "Okta", icon: "brand/okta", group: "Identity", url: "https://YOUR_ORG.okta.com", audience: "", tenant: true },
  { id: "auth0", label: "Auth0", icon: "brand/auth0", group: "Identity", url: "https://YOUR_TENANT.auth0.com", audience: "", tenant: true },
  { id: "keycloak", label: "Keycloak", icon: "brand/keycloak", group: "Identity", url: "https://keycloak.example.com/realms/REALM", audience: "", tenant: true },
  { id: "kubernetes", label: "Kubernetes", icon: "brand/kubernetes", group: "Identity", url: "", audience: "sts.amazonaws.com", tenant: true },
];

/** A provider URL's logo, matched by host. */
export function oidcIcon(url: string | undefined): string | undefined {
  const u = (url ?? "").replace(/^https?:\/\//, "");
  if (u.startsWith("oidc.eks.")) return "service/AmazonElasticKubernetesService";
  const host = u.split("/")[0];
  return OIDC_PRESETS.find((p) => !p.tenant && p.url && new URL(p.url).host === host)?.icon ?? OIDC_PRESETS.find((p) => p.tenant && p.url && host.endsWith(new URL(p.url).host.split(".").slice(-2).join(".")))?.icon;
}
