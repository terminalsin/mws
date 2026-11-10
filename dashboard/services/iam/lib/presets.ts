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
  trust?: "account" | "custom";
  name: string;
  /** An AWS managed policy the role usually needs, attached on create. */
  attach?: string;
}

const P = "arn:aws:iam::aws:policy/";

export const ROLE_PRESETS: RolePreset[] = [
  { id: "lambda", label: "Lambda", icon: "service/AWSLambda", group: "AWS service", service: "lambda.amazonaws.com", name: "lambda-role", attach: `${P}service-role/AWSLambdaBasicExecutionRole` },
  { id: "ec2", label: "EC2", icon: "service/AmazonEC2", group: "AWS service", service: "ec2.amazonaws.com", name: "ec2-role", attach: `${P}AmazonSSMManagedInstanceCore` },
  { id: "ecs-tasks", label: "ECS task", icon: "service/AmazonElasticContainerService", group: "AWS service", service: "ecs-tasks.amazonaws.com", name: "ecs-task-role", attach: `${P}service-role/AmazonECSTaskExecutionRolePolicy` },
  { id: "eks", label: "EKS", icon: "service/AmazonElasticKubernetesService", group: "AWS service", service: "eks.amazonaws.com", name: "eks-cluster-role", attach: `${P}AmazonEKSClusterPolicy` },
  { id: "states", label: "Step Functions", icon: "service/AWSStepFunctions", group: "AWS service", service: "states.amazonaws.com", name: "states-role", attach: `${P}service-role/AWSLambdaRole` },
  { id: "events", label: "EventBridge", icon: "service/AmazonEventBridge", group: "AWS service", service: "events.amazonaws.com", name: "events-role" },
  { id: "scheduler", label: "Scheduler", icon: "service/AmazonEventBridge", group: "AWS service", service: "scheduler.amazonaws.com", name: "scheduler-role" },
  { id: "apigateway", label: "API Gateway", icon: "service/AmazonAPIGateway", group: "AWS service", service: "apigateway.amazonaws.com", name: "apigateway-role", attach: `${P}service-role/AmazonAPIGatewayPushToCloudWatchLogs` },
  { id: "glue", label: "Glue", icon: "service/AWSGlue", group: "AWS service", service: "glue.amazonaws.com", name: "glue-role", attach: `${P}service-role/AWSGlueServiceRole` },
  { id: "codebuild", label: "CodeBuild", icon: "service/AWSCodeBuild", group: "AWS service", service: "codebuild.amazonaws.com", name: "codebuild-role", attach: `${P}CloudWatchLogsFullAccess` },
  { id: "firehose", label: "Firehose", icon: "service/AmazonDataFirehose", group: "AWS service", service: "firehose.amazonaws.com", name: "firehose-role" },
  { id: "bedrock", label: "Bedrock", icon: "service/AmazonBedrock", group: "AWS service", service: "bedrock.amazonaws.com", name: "bedrock-role" },
  { id: "account", label: "This account", icon: "resource/AWSOrganizationsAccount", group: "Other", trust: "account", name: "account-role" },
  { id: "custom", label: "Custom", icon: "resource/AWSIdentityAccessManagementPermissions", group: "Other", trust: "custom", name: "" },
];

export interface PolicyPreset {
  id: string;
  label: string;
  icon: string;
  name: string;
  description?: string;
  actions: string[];
  resource: string;
}

export const POLICY_PRESETS: PolicyPreset[] = [
  { id: "s3-read", label: "S3 read", icon: "service/AmazonSimpleStorageService", name: "S3ReadOnly", description: "Read objects", actions: ["s3:GetObject", "s3:ListBucket"], resource: "*" },
  { id: "s3-write", label: "S3 read/write", icon: "resource/AmazonSimpleStorageServiceBucket", name: "S3ReadWrite", description: "Read and write objects", actions: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"], resource: "*" },
  { id: "dynamodb", label: "DynamoDB", icon: "service/AmazonDynamoDB", name: "DynamoDBReadWrite", description: "Read and write items", actions: ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"], resource: "*" },
  { id: "sqs", label: "SQS", icon: "service/AmazonSimpleQueueService", name: "SQSSendReceive", description: "Send and receive messages", actions: ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], resource: "*" },
  { id: "sns", label: "SNS", icon: "service/AmazonSimpleNotificationService", name: "SNSPublish", description: "Publish to topics", actions: ["sns:Publish"], resource: "*" },
  { id: "lambda", label: "Lambda", icon: "service/AWSLambda", name: "LambdaInvoke", description: "Invoke functions", actions: ["lambda:InvokeFunction"], resource: "*" },
  { id: "logs", label: "Logs", icon: "resource/AmazonCloudWatchLogs", name: "LogsWrite", description: "Write log events", actions: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], resource: "*" },
  { id: "secrets", label: "Secrets", icon: "service/AWSSecretsManager", name: "SecretsRead", description: "Read secret values", actions: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], resource: "*" },
  { id: "kms", label: "KMS", icon: "service/AWSKeyManagementService", name: "KMSEncryptDecrypt", description: "Encrypt and decrypt", actions: ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"], resource: "*" },
  { id: "custom", label: "Custom", icon: "resource/AWSIdentityAccessManagementPermissions", name: "", actions: ["s3:GetObject"], resource: "*" },
];

export const policyJson = (p: PolicyPreset) =>
  JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: p.actions.length === 1 ? p.actions[0] : p.actions, Resource: p.resource }] }, null, 2);

export const trustJson = (account: string) =>
  JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: "sts:AssumeRole" }] }, null, 2);

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
