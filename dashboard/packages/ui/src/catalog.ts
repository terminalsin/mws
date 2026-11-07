// Every service the console knows: how to show it (official AWS icon and
// name), where it sits in the navigation (category), and which zone serves
// its pages. Navigation lists only services whose `zone` is set, so a service
// appears the moment its pages exist.
import type { ZoneId } from "./zones";

export type CategoryId =
  | "compute"
  | "containers"
  | "storage"
  | "database"
  | "networking"
  | "integration"
  | "analytics"
  | "security"
  | "management"
  | "developer"
  | "ai"
  | "frontend"
  | "cost";

export interface Category {
  id: CategoryId;
  name: string;
  /** File name (no extension) under /icons/aws/. */
  icon: string;
}

export const CATEGORIES: Category[] = [
  { id: "compute", name: "Compute", icon: "category/Compute" },
  { id: "containers", name: "Containers", icon: "category/Containers" },
  { id: "storage", name: "Storage", icon: "category/Storage" },
  { id: "database", name: "Database", icon: "category/Databases" },
  { id: "networking", name: "Networking", icon: "category/NetworkingContentDelivery" },
  { id: "integration", name: "Integration", icon: "category/ApplicationIntegration" },
  { id: "analytics", name: "Analytics", icon: "category/Analytics" },
  { id: "security", name: "Security & Identity", icon: "category/SecurityIdentity" },
  { id: "management", name: "Management", icon: "category/ManagementTools" },
  { id: "developer", name: "Developer Tools", icon: "category/DeveloperTools" },
  { id: "ai", name: "AI", icon: "category/ArtificialIntelligence" },
  { id: "frontend", name: "Web & Mobile", icon: "category/FrontEndWebMobile" },
  { id: "cost", name: "Cost", icon: "category/CloudFinancialManagement" },
];

export interface Service {
  /** Stable id, used in URLs and search results. */
  id: string;
  name: string;
  /** Short name for the sidebar. */
  short: string;
  category: CategoryId;
  icon: string;
  /** The zone that serves the service's pages, once it has any. */
  zone?: ZoneId;
  /** The service's landing path inside its zone. */
  path?: string;
  /** The names MWS's /_mws/health reports for this service. */
  endpoints: string[];
}

const svc = (s: Service) => s;

export const SERVICES: Service[] = [
  // Compute
  svc({ id: "ec2", name: "Amazon EC2", short: "EC2", category: "compute", icon: "service/AmazonEC2", zone: "compute", path: "/ec2", endpoints: ["ec2"] }),
  svc({ id: "lambda", name: "AWS Lambda", short: "Lambda", category: "compute", icon: "service/AWSLambda", zone: "compute", path: "/lambda", endpoints: ["lambda"] }),
  svc({ id: "autoscaling", name: "EC2 Auto Scaling", short: "Auto Scaling", category: "compute", icon: "service/AmazonEC2AutoScaling", endpoints: ["autoscaling"] }),
  svc({ id: "imagebuilder", name: "EC2 Image Builder", short: "Image Builder", category: "compute", icon: "service/AmazonEC2ImageBuilder", endpoints: ["imagebuilder"] }),
  // Containers
  svc({ id: "ecr", name: "Amazon ECR", short: "ECR", category: "containers", icon: "service/AmazonElasticContainerRegistry", endpoints: ["ecr", "ecr-public"] }),
  svc({ id: "ecs", name: "Amazon ECS", short: "ECS", category: "containers", icon: "service/AmazonElasticContainerService", endpoints: ["ecs"] }),
  svc({ id: "eks", name: "Amazon EKS", short: "EKS", category: "containers", icon: "service/AmazonElasticKubernetesService", endpoints: ["eks"] }),
  // Storage
  svc({ id: "s3", name: "Amazon S3", short: "S3", category: "storage", icon: "service/AmazonSimpleStorageService", zone: "storage", path: "/s3", endpoints: ["s3", "s3control"] }),
  svc({ id: "efs", name: "Amazon EFS", short: "EFS", category: "storage", icon: "service/AmazonEFS", endpoints: ["elasticfilesystem"] }),
  // Database
  svc({ id: "rds", name: "Amazon RDS", short: "RDS", category: "database", icon: "service/AmazonRDS", endpoints: ["rds"] }),
  svc({ id: "elasticache", name: "Amazon ElastiCache", short: "ElastiCache", category: "database", icon: "service/AmazonElastiCache", endpoints: ["elasticache"] }),
  // Networking
  svc({ id: "vpc", name: "Amazon VPC", short: "VPC", category: "networking", icon: "service/AmazonVirtualPrivateCloud", endpoints: ["ec2"] }),
  svc({ id: "route53", name: "Amazon Route 53", short: "Route 53", category: "networking", icon: "service/AmazonRoute53", endpoints: ["route53"] }),
  svc({ id: "elb", name: "Elastic Load Balancing", short: "Load Balancers", category: "networking", icon: "service/ElasticLoadBalancing", endpoints: ["elb", "elbv2"] }),
  svc({ id: "globalaccelerator", name: "AWS Global Accelerator", short: "Global Accelerator", category: "networking", icon: "service/AWSGlobalAccelerator", endpoints: ["globalaccelerator"] }),
  // Integration
  svc({ id: "sqs", name: "Amazon SQS", short: "SQS", category: "integration", icon: "service/AmazonSimpleQueueService", zone: "messaging", path: "/sqs", endpoints: ["sqs"] }),
  svc({ id: "sns", name: "Amazon SNS", short: "SNS", category: "integration", icon: "service/AmazonSimpleNotificationService", zone: "messaging", path: "/sns", endpoints: ["sns"] }),
  svc({ id: "events", name: "Amazon EventBridge", short: "EventBridge", category: "integration", icon: "service/AmazonEventBridge", zone: "messaging", path: "/events", endpoints: ["events"] }),
  svc({ id: "ses", name: "Amazon SES", short: "SES", category: "integration", icon: "service/AmazonSimpleEmailService", zone: "messaging", path: "/ses", endpoints: ["ses", "sesv2"] }),
  // Analytics
  svc({ id: "kinesis", name: "Amazon Kinesis Data Streams", short: "Kinesis", category: "analytics", icon: "service/AmazonKinesisDataStreams", endpoints: ["kinesis"] }),
  svc({ id: "firehose", name: "Amazon Data Firehose", short: "Firehose", category: "analytics", icon: "service/AmazonDataFirehose", endpoints: ["firehose"] }),
  // Security & identity
  svc({ id: "iam", name: "AWS IAM", short: "IAM", category: "security", icon: "service/AWSIdentityandAccessManagement", zone: "security", path: "/iam", endpoints: ["iam", "sts"] }),
  svc({ id: "kms", name: "AWS KMS", short: "KMS", category: "security", icon: "service/AWSKeyManagementService", zone: "security", path: "/kms", endpoints: ["kms"] }),
  svc({ id: "secretsmanager", name: "AWS Secrets Manager", short: "Secrets Manager", category: "security", icon: "service/AWSSecretsManager", zone: "security", path: "/secrets", endpoints: ["secretsmanager"] }),
  svc({ id: "acm", name: "AWS Certificate Manager", short: "Certificates", category: "security", icon: "service/AWSCertificateManager", endpoints: ["acm"] }),
  svc({ id: "acmpca", name: "AWS Private CA", short: "Private CA", category: "security", icon: "service/AWSPrivateCertificateAuthority", endpoints: ["acm-pca", "pca-connector-scep"] }),
  svc({ id: "identitycenter", name: "IAM Identity Center", short: "Identity Center", category: "security", icon: "service/AWSIAMIdentityCenter", endpoints: ["sso", "identitystore", "awsssoportal", "sso-oauth"] }),
  svc({ id: "guardduty", name: "Amazon GuardDuty", short: "GuardDuty", category: "security", icon: "service/AmazonGuardDuty", endpoints: ["guardduty"] }),
  svc({ id: "securityhub", name: "AWS Security Hub", short: "Security Hub", category: "security", icon: "service/AWSSecurityHub", endpoints: ["securityhub"] }),
  svc({ id: "ram", name: "AWS Resource Access Manager", short: "RAM", category: "security", icon: "service/AWSResourceAccessManager", endpoints: ["ram"] }),
  // Management
  svc({ id: "cloudwatch", name: "Amazon CloudWatch", short: "CloudWatch", category: "management", icon: "service/AmazonCloudWatch", zone: "observability", path: "/logs", endpoints: ["logs", "monitoring"] }),
  svc({ id: "ssm", name: "AWS Systems Manager", short: "Systems Manager", category: "management", icon: "service/AWSSystemsManager", zone: "security", path: "/ssm", endpoints: ["ssm"] }),
  svc({ id: "cloudformation", name: "AWS CloudFormation", short: "CloudFormation", category: "management", icon: "service/AWSCloudFormation", endpoints: ["cloudformation"] }),
  svc({ id: "cloudtrail", name: "AWS CloudTrail", short: "CloudTrail", category: "management", icon: "service/AWSCloudTrail", endpoints: ["cloudtrail", "cloudtrail-data"] }),
  svc({ id: "organizations", name: "AWS Organizations", short: "Organizations", category: "management", icon: "service/AWSOrganizations", endpoints: ["organizations"] }),
  svc({ id: "servicequotas", name: "Service Quotas", short: "Service Quotas", category: "management", icon: "service/AWSTrustedAdvisor", endpoints: ["servicequotas"] }),
  // Developer tools
  svc({ id: "codeartifact", name: "AWS CodeArtifact", short: "CodeArtifact", category: "developer", icon: "service/AWSCodeArtifact", endpoints: ["codeartifact"] }),
  // AI
  svc({ id: "bedrock", name: "Amazon Bedrock", short: "Bedrock", category: "ai", icon: "service/AmazonBedrock", endpoints: ["bedrock", "bedrock-runtime"] }),
  // Web & mobile
  svc({ id: "amplify", name: "AWS Amplify", short: "Amplify", category: "frontend", icon: "service/AWSAmplify", endpoints: ["amplify"] }),
  // Cost
  svc({ id: "ce", name: "AWS Cost Explorer", short: "Cost Explorer", category: "cost", icon: "service/AWSCostExplorer", endpoints: ["ce"] }),
  svc({ id: "marketplace", name: "AWS Marketplace", short: "Marketplace", category: "cost", icon: "service/AWSMarketplace", endpoints: ["marketplace-metering", "marketplace-entitlement"] }),
];

export function service(id: string): Service {
  const s = SERVICES.find((x) => x.id === id);
  if (!s) throw new Error(`unknown service ${id}`);
  return s;
}

/** Services that have console pages, grouped by category in catalog order. */
export function navigation() {
  return CATEGORIES.map((c) => ({ category: c, services: SERVICES.filter((s) => s.category === c.id && s.zone) })).filter(
    (g) => g.services.length > 0,
  );
}

/** The URL of an icon served by the shell (from the official AWS icon set). */
export function iconUrl(icon: string) {
  return icon.startsWith("brand/") ? `/icons/${icon}.svg` : `/icons/aws/${icon}.svg`;
}

/** The logo of a Lambda runtime ("python3.12", "nodejs20.x") or a language. */
export function runtimeIcon(runtime: string | undefined): string | undefined {
  if (!runtime) return undefined;
  const brands: [RegExp, string][] = [
    [/^nodejs/, "brand/nodedotjs"],
    [/^python/, "brand/python"],
    [/^java/, "brand/openjdk"],
    [/^dotnet/, "brand/dotnet"],
    [/^ruby/, "brand/ruby"],
    [/^go/, "brand/go"],
    [/^provided/, "brand/linux"],
    [/rust/, "brand/rust"],
    [/docker|image/i, "brand/docker"],
  ];
  return brands.find(([re]) => re.test(runtime))?.[1];
}
