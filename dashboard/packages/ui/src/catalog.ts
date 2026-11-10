// Every service the console knows: how to show it (official AWS icon and
// name), where it sits in the navigation (category), and where its pages
// are. Each service's pages are their own package (services/<id>/), mounted
// into the one console app; navigation lists only services with a `path`.

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
  /** The service's landing page, once it has pages. */
  path?: string;
  /** The names MWS's /_mws/health reports for this service. */
  endpoints: string[];
  /** The service's own navigation, as in the AWS console's service sidebar:
   * each with a resource icon. */
  nav?: NavItem[];
}

export interface NavItem {
  label: string;
  path: string;
  icon: string;
}

const NAV: Record<string, NavItem[]> = {
  bedrock: [
    { label: "Model catalog", path: "/bedrock", icon: "service/AmazonBedrock" },
    { label: "Chat playground", path: "/bedrock/playground", icon: "resource/AmazonSageMakerAIModel" },
    { label: "Guardrails", path: "/bedrock/guardrails", icon: "resource/AWSIdentityAccessManagementPermissions" },
    { label: "Inference profiles", path: "/bedrock/profiles", icon: "group/Region" },
    { label: "Settings", path: "/bedrock/settings", icon: "service/AmazonCloudWatch" },
  ],
  amplify: [{ label: "All apps", path: "/amplify", icon: "service/AWSAmplify" }],
  codeartifact: [
    { label: "Repositories", path: "/codeartifact", icon: "service/AWSCodeArtifact" },
    { label: "Domains", path: "/codeartifact?tab=domains", icon: "group/AWSAccount" },
  ],
  imagebuilder: [
    { label: "Image pipelines", path: "/imagebuilder", icon: "service/AmazonEC2ImageBuilder" },
    { label: "Images", path: "/imagebuilder?tab=images", icon: "resource/AmazonEC2AMI" },
    { label: "Image recipes", path: "/imagebuilder?tab=recipes", icon: "resource/AWSCloudFormationTemplate" },
    { label: "Components", path: "/imagebuilder?tab=components", icon: "resource/AmazonSimpleStorageServiceObject" },
    { label: "Infrastructure configurations", path: "/imagebuilder?tab=infrastructure", icon: "resource/AmazonEC2Instance" },
  ],
  autoscaling: [{ label: "Auto Scaling groups", path: "/autoscaling", icon: "resource/AmazonEC2AutoScaling" }],
  marketplace: [
    { label: "Products", path: "/marketplace", icon: "service/AWSMarketplace" },
    { label: "Metering records", path: "/marketplace?tab=records", icon: "service/AmazonCloudWatch" },
  ],
  organizations: [
    { label: "AWS accounts", path: "/organizations", icon: "resource/AWSOrganizationsAccount" },
    { label: "Policies", path: "/organizations?tab=policies", icon: "resource/AWSIdentityAccessManagementPermissions" },
  ],
  cloudformation: [{ label: "Stacks", path: "/cloudformation", icon: "resource/AWSCloudFormationStack" }],
  cloudtrail: [
    { label: "Event history", path: "/cloudtrail", icon: "service/AWSCloudTrail" },
    { label: "Trails", path: "/cloudtrail?tab=trails", icon: "resource/AWSCloudTrailCloudTrailLake" },
  ],
  servicequotas: [
    { label: "AWS services", path: "/servicequotas", icon: "service/AWSTrustedAdvisor" },
    { label: "Quota request history", path: "/servicequotas?tab=requests", icon: "resource/AWSIdentityAccessManagementPermissions" },
  ],
  ce: [
    { label: "Cost and usage", path: "/ce", icon: "service/AWSCostExplorer" },
    { label: "Anomaly detection", path: "/ce/anomalies", icon: "resource/AWSTrustedAdvisorChecklistCost" },
    { label: "Cost categories", path: "/ce/categories", icon: "service/AWSCostandUsageReport" },
  ],
  securityhub: [
    { label: "Findings", path: "/securityhub", icon: "resource/AWSSecurityHubFinding" },
    { label: "Insights", path: "/securityhub?tab=insights", icon: "resource/AmazonCloudWatchMetricsInsights" },
    { label: "Automation rules", path: "/securityhub?tab=rules", icon: "resource/AmazonEventBridgeRule" },
    { label: "Custom actions", path: "/securityhub?tab=actions", icon: "resource/AmazonEventBridgeCustomEventBus" },
    { label: "Security standards", path: "/securityhub?tab=standards", icon: "service/AWSSecurityHub" },
  ],
  guardduty: [{ label: "Findings", path: "/guardduty", icon: "service/AmazonGuardDuty" }],
  identitycenter: [
    { label: "Users", path: "/identitycenter", icon: "resource/User" },
    { label: "Groups", path: "/identitycenter?tab=groups", icon: "resource/Users" },
    { label: "Permission sets", path: "/identitycenter?tab=permissionsets", icon: "resource/AWSIdentityAccessManagementPermissions" },
  ],
  ram: [
    { label: "Shared by me", path: "/ram", icon: "service/AWSResourceAccessManager" },
    { label: "Shared with me", path: "/ram?tab=others", icon: "resource/AWSOrganizationsAccount" },
  ],
  ecr: [{ label: "Private repositories", path: "/ecr", icon: "resource/AmazonElasticContainerRegistryRegistry" }],
  ecs: [
    { label: "Clusters", path: "/ecs", icon: "service/AmazonElasticContainerService" },
    { label: "Task definitions", path: "/ecs?tab=taskdefs", icon: "resource/AmazonElasticContainerServiceTask" },
  ],
  eks: [{ label: "Clusters", path: "/eks", icon: "brand/kubernetes" }],
  rds: [
    { label: "Databases", path: "/rds", icon: "service/AmazonRDS" },
    { label: "Snapshots", path: "/rds?tab=snapshots", icon: "resource/AmazonRDSMultiAZ" },
  ],
  elasticache: [{ label: "Caches", path: "/elasticache", icon: "resource/AmazonElastiCacheCacheNode" }],
  efs: [{ label: "File systems", path: "/efs", icon: "resource/AmazonElasticFileSystemFileSystem" }],
  kinesis: [{ label: "Data streams", path: "/kinesis", icon: "service/AmazonKinesisDataStreams" }],
  firehose: [{ label: "Firehose streams", path: "/firehose", icon: "service/AmazonDataFirehose" }],
  vpc: [
    { label: "Your VPCs", path: "/vpc", icon: "resource/AmazonVPCVirtualprivatecloudVPC" },
    { label: "Subnets", path: "/vpc?tab=subnets", icon: "group/Privatesubnet" },
    { label: "Route tables", path: "/vpc?tab=routes", icon: "resource/AmazonVPCRouter" },
    { label: "Internet gateways", path: "/vpc?tab=igw", icon: "resource/AmazonVPCInternetGateway" },
    { label: "NAT gateways", path: "/vpc?tab=nat", icon: "resource/AmazonVPCNATGateway" },
    { label: "Endpoints", path: "/vpc?tab=endpoints", icon: "resource/AmazonVPCEndpoints" },
    { label: "Peering connections", path: "/vpc?tab=peering", icon: "resource/AmazonVPCPeeringConnection" },
    { label: "Network ACLs", path: "/vpc?tab=acls", icon: "resource/AmazonVPCNetworkAccessControlList" },
  ],
  route53: [
    { label: "Hosted zones", path: "/route53", icon: "resource/AmazonRoute53HostedZone" },
    { label: "Health checks", path: "/route53?tab=health", icon: "resource/AmazonRoute53ReadinessChecks" },
  ],
  elb: [
    { label: "Load balancers", path: "/elb", icon: "resource/ElasticLoadBalancingApplicationLoadBalancer" },
    { label: "Target groups", path: "/elb?tab=targets", icon: "resource/ElasticLoadBalancingNetworkLoadBalancer" },
  ],
  globalaccelerator: [{ label: "Accelerators", path: "/ga", icon: "service/AWSGlobalAccelerator" }],
  acm: [{ label: "Certificates", path: "/acm", icon: "service/AWSCertificateManager" }],
  acmpca: [{ label: "Private CAs", path: "/pca", icon: "resource/AWSCertificateManagerCertificateAuthority" }],
  ec2: [
    { label: "Instances", path: "/ec2", icon: "resource/AmazonEC2Instances" },
    { label: "Images", path: "/ec2?tab=images", icon: "resource/AmazonEC2AMI" },
    { label: "Key pairs", path: "/ec2?tab=keys", icon: "resource/AWSIdentityAccessManagementLongTermSecurityCredential" },
    { label: "Security groups", path: "/ec2?tab=groups", icon: "resource/AmazonVPCNetworkAccessControlList" },
  ],
  lambda: [{ label: "Functions", path: "/lambda", icon: "resource/AWSLambdaLambdaFunction" }],
  s3: [{ label: "Buckets", path: "/s3", icon: "resource/AmazonSimpleStorageServiceBucket" }],
  sqs: [{ label: "Queues", path: "/sqs", icon: "resource/AmazonSimpleQueueServiceQueue" }],
  sns: [
    { label: "Topics", path: "/sns", icon: "resource/AmazonSimpleNotificationServiceTopic" },
    { label: "Deliveries", path: "/sns?tab=outbox", icon: "resource/AmazonSimpleNotificationServiceEmailNotification" },
  ],
  events: [{ label: "Buses and rules", path: "/events", icon: "resource/AmazonEventBridgeRule" }],
  ses: [
    { label: "Identities", path: "/ses", icon: "resource/AmazonSimpleEmailServiceEmail" },
    { label: "Sent mail", path: "/ses?tab=outbox", icon: "resource/AmazonSimpleNotificationServiceEmailNotification" },
  ],
  iam: [
    { label: "Users", path: "/iam", icon: "resource/User" },
    { label: "Roles", path: "/iam?tab=roles", icon: "resource/AWSIdentityAccessManagementRole" },
    { label: "Groups", path: "/iam?tab=groups", icon: "resource/Users" },
    { label: "Policies", path: "/iam?tab=policies", icon: "resource/AWSIdentityAccessManagementPermissions" },
  ],
  kms: [
    { label: "Customer managed keys", path: "/kms", icon: "resource/AWSIdentityAccessManagementDataEncryptionKey" },
    { label: "AWS managed keys", path: "/kms?tab=aws", icon: "resource/AWSIdentityAccessManagementEncryptedData" },
  ],
  secretsmanager: [{ label: "Secrets", path: "/secrets", icon: "service/AWSSecretsManager" }],
  ssm: [{ label: "Parameter Store", path: "/ssm", icon: "resource/AWSSystemsManagerParameterStore" }],
  cloudwatch: [
    { label: "Alarms", path: "/alarms", icon: "resource/AmazonCloudWatchAlarm" },
    { label: "Log groups", path: "/logs", icon: "resource/AmazonCloudWatchLogs" },
    { label: "Metrics", path: "/metrics", icon: "resource/AmazonCloudWatchMetricsInsights" },
  ],
};

const svc = (s: Service): Service => ({ ...s, nav: s.nav ?? NAV[s.id] });

export const SERVICES: Service[] = [
  // Compute
  svc({ id: "ec2", name: "Amazon EC2", short: "EC2", category: "compute", icon: "service/AmazonEC2", path: "/ec2", endpoints: ["ec2"] }),
  svc({ id: "lambda", name: "AWS Lambda", short: "Lambda", category: "compute", icon: "service/AWSLambda", path: "/lambda", endpoints: ["lambda"] }),
  svc({ id: "autoscaling", name: "EC2 Auto Scaling", short: "Auto Scaling", category: "compute", icon: "service/AmazonEC2AutoScaling", path: "/autoscaling", endpoints: ["autoscaling"] }),
  svc({ id: "imagebuilder", name: "EC2 Image Builder", short: "Image Builder", category: "compute", icon: "service/AmazonEC2ImageBuilder", path: "/imagebuilder", endpoints: ["imagebuilder"] }),
  // Containers
  svc({ id: "ecr", name: "Amazon ECR", short: "ECR", category: "containers", icon: "service/AmazonElasticContainerRegistry", path: "/ecr", endpoints: ["ecr", "ecr-public"] }),
  svc({ id: "ecs", name: "Amazon ECS", short: "ECS", category: "containers", icon: "service/AmazonElasticContainerService", path: "/ecs", endpoints: ["ecs"] }),
  svc({ id: "eks", name: "Amazon EKS", short: "EKS", category: "containers", icon: "service/AmazonElasticKubernetesService", path: "/eks", endpoints: ["eks"] }),
  // Storage
  svc({ id: "s3", name: "Amazon S3", short: "S3", category: "storage", icon: "service/AmazonSimpleStorageService", path: "/s3", endpoints: ["s3", "s3control"] }),
  svc({ id: "efs", name: "Amazon EFS", short: "EFS", category: "storage", icon: "service/AmazonEFS", path: "/efs", endpoints: ["elasticfilesystem"] }),
  // Database
  svc({ id: "rds", name: "Amazon RDS", short: "RDS", category: "database", icon: "service/AmazonRDS", path: "/rds", endpoints: ["rds"] }),
  svc({ id: "elasticache", name: "Amazon ElastiCache", short: "ElastiCache", category: "database", icon: "service/AmazonElastiCache", path: "/elasticache", endpoints: ["elasticache"] }),
  // Networking
  svc({ id: "vpc", name: "Amazon VPC", short: "VPC", category: "networking", icon: "service/AmazonVirtualPrivateCloud", path: "/vpc", endpoints: ["ec2"] }),
  svc({ id: "route53", name: "Amazon Route 53", short: "Route 53", category: "networking", icon: "service/AmazonRoute53", path: "/route53", endpoints: ["route53"] }),
  svc({ id: "elb", name: "Elastic Load Balancing", short: "Load Balancers", category: "networking", icon: "service/ElasticLoadBalancing", path: "/elb", endpoints: ["elb", "elbv2"] }),
  svc({ id: "globalaccelerator", name: "AWS Global Accelerator", short: "Global Accelerator", category: "networking", icon: "service/AWSGlobalAccelerator", path: "/ga", endpoints: ["globalaccelerator"] }),
  // Integration
  svc({ id: "sqs", name: "Amazon SQS", short: "SQS", category: "integration", icon: "service/AmazonSimpleQueueService", path: "/sqs", endpoints: ["sqs"] }),
  svc({ id: "sns", name: "Amazon SNS", short: "SNS", category: "integration", icon: "service/AmazonSimpleNotificationService", path: "/sns", endpoints: ["sns"] }),
  svc({ id: "events", name: "Amazon EventBridge", short: "EventBridge", category: "integration", icon: "service/AmazonEventBridge", path: "/events", endpoints: ["events"] }),
  svc({ id: "ses", name: "Amazon SES", short: "SES", category: "integration", icon: "service/AmazonSimpleEmailService", path: "/ses", endpoints: ["ses", "sesv2"] }),
  // Analytics
  svc({ id: "kinesis", name: "Amazon Kinesis Data Streams", short: "Kinesis", category: "analytics", icon: "service/AmazonKinesisDataStreams", path: "/kinesis", endpoints: ["kinesis"] }),
  svc({ id: "firehose", name: "Amazon Data Firehose", short: "Firehose", category: "analytics", icon: "service/AmazonDataFirehose", path: "/firehose", endpoints: ["firehose"] }),
  // Security & identity
  svc({ id: "iam", name: "AWS IAM", short: "IAM", category: "security", icon: "service/AWSIdentityandAccessManagement", path: "/iam", endpoints: ["iam", "sts"] }),
  svc({ id: "kms", name: "AWS KMS", short: "KMS", category: "security", icon: "service/AWSKeyManagementService", path: "/kms", endpoints: ["kms"] }),
  svc({ id: "secretsmanager", name: "AWS Secrets Manager", short: "Secrets Manager", category: "security", icon: "service/AWSSecretsManager", path: "/secrets", endpoints: ["secretsmanager"] }),
  svc({ id: "acm", name: "AWS Certificate Manager", short: "Certificates", category: "security", icon: "service/AWSCertificateManager", path: "/acm", endpoints: ["acm"] }),
  svc({ id: "acmpca", name: "AWS Private CA", short: "Private CA", category: "security", icon: "service/AWSPrivateCertificateAuthority", path: "/pca", endpoints: ["acm-pca", "pca-connector-scep"] }),
  svc({ id: "identitycenter", name: "IAM Identity Center", short: "Identity Center", category: "security", icon: "service/AWSIAMIdentityCenter", path: "/identitycenter", endpoints: ["sso", "identitystore", "awsssoportal", "sso-oauth"] }),
  svc({ id: "guardduty", name: "Amazon GuardDuty", short: "GuardDuty", category: "security", icon: "service/AmazonGuardDuty", path: "/guardduty", endpoints: ["guardduty"] }),
  svc({ id: "securityhub", name: "AWS Security Hub", short: "Security Hub", category: "security", icon: "service/AWSSecurityHub", path: "/securityhub", endpoints: ["securityhub"] }),
  svc({ id: "ram", name: "AWS Resource Access Manager", short: "RAM", category: "security", icon: "service/AWSResourceAccessManager", path: "/ram", endpoints: ["ram"] }),
  // Management
  svc({ id: "cloudwatch", name: "Amazon CloudWatch", short: "CloudWatch", category: "management", icon: "service/AmazonCloudWatch", path: "/logs", endpoints: ["logs", "monitoring"] }),
  svc({ id: "ssm", name: "AWS Systems Manager", short: "Systems Manager", category: "management", icon: "service/AWSSystemsManager", path: "/ssm", endpoints: ["ssm"] }),
  svc({ id: "cloudformation", name: "AWS CloudFormation", short: "CloudFormation", category: "management", icon: "service/AWSCloudFormation", path: "/cloudformation", endpoints: ["cloudformation"] }),
  svc({ id: "cloudtrail", name: "AWS CloudTrail", short: "CloudTrail", category: "management", icon: "service/AWSCloudTrail", path: "/cloudtrail", endpoints: ["cloudtrail", "cloudtrail-data"] }),
  svc({ id: "organizations", name: "AWS Organizations", short: "Organizations", category: "management", icon: "service/AWSOrganizations", path: "/organizations", endpoints: ["organizations"] }),
  svc({ id: "servicequotas", name: "Service Quotas", short: "Service Quotas", category: "management", icon: "service/AWSTrustedAdvisor", path: "/servicequotas", endpoints: ["servicequotas"] }),
  // Developer tools
  svc({ id: "codeartifact", name: "AWS CodeArtifact", short: "CodeArtifact", category: "developer", icon: "service/AWSCodeArtifact", path: "/codeartifact", endpoints: ["codeartifact"] }),
  // AI
  svc({ id: "bedrock", name: "Amazon Bedrock", short: "Bedrock", category: "ai", icon: "service/AmazonBedrock", path: "/bedrock", endpoints: ["bedrock", "bedrock-runtime"] }),
  // Web & mobile
  svc({ id: "amplify", name: "AWS Amplify", short: "Amplify", category: "frontend", icon: "service/AWSAmplify", path: "/amplify", endpoints: ["amplify"] }),
  // Cost
  svc({ id: "ce", name: "AWS Cost Explorer", short: "Cost Explorer", category: "cost", icon: "service/AWSCostExplorer", path: "/ce", endpoints: ["ce"] }),
  svc({ id: "marketplace", name: "AWS Marketplace", short: "Marketplace", category: "cost", icon: "service/AWSMarketplace", path: "/marketplace", endpoints: ["marketplace-metering", "marketplace-entitlement"] }),
];

export function service(id: string): Service {
  const s = SERVICES.find((x) => x.id === id);
  if (!s) throw new Error(`unknown service ${id}`);
  return s;
}

/** Services that have console pages, grouped by category in catalog order. */
export function navigation() {
  return CATEGORIES.map((c) => ({ category: c, services: SERVICES.filter((s) => s.category === c.id && s.path) })).filter(
    (g) => g.services.length > 0,
  );
}

/** The URL of an icon served by the console (from the official AWS icon set). */
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
