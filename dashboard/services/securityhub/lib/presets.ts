// What the console fills in for a new insight or automation rule, and the
// logos findings lead with. Shared by the server pages and the client
// fields (no server-only imports).

/** The finding attributes an insight can group by (the ASFF filter names). */
export const GROUP_BY = [
  "ResourceId", "ResourceType", "ResourceRegion", "ResourceTags", "ResourceAwsIamUserUserName", "ResourceContainerImageName",
  "AwsAccountId", "AwsAccountName", "Region", "ProductArn", "ProductName", "CompanyName", "GeneratorId", "Type", "Title",
  "SeverityLabel", "Criticality", "Confidence", "ComplianceStatus", "ComplianceSecurityControlId", "ComplianceAssociatedStandardsId",
  "WorkflowStatus", "RecordState", "VerificationState", "MalwareName", "MalwareType", "NetworkSourceIpV4", "NetworkDestinationDomain",
  "ProcessName", "ThreatIntelIndicatorType", "NoteUpdatedBy", "VulnerabilitiesExploitAvailable", "VulnerabilitiesFixAvailable",
];

export interface InsightPreset {
  id: string;
  label: string;
  /** An icon id, or a lucide icon the client fields draw (`lucide:<name>`). */
  icon: string;
  name: string;
  group: string;
  severity?: string;
}

export const INSIGHT_PRESETS: InsightPreset[] = [
  { id: "resource", label: "By resource", icon: "lucide:boxes", name: "Findings by resource", group: "ResourceId" },
  { id: "critical", label: "Critical", icon: "lucide:siren", name: "Critical findings by resource", group: "ResourceId", severity: "CRITICAL" },
  { id: "resource-type", label: "By resource type", icon: "lucide:layers", name: "Findings by resource type", group: "ResourceType" },
  { id: "type", label: "By finding type", icon: "resource/AWSSecurityHubFinding", name: "Findings by type", group: "Type" },
  { id: "control", label: "By control", icon: "resource/AWSTrustedAdvisorChecklistSecurity", name: "Findings by control", group: "ComplianceSecurityControlId" },
  { id: "product", label: "By product", icon: "service/AWSSecurityHub", name: "Findings by product", group: "ProductName" },
  { id: "account", label: "By account", icon: "resource/AWSOrganizationsAccount", name: "Findings by account", group: "AwsAccountId" },
  { id: "ip", label: "By source IP", icon: "lucide:network", name: "Findings by source IP", group: "NetworkSourceIpV4" },
  { id: "user", label: "By IAM user", icon: "resource/AWSIdentityAccessManagementLongTermSecurityCredential", name: "Findings by IAM user", group: "ResourceAwsIamUserUserName" },
];

export interface RulePreset {
  id: string;
  label: string;
  icon: string;
  name: string;
  severity: string;
  status: string;
}

export const RULE_PRESETS: RulePreset[] = [
  { id: "suppress-informational", label: "Suppress informational", icon: "lucide:bell-off", name: "Suppress informational findings", severity: "INFORMATIONAL", status: "SUPPRESSED" },
  { id: "suppress-low", label: "Suppress low", icon: "lucide:bell-minus", name: "Suppress low findings", severity: "LOW", status: "SUPPRESSED" },
  { id: "notify-critical", label: "Notify critical", icon: "lucide:siren", name: "Notify on critical findings", severity: "CRITICAL", status: "NOTIFIED" },
  { id: "notify-high", label: "Notify high", icon: "lucide:bell-ring", name: "Notify on high findings", severity: "HIGH", status: "NOTIFIED" },
];

/** The logo of the product that sent a finding. */
export function productIcon(productArn: string | undefined, productName?: string): string {
  const p = `${productArn ?? ""} ${productName ?? ""}`.toLowerCase();
  if (p.includes("guardduty")) return "service/AmazonGuardDuty";
  if (p.includes("inspector")) return "service/AmazonInspector";
  if (p.includes("macie")) return "service/AmazonMacie";
  if (p.includes("access-analyzer") || p.includes("access analyzer")) return "resource/AWSIdentityAccessManagementIAMAccessAnalyzer";
  if (p.includes("/config") || p.includes(" config")) return "service/AWSConfig";
  if (p.includes("firewall-manager") || p.includes("firewall manager")) return "service/AWSFirewallManager";
  if (p.includes("health")) return "service/AWSHealthDashboard";
  return "resource/AWSSecurityHubFinding";
}

const CONTROL_SERVICE: Record<string, string> = {
  S3: "AmazonSimpleStorageService",
  EC2: "AmazonEC2",
  IAM: "AWSIdentityandAccessManagement",
  Lambda: "AWSLambda",
  KMS: "AWSKeyManagementService",
  RDS: "AmazonRDS",
  CloudTrail: "AWSCloudTrail",
  Config: "AWSConfig",
  GuardDuty: "AmazonGuardDuty",
  SecretsManager: "AWSSecretsManager",
  SQS: "AmazonSimpleQueueService",
  SNS: "AmazonSimpleNotificationService",
  EKS: "AmazonElasticKubernetesService",
  ECS: "AmazonElasticContainerService",
  ECR: "AmazonElasticContainerRegistry",
  ELB: "ElasticLoadBalancing",
  DynamoDB: "AmazonDynamoDB",
  CloudWatch: "AmazonCloudWatch",
  CloudFront: "AmazonCloudFront",
  APIGateway: "AmazonAPIGateway",
  WAF: "AWSWAF",
  Opensearch: "AmazonOpenSearchService",
  ES: "AmazonOpenSearchService",
  Redshift: "AmazonRedshift",
  ACM: "AWSCertificateManager",
  ElastiCache: "AmazonElastiCache",
  EFS: "AmazonEFS",
  EMR: "AmazonEMR",
  SageMaker: "AmazonSageMaker",
  CloudFormation: "AWSCloudFormation",
  CodeBuild: "AWSCodeBuild",
  Kinesis: "AmazonKinesisDataStreams",
  EventBridge: "AmazonEventBridge",
  StepFunctions: "AWSStepFunctions",
  AutoScaling: "AmazonEC2AutoScaling",
  SSM: "AWSSystemsManager",
  Macie: "AmazonMacie",
  Inspector: "AmazonInspector",
  Route53: "AmazonRoute53",
  DocumentDB: "AmazonDocumentDB",
  Neptune: "AmazonNeptune",
  Backup: "AWSBackup",
  NetworkFirewall: "AWSNetworkFirewall",
  Athena: "AmazonAthena",
  Glue: "AWSGlue",
  MQ: "AmazonMQ",
  MSK: "AmazonManagedStreamingforApacheKafka",
  DataFirehose: "AmazonDataFirehose",
  AppSync: "AWSAppSync",
  Cognito: "AmazonCognito",
  VPC: "AmazonVirtualPrivateCloud",
};

/** The service a control checks, from its id (`S3.1` → S3's icon). */
export function controlIcon(id: string | undefined): string {
  const svc = CONTROL_SERVICE[(id ?? "").split(".")[0]];
  return svc ? `service/${svc}` : "service/AWSSecurityHub";
}
