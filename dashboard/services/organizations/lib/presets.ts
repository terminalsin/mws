// Starting points for organization policies: the guardrails people set up
// first. Plain data, shared by server and client.

export interface OrgPolicyPreset {
  id: string;
  label: string;
  icon: string;
  name: string;
  description: string;
  /** The document, for the console's current Region and this organization. */
  content: (region: string, org: string) => object;
}

const doc = (...Statement: object[]) => ({ Version: "2012-10-17", Statement });

const SCP: OrgPolicyPreset[] = [
  {
    id: "region",
    label: "Region lock",
    icon: "category/NetworkingContentDelivery",
    name: "DenyOutsideRegion",
    description: "Deny actions outside the allowed Regions",
    content: (region) =>
      doc({ Sid: "DenyOutsideRegions", Effect: "Deny", NotAction: ["iam:*", "organizations:*", "sts:*", "support:*", "cloudfront:*", "route53:*"], Resource: "*", Condition: { StringNotEquals: { "aws:RequestedRegion": [region] } } }),
  },
  {
    id: "leave",
    label: "Stay in org",
    icon: "service/AWSOrganizations",
    name: "DenyLeaveOrganization",
    description: "Accounts cannot leave the organization",
    content: () => doc({ Sid: "DenyLeave", Effect: "Deny", Action: "organizations:LeaveOrganization", Resource: "*" }),
  },
  {
    id: "root",
    label: "No root user",
    icon: "resource/User",
    name: "DenyRootUser",
    description: "Deny everything to member accounts' root users",
    content: () => doc({ Sid: "DenyRoot", Effect: "Deny", Action: "*", Resource: "*", Condition: { StringLike: { "aws:PrincipalArn": "arn:aws:iam::*:root" } } }),
  },
  {
    id: "cloudtrail",
    label: "Keep CloudTrail",
    icon: "service/AWSCloudTrail",
    name: "ProtectCloudTrail",
    description: "Trails cannot be stopped or deleted",
    content: () => doc({ Sid: "ProtectCloudTrail", Effect: "Deny", Action: ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"], Resource: "*" }),
  },
  {
    id: "guardduty",
    label: "Keep GuardDuty",
    icon: "service/AmazonGuardDuty",
    name: "ProtectGuardDuty",
    description: "GuardDuty cannot be turned off",
    content: () => doc({ Sid: "ProtectGuardDuty", Effect: "Deny", Action: ["guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount", "guardduty:UpdateDetector", "guardduty:DeleteMembers", "guardduty:StopMonitoringMembers"], Resource: "*" }),
  },
  {
    id: "s3-public",
    label: "No public S3",
    icon: "service/AmazonSimpleStorageService",
    name: "ProtectS3PublicAccessBlock",
    description: "S3 Block Public Access cannot be changed",
    content: () => doc({ Sid: "ProtectBlockPublicAccess", Effect: "Deny", Action: ["s3:PutAccountPublicAccessBlock", "s3:PutBucketPublicAccessBlock"], Resource: "*" }),
  },
  {
    id: "imdsv2",
    label: "Require IMDSv2",
    icon: "service/AmazonEC2",
    name: "RequireIMDSv2",
    description: "Instances must use IMDSv2",
    content: () => doc({ Sid: "RequireImdsV2", Effect: "Deny", Action: "ec2:RunInstances", Resource: "arn:aws:ec2:*:*:instance/*", Condition: { StringNotEquals: { "ec2:MetadataHttpTokens": "required" } } }),
  },
];

const RCP: OrgPolicyPreset[] = [
  {
    id: "tls",
    label: "Enforce TLS",
    icon: "service/AmazonSimpleStorageService",
    name: "EnforceTLS",
    description: "Deny S3 requests without TLS",
    content: () => doc({ Sid: "EnforceTLS", Effect: "Deny", Principal: "*", Action: "s3:*", Resource: "*", Condition: { BoolIfExists: { "aws:SecureTransport": "false" } } }),
  },
  {
    id: "org-only",
    label: "Org only",
    icon: "service/AWSOrganizations",
    name: "OrganizationOnly",
    description: "Only principals in the organization reach S3, SQS, KMS and Secrets Manager",
    content: (_, org) =>
      doc({
        Sid: "EnforceOrgIdentities",
        Effect: "Deny",
        Principal: "*",
        Action: ["s3:*", "sqs:*", "kms:*", "secretsmanager:*", "sts:AssumeRole"],
        Resource: "*",
        Condition: { StringNotEqualsIfExists: { "aws:PrincipalOrgID": org }, BoolIfExists: { "aws:PrincipalIsAWSService": "false" } },
      }),
  },
];

/** The templates offered for a policy type (none: the type's example only). */
export const ORG_POLICY_PRESETS: Record<string, OrgPolicyPreset[]> = { SERVICE_CONTROL_POLICY: SCP, RESOURCE_CONTROL_POLICY: RCP };

/** "Dash Staging" → "dash-staging" for an email's plus tag. */
export const emailTag = (name: string) =>
  name
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
