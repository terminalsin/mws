import "server-only";

import { CloudFormationClient } from "@aws-sdk/client-cloudformation";
import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { CostExplorerClient } from "@aws-sdk/client-cost-explorer";
import { GuardDutyClient } from "@aws-sdk/client-guardduty";
import { IdentitystoreClient } from "@aws-sdk/client-identitystore";
import { OrganizationsClient } from "@aws-sdk/client-organizations";
import { RAMClient } from "@aws-sdk/client-ram";
import { SecurityHubClient } from "@aws-sdk/client-securityhub";
import { ServiceQuotasClient } from "@aws-sdk/client-service-quotas";
import { SSOAdminClient } from "@aws-sdk/client-sso-admin";
import { client } from "@mws-dashboard/aws";

export const organizations = () => client(OrganizationsClient);
export const cloudformation = () => client(CloudFormationClient);
export const cloudtrail = () => client(CloudTrailClient);
export const quotas = () => client(ServiceQuotasClient);
export const ce = () => client(CostExplorerClient);
export const securityhub = () => client(SecurityHubClient);
export const guardduty = () => client(GuardDutyClient);
export const ssoAdmin = () => client(SSOAdminClient);
export const identitystore = () => client(IdentitystoreClient);
export const ram = () => client(RAMClient);

export const ICONS = {
  organizations: "service/AWSOrganizations",
  account: "resource/AWSOrganizationsAccount",
  management: "resource/AWSOrganizationsManagementAccount",
  ou: "resource/AWSOrganizationsOrganizationalUnit",
  cloudformation: "service/AWSCloudFormation",
  stack: "resource/AWSCloudFormationStack",
  template: "resource/AWSCloudFormationTemplate",
  changeSet: "resource/AWSCloudFormationChangeSet",
  cloudtrail: "service/AWSCloudTrail",
  quotas: "service/AWSTrustedAdvisor",
  ce: "service/AWSCostExplorer",
  securityhub: "service/AWSSecurityHub",
  finding: "resource/AWSSecurityHubFinding",
  guardduty: "service/AmazonGuardDuty",
  identitycenter: "service/AWSIAMIdentityCenter",
  ram: "service/AWSResourceAccessManager",
  user: "resource/User",
  users: "resource/Users",
  policy: "resource/AWSIdentityAccessManagementPermissions",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

/** CloudFormation's status words, as the console colours them. */
export function stackTone(status: string | undefined): Tone {
  const s = status ?? "";
  if (s.endsWith("_FAILED") || s.includes("ROLLBACK")) return "bad";
  if (s.endsWith("_IN_PROGRESS")) return "warn";
  if (s.endsWith("_COMPLETE")) return "good";
  return "neutral";
}

/** Security Hub and GuardDuty severity, both as a label and a tone. */
export function severity(label: string | number | undefined): { label: string; tone: Tone; rank: number } {
  const v = typeof label === "number" ? (label >= 9 ? "CRITICAL" : label >= 7 ? "HIGH" : label >= 4 ? "MEDIUM" : label >= 1 ? "LOW" : "INFORMATIONAL") : (label ?? "INFORMATIONAL").toUpperCase();
  const rank = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(v);
  return { label: v[0] + v.slice(1).toLowerCase(), tone: rank >= 3 ? "bad" : rank === 2 ? "warn" : "neutral", rank };
}
