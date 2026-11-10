import "server-only";

import { SecurityHubClient } from "@aws-sdk/client-securityhub";
import { client } from "@mws-dashboard/aws";

export const securityhub = () => client(SecurityHubClient);

export const ICONS = {
  securityhub: "service/AWSSecurityHub",
  finding: "resource/AWSSecurityHubFinding",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

/** Security Hub and GuardDuty severity, both as a label and a tone. */
export function severity(label: string | number | undefined): { label: string; tone: Tone; rank: number } {
  const v = typeof label === "number" ? (label >= 9 ? "CRITICAL" : label >= 7 ? "HIGH" : label >= 4 ? "MEDIUM" : label >= 1 ? "LOW" : "INFORMATIONAL") : (label ?? "INFORMATIONAL").toUpperCase();
  const rank = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(v);
  return { label: v[0] + v.slice(1).toLowerCase(), tone: rank >= 3 ? "bad" : rank === 2 ? "warn" : "neutral", rank };
}

export const SEVERITY_LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
export const WORKFLOWS = ["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"] as const;
export const word = (s: string | undefined) => (s ?? "").toLowerCase().replace(/_/g, " ");
export const workflowTone = (s: string | undefined): Tone => (s === "NEW" ? "info" : s === "NOTIFIED" ? "warn" : s === "RESOLVED" ? "good" : "neutral");
export const isManagedInsight = (arn: string | undefined) => !!arn && /:insight\/securityhub\/default\//.test(arn);
