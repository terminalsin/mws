import "server-only";

import { GuardDutyClient } from "@aws-sdk/client-guardduty";
import { client } from "@mws-dashboard/aws";

export const guardduty = () => client(GuardDutyClient);

export const ICONS = {
  guardduty: "service/AmazonGuardDuty",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

/** Security Hub and GuardDuty severity, both as a label and a tone. */
export function severity(label: string | number | undefined): { label: string; tone: Tone; rank: number } {
  const v = typeof label === "number" ? (label >= 9 ? "CRITICAL" : label >= 7 ? "HIGH" : label >= 4 ? "MEDIUM" : label >= 1 ? "LOW" : "INFORMATIONAL") : (label ?? "INFORMATIONAL").toUpperCase();
  const rank = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(v);
  return { label: v[0] + v.slice(1).toLowerCase(), tone: rank >= 3 ? "bad" : rank === 2 ? "warn" : "neutral", rank };
}
