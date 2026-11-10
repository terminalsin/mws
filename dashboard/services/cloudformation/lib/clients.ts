import "server-only";

import { CloudFormationClient } from "@aws-sdk/client-cloudformation";
import { client } from "@mws-dashboard/aws";

export const cloudformation = () => client(CloudFormationClient);

export const ICONS = {
  cloudformation: "service/AWSCloudFormation",
  stack: "resource/AWSCloudFormationStack",
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
