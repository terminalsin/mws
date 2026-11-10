import "server-only";

import { CloudFormationClient } from "@aws-sdk/client-cloudformation";
import { client } from "@mws-dashboard/aws";

export const cloudformation = () => client(CloudFormationClient);

export const ICONS = {
  cloudformation: "service/AWSCloudFormation",
  stack: "resource/AWSCloudFormationStack",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

/** CloudFormation's status words, as the console colours them: anything
 * still moving is in progress (rollbacks included), a failure or a create
 * that rolled back is bad, and an update that rolled back is a stable stack
 * again (neutral). */
export function stackTone(status: string | undefined): Tone {
  const s = status ?? "";
  if (s.endsWith("_IN_PROGRESS") || s === "REVIEW_IN_PROGRESS") return "warn";
  if (s.endsWith("_FAILED") || s === "ROLLBACK_COMPLETE" || s === "FAILED") return "bad";
  if (s === "UPDATE_ROLLBACK_COMPLETE" || s === "IMPORT_ROLLBACK_COMPLETE") return "neutral";
  if (s.endsWith("_COMPLETE") || s === "IN_SYNC" || s === "AVAILABLE" || s === "SUCCEEDED" || s === "CURRENT" || s === "ACTIVE") return "good";
  if (s === "DRIFTED" || s === "MODIFIED" || s === "DELETED" || s === "OUTDATED") return "warn";
  return "neutral";
}
