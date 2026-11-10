import "server-only";

import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { EC2Client } from "@aws-sdk/client-ec2";
import { ECSClient } from "@aws-sdk/client-ecs";
import { client } from "@mws-dashboard/aws";

export const ecs = () => client(ECSClient);
export const ec2 = () => client(EC2Client);
export const logs = () => client(CloudWatchLogsClient);

export const ICONS = {
  ecs: "service/AmazonElasticContainerService",
  ecsService: "resource/AmazonElasticContainerServiceService",
  task: "resource/AmazonElasticContainerServiceTask",
};

export const STATUS_TONE = (s: string | undefined): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready"].includes(v)) return "good";
  if (["failed", "inaccessible-encryption-credentials", "incompatible-parameters", "storage-full", "deleting", "error", "degraded", "create_failed", "delete_failed"].includes(v)) return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v)) return "neutral";
  return "warn";
};
