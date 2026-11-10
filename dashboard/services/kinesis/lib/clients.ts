import "server-only";

import { KinesisClient } from "@aws-sdk/client-kinesis";
import { client } from "@mws-dashboard/aws";

export const kinesis = () => client(KinesisClient);

export const ICONS = {
  kinesis: "service/AmazonKinesisDataStreams",
};

export const STATUS_TONE = (s: string | undefined): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready"].includes(v)) return "good";
  if (["failed", "inaccessible-encryption-credentials", "incompatible-parameters", "storage-full", "deleting", "error", "degraded", "create_failed", "delete_failed"].includes(v)) return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v)) return "neutral";
  return "warn";
};
