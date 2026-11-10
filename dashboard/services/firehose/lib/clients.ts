import "server-only";

import { FirehoseClient } from "@aws-sdk/client-firehose";
import { IAMClient } from "@aws-sdk/client-iam";
import { KinesisClient } from "@aws-sdk/client-kinesis";
import { client } from "@mws-dashboard/aws";

export const firehose = () => client(FirehoseClient);
export const iam = () => client(IAMClient);
export const kinesis = () => client(KinesisClient);

export const ICONS = {
  kinesis: "service/AmazonKinesisDataStreams",
  firehose: "service/AmazonDataFirehose",
};

export const STATUS_TONE = (s: string | undefined): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready"].includes(v)) return "good";
  if (["failed", "inaccessible-encryption-credentials", "incompatible-parameters", "storage-full", "deleting", "error", "degraded", "create_failed", "delete_failed"].includes(v)) return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v)) return "neutral";
  return "warn";
};
