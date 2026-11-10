import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { EFSClient } from "@aws-sdk/client-efs";
import { client } from "@mws-dashboard/aws";

export const efs = () => client(EFSClient);
export const ec2 = () => client(EC2Client);

export const ICONS = {
  efs: "service/AmazonEFS",
  fileSystem: "resource/AmazonElasticFileSystemFileSystem",
};

export const STATUS_TONE = (s: string | undefined): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready"].includes(v)) return "good";
  if (["failed", "inaccessible-encryption-credentials", "incompatible-parameters", "storage-full", "deleting", "error", "degraded", "create_failed", "delete_failed"].includes(v)) return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v)) return "neutral";
  return "warn";
};

export const tagsOf = (list: { Key?: string; Value?: string; key?: string; value?: string }[] | undefined) =>
  Object.fromEntries((list ?? []).map((t) => [t.Key ?? t.key ?? "", t.Value ?? t.value ?? ""]).filter(([k]) => k));
