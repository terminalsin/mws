import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { EKSClient } from "@aws-sdk/client-eks";
import { IAMClient } from "@aws-sdk/client-iam";
import { client } from "@mws-dashboard/aws";

export const eks = () => client(EKSClient);
export const ec2 = () => client(EC2Client);
export const iam = () => client(IAMClient);

export const ICONS = {
  eks: "service/AmazonElasticKubernetesService",
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
};

export const STATUS_TONE = (s: string | undefined): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready"].includes(v)) return "good";
  if (["failed", "inaccessible-encryption-credentials", "incompatible-parameters", "storage-full", "deleting", "error", "degraded", "create_failed", "delete_failed"].includes(v)) return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v)) return "neutral";
  return "warn";
};
