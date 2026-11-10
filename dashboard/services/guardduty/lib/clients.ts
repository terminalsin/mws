import "server-only";

import { GuardDutyClient, ListDetectorsCommand } from "@aws-sdk/client-guardduty";
import { ListBucketsCommand, ListObjectsV2Command, S3Client } from "@aws-sdk/client-s3";
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

/** The region's detector, if GuardDuty is on. */
export async function detectorId(): Promise<string | undefined> {
  return (await (await guardduty()).send(new ListDetectorsCommand({}))).DetectorIds?.[0];
}

/** GuardDuty rejects everything as BadRequestException; its message says
 * which input was wrong. Form field and issue code per message. */
export const MESSAGE_FIELDS: [RegExp, string, "taken" | "format" | "pattern" | "range"][] = [
  [/with the same name already exists/, "name", "taken"],
  [/name is invalid/, "name", "pattern"],
  [/location is not a valid S3 URL/, "location", "format"],
  [/rank is out of range/, "rank", "range"],
];

/** s3:// URLs of the objects a list could be read from, for suggestions. */
export async function s3Objects(): Promise<string[]> {
  try {
    const s3 = await client(S3Client);
    // The newest buckets are the likeliest home of a list just uploaded.
    const buckets = ((await s3.send(new ListBucketsCommand({}))).Buckets ?? []).sort((a, b) => (b.CreationDate?.getTime() ?? 0) - (a.CreationDate?.getTime() ?? 0)).slice(0, 20);
    const keys = await Promise.all(
      buckets.map((b) =>
        s3
          .send(new ListObjectsV2Command({ Bucket: b.Name!, MaxKeys: 50 }))
          .then((r) => (r.Contents ?? []).filter((o) => !o.Key!.endsWith("/")).map((o) => `s3://${b.Name}/${o.Key}`))
          .catch(() => []),
      ),
    );
    return keys.flat();
  } catch {
    return [];
  }
}

/** GuardDuty's severity bands as finding criteria (Critical 9+, High 7-8.9,
 * Medium 4-6.9, Low 1-3.9, Informational below 1). */
export const BANDS = [
  { id: "critical", label: "Critical", gte: 9, lt: 11, tone: "bad" as Tone },
  { id: "high", label: "High", gte: 7, lt: 9, tone: "bad" as Tone },
  { id: "medium", label: "Medium", gte: 4, lt: 7, tone: "warn" as Tone },
  { id: "low", label: "Low", gte: 1, lt: 4, tone: "neutral" as Tone },
  { id: "informational", label: "Informational", gte: 0, lt: 1, tone: "neutral" as Tone },
];

export const RESOURCE_ICON: Record<string, string> = {
  Instance: "resource/AmazonEC2Instance",
  AccessKey: "resource/AWSIdentityAccessManagementLongTermSecurityCredential",
  S3Bucket: "resource/AmazonSimpleStorageServiceBucket",
  S3Object: "resource/AmazonSimpleStorageServiceObject",
  EKSCluster: "service/AmazonElasticKubernetesService",
  Lambda: "resource/AWSLambdaLambdaFunction",
  RDSDBInstance: "service/AmazonRDS",
  RDSLimitlessDB: "service/AmazonRDS",
  Container: "resource/AmazonElasticContainerServiceContainer1",
  ECSCluster: "service/AmazonElasticContainerService",
  EBSVolume: "resource/AmazonElasticBlockStoreVolume",
};

export const planTone = (s: string | undefined): Tone => (s === "ACTIVE" ? "good" : s === "ERROR" ? "bad" : "warn");
export const resultTone = (s: string | undefined): Tone => (s === "THREATS_FOUND" || s === "ACCESS_DENIED" || s === "FAILED" ? "bad" : s === "NO_THREATS_FOUND" ? "good" : "neutral");
