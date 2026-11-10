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
    const buckets = ((await s3.send(new ListBucketsCommand({}))).Buckets ?? []).slice(0, 20);
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
