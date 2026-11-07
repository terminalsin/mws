import "server-only";

import { S3Client } from "@aws-sdk/client-s3";
import { client } from "@mws-dashboard/aws";

// Path-style keeps bucket names out of the host name of a local endpoint.
export const s3 = () => client(S3Client, { forcePathStyle: true });

export const ICON = "service/AmazonSimpleStorageService";
export const BUCKET_ICON = "resource/AmazonSimpleStorageServiceBucket";

export function bucketHref(bucket: string, extra: Record<string, string> = {}) {
  const q = new URLSearchParams(Object.entries(extra).filter(([, v]) => v));
  return `/s3/${encodeURIComponent(bucket)}${q.size ? `?${q}` : ""}`;
}

export function objectHref(bucket: string, key: string) {
  return `/s3/${encodeURIComponent(bucket)}/object?key=${encodeURIComponent(key)}`;
}

/** What buckets are for, so the list reads by purpose rather than name. */
export const BUCKET_PURPOSES = [
  { id: "logs", title: "Logs & audit", prototype: "logs logging access logs audit trail cloudtrail flow logs", rule: /(^|[-_.])(logs?|logging|trail|audit|access-?logs?)([-_.]|$)/i },
  { id: "web", title: "Websites & assets", prototype: "website static site assets cdn public www frontend", rule: /(^|[-_.])(www|web|site|static|assets|cdn|public|frontend)([-_.]|$)/i },
  { id: "artifacts", title: "Builds & artifacts", prototype: "artifacts build deploy release packages code lambda layers templates", rule: /(^|[-_.])(artifacts?|builds?|deploy(ments)?|releases?|packages?|code|templates?|cfn)([-_.]|$)/i },
  { id: "backups", title: "Backups & archives", prototype: "backup snapshots archive dumps restore", rule: /(^|[-_.])(backups?|snapshots?|archives?|dumps?)([-_.]|$)/i },
  { id: "data", title: "Data", prototype: "data lake raw processed analytics etl ingest exports inventory reports warehouse", rule: /(^|[-_.])(data|lake|raw|analytics|etl|ingest|exports?|inventory|reports?|warehouse|events)([-_.]|$)/i },
  { id: "media", title: "Uploads & media", prototype: "uploads user content media images videos documents attachments", rule: /(^|[-_.])(uploads?|media|images?|videos?|docs|documents|attachments|avatars)([-_.]|$)/i },
];
