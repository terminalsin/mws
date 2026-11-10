import "server-only";

import { S3Client } from "@aws-sdk/client-s3";
import { S3ControlClient } from "@aws-sdk/client-s3-control";
import { client, endpoint, frameInfo } from "@mws-dashboard/aws";

// Path-style keeps bucket names out of the host name of a local endpoint.
export const s3 = () => client(S3Client, { forcePathStyle: true });

// S3 Control's endpoint rules put the account ID in the host name
// (`<account>.s3-control...`), which a local endpoint can't take: send every
// request to MWS as it is; the account travels in `x-amz-account-id`.
export const control = () => client(S3ControlClient, { endpointProvider: () => ({ url: new URL(`${endpoint()}/`) }) });

/** The caller's account, which every S3 Control request names. */
export async function account(): Promise<string> {
  const me = await frameInfo();
  if (!me.account) throw new Error(me.error ?? "Could not resolve the account (sts:GetCallerIdentity)");
  return me.account;
}

export const ICON = "service/AmazonSimpleStorageService";
export const BUCKET_ICON = "resource/AmazonSimpleStorageServiceBucket";
export const CONTROL_ICONS = {
  accessPoint: "resource/AmazonSimpleStorageServiceGeneralAccessPoints",
  vpcAccessPoint: "resource/AmazonSimpleStorageServiceVPCAccessPoints",
  objectLambda: "resource/AmazonSimpleStorageServiceS3ObjectLambdaAccessPoints",
  mrap: "resource/AmazonSimpleStorageServiceS3MultiRegionAccessPoints",
  batch: "resource/AmazonSimpleStorageServiceS3BatchOperations",
  lens: "resource/AmazonSimpleStorageServiceS3StorageLens",
  lock: "resource/AmazonSimpleStorageServiceS3ObjectLock",
  replication: "resource/AmazonSimpleStorageServiceS3Replication",
  object: "resource/AmazonSimpleStorageServiceObject",
};

export function bucketHref(bucket: string, extra: Record<string, string | undefined> = {}) {
  const q = new URLSearchParams(Object.entries(extra).filter((e): e is [string, string] => !!e[1]));
  return `/s3/${encodeURIComponent(bucket)}${q.size ? `?${q}` : ""}`;
}

export function objectHref(bucket: string, key: string, version?: string) {
  return `/s3/${encodeURIComponent(bucket)}/object?key=${encodeURIComponent(key)}${version ? `&version=${encodeURIComponent(version)}` : ""}`;
}

export const downloadHref = (bucket: string, key: string, version?: string) =>
  `/api/s3/object?bucket=${encodeURIComponent(bucket)}&key=${encodeURIComponent(key)}${version ? `&version=${encodeURIComponent(version)}` : ""}`;

export const accessPointHref = (bucket: string, name: string) => `/s3/${encodeURIComponent(bucket)}/access-point?name=${encodeURIComponent(name)}`;

export const controlHref = (tab: string, extra: Record<string, string | undefined> = {}) => {
  const q = new URLSearchParams(Object.entries({ tab, ...extra }).filter((e): e is [string, string] => !!e[1]));
  return `/s3?${q}`;
};

/** Console pages of the things S3 points at. */
export const links = {
  topic: (arn: string) => `/sns/topic?arn=${encodeURIComponent(arn)}`,
  queue: (arn: string) => `/sqs/${encodeURIComponent(arn.split(":").pop() ?? arn)}`,
  lambda: (arn: string) => `/lambda/${encodeURIComponent(arn.split(":")[6] ?? arn)}`,
  key: (id: string) => `/kms/key?id=${encodeURIComponent(id.split("/").pop() ?? id)}`,
  role: (arn: string) => `/iam/roles/${encodeURIComponent(arn.split("/").pop() ?? arn)}`,
  vpc: (id: string) => `/vpc/${encodeURIComponent(id)}`,
};

/** A missing configuration is an error in S3 (NoSuchBucketPolicy, ...). */
export async function optional<T>(read: () => Promise<T>): Promise<T | null> {
  try {
    return await read();
  } catch (e) {
    const name = (e as Error).name ?? "";
    if (/^NoSuch|NotFound|NotExists/.test(name)) return null;
    throw e;
  }
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
