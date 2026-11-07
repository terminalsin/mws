import "server-only";

import { S3Client } from "@aws-sdk/client-s3";
import { client } from "@mws-dashboard/aws";

// Path-style keeps bucket names out of the host name of a local endpoint.
export const s3 = () => client(S3Client, { forcePathStyle: true });

export function objectHref(bucket: string, key: string) {
  return `/s3/${encodeURIComponent(bucket)}/object?key=${encodeURIComponent(key)}`;
}

export function folderHref(bucket: string, prefix: string) {
  return `/s3/${encodeURIComponent(bucket)}${prefix ? `?prefix=${encodeURIComponent(prefix)}` : ""}`;
}
