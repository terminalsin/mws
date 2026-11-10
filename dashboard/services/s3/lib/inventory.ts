import "server-only";

import { ListBucketsCommand } from "@aws-sdk/client-s3";
import type { InventoryItem } from "@mws-dashboard/aws";

import { s3 } from "./s3";

export async function buckets(): Promise<InventoryItem[]> {
  const out = await (await s3()).send(new ListBucketsCommand({}));
  return (out.Buckets ?? []).map((b) => ({
    service: "s3",
    type: "Bucket",
    id: `arn:aws:s3:::${b.Name}`,
    name: b.Name!,
    href: `/s3/${encodeURIComponent(b.Name!)}`,
    detail: b.BucketRegion,
  }));
}
