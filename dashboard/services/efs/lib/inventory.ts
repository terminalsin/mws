import "server-only";

import { DescribeFileSystemsCommand } from "@aws-sdk/client-efs";
import type { InventoryItem } from "@mws-dashboard/aws";

import { efs, tagsOf } from "./clients";

export async function fileSystems(): Promise<InventoryItem[]> {
  const out = await (await efs()).send(new DescribeFileSystemsCommand({}));
  return (out.FileSystems ?? []).map((f) => ({
    service: "efs",
    type: "File system",
    id: f.FileSystemArn!,
    name: f.Name ?? f.FileSystemId!,
    href: `/efs/fs?id=${f.FileSystemId}`,
    detail: f.FileSystemId,
    tags: tagsOf(f.Tags),
  }));
}
