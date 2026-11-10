import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { DescribeAccessPointsCommand, DescribeFileSystemsCommand, DescribeMountTargetsCommand, EFSClient } from "@aws-sdk/client-efs";
import { all, client } from "@mws-dashboard/aws";

export const efs = () => client(EFSClient);
export const ec2 = () => client(EC2Client);

export const ICONS = {
  efs: "service/AmazonEFS",
  fileSystem: "resource/AmazonElasticFileSystemFileSystem",
  eni: "resource/AmazonVPCElasticNetworkInterface",
};

export const STATUS_TONE = (s: string | undefined): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready", "enabled"].includes(v)) return "good";
  if (["failed", "inaccessible-encryption-credentials", "incompatible-parameters", "storage-full", "error", "degraded", "create_failed", "delete_failed"].includes(v)) return "bad";
  if (["stopped", "inactive", "disabled", "draining", "deleted"].includes(v)) return "neutral";
  // creating, updating, deleting, enabling, pausing...: on their way somewhere.
  return "warn";
};

export const tagsOf = (list: { Key?: string; Value?: string; key?: string; value?: string }[] | undefined) =>
  Object.fromEntries((list ?? []).map((t) => [t.Key ?? t.key ?? "", t.Value ?? t.value ?? ""]).filter(([k]) => k));

export const fsHref = (id: string, tab?: string) => `/efs/fs?id=${encodeURIComponent(id)}${tab ? `&tab=${tab}` : ""}`;

export const links = {
  vpc: (id: string) => `/vpc/${encodeURIComponent(id)}`,
  subnet: (id: string) => `/vpc/subnet?id=${encodeURIComponent(id)}`,
  group: (id: string) => `/ec2/group?id=${encodeURIComponent(id)}`,
  key: (id: string) => `/kms/key?id=${encodeURIComponent(id.split("/").pop() ?? id)}`,
  role: (arn: string) => `/iam/roles/${encodeURIComponent(arn.split("/").pop() ?? arn)}`,
};

/** Every file system (DescribeFileSystems pages at 100 by Marker). */
export async function allFileSystems() {
  const c = await efs();
  return all(
    (Marker) => c.send(new DescribeFileSystemsCommand({ Marker })),
    (r) => r.FileSystems,
    (r) => r.NextMarker,
  );
}

/** Every mount target of a file system (pages at 10 by default). */
export async function mountTargets(id: string) {
  const c = await efs();
  return all(
    (Marker) => c.send(new DescribeMountTargetsCommand({ FileSystemId: id, Marker })),
    (r) => r.MountTargets,
    (r) => r.NextMarker,
  );
}

export async function accessPoints(id: string) {
  const c = await efs();
  return all(
    (NextToken) => c.send(new DescribeAccessPointsCommand({ FileSystemId: id, NextToken })),
    (r) => r.AccessPoints,
    (r) => r.NextToken,
  );
}
