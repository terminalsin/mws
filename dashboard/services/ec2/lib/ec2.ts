import "server-only";

import {
  DescribeImagesCommand,
  DescribeInstancesCommand,
  DescribeKeyPairsCommand,
  DescribeLaunchTemplatesCommand,
  DescribeManagedPrefixListsCommand,
  DescribeSecurityGroupRulesCommand,
  DescribeSecurityGroupsCommand,
  DescribeSnapshotsCommand,
  DescribeSubnetsCommand,
  DescribeVolumesCommand,
  DescribeVpcsCommand,
  type Filter,
  type SecurityGroupRule,
} from "@aws-sdk/client-ec2";
import { ListInstanceProfilesCommand } from "@aws-sdk/client-iam";
import { all } from "@mws-dashboard/aws";
import type { Tone } from "@mws-dashboard/ui";

import { ec2, iam } from "./clients";

export const STATE_TONE: Record<string, Tone> = {
  running: "good",
  pending: "warn",
  stopping: "warn",
  "shutting-down": "warn",
  stopped: "neutral",
  terminated: "bad",
};

/** EBS volume, snapshot and image states. */
export const RESOURCE_TONE: Record<string, Tone> = {
  available: "good",
  "in-use": "info",
  creating: "warn",
  deleting: "warn",
  pending: "warn",
  optimizing: "warn",
  modifying: "warn",
  completed: "good",
  error: "bad",
  failed: "bad",
  invalid: "bad",
  recoverable: "warn",
  recovering: "warn",
  disabled: "neutral",
  deregistered: "neutral",
  transient: "warn",
};

export async function listInstances(Filters?: Filter[]) {
  const client = await ec2();
  const reservations = await all(
    (NextToken) => client.send(new DescribeInstancesCommand({ NextToken, Filters })),
    (r) => r.Reservations,
    (r) => r.NextToken,
  );
  return reservations.flatMap((r) => r.Instances ?? []);
}

export async function listVolumes(Filters?: Filter[]) {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeVolumesCommand({ NextToken, Filters })),
    (r) => r.Volumes,
    (r) => r.NextToken,
  );
}

/** Snapshots this account owns (AWS's console default: public snapshots are millions). */
export async function listSnapshots(Filters?: Filter[]) {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeSnapshotsCommand({ NextToken, OwnerIds: ["self"], Filters })),
    (r) => r.Snapshots,
    (r) => r.NextToken,
  );
}

/** Images by owner: "self" for "Owned by me", "amazon" for the public catalogue. */
export async function listImages(Owners: string[]) {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeImagesCommand({ NextToken, Owners })),
    (r) => r.Images,
    (r) => r.NextToken,
  );
}

/** Images a launch can use: mine and Amazon's, available only. */
export async function launchableImages() {
  const [mine, amazon] = await Promise.all([listImages(["self"]), listImages(["amazon"])]);
  const seen = new Set<string>();
  return [...mine, ...amazon].filter((i) => (i.State ?? "available") === "available" && !seen.has(i.ImageId!) && seen.add(i.ImageId!));
}

export async function listKeyPairs() {
  return (await (await ec2()).send(new DescribeKeyPairsCommand({ IncludePublicKey: true }))).KeyPairs ?? [];
}

export async function listGroups(Filters?: Filter[]) {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeSecurityGroupsCommand({ NextToken, Filters })),
    (r) => r.SecurityGroups,
    (r) => r.NextToken,
  );
}

export async function listRules(Filters?: Filter[]) {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeSecurityGroupRulesCommand({ NextToken, Filters, MaxResults: 1000 })),
    (r) => r.SecurityGroupRules,
    (r) => r.NextToken,
  );
}

export async function listVpcs() {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeVpcsCommand({ NextToken })),
    (r) => r.Vpcs,
    (r) => r.NextToken,
  );
}

export async function listSubnets() {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeSubnetsCommand({ NextToken })),
    (r) => r.Subnets,
    (r) => r.NextToken,
  );
}

export async function listTemplates() {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeLaunchTemplatesCommand({ NextToken })),
    (r) => r.LaunchTemplates,
    (r) => r.NextToken,
  );
}

export async function listPrefixLists() {
  const client = await ec2();
  return all(
    (NextToken) => client.send(new DescribeManagedPrefixListsCommand({ NextToken })),
    (r) => r.PrefixLists,
    (r) => r.NextToken,
  );
}

/** IAM instance profiles, for the launch form and the "Modify IAM role" sheet. */
export async function listInstanceProfiles() {
  const client = await iam();
  return all(
    (Marker) => client.send(new ListInstanceProfilesCommand({ Marker })),
    (r) => r.InstanceProfiles,
    (r) => (r.IsTruncated ? r.Marker : undefined),
  );
}

const SENSITIVE = new Set([22, 3389, 3306, 5432, 6379, 27017, 9200, 11211]);

/** A rule as people say it ("443 from anywhere"), and whether it exposes an admin or database port to the internet. */
export function describeRule(r: SecurityGroupRule) {
  const ports = r.IpProtocol === "-1" ? "all" : r.FromPort === r.ToPort ? `${r.FromPort}` : `${r.FromPort}-${r.ToPort}`;
  const open = r.CidrIpv4 === "0.0.0.0/0" || r.CidrIpv6 === "::/0";
  const peer = r.CidrIpv4 ?? r.CidrIpv6 ?? r.ReferencedGroupInfo?.GroupId ?? r.PrefixListId ?? "";
  const source = open ? "anywhere" : peer;
  const exposed =
    !r.IsEgress && open && (r.IpProtocol === "-1" || [...SENSITIVE].some((p) => (r.FromPort ?? 0) <= p && p <= (r.ToPort ?? 65535)));
  const arrow = r.IsEgress ? "→" : "←";
  return { ports, source, peer, exposed, text: `${r.IpProtocol === "-1" ? "" : `${r.IpProtocol} `}${ports} ${arrow} ${source}` };
}

/** "8 GiB gp3", "100 GiB io2 · 5000 IOPS". */
export function volumeSpec(v: { Size?: number; VolumeType?: string; Iops?: number; Throughput?: number }) {
  return [`${v.Size} GiB ${v.VolumeType ?? ""}`.trim(), v.VolumeType !== "gp2" && v.Iops ? `${v.Iops} IOPS` : null, v.Throughput ? `${v.Throughput} MiB/s` : null]
    .filter(Boolean)
    .join(" · ");
}
