import "server-only";

import { DescribeRepositoriesCommand } from "@aws-sdk/client-ecr";
import { ListClustersCommand as ListEcsClustersCommand } from "@aws-sdk/client-ecs";
import { DescribeFileSystemsCommand } from "@aws-sdk/client-efs";
import { ListClustersCommand } from "@aws-sdk/client-eks";
import { DescribeReplicationGroupsCommand, DescribeServerlessCachesCommand } from "@aws-sdk/client-elasticache";
import { ListDeliveryStreamsCommand } from "@aws-sdk/client-firehose";
import { ListStreamsCommand } from "@aws-sdk/client-kinesis";
import { DescribeDBClustersCommand, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import type { InventoryItem } from "@mws-dashboard/aws";

import { STATUS_TONE, ecr, ecs, efs, eks, elasticache, firehose, kinesis, rds, tagsOf } from "./clients";

const base = "/data";
const signal = (status: string | undefined) => (STATUS_TONE(status) === "bad" ? { tone: "bad" as const, text: status ?? "" } : undefined);

export async function databases(): Promise<InventoryItem[]> {
  const client = await rds();
  const [instances, clusters] = await Promise.all([
    client.send(new DescribeDBInstancesCommand({})).then((r) => r.DBInstances ?? []),
    client.send(new DescribeDBClustersCommand({})).then((r) => r.DBClusters ?? []),
  ]);
  return [
    ...clusters.map((c) => ({
      service: "rds",
      type: "DB cluster",
      id: c.DBClusterArn!,
      name: c.DBClusterIdentifier!,
      href: `${base}/rds/db?cluster=${encodeURIComponent(c.DBClusterIdentifier!)}`,
      detail: `${c.Engine} ${c.EngineVersion}`,
      tags: tagsOf(c.TagList),
      signal: signal(c.Status),
    })),
    ...instances
      .filter((i) => !i.DBClusterIdentifier)
      .map((i) => ({
        service: "rds",
        type: "DB instance",
        id: i.DBInstanceArn!,
        name: i.DBInstanceIdentifier!,
        href: `${base}/rds/db?id=${encodeURIComponent(i.DBInstanceIdentifier!)}`,
        detail: `${i.Engine} ${i.EngineVersion}`,
        tags: tagsOf(i.TagList),
        signal: signal(i.DBInstanceStatus),
      })),
  ];
}

export async function caches(): Promise<InventoryItem[]> {
  const client = await elasticache();
  const [groups, serverless] = await Promise.all([
    client.send(new DescribeReplicationGroupsCommand({})).then((r) => r.ReplicationGroups ?? []),
    client.send(new DescribeServerlessCachesCommand({})).then((r) => r.ServerlessCaches ?? [], () => []),
  ]);
  return [
    ...groups.map((g) => ({
      service: "elasticache",
      type: "Cache",
      id: g.ARN!,
      name: g.ReplicationGroupId!,
      href: `${base}/elasticache/cache?id=${encodeURIComponent(g.ReplicationGroupId!)}`,
      detail: g.Engine,
      signal: signal(g.Status),
    })),
    ...serverless.map((s) => ({
      service: "elasticache",
      type: "Serverless cache",
      id: s.ARN!,
      name: s.ServerlessCacheName!,
      href: `${base}/elasticache/cache?serverless=${encodeURIComponent(s.ServerlessCacheName!)}`,
      detail: s.Engine,
      signal: signal(s.Status),
    })),
  ];
}

export async function repositories(): Promise<InventoryItem[]> {
  const out = await (await ecr()).send(new DescribeRepositoriesCommand({}));
  return (out.repositories ?? []).map((r) => ({
    service: "ecr",
    type: "Repository",
    id: r.repositoryArn!,
    name: r.repositoryName!,
    href: `${base}/ecr/repo?name=${encodeURIComponent(r.repositoryName!)}`,
    detail: r.repositoryUri,
  }));
}

export async function ecsClusters(): Promise<InventoryItem[]> {
  const out = await (await ecs()).send(new ListEcsClustersCommand({}));
  return (out.clusterArns ?? []).map((arn) => {
    const name = arn.split("/").pop()!;
    return { service: "ecs", type: "ECS cluster", id: arn, name, href: `${base}/ecs/cluster?name=${encodeURIComponent(name)}` };
  });
}

export async function eksClusters(): Promise<InventoryItem[]> {
  const out = await (await eks()).send(new ListClustersCommand({}));
  return (out.clusters ?? []).map((name) => ({ service: "eks", type: "EKS cluster", id: `eks:${name}`, name, href: `${base}/eks/cluster?name=${encodeURIComponent(name)}` }));
}

export async function fileSystems(): Promise<InventoryItem[]> {
  const out = await (await efs()).send(new DescribeFileSystemsCommand({}));
  return (out.FileSystems ?? []).map((f) => ({
    service: "efs",
    type: "File system",
    id: f.FileSystemArn!,
    name: f.Name ?? f.FileSystemId!,
    href: `${base}/efs/fs?id=${f.FileSystemId}`,
    detail: f.FileSystemId,
    tags: tagsOf(f.Tags),
  }));
}

export async function streams(): Promise<InventoryItem[]> {
  const [k, f] = await Promise.all([
    (await kinesis()).send(new ListStreamsCommand({})).then((r) => r.StreamSummaries ?? []),
    (await firehose()).send(new ListDeliveryStreamsCommand({})).then((r) => r.DeliveryStreamNames ?? []),
  ]);
  return [
    ...k.map((s) => ({
      service: "kinesis",
      type: "Data stream",
      id: s.StreamARN!,
      name: s.StreamName!,
      href: `${base}/kinesis/stream?name=${encodeURIComponent(s.StreamName!)}`,
      detail: s.StreamModeDetails?.StreamMode === "ON_DEMAND" ? "On-demand" : "Provisioned",
    })),
    ...f.map((name) => ({ service: "firehose", type: "Firehose stream", id: `firehose:${name}`, name, href: `${base}/firehose/stream?name=${encodeURIComponent(name)}` })),
  ];
}
