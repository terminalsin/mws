import "server-only";

import {
  DescribeCacheClustersCommand,
  DescribeCacheEngineVersionsCommand,
  DescribeReplicationGroupsCommand,
  DescribeReservedCacheNodesOfferingsCommand,
  DescribeServerlessCacheSnapshotsCommand,
  DescribeServerlessCachesCommand,
  DescribeSnapshotsCommand,
  type CacheCluster,
  type DescribeCacheClustersCommandInput,
} from "@aws-sdk/client-elasticache";
import { all } from "@mws-dashboard/aws";

import { elasticache } from "./clients";

export interface Cache {
  kind: "serverless" | "group" | "cluster";
  name: string;
  arn?: string;
  engine: string;
  version?: string;
  status?: string;
  nodes?: number;
  shards?: number;
  nodeType?: string;
  endpoint?: string;
  tls?: boolean;
  clusterMode?: boolean;
  href: string;
}

// Every Describe* here follows Marker / NextToken: lists never stop at the
// first page, and a failing call fails the page instead of hiding caches.

export async function cacheClusters(input: DescribeCacheClustersCommandInput = {}): Promise<CacheCluster[]> {
  const client = await elasticache();
  return all((Marker) => client.send(new DescribeCacheClustersCommand({ ShowCacheNodeInfo: true, ...input, Marker })), (r) => r.CacheClusters, (r) => r.Marker);
}

export async function replicationGroups(id?: string) {
  const client = await elasticache();
  return all((Marker) => client.send(new DescribeReplicationGroupsCommand({ ReplicationGroupId: id, Marker })), (r) => r.ReplicationGroups, (r) => r.Marker);
}

export async function serverlessCaches(name?: string) {
  const client = await elasticache();
  return all((NextToken) => client.send(new DescribeServerlessCachesCommand({ ServerlessCacheName: name, NextToken })), (r) => r.ServerlessCaches, (r) => r.NextToken);
}

export async function listCaches(): Promise<Cache[]> {
  const [groups, serverless, clusters] = await Promise.all([replicationGroups(), serverlessCaches(), cacheClusters()]);
  // A replication group's engine version is its member clusters'.
  const versionOf = new Map(clusters.filter((c) => c.ReplicationGroupId).map((c) => [c.ReplicationGroupId!, c.EngineVersion]));
  return [
    ...serverless.map((s) => ({
      kind: "serverless" as const,
      name: s.ServerlessCacheName!,
      arn: s.ARN,
      engine: s.Engine ?? "valkey",
      version: s.FullEngineVersion ?? s.MajorEngineVersion,
      status: s.Status,
      endpoint: s.Endpoint?.Address ? `${s.Endpoint.Address}:${s.Endpoint.Port}` : undefined,
      tls: true,
      href: `/elasticache/cache?serverless=${encodeURIComponent(s.ServerlessCacheName!)}`,
    })),
    ...groups.map((g) => {
      const ep = g.ConfigurationEndpoint ?? g.NodeGroups?.[0]?.PrimaryEndpoint;
      return {
        kind: "group" as const,
        name: g.ReplicationGroupId!,
        arn: g.ARN,
        engine: g.Engine ?? "redis",
        version: versionOf.get(g.ReplicationGroupId!),
        status: g.Status,
        nodes: g.MemberClusters?.length,
        shards: g.NodeGroups?.length,
        nodeType: g.CacheNodeType,
        endpoint: ep?.Address ? `${ep.Address}:${ep.Port}` : undefined,
        tls: g.TransitEncryptionEnabled,
        clusterMode: !!g.ClusterEnabled,
        href: `/elasticache/cache?id=${encodeURIComponent(g.ReplicationGroupId!)}`,
      };
    }),
    ...clusters
      .filter((c) => !c.ReplicationGroupId)
      .map((c) => ({
        kind: "cluster" as const,
        name: c.CacheClusterId!,
        arn: c.ARN,
        engine: c.Engine ?? "memcached",
        version: c.EngineVersion,
        status: c.CacheClusterStatus,
        nodes: c.NumCacheNodes,
        nodeType: c.CacheNodeType,
        endpoint: c.ConfigurationEndpoint?.Address ? `${c.ConfigurationEndpoint.Address}:${c.ConfigurationEndpoint.Port}` : c.CacheNodes?.[0]?.Endpoint?.Address ? `${c.CacheNodes[0].Endpoint.Address}:${c.CacheNodes[0].Endpoint.Port}` : undefined,
        tls: c.TransitEncryptionEnabled,
        href: `/elasticache/cache?cluster=${encodeURIComponent(c.CacheClusterId!)}`,
      })),
  ];
}

/** The node types the region offers an engine, read from its reserved-node
 * offerings (one row per type for a single term, payment option and product). */
export async function nodeTypes(engine = "redis"): Promise<string[]> {
  const client = await elasticache();
  const offers = await all(
    (Marker) =>
      client.send(new DescribeReservedCacheNodesOfferingsCommand({ Duration: "1", OfferingType: "No Upfront", ProductDescription: engine === "memcached" ? "memcached" : "redis", MaxRecords: 100, Marker })),
    (r) => r.ReservedCacheNodesOfferings,
    (r) => r.Marker,
  );
  return [...new Set(offers.map((o) => o.CacheNodeType!).filter(Boolean))].sort();
}

/** The versions ElastiCache offers an engine, newest first. */
export async function engineVersions(engine: string): Promise<string[]> {
  const client = await elasticache();
  const list = await all((Marker) => client.send(new DescribeCacheEngineVersionsCommand({ Engine: engine, Marker })), (r) => r.CacheEngineVersions, (r) => r.Marker);
  return [...new Set(list.map((v) => v.EngineVersion!).filter(Boolean))].sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
}

/** A snapshot as the console lists it: of a node-based cache or a serverless one. */
export interface Snap {
  kind: "node" | "serverless";
  name: string;
  arn?: string;
  source?: string;
  engine?: string;
  version?: string;
  status?: string;
  type?: string;
  at?: Date;
  nodeType?: string;
  shards?: number;
  size?: string;
}

export async function snapshots(filter: { group?: string; cluster?: string; serverless?: string } = {}): Promise<Snap[]> {
  const client = await elasticache();
  const wantsNode = !filter.serverless;
  const wantsServerless = !filter.group && !filter.cluster;
  const [nodes, serverless] = await Promise.all([
    wantsNode
      ? all(
          (Marker) => client.send(new DescribeSnapshotsCommand({ ReplicationGroupId: filter.group, CacheClusterId: filter.cluster, ShowNodeGroupConfig: true, Marker })),
          (r) => r.Snapshots,
          (r) => r.Marker,
        )
      : [],
    wantsServerless
      ? all(
          (NextToken) => client.send(new DescribeServerlessCacheSnapshotsCommand({ ServerlessCacheName: filter.serverless, NextToken })),
          (r) => r.ServerlessCacheSnapshots,
          (r) => r.NextToken,
        )
      : [],
  ]);
  return [
    ...nodes.map((s) => ({
      kind: "node" as const,
      name: s.SnapshotName!,
      arn: s.ARN,
      source: s.ReplicationGroupId ?? s.CacheClusterId,
      engine: s.Engine,
      version: s.EngineVersion,
      status: s.SnapshotStatus,
      type: s.SnapshotSource,
      at: s.NodeSnapshots?.[0]?.SnapshotCreateTime ?? s.CacheClusterCreateTime,
      nodeType: s.CacheNodeType,
      shards: s.NumNodeGroups,
    })),
    ...serverless.map((s) => ({
      kind: "serverless" as const,
      name: s.ServerlessCacheSnapshotName!,
      arn: s.ARN,
      source: s.ServerlessCacheConfiguration?.ServerlessCacheName,
      engine: s.ServerlessCacheConfiguration?.Engine,
      version: s.ServerlessCacheConfiguration?.MajorEngineVersion,
      status: s.Status,
      type: s.SnapshotType,
      at: s.CreateTime,
      size: s.BytesUsedForCache,
    })),
  ].sort((a, b) => (b.at?.getTime() ?? 0) - (a.at?.getTime() ?? 0));
}
