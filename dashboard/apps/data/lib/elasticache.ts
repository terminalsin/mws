import "server-only";

import { DescribeCacheClustersCommand, DescribeReplicationGroupsCommand, DescribeServerlessCachesCommand } from "@aws-sdk/client-elasticache";

import { elasticache } from "./clients";

export interface Cache {
  kind: "serverless" | "group" | "cluster";
  name: string;
  engine: string;
  version?: string;
  status?: string;
  nodes?: number;
  nodeType?: string;
  endpoint?: string;
  tls?: boolean;
  href: string;
}

export async function listCaches(): Promise<Cache[]> {
  const client = await elasticache();
  const [groups, serverless, clusters] = await Promise.all([
    client.send(new DescribeReplicationGroupsCommand({})).then((r) => r.ReplicationGroups ?? []),
    client.send(new DescribeServerlessCachesCommand({})).then((r) => r.ServerlessCaches ?? [], () => []),
    client.send(new DescribeCacheClustersCommand({ ShowCacheNodeInfo: true })).then((r) => r.CacheClusters ?? []),
  ]);
  return [
    ...serverless.map((s) => ({
      kind: "serverless" as const,
      name: s.ServerlessCacheName!,
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
        engine: g.Engine ?? "redis",
        status: g.Status,
        nodes: g.MemberClusters?.length,
        nodeType: g.CacheNodeType,
        endpoint: ep?.Address ? `${ep.Address}:${ep.Port}` : undefined,
        tls: g.TransitEncryptionEnabled,
        href: `/elasticache/cache?id=${encodeURIComponent(g.ReplicationGroupId!)}`,
      };
    }),
    ...clusters
      .filter((c) => !c.ReplicationGroupId)
      .map((c) => ({
        kind: "cluster" as const,
        name: c.CacheClusterId!,
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
