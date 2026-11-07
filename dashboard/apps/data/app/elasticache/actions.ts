"use server";

import {
  CreateCacheClusterCommand,
  CreateReplicationGroupCommand,
  CreateServerlessCacheCommand,
  DeleteCacheClusterCommand,
  DeleteReplicationGroupCommand,
  DeleteServerlessCacheCommand,
} from "@aws-sdk/client-elasticache";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { elasticache } from "../../lib/clients";

export async function createCache(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const engine = text(form, "engine") || "valkey";
    const mode = text(form, "mode") || "serverless";
    const client = await elasticache();
    if (mode === "serverless") {
      await client.send(new CreateServerlessCacheCommand({ ServerlessCacheName: name, Engine: engine }));
      redirect(`/elasticache/cache?serverless=${encodeURIComponent(name)}`);
    }
    const CacheNodeType = text(form, "nodeType") || "cache.t4g.micro";
    if (engine === "memcached") {
      await client.send(new CreateCacheClusterCommand({ CacheClusterId: name, Engine: engine, CacheNodeType, NumCacheNodes: Number(text(form, "nodes") || 1) }));
      redirect(`/elasticache/cache?cluster=${encodeURIComponent(name)}`);
    }
    const replicas = Number(text(form, "nodes") || 1) - 1;
    await client.send(
      new CreateReplicationGroupCommand({
        ReplicationGroupId: name,
        ReplicationGroupDescription: name,
        Engine: engine,
        CacheNodeType,
        NumNodeGroups: 1,
        ReplicasPerNodeGroup: Math.max(0, replicas),
        AutomaticFailoverEnabled: replicas > 0,
        TransitEncryptionEnabled: text(form, "tls") === "on",
      }),
    );
    redirect(`/elasticache/cache?id=${encodeURIComponent(name)}`);
  });
}

export async function deleteCache(kind: "serverless" | "group" | "cluster", name: string) {
  return act(async () => {
    const client = await elasticache();
    if (kind === "serverless") await client.send(new DeleteServerlessCacheCommand({ ServerlessCacheName: name }));
    else if (kind === "group") await client.send(new DeleteReplicationGroupCommand({ ReplicationGroupId: name }));
    else await client.send(new DeleteCacheClusterCommand({ CacheClusterId: name }));
    redirect("/elasticache");
  });
}
