"use server";

import {
  CreateCacheClusterCommand,
  CreateReplicationGroupCommand,
  CreateServerlessCacheCommand,
  DeleteCacheClusterCommand,
  DeleteReplicationGroupCommand,
  DeleteServerlessCacheCommand,
} from "@aws-sdk/client-elasticache";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { elasticache } from "../../lib/clients";

// The form's fields by the API members (and error codes) they fill: one name
// field serves all three kinds of cache.
const FIELDS = {
  ServerlessCacheName: "name",
  ReplicationGroupId: "name",
  CacheClusterId: "name",
  CacheNodeType: "nodeType",
  NumCacheNodes: "nodes",
  ReplicasPerNodeGroup: "nodes",
};

/** ElastiCache's InvalidParameterValue names the parameter in prose
 * ("Invalid CacheNodeType: x", "The parameter CacheClusterId is not a valid
 * identifier..."): put it on that parameter's field. */
function onField(e: unknown): never {
  const message = e instanceof Error ? e.message : "";
  const member = message.match(/^(?:Invalid|The parameter) (\w+)/)?.[1] as keyof typeof FIELDS | undefined;
  const field = member && FIELDS[member];
  if (field && e instanceof Error && /^Invalid(ParameterValue|ParameterCombination)/.test(e.name)) {
    throw new FieldError(field, message, member === "CacheNodeType" ? "enum" : "server");
  }
  throw e;
}

export async function createCache(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      // ElastiCache stores identifiers in lowercase.
      const id = encodeURIComponent(name.toLowerCase());
      const engine = text(form, "engine") || "valkey";
      const mode = text(form, "mode") || "serverless";
      const client = await elasticache();
      if (mode === "serverless") {
        await client.send(new CreateServerlessCacheCommand({ ServerlessCacheName: name, Engine: engine })).catch(onField);
        redirect(`/elasticache/cache?serverless=${id}`);
      }
      const CacheNodeType = text(form, "nodeType") || "cache.t4g.micro";
      const nodes = Number(text(form, "nodes") || 1);
      if (engine === "memcached") {
        await client.send(new CreateCacheClusterCommand({ CacheClusterId: name, Engine: engine, CacheNodeType, NumCacheNodes: nodes })).catch(onField);
        redirect(`/elasticache/cache?cluster=${id}`);
      }
      // A Valkey or Redis OSS shard is one primary and up to five replicas.
      if (nodes > 6) throw new FieldError("nodes", "1 primary and up to 5 replicas", "range", { min: 1, max: 6 });
      const replicas = Math.max(0, nodes - 1);
      await client
        .send(
          new CreateReplicationGroupCommand({
            ReplicationGroupId: name,
            ReplicationGroupDescription: name,
            Engine: engine,
            CacheNodeType,
            NumNodeGroups: 1,
            ReplicasPerNodeGroup: replicas,
            AutomaticFailoverEnabled: replicas > 0,
            TransitEncryptionEnabled: text(form, "tls") === "on",
          }),
        )
        .catch(onField);
      redirect(`/elasticache/cache?id=${id}`);
    },
    { revalidate: ["/elasticache"], fields: FIELDS },
  );
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
