"use server";

import {
  CopyServerlessCacheSnapshotCommand,
  CopySnapshotCommand,
  CreateCacheClusterCommand,
  CreateReplicationGroupCommand,
  CreateServerlessCacheCommand,
  CreateServerlessCacheSnapshotCommand,
  CreateSnapshotCommand,
  DecreaseReplicaCountCommand,
  DeleteCacheClusterCommand,
  DeleteReplicationGroupCommand,
  DeleteServerlessCacheCommand,
  DeleteServerlessCacheSnapshotCommand,
  DeleteSnapshotCommand,
  IncreaseReplicaCountCommand,
  ModifyCacheClusterCommand,
  ModifyReplicationGroupCommand,
  ModifyReplicationGroupShardConfigurationCommand,
  ModifyServerlessCacheCommand,
  RebootCacheClusterCommand,
  TestFailoverCommand,
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
  NumNodeGroups: "shards",
  NodeGroupCount: "shards",
  NewReplicaCount: "replicas",
  EngineVersion: "version",
  SnapshotRetentionLimit: "retention",
  SnapshotName: "snapshot",
  TargetSnapshotName: "snapshot",
  ServerlessCacheSnapshotName: "snapshot",
  TargetServerlessCacheSnapshotName: "snapshot",
  FinalSnapshotIdentifier: "finalName",
  FinalSnapshotName: "finalName",
  SnapshotAlreadyExistsFault: "snapshot",
  ServerlessCacheSnapshotAlreadyExistsFault: "snapshot",
  ReplicationGroupAlreadyExistsFault: "name",
  CacheClusterAlreadyExistsFault: "name",
  ServerlessCacheAlreadyExistsFault: "name",
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

const int = (form: FormData, name: string) => (text(form, name) === "" ? undefined : Number(text(form, name)));
const on = (form: FormData, name: string) => text(form, name) === "on";
type Kind = "serverless" | "group" | "cluster";
const cacheHref = (kind: Kind, id: string) => `/elasticache/cache?${kind === "serverless" ? "serverless" : kind === "group" ? "id" : "cluster"}=${encodeURIComponent(id)}`;

export async function createCache(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      // ElastiCache stores identifiers in lowercase.
      const name = required(form, "name", "Name").toLowerCase();
      const engine = text(form, "engine") || "valkey";
      const mode = text(form, "mode") || "serverless";
      const EngineVersion = text(form, "version") || undefined;
      const restore = text(form, "restore") || undefined;
      const client = await elasticache();
      if (mode === "serverless") {
        await client
          .send(
            new CreateServerlessCacheCommand({
              ServerlessCacheName: name,
              Engine: engine,
              MajorEngineVersion: EngineVersion,
              SnapshotArnsToRestore: restore ? [restore] : undefined,
              SnapshotRetentionLimit: int(form, "retention"),
            }),
          )
          .catch(onField);
        redirect(cacheHref("serverless", name));
      }
      const CacheNodeType = text(form, "nodeType") || "cache.t4g.micro";
      const nodes = Number(text(form, "nodes") || 1);
      const TransitEncryptionEnabled = on(form, "tls");
      if (engine === "memcached") {
        await client.send(new CreateCacheClusterCommand({ CacheClusterId: name, Engine: engine, EngineVersion, CacheNodeType, NumCacheNodes: nodes, TransitEncryptionEnabled })).catch(onField);
        redirect(cacheHref("cluster", name));
      }
      // A Valkey or Redis OSS shard is one primary and up to five replicas.
      if (nodes > 6) throw new FieldError("nodes", "1 primary and up to 5 replicas", "range", { min: 1, max: 6 });
      const replicas = Math.max(0, nodes - 1);
      const shards = on(form, "clusterMode") ? Number(text(form, "shards") || 1) : 1;
      await client
        .send(
          new CreateReplicationGroupCommand({
            ReplicationGroupId: name,
            ReplicationGroupDescription: name,
            Engine: engine,
            EngineVersion,
            CacheNodeType,
            NumNodeGroups: shards,
            ReplicasPerNodeGroup: replicas,
            ClusterMode: on(form, "clusterMode") ? "enabled" : undefined,
            AutomaticFailoverEnabled: replicas > 0 || on(form, "clusterMode"),
            MultiAZEnabled: replicas > 0 ? true : undefined,
            TransitEncryptionEnabled,
            SnapshotName: restore,
            SnapshotRetentionLimit: int(form, "retention"),
          }),
        )
        .catch(onField);
      redirect(cacheHref("group", name));
    },
    { revalidate: ["/elasticache"], fields: FIELDS },
  );
}

/** What a modify form started from, so only changed settings are sent. */
export interface Current {
  nodeType?: string;
  version?: string;
  retention?: number;
  failover?: boolean;
  multiAz?: boolean;
  nodes?: number;
  nodeIds?: string[];
  storage?: number;
  ecpu?: number;
}

export async function modifyCache(kind: Kind, id: string, current: Current, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const changed = <T>(value: T | undefined, was: T | undefined) => (value === undefined || value === was ? undefined : value);
      const ApplyImmediately = on(form, "now");
      const EngineVersion = changed(text(form, "version") || undefined, current.version);
      const SnapshotRetentionLimit = changed(int(form, "retention"), current.retention);
      const client = await elasticache();
      if (kind === "serverless") {
        const storage = changed(int(form, "storage"), current.storage);
        const ecpu = changed(int(form, "ecpu"), current.ecpu);
        const input = {
          CacheUsageLimits:
            storage !== undefined || ecpu !== undefined
              ? { DataStorage: int(form, "storage") ? { Maximum: int(form, "storage"), Unit: "GB" as const } : undefined, ECPUPerSecond: int(form, "ecpu") ? { Maximum: int(form, "ecpu") } : undefined }
              : undefined,
          SnapshotRetentionLimit,
          MajorEngineVersion: EngineVersion,
        };
        if (Object.values(input).every((v) => v === undefined)) throw new Error("Nothing changed");
        await client.send(new ModifyServerlessCacheCommand({ ServerlessCacheName: id, ...input })).catch(onField);
        return "Modifying";
      }
      if (kind === "cluster") {
        const nodes = changed(int(form, "nodes"), current.nodes);
        // Removing nodes names them: the newest go first.
        const remove = nodes !== undefined && nodes < (current.nodes ?? 0) ? (current.nodeIds ?? []).slice(nodes) : undefined;
        const input = { NumCacheNodes: nodes, CacheNodeIdsToRemove: remove, EngineVersion, CacheNodeType: changed(text(form, "nodeType") || undefined, current.nodeType) };
        if (Object.values(input).every((v) => v === undefined)) throw new Error("Nothing changed");
        await client.send(new ModifyCacheClusterCommand({ CacheClusterId: id, ApplyImmediately, ...input })).catch(onField);
        return ApplyImmediately ? "Modifying" : "Changes pending for the next maintenance window";
      }
      const failover = changed(on(form, "failover"), !!current.failover);
      const multiAz = changed(on(form, "multiAz"), !!current.multiAz);
      const input = {
        CacheNodeType: changed(text(form, "nodeType") || undefined, current.nodeType),
        EngineVersion,
        SnapshotRetentionLimit,
        AutomaticFailoverEnabled: failover,
        MultiAZEnabled: multiAz,
      };
      if (Object.values(input).every((v) => v === undefined)) throw new Error("Nothing changed");
      await client.send(new ModifyReplicationGroupCommand({ ReplicationGroupId: id, ApplyImmediately, ...input })).catch(onField);
      return ApplyImmediately ? "Modifying" : "Changes pending for the next maintenance window";
    },
    { revalidate: ["/elasticache", "/elasticache/cache"], fields: FIELDS },
  );
}

/** Replicas per shard (Increase/DecreaseReplicaCount) and, in cluster mode,
 * the number of shards (ModifyReplicationGroupShardConfiguration). */
export async function resizeGroup(id: string, was: { replicas: number; shards: number; clusterMode: boolean }, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const replicas = Number(required(form, "replicas", "Replicas per shard"));
      const shards = was.clusterMode ? Number(required(form, "shards", "Shards")) : was.shards;
      const client = await elasticache();
      if (shards !== was.shards) {
        await client.send(new ModifyReplicationGroupShardConfigurationCommand({ ReplicationGroupId: id, NodeGroupCount: shards, ApplyImmediately: true })).catch(onField);
        return `Resharding to ${shards}`;
      }
      if (replicas > was.replicas) await client.send(new IncreaseReplicaCountCommand({ ReplicationGroupId: id, NewReplicaCount: replicas, ApplyImmediately: true })).catch(onField);
      else if (replicas < was.replicas) await client.send(new DecreaseReplicaCountCommand({ ReplicationGroupId: id, NewReplicaCount: replicas, ApplyImmediately: true })).catch(onField);
      else throw new Error("Nothing changed");
      return `${replicas} replicas per shard`;
    },
    { revalidate: ["/elasticache", "/elasticache/cache"], fields: FIELDS },
  );
}

export async function rebootNodes(cluster: string, nodeIds: string[]) {
  return act(async () => {
    await (await elasticache()).send(new RebootCacheClusterCommand({ CacheClusterId: cluster, CacheNodeIdsToReboot: nodeIds }));
    return "Rebooting";
  }, "/elasticache/cache");
}

export async function testFailover(group: string, shard: string) {
  return act(async () => {
    await (await elasticache()).send(new TestFailoverCommand({ ReplicationGroupId: group, NodeGroupId: shard }));
    return "Failing over";
  }, "/elasticache/cache");
}

export async function takeSnapshot(kind: Kind, id: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "snapshot", "Snapshot name");
      const client = await elasticache();
      if (kind === "serverless") await client.send(new CreateServerlessCacheSnapshotCommand({ ServerlessCacheName: id, ServerlessCacheSnapshotName: name })).catch(onField);
      else if (kind === "group") await client.send(new CreateSnapshotCommand({ ReplicationGroupId: id, SnapshotName: name })).catch(onField);
      else await client.send(new CreateSnapshotCommand({ CacheClusterId: id, SnapshotName: name })).catch(onField);
      return `Snapshot ${name} started`;
    },
    { revalidate: ["/elasticache", "/elasticache/cache"], fields: FIELDS },
  );
}

export async function copySnapshot(kind: "node" | "serverless", name: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const target = required(form, "snapshot", "Snapshot name");
      const client = await elasticache();
      if (kind === "serverless") await client.send(new CopyServerlessCacheSnapshotCommand({ SourceServerlessCacheSnapshotName: name, TargetServerlessCacheSnapshotName: target })).catch(onField);
      else await client.send(new CopySnapshotCommand({ SourceSnapshotName: name, TargetSnapshotName: target })).catch(onField);
      return `Copying to ${target}`;
    },
    { revalidate: ["/elasticache"], fields: FIELDS },
  );
}

export async function deleteSnapshot(kind: "node" | "serverless", name: string) {
  return act(async () => {
    const client = await elasticache();
    if (kind === "serverless") await client.send(new DeleteServerlessCacheSnapshotCommand({ ServerlessCacheSnapshotName: name }));
    else await client.send(new DeleteSnapshotCommand({ SnapshotName: name }));
    return "Snapshot deleted";
  }, "/elasticache", "/elasticache/cache");
}

/** A new cache from a snapshot: node snapshots restore into a replication
 * group, serverless ones into a serverless cache. */
export async function restoreSnapshot(kind: "node" | "serverless", snap: { name: string; arn?: string; engine?: string; nodeType?: string; shards?: number }, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name").toLowerCase();
      const client = await elasticache();
      if (kind === "serverless") {
        await client.send(new CreateServerlessCacheCommand({ ServerlessCacheName: name, Engine: snap.engine ?? "valkey", SnapshotArnsToRestore: [snap.arn!] })).catch(onField);
        redirect(cacheHref("serverless", name));
      }
      if (snap.engine === "memcached") throw new Error("Memcached has no backups to restore");
      await client
        .send(
          new CreateReplicationGroupCommand({
            ReplicationGroupId: name,
            ReplicationGroupDescription: name,
            Engine: snap.engine,
            CacheNodeType: text(form, "nodeType") || snap.nodeType,
            NumNodeGroups: snap.shards,
            ClusterMode: (snap.shards ?? 1) > 1 ? "enabled" : undefined,
            SnapshotName: snap.name,
          }),
        )
        .catch(onField);
      redirect(cacheHref("group", name));
    },
    { fields: FIELDS },
  );
}

export async function deleteCache(kind: Kind, name: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const finalName = on(form, "final") ? required(form, "finalName", "Final snapshot name") : undefined;
      const client = await elasticache();
      if (kind === "serverless") await client.send(new DeleteServerlessCacheCommand({ ServerlessCacheName: name, FinalSnapshotName: finalName })).catch(onField);
      else if (kind === "group") await client.send(new DeleteReplicationGroupCommand({ ReplicationGroupId: name, FinalSnapshotIdentifier: finalName })).catch(onField);
      else await client.send(new DeleteCacheClusterCommand({ CacheClusterId: name, FinalSnapshotIdentifier: finalName })).catch(onField);
      redirect("/elasticache");
    },
    { fields: FIELDS },
  );
}
