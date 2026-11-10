"use client";

import { ActionForm, Field, type Rule } from "@mws-dashboard/ui";
import { CreateCacheCluster, CreateReplicationGroup, CreateServerlessCache } from "@mws-dashboard/ui/model/elasticache";
import { useState } from "react";

import { NAME } from "../../lib/rules";
import { createCache } from "./actions";

export interface Restorable {
  kind: "node" | "serverless";
  name: string;
  arn?: string;
  engine?: string;
}

/** The create sheet's form: what it asks follows the engine and deployment
 * (serverless caches have no node type or count, Memcached no backups). */
export function CreateCacheForm({
  names,
  types,
  versions,
  snapshots,
}: {
  names: string[];
  types: Record<string, string[]>;
  versions: Record<string, string[]>;
  snapshots: Restorable[];
}) {
  const [engine, setEngine] = useState("valkey");
  const [mode, setMode] = useState("serverless");
  const [clusterMode, setClusterMode] = useState(false);
  const serverless = mode === "serverless";
  const memcached = engine === "memcached";
  const offered = types[memcached ? "memcached" : "redis"] ?? [];
  const nodeType: Rule = { ...CreateCacheCluster.CacheNodeType, ...(offered.length ? { enum: offered } : {}) };
  const restorable = snapshots.filter((s) => s.kind === (serverless ? "serverless" : "node") && (s.engine ?? "") === engine);
  // Serverless versions are major versions ("8"); node-based ones are full.
  const versionList = serverless ? [...new Set((versions[engine] ?? []).map((v) => v.split(".")[0]))] : (versions[engine] ?? []);
  return (
    <ActionForm action={createCache} submit="Create" testId="create-cache">
      <div className="form-row">
        <Field label="Engine">
          <select name="engine" value={engine} onChange={(e) => setEngine(e.target.value)}>
            <option value="valkey">Valkey</option>
            <option value="redis">Redis OSS</option>
            <option value="memcached">Memcached</option>
          </select>
        </Field>
        <Field label="Deployment">
          <select name="mode" value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="serverless">Serverless</option>
            <option value="nodes">Design your own cache</option>
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="Name" rule={{ ...CreateServerlessCache.ServerlessCacheName, ...NAME }} taken={names} unique>
          <input name="name" required maxLength={40} autoFocus spellCheck={false} />
        </Field>
        <Field label="Engine version">
          <select name="version" key={`${engine}-${mode}`} defaultValue="">
            <option value="">Default</option>
            {versionList.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {!serverless && (
        <>
          <div className="form-row">
            <Field label="Node type" rule={nodeType} known={offered}>
              <input name="nodeType" defaultValue="cache.t4g.micro" list="node-types" autoComplete="off" />
            </Field>
            <Field label={memcached ? "Nodes" : "Nodes per shard"} rule={memcached ? CreateCacheCluster.NumCacheNodes : undefined}>
              <input name="nodes" type="number" min={1} max={memcached ? 40 : undefined} defaultValue={memcached ? 1 : 2} />
            </Field>
          </div>
          <datalist id="node-types">
            {offered.map((t) => (
              <option key={t} value={t} />
            ))}
          </datalist>
          {!memcached && (
            <div className="form-row">
              <label className="check">
                <input type="checkbox" name="clusterMode" checked={clusterMode} onChange={(e) => setClusterMode(e.target.checked)} /> Cluster mode
              </label>
              {clusterMode && (
                <Field label="Shards" rule={{ ...CreateReplicationGroup.NumNodeGroups, type: "integer", min: 1, max: 500 }}>
                  <input name="shards" type="number" defaultValue={3} />
                </Field>
              )}
            </div>
          )}
          <label className="check">
            <input type="checkbox" name="tls" /> Encryption in transit
          </label>
        </>
      )}
      {!memcached && (
        <div className="form-row">
          <Field label="Backup retention (days)" rule={{ type: "integer", min: 0, max: 35 }}>
            <input name="retention" type="number" defaultValue={serverless ? 0 : 1} key={mode} />
          </Field>
          {restorable.length > 0 && (
            <Field label="Restore from snapshot">
              <select name="restore" defaultValue="" key={`${engine}-${mode}-restore`}>
                <option value="">None</option>
                {restorable.map((s) => (
                  <option key={s.name} value={s.kind === "serverless" ? s.arn : s.name}>
                    {s.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>
      )}
    </ActionForm>
  );
}
