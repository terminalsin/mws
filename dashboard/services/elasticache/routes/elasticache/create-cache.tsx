"use client";

import { ActionForm, Field, type Rule } from "@mws-dashboard/ui";
import { CreateCacheCluster, CreateReplicationGroup, CreateServerlessCache } from "@mws-dashboard/ui/model/elasticache";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { Cloud, Server } from "lucide-react";
import { useState } from "react";

import { ENGINE_PRESETS, MODE_PRESETS, type EnginePreset, type ModePreset } from "../../lib/presets";
import { NAME } from "../../lib/rules";
import { createCache } from "./actions";

export interface Restorable {
  kind: "node" | "serverless";
  name: string;
  arn?: string;
  engine?: string;
}

const MODE_ICON = { serverless: <Cloud size={26} strokeWidth={1.5} aria-hidden />, nodes: <Server size={26} strokeWidth={1.5} aria-hidden /> };

/** The create sheet's form. It opens on the engines' logos and the two ways
 * to run one: serverless (one click: the name is filled in) or nodes. What it
 * asks follows the choice; versions, TLS and backups wait under More. */
export function CreateCacheForm({
  names,
  types,
  versions,
  snapshots,
  inUse = [],
}: {
  names: string[];
  types: Record<string, string[]>;
  versions: Record<string, string[]>;
  snapshots: Restorable[];
  inUse?: string[];
}) {
  const [preset, setPreset] = useState<EnginePreset>(ENGINE_PRESETS[0]);
  const [modePreset, setModePreset] = useState<ModePreset>(MODE_PRESETS[0]);
  const [clusterMode, setClusterMode] = useState(false);
  const engine = preset.id;
  const mode = modePreset.id;
  const serverless = mode === "serverless";
  const memcached = engine === "memcached";
  const offered = types[memcached ? "memcached" : "redis"] ?? [];
  const nodeType: Rule = { ...CreateCacheCluster.CacheNodeType, ...(offered.length ? { enum: offered } : {}) };
  const restorable = snapshots.filter((s) => s.kind === (serverless ? "serverless" : "node") && (s.engine ?? "") === engine);
  // Serverless versions are major versions ("8"); node-based ones are full.
  const versionList = serverless ? [...new Set((versions[engine] ?? []).map((v) => v.split(".")[0]))] : (versions[engine] ?? []);
  return (
    <ActionForm action={createCache} submit="Create" testId="create-cache">
      <PresetGallery presets={ENGINE_PRESETS.map((p) => ({ ...p, added: inUse.includes(p.id) }))} chosen={engine} choose={setPreset} label="Engine" />
      <PresetGallery presets={MODE_PRESETS.map((m) => ({ ...m, icon: MODE_ICON[m.id] }))} chosen={mode} choose={setModePreset} label="Deployment" testId="mode" />
      <input type="hidden" name="engine" value={engine} />
      <input type="hidden" name="mode" value={mode} />
      {/* Fields remount per choice, so each starts from that choice's defaults. */}
      <div key={`${engine}-${mode}`} className="preset-fields">
        <Field label="Name" rule={{ ...CreateServerlessCache.ServerlessCacheName, ...NAME }} taken={names} unique>
          <input name="name" required maxLength={40} spellCheck={false} defaultValue={freeName(serverless ? engine : `${engine}-nodes`, names)} />
        </Field>
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
          </>
        )}
        <MoreFields>
          <div className="form-row">
            <Field label="Engine version">
              <select name="version" defaultValue="">
                <option value="">Default</option>
                {versionList.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </Field>
            {!memcached && (
              <Field label="Backup retention (days)" rule={{ type: "integer", min: 0, max: 35 }}>
                <input name="retention" type="number" defaultValue={serverless ? 0 : 1} />
              </Field>
            )}
          </div>
          {!memcached && restorable.length > 0 && (
            <Field label="Restore from snapshot">
              <select name="restore" defaultValue="">
                <option value="">None</option>
                {restorable.map((s) => (
                  <option key={s.name} value={s.kind === "serverless" ? s.arn : s.name}>
                    {s.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
          {!serverless && (
            <label className="check">
              <input type="checkbox" name="tls" /> Encryption in transit
            </label>
          )}
        </MoreFields>
      </div>
    </ActionForm>
  );
}
