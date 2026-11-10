import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateCacheCluster, CreateServerlessCache } from "@mws-dashboard/ui/model/elasticache";
import { Lock } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, engineIcon } from "../../lib/clients";
import { listCaches, nodeTypes } from "../../lib/elasticache";
import { createCache } from "./actions";

export const metadata: Metadata = { title: "ElastiCache" };

// The model leaves identifiers unconstrained; ElastiCache's rules are in its
// docs (and MWS enforces them): a letter first, then letters, digits and
// single hyphens, no hyphen at the end, at most 40 characters.
const NAME: Rule = {
  ...CreateServerlessCache.ServerlessCacheName,
  maxLength: 40,
  pattern: "^[a-zA-Z](?!.*--)[a-zA-Z0-9-]*(?<!-)$",
  hint: "Starts with a letter; letters, digits and single hyphens",
  generate: "name",
};

function CreateCache({ names = [], types = [], list }: { names?: string[]; types?: string[]; list: string }) {
  const nodeType: Rule = { ...CreateCacheCluster.CacheNodeType, ...(types.length ? { enum: types } : {}) };
  return (
    <Sheet title="Create cache" label="Create cache" testId="create-cache">
      <ActionForm action={createCache} submit="Create" testId="create-cache">
        <div className="form-row">
          <Field label="Engine">
            <select name="engine" defaultValue="valkey">
              <option value="valkey">Valkey</option>
              <option value="redis">Redis OSS</option>
              <option value="memcached">Memcached</option>
            </select>
          </Field>
          <Field label="Deployment">
            <select name="mode" defaultValue="serverless">
              <option value="serverless">Serverless</option>
              <option value="nodes">Design your own cache</option>
            </select>
          </Field>
        </div>
        <Field label="Name" rule={NAME} taken={names} unique>
          <input name="name" required maxLength={40} autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Node type" rule={nodeType} known={types}>
            <input name="nodeType" defaultValue="cache.t4g.micro" list={list} autoComplete="off" />
            <datalist id={list}>
              {types.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
          </Field>
          <Field label="Nodes" rule={CreateCacheCluster.NumCacheNodes}>
            <input name="nodes" type="number" min={1} max={40} defaultValue={1} />
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" name="tls" /> Encryption in transit
        </label>
      </ActionForm>
    </Sheet>
  );
}

export default async function Caches() {
  const [caches, types] = await Promise.all([load(listCaches), load(nodeTypes)]);
  const known = { names: caches.ok ? caches.value.map((c) => c.name) : [], types: types.ok ? types.value : [] };
  const create = <CreateCache {...known} list="node-types" />;
  if (!caches.ok) {
    return (
      <Page title="Caches" actions={create}>
        <ErrorNotice error={caches.error} />
      </Page>
    );
  }
  return (
    <Page title="Caches" actions={create}>
      <Curated
        label="Caches"
        sections={[
          { id: "valkey", title: "Valkey", items: caches.value.filter((c) => c.engine === "valkey") },
          { id: "redis", title: "Redis OSS", items: caches.value.filter((c) => c.engine === "redis") },
          { id: "memcached", title: "Memcached", items: caches.value.filter((c) => c.engine === "memcached") },
        ]}
        empty={<Empty icon={ICONS.elasticache} action={<CreateCache {...known} list="node-types-empty" />} />}
        row={(c) => ({
          key: `${c.kind}:${c.name}`,
          icon: <AwsIcon icon={engineIcon(c.engine)} size={24} />,
          title: c.name,
          subtitle: c.endpoint ? <code className="clip">{c.endpoint}</code> : undefined,
          href: c.href,
          meta: (
            <>
              {c.kind === "serverless" ? <Pill tone="info">Serverless</Pill> : <span>{c.nodes} × {c.nodeType}</span>}
              {c.tls && <Lock size={13} aria-label="TLS" />}
              <Status tone={STATUS_TONE(c.status)}>{c.status}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
