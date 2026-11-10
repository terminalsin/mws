import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Page, Pill, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { Lock, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, engineIcon } from "../../lib/clients";
import { engineVersions, listCaches, nodeTypes, snapshots, type Snap } from "../../lib/elasticache";
import { deleteSnapshot } from "./actions";
import { CreateCacheForm } from "./create-cache.tsx";
import { CopySnapshot, RestoreSnapshot } from "./forms.tsx";

export const metadata: Metadata = { title: "ElastiCache" };

type Props = { searchParams: Promise<{ tab?: string }> };

async function offers() {
  const [redis, memcached, valkeyV, redisV, memcachedV] = await Promise.all([
    nodeTypes("redis"),
    nodeTypes("memcached").catch(() => [] as string[]),
    engineVersions("valkey").catch(() => [] as string[]),
    engineVersions("redis").catch(() => [] as string[]),
    engineVersions("memcached").catch(() => [] as string[]),
  ]);
  return { types: { redis, memcached: memcached.length ? memcached : redis }, versions: { valkey: valkeyV, redis: redisV, memcached: memcachedV } };
}

export default async function Caches({ searchParams }: Props) {
  const { tab = "caches" } = await searchParams;
  const [caches, offered, snaps] = await Promise.all([load(listCaches), load(offers), load(() => snapshots())]);
  const names = caches.ok ? caches.value.map((c) => c.name) : [];
  const snapList: Snap[] = snaps.ok ? snaps.value : [];
  const create = (
    <Sheet title="Create cache" label="Create cache" testId="create-cache">
      <CreateCacheForm
        names={names}
        types={offered.ok ? offered.value.types : {}}
        versions={offered.ok ? offered.value.versions : {}}
        snapshots={snapList.filter((s) => s.status === "available").map((s) => ({ kind: s.kind, name: s.name, arn: s.arn, engine: s.engine }))}
        inUse={caches.ok ? [...new Set(caches.value.map((c) => c.engine ?? ""))] : []}
      />
    </Sheet>
  );
  const tabs = (
    <Segments
      label="ElastiCache"
      items={[
        { label: "Caches", href: "/elasticache", active: tab !== "snapshots", count: caches.ok ? caches.value.length || undefined : undefined },
        { label: "Snapshots", href: "/elasticache?tab=snapshots", active: tab === "snapshots", count: snapList.length || undefined },
      ]}
    />
  );
  if (tab === "snapshots") {
    const live = new Set(names);
    const types = offered.ok ? offered.value.types.redis : [];
    return (
      <Page title="Snapshots" actions={create}>
        {tabs}
        {snaps.ok ? (
          <Curated
            label="Snapshots"
            sections={[
              { id: "manual", title: "Manual", items: snapList.filter((s) => s.type === "manual") },
              { id: "automatic", title: "Automatic", items: snapList.filter((s) => s.type !== "manual") },
            ]}
            empty={<Empty icon={ICONS.elasticache} />}
            row={(s) => {
              const href = s.source && live.has(s.source) ? `/elasticache/cache?${s.kind === "serverless" ? "serverless" : "id"}=${encodeURIComponent(s.source)}` : undefined;
              return {
                key: `${s.kind}:${s.name}`,
                icon: <AwsIcon icon={engineIcon(s.engine)} size={22} />,
                title: s.name,
                subtitle: s.source ? (href ? s.source : `${s.source} (deleted)`) : undefined,
                href,
                meta: (
                  <>
                    {s.kind === "serverless" ? <Pill tone="info">Serverless</Pill> : s.nodeType && <span>{s.nodeType}</span>}
                    {s.version && <span>{s.version}</span>}
                    <Status tone={STATUS_TONE(s.status)}>{s.status ?? ""}</Status>
                    <span>{ago(s.at)}</span>
                  </>
                ),
                actions: (
                  <>
                    {s.status === "available" && <RestoreSnapshot snap={s} taken={names} types={types} />}
                    {s.status === "available" && <CopySnapshot kind={s.kind} name={s.name} taken={snapList.map((x) => x.name)} />}
                    <ActionForm action={deleteSnapshot.bind(null, s.kind, s.name)} submit={`Delete ${s.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.name}?`} />
                  </>
                ),
              };
            }}
          />
        ) : (
          <ErrorNotice error={snaps.error} />
        )}
      </Page>
    );
  }
  if (!caches.ok) {
    return (
      <Page title="Caches" actions={create}>
        {tabs}
        <ErrorNotice error={caches.error} />
      </Page>
    );
  }
  return (
    <Page title="Caches" actions={create}>
      {tabs}
      <Curated
        label="Caches"
        sections={[
          { id: "valkey", title: "Valkey", items: caches.value.filter((c) => c.engine === "valkey") },
          { id: "redis", title: "Redis OSS", items: caches.value.filter((c) => c.engine === "redis") },
          { id: "memcached", title: "Memcached", items: caches.value.filter((c) => c.engine === "memcached") },
        ]}
        empty={<Empty icon={ICONS.elasticache} action={create} />}
        row={(c) => ({
          key: `${c.kind}:${c.name}`,
          icon: <AwsIcon icon={engineIcon(c.engine)} size={24} />,
          title: c.name,
          subtitle: c.endpoint ? <code className="clip">{c.endpoint}</code> : undefined,
          href: c.href,
          meta: (
            <>
              {c.kind === "serverless" ? (
                <Pill tone="info">Serverless</Pill>
              ) : c.clusterMode ? (
                <span>
                  {c.shards} shards · {c.nodes} × {c.nodeType}
                </span>
              ) : (
                <span>
                  {c.nodes} × {c.nodeType}
                </span>
              )}
              {c.version && <span>{c.version}</span>}
              {c.tls && <Lock size={13} aria-label="TLS" />}
              <Status tone={STATUS_TONE(c.status)}>{c.status ?? ""}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
