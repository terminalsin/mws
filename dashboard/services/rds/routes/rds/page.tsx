import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Clock, Lock, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, engineIcon } from "../../lib/clients";
import { clusters as listClusters, engineVersions, instances as listInstances, orderableClasses, snapshots } from "../../lib/data";
import { ENGINES } from "../../lib/rules";
import { deleteSnapshot } from "./actions";
import { CreateDatabaseForm } from "./create-database.tsx";
import { CopySnapshot, RestoreSnapshot } from "./forms.tsx";

export const metadata: Metadata = { title: "RDS" };

type Props = { searchParams: Promise<{ tab?: string }> };

/** The classes and versions RDS offers each engine the console creates. */
async function offers() {
  const entries = await Promise.all(
    ENGINES.map(async ({ value }) => {
      const [classes, versions] = await Promise.all([orderableClasses(value), engineVersions(value).catch(() => [])]);
      return [value, { classes, versions: versions.map((v) => v.version) }] as const;
    }),
  );
  return Object.fromEntries(entries) as Record<string, { classes: string[]; versions: string[] }>;
}

function CreateDatabase({ offered, taken, inUse }: { offered: Record<string, { classes: string[]; versions: string[] }>; taken: string[]; inUse?: string[] }) {
  return (
    <Sheet title="Create database" label="Create database" testId="create-database">
      <CreateDatabaseForm
        classes={Object.fromEntries(Object.entries(offered).map(([k, v]) => [k, v.classes]))}
        versions={Object.fromEntries(Object.entries(offered).map(([k, v]) => [k, v.versions]))}
        taken={taken}
        inUse={inUse}
      />
    </Sheet>
  );
}

export default async function Databases({ searchParams }: Props) {
  const { tab = "databases" } = await searchParams;
  const [offered, data] = await Promise.all([
    load(offers),
    load(async () => {
      const [instances, clusters] = await Promise.all([listInstances(), listClusters()]);
      return { instances, clusters };
    }),
  ]);
  const offers_ = offered.ok ? offered.value : {};
  const names = data.ok ? [...data.value.instances.map((i) => i.DBInstanceIdentifier!), ...data.value.clusters.map((c) => c.DBClusterIdentifier!)] : [];
  if (tab === "snapshots") {
    const snaps = await load(() => snapshots());
    const live = new Set(names);
    const snapNames = snaps.ok ? snaps.value.map((s) => s.id) : [];
    return (
      <Page title="Snapshots">
        {snaps.ok ? (
          <Curated
            label="Snapshots"
            sections={[
              { id: "manual", title: "Manual", items: snaps.value.filter((s) => s.type === "manual") },
              { id: "automated", title: "System", items: snaps.value.filter((s) => s.type === "automated") },
              { id: "other", title: "AWS Backup", items: snaps.value.filter((s) => s.type !== "manual" && s.type !== "automated") },
            ]}
            empty={<Empty icon={ICONS.rds} />}
            row={(s) => {
              const available = s.status === "available";
              return {
                key: `${s.kind}:${s.id}`,
                icon: <AwsIcon icon={engineIcon(s.engine)} size={22} />,
                title: s.id,
                subtitle: s.source && live.has(s.source) ? s.source : s.source ? `${s.source} (deleted)` : undefined,
                href: s.source && live.has(s.source) ? `/rds/db?${s.kind === "cluster" ? "cluster" : "id"}=${encodeURIComponent(s.source)}` : undefined,
                meta: (
                  <>
                    {s.kind === "cluster" && <Pill tone="info">Cluster</Pill>}
                    {s.encrypted && <Lock size={13} aria-label="Encrypted" />}
                    {s.size ? <span>{s.size} GiB</span> : null}
                    <span>{s.version}</span>
                    <Status tone={STATUS_TONE(s.status)}>{s.status ?? ""}</Status>
                    <span>{ago(s.at)}</span>
                  </>
                ),
                actions: (
                  <>
                    {available && <RestoreSnapshot kind={s.kind} id={s.id} engine={s.engine ?? ""} classes={offers_[s.engine ?? ""]?.classes ?? []} taken={names} />}
                    {available && <CopySnapshot kind={s.kind} id={s.id} taken={snapNames} />}
                    {s.type === "manual" && (
                      <ActionForm action={deleteSnapshot.bind(null, s.kind, s.id)} submit={`Delete ${s.id}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.id}?`} />
                    )}
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
  const inUse = data.ok ? [...new Set([...data.value.instances.filter((i) => !i.DBClusterIdentifier).map((i) => i.Engine ?? ""), ...data.value.clusters.map((c) => c.Engine ?? "")])] : [];
  const create = (taken: string[]) => <CreateDatabase offered={offers_} taken={taken} inUse={inUse} />;
  if (!data.ok) {
    return (
      <Page title="Databases" actions={create([])}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { instances, clusters } = data.value;
  const rows = [
    ...clusters.map((c) => ({
      key: `cluster:${c.DBClusterIdentifier}`,
      name: c.DBClusterIdentifier!,
      href: `/rds/db?cluster=${encodeURIComponent(c.DBClusterIdentifier!)}`,
      engine: c.Engine,
      version: c.EngineVersion,
      status: c.Status,
      size: `${c.DBClusterMembers?.length ?? 0} instances`,
      multiAz: c.MultiAZ,
      endpoint: c.Endpoint,
      cluster: true,
      replicaOf: undefined as string | undefined,
      pending: !!c.PendingModifiedValues && Object.values(c.PendingModifiedValues).some((v) => v !== undefined),
    })),
    // Cluster members are listed on their cluster's page.
    ...instances
      .filter((i) => !i.DBClusterIdentifier)
      .map((i) => ({
        key: `instance:${i.DBInstanceIdentifier}`,
        name: i.DBInstanceIdentifier!,
        href: `/rds/db?id=${encodeURIComponent(i.DBInstanceIdentifier!)}`,
        engine: i.Engine,
        version: i.EngineVersion,
        status: i.DBInstanceStatus,
        size: i.DBInstanceClass,
        multiAz: i.MultiAZ,
        endpoint: i.Endpoint?.Address ? `${i.Endpoint.Address}:${i.Endpoint.Port}` : undefined,
        cluster: false,
        replicaOf: i.ReadReplicaSourceDBInstanceIdentifier,
        pending: !!i.PendingModifiedValues && Object.values(i.PendingModifiedValues).some((v) => v !== undefined),
      })),
  ].sort((a, b) => a.name.localeCompare(b.name));
  const family = (e: string | undefined) => (e?.includes("postgres") ? "postgres" : e?.includes("mysql") || e?.includes("mariadb") ? "mysql" : "other");
  return (
    <Page title="Databases" actions={create(names)}>
      <Curated
        label="Databases"
        sections={[
          { id: "postgres", title: "PostgreSQL", items: rows.filter((d) => family(d.engine) === "postgres") },
          { id: "mysql", title: "MySQL and MariaDB", items: rows.filter((d) => family(d.engine) === "mysql") },
          { id: "other", title: "Other engines", items: rows.filter((d) => family(d.engine) === "other") },
        ]}
        empty={<Empty icon={ICONS.rds} action={create([])} />}
        row={(d) => ({
          key: d.key,
          icon: <AwsIcon icon={engineIcon(d.engine)} size={24} />,
          title: d.name,
          subtitle: d.endpoint ? <code className="clip">{d.endpoint}</code> : undefined,
          href: d.href,
          meta: (
            <>
              {d.cluster && <Pill tone="info">Cluster</Pill>}
              {d.replicaOf && <Pill title={`Read replica of ${d.replicaOf}`}>Replica</Pill>}
              {d.multiAz && <Pill>Multi-AZ</Pill>}
              {d.pending && <Pill tone="warn" icon={<Clock size={12} />} title="Pending modifications">Pending</Pill>}
              <span>{d.size}</span>
              <span>{d.version}</span>
              <Status tone={STATUS_TONE(d.status)}>{d.status ?? ""}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
