import { DescribeDBClusterSnapshotsCommand, DescribeDBClustersCommand, DescribeDBInstancesCommand, DescribeDBSnapshotsCommand } from "@aws-sdk/client-rds";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, engineIcon, rds } from "../../lib/clients";
import { createDatabase, deleteSnapshot } from "./actions";

export const metadata: Metadata = { title: "RDS" };

type Props = { searchParams: Promise<{ tab?: string }> };

const ENGINES = [
  { value: "postgres", label: "PostgreSQL" },
  { value: "mysql", label: "MySQL" },
  { value: "mariadb", label: "MariaDB" },
  { value: "aurora-postgresql", label: "Aurora PostgreSQL" },
  { value: "aurora-mysql", label: "Aurora MySQL" },
];

function CreateDatabase() {
  return (
    <Sheet title="Create database" label="Create database" testId="create-database">
      <ActionForm action={createDatabase} submit="Create database" testId="create-database">
        <Field label="Engine">
          <select name="engine" defaultValue="postgres">
            {ENGINES.map((e) => (
              <option key={e.value} value={e.value}>
                {e.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="DB identifier">
          <input name="id" required pattern="[a-zA-Z][a-zA-Z0-9\-]*" maxLength={63} autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Master username">
            <input name="username" required defaultValue="postgres" />
          </Field>
          <Field label="Master password">
            <input name="password" type="password" required minLength={8} />
          </Field>
        </div>
        <div className="form-row">
          <Field label="Instance class">
            <input name="class" defaultValue="db.t4g.micro" list="db-classes" />
          </Field>
          <Field label="Storage (GiB)">
            <input name="storage" type="number" min={20} defaultValue={20} />
          </Field>
        </div>
        <datalist id="db-classes">
          {["db.t4g.micro", "db.t4g.small", "db.t4g.medium", "db.m7g.large", "db.r7g.large", "db.serverless"].map((c) => (
            <option key={c} value={c} />
          ))}
        </datalist>
        <label className="check">
          <input type="checkbox" name="multiAz" /> Multi-AZ
        </label>
      </ActionForm>
    </Sheet>
  );
}

export default async function Databases({ searchParams }: Props) {
  const { tab = "databases" } = await searchParams;
  const client = await rds();
  if (tab === "snapshots") {
    const snaps = await load(async () => {
      const [i, c] = await Promise.all([
        client.send(new DescribeDBSnapshotsCommand({})).then((r) => r.DBSnapshots ?? []),
        client.send(new DescribeDBClusterSnapshotsCommand({})).then((r) => r.DBClusterSnapshots ?? []),
      ]);
      return [
        ...i.map((s) => ({ kind: "instance" as const, id: s.DBSnapshotIdentifier!, source: s.DBInstanceIdentifier, engine: s.Engine, type: s.SnapshotType, status: s.Status, at: s.SnapshotCreateTime, size: s.AllocatedStorage })),
        ...c.map((s) => ({ kind: "cluster" as const, id: s.DBClusterSnapshotIdentifier!, source: s.DBClusterIdentifier, engine: s.Engine, type: s.SnapshotType, status: s.Status, at: s.SnapshotCreateTime, size: s.AllocatedStorage })),
      ].sort((a, b) => (b.at?.getTime() ?? 0) - (a.at?.getTime() ?? 0));
    });
    return (
      <Page title="Snapshots">
        {snaps.ok ? (
          <Curated
            label="Snapshots"
            sections={[
              { id: "manual", title: "Manual", items: snaps.value.filter((s) => s.type === "manual") },
              { id: "automated", title: "System", items: snaps.value.filter((s) => s.type !== "manual") },
            ]}
            empty={<Empty icon={ICONS.rds} />}
            row={(s) => ({
              key: `${s.kind}:${s.id}`,
              icon: <AwsIcon icon={engineIcon(s.engine)} size={22} />,
              title: s.id,
              subtitle: s.source,
              href: `/rds/db?${s.kind === "cluster" ? "cluster" : "id"}=${encodeURIComponent(s.source ?? "")}`,
              meta: (
                <>
                  {s.size ? <span>{s.size} GiB</span> : null}
                  <Status tone={STATUS_TONE(s.status)}>{s.status}</Status>
                  <span>{ago(s.at)}</span>
                </>
              ),
              actions: s.type === "manual" ? <ActionForm action={deleteSnapshot.bind(null, s.kind, s.id)} submit={`Delete ${s.id}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.id}?`} /> : undefined,
            })}
          />
        ) : (
          <ErrorNotice error={snaps.error} />
        )}
      </Page>
    );
  }
  const data = await load(async () => {
    const [instances, clusters] = await Promise.all([
      client.send(new DescribeDBInstancesCommand({})).then((r) => r.DBInstances ?? []),
      client.send(new DescribeDBClustersCommand({})).then((r) => r.DBClusters ?? []),
    ]);
    return [
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
      })),
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
        })),
    ];
  });
  if (!data.ok) {
    return (
      <Page title="Databases" actions={<CreateDatabase />}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const all = data.value.sort((a, b) => a.name.localeCompare(b.name));
  const family = (e: string | undefined) => (e?.includes("postgres") ? "postgres" : e?.includes("mysql") || e?.includes("mariadb") ? "mysql" : "other");
  return (
    <Page title="Databases" actions={<CreateDatabase />}>
      <Curated
        label="Databases"
        sections={[
          { id: "postgres", title: "PostgreSQL", items: all.filter((d) => family(d.engine) === "postgres") },
          { id: "mysql", title: "MySQL and MariaDB", items: all.filter((d) => family(d.engine) === "mysql") },
          { id: "other", title: "Other engines", items: all.filter((d) => family(d.engine) === "other") },
        ]}
        empty={<Empty icon={ICONS.rds} action={<CreateDatabase />} />}
        row={(d) => ({
          key: d.key,
          icon: <AwsIcon icon={engineIcon(d.engine)} size={24} />,
          title: d.name,
          subtitle: d.endpoint ? <code className="clip">{d.endpoint}</code> : undefined,
          href: d.href,
          meta: (
            <>
              {d.cluster && <Pill tone="info">Cluster</Pill>}
              {d.multiAz && <Pill>Multi-AZ</Pill>}
              <span>{d.size}</span>
              <span>{d.version}</span>
              <Status tone={STATUS_TONE(d.status)}>{d.status}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
